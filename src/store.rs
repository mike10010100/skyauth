//! Sharded Concurrent OAuth State Store and Storage Abstractions.
//!
//! Provides the [`OAuthStore`] trait and a 64-shard in-memory [`OAuthStateStore`].
//!
//! ## Security & Resilience Invariants
//!
//! - **64 Independent Shards**: State entries are partitioned across 64 [`parking_lot::RwLock`]
//!   shards using deterministic hashing ([`ahash::AHasher`]) to reduce lock contention.
//! - **Single-Use Atomic Consumption**: Calling [`OAuthStore::consume_state`] or
//!   [`OAuthStateStore::consume_state_sync`] atomically moves a pending state to a terminal slot.
//! - **Drift-Free Background TTL Pruning**: Expired state records are periodically pruned using
//!   [`tokio::time::interval`] with missed-tick skipping and clock-warp safe time comparisons.
//! - **No Lock Across Await Points**: Shard lock guards are released before suspension points.

use std::collections::HashMap;
use std::future::Future;
use std::hash::{Hash, Hasher};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use ahash::AHasher;
use parking_lot::{Mutex, RwLock};
use tokio::sync::Notify;
use tokio::task::JoinSet;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::client::StoredStateEntry;
use crate::crypto::base64url_encode;
use crate::error::StoreError;
use crate::policy::{shard_index_for, state_take_accepts};
use crate::session::OAuthSession;

/// Number of independent `RwLock` shards in [`OAuthStateStore`].
pub const NUM_SHARDS: usize = 64;

/// Default time-to-live (TTL) for authorization state tokens (5 minutes / 300 seconds).
pub const DEFAULT_STATE_TTL: Duration = Duration::from_secs(300);

/// Default maximum number of coordinated refresh sessions.
pub const DEFAULT_MAX_REFRESH_SESSIONS: usize = 4_096;

/// Default idle lifetime for completed refresh-coordination records.
pub const DEFAULT_REFRESH_RECORD_IDLE_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// Asynchronous, zero-cost storage abstraction for AT Protocol OAuth state and sessions.
///
/// Implemented by [`OAuthStateStore`] for high-performance in-memory storage, and can
/// be implemented by external crates for Redis, SQL, or distributed backends.
/// Boxed asynchronous operation returned by an [`OAuthStore`].
pub type OAuthStoreFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, StoreError>> + Send + 'a>>;

/// Storage abstraction for AT Protocol OAuth authorization state.
pub trait OAuthStore: std::fmt::Debug + Send + Sync + 'static {
    /// Inserts a temporary authorization state entry with a specified TTL.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the underlying storage backend fails.
    fn insert_state(
        &self,
        state: String,
        entry: StoredStateEntry,
        ttl: Duration,
    ) -> OAuthStoreFuture<'_, ()>;

    /// Atomically takes and removes an authorization state entry by state token.
    ///
    /// Single-use semantics: If the state is found and has not expired, it is returned
    /// and immediately removed from storage. Subsequent lookups with the same token
    /// will return `Ok(None)`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the underlying storage backend fails.
    fn consume_state(&self, state: &str) -> OAuthStoreFuture<'_, StateTakeResult>;

    /// Atomically takes a pending authorization state entry.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the underlying storage backend fails.
    fn take_state(&self, state: &str) -> OAuthStoreFuture<'_, Option<StoredStateEntry>> {
        let state = state.to_string();
        Box::pin(async move {
            Ok(match self.consume_state(&state).await? {
                StateTakeResult::Acquired(entry) => Some(*entry),
                StateTakeResult::Missing | StateTakeResult::Expired | StateTakeResult::Replayed => {
                    None
                }
            })
        })
    }

    /// Checks whether an active, unexpired state entry exists without consuming it.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the underlying storage backend fails.
    fn contains_state(&self, state: &str) -> OAuthStoreFuture<'_, bool>;

    /// Prunes all expired state entries across the store, returning the number of evicted entries.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the underlying storage backend fails.
    fn prune_expired(&self) -> OAuthStoreFuture<'_, usize>;

    /// Acquires exclusive ownership of one session token-set generation.
    ///
    /// Concurrent callers either receive the lease or wait for and receive the committed session.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the backend cannot make an atomic decision.
    fn acquire_refresh(
        &self,
        session_id: &str,
        generation: u64,
    ) -> OAuthStoreFuture<'_, RefreshAcquire>;

    /// Atomically commits a complete replacement session for a refresh lease.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the lease is stale or the replacement is inconsistent.
    fn commit_refresh(
        &self,
        lease: RefreshLease,
        replacement: OAuthSession,
    ) -> OAuthStoreFuture<'_, OAuthSession>;

    /// Permanently records an uncertain refresh outcome for the leased generation.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the lease is stale.
    fn fail_refresh(&self, lease: RefreshLease) -> OAuthStoreFuture<'_, ()>;
}

/// Exclusive backend lease for one refresh-token generation.
#[derive(Clone)]
pub struct RefreshLease {
    session_id: String,
    generation: u64,
    lease_id: String,
}

impl std::fmt::Debug for RefreshLease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RefreshLease")
            .field("session_id", &self.session_id)
            .field("generation", &self.generation)
            .field("lease_id", &"[REDACTED]")
            .finish()
    }
}

impl RefreshLease {
    /// Constructs a lease returned by a trusted storage backend.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::RefreshConflict`] for empty identifiers.
    pub fn for_backend(
        session_id: impl Into<String>,
        generation: u64,
        lease_id: impl Into<String>,
    ) -> Result<Self, StoreError> {
        let session_id = session_id.into();
        let lease_id = lease_id.into();
        if session_id.is_empty() || lease_id.is_empty() {
            return Err(StoreError::RefreshConflict);
        }
        Ok(Self {
            session_id,
            generation,
            lease_id,
        })
    }

    /// Returns the stable session identifier.
    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Returns the leased token-set generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the backend's opaque lease identifier.
    #[must_use]
    pub fn lease_id(&self) -> &str {
        &self.lease_id
    }
}

/// Result of acquiring refresh ownership for a token-set generation.
#[derive(Debug)]
pub enum RefreshAcquire {
    /// The caller owns the refresh exchange and must commit or fail the lease.
    Acquired(RefreshLease),
    /// A concurrent caller already committed a newer complete session.
    Current(Box<OAuthSession>),
}

/// Result of atomically consuming an authorization transaction.
#[derive(Debug)]
pub enum StateTakeResult {
    /// The pending transaction was acquired and consumed.
    Acquired(Box<StoredStateEntry>),
    /// No transaction or live tombstone exists for the identifier.
    Missing,
    /// The pending transaction expired before consumption.
    Expired,
    /// The transaction was already consumed within its lifetime.
    Replayed,
}

/// Internal record wrapping a [`StoredStateEntry`] with monotonic expiration bounds.
#[derive(Debug, Clone)]
struct StoredStateRecord {
    entry: StoredStateEntry,
    created_at: Instant,
    expires_at: Instant,
}

#[derive(Debug)]
enum StateSlot {
    Pending(Box<StoredStateRecord>),
    Consumed { expires_at: Instant },
}

#[derive(Debug)]
struct RefreshRecord {
    current: Option<OAuthSession>,
    in_flight: Option<(u64, String)>,
    failed_generation: Option<u64>,
    notify: Arc<Notify>,
    last_touched: Instant,
}

impl RefreshRecord {
    /// Creates a refresh record with one active generation lease.
    fn new(generation: u64, lease_id: String, now: Instant) -> Self {
        Self {
            current: None,
            in_flight: Some((generation, lease_id)),
            failed_generation: None,
            notify: Arc::new(Notify::new()),
            last_touched: now,
        }
    }
}

/// Registers a refresh waiter before the coordination lock can be released.
fn registered_refresh_waiter(notify: Arc<Notify>) -> Pin<Box<tokio::sync::futures::OwnedNotified>> {
    let mut waiter = Box::pin(notify.notified_owned());
    waiter.as_mut().enable();
    waiter
}

impl StateSlot {
    fn is_expired(&self, now: Instant) -> bool {
        match self {
            Self::Pending(record) => record.is_expired(now),
            Self::Consumed { expires_at } => now >= *expires_at,
        }
    }
}

impl StoredStateRecord {
    /// Creates a new record with monotonic timestamps.
    fn new(entry: StoredStateEntry, ttl: Duration) -> Result<Self, StoreError> {
        let now = Instant::now();
        let expires_at = now.checked_add(ttl).ok_or_else(|| {
            StoreError::Backend("State expiration exceeds monotonic clock range".to_string())
        })?;
        Ok(Self {
            entry,
            created_at: now,
            expires_at,
        })
    }

    /// Checks if this record has expired based on monotonic time with clock-warp safety.
    fn is_expired(&self, now: Instant) -> bool {
        if now >= self.expires_at {
            true
        } else {
            // Guard against clock warp / monotonic backward step
            let elapsed = now.saturating_duration_since(self.created_at);
            let ttl = self.expires_at.saturating_duration_since(self.created_at);
            elapsed >= ttl
        }
    }
}

/// A 64-shard partitioned concurrent in-memory OAuth state store.
///
/// Distributes keys uniformly across 64 independent [`parking_lot::RwLock`] shards using
/// deterministic [`ahash`] hashing. Shard locks are synchronous and are not held across `.await`.
#[derive(Debug)]
pub struct OAuthStateStore {
    shards: [RwLock<HashMap<String, StateSlot>>; NUM_SHARDS],
    default_ttl: Duration,
    refreshes: Mutex<HashMap<String, RefreshRecord>>,
    max_refresh_sessions: usize,
    refresh_record_idle_ttl: Duration,
}

impl Default for OAuthStateStore {
    fn default() -> Self {
        Self::new(DEFAULT_STATE_TTL)
    }
}

impl OAuthStateStore {
    /// Creates a new `OAuthStateStore` with the specified default TTL.
    #[must_use]
    pub fn new(default_ttl: Duration) -> Self {
        Self::with_refresh_capacity(default_ttl, DEFAULT_MAX_REFRESH_SESSIONS)
    }

    /// Creates a store with explicit state lifetime and refresh-session capacity.
    #[must_use]
    pub fn with_refresh_capacity(default_ttl: Duration, max_refresh_sessions: usize) -> Self {
        let shards = std::array::from_fn(|_| RwLock::new(HashMap::new()));
        Self {
            shards,
            default_ttl,
            refreshes: Mutex::new(HashMap::new()),
            max_refresh_sessions,
            refresh_record_idle_ttl: DEFAULT_REFRESH_RECORD_IDLE_TTL,
        }
    }

    /// Computes the deterministic shard index for a given state token.
    #[must_use]
    #[inline]
    pub fn shard_index(&self, key: &str) -> usize {
        let mut hasher = AHasher::default();
        key.hash(&mut hasher);
        shard_index_for(hasher.finish() as usize, NUM_SHARDS)
    }

    /// Returns the configured default TTL duration.
    #[must_use]
    pub fn default_ttl(&self) -> Duration {
        self.default_ttl
    }

    /// Synchronously inserts a state entry with a specific TTL.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if state insertion fails.
    pub fn insert_state_sync(
        &self,
        state: String,
        entry: StoredStateEntry,
        ttl: Duration,
    ) -> Result<(), StoreError> {
        crate::client::validate_state_token(&state)?;
        if entry.state() != state {
            return Err(StoreError::InvalidStateEntry("state mismatch"));
        }
        if ttl.is_zero() {
            return Err(StoreError::InvalidStateEntry("zero lifetime"));
        }
        let idx = self.shard_index(&state);
        let record = StoredStateRecord::new(entry, ttl)?;
        let mut shard = self.shards[idx].write();
        match shard.entry(state.clone()) {
            std::collections::hash_map::Entry::Vacant(slot) => {
                slot.insert(StateSlot::Pending(Box::new(record)));
                Ok(())
            }
            std::collections::hash_map::Entry::Occupied(_) => Err(StoreError::StateCollision),
        }
    }

    /// Synchronously inserts a state entry using the store's default TTL.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if state insertion fails.
    pub fn insert_default_sync(
        &self,
        state: String,
        entry: StoredStateEntry,
    ) -> Result<(), StoreError> {
        self.insert_state_sync(state, entry, self.default_ttl)
    }

    /// Synchronously consumes and atomically removes a state entry on first read.
    ///
    /// Single-use semantics: Returns `Some(entry)` only on the first call for an active,
    /// unexpired token. Subsequent calls or lookups on expired tokens return `None`.
    #[must_use]
    pub fn take_state_sync(&self, state: &str) -> Option<StoredStateEntry> {
        match self.consume_state_sync(state) {
            StateTakeResult::Acquired(entry) => Some(*entry),
            StateTakeResult::Missing | StateTakeResult::Expired | StateTakeResult::Replayed => None,
        }
    }

    /// Synchronously consumes a state entry and retains a bounded replay marker.
    #[must_use]
    pub fn consume_state_sync(&self, state: &str) -> StateTakeResult {
        let idx = self.shard_index(state);
        let mut shard = self.shards[idx].write();
        let now = Instant::now();
        match shard.remove(state) {
            Some(StateSlot::Pending(record)) => {
                if state_take_accepts(true, record.is_expired(now)) {
                    let expires_at = record.expires_at;
                    shard.insert(state.to_string(), StateSlot::Consumed { expires_at });
                    StateTakeResult::Acquired(Box::new(record.entry))
                } else {
                    StateTakeResult::Expired
                }
            }
            Some(StateSlot::Consumed { expires_at }) if now < expires_at => {
                shard.insert(state.to_string(), StateSlot::Consumed { expires_at });
                StateTakeResult::Replayed
            }
            Some(StateSlot::Consumed { .. }) | None => StateTakeResult::Missing,
        }
    }

    /// Synchronously checks if an active, unexpired state entry exists without consuming it.
    #[must_use]
    pub fn contains_state_sync(&self, state: &str) -> bool {
        let idx = self.shard_index(state);
        let shard = self.shards[idx].read();
        if let Some(StateSlot::Pending(record)) = shard.get(state) {
            let now = Instant::now();
            !record.is_expired(now)
        } else {
            false
        }
    }

    /// Synchronously prunes expired state entries across all 64 shards.
    ///
    /// Locks each shard sequentially one at a time to minimize lock hold duration and
    /// avoid blocking other shards. Returns the total count of evicted entries.
    pub fn prune_expired_sync(&self) -> usize {
        let now = Instant::now();
        let mut total_pruned = 0;
        for shard in &self.shards {
            let mut guard = shard.write();
            let initial_count = guard.len();
            guard.retain(|_, slot| !slot.is_expired(now));
            total_pruned += initial_count.saturating_sub(guard.len());
        }
        total_pruned
    }

    /// Returns the total number of items currently stored across all 64 shards (including unpruned expired ones).
    #[must_use]
    pub fn total_entries(&self) -> usize {
        let mut sum = 0;
        for shard in &self.shards {
            sum += shard
                .read()
                .values()
                .filter(|slot| matches!(slot, StateSlot::Pending(_)))
                .count();
        }
        sum
    }

    /// Returns the number of entries in a specific shard.
    #[must_use]
    pub fn shard_len(&self, shard_idx: usize) -> usize {
        self.shards[shard_idx % NUM_SHARDS].read().len()
    }

    /// Checks whether the entire store is empty across all 64 shards.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.total_entries() == 0
    }

    /// Clears all entries from all 64 shards.
    pub fn clear(&self) {
        for shard in &self.shards {
            shard.write().clear();
        }
        self.refreshes.lock().clear();
    }

    async fn acquire_refresh_inner(
        &self,
        session_id: &str,
        generation: u64,
    ) -> Result<RefreshAcquire, StoreError> {
        if session_id.is_empty() {
            return Err(StoreError::RefreshConflict);
        }
        loop {
            let wait = {
                let mut refreshes = self.refreshes.lock();
                let now = Instant::now();
                if let Some(record) = refreshes.get_mut(session_id) {
                    record.last_touched = now;
                    if let Some(current) = record.current.as_ref() {
                        if current.generation() > generation {
                            return Ok(RefreshAcquire::Current(Box::new(current.clone())));
                        }
                    }
                    if record.failed_generation == Some(generation) {
                        return Err(StoreError::RefreshInDoubt);
                    }
                    if record.in_flight.is_none() {
                        let lease_id = new_lease_id();
                        record.in_flight = Some((generation, lease_id.clone()));
                        return RefreshLease::for_backend(session_id, generation, lease_id)
                            .map(RefreshAcquire::Acquired);
                    }
                    Some(registered_refresh_waiter(Arc::clone(&record.notify)))
                } else {
                    if refreshes.len() >= self.max_refresh_sessions {
                        Self::prune_idle_refreshes_locked(
                            &mut refreshes,
                            now,
                            self.refresh_record_idle_ttl,
                        );
                        if refreshes.len() >= self.max_refresh_sessions {
                            return Err(StoreError::RefreshCapacity);
                        }
                    }
                    let lease_id = new_lease_id();
                    refreshes.insert(
                        session_id.to_string(),
                        RefreshRecord::new(generation, lease_id.clone(), now),
                    );
                    return RefreshLease::for_backend(session_id, generation, lease_id)
                        .map(RefreshAcquire::Acquired);
                }
            };
            if let Some(notified) = wait {
                notified.await;
            }
        }
    }

    fn commit_refresh_inner(
        &self,
        lease: &RefreshLease,
        replacement: OAuthSession,
    ) -> Result<OAuthSession, StoreError> {
        let expected_generation = lease
            .generation
            .checked_add(1)
            .ok_or(StoreError::RefreshConflict)?;
        if replacement.session_id() != lease.session_id
            || replacement.generation() != expected_generation
        {
            return Err(StoreError::RefreshConflict);
        }
        let notify = {
            let mut refreshes = self.refreshes.lock();
            let record = refreshes
                .get_mut(&lease.session_id)
                .ok_or(StoreError::RefreshConflict)?;
            if record.in_flight.as_ref() != Some(&(lease.generation, lease.lease_id.clone())) {
                return Err(StoreError::RefreshConflict);
            }
            record.in_flight = None;
            record.failed_generation = None;
            record.current = Some(replacement.clone());
            record.last_touched = Instant::now();
            Arc::clone(&record.notify)
        };
        notify.notify_waiters();
        Ok(replacement)
    }

    fn fail_refresh_inner(&self, lease: &RefreshLease) -> Result<(), StoreError> {
        let notify = {
            let mut refreshes = self.refreshes.lock();
            let record = refreshes
                .get_mut(&lease.session_id)
                .ok_or(StoreError::RefreshConflict)?;
            if record.in_flight.as_ref() != Some(&(lease.generation, lease.lease_id.clone())) {
                return Err(StoreError::RefreshConflict);
            }
            record.in_flight = None;
            record.failed_generation = Some(lease.generation);
            record.last_touched = Instant::now();
            Arc::clone(&record.notify)
        };
        notify.notify_waiters();
        Ok(())
    }

    fn prune_idle_refreshes_locked(
        refreshes: &mut HashMap<String, RefreshRecord>,
        now: Instant,
        idle_ttl: Duration,
    ) -> usize {
        let initial = refreshes.len();
        refreshes.retain(|_, record| {
            record.in_flight.is_some()
                || now.saturating_duration_since(record.last_touched) < idle_ttl
        });
        initial.saturating_sub(refreshes.len())
    }

    fn prune_idle_refreshes_sync(&self) -> usize {
        Self::prune_idle_refreshes_locked(
            &mut self.refreshes.lock(),
            Instant::now(),
            self.refresh_record_idle_ttl,
        )
    }

    /// Spawns a background task that periodically executes drift-free TTL pruning.
    ///
    /// Uses [`tokio::time::interval`] with [`tokio::time::MissedTickBehavior::Skip`] to prevent
    /// schedule drift, and gracefully terminates when the provided [`CancellationToken`] is triggered.
    pub fn spawn_pruning_task(
        self: &Arc<Self>,
        interval_duration: Duration,
        cancellation_token: CancellationToken,
    ) -> StatePruner {
        let store = Arc::clone(self);
        let worker_token = cancellation_token.clone();
        let mut tasks = JoinSet::new();
        tasks.spawn(async move {
            let mut interval = tokio::time::interval(interval_duration);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    _ = worker_token.cancelled() => {
                        break;
                    }
                    _ = interval.tick() => {
                        store.prune_expired_sync();
                        store.prune_idle_refreshes_sync();
                    }
                }
            }
        });
        StatePruner {
            cancellation_token,
            tasks,
        }
    }
}

fn new_lease_id() -> String {
    let mut bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
    base64url_encode(&bytes)
}

/// Managed background state-pruning tasks.
pub struct StatePruner {
    cancellation_token: CancellationToken,
    tasks: JoinSet<()>,
}

impl std::fmt::Debug for StatePruner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StatePruner")
            .field("tasks", &self.tasks.len())
            .finish()
    }
}

impl StatePruner {
    /// Cancels and joins all pruning tasks.
    ///
    /// # Errors
    ///
    /// Returns an error if a pruning task fails to join.
    pub async fn shutdown(&mut self) -> Result<(), StoreError> {
        self.shutdown_with_timeout(Duration::from_secs(5)).await
    }

    /// Cancels background work and enforces a maximum join duration.
    ///
    /// # Errors
    ///
    /// Returns an error when a task fails to join or the deadline expires.
    pub async fn shutdown_with_timeout(&mut self, timeout: Duration) -> Result<(), StoreError> {
        self.cancellation_token.cancel();
        let joined = tokio::time::timeout(timeout, async {
            while let Some(result) = self.tasks.join_next().await {
                result.map_err(|error| StoreError::Backend(error.to_string()))?;
            }
            Ok(())
        })
        .await;
        match joined {
            Ok(result) => result,
            Err(_) => {
                self.tasks.abort_all();
                while self.tasks.join_next().await.is_some() {}
                Err(StoreError::ShutdownTimeout)
            }
        }
    }
}

impl Drop for StatePruner {
    fn drop(&mut self) {
        self.cancellation_token.cancel();
        self.tasks.abort_all();
    }
}

impl OAuthStore for OAuthStateStore {
    fn insert_state(
        &self,
        state: String,
        entry: StoredStateEntry,
        ttl: Duration,
    ) -> OAuthStoreFuture<'_, ()> {
        Box::pin(async move { self.insert_state_sync(state, entry, ttl) })
    }

    fn consume_state(&self, state: &str) -> OAuthStoreFuture<'_, StateTakeResult> {
        let state = state.to_string();
        Box::pin(async move { Ok(self.consume_state_sync(&state)) })
    }

    fn contains_state(&self, state: &str) -> OAuthStoreFuture<'_, bool> {
        let state = state.to_string();
        Box::pin(async move { Ok(self.contains_state_sync(&state)) })
    }

    fn prune_expired(&self) -> OAuthStoreFuture<'_, usize> {
        Box::pin(async move { Ok(self.prune_expired_sync()) })
    }

    fn acquire_refresh(
        &self,
        session_id: &str,
        generation: u64,
    ) -> OAuthStoreFuture<'_, RefreshAcquire> {
        let session_id = session_id.to_string();
        Box::pin(async move { self.acquire_refresh_inner(&session_id, generation).await })
    }

    fn commit_refresh(
        &self,
        lease: RefreshLease,
        replacement: OAuthSession,
    ) -> OAuthStoreFuture<'_, OAuthSession> {
        Box::pin(async move { self.commit_refresh_inner(&lease, replacement) })
    }

    fn fail_refresh(&self, lease: RefreshLease) -> OAuthStoreFuture<'_, ()> {
        Box::pin(async move { self.fail_refresh_inner(&lease) })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]
mod tests {
    use super::*;
    use crate::dpop::DPoPKey;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::SystemTime;

    fn mock_stored_state(state: &str) -> StoredStateEntry {
        StoredStateEntry::builder(state, DPoPKey::generate())
            .client_id("https://app.example.com/client-metadata.json")
            .code_verifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
            .issuer("https://auth.example.com")
            .identity(
                Some("did:plc:alice123".to_string()),
                Some("alice.bsky.social".to_string()),
            )
            .redirect_uri("https://app.example.com/callback")
            .pds_endpoint("https://pds.example.com")
            .token_endpoint("https://auth.example.com/oauth/token")
            .scopes("atproto")
            .lifetime(SystemTime::now(), 300)
            .build()
            .unwrap()
    }

    fn insert_expired_state(store: &OAuthStateStore, state: &str) {
        let now = Instant::now();
        let record = StoredStateRecord {
            entry: mock_stored_state(state),
            created_at: now.checked_sub(Duration::from_secs(2)).unwrap(),
            expires_at: now.checked_sub(Duration::from_secs(1)).unwrap(),
        };
        store.shards[store.shard_index(state)]
            .write()
            .insert(state.to_string(), StateSlot::Pending(Box::new(record)));
    }

    #[test]
    fn test_store_initialization_and_num_shards() {
        let store = OAuthStateStore::default();
        assert_eq!(store.shards.len(), 64);
        assert_eq!(store.total_entries(), 0);
        assert!(store.is_empty());
    }

    #[test]
    fn test_store_insert_and_single_use_consumption() {
        let store = OAuthStateStore::default();
        let state = "csrf_token_test_123";
        let entry = mock_stored_state(state);

        assert!(!store.contains_state_sync(state));
        store
            .insert_state_sync(state.to_string(), entry.clone(), Duration::from_secs(60))
            .unwrap();
        assert!(store.contains_state_sync(state));
        assert_eq!(store.total_entries(), 1);

        // First take succeeds
        let consumed = store.take_state_sync(state);
        assert!(consumed.is_some());
        let consumed = consumed.unwrap();
        assert_eq!(consumed.state(), state);
        assert_eq!(consumed.client_id(), entry.client_id());

        // Second take returns None
        let second_take = store.take_state_sync(state);
        assert!(second_take.is_none());
        assert!(!store.contains_state_sync(state));
        assert_eq!(store.total_entries(), 0);
    }

    #[test]
    fn test_shard_distribution_uniformity() {
        let store = OAuthStateStore::default();
        let mut hit_shards = std::collections::HashSet::new();

        for i in 0..1000 {
            let key = format!("state_entropy_sample_token_{i}");
            hit_shards.insert(store.shard_index(&key));
        }

        // With 1000 random keys, we expect >= 58 shards out of 64 to be hit
        assert!(
            hit_shards.len() >= 55,
            "Shard distribution too sparse: hit {} shards out of 64",
            hit_shards.len()
        );
    }

    #[test]
    fn test_concurrent_single_use_50_threads() {
        let store = Arc::new(OAuthStateStore::default());
        let state = "race_condition_state_token";
        let entry = mock_stored_state(state);

        store
            .insert_state_sync(state.to_string(), entry, Duration::from_secs(60))
            .unwrap();

        let winner_count = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(std::sync::Barrier::new(50));
        let mut handles = Vec::new();

        for _ in 0..50 {
            let s = Arc::clone(&store);
            let w = Arc::clone(&winner_count);
            let b = Arc::clone(&barrier);
            let state_str = state.to_string();

            handles.push(std::thread::spawn(move || {
                b.wait();
                if s.take_state_sync(&state_str).is_some() {
                    w.fetch_add(1, Ordering::SeqCst);
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(
            winner_count.load(Ordering::SeqCst),
            1,
            "Exactly one thread must successfully consume state among 50 racers"
        );
        assert_eq!(store.total_entries(), 0);
    }

    #[test]
    fn test_ttl_expiration_and_pruning() {
        let store = OAuthStateStore::default();
        let state_active = "active_state";
        let state_expired = "expired_state";

        store
            .insert_state_sync(
                state_active.to_string(),
                mock_stored_state(state_active),
                Duration::from_secs(60),
            )
            .unwrap();
        insert_expired_state(&store, state_expired);

        assert_eq!(store.total_entries(), 2);
        assert!(store.contains_state_sync(state_active));
        assert!(!store.contains_state_sync(state_expired));

        // take_state on expired returns None and cleans up
        assert!(store.take_state_sync(state_expired).is_none());

        insert_expired_state(&store, state_expired);
        let pruned = store.prune_expired_sync();
        assert_eq!(pruned, 1);
        assert_eq!(store.total_entries(), 1);
        assert!(store.contains_state_sync(state_active));
    }

    #[tokio::test]
    async fn test_oauth_store_trait_async_operations() {
        let store = OAuthStateStore::default();
        let state = "async_trait_test_state";
        let entry = mock_stored_state(state);

        store
            .insert_state(state.to_string(), entry.clone(), Duration::from_secs(300))
            .await
            .unwrap();
        assert!(store.contains_state(state).await.unwrap());

        let taken = store.take_state(state).await.unwrap();
        assert!(taken.is_some());
        assert_eq!(taken.unwrap().state(), state);

        assert!(!store.contains_state(state).await.unwrap());
        assert!(store.take_state(state).await.unwrap().is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn test_background_pruning_task_cancellation() {
        let store = Arc::new(OAuthStateStore::default());
        let cancel_token = CancellationToken::new();

        insert_expired_state(&store, "exp1");
        insert_expired_state(&store, "exp2");
        assert_eq!(store.total_entries(), 2);

        let mut handle = store.spawn_pruning_task(Duration::from_millis(20), cancel_token.clone());

        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(20)).await;
        assert_eq!(store.total_entries(), 0);

        // Cancel and await join
        cancel_token.cancel();
        let res = handle.shutdown().await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn pruning_shutdown_aborts_after_deadline() {
        let cancellation_token = CancellationToken::new();
        let mut tasks = JoinSet::new();
        tasks.spawn(std::future::pending());
        let mut pruner = StatePruner {
            cancellation_token,
            tasks,
        };
        assert!(matches!(
            pruner.shutdown_with_timeout(Duration::ZERO).await,
            Err(StoreError::ShutdownTimeout)
        ));
        assert!(pruner.tasks.is_empty());
    }

    #[tokio::test]
    async fn registered_refresh_waiter_receives_pre_poll_broadcast() {
        let notify = Arc::new(Notify::new());
        let waiter = registered_refresh_waiter(Arc::clone(&notify));

        notify.notify_waiters();

        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("enabled waiter must observe notify_waiters");
    }

    #[tokio::test]
    async fn concurrent_refresh_waiters_receive_one_committed_session() {
        let store = Arc::new(OAuthStateStore::default());
        let session = OAuthSession::new(
            "did:plc:alice123",
            "access-0",
            Some("refresh-0".to_string()),
            "DPoP",
            Some("atproto".to_string()),
            Some(300),
            DPoPKey::generate(),
            Some("https://pds.example.com".to_string()),
            Some("https://auth.example.com".to_string()),
            Some("https://auth.example.com/token".to_string()),
        )
        .unwrap();
        let lease = match store
            .acquire_refresh(session.session_id(), session.generation())
            .await
            .unwrap()
        {
            RefreshAcquire::Acquired(lease) => lease,
            RefreshAcquire::Current(_) => panic!("first caller must acquire the lease"),
        };

        let mut waiters = JoinSet::new();
        for _ in 0..32 {
            let store = Arc::clone(&store);
            let session_id = session.session_id().to_string();
            waiters.spawn(async move { store.acquire_refresh(&session_id, 0).await });
        }
        tokio::task::yield_now().await;

        let mut replacement = session.clone();
        replacement
            .rotate_tokens(
                "access-1",
                Some("refresh-1".to_string()),
                Some("atproto".to_string()),
                Some(300),
            )
            .unwrap();
        store
            .commit_refresh(lease, replacement.clone())
            .await
            .unwrap();

        while let Some(result) = waiters.join_next().await {
            match result.unwrap().unwrap() {
                RefreshAcquire::Current(current) => {
                    assert_eq!(current.generation(), 1);
                    assert_eq!(current.expose_access_token(), "access-1");
                }
                RefreshAcquire::Acquired(_) => panic!("a waiter acquired a duplicate lease"),
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn idle_completed_refresh_records_are_evicted_at_capacity() {
        let mut store = OAuthStateStore::with_refresh_capacity(DEFAULT_STATE_TTL, 1);
        store.refresh_record_idle_ttl = Duration::from_secs(1);

        let first = match store.acquire_refresh("session-one", 0).await.unwrap() {
            RefreshAcquire::Acquired(lease) => lease,
            RefreshAcquire::Current(_) => panic!("a new session must acquire a lease"),
        };
        store.fail_refresh(first).await.unwrap();
        tokio::time::advance(Duration::from_secs(2)).await;

        assert!(matches!(
            store.acquire_refresh("session-two", 0).await.unwrap(),
            RefreshAcquire::Acquired(_)
        ));
        let refreshes = store.refreshes.lock();
        assert!(!refreshes.contains_key("session-one"));
        assert!(refreshes.contains_key("session-two"));
    }

    #[tokio::test(start_paused = true)]
    async fn idle_pruning_never_evicts_an_in_flight_refresh() {
        let mut store = OAuthStateStore::with_refresh_capacity(DEFAULT_STATE_TTL, 1);
        store.refresh_record_idle_ttl = Duration::from_secs(1);
        assert!(matches!(
            store.acquire_refresh("session-one", 0).await.unwrap(),
            RefreshAcquire::Acquired(_)
        ));
        tokio::time::advance(Duration::from_secs(2)).await;

        assert!(matches!(
            store.acquire_refresh("session-two", 0).await,
            Err(StoreError::RefreshCapacity)
        ));
        assert!(store.refreshes.lock()["session-one"].in_flight.is_some());
    }
}
