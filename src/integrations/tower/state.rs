use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::hash::Hash;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use rand::RngCore;

use crate::crypto::{base64url_encode, constant_time_eq};
use crate::error::DPoPError;
use crate::policy::{nonce_accepts, replay_insert_accepts};

const STATE_SHARDS: usize = 64;
const PRUNE_BATCH: usize = 32;

#[derive(Debug)]
struct ExpiringShard<K, V> {
    entries: HashMap<K, TimedEntry<V>>,
    expirations: BinaryHeap<Reverse<Expiry<K>>>,
    next_sequence: u128,
}

#[derive(Debug)]
struct TimedEntry<V> {
    value: V,
    sequence: u128,
    expires_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Expiry<K> {
    expires_at: u64,
    sequence: u128,
    key: K,
}

impl<K, V> Default for ExpiringShard<K, V> {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
            expirations: BinaryHeap::new(),
            next_sequence: 0,
        }
    }
}

impl<K, V> ExpiringShard<K, V>
where
    K: Clone + Eq + Hash + Ord,
{
    /// Removes at most `limit` elapsed heap records and their live entries.
    fn prune_expired(&mut self, now: u64, limit: usize) {
        let mut examined = 0usize;
        while examined < limit {
            let Some(Reverse(next)) = self.expirations.peek() else {
                break;
            };
            if next.expires_at > now {
                break;
            }
            let Some(Reverse(expired)) = self.expirations.pop() else {
                break;
            };
            examined = examined.saturating_add(1);
            let remove = self
                .entries
                .get(&expired.key)
                .is_some_and(|entry| entry.sequence == expired.sequence);
            if remove {
                self.entries.remove(&expired.key);
            }
        }
    }

    /// Inserts or replaces one value and indexes its expiration generation.
    fn insert(&mut self, key: K, value: V, expires_at: u64) {
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);
        self.expirations.push(Reverse(Expiry {
            expires_at,
            sequence,
            key: key.clone(),
        }));
        self.entries.insert(
            key,
            TimedEntry {
                value,
                sequence,
                expires_at,
            },
        );
    }

    /// Returns the value stored for a key only while its lifetime remains live.
    fn get(&self, key: &K, now: u64) -> Option<&V> {
        self.entries
            .get(key)
            .filter(|entry| entry.expires_at > now)
            .map(|entry| &entry.value)
    }

    /// Reports whether a key currently has an unexpired map entry.
    fn contains_key(&self, key: &K, now: u64) -> bool {
        self.entries
            .get(key)
            .is_some_and(|entry| entry.expires_at > now)
    }

    /// Returns the number of live map entries.
    fn len(&self) -> usize {
        self.entries.len()
    }
}

/// Atomic storage for accepted DPoP proof identifiers.
pub trait DPoPReplayStore: std::fmt::Debug + Send + Sync + 'static {
    /// Records an accepted proof unless its identifier is already live.
    ///
    /// # Errors
    ///
    /// Returns [`DPoPError`] when the proof was already accepted or storage is unavailable.
    fn insert_once(
        &self,
        issuer: &str,
        token_identifier: &str,
        thumbprint: &str,
        proof_identifier: &str,
        now: u64,
        expires_at: u64,
    ) -> Result<(), DPoPError>;
}

/// Bounded, sharded in-memory DPoP replay store.
#[derive(Debug, Clone)]
pub struct InMemoryDPoPReplayStore {
    shards: Arc<[Mutex<ExpiringShard<ReplayKey, ()>>; STATE_SHARDS]>,
    shard_capacities: Arc<[usize; STATE_SHARDS]>,
}

impl InMemoryDPoPReplayStore {
    /// Creates a replay store with the requested total entry bound.
    ///
    /// # Errors
    ///
    /// Returns [`DPoPError`] when the bound cannot allocate at least one entry per shard.
    pub fn new(max_entries: usize) -> Result<Self, DPoPError> {
        if max_entries < STATE_SHARDS {
            return Err(DPoPError::ReplayStoreUnavailable);
        }
        let base = max_entries / STATE_SHARDS;
        let remainder = max_entries % STATE_SHARDS;
        Ok(Self {
            shards: Arc::new(std::array::from_fn(
                |_| Mutex::new(ExpiringShard::default()),
            )),
            shard_capacities: Arc::new(std::array::from_fn(|index| {
                base + usize::from(index < remainder)
            })),
        })
    }
}

impl DPoPReplayStore for InMemoryDPoPReplayStore {
    fn insert_once(
        &self,
        issuer: &str,
        token_identifier: &str,
        thumbprint: &str,
        proof_identifier: &str,
        now: u64,
        expires_at: u64,
    ) -> Result<(), DPoPError> {
        let key = ReplayKey::new(issuer, token_identifier, thumbprint, proof_identifier);
        let shard_index = shard_index(&key);
        let mut shard = self.shards[shard_index].lock();
        shard.prune_expired(now, PRUNE_BATCH);
        let already_live = shard.contains_key(&key, now);
        let mut capacity_available = shard.len() < self.shard_capacities[shard_index];
        if !already_live && !capacity_available {
            shard.prune_expired(now, usize::MAX);
            capacity_available = shard.len() < self.shard_capacities[shard_index];
        }
        if !replay_insert_accepts(already_live, capacity_available) && already_live {
            return Err(DPoPError::ReplayDetected);
        }
        if !replay_insert_accepts(already_live, capacity_available) {
            return Err(DPoPError::ReplayStoreUnavailable);
        }
        shard.insert(key, (), expires_at);
        Ok(())
    }
}

/// Result of atomically evaluating a DPoP nonce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DPoPNonceDecision {
    /// The request may proceed and the returned nonce is required next.
    Accepted(String),
    /// The request must be retried with the returned nonce.
    Challenge(String),
}

/// Atomic storage for rotating DPoP nonces.
pub trait DPoPNonceStore: std::fmt::Debug + Send + Sync + 'static {
    /// Evaluates a nonce and rotates the stored value.
    ///
    /// # Errors
    ///
    /// Returns [`DPoPError`] when nonce state cannot be checked.
    fn evaluate_and_rotate(
        &self,
        issuer: &str,
        token_identifier: &str,
        thumbprint: &str,
        presented_nonce: Option<&str>,
        require_initial_nonce: bool,
        now: u64,
    ) -> Result<DPoPNonceDecision, DPoPError>;
}

/// Bounded, sharded in-memory DPoP nonce store.
#[derive(Debug, Clone)]
pub struct InMemoryDPoPNonceStore {
    shards: Arc<[Mutex<ExpiringShard<NonceKey, NonceRecord>>; STATE_SHARDS]>,
    shard_capacities: Arc<[usize; STATE_SHARDS]>,
    ttl: Duration,
}

impl InMemoryDPoPNonceStore {
    /// Creates a nonce store with total entry and lifetime bounds.
    ///
    /// # Errors
    ///
    /// Returns [`DPoPError`] for an unusable bound or zero lifetime.
    pub fn new(max_entries: usize, ttl: Duration) -> Result<Self, DPoPError> {
        if max_entries < STATE_SHARDS || ttl.is_zero() {
            return Err(DPoPError::NonceStoreUnavailable);
        }
        let base = max_entries / STATE_SHARDS;
        let remainder = max_entries % STATE_SHARDS;
        Ok(Self {
            shards: Arc::new(std::array::from_fn(
                |_| Mutex::new(ExpiringShard::default()),
            )),
            shard_capacities: Arc::new(std::array::from_fn(|index| {
                base + usize::from(index < remainder)
            })),
            ttl,
        })
    }
}

impl DPoPNonceStore for InMemoryDPoPNonceStore {
    fn evaluate_and_rotate(
        &self,
        issuer: &str,
        token_identifier: &str,
        thumbprint: &str,
        presented_nonce: Option<&str>,
        require_initial_nonce: bool,
        now: u64,
    ) -> Result<DPoPNonceDecision, DPoPError> {
        let key = NonceKey::new(issuer, token_identifier, thumbprint);
        let shard_index = shard_index(&key);
        let mut shard = self.shards[shard_index].lock();
        shard.prune_expired(now, PRUNE_BATCH);

        let current = shard.get(&key, now).cloned();
        let nonce_matches = current.as_ref().is_some_and(|record| {
            presented_nonce.is_some_and(|presented| {
                constant_time_eq(presented.as_bytes(), record.current.as_bytes())
                    || record.previous.as_ref().is_some_and(|previous| {
                        constant_time_eq(presented.as_bytes(), previous.as_bytes())
                    })
            })
        });
        let accepted = nonce_accepts(
            current.is_some(),
            presented_nonce.is_some(),
            nonce_matches,
            require_initial_nonce,
        );
        let existing = shard.contains_key(&key, now);
        if !existing && shard.len() >= self.shard_capacities[shard_index] {
            shard.prune_expired(now, usize::MAX);
            if shard.len() >= self.shard_capacities[shard_index] {
                return Err(DPoPError::NonceStoreUnavailable);
            }
        }

        if accepted {
            let nonce = random_nonce();
            let previous = current.as_ref().map(|record| record.current.clone());
            shard.insert(
                key,
                NonceRecord {
                    current: nonce.clone(),
                    previous,
                },
                now.saturating_add(self.ttl.as_secs()),
            );
            Ok(DPoPNonceDecision::Accepted(nonce))
        } else if let Some(record) = current {
            Ok(DPoPNonceDecision::Challenge(record.current))
        } else {
            let nonce = random_nonce();
            shard.insert(
                key,
                NonceRecord {
                    current: nonce.clone(),
                    previous: None,
                },
                now.saturating_add(self.ttl.as_secs()),
            );
            Ok(DPoPNonceDecision::Challenge(nonce))
        }
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
struct ReplayKey {
    issuer: String,
    token_identifier: String,
    thumbprint: String,
    proof_identifier: String,
}

impl ReplayKey {
    /// Constructs the complete replay-isolation key.
    fn new(issuer: &str, token_identifier: &str, thumbprint: &str, proof_identifier: &str) -> Self {
        Self {
            issuer: issuer.to_string(),
            token_identifier: token_identifier.to_string(),
            thumbprint: thumbprint.to_string(),
            proof_identifier: proof_identifier.to_string(),
        }
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
struct NonceKey {
    issuer: String,
    token_identifier: String,
    thumbprint: String,
}

impl NonceKey {
    /// Constructs the issuer, token, and proof-key nonce identity.
    fn new(issuer: &str, token_identifier: &str, thumbprint: &str) -> Self {
        Self {
            issuer: issuer.to_string(),
            token_identifier: token_identifier.to_string(),
            thumbprint: thumbprint.to_string(),
        }
    }
}

#[derive(Debug, Clone)]
struct NonceRecord {
    current: String,
    previous: Option<String>,
}

/// Maps one state key onto the fixed shard set.
fn shard_index<T: std::hash::Hash>(value: &T) -> usize {
    use std::hash::Hasher;

    let mut hasher = ahash::AHasher::default();
    value.hash(&mut hasher);
    (hasher.finish() as usize) % STATE_SHARDS
}

/// Generates a fresh 256-bit base64url nonce.
fn random_nonce() -> String {
    let mut bytes = [0_u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64url_encode(&bytes)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]
mod tests {
    use super::*;

    #[test]
    fn elapsed_entry_is_never_live_after_bounded_pruning() {
        let mut shard = ExpiringShard::default();
        for key in 0..=PRUNE_BATCH {
            shard.insert(key, key, 1);
        }

        shard.prune_expired(2, PRUNE_BATCH);

        assert_eq!(shard.len(), 1);
        assert_eq!(shard.get(&PRUNE_BATCH, 2), None);
        assert!(!shard.contains_key(&PRUNE_BATCH, 2));
    }
}
