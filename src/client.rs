//! High-Level AT Protocol OAuth 2.1 Client.
//!
//! Provides the primary [`AtprotoOAuthClient`] orchestrating user identity resolution,
//! OAuth discovery, RFC 7636 PKCE, RFC 9126 PAR, authorization URL generation,
//! RFC 9449 DPoP-bound code exchange, single-use refresh token rotation, and transparent
//! auto-nonce negotiation loops.

use std::sync::Arc;
use std::time::{Duration, SystemTime};
use url::Url;

use crate::crypto::base64url_encode;
use crate::dpop::{compute_access_token_hash, extract_dpop_nonce, DPoPKey, DPoPNonceCache};
use crate::error::{AtprotoOAuthError, DPoPError, ParError, TokenError};
use crate::identity::{IdentityResolver, IdentityResolverBuilder};
use crate::par::{build_authorization_url, execute_par_request, ParParameters};
use crate::pkce::PkcePair;
use crate::session::OAuthSession;
use crate::ssrf::{read_bounded_body, SsrfFilter, MAX_OAUTH_RESPONSE_BYTES};
use crate::store::{OAuthStateStore, OAuthStore, DEFAULT_STATE_TTL};

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Client configuration and metadata for an AT Protocol OAuth client.
#[derive(Clone, PartialEq, Eq)]
pub struct OAuthClientMetadata {
    /// Canonical OAuth client ID (usually a Client Metadata Document URL).
    pub client_id: String,
    /// Registered OAuth redirect callback URI.
    pub redirect_uri: String,
    /// Requested OAuth scopes (defaults to `"atproto"`).
    pub scope: String,
    /// Optional human-readable client display name.
    pub client_name: Option<String>,
}

impl std::fmt::Debug for OAuthClientMetadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthClientMetadata")
            .field("client_id", &self.client_id)
            .field("redirect_uri", &self.redirect_uri)
            .field("scope", &self.scope)
            .field("client_name", &self.client_name)
            .finish()
    }
}

impl OAuthClientMetadata {
    /// Creates a new `OAuthClientMetadata` with default scope `"atproto"`.
    #[must_use]
    pub fn new(client_id: impl Into<String>, redirect_uri: impl Into<String>) -> Self {
        Self {
            client_id: client_id.into(),
            redirect_uri: redirect_uri.into(),
            scope: "atproto".to_string(),
            client_name: None,
        }
    }

    /// Sets the requested OAuth scopes.
    #[must_use]
    pub fn with_scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = scope.into();
        self
    }

    /// Sets the optional client display name.
    #[must_use]
    pub fn with_client_name(mut self, name: impl Into<String>) -> Self {
        self.client_name = Some(name.into());
        self
    }
}

/// Stored authorization state entry for tracking an in-flight login transaction.
///
/// Saved into the OAuth state store prior to user agent redirection, and consumed
/// atomically upon callback receipt to guarantee single-use CSRF/replay protection.
///
/// # Memory Zeroization & Partial Moves
/// This struct implements [`Drop`] and [`ZeroizeOnDrop`] to securely zeroize sensitive
/// cryptographic credentials (`code_verifier`) from memory on destruction. As a consequence
/// of Rust's [`Drop`] safety rules (E0509), partial moves of individual fields out of
/// this struct are prohibited; callers should borrow fields or clone the structure.
#[derive(Clone)]
pub struct StoredStateEntry {
    /// The random state identifier token.
    pub state: String,
    /// Configured client ID.
    pub client_id: String,
    /// PKCE code verifier required for token code exchange.
    pub code_verifier: String,
    /// Ephemeral ECDSA P-256 keypair generated for this session.
    pub dpop_key: DPoPKey,
    /// Authoritative authorization server issuer URL.
    pub issuer: String,
    /// Expected subject DID, if resolved during login initiation.
    pub did: Option<String>,
    /// User account handle, if login started with handle.
    pub handle: Option<String>,
    /// Redirect URI used in the PAR request.
    pub redirect_uri: String,
    /// Resolved PDS endpoint URL.
    pub pds_endpoint: String,
    /// Authorization server token endpoint URL.
    pub token_endpoint: String,
    /// Requested OAuth scopes.
    pub scopes: String,
    /// Timestamp when this state entry was created.
    pub created_at: SystemTime,
    /// State validity duration in seconds (defaults to 300s).
    pub expires_in_secs: u64,
}

impl std::fmt::Debug for StoredStateEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredStateEntry")
            .field("state", &self.state)
            .field("client_id", &self.client_id)
            .field("code_verifier", &"[REDACTED]")
            .field("dpop_key", &self.dpop_key)
            .field("issuer", &self.issuer)
            .field("did", &self.did)
            .field("handle", &self.handle)
            .field("redirect_uri", &self.redirect_uri)
            .field("pds_endpoint", &self.pds_endpoint)
            .field("token_endpoint", &self.token_endpoint)
            .field("scopes", &self.scopes)
            .field("created_at", &self.created_at)
            .field("expires_in_secs", &self.expires_in_secs)
            .finish()
    }
}

impl Zeroize for StoredStateEntry {
    fn zeroize(&mut self) {
        self.code_verifier.zeroize();
    }
}

impl Drop for StoredStateEntry {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for StoredStateEntry {}

impl StoredStateEntry {
    /// Checks whether this stored state entry has expired.
    ///
    /// Fails closed: if the system clock is earlier than `created_at` (backward
    /// step / NTP correction), the entry is treated as expired rather than valid.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now();
        let max_age = Duration::from_secs(self.expires_in_secs);
        match now.duration_since(self.created_at) {
            Ok(elapsed) => elapsed > max_age,
            // Clock moved backward below `created_at`: fail closed.
            Err(_) => true,
        }
    }
}

/// The result of initiating an OAuth authorization flow.
#[derive(Debug, Clone)]
pub struct AuthorizationRequest {
    /// The complete browser redirection URL pointing to the authorization server.
    pub authorization_url: Url,
    /// The unique state token.
    pub state: String,
    /// The back-channel PAR request URI (`urn:ietf:params:oauth:request_uri:...`).
    pub request_uri: String,
    /// Lifetime of the PAR request URI in seconds.
    pub expires_in: u64,
    /// Complete stored state entry for session persistence.
    pub stored_state: StoredStateEntry,
}

/// Callback parameters extracted from the OAuth redirect URI query string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallbackParams {
    /// The authorization code issued by the authorization server.
    pub code: String,
    /// The state token returned by the authorization server.
    pub state: String,
    /// Optional RFC 9207 issuer parameter.
    pub iss: Option<String>,
}

impl CallbackParams {
    /// Creates a new `CallbackParams` with mandatory `code` and `state`.
    #[must_use]
    pub fn new(code: impl Into<String>, state: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            state: state.into(),
            iss: None,
        }
    }

    /// Sets the optional RFC 9207 `iss` issuer parameter.
    #[must_use]
    pub fn with_iss(mut self, iss: impl Into<String>) -> Self {
        self.iss = Some(iss.into());
        self
    }
}

/// Raw parsed token endpoint response representation.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct TokenResponse {
    /// Access token string.
    pub access_token: String,
    /// Token type (must be `"DPoP"`).
    pub token_type: String,
    /// Access token lifetime in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<u64>,
    /// Single-use refresh token string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// Granted OAuth scopes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Authenticated subject DID.
    pub sub: String,
}

/// Builder for constructing an [`AtprotoOAuthClient`].
#[derive(Debug, Clone)]
pub struct AtprotoOAuthClientBuilder {
    metadata: Option<OAuthClientMetadata>,
    resolver: Option<IdentityResolver>,
    nonce_cache: Option<DPoPNonceCache>,
    ssrf_filter: SsrfFilter,
    state_store: Option<Arc<OAuthStateStore>>,
    state_ttl: Duration,
}

impl Default for AtprotoOAuthClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl AtprotoOAuthClientBuilder {
    /// Creates a new builder with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self {
            metadata: None,
            resolver: None,
            nonce_cache: None,
            ssrf_filter: SsrfFilter::default(),
            state_store: None,
            state_ttl: DEFAULT_STATE_TTL,
        }
    }

    /// Sets the client metadata.
    #[must_use]
    pub fn client_metadata(mut self, metadata: OAuthClientMetadata) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Alias for [`Self::client_metadata`].
    #[must_use]
    pub fn metadata(self, metadata: OAuthClientMetadata) -> Self {
        self.client_metadata(metadata)
    }

    /// Sets the identity resolver.
    #[must_use]
    pub fn identity_resolver(mut self, resolver: IdentityResolver) -> Self {
        self.resolver = Some(resolver);
        self
    }

    /// Sets the shared DPoP nonce cache.
    #[must_use]
    pub fn nonce_cache(mut self, cache: DPoPNonceCache) -> Self {
        self.nonce_cache = Some(cache);
        self
    }

    /// Sets the SSRF filter configuration.
    #[must_use]
    pub fn ssrf_filter(mut self, filter: SsrfFilter) -> Self {
        self.ssrf_filter = filter;
        self
    }

    /// Configures whether insecure HTTP and localhost connections are permitted (for test environments).
    #[must_use]
    pub fn allow_insecure_localhost(mut self, allow: bool) -> Self {
        self.ssrf_filter.allow_insecure_localhost = allow;
        self
    }

    /// Sets the shared OAuth state store for session tracking and single-use consumption.
    #[must_use]
    pub fn state_store(mut self, store: Arc<OAuthStateStore>) -> Self {
        self.state_store = Some(store);
        self
    }

    /// Sets the TTL duration for authorization state entries.
    #[must_use]
    pub fn state_ttl(mut self, ttl: Duration) -> Self {
        self.state_ttl = ttl;
        self
    }

    /// Builds the configured [`AtprotoOAuthClient`].
    ///
    /// # Panics / Errors
    ///
    /// Returns error if client metadata is missing.
    /// Builds the configured [`AtprotoOAuthClient`].
    ///
    /// # Panics / Errors
    ///
    /// Returns [`AtprotoOAuthError`] if client metadata was not configured, or if
    /// the configured `state_ttl` is not a whole number of seconds — sub-second
    /// TTLs would be truncated by `StoredStateEntry::expires_in_secs`, making
    /// entries appear instantly expired while the store still holds them.
    pub fn build(self) -> Result<AtprotoOAuthClient, AtprotoOAuthError> {
        if self.state_ttl.subsec_nanos() != 0 {
            return Err(AtprotoOAuthError::Token(TokenError::InvalidStateTtl(
                self.state_ttl,
            )));
        }
        let metadata = self
            .metadata
            .ok_or(ParError::MissingField("client_metadata"))?;

        let resolver = self.resolver.unwrap_or_else(|| {
            IdentityResolverBuilder::new()
                .ssrf_filter(self.ssrf_filter)
                .build()
        });

        let nonce_cache = self.nonce_cache.unwrap_or_default();
        let default_store_created = self.state_store.is_none();
        let state_store = self
            .state_store
            .unwrap_or_else(|| Arc::new(OAuthStateStore::new(self.state_ttl)));

        // Review M2: the default in-memory store previously grew unboundedly —
        // abandoned login flows stayed resident forever. When the high-level
        // client created the store itself (and a tokio runtime context exists),
        // start drift-free TTL pruning tied to the client's lifetime. Explicitly
        // provided stores keep caller-owned lifecycle (they may be shared).
        if default_store_created {
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                let pruner_store = Arc::clone(&state_store);
                let prune_interval = self.state_ttl.max(Duration::from_secs(60));
                handle.spawn(async move {
                    let mut interval = tokio::time::interval(prune_interval);
                    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                    // Prune ~once per interval for the life of the client. The task
                    // is a daemon: it ends when the runtime (and thus the client)
                    // is dropped. Bounded by the admission cap in the worst case.
                    loop {
                        interval.tick().await;
                        let pruned = pruner_store.prune_expired_sync();
                        if pruned > 0 {
                            tracing::trace!("default state store pruned {pruned} expired states");
                        }
                    }
                });
            }
        }

        Ok(AtprotoOAuthClient {
            metadata,
            resolver,
            nonce_cache,
            ssrf_filter: self.ssrf_filter,
            state_store,
            state_ttl: self.state_ttl,
            refresh_single_flight: Arc::new(RefreshSingleFlight::new()),
        })
    }
}

/// High-level AT Protocol OAuth 2.1 Client.
///
/// Orchestrates the entire lifecycle: identity resolution, discovery, PAR, code exchange,
/// token rotation, and transparent auto-nonce retry loops.
/// Per-subject single-flight coordination for refresh-token exchanges
/// (review H4, mirroring `@atproto/oauth-client-node`'s per-DID `requestLock`).
///
/// A refresh token is single-use: two concurrent refreshes for the same
/// session race at the authorization server, and the loser receives
/// `invalid_grant` with no recovery. This guard serializes refreshes per
/// subject so concurrent callers *share* one refresh outcome instead of
/// competing for the grant.
#[derive(Debug, Default)]
struct RefreshSingleFlight {
    /// One mutex per in-flight subject; entries are intentionally left in the
    /// map after use (bounded by distinct subjects per client instance).
    locks: parking_lot::RwLock<std::collections::HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

impl RefreshSingleFlight {
    fn new() -> Self {
        Self::default()
    }

    /// Returns the mutex guarding refreshes for `sub`.
    fn lock_for(&self, sub: &str) -> Arc<tokio::sync::Mutex<()>> {
        // Sync RwLock read fast-path; write lock upgrade path is a plain loop
        // (no await held across lock acquisition).
        if let Some(existing) = self.locks.read().get(sub) {
            return Arc::clone(existing);
        }
        let mut guard = self.locks.write();
        if let Some(existing) = guard.get(sub) {
            return Arc::clone(existing);
        }
        let fresh = Arc::new(tokio::sync::Mutex::new(()));
        guard.insert(sub.to_string(), Arc::clone(&fresh));
        fresh
    }
}

/// High-level AT Protocol OAuth 2.1 Client.
///
/// Orchestrates the entire lifecycle: identity resolution, discovery, PAR, code exchange,
/// token rotation, and transparent auto-nonce retry loops.
#[derive(Debug, Clone)]
pub struct AtprotoOAuthClient {
    metadata: OAuthClientMetadata,
    resolver: IdentityResolver,
    nonce_cache: DPoPNonceCache,
    ssrf_filter: SsrfFilter,
    state_store: Arc<OAuthStateStore>,
    state_ttl: Duration,
    refresh_single_flight: Arc<RefreshSingleFlight>,
}

impl AtprotoOAuthClient {
    /// Creates a new `AtprotoOAuthClient` with the given client ID and redirect URI.
    #[must_use]
    pub fn new(client_id: impl Into<String>, redirect_uri: impl Into<String>) -> Self {
        let metadata = OAuthClientMetadata::new(client_id, redirect_uri);
        let ssrf_filter = SsrfFilter::default();
        let resolver = IdentityResolverBuilder::new()
            .ssrf_filter(ssrf_filter)
            .build();

        Self {
            metadata,
            resolver,
            nonce_cache: DPoPNonceCache::new(),
            ssrf_filter,
            state_store: Arc::new(OAuthStateStore::default()),
            state_ttl: DEFAULT_STATE_TTL,
            refresh_single_flight: Arc::new(RefreshSingleFlight::new()),
        }
    }

    /// Creates a builder for custom client construction.
    #[must_use]
    pub fn builder() -> AtprotoOAuthClientBuilder {
        AtprotoOAuthClientBuilder::new()
    }

    /// Returns a reference to the configured client metadata.
    #[must_use]
    pub const fn metadata(&self) -> &OAuthClientMetadata {
        &self.metadata
    }

    /// Returns a reference to the internal identity resolver.
    #[must_use]
    pub const fn resolver(&self) -> &IdentityResolver {
        &self.resolver
    }

    /// Returns a reference to the shared DPoP nonce cache.
    #[must_use]
    pub const fn nonce_cache(&self) -> &DPoPNonceCache {
        &self.nonce_cache
    }

    /// Returns a reference to the active SSRF filter.
    #[must_use]
    pub const fn ssrf_filter(&self) -> &SsrfFilter {
        &self.ssrf_filter
    }

    /// Returns a reference to the internal OAuth state store.
    #[must_use]
    pub fn state_store(&self) -> &Arc<OAuthStateStore> {
        &self.state_store
    }

    /// Returns the configured state TTL duration.
    #[must_use]
    pub const fn state_ttl(&self) -> Duration {
        self.state_ttl
    }

    /// Initiates an OAuth authorization flow for a user handle or DID and returns the [`AuthorizationRequest`].
    ///
    /// The authorization state entry is automatically registered into the client's internal
    /// state store for atomic, single-use callback verification via [`Self::handle_callback`].
    ///
    /// # Errors
    ///
    /// Returns [`AtprotoOAuthError`] if identity resolution, PAR, or cryptographic operations fail.
    pub async fn authorize(
        &self,
        handle_or_did: &str,
    ) -> Result<AuthorizationRequest, AtprotoOAuthError> {
        let (req, _) = self.initiate_login(handle_or_did).await?;
        Ok(req)
    }

    /// Initiates an OAuth login flow for a user handle or DID.
    ///
    /// # Pipeline
    /// 1. Discovers identity, PDS endpoint, and authorization server metadata.
    /// 2. Generates a fresh S256 PKCE code challenge and verifier.
    /// 3. Generates a high-entropy 256-bit random state token.
    /// 4. Generates an ephemeral session [`DPoPKey`].
    /// 5. Pushes parameters to the authorization server's PAR endpoint with DPoP proof.
    /// 6. Constructs the browser authorization redirect URL with `client_id` and `request_uri`.
    /// 7. Automatically inserts the state entry into [`Self::state_store`].
    /// 8. Returns `(AuthorizationRequest, StoredStateEntry)`.
    ///
    /// # Errors
    ///
    /// Returns [`AtprotoOAuthError`] if discovery, PAR, or cryptographic operations fail.
    pub async fn initiate_login(
        &self,
        handle_or_did: &str,
    ) -> Result<(AuthorizationRequest, StoredStateEntry), AtprotoOAuthError> {
        self.initiate_login_with_scope(handle_or_did, &self.metadata.scope)
            .await
    }

    /// Initiates an OAuth login flow with custom scope overrides.
    pub async fn initiate_login_with_scope(
        &self,
        handle_or_did: &str,
        scope: &str,
    ) -> Result<(AuthorizationRequest, StoredStateEntry), AtprotoOAuthError> {
        let endpoints = self
            .resolver
            .discover_oauth_endpoints(handle_or_did)
            .await?;

        let pkce = PkcePair::generate();
        let mut state_bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut state_bytes);
        let state = base64url_encode(&state_bytes);

        let dpop_key = DPoPKey::generate();

        let mut params = ParParameters::new(
            &self.metadata.client_id,
            &self.metadata.redirect_uri,
            scope,
            &state,
            &pkce.challenge,
        );

        if let Some(ref handle) = endpoints.handle {
            params = params.with_login_hint(handle);
        } else {
            params = params.with_login_hint(&endpoints.did);
        }

        let par_res = execute_par_request(
            &self.ssrf_filter,
            &endpoints.par_endpoint,
            &params,
            &dpop_key,
            &self.nonce_cache,
        )
        .await?;

        let auth_url = build_authorization_url(
            &endpoints.authorization_endpoint,
            &self.metadata.client_id,
            &par_res.request_uri,
        )?;

        let stored_state = StoredStateEntry {
            state: state.clone(),
            client_id: self.metadata.client_id.clone(),
            code_verifier: pkce.verifier,
            dpop_key,
            issuer: endpoints.auth_server_issuer.clone(),
            did: Some(endpoints.did),
            handle: endpoints.handle,
            redirect_uri: self.metadata.redirect_uri.clone(),
            pds_endpoint: endpoints.pds_endpoint,
            token_endpoint: endpoints.token_endpoint,
            scopes: scope.to_string(),
            created_at: SystemTime::now(),
            expires_in_secs: self.state_ttl.as_secs(),
        };

        self.state_store
            .insert_state(state.clone(), stored_state.clone(), self.state_ttl)
            .await?;

        let auth_req = AuthorizationRequest {
            authorization_url: auth_url,
            state: state.clone(),
            request_uri: par_res.request_uri,
            expires_in: par_res.expires_in,
            stored_state: stored_state.clone(),
        };

        Ok((auth_req, stored_state))
    }

    /// Exchanges an authorization code for an authenticated [`OAuthSession`].
    ///
    /// # Checks Performed
    /// 1. Dispatches POST request to `state_entry.token_endpoint` with `grant_type=authorization_code`.
    /// 2. Signs DPoP proof with `state_entry.dpop_key` for `POST <token_endpoint>`.
    /// 3. Transparently handles `use_dpop_nonce` error challenge with automated single-retry loop.
    /// 4. Validates `token_type` is case-insensitively `"DPoP"`.
    /// 5. Validates `sub` matches `state_entry.did` if set.
    /// 6. Validates `scope` includes mandatory `"atproto"` scope.
    ///
    /// # Errors
    ///
    /// Returns [`AtprotoOAuthError`] if token endpoint exchange or validation fails.
    pub async fn exchange_code(
        &self,
        code: &str,
        state_entry: &StoredStateEntry,
    ) -> Result<OAuthSession, AtprotoOAuthError> {
        let form_pairs: Vec<(&str, &str)> = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", state_entry.redirect_uri.as_str()),
            ("client_id", state_entry.client_id.as_str()),
            ("code_verifier", state_entry.code_verifier.as_str()),
        ];

        let form_body =
            serde_urlencoded::to_string(form_pairs).map_err(|e| TokenError::Http(e.to_string()))?;

        let resp_json: TokenResponse = self
            .send_dpop_token_request(
                &state_entry.token_endpoint,
                &state_entry.dpop_key,
                form_body.into_bytes(),
            )
            .await?;

        if !resp_json.token_type.eq_ignore_ascii_case("DPoP") {
            return Err(TokenError::InvalidTokenType(resp_json.token_type).into());
        }

        if resp_json.sub.trim().is_empty() {
            return Err(TokenError::MissingDid.into());
        }
        if let Some(ref expected_did) = state_entry.did {
            if &resp_json.sub != expected_did {
                return Err(TokenError::SubMismatch {
                    expected: expected_did.clone(),
                    actual: resp_json.sub.clone(),
                }
                .into());
            }
        }

        let scope_str = resp_json.scope.as_deref().ok_or(TokenError::MissingScope)?;

        let has_atproto = scope_str.split_whitespace().any(|s| s == "atproto");
        if !has_atproto {
            return Err(TokenError::MissingAtprotoScope(scope_str.to_string()).into());
        }

        OAuthSession::new(
            resp_json.sub,
            resp_json.access_token,
            resp_json.refresh_token,
            resp_json.token_type,
            resp_json.scope,
            resp_json.expires_in,
            state_entry.dpop_key.clone(),
            Some(state_entry.pds_endpoint.clone()),
            Some(state_entry.issuer.clone()),
            Some(state_entry.token_endpoint.clone()),
        )
    }

    /// Handles an OAuth redirect callback by atomically consuming the stored state from the
    /// internal [`OAuthStateStore`], verifying expiration and RFC 9207 `iss`, and exchanging the code.
    ///
    /// # Single-Use Guarantee
    /// The state token is atomically consumed from storage on first attempt. Replaying the callback
    /// or presenting an expired state will immediately return an error.
    ///
    /// # Errors
    /// - Returns [`TokenError::InvalidState`] if the state token is not found, has expired, or was already consumed.
    /// - Returns [`TokenError::StateExpired`] if the stored state entry has expired.
    /// - Returns [`TokenError::MissingCallbackIssuer`] if callback `iss` is missing.
    /// - Returns [`TokenError::IssuerMismatch`] if callback `iss` does not match the stored issuer.
    pub async fn handle_callback(
        &self,
        callback_params: &CallbackParams,
    ) -> Result<OAuthSession, AtprotoOAuthError> {
        let state_entry = self
            .state_store
            .take_state(&callback_params.state)
            .await?
            .ok_or_else(|| {
                TokenError::InvalidState(format!(
                    "State token '{}' not found, expired, or already consumed",
                    callback_params.state
                ))
            })?;

        self.handle_callback_with_entry(callback_params, &state_entry)
            .await
    }

    /// Handles an OAuth redirect callback with an explicitly provided [`StoredStateEntry`],
    /// enforcing expiration and RFC 9207 `iss` verification before code exchange.
    ///
    /// # Errors
    /// - Returns [`TokenError::InvalidState`] if `callback_params.state` does not match `state_entry.state`.
    /// - Returns [`TokenError::StateExpired`] if `state_entry` has expired.
    /// - Returns [`TokenError::MissingCallbackIssuer`] if callback `iss` is missing.
    /// - Returns [`TokenError::IssuerMismatch`] if callback `iss` does not match `state_entry.issuer`.
    pub async fn handle_callback_with_entry(
        &self,
        callback_params: &CallbackParams,
        state_entry: &StoredStateEntry,
    ) -> Result<OAuthSession, AtprotoOAuthError> {
        if callback_params.state != state_entry.state {
            return Err(TokenError::InvalidState(format!(
                "Callback state '{}' does not match expected state '{}'",
                callback_params.state, state_entry.state
            ))
            .into());
        }

        if state_entry.is_expired() {
            return Err(TokenError::StateExpired.into());
        }

        let callback_iss = callback_params
            .iss
            .as_deref()
            .ok_or(TokenError::MissingCallbackIssuer)?;

        let norm_callback = callback_iss.trim().trim_end_matches('/');
        let norm_expected = state_entry.issuer.trim().trim_end_matches('/');
        if norm_callback != norm_expected {
            return Err(TokenError::IssuerMismatch {
                expected: state_entry.issuer.clone(),
                actual: callback_iss.to_string(),
            }
            .into());
        }

        self.exchange_code(&callback_params.code, state_entry).await
    }

    /// Refreshes an authenticated [`OAuthSession`] using its single-use refresh token.
    ///
    /// Atomically updates the session's access token, rotated refresh token, and expiration timestamp.
    ///
    /// # Errors
    /// - Returns [`TokenError::MissingRefreshToken`] if the session has no refresh token.
    /// - Returns [`TokenError::MissingField`] if the session has no token endpoint recorded.
    /// - Returns [`AtprotoOAuthError`] if token refresh or validation fails.
    pub async fn refresh_session(
        &self,
        session: &mut OAuthSession,
    ) -> Result<(), AtprotoOAuthError> {
        // Per-subject single-flight: serialize refreshes for the same DID so
        // concurrent callers share one grant instead of racing the single-use
        // refresh token (review H4; mirrors @atproto/oauth-client-node).
        let refresh_lock = self.refresh_single_flight.lock_for(session.sub());
        let _refresh_guard = refresh_lock.lock().await;

        let refresh_token = session
            .refresh_token()
            .ok_or(TokenError::MissingRefreshToken)?;

        let token_endpoint = session
            .token_endpoint()
            .ok_or(TokenError::MissingField("token_endpoint"))?
            .to_string();

        let form_pairs: Vec<(&str, &str)> = vec![
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", self.metadata.client_id.as_str()),
        ];

        let form_body =
            serde_urlencoded::to_string(form_pairs).map_err(|e| TokenError::Http(e.to_string()))?;

        let resp_json: TokenResponse = self
            .send_dpop_token_request(&token_endpoint, session.dpop_key(), form_body.into_bytes())
            .await?;

        if !resp_json.token_type.eq_ignore_ascii_case("DPoP") {
            return Err(TokenError::InvalidTokenType(resp_json.token_type).into());
        }

        // Identity invariant (review H4): the refresh response's `sub` MUST be
        // present and match the session's subject. An empty `sub` is a
        // protocol violation — accepting it would let a token without proven
        // identity rotate the session.
        if resp_json.sub.is_empty() {
            return Err(TokenError::RequestFailed {
                status: 200,
                error: "invalid_request".to_string(),
                description: Some(
                    "Refresh response is missing mandatory `sub` claim (review H4: fail-closed)"
                        .to_string(),
                ),
            }
            .into());
        }
        if resp_json.sub != session.sub() {
            return Err(TokenError::SubMismatch {
                expected: session.sub().to_string(),
                actual: resp_json.sub,
            }
            .into());
        }

        // Scope revalidation (RFC 6749 § 6 + review H4):
        // - the refreshed scope MUST NOT exceed the original grant (expansion is
        //   rejected — privileges cannot silently accumulate);
        // - ATProto profiles mandate that "atproto" remains present;
        // - the returned scope is persisted atomically with the tokens so
        //   authorization decisions cannot use stale grants.
        let granted_scope = session.scope().unwrap_or("").to_string();
        if let Some(ref new_scope) = resp_json.scope {
            if !new_scope.split_whitespace().any(|s| s == "atproto") {
                return Err(TokenError::MissingAtprotoScope(new_scope.clone()).into());
            }
            if !granted_scope.is_empty() {
                // Expansion check: every newly-requested scope must be in the
                // original grant (order-insensitive).
                let granted: std::collections::HashSet<&str> =
                    granted_scope.split_whitespace().collect();
                let expanded: Vec<&str> = new_scope
                    .split_whitespace()
                    .filter(|s| !granted.contains(*s))
                    .collect();
                if !expanded.is_empty() {
                    return Err(TokenError::ScopeExpansion {
                        granted: granted_scope,
                        requested: new_scope.clone(),
                    }
                    .into());
                }
            }
        }

        session.rotate_tokens_with_scope(
            resp_json.access_token,
            resp_json.refresh_token,
            resp_json.expires_in,
            resp_json.scope,
        );

        Ok(())
    }

    /// Refreshes a session and returns a new updated [`OAuthSession`] instance.
    pub async fn refresh_token(
        &self,
        session: &OAuthSession,
    ) -> Result<OAuthSession, AtprotoOAuthError> {
        let mut cloned = session.clone();
        self.refresh_session(&mut cloned).await?;
        Ok(cloned)
    }

    /// Internal helper for sending token endpoint requests with DPoP and transparent auto-nonce retry.
    async fn send_dpop_token_request(
        &self,
        token_endpoint: &str,
        dpop_key: &DPoPKey,
        body_bytes: Vec<u8>,
    ) -> Result<TokenResponse, AtprotoOAuthError> {
        send_dpop_token_request_inner(
            &self.ssrf_filter,
            &self.nonce_cache,
            token_endpoint,
            dpop_key,
            body_bytes,
        )
        .await
    }

    /// Executes an arbitrary HTTP request authenticated with DPoP and automatic nonce retry handling.
    ///
    /// Used for calling protected XRPC endpoints on the user's Personal Data Server (PDS).
    pub async fn send_dpop_request(
        &self,
        dpop_key: &DPoPKey,
        method: reqwest::Method,
        url_str: &str,
        access_token: Option<&str>,
        body_bytes: Option<Vec<u8>>,
        content_type: Option<&str>,
    ) -> Result<reqwest::Response, AtprotoOAuthError> {
        let parsed_url = Url::parse(url_str)
            .map_err(|e| TokenError::Http(format!("Invalid URL '{url_str}': {e}")))?;

        let (client, _pinned_addr, host_header) = self
            .ssrf_filter
            .build_pinned_client(&parsed_url)
            .await
            .map_err(TokenError::from)?;

        let server_origin = parsed_url.origin().ascii_serialization();

        let ath = access_token.map(compute_access_token_hash);

        let initial_nonce = self.nonce_cache.get_nonce(&server_origin);
        let proof = dpop_key.create_proof(
            method.as_str(),
            url_str,
            initial_nonce.as_deref(),
            ath.as_deref(),
        )?;

        let mut req = client
            .request(method.clone(), url_str)
            .header(reqwest::header::HOST, host_header.clone())
            .header("dpop", proof);

        if let Some(token) = access_token {
            req = req.header("authorization", format!("DPoP {token}"));
        }
        if let Some(ct) = content_type {
            req = req.header("content-type", ct);
        }
        if let Some(ref bytes) = body_bytes {
            req = req.body(bytes.clone());
        }

        let resp = req
            .send()
            .await
            .map_err(|e| TokenError::Http(e.to_string()))?;

        if let Some(new_nonce) = extract_dpop_nonce(
            resp.headers()
                .get("dpop-nonce")
                .and_then(|h| h.to_str().ok()),
        ) {
            self.nonce_cache.set_nonce(&server_origin, new_nonce);
        }

        let status = resp.status();
        if status == reqwest::StatusCode::BAD_REQUEST || status == reqwest::StatusCode::UNAUTHORIZED
        {
            // Retry ONLY on an explicit `use_dpop_nonce` challenge per RFC 9449 § 8.4.
            // A Resource Server signals the challenge via
            // `WWW-Authenticate: DPoP error="use_dpop_nonce"`, with the JSON error body
            // accepted as a secondary signal (mirroring the reference client's
            // dual-check). Retrying any 400/401 that merely carries a `DPoP-Nonce`
            // header (conforming RS responses always carry one — review H3) would
            // replay non-idempotent request bodies on unrelated errors like
            // `invalid_token`.
            //
            // Classification strategy: the WWW-Authenticate check is non-destructive.
            // Only when it does not match, the (bounded) body is buffered to check the
            // JSON error field; in the non-challenge case the response is reconstructed
            // from the buffer so the caller still receives the identical status,
            // headers, and body.
            // Capture headers before any body read (the read consumes `resp`).
            // Capture headers before any body read (the read consumes `resp`).
            let resp_headers = resp.headers().clone();
            if !is_rs_dpop_nonce_challenge(&resp_headers) {
                // WWW-Authenticate did not signal a challenge; check the JSON error
                // body (bounded read — the read consumes the response, so the
                // non-challenge path reconstructs it from the buffered bytes).
                let bytes = read_bounded_body(resp, MAX_OAUTH_RESPONSE_BYTES)
                    .await
                    .map_err(|e| TokenError::Http(e.to_string()))?;
                let body_is_challenge =
                    is_use_dpop_nonce_error(serde_json::from_slice(&bytes).ok().as_ref());
                if !body_is_challenge {
                    // Unrelated 400/401 (e.g. `invalid_token`): NO retry — return the
                    // original response rebuilt from the buffered body (identical
                    // status, headers, body) so the caller can handle the error.
                    // (No DPoP-Nonce enforcement here: error responses are not the
                    // success-path profile target; the caller inspects the failure.)
                    let mut builder = http::Response::builder().status(status);
                    for (name, value) in resp_headers.iter() {
                        builder = builder.header(name.clone(), value.clone());
                    }
                    let rebuilt = builder.body(bytes).map_err(|e| {
                        TokenError::Http(format!("Failed to rebuild response: {e}"))
                    })?;
                    return Ok(reqwest::Response::from(rebuilt));
                }
                // Body confirmed the challenge; fall through to the retry block.
            }

            // Reaching here means either WWW-Authenticate or the buffered JSON body
            // confirmed the `use_dpop_nonce` challenge; perform the single retry.
            {
                let fresh_nonce = self.nonce_cache.get_nonce(&server_origin).ok_or_else(|| {
                    TokenError::RequestFailed {
                        status: status.as_u16(),
                        error: "use_dpop_nonce".to_string(),
                        description: Some("Missing DPoP-Nonce header".to_string()),
                    }
                })?;

                let retry_proof = dpop_key.create_proof(
                    method.as_str(),
                    url_str,
                    Some(&fresh_nonce),
                    ath.as_deref(),
                )?;

                let (retry_client, _retry_pinned_addr, retry_host_header) = self
                    .ssrf_filter
                    .build_pinned_client(&parsed_url)
                    .await
                    .map_err(TokenError::from)?;

                let mut retry_req = retry_client
                    .request(method, url_str)
                    .header(reqwest::header::HOST, retry_host_header)
                    .header("dpop", retry_proof);

                if let Some(token) = access_token {
                    retry_req = retry_req.header("authorization", format!("DPoP {token}"));
                }
                if let Some(ct) = content_type {
                    retry_req = retry_req.header("content-type", ct);
                }
                if let Some(bytes) = body_bytes {
                    retry_req = retry_req.body(bytes);
                }

                let retry_resp = retry_req
                    .send()
                    .await
                    .map_err(|e| TokenError::Http(e.to_string()))?;

                if let Some(new_nonce) = extract_dpop_nonce(
                    retry_resp
                        .headers()
                        .get("dpop-nonce")
                        .and_then(|h| h.to_str().ok()),
                ) {
                    self.nonce_cache.set_nonce(&server_origin, new_nonce);
                }

                let retry_status = retry_resp.status();
                if retry_status == reqwest::StatusCode::BAD_REQUEST
                    || retry_status == reqwest::StatusCode::UNAUTHORIZED
                {
                    let retry_headers = retry_resp.headers().clone();
                    if is_rs_dpop_nonce_challenge(&retry_headers) {
                        return Err(DPoPError::NonceRetryLimitExceeded.into());
                    }
                    // Mirror the initial-path classification: a challenge may also be
                    // signalled by the JSON error body alone. If the body does NOT
                    // signal a challenge, rebuild and return the response so the
                    // caller sees the original error intact.
                    let bytes = read_bounded_body(retry_resp, MAX_OAUTH_RESPONSE_BYTES)
                        .await
                        .map_err(|e| TokenError::Http(e.to_string()))?;
                    if is_use_dpop_nonce_error(serde_json::from_slice(&bytes).ok().as_ref()) {
                        return Err(DPoPError::NonceRetryLimitExceeded.into());
                    }
                    let mut builder = http::Response::builder().status(retry_status);
                    for (name, value) in retry_headers.iter() {
                        builder = builder.header(name.clone(), value.clone());
                    }
                    let rebuilt = builder.body(bytes).map_err(|e| {
                        TokenError::Http(format!("Failed to rebuild response: {e}"))
                    })?;
                    return Ok(reqwest::Response::from(rebuilt));
                }

                if retry_status.is_success() {
                    // ATProto profile (review H2): enforce DPoP-Nonce on the retry
                    // response too.
                    crate::dpop::require_dpop_nonce(retry_resp.headers())
                        .map_err(AtprotoOAuthError::from)?;
                }

                return Ok(retry_resp);
            }
        }

        // ATProto profile (review H2): an RS response to a DPoP-authenticated
        // request MUST carry a DPoP-Nonce; refuse to continue with a server
        // that omits it.
        crate::dpop::require_dpop_nonce(resp.headers()).map_err(AtprotoOAuthError::from)?;
        Ok(resp)
    }

    /// Validates an XRPC NSID against the ATProto NSID grammar
    /// (`<https://atproto.com/specs/nsid>`, mirroring the reference validator in
    /// `bluesky-social/atproto/packages/syntax`).
    ///
    /// Grammar: `nsid = authority delim name` where every segment is
    /// `alpha *( alpha / number / "-" )` (<=63 chars, no leading/trailing hyphen),
    /// the total length is <=317, the first authority segment must start with a
    /// letter, and the final name segment is `alpha *( alpha / number )` — letters
    /// and digits only, no hyphens, no leading digit.
    fn validate_xrpc_nsid(nsid: &str) -> Result<(), TokenError> {
        // Delegates the grammar decision to the provable kernel; this wrapper
        // only maps the boolean onto the typed error. Logic previously inline
        // here moved verbatim to `kernels::nsid_bytes::is_valid_nsid`.
        if crate::kernels::nsid_bytes::is_valid_nsid(nsid) {
            Ok(())
        } else {
            Err(TokenError::InvalidNsid(nsid.to_string()))
        }
    }

    /// Executes an authenticated XRPC request against the session's PDS endpoint with DPoP signing and auto-nonce retry.
    ///
    /// # Arguments
    ///
    /// - `session`: The authenticated [`OAuthSession`].
    /// - `nsid`: The Lexicon method identifier (e.g. `"com.atproto.repo.describeRepo"`).
    /// - `query_params`: Optional URL query parameter key-value pairs.
    ///
    /// # Errors
    ///
    /// Returns [`AtprotoOAuthError`] if the PDS endpoint is missing or invalid, the NSID
    /// fails Lexicon NSID grammar validation, or the request fails.
    pub async fn send_xrpc_request(
        &self,
        session: &OAuthSession,
        nsid: &str,
        query_params: &[(&str, &str)],
    ) -> Result<reqwest::Response, AtprotoOAuthError> {
        Self::validate_xrpc_nsid(nsid).map_err(AtprotoOAuthError::Token)?;
        let pds_endpoint = session
            .pds_endpoint()
            .ok_or(TokenError::MissingField("pds_endpoint"))?;
        let mut url = Url::parse(pds_endpoint)
            .map_err(|e| TokenError::Http(format!("Invalid PDS endpoint: {e}")))?;
        let trimmed_nsid = nsid.trim_start_matches('/');
        // Preserve any base path on the PDS endpoint (e.g. `https://host/pds`) so
        // sub-path deployments resolve to `/pds/xrpc/...` and the DPoP `htu` matches
        // the actual request target.
        let base_path = url.path().trim_end_matches('/');
        url.set_path(&format!("{}/xrpc/{}", base_path, trimmed_nsid));
        if !query_params.is_empty() {
            url.query_pairs_mut()
                .extend_pairs(query_params.iter().copied());
        }
        self.send_dpop_request(
            session.dpop_key(),
            reqwest::Method::GET,
            url.as_str(),
            Some(session.access_token()),
            None,
            None,
        )
        .await
    }
}

/// Extracts the OAuth `error` and `error_description` fields from a JSON body.
fn parse_oauth_error_fields(json: Option<&serde_json::Value>) -> (String, Option<String>) {
    let error_code = json
        .and_then(|j| j.get("error"))
        .and_then(|e| e.as_str())
        .unwrap_or("token_request_failed")
        .to_string();
    let error_desc = json
        .and_then(|j| j.get("error_description"))
        .and_then(|d| d.as_str())
        .map(ToString::to_string);
    (error_code, error_desc)
}

/// Checks whether a parsed JSON body is a `use_dpop_nonce` DPoP challenge.
fn is_use_dpop_nonce_error(json: Option<&serde_json::Value>) -> bool {
    json.and_then(|j| j.get("error")).and_then(|e| e.as_str()) == Some("use_dpop_nonce")
}

/// Checks whether a Resource Server response signals a `use_dpop_nonce` DPoP
/// nonce challenge via `WWW-Authenticate: DPoP error="use_dpop_nonce"`
/// (RFC 9449 § 8.4; RFC 6750 § 3 challenge parameter syntax).
///
/// Returns `true` only when the `WWW-Authenticate` header's scheme is `DPoP`
/// (case-insensitive) AND carries `error="use_dpop_nonce"`. A bare `DPoP-Nonce`
/// response header is NOT sufficient — conforming RS responses carry it on
/// every DPoP-authenticated response (review H3).
fn is_rs_dpop_nonce_challenge(headers: &reqwest::header::HeaderMap) -> bool {
    headers
        .get_all(reqwest::header::WWW_AUTHENTICATE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|challenge| {
            let challenge = challenge.trim();
            // Scheme must be DPoP (case-insensitive), followed by params.
            let Some(space) = challenge.find(' ') else {
                return false;
            };
            let (scheme, rest) = challenge.split_at(space);
            if !scheme.eq_ignore_ascii_case("DPoP") {
                return false;
            }
            let rest = rest.trim_start();
            rest.split(',').any(|param| {
                let param = param.trim();
                let Some((key, value)) = param.split_once('=') else {
                    return false;
                };
                let key = key.trim();
                if !key.eq_ignore_ascii_case("error") {
                    return false;
                }
                let value = value.trim().trim_matches('"');
                value.eq_ignore_ascii_case("use_dpop_nonce")
            })
        })
}

/// Reads a bounded body and parses it as lenient JSON, returning `None` on non-JSON bodies.
async fn read_bounded_json(
    resp: reqwest::Response,
) -> Result<Option<serde_json::Value>, TokenError> {
    let bytes = read_bounded_body(resp, MAX_OAUTH_RESPONSE_BYTES)
        .await
        .map_err(|e| TokenError::Http(e.to_string()))?;
    Ok(serde_json::from_slice(&bytes).ok())
}

/// Free-function core for DPoP-bound token endpoint requests with transparent
/// auto-nonce retry, shared by code exchange and session refresh.
///
/// Redirects are rejected per RFC 6749; a single retry is performed when the
/// server responds with a `use_dpop_nonce` challenge.
async fn send_dpop_token_request_inner(
    ssrf_filter: &SsrfFilter,
    nonce_cache: &DPoPNonceCache,
    token_endpoint: &str,
    dpop_key: &DPoPKey,
    body_bytes: Vec<u8>,
) -> Result<TokenResponse, AtprotoOAuthError> {
    let parsed_url = Url::parse(token_endpoint).map_err(|e| {
        TokenError::Http(format!(
            "Invalid token endpoint URL '{token_endpoint}': {e}"
        ))
    })?;

    let (client, _pinned_addr, host_header) = ssrf_filter
        .build_pinned_client(&parsed_url)
        .await
        .map_err(TokenError::from)?;

    let server_origin = parsed_url.origin().ascii_serialization();

    let initial_nonce = nonce_cache.get_nonce(&server_origin);
    let proof = dpop_key.create_proof("POST", token_endpoint, initial_nonce.as_deref(), None)?;

    let resp = client
        .post(token_endpoint)
        .header(reqwest::header::HOST, host_header.clone())
        .header("content-type", "application/x-www-form-urlencoded")
        .header("accept", "application/json")
        .header("dpop", proof)
        .body(body_bytes.clone())
        .send()
        .await
        .map_err(|e| TokenError::Http(e.to_string()))?;

    if let Some(new_nonce) = extract_dpop_nonce(
        resp.headers()
            .get("dpop-nonce")
            .and_then(|h| h.to_str().ok()),
    ) {
        nonce_cache.set_nonce(&server_origin, new_nonce);
    }

    let status = resp.status();

    if status.is_redirection() {
        return Err(TokenError::RequestFailed {
            status: status.as_u16(),
            error: "invalid_request".to_string(),
            description: Some("Redirects are not permitted for token endpoints".to_string()),
        }
        .into());
    }

    if status == reqwest::StatusCode::BAD_REQUEST || status == reqwest::StatusCode::UNAUTHORIZED {
        let json_err = read_bounded_json(resp).await?;
        if is_use_dpop_nonce_error(json_err.as_ref()) {
            let fresh_nonce =
                nonce_cache
                    .get_nonce(&server_origin)
                    .ok_or_else(|| TokenError::RequestFailed {
                        status: status.as_u16(),
                        error: "use_dpop_nonce".to_string(),
                        description: Some(
                            "Missing DPoP-Nonce header in challenge response".to_string(),
                        ),
                    })?;

            let retry_proof =
                dpop_key.create_proof("POST", token_endpoint, Some(&fresh_nonce), None)?;

            let (retry_client, _retry_pinned_addr, retry_host_header) = ssrf_filter
                .build_pinned_client(&parsed_url)
                .await
                .map_err(TokenError::from)?;

            let retry_resp = retry_client
                .post(token_endpoint)
                .header(reqwest::header::HOST, retry_host_header)
                .header("content-type", "application/x-www-form-urlencoded")
                .header("accept", "application/json")
                .header("dpop", retry_proof)
                .body(body_bytes)
                .send()
                .await
                .map_err(|e| TokenError::Http(e.to_string()))?;

            if let Some(new_nonce) = extract_dpop_nonce(
                retry_resp
                    .headers()
                    .get("dpop-nonce")
                    .and_then(|h| h.to_str().ok()),
            ) {
                nonce_cache.set_nonce(&server_origin, new_nonce);
            }

            let retry_status = retry_resp.status();

            if retry_status.is_redirection() {
                return Err(TokenError::RequestFailed {
                    status: retry_status.as_u16(),
                    error: "invalid_request".to_string(),
                    description: Some(
                        "Redirects are not permitted for token endpoints".to_string(),
                    ),
                }
                .into());
            }

            if retry_status.is_success() {
                // Same profile enforcement on the retry response (review H2).
                crate::dpop::require_dpop_nonce(retry_resp.headers()).map_err(TokenError::from)?;
                let bytes = read_bounded_body(retry_resp, MAX_OAUTH_RESPONSE_BYTES)
                    .await
                    .map_err(|e| TokenError::Http(e.to_string()))?;
                let res: TokenResponse =
                    serde_json::from_slice(&bytes).map_err(|e| TokenError::Json(e.to_string()))?;
                return Ok(res);
            }

            let err_json = read_bounded_json(retry_resp).await?;
            if is_use_dpop_nonce_error(err_json.as_ref()) {
                return Err(DPoPError::NonceRetryLimitExceeded.into());
            }

            let (error_code, error_desc) = parse_oauth_error_fields(err_json.as_ref());
            return Err(TokenError::RequestFailed {
                status: retry_status.as_u16(),
                error: error_code,
                description: error_desc,
            }
            .into());
        }

        let (error_code, error_desc) = parse_oauth_error_fields(json_err.as_ref());
        return Err(TokenError::RequestFailed {
            status: status.as_u16(),
            error: error_code,
            description: error_desc,
        }
        .into());
    }

    if !status.is_success() {
        let err_json = read_bounded_json(resp).await?;
        let (error_code, error_desc) = parse_oauth_error_fields(err_json.as_ref());
        return Err(TokenError::RequestFailed {
            status: status.as_u16(),
            error: error_code,
            description: error_desc,
        }
        .into());
    }

    // ATProto profile (review H2): a token response to a DPoP-authenticated request
    // MUST carry a DPoP-Nonce; refuse to continue with a server that omits it.
    crate::dpop::require_dpop_nonce(resp.headers()).map_err(TokenError::from)?;

    let bytes = read_bounded_body(resp, MAX_OAUTH_RESPONSE_BYTES)
        .await
        .map_err(|e| TokenError::Http(e.to_string()))?;
    let res: TokenResponse =
        serde_json::from_slice(&bytes).map_err(|e| TokenError::Json(e.to_string()))?;
    Ok(res)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderMap, HeaderValue};

    #[test]
    fn test_rs_dpop_nonce_challenge_parsing() {
        // Exact RFC 9449 § 8.4 challenge.
        let mut h = HeaderMap::new();
        h.insert(
            reqwest::header::WWW_AUTHENTICATE,
            HeaderValue::from_static("DPoP algs=\"ES256\", error=\"use_dpop_nonce\""),
        );
        assert!(is_rs_dpop_nonce_challenge(&h));

        // Case-insensitive scheme + value.
        let mut h2 = HeaderMap::new();
        h2.insert(
            reqwest::header::WWW_AUTHENTICATE,
            HeaderValue::from_static("dpop error=\"USE_DPOP_NONCE\""),
        );
        assert!(is_rs_dpop_nonce_challenge(&h2));

        // Multiple challenge headers, one matching.
        let mut h3 = HeaderMap::new();
        h3.insert(
            reqwest::header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Bearer realm=\"x\""),
        );
        h3.append(
            reqwest::header::WWW_AUTHENTICATE,
            HeaderValue::from_static("DPoP error=\"use_dpop_nonce\""),
        );
        assert!(is_rs_dpop_nonce_challenge(&h3));

        // Wrong scheme.
        let mut h4 = HeaderMap::new();
        h4.insert(
            reqwest::header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Bearer error=\"use_dpop_nonce\""),
        );
        assert!(!is_rs_dpop_nonce_challenge(&h4));

        // DPoP scheme but different error (the H3 case: must NOT retry).
        let mut h5 = HeaderMap::new();
        h5.insert(
            reqwest::header::WWW_AUTHENTICATE,
            HeaderValue::from_static("DPoP error=\"invalid_token\""),
        );
        assert!(!is_rs_dpop_nonce_challenge(&h5));

        // DPoP scheme with no error parameter (plain 401 challenge).
        let mut h6 = HeaderMap::new();
        h6.insert(
            reqwest::header::WWW_AUTHENTICATE,
            HeaderValue::from_static("DPoP algs=\"ES256\""),
        );
        assert!(!is_rs_dpop_nonce_challenge(&h6));

        // No WWW-Authenticate at all.
        assert!(!is_rs_dpop_nonce_challenge(&HeaderMap::new()));
    }

    #[test]
    fn test_client_builder_and_metadata() {
        let client = AtprotoOAuthClient::builder()
            .client_metadata(
                OAuthClientMetadata::new(
                    "https://app.example.com/client.json",
                    "https://app.example.com/callback",
                )
                .with_scope("atproto transition:generic")
                .with_client_name("Example App"),
            )
            .allow_insecure_localhost(true)
            .build()
            .unwrap();

        assert_eq!(
            client.metadata().client_id,
            "https://app.example.com/client.json"
        );
        assert_eq!(
            client.metadata().redirect_uri,
            "https://app.example.com/callback"
        );
        assert_eq!(client.metadata().scope, "atproto transition:generic");
        assert_eq!(
            client.metadata().client_name.as_deref(),
            Some("Example App")
        );
    }

    #[test]
    fn test_stored_state_expiration() {
        let entry = StoredStateEntry {
            state: "state123".to_string(),
            client_id: "client123".to_string(),
            code_verifier: "verifier123".to_string(),
            dpop_key: DPoPKey::generate(),
            issuer: "https://auth.example.com".to_string(),
            did: Some("did:plc:alice".to_string()),
            handle: Some("alice.bsky.social".to_string()),
            redirect_uri: "https://app.example.com/callback".to_string(),
            pds_endpoint: "https://pds.example.com".to_string(),
            token_endpoint: "https://auth.example.com/oauth/token".to_string(),
            scopes: "atproto".to_string(),
            created_at: SystemTime::now() - Duration::from_secs(400),
            expires_in_secs: 300,
        };

        assert!(entry.is_expired());
    }

    #[tokio::test]
    async fn test_handle_callback_with_expired_entry_rejected() {
        let client = AtprotoOAuthClient::builder()
            .client_metadata(OAuthClientMetadata::new(
                "https://app.example.com/client.json",
                "https://app.example.com/callback",
            ))
            .allow_insecure_localhost(true)
            .build()
            .unwrap();

        let expired_entry = StoredStateEntry {
            state: "state_exp".to_string(),
            client_id: "https://app.example.com/client.json".to_string(),
            code_verifier: "verifier123".to_string(),
            dpop_key: DPoPKey::generate(),
            issuer: "https://auth.example.com".to_string(),
            did: Some("did:plc:alice".to_string()),
            handle: Some("alice.bsky.social".to_string()),
            redirect_uri: "https://app.example.com/callback".to_string(),
            pds_endpoint: "https://pds.example.com".to_string(),
            token_endpoint: "https://auth.example.com/oauth/token".to_string(),
            scopes: "atproto".to_string(),
            created_at: SystemTime::now() - Duration::from_secs(400),
            expires_in_secs: 300,
        };

        let cb = CallbackParams::new("code123", "state_exp").with_iss("https://auth.example.com");
        let err = client.handle_callback_with_entry(&cb, &expired_entry).await;
        assert!(matches!(
            err,
            Err(AtprotoOAuthError::Token(TokenError::StateExpired))
        ));
    }

    #[test]
    fn test_callback_params() {
        let cb = CallbackParams::new("code123", "state123").with_iss("https://auth.example.com");
        assert_eq!(cb.code, "code123");
        assert_eq!(cb.state, "state123");
        assert_eq!(cb.iss.as_deref(), Some("https://auth.example.com"));
    }

    #[tokio::test]
    async fn test_send_xrpc_request_missing_pds_endpoint() {
        let client = AtprotoOAuthClient::builder()
            .client_metadata(OAuthClientMetadata::new(
                "https://app.example.com/client.json",
                "https://app.example.com/callback",
            ))
            .allow_insecure_localhost(true)
            .build()
            .unwrap();

        let session = OAuthSession::new(
            "did:plc:alice123",
            "at_123",
            None,
            "DPoP",
            None,
            None,
            DPoPKey::generate(),
            None,
            None,
            None,
        )
        .unwrap();

        let err = client
            .send_xrpc_request(&session, "com.atproto.repo.describeRepo", &[])
            .await;
        assert!(matches!(
            err,
            Err(AtprotoOAuthError::Token(TokenError::MissingField(
                "pds_endpoint"
            )))
        ));
    }

    #[test]
    fn test_validate_xrpc_nsid_accepts_valid_grammar() {
        // Includes upstream interop-suite valid cases: digit-start authority
        // segments ("one.2.three"), hyphenated authority segments ("a-0.b-1.c"),
        // and camel-case names ("com.example.fooBar").
        for nsid in [
            "com.atproto.repo.describeRepo",
            "/app.bsky.feed.getTimeline",
            "a.b.c",
            "one.2.three",
            "one.two.three.four-and.FiVe",
            "a-0.b-1.c",
            "com.example.fooBar",
            "com.example.fooBarV2",
            "m.xn--masekowski-d0b.pl",
        ] {
            assert!(
                AtprotoOAuthClient::validate_xrpc_nsid(nsid).is_ok(),
                "expected valid NSID: {nsid}"
            );
        }
    }

    #[test]
    fn test_validate_xrpc_nsid_rejects_traversal_and_malformed() {
        for nsid in [
            "../../admin",
            "com.atproto..describeRepo",
            "com..atproto",
            "com.atproto.repo.",
            "com.atproto",
            ".one.two.three",
            "1.0.0.127.record",
            "0two.example.foo",
            "3com.atproto.repo",
            "com.atproto.-repo",
            "com.atproto.repo.name-",
            "com.atproto.repo.-name",
            "a-0.b-1.c-3",
            "a-0.b-1.c-o",
            "com.example.foo.*",
            "com.example.foo.blah*",
            "com.atproto.re\\po",
            "com.atproto.re%70o",
            "",
        ] {
            assert!(
                matches!(
                    AtprotoOAuthClient::validate_xrpc_nsid(nsid),
                    Err(TokenError::InvalidNsid(_))
                ),
                "expected InvalidNsid: {nsid:?}"
            );
        }
    }

    #[test]
    fn test_validate_xrpc_nsid_length_limits() {
        // Segment cap: 63 chars is valid, 64 is not.
        let seg63 = "o".repeat(63);
        let seg64 = "o".repeat(64);
        assert!(AtprotoOAuthClient::validate_xrpc_nsid(&format!("com.{seg63}.foo")).is_ok());
        assert!(matches!(
            AtprotoOAuthClient::validate_xrpc_nsid(&format!("com.{seg64}.foo")),
            Err(TokenError::InvalidNsid(_))
        ));
        // Total cap: 317 chars (253-char authority + '.' + 63-char name), matching
        // the upstream length-check vectors.
        let long_authority = format!("{}.{}.{}.{}", seg63, seg63, "o".repeat(62), "o".repeat(62));
        let nsid_317 = format!("{long_authority}.{}", "f".repeat(63));
        assert_eq!(nsid_317.len(), 317);
        assert!(AtprotoOAuthClient::validate_xrpc_nsid(&nsid_317).is_ok());
        let nsid_318 = format!("{nsid_317}x");
        assert_eq!(nsid_318.len(), 318);
        assert!(matches!(
            AtprotoOAuthClient::validate_xrpc_nsid(&nsid_318),
            Err(TokenError::InvalidNsid(_))
        ));
    }
}
