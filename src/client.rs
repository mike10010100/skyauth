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
use crate::ssrf::{read_bounded_body, SsrfFilter};
use crate::store::{OAuthStateStore, OAuthStore, DEFAULT_STATE_TTL};

/// Client configuration and metadata for an AT Protocol OAuth client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthClientMetadata {
    /// Canonical OAuth client ID (usually a Client Metadata Document URL).
    pub client_id: String,
    /// Registered OAuth redirect callback URI.
    pub redirect_uri: String,
    /// Requested OAuth scopes (defaults to `"atproto"`).
    pub scope: String,
    /// Optional human-readable client display name.
    pub client_name: Option<String>,
    /// Optional client secret for confidential client authentication.
    pub client_secret: Option<String>,
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
            client_secret: None,
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

    /// Sets the optional client secret.
    #[must_use]
    pub fn with_client_secret(mut self, secret: impl Into<String>) -> Self {
        self.client_secret = Some(secret.into());
        self
    }
}

/// Stored authorization state entry for tracking an in-flight login transaction.
///
/// Saved into the OAuth state store prior to user agent redirection, and consumed
/// atomically upon callback receipt to guarantee single-use CSRF/replay protection.
#[derive(Debug, Clone)]
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

impl StoredStateEntry {
    /// Checks whether this stored state entry has expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now();
        let max_age = Duration::from_secs(self.expires_in_secs);
        now.duration_since(self.created_at)
            .unwrap_or(Duration::ZERO)
            > max_age
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
    pub fn build(self) -> Result<AtprotoOAuthClient, AtprotoOAuthError> {
        let metadata = self
            .metadata
            .ok_or(ParError::MissingField("client_metadata"))?;

        let resolver = self.resolver.unwrap_or_else(|| {
            IdentityResolverBuilder::new()
                .ssrf_filter(self.ssrf_filter)
                .build()
        });

        let nonce_cache = self.nonce_cache.unwrap_or_default();
        let state_store = self
            .state_store
            .unwrap_or_else(|| Arc::new(OAuthStateStore::new(self.state_ttl)));

        Ok(AtprotoOAuthClient {
            metadata,
            resolver,
            nonce_cache,
            ssrf_filter: self.ssrf_filter,
            state_store,
            state_ttl: self.state_ttl,
        })
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

    /// Initiates an OAuth login flow for a user handle or DID.
    ///
    /// # Pipeline
    /// 1. Discovers identity, PDS endpoint, and authorization server metadata.
    /// 2. Generates a fresh S256 PKCE code challenge and verifier.
    /// 3. Generates a high-entropy 256-bit random state token.
    /// 4. Generates an ephemeral session [`DPoPKey`].
    /// 5. Pushes parameters to the authorization server's PAR endpoint with DPoP proof.
    /// 6. Constructs the browser authorization redirect URL with `client_id` and `request_uri`.
    /// 7. Returns `(AuthorizationRequest, StoredStateEntry)`.
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
        // 1. Identity & OAuth Discovery
        let endpoints = self
            .resolver
            .discover_oauth_endpoints(handle_or_did)
            .await?;

        // 2. PKCE and State Generation
        let pkce = PkcePair::generate();
        let mut state_bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut state_bytes);
        let state = base64url_encode(&state_bytes);

        // 3. Ephemeral DPoP Keypair
        let dpop_key = DPoPKey::generate();

        // 4. PAR Request Builder
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

        // 5. Execute PAR with DPoP signing & auto-nonce retry
        let par_res = execute_par_request(
            &self.ssrf_filter,
            &endpoints.par_endpoint,
            &params,
            &dpop_key,
            &self.nonce_cache,
        )
        .await?;

        // 6. Build Authorization Redirect URL
        let auth_url = build_authorization_url(
            &endpoints.authorization_endpoint,
            &self.metadata.client_id,
            &par_res.request_uri,
        )?;

        // 7. Assemble StoredStateEntry and AuthorizationRequest
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

        // 8. Atomically persist state into internal store with TTL
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
        let form_body = serde_urlencoded::to_string([
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", &state_entry.redirect_uri),
            ("client_id", &state_entry.client_id),
            ("code_verifier", &state_entry.code_verifier),
        ])
        .map_err(|e| TokenError::Http(e.to_string()))?;

        let resp_json: TokenResponse = self
            .send_dpop_token_request(
                &state_entry.token_endpoint,
                &state_entry.dpop_key,
                form_body.into_bytes(),
            )
            .await?;

        // 1. Validate token_type == "DPoP" (case-insensitive)
        if !resp_json.token_type.eq_ignore_ascii_case("DPoP") {
            return Err(TokenError::InvalidTokenType(resp_json.token_type).into());
        }

        // 2. Validate sub DID
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

        // 3. Validate Scope is present and contains "atproto"
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
        let refresh_token = session
            .refresh_token()
            .ok_or(TokenError::MissingRefreshToken)?;

        let token_endpoint = session
            .token_endpoint()
            .ok_or(TokenError::MissingField("token_endpoint"))?
            .to_string();

        let form_body = serde_urlencoded::to_string([
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", &self.metadata.client_id),
        ])
        .map_err(|e| TokenError::Http(e.to_string()))?;

        let resp_json: TokenResponse = self
            .send_dpop_token_request(&token_endpoint, session.dpop_key(), form_body.into_bytes())
            .await?;

        if !resp_json.token_type.eq_ignore_ascii_case("DPoP") {
            return Err(TokenError::InvalidTokenType(resp_json.token_type).into());
        }

        if !resp_json.sub.is_empty() && resp_json.sub != session.sub() {
            return Err(TokenError::SubMismatch {
                expected: session.sub().to_string(),
                actual: resp_json.sub,
            }
            .into());
        }

        session.rotate_tokens(
            resp_json.access_token,
            resp_json.refresh_token,
            resp_json.expires_in,
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
        let parsed_url = Url::parse(token_endpoint).map_err(|e| {
            TokenError::Http(format!(
                "Invalid token endpoint URL '{token_endpoint}': {e}"
            ))
        })?;

        let (client, _pinned_addr, host_header) = self
            .ssrf_filter
            .build_pinned_client(&parsed_url)
            .await
            .map_err(TokenError::from)?;

        let server_origin = parsed_url.origin().ascii_serialization();

        // Initial Attempt with cached nonce (if any)
        let initial_nonce = self.nonce_cache.get_nonce(&server_origin);
        let proof =
            dpop_key.create_proof("POST", token_endpoint, initial_nonce.as_deref(), None)?;

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

        // Cache any returned DPoP-Nonce header
        if let Some(new_nonce) = extract_dpop_nonce(
            resp.headers()
                .get("dpop-nonce")
                .and_then(|h| h.to_str().ok()),
        ) {
            self.nonce_cache.set_nonce(&server_origin, new_nonce);
        }

        let status = resp.status();

        // Disallow redirects on token endpoints (RFC 6749)
        if status.is_redirection() {
            return Err(TokenError::RequestFailed {
                status: status.as_u16(),
                error: "invalid_request".to_string(),
                description: Some("Redirects are not permitted for token endpoints".to_string()),
            }
            .into());
        }

        // Check for use_dpop_nonce error challenge
        if status == reqwest::StatusCode::BAD_REQUEST || status == reqwest::StatusCode::UNAUTHORIZED
        {
            let resp_bytes = read_bounded_body(resp, 1_048_576)
                .await
                .map_err(|e| TokenError::Http(e.to_string()))?;

            let json_err: Option<serde_json::Value> = serde_json::from_slice(&resp_bytes).ok();
            let is_nonce_error = json_err
                .as_ref()
                .and_then(|j| j.get("error"))
                .and_then(|e| e.as_str())
                == Some("use_dpop_nonce");

            if is_nonce_error {
                let fresh_nonce = self.nonce_cache.get_nonce(&server_origin).ok_or_else(|| {
                    TokenError::RequestFailed {
                        status: status.as_u16(),
                        error: "use_dpop_nonce".to_string(),
                        description: Some(
                            "Missing DPoP-Nonce header in challenge response".to_string(),
                        ),
                    }
                })?;

                // Single Retry with fresh nonce
                let retry_proof =
                    dpop_key.create_proof("POST", token_endpoint, Some(&fresh_nonce), None)?;

                let (retry_client, _retry_pinned_addr, retry_host_header) = self
                    .ssrf_filter
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
                    self.nonce_cache.set_nonce(&server_origin, new_nonce);
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
                    let bytes = read_bounded_body(retry_resp, 1_048_576)
                        .await
                        .map_err(|e| TokenError::Http(e.to_string()))?;
                    let res: TokenResponse = serde_json::from_slice(&bytes)
                        .map_err(|e| TokenError::Json(e.to_string()))?;
                    return Ok(res);
                }

                let err_bytes = read_bounded_body(retry_resp, 1_048_576)
                    .await
                    .map_err(|e| TokenError::Http(e.to_string()))?;
                let err_json: Option<serde_json::Value> = serde_json::from_slice(&err_bytes).ok();
                if err_json
                    .as_ref()
                    .and_then(|j| j.get("error"))
                    .and_then(|e| e.as_str())
                    == Some("use_dpop_nonce")
                {
                    return Err(DPoPError::NonceRetryLimitExceeded.into());
                }

                let error_code = err_json
                    .as_ref()
                    .and_then(|j| j.get("error"))
                    .and_then(|e| e.as_str())
                    .unwrap_or("token_request_failed")
                    .to_string();
                let error_desc = err_json
                    .as_ref()
                    .and_then(|j| j.get("error_description"))
                    .and_then(|d| d.as_str())
                    .map(ToString::to_string);

                return Err(TokenError::RequestFailed {
                    status: retry_status.as_u16(),
                    error: error_code,
                    description: error_desc,
                }
                .into());
            }

            let error_code = json_err
                .as_ref()
                .and_then(|j| j.get("error"))
                .and_then(|e| e.as_str())
                .unwrap_or("token_request_failed")
                .to_string();
            let error_desc = json_err
                .as_ref()
                .and_then(|j| j.get("error_description"))
                .and_then(|d| d.as_str())
                .map(ToString::to_string);

            return Err(TokenError::RequestFailed {
                status: status.as_u16(),
                error: error_code,
                description: error_desc,
            }
            .into());
        }

        if !status.is_success() {
            let err_bytes = read_bounded_body(resp, 1_048_576)
                .await
                .map_err(|e| TokenError::Http(e.to_string()))?;
            let err_json: Option<serde_json::Value> = serde_json::from_slice(&err_bytes).ok();
            let error_code = err_json
                .as_ref()
                .and_then(|j| j.get("error"))
                .and_then(|e| e.as_str())
                .unwrap_or("token_request_failed")
                .to_string();
            let error_desc = err_json
                .as_ref()
                .and_then(|j| j.get("error_description"))
                .and_then(|d| d.as_str())
                .map(ToString::to_string);

            return Err(TokenError::RequestFailed {
                status: status.as_u16(),
                error: error_code,
                description: error_desc,
            }
            .into());
        }

        let bytes = read_bounded_body(resp, 1_048_576)
            .await
            .map_err(|e| TokenError::Http(e.to_string()))?;
        let res: TokenResponse =
            serde_json::from_slice(&bytes).map_err(|e| TokenError::Json(e.to_string()))?;
        Ok(res)
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

        // 1. Initial Attempt
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
            let is_nonce_challenge = resp
                .headers()
                .get("dpop-nonce")
                .and_then(|h| h.to_str().ok())
                .is_some();

            if is_nonce_challenge {
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
                    // Check if still failing with use_dpop_nonce
                    let retry_is_nonce = retry_resp
                        .headers()
                        .get("dpop-nonce")
                        .and_then(|h| h.to_str().ok())
                        .is_some();
                    if retry_is_nonce {
                        return Err(DPoPError::NonceRetryLimitExceeded.into());
                    }
                }

                return Ok(retry_resp);
            }
        }

        Ok(resp)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]
mod tests {
    use super::*;

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
}
