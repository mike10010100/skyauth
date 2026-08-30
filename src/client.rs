//! High-Level AT Protocol OAuth 2.1 Client.
//!
//! Provides the primary [`AtprotoOAuthClient`] orchestrating user identity resolution,
//! OAuth discovery, RFC 7636 PKCE, RFC 9126 PAR, authorization URL generation,
//! RFC 9449 DPoP-bound code exchange, single-use refresh token rotation, and transparent
//! auto-nonce negotiation loops.

use std::sync::Arc;
use std::time::SystemTime;

use reqwest::header::{HeaderMap, HeaderName, HeaderValue, ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use url::Url;

use crate::crypto::base64url_encode;
use crate::dpop::{compute_access_token_hash, extract_dpop_nonce, DPoPKey, DPoPNonceCache};
use crate::error::{
    sanitize_oauth_error_code, AtprotoOAuthError, ClientMetadataError, DPoPError, ParError,
    StoreError, TokenError,
};
use crate::identity::{IdentityResolver, IdentityResolverBuilder};
use crate::par::{build_authorization_url, execute_par_request, ParParameters};
use crate::permission::PermissionSetResolver;
use crate::pkce::PkcePair;
use crate::policy::time_window_expired;
use crate::scope::ScopeSet;
use crate::session::OAuthSession;
use crate::ssrf::{collect_limited, is_loopback_ip_host, SafeHttpClient, SsrfFilter};
use crate::store::{
    OAuthStateStore, OAuthStore, RefreshAcquire, StateTakeResult, DEFAULT_STATE_TTL,
};

/// Client configuration and metadata for an AT Protocol OAuth client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthClientMetadata {
    client_id: String,
    redirect_uri: String,
    scope: String,
    client_name: Option<String>,
    application_type: ApplicationType,
    refresh_tokens: bool,
}

/// OAuth application type used to validate redirect URIs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplicationType {
    /// Browser or server-hosted web client.
    Web,
    /// Native application using a loopback or application redirect URI.
    Native,
}

impl ApplicationType {
    /// Returns the client metadata string representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Web => "web",
            Self::Native => "native",
        }
    }
}

impl OAuthClientMetadata {
    /// Creates a new `OAuthClientMetadata` with default scope `"atproto"`.
    #[must_use]
    pub fn new(client_id: impl Into<String>, redirect_uri: impl Into<String>) -> Self {
        let redirect_uri = redirect_uri.into();
        let application_type = Url::parse(&redirect_uri).map_or(ApplicationType::Web, |url| {
            if url.scheme() == "http"
                && (is_loopback_ip_host(&url) || url.host_str() == Some("localhost"))
            {
                ApplicationType::Native
            } else {
                ApplicationType::Web
            }
        });
        Self {
            client_id: client_id.into(),
            redirect_uri,
            scope: "atproto".to_string(),
            client_name: None,
            application_type,
            refresh_tokens: true,
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

    /// Sets the application type used for redirect validation.
    #[must_use]
    pub const fn with_application_type(mut self, application_type: ApplicationType) -> Self {
        self.application_type = application_type;
        self
    }

    /// Disables refresh-token requests for this client.
    #[must_use]
    pub const fn without_refresh_tokens(mut self) -> Self {
        self.refresh_tokens = false;
        self
    }

    /// Returns the canonical client identifier.
    #[must_use]
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// Returns the registered redirect URI.
    #[must_use]
    pub fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }

    /// Returns the maximum declared scope string.
    #[must_use]
    pub fn scope(&self) -> &str {
        &self.scope
    }

    /// Returns the display name, when configured.
    #[must_use]
    pub fn client_name(&self) -> Option<&str> {
        self.client_name.as_deref()
    }

    /// Returns the declared application type.
    #[must_use]
    pub const fn application_type(&self) -> ApplicationType {
        self.application_type
    }

    /// Returns whether refresh tokens are declared and requested.
    #[must_use]
    pub const fn refresh_tokens(&self) -> bool {
        self.refresh_tokens
    }

    /// Validates identifiers, redirect policy, and scopes under the selected local mode.
    fn validate(&self, allow_local: bool) -> Result<(), AtprotoOAuthError> {
        let client_id = validate_client_id(&self.client_id, allow_local)?;
        validate_redirect_uri(&self.redirect_uri, self.application_type, &client_id)?;
        ScopeSet::parse(&self.scope)?;
        if client_id.scheme() == "http" {
            validate_virtual_client_id(&client_id, &self.redirect_uri, &self.scope)?;
        }
        Ok(())
    }
}

/// Parses and validates one OAuth client identifier.
fn validate_client_id(value: &str, allow_local: bool) -> Result<Url, ClientMetadataError> {
    let url = Url::parse(value).map_err(|_| ClientMetadataError::InvalidClientId)?;
    let local = allow_local && url.scheme() == "http" && url.host_str() == Some("localhost");
    if (url.scheme() != "https" && !local)
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || (!local && url.port().is_some())
        || (local && (url.port().is_some() || url.path() != "/"))
    {
        return Err(ClientMetadataError::InvalidClientId);
    }
    Ok(url)
}

/// Validates a redirect URI against the client application type and identifier.
fn validate_redirect_uri(
    value: &str,
    application_type: ApplicationType,
    client_id: &Url,
) -> Result<(), ClientMetadataError> {
    let url = Url::parse(value).map_err(|_| ClientMetadataError::InvalidRedirectUri)?;
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return Err(ClientMetadataError::InvalidRedirectUri);
    }
    let valid = match application_type {
        ApplicationType::Web => url.scheme() == "https" && url.host_str().is_some(),
        ApplicationType::Native => {
            (url.scheme() == "http" && is_loopback_ip_host(&url))
                || (url.scheme() == "https" && url.origin() == client_id.origin())
                || valid_native_redirect(value, &url, client_id)
        }
    };
    if valid {
        Ok(())
    } else {
        Err(ClientMetadataError::InvalidRedirectUri)
    }
}

/// Checks a native private-use redirect against its reversed-domain scheme.
fn valid_native_redirect(value: &str, redirect: &Url, client_id: &Url) -> bool {
    let Some(host) = client_id.host_str() else {
        return false;
    };
    let expected_scheme = host.split('.').rev().collect::<Vec<_>>().join(".");
    redirect.scheme() == expected_scheme
        && redirect.host_str().is_none()
        && value.starts_with(&format!("{expected_scheme}:/"))
        && !value.starts_with(&format!("{expected_scheme}://"))
}

/// Enforces the AT Protocol localhost virtual-client identifier profile.
fn validate_virtual_client_id(
    client_id: &Url,
    redirect_uri: &str,
    scope: &str,
) -> Result<(), ClientMetadataError> {
    let mut redirects = Vec::new();
    let mut declared_scope = None;
    for (name, value) in client_id.query_pairs() {
        match name.as_ref() {
            "redirect_uri" => redirects.push(value.into_owned()),
            "scope" if declared_scope.is_none() => declared_scope = Some(value.into_owned()),
            _ => return Err(ClientMetadataError::InvalidClientId),
        }
    }
    if declared_scope.as_deref().unwrap_or("atproto") != scope {
        return Err(ClientMetadataError::Profile(
            "configured scope does not match localhost client ID",
        ));
    }
    if redirects.is_empty() {
        redirects.extend(["http://127.0.0.1/".to_string(), "http://[::1]/".to_string()]);
    }
    let configured =
        Url::parse(redirect_uri).map_err(|_| ClientMetadataError::InvalidRedirectUri)?;
    let matches = redirects.into_iter().any(|declared| {
        Url::parse(&declared).is_ok_and(|declared| {
            declared.scheme() == configured.scheme()
                && declared.host_str() == configured.host_str()
                && declared.path() == configured.path()
                && declared.query() == configured.query()
        })
    });
    if matches {
        Ok(())
    } else {
        Err(ClientMetadataError::InvalidRedirectUri)
    }
}

/// Stored authorization state entry for tracking an in-flight login transaction.
///
/// Saved into the OAuth state store prior to user agent redirection, and consumed
/// atomically upon callback receipt to guarantee single-use CSRF/replay protection.
///
/// ```compile_fail
/// use skyauth::client::StoredStateEntry;
///
/// fn read_private(entry: StoredStateEntry) {
///     let StoredStateEntry { state, .. } = entry;
///     drop(state);
/// }
/// ```
#[derive(Clone)]
pub struct StoredStateEntry {
    state: String,
    client_id: String,
    code_verifier: String,
    dpop_key: DPoPKey,
    issuer: String,
    did: Option<String>,
    handle: Option<String>,
    redirect_uri: String,
    pds_endpoint: String,
    token_endpoint: String,
    scopes: String,
    created_at: SystemTime,
    expires_in_secs: u64,
}

impl std::fmt::Debug for StoredStateEntry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StoredStateEntry")
            .field("state", &"[REDACTED]")
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

impl StoredStateEntry {
    /// Starts a validated transaction builder.
    #[must_use]
    pub fn builder(state: impl Into<String>, dpop_key: DPoPKey) -> StoredStateEntryBuilder {
        StoredStateEntryBuilder::new(state.into(), dpop_key)
    }

    /// Returns the transaction state identifier.
    #[must_use]
    pub fn state(&self) -> &str {
        &self.state
    }

    /// Returns the configured client identifier.
    #[must_use]
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// Returns the authorization-server issuer.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Returns a copy rebound to a different validated state identifier.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the state identifier is malformed.
    pub fn with_state(mut self, state: impl Into<String>) -> Result<Self, StoreError> {
        let state = state.into();
        validate_state_token(&state)?;
        self.state = state;
        Ok(self)
    }

    /// Checks whether this stored state entry has expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs());
        let created_at = self
            .created_at
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(now, |duration| duration.as_secs());
        time_window_expired(now, created_at, self.expires_in_secs)
    }
}

/// Builder for a validated pending authorization transaction.
pub struct StoredStateEntryBuilder {
    state: String,
    dpop_key: DPoPKey,
    client_id: Option<String>,
    code_verifier: Option<String>,
    issuer: Option<String>,
    did: Option<String>,
    handle: Option<String>,
    redirect_uri: Option<String>,
    pds_endpoint: Option<String>,
    token_endpoint: Option<String>,
    scopes: Option<String>,
    created_at: SystemTime,
    expires_in_secs: u64,
}

impl StoredStateEntryBuilder {
    /// Starts a pending-state builder with its state token and DPoP key.
    fn new(state: String, dpop_key: DPoPKey) -> Self {
        Self {
            state,
            dpop_key,
            client_id: None,
            code_verifier: None,
            issuer: None,
            did: None,
            handle: None,
            redirect_uri: None,
            pds_endpoint: None,
            token_endpoint: None,
            scopes: None,
            created_at: SystemTime::now(),
            expires_in_secs: 300,
        }
    }

    /// Sets the client identifier.
    #[must_use]
    pub fn client_id(mut self, value: impl Into<String>) -> Self {
        self.client_id = Some(value.into());
        self
    }

    /// Sets the PKCE verifier.
    #[must_use]
    pub fn code_verifier(mut self, value: impl Into<String>) -> Self {
        self.code_verifier = Some(value.into());
        self
    }

    /// Sets the authorization-server issuer.
    #[must_use]
    pub fn issuer(mut self, value: impl Into<String>) -> Self {
        self.issuer = Some(value.into());
        self
    }

    /// Sets the resolved account identity.
    #[must_use]
    pub fn identity(mut self, did: Option<String>, handle: Option<String>) -> Self {
        self.did = did;
        self.handle = handle;
        self
    }

    /// Sets the redirect URI.
    #[must_use]
    pub fn redirect_uri(mut self, value: impl Into<String>) -> Self {
        self.redirect_uri = Some(value.into());
        self
    }

    /// Sets the resolved PDS endpoint.
    #[must_use]
    pub fn pds_endpoint(mut self, value: impl Into<String>) -> Self {
        self.pds_endpoint = Some(value.into());
        self
    }

    /// Sets the token endpoint.
    #[must_use]
    pub fn token_endpoint(mut self, value: impl Into<String>) -> Self {
        self.token_endpoint = Some(value.into());
        self
    }

    /// Sets the exact requested scope string.
    #[must_use]
    pub fn scopes(mut self, value: impl Into<String>) -> Self {
        self.scopes = Some(value.into());
        self
    }

    /// Sets the creation time and transaction lifetime.
    #[must_use]
    pub const fn lifetime(mut self, created_at: SystemTime, expires_in_secs: u64) -> Self {
        self.created_at = created_at;
        self.expires_in_secs = expires_in_secs;
        self
    }

    /// Validates and builds the pending transaction.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when a mandatory value is absent or malformed.
    pub fn build(self) -> Result<StoredStateEntry, StoreError> {
        validate_state_token(&self.state)?;
        if self.expires_in_secs == 0 {
            return Err(StoreError::InvalidStateEntry("zero lifetime"));
        }
        let client_id = required_state_field(self.client_id, "client_id")?;
        validate_absolute_url(&client_id, "client_id")?;
        let code_verifier = required_state_field(self.code_verifier, "code_verifier")?;
        crate::pkce::validate_verifier(&code_verifier)
            .map_err(|_| StoreError::InvalidStateEntry("code_verifier"))?;
        let issuer = required_state_field(self.issuer, "issuer")?;
        validate_absolute_url(&issuer, "issuer")?;
        let redirect_uri = required_state_field(self.redirect_uri, "redirect_uri")?;
        validate_redirect_url(&redirect_uri)?;
        let pds_endpoint = required_state_field(self.pds_endpoint, "pds_endpoint")?;
        validate_absolute_url(&pds_endpoint, "pds_endpoint")?;
        let token_endpoint = required_state_field(self.token_endpoint, "token_endpoint")?;
        validate_absolute_url(&token_endpoint, "token_endpoint")?;
        let scopes = required_state_field(self.scopes, "scopes")?;
        ScopeSet::parse(&scopes).map_err(|_| StoreError::InvalidStateEntry("scopes"))?;
        if self.did.as_ref().is_some_and(|value| value.is_empty())
            || self.handle.as_ref().is_some_and(|value| value.is_empty())
        {
            return Err(StoreError::InvalidStateEntry("identity"));
        }

        Ok(StoredStateEntry {
            state: self.state,
            client_id,
            code_verifier,
            dpop_key: self.dpop_key,
            issuer,
            did: self.did,
            handle: self.handle,
            redirect_uri,
            pds_endpoint,
            token_endpoint,
            scopes,
            created_at: self.created_at,
            expires_in_secs: self.expires_in_secs,
        })
    }
}

/// Extracts one required, bounded pending-state field.
fn required_state_field(value: Option<String>, name: &'static str) -> Result<String, StoreError> {
    value
        .filter(|value| !value.is_empty() && value.len() <= 4_096)
        .ok_or(StoreError::InvalidStateEntry(name))
}

/// Validates length and character constraints for a state token.
pub(crate) fn validate_state_token(value: &str) -> Result<(), StoreError> {
    if value.is_empty()
        || value.len() > 1_024
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
    {
        Err(StoreError::InvalidStateEntry("state"))
    } else {
        Ok(())
    }
}

/// Requires an absolute HTTP or HTTPS URL for a pending-state field.
fn validate_absolute_url(value: &str, name: &'static str) -> Result<(), StoreError> {
    Url::parse(value)
        .ok()
        .filter(|url| url.has_host() && matches!(url.scheme(), "http" | "https"))
        .map(|_| ())
        .ok_or(StoreError::InvalidStateEntry(name))
}

/// Validates a stored redirect while allowing native private-use schemes.
fn validate_redirect_url(value: &str) -> Result<(), StoreError> {
    Url::parse(value)
        .ok()
        .filter(|url| {
            !url.scheme().is_empty()
                && url.username().is_empty()
                && url.password().is_none()
                && url.fragment().is_none()
        })
        .map(|_| ())
        .ok_or(StoreError::InvalidStateEntry("redirect_uri"))
}

/// The result of initiating an OAuth authorization flow.
#[derive(Clone)]
pub struct AuthorizationRequest {
    /// The complete browser redirection URL pointing to the authorization server.
    authorization_url: Url,
    /// The unique state token.
    state: String,
    /// The back-channel PAR request URI (`urn:ietf:params:oauth:request_uri:...`).
    request_uri: String,
    /// Lifetime of the PAR request URI in seconds.
    expires_in: u64,
}

impl AuthorizationRequest {
    /// Creates a validated authorization request result.
    ///
    /// # Errors
    ///
    /// Returns [`ParError`] when state, request URI, or lifetime values are invalid.
    pub fn new(
        authorization_url: Url,
        state: impl Into<String>,
        request_uri: impl Into<String>,
        expires_in: u64,
    ) -> Result<Self, ParError> {
        let state = state.into();
        let request_uri = request_uri.into();
        if state.is_empty() {
            return Err(ParError::MissingField("state"));
        }
        if !request_uri.starts_with("urn:ietf:params:oauth:request_uri:") {
            return Err(ParError::InvalidRequestUri(request_uri));
        }
        if expires_in == 0 {
            return Err(ParError::MissingField("expires_in"));
        }
        Ok(Self {
            authorization_url,
            state,
            request_uri,
            expires_in,
        })
    }

    /// Returns the complete browser authorization URL.
    #[must_use]
    pub const fn authorization_url(&self) -> &Url {
        &self.authorization_url
    }

    /// Explicitly exposes the callback state token for redirect correlation.
    #[must_use]
    pub fn expose_state(&self) -> &str {
        &self.state
    }

    /// Returns the PAR request URI.
    #[must_use]
    pub fn request_uri(&self) -> &str {
        &self.request_uri
    }

    /// Returns the PAR request URI lifetime in seconds.
    #[must_use]
    pub const fn expires_in(&self) -> u64 {
        self.expires_in
    }
}

impl std::fmt::Debug for AuthorizationRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthorizationRequest")
            .field("authorization_url", &self.authorization_url.origin())
            .field("state", &"[REDACTED]")
            .field("request_uri", &"[REDACTED]")
            .field("expires_in", &self.expires_in)
            .finish()
    }
}

/// Callback parameters extracted from the OAuth redirect URI query string.
#[derive(Clone, PartialEq, Eq)]
pub struct CallbackParams {
    /// The authorization code issued by the authorization server.
    code: String,
    /// The state token returned by the authorization server.
    state: String,
    /// Optional RFC 9207 issuer parameter.
    iss: Option<String>,
}

impl std::fmt::Debug for CallbackParams {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CallbackParams")
            .field("code", &"[REDACTED]")
            .field("state", &"[REDACTED]")
            .field("iss", &self.iss)
            .finish()
    }
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

    /// Explicitly exposes the authorization code for the token exchange boundary.
    #[must_use]
    pub fn expose_code(&self) -> &str {
        &self.code
    }

    /// Explicitly exposes the callback state for atomic store consumption.
    #[must_use]
    pub fn expose_state(&self) -> &str {
        &self.state
    }

    /// Returns the authorization response issuer.
    #[must_use]
    pub fn issuer(&self) -> Option<&str> {
        self.iss.as_deref()
    }
}

/// Raw parsed token endpoint response representation.
#[derive(serde::Deserialize)]
pub struct TokenResponse {
    access_token: crate::secret::SecretString,
    token_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_in: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<crate::secret::SecretString>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
    sub: String,
}

impl std::fmt::Debug for TokenResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TokenResponse")
            .field("access_token", &"[REDACTED]")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .field("scope", &self.scope)
            .field("sub", &self.sub)
            .finish()
    }
}

impl TokenResponse {
    /// Returns the token type.
    #[must_use]
    pub fn token_type(&self) -> &str {
        &self.token_type
    }

    /// Returns the access-token lifetime.
    #[must_use]
    pub const fn expires_in(&self) -> Option<u64> {
        self.expires_in
    }

    /// Returns the granted scope string.
    #[must_use]
    pub fn scope(&self) -> Option<&str> {
        self.scope.as_deref()
    }

    /// Returns the authenticated subject DID.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.sub
    }
}

/// Builder for constructing an [`AtprotoOAuthClient`].
#[derive(Debug, Clone)]
pub struct AtprotoOAuthClientBuilder {
    metadata: Option<OAuthClientMetadata>,
    resolver: Option<IdentityResolver>,
    nonce_cache: Option<DPoPNonceCache>,
    ssrf_filter: SsrfFilter,
    state_store: Option<Arc<dyn OAuthStore>>,
    permission_set_resolver: Option<Arc<dyn PermissionSetResolver>>,
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
            permission_set_resolver: None,
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

    /// Sets the authorization state store.
    #[must_use]
    pub fn state_store(mut self, store: Arc<dyn OAuthStore>) -> Self {
        self.state_store = Some(store);
        self
    }

    /// Selects the bounded in-memory state and refresh store.
    #[must_use]
    pub fn in_memory_state_store(mut self) -> Self {
        self.state_store = Some(Arc::new(OAuthStateStore::default()));
        self
    }

    /// Sets the authenticated Lexicon permission-set resolver.
    #[must_use]
    pub fn permission_set_resolver(mut self, resolver: Arc<dyn PermissionSetResolver>) -> Self {
        self.permission_set_resolver = Some(resolver);
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
        metadata.validate(self.ssrf_filter.allow_insecure_localhost)?;

        let resolver = self.resolver.unwrap_or_else(|| {
            IdentityResolverBuilder::new()
                .ssrf_filter(self.ssrf_filter)
                .build()
        });

        let nonce_cache = self.nonce_cache.unwrap_or_default();
        let state_store = self
            .state_store
            .ok_or(ClientMetadataError::MissingStateStore)?;

        Ok(AtprotoOAuthClient {
            metadata,
            resolver,
            nonce_cache,
            ssrf_filter: self.ssrf_filter,
            http_client: SafeHttpClient::new(self.ssrf_filter),
            state_store,
            permission_set_resolver: self.permission_set_resolver,
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
    http_client: SafeHttpClient,
    state_store: Arc<dyn OAuthStore>,
    permission_set_resolver: Option<Arc<dyn PermissionSetResolver>>,
}

impl AtprotoOAuthClient {
    /// Creates a new `AtprotoOAuthClient` with the given client ID and redirect URI.
    pub fn new(
        client_id: impl Into<String>,
        redirect_uri: impl Into<String>,
        state_store: Arc<dyn OAuthStore>,
    ) -> Result<Self, AtprotoOAuthError> {
        let metadata = OAuthClientMetadata::new(client_id, redirect_uri);
        metadata.validate(false)?;
        let ssrf_filter = SsrfFilter::default();
        let resolver = IdentityResolverBuilder::new()
            .ssrf_filter(ssrf_filter)
            .build();
        Ok(Self {
            metadata,
            resolver,
            nonce_cache: DPoPNonceCache::new(),
            ssrf_filter,
            http_client: SafeHttpClient::new(ssrf_filter),
            state_store,
            permission_set_resolver: None,
        })
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

    /// Returns the authorization state store.
    #[must_use]
    pub fn state_store(&self) -> &Arc<dyn OAuthStore> {
        &self.state_store
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
    /// 7. Persists the pending transaction and returns the authorization request.
    ///
    /// # Errors
    ///
    /// Returns [`AtprotoOAuthError`] if discovery, PAR, or cryptographic operations fail.
    pub async fn initiate_login(
        &self,
        handle_or_did: &str,
    ) -> Result<AuthorizationRequest, AtprotoOAuthError> {
        self.initiate_login_with_scope(handle_or_did, &self.metadata.scope)
            .await
    }

    /// Initiates an OAuth login flow with custom scope overrides.
    pub async fn initiate_login_with_scope(
        &self,
        handle_or_did: &str,
        scope: &str,
    ) -> Result<AuthorizationRequest, AtprotoOAuthError> {
        let requested_scope = ScopeSet::parse(scope)?;
        let maximum_scope = ScopeSet::parse(&self.metadata.scope)?;
        if !requested_scope.is_subset_of(&maximum_scope) {
            return Err(
                ClientMetadataError::Profile("requested scope exceeds declared scope").into(),
            );
        }
        self.resolve_permission_sets(&requested_scope).await?;
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
        let stored_state = StoredStateEntry::builder(state.clone(), dpop_key)
            .client_id(self.metadata.client_id.clone())
            .code_verifier(pkce.verifier)
            .issuer(endpoints.auth_server_issuer.clone())
            .identity(Some(endpoints.did), endpoints.handle)
            .redirect_uri(self.metadata.redirect_uri.clone())
            .pds_endpoint(endpoints.pds_endpoint)
            .token_endpoint(endpoints.token_endpoint)
            .scopes(scope)
            .build()?;

        self.state_store
            .insert_state(state.clone(), stored_state, DEFAULT_STATE_TTL)
            .await?;

        let auth_req = AuthorizationRequest {
            authorization_url: auth_url,
            state,
            request_uri: par_res.request_uri,
            expires_in: par_res.expires_in,
        };

        Ok(auth_req)
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
    async fn exchange_code(
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

        let granted_scope = resp_json
            .scope
            .as_deref()
            .ok_or(TokenError::MissingField("scope"))?;
        let granted = ScopeSet::parse(granted_scope).map_err(|_| {
            TokenError::MissingAtprotoScope("invalid or missing scope set".to_string())
        })?;
        let requested = ScopeSet::parse(&state_entry.scopes)?;
        if !granted.is_subset_of(&requested) {
            return Err(TokenError::ScopeEscalation.into());
        }
        self.resolve_permission_sets(&granted).await?;

        OAuthSession::new(
            resp_json.sub,
            resp_json.access_token.expose(),
            resp_json
                .refresh_token
                .as_ref()
                .map(|token| token.expose().to_string()),
            resp_json.token_type,
            resp_json.scope,
            resp_json.expires_in,
            state_entry.dpop_key.clone(),
            Some(state_entry.pds_endpoint.clone()),
            Some(state_entry.issuer.clone()),
            Some(state_entry.token_endpoint.clone()),
        )
    }

    /// Handles an OAuth redirect callback by verifying `state` and `iss` before code exchange.
    ///
    /// # Errors
    /// - Returns [`TokenError::InvalidState`] if callback `state` does not match `state_entry.state`.
    /// - Returns [`TokenError::IssuerMismatch`] if callback `iss` does not match `state_entry.issuer`.
    pub async fn handle_callback(
        &self,
        callback_params: &CallbackParams,
    ) -> Result<OAuthSession, AtprotoOAuthError> {
        validate_state_token(&callback_params.state).map_err(|_| TokenError::InvalidState)?;
        if callback_params.code.is_empty()
            || callback_params.code.len() > 4_096
            || callback_params
                .code
                .bytes()
                .any(|byte| byte.is_ascii_control())
        {
            return Err(TokenError::MissingField("code").into());
        }
        let state_entry = match self
            .state_store
            .consume_state(&callback_params.state)
            .await?
        {
            StateTakeResult::Acquired(entry) => *entry,
            StateTakeResult::Missing => {
                return Err(StoreError::StateNotFound.into());
            }
            StateTakeResult::Expired => return Err(TokenError::StateExpired.into()),
            StateTakeResult::Replayed => return Err(TokenError::StateReplayed.into()),
        };
        if state_entry.state != callback_params.state {
            return Err(TokenError::InvalidState.into());
        }

        let callback_iss = callback_params
            .iss
            .as_deref()
            .ok_or(TokenError::MissingField("iss"))?;
        if callback_iss != state_entry.issuer {
            return Err(TokenError::IssuerMismatch {
                expected: state_entry.issuer.clone(),
                actual: callback_iss.to_string(),
            }
            .into());
        }

        self.exchange_code(&callback_params.code, &state_entry)
            .await
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
        *session = self.refresh_token(session).await?;
        Ok(())
    }

    /// Refreshes a session and returns the committed replacement token set.
    pub async fn refresh_token(
        &self,
        session: &OAuthSession,
    ) -> Result<OAuthSession, AtprotoOAuthError> {
        match self
            .state_store
            .acquire_refresh(session.session_id(), session.generation())
            .await?
        {
            RefreshAcquire::Current(current) => Ok(*current),
            RefreshAcquire::Acquired(lease) => match self.refresh_once(session).await {
                Ok(replacement) => self
                    .state_store
                    .commit_refresh(lease, replacement)
                    .await
                    .map_err(Into::into),
                Err(error) => {
                    self.state_store.fail_refresh(lease).await?;
                    Err(error)
                }
            },
        }
    }

    /// Performs one refresh-token exchange for a store-issued generation lease.
    async fn refresh_once(
        &self,
        session: &OAuthSession,
    ) -> Result<OAuthSession, AtprotoOAuthError> {
        let refresh_token = session
            .expose_refresh_token()
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

        let refreshed_scope = resp_json
            .scope
            .as_deref()
            .ok_or(TokenError::MissingField("scope"))?;
        let refreshed = ScopeSet::parse(refreshed_scope).map_err(|_| {
            TokenError::MissingAtprotoScope("invalid or missing scope set".to_string())
        })?;
        let prior = session
            .scope()
            .ok_or(TokenError::MissingField("session_scope"))?;
        let prior = ScopeSet::parse(prior)?;
        if !refreshed.is_subset_of(&prior) {
            return Err(TokenError::ScopeEscalation.into());
        }
        self.resolve_permission_sets(&refreshed).await?;

        let rotated_refresh_token = resp_json.refresh_token.as_ref().map_or_else(
            || refresh_token.to_string(),
            |token| token.expose().to_string(),
        );
        let mut replacement = session.clone();
        replacement.rotate_tokens(
            resp_json.access_token.expose(),
            Some(rotated_refresh_token),
            resp_json.scope,
            resp_json.expires_in,
        )?;

        Ok(replacement)
    }

    /// Authenticates and resolves each permission-set scope before use.
    async fn resolve_permission_sets(&self, scopes: &ScopeSet) -> Result<(), AtprotoOAuthError> {
        let has_includes = scopes.items().iter().any(|item| {
            matches!(
                item,
                crate::scope::ScopeItem::Permission(permission)
                    if permission.resource() == crate::scope::PermissionResource::Include
            )
        });
        if !has_includes {
            return Ok(());
        }
        let resolver = self
            .permission_set_resolver
            .as_ref()
            .ok_or(crate::error::ScopeError::ResolverRequired)?;
        resolver.resolve_scope_sets(scopes).await?;
        Ok(())
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

        self.ssrf_filter
            .validate_url(&parsed_url)
            .map_err(TokenError::from)?;
        let server_origin = parsed_url.origin().ascii_serialization();
        let initial_nonce = self.nonce_cache.get_nonce(dpop_key, &server_origin);
        let proof =
            dpop_key.create_proof("POST", token_endpoint, initial_nonce.as_deref(), None)?;
        let (status, bytes) = self
            .send_token_attempt(
                token_endpoint,
                &server_origin,
                dpop_key,
                &proof,
                body_bytes.clone(),
            )
            .await?;

        if status.is_success() {
            return parse_token_response(&bytes);
        }

        let (error, description) = parse_oauth_error(&bytes);
        if error == "use_dpop_nonce" {
            let fresh_nonce = self
                .nonce_cache
                .get_nonce(dpop_key, &server_origin)
                .ok_or_else(|| TokenError::RequestFailed {
                    status: status.as_u16(),
                    error: error.clone(),
                    description: Some("DPoP-Nonce response header is required".to_string()),
                })?;
            let retry_proof =
                dpop_key.create_proof("POST", token_endpoint, Some(&fresh_nonce), None)?;
            let (retry_status, retry_bytes) = self
                .send_token_attempt(
                    token_endpoint,
                    &server_origin,
                    dpop_key,
                    &retry_proof,
                    body_bytes,
                )
                .await?;
            if retry_status.is_success() {
                return parse_token_response(&retry_bytes);
            }
            let (retry_error, retry_description) = parse_oauth_error(&retry_bytes);
            if retry_error == "use_dpop_nonce" {
                return Err(DPoPError::NonceRetryLimitExceeded.into());
            }
            return Err(TokenError::RequestFailed {
                status: retry_status.as_u16(),
                error: retry_error,
                description: retry_description,
            }
            .into());
        }

        Err(TokenError::RequestFailed {
            status: status.as_u16(),
            error,
            description,
        }
        .into())
    }

    /// Sends one DPoP-bound token request and reads its bounded response.
    async fn send_token_attempt(
        &self,
        token_endpoint: &str,
        server_origin: &str,
        dpop_key: &DPoPKey,
        proof: &str,
        body: Vec<u8>,
    ) -> Result<(reqwest::StatusCode, Vec<u8>), AtprotoOAuthError> {
        let response = self
            .http_client
            .send(
                reqwest::Method::POST,
                token_endpoint,
                dpop_headers(proof, None, Some("application/x-www-form-urlencoded"))?,
                Some(body),
            )
            .await
            .map_err(TokenError::from)?;
        cache_required_nonce(&response, &self.nonce_cache, dpop_key, server_origin)?;
        let status = response.status();
        let bytes = collect_limited(response, 65_536)
            .await
            .map_err(TokenError::from)?;
        Ok((status, bytes))
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

        self.ssrf_filter
            .validate_url(&parsed_url)
            .map_err(TokenError::from)?;

        let server_origin = parsed_url.origin().ascii_serialization();

        let ath = access_token.map(compute_access_token_hash);

        let initial_nonce = self.nonce_cache.get_nonce(dpop_key, &server_origin);
        let proof = dpop_key.create_proof(
            method.as_str(),
            url_str,
            initial_nonce.as_deref(),
            ath.as_deref(),
        )?;

        let resp = self
            .http_client
            .send(
                method.clone(),
                url_str,
                dpop_headers(&proof, access_token, content_type)?,
                body_bytes.clone(),
            )
            .await
            .map_err(TokenError::from)?;
        cache_required_nonce(&resp, &self.nonce_cache, dpop_key, &server_origin)?;

        let status = resp.status();
        if status == reqwest::StatusCode::BAD_REQUEST || status == reqwest::StatusCode::UNAUTHORIZED
        {
            let response_bytes = collect_limited(resp, 65_536)
                .await
                .map_err(TokenError::from)?;
            let (error, description) = parse_oauth_error(&response_bytes);
            if error == "use_dpop_nonce" {
                let fresh_nonce = self
                    .nonce_cache
                    .get_nonce(dpop_key, &server_origin)
                    .ok_or_else(|| TokenError::RequestFailed {
                        status: status.as_u16(),
                        error: "use_dpop_nonce".to_string(),
                        description: Some("Missing DPoP-Nonce header".to_string()),
                    })?;

                let retry_proof = dpop_key.create_proof(
                    method.as_str(),
                    url_str,
                    Some(&fresh_nonce),
                    ath.as_deref(),
                )?;

                let retry_resp = self
                    .http_client
                    .send(
                        method,
                        url_str,
                        dpop_headers(&retry_proof, access_token, content_type)?,
                        body_bytes,
                    )
                    .await
                    .map_err(TokenError::from)?;
                cache_required_nonce(&retry_resp, &self.nonce_cache, dpop_key, &server_origin)?;

                let retry_status = retry_resp.status();
                if retry_status == reqwest::StatusCode::BAD_REQUEST
                    || retry_status == reqwest::StatusCode::UNAUTHORIZED
                {
                    let retry_bytes = collect_limited(retry_resp, 65_536)
                        .await
                        .map_err(TokenError::from)?;
                    let (retry_error, retry_description) = parse_oauth_error(&retry_bytes);
                    if retry_error == "use_dpop_nonce" {
                        return Err(DPoPError::NonceRetryLimitExceeded.into());
                    }
                    return Err(TokenError::RequestFailed {
                        status: retry_status.as_u16(),
                        error: retry_error,
                        description: retry_description,
                    }
                    .into());
                }

                return Ok(retry_resp);
            }
            return Err(TokenError::RequestFailed {
                status: status.as_u16(),
                error,
                description,
            }
            .into());
        }

        Ok(resp)
    }
}

/// Builds the content and DPoP headers for one token endpoint request.
fn dpop_headers(
    proof: &str,
    access_token: Option<&str>,
    content_type: Option<&str>,
) -> Result<HeaderMap, TokenError> {
    let mut headers = HeaderMap::new();
    headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
    let proof =
        HeaderValue::from_str(proof).map_err(|error| TokenError::Http(error.to_string()))?;
    headers.insert(HeaderName::from_static("dpop"), proof);
    if let Some(token) = access_token {
        let value = HeaderValue::from_str(&format!("DPoP {token}"))
            .map_err(|error| TokenError::Http(error.to_string()))?;
        headers.insert(AUTHORIZATION, value);
    }
    if let Some(value) = content_type {
        let value =
            HeaderValue::from_str(value).map_err(|error| TokenError::Http(error.to_string()))?;
        headers.insert(CONTENT_TYPE, value);
    }
    Ok(headers)
}

/// Caches the AT Protocol-required nonce returned by a DPoP response.
fn cache_required_nonce(
    response: &reqwest::Response,
    cache: &DPoPNonceCache,
    key: &DPoPKey,
    origin: &str,
) -> Result<(), TokenError> {
    let raw_nonce = response
        .headers()
        .get("dpop-nonce")
        .and_then(|value| value.to_str().ok())
        .ok_or(TokenError::MissingField("DPoP-Nonce"))?;
    if raw_nonce.len() > 1_024 {
        return Err(TokenError::Http(
            "DPoP-Nonce response header exceeds 1024 bytes".to_string(),
        ));
    }
    let nonce =
        extract_dpop_nonce(Some(raw_nonce)).ok_or(TokenError::MissingField("DPoP-Nonce"))?;
    cache.set_nonce(key, origin, nonce);
    Ok(())
}

/// Parses a bounded OAuth error body into its code and optional description.
fn parse_oauth_error(bytes: &[u8]) -> (String, Option<String>) {
    let parsed: Option<serde_json::Value> = serde_json::from_slice(bytes).ok();
    let error = sanitize_oauth_error_code(
        parsed
            .as_ref()
            .and_then(|value| value.get("error"))
            .and_then(|value| value.as_str()),
        "token_request_failed",
    );
    (error, None)
}

/// Deserializes a bounded token response body.
fn parse_token_response(bytes: &[u8]) -> Result<TokenResponse, AtprotoOAuthError> {
    serde_json::from_slice(bytes)
        .map_err(|error| TokenError::Json(error.to_string()))
        .map_err(AtprotoOAuthError::from)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_client_builder_and_metadata() {
        let client = AtprotoOAuthClient::builder()
            .in_memory_state_store()
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
        let entry = StoredStateEntry::builder("state123", DPoPKey::generate())
            .client_id("https://app.example.com/client.json")
            .code_verifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk-sample-pkce-verifier")
            .issuer("https://auth.example.com")
            .identity(
                Some("did:plc:alice".to_string()),
                Some("alice.bsky.social".to_string()),
            )
            .redirect_uri("https://app.example.com/callback")
            .pds_endpoint("https://pds.example.com")
            .token_endpoint("https://auth.example.com/oauth/token")
            .scopes("atproto")
            .lifetime(SystemTime::now() - Duration::from_secs(400), 300)
            .build()
            .unwrap();

        assert!(entry.is_expired());
    }

    #[test]
    fn test_callback_params() {
        let cb = CallbackParams::new("code123", "state123").with_iss("https://auth.example.com");
        assert_eq!(cb.code, "code123");
        assert_eq!(cb.state, "state123");
        assert_eq!(cb.iss.as_deref(), Some("https://auth.example.com"));
    }

    #[test]
    fn native_ipv6_loopback_redirect_is_accepted() {
        let metadata = OAuthClientMetadata::new(
            "https://app.example.com/client.json",
            "http://[::1]:43210/callback",
        );
        assert_eq!(metadata.application_type(), ApplicationType::Native);
        metadata.validate(false).unwrap();
    }
}
