//! OAuth 2.0 Discovery Engine (RFC 8414 & RFC 9728).
//!
//! Implements multi-stage discovery for the AT Protocol:
//! 1. **Protected Resource Discovery (RFC 9728)**: Discovers authorization servers
//!    guarding the user's Personal Data Server (PDS) via `/.well-known/oauth-protected-resource`.
//! 2. **Authorization Server Discovery (RFC 8414 / OIDC)**: Discovers OAuth 2.0 endpoints
//!    via `/.well-known/oauth-authorization-server` with fallback to `/.well-known/openid-configuration`.
//! 3. **Mandatory Security Validation**: Asserts issuer origin equality, `ES256` DPoP support,
//!    `S256` PKCE enforcement, and PAR endpoint availability.
//! 4. **End-to-End Discovery Pipeline**: Integrates identity resolution and SSRF defense
//!    into a unified discovery entry point.

use serde::{Deserialize, Serialize};
use url::Url;

use crate::error::{DiscoveryError, SsrfError};
use crate::identity::IdentityResolver;
use crate::ssrf::{SsrfFilter, MAX_OAUTH_RESPONSE_BYTES};

/// RFC 9728 OAuth 2.0 Protected Resource Metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectedResourceMetadata {
    /// URI of the protected resource (PDS origin).
    pub resource: String,
    /// List of trusted Authorization Server URLs protecting this resource.
    pub authorization_servers: Vec<String>,
    /// Scopes supported by this protected resource (e.g. `["atproto"]`).
    #[serde(default)]
    pub scopes_supported: Vec<String>,
    /// Supported bearer presentation methods (e.g. `["header"]`).
    #[serde(default)]
    pub bearer_methods_supported: Vec<String>,
    /// Documentation URI for the resource.
    #[serde(default)]
    pub resource_documentation: Option<String>,
}

/// RFC 8414 OAuth 2.0 Authorization Server Metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationServerMetadata {
    /// Issuer identifier URL (MUST match discovery origin).
    pub issuer: String,
    /// URL for user authorization browser redirects.
    pub authorization_endpoint: String,
    /// URL for token exchange and refresh requests.
    pub token_endpoint: String,
    /// URL for RFC 9126 Pushed Authorization Requests.
    #[serde(default)]
    pub pushed_authorization_request_endpoint: String,
    /// Whether PAR is required by the authorization server.
    #[serde(default)]
    pub require_pushed_authorization_requests: bool,
    /// Supported DPoP signing algorithms (must include `"ES256"`).
    #[serde(default)]
    pub dpop_signing_alg_values_supported: Vec<String>,
    /// Supported PKCE code challenge methods (must include `"S256"`).
    #[serde(default)]
    pub code_challenge_methods_supported: Vec<String>,
    /// Supported response types (e.g. `["code"]`).
    #[serde(default)]
    pub response_types_supported: Vec<String>,
    /// Supported grant types (e.g. `["authorization_code", "refresh_token"]`).
    #[serde(default)]
    pub grant_types_supported: Vec<String>,
    /// Supported client authentication methods for the token endpoint.
    #[serde(default)]
    pub token_endpoint_auth_methods_supported: Vec<String>,
    /// Supported client authentication signing algorithms.
    #[serde(default)]
    pub token_endpoint_auth_signing_alg_values_supported: Vec<String>,
    /// Supported OAuth scopes (e.g. `["atproto"]`).
    #[serde(default)]
    pub scopes_supported: Vec<String>,
    /// Whether RFC 9207 `iss` response parameter is returned.
    #[serde(default)]
    pub authorization_response_iss_parameter_supported: bool,
    /// Whether client ID metadata document resolution is supported.
    #[serde(default)]
    pub client_id_metadata_document_supported: bool,
}

/// Fully discovered and validated OAuth endpoints bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveredAuthEndpoints {
    /// Authenticated subject DID.
    pub did: String,
    /// Verified account handle, if resolved from handle.
    pub handle: Option<String>,
    /// Resolved PDS origin URL.
    pub pds_endpoint: String,
    /// Authoritative Authorization Server issuer URL.
    pub auth_server_issuer: String,
    /// RFC 9126 PAR endpoint URL.
    pub par_endpoint: String,
    /// User authorization redirect endpoint URL.
    pub authorization_endpoint: String,
    /// Token exchange endpoint URL.
    pub token_endpoint: String,
    /// Supported DPoP signing algorithms.
    pub dpop_algs: Vec<String>,
    /// Supported OAuth scopes.
    pub scopes: Vec<String>,
    /// Complete RFC 9728 Protected Resource Metadata.
    pub protected_resource_metadata: ProtectedResourceMetadata,
    /// Complete RFC 8414 Authorization Server Metadata.
    pub auth_server_metadata: AuthorizationServerMetadata,
}

/// Checks whether a URL is an origin-only URL (scheme + host + optional non-default port, no path/query/fragment).
///
/// Rejects explicit default HTTPS port (`:443`) or explicit default HTTP port (`:80`),
/// as well as userinfo, paths (other than empty or `/`), query parameters, and fragments.
fn is_origin_only(url_str: &str) -> bool {
    if let Ok(parsed) = Url::parse(url_str) {
        let scheme = parsed.scheme();
        let host = parsed.host_str().unwrap_or("");
        let is_loopback =
            host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "[::1]";
        if scheme != "https" && !(scheme == "http" && is_loopback) {
            return false;
        }
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return false;
        }
        // The `url` crate normalizes default ports away (`port()` is `None` for explicit `:443`),
        // so detect the explicit spelling from the raw AUTHORITY segment; scanning only there
        // also avoids false positives from ports that merely contain ":443"/":80" (e.g. 44371).
        let after_scheme = url_str
            .split_once("://")
            .map(|(_, rest)| rest)
            .unwrap_or(url_str);
        let authority = after_scheme
            .split(['/', '?', '#'])
            .next()
            .unwrap_or(after_scheme);
        let host_port = authority.rsplit('@').next().unwrap_or(authority);
        let has_explicit_port = match host_port.rfind(']') {
            Some(bracket_end) => host_port[bracket_end..].contains(':'),
            None => host_port.contains(':'),
        };
        if has_explicit_port {
            // Parse the port numerically so leading-zero spellings (`:0443`, `:0080`)
            // match the default-port forms they normalize to; a non-numeric port fails
            // the origin check outright.
            let port_str = host_port.rsplit(':').next().unwrap_or("");
            match port_str.parse::<u16>() {
                Ok(443) if scheme == "https" => return false,
                Ok(80) if scheme == "http" => return false,
                Ok(_) => {}
                Err(_) => return false,
            }
        }
        if host_port.contains('\\') {
            return false;
        }
        let path = parsed.path();
        (path.is_empty() || path == "/") && parsed.query().is_none() && parsed.fragment().is_none()
    } else {
        false
    }
}

/// Normalizes a URL to its ASCII origin representation (or stripped base).
fn normalize_origin(url_str: &str) -> String {
    if let Ok(parsed) = Url::parse(url_str) {
        parsed.origin().ascii_serialization()
    } else {
        url_str.trim().trim_end_matches('/').to_string()
    }
}

/// Fetches and parses RFC 9728 Protected Resource Metadata from a PDS endpoint.
///
/// # Errors
/// - Returns [`DiscoveryError::MissingAuthorizationServers`] if the `authorization_servers` list is empty.
/// - Returns [`DiscoveryError::MultipleAuthorizationServers`] if more than 1 authorization server is listed.
/// - Returns [`DiscoveryError::InvalidAuthorizationServerUrl`] if the authorization server URL is not a valid origin.
/// - Returns [`DiscoveryError::ResourceMismatch`] if the `resource` field does not match the PDS endpoint origin.
/// - Returns [`DiscoveryError::ProtectedResourceDiscoveryFailed`] if the HTTP request or JSON parsing fails.
pub async fn fetch_protected_resource_metadata(
    ssrf_filter: &SsrfFilter,
    pds_endpoint: &str,
) -> Result<ProtectedResourceMetadata, DiscoveryError> {
    let url = format!(
        "{}/.well-known/oauth-protected-resource",
        pds_endpoint.trim_end_matches('/')
    );

    let meta: ProtectedResourceMetadata = ssrf_filter
        .safe_get_json(&url, MAX_OAUTH_RESPONSE_BYTES)
        .await
        .map_err(|e| match e {
            SsrfError::HttpStatus(status, msg) => DiscoveryError::ProtectedResourceDiscoveryFailed(
                format!("HTTP {status} fetching protected resource metadata from {url}: {msg}"),
            ),
            SsrfError::Json(err) => DiscoveryError::ProtectedResourceDiscoveryFailed(format!(
                "Invalid JSON in protected resource metadata from {url}: {err}"
            )),
            other => DiscoveryError::Ssrf(other),
        })?;

    // ATProto requires exactly one authorization server.
    if meta.authorization_servers.is_empty() {
        return Err(DiscoveryError::MissingAuthorizationServers(
            pds_endpoint.to_string(),
        ));
    }
    if meta.authorization_servers.len() > 1 {
        return Err(DiscoveryError::MultipleAuthorizationServers(
            meta.authorization_servers.len(),
        ));
    }

    let as_url = &meta.authorization_servers[0];
    if !is_origin_only(as_url) {
        return Err(DiscoveryError::InvalidAuthorizationServerUrl(
            as_url.clone(),
        ));
    }

    let expected_origin = normalize_origin(pds_endpoint);
    let actual_origin = normalize_origin(&meta.resource);
    if expected_origin != actual_origin {
        return Err(DiscoveryError::ResourceMismatch {
            expected: expected_origin,
            actual: meta.resource.clone(),
        });
    }
    // RFC 9728 identifiers for an origin-scoped resource are bare origins; a path
    // or query would make the declared identifier differ from the queried PDS and
    // is metadata-confusion signal, so it is rejected even at the same origin.
    let resource_parsed = Url::parse(&meta.resource).map_err(|e| {
        DiscoveryError::InvalidEndpointUrl(format!(
            "Invalid resource identifier '{}': {e}",
            meta.resource
        ))
    })?;
    if (resource_parsed.path() != "/" && !resource_parsed.path().is_empty())
        || resource_parsed.query().is_some()
        || resource_parsed.fragment().is_some()
    {
        return Err(DiscoveryError::ResourceMismatch {
            expected: expected_origin,
            actual: meta.resource.clone(),
        });
    }

    Ok(meta)
}

/// Fetches and parses RFC 8414 Authorization Server Metadata with OIDC fallback.
///
/// # Invariants
/// 1. Tries primary endpoint: `<auth_server>/.well-known/oauth-authorization-server`.
/// 2. If primary returns 404, falls back to: `<auth_server>/.well-known/openid-configuration`.
/// 3. Validates mandatory security invariants: `issuer` matching, `ES256` DPoP support,
///    `S256` PKCE challenge method, and non-empty PAR, token, and authorization endpoints.
///
/// # Errors
/// - Returns [`DiscoveryError::IssuerMismatch`] if `issuer` does not match `auth_server_url`.
/// - Returns [`DiscoveryError::MissingDpopAlgorithm`] if `ES256` is missing.
/// - Returns [`DiscoveryError::MissingPkceMethod`] if `S256` is missing.
/// - Returns [`DiscoveryError::MissingParEndpoint`] if PAR endpoint is missing.
pub async fn fetch_auth_server_metadata(
    ssrf_filter: &SsrfFilter,
    auth_server_url: &str,
) -> Result<AuthorizationServerMetadata, DiscoveryError> {
    let base = auth_server_url.trim_end_matches('/');
    let primary_url = format!("{base}/.well-known/oauth-authorization-server");

    let meta: AuthorizationServerMetadata = match ssrf_filter
        .safe_get_json(&primary_url, MAX_OAUTH_RESPONSE_BYTES)
        .await
    {
        Ok(m) => m,
        Err(SsrfError::HttpStatus(404, _)) => {
            let fallback_url = format!("{base}/.well-known/openid-configuration");
            ssrf_filter
                .safe_get_json(&fallback_url, MAX_OAUTH_RESPONSE_BYTES)
                .await
                .map_err(|e| match e {
                    SsrfError::HttpStatus(status, msg) => {
                        DiscoveryError::AuthServerDiscoveryFailed(format!(
                            "HTTP {status} fetching fallback authorization server metadata from {fallback_url}: {msg}"
                        ))
                    }
                    SsrfError::Json(err) => DiscoveryError::AuthServerDiscoveryFailed(format!(
                        "Invalid JSON in fallback authorization server metadata from {fallback_url}: {err}"
                    )),
                    other => DiscoveryError::Ssrf(other),
                })?
        }
        Err(SsrfError::HttpStatus(status, msg)) => {
            return Err(DiscoveryError::AuthServerDiscoveryFailed(format!(
                "HTTP {status} fetching authorization server metadata from {primary_url}: {msg}"
            )));
        }
        Err(SsrfError::Json(err)) => {
            return Err(DiscoveryError::AuthServerDiscoveryFailed(format!(
                "Invalid JSON in authorization server metadata from {primary_url}: {err}"
            )));
        }
        Err(other) => return Err(DiscoveryError::Ssrf(other)),
    };

    validate_auth_server_capabilities(&meta, auth_server_url)?;
    Ok(meta)
}

/// Validates security capabilities and invariant compliance on Authorization Server Metadata
/// according to the AT Protocol OAuth specification profile.
pub fn validate_auth_server_capabilities(
    meta: &AuthorizationServerMetadata,
    auth_server_url: &str,
) -> Result<(), DiscoveryError> {
    if !is_origin_only(auth_server_url) {
        return Err(DiscoveryError::InvalidAuthorizationServerUrl(
            auth_server_url.to_string(),
        ));
    }
    if !is_origin_only(&meta.issuer) {
        return Err(DiscoveryError::InvalidAuthorizationServerUrl(
            meta.issuer.clone(),
        ));
    }
    let expected_origin = normalize_origin(auth_server_url);
    let actual_origin = normalize_origin(&meta.issuer);
    if expected_origin != actual_origin {
        return Err(DiscoveryError::IssuerMismatch {
            expected: auth_server_url.to_string(),
            actual: meta.issuer.clone(),
        });
    }

    if meta.pushed_authorization_request_endpoint.trim().is_empty() {
        return Err(DiscoveryError::MissingParEndpoint(
            auth_server_url.to_string(),
        ));
    }
    if let Err(e) = Url::parse(&meta.pushed_authorization_request_endpoint) {
        return Err(DiscoveryError::InvalidEndpointUrl(format!(
            "Invalid PAR endpoint URL '{}': {e}",
            meta.pushed_authorization_request_endpoint
        )));
    }

    // ATProto profile mandates PAR.
    if !meta.require_pushed_authorization_requests {
        return Err(DiscoveryError::ParNotRequired(auth_server_url.to_string()));
    }

    if meta.token_endpoint.trim().is_empty() {
        return Err(DiscoveryError::MissingTokenEndpoint(
            auth_server_url.to_string(),
        ));
    }
    if let Err(e) = Url::parse(&meta.token_endpoint) {
        return Err(DiscoveryError::InvalidEndpointUrl(format!(
            "Invalid token endpoint URL '{}': {e}",
            meta.token_endpoint
        )));
    }

    if meta.authorization_endpoint.trim().is_empty() {
        return Err(DiscoveryError::MissingAuthorizationEndpoint(
            auth_server_url.to_string(),
        ));
    }
    if let Err(e) = Url::parse(&meta.authorization_endpoint) {
        return Err(DiscoveryError::InvalidEndpointUrl(format!(
            "Invalid authorization endpoint URL '{}': {e}",
            meta.authorization_endpoint
        )));
    }

    if !meta.response_types_supported.iter().any(|r| r == "code") {
        return Err(DiscoveryError::MissingResponseType(
            auth_server_url.to_string(),
        ));
    }

    if !meta
        .grant_types_supported
        .iter()
        .any(|g| g == "authorization_code")
    {
        return Err(DiscoveryError::MissingGrantType {
            auth_server: auth_server_url.to_string(),
            missing: "authorization_code".to_string(),
        });
    }
    if !meta
        .grant_types_supported
        .iter()
        .any(|g| g == "refresh_token")
    {
        return Err(DiscoveryError::MissingGrantType {
            auth_server: auth_server_url.to_string(),
            missing: "refresh_token".to_string(),
        });
    }

    // ATProto profile mandates both "none" and "private_key_jwt" auth methods.
    let has_none = meta
        .token_endpoint_auth_methods_supported
        .iter()
        .any(|m| m == "none");
    let has_private_key_jwt = meta
        .token_endpoint_auth_methods_supported
        .iter()
        .any(|m| m == "private_key_jwt");
    if !has_none || !has_private_key_jwt {
        return Err(DiscoveryError::MissingTokenAuthMethod(
            auth_server_url.to_string(),
        ));
    }

    if !meta
        .token_endpoint_auth_signing_alg_values_supported
        .iter()
        .any(|alg| alg == "ES256")
    {
        return Err(DiscoveryError::MissingTokenAuthSigningAlg(
            auth_server_url.to_string(),
        ));
    }
    if meta
        .token_endpoint_auth_signing_alg_values_supported
        .iter()
        .any(|alg| alg == "none")
    {
        return Err(DiscoveryError::InvalidTokenAuthSigningAlg(
            auth_server_url.to_string(),
        ));
    }

    if !meta.scopes_supported.iter().any(|s| s == "atproto") {
        return Err(DiscoveryError::MissingAtprotoScope(
            auth_server_url.to_string(),
        ));
    }

    // RFC 9207 `iss` is mandatory in the ATProto profile.
    if !meta.authorization_response_iss_parameter_supported {
        return Err(DiscoveryError::MissingIssParameterSupport(
            auth_server_url.to_string(),
        ));
    }

    if !meta.client_id_metadata_document_supported {
        return Err(DiscoveryError::MissingClientMetadataSupport(
            auth_server_url.to_string(),
        ));
    }

    if !meta
        .dpop_signing_alg_values_supported
        .iter()
        .any(|alg| alg == "ES256")
    {
        return Err(DiscoveryError::MissingDpopAlgorithm(
            auth_server_url.to_string(),
        ));
    }

    if !meta
        .code_challenge_methods_supported
        .iter()
        .any(|method| method == "S256")
    {
        return Err(DiscoveryError::MissingPkceMethod(
            auth_server_url.to_string(),
        ));
    }

    Ok(())
}

/// Executes the complete AT Protocol discovery pipeline for a user handle or DID.
///
/// # Multi-Stage Execution:
/// 1. Resolves identity (Handle -> DID -> DID Document, or DID -> DID Document).
/// 2. Verifies bidirectional handle linkage if a handle was provided.
/// 3. Extracts the authoritative `#atproto_pds` service endpoint.
/// 4. Fetches RFC 9728 Protected Resource Metadata from `<pds>/.well-known/oauth-protected-resource`.
/// 5. Selects the primary Authorization Server URL from `authorization_servers[0]`.
/// 6. Fetches and validates RFC 8414 Authorization Server Metadata.
/// 7. Returns fully assembled [`DiscoveredAuthEndpoints`].
pub async fn discover_oauth_endpoints(
    resolver: &IdentityResolver,
    did_or_handle: &str,
) -> Result<DiscoveredAuthEndpoints, DiscoveryError> {
    let identity = resolver.resolve_ident(did_or_handle).await?;

    let pds_meta =
        fetch_protected_resource_metadata(resolver.ssrf_filter(), &identity.pds_endpoint).await?;

    let auth_server_url = &pds_meta.authorization_servers[0];

    let as_meta = fetch_auth_server_metadata(resolver.ssrf_filter(), auth_server_url).await?;

    Ok(DiscoveredAuthEndpoints {
        did: identity.did,
        handle: identity.handle,
        pds_endpoint: identity.pds_endpoint,
        auth_server_issuer: as_meta.issuer.clone(),
        par_endpoint: as_meta.pushed_authorization_request_endpoint.clone(),
        authorization_endpoint: as_meta.authorization_endpoint.clone(),
        token_endpoint: as_meta.token_endpoint.clone(),
        dpop_algs: as_meta.dpop_signing_alg_values_supported.clone(),
        scopes: if !as_meta.scopes_supported.is_empty() {
            as_meta.scopes_supported.clone()
        } else if !pds_meta.scopes_supported.is_empty() {
            pds_meta.scopes_supported.clone()
        } else {
            vec!["atproto".to_string()]
        },
        protected_resource_metadata: pds_meta,
        auth_server_metadata: as_meta,
    })
}

impl IdentityResolver {
    /// Executes the full OAuth discovery pipeline for a user handle or DID.
    pub async fn discover_oauth_endpoints(
        &self,
        did_or_handle: &str,
    ) -> Result<DiscoveredAuthEndpoints, DiscoveryError> {
        discover_oauth_endpoints(self, did_or_handle).await
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]
mod tests {
    use super::*;

    fn valid_test_metadata() -> AuthorizationServerMetadata {
        AuthorizationServerMetadata {
            issuer: "https://auth.example.com".to_string(),
            authorization_endpoint: "https://auth.example.com/oauth/authorize".to_string(),
            token_endpoint: "https://auth.example.com/oauth/token".to_string(),
            pushed_authorization_request_endpoint: "https://auth.example.com/oauth/par".to_string(),
            require_pushed_authorization_requests: true,
            dpop_signing_alg_values_supported: vec!["ES256".to_string()],
            code_challenge_methods_supported: vec!["S256".to_string()],
            response_types_supported: vec!["code".to_string()],
            grant_types_supported: vec![
                "authorization_code".to_string(),
                "refresh_token".to_string(),
            ],
            token_endpoint_auth_methods_supported: vec![
                "none".to_string(),
                "private_key_jwt".to_string(),
            ],
            token_endpoint_auth_signing_alg_values_supported: vec!["ES256".to_string()],
            scopes_supported: vec!["atproto".to_string()],
            authorization_response_iss_parameter_supported: true,
            client_id_metadata_document_supported: true,
        }
    }

    #[test]
    fn test_validate_auth_server_capabilities_valid() {
        let meta = valid_test_metadata();
        assert!(validate_auth_server_capabilities(&meta, "https://auth.example.com").is_ok());
    }

    #[test]
    fn test_validate_auth_server_capabilities_missing_es256() {
        let meta = AuthorizationServerMetadata {
            dpop_signing_alg_values_supported: vec!["RS256".to_string()],
            ..valid_test_metadata()
        };

        assert!(matches!(
            validate_auth_server_capabilities(&meta, "https://auth.example.com"),
            Err(DiscoveryError::MissingDpopAlgorithm(_))
        ));
    }

    #[test]
    fn test_validate_auth_server_capabilities_missing_s256_pkce() {
        let meta = AuthorizationServerMetadata {
            code_challenge_methods_supported: vec!["plain".to_string()],
            ..valid_test_metadata()
        };

        assert!(matches!(
            validate_auth_server_capabilities(&meta, "https://auth.example.com"),
            Err(DiscoveryError::MissingPkceMethod(_))
        ));
    }

    #[test]
    fn test_validate_auth_server_capabilities_issuer_mismatch() {
        let meta = AuthorizationServerMetadata {
            issuer: "https://attacker.example.com".to_string(),
            ..valid_test_metadata()
        };

        assert!(matches!(
            validate_auth_server_capabilities(&meta, "https://auth.example.com"),
            Err(DiscoveryError::IssuerMismatch { .. })
        ));
    }

    #[test]
    fn test_validate_auth_server_capabilities_missing_token_auth_signing_alg() {
        let meta = AuthorizationServerMetadata {
            token_endpoint_auth_signing_alg_values_supported: vec!["RS256".to_string()],
            ..valid_test_metadata()
        };

        assert!(matches!(
            validate_auth_server_capabilities(&meta, "https://auth.example.com"),
            Err(DiscoveryError::MissingTokenAuthSigningAlg(_))
        ));
    }

    #[test]
    fn test_validate_auth_server_capabilities_invalid_token_auth_signing_alg_none() {
        let meta = AuthorizationServerMetadata {
            token_endpoint_auth_signing_alg_values_supported: vec![
                "ES256".to_string(),
                "none".to_string(),
            ],
            ..valid_test_metadata()
        };

        assert!(matches!(
            validate_auth_server_capabilities(&meta, "https://auth.example.com"),
            Err(DiscoveryError::InvalidTokenAuthSigningAlg(_))
        ));
    }

    #[test]
    fn test_validate_auth_server_capabilities_explicit_443_rejected() {
        let meta = AuthorizationServerMetadata {
            issuer: "https://auth.example.com:443".to_string(),
            ..valid_test_metadata()
        };

        assert!(matches!(
            validate_auth_server_capabilities(&meta, "https://auth.example.com"),
            Err(DiscoveryError::InvalidAuthorizationServerUrl(_))
        ));

        let valid_meta = valid_test_metadata();
        assert!(matches!(
            validate_auth_server_capabilities(&valid_meta, "https://auth.example.com:443"),
            Err(DiscoveryError::InvalidAuthorizationServerUrl(_))
        ));
    }

    #[test]
    fn test_is_origin_only_rejects_explicit_443() {
        assert!(is_origin_only("https://auth.example.com"));
        assert!(!is_origin_only("https://auth.example.com:443"));
        assert!(!is_origin_only("https://auth.example.com:443/"));
        assert!(is_origin_only("https://auth.example.com:8443"));
    }

    #[test]
    fn test_is_origin_only_rejects_leading_zero_and_malformed_ports() {
        // Leading-zero spellings normalize to the default port.
        assert!(!is_origin_only("https://auth.example.com:0443"));
        assert!(!is_origin_only("http://auth.example.com:0080"));
        // Non-numeric and malformed ports never form a valid origin.
        assert!(!is_origin_only("https://auth.example.com:not_a_port"));
        assert!(!is_origin_only("https://auth.example.com:443\\"));
        // A port that merely contains the default digits stays valid.
        assert!(is_origin_only("https://auth.example.com:44371"));
        assert!(is_origin_only("http://127.0.0.1:8080"));
    }

    #[test]
    fn test_is_origin_only_loopback_http_acceptance_boundaries() {
        assert!(is_origin_only("http://localhost"));
        assert!(is_origin_only("http://127.0.0.1"));
        assert!(is_origin_only("http://127.0.0.1:8080"));
        assert!(is_origin_only("http://[::1]:8080"));
        assert!(!is_origin_only("http://auth.example.com"));
        assert!(!is_origin_only("http://auth.example.com:80"));
        assert!(!is_origin_only("http://auth.example.com:8080"));
        assert!(!is_origin_only("http://127.0.0.2")); // near-loopback, not loopback
        assert!(!is_origin_only("http://user@127.0.0.1"));
        assert!(!is_origin_only("http://127.0.0.1/xrpc"));
        assert!(!is_origin_only("https://auth.example.com/?a=b"));
        assert!(!is_origin_only("https://auth.example.com/#frag"));
        assert!(is_origin_only("https://auth.example.com:8080"));
        assert!(is_origin_only("https://auth.example.com:44371"));
    }
}
