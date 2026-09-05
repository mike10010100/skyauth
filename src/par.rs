//! RFC 9126 Pushed Authorization Requests (PAR) and Authorization URL Builder.
//!
//! Implements back-channel authorization request pushing to the Authorization Server's
//! PAR endpoint with signed RFC 9449 DPoP proof headers and transparent auto-nonce retry.
//!
//! Reference: <https://datatracker.ietf.org/doc/html/rfc9126>

use serde::{Deserialize, Serialize};
use url::Url;

use crate::dpop::{extract_dpop_nonce, DPoPKey, DPoPNonceCache};
use crate::error::{AtprotoOAuthError, DPoPError, ParError};
use crate::ssrf::{read_bounded_body, SsrfFilter, MAX_OAUTH_RESPONSE_BYTES};

/// Parameters for an RFC 9126 Pushed Authorization Request.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParParameters {
    /// Canonical OAuth client ID (metadata URL or registered client identifier).
    pub client_id: String,
    /// OAuth redirect callback URI.
    pub redirect_uri: String,
    /// Space-separated requested OAuth scopes (e.g. `"atproto transition:generic"`).
    pub scope: String,
    /// Cryptographic state token for CSRF defense and session tracking.
    pub state: String,
    /// Derived S256 PKCE code challenge.
    pub code_challenge: String,
    /// PKCE code challenge transformation method (defaults to `"S256"`).
    pub code_challenge_method: String,
    /// OAuth response type (defaults to `"code"`).
    pub response_type: String,
    /// Optional user handle or DID login hint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub login_hint: Option<String>,
    /// Optional client assertion type for confidential clients.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_assertion_type: Option<String>,
    /// Optional client assertion JWT for confidential clients.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_assertion: Option<String>,
}

impl std::fmt::Debug for ParParameters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ParParameters")
            .field("client_id", &self.client_id)
            .field("redirect_uri", &self.redirect_uri)
            .field("scope", &self.scope)
            .field("state", &self.state)
            .field("code_challenge", &self.code_challenge)
            .field("code_challenge_method", &self.code_challenge_method)
            .field("response_type", &self.response_type)
            .field("login_hint", &self.login_hint)
            .field("client_assertion_type", &self.client_assertion_type)
            .field(
                "client_assertion",
                &self.client_assertion.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

impl ParParameters {
    /// Creates a new `ParParameters` with mandatory OAuth 2.1 parameters.
    #[must_use]
    pub fn new(
        client_id: impl Into<String>,
        redirect_uri: impl Into<String>,
        scope: impl Into<String>,
        state: impl Into<String>,
        code_challenge: impl Into<String>,
    ) -> Self {
        Self {
            client_id: client_id.into(),
            redirect_uri: redirect_uri.into(),
            scope: scope.into(),
            state: state.into(),
            code_challenge: code_challenge.into(),
            code_challenge_method: "S256".to_string(),
            response_type: "code".to_string(),
            login_hint: None,
            client_assertion_type: None,
            client_assertion: None,
        }
    }

    /// Sets the optional `login_hint` parameter (user handle or DID).
    #[must_use]
    pub fn with_login_hint(mut self, login_hint: impl Into<String>) -> Self {
        self.login_hint = Some(login_hint.into());
        self
    }

    /// Sets optional client assertion parameters for confidential client authentication.
    #[must_use]
    pub fn with_client_assertion(
        mut self,
        assertion_type: impl Into<String>,
        assertion: impl Into<String>,
    ) -> Self {
        self.client_assertion_type = Some(assertion_type.into());
        self.client_assertion = Some(assertion.into());
        self
    }

    /// Single source of truth for the PAR parameter set. Any new RFC 9126 field
    /// must be added here exactly once, so the two public serializers cannot drift.
    fn encode_pairs<'a>(&'a self, serializer: &mut url::form_urlencoded::Serializer<'a, String>) {
        serializer.append_pair("client_id", &self.client_id);
        serializer.append_pair("response_type", &self.response_type);
        serializer.append_pair("redirect_uri", &self.redirect_uri);
        serializer.append_pair("scope", &self.scope);
        serializer.append_pair("state", &self.state);
        serializer.append_pair("code_challenge", &self.code_challenge);
        serializer.append_pair("code_challenge_method", &self.code_challenge_method);

        if let Some(ref hint) = self.login_hint {
            serializer.append_pair("login_hint", hint);
        }
        if let Some(ref cat) = self.client_assertion_type {
            serializer.append_pair("client_assertion_type", cat);
        }
        if let Some(ref ca) = self.client_assertion {
            serializer.append_pair("client_assertion", ca);
        }
    }

    /// Serializes the parameters into standard `application/x-www-form-urlencoded` format.
    #[must_use]
    pub fn to_form_urlencoded(&self) -> String {
        let mut serializer = url::form_urlencoded::Serializer::new(String::new());
        self.encode_pairs(&mut serializer);
        serializer.finish()
    }
}

/// Parsed response from an RFC 9126 Pushed Authorization Request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParResponse {
    /// The authorization request URI issued by the authorization server.
    ///
    /// Must conform to `urn:ietf:params:oauth:request_uri:<unique_value>`.
    pub request_uri: String,
    /// Request URI lifetime in seconds (typically 60-90 seconds).
    pub expires_in: u64,
}

/// Constructs the browser authorization redirect URL from authorization endpoint, client ID, and request URI.
///
/// Format: `<authorization_endpoint>?client_id=<encoded_client_id>&request_uri=<encoded_request_uri>`
///
/// Preserves any existing query parameters already present on `authorization_endpoint`.
///
/// # Errors
///
/// Returns [`ParError::InvalidEndpoint`] if `authorization_endpoint` cannot be parsed as a URL.
pub fn build_authorization_url(
    authorization_endpoint: &str,
    client_id: &str,
    request_uri: &str,
) -> Result<Url, AtprotoOAuthError> {
    let mut url = Url::parse(authorization_endpoint).map_err(|e| {
        ParError::InvalidEndpoint(format!(
            "Invalid authorization endpoint '{authorization_endpoint}': {e}"
        ))
    })?;

    url.query_pairs_mut()
        .append_pair("client_id", client_id)
        .append_pair("request_uri", request_uri);

    Ok(url)
}

/// Executes an RFC 9126 PAR request with DPoP signing and transparent auto-nonce retry.
///
/// # Flow
/// 1. Validates the PAR endpoint URL against the SSRF filter.
/// 2. Extracts existing cached DPoP nonce for the authorization server origin.
/// 3. Signs an RFC 9449 DPoP proof for `POST <par_endpoint>`.
/// 4. Dispatches the HTTP POST request with `Content-Type: application/x-www-form-urlencoded`.
/// 5. Updates the nonce cache if a `DPoP-Nonce` header is returned.
/// 6. If the response returns HTTP 400 with `error: "use_dpop_nonce"`, intercepts `DPoP-Nonce`,
///    regenerates the DPoP proof with a fresh nonce and fresh `jti`, and retries once.
/// 7. Parses and validates the returned [`ParResponse`].
///
/// # Errors
///
/// Returns [`AtprotoOAuthError`] if SSRF validation, DPoP signing, HTTP transport,
/// or response parsing fails.
pub async fn execute_par_request(
    ssrf_filter: &SsrfFilter,
    par_endpoint: &str,
    params: &ParParameters,
    dpop_key: &DPoPKey,
    nonce_cache: &DPoPNonceCache,
) -> Result<ParResponse, AtprotoOAuthError> {
    let parsed_url = Url::parse(par_endpoint).map_err(|e| {
        ParError::InvalidEndpoint(format!("Invalid PAR endpoint URL '{par_endpoint}': {e}"))
    })?;

    let (client, _pinned_addr, host_header) = ssrf_filter
        .build_pinned_client(&parsed_url)
        .await
        .map_err(ParError::from)?;

    let server_origin = parsed_url.origin().ascii_serialization();

    let form_body = params.to_form_urlencoded();

    let initial_nonce = nonce_cache.get_nonce(&server_origin);
    let proof = dpop_key.create_proof("POST", par_endpoint, initial_nonce.as_deref(), None)?;

    let resp = client
        .post(par_endpoint)
        .header(reqwest::header::HOST, host_header.clone())
        .header("content-type", "application/x-www-form-urlencoded")
        .header("accept", "application/json")
        .header("dpop", proof)
        .body(form_body.clone())
        .send()
        .await
        .map_err(|e| ParError::Http(e.to_string()))?;

    // Cache the returned DPoP nonce so later requests to this origin don't re-trigger the challenge.
    if let Some(new_nonce) = extract_dpop_nonce(
        resp.headers()
            .get("dpop-nonce")
            .and_then(|h| h.to_str().ok()),
    ) {
        nonce_cache.set_nonce(&server_origin, new_nonce);
    }

    let status = resp.status();

    // PAR endpoints must not be followed through redirects (RFC 9126).
    if status.is_redirection() {
        return Err(ParError::RequestFailed {
            status: status.as_u16(),
            error: "invalid_request".to_string(),
            description: Some("Redirects are not permitted for PAR endpoints".to_string()),
        }
        .into());
    }

    // The server answered 400/401 with `use_dpop_nonce`: replay with the fresh nonce.
    if status == reqwest::StatusCode::BAD_REQUEST || status == reqwest::StatusCode::UNAUTHORIZED {
        let resp_bytes = read_bounded_body(resp, MAX_OAUTH_RESPONSE_BYTES)
            .await
            .map_err(|e| ParError::Http(e.to_string()))?;

        let json_err: Option<serde_json::Value> = serde_json::from_slice(&resp_bytes).ok();
        let is_nonce_error = json_err
            .as_ref()
            .and_then(|j| j.get("error"))
            .and_then(|e| e.as_str())
            == Some("use_dpop_nonce");

        if is_nonce_error {
            let fresh_nonce =
                nonce_cache
                    .get_nonce(&server_origin)
                    .ok_or_else(|| ParError::RequestFailed {
                        status: status.as_u16(),
                        error: "use_dpop_nonce".to_string(),
                        description: Some(
                            "Missing DPoP-Nonce header in challenge response".to_string(),
                        ),
                    })?;

            let retry_proof =
                dpop_key.create_proof("POST", par_endpoint, Some(&fresh_nonce), None)?;

            let (retry_client, _retry_pinned_addr, retry_host_header) = ssrf_filter
                .build_pinned_client(&parsed_url)
                .await
                .map_err(ParError::from)?;

            let retry_resp = retry_client
                .post(par_endpoint)
                .header(reqwest::header::HOST, retry_host_header)
                .header("content-type", "application/x-www-form-urlencoded")
                .header("accept", "application/json")
                .header("dpop", retry_proof)
                .body(form_body)
                .send()
                .await
                .map_err(|e| ParError::Http(e.to_string()))?;

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
                return Err(ParError::RequestFailed {
                    status: retry_status.as_u16(),
                    error: "invalid_request".to_string(),
                    description: Some("Redirects are not permitted for PAR endpoints".to_string()),
                }
                .into());
            }

            if retry_status.is_success() {
                // Same profile enforcement on the retry response (review H2).
                crate::dpop::require_dpop_nonce(retry_resp.headers()).map_err(ParError::from)?;
                let body_bytes = read_bounded_body(retry_resp, MAX_OAUTH_RESPONSE_BYTES)
                    .await
                    .map_err(|e| ParError::Http(e.to_string()))?;
                return parse_par_response(&body_bytes);
            }

            let err_bytes = read_bounded_body(retry_resp, MAX_OAUTH_RESPONSE_BYTES)
                .await
                .map_err(|e| ParError::Http(e.to_string()))?;
            let err_json: Option<serde_json::Value> = serde_json::from_slice(&err_bytes).ok();
            if err_json
                .as_ref()
                .and_then(|j| j.get("error"))
                .and_then(|e| e.as_str())
                == Some("use_dpop_nonce")
            {
                return Err(DPoPError::NonceRetryLimitExceeded.into());
            }

            let (error_code, error_desc) = parse_par_error_fields(err_json.as_ref());

            return Err(ParError::RequestFailed {
                status: retry_status.as_u16(),
                error: error_code,
                description: error_desc,
            }
            .into());
        }

        let (error_code, error_desc) = parse_par_error_fields(json_err.as_ref());

        return Err(ParError::RequestFailed {
            status: status.as_u16(),
            error: error_code,
            description: error_desc,
        }
        .into());
    }

    if !status.is_success() {
        let err_bytes = read_bounded_body(resp, MAX_OAUTH_RESPONSE_BYTES)
            .await
            .map_err(|e| ParError::Http(e.to_string()))?;
        let err_json: Option<serde_json::Value> = serde_json::from_slice(&err_bytes).ok();
        let error_code = err_json
            .as_ref()
            .and_then(|j| j.get("error"))
            .and_then(|e| e.as_str())
            .unwrap_or("par_request_failed")
            .to_string();
        let error_desc = err_json
            .as_ref()
            .and_then(|j| j.get("error_description"))
            .and_then(|d| d.as_str())
            .map(ToString::to_string);

        return Err(ParError::RequestFailed {
            status: status.as_u16(),
            error: error_code,
            description: error_desc,
        }
        .into());
    }

    // ATProto profile (review H2): a PAR response to a DPoP-authenticated request
    // MUST carry a DPoP-Nonce; refuse to continue with a server that omits it.
    crate::dpop::require_dpop_nonce(resp.headers()).map_err(ParError::from)?;

    let body_bytes = read_bounded_body(resp, MAX_OAUTH_RESPONSE_BYTES)
        .await
        .map_err(|e| ParError::Http(e.to_string()))?;
    parse_par_response(&body_bytes)
}

fn parse_par_response(bytes: &[u8]) -> Result<ParResponse, AtprotoOAuthError> {
    let parsed: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| ParError::Json(e.to_string()))?;

    let request_uri = parsed
        .get("request_uri")
        .and_then(|v| v.as_str())
        .ok_or(ParError::MissingField("request_uri"))?
        .to_string();

    if request_uri.trim().is_empty() {
        return Err(ParError::InvalidRequestUri("Empty request_uri".to_string()).into());
    }

    let expires_in = parsed
        .get("expires_in")
        .and_then(|v| v.as_u64())
        .ok_or(ParError::MissingField("expires_in"))?;

    Ok(ParResponse {
        request_uri,
        expires_in,
    })
}

/// Extracts `(error_code, error_description)` from a PAR error body, defaulting
/// the code to `par_request_failed` when the body carries no `error` field
/// (review L12: this extraction was duplicated three times).
fn parse_par_error_fields(json: Option<&serde_json::Value>) -> (String, Option<String>) {
    let error_code = json
        .as_ref()
        .and_then(|j| j.get("error"))
        .and_then(|e| e.as_str())
        .unwrap_or("par_request_failed")
        .to_string();
    let error_desc = json
        .as_ref()
        .and_then(|j| j.get("error_description"))
        .and_then(|d| d.as_str())
        .map(ToString::to_string);
    (error_code, error_desc)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]
mod tests {
    use super::*;

    #[test]
    fn test_par_parameters_form_encoding() {
        let params = ParParameters::new(
            "https://app.example.com/client.json",
            "https://app.example.com/callback",
            "atproto transition:generic",
            "state_random_123",
            "pkce_challenge_456",
        )
        .with_login_hint("alice.bsky.social");

        let encoded = params.to_form_urlencoded();
        assert!(encoded.contains("client_id=https%3A%2F%2Fapp.example.com%2Fclient.json"));
        assert!(encoded.contains("response_type=code"));
        assert!(encoded.contains("redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback"));
        assert!(encoded.contains("scope=atproto+transition%3Ageneric"));
        assert!(encoded.contains("state=state_random_123"));
        assert!(encoded.contains("code_challenge=pkce_challenge_456"));
        assert!(encoded.contains("code_challenge_method=S256"));
        assert!(encoded.contains("login_hint=alice.bsky.social"));
    }

    #[test]
    fn test_build_authorization_url_valid() {
        let auth_ep = "https://auth.example.com/oauth/authorize";
        let client_id = "https://app.example.com/client.json";
        let request_uri = "urn:ietf:params:oauth:request_uri:req-12345";

        let url = build_authorization_url(auth_ep, client_id, request_uri).unwrap();
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host_str(), Some("auth.example.com"));
        assert_eq!(url.path(), "/oauth/authorize");

        let pairs: Vec<(String, String)> = url
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        assert!(pairs.contains(&("client_id".to_string(), client_id.to_string())));
        assert!(pairs.contains(&("request_uri".to_string(), request_uri.to_string())));
    }

    #[test]
    fn test_build_authorization_url_preserves_query() {
        let auth_ep = "https://auth.example.com/oauth/authorize?existing=value";
        let client_id = "https://app.example.com/client.json";
        let request_uri = "urn:ietf:params:oauth:request_uri:req-12345";

        let url = build_authorization_url(auth_ep, client_id, request_uri).unwrap();
        assert!(url.as_str().contains("existing=value"));
        assert!(url.as_str().contains("client_id="));
        assert!(url.as_str().contains("request_uri="));
    }

    #[test]
    fn test_parse_par_response_valid() {
        let raw = br#"{"request_uri":"urn:ietf:params:oauth:request_uri:abc","expires_in":90}"#;
        let res = parse_par_response(raw).unwrap();
        assert_eq!(res.request_uri, "urn:ietf:params:oauth:request_uri:abc");
        assert_eq!(res.expires_in, 90);
    }

    #[test]
    fn test_parse_par_response_missing_fields() {
        let missing_exp = br#"{"request_uri":"urn:ietf:params:oauth:request_uri:abc"}"#;
        assert!(matches!(
            parse_par_response(missing_exp),
            Err(AtprotoOAuthError::Par(ParError::MissingField("expires_in")))
        ));

        let missing_uri = br#"{"expires_in":90}"#;
        assert!(matches!(
            parse_par_response(missing_uri),
            Err(AtprotoOAuthError::Par(ParError::MissingField(
                "request_uri"
            )))
        ));
    }
}
