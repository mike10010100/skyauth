//! Axum 0.7 extractors, response helpers, and middleware for AT Protocol OAuth.
//!
//! Provides idiomatic Axum integration including:
//! - [`OAuthCallbackQuery`]: Extracting and validating OAuth redirect callback query parameters.
//! - [`AuthenticatedUser`]: Extracting authenticated session credentials from request extensions.
//! - [`client_metadata_response`]: Generating compliant `/oauth/client-metadata.json` HTTP responses.
//! - [`redirect_to_authorization`]: Generating HTTP 303 See Other redirects to authorization servers.

use axum::async_trait;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::{header, StatusCode};
use axum::response::Response;
use axum::Json;
use serde_json::json;

use super::{AuthenticatedUser, OAuthCallbackQuery, OAuthSessionExtension};
use crate::client::{AuthorizationRequest, OAuthClientMetadata};
use crate::error::IntegrationError;

#[async_trait]
impl<S> FromRequestParts<S> for OAuthCallbackQuery
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, Json<serde_json::Value>);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let query_str = parts.uri.query().unwrap_or("");
        serde_urlencoded::from_str(query_str).map_err(|err| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "invalid_request",
                    "error_description": format!("Malformed OAuth callback query parameters: {err}")
                })),
            )
        })
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for AuthenticatedUser
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, Json<serde_json::Value>);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // OAuthSessionExtension is injected by the Tower middleware; it takes precedence over a bare AuthenticatedUser.
        if let Some(ext) = parts.extensions.get::<OAuthSessionExtension>() {
            return Ok(ext.user.clone());
        }

        if let Some(user) = parts.extensions.get::<AuthenticatedUser>() {
            return Ok(user.clone());
        }

        if let Some(auth_header) = parts.headers.get(header::AUTHORIZATION) {
            if let Ok(auth_str) = auth_header.to_str() {
                // RFC 7235 § 2.1: the auth-scheme token is case-insensitive.
                // (Mutation-killer: the previous exact-prefix check rejected
                // e.g. `DpOp <token>`, which the Tower middleware accepts.)
                let scheme_ok = auth_str
                    .split_once(' ')
                    .is_some_and(|(scheme, _)| scheme.eq_ignore_ascii_case("DPoP"));
                if !scheme_ok {
                    return Err((
                        StatusCode::UNAUTHORIZED,
                        Json(json!({
                            "error": "invalid_token",
                            "error_description": "Invalid Authorization scheme: expected 'DPoP'"
                        })),
                    ));
                }
            }
        }

        Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "unauthorized",
                "error_description": "Missing authenticated session extension or credentials"
            })),
        ))
    }
}

/// Generates an HTTP 200 OK response serving the OAuth Client Metadata Document.
///
/// Sets `Content-Type: application/json` and `Access-Control-Allow-Origin: *` as required
/// by the AT Protocol OAuth client specification.
///
/// # Errors
///
/// Returns [`IntegrationError::Internal`] if metadata serialization or response creation fails.
pub fn client_metadata_response(
    metadata: &OAuthClientMetadata,
) -> Result<Response, IntegrationError> {
    let redirect_uris = [metadata.redirect_uri.clone()];
    let grant_types = [
        "authorization_code".to_string(),
        "refresh_token".to_string(),
    ];
    let response_types = ["code".to_string()];

    // Review M7: absent optional fields must be OMITTED (not serialized as
    // JSON null, which fails the client-metadata schema).
    let mut payload = serde_json::Map::new();
    payload.insert(
        "client_id".to_string(),
        serde_json::Value::String(metadata.client_id.clone()),
    );
    if let Some(name) = &metadata.client_name {
        payload.insert(
            "client_name".to_string(),
            serde_json::Value::String(name.clone()),
        );
    }
    payload.insert(
        "client_uri".to_string(),
        serde_json::Value::String(metadata.client_id.clone()),
    );
    payload.insert(
        "redirect_uris".to_string(),
        serde_json::Value::Array(
            redirect_uris
                .iter()
                .map(|u| serde_json::Value::String(u.clone()))
                .collect(),
        ),
    );
    payload.insert(
        "grant_types".to_string(),
        serde_json::Value::Array(
            grant_types
                .iter()
                .map(|g| serde_json::Value::String(g.clone()))
                .collect(),
        ),
    );
    payload.insert(
        "response_types".to_string(),
        serde_json::Value::Array(
            response_types
                .iter()
                .map(|r| serde_json::Value::String(r.clone()))
                .collect(),
        ),
    );
    payload.insert(
        "scope".to_string(),
        serde_json::Value::String(metadata.scope.clone()),
    );
    // ATProto OAuth profile: only public clients (`none`) are supported;
    // confidential clients use private_key_jwt, not shared secrets (review H1).
    payload.insert(
        "token_endpoint_auth_method".to_string(),
        serde_json::Value::String("none".to_string()),
    );
    payload.insert(
        "dpop_bound_access_tokens".to_string(),
        serde_json::Value::Bool(true),
    );
    let payload = serde_json::Value::Object(payload);

    let json_bytes = serde_json::to_vec(&payload).map_err(|e| {
        IntegrationError::Internal(format!("Failed to serialize client metadata: {e}"))
    })?;

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
        .body(axum::body::Body::from(json_bytes))
        .map_err(|e| {
            IntegrationError::Internal(format!("Failed to construct metadata response: {e}"))
        })
}

/// Generates an HTTP 303 See Other response redirecting the user agent to the Authorization Server.
///
/// # Errors
///
/// Returns [`IntegrationError::Internal`] if response construction fails.
pub fn redirect_to_authorization(
    auth_req: &AuthorizationRequest,
) -> Result<Response, IntegrationError> {
    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(header::LOCATION, auth_req.authorization_url.as_str())
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::PRAGMA, "no-cache")
        .body(axum::body::Body::empty())
        .map_err(|e| {
            IntegrationError::Internal(format!("Failed to construct redirect response: {e}"))
        })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]
mod tests {
    use super::*;
    use axum::http::Request;
    use url::Url;

    #[tokio::test]
    async fn test_axum_callback_query_extractor_success() {
        let req = Request::builder()
            .uri("/oauth/callback?code=test_code_123&state=test_state_456&iss=https%3A%2F%2Fauth.example.com")
            .body(axum::body::Body::empty())
            .unwrap();

        let (mut parts, _) = req.into_parts();
        let query = OAuthCallbackQuery::from_request_parts(&mut parts, &())
            .await
            .unwrap();

        assert_eq!(query.code.as_deref(), Some("test_code_123"));
        assert_eq!(query.state.as_deref(), Some("test_state_456"));
        assert_eq!(query.iss.as_deref(), Some("https://auth.example.com"));

        let params = query.to_callback_params().unwrap();
        assert_eq!(params.code, "test_code_123");
        assert_eq!(params.state, "test_state_456");
        assert_eq!(params.iss.as_deref(), Some("https://auth.example.com"));
    }

    #[tokio::test]
    async fn test_axum_callback_query_extractor_error() {
        let req = Request::builder()
            .uri("/oauth/callback?error=access_denied&error_description=The+user+cancelled+login")
            .body(axum::body::Body::empty())
            .unwrap();

        let (mut parts, _) = req.into_parts();
        let query = OAuthCallbackQuery::from_request_parts(&mut parts, &())
            .await
            .unwrap();

        assert_eq!(query.error.as_deref(), Some("access_denied"));
        assert!(matches!(
            query.to_callback_params(),
            Err(IntegrationError::OAuthError { .. })
        ));
    }

    #[tokio::test]
    async fn test_axum_authenticated_user_from_extensions() {
        let user =
            AuthenticatedUser::new("did:plc:alice123", "at_alice_token", "jkt_alice_thumbprint");
        let ext = OAuthSessionExtension::new(user.clone());

        let mut req = Request::builder()
            .uri("/api/profile")
            .body(axum::body::Body::empty())
            .unwrap();
        req.extensions_mut().insert(ext);

        let (mut parts, _) = req.into_parts();
        let extracted = AuthenticatedUser::from_request_parts(&mut parts, &())
            .await
            .unwrap();

        assert_eq!(extracted.did, "did:plc:alice123");
        assert_eq!(extracted.access_token, "at_alice_token");
        assert_eq!(extracted.dpop_thumbprint, "jkt_alice_thumbprint");
    }

    #[test]
    fn test_axum_client_metadata_response_format() {
        let metadata = OAuthClientMetadata::new(
            "https://app.example.com/oauth/client-metadata.json",
            "https://app.example.com/oauth/callback",
        )
        .with_client_name("Example App")
        .with_scope("atproto transition:generic");

        let resp = client_metadata_response(&metadata).unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        assert_eq!(
            resp.headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap(),
            "*"
        );
    }

    #[test]
    fn test_axum_redirect_to_authorization() {
        let url = Url::parse("https://auth.example.com/oauth/authorize?client_id=test&request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3A123").unwrap();
        let stored_state = crate::client::StoredStateEntry {
            state: "state_123".to_string(),
            client_id: "test".to_string(),
            code_verifier: "pkce_123".to_string(),
            dpop_key: crate::dpop::DPoPKey::generate(),
            issuer: "https://auth.example.com".to_string(),
            did: None,
            handle: None,
            redirect_uri: "https://app.example.com/callback".to_string(),
            pds_endpoint: "https://pds.example.com".to_string(),
            token_endpoint: "https://auth.example.com/token".to_string(),
            scopes: "atproto".to_string(),
            created_at: std::time::SystemTime::now(),
            expires_in_secs: 300,
        };
        let auth_req = AuthorizationRequest {
            authorization_url: url.clone(),
            state: "state_123".to_string(),
            request_uri: "urn:ietf:params:oauth:request_uri:123".to_string(),
            expires_in: 300,
            stored_state,
        };

        let resp = redirect_to_authorization(&auth_req).unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(resp.headers().get(header::LOCATION).unwrap(), url.as_str());
    }
}

/// Mutation-killer regression tests (2026-09-07 mutation sweep: the
/// `&&`-to-`||` mutant in the scheme check survived — no test presented a
/// lowercase `dpop ` Authorization header, which the mutant would reject).
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]
mod mutation_killer_tests {
    use super::*;
    use axum::extract::FromRequestParts;
    use axum::http::{Request, StatusCode};

    #[tokio::test]
    async fn killer_lowercase_dpop_scheme_is_accepted() {
        // A lowercase `dpop ` scheme (RFC 7235: auth-scheme is
        // case-insensitive) with no session extension falls through to the
        // scheme check and must NOT be rejected as an invalid scheme —
        // the final error is "unauthorized" (no extension), not
        // "invalid_token" (bad scheme).
        let req = Request::builder()
            .uri("/api/profile")
            .header(header::AUTHORIZATION, "dpop some_token")
            .body(axum::body::Body::empty())
            .unwrap();
        let (mut parts, _) = req.into_parts();
        let err = AuthenticatedUser::from_request_parts(&mut parts, &())
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
        assert_eq!(
            err.1["error"], "unauthorized",
            "lowercase dpop scheme must pass the scheme check"
        );

        // Mixed case must also pass the scheme check.
        let req_mixed = Request::builder()
            .uri("/api/profile")
            .header(header::AUTHORIZATION, "DpOp some_token")
            .body(axum::body::Body::empty())
            .unwrap();
        let (mut parts2, _) = req_mixed.into_parts();
        let err2 = AuthenticatedUser::from_request_parts(&mut parts2, &())
            .await
            .unwrap_err();
        assert_eq!(
            err2.1["error"], "unauthorized",
            "mixed-case dpop scheme must pass the scheme check"
        );

        // Sanity: a Bearer header still IS rejected as invalid scheme.
        let req_bearer = Request::builder()
            .uri("/api/profile")
            .header(header::AUTHORIZATION, "Bearer tok")
            .body(axum::body::Body::empty())
            .unwrap();
        let (mut parts3, _) = req_bearer.into_parts();
        let err3 = AuthenticatedUser::from_request_parts(&mut parts3, &())
            .await
            .unwrap_err();
        assert_eq!(err3.1["error"], "invalid_token");
    }
}
