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

use super::{
    client_metadata_payload, AuthenticatedUser, OAuthCallbackQuery, OAuthSessionExtension,
};
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
        // First check for session extension injected by Tower middleware
        if let Some(ext) = parts.extensions.get::<OAuthSessionExtension>() {
            return Ok(ext.user.clone());
        }

        if let Some(user) = parts.extensions.get::<AuthenticatedUser>() {
            return Ok(user.clone());
        }

        // Fallback: Check if Authorization header is present
        if let Some(auth_header) = parts.headers.get(header::AUTHORIZATION) {
            if let Ok(auth_str) = auth_header.to_str() {
                if !auth_str.starts_with("DPoP ") && !auth_str.starts_with("dpop ") {
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
    let payload = client_metadata_payload(metadata);

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
        .header(header::LOCATION, auth_req.authorization_url().as_str())
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

        assert_eq!(query.expose_code(), Some("test_code_123"));
        assert_eq!(query.expose_state(), Some("test_state_456"));
        assert_eq!(query.issuer(), Some("https://auth.example.com"));

        let params = query.to_callback_params().unwrap();
        assert_eq!(params.expose_code(), "test_code_123");
        assert_eq!(params.expose_state(), "test_state_456");
        assert_eq!(params.issuer(), Some("https://auth.example.com"));
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

        assert_eq!(query.error_code(), Some("access_denied"));
        assert!(matches!(
            query.to_callback_params(),
            Err(IntegrationError::OAuthError { .. })
        ));
    }

    #[tokio::test]
    async fn test_axum_authenticated_user_from_extensions() {
        let user = AuthenticatedUser::new("did:plc:alice123", "jkt_alice_thumbprint");
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
        let auth_req = AuthorizationRequest::new(
            url.clone(),
            "state_123",
            "urn:ietf:params:oauth:request_uri:123",
            300,
        )
        .unwrap();

        let resp = redirect_to_authorization(&auth_req).unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(resp.headers().get(header::LOCATION).unwrap(), url.as_str());
    }
}
