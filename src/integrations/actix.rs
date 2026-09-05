//! Actix-web extractors and HTTP response generators for AT Protocol OAuth.
//!
//! Provides:
//! - [`OAuthCallbackQuery`]: Actix [`actix_web::FromRequest`] extractor for callback query parameters.
//! - [`AuthenticatedUser`]: Actix [`actix_web::FromRequest`] extractor for authenticated user sessions.
//! - [`client_metadata_http_response`]: Generates Actix [`actix_web::HttpResponse`] serving `/oauth/client-metadata.json`.
//! - [`redirect_to_authorization_http_response`]: Generates Actix [`actix_web::HttpResponse`] redirecting to the Authorization Server.

use std::future::{ready, Ready};

use actix_web::dev::Payload;
use actix_web::error::{ErrorBadRequest, ErrorUnauthorized};
use actix_web::http::header;
use actix_web::{Error, FromRequest, HttpMessage, HttpRequest, HttpResponse};
use serde_json::json;

use super::{AuthenticatedUser, OAuthCallbackQuery, OAuthSessionExtension};
use crate::client::{AuthorizationRequest, OAuthClientMetadata};
use crate::error::IntegrationError;

impl FromRequest for OAuthCallbackQuery {
    type Error = Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let query_str = req.query_string();
        match serde_urlencoded::from_str(query_str) {
            Ok(query) => ready(Ok(query)),
            Err(err) => ready(Err(ErrorBadRequest(format!(
                "Malformed OAuth callback query parameters: {err}"
            )))),
        }
    }
}

impl FromRequest for AuthenticatedUser {
    type Error = Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        // OAuthSessionExtension is injected by the Tower middleware; it takes precedence over a bare AuthenticatedUser.
        let extensions = req.extensions();
        if let Some(ext) = extensions.get::<OAuthSessionExtension>() {
            return ready(Ok(ext.user.clone()));
        }

        if let Some(user) = extensions.get::<AuthenticatedUser>() {
            return ready(Ok(user.clone()));
        }

        if let Some(auth_header) = req.headers().get(header::AUTHORIZATION) {
            if let Ok(auth_str) = auth_header.to_str() {
                if !auth_str.starts_with("DPoP ") && !auth_str.starts_with("dpop ") {
                    return ready(Err(ErrorUnauthorized(
                        "Invalid Authorization scheme: expected 'DPoP'",
                    )));
                }
            }
        }

        ready(Err(ErrorUnauthorized(
            "Missing authenticated session extension or credentials",
        )))
    }
}

/// Generates an Actix [`HttpResponse`] serving the OAuth Client Metadata Document.
///
/// Sets `Content-Type: application/json` and `Access-Control-Allow-Origin: *`.
///
/// # Errors
///
/// Returns [`IntegrationError::Internal`] if JSON serialization fails.
pub fn client_metadata_http_response(
    metadata: &OAuthClientMetadata,
) -> Result<HttpResponse, IntegrationError> {
    let redirect_uris = vec![metadata.redirect_uri.clone()];
    let grant_types = vec![
        "authorization_code".to_string(),
        "refresh_token".to_string(),
    ];
    let response_types = vec!["code".to_string()];

    let payload = json!({
        "client_id": metadata.client_id,
        "client_name": metadata.client_name,
        "client_uri": metadata.client_id,
        "redirect_uris": redirect_uris,
        "grant_types": grant_types,
        "response_types": response_types,
        "scope": metadata.scope,
        // ATProto OAuth profile: only public clients (`none`) are supported;
        // confidential clients use private_key_jwt, not shared secrets (review H1).
        "token_endpoint_auth_method": "none",
        "dpop_bound_access_tokens": true
    });

    let json_string = serde_json::to_string(&payload)
        .map_err(|e| IntegrationError::Internal(format!("Failed to serialize metadata: {e}")))?;

    Ok(HttpResponse::Ok()
        .content_type("application/json")
        .insert_header((header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"))
        .body(json_string))
}

/// Generates an Actix [`HttpResponse`] redirecting (HTTP 303 See Other) to the Authorization Server.
#[must_use]
pub fn redirect_to_authorization_http_response(auth_req: &AuthorizationRequest) -> HttpResponse {
    HttpResponse::SeeOther()
        .insert_header((header::LOCATION, auth_req.authorization_url.as_str()))
        .insert_header((header::CACHE_CONTROL, "no-store"))
        .insert_header((header::PRAGMA, "no-cache"))
        .finish()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]
mod tests {
    use super::*;
    use crate::client::StoredStateEntry;
    use actix_web::test::TestRequest;
    use url::Url;

    #[tokio::test]
    async fn test_actix_callback_query_extractor_success() {
        let req = TestRequest::get()
            .uri("/oauth/callback?code=actix_code_123&state=actix_state_456&iss=https%3A%2F%2Fauth.example.com")
            .to_http_request();

        let mut payload = Payload::None;
        let query = OAuthCallbackQuery::from_request(&req, &mut payload)
            .await
            .unwrap();

        assert_eq!(query.code.as_deref(), Some("actix_code_123"));
        assert_eq!(query.state.as_deref(), Some("actix_state_456"));
        assert_eq!(query.iss.as_deref(), Some("https://auth.example.com"));

        let params = query.to_callback_params().unwrap();
        assert_eq!(params.code, "actix_code_123");
        assert_eq!(params.state, "actix_state_456");
    }

    #[tokio::test]
    async fn test_actix_authenticated_user_from_extensions() {
        let user = AuthenticatedUser::new("did:plc:bob456", "at_bob_token", "jkt_bob_thumbprint");
        let ext = OAuthSessionExtension::new(user.clone());

        let req = TestRequest::get().uri("/api/feed").to_http_request();
        req.extensions_mut().insert(ext);

        let mut payload = Payload::None;
        let extracted = AuthenticatedUser::from_request(&req, &mut payload)
            .await
            .unwrap();

        assert_eq!(extracted.did, "did:plc:bob456");
        assert_eq!(extracted.access_token, "at_bob_token");
        assert_eq!(extracted.dpop_thumbprint, "jkt_bob_thumbprint");
    }

    #[test]
    fn test_actix_client_metadata_response() {
        let metadata = OAuthClientMetadata::new(
            "https://app.example.com/oauth/client-metadata.json",
            "https://app.example.com/oauth/callback",
        );

        let resp = client_metadata_http_response(&metadata).unwrap();
        assert_eq!(resp.status(), actix_web::http::StatusCode::OK);
    }

    #[test]
    fn test_actix_redirect_to_authorization() {
        let url = Url::parse("https://auth.example.com/authorize?req=123").unwrap();
        let stored_state = StoredStateEntry {
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

        let resp = redirect_to_authorization_http_response(&auth_req);
        assert_eq!(resp.status(), actix_web::http::StatusCode::SEE_OTHER);
        assert_eq!(
            resp.headers()
                .get(header::LOCATION)
                .unwrap()
                .to_str()
                .unwrap(),
            url.as_str()
        );
    }
}
