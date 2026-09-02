//! Integration Tests for Framework Adapters (Axum, Actix, Tower).

use std::convert::Infallible;
use std::sync::Arc;
use std::time::SystemTime;

use http::{header, Request, Response, StatusCode};
use skyauth::client::{AuthorizationRequest, OAuthClientMetadata, StoredStateEntry};
use skyauth::dpop::{compute_access_token_hash, DPoPKey, DPoPVerifier};
use skyauth::error::IntegrationError;
use skyauth::integrations::{AuthenticatedUser, OAuthCallbackQuery, OAuthSessionExtension};
use tower_layer::Layer;
use tower_service::Service;
use url::Url;

fn mock_authorization_request() -> AuthorizationRequest {
    let url = Url::parse("https://auth.bsky.social/oauth/authorize?client_id=https%3A%2F%2Ffeed.example.com%2Fclient-metadata.json&request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Apar_12345").unwrap();
    let stored_state = StoredStateEntry {
        state: "state_entropy_secret_123".to_string(),
        client_id: "https://feed.example.com/client-metadata.json".to_string(),
        code_verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".to_string(),
        dpop_key: DPoPKey::generate(),
        issuer: "https://auth.bsky.social".to_string(),
        did: Some("did:plc:ragtjsm2j2vknq6tfur4vg6u".to_string()),
        handle: Some("alice.bsky.social".to_string()),
        redirect_uri: "https://feed.example.com/oauth/callback".to_string(),
        pds_endpoint: "https://morel.us-east.host.bsky.network".to_string(),
        token_endpoint: "https://auth.bsky.social/oauth/token".to_string(),
        scopes: "atproto transition:generic".to_string(),
        created_at: SystemTime::now(),
        expires_in_secs: 300,
    };

    AuthorizationRequest {
        authorization_url: url,
        state: "state_entropy_secret_123".to_string(),
        request_uri: "urn:ietf:params:oauth:request_uri:par_12345".to_string(),
        expires_in: 300,
        stored_state,
    }
}

fn mock_client_metadata() -> OAuthClientMetadata {
    OAuthClientMetadata::new(
        "https://feed.example.com/oauth/client-metadata.json",
        "https://feed.example.com/oauth/callback",
    )
    .with_client_name("FYC Feed Generator")
    .with_scope("atproto transition:generic")
}

#[cfg(feature = "axum")]
mod axum_tests {
    use super::*;
    use axum::extract::FromRequestParts;
    use skyauth::integrations::axum::{client_metadata_response, redirect_to_authorization};

    #[tokio::test]
    async fn test_axum_extract_callback_query_valid() {
        let uri = "/oauth/callback?code=oauth_code_789&state=state_entropy_123&iss=https%3A%2F%2Fauth.bsky.social";
        let req = Request::builder()
            .uri(uri)
            .body(axum::body::Body::empty())
            .unwrap();

        let (mut parts, _) = req.into_parts();
        let query = OAuthCallbackQuery::from_request_parts(&mut parts, &())
            .await
            .unwrap();

        assert_eq!(query.code.as_deref(), Some("oauth_code_789"));
        assert_eq!(query.state.as_deref(), Some("state_entropy_123"));
        assert_eq!(query.iss.as_deref(), Some("https://auth.bsky.social"));

        let params = query.to_callback_params().unwrap();
        assert_eq!(params.code, "oauth_code_789");
        assert_eq!(params.state, "state_entropy_123");
        assert_eq!(params.iss.as_deref(), Some("https://auth.bsky.social"));
    }

    #[tokio::test]
    async fn test_axum_extract_callback_query_error_response() {
        let uri = "/oauth/callback?error=access_denied&error_description=User+denied+authorization";
        let req = Request::builder()
            .uri(uri)
            .body(axum::body::Body::empty())
            .unwrap();

        let (mut parts, _) = req.into_parts();
        let query = OAuthCallbackQuery::from_request_parts(&mut parts, &())
            .await
            .unwrap();

        assert_eq!(query.error.as_deref(), Some("access_denied"));
        let err = query.to_callback_params().unwrap_err();
        assert!(matches!(
            err,
            IntegrationError::OAuthError {
                error,
                ..
            } if error == "access_denied"
        ));
    }

    #[tokio::test]
    async fn test_axum_extract_authenticated_user_from_extensions() {
        let user = AuthenticatedUser::new(
            "did:plc:ragtjsm2j2vknq6tfur4vg6u",
            "at_access_token_sample",
            "jkt_sample_thumbprint",
        )
        .with_scope("atproto transition:generic");

        let ext = OAuthSessionExtension::new(user.clone());

        let mut req = Request::builder()
            .uri("/xrpc/app.bsky.actor.getProfile")
            .body(axum::body::Body::empty())
            .unwrap();
        req.extensions_mut().insert(ext);

        let (mut parts, _) = req.into_parts();
        let extracted = AuthenticatedUser::from_request_parts(&mut parts, &())
            .await
            .unwrap();

        assert_eq!(extracted.did, "did:plc:ragtjsm2j2vknq6tfur4vg6u");
        assert_eq!(extracted.access_token, "at_access_token_sample");
        assert_eq!(extracted.dpop_thumbprint, "jkt_sample_thumbprint");
        assert_eq!(
            extracted.scope.as_deref(),
            Some("atproto transition:generic")
        );
    }

    #[tokio::test]
    async fn test_axum_client_metadata_response_compliance() {
        let metadata = mock_client_metadata();
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

    #[tokio::test]
    async fn test_axum_redirect_to_authorization_headers() {
        let auth_req = mock_authorization_request();
        let resp = redirect_to_authorization(&auth_req).unwrap();

        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            resp.headers().get(header::LOCATION).unwrap(),
            auth_req.authorization_url.as_str()
        );
        assert_eq!(
            resp.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
    }
}

#[cfg(feature = "actix")]
mod actix_tests {
    use super::*;
    use actix_web::dev::Payload;
    use actix_web::http::header as actix_header;
    use actix_web::test::TestRequest;
    use actix_web::{FromRequest, HttpMessage};
    use skyauth::integrations::actix::{
        client_metadata_http_response, redirect_to_authorization_http_response,
    };

    #[tokio::test]
    async fn test_actix_extract_callback_query_valid() {
        let uri = "/oauth/callback?code=actix_auth_code_99&state=actix_state_88&iss=https%3A%2F%2Fauth.bsky.social";
        let req = TestRequest::get().uri(uri).to_http_request();

        let mut payload = Payload::None;
        let query = OAuthCallbackQuery::from_request(&req, &mut payload)
            .await
            .unwrap();

        assert_eq!(query.code.as_deref(), Some("actix_auth_code_99"));
        assert_eq!(query.state.as_deref(), Some("actix_state_88"));
        assert_eq!(query.iss.as_deref(), Some("https://auth.bsky.social"));

        let params = query.to_callback_params().unwrap();
        assert_eq!(params.code, "actix_auth_code_99");
        assert_eq!(params.state, "actix_state_88");
    }

    #[tokio::test]
    async fn test_actix_extract_authenticated_user_from_extensions() {
        let user = AuthenticatedUser::new(
            "did:plc:ragtjsm2j2vknq6tfur4vg6u",
            "at_actix_token",
            "jkt_actix_thumbprint",
        );
        let ext = OAuthSessionExtension::new(user.clone());

        let req = TestRequest::get()
            .uri("/xrpc/app.bsky.feed.getFeedSkeleton")
            .to_http_request();
        req.extensions_mut().insert(ext);

        let mut payload = Payload::None;
        let extracted = AuthenticatedUser::from_request(&req, &mut payload)
            .await
            .unwrap();

        assert_eq!(extracted.did, "did:plc:ragtjsm2j2vknq6tfur4vg6u");
        assert_eq!(extracted.access_token, "at_actix_token");
        assert_eq!(extracted.dpop_thumbprint, "jkt_actix_thumbprint");
    }

    #[test]
    fn test_actix_client_metadata_http_response() {
        let metadata = mock_client_metadata();
        let resp = client_metadata_http_response(&metadata).unwrap();

        assert_eq!(resp.status(), actix_web::http::StatusCode::OK);
        assert_eq!(
            resp.headers().get(actix_header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        assert_eq!(
            resp.headers()
                .get(actix_header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap(),
            "*"
        );
    }

    #[test]
    fn test_actix_redirect_to_authorization_response() {
        let auth_req = mock_authorization_request();
        let resp = redirect_to_authorization_http_response(&auth_req);

        assert_eq!(resp.status(), actix_web::http::StatusCode::SEE_OTHER);
        assert_eq!(
            resp.headers()
                .get(actix_header::LOCATION)
                .unwrap()
                .to_str()
                .unwrap(),
            auth_req.authorization_url.as_str()
        );
        assert_eq!(
            resp.headers()
                .get(actix_header::CACHE_CONTROL)
                .unwrap()
                .to_str()
                .unwrap(),
            "no-store"
        );
    }
}

#[cfg(feature = "tower")]
mod tower_tests {
    use super::*;
    use skyauth::integrations::tower::OAuthAuthLayer;
    use tower::service_fn;

    #[tokio::test]
    async fn test_tower_middleware_full_dpop_handshake_flow() {
        let key = DPoPKey::generate();
        let jkt = key.jwk_thumbprint();
        let access_token = "valid_skyauth_token_12345";
        let ath = compute_access_token_hash(access_token);
        let uri = "https://pds.example.com/xrpc/app.bsky.feed.getTimeline";

        let proof = key.create_proof("GET", uri, None, Some(&ath)).unwrap();

        let store = skyauth::integrations::InMemoryTokenValidator::new();
        store.register_token(
            access_token,
            "did:plc:alice123",
            &jkt,
            Some("atproto".to_string()),
            None,
        );

        let verifier = Arc::new(DPoPVerifier::new());
        let layer = OAuthAuthLayer::from_token_store(verifier, store).with_require_ath(true);

        let target_jkt = jkt.clone();
        let inner = service_fn(move |req: Request<()>| {
            let expected_jkt = target_jkt.clone();
            async move {
                let user = req.extensions().get::<AuthenticatedUser>().cloned();
                assert!(
                    user.is_some(),
                    "AuthenticatedUser must be injected into extensions"
                );
                let u = user.unwrap();
                assert_eq!(u.access_token, "valid_skyauth_token_12345");
                assert_eq!(u.dpop_thumbprint, expected_jkt);
                Ok::<Response<String>, Infallible>(Response::new("XRPC Response Data".to_string()))
            }
        });

        let mut service = layer.layer(inner);

        let req = Request::builder()
            .method("GET")
            .uri(uri)
            .header(header::AUTHORIZATION, format!("DPoP {access_token}"))
            .header("DPoP", proof.clone())
            .body(())
            .unwrap();

        let resp = service.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.body(), "XRPC Response Data");

        let req_missing_dpop = Request::builder()
            .method("GET")
            .uri(uri)
            .header(header::AUTHORIZATION, format!("DPoP {access_token}"))
            .body(())
            .unwrap();

        let resp_missing = service.call(req_missing_dpop).await.unwrap();
        assert_eq!(resp_missing.status(), StatusCode::UNAUTHORIZED);
        assert!(resp_missing
            .headers()
            .contains_key(header::WWW_AUTHENTICATE));

        let post_proof = key.create_proof("POST", uri, None, Some(&ath)).unwrap();
        let req_wrong_method = Request::builder()
            .method("GET")
            .uri(uri)
            .header(header::AUTHORIZATION, format!("DPoP {access_token}"))
            .header("DPoP", post_proof)
            .body(())
            .unwrap();

        let resp_wrong_method = service.call(req_wrong_method).await.unwrap();
        assert_eq!(resp_wrong_method.status(), StatusCode::UNAUTHORIZED);

        let req_missing_auth = Request::builder()
            .method("GET")
            .uri(uri)
            .header("DPoP", proof)
            .body(())
            .unwrap();

        let resp_no_auth = service.call(req_missing_auth).await.unwrap();
        assert_eq!(resp_no_auth.status(), StatusCode::UNAUTHORIZED);
    }
}
