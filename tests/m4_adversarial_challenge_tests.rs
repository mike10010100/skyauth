//! Adversarial Challenge Test Suite for Milestone 4 (Framework Integrations & Tower DPoP Middleware).
//!
//! Stress-tests:
//! 1. Tower DPoP Authentication Middleware:
//!    - Tampered DPoP proofs (signature tampering, header alg/typ/jwk tampering, payload tampering, malformed JWTs, private key in JWK)
//!    - Missing Authorization headers
//!    - Invalid Authorization schemes (Bearer, Basic, Token, malformed DPoP prefixes)
//!    - Expired DPoP proofs (past iat beyond max age, future iat beyond clock skew, expired exp claim)
//!    - Mismatched or missing ath access token hash
//!    - URI / Method / Nonce mismatches
//! 2. Axum & Actix Extractor Edge Cases:
//!    - Missing code/state parameters (missing code, missing state, missing both, error responses, empty strings)
//!    - Oversized query strings (large payloads > 50KB, 1000 parameters, duplicate keys, injection payloads)
//!    - AuthenticatedUser extractor fallback and extension paths
//!    - Client metadata and authorization redirect response helpers

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

use std::convert::Infallible;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use http::{header, Request, Response, StatusCode};
use p256::pkcs8::DecodePrivateKey;
use skyauth::client::{AuthorizationRequest, OAuthClientMetadata, StoredStateEntry};
use skyauth::crypto::base64url_encode;
use skyauth::dpop::{compute_access_token_hash, DPoPKey, DPoPVerifier};
use skyauth::error::IntegrationError;
use skyauth::integrations::{AuthenticatedUser, OAuthCallbackQuery, OAuthSessionExtension};
use tower_layer::Layer;
use tower_service::Service;
use url::Url;

fn mock_authorization_request() -> AuthorizationRequest {
    let url = Url::parse("https://auth.bsky.social/oauth/authorize?client_id=https%3A%2F%2Fapp.example.com%2Fclient-metadata.json&request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Apar_999").unwrap();
    let stored_state = StoredStateEntry {
        state: "state_secret_123".to_string(),
        client_id: "https://app.example.com/client-metadata.json".to_string(),
        code_verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".to_string(),
        dpop_key: DPoPKey::generate(),
        issuer: "https://auth.bsky.social".to_string(),
        did: Some("did:plc:ragtjsm2j2vknq6tfur4vg6u".to_string()),
        handle: Some("alice.bsky.social".to_string()),
        redirect_uri: "https://app.example.com/oauth/callback".to_string(),
        pds_endpoint: "https://morel.us-east.host.bsky.network".to_string(),
        token_endpoint: "https://auth.bsky.social/oauth/token".to_string(),
        scopes: "atproto transition:generic".to_string(),
        created_at: SystemTime::now(),
        expires_in_secs: 300,
    };

    AuthorizationRequest {
        authorization_url: url,
        state: "state_secret_123".to_string(),
        request_uri: "urn:ietf:params:oauth:request_uri:par_999".to_string(),
        expires_in: 300,
        stored_state,
    }
}

fn mock_client_metadata() -> OAuthClientMetadata {
    OAuthClientMetadata::new(
        "https://app.example.com/oauth/client-metadata.json",
        "https://app.example.com/oauth/callback",
    )
    .with_client_name("ATProto Test App")
    .with_scope("atproto transition:generic")
}

// =========================================================================
// SECTION 1: TOWER DPOP AUTHENTICATION MIDDLEWARE ADVERSARIAL TESTS
// =========================================================================

#[cfg(feature = "tower")]
mod tower_adversarial_tests {
    use super::*;
    use skyauth::integrations::tower::OAuthAuthLayer;

    #[derive(Clone)]
    struct MockService;

    impl Service<Request<()>> for MockService {
        type Response = Response<String>;
        type Error = Infallible;
        type Future =
            Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: Request<()>) -> Self::Future {
            let user = req.extensions().get::<AuthenticatedUser>().cloned();
            let session_ext = req.extensions().get::<OAuthSessionExtension>().cloned();
            Box::pin(async move {
                if let (Some(u), Some(ext)) = (user, session_ext) {
                    assert_eq!(u.did, ext.user.did);
                    Ok(Response::new(format!("OK:{}", u.did)))
                } else {
                    Ok(Response::new("NO_USER".to_string()))
                }
            })
        }
    }

    fn test_layer(verifier: Arc<DPoPVerifier>) -> OAuthAuthLayer {
        let store = skyauth::integrations::InMemoryTokenValidator::new();
        OAuthAuthLayer::from_token_store(verifier, store)
    }

    #[tokio::test]
    async fn test_tower_tampered_dpop_signature_rejection() {
        let key = DPoPKey::generate();
        let access_token = "valid_atproto_token_xyz";
        let ath = compute_access_token_hash(access_token);
        let uri = "https://pds.example.com/xrpc/app.bsky.actor.getProfile";

        let valid_proof = key.create_proof("GET", uri, None, Some(&ath)).unwrap();
        let parts: Vec<&str> = valid_proof.split('.').collect();
        assert_eq!(parts.len(), 3);

        // Tamper with the signature bytes by flipping characters
        let mut tampered_sig = parts[2].to_string();
        if tampered_sig.starts_with('A') {
            tampered_sig.replace_range(0..1, "B");
        } else {
            tampered_sig.replace_range(0..1, "A");
        }
        let tampered_proof = format!("{}.{}.{}", parts[0], parts[1], tampered_sig);

        let verifier = Arc::new(DPoPVerifier::new());
        let layer = test_layer(verifier);
        let mut service = layer.layer(MockService);

        let req = Request::builder()
            .method("GET")
            .uri(uri)
            .header(header::AUTHORIZATION, format!("DPoP {access_token}"))
            .header("DPoP", tampered_proof)
            .body(())
            .unwrap();

        let resp = service.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let auth_hdr = resp
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(auth_hdr.contains("invalid_dpop_proof"));
    }

    #[tokio::test]
    async fn test_tower_tampered_dpop_payload_rejection() {
        let key = DPoPKey::generate();
        let access_token = "valid_atproto_token_xyz";
        let ath = compute_access_token_hash(access_token);
        let uri = "https://pds.example.com/xrpc/app.bsky.actor.getProfile";

        let valid_proof = key.create_proof("GET", uri, None, Some(&ath)).unwrap();
        let parts: Vec<&str> = valid_proof.split('.').collect();

        // Tamper with payload (substituting forged method/uri while keeping original signature)
        let malicious_payload = serde_json::json!({
            "jti": "forged_jti_12345",
            "htm": "POST",
            "htu": "https://pds.example.com/xrpc/forged.action",
            "iat": 1700000000,
            "ath": ath,
        });
        let forged_payload_b64 = base64url_encode(malicious_payload.to_string().as_bytes());
        let tampered_proof = format!("{}.{}.{}", parts[0], forged_payload_b64, parts[2]);

        let verifier = Arc::new(DPoPVerifier::new());
        let layer = test_layer(verifier);
        let mut service = layer.layer(MockService);

        let req = Request::builder()
            .method("GET")
            .uri(uri)
            .header(header::AUTHORIZATION, format!("DPoP {access_token}"))
            .header("DPoP", tampered_proof)
            .body(())
            .unwrap();

        let resp = service.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_tower_tampered_dpop_header_alg_typ_jwk() {
        let key = DPoPKey::generate();
        let access_token = "valid_token_123";
        let ath = compute_access_token_hash(access_token);
        let uri = "https://pds.example.com/xrpc/test";

        let valid_proof = key.create_proof("GET", uri, None, Some(&ath)).unwrap();
        let parts: Vec<&str> = valid_proof.split('.').collect();

        // 1. Alg = "none" tampering
        let header_alg_none = serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "none",
            "jwk": key.public_jwk()
        });
        let h_b64 = base64url_encode(header_alg_none.to_string().as_bytes());
        let bad_alg_proof = format!("{h_b64}.{}.{}", parts[1], parts[2]);

        let verifier = Arc::new(DPoPVerifier::new());
        let layer = test_layer(verifier);
        let mut service = layer.layer(MockService);

        let req = Request::builder()
            .method("GET")
            .uri(uri)
            .header(header::AUTHORIZATION, format!("DPoP {access_token}"))
            .header("DPoP", bad_alg_proof)
            .body(())
            .unwrap();

        let resp = service.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // 2. Typ = "jwt" tampering (missing dpop+)
        let header_bad_typ = serde_json::json!({
            "typ": "jwt",
            "alg": "ES256",
            "jwk": key.public_jwk()
        });
        let h_b64 = base64url_encode(header_bad_typ.to_string().as_bytes());
        let bad_typ_proof = format!("{h_b64}.{}.{}", parts[1], parts[2]);

        let req = Request::builder()
            .method("GET")
            .uri(uri)
            .header(header::AUTHORIZATION, format!("DPoP {access_token}"))
            .header("DPoP", bad_typ_proof)
            .body(())
            .unwrap();

        let resp = service.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // 3. JWK containing private key parameter "d"
        let header_with_privkey = serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "ES256",
            "jwk": {
                "kty": "EC",
                "crv": "P-256",
                "x": key.public_jwk().x,
                "y": key.public_jwk().y,
                "d": "leaked_private_key_coordinate"
            }
        });
        let h_b64 = base64url_encode(header_with_privkey.to_string().as_bytes());
        let privkey_proof = format!("{h_b64}.{}.{}", parts[1], parts[2]);

        let req = Request::builder()
            .method("GET")
            .uri(uri)
            .header(header::AUTHORIZATION, format!("DPoP {access_token}"))
            .header("DPoP", privkey_proof)
            .body(())
            .unwrap();

        let resp = service.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_tower_malformed_jwt_variations() {
        let verifier = Arc::new(DPoPVerifier::new());
        let layer = test_layer(verifier);
        let mut service = layer.layer(MockService);

        let malformed_proofs = vec![
            "",
            "   ",
            "not.a.valid.jwt.with.too.many.parts",
            "onlyonepart",
            "two.parts",
            "header.invalid_base64!@#$.sig",
            "???...!!!",
        ];

        for malformed in malformed_proofs {
            let req = Request::builder()
                .method("GET")
                .uri("https://pds.example.com/xrpc/app.bsky.actor.getProfile")
                .header(header::AUTHORIZATION, "DPoP token_123")
                .header("DPoP", malformed)
                .body(())
                .unwrap();

            let resp = service.call(req).await.unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::UNAUTHORIZED,
                "Expected 401 for malformed DPoP proof: '{malformed}'"
            );
        }
    }

    #[tokio::test]
    async fn test_tower_missing_authorization_header() {
        let key = DPoPKey::generate();
        let access_token = "valid_token";
        let ath = compute_access_token_hash(access_token);
        let uri = "https://pds.example.com/xrpc/test";
        let proof = key.create_proof("GET", uri, None, Some(&ath)).unwrap();

        let verifier = Arc::new(DPoPVerifier::new());
        let layer = test_layer(verifier);
        let mut service = layer.layer(MockService);

        // Request with DPoP proof header but NO Authorization header
        let req = Request::builder()
            .method("GET")
            .uri(uri)
            .header("DPoP", proof)
            .body(())
            .unwrap();

        let resp = service.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let auth_hdr = resp
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(auth_hdr.contains("missing_token"));
    }

    #[tokio::test]
    async fn test_tower_invalid_authorization_schemes() {
        let key = DPoPKey::generate();
        let access_token = "valid_token_123";
        let ath = compute_access_token_hash(access_token);
        let uri = "https://pds.example.com/xrpc/test";
        let proof = key.create_proof("GET", uri, None, Some(&ath)).unwrap();

        let invalid_auth_headers = vec![
            format!("Bearer {access_token}"),
            format!("Basic {access_token}"),
            format!("Token {access_token}"),
            format!("dpop_custom {access_token}"),
            format!("DPoP:{access_token}"),
            "DPoP".to_string(),
            "".to_string(),
            "   ".to_string(),
        ];

        let verifier = Arc::new(DPoPVerifier::new());
        let layer = test_layer(verifier);
        let mut service = layer.layer(MockService);

        for auth_hdr in invalid_auth_headers {
            let req = Request::builder()
                .method("GET")
                .uri(uri)
                .header(header::AUTHORIZATION, auth_hdr.clone())
                .header("DPoP", proof.clone())
                .body(())
                .unwrap();

            let resp = service.call(req).await.unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::UNAUTHORIZED,
                "Expected 401 for invalid auth header: '{auth_hdr}'"
            );
            let www_auth = resp
                .headers()
                .get(header::WWW_AUTHENTICATE)
                .unwrap()
                .to_str()
                .unwrap();
            assert!(www_auth.contains("invalid_scheme"));
        }
    }

    #[tokio::test]
    async fn test_tower_expired_dpop_proof_with_max_age() {
        let key = DPoPKey::generate();
        let access_token = "valid_token_123";
        let ath = compute_access_token_hash(access_token);
        let uri = "https://pds.example.com/xrpc/test";

        let proof = key.create_proof("GET", uri, None, Some(&ath)).unwrap();

        // Configure verifier with 1 second max proof age
        let verifier = Arc::new(
            DPoPVerifier::new()
                .with_max_proof_age(Duration::from_secs(1))
                .with_max_clock_skew(Duration::ZERO),
        );
        let layer = test_layer(verifier);
        let mut service = layer.layer(MockService);

        // Sleep 2 seconds to exceed 1s max age
        tokio::time::sleep(Duration::from_secs(2)).await;

        let req = Request::builder()
            .method("GET")
            .uri(uri)
            .header(header::AUTHORIZATION, format!("DPoP {access_token}"))
            .header("DPoP", proof)
            .body(())
            .unwrap();

        let resp = service.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let www_auth = resp
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(www_auth.contains("invalid_dpop_proof"));
    }

    #[tokio::test]
    async fn test_tower_expired_dpop_proof_with_exp_claim_verification() {
        let key = DPoPKey::generate();
        let access_token = "valid_token_123";
        let ath = compute_access_token_hash(access_token);
        let uri = "https://pds.example.com/xrpc/test";

        // Create proof directly with an expired `exp` claim (in past)
        let header_json = serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "ES256",
            "jwk": key.public_jwk()
        });
        let payload_json = serde_json::json!({
            "jti": "jti_expired_exp_test",
            "htm": "GET",
            "htu": uri,
            "iat": 1000000,
            "exp": 1000001, // Expired long ago
            "ath": ath
        });

        let h_b64 = base64url_encode(header_json.to_string().as_bytes());
        let p_b64 = base64url_encode(payload_json.to_string().as_bytes());
        let signing_input = format!("{h_b64}.{p_b64}");
        let sig_bytes = skyauth::crypto::sign_p256_raw(
            &p256::ecdsa::SigningKey::from_pkcs8_pem(&key.to_pkcs8_pem().unwrap()).unwrap(),
            signing_input.as_bytes(),
        )
        .unwrap();
        let sig_b64 = base64url_encode(&sig_bytes);
        let expired_exp_jwt = format!("{signing_input}.{sig_b64}");

        let verifier = Arc::new(DPoPVerifier::new());
        let layer = test_layer(verifier);
        let mut service = layer.layer(MockService);

        let req = Request::builder()
            .method("GET")
            .uri(uri)
            .header(header::AUTHORIZATION, format!("DPoP {access_token}"))
            .header("DPoP", expired_exp_jwt)
            .body(())
            .unwrap();

        let resp = service.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_tower_future_dpop_proof_clock_skew_verification() {
        let key = DPoPKey::generate();
        let access_token = "valid_token_123";
        let ath = compute_access_token_hash(access_token);
        let uri = "https://pds.example.com/xrpc/test";

        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let future_iat = now_secs + 10000; // Far in the future

        let header_json = serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "ES256",
            "jwk": key.public_jwk()
        });
        let payload_json = serde_json::json!({
            "jti": "jti_future_iat_test",
            "htm": "GET",
            "htu": uri,
            "iat": future_iat,
            "ath": ath
        });

        let h_b64 = base64url_encode(header_json.to_string().as_bytes());
        let p_b64 = base64url_encode(payload_json.to_string().as_bytes());
        let signing_input = format!("{h_b64}.{p_b64}");
        let sig_bytes = skyauth::crypto::sign_p256_raw(
            &p256::ecdsa::SigningKey::from_pkcs8_pem(&key.to_pkcs8_pem().unwrap()).unwrap(),
            signing_input.as_bytes(),
        )
        .unwrap();
        let sig_b64 = base64url_encode(&sig_bytes);
        let future_jwt = format!("{signing_input}.{sig_b64}");

        let verifier = Arc::new(DPoPVerifier::new());
        let layer = test_layer(verifier);
        let mut service = layer.layer(MockService);

        let req = Request::builder()
            .method("GET")
            .uri(uri)
            .header(header::AUTHORIZATION, format!("DPoP {access_token}"))
            .header("DPoP", future_jwt)
            .body(())
            .unwrap();

        let resp = service.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_tower_mismatched_ath_token_hash() {
        let key = DPoPKey::generate();
        let token_a = "token_authorized_for_alice";
        let token_b = "token_authorized_for_attacker";
        let ath_a = compute_access_token_hash(token_a);
        let uri = "https://pds.example.com/xrpc/test";

        // Proof binds to token_a, but request sends token_b
        let proof_for_token_a = key.create_proof("GET", uri, None, Some(&ath_a)).unwrap();

        let verifier = Arc::new(DPoPVerifier::new());
        let layer = test_layer(verifier).with_require_ath(true);
        let mut service = layer.layer(MockService);

        let req = Request::builder()
            .method("GET")
            .uri(uri)
            .header(header::AUTHORIZATION, format!("DPoP {token_b}"))
            .header("DPoP", proof_for_token_a)
            .body(())
            .unwrap();

        let resp = service.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_tower_missing_ath_when_strictly_required() {
        let key = DPoPKey::generate();
        let access_token = "valid_token_123";
        let uri = "https://pds.example.com/xrpc/test";

        // Proof without ath claim
        let proof_without_ath = key.create_proof("GET", uri, None, None).unwrap();

        let verifier = Arc::new(DPoPVerifier::new());
        let layer = test_layer(verifier).with_require_ath(true);
        let mut service = layer.layer(MockService);

        let req = Request::builder()
            .method("GET")
            .uri(uri)
            .header(header::AUTHORIZATION, format!("DPoP {access_token}"))
            .header("DPoP", proof_without_ath)
            .body(())
            .unwrap();

        let resp = service.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_tower_uri_and_method_mismatch_rejections() {
        let key = DPoPKey::generate();
        let access_token = "valid_token_123";
        let ath = compute_access_token_hash(access_token);
        let valid_uri = "https://pds.example.com/xrpc/app.bsky.actor.getProfile";
        let wrong_uri = "https://pds.example.com/xrpc/app.bsky.feed.getTimeline";

        let proof = key
            .create_proof("GET", valid_uri, None, Some(&ath))
            .unwrap();

        let verifier = Arc::new(DPoPVerifier::new());
        let layer = test_layer(verifier);
        let mut service = layer.layer(MockService);

        // 1. URI Mismatch
        let req_wrong_uri = Request::builder()
            .method("GET")
            .uri(wrong_uri)
            .header(header::AUTHORIZATION, format!("DPoP {access_token}"))
            .header("DPoP", proof.clone())
            .body(())
            .unwrap();

        let resp_uri = service.call(req_wrong_uri).await.unwrap();
        assert_eq!(resp_uri.status(), StatusCode::UNAUTHORIZED);

        // 2. Method Mismatch (POST request with GET proof)
        let req_wrong_method = Request::builder()
            .method("POST")
            .uri(valid_uri)
            .header(header::AUTHORIZATION, format!("DPoP {access_token}"))
            .header("DPoP", proof)
            .body(())
            .unwrap();

        let resp_method = service.call(req_wrong_method).await.unwrap();
        assert_eq!(resp_method.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_tower_adversarial_invented_credentials_rejected() {
        let auth_key = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let auth_verifying_key = *auth_key.verifying_key();

        // Attacker generates own key and invents random access token string
        let attacker_dpop_key = DPoPKey::generate();
        let invented_token = "attacker_invented_token_xyz999";
        let ath = compute_access_token_hash(invented_token);
        let uri = "https://pds.example.com/xrpc/app.bsky.actor.getProfile";

        let proof = attacker_dpop_key
            .create_proof("GET", uri, None, Some(&ath))
            .unwrap();

        let verifier = Arc::new(DPoPVerifier::new());
        let jwt_validator = skyauth::integrations::JwtAccessTokenValidator::new()
            .with_verifying_key(auth_verifying_key)
            .with_expected_issuer("https://auth.example.com")
            .with_expected_audience("https://pds.example.com");

        let layer = OAuthAuthLayer::from_jwt_validator(verifier, jwt_validator);
        let mut service = layer.layer(MockService);

        let req = Request::builder()
            .method("GET")
            .uri(uri)
            .header(header::AUTHORIZATION, format!("DPoP {invented_token}"))
            .header("DPoP", proof)
            .body(())
            .unwrap();

        let resp = service.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let auth_hdr = resp
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(auth_hdr.contains("invalid_token"));
    }

    #[tokio::test]
    async fn test_tower_adversarial_stolen_token_with_attacker_dpop_proof_cnf_mismatch() {
        let auth_key = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let auth_verifying_key = *auth_key.verifying_key();

        let alice_dpop_key = DPoPKey::generate();
        let alice_jkt = alice_dpop_key.jwk_thumbprint();

        let attacker_dpop_key = DPoPKey::generate();
        let uri = "https://pds.example.com/xrpc/app.bsky.actor.getProfile";

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Valid token issued to Alice and bound to Alice's DPoP key
        let alice_claims = skyauth::integrations::JwtAccessTokenClaims::new(
            "https://auth.example.com",
            "did:plc:alice123",
            now + 3600,
            &alice_jkt,
        )
        .with_audience("https://pds.example.com");

        let alice_jwt = alice_claims.sign_jwt(&auth_key, None).unwrap();
        let ath = compute_access_token_hash(&alice_jwt);

        // Attacker attempts to present Alice's JWT token with Attacker's DPoP proof
        let attacker_proof = attacker_dpop_key
            .create_proof("GET", uri, None, Some(&ath))
            .unwrap();

        let verifier = Arc::new(DPoPVerifier::new());
        let jwt_validator = skyauth::integrations::JwtAccessTokenValidator::new()
            .with_verifying_key(auth_verifying_key)
            .with_expected_issuer("https://auth.example.com")
            .with_expected_audience("https://pds.example.com");

        let layer = OAuthAuthLayer::from_jwt_validator(verifier, jwt_validator);
        let mut service = layer.layer(MockService);

        let req = Request::builder()
            .method("GET")
            .uri(uri)
            .header(header::AUTHORIZATION, format!("DPoP {alice_jwt}"))
            .header("DPoP", attacker_proof)
            .body(())
            .unwrap();

        let resp = service.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let auth_hdr = resp
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(auth_hdr.contains("invalid_token"));
    }

    #[tokio::test]
    async fn test_tower_adversarial_forged_jwt_signature_rejected() {
        let auth_key = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let auth_verifying_key = *auth_key.verifying_key();

        // Attacker creates a bogus signing key
        let attacker_signing_key = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let attacker_dpop_key = DPoPKey::generate();
        let attacker_jkt = attacker_dpop_key.jwk_thumbprint();
        let uri = "https://pds.example.com/xrpc/app.bsky.actor.getProfile";

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Attacker crafts a token claim bound to attacker_jkt but signs with attacker's bogus key
        let forged_claims = skyauth::integrations::JwtAccessTokenClaims::new(
            "https://auth.example.com",
            "did:plc:alice123",
            now + 3600,
            &attacker_jkt,
        )
        .with_audience("https://pds.example.com");

        let forged_jwt = forged_claims.sign_jwt(&attacker_signing_key, None).unwrap();
        let ath = compute_access_token_hash(&forged_jwt);

        let proof = attacker_dpop_key
            .create_proof("GET", uri, None, Some(&ath))
            .unwrap();

        let verifier = Arc::new(DPoPVerifier::new());
        let jwt_validator = skyauth::integrations::JwtAccessTokenValidator::new()
            .with_verifying_key(auth_verifying_key)
            .with_expected_issuer("https://auth.example.com")
            .with_expected_audience("https://pds.example.com");

        let layer = OAuthAuthLayer::from_jwt_validator(verifier, jwt_validator);
        let mut service = layer.layer(MockService);

        let req = Request::builder()
            .method("GET")
            .uri(uri)
            .header(header::AUTHORIZATION, format!("DPoP {forged_jwt}"))
            .header("DPoP", proof)
            .body(())
            .unwrap();

        let resp = service.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_tower_adversarial_valid_token_and_proof_succeeds() {
        let auth_key = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let auth_verifying_key = *auth_key.verifying_key();

        let client_dpop_key = DPoPKey::generate();
        let client_jkt = client_dpop_key.jwk_thumbprint();
        let uri = "https://pds.example.com/xrpc/app.bsky.actor.getProfile";

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let claims = skyauth::integrations::JwtAccessTokenClaims::new(
            "https://auth.example.com",
            "did:plc:alice123",
            now + 3600,
            &client_jkt,
        )
        .with_audience("https://pds.example.com")
        .with_scope("atproto transition:generic");

        let valid_jwt = claims.sign_jwt(&auth_key, None).unwrap();
        let ath = compute_access_token_hash(&valid_jwt);

        let proof = client_dpop_key
            .create_proof("GET", uri, None, Some(&ath))
            .unwrap();

        let verifier = Arc::new(DPoPVerifier::new());
        let jwt_validator = skyauth::integrations::JwtAccessTokenValidator::new()
            .with_verifying_key(auth_verifying_key)
            .with_expected_issuer("https://auth.example.com")
            .with_expected_audience("https://pds.example.com");

        let layer = OAuthAuthLayer::from_jwt_validator(verifier, jwt_validator);
        let mut service = layer.layer(MockService);

        let req = Request::builder()
            .method("GET")
            .uri(uri)
            .header(header::AUTHORIZATION, format!("DPoP {valid_jwt}"))
            .header("DPoP", proof)
            .body(())
            .unwrap();

        let resp = service.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.body(), "OK:did:plc:alice123");
    }

    #[tokio::test]
    async fn test_tower_adversarial_replay_attack_rejected() {
        let auth_key = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let auth_verifying_key = *auth_key.verifying_key();

        let client_dpop_key = DPoPKey::generate();
        let client_jkt = client_dpop_key.jwk_thumbprint();
        let uri = "https://pds.example.com/xrpc/app.bsky.actor.getProfile";

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let claims = skyauth::integrations::JwtAccessTokenClaims::new(
            "https://auth.example.com",
            "did:plc:alice123",
            now + 3600,
            &client_jkt,
        )
        .with_audience("https://pds.example.com");

        let valid_jwt = claims.sign_jwt(&auth_key, None).unwrap();
        let ath = compute_access_token_hash(&valid_jwt);

        let proof = client_dpop_key
            .create_proof("GET", uri, None, Some(&ath))
            .unwrap();

        let verifier = Arc::new(DPoPVerifier::new());
        let jwt_validator = skyauth::integrations::JwtAccessTokenValidator::new()
            .with_verifying_key(auth_verifying_key)
            .with_expected_issuer("https://auth.example.com")
            .with_expected_audience("https://pds.example.com");

        let layer = OAuthAuthLayer::from_jwt_validator(verifier, jwt_validator);
        let mut service = layer.layer(MockService);

        // 1. Initial valid request succeeds
        let req1 = Request::builder()
            .method("GET")
            .uri(uri)
            .header(header::AUTHORIZATION, format!("DPoP {valid_jwt}"))
            .header("DPoP", proof.clone())
            .body(())
            .unwrap();

        let resp1 = service.call(req1).await.unwrap();
        assert_eq!(resp1.status(), StatusCode::OK);
        assert_eq!(resp1.body(), "OK:did:plc:alice123");

        // 2. Attacker replays the exact same proof during the validity window -> MUST be rejected (RFC 9449 § 4.3 / § 11.1)
        let req2 = Request::builder()
            .method("GET")
            .uri(uri)
            .header(header::AUTHORIZATION, format!("DPoP {valid_jwt}"))
            .header("DPoP", proof)
            .body(())
            .unwrap();

        let resp2 = service.call(req2).await.unwrap();
        assert_eq!(resp2.status(), StatusCode::UNAUTHORIZED);
        let auth_hdr = resp2
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(auth_hdr.contains("invalid_dpop_proof"));
        assert!(auth_hdr.contains("replay detected"));
    }

    #[tokio::test]
    async fn test_tower_adversarial_server_nonce_challenge_and_enforcement() {
        let auth_key = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let auth_verifying_key = *auth_key.verifying_key();

        let client_dpop_key = DPoPKey::generate();
        let client_jkt = client_dpop_key.jwk_thumbprint();
        let uri = "https://pds.example.com/xrpc/app.bsky.actor.getProfile";

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let claims = skyauth::integrations::JwtAccessTokenClaims::new(
            "https://auth.example.com",
            "did:plc:alice123",
            now + 3600,
            &client_jkt,
        )
        .with_audience("https://pds.example.com");

        let valid_jwt = claims.sign_jwt(&auth_key, None).unwrap();
        let ath = compute_access_token_hash(&valid_jwt);

        let verifier = Arc::new(DPoPVerifier::new());
        let jwt_validator = skyauth::integrations::JwtAccessTokenValidator::new()
            .with_verifying_key(auth_verifying_key)
            .with_expected_issuer("https://auth.example.com")
            .with_expected_audience("https://pds.example.com");

        // Layer configured to enforce server-provided nonces with 60s TTL
        let layer = OAuthAuthLayer::from_jwt_validator(verifier, jwt_validator)
            .with_server_nonces(std::time::Duration::from_secs(60));
        let mut service = layer.layer(MockService);

        // 1. Initial request without nonce receives 401 with DPoP-Nonce
        let proof_no_nonce = client_dpop_key
            .create_proof("GET", uri, None, Some(&ath))
            .unwrap();

        let req1 = Request::builder()
            .method("GET")
            .uri(uri)
            .header(header::AUTHORIZATION, format!("DPoP {valid_jwt}"))
            .header("DPoP", proof_no_nonce)
            .body(())
            .unwrap();

        let resp1 = service.call(req1).await.unwrap();
        assert_eq!(resp1.status(), StatusCode::UNAUTHORIZED);
        let issued_nonce = resp1
            .headers()
            .get("dpop-nonce")
            .expect("Must return DPoP-Nonce header")
            .to_str()
            .unwrap()
            .to_string();

        // 2. Attacker tries an invented/bogus nonce
        let proof_bogus_nonce = client_dpop_key
            .create_proof("GET", uri, Some("bogus_nonce_attack"), Some(&ath))
            .unwrap();

        let req_bogus = Request::builder()
            .method("GET")
            .uri(uri)
            .header(header::AUTHORIZATION, format!("DPoP {valid_jwt}"))
            .header("DPoP", proof_bogus_nonce)
            .body(())
            .unwrap();

        let resp_bogus = service.call(req_bogus).await.unwrap();
        assert_eq!(resp_bogus.status(), StatusCode::UNAUTHORIZED);

        // 3. Client presents proof with the server-issued challenge nonce -> succeeds
        let proof_valid_nonce = client_dpop_key
            .create_proof("GET", uri, Some(&issued_nonce), Some(&ath))
            .unwrap();

        let req_valid = Request::builder()
            .method("GET")
            .uri(uri)
            .header(header::AUTHORIZATION, format!("DPoP {valid_jwt}"))
            .header("DPoP", proof_valid_nonce)
            .body(())
            .unwrap();

        let resp_valid = service.call(req_valid).await.unwrap();
        assert_eq!(resp_valid.status(), StatusCode::OK);
        assert_eq!(resp_valid.body(), "OK:did:plc:alice123");
    }
}

// =========================================================================
// SECTION 2: AXUM EXTRACTOR ADVERSARIAL EDGE CASES
// =========================================================================

#[cfg(feature = "axum")]
mod axum_adversarial_tests {
    use super::*;
    use axum::extract::FromRequestParts;
    use skyauth::integrations::axum::{client_metadata_response, redirect_to_authorization};

    #[tokio::test]
    async fn test_axum_missing_code_and_state_parameters() {
        // 1. Missing state
        let req_no_state = Request::builder()
            .uri("/oauth/callback?code=valid_code_only")
            .body(axum::body::Body::empty())
            .unwrap();
        let (mut parts, _) = req_no_state.into_parts();
        let query = OAuthCallbackQuery::from_request_parts(&mut parts, &())
            .await
            .unwrap();
        assert!(matches!(
            query.to_callback_params(),
            Err(IntegrationError::MissingState)
        ));

        // 2. Missing code
        let req_no_code = Request::builder()
            .uri("/oauth/callback?state=valid_state_only")
            .body(axum::body::Body::empty())
            .unwrap();
        let (mut parts, _) = req_no_code.into_parts();
        let query = OAuthCallbackQuery::from_request_parts(&mut parts, &())
            .await
            .unwrap();
        assert!(matches!(
            query.to_callback_params(),
            Err(IntegrationError::MissingCode)
        ));

        // 3. Completely empty query
        let req_empty = Request::builder()
            .uri("/oauth/callback")
            .body(axum::body::Body::empty())
            .unwrap();
        let (mut parts, _) = req_empty.into_parts();
        let query = OAuthCallbackQuery::from_request_parts(&mut parts, &())
            .await
            .unwrap();
        assert!(matches!(
            query.to_callback_params(),
            Err(IntegrationError::MissingCode)
        ));

        // 4. Server error response parameter
        let req_err = Request::builder()
            .uri("/oauth/callback?error=invalid_grant&error_description=Code+expired")
            .body(axum::body::Body::empty())
            .unwrap();
        let (mut parts, _) = req_err.into_parts();
        let query = OAuthCallbackQuery::from_request_parts(&mut parts, &())
            .await
            .unwrap();
        assert!(matches!(
            query.to_callback_params(),
            Err(IntegrationError::OAuthError { error, description })
            if error == "invalid_grant" && description == "Code expired"
        ));
    }

    #[tokio::test]
    async fn test_axum_oversized_and_parameter_polluted_query_strings() {
        // Construct an oversized query string (>50KB) with 1,000 dummy parameters + valid code & state
        let mut query_params = vec![
            ("code".to_string(), "target_code_123".to_string()),
            ("state".to_string(), "target_state_456".to_string()),
        ];
        for i in 0..1000 {
            query_params.push((
                format!("dummy_key_{i:04}"),
                format!("dummy_value_{i:04}_padding_string_content_for_size"),
            ));
        }

        let serialized_query = serde_urlencoded::to_string(&query_params).unwrap();
        assert!(serialized_query.len() > 50_000);

        let uri = format!("/oauth/callback?{serialized_query}");
        let req = Request::builder()
            .uri(&uri)
            .body(axum::body::Body::empty())
            .unwrap();

        let (mut parts, _) = req.into_parts();
        let query = OAuthCallbackQuery::from_request_parts(&mut parts, &())
            .await
            .unwrap();

        let params = query.to_callback_params().unwrap();
        assert_eq!(params.code, "target_code_123");
        assert_eq!(params.state, "target_state_456");
    }

    #[tokio::test]
    async fn test_axum_injection_payload_query_strings() {
        let uri = "/oauth/callback?code=%27%20OR%201%3D1%3B--&state=%3Cscript%3Ealert(1)%3C%2Fscript%3E&iss=https%3A%2F%2Fauth.example.com";
        let req = Request::builder()
            .uri(uri)
            .body(axum::body::Body::empty())
            .unwrap();

        let (mut parts, _) = req.into_parts();
        let query = OAuthCallbackQuery::from_request_parts(&mut parts, &())
            .await
            .unwrap();

        let params = query.to_callback_params().unwrap();
        assert_eq!(params.code, "' OR 1=1;--");
        assert_eq!(params.state, "<script>alert(1)</script>");
        assert_eq!(params.iss.as_deref(), Some("https://auth.example.com"));
    }

    #[tokio::test]
    async fn test_axum_authenticated_user_extractor_rejections() {
        // 1. Completely unauthenticated request (no extensions, no headers)
        let req_empty = Request::builder()
            .uri("/api/profile")
            .body(axum::body::Body::empty())
            .unwrap();
        let (mut parts, _) = req_empty.into_parts();
        let err = AuthenticatedUser::from_request_parts(&mut parts, &())
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);

        // 2. Request with invalid Authorization scheme (Bearer instead of DPoP)
        let req_bearer = Request::builder()
            .uri("/api/profile")
            .header(header::AUTHORIZATION, "Bearer some_bearer_token")
            .body(axum::body::Body::empty())
            .unwrap();
        let (mut parts, _) = req_bearer.into_parts();
        let err = AuthenticatedUser::from_request_parts(&mut parts, &())
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
        assert_eq!(err.1["error"], "invalid_token");
    }

    #[tokio::test]
    async fn test_axum_client_metadata_and_redirect_helpers() {
        let metadata = mock_client_metadata();
        let meta_resp = client_metadata_response(&metadata).unwrap();
        assert_eq!(meta_resp.status(), StatusCode::OK);
        assert_eq!(
            meta_resp.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        assert_eq!(
            meta_resp
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap(),
            "*"
        );

        let auth_req = mock_authorization_request();
        let redir_resp = redirect_to_authorization(&auth_req).unwrap();
        assert_eq!(redir_resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            redir_resp.headers().get(header::LOCATION).unwrap(),
            auth_req.authorization_url.as_str()
        );
        assert_eq!(
            redir_resp.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
    }
}

// =========================================================================
// SECTION 3: ACTIX-WEB EXTRACTOR ADVERSARIAL EDGE CASES
// =========================================================================

#[cfg(feature = "actix")]
mod actix_adversarial_tests {
    use super::*;
    use actix_web::dev::Payload;
    use actix_web::http::header as actix_header;
    use actix_web::http::StatusCode as ActixStatusCode;
    use actix_web::test::TestRequest;
    use actix_web::FromRequest;
    use skyauth::integrations::actix::{
        client_metadata_http_response, redirect_to_authorization_http_response,
    };

    #[tokio::test]
    async fn test_actix_missing_code_and_state_parameters() {
        let req_no_state = TestRequest::get()
            .uri("/oauth/callback?code=actix_code_only")
            .to_http_request();
        let mut payload = Payload::None;
        let query = OAuthCallbackQuery::from_request(&req_no_state, &mut payload)
            .await
            .unwrap();
        assert!(matches!(
            query.to_callback_params(),
            Err(IntegrationError::MissingState)
        ));

        let req_no_code = TestRequest::get()
            .uri("/oauth/callback?state=actix_state_only")
            .to_http_request();
        let mut payload = Payload::None;
        let query = OAuthCallbackQuery::from_request(&req_no_code, &mut payload)
            .await
            .unwrap();
        assert!(matches!(
            query.to_callback_params(),
            Err(IntegrationError::MissingCode)
        ));

        let req_err = TestRequest::get()
            .uri("/oauth/callback?error=unauthorized_client&error_description=App+not+registered")
            .to_http_request();
        let mut payload = Payload::None;
        let query = OAuthCallbackQuery::from_request(&req_err, &mut payload)
            .await
            .unwrap();
        assert!(matches!(
            query.to_callback_params(),
            Err(IntegrationError::OAuthError { error, .. })
            if error == "unauthorized_client"
        ));
    }

    #[tokio::test]
    async fn test_actix_oversized_and_injection_query_strings() {
        let mut query_params = vec![
            ("code".to_string(), "actix_code_injection_<!>".to_string()),
            ("state".to_string(), "actix_state_injection_#".to_string()),
        ];
        for i in 0..500 {
            query_params.push((
                format!("actix_dummy_{i:03}"),
                format!("val_{i:03}_padding_1234567890"),
            ));
        }

        let serialized = serde_urlencoded::to_string(&query_params).unwrap();
        let uri = format!("/oauth/callback?{serialized}");

        let req = TestRequest::get().uri(&uri).to_http_request();
        let mut payload = Payload::None;
        let query = OAuthCallbackQuery::from_request(&req, &mut payload)
            .await
            .unwrap();

        let params = query.to_callback_params().unwrap();
        assert_eq!(params.code, "actix_code_injection_<!>");
        assert_eq!(params.state, "actix_state_injection_#");
    }

    #[tokio::test]
    async fn test_actix_authenticated_user_extractor_rejections() {
        // 1. Empty request
        let req_empty = TestRequest::get().uri("/api/feed").to_http_request();
        let mut payload = Payload::None;
        let err = AuthenticatedUser::from_request(&req_empty, &mut payload)
            .await
            .unwrap_err();
        assert_eq!(err.error_response().status(), ActixStatusCode::UNAUTHORIZED);

        // 2. Invalid Scheme
        let req_bearer = TestRequest::get()
            .uri("/api/feed")
            .insert_header(("Authorization", "Bearer actix_bearer_token"))
            .to_http_request();
        let mut payload = Payload::None;
        let err = AuthenticatedUser::from_request(&req_bearer, &mut payload)
            .await
            .unwrap_err();
        assert_eq!(err.error_response().status(), ActixStatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_actix_client_metadata_and_redirect_helpers() {
        let metadata = mock_client_metadata();
        let meta_resp = client_metadata_http_response(&metadata).unwrap();
        assert_eq!(meta_resp.status(), ActixStatusCode::OK);
        assert_eq!(
            meta_resp.headers().get(actix_header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        assert_eq!(
            meta_resp
                .headers()
                .get(actix_header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap(),
            "*"
        );

        let auth_req = mock_authorization_request();
        let redir_resp = redirect_to_authorization_http_response(&auth_req);
        assert_eq!(redir_resp.status(), ActixStatusCode::SEE_OTHER);
        assert_eq!(
            redir_resp
                .headers()
                .get(actix_header::LOCATION)
                .unwrap()
                .to_str()
                .unwrap(),
            auth_req.authorization_url.as_str()
        );
        assert_eq!(
            redir_resp
                .headers()
                .get(actix_header::CACHE_CONTROL)
                .unwrap()
                .to_str()
                .unwrap(),
            "no-store"
        );
    }
}
