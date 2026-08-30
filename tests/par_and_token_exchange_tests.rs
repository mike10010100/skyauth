//! Comprehensive integration tests for Milestone 3 (PAR, Code Exchange, Session, and Auto-Nonce Negotiation).

#![allow(
    dead_code,
    unused_imports,
    missing_docs,
    clippy::all,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

mod e2e_harness;

use std::time::{Duration, SystemTime};
use wiremock::matchers::{body_string_contains, header, header_exists, method, path};
use wiremock::{Mock, ResponseTemplate};

use skyauth::client::{AtprotoOAuthClient, CallbackParams, OAuthClientMetadata, StoredStateEntry};
use skyauth::crypto::constant_time_eq;
use skyauth::dpop::{compute_access_token_hash, DPoPKey, DPoPNonceCache, DPoPVerifier};
use skyauth::error::{AtprotoOAuthError, DPoPError, ParError, StoreError, TokenError};
use skyauth::identity::{IdentityResolverBuilder, ResolvedIdentity};
use skyauth::par::{build_authorization_url, execute_par_request, ParParameters};
use skyauth::pkce::PkcePair;
use skyauth::session::OAuthSession;
use skyauth::ssrf::SsrfFilter;

use e2e_harness::fixtures::*;
use e2e_harness::MockOAuthEnvironment;

#[tokio::test]
async fn test_full_login_and_code_exchange_e2e() {
    let env = MockOAuthEnvironment::start_default().await;

    let request_uri = "urn:ietf:params:oauth:request_uri:req-alice-m3-01";
    env.auth_server.mount_par_success(request_uri, 90).await;

    let access_token = "at_alice_access_token_m3_test";
    let refresh_token = "rt_alice_refresh_token_m3_test";
    env.auth_server
        .mount_token_exchange_success(access_token, refresh_token, TEST_ALICE_DID, 3600)
        .await;

    let ssrf_filter = SsrfFilter::new(true);
    let resolver = IdentityResolverBuilder::new()
        .ssrf_filter(ssrf_filter)
        .plc_directory_url(env.plc.uri())
        .dns_resolver(std::sync::Arc::new(env.dns.clone()))
        .build();

    let client = AtprotoOAuthClient::builder()
        .in_memory_state_store()
        .client_metadata(OAuthClientMetadata::new(TEST_CLIENT_ID, TEST_REDIRECT_URI))
        .identity_resolver(resolver)
        .allow_insecure_localhost(true)
        .build()
        .unwrap();

    // 1. Initiate Login
    let auth_req = client.initiate_login(TEST_ALICE_HANDLE).await.unwrap();

    assert_eq!(auth_req.request_uri(), request_uri);
    assert_eq!(auth_req.expires_in(), 90);
    assert!(auth_req
        .authorization_url()
        .as_str()
        .contains("request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Areq-alice-m3-01"));

    // 2. Exchange Code
    let callback = CallbackParams::new("auth_code_from_redirect", auth_req.expose_state())
        .with_iss(env.auth_server.uri());
    let session = client.handle_callback(&callback).await.unwrap();

    assert_eq!(session.sub(), TEST_ALICE_DID);
    assert_eq!(session.expose_access_token(), access_token);
    assert_eq!(session.expose_refresh_token(), Some(refresh_token));
    assert_eq!(session.token_type(), "DPoP");
    assert_eq!(session.scope(), Some("atproto"));
    assert!(!session.is_expired());
    assert_eq!(session.dpop_auth_header(), format!("DPoP {access_token}"));

    // 3. Create DPoP proof for resource access
    let xrpc_url = format!("{}/xrpc/app.bsky.actor.getProfile", env.pds.uri());
    let proof = session.create_dpop_proof("GET", &xrpc_url, None).unwrap();

    let ath = compute_access_token_hash(access_token);
    let verifier = DPoPVerifier::new();
    let (claims, jwk) = verifier
        .verify_proof(&proof, "GET", &xrpc_url, None, Some(&ath), None)
        .unwrap();

    assert_eq!(claims.htm, "GET");
    assert_eq!(claims.ath.as_deref(), Some(ath.as_str()));
    assert_eq!(jwk.thumbprint(), session.dpop_key().jwk_thumbprint());
}

#[tokio::test]
async fn test_callback_handler_with_iss_and_state_validation() {
    let env = MockOAuthEnvironment::start_default().await;

    let request_uri = "urn:ietf:params:oauth:request_uri:req-alice-cb-01";
    env.auth_server.mount_par_success(request_uri, 90).await;

    let access_token = "at_alice_cb_token";
    let refresh_token = "rt_alice_cb_refresh";
    env.auth_server
        .mount_token_exchange_success(access_token, refresh_token, TEST_ALICE_DID, 3600)
        .await;

    let ssrf_filter = SsrfFilter::new(true);
    let resolver = IdentityResolverBuilder::new()
        .ssrf_filter(ssrf_filter)
        .plc_directory_url(env.plc.uri())
        .dns_resolver(std::sync::Arc::new(env.dns.clone()))
        .build();

    let client = AtprotoOAuthClient::builder()
        .in_memory_state_store()
        .client_metadata(OAuthClientMetadata::new(TEST_CLIENT_ID, TEST_REDIRECT_URI))
        .identity_resolver(resolver)
        .allow_insecure_localhost(true)
        .build()
        .unwrap();

    let auth_req = client.initiate_login(TEST_ALICE_HANDLE).await.unwrap();

    // Valid callback with matching state and iss
    let valid_cb = CallbackParams::new("code_valid_123", auth_req.expose_state())
        .with_iss(env.auth_server.uri());

    let session = client.handle_callback(&valid_cb).await.unwrap();
    assert_eq!(session.sub(), TEST_ALICE_DID);

    // Mismatched state should fail
    let invalid_state_cb =
        CallbackParams::new("code_valid_123", "wrong_state_token").with_iss(&env.auth_server.uri());
    let err_state = client.handle_callback(&invalid_state_cb).await;
    assert!(matches!(
        err_state,
        Err(AtprotoOAuthError::Store(StoreError::StateNotFound))
    ));

    // Mismatched issuer should fail
    let issuer_req = client.initiate_login(TEST_ALICE_HANDLE).await.unwrap();
    let invalid_iss_cb = CallbackParams::new("code_valid_123", issuer_req.expose_state())
        .with_iss("https://attacker-issuer.com");
    let err_iss = client.handle_callback(&invalid_iss_cb).await;
    assert!(matches!(
        err_iss,
        Err(AtprotoOAuthError::Token(TokenError::IssuerMismatch { .. }))
    ));
}

#[tokio::test]
async fn test_par_auto_nonce_retry_success() {
    let env = MockOAuthEnvironment::start_default().await;

    // Challenge nonce once, then succeed
    env.auth_server
        .mount_par_nonce_challenge_once("fresh-par-nonce-turn-1")
        .await;

    let request_uri = "urn:ietf:params:oauth:request_uri:req-after-nonce";
    env.auth_server.mount_par_success(request_uri, 60).await;

    let ssrf_filter = SsrfFilter::new(true);
    let resolver = IdentityResolverBuilder::new()
        .ssrf_filter(ssrf_filter)
        .plc_directory_url(env.plc.uri())
        .dns_resolver(std::sync::Arc::new(env.dns.clone()))
        .build();

    let client = AtprotoOAuthClient::builder()
        .in_memory_state_store()
        .client_metadata(OAuthClientMetadata::new(TEST_CLIENT_ID, TEST_REDIRECT_URI))
        .identity_resolver(resolver)
        .allow_insecure_localhost(true)
        .build()
        .unwrap();

    let auth_req = client.initiate_login(TEST_ALICE_HANDLE).await.unwrap();
    assert_eq!(auth_req.request_uri(), request_uri);
}

#[tokio::test]
async fn test_par_nonce_retry_exhaustion_fails() {
    let env = MockOAuthEnvironment::start_default().await;

    // Always challenge nonce
    env.auth_server
        .mount_par_nonce_challenge("infinite-nonce-loop")
        .await;

    let ssrf_filter = SsrfFilter::new(true);
    let resolver = IdentityResolverBuilder::new()
        .ssrf_filter(ssrf_filter)
        .plc_directory_url(env.plc.uri())
        .dns_resolver(std::sync::Arc::new(env.dns.clone()))
        .build();

    let client = AtprotoOAuthClient::builder()
        .in_memory_state_store()
        .client_metadata(OAuthClientMetadata::new(TEST_CLIENT_ID, TEST_REDIRECT_URI))
        .identity_resolver(resolver)
        .allow_insecure_localhost(true)
        .build()
        .unwrap();

    let res = client.initiate_login(TEST_ALICE_HANDLE).await;
    assert!(matches!(
        res,
        Err(AtprotoOAuthError::DPoP(DPoPError::NonceRetryLimitExceeded))
    ));
}

#[tokio::test]
async fn test_token_exchange_auto_nonce_retry_success() {
    let env = MockOAuthEnvironment::start_default().await;

    let request_uri = "urn:ietf:params:oauth:request_uri:req-tok-01";
    env.auth_server.mount_par_success(request_uri, 90).await;

    // Token endpoint challenges once with fresh nonce, then succeeds
    env.auth_server
        .mount_token_nonce_challenge_once("token-fresh-nonce-99")
        .await;

    let access_token = "at_token_after_nonce";
    let refresh_token = "rt_token_after_nonce";
    env.auth_server
        .mount_token_exchange_success(access_token, refresh_token, TEST_ALICE_DID, 3600)
        .await;

    let ssrf_filter = SsrfFilter::new(true);
    let resolver = IdentityResolverBuilder::new()
        .ssrf_filter(ssrf_filter)
        .plc_directory_url(env.plc.uri())
        .dns_resolver(std::sync::Arc::new(env.dns.clone()))
        .build();

    let client = AtprotoOAuthClient::builder()
        .in_memory_state_store()
        .client_metadata(OAuthClientMetadata::new(TEST_CLIENT_ID, TEST_REDIRECT_URI))
        .identity_resolver(resolver)
        .allow_insecure_localhost(true)
        .build()
        .unwrap();

    let auth_req = client.initiate_login(TEST_ALICE_HANDLE).await.unwrap();
    let callback = CallbackParams::new("auth_code_xyz", auth_req.expose_state())
        .with_iss(env.auth_server.uri());
    let session = client.handle_callback(&callback).await.unwrap();
    assert_eq!(session.expose_access_token(), access_token);
    assert_eq!(
        client
            .nonce_cache()
            .get_nonce(session.dpop_key(), &env.auth_server.uri()),
        Some("token-success-nonce".to_string())
    );
}

#[tokio::test]
async fn test_token_exchange_invalid_token_type_rejected() {
    let env = MockOAuthEnvironment::start_default().await;

    let request_uri = "urn:ietf:params:oauth:request_uri:req-tok-invalid-type";
    env.auth_server.mount_par_success(request_uri, 90).await;

    // Mock token endpoint returning Bearer instead of DPoP
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .insert_header("dpop-nonce", "nonce-token-type")
                .set_body_json(serde_json::json!({
                    "access_token": "bearer_token_123",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "refresh_token": "rt_bearer_123",
                    "scope": "atproto",
                    "sub": TEST_ALICE_DID
                })),
        )
        .mount(&env.auth_server.server)
        .await;

    let ssrf_filter = SsrfFilter::new(true);
    let resolver = IdentityResolverBuilder::new()
        .ssrf_filter(ssrf_filter)
        .plc_directory_url(env.plc.uri())
        .dns_resolver(std::sync::Arc::new(env.dns.clone()))
        .build();

    let client = AtprotoOAuthClient::builder()
        .in_memory_state_store()
        .client_metadata(OAuthClientMetadata::new(TEST_CLIENT_ID, TEST_REDIRECT_URI))
        .identity_resolver(resolver)
        .allow_insecure_localhost(true)
        .build()
        .unwrap();

    let auth_req = client.initiate_login(TEST_ALICE_HANDLE).await.unwrap();
    let callback =
        CallbackParams::new("code_123", auth_req.expose_state()).with_iss(env.auth_server.uri());
    let res = client.handle_callback(&callback).await;
    assert!(matches!(
        res,
        Err(AtprotoOAuthError::Token(TokenError::InvalidTokenType(_)))
    ));
}

#[tokio::test]
async fn test_token_exchange_sub_mismatch_rejected() {
    let env = MockOAuthEnvironment::start_default().await;

    let request_uri = "urn:ietf:params:oauth:request_uri:req-tok-sub-mismatch";
    env.auth_server.mount_par_success(request_uri, 90).await;

    // Server returns different sub DID than expected
    env.auth_server
        .mount_token_exchange_success(
            "at_sample",
            "rt_sample",
            "did:plc:attacker999999999999999",
            3600,
        )
        .await;

    let ssrf_filter = SsrfFilter::new(true);
    let resolver = IdentityResolverBuilder::new()
        .ssrf_filter(ssrf_filter)
        .plc_directory_url(env.plc.uri())
        .dns_resolver(std::sync::Arc::new(env.dns.clone()))
        .build();

    let client = AtprotoOAuthClient::builder()
        .in_memory_state_store()
        .client_metadata(OAuthClientMetadata::new(TEST_CLIENT_ID, TEST_REDIRECT_URI))
        .identity_resolver(resolver)
        .allow_insecure_localhost(true)
        .build()
        .unwrap();

    let auth_req = client.initiate_login(TEST_ALICE_HANDLE).await.unwrap();
    let callback =
        CallbackParams::new("code_123", auth_req.expose_state()).with_iss(env.auth_server.uri());
    let res = client.handle_callback(&callback).await;
    assert!(matches!(
        res,
        Err(AtprotoOAuthError::Token(TokenError::SubMismatch { .. }))
    ));
}

#[tokio::test]
async fn test_token_exchange_missing_atproto_scope_rejected() {
    let env = MockOAuthEnvironment::start_default().await;

    let request_uri = "urn:ietf:params:oauth:request_uri:req-tok-no-atproto-scope";
    env.auth_server.mount_par_success(request_uri, 90).await;

    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .insert_header("dpop-nonce", "nonce-missing-scope")
                .set_body_json(serde_json::json!({
                    "access_token": "at_123",
                    "token_type": "DPoP",
                    "expires_in": 3600,
                    "refresh_token": "rt_123",
                    "scope": "email profile",
                    "sub": TEST_ALICE_DID
                })),
        )
        .mount(&env.auth_server.server)
        .await;

    let ssrf_filter = SsrfFilter::new(true);
    let resolver = IdentityResolverBuilder::new()
        .ssrf_filter(ssrf_filter)
        .plc_directory_url(env.plc.uri())
        .dns_resolver(std::sync::Arc::new(env.dns.clone()))
        .build();

    let client = AtprotoOAuthClient::builder()
        .in_memory_state_store()
        .client_metadata(OAuthClientMetadata::new(TEST_CLIENT_ID, TEST_REDIRECT_URI))
        .identity_resolver(resolver)
        .allow_insecure_localhost(true)
        .build()
        .unwrap();

    let auth_req = client.initiate_login(TEST_ALICE_HANDLE).await.unwrap();
    let callback =
        CallbackParams::new("code_123", auth_req.expose_state()).with_iss(env.auth_server.uri());
    let res = client.handle_callback(&callback).await;
    assert!(matches!(
        res,
        Err(AtprotoOAuthError::Token(TokenError::MissingAtprotoScope(_)))
    ));
}

#[tokio::test]
async fn test_refresh_session_and_rotation_success() {
    let auth_server = e2e_harness::MockAuthServer::start().await;

    let initial_key = DPoPKey::generate();
    let mut session = OAuthSession::new(
        TEST_ALICE_DID,
        "at_initial_token",
        Some("rt_initial_token".to_string()),
        "DPoP",
        Some("atproto".to_string()),
        Some(300),
        initial_key.clone(),
        Some("https://pds.example.com".to_string()),
        Some(auth_server.uri()),
        Some(format!("{}/oauth/token", auth_server.uri())),
    )
    .unwrap();

    let rotated_access_token = "at_refreshed_super_fresh";
    let rotated_refresh_token = "rt_refreshed_rotation_2";

    auth_server
        .mount_token_exchange_success(
            rotated_access_token,
            rotated_refresh_token,
            TEST_ALICE_DID,
            3600,
        )
        .await;

    let client = AtprotoOAuthClient::builder()
        .in_memory_state_store()
        .client_metadata(OAuthClientMetadata::new(TEST_CLIENT_ID, TEST_REDIRECT_URI))
        .allow_insecure_localhost(true)
        .build()
        .unwrap();

    client.refresh_session(&mut session).await.unwrap();

    assert_eq!(session.expose_access_token(), rotated_access_token);
    assert_eq!(session.expose_refresh_token(), Some(rotated_refresh_token));
    assert!(!session.is_expired());
}

#[tokio::test]
async fn test_refresh_session_nonce_retry_success() {
    let auth_server = e2e_harness::MockAuthServer::start().await;

    let initial_key = DPoPKey::generate();
    let mut session = OAuthSession::new(
        TEST_ALICE_DID,
        "at_initial_token",
        Some("rt_initial_token".to_string()),
        "DPoP",
        Some("atproto".to_string()),
        Some(300),
        initial_key.clone(),
        Some("https://pds.example.com".to_string()),
        Some(auth_server.uri()),
        Some(format!("{}/oauth/token", auth_server.uri())),
    )
    .unwrap();

    // Token refresh endpoint challenges nonce once
    auth_server
        .mount_token_nonce_challenge_once("refresh-challenge-nonce-88")
        .await;

    let rotated_access_token = "at_after_refresh_nonce";
    let rotated_refresh_token = "rt_after_refresh_nonce";
    auth_server
        .mount_token_exchange_success(
            rotated_access_token,
            rotated_refresh_token,
            TEST_ALICE_DID,
            3600,
        )
        .await;

    let client = AtprotoOAuthClient::builder()
        .in_memory_state_store()
        .client_metadata(OAuthClientMetadata::new(TEST_CLIENT_ID, TEST_REDIRECT_URI))
        .allow_insecure_localhost(true)
        .build()
        .unwrap();

    client.refresh_session(&mut session).await.unwrap();

    assert_eq!(session.expose_access_token(), rotated_access_token);
    assert_eq!(session.expose_refresh_token(), Some(rotated_refresh_token));
    assert_eq!(
        client
            .nonce_cache()
            .get_nonce(session.dpop_key(), &auth_server.uri()),
        Some("token-success-nonce".to_string())
    );
}

#[tokio::test]
async fn test_refresh_session_missing_refresh_token_rejected() {
    let initial_key = DPoPKey::generate();
    let mut session = OAuthSession::new(
        TEST_ALICE_DID,
        "at_initial_token",
        None, // No refresh token
        "DPoP",
        Some("atproto".to_string()),
        Some(300),
        initial_key.clone(),
        None,
        None,
        Some("https://auth.example.com/oauth/token".to_string()),
    )
    .unwrap();

    let client = AtprotoOAuthClient::builder()
        .in_memory_state_store()
        .client_metadata(OAuthClientMetadata::new(TEST_CLIENT_ID, TEST_REDIRECT_URI))
        .allow_insecure_localhost(true)
        .build()
        .unwrap();

    let res = client.refresh_session(&mut session).await;
    assert!(matches!(
        res,
        Err(AtprotoOAuthError::Token(TokenError::MissingRefreshToken))
    ));
}

#[tokio::test]
async fn test_send_dpop_request_for_xrpc_with_nonce_challenge_recovery() {
    let pds = e2e_harness::MockPds::start().await;

    let access_token = "at_alice_for_xrpc";
    let dpop_key = DPoPKey::generate();

    let xrpc_url = format!("{}/xrpc/app.bsky.actor.getProfile", pds.uri());

    pds.mount_xrpc_dpop_nonce_challenge_once("pds-xrpc-nonce-challenge-55")
        .await;
    pds.mount_xrpc_get_profile(TEST_ALICE_DID, TEST_ALICE_HANDLE)
        .await;

    let client = AtprotoOAuthClient::builder()
        .in_memory_state_store()
        .client_metadata(OAuthClientMetadata::new(TEST_CLIENT_ID, TEST_REDIRECT_URI))
        .allow_insecure_localhost(true)
        .build()
        .unwrap();

    let resp = client
        .send_dpop_request(
            &dpop_key,
            reqwest::Method::GET,
            &xrpc_url,
            Some(access_token),
            None,
            None,
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let profile: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(profile["did"], TEST_ALICE_DID);
    assert_eq!(profile["handle"], TEST_ALICE_HANDLE);
    assert_eq!(
        client.nonce_cache().get_nonce(&dpop_key, &pds.uri()),
        Some("pds-success-nonce".to_string())
    );
}

#[tokio::test]
async fn test_initiate_login_with_custom_scope() {
    let env = MockOAuthEnvironment::start_default().await;

    let request_uri = "urn:ietf:params:oauth:request_uri:req-custom-scope";
    Mock::given(method("POST"))
        .and(path("/oauth/par"))
        .and(header_exists("dpop"))
        .and(body_string_contains(
            "scope=atproto+transition%3Ageneric+transition%3Achat",
        ))
        .respond_with(
            ResponseTemplate::new(201)
                .insert_header("content-type", "application/json")
                .insert_header("dpop-nonce", "par-custom-scope-nonce")
                .set_body_json(serde_json::json!({
                    "request_uri": request_uri,
                    "expires_in": 90
                })),
        )
        .mount(&env.auth_server.server)
        .await;

    let ssrf_filter = SsrfFilter::new(true);
    let resolver = IdentityResolverBuilder::new()
        .ssrf_filter(ssrf_filter)
        .plc_directory_url(env.plc.uri())
        .dns_resolver(std::sync::Arc::new(env.dns.clone()))
        .build();

    let custom_scope = "atproto transition:generic transition:chat";
    let client = AtprotoOAuthClient::builder()
        .in_memory_state_store()
        .client_metadata(
            OAuthClientMetadata::new(TEST_CLIENT_ID, TEST_REDIRECT_URI).with_scope(custom_scope),
        )
        .identity_resolver(resolver)
        .allow_insecure_localhost(true)
        .build()
        .unwrap();

    let auth_req = client
        .initiate_login_with_scope(TEST_ALICE_HANDLE, custom_scope)
        .await
        .unwrap();

    assert_eq!(auth_req.request_uri(), request_uri);
    assert!(client
        .state_store()
        .contains_state(auth_req.expose_state())
        .await
        .unwrap());
}

#[tokio::test]
async fn test_refresh_token_returns_new_session_instance() {
    let auth_server = e2e_harness::MockAuthServer::start().await;

    let initial_key = DPoPKey::generate();
    let session = OAuthSession::new(
        TEST_ALICE_DID,
        "at_old_token",
        Some("rt_old_token".to_string()),
        "DPoP",
        Some("atproto".to_string()),
        Some(300),
        initial_key.clone(),
        Some("https://pds.example.com".to_string()),
        Some(auth_server.uri()),
        Some(format!("{}/oauth/token", auth_server.uri())),
    )
    .unwrap();

    let new_at = "at_brand_new";
    let new_rt = "rt_brand_new";
    auth_server
        .mount_token_exchange_success(new_at, new_rt, TEST_ALICE_DID, 7200)
        .await;

    let client = AtprotoOAuthClient::builder()
        .in_memory_state_store()
        .client_metadata(OAuthClientMetadata::new(TEST_CLIENT_ID, TEST_REDIRECT_URI))
        .allow_insecure_localhost(true)
        .build()
        .unwrap();

    let updated_session = client.refresh_token(&session).await.unwrap();

    assert_eq!(updated_session.expose_access_token(), new_at);
    assert_eq!(updated_session.expose_refresh_token(), Some(new_rt));
    assert_eq!(session.expose_access_token(), "at_old_token"); // Original unchanged
}

#[test]
fn test_par_parameters_with_client_assertion() {
    let params = ParParameters::new(
        "https://app.example.com/client.json",
        "https://app.example.com/callback",
        "atproto",
        "state_token",
        "pkce_challenge",
    )
    .with_client_assertion(
        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "jwt.assertion.token",
    );

    let form = params.to_form_urlencoded();
    assert!(form.contains(
        "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer"
    ));
    assert!(form.contains("client_assertion=jwt.assertion.token"));
}

#[test]
fn test_session_expiration_leeway_calculations() {
    let key = DPoPKey::generate();
    let session = OAuthSession::new(
        "did:plc:test",
        "at_123",
        None,
        "DPoP",
        None,
        Some(60), // Expires in 60s
        key,
        None,
        None,
        None,
    )
    .unwrap();

    assert!(!session.is_expired());
    assert!(!session.is_expired_with_leeway(Duration::from_secs(30)));
    assert!(session.is_expired_with_leeway(Duration::from_secs(120)));
}
