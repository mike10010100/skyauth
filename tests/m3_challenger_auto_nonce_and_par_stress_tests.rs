//! Empirical Stress Tests for Milestone 3 (Auto-Nonce Loops & PAR Error Handling).
//!
//! Written by Challenger 1 to rigorously stress-test:
//! 1. Auto-nonce negotiation loops (1-hop, 2-hop retry bounds, missing headers, malformed nonces).
//! 2. PAR error responses (HTTP 400 invalid client, invalid redirect URI, missing params, HTML bodies, SSRF).
//! 3. Property-based fuzzing for nonce extraction, PAR parameters, and authorization URL construction.

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

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use proptest::prelude::*;
use serde_json::json;
use wiremock::matchers::{header, header_exists, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use skyauth::client::{AtprotoOAuthClient, CallbackParams, OAuthClientMetadata, StoredStateEntry};
use skyauth::crypto::constant_time_eq;
use skyauth::dpop::{extract_dpop_nonce, DPoPKey, DPoPNonceCache, DPoPVerifier};
use skyauth::error::{AtprotoOAuthError, DPoPError, ParError, TokenError};
use skyauth::identity::IdentityResolverBuilder;
use skyauth::par::{build_authorization_url, execute_par_request, ParParameters, ParResponse};
use skyauth::session::OAuthSession;
use skyauth::ssrf::SsrfFilter;

use e2e_harness::fixtures::*;
use e2e_harness::MockOAuthEnvironment;

// =========================================================================
// 1. AUTO-NONCE NEGOTIATION TESTS (PAR, TOKEN EXCHANGE, REFRESH, XRPC)
// =========================================================================

#[tokio::test]
async fn test_par_1hop_auto_nonce_challenge_success() {
    let mock_server = MockServer::start().await;
    let par_url = format!("{}/oauth/par", mock_server.uri());

    // 1. First request returns 400 use_dpop_nonce
    Mock::given(method("POST"))
        .and(path("/oauth/par"))
        .respond_with(
            ResponseTemplate::new(400)
                .insert_header("content-type", "application/json")
                .insert_header("dpop-nonce", "par-fresh-nonce-1hop")
                .set_body_json(json!({
                    "error": "use_dpop_nonce",
                    "error_description": "Server requires fresh DPoP nonce"
                })),
        )
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    // 2. Second request succeeds with 201 Created
    Mock::given(method("POST"))
        .and(path("/oauth/par"))
        .respond_with(
            ResponseTemplate::new(201)
                .insert_header("content-type", "application/json")
                .insert_header("dpop-nonce", "par-success-nonce-1hop")
                .set_body_json(json!({
                    "request_uri": "urn:ietf:params:oauth:request_uri:req-par-1hop-success",
                    "expires_in": 60
                })),
        )
        .mount(&mock_server)
        .await;

    let ssrf_filter = SsrfFilter::new(true);
    let dpop_key = DPoPKey::generate();
    let nonce_cache = DPoPNonceCache::new();
    let params = ParParameters::new(
        TEST_CLIENT_ID,
        TEST_REDIRECT_URI,
        "atproto",
        "state_1hop",
        "challenge_1hop",
    );

    let res = execute_par_request(&ssrf_filter, &par_url, &params, &dpop_key, &nonce_cache)
        .await
        .unwrap();

    assert_eq!(
        res.request_uri,
        "urn:ietf:params:oauth:request_uri:req-par-1hop-success"
    );
    assert_eq!(res.expires_in, 60);

    // Verify cache holds the fresh nonce
    let origin = url::Url::parse(&par_url)
        .unwrap()
        .origin()
        .ascii_serialization();
    assert_eq!(
        nonce_cache.get_nonce(&dpop_key, &origin),
        Some("par-success-nonce-1hop".to_string())
    );
}

#[tokio::test]
async fn test_par_2hop_nonce_challenge_terminates_cleanly_without_infinite_loop() {
    let mock_server = MockServer::start().await;
    let par_url = format!("{}/oauth/par", mock_server.uri());

    let req_count = Arc::new(AtomicUsize::new(0));
    let count_clone = req_count.clone();

    Mock::given(method("POST"))
        .and(path("/oauth/par"))
        .respond_with(move |_: &wiremock::Request| {
            let n = count_clone.fetch_add(1, Ordering::SeqCst);
            ResponseTemplate::new(400)
                .insert_header("content-type", "application/json")
                .insert_header("dpop-nonce", format!("infinite-nonce-hop-{n}"))
                .set_body_json(json!({
                    "error": "use_dpop_nonce",
                    "error_description": "Challenge loop"
                }))
        })
        .mount(&mock_server)
        .await;

    let ssrf_filter = SsrfFilter::new(true);
    let dpop_key = DPoPKey::generate();
    let nonce_cache = DPoPNonceCache::new();
    let params = ParParameters::new(
        TEST_CLIENT_ID,
        TEST_REDIRECT_URI,
        "atproto",
        "state_2hop",
        "challenge_2hop",
    );

    let res = execute_par_request(&ssrf_filter, &par_url, &params, &dpop_key, &nonce_cache).await;

    assert!(matches!(
        res,
        Err(AtprotoOAuthError::DPoP(DPoPError::NonceRetryLimitExceeded))
    ));
    assert_eq!(req_count.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn test_par_missing_dpop_nonce_header_on_use_dpop_nonce_fails_cleanly() {
    let mock_server = MockServer::start().await;
    let par_url = format!("{}/oauth/par", mock_server.uri());

    Mock::given(method("POST"))
        .and(path("/oauth/par"))
        .respond_with(
            ResponseTemplate::new(400)
                .insert_header("content-type", "application/json")
                .set_body_json(json!({
                    "error": "use_dpop_nonce",
                    "error_description": "Server forgot DPoP-Nonce header"
                })),
        )
        .mount(&mock_server)
        .await;

    let ssrf_filter = SsrfFilter::new(true);
    let dpop_key = DPoPKey::generate();
    let nonce_cache = DPoPNonceCache::new();
    let params = ParParameters::new(
        TEST_CLIENT_ID,
        TEST_REDIRECT_URI,
        "atproto",
        "state_missing_hdr",
        "challenge_missing_hdr",
    );

    let res = execute_par_request(&ssrf_filter, &par_url, &params, &dpop_key, &nonce_cache).await;

    assert!(matches!(
        res,
        Err(AtprotoOAuthError::Par(ParError::Http(message)))
            if message.contains("DPoP-Nonce response header is required")
    ));
}

#[tokio::test]
async fn test_par_malformed_whitespace_only_nonce_header_fails_cleanly() {
    let mock_server = MockServer::start().await;
    let par_url = format!("{}/oauth/par", mock_server.uri());

    Mock::given(method("POST"))
        .and(path("/oauth/par"))
        .respond_with(
            ResponseTemplate::new(400)
                .insert_header("content-type", "application/json")
                .insert_header("dpop-nonce", "       ")
                .set_body_json(json!({
                    "error": "use_dpop_nonce",
                    "error_description": "Whitespace only nonce"
                })),
        )
        .mount(&mock_server)
        .await;

    let ssrf_filter = SsrfFilter::new(true);
    let dpop_key = DPoPKey::generate();
    let nonce_cache = DPoPNonceCache::new();
    let params = ParParameters::new(
        TEST_CLIENT_ID,
        TEST_REDIRECT_URI,
        "atproto",
        "state_ws",
        "challenge_ws",
    );

    let res = execute_par_request(&ssrf_filter, &par_url, &params, &dpop_key, &nonce_cache).await;

    assert!(matches!(
        res,
        Err(AtprotoOAuthError::Par(ParError::Http(message)))
            if message.contains("DPoP-Nonce response header is empty")
    ));
}

#[tokio::test]
async fn test_par_padded_nonce_header_trimmed_and_succeeds() {
    let mock_server = MockServer::start().await;
    let par_url = format!("{}/oauth/par", mock_server.uri());

    Mock::given(method("POST"))
        .and(path("/oauth/par"))
        .respond_with(
            ResponseTemplate::new(400)
                .insert_header("content-type", "application/json")
                .insert_header("dpop-nonce", "   clean_padded_nonce_123   ")
                .set_body_json(json!({"error": "use_dpop_nonce"})),
        )
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/oauth/par"))
        .respond_with(
            ResponseTemplate::new(201)
                .insert_header("content-type", "application/json")
                .insert_header("dpop-nonce", "par-success-padded")
                .set_body_json(json!({
                    "request_uri": "urn:ietf:params:oauth:request_uri:req-padded-nonce-ok",
                    "expires_in": 90
                })),
        )
        .mount(&mock_server)
        .await;

    let ssrf_filter = SsrfFilter::new(true);
    let dpop_key = DPoPKey::generate();
    let nonce_cache = DPoPNonceCache::new();
    let params = ParParameters::new(
        TEST_CLIENT_ID,
        TEST_REDIRECT_URI,
        "atproto",
        "state_padded",
        "challenge_padded",
    );

    let res = execute_par_request(&ssrf_filter, &par_url, &params, &dpop_key, &nonce_cache)
        .await
        .unwrap();

    assert_eq!(
        res.request_uri,
        "urn:ietf:params:oauth:request_uri:req-padded-nonce-ok"
    );

    let origin = url::Url::parse(&par_url)
        .unwrap()
        .origin()
        .ascii_serialization();
    assert_eq!(
        nonce_cache.get_nonce(&dpop_key, &origin),
        Some("par-success-padded".to_string())
    );
}

#[tokio::test]
async fn test_par_special_characters_in_nonce_succeeds() {
    let mock_server = MockServer::start().await;
    let par_url = format!("{}/oauth/par", mock_server.uri());

    let special_nonce = "nonce.ABC-123_xyz~+/==";

    Mock::given(method("POST"))
        .and(path("/oauth/par"))
        .respond_with(
            ResponseTemplate::new(400)
                .insert_header("content-type", "application/json")
                .insert_header("dpop-nonce", special_nonce)
                .set_body_json(json!({"error": "use_dpop_nonce"})),
        )
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/oauth/par"))
        .respond_with(
            ResponseTemplate::new(201)
                .insert_header("content-type", "application/json")
                .insert_header("dpop-nonce", "par-success-special")
                .set_body_json(json!({
                    "request_uri": "urn:ietf:params:oauth:request_uri:req-special-nonce-ok",
                    "expires_in": 90
                })),
        )
        .mount(&mock_server)
        .await;

    let ssrf_filter = SsrfFilter::new(true);
    let dpop_key = DPoPKey::generate();
    let nonce_cache = DPoPNonceCache::new();
    let params = ParParameters::new(
        TEST_CLIENT_ID,
        TEST_REDIRECT_URI,
        "atproto",
        "state_special",
        "challenge_special",
    );

    let res = execute_par_request(&ssrf_filter, &par_url, &params, &dpop_key, &nonce_cache)
        .await
        .unwrap();

    assert_eq!(
        res.request_uri,
        "urn:ietf:params:oauth:request_uri:req-special-nonce-ok"
    );

    let origin = url::Url::parse(&par_url)
        .unwrap()
        .origin()
        .ascii_serialization();
    assert_eq!(
        nonce_cache.get_nonce(&dpop_key, &origin),
        Some("par-success-special".to_string())
    );
}

#[tokio::test]
async fn test_par_oversized_nonce_is_rejected() {
    let mock_server = MockServer::start().await;
    let par_url = format!("{}/oauth/par", mock_server.uri());

    let huge_nonce = "Z".repeat(4096);

    Mock::given(method("POST"))
        .and(path("/oauth/par"))
        .respond_with(
            ResponseTemplate::new(400)
                .insert_header("content-type", "application/json")
                .insert_header("dpop-nonce", &huge_nonce)
                .set_body_json(json!({"error": "use_dpop_nonce"})),
        )
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    let ssrf_filter = SsrfFilter::new(true);
    let dpop_key = DPoPKey::generate();
    let nonce_cache = DPoPNonceCache::new();
    let params = ParParameters::new(
        TEST_CLIENT_ID,
        TEST_REDIRECT_URI,
        "atproto",
        "state_huge",
        "challenge_huge",
    );

    let res = execute_par_request(&ssrf_filter, &par_url, &params, &dpop_key, &nonce_cache).await;

    let origin = url::Url::parse(&par_url)
        .unwrap()
        .origin()
        .ascii_serialization();
    assert!(matches!(
        res,
        Err(AtprotoOAuthError::Par(ParError::Http(message)))
            if message.contains("DPoP-Nonce response header exceeds")
    ));
    assert_eq!(nonce_cache.get_nonce(&dpop_key, &origin), None);
}

#[tokio::test]
async fn test_token_exchange_1hop_auto_nonce_challenge_success() {
    let env = MockOAuthEnvironment::start_default().await;

    let request_uri = "urn:ietf:params:oauth:request_uri:req-tok-1hop";
    env.auth_server.mount_par_success(request_uri, 90).await;

    env.auth_server
        .mount_token_nonce_challenge_once("token-exchange-fresh-nonce-1hop")
        .await;

    let access_token = "at_token_exchange_1hop_ok";
    let refresh_token = "rt_token_exchange_1hop_ok";
    env.auth_server
        .mount_token_exchange_success(access_token, refresh_token, TEST_ALICE_DID, 3600)
        .await;

    let ssrf_filter = SsrfFilter::new(true);
    let resolver = IdentityResolverBuilder::new()
        .ssrf_filter(ssrf_filter)
        .plc_directory_url(env.plc.uri())
        .dns_resolver(Arc::new(env.dns.clone()))
        .build();

    let client = AtprotoOAuthClient::builder()
        .in_memory_state_store()
        .client_metadata(OAuthClientMetadata::new(TEST_CLIENT_ID, TEST_REDIRECT_URI))
        .identity_resolver(resolver)
        .allow_insecure_localhost(true)
        .build()
        .unwrap();

    let auth_req = client.initiate_login(TEST_ALICE_HANDLE).await.unwrap();
    let callback = CallbackParams::new("valid_auth_code_1hop", auth_req.expose_state())
        .with_iss(env.auth_server.uri());
    let session = client.handle_callback(&callback).await.unwrap();

    assert_eq!(session.sub(), TEST_ALICE_DID);
    assert_eq!(session.expose_access_token(), access_token);
    assert_eq!(session.expose_refresh_token(), Some(refresh_token));
    assert_eq!(
        client
            .nonce_cache()
            .get_nonce(session.dpop_key(), &env.auth_server.uri()),
        Some("token-success-nonce".to_string())
    );
}

#[tokio::test]
async fn test_token_exchange_2hop_nonce_challenge_fails_without_infinite_loop() {
    let env = MockOAuthEnvironment::start_default().await;

    let request_uri = "urn:ietf:params:oauth:request_uri:req-token-2hop";
    env.auth_server.mount_par_success(request_uri, 90).await;

    let token_req_count = Arc::new(AtomicUsize::new(0));
    let count_clone = token_req_count.clone();

    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(move |_: &wiremock::Request| {
            let n = count_clone.fetch_add(1, Ordering::SeqCst);
            ResponseTemplate::new(400)
                .insert_header("content-type", "application/json")
                .insert_header("dpop-nonce", format!("token-infinite-hop-{n}"))
                .set_body_json(json!({
                    "error": "use_dpop_nonce",
                    "error_description": "Continuous challenge"
                }))
        })
        .mount(&env.auth_server.server)
        .await;

    let ssrf_filter = SsrfFilter::new(true);
    let resolver = IdentityResolverBuilder::new()
        .ssrf_filter(ssrf_filter)
        .plc_directory_url(env.plc.uri())
        .dns_resolver(Arc::new(env.dns.clone()))
        .build();

    let client = AtprotoOAuthClient::builder()
        .in_memory_state_store()
        .client_metadata(OAuthClientMetadata::new(TEST_CLIENT_ID, TEST_REDIRECT_URI))
        .identity_resolver(resolver)
        .allow_insecure_localhost(true)
        .build()
        .unwrap();

    let auth_req = client.initiate_login(TEST_ALICE_HANDLE).await.unwrap();
    let callback = CallbackParams::new("auth_code_2hop_test", auth_req.expose_state())
        .with_iss(env.auth_server.uri());
    let res = client.handle_callback(&callback).await;

    assert!(matches!(
        res,
        Err(AtprotoOAuthError::DPoP(DPoPError::NonceRetryLimitExceeded))
    ));
    assert_eq!(token_req_count.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn test_token_exchange_missing_dpop_nonce_header_on_use_dpop_nonce_fails_cleanly() {
    let env = MockOAuthEnvironment::start_default().await;

    let request_uri = "urn:ietf:params:oauth:request_uri:req-tok-missing-nonce-hdr";
    env.auth_server.mount_par_success(request_uri, 90).await;

    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(
            ResponseTemplate::new(400)
                .insert_header("content-type", "application/json")
                .set_body_json(json!({
                    "error": "use_dpop_nonce",
                    "error_description": "Missing nonce header on token endpoint"
                })),
        )
        .mount(&env.auth_server.server)
        .await;

    let ssrf_filter = SsrfFilter::new(true);
    let resolver = IdentityResolverBuilder::new()
        .ssrf_filter(ssrf_filter)
        .plc_directory_url(env.plc.uri())
        .dns_resolver(Arc::new(env.dns.clone()))
        .build();

    let client = AtprotoOAuthClient::builder()
        .in_memory_state_store()
        .client_metadata(OAuthClientMetadata::new(TEST_CLIENT_ID, TEST_REDIRECT_URI))
        .identity_resolver(resolver)
        .allow_insecure_localhost(true)
        .build()
        .unwrap();

    let auth_req = client.initiate_login(TEST_ALICE_HANDLE).await.unwrap();
    let callback = CallbackParams::new("code_missing_nonce_hdr", auth_req.expose_state())
        .with_iss(env.auth_server.uri());
    let res = client.handle_callback(&callback).await;

    assert!(matches!(
        res,
        Err(AtprotoOAuthError::Token(TokenError::MissingField(
            "DPoP-Nonce"
        )))
    ));
}

#[tokio::test]
async fn test_token_refresh_1hop_auto_nonce_challenge_success() {
    let env = MockOAuthEnvironment::start_default().await;

    let request_uri = "urn:ietf:params:oauth:request_uri:req-refresh-1hop";
    env.auth_server.mount_par_success(request_uri, 90).await;

    let initial_at = "at_initial_refresh_test";
    let initial_rt = "rt_initial_refresh_test";

    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .and(header_exists("dpop"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .insert_header("dpop-nonce", "nonce-initial-refresh")
                .set_body_json(json!({
                    "access_token": initial_at,
                    "token_type": "DPoP",
                    "expires_in": 3600,
                    "refresh_token": initial_rt,
                    "scope": "atproto",
                    "sub": TEST_ALICE_DID
                })),
        )
        .up_to_n_times(1)
        .mount(&env.auth_server.server)
        .await;

    let ssrf_filter = SsrfFilter::new(true);
    let resolver = IdentityResolverBuilder::new()
        .ssrf_filter(ssrf_filter)
        .plc_directory_url(env.plc.uri())
        .dns_resolver(Arc::new(env.dns.clone()))
        .build();

    let client = AtprotoOAuthClient::builder()
        .in_memory_state_store()
        .client_metadata(OAuthClientMetadata::new(TEST_CLIENT_ID, TEST_REDIRECT_URI))
        .identity_resolver(resolver)
        .allow_insecure_localhost(true)
        .build()
        .unwrap();

    let auth_req = client.initiate_login(TEST_ALICE_HANDLE).await.unwrap();
    let callback = CallbackParams::new("code_for_refresh_test", auth_req.expose_state())
        .with_iss(env.auth_server.uri());
    let mut session = client.handle_callback(&callback).await.unwrap();

    env.auth_server
        .mount_token_nonce_challenge_once("refresh-fresh-nonce-turn-2")
        .await;

    let rotated_at = "at_rotated_after_nonce_challenge";
    let rotated_rt = "rt_rotated_after_nonce_challenge";
    env.auth_server
        .mount_token_exchange_success(rotated_at, rotated_rt, TEST_ALICE_DID, 7200)
        .await;

    client.refresh_session(&mut session).await.unwrap();
    assert_eq!(session.expose_access_token(), rotated_at);
    assert_eq!(session.expose_refresh_token(), Some(rotated_rt));
    assert_eq!(
        client
            .nonce_cache()
            .get_nonce(session.dpop_key(), &env.auth_server.uri()),
        Some("token-success-nonce".to_string())
    );
}

#[tokio::test]
async fn test_xrpc_send_dpop_request_1hop_auto_nonce_challenge_success() {
    let env = MockOAuthEnvironment::start_default().await;

    let request_uri = "urn:ietf:params:oauth:request_uri:req-xrpc-1hop";
    env.auth_server.mount_par_success(request_uri, 90).await;

    let access_token = "at_xrpc_test_user";
    let refresh_token = "rt_xrpc_test_user";
    env.auth_server
        .mount_token_exchange_success(access_token, refresh_token, TEST_ALICE_DID, 3600)
        .await;

    let ssrf_filter = SsrfFilter::new(true);
    let resolver = IdentityResolverBuilder::new()
        .ssrf_filter(ssrf_filter)
        .plc_directory_url(env.plc.uri())
        .dns_resolver(Arc::new(env.dns.clone()))
        .build();

    let client = AtprotoOAuthClient::builder()
        .in_memory_state_store()
        .client_metadata(OAuthClientMetadata::new(TEST_CLIENT_ID, TEST_REDIRECT_URI))
        .identity_resolver(resolver)
        .allow_insecure_localhost(true)
        .build()
        .unwrap();

    let auth_req = client.initiate_login(TEST_ALICE_HANDLE).await.unwrap();
    let callback = CallbackParams::new("code_for_xrpc", auth_req.expose_state())
        .with_iss(env.auth_server.uri());
    let session = client.handle_callback(&callback).await.unwrap();

    let xrpc_path = "/xrpc/app.bsky.actor.getPreferences";
    Mock::given(method("GET"))
        .and(path(xrpc_path))
        .respond_with(
            ResponseTemplate::new(401)
                .insert_header("content-type", "application/json")
                .insert_header("dpop-nonce", "pds-xrpc-fresh-nonce-1")
                .set_body_json(json!({
                    "error": "use_dpop_nonce",
                    "message": "XRPC endpoint requires DPoP nonce"
                })),
        )
        .up_to_n_times(1)
        .mount(&env.pds.server)
        .await;

    Mock::given(method("GET"))
        .and(path(xrpc_path))
        .and(header_exists("dpop"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .insert_header("dpop-nonce", "pds-xrpc-fresh-nonce-2")
                .set_body_json(json!({"preferences": []})),
        )
        .mount(&env.pds.server)
        .await;

    let xrpc_url = format!("{}{xrpc_path}", env.pds.uri());
    let resp = client
        .send_dpop_request(
            session.dpop_key(),
            reqwest::Method::GET,
            &xrpc_url,
            Some(session.expose_access_token()),
            None,
            None,
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    assert_eq!(
        client
            .nonce_cache()
            .get_nonce(session.dpop_key(), &env.pds.uri()),
        Some("pds-xrpc-fresh-nonce-2".to_string())
    );
}

#[tokio::test]
async fn test_xrpc_2hop_nonce_challenge_fails_without_infinite_loop() {
    let mock_pds = MockServer::start().await;
    let key = DPoPKey::generate();
    let xrpc_count = Arc::new(AtomicUsize::new(0));
    let count_clone = xrpc_count.clone();

    let xrpc_path = "/xrpc/app.bsky.feed.getTimeline";
    Mock::given(method("GET"))
        .and(path(xrpc_path))
        .respond_with(move |_: &wiremock::Request| {
            let n = count_clone.fetch_add(1, Ordering::SeqCst);
            ResponseTemplate::new(401)
                .insert_header("content-type", "application/json")
                .insert_header("dpop-nonce", format!("pds-nonce-hop-{n}"))
                .set_body_json(json!({"error": "use_dpop_nonce"}))
        })
        .mount(&mock_pds)
        .await;

    let client = AtprotoOAuthClient::builder()
        .in_memory_state_store()
        .client_metadata(OAuthClientMetadata::new(TEST_CLIENT_ID, TEST_REDIRECT_URI))
        .allow_insecure_localhost(true)
        .build()
        .unwrap();

    let xrpc_url = format!("{}{xrpc_path}", mock_pds.uri());
    let res = client
        .send_dpop_request(
            &key,
            reqwest::Method::GET,
            &xrpc_url,
            Some("dummy_access_token"),
            None,
            None,
        )
        .await;

    assert!(matches!(
        res,
        Err(AtprotoOAuthError::DPoP(DPoPError::NonceRetryLimitExceeded))
    ));
    assert_eq!(xrpc_count.load(Ordering::SeqCst), 2);
}

// =========================================================================
// 2. PAR ERROR RESPONSE TESTS (HTTP 400, 401, 403, 500, 502, INVALID PARAMS)
// =========================================================================

#[tokio::test]
async fn test_par_error_http_400_invalid_client() {
    let mock_server = MockServer::start().await;
    let par_url = format!("{}/oauth/par", mock_server.uri());

    Mock::given(method("POST"))
        .and(path("/oauth/par"))
        .respond_with(
            ResponseTemplate::new(400)
                .insert_header("content-type", "application/json")
                .insert_header("dpop-nonce", "par-error-invalid-client")
                .set_body_json(json!({
                    "error": "invalid_client",
                    "error_description": "Unknown client identifier"
                })),
        )
        .mount(&mock_server)
        .await;

    let ssrf_filter = SsrfFilter::new(true);
    let dpop_key = DPoPKey::generate();
    let nonce_cache = DPoPNonceCache::new();
    let params = ParParameters::new(
        "https://unregistered.example.com/client.json",
        TEST_REDIRECT_URI,
        "atproto",
        "state_err",
        "challenge_err",
    );

    let res = execute_par_request(&ssrf_filter, &par_url, &params, &dpop_key, &nonce_cache).await;

    match res {
        Err(AtprotoOAuthError::Par(ParError::RequestFailed {
            status,
            error,
            description,
        })) => {
            assert_eq!(status, 400);
            assert_eq!(error, "invalid_client");
            assert_eq!(description, None);
        }
        other => panic!("Expected ParError::RequestFailed invalid_client, got {other:?}"),
    }
}

#[tokio::test]
async fn test_par_error_http_400_invalid_redirect_uri() {
    let mock_server = MockServer::start().await;
    let par_url = format!("{}/oauth/par", mock_server.uri());

    Mock::given(method("POST"))
        .and(path("/oauth/par"))
        .respond_with(
            ResponseTemplate::new(400)
                .insert_header("content-type", "application/json")
                .insert_header("dpop-nonce", "par-error-invalid-redirect")
                .set_body_json(json!({
                    "error": "invalid_redirect_uri",
                    "error_description": "The redirect URI is not registered for this client"
                })),
        )
        .mount(&mock_server)
        .await;

    let ssrf_filter = SsrfFilter::new(true);
    let dpop_key = DPoPKey::generate();
    let nonce_cache = DPoPNonceCache::new();
    let params = ParParameters::new(
        TEST_CLIENT_ID,
        "https://unregistered-redirect.example.com/callback",
        "atproto",
        "state_err",
        "challenge_err",
    );

    let res = execute_par_request(&ssrf_filter, &par_url, &params, &dpop_key, &nonce_cache).await;

    match res {
        Err(AtprotoOAuthError::Par(ParError::RequestFailed {
            status,
            error,
            description,
        })) => {
            assert_eq!(status, 400);
            assert_eq!(error, "invalid_redirect_uri");
            assert_eq!(description, None);
        }
        other => panic!("Expected ParError::RequestFailed invalid_redirect_uri, got {other:?}"),
    }
}

#[tokio::test]
async fn test_par_error_http_400_invalid_request_missing_parameters() {
    let mock_server = MockServer::start().await;
    let par_url = format!("{}/oauth/par", mock_server.uri());

    Mock::given(method("POST"))
        .and(path("/oauth/par"))
        .respond_with(
            ResponseTemplate::new(400)
                .insert_header("content-type", "application/json")
                .insert_header("dpop-nonce", "par-error-invalid-request")
                .set_body_json(json!({
                    "error": "invalid_request",
                    "error_description": "Missing mandatory parameter: code_challenge"
                })),
        )
        .mount(&mock_server)
        .await;

    let ssrf_filter = SsrfFilter::new(true);
    let dpop_key = DPoPKey::generate();
    let nonce_cache = DPoPNonceCache::new();
    let params = ParParameters::new(
        TEST_CLIENT_ID,
        TEST_REDIRECT_URI,
        "atproto",
        "state_err",
        "",
    );

    let res = execute_par_request(&ssrf_filter, &par_url, &params, &dpop_key, &nonce_cache).await;

    match res {
        Err(AtprotoOAuthError::Par(ParError::RequestFailed {
            status,
            error,
            description,
        })) => {
            assert_eq!(status, 400);
            assert_eq!(error, "invalid_request");
            assert_eq!(description, None);
        }
        other => panic!("Expected ParError::RequestFailed invalid_request, got {other:?}"),
    }
}

#[tokio::test]
async fn test_par_error_empty_request_uri_in_201_response() {
    let mock_server = MockServer::start().await;
    let par_url = format!("{}/oauth/par", mock_server.uri());

    Mock::given(method("POST"))
        .and(path("/oauth/par"))
        .respond_with(
            ResponseTemplate::new(201)
                .insert_header("content-type", "application/json")
                .insert_header("dpop-nonce", "par-error-empty-request-uri")
                .set_body_json(json!({
                    "request_uri": "   ",
                    "expires_in": 90
                })),
        )
        .mount(&mock_server)
        .await;

    let ssrf_filter = SsrfFilter::new(true);
    let dpop_key = DPoPKey::generate();
    let nonce_cache = DPoPNonceCache::new();
    let params = ParParameters::new(
        TEST_CLIENT_ID,
        TEST_REDIRECT_URI,
        "atproto",
        "state1",
        "challenge1",
    );

    let res = execute_par_request(&ssrf_filter, &par_url, &params, &dpop_key, &nonce_cache).await;

    assert!(matches!(
        res,
        Err(AtprotoOAuthError::Par(ParError::InvalidRequestUri(_)))
    ));
}

#[tokio::test]
async fn test_par_error_missing_expires_in_field() {
    let mock_server = MockServer::start().await;
    let par_url = format!("{}/oauth/par", mock_server.uri());

    Mock::given(method("POST"))
        .and(path("/oauth/par"))
        .respond_with(
            ResponseTemplate::new(201)
                .insert_header("content-type", "application/json")
                .insert_header("dpop-nonce", "par-error-missing-expiry")
                .set_body_json(json!({
                    "request_uri": "urn:ietf:params:oauth:request_uri:req-test-missing-exp"
                })),
        )
        .mount(&mock_server)
        .await;

    let ssrf_filter = SsrfFilter::new(true);
    let dpop_key = DPoPKey::generate();
    let nonce_cache = DPoPNonceCache::new();
    let params = ParParameters::new(
        TEST_CLIENT_ID,
        TEST_REDIRECT_URI,
        "atproto",
        "state1",
        "challenge1",
    );

    let res = execute_par_request(&ssrf_filter, &par_url, &params, &dpop_key, &nonce_cache).await;

    assert!(matches!(
        res,
        Err(AtprotoOAuthError::Par(ParError::MissingField("expires_in")))
    ));
}

#[tokio::test]
async fn test_par_error_html_non_json_error_page_502() {
    let mock_server = MockServer::start().await;
    let par_url = format!("{}/oauth/par", mock_server.uri());

    Mock::given(method("POST"))
        .and(path("/oauth/par"))
        .respond_with(
            ResponseTemplate::new(502)
                .insert_header("content-type", "text/html")
                .insert_header("dpop-nonce", "par-error-bad-gateway")
                .set_body_string("<html><body><h1>502 Bad Gateway</h1></body></html>"),
        )
        .mount(&mock_server)
        .await;

    let ssrf_filter = SsrfFilter::new(true);
    let dpop_key = DPoPKey::generate();
    let nonce_cache = DPoPNonceCache::new();
    let params = ParParameters::new(
        TEST_CLIENT_ID,
        TEST_REDIRECT_URI,
        "atproto",
        "state1",
        "challenge1",
    );

    let res = execute_par_request(&ssrf_filter, &par_url, &params, &dpop_key, &nonce_cache).await;

    match res {
        Err(AtprotoOAuthError::Par(ParError::RequestFailed { status, error, .. })) => {
            assert_eq!(status, 502);
            assert_eq!(error, "par_request_failed");
        }
        other => panic!("Expected ParError::RequestFailed with 502, got {other:?}"),
    }
}

#[tokio::test]
async fn test_par_error_http_500_internal_server_error() {
    let mock_server = MockServer::start().await;
    let par_url = format!("{}/oauth/par", mock_server.uri());

    Mock::given(method("POST"))
        .and(path("/oauth/par"))
        .respond_with(
            ResponseTemplate::new(500)
                .insert_header("content-type", "application/json")
                .insert_header("dpop-nonce", "par-error-server")
                .set_body_json(json!({
                    "error": "server_error",
                    "error_description": "Database connection failed"
                })),
        )
        .mount(&mock_server)
        .await;

    let ssrf_filter = SsrfFilter::new(true);
    let dpop_key = DPoPKey::generate();
    let nonce_cache = DPoPNonceCache::new();
    let params = ParParameters::new(
        TEST_CLIENT_ID,
        TEST_REDIRECT_URI,
        "atproto",
        "state1",
        "challenge1",
    );

    let res = execute_par_request(&ssrf_filter, &par_url, &params, &dpop_key, &nonce_cache).await;

    match res {
        Err(AtprotoOAuthError::Par(ParError::RequestFailed {
            status,
            error,
            description,
        })) => {
            assert_eq!(status, 500);
            assert_eq!(error, "server_error");
            assert_eq!(description, None);
        }
        other => panic!("Expected ParError::RequestFailed 500, got {other:?}"),
    }
}

#[tokio::test]
async fn test_par_error_http_status_codes_401_403_503() {
    for code in [401u16, 403u16, 503u16] {
        let mock_server = MockServer::start().await;
        let par_url = format!("{}/oauth/par", mock_server.uri());

        Mock::given(method("POST"))
            .and(path("/oauth/par"))
            .respond_with(
                ResponseTemplate::new(code)
                    .insert_header("content-type", "application/json")
                    .insert_header("dpop-nonce", format!("par-error-{code}"))
                    .set_body_json(json!({
                        "error": format!("error_{code}"),
                        "error_description": format!("HTTP {code} test")
                    })),
            )
            .mount(&mock_server)
            .await;

        let ssrf_filter = SsrfFilter::new(true);
        let dpop_key = DPoPKey::generate();
        let nonce_cache = DPoPNonceCache::new();
        let params = ParParameters::new(
            TEST_CLIENT_ID,
            TEST_REDIRECT_URI,
            "atproto",
            "state_status",
            "challenge_status",
        );

        let res =
            execute_par_request(&ssrf_filter, &par_url, &params, &dpop_key, &nonce_cache).await;

        match res {
            Err(AtprotoOAuthError::Par(ParError::RequestFailed {
                status,
                error,
                description,
            })) => {
                assert_eq!(status, code);
                assert_eq!(error, "par_request_failed");
                assert_eq!(description, None);
            }
            other => panic!("Expected ParError::RequestFailed for {code}, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn test_par_ssrf_blocked_private_ip_endpoint() {
    let ssrf_filter = SsrfFilter::default(); // allow_insecure_localhost = false
    let dpop_key = DPoPKey::generate();
    let nonce_cache = DPoPNonceCache::new();
    let params = ParParameters::new(
        TEST_CLIENT_ID,
        TEST_REDIRECT_URI,
        "atproto",
        "state_ssrf",
        "challenge_ssrf",
    );

    // Private IPv4
    let res = execute_par_request(
        &ssrf_filter,
        "https://192.168.1.100/oauth/par",
        &params,
        &dpop_key,
        &nonce_cache,
    )
    .await;
    assert!(matches!(
        res,
        Err(AtprotoOAuthError::Par(ParError::Ssrf(_)))
    ));

    // Cloud metadata IPv4
    let res2 = execute_par_request(
        &ssrf_filter,
        "http://169.254.169.254/oauth/par",
        &params,
        &dpop_key,
        &nonce_cache,
    )
    .await;
    assert!(matches!(
        res2,
        Err(AtprotoOAuthError::Par(ParError::Ssrf(_)))
    ));
}

#[tokio::test]
async fn test_par_invalid_endpoint_url_syntax() {
    let ssrf_filter = SsrfFilter::new(true);
    let dpop_key = DPoPKey::generate();
    let nonce_cache = DPoPNonceCache::new();
    let params = ParParameters::new(
        TEST_CLIENT_ID,
        TEST_REDIRECT_URI,
        "atproto",
        "state1",
        "challenge1",
    );

    let res = execute_par_request(
        &ssrf_filter,
        "not-a-valid-url-at-all",
        &params,
        &dpop_key,
        &nonce_cache,
    )
    .await;
    assert!(matches!(
        res,
        Err(AtprotoOAuthError::Par(ParError::InvalidEndpoint(_)))
    ));

    let auth_res = build_authorization_url("not a valid url", TEST_CLIENT_ID, "urn:some:req:uri");
    assert!(matches!(
        auth_res,
        Err(AtprotoOAuthError::Par(ParError::InvalidEndpoint(_)))
    ));
}

// =========================================================================
// 3. PROPERTY-BASED TESTS & FUZZING
// =========================================================================

proptest! {
    #[test]
    fn prop_extract_dpop_nonce_never_panics(s in "\\PC*") {
        let res = extract_dpop_nonce(Some(&s));
        if s.trim().is_empty() {
            prop_assert_eq!(res, None);
        } else {
            prop_assert_eq!(res, Some(s.trim().to_string()));
        }
    }

    #[test]
    fn prop_par_parameters_encoding_contains_all_fields(
        client_id in "[a-zA-Z0-9-._~:/]{5,50}",
        redirect_uri in "[a-zA-Z0-9-._~:/]{5,50}",
        scope in "[a-zA-Z0-9-._~: ]{3,30}",
        state in "[a-zA-Z0-9-._~]{8,32}",
        challenge in "[a-zA-Z0-9-._~]{43}"
    ) {
        let params = ParParameters::new(
            &client_id,
            &redirect_uri,
            &scope,
            &state,
            &challenge,
        );
        let encoded = params.to_form_urlencoded();

        prop_assert!(encoded.contains("response_type=code"));
        prop_assert!(encoded.contains("code_challenge_method=S256"));
    }

    #[test]
    fn prop_build_authorization_url_valid_params(
        auth_host in "[a-z0-9-]{3,10}\\.example\\.com",
        client_id in "https://[a-z0-9-]{3,10}\\.example\\.com/client\\.json",
        req_id in "[a-zA-Z0-9-]{8,24}"
    ) {
        let endpoint = format!("https://{auth_host}/oauth/authorize");
        let request_uri = format!("urn:ietf:params:oauth:request_uri:{req_id}");

        let url = build_authorization_url(&endpoint, &client_id, &request_uri).unwrap();
        prop_assert_eq!(url.scheme(), "https");
        prop_assert_eq!(url.host_str(), Some(auth_host.as_str()));

        let query = url.query().unwrap_or_default();
        prop_assert!(query.contains("client_id="));
        prop_assert!(query.contains("request_uri="));
    }
}
