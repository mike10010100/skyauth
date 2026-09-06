//! Milestone 7 Challenger 2: End-to-End OAuth Flow Fuzzing, Multi-Threading Stress, and Adversarial Hardening.
//!
//! Covers:
//! 1. End-to-end multi-hop nonce negotiation challenges and header fuzzing.
//! 2. Concurrent code exchange races and single-use anti-replay validation.
//! 3. 64-shard state store hash collision, chaos CRUD concurrency, and extreme key fuzzing.
//! 4. Refresh token replay detection, concurrent rotation races, and DID subject tampering.
//! 5. Upstream mock server malformed JSON response fuzzing (Discovery, PAR, Token, PLC DID docs).

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

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use proptest::prelude::*;
use serde_json::json;
use wiremock::matchers::{header, header_exists, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use skyauth::client::{
    AtprotoOAuthClient, AtprotoOAuthClientBuilder, CallbackParams, OAuthClientMetadata,
    StoredStateEntry, TokenResponse,
};
use skyauth::crypto::{base64url_decode, base64url_encode, constant_time_eq};
use skyauth::discovery::{
    fetch_auth_server_metadata, fetch_protected_resource_metadata,
    validate_auth_server_capabilities, AuthorizationServerMetadata, ProtectedResourceMetadata,
};
use skyauth::dpop::{
    compute_access_token_hash, extract_dpop_nonce, DPoPKey, DPoPNonceCache, DPoPVerifier,
};
use skyauth::error::{
    AtprotoOAuthError, CryptoError, DPoPError, DiscoveryError, IdentityError, ParError, PkceError,
    SsrfError, StoreError, TokenError,
};
use skyauth::identity::{DidDocument, IdentityResolver, IdentityResolverBuilder};
use skyauth::par::{build_authorization_url, execute_par_request, ParParameters, ParResponse};
use skyauth::pkce::{derive_s256_challenge, PkcePair};
use skyauth::session::OAuthSession;
use skyauth::ssrf::SsrfFilter;
use skyauth::store::{OAuthStateStore, OAuthStore, DEFAULT_STATE_TTL, NUM_SHARDS};

use e2e_harness::fixtures::*;
use e2e_harness::MockOAuthEnvironment;

fn create_test_state_entry(
    state: &str,
    token_endpoint: &str,
    issuer: &str,
    did: &str,
    dpop_key: DPoPKey,
) -> StoredStateEntry {
    StoredStateEntry {
        state: state.to_string(),
        client_id: TEST_CLIENT_ID.to_string(),
        code_verifier: RFC7636_VERIFIER.to_string(),
        dpop_key,
        issuer: issuer.to_string(),
        did: Some(did.to_string()),
        handle: Some(TEST_ALICE_HANDLE.to_string()),
        redirect_uri: TEST_REDIRECT_URI.to_string(),
        pds_endpoint: "https://pds.example.com".to_string(),
        token_endpoint: token_endpoint.to_string(),
        scopes: "atproto".to_string(),
        created_at: SystemTime::now(),
        expires_in_secs: 300,
    }
}

#[tokio::test]
async fn test_adv_par_auto_nonce_retry_success() {
    let mock_server = MockServer::start().await;
    let par_url = format!("{}/oauth/par", mock_server.uri());

    Mock::given(method("POST"))
        .and(path("/oauth/par"))
        .respond_with(
            ResponseTemplate::new(400)
                .insert_header("content-type", "application/json")
                .insert_header("dpop-nonce", "fresh-par-nonce-seq-1")
                .set_body_json(json!({
                    "error": "use_dpop_nonce",
                    "error_description": "PAR endpoint requires fresh DPoP nonce"
                })),
        )
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/oauth/par"))
        .and(header_exists("dpop"))
        .respond_with(
            ResponseTemplate::new(201)
                .insert_header("content-type", "application/json")
                .insert_header("dpop-nonce", "subsequent-nonce-2")
                .set_body_json(json!({
                    "request_uri": "urn:ietf:params:oauth:request_uri:req-fuzz-1",
                    "expires_in": 90
                })),
        )
        .mount(&mock_server)
        .await;

    let ssrf_filter = SsrfFilter {
        allow_insecure_localhost: true,
    };
    let dpop_key = DPoPKey::generate();
    let nonce_cache = DPoPNonceCache::new();
    let pkce = PkcePair::generate();
    let params = ParParameters::new(
        TEST_CLIENT_ID,
        TEST_REDIRECT_URI,
        "atproto",
        "state-nonce-123",
        &pkce.challenge,
    );

    let res = execute_par_request(&ssrf_filter, &par_url, &params, &dpop_key, &nonce_cache)
        .await
        .expect("PAR request should succeed on retry");

    assert_eq!(
        res.request_uri,
        "urn:ietf:params:oauth:request_uri:req-fuzz-1"
    );
    assert_eq!(res.expires_in, 90);

    let origin = url::Url::parse(&par_url)
        .unwrap()
        .origin()
        .ascii_serialization();
    assert_eq!(
        nonce_cache.get_nonce(&origin).as_deref(),
        Some("subsequent-nonce-2")
    );
}

#[tokio::test]
async fn test_adv_token_exchange_auto_nonce_retry() {
    let mock_server = MockServer::start().await;
    let token_endpoint = format!("{}/oauth/token", mock_server.uri());

    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(
            ResponseTemplate::new(400)
                .insert_header("content-type", "application/json")
                .insert_header("dpop-nonce", "token-exchange-fresh-nonce-42")
                .set_body_json(json!({
                    "error": "use_dpop_nonce",
                    "error_description": "Token endpoint requires fresh DPoP nonce"
                })),
        )
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .insert_header("dpop-nonce", "token-next-nonce-43")
                .set_body_json(json!({
                    "access_token": "at-fresh-access-token-123",
                    "token_type": "DPoP",
                    "expires_in": 3600,
                    "refresh_token": "rt-fresh-refresh-token-456",
                    "scope": "atproto transition:generic",
                    "sub": TEST_ALICE_DID
                })),
        )
        .mount(&mock_server)
        .await;

    let client = AtprotoOAuthClient::builder()
        .client_metadata(OAuthClientMetadata::new(TEST_CLIENT_ID, TEST_REDIRECT_URI))
        .allow_insecure_localhost(true)
        .build()
        .unwrap();

    let dpop_key = DPoPKey::generate();
    let state_entry = create_test_state_entry(
        "state-token-retry-1",
        &token_endpoint,
        &mock_server.uri(),
        TEST_ALICE_DID,
        dpop_key,
    );

    let session = client
        .exchange_code("authz-code-12345", &state_entry)
        .await
        .expect("Exchange code must succeed after single nonce retry");

    assert_eq!(session.sub(), TEST_ALICE_DID);
    assert_eq!(session.access_token(), "at-fresh-access-token-123");
    assert_eq!(session.refresh_token(), Some("rt-fresh-refresh-token-456"));
}

#[tokio::test]
async fn test_adv_token_refresh_auto_nonce_retry() {
    let mock_server = MockServer::start().await;
    let token_endpoint = format!("{}/oauth/token", mock_server.uri());

    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(
            ResponseTemplate::new(401)
                .insert_header("content-type", "application/json")
                .insert_header("dpop-nonce", "refresh-fresh-nonce-99")
                .set_body_json(json!({
                    "error": "use_dpop_nonce",
                    "error_description": "Refresh request requires fresh DPoP nonce"
                })),
        )
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .insert_header("dpop-nonce", "refresh-next-nonce-100")
                .set_body_json(json!({
                    "access_token": "at-rotated-token-888",
                    "token_type": "DPoP",
                    "expires_in": 7200,
                    "refresh_token": "rt-rotated-refresh-999",
                    "scope": "atproto",
                    "sub": TEST_ALICE_DID
                })),
        )
        .mount(&mock_server)
        .await;

    let client = AtprotoOAuthClient::builder()
        .client_metadata(OAuthClientMetadata::new(TEST_CLIENT_ID, TEST_REDIRECT_URI))
        .allow_insecure_localhost(true)
        .build()
        .unwrap();

    let dpop_key = DPoPKey::generate();
    let mut session = OAuthSession::new(
        TEST_ALICE_DID.to_string(),
        "at-old-token-000".to_string(),
        Some("rt-old-refresh-000".to_string()),
        "DPoP".to_string(),
        Some("atproto".to_string()),
        Some(3600),
        dpop_key,
        Some("https://pds.example.com".to_string()),
        Some(mock_server.uri()),
        Some(token_endpoint),
    )
    .unwrap();

    client
        .refresh_session(&mut session)
        .await
        .expect("Session refresh should transparently retry and succeed");

    assert_eq!(session.access_token(), "at-rotated-token-888");
    assert_eq!(session.refresh_token(), Some("rt-rotated-refresh-999"));
    assert!(session.expires_at().is_some());
}

#[tokio::test]
async fn test_adv_infinite_nonce_loop_defense_bounded_retry() {
    let mock_server = MockServer::start().await;
    let par_url = format!("{}/oauth/par", mock_server.uri());

    Mock::given(method("POST"))
        .and(path("/oauth/par"))
        .respond_with(
            ResponseTemplate::new(400)
                .insert_header("content-type", "application/json")
                .insert_header("dpop-nonce", "looping-nonce-infinite")
                .set_body_json(json!({
                    "error": "use_dpop_nonce",
                    "error_description": "Always challenging nonce"
                })),
        )
        .mount(&mock_server)
        .await;

    let ssrf_filter = SsrfFilter {
        allow_insecure_localhost: true,
    };
    let dpop_key = DPoPKey::generate();
    let nonce_cache = DPoPNonceCache::new();
    let pkce = PkcePair::generate();
    let params = ParParameters::new(
        TEST_CLIENT_ID,
        TEST_REDIRECT_URI,
        "atproto",
        "state-infinite-loop",
        &pkce.challenge,
    );

    let res = execute_par_request(&ssrf_filter, &par_url, &params, &dpop_key, &nonce_cache).await;
    assert!(
        res.is_err(),
        "Client must terminate bounded retry loop and return error"
    );
}

#[tokio::test]
async fn test_adv_missing_dpop_nonce_header_on_challenge() {
    let mock_server = MockServer::start().await;
    let par_url = format!("{}/oauth/par", mock_server.uri());

    Mock::given(method("POST"))
        .and(path("/oauth/par"))
        .respond_with(
            ResponseTemplate::new(400)
                .insert_header("content-type", "application/json")
                .set_body_json(json!({
                    "error": "use_dpop_nonce",
                    "error_description": "Requires nonce but forgot header"
                })),
        )
        .mount(&mock_server)
        .await;

    let ssrf_filter = SsrfFilter {
        allow_insecure_localhost: true,
    };
    let dpop_key = DPoPKey::generate();
    let nonce_cache = DPoPNonceCache::new();
    let pkce = PkcePair::generate();
    let params = ParParameters::new(
        TEST_CLIENT_ID,
        TEST_REDIRECT_URI,
        "atproto",
        "state-missing-header",
        &pkce.challenge,
    );

    let res = execute_par_request(&ssrf_filter, &par_url, &params, &dpop_key, &nonce_cache).await;
    assert!(
        res.is_err(),
        "Must return error when dpop-nonce header is missing"
    );
}

#[test]
fn test_adv_nonce_header_fuzzing_extraction() {
    assert_eq!(extract_dpop_nonce(Some("")), None);
    assert_eq!(extract_dpop_nonce(Some("   \t  \r\n ")), None);
    assert_eq!(
        extract_dpop_nonce(Some("  valid_nonce_abc  ")),
        Some("valid_nonce_abc".to_string())
    );
    let unicode_res = extract_dpop_nonce(Some("nonce-🔐-secure-🚀"));
    assert_eq!(unicode_res, Some("nonce-🔐-secure-🚀".to_string()));
    let giant_nonce = "A".repeat(8192);
    let giant_res = extract_dpop_nonce(Some(&giant_nonce));
    assert_eq!(giant_res, Some(giant_nonce));
}

#[tokio::test]
async fn test_adv_rapid_nonce_oscillation_concurrency() {
    let cache = Arc::new(DPoPNonceCache::new());
    let mut handles = Vec::new();

    let num_threads = 50;
    let iterations = 100;

    for t_idx in 0..num_threads {
        let cache_clone = Arc::clone(&cache);
        handles.push(tokio::spawn(async move {
            for i in 0..iterations {
                let origin = format!("https://auth-server-{}.example.com", i % 5);
                let nonce = format!("nonce-t{t_idx}-iter{i}");
                cache_clone.set_nonce(&origin, nonce.clone());

                let retrieved = cache_clone.get_nonce(&origin);
                assert!(retrieved.is_some(), "Nonce must be present after set");
            }
        }));
    }

    for h in handles {
        h.await.unwrap();
    }
}

#[tokio::test]
async fn test_adv_concurrent_50_tasks_racing_exact_same_code_and_state() {
    let mock_server = MockServer::start().await;
    let token_endpoint = format!("{}/oauth/token", mock_server.uri());

    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("dpop-nonce", "m7-success-nonce") // ATProto profile (H2)
                .insert_header("content-type", "application/json")
                .set_body_json(json!({
                    "access_token": "at-unique-token-xyz",
                    "token_type": "DPoP",
                    "expires_in": 3600,
                    "refresh_token": "rt-unique-token-xyz",
                    "scope": "atproto",
                    "sub": TEST_ALICE_DID
                })),
        )
        .mount(&mock_server)
        .await;

    let store = Arc::new(OAuthStateStore::default());
    let client = Arc::new(
        AtprotoOAuthClient::builder()
            .client_metadata(OAuthClientMetadata::new(TEST_CLIENT_ID, TEST_REDIRECT_URI))
            .allow_insecure_localhost(true)
            .state_store(Arc::clone(&store))
            .build()
            .unwrap(),
    );
    let state_key = "race-state-token-single-use-12345";
    let dpop_key = DPoPKey::generate();
    let state_entry = create_test_state_entry(
        state_key,
        &token_endpoint,
        &mock_server.uri(),
        TEST_ALICE_DID,
        dpop_key,
    );

    store
        .insert_state(state_key.to_string(), state_entry, Duration::from_secs(300))
        .await
        .unwrap();

    let concurrency = 50;
    let issuer = mock_server.uri();
    let success_count = Arc::new(AtomicUsize::new(0));
    let invalid_state_count = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::with_capacity(concurrency);
    for _ in 0..concurrency {
        let store_clone = Arc::clone(&store);
        let client_clone = Arc::clone(&client);
        let success_clone = Arc::clone(&success_count);
        let invalid_clone = Arc::clone(&invalid_state_count);
        let state_key_owned = state_key.to_string();
        let issuer_owned = issuer.clone();

        handles.push(tokio::spawn(async move {
            let callback_params =
                CallbackParams::new("authz-code-race-1", state_key_owned).with_iss(issuer_owned);
            let res = client_clone.handle_callback(&callback_params).await;
            match res {
                Ok(_) => {
                    success_clone.fetch_add(1, Ordering::SeqCst);
                }
                Err(skyauth::error::AtprotoOAuthError::Token(TokenError::InvalidState(_))) => {
                    invalid_clone.fetch_add(1, Ordering::SeqCst);
                }
                Err(other) => {
                    panic!("unexpected error in callback race: {other:?}");
                }
            }
            let _ = store_clone; // keep Arc alive for the task lifetime
        }));
    }

    for h in handles {
        h.await.unwrap();
    }

    assert_eq!(
        success_count.load(Ordering::SeqCst),
        1,
        "Exactly 1 concurrent task must win the take_state race and complete the code exchange"
    );
    assert_eq!(
        invalid_state_count.load(Ordering::SeqCst),
        concurrency - 1,
        "All other 49 tasks must be rejected by atomic single-use state consumption"
    );
}

#[tokio::test]
async fn test_adv_concurrent_100_tasks_racing_with_corrupted_states() {
    let client = AtprotoOAuthClient::builder()
        .client_metadata(OAuthClientMetadata::new(TEST_CLIENT_ID, TEST_REDIRECT_URI))
        .allow_insecure_localhost(true)
        .build()
        .unwrap();

    let valid_state = "valid-state-parameter-xyz";
    let dpop_key = DPoPKey::generate();
    let state_entry = create_test_state_entry(
        valid_state,
        "https://auth.example.com/token",
        "https://auth.example.com",
        TEST_ALICE_DID,
        dpop_key,
    );

    let mut handles = Vec::new();
    for i in 0..100 {
        let client_clone = client.clone();
        let entry_clone = state_entry.clone();
        let corrupted_state = format!("{valid_state}-corrupted-{i}");

        handles.push(tokio::spawn(async move {
            let callback = CallbackParams::new("code-123", corrupted_state)
                .with_iss("https://auth.example.com");
            let res = client_clone
                .handle_callback_with_entry(&callback, &entry_clone)
                .await;
            assert!(res.is_err(), "Corrupted state must be rejected");
        }));
    }

    for h in handles {
        h.await.unwrap();
    }
}

#[tokio::test]
async fn test_adv_code_replay_after_successful_exchange() {
    let mock_server = MockServer::start().await;
    let token_endpoint = format!("{}/oauth/token", mock_server.uri());

    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("dpop-nonce", "m7-success-nonce") // ATProto profile (H2)
                .insert_header("content-type", "application/json")
                .set_body_json(json!({
                    "access_token": "at-initial-123",
                    "token_type": "DPoP",
                    "expires_in": 3600,
                    "refresh_token": "rt-initial-456",
                    "scope": "atproto",
                    "sub": TEST_ALICE_DID
                })),
        )
        .mount(&mock_server)
        .await;

    let store = OAuthStateStore::new(Duration::from_secs(300));
    let client = AtprotoOAuthClient::builder()
        .client_metadata(OAuthClientMetadata::new(TEST_CLIENT_ID, TEST_REDIRECT_URI))
        .allow_insecure_localhost(true)
        .build()
        .unwrap();

    let state_key = "replay-test-state";
    let state_entry = create_test_state_entry(
        state_key,
        &token_endpoint,
        &mock_server.uri(),
        TEST_ALICE_DID,
        DPoPKey::generate(),
    );

    store
        .insert_state(state_key.to_string(), state_entry, Duration::from_secs(300))
        .await
        .unwrap();

    let consumed1 = store.take_state(state_key).await.unwrap();
    assert!(consumed1.is_some());
    let session = client
        .handle_callback_with_entry(
            &CallbackParams::new("code-replay-test", state_key).with_iss(&mock_server.uri()),
            &consumed1.unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(session.sub(), TEST_ALICE_DID);

    let consumed2 = store.take_state(state_key).await.unwrap();
    assert!(consumed2.is_none(), "Replayed state must return None");
}

#[tokio::test]
async fn test_adv_state_consumption_racing_with_ttl_eviction() {
    let store = Arc::new(OAuthStateStore::new(Duration::from_millis(50)));
    let state_key = "racing-ttl-state";
    let state_entry = create_test_state_entry(
        state_key,
        "https://auth.example.com/token",
        "https://auth.example.com",
        TEST_ALICE_DID,
        DPoPKey::generate(),
    );

    store
        .insert_state(state_key.to_string(), state_entry, Duration::from_millis(1))
        .await
        .unwrap();

    let store_clone1 = Arc::clone(&store);
    let store_clone2 = Arc::clone(&store);

    let take_handle =
        tokio::spawn(async move { store_clone1.take_state(state_key).await.unwrap() });

    let prune_handle = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(2)).await;
        store_clone2.prune_expired().await.unwrap()
    });

    let (take_res, prune_res) = tokio::join!(take_handle, prune_handle);
    let entry_opt = take_res.unwrap();
    let _pruned_count = prune_res.unwrap();

    if let Some(entry) = entry_opt {
        assert_eq!(entry.state, state_key);
    }
}

#[tokio::test]
async fn test_adv_sharded_store_1000_tasks_hash_collision_stress() {
    let store = Arc::new(OAuthStateStore::default());
    let num_tasks = 1000;
    let mut handles = Vec::with_capacity(num_tasks);

    for i in 0..num_tasks {
        let store_clone = Arc::clone(&store);
        handles.push(tokio::spawn(async move {
            let state_key = format!("state_prefix_collision_test_key_{:06}", i);
            let entry = create_test_state_entry(
                &state_key,
                "https://auth.example.com/token",
                "https://auth.example.com",
                TEST_ALICE_DID,
                DPoPKey::generate(),
            );

            store_clone
                .insert_state(state_key.clone(), entry, Duration::from_secs(60))
                .await
                .unwrap();

            assert!(
                store_clone.contains_state(&state_key).await.unwrap(),
                "Store must contain inserted state"
            );

            let taken = store_clone.take_state(&state_key).await.unwrap();
            assert!(taken.is_some(), "Must successfully take inserted state");
            assert_eq!(taken.unwrap().state, state_key);

            assert!(
                !store_clone.contains_state(&state_key).await.unwrap(),
                "Store must no longer contain consumed state"
            );
        }));
    }

    for h in handles {
        h.await.unwrap();
    }
}

#[tokio::test]
async fn test_adv_sharded_store_interleaved_crud_chaos() {
    let store = Arc::new(OAuthStateStore::default());
    let num_workers = 50;
    let ops_per_worker = 100;
    let total_taken = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::with_capacity(num_workers);
    for w in 0..num_workers {
        let store_clone = Arc::clone(&store);
        let taken_counter = Arc::clone(&total_taken);

        handles.push(tokio::spawn(async move {
            for op in 0..ops_per_worker {
                let key = format!("chaos_key_{}", (w * ops_per_worker + op) % 200);
                match op % 4 {
                    0 => {
                        let entry = create_test_state_entry(
                            &key,
                            "https://auth.example.com/token",
                            "https://auth.example.com",
                            TEST_ALICE_DID,
                            DPoPKey::generate(),
                        );
                        let _ = store_clone
                            .insert_state(key, entry, Duration::from_millis(50))
                            .await;
                    }
                    1 => {
                        if let Ok(Some(_)) = store_clone.take_state(&key).await {
                            taken_counter.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                    2 => {
                        let _ = store_clone.contains_state(&key).await;
                    }
                    3 => {
                        let _ = store_clone.prune_expired().await;
                    }
                    _ => unreachable!(),
                }
            }
        }));
    }

    for h in handles {
        h.await.unwrap();
    }
}

#[tokio::test]
async fn test_adv_sharded_store_extreme_key_fuzzing() {
    let store = OAuthStateStore::default();

    let extreme_keys = vec![
        "".to_string(),                                        // Empty key
        "A".repeat(16384),                                     // 16KB giant key
        "null\0control\r\n\tbytes".to_string(),                // Control chars & null byte
        "🚀🔥💎✨🔒OAuthState🔑🌍".to_string(),                // Emoji & multi-byte UTF-8
        "مرحبا_بالعالم_state_key".to_string(),                 // Arabic script
        "state_key_with_spaces and / ? # & = + %".to_string(), // URL reserved chars
    ];

    for key in &extreme_keys {
        let entry = create_test_state_entry(
            key,
            "https://auth.example.com/token",
            "https://auth.example.com",
            TEST_ALICE_DID,
            DPoPKey::generate(),
        );

        store
            .insert_state(key.clone(), entry, Duration::from_secs(60))
            .await
            .unwrap();

        assert!(store.contains_state(key).await.unwrap());

        let taken = store.take_state(key).await.unwrap();
        assert!(taken.is_some());
        assert_eq!(&taken.unwrap().state, key);

        assert!(store.take_state(key).await.unwrap().is_none());
    }
}

#[tokio::test]
async fn test_adv_sharded_store_pruner_cancellation_cycles() {
    let store = Arc::new(OAuthStateStore::default());

    for _ in 0..50 {
        let cancel_token = tokio_util::sync::CancellationToken::new();
        let pruner_handle =
            store.spawn_pruning_task(Duration::from_millis(10), cancel_token.clone());

        tokio::time::sleep(Duration::from_millis(5)).await;

        cancel_token.cancel();
        let _ = pruner_handle.await;
    }
}

#[tokio::test]
async fn test_adv_refresh_token_replay_attack() {
    let mock_server = MockServer::start().await;
    let token_endpoint = format!("{}/oauth/token", mock_server.uri());

    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("dpop-nonce", "m7-success-nonce") // ATProto profile (H2)
                .insert_header("content-type", "application/json")
                .set_body_json(json!({
                    "access_token": "at-rotated-v1",
                    "token_type": "DPoP",
                    "expires_in": 3600,
                    "refresh_token": "rt-rotated-v2",
                    "scope": "atproto",
                    "sub": TEST_ALICE_DID
                })),
        )
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(
            ResponseTemplate::new(400)
                .insert_header("content-type", "application/json")
                .set_body_json(json!({
                    "error": "invalid_grant",
                    "error_description": "Refresh token has already been used (replayed)"
                })),
        )
        .mount(&mock_server)
        .await;

    let client = AtprotoOAuthClient::builder()
        .client_metadata(OAuthClientMetadata::new(TEST_CLIENT_ID, TEST_REDIRECT_URI))
        .allow_insecure_localhost(true)
        .build()
        .unwrap();

    let mut session = OAuthSession::new(
        TEST_ALICE_DID.to_string(),
        "at-initial-v0".to_string(),
        Some("rt-initial-v1".to_string()),
        "DPoP".to_string(),
        Some("atproto".to_string()),
        Some(3600),
        DPoPKey::generate(),
        Some("https://pds.example.com".to_string()),
        Some(mock_server.uri()),
        Some(token_endpoint.clone()),
    )
    .unwrap();

    client.refresh_session(&mut session).await.unwrap();
    assert_eq!(session.access_token(), "at-rotated-v1");
    assert_eq!(session.refresh_token(), Some("rt-rotated-v2"));

    let mut forged_session = OAuthSession::new(
        TEST_ALICE_DID.to_string(),
        "at-stolen".to_string(),
        Some("rt-initial-v1".to_string()),
        "DPoP".to_string(),
        Some("atproto".to_string()),
        Some(3600),
        DPoPKey::generate(),
        Some("https://pds.example.com".to_string()),
        Some(mock_server.uri()),
        Some(token_endpoint),
    )
    .unwrap();

    let replay_res = client.refresh_session(&mut forged_session).await;
    assert!(
        replay_res.is_err(),
        "Server must reject replayed refresh token"
    );
}

#[tokio::test]
async fn test_adv_concurrent_50_tasks_racing_same_refresh_token() {
    let mock_server = MockServer::start().await;
    let token_endpoint = format!("{}/oauth/token", mock_server.uri());

    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("dpop-nonce", "m7-success-nonce") // ATProto profile (H2)
                .insert_header("content-type", "application/json")
                .set_body_json(json!({
                    "access_token": "at-race-winner",
                    "token_type": "DPoP",
                    "expires_in": 3600,
                    "refresh_token": "rt-race-winner",
                    "scope": "atproto",
                    "sub": TEST_ALICE_DID
                })),
        )
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(
            ResponseTemplate::new(400)
                .insert_header("content-type", "application/json")
                .set_body_json(json!({
                    "error": "invalid_grant",
                    "error_description": "Refresh token already rotated"
                })),
        )
        .mount(&mock_server)
        .await;

    let client = Arc::new(
        AtprotoOAuthClient::builder()
            .client_metadata(OAuthClientMetadata::new(TEST_CLIENT_ID, TEST_REDIRECT_URI))
            .allow_insecure_localhost(true)
            .build()
            .unwrap(),
    );

    let session = OAuthSession::new(
        TEST_ALICE_DID.to_string(),
        "at-old".to_string(),
        Some("rt-race-target".to_string()),
        "DPoP".to_string(),
        Some("atproto".to_string()),
        Some(3600),
        DPoPKey::generate(),
        Some("https://pds.example.com".to_string()),
        Some(mock_server.uri()),
        Some(token_endpoint),
    )
    .unwrap();

    let concurrency = 50;
    let success_count = Arc::new(AtomicUsize::new(0));
    let failure_count = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::new();
    for _ in 0..concurrency {
        let client_clone = Arc::clone(&client);
        let session_clone = session.clone();
        let success_clone = Arc::clone(&success_count);
        let fail_clone = Arc::clone(&failure_count);

        handles.push(tokio::spawn(async move {
            let res = client_clone.refresh_token(&session_clone).await;
            if res.is_ok() {
                success_clone.fetch_add(1, Ordering::SeqCst);
            } else {
                fail_clone.fetch_add(1, Ordering::SeqCst);
            }
        }));
    }

    for h in handles {
        h.await.unwrap();
    }

    assert_eq!(
        success_count.load(Ordering::SeqCst),
        1,
        "Exactly 1 concurrent refresh request should succeed"
    );
    assert_eq!(
        failure_count.load(Ordering::SeqCst),
        concurrency - 1,
        "All other concurrent refresh requests must fail due to single-use token rotation"
    );
}

#[tokio::test]
async fn test_adv_refresh_sub_did_tampering_rejection() {
    let mock_server = MockServer::start().await;
    let token_endpoint = format!("{}/oauth/token", mock_server.uri());

    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("dpop-nonce", "m7-success-nonce") // ATProto profile (H2)
                .insert_header("content-type", "application/json")
                .set_body_json(json!({
                    "access_token": "at-tampered",
                    "token_type": "DPoP",
                    "expires_in": 3600,
                    "refresh_token": "rt-tampered",
                    "scope": "atproto",
                    "sub": "did:plc:maliciousattacker999"
                })),
        )
        .mount(&mock_server)
        .await;

    let client = AtprotoOAuthClient::builder()
        .client_metadata(OAuthClientMetadata::new(TEST_CLIENT_ID, TEST_REDIRECT_URI))
        .allow_insecure_localhost(true)
        .build()
        .unwrap();

    let mut session = OAuthSession::new(
        TEST_ALICE_DID.to_string(),
        "at-original".to_string(),
        Some("rt-original".to_string()),
        "DPoP".to_string(),
        Some("atproto".to_string()),
        Some(3600),
        DPoPKey::generate(),
        Some("https://pds.example.com".to_string()),
        Some(mock_server.uri()),
        Some(token_endpoint),
    )
    .unwrap();

    let res = client.refresh_session(&mut session).await;
    assert!(
        res.is_err(),
        "Client must reject refresh response when subject DID is tampered"
    );
    assert_eq!(session.sub(), TEST_ALICE_DID);
    assert_eq!(session.access_token(), "at-original");
}

#[test]
fn test_adv_session_rotation_and_expiry_validation() {
    let key = DPoPKey::generate();
    let mut session = OAuthSession::new(
        TEST_ALICE_DID.to_string(),
        "access-token-123".to_string(),
        Some("refresh-token-456".to_string()),
        "DPoP".to_string(),
        Some("atproto transition:generic".to_string()),
        Some(3600),
        key,
        Some("https://pds.example.com".to_string()),
        Some("https://auth.example.com".to_string()),
        Some("https://auth.example.com/oauth/token".to_string()),
    )
    .unwrap();

    assert!(!session.is_expired());
    assert!(!session.is_expired_with_leeway(Duration::from_secs(60)));

    session.rotate_tokens(
        "new-access-token-789".to_string(),
        Some("new-refresh-token-012".to_string()),
        Some(1800),
    );

    assert_eq!(session.access_token(), "new-access-token-789");
    assert_eq!(session.refresh_token(), Some("new-refresh-token-012"));
    assert!(session.expires_at().is_some());
}

#[tokio::test]
async fn test_adv_malformed_discovery_protected_resource_json() {
    let pds_server = MockServer::start().await;
    let ssrf = SsrfFilter {
        allow_insecure_localhost: true,
    };

    let malformed_cases = vec![
        (
            "Truncated JSON",
            "{\"resource\": \"https://pds.example.com\", \"auth",
        ),
        ("Array instead of Object", "[1, 2, 3, \"pds\"]"),
        ("Integer instead of Object", "1234567"),
        ("Boolean instead of Object", "true"),
        (
            "HTML Error 500 Page",
            "<!DOCTYPE html><html><body>500 Internal Server Error</body></html>",
        ),
        (
            "Missing authorization_servers",
            "{\"resource\": \"https://pds.example.com\"}",
        ),
        (
            "Empty authorization_servers array",
            "{\"resource\": \"https://pds.example.com\", \"authorization_servers\": []}",
        ),
    ];

    for (desc, body) in malformed_cases {
        Mock::given(method("GET"))
            .and(path("/.well-known/oauth-protected-resource"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("dpop-nonce", "m7-success-nonce") // ATProto profile (H2)
                    .insert_header("content-type", "application/json")
                    .set_body_string(body.to_string()),
            )
            .mount(&pds_server)
            .await;

        let res = fetch_protected_resource_metadata(&ssrf, &pds_server.uri()).await;
        assert!(res.is_err(), "Failed on case: {desc}");
        pds_server.reset().await;
    }
}

#[tokio::test]
async fn test_adv_malformed_discovery_auth_server_json() {
    let as_server = MockServer::start().await;
    let ssrf = SsrfFilter {
        allow_insecure_localhost: true,
    };

    let malformed_as_cases = vec![
        ("Truncated AS JSON", "{\"issuer\": \"https://auth.example.com".to_string()),
        ("HTML Error Page", "<html><body>502 Bad Gateway</body></html>".to_string()),
        ("Missing issuer", "{\"authorization_endpoint\": \"https://auth/a\", \"token_endpoint\": \"https://auth/t\"}".to_string()),
        ("Missing token_endpoint", format!("{{\"issuer\": \"{}\", \"authorization_endpoint\": \"https://auth/a\"}}", as_server.uri())),
        ("Missing par_endpoint", format!("{{\"issuer\": \"{}\", \"authorization_endpoint\": \"https://auth/a\", \"token_endpoint\": \"https://auth/t\"}}", as_server.uri())),
        ("Issuer Mismatch", "{\"issuer\": \"https://different-issuer.example.com\", \"authorization_endpoint\": \"https://auth/a\", \"token_endpoint\": \"https://auth/t\", \"pushed_authorization_request_endpoint\": \"https://auth/p\"}".to_string()),
    ];

    for (desc, body) in malformed_as_cases {
        Mock::given(method("GET"))
            .and(path("/.well-known/oauth-authorization-server"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("dpop-nonce", "m7-success-nonce") // ATProto profile (H2)
                    .insert_header("content-type", "application/json")
                    .set_body_string(body),
            )
            .mount(&as_server)
            .await;

        let res = fetch_auth_server_metadata(&ssrf, &as_server.uri()).await;
        assert!(res.is_err(), "Failed on case: {desc}");
        as_server.reset().await;
    }
}

#[tokio::test]
async fn test_adv_malformed_par_response_json() {
    let as_server = MockServer::start().await;
    let par_url = format!("{}/oauth/par", as_server.uri());
    let ssrf = SsrfFilter {
        allow_insecure_localhost: true,
    };
    let dpop_key = DPoPKey::generate();
    let nonce_cache = DPoPNonceCache::new();
    let pkce = PkcePair::generate();
    let params = ParParameters::new(
        TEST_CLIENT_ID,
        TEST_REDIRECT_URI,
        "atproto",
        "state-par-malformed",
        &pkce.challenge,
    );

    let malformed_par_cases = vec![
        ("Truncated JSON", "{\"request_uri\": \"urn:ietf"),
        (
            "HTML Error Page",
            "<html><body>500 Internal Error</body></html>",
        ),
        ("Missing request_uri", "{\"expires_in\": 90}"),
        (
            "Integer request_uri",
            "{\"request_uri\": 12345, \"expires_in\": 90}",
        ),
        (
            "Negative expires_in",
            "{\"request_uri\": \"urn:ietf:req:1\", \"expires_in\": -90}",
        ),
        (
            "String expires_in",
            "{\"request_uri\": \"urn:ietf:req:1\", \"expires_in\": \"ninety\"}",
        ),
        ("Empty body", ""),
    ];

    for (desc, body) in malformed_par_cases {
        Mock::given(method("POST"))
            .and(path("/oauth/par"))
            .respond_with(
                ResponseTemplate::new(201)
                    .insert_header("dpop-nonce", "m7-success-nonce") // ATProto profile (H2)
                    .insert_header("content-type", "application/json")
                    .set_body_string(body.to_string()),
            )
            .mount(&as_server)
            .await;

        let res = execute_par_request(&ssrf, &par_url, &params, &dpop_key, &nonce_cache).await;
        assert!(res.is_err(), "PAR request must fail on case: {desc}");
        as_server.reset().await;
    }
}

#[tokio::test]
async fn test_adv_malformed_token_response_json() {
    let as_server = MockServer::start().await;
    let token_url = format!("{}/oauth/token", as_server.uri());
    let client = AtprotoOAuthClient::builder()
        .client_metadata(OAuthClientMetadata::new(TEST_CLIENT_ID, TEST_REDIRECT_URI))
        .allow_insecure_localhost(true)
        .build()
        .unwrap();

    let dpop_key = DPoPKey::generate();
    let state_entry = create_test_state_entry(
        "state-token-malformed",
        &token_url,
        &as_server.uri(),
        TEST_ALICE_DID,
        dpop_key,
    );

    let malformed_token_cases = vec![
        ("Truncated JSON", "{\"access_token\": \"at-123\", \"token_type\":".to_string()),
        ("HTML Error Page", "<html><body>500 Internal Error</body></html>".to_string()),
        ("Missing access_token", format!("{{\"token_type\": \"DPoP\", \"sub\": \"{TEST_ALICE_DID}\"}}")),
        ("Missing token_type", format!("{{\"access_token\": \"at-1\", \"sub\": \"{TEST_ALICE_DID}\"}}")),
        ("Invalid token_type Bearer", format!("{{\"access_token\": \"at-1\", \"token_type\": \"Bearer\", \"sub\": \"{TEST_ALICE_DID}\"}}")),
        ("Missing sub DID", "{\"access_token\": \"at-1\", \"token_type\": \"DPoP\"}".to_string()),
        ("Empty sub DID", "{\"access_token\": \"at-1\", \"token_type\": \"DPoP\", \"sub\": \"   \"}".to_string()),
        ("Mismatched sub DID", "{\"access_token\": \"at-1\", \"token_type\": \"DPoP\", \"sub\": \"did:plc:otheruser123\"}".to_string()),
    ];

    for (desc, body) in malformed_token_cases {
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("dpop-nonce", "m7-success-nonce") // ATProto profile (H2)
                    .insert_header("content-type", "application/json")
                    .set_body_string(body),
            )
            .mount(&as_server)
            .await;

        let res = client.exchange_code("test-code-123", &state_entry).await;
        assert!(res.is_err(), "Token exchange must fail on case: {desc}");
        as_server.reset().await;
    }
}

#[tokio::test]
async fn test_adv_malformed_plc_did_document_json() {
    let plc_server = MockServer::start().await;
    let ssrf = SsrfFilter {
        allow_insecure_localhost: true,
    };

    let malformed_did_cases = vec![
        ("Truncated JSON", "{\"id\": \"did:plc:123\", \"alsoKnownAs\":".to_string()),
        ("Empty Object", "{}".to_string()),
        ("Missing service array", format!("{{\"id\": \"{TEST_ALICE_DID}\", \"alsoKnownAs\": [\"at://{TEST_ALICE_HANDLE}\"]}}")),
        ("Service is string instead of array", format!("{{\"id\": \"{TEST_ALICE_DID}\", \"service\": \"not-an-array\"}}")),
        ("Service missing #atproto_pds", format!("{{\"id\": \"{TEST_ALICE_DID}\", \"service\": [{{\"id\": \"#other_service\", \"type\": \"OtherService\", \"serviceEndpoint\": \"https://pds.example.com\"}}]}}")),
        ("Service missing serviceEndpoint", format!("{{\"id\": \"{TEST_ALICE_DID}\", \"service\": [{{\"id\": \"#atproto_pds\", \"type\": \"AtprotoPersonalDataServer\"}}]}}")),
        ("Missing alsoKnownAs array", format!("{{\"id\": \"{TEST_ALICE_DID}\", \"service\": [{{\"id\": \"#atproto_pds\", \"type\": \"AtprotoPersonalDataServer\", \"serviceEndpoint\": \"https://pds.example.com\"}}]}}")),
        ("alsoKnownAs handle mismatch", format!("{{\"id\": \"{TEST_ALICE_DID}\", \"alsoKnownAs\": [\"at://impostor.handle.com\"], \"service\": [{{\"id\": \"#atproto_pds\", \"type\": \"AtprotoPersonalDataServer\", \"serviceEndpoint\": \"https://pds.example.com\"}}]}}")),
    ];

    for (desc, body) in malformed_did_cases {
        Mock::given(method("GET"))
            .and(path(format!("/{TEST_ALICE_DID}")))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("dpop-nonce", "m7-success-nonce") // ATProto profile (H2)
                    .insert_header("content-type", "application/json")
                    .set_body_string(body),
            )
            .mount(&plc_server)
            .await;

        let resolver = IdentityResolverBuilder::new()
            .ssrf_filter(ssrf)
            .plc_directory_url(plc_server.uri())
            .build();

        let res = resolver.resolve_did(TEST_ALICE_DID).await;
        if let Ok(doc) = res {
            let pds_res = doc.extract_pds_endpoint();
            let handle_res = doc.verify_handle_bidirectional(TEST_ALICE_HANDLE);
            assert!(
                pds_res.is_err() || handle_res.is_err(),
                "Case {desc} must fail PDS extraction or handle verification"
            );
        }
        plc_server.reset().await;
    }
}
