//! Adversarial Stress and Challenge Tests for Milestone 3 (atproto-oauth-rs).
//!
//! Focus areas:
//! 1. Refresh token rotation: single-use enforcement, multi-hop invalidation, replay detection, concurrent rotation races.
//! 2. Concurrent token exchange: race conditions on authorization code consumption, state parameter verification under concurrent logins, RFC 9207 iss verification.
//! 3. Token response tampering: mismatched sub DID, missing atproto scope, incorrect token_type (Bearer vs DPoP), corrupted JSON, HTTP error mapping, SSRF filtering.

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

use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use serde_json::json;
use wiremock::matchers::{header_exists, method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

use skyauth::client::{AtprotoOAuthClient, CallbackParams, OAuthClientMetadata, StoredStateEntry};
use skyauth::crypto::constant_time_eq;
use skyauth::dpop::{compute_access_token_hash, DPoPKey, DPoPNonceCache, DPoPVerifier};
use skyauth::error::{AtprotoOAuthError, DPoPError, ParError, SsrfError, TokenError};
use skyauth::identity::IdentityResolverBuilder;
use skyauth::session::OAuthSession;
use skyauth::ssrf::SsrfFilter;

use e2e_harness::fixtures::*;
use e2e_harness::MockOAuthEnvironment;

// ============================================================================
// Custom WireMock Responders for Stateful Protocol Emulation
// ============================================================================

/// Stateful responder tracking single-use refresh token rotation.
///
/// Ensures each refresh token can only be consumed once. Replay attempts receive HTTP 400 invalid_grant.
struct StatefulRefreshTokenResponder {
    active_token: Mutex<String>,
    generation: AtomicUsize,
    sub_did: String,
}

impl StatefulRefreshTokenResponder {
    fn new(initial_token: &str, sub_did: &str) -> Self {
        Self {
            active_token: Mutex::new(initial_token.to_string()),
            generation: AtomicUsize::new(0),
            sub_did: sub_did.to_string(),
        }
    }
}

impl Respond for StatefulRefreshTokenResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body_str = String::from_utf8_lossy(&request.body);
        let pairs = url::form_urlencoded::parse(body_str.as_bytes());
        let mut provided_rt = None;
        let mut grant_type = None;

        for (k, v) in pairs {
            if k == "refresh_token" {
                provided_rt = Some(v.into_owned());
            } else if k == "grant_type" {
                grant_type = Some(v.into_owned());
            }
        }

        if grant_type.as_deref() != Some("refresh_token") {
            return ResponseTemplate::new(400)
                .insert_header("content-type", "application/json")
                .set_body_json(json!({
                    "error": "unsupported_grant_type",
                    "error_description": "Expected grant_type=refresh_token"
                }));
        }

        let mut lock = self.active_token.lock().unwrap();
        if let Some(rt) = provided_rt {
            if *lock == rt {
                let gen = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
                let next_rt = format!("rt_gen_{gen}_{}", rand::random::<u32>());
                let next_at = format!("at_gen_{gen}_{}", rand::random::<u32>());
                *lock = next_rt.clone();

                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/json")
                    .set_body_json(json!({
                        "access_token": next_at,
                        "token_type": "DPoP",
                        "expires_in": 3600,
                        "refresh_token": next_rt,
                        "scope": "atproto transition:generic",
                        "sub": self.sub_did
                    }))
            } else {
                // Stale / Replayed refresh token
                ResponseTemplate::new(400)
                    .insert_header("content-type", "application/json")
                    .set_body_json(json!({
                        "error": "invalid_grant",
                        "error_description": "Stale or revoked refresh token presented (replay detected)"
                    }))
            }
        } else {
            ResponseTemplate::new(400)
                .insert_header("content-type", "application/json")
                .set_body_json(json!({
                    "error": "invalid_request",
                    "error_description": "Missing refresh_token parameter"
                }))
        }
    }
}

/// Stateful responder ensuring authorization code single-use.
struct SingleUseCodeResponder {
    valid_code: String,
    consumed: Mutex<bool>,
    sub_did: String,
}

impl SingleUseCodeResponder {
    fn new(code: &str, sub_did: &str) -> Self {
        Self {
            valid_code: code.to_string(),
            consumed: Mutex::new(false),
            sub_did: sub_did.to_string(),
        }
    }
}

impl Respond for SingleUseCodeResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body_str = String::from_utf8_lossy(&request.body);
        let pairs = url::form_urlencoded::parse(body_str.as_bytes());
        let mut provided_code = None;

        for (k, v) in pairs {
            if k == "code" {
                provided_code = Some(v.into_owned());
            }
        }

        let mut lock = self.consumed.lock().unwrap();
        if let Some(code) = provided_code {
            if code == self.valid_code {
                if *lock {
                    // Already consumed!
                    ResponseTemplate::new(400)
                        .insert_header("content-type", "application/json")
                        .set_body_json(json!({
                            "error": "invalid_grant",
                            "error_description": "Authorization code has already been consumed"
                        }))
                } else {
                    *lock = true;
                    ResponseTemplate::new(200)
                        .insert_header("content-type", "application/json")
                        .set_body_json(json!({
                            "access_token": "at_single_use_success",
                            "token_type": "DPoP",
                            "expires_in": 3600,
                            "refresh_token": "rt_single_use_success",
                            "scope": "atproto",
                            "sub": self.sub_did
                        }))
                }
            } else {
                ResponseTemplate::new(400)
                    .insert_header("content-type", "application/json")
                    .set_body_json(json!({
                        "error": "invalid_grant",
                        "error_description": "Unknown or invalid authorization code"
                    }))
            }
        } else {
            ResponseTemplate::new(400)
                .insert_header("content-type", "application/json")
                .set_body_json(json!({
                    "error": "invalid_request",
                    "error_description": "Missing code parameter"
                }))
        }
    }
}

// ============================================================================
// 1. REFRESH TOKEN ROTATION CHALLENGE TESTS
// ============================================================================

#[tokio::test]
async fn test_refresh_token_rotation_single_use_and_replay_detection() {
    let auth_server = MockServer::start().await;
    let initial_rt = "rt_initial_genesis_token";
    let responder = StatefulRefreshTokenResponder::new(initial_rt, TEST_ALICE_DID);

    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .and(header_exists("dpop"))
        .respond_with(responder)
        .mount(&auth_server)
        .await;

    let key = DPoPKey::generate();
    let mut session = OAuthSession::new(
        TEST_ALICE_DID,
        "at_initial",
        Some(initial_rt.to_string()),
        "DPoP",
        Some("atproto".to_string()),
        Some(300),
        key.clone(),
        Some("https://pds.example.com".to_string()),
        Some(auth_server.uri()),
        Some(format!("{}/oauth/token", auth_server.uri())),
    )
    .unwrap();

    let client = AtprotoOAuthClient::builder()
        .client_metadata(OAuthClientMetadata::new(TEST_CLIENT_ID, TEST_REDIRECT_URI))
        .allow_insecure_localhost(true)
        .build()
        .unwrap();

    // 1. First rotation: rt_initial -> rt_gen_1
    client.refresh_session(&mut session).await.unwrap();
    let rt_gen_1 = session.refresh_token().unwrap().to_string();
    assert_ne!(rt_gen_1, initial_rt);
    assert!(session.access_token().starts_with("at_gen_1_"));

    // 2. Attacker attempts to replay initial_rt: must be rejected with invalid_grant!
    let mut stale_session = OAuthSession::new(
        TEST_ALICE_DID,
        "at_stale",
        Some(initial_rt.to_string()),
        "DPoP",
        Some("atproto".to_string()),
        Some(300),
        key.clone(),
        Some("https://pds.example.com".to_string()),
        Some(auth_server.uri()),
        Some(format!("{}/oauth/token", auth_server.uri())),
    )
    .unwrap();

    let replay_res = client.refresh_session(&mut stale_session).await;
    assert!(
        matches!(
            &replay_res,
            Err(AtprotoOAuthError::Token(TokenError::RequestFailed {
                status: 400,
                error,
                ..
            })) if error == "invalid_grant"
        ),
        "Expected invalid_grant on replay, got: {replay_res:?}"
    );

    // 3. Legitimate user refreshes with rt_gen_1: succeeds and advances to rt_gen_2
    client.refresh_session(&mut session).await.unwrap();
    let rt_gen_2 = session.refresh_token().unwrap().to_string();
    assert_ne!(rt_gen_2, rt_gen_1);
    assert!(session.access_token().starts_with("at_gen_2_"));

    // 4. Replaying rt_gen_1 now fails
    let mut stale_session_2 = OAuthSession::new(
        TEST_ALICE_DID,
        "at_stale",
        Some(rt_gen_1),
        "DPoP",
        Some("atproto".to_string()),
        Some(300),
        key,
        Some("https://pds.example.com".to_string()),
        Some(auth_server.uri()),
        Some(format!("{}/oauth/token", auth_server.uri())),
    )
    .unwrap();

    let replay_res_2 = client.refresh_session(&mut stale_session_2).await;
    assert!(matches!(
        replay_res_2,
        Err(AtprotoOAuthError::Token(TokenError::RequestFailed {
            status: 400,
            ..
        }))
    ));
}

#[tokio::test]
async fn test_refresh_token_rotation_multi_hop_chain() {
    let auth_server = MockServer::start().await;
    let initial_rt = "rt_hop_0";
    let responder = StatefulRefreshTokenResponder::new(initial_rt, TEST_ALICE_DID);

    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .and(header_exists("dpop"))
        .respond_with(responder)
        .mount(&auth_server)
        .await;

    let key = DPoPKey::generate();
    let mut session = OAuthSession::new(
        TEST_ALICE_DID,
        "at_hop_0",
        Some(initial_rt.to_string()),
        "DPoP",
        Some("atproto".to_string()),
        Some(300),
        key.clone(),
        Some("https://pds.example.com".to_string()),
        Some(auth_server.uri()),
        Some(format!("{}/oauth/token", auth_server.uri())),
    )
    .unwrap();

    let client = AtprotoOAuthClient::builder()
        .client_metadata(OAuthClientMetadata::new(TEST_CLIENT_ID, TEST_REDIRECT_URI))
        .allow_insecure_localhost(true)
        .build()
        .unwrap();

    let mut past_tokens = vec![initial_rt.to_string()];

    // Execute 10 consecutive rotations
    for hop in 1..=10 {
        client.refresh_session(&mut session).await.unwrap();
        let current_rt = session.refresh_token().unwrap().to_string();
        assert!(session
            .access_token()
            .starts_with(&format!("at_gen_{hop}_")));
        past_tokens.push(current_rt);
    }

    // Verify all 10 previous tokens are dead
    for stale_rt in &past_tokens[..10] {
        let mut stale_session = OAuthSession::new(
            TEST_ALICE_DID,
            "at_test",
            Some(stale_rt.clone()),
            "DPoP",
            Some("atproto".to_string()),
            Some(300),
            key.clone(),
            Some("https://pds.example.com".to_string()),
            Some(auth_server.uri()),
            Some(format!("{}/oauth/token", auth_server.uri())),
        )
        .unwrap();

        let err = client.refresh_session(&mut stale_session).await;
        assert!(matches!(
            err,
            Err(AtprotoOAuthError::Token(TokenError::RequestFailed {
                status: 400,
                ..
            }))
        ));
    }
}

#[tokio::test]
async fn test_refresh_token_rotation_concurrent_race() {
    let auth_server = MockServer::start().await;
    let initial_rt = "rt_shared_race_target";
    let responder = StatefulRefreshTokenResponder::new(initial_rt, TEST_ALICE_DID);

    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .and(header_exists("dpop"))
        .respond_with(responder)
        .mount(&auth_server)
        .await;

    let key = DPoPKey::generate();
    let base_session = OAuthSession::new(
        TEST_ALICE_DID,
        "at_shared",
        Some(initial_rt.to_string()),
        "DPoP",
        Some("atproto".to_string()),
        Some(300),
        key,
        Some("https://pds.example.com".to_string()),
        Some(auth_server.uri()),
        Some(format!("{}/oauth/token", auth_server.uri())),
    )
    .unwrap();

    let client = Arc::new(
        AtprotoOAuthClient::builder()
            .client_metadata(OAuthClientMetadata::new(TEST_CLIENT_ID, TEST_REDIRECT_URI))
            .allow_insecure_localhost(true)
            .build()
            .unwrap(),
    );

    let concurrency = 15;
    let local = tokio::task::LocalSet::new();

    let (successes, failures) = local
        .run_until(async move {
            let mut handles = Vec::new();

            for _ in 0..concurrency {
                let client_clone = client.clone();
                let session_clone = base_session.clone();

                handles.push(tokio::task::spawn_local(async move {
                    client_clone.refresh_token(&session_clone).await
                }));
            }

            let mut succ = 0;
            let mut fail = 0;

            for h in handles {
                match h.await.unwrap() {
                    Ok(_) => succ += 1,
                    Err(AtprotoOAuthError::Token(TokenError::RequestFailed {
                        status: 400,
                        ..
                    })) => {
                        fail += 1;
                    }
                    Err(other) => panic!("Unexpected error in race condition test: {other:?}"),
                }
            }
            (succ, fail)
        })
        .await;

    assert_eq!(
        successes, 1,
        "Exactly 1 concurrent refresh request should succeed on single-use refresh token"
    );
    assert_eq!(
        failures,
        concurrency - 1,
        "All other concurrent refresh requests should fail with invalid_grant"
    );
}

#[tokio::test]
async fn test_refresh_token_omitted_by_server_sets_none() {
    let auth_server = MockServer::start().await;

    // Server returns access_token without a new refresh_token
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_json(json!({
                    "access_token": "at_new_without_rt",
                    "token_type": "DPoP",
                    "expires_in": 3600,
                    "scope": "atproto",
                    "sub": TEST_ALICE_DID
                })),
        )
        .mount(&auth_server)
        .await;

    let key = DPoPKey::generate();
    let mut session = OAuthSession::new(
        TEST_ALICE_DID,
        "at_old",
        Some("rt_initial".to_string()),
        "DPoP",
        Some("atproto".to_string()),
        Some(300),
        key,
        Some("https://pds.example.com".to_string()),
        Some(auth_server.uri()),
        Some(format!("{}/oauth/token", auth_server.uri())),
    )
    .unwrap();

    let client = AtprotoOAuthClient::builder()
        .client_metadata(OAuthClientMetadata::new(TEST_CLIENT_ID, TEST_REDIRECT_URI))
        .allow_insecure_localhost(true)
        .build()
        .unwrap();

    client.refresh_session(&mut session).await.unwrap();

    assert_eq!(session.access_token(), "at_new_without_rt");
    assert_eq!(session.refresh_token(), None);

    // Subsequent refresh attempts must immediately fail locally with MissingRefreshToken
    let next_err = client.refresh_session(&mut session).await;
    assert!(matches!(
        next_err,
        Err(AtprotoOAuthError::Token(TokenError::MissingRefreshToken))
    ));
}

// ============================================================================
// 2. CONCURRENT TOKEN EXCHANGE & STATE PARAMETER TESTS
// ============================================================================

#[tokio::test]
async fn test_concurrent_independent_logins_20_actors() {
    let env = MockOAuthEnvironment::start_default().await;

    let request_uri = "urn:ietf:params:oauth:request_uri:req-multi-20";
    env.auth_server.mount_par_success(request_uri, 120).await;

    let ssrf_filter = SsrfFilter::new(true);
    let resolver = IdentityResolverBuilder::new()
        .ssrf_filter(ssrf_filter)
        .plc_directory_url(env.plc.uri())
        .dns_resolver(std::sync::Arc::new(env.dns.clone()))
        .build();

    let client = Arc::new(
        AtprotoOAuthClient::builder()
            .client_metadata(OAuthClientMetadata::new(TEST_CLIENT_ID, TEST_REDIRECT_URI))
            .identity_resolver(resolver)
            .allow_insecure_localhost(true)
            .build()
            .unwrap(),
    );

    let actor_count = 20;
    let mut handles = Vec::new();

    for _ in 0..actor_count {
        let client_clone = client.clone();
        handles.push(tokio::spawn(async move {
            client_clone.initiate_login(TEST_ALICE_HANDLE).await
        }));
    }

    let mut state_tokens = HashSet::new();
    let mut dpop_thumbprints = HashSet::new();

    for h in handles {
        let (auth_req, stored_state) = h.await.unwrap().unwrap();
        assert_eq!(auth_req.request_uri, request_uri);
        assert_eq!(auth_req.state, stored_state.state);
        assert_eq!(stored_state.did.as_deref(), Some(TEST_ALICE_DID));

        // State tokens must have 256-bit entropy and zero collisions
        assert!(
            state_tokens.insert(auth_req.state),
            "Detected state token collision!"
        );

        // Ephemeral DPoP keypairs must be unique per session
        let jkt = stored_state.dpop_key.jwk_thumbprint();
        assert!(
            dpop_thumbprints.insert(jkt),
            "Detected DPoP key collision across logins!"
        );
    }

    assert_eq!(state_tokens.len(), actor_count);
    assert_eq!(dpop_thumbprints.len(), actor_count);
}

#[tokio::test]
async fn test_concurrent_authorization_code_single_use_race() {
    let auth_server = MockServer::start().await;
    let single_code = "auth_code_high_concurrency_race";
    let responder = SingleUseCodeResponder::new(single_code, TEST_ALICE_DID);

    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .and(header_exists("dpop"))
        .respond_with(responder)
        .mount(&auth_server)
        .await;

    let client = Arc::new(
        AtprotoOAuthClient::builder()
            .client_metadata(OAuthClientMetadata::new(TEST_CLIENT_ID, TEST_REDIRECT_URI))
            .allow_insecure_localhost(true)
            .build()
            .unwrap(),
    );

    let dpop_key = DPoPKey::generate();
    let state_entry = StoredStateEntry {
        state: "state_race_123".to_string(),
        client_id: TEST_CLIENT_ID.to_string(),
        code_verifier: "pkce_verifier_123".to_string(),
        dpop_key,
        issuer: auth_server.uri(),
        did: Some(TEST_ALICE_DID.to_string()),
        handle: Some(TEST_ALICE_HANDLE.to_string()),
        redirect_uri: TEST_REDIRECT_URI.to_string(),
        pds_endpoint: "https://pds.example.com".to_string(),
        token_endpoint: format!("{}/oauth/token", auth_server.uri()),
        scopes: "atproto".to_string(),
        created_at: SystemTime::now(),
        expires_in_secs: 300,
    };

    let concurrency = 20;
    let local = tokio::task::LocalSet::new();

    let (successes, failures) = local
        .run_until(async move {
            let mut handles = Vec::new();

            for _ in 0..concurrency {
                let client_clone = client.clone();
                let entry_clone = state_entry.clone();

                handles.push(tokio::task::spawn_local(async move {
                    client_clone.exchange_code(single_code, &entry_clone).await
                }));
            }

            let mut succ = 0;
            let mut fail = 0;

            for h in handles {
                match h.await.unwrap() {
                    Ok(session) => {
                        assert_eq!(session.sub(), TEST_ALICE_DID);
                        assert_eq!(session.access_token(), "at_single_use_success");
                        succ += 1;
                    }
                    Err(AtprotoOAuthError::Token(TokenError::RequestFailed {
                        status: 400,
                        ..
                    })) => {
                        fail += 1;
                    }
                    Err(other) => panic!("Unexpected error in code race: {other:?}"),
                }
            }
            (succ, fail)
        })
        .await;

    assert_eq!(
        successes, 1,
        "Exactly 1 code exchange must succeed for single-use authorization code"
    );
    assert_eq!(
        failures,
        concurrency - 1,
        "All other concurrent code exchange attempts must fail with invalid_grant"
    );
}

#[tokio::test]
async fn test_callback_state_swapping_under_concurrency() {
    let client = AtprotoOAuthClient::builder()
        .client_metadata(OAuthClientMetadata::new(TEST_CLIENT_ID, TEST_REDIRECT_URI))
        .allow_insecure_localhost(true)
        .build()
        .unwrap();

    let user_count = 30;
    let mut stored_states = Vec::new();

    for i in 0..user_count {
        let state = format!("state_user_{i}_{}", rand::random::<u64>());
        let entry = StoredStateEntry {
            state: state.clone(),
            client_id: TEST_CLIENT_ID.to_string(),
            code_verifier: format!("verifier_{i}"),
            dpop_key: DPoPKey::generate(),
            issuer: "https://auth.example.com".to_string(),
            did: Some(format!("did:plc:user_{i}")),
            handle: Some(format!("user_{i}.bsky.social")),
            redirect_uri: TEST_REDIRECT_URI.to_string(),
            pds_endpoint: "https://pds.example.com".to_string(),
            token_endpoint: "https://auth.example.com/oauth/token".to_string(),
            scopes: "atproto".to_string(),
            created_at: SystemTime::now(),
            expires_in_secs: 300,
        };
        stored_states.push(entry);
    }

    // Attempt callbacks where state parameter is mismatched/swapped with a different user
    for i in 0..user_count {
        let other_idx = (i + 1) % user_count;
        let swapped_cb = CallbackParams::new("auth_code_123", &stored_states[other_idx].state)
            .with_iss("https://auth.example.com");

        let err = client
            .handle_callback_with_entry(&swapped_cb, &stored_states[i])
            .await;
        assert!(
            matches!(
                err,
                Err(AtprotoOAuthError::Token(TokenError::InvalidState(_)))
            ),
            "Swapped state callback for user {i} should be rejected with InvalidState"
        );
    }
}

#[tokio::test]
async fn test_callback_issuer_tampering_variants() {
    let client = AtprotoOAuthClient::builder()
        .client_metadata(OAuthClientMetadata::new(TEST_CLIENT_ID, TEST_REDIRECT_URI))
        .allow_insecure_localhost(true)
        .build()
        .unwrap();

    let expected_issuer = "https://auth.bsky.social";
    let state_entry = StoredStateEntry {
        state: "valid_state_123".to_string(),
        client_id: TEST_CLIENT_ID.to_string(),
        code_verifier: "verifier_123".to_string(),
        dpop_key: DPoPKey::generate(),
        issuer: expected_issuer.to_string(),
        did: Some(TEST_ALICE_DID.to_string()),
        handle: Some(TEST_ALICE_HANDLE.to_string()),
        redirect_uri: TEST_REDIRECT_URI.to_string(),
        pds_endpoint: "https://pds.bsky.social".to_string(),
        token_endpoint: "https://auth.bsky.social/oauth/token".to_string(),
        scopes: "atproto".to_string(),
        created_at: SystemTime::now(),
        expires_in_secs: 300,
    };

    let invalid_issuers = vec![
        "https://evil-auth.bsky.social",
        "https://auth.bsky.social.evil.com",
        "http://auth.bsky.social",
        "https://auth.bsky.social:8443",
        "https://auth.example.com",
        "",
    ];

    for bad_iss in invalid_issuers {
        let cb = CallbackParams::new("code_123", "valid_state_123").with_iss(bad_iss);
        let err = client.handle_callback_with_entry(&cb, &state_entry).await;
        assert!(
            matches!(
                err,
                Err(AtprotoOAuthError::Token(TokenError::IssuerMismatch { .. }))
            ),
            "Issuer {bad_iss} should have failed IssuerMismatch"
        );
    }

    // Missing callback iss entirely (RFC 9207 mandatory)
    let missing_iss_cb = CallbackParams::new("code_123", "valid_state_123");
    let err_missing_iss = client
        .handle_callback_with_entry(&missing_iss_cb, &state_entry)
        .await;
    assert!(
        matches!(
            err_missing_iss,
            Err(AtprotoOAuthError::Token(TokenError::MissingCallbackIssuer))
        ),
        "Missing callback iss must fail with MissingCallbackIssuer"
    );

    // Trailing slash normalization: https://auth.bsky.social/ vs https://auth.bsky.social
    // (Both normalize to the same authority/path)
    let trailing_slash_cb =
        CallbackParams::new("code_123", "valid_state_123").with_iss("https://auth.bsky.social/");
    let res = client
        .handle_callback_with_entry(&trailing_slash_cb, &state_entry)
        .await;
    assert!(
        !matches!(
            res,
            Err(AtprotoOAuthError::Token(TokenError::IssuerMismatch { .. }))
        ),
        "Trailing slash in issuer should be normalized and pass issuer check"
    );
}

// ============================================================================
// 3. TOKEN RESPONSE TAMPERING CHALLENGE TESTS
// ============================================================================

#[tokio::test]
async fn test_token_response_sub_mismatch_and_empty_did_variants() {
    let auth_server = MockServer::start().await;

    let sub_tamper_cases = vec![
        ("did:plc:attacker999999999999999", "sub_mismatch"),
        ("did:web:attacker.com", "sub_mismatch"),
        ("", "missing_did"),
        ("   ", "missing_did"),
    ];

    let client = AtprotoOAuthClient::builder()
        .client_metadata(OAuthClientMetadata::new(TEST_CLIENT_ID, TEST_REDIRECT_URI))
        .allow_insecure_localhost(true)
        .build()
        .unwrap();

    for (resp_sub, expected_err) in sub_tamper_cases {
        auth_server.reset().await;

        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/json")
                    .set_body_json(json!({
                        "access_token": "at_test",
                        "token_type": "DPoP",
                        "expires_in": 3600,
                        "refresh_token": "rt_test",
                        "scope": "atproto",
                        "sub": resp_sub
                    })),
            )
            .mount(&auth_server)
            .await;

        let state_entry = StoredStateEntry {
            state: "state_123".to_string(),
            client_id: TEST_CLIENT_ID.to_string(),
            code_verifier: "verifier_123".to_string(),
            dpop_key: DPoPKey::generate(),
            issuer: auth_server.uri(),
            did: Some(TEST_ALICE_DID.to_string()),
            handle: Some(TEST_ALICE_HANDLE.to_string()),
            redirect_uri: TEST_REDIRECT_URI.to_string(),
            pds_endpoint: "https://pds.example.com".to_string(),
            token_endpoint: format!("{}/oauth/token", auth_server.uri()),
            scopes: "atproto".to_string(),
            created_at: SystemTime::now(),
            expires_in_secs: 300,
        };

        let res = client.exchange_code("code_123", &state_entry).await;
        match expected_err {
            "sub_mismatch" => {
                assert!(
                    matches!(
                        res,
                        Err(AtprotoOAuthError::Token(TokenError::SubMismatch { .. }))
                    ),
                    "Expected SubMismatch for sub='{resp_sub}', got: {res:?}"
                );
            }
            "missing_did" => {
                assert!(
                    matches!(res, Err(AtprotoOAuthError::Token(TokenError::MissingDid))),
                    "Expected MissingDid for sub='{resp_sub}', got: {res:?}"
                );
            }
            _ => unreachable!(),
        }
    }
}

#[tokio::test]
async fn test_token_response_sub_tampering_during_refresh() {
    let auth_server = MockServer::start().await;

    // Refresh response tries to swap Alice's session with Bob's DID
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_json(json!({
                    "access_token": "at_bob_tampered",
                    "token_type": "DPoP",
                    "expires_in": 3600,
                    "refresh_token": "rt_bob_tampered",
                    "scope": "atproto",
                    "sub": TEST_BOB_DID
                })),
        )
        .mount(&auth_server)
        .await;

    let key = DPoPKey::generate();
    let mut session = OAuthSession::new(
        TEST_ALICE_DID,
        "at_alice",
        Some("rt_alice".to_string()),
        "DPoP",
        Some("atproto".to_string()),
        Some(300),
        key,
        Some("https://pds.example.com".to_string()),
        Some(auth_server.uri()),
        Some(format!("{}/oauth/token", auth_server.uri())),
    )
    .unwrap();

    let client = AtprotoOAuthClient::builder()
        .client_metadata(OAuthClientMetadata::new(TEST_CLIENT_ID, TEST_REDIRECT_URI))
        .allow_insecure_localhost(true)
        .build()
        .unwrap();

    let err = client.refresh_session(&mut session).await;
    assert!(
        matches!(
            &err,
            Err(AtprotoOAuthError::Token(TokenError::SubMismatch {
                ref expected,
                ref actual
            })) if expected == TEST_ALICE_DID && actual == TEST_BOB_DID
        ),
        "Expected SubMismatch during refresh DID tampering, got: {err:?}"
    );
}

#[tokio::test]
async fn test_token_response_token_type_tampering_exhaustive() {
    let auth_server = MockServer::start().await;
    let valid_types = vec!["DPoP", "dpop", "DPOP", "dPoP", "dpOp"];
    let invalid_types = vec![
        "Bearer",
        "bearer",
        "BEARER",
        "MAC",
        "Basic",
        "OAuth",
        "token",
        "",
        "DPoP token",
        "DPoP2",
    ];

    let client = AtprotoOAuthClient::builder()
        .client_metadata(OAuthClientMetadata::new(TEST_CLIENT_ID, TEST_REDIRECT_URI))
        .allow_insecure_localhost(true)
        .build()
        .unwrap();

    for vtype in valid_types {
        auth_server.reset().await;
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/json")
                    .set_body_json(json!({
                        "access_token": "at_valid",
                        "token_type": vtype,
                        "expires_in": 3600,
                        "refresh_token": "rt_valid",
                        "scope": "atproto",
                        "sub": TEST_ALICE_DID
                    })),
            )
            .mount(&auth_server)
            .await;

        let state_entry = StoredStateEntry {
            state: "state_123".to_string(),
            client_id: TEST_CLIENT_ID.to_string(),
            code_verifier: "verifier_123".to_string(),
            dpop_key: DPoPKey::generate(),
            issuer: auth_server.uri(),
            did: Some(TEST_ALICE_DID.to_string()),
            handle: Some(TEST_ALICE_HANDLE.to_string()),
            redirect_uri: TEST_REDIRECT_URI.to_string(),
            pds_endpoint: "https://pds.example.com".to_string(),
            token_endpoint: format!("{}/oauth/token", auth_server.uri()),
            scopes: "atproto".to_string(),
            created_at: SystemTime::now(),
            expires_in_secs: 300,
        };

        let session = client
            .exchange_code("code_123", &state_entry)
            .await
            .unwrap();
        assert_eq!(session.token_type(), vtype);
    }

    for itype in invalid_types {
        auth_server.reset().await;
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/json")
                    .set_body_json(json!({
                        "access_token": "at_invalid",
                        "token_type": itype,
                        "expires_in": 3600,
                        "refresh_token": "rt_invalid",
                        "scope": "atproto",
                        "sub": TEST_ALICE_DID
                    })),
            )
            .mount(&auth_server)
            .await;

        let state_entry = StoredStateEntry {
            state: "state_123".to_string(),
            client_id: TEST_CLIENT_ID.to_string(),
            code_verifier: "verifier_123".to_string(),
            dpop_key: DPoPKey::generate(),
            issuer: auth_server.uri(),
            did: Some(TEST_ALICE_DID.to_string()),
            handle: Some(TEST_ALICE_HANDLE.to_string()),
            redirect_uri: TEST_REDIRECT_URI.to_string(),
            pds_endpoint: "https://pds.example.com".to_string(),
            token_endpoint: format!("{}/oauth/token", auth_server.uri()),
            scopes: "atproto".to_string(),
            created_at: SystemTime::now(),
            expires_in_secs: 300,
        };

        let err = client.exchange_code("code_123", &state_entry).await;
        assert!(
            matches!(
                err,
                Err(AtprotoOAuthError::Token(TokenError::InvalidTokenType(_)))
            ),
            "Expected InvalidTokenType for '{itype}', got: {err:?}"
        );
    }
}

#[tokio::test]
async fn test_token_response_missing_atproto_scope_variants() {
    let auth_server = MockServer::start().await;
    let invalid_scopes = vec![
        "email profile",
        "transition:generic",
        "atproto_fake",
        "notatproto",
        "atprotocol",
        "atproto-extra",
        "",
    ];

    let client = AtprotoOAuthClient::builder()
        .client_metadata(OAuthClientMetadata::new(TEST_CLIENT_ID, TEST_REDIRECT_URI))
        .allow_insecure_localhost(true)
        .build()
        .unwrap();

    for bad_scope in invalid_scopes {
        auth_server.reset().await;
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/json")
                    .set_body_json(json!({
                        "access_token": "at_scope_test",
                        "token_type": "DPoP",
                        "expires_in": 3600,
                        "refresh_token": "rt_scope_test",
                        "scope": bad_scope,
                        "sub": TEST_ALICE_DID
                    })),
            )
            .mount(&auth_server)
            .await;

        let state_entry = StoredStateEntry {
            state: "state_123".to_string(),
            client_id: TEST_CLIENT_ID.to_string(),
            code_verifier: "verifier_123".to_string(),
            dpop_key: DPoPKey::generate(),
            issuer: auth_server.uri(),
            did: Some(TEST_ALICE_DID.to_string()),
            handle: Some(TEST_ALICE_HANDLE.to_string()),
            redirect_uri: TEST_REDIRECT_URI.to_string(),
            pds_endpoint: "https://pds.example.com".to_string(),
            token_endpoint: format!("{}/oauth/token", auth_server.uri()),
            scopes: "atproto".to_string(),
            created_at: SystemTime::now(),
            expires_in_secs: 300,
        };

        let err = client.exchange_code("code_123", &state_entry).await;
        assert!(
            matches!(
                err,
                Err(AtprotoOAuthError::Token(TokenError::MissingAtprotoScope(_)))
            ),
            "Scope '{bad_scope}' should be rejected with MissingAtprotoScope, got: {err:?}"
        );
    }

    // Completely omitted scope field (ATProto requires mandatory scope in token response)
    auth_server.reset().await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_json(json!({
                    "access_token": "at_missing_scope",
                    "token_type": "DPoP",
                    "expires_in": 3600,
                    "refresh_token": "rt_missing_scope",
                    "sub": TEST_ALICE_DID
                })),
        )
        .mount(&auth_server)
        .await;

    let state_entry_no_scope = StoredStateEntry {
        state: "state_123".to_string(),
        client_id: TEST_CLIENT_ID.to_string(),
        code_verifier: "verifier_123".to_string(),
        dpop_key: DPoPKey::generate(),
        issuer: auth_server.uri(),
        did: Some(TEST_ALICE_DID.to_string()),
        handle: Some(TEST_ALICE_HANDLE.to_string()),
        redirect_uri: TEST_REDIRECT_URI.to_string(),
        pds_endpoint: "https://pds.example.com".to_string(),
        token_endpoint: format!("{}/oauth/token", auth_server.uri()),
        scopes: "atproto".to_string(),
        created_at: SystemTime::now(),
        expires_in_secs: 300,
    };

    let err_no_scope = client
        .exchange_code("code_123", &state_entry_no_scope)
        .await;
    assert!(
        matches!(
            err_no_scope,
            Err(AtprotoOAuthError::Token(TokenError::MissingScope))
        ),
        "Omitted scope must fail with MissingScope"
    );

    // Valid scopes containing "atproto" as distinct whitespace token
    let valid_scopes = vec![
        "atproto",
        "atproto transition:generic",
        "transition:generic atproto",
        "transition:generic atproto transition:chat",
    ];

    for good_scope in valid_scopes {
        auth_server.reset().await;
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/json")
                    .set_body_json(json!({
                        "access_token": "at_valid_scope",
                        "token_type": "DPoP",
                        "expires_in": 3600,
                        "refresh_token": "rt_valid_scope",
                        "scope": good_scope,
                        "sub": TEST_ALICE_DID
                    })),
            )
            .mount(&auth_server)
            .await;

        let state_entry = StoredStateEntry {
            state: "state_123".to_string(),
            client_id: TEST_CLIENT_ID.to_string(),
            code_verifier: "verifier_123".to_string(),
            dpop_key: DPoPKey::generate(),
            issuer: auth_server.uri(),
            did: Some(TEST_ALICE_DID.to_string()),
            handle: Some(TEST_ALICE_HANDLE.to_string()),
            redirect_uri: TEST_REDIRECT_URI.to_string(),
            pds_endpoint: "https://pds.example.com".to_string(),
            token_endpoint: format!("{}/oauth/token", auth_server.uri()),
            scopes: "atproto".to_string(),
            created_at: SystemTime::now(),
            expires_in_secs: 300,
        };

        let session = client
            .exchange_code("code_123", &state_entry)
            .await
            .unwrap();
        assert_eq!(session.scope(), Some(good_scope));
    }
}

#[tokio::test]
async fn test_token_response_corrupted_json_and_wrong_types() {
    let auth_server = MockServer::start().await;
    let corrupted_payloads = vec![
        "{ incomplete json: ",
        r#"{"access_token": 12345, "token_type": "DPoP", "sub": "did:plc:alice"}"#,
        r#"{"access_token": "at_123", "token_type": 123, "sub": "did:plc:alice"}"#,
        r#"{"token_type": "DPoP", "sub": "did:plc:alice"}"#, // Missing access_token
        r#"{"access_token": "at_123", "token_type": "DPoP"}"#, // Missing sub
        "",
    ];

    let client = AtprotoOAuthClient::builder()
        .client_metadata(OAuthClientMetadata::new(TEST_CLIENT_ID, TEST_REDIRECT_URI))
        .allow_insecure_localhost(true)
        .build()
        .unwrap();

    for payload in corrupted_payloads {
        auth_server.reset().await;
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/json")
                    .set_body_raw(payload.as_bytes(), "application/json"),
            )
            .mount(&auth_server)
            .await;

        let state_entry = StoredStateEntry {
            state: "state_123".to_string(),
            client_id: TEST_CLIENT_ID.to_string(),
            code_verifier: "verifier_123".to_string(),
            dpop_key: DPoPKey::generate(),
            issuer: auth_server.uri(),
            did: Some(TEST_ALICE_DID.to_string()),
            handle: Some(TEST_ALICE_HANDLE.to_string()),
            redirect_uri: TEST_REDIRECT_URI.to_string(),
            pds_endpoint: "https://pds.example.com".to_string(),
            token_endpoint: format!("{}/oauth/token", auth_server.uri()),
            scopes: "atproto".to_string(),
            created_at: SystemTime::now(),
            expires_in_secs: 300,
        };

        let res = client.exchange_code("code_123", &state_entry).await;
        assert!(
            matches!(res, Err(AtprotoOAuthError::Token(TokenError::Json(_)))),
            "Expected Json error on payload '{payload}', got: {res:?}"
        );
    }
}

#[tokio::test]
async fn test_token_response_http_error_codes_mapping() {
    let auth_server = MockServer::start().await;
    let error_scenarios = vec![
        (400, "invalid_request", Some("Missing code verifier")),
        (400, "invalid_client", Some("Client authentication failed")),
        (400, "invalid_grant", Some("Authorization code expired")),
        (
            400,
            "unauthorized_client",
            Some("Client not authorized for grant"),
        ),
        (
            400,
            "unsupported_grant_type",
            Some("Grant type not supported"),
        ),
        (400, "invalid_scope", Some("Scope not allowed")),
        (
            500,
            "server_error",
            Some("Internal auth server database failure"),
        ),
        (503, "temporarily_unavailable", Some("Server overloaded")),
    ];

    let client = AtprotoOAuthClient::builder()
        .client_metadata(OAuthClientMetadata::new(TEST_CLIENT_ID, TEST_REDIRECT_URI))
        .allow_insecure_localhost(true)
        .build()
        .unwrap();

    for (status, err_code, desc) in error_scenarios {
        auth_server.reset().await;
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(
                ResponseTemplate::new(status)
                    .insert_header("content-type", "application/json")
                    .set_body_json(json!({
                        "error": err_code,
                        "error_description": desc
                    })),
            )
            .mount(&auth_server)
            .await;

        let state_entry = StoredStateEntry {
            state: "state_123".to_string(),
            client_id: TEST_CLIENT_ID.to_string(),
            code_verifier: "verifier_123".to_string(),
            dpop_key: DPoPKey::generate(),
            issuer: auth_server.uri(),
            did: Some(TEST_ALICE_DID.to_string()),
            handle: Some(TEST_ALICE_HANDLE.to_string()),
            redirect_uri: TEST_REDIRECT_URI.to_string(),
            pds_endpoint: "https://pds.example.com".to_string(),
            token_endpoint: format!("{}/oauth/token", auth_server.uri()),
            scopes: "atproto".to_string(),
            created_at: SystemTime::now(),
            expires_in_secs: 300,
        };

        let res = client.exchange_code("code_123", &state_entry).await;
        assert!(
            matches!(
                &res,
                Err(AtprotoOAuthError::Token(TokenError::RequestFailed {
                    status: s,
                    error: e,
                    description: d
                })) if *s == status && e == err_code && d.as_deref() == desc
            ),
            "Expected structured RequestFailed for status {status}, got: {res:?}"
        );
    }
}

#[tokio::test]
async fn test_token_endpoint_ssrf_filtering() {
    let client = AtprotoOAuthClient::builder()
        .client_metadata(OAuthClientMetadata::new(TEST_CLIENT_ID, TEST_REDIRECT_URI))
        .allow_insecure_localhost(false) // Strict SSRF on
        .build()
        .unwrap();

    let ssrf_endpoints = vec![
        "http://169.254.169.254/latest/meta-data", // Cloud metadata
        "http://127.0.0.1:8080/oauth/token",       // Loopback IPv4
        "http://[::1]:8080/oauth/token",           // Loopback IPv6
        "http://10.0.0.1/oauth/token",             // RFC 1918 Private
        "http://192.168.1.1/oauth/token",          // RFC 1918 Private
        "http://172.16.0.1/oauth/token",           // RFC 1918 Private
        "http://100.64.0.1/oauth/token",           // CGNAT
    ];

    for ssrf_url in ssrf_endpoints {
        let state_entry = StoredStateEntry {
            state: "state_123".to_string(),
            client_id: TEST_CLIENT_ID.to_string(),
            code_verifier: "verifier_123".to_string(),
            dpop_key: DPoPKey::generate(),
            issuer: "https://auth.example.com".to_string(),
            did: Some(TEST_ALICE_DID.to_string()),
            handle: Some(TEST_ALICE_HANDLE.to_string()),
            redirect_uri: TEST_REDIRECT_URI.to_string(),
            pds_endpoint: "https://pds.example.com".to_string(),
            token_endpoint: ssrf_url.to_string(),
            scopes: "atproto".to_string(),
            created_at: SystemTime::now(),
            expires_in_secs: 300,
        };

        let err = client.exchange_code("code_123", &state_entry).await;
        assert!(
            matches!(err, Err(AtprotoOAuthError::Token(TokenError::Ssrf(_)))),
            "Token endpoint '{ssrf_url}' must be blocked by SSRF filter, got: {err:?}"
        );
    }
}
