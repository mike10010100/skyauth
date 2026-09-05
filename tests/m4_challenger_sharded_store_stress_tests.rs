//! Empirical Stress and Adversarial Challenge Tests for Milestone 4.
//!
//! Written by Challenger 1 to rigorously stress-test:
//! 1. 64-shard concurrent race condition: 100 racing threads attempting to `take_state` simultaneously on the same key.
//! 2. TTL pruning boundary stress: items expiring at t - epsilon, t + epsilon, massive concurrent insertions during background pruning sweeps.
//! 3. Shard distribution uniformity test across 10,000 random keys (Chi-squared goodness-of-fit).
//! 4. Concurrency and edge cases in Tower, Axum, and Actix framework integrations.
//! 5. Proptest property-based verification of store invariants.

#![allow(
    dead_code,
    unused_imports,
    missing_docs,
    clippy::all,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use std::collections::{HashMap, HashSet};
use std::convert::Infallible;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant, SystemTime};

use http::{header, Request, Response, StatusCode};
use proptest::prelude::*;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use tokio_util::sync::CancellationToken;
#[cfg(feature = "tower")]
use tower_layer::Layer;
#[cfg(feature = "tower")]
use tower_service::Service;

use skyauth::client::{AuthorizationRequest, OAuthClientMetadata, StoredStateEntry};
use skyauth::crypto::constant_time_eq;
use skyauth::dpop::{compute_access_token_hash, DPoPKey, DPoPVerifier};
use skyauth::error::{IntegrationError, StoreError};
use skyauth::integrations::{AuthenticatedUser, OAuthCallbackQuery, OAuthSessionExtension};
use skyauth::store::{OAuthStateStore, OAuthStore, DEFAULT_STATE_TTL, NUM_SHARDS};

fn mock_stored_state(state: &str, ttl_secs: u64) -> StoredStateEntry {
    StoredStateEntry {
        state: state.to_string(),
        client_id: "https://app.example.com/client-metadata.json".to_string(),
        code_verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk-sample-pkce-verifier"
            .to_string(),
        dpop_key: DPoPKey::generate(),
        issuer: "https://auth.example.com".to_string(),
        did: Some("did:plc:alice1234567890abcdef".to_string()),
        handle: Some("alice.bsky.social".to_string()),
        redirect_uri: "https://app.example.com/callback".to_string(),
        pds_endpoint: "https://pds.example.com".to_string(),
        token_endpoint: "https://auth.example.com/oauth/token".to_string(),
        scopes: "atproto transition:generic".to_string(),
        created_at: SystemTime::now(),
        expires_in_secs: ttl_secs,
    }
}

#[test]
fn test_challenge_100_threads_racing_take_state_single_key() {
    let store = Arc::new(OAuthStateStore::default());

    for round in 0..20 {
        let state_key = format!(
            "race_target_token_round_{round}_{}",
            thread_rng().gen::<u64>()
        );
        let entry = mock_stored_state(&state_key, 300);

        store
            .insert_state_sync(state_key.clone(), entry, Duration::from_secs(300))
            .unwrap();
        assert_eq!(store.total_entries(), 1);

        let num_racers = 100;
        let winner_count = Arc::new(AtomicUsize::new(0));
        let start_barrier = Arc::new(Barrier::new(num_racers));
        let mut handles = Vec::with_capacity(num_racers);

        for thread_idx in 0..num_racers {
            let s = Arc::clone(&store);
            let w = Arc::clone(&winner_count);
            let b = Arc::clone(&start_barrier);
            let k = state_key.clone();

            handles.push(
                std::thread::Builder::new()
                    .name(format!("racer-{round}-{thread_idx}"))
                    .spawn(move || {
                        b.wait();
                        let result = s.take_state_sync(&k);
                        if let Some(record) = result {
                            assert_eq!(record.state, k);
                            w.fetch_add(1, Ordering::SeqCst);
                        }
                    })
                    .unwrap(),
            );
        }

        for h in handles {
            h.join().unwrap();
        }

        let winners = winner_count.load(Ordering::SeqCst);
        assert_eq!(
            winners, 1,
            "Round {round}: Exactly 1 thread out of 100 must win the race! Got {winners}"
        );

        assert_eq!(store.total_entries(), 0);
        assert!(store.take_state_sync(&state_key).is_none());
        assert!(!store.contains_state_sync(&state_key));
    }
}

#[tokio::test]
async fn test_challenge_100_async_tasks_racing_take_state() {
    let store = Arc::new(OAuthStateStore::default());
    let state_key = "async_tokio_100_race_key";
    let entry = mock_stored_state(state_key, 300);

    store
        .insert_state(state_key.to_string(), entry, Duration::from_secs(300))
        .await
        .unwrap();

    let num_tasks = 100;
    let winner_count = Arc::new(AtomicUsize::new(0));
    let barrier = Arc::new(tokio::sync::Barrier::new(num_tasks));
    let mut tasks = Vec::with_capacity(num_tasks);

    for _ in 0..num_tasks {
        let s = Arc::clone(&store);
        let w = Arc::clone(&winner_count);
        let b = Arc::clone(&barrier);
        let k = state_key.to_string();

        tasks.push(tokio::spawn(async move {
            b.wait().await;
            if let Ok(Some(record)) = s.take_state(&k).await {
                assert_eq!(record.state, k);
                w.fetch_add(1, Ordering::SeqCst);
            }
        }));
    }

    for t in tasks {
        t.await.unwrap();
    }

    assert_eq!(
        winner_count.load(Ordering::SeqCst),
        1,
        "Async trait take_state: Exactly 1 out of 100 tokio tasks must consume the state"
    );
    assert!(!store.contains_state(state_key).await.unwrap());
}

#[test]
fn test_challenge_multi_key_high_contention_100_threads_x_10_keys() {
    let store = Arc::new(OAuthStateStore::default());
    let num_keys = 10;
    let mut keys = Vec::new();

    for i in 0..num_keys {
        let key = format!("multi_race_key_{i}");
        store
            .insert_state_sync(
                key.clone(),
                mock_stored_state(&key, 300),
                Duration::from_secs(300),
            )
            .unwrap();
        keys.push(key);
    }
    assert_eq!(store.total_entries(), num_keys);

    let num_threads = 100;
    let consumed_counts = Arc::new(
        (0..num_keys)
            .map(|_| AtomicUsize::new(0))
            .collect::<Vec<_>>(),
    );
    let start_barrier = Arc::new(Barrier::new(num_threads));
    let mut handles = Vec::with_capacity(num_threads);

    for t_idx in 0..num_threads {
        let s = Arc::clone(&store);
        let c = Arc::clone(&consumed_counts);
        let b = Arc::clone(&start_barrier);
        let all_keys = keys.clone();

        handles.push(std::thread::spawn(move || {
            b.wait();
            for (offset, _) in all_keys.iter().enumerate() {
                let key_idx = (t_idx + offset) % all_keys.len();
                let target_key = &all_keys[key_idx];
                if s.take_state_sync(target_key).is_some() {
                    c[key_idx].fetch_add(1, Ordering::SeqCst);
                }
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    for (i, count) in consumed_counts.iter().enumerate() {
        let val = count.load(Ordering::SeqCst);
        assert_eq!(val, 1, "Key {i} must be consumed exactly once! Got {val}");
    }

    assert_eq!(store.total_entries(), 0);
}

#[test]
fn test_challenge_interleaved_insert_contains_take_concurrent_chaos() {
    let store = Arc::new(OAuthStateStore::default());
    let num_workers = 40;
    let ops_per_worker = 100;
    let start_barrier = Arc::new(Barrier::new(num_workers));
    let total_successful_takes = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::with_capacity(num_workers);

    for worker_id in 0..num_workers {
        let s = Arc::clone(&store);
        let b = Arc::clone(&start_barrier);
        let takes = Arc::clone(&total_successful_takes);

        handles.push(std::thread::spawn(move || {
            b.wait();
            for i in 0..ops_per_worker {
                let key = format!("chaos_key_{worker_id}_{i}");
                let entry = mock_stored_state(&key, 60);

                s.insert_state_sync(key.clone(), entry, Duration::from_secs(60))
                    .unwrap();

                assert!(s.contains_state_sync(&key));

                if s.take_state_sync(&key).is_some() {
                    takes.fetch_add(1, Ordering::SeqCst);
                }

                assert!(s.take_state_sync(&key).is_none());
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    assert_eq!(
        total_successful_takes.load(Ordering::SeqCst),
        num_workers * ops_per_worker
    );
    assert_eq!(store.total_entries(), 0);
}

#[test]
fn test_challenge_ttl_boundary_exact_epsilon_resolution() {
    let store = OAuthStateStore::default();

    let key_short = "key_short_ttl_200ms";
    let key_long = "key_long_ttl_500ms";

    store
        .insert_state_sync(
            key_short.to_string(),
            mock_stored_state(key_short, 1),
            Duration::from_millis(200),
        )
        .unwrap();

    store
        .insert_state_sync(
            key_long.to_string(),
            mock_stored_state(key_long, 1),
            Duration::from_millis(500),
        )
        .unwrap();

    assert_eq!(store.total_entries(), 2);

    std::thread::sleep(Duration::from_millis(50));
    assert!(
        store.contains_state_sync(key_short),
        "key_short must be active at t - eps"
    );
    assert!(
        store.contains_state_sync(key_long),
        "key_long must be active at t - eps"
    );

    std::thread::sleep(Duration::from_millis(210));
    assert!(
        !store.contains_state_sync(key_short),
        "key_short must be expired at t + eps (260ms > 200ms)"
    );
    assert!(
        store.take_state_sync(key_short).is_none(),
        "take_state_sync on expired key_short must return None"
    );
    assert!(
        store.contains_state_sync(key_long),
        "key_long must still be active at 260ms < 500ms"
    );

    std::thread::sleep(Duration::from_millis(300));
    assert!(
        !store.contains_state_sync(key_long),
        "key_long must be expired at 560ms > 500ms"
    );
    assert!(
        store.take_state_sync(key_long).is_none(),
        "take_state_sync on expired key_long must return None"
    );

    assert_eq!(store.total_entries(), 0);
}

#[test]
fn test_challenge_ttl_edge_cases_zero_and_extreme_durations() {
    let store = OAuthStateStore::default();

    let zero_key = "zero_ttl_key";
    store
        .insert_state_sync(
            zero_key.to_string(),
            mock_stored_state(zero_key, 0),
            Duration::ZERO,
        )
        .unwrap();

    assert!(!store.contains_state_sync(zero_key));
    assert!(store.take_state_sync(zero_key).is_none());

    let nano_key = "nano_ttl_key";
    store
        .insert_state_sync(
            nano_key.to_string(),
            mock_stored_state(nano_key, 0),
            Duration::from_nanos(1),
        )
        .unwrap();

    std::thread::sleep(Duration::from_millis(1));
    assert!(!store.contains_state_sync(nano_key));
    assert!(store.take_state_sync(nano_key).is_none());

    let huge_key = "huge_ttl_key";
    store
        .insert_state_sync(
            huge_key.to_string(),
            mock_stored_state(huge_key, 86400 * 365),
            Duration::from_secs(86400 * 365),
        )
        .unwrap();

    assert!(store.contains_state_sync(huge_key));
    let taken = store.take_state_sync(huge_key);
    assert!(taken.is_some());
    assert_eq!(taken.unwrap().state, huge_key);
}

#[tokio::test]
async fn test_challenge_massive_concurrent_insertions_during_background_pruner() {
    let store = Arc::new(OAuthStateStore::default());
    let cancel_token = CancellationToken::new();

    let pruner_handle = store.spawn_pruning_task(Duration::from_millis(2), cancel_token.clone());

    let num_writers = 40;
    let items_per_writer = 100;
    let barrier = Arc::new(tokio::sync::Barrier::new(num_writers));
    let mut writer_tasks = Vec::with_capacity(num_writers);

    for w_id in 0..num_writers {
        let s = Arc::clone(&store);
        let b = Arc::clone(&barrier);

        writer_tasks.push(tokio::spawn(async move {
            b.wait().await;
            for i in 0..items_per_writer {
                let key = format!("stream_{w_id}_{i}");
                let entry = mock_stored_state(&key, 300);

                let ttl = match i % 4 {
                    0 => Duration::ZERO,
                    1 => Duration::from_millis(15),
                    2 => Duration::from_millis(35),
                    _ => Duration::from_secs(60),
                };

                s.insert_state(key, entry, ttl).await.unwrap();
            }
        }));
    }

    for task in writer_tasks {
        task.await.unwrap();
    }

    tokio::time::sleep(Duration::from_millis(70)).await;

    let _ = store.prune_expired().await.unwrap();

    let remaining = store.total_entries();
    let expected_active = (num_writers * items_per_writer) / 4;
    assert_eq!(
        remaining, expected_active,
        "Expected exactly {expected_active} active items remaining, got {remaining}"
    );

    cancel_token.cancel();
    let res = pruner_handle.await;
    assert!(res.is_ok());

    for w_id in 0..num_writers {
        for i in (3..items_per_writer).step_by(4) {
            let key = format!("stream_{w_id}_{i}");
            let taken = store.take_state(&key).await.unwrap();
            assert!(taken.is_some(), "Key {key} should have been active");
        }
    }

    assert_eq!(store.total_entries(), 0);
}

#[test]
fn test_challenge_shard_distribution_uniformity_10000_random_keys() {
    let store = OAuthStateStore::default();
    let total_keys = 10_000usize;
    let mut shard_counts = vec![0usize; NUM_SHARDS];

    let mut rng = thread_rng();

    for i in 0..total_keys {
        let key = match i % 4 {
            0 => {
                let bytes: Vec<u8> = (0..32).map(|_| rng.gen::<u8>()).collect();
                base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &bytes)
            }
            1 => {
                let bytes: Vec<u8> = (0..32).map(|_| rng.gen::<u8>()).collect();
                hex::encode(bytes)
            }
            2 => {
                format!(
                    "{:08x}-{:04x}-4{:03x}-{:04x}-{:012x}",
                    rng.gen::<u32>(),
                    rng.gen::<u16>(),
                    rng.gen::<u16>() & 0x0fff,
                    (rng.gen::<u16>() & 0x3fff) | 0x8000,
                    rng.gen::<u64>() & 0x0000_ffff_ffff_ffff
                )
            }
            _ => {
                let len = rng.gen_range(43..=128);
                (0..len)
                    .map(|_| rng.sample(Alphanumeric) as char)
                    .collect::<String>()
            }
        };

        let shard_idx = store.shard_index(&key);
        assert!(
            shard_idx < NUM_SHARDS,
            "Shard index {shard_idx} exceeds NUM_SHARDS (64)"
        );
        shard_counts[shard_idx] += 1;
    }

    for (idx, &count) in shard_counts.iter().enumerate() {
        assert!(
            count > 0,
            "Shard {idx} was completely starved (0 keys allocated)"
        );
    }

    let expected = (total_keys as f64) / (NUM_SHARDS as f64);
    let mut chi_squared = 0.0;

    for &observed in &shard_counts {
        let diff = (observed as f64) - expected;
        chi_squared += (diff * diff) / expected;
    }

    assert!(
        chi_squared < 103.44,
        "Chi-squared test failed! chi_squared = {chi_squared:.2} exceeds critical threshold 103.44 (df=63)"
    );

    let min_count = *shard_counts.iter().min().unwrap();
    let max_count = *shard_counts.iter().max().unwrap();

    assert!(
        min_count >= 80,
        "Minimum shard count {min_count} is too low (expected ~156)"
    );
    assert!(
        max_count <= 240,
        "Maximum shard count {max_count} is too high (expected ~156)"
    );
}

#[test]
fn test_challenge_shard_index_deterministic_invariance() {
    let store = OAuthStateStore::default();
    let mut rng = thread_rng();

    for _ in 0..1000 {
        let key: String = (0..32).map(|_| rng.sample(Alphanumeric) as char).collect();
        let idx1 = store.shard_index(&key);
        let idx2 = store.shard_index(&key);
        let idx3 = store.shard_index(&key);

        assert_eq!(idx1, idx2);
        assert_eq!(idx2, idx3);
    }
}

#[cfg(feature = "tower")]
mod tower_stress_tests {
    use super::*;
    use skyauth::integrations::tower::OAuthAuthLayer;
    use tower::service_fn;

    #[tokio::test]
    async fn test_challenge_tower_middleware_concurrent_valid_and_invalid_dpop() {
        let key = DPoPKey::generate();
        let jkt = key.jwk_thumbprint();
        let access_token = "concurrent_valid_access_token_xyz";
        let ath = compute_access_token_hash(access_token);
        let uri = "https://pds.example.com/xrpc/app.bsky.feed.getFeedSkeleton";

        let store = skyauth::integrations::InMemoryTokenValidator::new();
        store.register_token(
            access_token,
            "did:plc:concurrent_user",
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
                if let Some(u) = user {
                    assert_eq!(u.dpop_thumbprint, expected_jkt);
                    Ok::<Response<String>, Infallible>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .body("Authenticated".to_string())
                            .unwrap(),
                    )
                } else {
                    Ok::<Response<String>, Infallible>(
                        Response::builder()
                            .status(StatusCode::INTERNAL_SERVER_ERROR)
                            .body("Missing user extension".to_string())
                            .unwrap(),
                    )
                }
            }
        });

        let service = Arc::new(tokio::sync::Mutex::new(layer.layer(inner)));

        let mut tasks = Vec::new();

        for i in 0..50 {
            let svc = Arc::clone(&service);
            let k = key.clone();
            let ath_str = ath.clone();
            let uri_str = uri.to_string();
            let tok_str = access_token.to_string();

            tasks.push(tokio::spawn(async move {
                let is_valid = i % 2 == 0;
                let proof = if is_valid {
                    k.create_proof("GET", &uri_str, None, Some(&ath_str))
                        .unwrap()
                } else {
                    k.create_proof("POST", &uri_str, None, Some(&ath_str))
                        .unwrap()
                };

                let req = Request::builder()
                    .method("GET")
                    .uri(&uri_str)
                    .header(header::AUTHORIZATION, format!("DPoP {tok_str}"))
                    .header("DPoP", proof)
                    .body(())
                    .unwrap();

                let mut guard = svc.lock().await;
                let resp = guard.call(req).await.unwrap();

                if is_valid {
                    assert_eq!(resp.status(), StatusCode::OK);
                } else {
                    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
                }
            }));
        }

        for t in tasks {
            t.await.unwrap();
        }
    }
}

#[cfg(feature = "axum")]
mod axum_adversarial_tests {
    use super::*;
    use axum::extract::FromRequestParts;
    use skyauth::integrations::axum::{client_metadata_response, redirect_to_authorization};

    #[tokio::test]
    async fn test_challenge_axum_extractor_missing_fields_and_error_params() {
        let uri = "/oauth/callback?some_other_param=123";
        let req = Request::builder()
            .uri(uri)
            .body(axum::body::Body::empty())
            .unwrap();
        let (mut parts, _) = req.into_parts();
        let query = OAuthCallbackQuery::from_request_parts(&mut parts, &())
            .await
            .unwrap();
        let err = query.to_callback_params().unwrap_err();
        assert!(matches!(err, IntegrationError::MissingCode));

        let uri = "/oauth/callback?code=abc12345";
        let req = Request::builder()
            .uri(uri)
            .body(axum::body::Body::empty())
            .unwrap();
        let (mut parts, _) = req.into_parts();
        let query = OAuthCallbackQuery::from_request_parts(&mut parts, &())
            .await
            .unwrap();
        let err = query.to_callback_params().unwrap_err();
        assert!(matches!(err, IntegrationError::MissingState));

        let uri =
            "/oauth/callback?error=server_error&error_description=Internal+Authentication+Failure";
        let req = Request::builder()
            .uri(uri)
            .body(axum::body::Body::empty())
            .unwrap();
        let (mut parts, _) = req.into_parts();
        let query = OAuthCallbackQuery::from_request_parts(&mut parts, &())
            .await
            .unwrap();
        let err = query.to_callback_params().unwrap_err();
        assert!(
            matches!(err, IntegrationError::OAuthError { error, description } if error == "server_error" && description == "Internal Authentication Failure")
        );
    }
}

proptest! {
    #[test]
    fn prop_shard_index_always_within_num_shards(s in "\\PC{0,100}") {
        let store = OAuthStateStore::default();
        let idx = store.shard_index(&s);
        prop_assert!(idx < 64);
    }

    #[test]
    fn prop_single_use_consumption_invariant(
        state_key in "[a-zA-Z0-9_-]{16,64}",
        ttl_secs in 10u64..3600u64
    ) {
        let store = OAuthStateStore::default();
        let entry = mock_stored_state(&state_key, ttl_secs);

        prop_assert!(!store.contains_state_sync(&state_key));
        store.insert_state_sync(state_key.clone(), entry.clone(), Duration::from_secs(ttl_secs)).unwrap();
        prop_assert!(store.contains_state_sync(&state_key));

        let first_take = store.take_state_sync(&state_key);
        prop_assert!(first_take.is_some());
        let record = first_take.unwrap();
        prop_assert_eq!(&record.state, &state_key);

        let second_take = store.take_state_sync(&state_key);
        prop_assert!(second_take.is_none());
        prop_assert!(!store.contains_state_sync(&state_key));
    }
}

#[cfg(feature = "actix")]
mod actix_adversarial_tests {
    use super::*;
    use actix_web::dev::Payload;
    use actix_web::test::TestRequest;
    use actix_web::FromRequest;

    #[tokio::test]
    async fn test_challenge_actix_extractor_missing_fields_and_error_params() {
        let uri = "/oauth/callback?other=test";
        let req = TestRequest::get().uri(uri).to_http_request();
        let mut payload = Payload::None;
        let query = OAuthCallbackQuery::from_request(&req, &mut payload)
            .await
            .unwrap();
        let err = query.to_callback_params().unwrap_err();
        assert!(matches!(err, IntegrationError::MissingCode));

        let uri = "/oauth/callback?code=actix_code_123";
        let req = TestRequest::get().uri(uri).to_http_request();
        let mut payload = Payload::None;
        let query = OAuthCallbackQuery::from_request(&req, &mut payload)
            .await
            .unwrap();
        let err = query.to_callback_params().unwrap_err();
        assert!(matches!(err, IntegrationError::MissingState));

        let uri =
            "/oauth/callback?error=invalid_scope&error_description=The+requested+scope+is+invalid";
        let req = TestRequest::get().uri(uri).to_http_request();
        let mut payload = Payload::None;
        let query = OAuthCallbackQuery::from_request(&req, &mut payload)
            .await
            .unwrap();
        let err = query.to_callback_params().unwrap_err();
        assert!(matches!(
            err,
            IntegrationError::OAuthError { error, description }
                if error == "invalid_scope" && description == "The requested scope is invalid"
        ));
    }

    #[tokio::test]
    async fn test_challenge_actix_user_extractor_missing_extension_rejects_unauthorized() {
        let req = TestRequest::get()
            .uri("/xrpc/app.bsky.actor.getProfile")
            .to_http_request();
        let mut payload = Payload::None;
        let res = AuthenticatedUser::from_request(&req, &mut payload).await;

        assert!(res.is_err());
        let http_err = res.unwrap_err();
        assert_eq!(
            http_err.error_response().status(),
            actix_web::http::StatusCode::UNAUTHORIZED
        );
    }
}

#[tokio::test]
async fn test_challenge_multiple_concurrent_pruners_and_rapid_cancel_cycles() {
    let store = Arc::new(OAuthStateStore::default());

    for cycle in 0..10 {
        let cancel_token = CancellationToken::new();
        let mut pruner_handles = Vec::new();

        for _ in 0..5 {
            pruner_handles
                .push(store.spawn_pruning_task(Duration::from_millis(1), cancel_token.clone()));
        }

        for i in 0..50 {
            let key = format!("cycle_{cycle}_item_{i}");
            let ttl = if i % 2 == 0 {
                Duration::ZERO
            } else {
                Duration::from_secs(60)
            };
            store
                .insert_state(key, mock_stored_state("item", 60), ttl)
                .await
                .unwrap();
        }

        tokio::time::sleep(Duration::from_millis(10)).await;

        cancel_token.cancel();
        for h in pruner_handles {
            let res = h.await;
            assert!(res.is_ok());
        }
    }

    let _ = store.prune_expired().await.unwrap();
    store.clear();
    assert_eq!(store.total_entries(), 0);
}

#[test]
fn test_challenge_extreme_key_sizes_and_special_character_encodings() {
    let store = OAuthStateStore::default();

    let empty_key = "";
    assert!(!store.contains_state_sync(empty_key));
    store
        .insert_state_sync(
            empty_key.to_string(),
            mock_stored_state("empty", 60),
            Duration::from_secs(60),
        )
        .unwrap();
    assert!(store.contains_state_sync(empty_key));
    let taken = store.take_state_sync(empty_key);
    assert!(taken.is_some());
    assert!(!store.contains_state_sync(empty_key));

    let large_key = "a".repeat(65536);
    store
        .insert_state_sync(
            large_key.clone(),
            mock_stored_state("large", 60),
            Duration::from_secs(60),
        )
        .unwrap();
    assert!(store.contains_state_sync(&large_key));
    let taken = store.take_state_sync(&large_key);
    assert!(taken.is_some());
    assert!(!store.contains_state_sync(&large_key));

    let unicode_key = "🔐_state_token_with_emoji_🚀_and_arabic_مرحبا_and_cjk_你好_123";
    store
        .insert_state_sync(
            unicode_key.to_string(),
            mock_stored_state(unicode_key, 60),
            Duration::from_secs(60),
        )
        .unwrap();
    assert!(store.contains_state_sync(unicode_key));
    let taken = store.take_state_sync(unicode_key);
    assert!(taken.is_some());
    assert_eq!(taken.unwrap().state, unicode_key);
    assert!(!store.contains_state_sync(unicode_key));
}
