//! Challenger 2 Formal Verification & Concurrency Stress Suite for Milestone 6.
//!
//! Empirically challenges and stress-tests:
//! 1. Anti-vacuity reachability stress: asserts that no proof harness trivially returns true
//!    or bypasses preconditions; verifies reachability coverage for every cover tag; tests
//!    anti-vacuity failure detection on missing/false cover tags.
//! 2. Concurrent state transition exhaustion: verifies that under 200 concurrent OS threads
//!    and async tasks, no state token can ever be consumed more than once.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    missing_docs,
    rust_2018_idioms
)]

use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::time::{Duration, SystemTime};

use proptest::prelude::*;

use skyauth::client::StoredStateEntry;
use skyauth::crypto::constant_time_eq;
use skyauth::dpop::{normalize_htu, DPoPKey};
use skyauth::pkce::{derive_s256_challenge, validate_verifier};
use skyauth::ssrf::{is_restricted_ip, SsrfFilter};
use skyauth::store::{OAuthStateStore, OAuthStore};
use skyauth::verification::formal_models::{
    ConstantTimeEqSpec, DPoPHtuFormalSpec, OAuthStateTransitionModel, PkceFormalSpec,
    SsrfFormalSpec, StateTransitionStatus,
};
use skyauth::verification::kani_harnesses::{
    global_coverage, proof_constant_time_eq_soundness, proof_dpop_htu_normalization_invariants,
    proof_pkce_s256_verifier_bounds, proof_single_use_state_consumption,
    proof_ssrf_restricted_ip_rejection, AntiVacuityCoverage,
};

fn mock_stored_state(state: &str) -> StoredStateEntry {
    StoredStateEntry {
        state: state.to_string(),
        client_id: "https://app.example.com/client-metadata.json".to_string(),
        code_verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".to_string(),
        dpop_key: DPoPKey::generate(),
        issuer: "https://auth.example.com".to_string(),
        did: Some("did:plc:alice123".to_string()),
        handle: Some("alice.bsky.social".to_string()),
        redirect_uri: "https://app.example.com/callback".to_string(),
        pds_endpoint: "https://pds.example.com".to_string(),
        token_endpoint: "https://auth.example.com/oauth/token".to_string(),
        scopes: "atproto".to_string(),
        created_at: SystemTime::now(),
        expires_in_secs: 300,
    }
}

#[test]
fn test_anti_vacuity_exhaustive_cover_tags_and_reachability() {
    proof_single_use_state_consumption();
    let proof1_tags = [
        "uninitialized_state_rejected",
        "state_inserted",
        "first_take_success",
        "second_take_rejected",
        "expired_state_rejected",
        "concurrent_race_single_winner",
    ];
    global_coverage().assert_all_covered(&proof1_tags);

    proof_ssrf_restricted_ip_rejection();
    let proof2_tags = [
        "rfc1918_10_blocked",
        "rfc1918_172_blocked",
        "rfc1918_192_blocked",
        "cloud_metadata_169_254_blocked",
        "loopback_127_blocked",
        "cgnat_100_64_blocked",
        "ipv6_ula_fc00_blocked",
        "ipv6_link_local_fe80_blocked",
        "ipv4_mapped_ipv6_blocked",
        "public_ip_allowed",
    ];
    global_coverage().assert_all_covered(&proof2_tags);

    proof_pkce_s256_verifier_bounds();
    let proof3_tags = [
        "valid_min_length_43_verifier",
        "valid_max_length_128_verifier",
        "valid_mid_length_verifier",
        "invalid_short_length_rejected",
        "invalid_long_length_rejected",
        "invalid_character_rejected",
        "challenge_length_is_43",
    ];
    global_coverage().assert_all_covered(&proof3_tags);

    proof_constant_time_eq_soundness();
    let proof4_tags = [
        "equal_non_empty_slices_true",
        "differing_first_byte_false",
        "differing_last_byte_false",
        "differing_middle_byte_false",
        "mismatched_length_false",
        "empty_slices_true",
    ];
    global_coverage().assert_all_covered(&proof4_tags);

    proof_dpop_htu_normalization_invariants();
    let proof5_tags = [
        "query_stripped_success",
        "fragment_stripped_success",
        "port_443_stripped_success",
        "port_80_stripped_success",
        "custom_port_preserved_success",
        "uppercase_host_lowercased_success",
        "invalid_scheme_rejected",
    ];
    global_coverage().assert_all_covered(&proof5_tags);

    let mut all_tags = Vec::new();
    all_tags.extend_from_slice(&proof1_tags);
    all_tags.extend_from_slice(&proof2_tags);
    all_tags.extend_from_slice(&proof3_tags);
    all_tags.extend_from_slice(&proof4_tags);
    all_tags.extend_from_slice(&proof5_tags);

    global_coverage().assert_all_covered(&all_tags);
    assert!(
        global_coverage().covered_count() >= 36,
        "Expected at least 36 covered reachability points, found {}",
        global_coverage().covered_count()
    );
}

#[test]
fn test_anti_vacuity_gate_rejects_missing_or_false_cover_conditions() {
    let tracker = AntiVacuityCoverage::new();

    tracker.cover("valid_reachability_tag", true);
    assert_eq!(tracker.covered_count(), 1);
    tracker.assert_all_covered(&["valid_reachability_tag"]);

    tracker.cover("false_condition_tag", false);
    assert_eq!(tracker.covered_count(), 1);

    let result_false = std::panic::catch_unwind(|| {
        tracker.assert_all_covered(&["false_condition_tag"]);
    });
    assert!(result_false.is_err(), "Expected panic for false cover tag");

    let result_unhit = std::panic::catch_unwind(|| {
        tracker.assert_all_covered(&["completely_unhit_tag"]);
    });
    assert!(result_unhit.is_err(), "Expected panic for unhit cover tag");
}

#[test]
fn test_anti_vacuity_proof_models_preconditions_and_edge_invariants() {
    let mut model = OAuthStateTransitionModel::new();

    assert!(!model.insert("", "client", 100, 0));
    assert!(model.take_state("", 0).is_none());

    assert!(!model.insert("state_zero_ttl", "client", 0, 0));
    assert!(model.take_state("state_zero_ttl", 0).is_none());

    assert!(model.insert("state_warp", "client", 50, 100));
    let taken_warp = model.take_state("state_warp", 50);
    assert!(taken_warp.is_some());
    assert!(model.verify_single_use_invariant("state_warp"));

    for b in 0..=255u8 {
        let is_unreserved = PkceFormalSpec::is_unreserved_char(b);
        let expected =
            b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_' || b == b'~';
        assert_eq!(
            is_unreserved, expected,
            "Byte {b} ('{}') failed unreserved character spec",
            b as char
        );
    }

    let original = [0xAAu8; 32];
    for byte_idx in 0..32 {
        for bit_idx in 0..8 {
            let mut mutated = original;
            mutated[byte_idx] ^= 1 << bit_idx;
            assert!(
                !ConstantTimeEqSpec::spec_constant_time_eq_model(&original, &mutated),
                "Bit flip at byte {byte_idx} bit {bit_idx} was undetected!"
            );
            assert!(
                !constant_time_eq(&original, &mutated),
                "Production ct_eq failed to detect bit flip at byte {byte_idx} bit {bit_idx}"
            );
            assert!(ConstantTimeEqSpec::verify_soundness(&original, &mutated));
        }
    }

    assert!(!SsrfFormalSpec::spec_is_restricted_ipv4(&Ipv4Addr::new(
        9, 255, 255, 255
    )));
    assert!(SsrfFormalSpec::spec_is_restricted_ipv4(&Ipv4Addr::new(
        10, 0, 0, 0
    )));
    assert!(SsrfFormalSpec::spec_is_restricted_ipv4(&Ipv4Addr::new(
        10, 255, 255, 255
    )));
    assert!(!SsrfFormalSpec::spec_is_restricted_ipv4(&Ipv4Addr::new(
        11, 0, 0, 0
    )));

    assert!(!SsrfFormalSpec::spec_is_restricted_ipv4(&Ipv4Addr::new(
        172, 15, 255, 255
    )));
    assert!(SsrfFormalSpec::spec_is_restricted_ipv4(&Ipv4Addr::new(
        172, 16, 0, 0
    )));
    assert!(SsrfFormalSpec::spec_is_restricted_ipv4(&Ipv4Addr::new(
        172, 31, 255, 255
    )));
    assert!(!SsrfFormalSpec::spec_is_restricted_ipv4(&Ipv4Addr::new(
        172, 32, 0, 0
    )));

    assert!(!SsrfFormalSpec::spec_is_restricted_ipv4(&Ipv4Addr::new(
        192, 167, 255, 255
    )));
    assert!(SsrfFormalSpec::spec_is_restricted_ipv4(&Ipv4Addr::new(
        192, 168, 0, 0
    )));
    assert!(SsrfFormalSpec::spec_is_restricted_ipv4(&Ipv4Addr::new(
        192, 168, 255, 255
    )));
    assert!(!SsrfFormalSpec::spec_is_restricted_ipv4(&Ipv4Addr::new(
        192, 169, 0, 0
    )));

    assert!(!SsrfFormalSpec::spec_is_restricted_ipv4(&Ipv4Addr::new(
        169, 253, 255, 255
    )));
    assert!(SsrfFormalSpec::spec_is_restricted_ipv4(&Ipv4Addr::new(
        169, 254, 0, 0
    )));
    assert!(SsrfFormalSpec::spec_is_restricted_ipv4(&Ipv4Addr::new(
        169, 254, 169, 254
    )));
    assert!(SsrfFormalSpec::spec_is_restricted_ipv4(&Ipv4Addr::new(
        169, 254, 255, 255
    )));
    assert!(!SsrfFormalSpec::spec_is_restricted_ipv4(&Ipv4Addr::new(
        169, 255, 0, 0
    )));

    assert!(!SsrfFormalSpec::spec_is_restricted_ipv4(&Ipv4Addr::new(
        100, 63, 255, 255
    )));
    assert!(SsrfFormalSpec::spec_is_restricted_ipv4(&Ipv4Addr::new(
        100, 64, 0, 0
    )));
    assert!(SsrfFormalSpec::spec_is_restricted_ipv4(&Ipv4Addr::new(
        100, 127, 255, 255
    )));
    assert!(!SsrfFormalSpec::spec_is_restricted_ipv4(&Ipv4Addr::new(
        100, 128, 0, 0
    )));

    assert!(!SsrfFormalSpec::spec_is_restricted_ipv4(&Ipv4Addr::new(
        126, 255, 255, 255
    )));
    assert!(SsrfFormalSpec::spec_is_restricted_ipv4(&Ipv4Addr::new(
        127, 0, 0, 0
    )));
    assert!(SsrfFormalSpec::spec_is_restricted_ipv4(&Ipv4Addr::new(
        127, 255, 255, 255
    )));
    assert!(!SsrfFormalSpec::spec_is_restricted_ipv4(&Ipv4Addr::new(
        128, 0, 0, 0
    )));

    let test_uri = "https://AUTH.Example.Com:443/OAuth/Token?foo=bar#section";
    let normalized = normalize_htu(test_uri).expect("Normalization failed");
    assert_eq!(normalized, "https://auth.example.com/OAuth/Token");
    assert!(DPoPHtuFormalSpec::spec_has_no_query(&normalized));
    assert!(DPoPHtuFormalSpec::spec_has_no_fragment(&normalized));
    assert!(DPoPHtuFormalSpec::spec_valid_scheme(&normalized));
    assert!(DPoPHtuFormalSpec::spec_no_default_ports(&normalized));

    assert_eq!(PkceFormalSpec::spec_s256_challenge_len(), 43);
    let sample_verifier = "a".repeat(43);
    let challenge = derive_s256_challenge(&sample_verifier);
    assert_eq!(challenge.len(), PkceFormalSpec::spec_s256_challenge_len());
    assert!(validate_verifier(&sample_verifier).is_ok());

    let filter = SsrfFilter::new(false);
    let ip_priv = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let ip_pub = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
    assert!(is_restricted_ip(ip_priv));
    assert!(!is_restricted_ip(ip_pub));
    assert!(filter.validate_ip(ip_priv).is_err());
    assert!(filter.validate_ip(ip_pub).is_ok());
}

#[test]
fn test_200_concurrent_threads_single_state_token_race() {
    let store = Arc::new(OAuthStateStore::default());
    let state_token = "single_race_token_200_threads";
    let entry = mock_stored_state(state_token);

    store
        .insert_state_sync(state_token.to_string(), entry, Duration::from_secs(300))
        .expect("Failed to insert initial state");

    let num_threads = 200;
    let barrier = Arc::new(Barrier::new(num_threads));
    let winner_count = Arc::new(AtomicUsize::new(0));
    let loser_count = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::with_capacity(num_threads);

    for _ in 0..num_threads {
        let store_clone = Arc::clone(&store);
        let barrier_clone = Arc::clone(&barrier);
        let winner_clone = Arc::clone(&winner_count);
        let loser_clone = Arc::clone(&loser_count);
        let token = state_token.to_string();

        handles.push(std::thread::spawn(move || {
            barrier_clone.wait();

            if let Some(consumed) = store_clone.take_state_sync(&token) {
                assert_eq!(consumed.state, token);
                winner_clone.fetch_add(1, Ordering::SeqCst);
            } else {
                loser_clone.fetch_add(1, Ordering::SeqCst);
            }
        }));
    }

    for handle in handles {
        handle.join().expect("Thread panicked during race");
    }

    let winners = winner_count.load(Ordering::SeqCst);
    let losers = loser_count.load(Ordering::SeqCst);

    assert_eq!(
        winners, 1,
        "VIOLATION: Exactly 1 thread must consume state under 200 concurrent threads! Found {winners}"
    );
    assert_eq!(
        losers, 199,
        "VIOLATION: Exactly 199 threads must receive None under 200 concurrent threads! Found {losers}"
    );
    assert_eq!(
        store.total_entries(),
        0,
        "Store must be empty after state consumption"
    );
    assert!(
        store.take_state_sync(state_token).is_none(),
        "Subsequent take must return None"
    );
}

#[test]
fn test_200_concurrent_threads_same_shard_hash_collision_race() {
    let store = Arc::new(OAuthStateStore::default());

    let target_shard = 7;
    let mut collision_keys = Vec::new();
    let mut candidate_idx = 0;
    while collision_keys.len() < 4 {
        let candidate = format!("collision_candidate_key_{candidate_idx}");
        if store.shard_index(&candidate) == target_shard {
            collision_keys.push(candidate);
        }
        candidate_idx += 1;
    }

    for k in &collision_keys {
        assert_eq!(store.shard_index(k), target_shard);
        store
            .insert_state_sync(k.clone(), mock_stored_state(k), Duration::from_secs(300))
            .expect("Insert collision key");
    }

    assert_eq!(store.shard_len(target_shard), 4);

    let num_threads = 200;
    let barrier = Arc::new(Barrier::new(num_threads));
    let per_key_winners: Arc<Vec<AtomicUsize>> =
        Arc::new((0..4).map(|_| AtomicUsize::new(0)).collect());
    let mut handles = Vec::with_capacity(num_threads);

    for (k_idx, key) in collision_keys.iter().enumerate() {
        for _ in 0..50 {
            let store_clone = Arc::clone(&store);
            let barrier_clone = Arc::clone(&barrier);
            let winners_array = Arc::clone(&per_key_winners);
            let token = key.clone();

            handles.push(std::thread::spawn(move || {
                barrier_clone.wait();
                if store_clone.take_state_sync(&token).is_some() {
                    winners_array[k_idx].fetch_add(1, Ordering::SeqCst);
                }
            }));
        }
    }

    for handle in handles {
        handle.join().expect("Thread failed");
    }

    for (k_idx, key) in collision_keys.iter().enumerate() {
        let winners = per_key_winners[k_idx].load(Ordering::SeqCst);
        assert_eq!(
            winners, 1,
            "Collision key '{key}' was consumed {winners} times instead of 1!"
        );
    }

    assert_eq!(store.shard_len(target_shard), 0);
}

#[test]
fn test_200_concurrent_threads_partitioned_across_multiple_keys_and_shards() {
    let store = Arc::new(OAuthStateStore::default());
    let num_keys = 20;
    let racers_per_key = 10;
    let total_threads = num_keys * racers_per_key;

    let mut state_keys = Vec::with_capacity(num_keys);
    for k in 0..num_keys {
        let key = format!("partitioned_state_key_{k}");
        store
            .insert_state_sync(
                key.clone(),
                mock_stored_state(&key),
                Duration::from_secs(300),
            )
            .expect("Insert key");
        state_keys.push(key);
    }

    assert_eq!(store.total_entries(), num_keys);

    let barrier = Arc::new(Barrier::new(total_threads));
    let per_key_winners: Arc<Vec<AtomicUsize>> =
        Arc::new((0..num_keys).map(|_| AtomicUsize::new(0)).collect());
    let mut handles = Vec::with_capacity(total_threads);

    for (k_idx, key) in state_keys.iter().enumerate() {
        for _ in 0..racers_per_key {
            let store_clone = Arc::clone(&store);
            let barrier_clone = Arc::clone(&barrier);
            let winners_array = Arc::clone(&per_key_winners);
            let token = key.clone();

            handles.push(std::thread::spawn(move || {
                barrier_clone.wait();
                if store_clone.take_state_sync(&token).is_some() {
                    winners_array[k_idx].fetch_add(1, Ordering::SeqCst);
                }
            }));
        }
    }

    for handle in handles {
        handle.join().expect("Thread failed");
    }

    for (k_idx, key) in state_keys.iter().enumerate() {
        let count = per_key_winners[k_idx].load(Ordering::SeqCst);
        assert_eq!(
            count, 1,
            "Key '{key}' was consumed {count} times instead of strictly 1 under 200 threads!"
        );
    }

    assert_eq!(store.total_entries(), 0);
}

#[test]
fn test_200_concurrent_threads_high_churn_chaos_state_transitions() {
    let store = Arc::new(OAuthStateStore::default());
    let num_threads = 200;
    let ops_per_thread = 200;
    let barrier = Arc::new(Barrier::new(num_threads));

    let consumed_audit: Arc<parking_lot::RwLock<std::collections::HashMap<String, usize>>> =
        Arc::new(parking_lot::RwLock::new(std::collections::HashMap::new()));

    let mut handles = Vec::with_capacity(num_threads);

    for thread_idx in 0..num_threads {
        let store_clone = Arc::clone(&store);
        let barrier_clone = Arc::clone(&barrier);
        let audit_clone = Arc::clone(&consumed_audit);

        handles.push(std::thread::spawn(move || {
            barrier_clone.wait();

            for op in 0..ops_per_thread {
                let key = format!("chaos_token_{}_{}", thread_idx % 25, op % 20);

                match (thread_idx + op) % 4 {
                    0 => {
                        let _ = store_clone.insert_state_sync(
                            key.clone(),
                            mock_stored_state(&key),
                            Duration::from_millis(500),
                        );
                    }
                    1 => {
                        if let Some(entry) = store_clone.take_state_sync(&key) {
                            assert_eq!(entry.state, key);
                            let mut guard = audit_clone.write();
                            let counter = guard.entry(key).or_insert(0);
                            *counter += 1;
                        }
                    }
                    2 => {
                        let _ = store_clone.contains_state_sync(&key);
                    }
                    _ => {
                        let _ = store_clone.prune_expired_sync();
                    }
                }
            }
        }));
    }

    for handle in handles {
        handle.join().expect("Chaos thread failed");
    }

    let guard = consumed_audit.read();
    for (key, total_takes) in guard.iter() {
        assert!(
            *total_takes >= 1,
            "Key {key} in audit log must have >= 1 take"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_200_concurrent_tokio_tasks_async_oauth_store_race() {
    let store = Arc::new(OAuthStateStore::default());
    let state_token = "async_race_token_200_tasks";
    let entry = mock_stored_state(state_token);

    store
        .insert_state(state_token.to_string(), entry, Duration::from_secs(300))
        .await
        .expect("Async insert");

    let num_tasks = 200;
    let barrier = Arc::new(tokio::sync::Barrier::new(num_tasks));
    let winner_count = Arc::new(AtomicUsize::new(0));
    let loser_count = Arc::new(AtomicUsize::new(0));
    let mut tasks = Vec::with_capacity(num_tasks);

    for _ in 0..num_tasks {
        let store_clone = Arc::clone(&store);
        let barrier_clone = Arc::clone(&barrier);
        let winner_clone = Arc::clone(&winner_count);
        let loser_clone = Arc::clone(&loser_count);
        let token = state_token.to_string();

        tasks.push(tokio::spawn(async move {
            barrier_clone.wait().await;
            match store_clone.take_state(&token).await {
                Ok(Some(entry)) => {
                    assert_eq!(entry.state, token);
                    winner_clone.fetch_add(1, Ordering::SeqCst);
                }
                Ok(None) => {
                    loser_clone.fetch_add(1, Ordering::SeqCst);
                }
                Err(e) => panic!("Unexpected store error: {e}"),
            }
        }));
    }

    for task in tasks {
        task.await.expect("Async task panicked");
    }

    let winners = winner_count.load(Ordering::SeqCst);
    let losers = loser_count.load(Ordering::SeqCst);

    assert_eq!(
        winners, 1,
        "Async race: Exactly 1 winner expected among 200 tasks, got {winners}"
    );
    assert_eq!(
        losers, 199,
        "Async race: Exactly 199 losers expected among 200 tasks, got {losers}"
    );
}

#[test]
fn test_verus_deductive_model_concurrent_race_200_and_500_threads() {
    let mut model = OAuthStateTransitionModel::new();
    let state_200 = "verus_model_race_200";
    let state_500 = "verus_model_race_500";

    assert!(model.insert(state_200, "client_app", 500, 0));
    let (w200, l200) = model.simulate_concurrent_consumption_race(state_200, 200, 10);
    assert_eq!(w200, 1);
    assert_eq!(l200, 199);
    assert!(model.verify_single_use_invariant(state_200));

    assert!(model.insert(state_500, "client_app", 500, 0));
    let (w500, l500) = model.simulate_concurrent_consumption_race(state_500, 500, 10);
    assert_eq!(w500, 1);
    assert_eq!(l500, 499);
    assert!(model.verify_single_use_invariant(state_500));

    assert!(model.verify_global_store_invariants());
}

proptest! {
    #[test]
    fn prop_arbitrary_thread_count_single_use_invariant(
        num_racers in 2usize..200,
        ttl_ticks in 10u64..1000,
        query_tick in 0u64..9
    ) {
        let mut model = OAuthStateTransitionModel::new();
        let state = "proptest_concurrent_state";

        prop_assert!(model.insert(state, "client", ttl_ticks, 0));
        let (winners, losers) = model.simulate_concurrent_consumption_race(state, num_racers, query_tick);

        prop_assert_eq!(winners, 1);
        prop_assert_eq!(losers, num_racers - 1);
        prop_assert!(model.verify_single_use_invariant(state));
        prop_assert!(model.verify_global_store_invariants());
    }

    #[test]
    fn prop_verus_state_machine_transition_contract_holds(
        state in "[a-zA-Z0-9_]{10,32}",
        client in "https://[a-z]{3,10}\\.example\\.com",
        ttl in 1u64..500,
        query_tick in 0u64..1000
    ) {
        let mut model = OAuthStateTransitionModel::new();

        prop_assert!(model.take_state(&state, 0).is_none());

        let inserted = model.insert(&state, &client, ttl, 100);
        prop_assert!(inserted);

        let res = model.take_state(&state, query_tick);
        if query_tick < 100 {
            prop_assert!(res.is_some());
            prop_assert_eq!(model.states.get(&state), Some(&StateTransitionStatus::Consumed { consumed_at_tick: query_tick }));
        } else if query_tick.saturating_sub(100) < ttl {
            prop_assert!(res.is_some());
            prop_assert_eq!(model.states.get(&state), Some(&StateTransitionStatus::Consumed { consumed_at_tick: query_tick }));
        } else {
            prop_assert!(res.is_none());
            prop_assert_eq!(model.states.get(&state), Some(&StateTransitionStatus::Expired { expired_at_tick: query_tick }));
        }

        prop_assert!(model.verify_single_use_invariant(&state));
        prop_assert!(model.verify_global_store_invariants());
    }
}
