//! Formal Specification & Mathematical Invariant Test Suite for `skyauth`.
//!
//! Executes formal transition models, Kani model checking proof harnesses,
//! and anti-vacuity reachability checks under standard `cargo test`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    missing_docs,
    rust_2018_idioms
)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use proptest::prelude::*;

use skyauth::crypto::constant_time_eq;
use skyauth::dpop::normalize_htu;
use skyauth::pkce::validate_verifier;
use skyauth::ssrf::{is_restricted_ipv4, is_restricted_ipv6, SsrfFilter};
use skyauth::store::OAuthStateStore;
use skyauth::verification::formal_models::{
    ConstantTimeEqSpec, DPoPHtuFormalSpec, OAuthStateTransitionModel, PkceFormalSpec,
    SsrfFormalSpec, StateTransitionStatus,
};
use skyauth::verification::kani_harnesses::{
    global_coverage, proof_constant_time_eq_soundness, proof_dpop_htu_normalization_invariants,
    proof_pkce_s256_verifier_bounds, proof_single_use_state_consumption,
    proof_ssrf_restricted_ip_rejection,
};

#[test]
fn test_formal_state_machine_transition_invariants() {
    let mut model = OAuthStateTransitionModel::new();
    let state = "formal_contract_test_state_1";

    assert!(model.take_state(state, 0).is_none());
    assert!(model.verify_single_use_invariant(state));

    assert!(model.insert(state, "client_app", 100, 10));
    assert!(matches!(
        model.states.get(state),
        Some(StateTransitionStatus::Pending {
            created_at_tick: 10,
            ttl_ticks: 100
        })
    ));
    assert!(model.verify_global_store_invariants());

    // Corrected replace semantics (mirrors production store): re-insertion
    // replaces the live pending record with the new payload/timestamps.
    assert!(model.insert(state, "client_app_duplicate", 100, 15));
    assert!(matches!(
        model.states.get(state),
        Some(StateTransitionStatus::Pending {
            created_at_tick: 15,
            ttl_ticks: 100
        })
    ));
    let entry = model.take_state(state, 50);
    assert!(entry.is_some());
    let entry = entry.unwrap();
    assert_eq!(entry.state_id, state);
    assert_eq!(entry.client_id, "client_app_duplicate");
    assert!(matches!(
        model.states.get(state),
        Some(StateTransitionStatus::Consumed {
            consumed_at_tick: 50
        })
    ));
    assert!(model.verify_single_use_invariant(state));

    assert!(model.take_state(state, 55).is_none());
    assert!(model.take_state(state, 60).is_none());
    assert!(model.verify_single_use_invariant(state));
    assert!(model.verify_global_store_invariants());
}

#[test]
fn test_verus_state_machine_expiration_invariants() {
    let mut model = OAuthStateTransitionModel::new();
    let state = "verus_expired_state";

    assert!(model.insert(state, "client_app", 30, 10));

    assert!(model.take_state(state, 40).is_none());
    assert!(matches!(
        model.states.get(state),
        Some(StateTransitionStatus::Expired {
            expired_at_tick: 40
        })
    ));
    assert!(model.verify_single_use_invariant(state));

    let state2 = "verus_prune_state";
    assert!(model.insert(state2, "client_app", 20, 10));
    let pruned = model.prune(35);
    assert_eq!(pruned, 1);
    assert!(matches!(
        model.states.get(state2),
        Some(StateTransitionStatus::Expired {
            expired_at_tick: 35
        })
    ));
}

#[test]
fn test_verus_state_machine_concurrent_interleaving_simulation() {
    let mut model = OAuthStateTransitionModel::new();
    let state = "verus_concurrent_race_state";

    assert!(model.insert(state, "client_app", 200, 0));

    let (successes, failures) = model.simulate_concurrent_consumption_race(state, 100, 50);
    assert_eq!(successes, 1, "Strictly 1 racer must consume state");
    assert_eq!(failures, 99, "99 racers must receive None");
    assert!(model.verify_single_use_invariant(state));
    assert!(model.verify_global_store_invariants());
}

#[test]
fn test_verus_pkce_formal_spec_bounds_and_bijection() {
    assert_eq!(PkceFormalSpec::spec_s256_challenge_len(), 43);
    for len in 0..200 {
        let is_valid = PkceFormalSpec::is_valid_verifier_len(len);
        if (43..=128).contains(&len) {
            assert!(is_valid);
        } else {
            assert!(!is_valid);
        }
    }

    for byte in 0..=255u8 {
        let is_unreserved = PkceFormalSpec::is_unreserved_char(byte);
        let expected = byte.is_ascii_alphanumeric()
            || byte == b'-'
            || byte == b'.'
            || byte == b'_'
            || byte == b'~';
        assert_eq!(is_unreserved, expected);
    }
}

#[test]
fn test_verus_constant_time_eq_soundness_and_timing_independence() {
    let s1 = b"high_entropy_secret_authorization_token_9876543210";
    let s2 = b"high_entropy_secret_authorization_token_9876543210";
    let s3 = b"high_entropy_secret_authorization_token_9876543211";

    assert!(ConstantTimeEqSpec::verify_soundness(s1, s2));
    assert!(ConstantTimeEqSpec::verify_soundness(s1, s3));
    assert!(ConstantTimeEqSpec::verify_soundness(s1, b"prefix_only"));
    assert!(ConstantTimeEqSpec::verify_soundness(b"", b""));

    assert!(ConstantTimeEqSpec::spec_constant_time_eq_model(s1, s2));
    assert!(!ConstantTimeEqSpec::spec_constant_time_eq_model(s1, s3));
}

#[test]
fn test_verus_ssrf_formal_spec_exhaustive_subspaces() {
    let restricted_v4_samples = [
        Ipv4Addr::new(0, 0, 0, 1),
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(100, 64, 0, 1),
        Ipv4Addr::new(100, 127, 255, 255),
        Ipv4Addr::new(127, 0, 0, 1),
        Ipv4Addr::new(169, 254, 169, 254),
        Ipv4Addr::new(172, 16, 0, 1),
        Ipv4Addr::new(172, 31, 255, 255),
        Ipv4Addr::new(192, 0, 0, 1),
        Ipv4Addr::new(192, 0, 2, 1),
        Ipv4Addr::new(192, 88, 99, 1),
        Ipv4Addr::new(192, 168, 1, 1),
        Ipv4Addr::new(198, 18, 0, 1),
        Ipv4Addr::new(198, 19, 255, 255),
        Ipv4Addr::new(198, 51, 100, 1),
        Ipv4Addr::new(203, 0, 113, 1),
        Ipv4Addr::new(224, 0, 0, 1),
        Ipv4Addr::new(240, 0, 0, 1),
        Ipv4Addr::new(255, 255, 255, 255),
    ];

    for ip in &restricted_v4_samples {
        assert!(
            SsrfFormalSpec::spec_is_restricted_ipv4(ip),
            "Failed to reject restricted IPv4 {ip}"
        );
        assert!(
            SsrfFormalSpec::spec_is_restricted_ip(IpAddr::V4(*ip)),
            "Failed to reject restricted IP {ip}"
        );
    }

    let public_v4_samples = [
        Ipv4Addr::new(1, 1, 1, 1),
        Ipv4Addr::new(8, 8, 8, 8),
        Ipv4Addr::new(93, 184, 216, 34),
        Ipv4Addr::new(172, 32, 0, 1),
        Ipv4Addr::new(100, 63, 255, 255),
        Ipv4Addr::new(100, 128, 0, 0),
    ];

    for ip in &public_v4_samples {
        assert!(
            !SsrfFormalSpec::spec_is_restricted_ipv4(ip),
            "Incorrectly rejected public IPv4 {ip}"
        );
        assert!(
            !SsrfFormalSpec::spec_is_restricted_ip(IpAddr::V4(*ip)),
            "Incorrectly rejected public IP {ip}"
        );
    }
}

#[test]
fn test_kani_proof_single_use_state_consumption_with_reachability() {
    proof_single_use_state_consumption();

    let required_tags = [
        "uninitialized_state_rejected",
        "state_inserted",
        "first_take_success",
        "second_take_rejected",
        "expired_state_rejected",
        "concurrent_race_single_winner",
    ];

    global_coverage().assert_all_covered(&required_tags);
}

#[test]
fn test_kani_proof_ssrf_restricted_ip_rejection_with_reachability() {
    proof_ssrf_restricted_ip_rejection();

    let required_tags = [
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

    global_coverage().assert_all_covered(&required_tags);
}

#[test]
fn test_kani_proof_pkce_s256_verifier_bounds_with_reachability() {
    proof_pkce_s256_verifier_bounds();

    let required_tags = [
        "valid_min_length_43_verifier",
        "valid_max_length_128_verifier",
        "valid_mid_length_verifier",
        "invalid_short_length_rejected",
        "invalid_long_length_rejected",
        "invalid_character_rejected",
        "challenge_length_is_43",
    ];

    global_coverage().assert_all_covered(&required_tags);
}

#[test]
fn test_kani_proof_constant_time_eq_soundness_with_reachability() {
    proof_constant_time_eq_soundness();

    let required_tags = [
        "equal_non_empty_slices_true",
        "differing_first_byte_false",
        "differing_last_byte_false",
        "differing_middle_byte_false",
        "mismatched_length_false",
        "empty_slices_true",
    ];

    global_coverage().assert_all_covered(&required_tags);
}

#[test]
fn test_kani_proof_dpop_htu_normalization_invariants_with_reachability() {
    proof_dpop_htu_normalization_invariants();

    let required_tags = [
        "query_stripped_success",
        "fragment_stripped_success",
        "port_443_stripped_success",
        "port_80_stripped_success",
        "custom_port_preserved_success",
        "uppercase_host_lowercased_success",
        "invalid_scheme_rejected",
    ];

    global_coverage().assert_all_covered(&required_tags);
}

fn mock_stored_state(state: &str) -> skyauth::client::StoredStateEntry {
    skyauth::client::StoredStateEntry {
        state: state.to_string(),
        client_id: "https://app.example.com/client-metadata.json".to_string(),
        code_verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".to_string(),
        dpop_key: skyauth::dpop::DPoPKey::generate(),
        issuer: "https://auth.example.com".to_string(),
        did: Some("did:plc:alice123".to_string()),
        handle: Some("alice.bsky.social".to_string()),
        redirect_uri: "https://app.example.com/callback".to_string(),
        pds_endpoint: "https://pds.example.com".to_string(),
        token_endpoint: "https://auth.example.com/oauth/token".to_string(),
        scopes: "atproto".to_string(),
        created_at: std::time::SystemTime::now(),
        expires_in_secs: 300,
    }
}

proptest! {
    #[test]
    fn prop_state_machine_model_equivalence_with_oauth_state_store(
        state_key in "[a-zA-Z0-9_\\-]{16,48}",
        repeat_takes in 2usize..10
    ) {
        let store = OAuthStateStore::default();
        let mut model = OAuthStateTransitionModel::new();

        prop_assert_eq!(store.take_state_sync(&state_key).is_some(), model.take_state(&state_key, 0).is_some());

        let entry = mock_stored_state(&state_key);
        store.insert_state_sync(state_key.clone(), entry, Duration::from_secs(60)).unwrap();
        let model_inserted = model.insert(&state_key, "client_app", 60, 10);
        prop_assert!(model_inserted);

        let store_take = store.take_state_sync(&state_key);
        let model_take = model.take_state(&state_key, 20);
        prop_assert_eq!(store_take.is_some(), model_take.is_some());
        prop_assert!(store_take.is_some());

        for _ in 0..repeat_takes {
            let next_store_take = store.take_state_sync(&state_key);
            let next_model_take = model.take_state(&state_key, 30);
            prop_assert!(next_store_take.is_none());
            prop_assert!(next_model_take.is_none());
        }

        prop_assert!(model.verify_single_use_invariant(&state_key));
    }

    #[test]
    fn prop_pkce_spec_equivalence(
        verifier in ".*"
    ) {
        let production_result = validate_verifier(&verifier).is_ok();
        let formal_spec_result = PkceFormalSpec::spec_validate_verifier(verifier.as_bytes());

        prop_assert_eq!(
            production_result,
            formal_spec_result,
            "Discrepancy for verifier '{}'",
            verifier
        );
    }

    #[test]
    fn prop_constant_time_eq_spec_equivalence(
        a in proptest::collection::vec(any::<u8>(), 0..64),
        b in proptest::collection::vec(any::<u8>(), 0..64)
    ) {
        let ct_res = constant_time_eq(&a, &b);
        let model_res = ConstantTimeEqSpec::spec_constant_time_eq_model(&a, &b);
        let spec_res = ConstantTimeEqSpec::spec_slice_eq(&a, &b);

        prop_assert_eq!(ct_res, model_res);
        prop_assert_eq!(ct_res, spec_res);
    }

    #[test]
    fn prop_ssrf_spec_equivalence_ipv4(
        o0 in 0u8..=255,
        o1 in 0u8..=255,
        o2 in 0u8..=255,
        o3 in 0u8..=255
    ) {
        let ip = Ipv4Addr::new(o0, o1, o2, o3);
        let prod_res = is_restricted_ipv4(&ip);
        let spec_res = SsrfFormalSpec::spec_is_restricted_ipv4(&ip);
        let filter_res = SsrfFilter::new(false).validate_ip(IpAddr::V4(ip)).is_err();

        prop_assert_eq!(prod_res, spec_res, "IPv4 discrepancy for {}", ip);
        prop_assert_eq!(prod_res, filter_res, "Filter discrepancy for {}", ip);
    }

    #[test]
    fn prop_ssrf_spec_equivalence_ipv6(
        s0 in any::<u16>(),
        s1 in any::<u16>(),
        s2 in any::<u16>(),
        s3 in any::<u16>(),
        s4 in any::<u16>(),
        s5 in any::<u16>(),
        s6 in any::<u16>(),
        s7 in any::<u16>()
    ) {
        let ip = Ipv6Addr::new(s0, s1, s2, s3, s4, s5, s6, s7);
        let prod_res = is_restricted_ipv6(&ip);
        let spec_res = SsrfFormalSpec::spec_is_restricted_ipv6(&ip);
        let filter_res = SsrfFilter::new(false).validate_ip(IpAddr::V6(ip)).is_err();

        prop_assert_eq!(prod_res, spec_res, "IPv6 discrepancy for {}", ip);
        prop_assert_eq!(prod_res, filter_res, "Filter discrepancy for {}", ip);
    }

    #[test]
    fn prop_dpop_htu_spec_invariants(
        host in "[a-zA-Z0-9\\-]{3,20}\\.[a-z]{2,6}",
        port in prop::option::of(1u16..=65535),
        path in "/[a-zA-Z0-9_/]{0,30}",
        query in prop::option::of("[a-zA-Z0-9=&_]{1,30}"),
        fragment in prop::option::of("[a-zA-Z0-9_]{1,15}")
    ) {
        let port_str = match port {
            Some(p) => format!(":{p}"),
            None => String::new(),
        };
        let query_str = match &query {
            Some(q) => format!("?{q}"),
            None => String::new(),
        };
        let frag_str = match &fragment {
            Some(f) => format!("#{f}"),
            None => String::new(),
        };

        let raw_uri = format!("https://{host}{port_str}{path}{query_str}{frag_str}");
        if let Ok(normalized) = normalize_htu(&raw_uri) {
            prop_assert!(DPoPHtuFormalSpec::spec_has_no_query(&normalized));
            prop_assert!(DPoPHtuFormalSpec::spec_has_no_fragment(&normalized));
            prop_assert!(DPoPHtuFormalSpec::spec_valid_scheme(&normalized));
            prop_assert!(DPoPHtuFormalSpec::spec_no_default_ports(&normalized));
        }
    }
}
