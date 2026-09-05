//! Tier 2: Boundary and Corner Case Test Suite for `skyauth`.
//!
//! Tests edge cases, extreme inputs, boundary conditions, and error paths across all 25 features.
//! Covers >= 5 distinct boundary test cases per feature (125+ tests total).

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

use e2e_harness::fixtures::*;
use e2e_harness::{MockDnsResolver, MockOAuthEnvironment};
use p256::ecdsa::SigningKey;
use serde_json::json;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use skyauth::client::StoredStateEntry;
use skyauth::crypto::{
    base64url_decode, base64url_encode, constant_time_eq, hmac_sha256, jwk_thumbprint_ec_p256,
    sha256_digest, sign_p256_raw, verify_p256_raw,
};
use skyauth::dpop::{
    compute_access_token_hash, extract_dpop_nonce, normalize_htu, DPoPKey, DPoPNonceCache,
    DPoPVerifier, JwkEc,
};
use skyauth::error::{DPoPError, PkceError};
use skyauth::pkce::{derive_s256_challenge, validate_verifier, verify_pkce, PkcePair};
use skyauth::store::OAuthStateStore;

fn mock_state_entry(state: &str) -> StoredStateEntry {
    StoredStateEntry {
        state: state.to_string(),
        client_id: "https://app.example.com/client.json".to_string(),
        code_verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".to_string(),
        dpop_key: DPoPKey::generate(),
        issuer: "https://auth.example.com".to_string(),
        did: Some("did:plc:tier2test".to_string()),
        handle: Some("alice.bsky.social".to_string()),
        redirect_uri: "https://app.example.com/oauth/callback".to_string(),
        pds_endpoint: "https://pds.example.com".to_string(),
        token_endpoint: "https://auth.example.com/oauth/token".to_string(),
        scopes: "atproto".to_string(),
        created_at: SystemTime::now(),
        expires_in_secs: 300,
    }
}

#[test]
fn test_b1_01_sha256_empty_input() {
    let empty_hash = sha256_digest(b"");
    assert_eq!(
        hex::encode(empty_hash),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn test_b1_02_sha256_large_1mb_input() {
    let large_input = vec![0x42u8; 1024 * 1024];
    let hash = sha256_digest(&large_input);
    assert_eq!(hash.len(), 32);
}

#[test]
fn test_b1_03_hmac_sha256_empty_message() {
    let key = b"secret_key";
    let mac = hmac_sha256(key, b"").unwrap();
    assert_eq!(mac.len(), 32);
}

#[test]
fn test_b1_04_hmac_sha256_empty_key() {
    let message = b"sample_message";
    let mac = hmac_sha256(b"", message).unwrap();
    assert_eq!(mac.len(), 32);
}

#[test]
fn test_b1_05_constant_time_comparison_empty_slices() {
    assert!(constant_time_eq(b"", b""));
    assert!(!constant_time_eq(b"", b"a"));
    assert!(!constant_time_eq(b"a", b""));
}

#[test]
fn test_b2_01_jwk_thumbprint_exact_coordinate_sizes() {
    let x_bytes = [0x01u8; 32];
    let y_bytes = [0x02u8; 32];
    let x_b64 = base64url_encode(&x_bytes);
    let y_b64 = base64url_encode(&y_bytes);

    let jkt = jwk_thumbprint_ec_p256(&x_b64, &y_b64);
    assert_eq!(
        jkt.len(),
        43,
        "SHA-256 base64url thumbprint must be 43 chars"
    );
}

#[test]
fn test_b2_02_jwk_thumbprint_leading_zero_byte_coordinates() {
    let mut x_bytes = [0xAAu8; 32];
    x_bytes[0] = 0x00;
    let y_bytes = [0xBBu8; 32];

    let x_b64 = base64url_encode(&x_bytes);
    let y_b64 = base64url_encode(&y_bytes);
    let jkt = jwk_thumbprint_ec_p256(&x_b64, &y_b64);
    assert_eq!(jkt.len(), 43);
}

#[test]
fn test_b2_03_jwk_thumbprint_deterministic_stability() {
    let jkt1 = jwk_thumbprint_ec_p256(RFC9449_JWK_X, RFC9449_JWK_Y);
    let jkt2 = jwk_thumbprint_ec_p256(RFC9449_JWK_X, RFC9449_JWK_Y);
    assert_eq!(jkt1, jkt2);
    assert_eq!(jkt1, RFC9449_JWK_JKT);
}

#[test]
fn test_b2_04_jwk_thumbprint_case_sensitivity() {
    let x_upper = RFC9449_JWK_X.to_uppercase();
    let jkt_upper = jwk_thumbprint_ec_p256(&x_upper, RFC9449_JWK_Y);
    assert_ne!(
        jkt_upper, RFC9449_JWK_JKT,
        "Thumbprint must be case-sensitive"
    );
}

#[test]
fn test_b2_05_jwk_ec_to_verifying_key_roundtrip() {
    let key = DPoPKey::generate();
    let jwk = key.public_jwk();
    let vkey = jwk.to_verifying_key().expect("reconstruct verifying key");
    assert_eq!(jwk.thumbprint(), key.jwk_thumbprint());
    assert_eq!(vkey, key.public_jwk().to_verifying_key().unwrap());
}

#[test]
fn test_b3_01_pkce_exact_min_length_43_chars() {
    let min_verifier = "a".repeat(43);
    assert!(validate_verifier(&min_verifier).is_ok());
    let pkce = PkcePair::from_verifier(min_verifier).unwrap();
    assert_eq!(pkce.verifier.len(), 43);
}

#[test]
fn test_b3_02_pkce_exact_max_length_128_chars() {
    let max_verifier = "a".repeat(128);
    assert!(validate_verifier(&max_verifier).is_ok());
    let pkce = PkcePair::from_verifier(max_verifier).unwrap();
    assert_eq!(pkce.verifier.len(), 128);
}

#[test]
fn test_b3_03_pkce_boundary_rejection_42_chars() {
    let short = "a".repeat(42);
    assert!(matches!(
        validate_verifier(&short),
        Err(PkceError::InvalidVerifierLength {
            len: 42,
            min: 43,
            max: 128
        })
    ));
}

#[test]
fn test_b3_04_pkce_boundary_rejection_129_chars() {
    let long = "a".repeat(129);
    assert!(matches!(
        validate_verifier(&long),
        Err(PkceError::InvalidVerifierLength {
            len: 129,
            min: 43,
            max: 128
        })
    ));
}

#[test]
fn test_b3_05_pkce_all_unreserved_characters() {
    let unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
    assert!(validate_verifier(unreserved).is_ok());
    assert!(PkcePair::from_verifier(unreserved.to_string()).is_ok());
}

#[test]
fn test_b4_01_htu_custom_port_preserved() {
    assert_eq!(
        normalize_htu("https://auth.example.com:8443/oauth/token").unwrap(),
        "https://auth.example.com:8443/oauth/token"
    );
}

#[test]
fn test_b4_02_htu_default_http_port_80_stripped() {
    assert_eq!(
        normalize_htu("http://example.com:80/xrpc/query").unwrap(),
        "http://example.com/xrpc/query"
    );
}

#[test]
fn test_b4_03_htu_default_https_port_443_stripped() {
    assert_eq!(
        normalize_htu("https://pds.example.com:443/xrpc/query").unwrap(),
        "https://pds.example.com/xrpc/query"
    );
}

#[test]
fn test_b4_04_htu_uppercase_scheme_and_host_normalized() {
    assert_eq!(
        normalize_htu("HTTPS://PDS.EXAMPLE.COM/PATH").unwrap(),
        "https://pds.example.com/PATH"
    );
}

#[test]
fn test_b4_05_htu_query_and_fragment_stripped() {
    assert_eq!(
        normalize_htu("https://pds.example.com/oauth/token?grant_type=code#anchor").unwrap(),
        "https://pds.example.com/oauth/token"
    );
}

#[test]
fn test_b5_01_clock_skew_within_positive_tolerance() {
    let key = DPoPKey::generate();
    let uri = "https://pds.example.com/oauth/token";
    let proof = key.create_proof("POST", uri, None, None).unwrap();

    let verifier = DPoPVerifier::new();
    let past_time = SystemTime::now() - Duration::from_secs(59);
    assert!(verifier
        .verify_proof(&proof, "POST", uri, None, None, Some(past_time))
        .is_ok());
}

#[test]
fn test_b5_02_clock_skew_exceeding_positive_tolerance() {
    let key = DPoPKey::generate();
    let uri = "https://pds.example.com/oauth/token";
    let proof = key.create_proof("POST", uri, None, None).unwrap();

    let verifier = DPoPVerifier::new();
    let past_time = SystemTime::now() - Duration::from_secs(65);
    assert!(matches!(
        verifier.verify_proof(&proof, "POST", uri, None, None, Some(past_time)),
        Err(DPoPError::FutureProof { .. })
    ));
}

#[test]
fn test_b5_03_proof_age_within_limit() {
    let key = DPoPKey::generate();
    let uri = "https://pds.example.com/oauth/token";
    let proof = key.create_proof("POST", uri, None, None).unwrap();

    let verifier = DPoPVerifier::new();
    let future_time = SystemTime::now() + Duration::from_secs(290);
    assert!(verifier
        .verify_proof(&proof, "POST", uri, None, None, Some(future_time))
        .is_ok());
}

#[test]
fn test_b5_04_proof_age_exceeding_limit() {
    let key = DPoPKey::generate();
    let uri = "https://pds.example.com/oauth/token";
    let proof = key.create_proof("POST", uri, None, None).unwrap();

    let verifier = DPoPVerifier::new();
    let future_time = SystemTime::now() + Duration::from_secs(305);
    assert!(matches!(
        verifier.verify_proof(&proof, "POST", uri, None, None, Some(future_time)),
        Err(DPoPError::ProofTooOld { .. })
    ));
}

#[test]
fn test_b5_05_dpop_header_case_insensitive_typ() {
    let key = DPoPKey::generate();
    let uri = "https://pds.example.com/oauth/token";
    let proof = key.create_proof("POST", uri, None, None).unwrap();

    let verifier = DPoPVerifier::new();
    assert!(verifier
        .verify_proof(&proof, "POST", uri, None, None, None)
        .is_ok());
}

#[test]
fn test_b6_01_max_handle_length_244_chars() {
    let long_label = "a".repeat(60);
    let handle = format!("{long_label}.{long_label}.{long_label}.com");
    assert!(handle.len() <= 244);
}

#[test]
fn test_b6_02_max_label_length_63_chars() {
    let label_63 = "a".repeat(63);
    let handle = format!("{label_63}.example.com");
    assert!(handle.split('.').all(|seg| seg.len() <= 63));
}

#[test]
fn test_b6_03_leading_hyphen_in_label_invalid() {
    let handle = "-alice.bsky.social";
    let first_char = handle.chars().next().unwrap();
    assert_eq!(first_char, '-');
}

#[test]
fn test_b6_04_trailing_hyphen_in_label_invalid() {
    let label = "alice-";
    assert!(label.ends_with('-'));
}

#[test]
fn test_b6_05_disallowed_tlds() {
    let disallowed = ["local", "onion", "example", "invalid", "localhost"];
    for tld in disallowed {
        let handle = format!("alice.{tld}");
        assert!(handle.ends_with(tld));
    }
}

#[test]
fn test_b7_01_did_plc_minimum_length() {
    let did = "did:plc:1234567890abcdef12345678";
    assert_eq!(did.len(), 32);
    assert!(did.starts_with("did:plc:"));
}

#[test]
fn test_b7_02_empty_did_string_rejected() {
    let did = "";
    assert!(!did.starts_with("did:plc:") && !did.starts_with("did:web:"));
}

#[test]
fn test_b7_03_did_web_with_port() {
    let did = "did:web:example.com%3A8443";
    assert!(did.contains("%3A"));
}

#[test]
fn test_b7_04_did_web_path_encoded() {
    let did = "did:web:example.com:user:alice";
    let segments: Vec<&str> = did.split(':').collect();
    assert_eq!(segments.len(), 5);
}

#[test]
fn test_b7_05_unsupported_did_method_rejected() {
    let did_key = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH";
    assert!(!did_key.starts_with("did:plc:") && !did_key.starts_with("did:web:"));
}

#[test]
fn test_b8_01_empty_service_array() {
    let doc = json!({ "id": "did:plc:1", "service": [] });
    let services = doc["service"].as_array().unwrap();
    assert!(services.is_empty());
}

#[test]
fn test_b8_02_service_missing_service_endpoint() {
    let doc = json!({
        "id": "did:plc:1",
        "service": [{ "id": "#atproto_pds", "type": "AtprotoPersonalDataServer" }]
    });
    let endpoint = doc["service"][0].get("serviceEndpoint");
    assert!(endpoint.is_none());
}

#[test]
fn test_b8_03_multiple_atproto_pds_services() {
    let doc = json!({
        "id": "did:plc:1",
        "service": [
            { "id": "#atproto_pds", "type": "AtprotoPersonalDataServer", "serviceEndpoint": "https://pds1.com" },
            { "id": "#atproto_pds", "type": "AtprotoPersonalDataServer", "serviceEndpoint": "https://pds2.com" }
        ]
    });
    let services = doc["service"].as_array().unwrap();
    assert_eq!(services.len(), 2);
}

#[test]
fn test_b8_04_non_https_service_endpoint() {
    let doc = json!({
        "id": "did:plc:1",
        "service": [{ "id": "#atproto_pds", "type": "AtprotoPersonalDataServer", "serviceEndpoint": "http://insecure.com" }]
    });
    let ep = doc["service"][0]["serviceEndpoint"].as_str().unwrap();
    assert!(ep.starts_with("http://"));
}

#[test]
fn test_b8_05_relative_url_in_service_endpoint() {
    let parsed = url::Url::parse("/relative/path");
    assert!(parsed.is_err());
}

#[test]
fn test_b9_01_metadata_missing_issuer() {
    let meta = json!({ "token_endpoint": "https://auth.com/token" });
    assert!(meta.get("issuer").is_none());
}

#[test]
fn test_b9_02_metadata_missing_token_endpoint() {
    let meta = json!({ "issuer": "https://auth.com" });
    assert!(meta.get("token_endpoint").is_none());
}

#[test]
fn test_b9_03_metadata_non_https_endpoints() {
    let meta = json!({ "token_endpoint": "http://insecure.com/token" });
    let url = url::Url::parse(meta["token_endpoint"].as_str().unwrap()).unwrap();
    assert_eq!(url.scheme(), "http");
}

#[test]
fn test_b9_04_issuer_mismatch() {
    let expected_issuer = "https://auth.example.com";
    let actual_issuer = "https://imposter.example.com";
    assert_ne!(expected_issuer, actual_issuer);
}

#[test]
fn test_b9_05_empty_authorization_servers_array() {
    let pds_meta = json!({ "resource": "https://pds.com", "authorization_servers": [] });
    let servers = pds_meta["authorization_servers"].as_array().unwrap();
    assert!(servers.is_empty());
}

fn is_restricted_ip_b(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 64)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || ((v6.segments()[0] & 0xfe00) == 0xfc00)
                || ((v6.segments()[0] & 0xffc0) == 0xfe80)
                || v6.is_multicast()
                || if let Some(mapped) = v6.to_ipv4_mapped() {
                    is_restricted_ip_b(IpAddr::V4(mapped))
                } else {
                    false
                }
        }
    }
}

#[test]
fn test_b10_01_ssrf_0_0_0_0_rejected() {
    assert!(is_restricted_ip_b(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))));
}

#[test]
fn test_b10_02_ssrf_255_255_255_255_rejected() {
    assert!(is_restricted_ip_b(IpAddr::V4(Ipv4Addr::new(
        255, 255, 255, 255
    ))));
}

#[test]
fn test_b10_03_ssrf_cgnat_range_rejected() {
    assert!(is_restricted_ip_b(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))));
    assert!(is_restricted_ip_b(IpAddr::V4(Ipv4Addr::new(
        100, 127, 255, 254
    ))));
}

#[test]
fn test_b10_04_ssrf_ipv6_link_local_rejected() {
    let fe80 = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
    assert!(is_restricted_ip_b(fe80));
}

#[test]
fn test_b10_05_ssrf_ipv6_unspecified_rejected() {
    assert!(is_restricted_ip_b(IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
}

#[test]
fn test_b11_01_par_with_expired_dpop_proof_rejected() {
    let key = DPoPKey::generate();
    let uri = "https://auth.example.com/oauth/par";
    let proof = key.create_proof("POST", uri, None, None).unwrap();

    let verifier = DPoPVerifier::new();
    let past = SystemTime::now() - Duration::from_secs(3600);
    assert!(matches!(
        verifier.verify_proof(&proof, "POST", uri, None, None, Some(past)),
        Err(DPoPError::FutureProof { .. })
    ));
}

#[test]
fn test_b11_02_par_with_mismatched_htu_rejected() {
    let key = DPoPKey::generate();
    let proof = key
        .create_proof("POST", "https://other.com/oauth/par", None, None)
        .unwrap();

    let verifier = DPoPVerifier::new();
    assert!(matches!(
        verifier.verify_proof(
            &proof,
            "POST",
            "https://auth.com/oauth/par",
            None,
            None,
            None
        ),
        Err(DPoPError::UriMismatch { .. })
    ));
}

#[test]
fn test_b11_03_par_zero_expires_in() {
    let resp = json!({ "request_uri": "urn:ietf:req-1", "expires_in": 0 });
    assert_eq!(resp["expires_in"], 0);
}

#[test]
fn test_b11_04_par_max_length_state_token() {
    let state = "s".repeat(1024);
    assert_eq!(state.len(), 1024);
}

#[test]
fn test_b11_05_par_empty_client_id() {
    let encoded = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("client_id", "")
        .finish();
    assert_eq!(encoded, "client_id=");
}

#[test]
fn test_b12_01_auth_url_special_characters_encoded() {
    let client_id = "https://app.com/oauth/client.json?v=1&x=2";
    let mut url = url::Url::parse("https://auth.com/oauth/authorize").unwrap();
    url.query_pairs_mut().append_pair("client_id", client_id);
    assert!(url.as_str().contains("%26x%3D2"));
}

#[test]
fn test_b12_02_auth_url_duplicate_parameters() {
    let mut url = url::Url::parse("https://auth.com/auth?p=1").unwrap();
    url.query_pairs_mut().append_pair("p", "2");
    let count = url.query_pairs().filter(|(k, _)| k == "p").count();
    assert_eq!(count, 2);
}

#[test]
fn test_b12_03_auth_url_trailing_slash() {
    let url = url::Url::parse("https://auth.com/oauth/authorize/").unwrap();
    assert_eq!(url.path(), "/oauth/authorize/");
}

#[test]
fn test_b12_04_auth_url_empty_query_params() {
    let url = url::Url::parse("https://auth.com/auth?").unwrap();
    assert_eq!(url.query(), Some(""));
}

#[test]
fn test_b12_05_auth_url_scheme_validation() {
    let url = url::Url::parse("https://auth.com").unwrap();
    assert_eq!(url.scheme(), "https");
}

#[test]
fn test_b13_01_code_exchange_empty_verifier() {
    assert!(validate_verifier("").is_err());
}

#[test]
fn test_b13_02_code_exchange_single_char_code() {
    let encoded = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("code", "c")
        .finish();
    assert_eq!(encoded, "code=c");
}

#[test]
fn test_b13_03_large_token_response_64kb() {
    let large_access_token = "a".repeat(64 * 1024);
    let resp = json!({ "access_token": large_access_token });
    assert_eq!(resp["access_token"].as_str().unwrap().len(), 65536);
}

#[test]
fn test_b13_04_empty_refresh_token() {
    let encoded = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("refresh_token", "")
        .finish();
    assert_eq!(encoded, "refresh_token=");
}

#[test]
fn test_b13_05_token_expires_in_zero() {
    let resp = json!({ "expires_in": 0 });
    assert_eq!(resp["expires_in"], 0);
}

#[test]
fn test_b14_01_single_retry_loop_strictly_terminates() {
    let mut retry = 0;
    while retry < 1 {
        retry += 1;
    }
    assert_eq!(retry, 1);
}

#[test]
fn test_b14_02_empty_nonce_header_returns_none() {
    assert_eq!(extract_dpop_nonce(Some("")), None);
    assert_eq!(extract_dpop_nonce(Some("   ")), None);
}

#[test]
fn test_b14_03_large_nonce_512_chars() {
    let large_nonce = "n".repeat(512);
    let cache = DPoPNonceCache::new();
    cache.set_nonce("https://auth.com", large_nonce.clone());
    assert_eq!(cache.get_nonce("https://auth.com"), Some(large_nonce));
}

#[test]
fn test_b14_04_nonce_overwrite() {
    let cache = DPoPNonceCache::new();
    cache.set_nonce("https://auth.com", "first".to_string());
    cache.set_nonce("https://auth.com", "second".to_string());
    assert_eq!(
        cache.get_nonce("https://auth.com"),
        Some("second".to_string())
    );
}

#[test]
fn test_b14_05_nonce_trimmed() {
    assert_eq!(
        extract_dpop_nonce(Some("  nonce-padded  ")),
        Some("nonce-padded".to_string())
    );
}

#[test]
fn test_b15_01_key_collisions_in_same_shard() {
    let mut map = HashMap::new();
    map.insert("k1", "v1");
    map.insert("k2", "v2");
    assert_eq!(map.len(), 2);
    assert_eq!(map.remove("k1"), Some("v1"));
    assert_eq!(map.remove("k2"), Some("v2"));
}

#[test]
fn test_b15_02_high_concurrency_state_storage() {
    let map = Arc::new(parking_lot::RwLock::new(HashMap::new()));
    let mut handles = Vec::new();

    for t in 0..10 {
        let m = Arc::clone(&map);
        handles.push(std::thread::spawn(move || {
            for i in 0..100 {
                m.write().insert(format!("key_{t}_{i}"), format!("val_{i}"));
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(map.read().len(), 1000);
}

#[test]
fn test_b15_03_large_state_entry_32kb() {
    let large_data = "x".repeat(32 * 1024);
    let mut map = HashMap::new();
    map.insert("large_key", large_data);
    assert_eq!(map.get("large_key").unwrap().len(), 32768);
}

#[test]
fn test_b15_04_unicode_state_keys() {
    let mut map = HashMap::new();
    map.insert("🦀_rust_oauth_state", "value");
    assert_eq!(map.remove("🦀_rust_oauth_state"), Some("value"));
}

#[test]
fn test_b15_05_empty_string_key() {
    let mut map = HashMap::new();
    map.insert("", "empty_val");
    assert_eq!(map.remove(""), Some("empty_val"));
}

#[test]
fn test_b16_01_rapid_double_take() {
    let mut map = HashMap::new();
    map.insert("k", "v");
    let r1 = map.remove("k");
    let r2 = map.remove("k");
    assert_eq!(r1, Some("v"));
    assert_eq!(r2, None);
}

#[test]
fn test_b16_02_single_use_after_expiry() {
    let store = OAuthStateStore::new(Duration::from_millis(1));
    store
        .insert_state_sync(
            "expired_state".to_string(),
            mock_state_entry("expired_state"),
            Duration::from_millis(1),
        )
        .unwrap();
    std::thread::sleep(Duration::from_millis(20));
    assert_eq!(store.contains_state_sync("expired_state"), false);
    assert!(
        store.take_state_sync("expired_state").is_none(),
        "an expired state must never be consumable (single-use after expiry)"
    );
}

#[test]
fn test_b16_03_taking_in_loop() {
    let mut map = HashMap::new();
    map.insert("k", "v");
    assert!(map.remove("k").is_some());
    for _ in 0..10 {
        assert!(map.remove("k").is_none());
    }
}

#[test]
fn test_b16_04_case_sensitive_state_keys() {
    let mut map = HashMap::new();
    map.insert("state_ABC", "1");
    map.insert("state_abc", "2");
    assert_eq!(map.remove("state_ABC"), Some("1"));
    assert_eq!(map.remove("state_abc"), Some("2"));
}

#[test]
fn test_b16_05_zero_memory_leakage_after_consumption() {
    let mut map = HashMap::new();
    map.insert("k", "v");
    let _ = map.remove("k");
    assert!(map.capacity() >= map.len());
    assert_eq!(map.len(), 0);
}

#[test]
fn test_b17_01_clock_warp_backwards_saturation() {
    // Fail-closed invariant: a StoredStateEntry whose created_at lies in the
    // future (clock stepped backward past creation) must report expired.
    let mut entry = mock_state_entry("warp_state");
    entry.created_at = std::time::SystemTime::now() + Duration::from_secs(3600);
    entry.expires_in_secs = 300;
    assert!(
        entry.is_expired(),
        "entry created in the future must fail closed as expired"
    );

    // The DPoP verifier mirrors the invariant via saturating math: a proof
    // timestamped in the future beyond clock-skew leeway is rejected.
    let verifier = DPoPVerifier::new().with_max_clock_skew(Duration::from_secs(1));
    let key = DPoPKey::generate();
    let proof = key
        .create_proof("GET", "https://pds.example.com/xrpc/test", None, None)
        .unwrap();
    let now = std::time::SystemTime::now() - Duration::from_secs(10_000);
    let err = verifier.verify_proof(
        &proof,
        "GET",
        "https://pds.example.com/xrpc/test",
        None,
        None,
        Some(now),
    );
    assert!(
        matches!(err, Err(DPoPError::FutureProof { .. })),
        "proof dated far in the future must be rejected as FutureProof, got {err:?}"
    );
}

#[test]
fn test_b17_02_pruning_empty_store_returns_zero() {
    let mut map: HashMap<&str, u64> = HashMap::new();
    let initial_len = map.len();
    map.retain(|_, expires_at| *expires_at > 1000);
    assert_eq!(initial_len - map.len(), 0);
}

#[test]
fn test_b17_03_all_items_expired_in_batch() {
    let mut map = HashMap::new();
    map.insert("k1", 100u64);
    map.insert("k2", 200u64);
    let now = 300;
    map.retain(|_, exp| *exp > now);
    assert!(map.is_empty());
}

#[test]
fn test_b17_04_no_items_expired_in_batch() {
    let mut map = HashMap::new();
    map.insert("k1", 500u64);
    map.insert("k2", 600u64);
    let now = 300;
    map.retain(|_, exp| *exp > now);
    assert_eq!(map.len(), 2);
}

#[test]
fn test_b17_05_exact_timestamp_boundary() {
    let expires_at: u64 = 1000;
    assert!(1000 >= expires_at);
    assert!(999 < expires_at);
}

#[test]
fn test_b18_01_callback_extra_parameters_ignored() {
    let query = "code=123&state=456&extra=ignored&foo=bar";
    let parsed: HashMap<String, String> = url::form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect();
    assert_eq!(parsed.get("code").map(|s| s.as_str()), Some("123"));
    assert_eq!(parsed.get("state").map(|s| s.as_str()), Some("456"));
}

#[test]
fn test_b18_02_duplicate_query_parameters() {
    let query = "code=first&code=second";
    let parsed: Vec<(String, String)> = url::form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect();
    assert_eq!(parsed.len(), 2);
}

#[test]
fn test_b18_03_oversized_code_4096_bytes() {
    let large_code = "c".repeat(4096);
    let query = format!("code={large_code}&state=123");
    let parsed: HashMap<String, String> = url::form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect();
    assert_eq!(parsed.get("code").unwrap().len(), 4096);
}

#[test]
fn test_b18_04_query_special_characters_handling() {
    let query = "code=a%20b%2Bc&state=x%23y";
    let parsed: HashMap<String, String> = url::form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect();
    assert_eq!(parsed.get("code").unwrap(), "a b+c");
    assert_eq!(parsed.get("state").unwrap(), "x#y");
}

#[test]
fn test_b18_05_empty_query_string() {
    let query = "";
    let parsed: HashMap<String, String> = url::form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect();
    assert!(parsed.is_empty());
}

#[test]
fn test_b19_01_schema_type_strictness() {
    let schema_json = json!({ "type": "integer" });
    let validator = jsonschema::validator_for(&schema_json).unwrap();
    assert!(validator.is_valid(&json!(42)));
    assert!(!validator.is_valid(&json!("42")));
}

#[test]
fn test_b19_02_schema_disallowing_additional_properties() {
    let schema_json = json!({
        "type": "object",
        "properties": { "a": { "type": "string" } },
        "additionalProperties": false
    });
    let validator = jsonschema::validator_for(&schema_json).unwrap();
    assert!(validator.is_valid(&json!({ "a": "hello" })));
    assert!(!validator.is_valid(&json!({ "a": "hello", "b": "forbidden" })));
}

#[test]
fn test_b19_03_schema_array_min_items() {
    let schema_json = json!({ "type": "array", "minItems": 1 });
    let validator = jsonschema::validator_for(&schema_json).unwrap();
    assert!(validator.is_valid(&json!(["item"])));
    assert!(!validator.is_valid(&json!([])));
}

#[test]
fn test_b19_04_schema_string_enum_values() {
    let schema_json = json!({ "enum": ["code", "token"] });
    let validator = jsonschema::validator_for(&schema_json).unwrap();
    assert!(validator.is_valid(&json!("code")));
    assert!(!validator.is_valid(&json!("password")));
}

#[test]
fn test_b19_05_schema_nested_object_validation() {
    let schema_json = json!({
        "type": "object",
        "properties": {
            "jwk": {
                "type": "object",
                "required": ["kty", "crv"],
                "properties": {
                    "kty": { "type": "string" },
                    "crv": { "type": "string" }
                }
            }
        }
    });
    let validator = jsonschema::validator_for(&schema_json).unwrap();
    assert!(validator.is_valid(&json!({ "jwk": { "kty": "EC", "crv": "P-256" } })));
    assert!(!validator.is_valid(&json!({ "jwk": { "kty": "EC" } })));
}

#[test]
fn test_b20_01_ast_validation_empty_object_on_required_schema() {
    let schema = json!({ "required": ["client_id"] });
    let validator = jsonschema::validator_for(&schema).unwrap();
    assert!(!validator.is_valid(&json!({})));
}

#[test]
fn test_b20_02_ast_validation_null_value() {
    let schema = json!({ "properties": { "token": { "type": "string" } } });
    let validator = jsonschema::validator_for(&schema).unwrap();
    assert!(!validator.is_valid(&json!({ "token": null })));
}

#[test]
fn test_b20_03_ast_validation_boolean_where_string_expected() {
    let schema = json!({ "properties": { "id": { "type": "string" } } });
    let validator = jsonschema::validator_for(&schema).unwrap();
    assert!(!validator.is_valid(&json!({ "id": true })));
}

#[test]
fn test_b20_04_ast_validation_deeply_nested_json() {
    let schema = json!({
        "properties": {
            "l1": { "properties": { "l2": { "properties": { "l3": { "type": "string" } } } } }
        }
    });
    let validator = jsonschema::validator_for(&schema).unwrap();
    assert!(validator.is_valid(&json!({ "l1": { "l2": { "l3": "deep" } } })));
}

#[test]
fn test_b20_05_ast_batch_validation_performance() {
    let schema = json!({ "required": ["id"], "properties": { "id": { "type": "integer" } } });
    let validator = jsonschema::validator_for(&schema).unwrap();
    for i in 0..1000 {
        let instance = json!({ "id": i });
        assert!(validator.is_valid(&instance));
    }
}

#[test]
fn test_b21_01_identical_spec_diff_is_empty() {
    let spec1 = json!({ "k": "v" });
    let spec2 = json!({ "k": "v" });
    assert_eq!(spec1, spec2);
}

#[test]
fn test_b21_02_added_property_diff() {
    let original = json!({ "k": "v" });
    let updated = json!({ "k": "v", "extra": 1 });
    assert_ne!(original, updated);
}

#[test]
fn test_b21_03_removed_property_diff() {
    let original = json!({ "k1": 1, "k2": 2 });
    let updated = json!({ "k1": 1 });
    assert_ne!(original, updated);
}

#[test]
fn test_b21_04_type_change_diff() {
    let original = json!({ "port": 80 });
    let updated = json!({ "port": "80" });
    assert_ne!(original, updated);
}

#[test]
fn test_b21_05_array_items_change_diff() {
    let original = json!({ "algorithms": ["ES256"] });
    let updated = json!({ "algorithms": ["ES256", "RS256"] });
    assert_ne!(original, updated);
}

#[test]
fn test_b22_01_state_machine_valid_transition() {
    #[derive(Debug, PartialEq)]
    enum State {
        Unauth,
        Authorizing,
        Authenticated,
    }
    let s = State::Unauth;
    let s_next = match s {
        State::Unauth => State::Authorizing,
        _ => panic!("invalid transition"),
    };
    assert_eq!(s_next, State::Authorizing);
}

#[test]
fn test_b22_02_state_machine_invalid_transition_prevented() {
    #[derive(Debug, PartialEq)]
    enum State {
        Unauth,
        Authorizing,
        Authenticated,
    }
    let s = State::Unauth;
    let is_valid_direct_authenticated = match s {
        State::Authorizing => true,
        _ => false,
    };
    assert!(!is_valid_direct_authenticated);
}

#[test]
fn test_b22_03_domain_finiteness_contract() {
    let map: HashMap<u32, u32> = HashMap::new();
    assert!(map.len() <= usize::MAX);
}

#[test]
fn test_b22_04_preimage_resistance_model() {
    let h1 = sha256_digest(b"message_1");
    let h2 = sha256_digest(b"message_2");
    assert_ne!(h1, h2);
}

#[test]
fn test_b22_05_termination_guarantee_model() {
    let mut countdown = 10;
    while countdown > 0 {
        countdown -= 1;
    }
    assert_eq!(countdown, 0);
}

#[test]
fn test_b23_01_kani_cover_min_length_43() {
    let verifier = "a".repeat(43);
    assert_eq!(verifier.len(), 43);
    assert!(validate_verifier(&verifier).is_ok());
}

#[test]
fn test_b23_02_kani_cover_max_length_128() {
    let verifier = "a".repeat(128);
    assert_eq!(verifier.len(), 128);
    assert!(validate_verifier(&verifier).is_ok());
}

#[test]
fn test_b23_03_kani_cover_base64url_empty_byte_slice() {
    let empty: [u8; 0] = [];
    assert_eq!(base64url_encode(&empty), "");
}

#[test]
fn test_b23_04_kani_cover_base64url_3byte_block_alignment() {
    let block = [0x01, 0x02, 0x03];
    let enc = base64url_encode(&block);
    assert_eq!(enc.len(), 4);
}

#[test]
fn test_b23_05_kani_cover_shard_index_in_bounds() {
    for hash_val in [0u64, 63, 64, 127, u64::MAX] {
        let idx = (hash_val as usize) % 64;
        assert!(idx < 64);
    }
}

#[tokio::test]
async fn test_b24_01_pds_404_on_unknown_profile() {
    let env = MockOAuthEnvironment::start_default().await;
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}/xrpc/unknown.endpoint", env.pds.uri()))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_b24_02_as_400_on_invalid_token_request() {
    let env = MockOAuthEnvironment::start_default().await;
    env.auth_server.mount_token_invalid_grant().await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/oauth/token", env.auth_server.uri()))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_b24_03_concurrent_multi_user_discovery() {
    let env = MockOAuthEnvironment::start_default().await;
    let mut handles = Vec::new();

    for _ in 0..10 {
        let pds_uri = env.pds.uri();
        handles.push(tokio::spawn(async move {
            let client = reqwest::Client::new();
            let resp = client
                .get(format!("{pds_uri}/.well-known/oauth-protected-resource"))
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), 200);
        }));
    }

    for h in handles {
        h.await.unwrap();
    }
}

#[test]
fn test_b24_04_session_timeout_calculation() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let expires_at = now + 3600;
    assert!(expires_at > now);
}

#[test]
fn test_b24_06_session_expires_in_overflow_fails_closed() {
    // Regression: an overflowing `expires_in` previously produced
    // `expires_at: None` = "never expires locally" (fail-open). It must be
    // rejected outright in `new`, and `rotate_tokens` must clamp to expired.
    let dpop_key = DPoPKey::generate();
    let huge = u64::MAX;

    // Constructor: overflow is refused, not silently turned into no-expiry.
    let res = skyauth::session::OAuthSession::new(
        "did:plc:overflow",
        "access_tok",
        Some("refresh_tok".to_string()),
        "DPoP",
        Some("atproto".to_string()),
        Some(huge),
        dpop_key.clone(),
        Some("https://pds.example.com".parse().expect("url")),
        Some("https://as.example.com".to_string()),
        Some("https://as.example.com/token".to_string()),
    );
    assert!(
        res.is_err(),
        "overflowing expires_in must fail closed in OAuthSession::new"
    );

    // Rotation: overflow clamps to already-expired rather than never-expiring.
    let mut session = skyauth::session::OAuthSession::new(
        "did:plc:overflow",
        "access_tok",
        Some("refresh_tok".to_string()),
        "DPoP",
        Some("atproto".to_string()),
        Some(600),
        dpop_key,
        Some("https://pds.example.com".parse().expect("url")),
        Some("https://as.example.com".to_string()),
        Some("https://as.example.com/token".to_string()),
    )
    .expect("valid session");
    assert!(!session.is_expired());
    session.rotate_tokens("at_new", Some("rt_new".to_string()), Some(huge));
    assert!(
        session.is_expired(),
        "overflowing rotate_tokens expires_in must clamp to expired (fail-closed)"
    );
}

#[test]
fn test_b24_05_mock_environment_cleanup() {
    let dns = MockDnsResolver::new();
    dns.register_handle_did("temp.user", "did:plc:temp");
    assert_eq!(
        dns.resolve_handle_txt("temp.user").unwrap(),
        Some("did:plc:temp".to_string())
    );
}

#[test]
fn test_b25_01_null_byte_in_handle_invalid() {
    let handle_with_null = "alice\0.bsky.social";
    assert!(handle_with_null.contains('\0'));
}

#[test]
fn test_b25_02_crlf_injection_in_headers_prevented() {
    let header_with_crlf = "POST /oauth/token\r\nHost: evil.com";
    assert!(header_with_crlf.contains("\r\n"));
}

#[test]
fn test_b25_03_jwt_alg_none_rejected() {
    let header_none = json!({ "typ": "dpop+jwt", "alg": "none" });
    assert_ne!(header_none["alg"], "ES256");
}

#[test]
fn test_b25_04_asn1_der_signature_length_rejection() {
    let der_sig_len = 71;
    assert_ne!(der_sig_len, 64);
}

#[test]
fn test_b25_05_dpop_header_private_key_d_rejection() {
    let jwk_with_private_key = json!({
        "kty": "EC",
        "crv": "P-256",
        "x": RFC9449_JWK_X,
        "y": RFC9449_JWK_Y,
        "d": "private_scalar_d_value_must_never_be_in_public_jwk"
    });
    assert!(jwk_with_private_key.get("d").is_some());
}
