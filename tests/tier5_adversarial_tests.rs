//! Tier 5: Adversarial Stress & Cryptographic Tampering Test Suite for `skyauth`.
//!
//! Driven by empirical challengers to stress-test:
//! 1. PKCE boundary conditions, ASCII character limits, and entropy bounds.
//! 2. DPoP proof tampering (signature mutation, header tampering, payload manipulation,
//!    temporal boundaries, clock skew, nonce challenges, missing/mismatched `ath`, key substitution).
//! 3. High-contention concurrent DPoP nonce cache stress.

#![allow(
    clippy::all,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    missing_docs
)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use p256::ecdsa::SigningKey;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::pkcs8::DecodePrivateKey;
use proptest::prelude::*;

use skyauth::crypto::{
    base64url_decode, base64url_encode, jwk_thumbprint_ec_p256, jwk_thumbprint_rsa, sign_p256_raw,
    verify_p256_raw, verifying_key_from_coordinates, verifying_key_to_coordinates,
};
use skyauth::dpop::{compute_access_token_hash, DPoPKey, DPoPNonceCache, DPoPVerifier, JwkEc};
use skyauth::error::{CryptoError, DPoPError, IdentityError, PkceError};
use skyauth::identity::{
    normalize_handle, validate_did_syntax, DidDocument, DidMethod, DidService, IdentityResolver,
};
use skyauth::pkce::{derive_s256_challenge, validate_verifier, verify_pkce, PkcePair};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn craft_custom_proof(
    key: &DPoPKey,
    htm: &str,
    htu: &str,
    iat: u64,
    exp: Option<u64>,
    nonce: Option<&str>,
    ath: Option<&str>,
) -> String {
    let pem = key.to_pkcs8_pem().unwrap();
    let signing_key = SigningKey::from_pkcs8_pem(&pem).unwrap();

    let header = serde_json::json!({
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": key.public_jwk()
    });

    let jti = format!("custom-adversarial-jti-{}", rand::random::<u64>());
    let mut payload = serde_json::json!({
        "jti": jti,
        "htm": htm,
        "htu": htu,
        "iat": iat
    });

    if let Some(e) = exp {
        payload
            .as_object_mut()
            .unwrap()
            .insert("exp".to_string(), serde_json::json!(e));
    }
    if let Some(n) = nonce {
        payload
            .as_object_mut()
            .unwrap()
            .insert("nonce".to_string(), serde_json::json!(n));
    }
    if let Some(a) = ath {
        payload
            .as_object_mut()
            .unwrap()
            .insert("ath".to_string(), serde_json::json!(a));
    }

    let h_b64 = base64url_encode(header.to_string().as_bytes());
    let p_b64 = base64url_encode(payload.to_string().as_bytes());
    let signing_input = format!("{h_b64}.{p_b64}");
    let sig = sign_p256_raw(&signing_key, signing_input.as_bytes()).unwrap();
    format!("{signing_input}.{}", base64url_encode(&sig))
}

fn sign_raw_json(key: &DPoPKey, header: &serde_json::Value, payload: &serde_json::Value) -> String {
    let pem = key.to_pkcs8_pem().unwrap();
    let signing_key = SigningKey::from_pkcs8_pem(&pem).unwrap();

    let h_b64 = base64url_encode(header.to_string().as_bytes());
    let p_b64 = base64url_encode(payload.to_string().as_bytes());
    let signing_input = format!("{h_b64}.{p_b64}");
    let sig = sign_p256_raw(&signing_key, signing_input.as_bytes()).unwrap();
    format!("{signing_input}.{}", base64url_encode(&sig))
}

#[test]
fn test_pkce_length_boundaries_exhaustive() {
    for len in 0..=42 {
        let candidate = "a".repeat(len);
        let res = validate_verifier(&candidate);
        assert!(
            matches!(res, Err(PkceError::InvalidVerifierLength { len: l, min: 43, max: 128 }) if l == len),
            "Length {len} should fail with InvalidVerifierLength"
        );
    }

    let min_candidate = "a".repeat(43);
    assert!(validate_verifier(&min_candidate).is_ok());

    let max_candidate = "a".repeat(128);
    assert!(validate_verifier(&max_candidate).is_ok());

    for len in 129..=200 {
        let candidate = "a".repeat(len);
        let res = validate_verifier(&candidate);
        assert!(
            matches!(res, Err(PkceError::InvalidVerifierLength { len: l, min: 43, max: 128 }) if l == len),
            "Length {len} should fail with InvalidVerifierLength"
        );
    }

    for extreme_len in [1_000, 10_000, 100_000] {
        let extreme_candidate = "a".repeat(extreme_len);
        let res = validate_verifier(&extreme_candidate);
        assert!(
            matches!(res, Err(PkceError::InvalidVerifierLength { len: l, min: 43, max: 128 }) if l == extreme_len)
        );
    }
}

#[test]
fn test_pkce_all_256_byte_values_character_rejection() {
    let is_allowed = |b: u8| -> bool {
        b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_' || b == b'~'
    };

    let allowed_count = (0u8..=255).filter(|&b| is_allowed(b)).count();
    assert_eq!(allowed_count, 26 + 26 + 10 + 4);

    for byte_val in 0u8..=255 {
        let mut verifier_bytes = vec![b'a'; 43];
        verifier_bytes[20] = byte_val;

        let as_str_res = std::str::from_utf8(&verifier_bytes);
        if let Ok(verifier_str) = as_str_res {
            let res = validate_verifier(verifier_str);
            if is_allowed(byte_val) {
                assert!(
                    res.is_ok(),
                    "Byte {byte_val} ({}) should be permitted",
                    byte_val as char
                );
            } else {
                assert!(
                    matches!(
                        res,
                        Err(PkceError::InvalidVerifierCharacter { position: 20, .. })
                    ),
                    "Byte {byte_val} should be rejected at position 20"
                );
            }
        }
    }
}

#[test]
fn test_pkce_positional_illegal_characters() {
    let beginning_bad = format!("!{}", "a".repeat(42));
    assert!(matches!(
        validate_verifier(&beginning_bad),
        Err(PkceError::InvalidVerifierCharacter {
            char: '!',
            position: 0
        })
    ));

    let end_bad_43 = format!("{}!", "a".repeat(42));
    assert!(matches!(
        validate_verifier(&end_bad_43),
        Err(PkceError::InvalidVerifierCharacter {
            char: '!',
            position: 42
        })
    ));

    let end_bad_128 = format!("{}!", "a".repeat(127));
    assert!(matches!(
        validate_verifier(&end_bad_128),
        Err(PkceError::InvalidVerifierCharacter {
            char: '!',
            position: 127
        })
    ));
}

#[test]
fn test_pkce_multibyte_and_unicode_rejections() {
    let unicode_cases = [
        "🦀".repeat(11),                                         // 44 bytes UTF-8, 11 chars
        format!("{}é{}", "a".repeat(20), "a".repeat(22)),        // 2-byte e acute
        format!("{}中{}", "a".repeat(20), "a".repeat(22)),       // 3-byte CJK
        format!("{}\u{202E}{}", "a".repeat(20), "a".repeat(22)), // RTL override
        format!("{}\u{0000}{}", "a".repeat(20), "a".repeat(22)), // Null byte
        format!("{}\r\n{}", "a".repeat(20), "a".repeat(22)),     // CRLF
    ];

    for case in unicode_cases {
        assert!(
            validate_verifier(&case).is_err(),
            "Expected unicode/multibyte string '{case}' to be rejected"
        );
    }
}

#[test]
fn test_pkce_entropy_sizes_bounds() {
    for size in 0..32 {
        assert!(
            PkcePair::generate_with_entropy_size(size).is_err(),
            "Entropy size {size} must fail"
        );
    }

    for size in 32..=96 {
        let pair = PkcePair::generate_with_entropy_size(size)
            .unwrap_or_else(|_| panic!("Entropy size {size} must succeed"));
        assert!(pair.verifier.len() >= 43 && pair.verifier.len() <= 128);
        assert!(pair.verify(&pair.verifier).is_ok());
    }

    for size in [97, 98, 128, 256, 1000] {
        assert!(
            PkcePair::generate_with_entropy_size(size).is_err(),
            "Entropy size {size} must fail"
        );
    }
}

#[test]
fn test_pkce_challenge_mismatch_and_tampering() {
    let pair = PkcePair::generate();

    assert!(matches!(
        verify_pkce(&pair.verifier, ""),
        Err(PkceError::InvalidChallengeLength { len: 0 })
    ));
    assert!(matches!(
        verify_pkce(&pair.verifier, "abc"),
        Err(PkceError::InvalidChallengeLength { len: 3 })
    ));
    assert!(matches!(
        verify_pkce(&pair.verifier, &"a".repeat(42)),
        Err(PkceError::InvalidChallengeLength { len: 42 })
    ));
    assert!(matches!(
        verify_pkce(&pair.verifier, &"a".repeat(44)),
        Err(PkceError::InvalidChallengeLength { len: 44 })
    ));

    let orig_challenge = pair.challenge.clone();
    for i in 0..43 {
        let mut chars: Vec<char> = orig_challenge.chars().collect();
        chars[i] = if chars[i] == 'A' { 'B' } else { 'A' };
        let tampered: String = chars.into_iter().collect();
        assert!(
            matches!(
                verify_pkce(&pair.verifier, &tampered),
                Err(PkceError::ChallengeMismatch)
            ),
            "Challenge with mutation at index {i} must be rejected"
        );
    }
}

#[test]
fn test_dpop_header_typ_tampering() {
    let key = DPoPKey::generate();
    let verifier = DPoPVerifier::new();

    for (i, valid_typ) in ["dpop+jwt", "DPOP+JWT", "dPoP+jWt", "DPoP+jwt"]
        .into_iter()
        .enumerate()
    {
        let header = serde_json::json!({
            "typ": valid_typ,
            "alg": "ES256",
            "jwk": key.public_jwk()
        });
        let payload = serde_json::json!({
            "jti": format!("jti-valid-typ-{i}"),
            "htm": "POST",
            "htu": "https://example.com/token",
            "iat": 1000
        });
        let jwt = sign_raw_json(&key, &header, &payload);

        let res = verifier.verify_proof(
            &jwt,
            "POST",
            "https://example.com/token",
            None,
            None,
            Some(UNIX_EPOCH + Duration::from_secs(1000)),
        );
        assert!(res.is_ok(), "Typ '{valid_typ}' should be accepted");
    }

    for invalid_typ in ["JWT", "dpop", "application/dpop+jwt", "at+jwt", "", "jwt"] {
        let header = serde_json::json!({
            "typ": invalid_typ,
            "alg": "ES256",
            "jwk": key.public_jwk()
        });
        let payload = serde_json::json!({
            "jti": "jti-1",
            "htm": "POST",
            "htu": "https://example.com/token",
            "iat": 1000
        });
        let jwt = sign_raw_json(&key, &header, &payload);

        let res = verifier.verify_proof(
            &jwt,
            "POST",
            "https://example.com/token",
            None,
            None,
            Some(UNIX_EPOCH + Duration::from_secs(1000)),
        );
        assert!(matches!(res, Err(DPoPError::InvalidHeaderTyp(_))));
    }

    let header_no_typ = serde_json::json!({
        "alg": "ES256",
        "jwk": key.public_jwk()
    });
    let payload = serde_json::json!({
        "jti": "jti-1",
        "htm": "POST",
        "htu": "https://example.com/token",
        "iat": 1000
    });
    let jwt = sign_raw_json(&key, &header_no_typ, &payload);
    let res = verifier.verify_proof(
        &jwt,
        "POST",
        "https://example.com/token",
        None,
        None,
        Some(UNIX_EPOCH + Duration::from_secs(1000)),
    );
    assert!(matches!(res, Err(DPoPError::InvalidHeaderTyp(_))));
}

#[test]
fn test_dpop_header_unsupported_alg_tampering() {
    let key = DPoPKey::generate();
    let verifier = DPoPVerifier::new();

    for forbidden_alg in [
        "none", "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES384", "ES512", "EdDSA",
        "PS256", "PS384", "PS512",
    ] {
        let header = serde_json::json!({
            "typ": "dpop+jwt",
            "alg": forbidden_alg,
            "jwk": key.public_jwk()
        });
        let payload = serde_json::json!({
            "jti": "jti-1",
            "htm": "POST",
            "htu": "https://example.com/token",
            "iat": 1000
        });
        let jwt = sign_raw_json(&key, &header, &payload);

        let res = verifier.verify_proof(
            &jwt,
            "POST",
            "https://example.com/token",
            None,
            None,
            Some(UNIX_EPOCH + Duration::from_secs(1000)),
        );
        assert!(matches!(res, Err(DPoPError::UnsupportedAlgorithm(_))));
    }
}

#[test]
fn test_dpop_header_jwk_tampering_and_private_key_leak() {
    let key = DPoPKey::generate();
    let verifier = DPoPVerifier::new();

    let header_no_jwk = serde_json::json!({
        "typ": "dpop+jwt",
        "alg": "ES256"
    });
    let payload = serde_json::json!({
        "jti": "jti-1",
        "htm": "POST",
        "htu": "https://example.com/token",
        "iat": 1000
    });
    let jwt = sign_raw_json(&key, &header_no_jwk, &payload);
    let res = verifier.verify_proof(
        &jwt,
        "POST",
        "https://example.com/token",
        None,
        None,
        Some(UNIX_EPOCH + Duration::from_secs(1000)),
    );
    assert!(matches!(res, Err(DPoPError::MissingJwk)));

    let mut jwk_with_d = serde_json::to_value(key.public_jwk()).unwrap();
    jwk_with_d
        .as_object_mut()
        .unwrap()
        .insert("d".to_string(), serde_json::json!("leaked_private_key"));
    let header_leak = serde_json::json!({
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": jwk_with_d
    });
    let jwt = sign_raw_json(&key, &header_leak, &payload);
    let res = verifier.verify_proof(
        &jwt,
        "POST",
        "https://example.com/token",
        None,
        None,
        Some(UNIX_EPOCH + Duration::from_secs(1000)),
    );
    assert!(matches!(res, Err(DPoPError::PrivateKeyInJwk)));

    for (kty, crv) in [
        ("RSA", "P-256"),
        ("OKP", "Ed25519"),
        ("EC", "P-384"),
        ("EC", "P-521"),
        ("EC", "secp256k1"),
    ] {
        let header_bad_jwk = serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "ES256",
            "jwk": {
                "kty": kty,
                "crv": crv,
                "x": key.public_jwk().x,
                "y": key.public_jwk().y
            }
        });
        let jwt = sign_raw_json(&key, &header_bad_jwk, &payload);
        let res = verifier.verify_proof(
            &jwt,
            "POST",
            "https://example.com/token",
            None,
            None,
            Some(UNIX_EPOCH + Duration::from_secs(1000)),
        );
        assert!(matches!(res, Err(DPoPError::InvalidJwk(_))));
    }
}

#[test]
fn test_dpop_key_substitution_attack_fails() {
    let key_alice = DPoPKey::generate();
    let key_mallory = DPoPKey::generate();

    let header = serde_json::json!({
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": key_alice.public_jwk() // Claiming to be Alice
    });
    let payload = serde_json::json!({
        "jti": "jti-subst",
        "htm": "POST",
        "htu": "https://example.com/token",
        "iat": 1000
    });
    let h_b64 = base64url_encode(header.to_string().as_bytes());
    let p_b64 = base64url_encode(payload.to_string().as_bytes());
    let signing_input = format!("{h_b64}.{p_b64}");

    let mallory_pem = key_mallory.to_pkcs8_pem().unwrap();
    let mallory_signing_key = SigningKey::from_pkcs8_pem(&mallory_pem).unwrap();
    let sig_bytes = sign_p256_raw(&mallory_signing_key, signing_input.as_bytes()).unwrap();
    let jwt = format!("{signing_input}.{}", base64url_encode(&sig_bytes));

    let verifier = DPoPVerifier::new();
    let res = verifier.verify_proof(
        &jwt,
        "POST",
        "https://example.com/token",
        None,
        None,
        Some(UNIX_EPOCH + Duration::from_secs(1000)),
    );

    assert!(matches!(res, Err(DPoPError::SignatureVerificationFailed)));
}

#[test]
fn test_dpop_signature_exhaustive_byte_mutations() {
    let key = DPoPKey::generate();
    let proof = key
        .create_proof("POST", "https://example.com/token", None, None)
        .unwrap();

    let parts: Vec<&str> = proof.split('.').collect();
    assert_eq!(parts.len(), 3);

    let sig_bytes = base64url_decode(parts[2]).unwrap();
    assert_eq!(sig_bytes.len(), 64);

    let verifier = DPoPVerifier::new();

    for byte_idx in 0..64 {
        let mut tampered_sig = sig_bytes.clone();
        tampered_sig[byte_idx] ^= 0x55;

        let tampered_jwt = format!(
            "{}.{}.{}",
            parts[0],
            parts[1],
            base64url_encode(&tampered_sig)
        );
        let res = verifier.verify_proof(
            &tampered_jwt,
            "POST",
            "https://example.com/token",
            None,
            None,
            None,
        );
        assert!(
            matches!(res, Err(DPoPError::SignatureVerificationFailed)),
            "Mutated signature at byte {byte_idx} should fail signature verification"
        );
    }
}

#[test]
fn test_dpop_signature_length_extremes_and_der_rejection() {
    let key = DPoPKey::generate();
    let proof = key
        .create_proof("POST", "https://example.com/token", None, None)
        .unwrap();
    let parts: Vec<&str> = proof.split('.').collect();

    let verifier = DPoPVerifier::new();

    for invalid_sig_len in [0, 1, 32, 63, 65, 70, 72, 128] {
        let bad_sig = vec![0x12; invalid_sig_len];
        let bad_jwt = format!("{}.{}.{}", parts[0], parts[1], base64url_encode(&bad_sig));
        let res = verifier.verify_proof(
            &bad_jwt,
            "POST",
            "https://example.com/token",
            None,
            None,
            None,
        );
        assert!(
            res.is_err(),
            "Signature length {invalid_sig_len} must be rejected"
        );
    }
}

#[test]
fn test_dpop_payload_jti_validation() {
    let key = DPoPKey::generate();
    let verifier = DPoPVerifier::new();

    let header = serde_json::json!({ "typ": "dpop+jwt", "alg": "ES256", "jwk": key.public_jwk() });
    let payload_no_jti = serde_json::json!({
        "htm": "POST",
        "htu": "https://example.com/token",
        "iat": 1000
    });
    let jwt_no_jti = sign_raw_json(&key, &header, &payload_no_jti);
    let res = verifier.verify_proof(
        &jwt_no_jti,
        "POST",
        "https://example.com/token",
        None,
        None,
        Some(UNIX_EPOCH + Duration::from_secs(1000)),
    );
    assert!(matches!(res, Err(DPoPError::MalformedJwt(_))));

    let payload_empty_jti = serde_json::json!({
        "jti": "",
        "htm": "POST",
        "htu": "https://example.com/token",
        "iat": 1000
    });
    let jwt_empty_jti = sign_raw_json(&key, &header, &payload_empty_jti);
    let res_empty = verifier.verify_proof(
        &jwt_empty_jti,
        "POST",
        "https://example.com/token",
        None,
        None,
        Some(UNIX_EPOCH + Duration::from_secs(1000)),
    );
    assert!(matches!(res_empty, Err(DPoPError::MissingClaim("jti"))));

    let payload_ws_jti = serde_json::json!({
        "jti": "   ",
        "htm": "POST",
        "htu": "https://example.com/token",
        "iat": 1000
    });
    let jwt_ws_jti = sign_raw_json(&key, &header, &payload_ws_jti);
    let res_ws = verifier.verify_proof(
        &jwt_ws_jti,
        "POST",
        "https://example.com/token",
        None,
        None,
        Some(UNIX_EPOCH + Duration::from_secs(1000)),
    );
    assert!(matches!(res_ws, Err(DPoPError::MissingClaim("jti"))));
}

#[test]
fn test_dpop_htm_method_mismatches() {
    let key = DPoPKey::generate();
    let methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"];

    for &method1 in &methods {
        let proof = key
            .create_proof(method1, "https://example.com/token", None, None)
            .unwrap();
        let verifier = DPoPVerifier::new();

        for &method2 in &methods {
            let res = verifier.verify_proof(
                &proof,
                method2,
                "https://example.com/token",
                None,
                None,
                None,
            );
            if method1 == method2 {
                assert!(res.is_ok());
            } else {
                assert!(
                    matches!(res, Err(DPoPError::MethodMismatch { .. })),
                    "Expected MethodMismatch for proof '{method1}' vs request '{method2}'"
                );
            }
        }
    }
}

#[test]
fn test_dpop_htu_normalization_and_mismatch() {
    let key = DPoPKey::generate();
    let verifier = DPoPVerifier::new();

    let proof = key
        .create_proof(
            "POST",
            "https://pds.example.com/oauth/token?foo=bar#section",
            None,
            None,
        )
        .unwrap();
    let res = verifier.verify_proof(
        &proof,
        "POST",
        "https://pds.example.com/oauth/token",
        None,
        None,
        None,
    );
    assert!(res.is_ok());

    let res_http = verifier.verify_proof(
        &proof,
        "POST",
        "http://pds.example.com/oauth/token",
        None,
        None,
        None,
    );
    assert!(matches!(res_http, Err(DPoPError::UriMismatch { .. })));

    let res_port = verifier.verify_proof(
        &proof,
        "POST",
        "https://pds.example.com:8443/oauth/token",
        None,
        None,
        None,
    );
    assert!(matches!(res_port, Err(DPoPError::UriMismatch { .. })));

    let res_path = verifier.verify_proof(
        &proof,
        "POST",
        "https://pds.example.com/oauth/token/v2",
        None,
        None,
        None,
    );
    assert!(matches!(res_path, Err(DPoPError::UriMismatch { .. })));
}

#[test]
fn test_dpop_nonce_and_ath_strict_validation() {
    let key = DPoPKey::generate();
    let verifier = DPoPVerifier::new();
    let valid_nonce = "server-challenge-nonce-12345";
    let token = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJkaWQ6cGxjOjEyMyJ9.sig";
    let valid_ath = compute_access_token_hash(token);

    let proof = key
        .create_proof(
            "POST",
            "https://example.com/resource",
            Some(valid_nonce),
            Some(&valid_ath),
        )
        .unwrap();

    let res = verifier.verify_proof(
        &proof,
        "POST",
        "https://example.com/resource",
        Some(valid_nonce),
        Some(&valid_ath),
        None,
    );
    assert!(res.is_ok());

    let res_bad_nonce = verifier.verify_proof(
        &proof,
        "POST",
        "https://example.com/resource",
        Some("wrong-nonce"),
        Some(&valid_ath),
        None,
    );
    assert!(matches!(
        res_bad_nonce,
        Err(DPoPError::NonceMismatch { .. })
    ));

    let res_bad_ath = verifier.verify_proof(
        &proof,
        "POST",
        "https://example.com/resource",
        Some(valid_nonce),
        Some("wrong-ath"),
        None,
    );
    assert!(matches!(res_bad_ath, Err(DPoPError::AthMismatch { .. })));

    let proof_no_nonce = key
        .create_proof(
            "POST",
            "https://example.com/resource",
            None,
            Some(&valid_ath),
        )
        .unwrap();
    let res_missing_nonce = verifier.verify_proof(
        &proof_no_nonce,
        "POST",
        "https://example.com/resource",
        Some(valid_nonce),
        Some(&valid_ath),
        None,
    );
    assert!(matches!(res_missing_nonce, Err(DPoPError::MissingNonce)));

    let proof_no_ath = key
        .create_proof(
            "POST",
            "https://example.com/resource",
            Some(valid_nonce),
            None,
        )
        .unwrap();
    let res_missing_ath = verifier.verify_proof(
        &proof_no_ath,
        "POST",
        "https://example.com/resource",
        Some(valid_nonce),
        Some(&valid_ath),
        None,
    );
    assert!(matches!(res_missing_ath, Err(DPoPError::MissingAth)));
}

#[test]
fn test_dpop_temporal_bounds_and_clock_skew() {
    let key = DPoPKey::generate();
    let verifier = DPoPVerifier::new()
        .with_max_clock_skew(Duration::from_secs(60))
        .with_max_proof_age(Duration::from_secs(300));

    let base_now = 1_000_000u64;

    let proof_fut_50 = craft_custom_proof(
        &key,
        "POST",
        "https://example.com/token",
        base_now + 50,
        None,
        None,
        None,
    );
    let res = verifier.verify_proof(
        &proof_fut_50,
        "POST",
        "https://example.com/token",
        None,
        None,
        Some(UNIX_EPOCH + Duration::from_secs(base_now)),
    );
    assert!(res.is_ok());

    let proof_fut_61 = craft_custom_proof(
        &key,
        "POST",
        "https://example.com/token",
        base_now + 61,
        None,
        None,
        None,
    );
    let res = verifier.verify_proof(
        &proof_fut_61,
        "POST",
        "https://example.com/token",
        None,
        None,
        Some(UNIX_EPOCH + Duration::from_secs(base_now)),
    );
    assert!(matches!(res, Err(DPoPError::FutureProof { .. })));

    let proof_past_290 = craft_custom_proof(
        &key,
        "POST",
        "https://example.com/token",
        base_now - 290,
        None,
        None,
        None,
    );
    let res = verifier.verify_proof(
        &proof_past_290,
        "POST",
        "https://example.com/token",
        None,
        None,
        Some(UNIX_EPOCH + Duration::from_secs(base_now)),
    );
    assert!(res.is_ok());

    let proof_past_301 = craft_custom_proof(
        &key,
        "POST",
        "https://example.com/token",
        base_now - 301,
        None,
        None,
        None,
    );
    let res = verifier.verify_proof(
        &proof_past_301,
        "POST",
        "https://example.com/token",
        None,
        None,
        Some(UNIX_EPOCH + Duration::from_secs(base_now)),
    );
    assert!(matches!(res, Err(DPoPError::ProofTooOld { .. })));

    let proof_exp_valid = craft_custom_proof(
        &key,
        "POST",
        "https://example.com/token",
        base_now,
        Some(base_now + 30),
        None,
        None,
    );
    let res_exp = verifier.verify_proof(
        &proof_exp_valid,
        "POST",
        "https://example.com/token",
        None,
        None,
        Some(UNIX_EPOCH + Duration::from_secs(base_now)),
    );
    assert!(res_exp.is_ok());

    let proof_exp_expired = craft_custom_proof(
        &key,
        "POST",
        "https://example.com/token",
        base_now - 200,
        Some(base_now - 100),
        None,
        None,
    );
    let res_expired = verifier.verify_proof(
        &proof_exp_expired,
        "POST",
        "https://example.com/token",
        None,
        None,
        Some(UNIX_EPOCH + Duration::from_secs(base_now)),
    );
    assert!(matches!(res_expired, Err(DPoPError::ExpiredProof { .. })));
}

#[test]
fn test_dpop_nonce_cache_high_concurrency_stress() {
    let cache = DPoPNonceCache::new();
    let thread_count = 50;
    let iterations = 200;

    let write_counter = Arc::new(AtomicUsize::new(0));

    let handles: Vec<_> = (0..thread_count)
        .map(|tid| {
            let cache_clone = cache.clone();
            let counter_clone = write_counter.clone();
            std::thread::spawn(move || {
                for iter in 0..iterations {
                    let origin_idx = (tid + iter) % 10;
                    let origin = format!("https://pds{origin_idx}.bsky.social/xrpc");
                    let nonce = format!("nonce-t{tid}-i{iter}");

                    cache_clone.set_nonce(&origin, nonce.clone());
                    counter_clone.fetch_add(1, Ordering::Relaxed);

                    let _ = cache_clone.get_nonce(&origin);

                    let upper_origin = format!("HTTPS://PDS{origin_idx}.BSKY.SOCIAL/XRPC");
                    let _ = cache_clone.get_nonce(&upper_origin);

                    if iter % 50 == 0 {
                        cache_clone.clear_nonce(&origin);
                    }
                }
            })
        })
        .collect();

    for h in handles {
        h.join().unwrap();
    }

    assert_eq!(
        write_counter.load(Ordering::SeqCst),
        thread_count * iterations
    );
}

#[test]
fn test_dpop_nonce_cache_case_and_whitespace_invariance() {
    let cache = DPoPNonceCache::new();

    cache.set_nonce(
        "  HTTPS://AUTH.EXAMPLE.COM:8443/OAUTH/TOKEN  ",
        "  challenge-nonce-xyz  ",
    );

    assert_eq!(
        cache.get_nonce("https://auth.example.com:8443/oauth/token"),
        Some("  challenge-nonce-xyz  ".to_string())
    );
    assert_eq!(
        cache.get_nonce("HTTPS://AUTH.EXAMPLE.COM:8443/OAUTH/TOKEN"),
        Some("  challenge-nonce-xyz  ".to_string())
    );

    cache.clear_nonce("https://auth.example.com:8443/oauth/token");
    assert_eq!(
        cache.get_nonce("https://auth.example.com:8443/oauth/token"),
        None
    );
}

proptest! {
    #[test]
    fn prop_fuzz_pkce_random_strings(s in "\\PC{1,150}") {
        let is_valid = (43..=128).contains(&s.len())
            && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_' || b == b'~');

        let validation_res = validate_verifier(&s);
        if is_valid {
            prop_assert!(validation_res.is_ok());
            let challenge = derive_s256_challenge(&s);
            prop_assert!(verify_pkce(&s, &challenge).is_ok());
        } else {
            prop_assert!(validation_res.is_err());
        }
    }

    #[test]
    fn prop_fuzz_dpop_proof_with_arbitrary_tokens(token in "\\PC{1,100}") {
        let ath = compute_access_token_hash(&token);
        prop_assert_eq!(ath.len(), 43);
    }
}

#[test]
fn test_dpop_proof_creation_and_verification_latency() {
    let key = DPoPKey::generate();
    let verifier = DPoPVerifier::new();
    let uri = "https://pds.example.com/xrpc/app.bsky.feed.getTimeline";
    let nonce = "challenge-nonce-12345";
    let token = "sample_bearer_access_token_value_for_benchmarking";
    let ath = compute_access_token_hash(token);

    for _ in 0..10 {
        let proof = key
            .create_proof("GET", uri, Some(nonce), Some(&ath))
            .unwrap();
        let _ = verifier
            .verify_proof(&proof, "GET", uri, Some(nonce), Some(&ath), None)
            .unwrap();
    }

    let iterations = 100;
    let mut creation_times = Vec::with_capacity(iterations);
    let mut verification_times = Vec::with_capacity(iterations);

    for _ in 0..iterations {
        let t0 = std::time::Instant::now();
        let proof = key
            .create_proof("GET", uri, Some(nonce), Some(&ath))
            .unwrap();
        creation_times.push(t0.elapsed());

        let t1 = std::time::Instant::now();
        let _ = verifier
            .verify_proof(&proof, "GET", uri, Some(nonce), Some(&ath), None)
            .unwrap();
        verification_times.push(t1.elapsed());
    }

    creation_times.sort();
    verification_times.sort();

    let p99_idx = (iterations * 99) / 100;
    let creation_p99 = creation_times[p99_idx];
    let verification_p99 = verification_times[p99_idx];

    #[cfg(debug_assertions)]
    let max_allowed = Duration::from_millis(2000);
    #[cfg(not(debug_assertions))]
    let max_allowed = Duration::from_millis(50);

    assert!(
        creation_p99 < max_allowed,
        "DPoP creation p99 took {:?}",
        creation_p99
    );
    assert!(
        verification_p99 < max_allowed,
        "DPoP verification p99 took {:?}",
        verification_p99
    );
}

#[test]
fn test_adv_jwk_field_ordering_canonicalization() {
    let x = "l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs";
    let y = "9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA";
    let expected_jkt = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I";

    let json_perm1 = format!(r#"{{"y":"{y}","x":"{x}","kty":"EC","crv":"P-256"}}"#);
    let jwk1: JwkEc = serde_json::from_str(&json_perm1).expect("parse perm1");
    assert_eq!(jwk1.thumbprint(), expected_jkt);

    let json_perm2 = format!(r#"{{"kty":"EC","crv":"P-256","y":"{y}","x":"{x}"}}"#);
    let jwk2: JwkEc = serde_json::from_str(&json_perm2).expect("parse perm2");
    assert_eq!(jwk2.thumbprint(), expected_jkt);

    assert_eq!(jwk_thumbprint_ec_p256(x, y), expected_jkt);
}

#[test]
fn test_adv_jwk_whitespace_and_formatting_immunity() {
    let x = "l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs";
    let y = "9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA";
    let expected_jkt = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I";

    let pretty_json = format!(
        "{{\n  \"crv\": \"P-256\",\n  \"kty\": \"EC\",\n  \"x\": \"{x}\",\n  \"y\": \"{y}\"\n}}"
    );
    let jwk: JwkEc = serde_json::from_str(&pretty_json).expect("parse pretty json");
    assert_eq!(jwk.thumbprint(), expected_jkt);

    let tab_json = format!(
        "{{\t\"crv\":\t\"P-256\",\t\"kty\":\t\"EC\",\t\"x\":\t\"{x}\",\t\"y\":\t\"{y}\"\t}}"
    );
    let jwk_tab: JwkEc = serde_json::from_str(&tab_json).expect("parse tab json");
    assert_eq!(jwk_tab.thumbprint(), expected_jkt);
}

#[test]
fn test_adv_jwk_extra_fields_omitted_from_thumbprint() {
    let x = "l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs";
    let y = "9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA";
    let expected_jkt = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I";

    let json_with_extra = format!(
        r#"{{"alg":"ES256","crv":"P-256","kid":"key-2026","kty":"EC","use":"sig","x":"{x}","y":"{y}"}}"#
    );
    let jwk: JwkEc = serde_json::from_value(serde_json::from_str(&json_with_extra).unwrap())
        .expect("parse jwk with extra fields");
    assert_eq!(jwk.thumbprint(), expected_jkt);
}

#[test]
fn test_adv_jwk_rsa_thumbprint_rfc7638_vector() {
    let n = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";
    let e = "AQAB";
    let jkt = jwk_thumbprint_rsa(e, n);
    assert_eq!(jkt, "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
    assert_eq!(
        jkt.len(),
        43,
        "Thumbprint must be exactly 43 Base64URL chars"
    );
}

#[test]
fn test_adv_jwk_malformed_coordinates_reconstruction_rejection() {
    let bad_jwk_b64 = JwkEc {
        kty: "EC".to_string(),
        crv: "P-256".to_string(),
        x: "not-valid-base64!@#$%^&*()".to_string(),
        y: "9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA".to_string(),
    };
    assert!(matches!(
        bad_jwk_b64.to_verifying_key(),
        Err(CryptoError::Base64Decode(_))
    ));

    let bad_jwk_short = JwkEc {
        kty: "EC".to_string(),
        crv: "P-256".to_string(),
        x: base64url_encode(&[0x01u8; 16]),
        y: base64url_encode(&[0x02u8; 32]),
    };
    assert!(matches!(
        bad_jwk_short.to_verifying_key(),
        Err(CryptoError::Base64Decode(_))
    ));

    let bad_jwk_long = JwkEc {
        kty: "EC".to_string(),
        crv: "P-256".to_string(),
        x: base64url_encode(&[0x01u8; 33]),
        y: base64url_encode(&[0x02u8; 32]),
    };
    assert!(matches!(
        bad_jwk_long.to_verifying_key(),
        Err(CryptoError::Base64Decode(_))
    ));
}

#[test]
fn test_adv_jwk_unsupported_key_types_in_dpop_verifier() {
    let verifier = DPoPVerifier::new();

    let header_rsa = serde_json::json!({
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": {
            "kty": "RSA",
            "e": "AQAB",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
        }
    });
    let payload = serde_json::json!({
        "jti": "test-jti-1",
        "htm": "POST",
        "htu": "https://server.com/token",
        "iat": 1562262616
    });
    let proof_rsa = format!(
        "{}.{}.AAAA",
        base64url_encode(header_rsa.to_string().as_bytes()),
        base64url_encode(payload.to_string().as_bytes())
    );
    assert!(matches!(
        verifier.verify_proof(
            &proof_rsa,
            "POST",
            "https://server.com/token",
            None,
            None,
            Some(UNIX_EPOCH + Duration::from_secs(1562262616))
        ),
        Err(DPoPError::InvalidJwk(_))
    ));

    let header_p384 = serde_json::json!({
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": {
            "kty": "EC",
            "crv": "P-384",
            "x": "l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs",
            "y": "9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA"
        }
    });
    let proof_p384 = format!(
        "{}.{}.AAAA",
        base64url_encode(header_p384.to_string().as_bytes()),
        base64url_encode(payload.to_string().as_bytes())
    );
    assert!(matches!(
        verifier.verify_proof(
            &proof_p384,
            "POST",
            "https://server.com/token",
            None,
            None,
            Some(UNIX_EPOCH + Duration::from_secs(1562262616))
        ),
        Err(DPoPError::InvalidJwk(_))
    ));

    let header_hs256 = serde_json::json!({
        "typ": "dpop+jwt",
        "alg": "HS256",
        "jwk": {
            "kty": "EC",
            "crv": "P-256",
            "x": "l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs",
            "y": "9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA"
        }
    });
    let proof_hs256 = format!(
        "{}.{}.AAAA",
        base64url_encode(header_hs256.to_string().as_bytes()),
        base64url_encode(payload.to_string().as_bytes())
    );
    assert!(matches!(
        verifier.verify_proof(
            &proof_hs256,
            "POST",
            "https://server.com/token",
            None,
            None,
            Some(UNIX_EPOCH + Duration::from_secs(1562262616))
        ),
        Err(DPoPError::UnsupportedAlgorithm(_))
    ));
}

#[test]
fn test_adv_sec1_generator_point_success() {
    let gx_hex = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
    let gy_hex = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";

    let mut gx = [0u8; 32];
    let mut gy = [0u8; 32];
    hex::decode_to_slice(gx_hex, &mut gx).expect("valid hex gx");
    hex::decode_to_slice(gy_hex, &mut gy).expect("valid hex gy");

    let vkey = verifying_key_from_coordinates(&gx, &gy).expect("G is on P-256 curve");
    let (rx, ry) = verifying_key_to_coordinates(&vkey);
    assert_eq!(rx, gx);
    assert_eq!(ry, gy);
}

#[test]
fn test_adv_sec1_negated_generator_point_success() {
    let neg_g = -p256::AffinePoint::GENERATOR;
    let encoded = neg_g.to_encoded_point(false);
    let neg_gx = encoded.x().unwrap();
    let neg_gy = encoded.y().unwrap();

    let mut gx = [0u8; 32];
    let mut gy = [0u8; 32];
    gx.copy_from_slice(neg_gx);
    gy.copy_from_slice(neg_gy);

    let vkey = verifying_key_from_coordinates(&gx, &gy).expect("-G must be on P-256 curve");
    let (rx, ry) = verifying_key_to_coordinates(&vkey);
    assert_eq!(rx, gx);
    assert_eq!(ry, gy);
}

#[test]
fn test_adv_sec1_off_curve_point_rejection() {
    let zero = [0u8; 32];
    assert!(matches!(
        verifying_key_from_coordinates(&zero, &zero),
        Err(CryptoError::InvalidPoint(_))
    ));

    let mut one = [0u8; 32];
    one[31] = 1;
    assert!(matches!(
        verifying_key_from_coordinates(&one, &one),
        Err(CryptoError::InvalidPoint(_))
    ));

    let gx_hex = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
    let gy_hex = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
    let mut gx = [0u8; 32];
    let mut gy = [0u8; 32];
    hex::decode_to_slice(gx_hex, &mut gx).unwrap();
    hex::decode_to_slice(gy_hex, &mut gy).unwrap();

    gy[31] ^= 0x01;
    assert!(matches!(
        verifying_key_from_coordinates(&gx, &gy),
        Err(CryptoError::InvalidPoint(_))
    ));
}

#[test]
fn test_adv_sec1_coordinate_exceeding_modulus_rejection() {
    let all_ff = [0xffu8; 32];
    let valid_y = [0x01u8; 32];

    assert!(matches!(
        verifying_key_from_coordinates(&all_ff, &valid_y),
        Err(CryptoError::InvalidPoint(_))
    ));
    assert!(matches!(
        verifying_key_from_coordinates(&valid_y, &all_ff),
        Err(CryptoError::InvalidPoint(_))
    ));
    assert!(matches!(
        verifying_key_from_coordinates(&all_ff, &all_ff),
        Err(CryptoError::InvalidPoint(_))
    ));
}

#[test]
fn test_adv_sec1_fuzz_random_coordinate_flips() {
    use rand::RngCore;
    let mut rng = rand::thread_rng();

    for _ in 0..50 {
        let key = p256::ecdsa::SigningKey::random(&mut rng);
        let vkey = key.verifying_key();
        let (mut x, y) = verifying_key_to_coordinates(vkey);

        let byte_pos = (rng.next_u32() as usize) % 32;
        let bit_mask = 1u8 << ((rng.next_u32() as usize) % 8);
        x[byte_pos] ^= bit_mask;

        let res = verifying_key_from_coordinates(&x, &y);
        if let Err(e) = res {
            assert!(matches!(e, CryptoError::InvalidPoint(_)));
        }
    }
}

#[test]
fn test_adv_ieee_p1363_length_enforcement() {
    let key = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
    let vkey = key.verifying_key();
    let message = b"IEEE P1363 Length Boundary Test";

    assert!(matches!(
        verify_p256_raw(vkey, message, &[]),
        Err(CryptoError::EcdsaVerify(_))
    ));

    let sig_32 = [0x01u8; 32];
    assert!(matches!(
        verify_p256_raw(vkey, message, &sig_32),
        Err(CryptoError::EcdsaVerify(_))
    ));

    let sig_63 = [0x01u8; 63];
    assert!(matches!(
        verify_p256_raw(vkey, message, &sig_63),
        Err(CryptoError::EcdsaVerify(_))
    ));

    let sig_65 = [0x01u8; 65];
    assert!(matches!(
        verify_p256_raw(vkey, message, &sig_65),
        Err(CryptoError::EcdsaVerify(_))
    ));

    let der_sig = [
        0x30, 0x44, 0x02, 0x20, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02, 0x20, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    ];
    assert!(matches!(
        verify_p256_raw(vkey, message, &der_sig),
        Err(CryptoError::EcdsaVerify(_))
    ));
}

#[test]
fn test_adv_ieee_p1363_scalar_out_of_range_rejection() {
    let key = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
    let vkey = key.verifying_key();
    let message = b"Scalar Range Test";

    let all_zero = [0x00u8; 64];
    assert!(matches!(
        verify_p256_raw(vkey, message, &all_zero),
        Err(CryptoError::EcdsaVerify(_))
    ));

    let mut r_zero = [0x01u8; 64];
    r_zero[..32].fill(0);
    assert!(matches!(
        verify_p256_raw(vkey, message, &r_zero),
        Err(CryptoError::EcdsaVerify(_))
    ));

    let mut s_zero = [0x01u8; 64];
    s_zero[32..].fill(0);
    assert!(matches!(
        verify_p256_raw(vkey, message, &s_zero),
        Err(CryptoError::EcdsaVerify(_))
    ));

    let all_ff = [0xffu8; 64];
    assert!(matches!(
        verify_p256_raw(vkey, message, &all_ff),
        Err(CryptoError::EcdsaVerify(_))
    ));
}

#[test]
fn test_adv_ieee_p1363_exhaustive_bit_flip_tamper_rejection() {
    let key = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
    let vkey = key.verifying_key();
    let message = b"Critical ATProto DPoP Authorization Token";

    let signature = sign_p256_raw(&key, message).expect("signature succeeds");
    assert_eq!(signature.len(), 64);
    assert!(verify_p256_raw(vkey, message, &signature).is_ok());

    for byte_idx in 0..64 {
        let mut tampered_sig = signature;
        tampered_sig[byte_idx] ^= 0x80;
        let result = verify_p256_raw(vkey, message, &tampered_sig);
        assert!(
            result.is_err(),
            "Tampered byte at index {byte_idx} must fail signature verification"
        );
    }
}

#[test]
fn test_adv_ieee_p1363_cross_message_and_key_isolation() {
    let key_a = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
    let key_b = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());

    let msg_a = b"Message Alpha";
    let msg_b = b"Message Beta";

    let sig_a = sign_p256_raw(&key_a, msg_a).expect("sign msg_a");

    assert!(verify_p256_raw(key_a.verifying_key(), msg_b, &sig_a).is_err());

    assert!(verify_p256_raw(key_b.verifying_key(), msg_a, &sig_a).is_err());

    assert!(verify_p256_raw(key_b.verifying_key(), msg_b, &sig_a).is_err());
}

#[test]
fn test_adv_ieee_p1363_empty_and_large_message_handling() {
    let key = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
    let vkey = key.verifying_key();

    let empty_msg = b"";
    let sig_empty = sign_p256_raw(&key, empty_msg).expect("sign empty");
    assert!(verify_p256_raw(vkey, empty_msg, &sig_empty).is_ok());

    let large_msg = vec![0x42u8; 1024 * 1024];
    let sig_large = sign_p256_raw(&key, &large_msg).expect("sign large");
    assert!(verify_p256_raw(vkey, &large_msg, &sig_large).is_ok());
    assert!(verify_p256_raw(vkey, b"different", &sig_large).is_err());
}

#[test]
fn test_adv_dpop_inbound_proof_with_malformed_signatures() {
    let key = DPoPKey::generate();
    let uri = "https://pds.example.com/xrpc/app.bsky.feed.getTimeline";
    let proof = key.create_proof("GET", uri, None, None).unwrap();
    let parts: Vec<&str> = proof.split('.').collect();
    assert_eq!(parts.len(), 3);

    let verifier = DPoPVerifier::new();

    let der_sig_b64 = base64url_encode(&[0x30, 0x44, 0x02, 0x20, 0xaa, 0xbb]);
    let proof_der = format!("{}.{}.{}", parts[0], parts[1], der_sig_b64);
    let res_der = verifier.verify_proof(&proof_der, "GET", uri, None, None, None);
    assert!(res_der.is_err());

    let zero_sig_b64 = base64url_encode(&[0x00u8; 64]);
    let proof_zero = format!("{}.{}.{}", parts[0], parts[1], zero_sig_b64);
    let res_zero = verifier.verify_proof(&proof_zero, "GET", uri, None, None, None);
    assert!(matches!(
        res_zero,
        Err(DPoPError::SignatureVerificationFailed) | Err(DPoPError::Crypto(_))
    ));

    let trunc_sig_b64 = base64url_encode(&[0x01u8; 32]);
    let proof_trunc = format!("{}.{}.{}", parts[0], parts[1], trunc_sig_b64);
    let res_trunc = verifier.verify_proof(&proof_trunc, "GET", uri, None, None, None);
    assert!(res_trunc.is_err());
}

proptest! {
    #[test]
    fn prop_adv_coordinate_extraction_roundtrip(
        seed in any::<[u8; 32]>()
    ) {
        use rand::SeedableRng;
        let mut rng = rand::rngs::StdRng::from_seed(seed);
        let signing_key = p256::ecdsa::SigningKey::random(&mut rng);
        let verifying_key = signing_key.verifying_key();

        let (x, y) = verifying_key_to_coordinates(verifying_key);
        let reconstructed = verifying_key_from_coordinates(&x, &y)
            .expect("Valid key must always reconstruct");

        prop_assert_eq!(
            verifying_key.to_encoded_point(false),
            reconstructed.to_encoded_point(false)
        );
    }

    #[test]
    fn prop_adv_jwk_thumbprint_invariance(
        seed in any::<[u8; 32]>()
    ) {
        use rand::SeedableRng;
        let mut rng = rand::rngs::StdRng::from_seed(seed);
        let signing_key = p256::ecdsa::SigningKey::random(&mut rng);
        let vkey = signing_key.verifying_key();
        let (x_bytes, y_bytes) = verifying_key_to_coordinates(vkey);

        let x_b64 = base64url_encode(&x_bytes);
        let y_b64 = base64url_encode(&y_bytes);

        let jkt1 = jwk_thumbprint_ec_p256(&x_b64, &y_b64);
        let jwk = JwkEc {
            kty: "EC".to_string(),
            crv: "P-256".to_string(),
            x: x_b64,
            y: y_b64,
        };
        let jkt2 = jwk.thumbprint();

        prop_assert_eq!(jkt1.clone(), jkt2);
        prop_assert_eq!(jkt1.len(), 43);
    }

    #[test]
    fn prop_adv_raw_signature_roundtrip_and_tamper(
        message in proptest::collection::vec(any::<u8>(), 0..512),
        tamper_idx in 0usize..64,
        tamper_val in 1u8..=255
    ) {
        let key = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let vkey = key.verifying_key();

        let signature = sign_p256_raw(&key, &message).expect("sign message");
        prop_assert_eq!(signature.len(), 64);

        prop_assert!(verify_p256_raw(vkey, &message, &signature).is_ok());

        let mut tampered = signature;
        tampered[tamper_idx] ^= tamper_val;
        prop_assert!(verify_p256_raw(vkey, &message, &tampered).is_err());
    }
}

#[test]
fn test_adv_handle_label_length_exhaustive_boundary_1_to_100() {
    for len in 1..=63 {
        let label = "a".repeat(len);
        let handle = format!("{label}.com");
        let res = normalize_handle(&handle);
        assert!(
            res.is_ok(),
            "Handle with label length {len} should succeed: {:?}",
            res.err()
        );
        assert_eq!(res.unwrap(), handle);
    }

    for len in 64..=100 {
        let label = "a".repeat(len);
        let handle = format!("{label}.com");
        let res = normalize_handle(&handle);
        assert!(
            matches!(res, Err(IdentityError::InvalidHandleSyntax(ref msg)) if msg.contains("outside valid range (1..=63)")),
            "Handle with label length {len} should fail with InvalidHandleSyntax, got: {:?}",
            res
        );
    }

    let len_63 = "b".repeat(63);
    let len_64 = "b".repeat(64);
    assert!(normalize_handle(&format!("alice.{len_63}.com")).is_ok());
    assert!(matches!(
        normalize_handle(&format!("alice.{len_64}.com")),
        Err(IdentityError::InvalidHandleSyntax(_))
    ));
    assert!(normalize_handle(&format!("{len_63}.bsky.social")).is_ok());
    assert!(matches!(
        normalize_handle(&format!("{len_64}.bsky.social")),
        Err(IdentityError::InvalidHandleSyntax(_))
    ));
}

#[test]
fn test_adv_handle_total_length_exact_244_vs_245_boundary() {
    let l1 = "a".repeat(60);
    let l2 = "b".repeat(60);
    let l3 = "c".repeat(60);
    let l4_57 = "d".repeat(57);
    let handle_244 = format!("{l1}.{l2}.{l3}.{l4_57}.com");
    assert_eq!(handle_244.len(), 244);
    assert!(
        normalize_handle(&handle_244).is_ok(),
        "Handle of exact length 244 must succeed"
    );

    let l4_58 = "d".repeat(58);
    let handle_245 = format!("{l1}.{l2}.{l3}.{l4_58}.com");
    assert_eq!(handle_245.len(), 245);
    let res_245 = normalize_handle(&handle_245);
    assert!(
        matches!(res_245, Err(IdentityError::InvalidHandleSyntax(ref msg)) if msg.contains("exceeds maximum allowed length of 244")),
        "Handle of exact length 245 must fail with length error, got: {:?}",
        res_245
    );

    let l4_56 = "d".repeat(56);
    let handle_243 = format!("{l1}.{l2}.{l3}.{l4_56}.com");
    assert_eq!(handle_243.len(), 243);
    assert!(normalize_handle(&handle_243).is_ok());

    let l4_59 = "d".repeat(59);
    let handle_246 = format!("{l1}.{l2}.{l3}.{l4_59}.com");
    assert_eq!(handle_246.len(), 246);
    assert!(matches!(
        normalize_handle(&handle_246),
        Err(IdentityError::InvalidHandleSyntax(_))
    ));

    let extreme_300 = format!("{}.com", "a".repeat(296));
    assert!(matches!(
        normalize_handle(&extreme_300),
        Err(IdentityError::InvalidHandleSyntax(_))
    ));
}

#[test]
fn test_adv_handle_disallowed_tlds_exhaustive_and_case_variants() {
    let disallowed = [
        "alt",
        "arpa",
        "example",
        "internal",
        "invalid",
        "local",
        "localhost",
        "onion",
    ];

    for tld in disallowed {
        let h_lower = format!("user.{tld}");
        assert!(
            matches!(
                normalize_handle(&h_lower),
                Err(IdentityError::DisallowedHandleTld(ref found)) if found == tld
            ),
            "Disallowed TLD '{tld}' in lowercase should be rejected"
        );

        let h_upper = format!("USER.{}", tld.to_uppercase());
        assert!(
            matches!(
                normalize_handle(&h_upper),
                Err(IdentityError::DisallowedHandleTld(ref found)) if found == tld
            ),
            "Disallowed TLD '{tld}' in uppercase should be rejected"
        );

        let mixed_tld = tld
            .chars()
            .enumerate()
            .map(|(i, c)| {
                if i % 2 == 0 {
                    c.to_ascii_uppercase()
                } else {
                    c.to_ascii_lowercase()
                }
            })
            .collect::<String>();
        let h_mixed = format!("user.{mixed_tld}");
        assert!(
            matches!(
                normalize_handle(&h_mixed),
                Err(IdentityError::DisallowedHandleTld(ref found)) if found == tld
            ),
            "Disallowed TLD '{tld}' in mixed case should be rejected"
        );

        let h_nested = format!("sub.domain.deep.user.{tld}");
        assert!(
            matches!(
                normalize_handle(&h_nested),
                Err(IdentityError::DisallowedHandleTld(ref found)) if found == tld
            ),
            "Disallowed TLD '{tld}' in nested subdomain should be rejected"
        );

        let h_valid = format!("{tld}.com");
        assert_eq!(
            normalize_handle(&h_valid).unwrap(),
            format!("{tld}.com"),
            "Disallowed TLD word used as subdomain label should be valid"
        );
        let h_valid_nested = format!("sub.{tld}.org");
        assert_eq!(
            normalize_handle(&h_valid_nested).unwrap(),
            format!("sub.{tld}.org"),
            "Disallowed TLD word used as middle label should be valid"
        );
    }

    assert!(matches!(
        normalize_handle("handle.invalid"),
        Err(IdentityError::DisallowedHandleTld(ref t)) if t == "handle.invalid" || t == "invalid"
    ));
    assert!(matches!(
        normalize_handle("HANDLE.INVALID"),
        Err(IdentityError::DisallowedHandleTld(_))
    ));
    assert!(matches!(
        normalize_handle("sub.handle.invalid"),
        Err(IdentityError::DisallowedHandleTld(_))
    ));
}

#[test]
fn test_adv_handle_punycode_and_homoglyph_attacks() {
    let valid_punycode = [
        "xn--bcher-kva.com",           // bücher.com
        "xn--fiqs8s.cn",               // 中国.cn
        "xn--80akhbyknj4f.ru",         // испытание.ru
        "xn----7sbab5aqcb1a.com",      // multi-hyphen punycode
        "alice.xn--fiqs8s.org",        // punycode middle label
        "user.xn--clchc0ea0b2g2a9gcd", // valid gTLD in punycode (.académie)
    ];

    for handle in valid_punycode {
        let res = normalize_handle(handle);
        assert!(
            res.is_ok(),
            "Valid punycode handle '{handle}' must be accepted, got: {:?}",
            res.err()
        );
    }

    let malformed_punycode = [
        "xn--.com",      // ends with hyphen
        "-xn--abc.com",  // starts with hyphen
        "xn--abc-.com",  // ends with hyphen
        "xn--.xn--.com", // multiple empty punycodes
    ];

    for handle in malformed_punycode {
        assert!(
            matches!(
                normalize_handle(handle),
                Err(IdentityError::InvalidHandleSyntax(_))
            ),
            "Malformed punycode handle '{handle}' must be rejected"
        );
    }

    let unicode_attacks = [
        "bücher.com",                  // German umlaut
        "аlice.com",                   // Cyrillic 'а'
        "alіce.com",                   // Ukrainian 'і'
        "paypal.com\u{200b}",          // Zero-width space
        "\u{202E}moc.elppa@alice.com", // RTL override
        "alice.bsky.social\0",         // Null byte injection
        "🚀.bsky.social",              // Emoji label
        "alice\n.bsky.social",         // Newline injection
        "alice\t.bsky.social",         // Tab injection
        "café.paris.fr",               // Accent acute
        "ユーザー.jp",                 // Japanese characters
        "한국.kr",                     // Korean Hangul
    ];

    for handle in unicode_attacks {
        assert!(
            matches!(
                normalize_handle(handle),
                Err(IdentityError::InvalidHandleSyntax(_))
            ),
            "Unicode/homoglyph handle '{handle}' must be rejected with InvalidHandleSyntax"
        );
    }
}

#[test]
fn test_adv_handle_hyphen_placement_permutations() {
    let bad_hyphen_placements = [
        "-alice.bsky.social",
        "alice-.bsky.social",
        "alice.-bsky.social",
        "alice.bsky-.social",
        "alice.bsky.-social",
        "alice.bsky.social-",
        "alice.-.social",
        "alice.--.social",
        "alice.---.social",
        "-.com",
        "com.-",
        "-a.b.c",
        "a-.b.c",
        "a.b.-c",
        "a.b.c-",
    ];

    for handle in bad_hyphen_placements {
        assert!(
            matches!(
                normalize_handle(handle),
                Err(IdentityError::InvalidHandleSyntax(ref msg)) if msg.contains("must not start or end with a hyphen") || msg.contains("must start with an alphanumeric")
            ),
            "Handle '{handle}' with invalid hyphen position should be rejected"
        );
    }

    let valid_internal_hyphens = [
        "a-b.c-d.com",
        "my--handle--name.bsky.social",
        "a---b.c---d.org",
        "0-0.1-1.com",
        "hello-world.example-valid.com",
        "a-1-b-2.c-3-d-4.co.uk",
    ];

    for handle in valid_internal_hyphens {
        let res = normalize_handle(handle);
        assert!(
            res.is_ok(),
            "Valid internal hyphen handle '{handle}' should succeed, got: {:?}",
            res.err()
        );
    }
}

#[test]
fn test_adv_handle_ip_address_and_formatting_edge_cases() {
    let ipv4_cases = [
        "127.0.0.1",
        "10.0.0.1",
        "192.168.1.1",
        "0.0.0.0",
        "255.255.255.255",
        "1.2.3.4",
        "8.8.8.8",
    ];
    for ip in ipv4_cases {
        assert!(
            matches!(
                normalize_handle(ip),
                Err(IdentityError::InvalidHandleSyntax(_))
            ),
            "Raw IPv4 '{ip}' must be rejected"
        );
    }

    let ipv6_cases = [
        "::1",
        "fe80::1",
        "2001:db8::1",
        "[::1]",
        "[fe80::1]",
        "[2001:db8::1]",
    ];
    for ip in ipv6_cases {
        assert!(
            matches!(
                normalize_handle(ip),
                Err(IdentityError::InvalidHandleSyntax(_))
            ),
            "Raw IPv6 '{ip}' must be rejected"
        );
    }

    assert!(normalize_handle("123.456.com").is_ok());
    assert!(normalize_handle("1.2.3.4.com").is_ok());
    assert!(normalize_handle("0.0.0.0.org").is_ok());

    assert!(matches!(
        normalize_handle("localhost"),
        Err(IdentityError::InvalidHandleSyntax(_))
    ));
    assert!(matches!(
        normalize_handle("com"),
        Err(IdentityError::InvalidHandleSyntax(_))
    ));
    assert!(matches!(
        normalize_handle("alice"),
        Err(IdentityError::InvalidHandleSyntax(_))
    ));

    assert!(matches!(
        normalize_handle(""),
        Err(IdentityError::InvalidHandleSyntax(_))
    ));
    assert!(matches!(
        normalize_handle("   "),
        Err(IdentityError::InvalidHandleSyntax(_))
    ));
    assert!(matches!(
        normalize_handle("@"),
        Err(IdentityError::InvalidHandleSyntax(_))
    ));
    assert!(matches!(
        normalize_handle("@@@@"),
        Err(IdentityError::InvalidHandleSyntax(_))
    ));

    assert!(matches!(
        normalize_handle("alice..com"),
        Err(IdentityError::InvalidHandleSyntax(_))
    ));
    assert!(matches!(
        normalize_handle("..alice.com"),
        Err(IdentityError::InvalidHandleSyntax(_))
    ));
    assert!(matches!(
        normalize_handle("alice.com.."),
        Err(IdentityError::InvalidHandleSyntax(_))
    ));
    assert!(matches!(
        normalize_handle("a.b..c.d"),
        Err(IdentityError::InvalidHandleSyntax(_))
    ));

    assert_eq!(
        normalize_handle("@alice.bsky.social").unwrap(),
        "alice.bsky.social"
    );
    assert_eq!(
        normalize_handle("@@@alice.bsky.social").unwrap(),
        "alice.bsky.social"
    );
    assert_eq!(
        normalize_handle("  @ALICE.BSKY.SOCIAL  ").unwrap(),
        "alice.bsky.social"
    );
}

#[test]
fn test_adv_did_document_missing_also_known_as_forgery() {
    let doc_empty = DidDocument {
        id: "did:plc:alice111111111111111111".to_string(),
        also_known_as: vec![],
        verification_method: vec![],
        service: vec![DidService {
            id: "#atproto_pds".to_string(),
            service_type: "AtprotoPersonalDataServer".to_string(),
            service_endpoint: "https://pds.example.com".to_string(),
        }],
    };
    assert!(!doc_empty.matches_handle("alice.bsky.social"));
    assert!(matches!(
        doc_empty.verify_handle_bidirectional("alice.bsky.social"),
        Err(IdentityError::HandleDidMismatch(ref h)) if h == "alice.bsky.social"
    ));

    let json_missing_aka = serde_json::json!({
        "id": "did:plc:alice111111111111111111",
        "service": [{
            "id": "#atproto_pds",
            "type": "AtprotoPersonalDataServer",
            "serviceEndpoint": "https://pds.example.com"
        }]
    });
    let doc_deserialized: DidDocument = serde_json::from_value(json_missing_aka).unwrap();
    assert!(doc_deserialized.also_known_as.is_empty());
    assert!(matches!(
        doc_deserialized.verify_handle_bidirectional("alice.bsky.social"),
        Err(IdentityError::HandleDidMismatch(_))
    ));
}

#[test]
fn test_adv_did_document_conflicting_handle_backlinks() {
    let doc_imposter = DidDocument {
        id: "did:plc:attacker111111111111111".to_string(),
        also_known_as: vec!["at://victim.com".to_string()],
        verification_method: vec![],
        service: vec![],
    };
    assert!(matches!(
        doc_imposter.verify_handle_bidirectional("attacker.com"),
        Err(IdentityError::HandleDidMismatch(ref h)) if h == "attacker.com"
    ));

    let doc_multi_unmatched = DidDocument {
        id: "did:plc:alice111111111111111111".to_string(),
        also_known_as: vec![
            "at://bob.bsky.social".to_string(),
            "at://charlie.bsky.social".to_string(),
        ],
        verification_method: vec![],
        service: vec![],
    };
    assert!(matches!(
        doc_multi_unmatched.verify_handle_bidirectional("alice.bsky.social"),
        Err(IdentityError::HandleDidMismatch(_))
    ));

    let doc_non_at_uri = DidDocument {
        id: "did:plc:alice111111111111111111".to_string(),
        also_known_as: vec![
            "https://alice.bsky.social".to_string(),
            "did:plc:123".to_string(),
            "alice.bsky.social".to_string(), // Missing scheme prefix
        ],
        verification_method: vec![],
        service: vec![],
    };
    assert!(matches!(
        doc_non_at_uri.verify_handle_bidirectional("alice.bsky.social"),
        Err(IdentityError::HandleDidMismatch(_))
    ));

    let doc_multi_matched = DidDocument {
        id: "did:plc:alice111111111111111111".to_string(),
        also_known_as: vec![
            "at://old-alice.bsky.social".to_string(),
            "at://alice.bsky.social".to_string(),
        ],
        verification_method: vec![],
        service: vec![],
    };
    assert!(doc_multi_matched
        .verify_handle_bidirectional("alice.bsky.social")
        .is_ok());

    let doc_uppercase_aka = DidDocument {
        id: "did:plc:alice111111111111111111".to_string(),
        also_known_as: vec!["at://ALICE.BSKY.SOCIAL".to_string()],
        verification_method: vec![],
        service: vec![],
    };
    assert!(doc_uppercase_aka
        .verify_handle_bidirectional("alice.bsky.social")
        .is_ok());
    assert!(doc_uppercase_aka
        .verify_handle_bidirectional("ALICE.BSKY.SOCIAL")
        .is_ok());
    assert!(doc_uppercase_aka
        .verify_handle_bidirectional("@alice.bsky.social")
        .is_ok());
}

#[test]
fn test_adv_did_document_id_mismatch_and_method_substitution() {
    let doc = DidDocument {
        id: "did:plc:imposter222222222222222".to_string(),
        also_known_as: vec!["at://alice.bsky.social".to_string()],
        verification_method: vec![],
        service: vec![],
    };

    let res = doc.validate_id("did:plc:alice111111111111111111");
    assert!(matches!(
        res,
        Err(IdentityError::DidDocumentIdMismatch { ref expected, ref actual })
            if expected == "did:plc:alice111111111111111111" && actual == "did:plc:imposter222222222222222"
    ));

    assert!(doc.validate_id("did:plc:imposter222222222222222").is_ok());

    let doc_web = DidDocument {
        id: "did:web:attacker.com".to_string(),
        also_known_as: vec![],
        verification_method: vec![],
        service: vec![],
    };
    assert!(matches!(
        doc_web.validate_id("did:web:auth.example.com"),
        Err(IdentityError::DidDocumentIdMismatch { .. })
    ));

    let doc_empty_id = DidDocument {
        id: String::new(),
        also_known_as: vec![],
        verification_method: vec![],
        service: vec![],
    };
    assert!(matches!(
        doc_empty_id.validate_id("did:plc:12345678"),
        Err(IdentityError::DidDocumentIdMismatch { .. })
    ));
}

#[test]
fn test_adv_did_service_endpoint_tampering() {
    let doc_no_service = DidDocument {
        id: "did:plc:alice12345678".to_string(),
        also_known_as: vec![],
        verification_method: vec![],
        service: vec![],
    };
    assert!(matches!(
        doc_no_service.extract_pds_endpoint(),
        Err(IdentityError::MissingPdsEndpoint(_))
    ));

    let doc_wrong_id = DidDocument {
        id: "did:plc:alice12345678".to_string(),
        also_known_as: vec![],
        verification_method: vec![],
        service: vec![DidService {
            id: "#my_custom_pds".to_string(),
            service_type: "AtprotoPersonalDataServer".to_string(),
            service_endpoint: "https://pds.example.com".to_string(),
        }],
    };
    assert!(matches!(
        doc_wrong_id.extract_pds_endpoint(),
        Err(IdentityError::MissingPdsEndpoint(_))
    ));

    let doc_wrong_type = DidDocument {
        id: "did:plc:alice12345678".to_string(),
        also_known_as: vec![],
        verification_method: vec![],
        service: vec![DidService {
            id: "#atproto_pds".to_string(),
            service_type: "PersonalDataServer".to_string(),
            service_endpoint: "https://pds.example.com".to_string(),
        }],
    };
    assert!(matches!(
        doc_wrong_type.extract_pds_endpoint(),
        Err(IdentityError::MissingPdsEndpoint(_))
    ));

    let bad_schemes = [
        "ftp://pds.example.com",
        "javascript:alert(1)",
        "data:text/plain,hello",
        "file:///etc/passwd",
        "ws://pds.example.com",
    ];
    for bad_url in bad_schemes {
        let doc_bad_scheme = DidDocument {
            id: "did:plc:alice12345678".to_string(),
            also_known_as: vec![],
            verification_method: vec![],
            service: vec![DidService {
                id: "#atproto_pds".to_string(),
                service_type: "AtprotoPersonalDataServer".to_string(),
                service_endpoint: bad_url.to_string(),
            }],
        };
        assert!(
            matches!(
                doc_bad_scheme.extract_pds_endpoint(),
                Err(IdentityError::InvalidPdsEndpoint(_))
            ),
            "PDS endpoint with scheme '{bad_url}' should fail"
        );
    }

    let doc_malformed_url = DidDocument {
        id: "did:plc:alice12345678".to_string(),
        also_known_as: vec![],
        verification_method: vec![],
        service: vec![DidService {
            id: "#atproto_pds".to_string(),
            service_type: "AtprotoPersonalDataServer".to_string(),
            service_endpoint: "://invalid-url".to_string(),
        }],
    };
    assert!(matches!(
        doc_malformed_url.extract_pds_endpoint(),
        Err(IdentityError::InvalidPdsEndpoint(_))
    ));

    let doc_slashes = DidDocument {
        id: "did:plc:alice12345678".to_string(),
        also_known_as: vec![],
        verification_method: vec![],
        service: vec![DidService {
            id: "#atproto_pds".to_string(),
            service_type: "AtprotoPersonalDataServer".to_string(),
            service_endpoint: "https://pds.example.com///".to_string(),
        }],
    };
    assert_eq!(
        doc_slashes.extract_pds_endpoint().unwrap(),
        "https://pds.example.com"
    );

    let doc_full_fragment = DidDocument {
        id: "did:plc:alice12345678".to_string(),
        also_known_as: vec![],
        verification_method: vec![],
        service: vec![
            DidService {
                id: "#decoy_service".to_string(),
                service_type: "DecoyType".to_string(),
                service_endpoint: "https://decoy.com".to_string(),
            },
            DidService {
                id: "did:plc:alice12345678#atproto_pds".to_string(),
                service_type: "AtprotoPersonalDataServer".to_string(),
                service_endpoint: "https://authoritative-pds.com".to_string(),
            },
        ],
    };
    assert_eq!(
        doc_full_fragment.extract_pds_endpoint().unwrap(),
        "https://authoritative-pds.com"
    );
}

#[test]
fn test_adv_did_syntax_fuzzing() {
    let not_dids = [
        "",
        "   ",
        "plc:12345678",
        "did",
        "did:",
        "did:plc",
        "did:web",
        "urn:did:plc:123",
        "http://did:plc:123",
    ];
    for candidate in not_dids {
        assert!(
            matches!(
                validate_did_syntax(candidate),
                Err(IdentityError::InvalidDidSyntax(_))
            ),
            "Candidate '{candidate}' must be rejected with InvalidDidSyntax"
        );
    }

    let unsupported_methods = [
        "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
        "did:ion:EiD35fQ4...",
        "did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFiYyJ9",
        "did:indy:sovrin:123",
        "did:peer:0z6MkpTHR...",
        "did:ethr:0x1234567890abcdef",
    ];
    for did in unsupported_methods {
        assert!(
            matches!(
                validate_did_syntax(did),
                Err(IdentityError::UnsupportedDidMethod(_))
            ),
            "DID '{did}' must be rejected with UnsupportedDidMethod"
        );
    }

    assert!(matches!(
        validate_did_syntax("did:plc:1234567"), // 7 chars (< 8)
        Err(IdentityError::InvalidDidSyntax(_))
    ));
    assert_eq!(
        validate_did_syntax("did:plc:12345678").unwrap(), // 8 chars (>= 8)
        DidMethod::Plc
    );
    assert_eq!(
        validate_did_syntax("did:plc:ewvi7nxzyoun6zhxrhs64oiz").unwrap(),
        DidMethod::Plc
    );

    assert!(matches!(
        validate_did_syntax("did:web:"),
        Err(IdentityError::InvalidDidSyntax(_))
    ));
    assert_eq!(
        validate_did_syntax("did:web:example.com").unwrap(),
        DidMethod::Web
    );
    assert_eq!(
        validate_did_syntax("did:web:auth.example.com:path:to:user").unwrap(),
        DidMethod::Web
    );
    assert_eq!(
        validate_did_syntax("did:web:localhost%3A8080").unwrap(),
        DidMethod::Web
    );
}

#[tokio::test]
async fn test_adv_identity_resolver_mock_server_spoofing_scenarios() {
    let mock_server = MockServer::start().await;
    let base_uri = mock_server.uri();

    let resolver = IdentityResolver::builder()
        .allow_insecure_localhost(true)
        .plc_directory_url(&base_uri)
        .build();

    Mock::given(method("GET"))
        .and(path("/did:plc:nonexistent123"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&mock_server)
        .await;

    let res_404 = resolver.resolve_did_plc("did:plc:nonexistent123").await;
    assert!(
        matches!(res_404, Err(IdentityError::DidNotFound(ref d)) if d == "did:plc:nonexistent123")
    );

    Mock::given(method("GET"))
        .and(path("/did:plc:malformed123"))
        .respond_with(ResponseTemplate::new(200).set_body_string("<html>Server Error</html>"))
        .mount(&mock_server)
        .await;

    let res_malformed = resolver.resolve_did_plc("did:plc:malformed123").await;
    assert!(matches!(
        res_malformed,
        Err(IdentityError::MalformedDidDocument(_))
    ));

    let mismatched_doc = DidDocument {
        id: "did:plc:evilimposter999".to_string(),
        also_known_as: vec!["at://victim.com".to_string()],
        verification_method: vec![],
        service: vec![DidService {
            id: "#atproto_pds".to_string(),
            service_type: "AtprotoPersonalDataServer".to_string(),
            service_endpoint: "https://pds.example.com".to_string(),
        }],
    };
    Mock::given(method("GET"))
        .and(path("/did:plc:victim12345678"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_json(&mismatched_doc),
        )
        .mount(&mock_server)
        .await;

    let res_mismatch = resolver.resolve_did_plc("did:plc:victim12345678").await;
    assert!(matches!(
        res_mismatch,
        Err(IdentityError::DidDocumentIdMismatch { ref expected, ref actual })
            if expected == "did:plc:victim12345678" && actual == "did:plc:evilimposter999"
    ));
}

proptest! {
    #[test]
    fn prop_fuzz_handle_arbitrary_strings(s in "\\PC{0,300}") {
        let res = normalize_handle(&s);
        if let Ok(handle) = res {
            prop_assert!(!handle.is_empty(), "Handle must not be empty");
            prop_assert!(handle.len() <= 244, "Handle length {} must be <= 244", handle.len());
            prop_assert!(handle.is_ascii(), "Handle must be ASCII");
            prop_assert_eq!(&handle, &handle.to_ascii_lowercase(), "Handle must be lowercase");
            let labels: Vec<&str> = handle.split('.').collect();
            prop_assert!(labels.len() >= 2, "Handle must contain >= 2 labels");

            for label in &labels {
                prop_assert!(!label.is_empty() && label.len() <= 63, "Label length {} out of bounds", label.len());
                prop_assert!(!label.starts_with('-') && !label.ends_with('-'), "Label must not start/end with hyphen");
                prop_assert!(label.chars().next().unwrap().is_ascii_alphanumeric(), "Label must start with alphanumeric");
                prop_assert!(label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'), "Label contains invalid characters");
            }

            let tld = labels.last().unwrap();
            let disallowed = ["alt", "arpa", "example", "internal", "invalid", "local", "localhost", "onion"];
            prop_assert!(!disallowed.contains(tld), "TLD '{}' must not be in disallowed list", tld);
            prop_assert_ne!(handle.as_str(), "handle.invalid", "Handle must not be 'handle.invalid'");
            prop_assert!(handle.parse::<std::net::IpAddr>().is_err(), "Handle must not be a valid IP address");
        }
    }

    #[test]
    fn prop_fuzz_did_syntax_arbitrary_strings(s in "\\PC{0,200}") {
        let res = validate_did_syntax(&s);
        if let Ok(method) = res {
            prop_assert!(s.trim().starts_with("did:"), "DID must start with did:");
            let parts: Vec<&str> = s.trim().split(':').collect();
            prop_assert!(parts.len() >= 3, "DID must have >= 3 parts");
            match method {
                DidMethod::Plc => {
                    prop_assert_eq!(parts[1], "plc");
                    prop_assert!(parts[2].len() >= 8, "PLC hash must be >= 8 chars");
                }
                DidMethod::Web => {
                    prop_assert_eq!(parts[1], "web");
                    prop_assert!(!parts[2].is_empty(), "Web domain must not be empty");
                }
            }
        }
    }

    #[test]
    fn prop_adv_did_document_validation_invariance(
        did_hash in "[a-z0-9]{8,32}",
        handle_name in "[a-z0-9]{1,10}\\.[a-z]{2,4}",
        other_name in "[a-z0-9]{1,10}\\.[a-z]{2,4}"
    ) {
        let expected_did = format!("did:plc:{did_hash}");
        let doc = DidDocument {
            id: expected_did.clone(),
            also_known_as: vec![format!("at://{handle_name}")],
            verification_method: vec![],
            service: vec![DidService {
                id: "#atproto_pds".to_string(),
                service_type: "AtprotoPersonalDataServer".to_string(),
                service_endpoint: "https://pds.example.com".to_string(),
            }],
        };

        prop_assert!(doc.validate_id(&expected_did).is_ok());

        let mismatched_did = format!("did:plc:{did_hash}different");
        prop_assert!(doc.validate_id(&mismatched_did).is_err());

        prop_assert!(doc.matches_handle(&handle_name));
        let at_handle = format!("@{handle_name}");
        prop_assert!(doc.matches_handle(&at_handle));
        let upper_handle = handle_name.to_uppercase();
        prop_assert!(doc.matches_handle(&upper_handle));

        if handle_name != other_name {
            prop_assert!(!doc.matches_handle(&other_name));
            prop_assert!(doc.verify_handle_bidirectional(&other_name).is_err());
        }

        prop_assert_eq!(
            doc.extract_pds_endpoint().unwrap(),
            "https://pds.example.com"
        );
    }
}

use skyauth::client::StoredStateEntry;
use skyauth::discovery::{
    fetch_auth_server_metadata, fetch_protected_resource_metadata, AuthorizationServerMetadata,
    ProtectedResourceMetadata,
};
use skyauth::error::{AtprotoOAuthError, DiscoveryError, TokenError};
use skyauth::par::{build_authorization_url, execute_par_request, ParParameters};
use skyauth::session::OAuthSession;
use skyauth::ssrf::{is_blocked_hostname, is_restricted_ipv4, is_restricted_ipv6, SsrfFilter};
use skyauth::store::{OAuthStateStore, OAuthStore};
use skyauth::verification::kani_harnesses::{
    global_coverage, proof_constant_time_eq_soundness, proof_dpop_htu_normalization_invariants,
    proof_pkce_s256_verifier_bounds, proof_single_use_state_consumption,
    proof_ssrf_restricted_ip_rejection,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[test]
fn test_m7_adv_ssrf_exhaustive_ip_and_hostname_boundaries() {
    let filter_strict = SsrfFilter::new(false);
    let filter_allow_local = SsrfFilter::new(true);

    let loopbacks = [
        Ipv4Addr::new(127, 0, 0, 1),
        Ipv4Addr::new(127, 0, 0, 255),
        Ipv4Addr::new(127, 100, 200, 1),
        Ipv4Addr::new(127, 255, 255, 255),
    ];
    for ip in &loopbacks {
        assert!(is_restricted_ipv4(ip), "Loopback {ip} must be restricted");
        assert!(filter_strict.is_ip_restricted(IpAddr::V4(*ip)));
        assert!(!filter_allow_local.is_ip_restricted(IpAddr::V4(*ip)));
    }

    let rfc1918 = [
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(10, 255, 255, 255),
        Ipv4Addr::new(172, 16, 0, 1),
        Ipv4Addr::new(172, 31, 255, 255),
        Ipv4Addr::new(192, 168, 0, 1),
        Ipv4Addr::new(192, 168, 255, 255),
    ];
    for ip in &rfc1918 {
        assert!(is_restricted_ipv4(ip), "RFC 1918 {ip} must be restricted");
        assert!(filter_strict.is_ip_restricted(IpAddr::V4(*ip)));
        assert!(filter_allow_local.is_ip_restricted(IpAddr::V4(*ip)));
    }

    let rfc1918_public_neighbors = [
        Ipv4Addr::new(172, 15, 255, 255),
        Ipv4Addr::new(172, 32, 0, 1),
        Ipv4Addr::new(9, 255, 255, 255),
        Ipv4Addr::new(11, 0, 0, 1),
        Ipv4Addr::new(192, 167, 255, 255),
        Ipv4Addr::new(192, 169, 0, 1),
    ];
    for ip in &rfc1918_public_neighbors {
        assert!(
            !is_restricted_ipv4(ip),
            "Public IP {ip} must NOT be restricted"
        );
        assert!(!filter_strict.is_ip_restricted(IpAddr::V4(*ip)));
    }

    let link_locals = [
        Ipv4Addr::new(169, 254, 169, 254),
        Ipv4Addr::new(169, 254, 170, 2),
        Ipv4Addr::new(169, 254, 0, 1),
        Ipv4Addr::new(169, 254, 255, 255),
    ];
    for ip in &link_locals {
        assert!(is_restricted_ipv4(ip), "Link local {ip} must be restricted");
        assert!(filter_strict.is_ip_restricted(IpAddr::V4(*ip)));
    }

    let cgnat = [
        Ipv4Addr::new(100, 64, 0, 1),
        Ipv4Addr::new(100, 100, 50, 1),
        Ipv4Addr::new(100, 127, 255, 255),
    ];
    for ip in &cgnat {
        assert!(is_restricted_ipv4(ip), "CGNAT {ip} must be restricted");
    }
    let cgnat_public = [
        Ipv4Addr::new(100, 63, 255, 255),
        Ipv4Addr::new(100, 128, 0, 1),
    ];
    for ip in &cgnat_public {
        assert!(
            !is_restricted_ipv4(ip),
            "Public IP {ip} must NOT be restricted"
        );
    }

    assert!(is_restricted_ipv4(&Ipv4Addr::new(0, 0, 0, 0)));
    assert!(is_restricted_ipv4(&Ipv4Addr::new(0, 1, 2, 3)));
    assert!(is_restricted_ipv4(&Ipv4Addr::new(224, 0, 0, 1)));
    assert!(is_restricted_ipv4(&Ipv4Addr::new(240, 0, 0, 1)));
    assert!(is_restricted_ipv4(&Ipv4Addr::new(255, 255, 255, 255)));
    assert!(is_restricted_ipv4(&Ipv4Addr::new(192, 0, 2, 1)));
    assert!(is_restricted_ipv4(&Ipv4Addr::new(198, 51, 100, 1)));
    assert!(is_restricted_ipv4(&Ipv4Addr::new(203, 0, 113, 1)));

    assert!(is_restricted_ipv6(&Ipv6Addr::UNSPECIFIED));
    assert!(is_restricted_ipv6(&Ipv6Addr::LOCALHOST));
    assert!(is_restricted_ipv6(&Ipv6Addr::new(
        0xfc00, 0, 0, 0, 0, 0, 0, 1
    )));
    assert!(is_restricted_ipv6(&Ipv6Addr::new(
        0xfd12, 0x3456, 0, 0, 0, 0, 0, 1
    )));
    assert!(is_restricted_ipv6(&Ipv6Addr::new(
        0xfe80, 0, 0, 0, 0, 0, 0, 1
    )));
    assert!(is_restricted_ipv6(&Ipv6Addr::new(
        0xff02, 0, 0, 0, 0, 0, 0, 1
    )));
    assert!(is_restricted_ipv6(&Ipv6Addr::new(
        0x2001, 0x0db8, 0, 0, 0, 0, 0, 1
    )));
    assert!(is_restricted_ipv6(&Ipv6Addr::new(
        0x0064, 0xff9b, 0, 0, 0, 0, 0, 1
    )));

    let mapped_loopback: Ipv6Addr = Ipv4Addr::new(127, 0, 0, 1).to_ipv6_mapped();
    let mapped_metadata: Ipv6Addr = Ipv4Addr::new(169, 254, 169, 254).to_ipv6_mapped();
    let mapped_public: Ipv6Addr = Ipv4Addr::new(8, 8, 8, 8).to_ipv6_mapped();
    assert!(is_restricted_ipv6(&mapped_loopback));
    assert!(is_restricted_ipv6(&mapped_metadata));
    assert!(!is_restricted_ipv6(&mapped_public));

    assert!(is_blocked_hostname("metadata.google.internal"));
    assert!(is_blocked_hostname("instance-data"));
    assert!(is_blocked_hostname("metadata.internal"));
    assert!(is_blocked_hostname("169.254.169.254"));
    assert!(is_blocked_hostname("service.internal"));
    assert!(is_blocked_hostname("router.local"));
    assert!(is_blocked_hostname("myapp.localhost"));
    assert!(!is_blocked_hostname("bsky.social"));
    assert!(!is_blocked_hostname("plc.directory"));
}

#[test]
fn test_m7_adv_dpop_htu_exhaustive_normalization() {
    use skyauth::dpop::normalize_htu;

    assert_eq!(
        normalize_htu("http://example.com:80/oauth/token").unwrap(),
        "http://example.com/oauth/token"
    );
    assert_eq!(
        normalize_htu("https://example.com:443/oauth/token").unwrap(),
        "https://example.com/oauth/token"
    );

    assert_eq!(
        normalize_htu("http://example.com:8080/oauth/token").unwrap(),
        "http://example.com:8080/oauth/token"
    );
    assert_eq!(
        normalize_htu("https://example.com:8443/oauth/token").unwrap(),
        "https://example.com:8443/oauth/token"
    );

    assert_eq!(
        normalize_htu("HTTPS://AUTH.EXAMPLE.COM/Oauth/Token").unwrap(),
        "https://auth.example.com/Oauth/Token"
    );

    assert_eq!(
        normalize_htu("https://example.com/oauth/token?client_id=123&scope=atproto#frag1").unwrap(),
        "https://example.com/oauth/token"
    );

    assert_eq!(
        normalize_htu("https://example.com").unwrap(),
        "https://example.com/"
    );

    assert!(normalize_htu("ftp://example.com/resource").is_err());
    assert!(normalize_htu("javascript:alert(1)").is_err());
    assert!(normalize_htu("file:///etc/passwd").is_err());
    assert!(normalize_htu("").is_err());
    assert!(normalize_htu("   ").is_err());
    assert!(normalize_htu("not a uri at all").is_err());
}

#[test]
fn test_m7_adv_pkce_custom_entropy_and_constant_time() {
    for entropy_len in [32, 40, 48, 64, 80, 96] {
        let pair = PkcePair::generate_with_entropy_size(entropy_len).unwrap();
        assert!(pair.verifier.len() >= 43 && pair.verifier.len() <= 128);
        assert_eq!(pair.challenge.len(), 43);
        assert!(pair.verify(&pair.verifier).is_ok());

        let mut tampered = pair.verifier.clone();
        let last_char = if tampered.ends_with('a') { 'b' } else { 'a' };
        tampered.pop();
        tampered.push(last_char);
        assert!(pair.verify(&tampered).is_err());
    }

    for bad_size in [0, 1, 16, 31, 97, 128, 256] {
        let err = PkcePair::generate_with_entropy_size(bad_size);
        assert!(matches!(err, Err(PkceError::InvalidVerifierLength { .. })));
    }
}

#[test]
fn test_m7_adv_oauth_session_rotation_and_auth_header() {
    let key = DPoPKey::generate();

    for valid_type in ["DPoP", "dpop", "DPOP", "dPoP"] {
        let session = OAuthSession::new(
            "did:plc:alice123",
            "initial_access_token_xyz",
            Some("initial_refresh_token_abc".to_string()),
            valid_type,
            Some("atproto transition:generic".to_string()),
            Some(3600),
            key.clone(),
            Some("https://pds.example.com".to_string()),
            Some("https://auth.example.com".to_string()),
            Some("https://auth.example.com/oauth/token".to_string()),
        )
        .unwrap();

        assert_eq!(session.sub(), "did:plc:alice123");
        assert_eq!(session.access_token(), "initial_access_token_xyz");
        assert_eq!(session.refresh_token(), Some("initial_refresh_token_abc"));
        assert_eq!(session.token_type(), valid_type);
        assert_eq!(session.dpop_auth_header(), "DPoP initial_access_token_xyz");
        assert!(!session.is_expired());
    }

    let bearer_err = OAuthSession::new(
        "did:plc:alice123",
        "tok_123",
        None,
        "Bearer",
        None,
        Some(3600),
        key.clone(),
        None,
        None,
        None,
    );
    assert!(matches!(
        bearer_err,
        Err(AtprotoOAuthError::Token(TokenError::InvalidTokenType(_)))
    ));

    let mut session = OAuthSession::new(
        "did:plc:alice123",
        "old_access_token",
        Some("old_refresh_token".to_string()),
        "DPoP",
        Some("atproto".to_string()),
        Some(10),
        key.clone(),
        None,
        None,
        None,
    )
    .unwrap();

    session.rotate_tokens(
        "new_access_token_999",
        Some("new_refresh_token_888".to_string()),
        Some(7200),
    );
    assert_eq!(session.access_token(), "new_access_token_999");
    assert_eq!(session.refresh_token(), Some("new_refresh_token_888"));
    assert_eq!(session.dpop_auth_header(), "DPoP new_access_token_999");
    assert!(!session.is_expired());

    let proof = session
        .create_dpop_proof(
            "POST",
            "https://pds.example.com/xrpc/app.bsky.feed.post",
            Some("nonce_123"),
        )
        .unwrap();
    let verifier = DPoPVerifier::new();
    let ath = compute_access_token_hash("new_access_token_999");
    let (claims, jwk) = verifier
        .verify_proof(
            &proof,
            "POST",
            "https://pds.example.com/xrpc/app.bsky.feed.post",
            Some("nonce_123"),
            Some(&ath),
            None,
        )
        .unwrap();
    assert_eq!(claims.htm, "POST");
    assert_eq!(claims.nonce.as_deref(), Some("nonce_123"));
    assert_eq!(claims.ath.as_deref(), Some(ath.as_str()));
    assert_eq!(jwk, key.public_jwk());
}

#[tokio::test]
async fn test_m7_adv_sharded_store_100_tasks_50_keys_race() {
    let store = Arc::new(OAuthStateStore::new(Duration::from_secs(60)));

    for k in 0..50 {
        let key = format!("state_key_{k}");
        let entry = StoredStateEntry {
            state: key.clone(),
            client_id: "https://app.example.com/client-metadata.json".to_string(),
            code_verifier: "pkce_verifier_string_1234567890123456789012".to_string(),
            dpop_key: DPoPKey::generate(),
            issuer: "https://auth.example.com".to_string(),
            did: Some("did:plc:test1234".to_string()),
            handle: Some("alice.bsky.social".to_string()),
            redirect_uri: "https://app.example.com/callback".to_string(),
            pds_endpoint: "https://pds.example.com".to_string(),
            token_endpoint: "https://auth.example.com/oauth/token".to_string(),
            scopes: "atproto".to_string(),
            created_at: std::time::SystemTime::now(),
            expires_in_secs: 60,
        };
        store
            .insert_state(key, entry, Duration::from_secs(60))
            .await
            .unwrap();
    }

    let mut handles = Vec::new();

    for task_id in 0..100 {
        let store_clone = Arc::clone(&store);
        let handle = tokio::spawn(async move {
            let key = format!("state_key_{}", task_id % 50);
            store_clone.take_state(&key).await
        });
        handles.push(handle);
    }

    let mut total_takes = 0;
    let mut total_misses = 0;
    for h in handles {
        let res = h.await.unwrap();
        match res {
            Ok(Some(_entry)) => total_takes += 1,
            Ok(None) => total_misses += 1,
            Err(e) => panic!("Unexpected store error: {e:?}"),
        }
    }

    assert_eq!(
        total_takes, 50,
        "Exactly 50 state takes must succeed, got {total_takes}"
    );
    assert_eq!(
        total_misses, 50,
        "Exactly 50 state takes must return None, got {total_misses}"
    );
}

#[test]
fn test_m7_adv_formal_anti_vacuity_and_kani_proofs() {
    proof_single_use_state_consumption();
    proof_ssrf_restricted_ip_rejection();
    proof_pkce_s256_verifier_bounds();
    proof_constant_time_eq_soundness();
    proof_dpop_htu_normalization_invariants();

    let coverage = global_coverage();
    let required_tags = [
        "uninitialized_state_rejected",
        "state_inserted",
        "first_take_success",
        "second_take_rejected",
        "expired_state_rejected",
        "concurrent_race_single_winner",
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
        "valid_min_length_43_verifier",
        "valid_max_length_128_verifier",
        "valid_mid_length_verifier",
        "invalid_short_length_rejected",
        "invalid_long_length_rejected",
        "invalid_character_rejected",
        "challenge_length_is_43",
        "equal_non_empty_slices_true",
        "differing_first_byte_false",
        "differing_last_byte_false",
        "differing_middle_byte_false",
        "mismatched_length_false",
        "empty_slices_true",
        "query_stripped_success",
        "fragment_stripped_success",
        "port_443_stripped_success",
        "port_80_stripped_success",
        "custom_port_preserved_success",
        "uppercase_host_lowercased_success",
        "invalid_scheme_rejected",
    ];

    coverage.assert_all_covered(&required_tags);
    assert!(coverage.covered_count() >= required_tags.len());
}

#[tokio::test]
async fn test_m7_adv_wiremock_discovery_and_par_scenarios() {
    let mock_server = MockServer::start().await;
    let base_uri = mock_server.uri();
    let ssrf_filter = SsrfFilter::new(true);

    let empty_as_meta = ProtectedResourceMetadata {
        resource: base_uri.clone(),
        authorization_servers: vec![],
        scopes_supported: vec!["atproto".to_string()],
        bearer_methods_supported: vec!["header".to_string()],
        resource_documentation: None,
    };

    Mock::given(method("GET"))
        .and(path("/.well-known/oauth-protected-resource"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_json(&empty_as_meta),
        )
        .mount(&mock_server)
        .await;

    let res_empty = fetch_protected_resource_metadata(&ssrf_filter, &base_uri).await;
    assert!(matches!(
        res_empty,
        Err(DiscoveryError::MissingAuthorizationServers(_))
    ));

    let mock_server2 = MockServer::start().await;
    let base_uri2 = mock_server2.uri();

    Mock::given(method("GET"))
        .and(path("/.well-known/oauth-authorization-server"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&mock_server2)
        .await;

    let valid_as_meta = AuthorizationServerMetadata {
        issuer: base_uri2.clone(),
        authorization_endpoint: format!("{base_uri2}/oauth/authorize"),
        token_endpoint: format!("{base_uri2}/oauth/token"),
        pushed_authorization_request_endpoint: format!("{base_uri2}/oauth/par"),
        require_pushed_authorization_requests: true,
        dpop_signing_alg_values_supported: vec!["ES256".to_string()],
        code_challenge_methods_supported: vec!["S256".to_string()],
        response_types_supported: vec!["code".to_string()],
        grant_types_supported: vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
        ],
        token_endpoint_auth_methods_supported: vec![
            "none".to_string(),
            "private_key_jwt".to_string(),
        ],
        token_endpoint_auth_signing_alg_values_supported: vec!["ES256".to_string()],
        scopes_supported: vec!["atproto".to_string()],
        authorization_response_iss_parameter_supported: true,
        client_id_metadata_document_supported: true,
        require_request_uri_registration: true,
    };

    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_json(&valid_as_meta),
        )
        .mount(&mock_server2)
        .await;

    let fallback_res = fetch_auth_server_metadata(&ssrf_filter, &base_uri2).await;
    assert!(fallback_res.is_ok(), "OIDC fallback must succeed on 404");
    let as_meta = fallback_res.unwrap();
    assert_eq!(as_meta.issuer, base_uri2);

    let mock_server3 = MockServer::start().await;
    let base_uri3 = mock_server3.uri();
    let par_endpoint = format!("{base_uri3}/oauth/par");

    Mock::given(method("POST"))
        .and(path("/oauth/par"))
        .respond_with(
            ResponseTemplate::new(400)
                .insert_header("DPoP-Nonce", "server_challenge_nonce_xyz")
                .set_body_json(serde_json::json!({
                    "error": "use_dpop_nonce",
                    "error_description": "Authorization server requires fresh nonce"
                })),
        )
        .up_to_n_times(1)
        .mount(&mock_server3)
        .await;

    Mock::given(method("POST"))
        .and(path("/oauth/par"))
        .respond_with(
            ResponseTemplate::new(201)
                .insert_header("content-type", "application/json")
                .set_body_json(serde_json::json!({
                    "request_uri": "urn:ietf:params:oauth:request_uri:req12345678",
                    "expires_in": 90
                })),
        )
        .mount(&mock_server3)
        .await;

    let dpop_key = DPoPKey::generate();
    let nonce_cache = DPoPNonceCache::new();
    let params = ParParameters::new(
        "https://app.example.com/client-metadata.json",
        "https://app.example.com/callback",
        "atproto",
        "state_token_123",
        "pkce_challenge_123",
    );

    let par_res = execute_par_request(
        &ssrf_filter,
        &par_endpoint,
        &params,
        &dpop_key,
        &nonce_cache,
    )
    .await;
    assert!(par_res.is_ok(), "1-hop auto-nonce retry must succeed");
    let par_data = par_res.unwrap();
    assert_eq!(
        par_data.request_uri,
        "urn:ietf:params:oauth:request_uri:req12345678"
    );
    assert_eq!(par_data.expires_in, 90);
    let server_origin = url::Url::parse(&par_endpoint)
        .unwrap()
        .origin()
        .ascii_serialization();
    assert_eq!(
        nonce_cache.get_nonce(&server_origin),
        Some("server_challenge_nonce_xyz".to_string())
    );
}

#[test]
fn test_m7_adv_authorization_url_query_preservation_and_form_encoding() {
    let auth_endpoint = "https://auth.example.com/oauth/authorize?prompt=consent&ui_locales=en";
    let client_id = "https://app.example.com/client-metadata.json";
    let request_uri = "urn:ietf:params:oauth:request_uri:test_req_uri_123";

    let url = build_authorization_url(auth_endpoint, client_id, request_uri).unwrap();
    let query_pairs: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();

    assert_eq!(
        query_pairs.get("prompt").map(|s| s.as_str()),
        Some("consent")
    );
    assert_eq!(
        query_pairs.get("ui_locales").map(|s| s.as_str()),
        Some("en")
    );
    assert_eq!(
        query_pairs.get("client_id").map(|s| s.as_str()),
        Some(client_id)
    );
    assert_eq!(
        query_pairs.get("request_uri").map(|s| s.as_str()),
        Some(request_uri)
    );

    let params = ParParameters::new(
        client_id,
        "https://app.example.com/callback",
        "atproto",
        "state1",
        "chal1",
    )
    .with_login_hint("alice.bsky.social")
    .with_client_assertion(
        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "jwt.assertion.token",
    );

    let encoded = params.to_form_urlencoded();
    assert!(encoded.contains("login_hint=alice.bsky.social"));
    assert!(encoded.contains("client_assertion_type="));
    assert!(encoded.contains("client_assertion=jwt.assertion.token"));
}
