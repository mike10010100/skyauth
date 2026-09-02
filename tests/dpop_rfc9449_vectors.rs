//! Comprehensive RFC 9449 DPoP & RFC 7638 JWK Thumbprint test vectors and edge cases.

use std::time::Duration;

use skyauth::crypto::{
    base64url_decode, base64url_encode, jwk_thumbprint_ec_p256, jwk_thumbprint_rsa,
};
use skyauth::dpop::{
    compute_access_token_hash, extract_dpop_nonce, normalize_htu, DPoPKey, DPoPNonceCache,
    DPoPVerifier, JwkEc,
};
use skyauth::error::DPoPError;

#[test]
fn test_rfc7638_section3_1_rsa_thumbprint() {
    // RFC 7638 Section 3.1 official vector
    let n = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";
    let e = "AQAB";

    let jkt = jwk_thumbprint_rsa(e, n);
    assert_eq!(jkt, "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
}

#[test]
fn test_rfc9449_figure8_and_11_ec_p256_thumbprint() {
    // RFC 9449 Figure 8 / Figure 11 cnf.jkt key
    let x = "l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs";
    let y = "9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA";

    let jwk = JwkEc {
        kty: "EC".to_string(),
        crv: "P-256".to_string(),
        x: x.to_string(),
        y: y.to_string(),
    };

    assert_eq!(
        jwk.thumbprint(),
        "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
    );
    assert_eq!(
        jwk_thumbprint_ec_p256(x, y),
        "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
    );
}

#[test]
fn test_rfc9449_section5_1_figure2_token_request_proof() {
    let raw_jwt = "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiItQndDM0VTYzZhY2MybFRjIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHBzOi8vc2VydmVyLmV4YW1wbGUuY29tL3Rva2VuIiwiaWF0IjoxNTYyMjYyNjE2fQ.2-GxA6T8lP4vfrg8v-FdWP0A0zdrj8igiMLvqRMUvwnQg4PtFLbdLXiOSsX0x7NVY-FNyJK70nfbV37xRZT3Lg";

    let verifier = DPoPVerifier::new()
        .with_max_clock_skew(Duration::from_secs(3600 * 24 * 365 * 20))
        .with_max_proof_age(Duration::from_secs(3600 * 24 * 365 * 20));

    let (claims, jwk) = verifier
        .verify_proof(
            raw_jwt,
            "POST",
            "https://server.example.com/token",
            None,
            None,
            Some(std::time::UNIX_EPOCH + Duration::from_secs(1562262616)),
        )
        .expect("RFC 9449 Figure 2 proof verification");

    assert_eq!(claims.jti, "-BwC3ESc6acc2lTc");
    assert_eq!(claims.htm, "POST");
    assert_eq!(claims.htu, "https://server.example.com/token");
    assert_eq!(claims.iat, 1562262616);
    assert_eq!(claims.nonce, None);
    assert_eq!(claims.ath, None);
    assert_eq!(
        jwk.thumbprint(),
        "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
    );
}

#[test]
fn test_rfc9449_section7_1_figure13_protected_resource_proof() {
    let raw_jwt = "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiJlMWozVl9iS2ljOC1MQUVCIiwiaHRtIjoiR0VUIiwiaHR1IjoiaHR0cHM6Ly9yZXNvdXJjZS5leGFtcGxlLm9yZy9wcm90ZWN0ZWRyZXNvdXJjZSIsImlhdCI6MTU2MjI2MjYxOCwiYXRoIjoiZlVIeU8ycjJaM0RaNTNFc05yV0JiMHhXWG9hTnk1OUlpS0NBcWtzbVFFbyJ9.2oW9RP35yRqzhrtNP86L-Ey71EOptxRimPPToA1plemAgR6pxHF8y6-yqyVnmcw6Fy1dqd-jfxSYoMxhAJpLjA";

    let access_token = "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU";
    let computed_ath = compute_access_token_hash(access_token);
    assert_eq!(computed_ath, "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo");

    let verifier = DPoPVerifier::new()
        .with_max_clock_skew(Duration::from_secs(3600 * 24 * 365 * 20))
        .with_max_proof_age(Duration::from_secs(3600 * 24 * 365 * 20));

    let (claims, jwk) = verifier
        .verify_proof(
            raw_jwt,
            "GET",
            "https://resource.example.org/protectedresource",
            None,
            Some(&computed_ath),
            Some(std::time::UNIX_EPOCH + Duration::from_secs(1562262618)),
        )
        .expect("RFC 9449 Figure 13 proof verification");

    assert_eq!(claims.jti, "e1j3V_bKic8-LAEB");
    assert_eq!(claims.htm, "GET");
    assert_eq!(claims.htu, "https://resource.example.org/protectedresource");
    assert_eq!(claims.iat, 1562262618);
    assert_eq!(
        claims.ath.as_deref(),
        Some("fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo")
    );
    assert_eq!(
        jwk.thumbprint(),
        "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
    );
}

#[test]
fn test_dpop_htu_normalization_matrix() {
    let cases = [
        (
            "https://example.com/oauth/par?client_id=123#fragment",
            "https://example.com/oauth/par",
        ),
        (
            "HTTPS://EXAMPLE.COM:443/xrpc/com.atproto.identity.resolveHandle",
            "https://example.com/xrpc/com.atproto.identity.resolveHandle",
        ),
        (
            "http://localhost:80/callback?code=abc",
            "http://localhost/callback",
        ),
        (
            "https://pds.example.com:8443/oauth/token",
            "https://pds.example.com:8443/oauth/token",
        ),
        ("https://example.com", "https://example.com/"),
    ];

    for (input, expected) in cases {
        let normalized = normalize_htu(input).unwrap();
        assert_eq!(normalized, expected, "Mismatch for input: {input}");
    }
}

#[test]
fn test_dpop_security_rejections() {
    let key = DPoPKey::generate();
    let proof = key
        .create_proof(
            "POST",
            "https://server.example.com/token",
            Some("server-nonce-123"),
            Some("test-ath"),
        )
        .unwrap();

    let verifier = DPoPVerifier::new();

    let res = verifier.verify_proof(
        &proof,
        "GET",
        "https://server.example.com/token",
        Some("server-nonce-123"),
        Some("test-ath"),
        None,
    );
    assert!(matches!(res, Err(DPoPError::MethodMismatch { .. })));

    let res = verifier.verify_proof(
        &proof,
        "POST",
        "https://server.example.com/other-endpoint",
        Some("server-nonce-123"),
        Some("test-ath"),
        None,
    );
    assert!(matches!(res, Err(DPoPError::UriMismatch { .. })));

    let res = verifier.verify_proof(
        &proof,
        "POST",
        "https://server.example.com/token",
        Some("wrong-nonce"),
        Some("test-ath"),
        None,
    );
    assert!(matches!(res, Err(DPoPError::NonceMismatch { .. })));

    let proof_without_nonce = key
        .create_proof("POST", "https://server.example.com/token", None, None)
        .unwrap();
    let res = verifier.verify_proof(
        &proof_without_nonce,
        "POST",
        "https://server.example.com/token",
        Some("required-nonce"),
        None,
        None,
    );
    assert!(matches!(res, Err(DPoPError::MissingNonce)));

    let res = verifier.verify_proof(
        &proof,
        "POST",
        "https://server.example.com/token",
        Some("server-nonce-123"),
        Some("wrong-ath"),
        None,
    );
    assert!(matches!(res, Err(DPoPError::AthMismatch { .. })));

    let res = verifier.verify_proof(
        &proof_without_nonce,
        "POST",
        "https://server.example.com/token",
        None,
        Some("required-ath"),
        None,
    );
    assert!(matches!(res, Err(DPoPError::MissingAth)));

    let parts: Vec<&str> = proof.split('.').collect();
    let mut sig_bytes = base64url_decode(parts[2]).unwrap();
    sig_bytes[5] ^= 0xff;
    let tampered_proof = format!("{}.{}.{}", parts[0], parts[1], base64url_encode(&sig_bytes));
    let res = verifier.verify_proof(
        &tampered_proof,
        "POST",
        "https://server.example.com/token",
        Some("server-nonce-123"),
        Some("test-ath"),
        None,
    );
    assert!(matches!(res, Err(DPoPError::SignatureVerificationFailed)));
}

#[test]
fn test_dpop_nonce_cache_concurrency() {
    let cache = DPoPNonceCache::new();
    let handles: Vec<_> = (0..10)
        .map(|i| {
            let cache_clone = cache.clone();
            std::thread::spawn(move || {
                let origin = format!("https://pds{i}.example.com");
                let nonce = format!("nonce-{i}");
                cache_clone.set_nonce(&origin, nonce.clone());
                assert_eq!(cache_clone.get_nonce(&origin), Some(nonce));
            })
        })
        .collect();

    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn test_extract_dpop_nonce_header() {
    assert_eq!(
        extract_dpop_nonce(Some("fresh-challenge-nonce-999")),
        Some("fresh-challenge-nonce-999".to_string())
    );
    assert_eq!(extract_dpop_nonce(None), None);
    assert_eq!(extract_dpop_nonce(Some("   ")), None);
}
