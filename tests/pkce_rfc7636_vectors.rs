//! Integration and property tests for RFC 7636 PKCE.

use proptest::prelude::*;
use skyauth::error::PkceError;
use skyauth::pkce::{derive_s256_challenge, validate_verifier, verify_pkce, PkceMethod, PkcePair};

#[test]
fn test_rfc7636_appendix_b_official_test_vector() {
    // RFC 7636 Appendix B official vector
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let expected_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    let derived_challenge = derive_s256_challenge(verifier);
    assert_eq!(derived_challenge, expected_challenge);

    let pair = PkcePair::from_verifier(verifier.to_string()).expect("valid verifier");
    assert_eq!(pair.verifier, verifier);
    assert_eq!(pair.challenge, expected_challenge);
    assert_eq!(pair.method, PkceMethod::S256);
    assert_eq!(pair.method.as_str(), "S256");
    assert_eq!(format!("{}", pair.method), "S256");

    assert!(pair.verify(verifier).is_ok());
    assert!(verify_pkce(verifier, expected_challenge).is_ok());
}

#[test]
fn test_pkce_generation_and_entropy_sizes() {
    let pair = PkcePair::generate();
    assert_eq!(pair.verifier.len(), 43);
    assert_eq!(pair.challenge.len(), 43);
    assert!(pair.verify(&pair.verifier).is_ok());

    let pair48 = PkcePair::generate_with_entropy_size(48).expect("valid 48 bytes entropy");
    assert_eq!(pair48.verifier.len(), 64);
    assert!(pair48.verify(&pair48.verifier).is_ok());

    let pair96 = PkcePair::generate_with_entropy_size(96).expect("valid 96 bytes entropy");
    assert_eq!(pair96.verifier.len(), 128);
    assert!(pair96.verify(&pair96.verifier).is_ok());

    // Out of range entropy sizes
    assert!(PkcePair::generate_with_entropy_size(16).is_err());
    assert!(PkcePair::generate_with_entropy_size(100).is_err());
}

#[test]
fn test_verifier_length_boundaries() {
    let short = "a".repeat(42);
    assert!(matches!(
        validate_verifier(&short),
        Err(PkceError::InvalidVerifierLength {
            len: 42,
            min: 43,
            max: 128
        })
    ));

    let min_valid = "a".repeat(43);
    assert!(validate_verifier(&min_valid).is_ok());

    let max_valid = "a".repeat(128);
    assert!(validate_verifier(&max_valid).is_ok());

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
fn test_verifier_unreserved_characters() {
    let all_allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
    assert!(all_allowed.len() >= 43);
    assert!(validate_verifier(all_allowed).is_ok());

    for forbidden in [
        ' ', '+', '/', '=', '@', ':', '?', '#', '[', ']', '!', '$', '&', '\'', '(', ')', '*', ',',
        ';', '%', 'ä', '🦀',
    ] {
        let test_str = format!("{}{}{}", "a".repeat(40), forbidden, "a".repeat(10));
        assert!(
            validate_verifier(&test_str).is_err(),
            "Expected failure for character '{forbidden}'"
        );
    }
}

#[test]
fn test_invalid_challenge_length_rejected() {
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    assert!(matches!(
        verify_pkce(verifier, "short"),
        Err(PkceError::InvalidChallengeLength { len: 5 })
    ));
    assert!(matches!(
        verify_pkce(verifier, &"a".repeat(44)),
        Err(PkceError::InvalidChallengeLength { len: 44 })
    ));
}

proptest! {
    #[test]
    fn prop_s256_challenge_bijection(verifier in "[A-Za-z0-9\\-._~]{43,128}") {
        let challenge = derive_s256_challenge(&verifier);
        prop_assert_eq!(challenge.len(), 43);
        prop_assert!(verify_pkce(&verifier, &challenge).is_ok());
    }

    #[test]
    fn prop_single_character_mutation_in_verifier_fails(
        verifier in "[A-Za-z0-9\\-._~]{43,128}",
        mutate_idx in 0usize..43
    ) {
        let challenge = derive_s256_challenge(&verifier);

        let mut mutated_chars: Vec<char> = verifier.chars().collect();
        let old_char = mutated_chars[mutate_idx];
        let new_char = if old_char == 'a' { 'b' } else { 'a' };
        mutated_chars[mutate_idx] = new_char;
        let mutated_verifier: String = mutated_chars.into_iter().collect();

        prop_assert!(verify_pkce(&mutated_verifier, &challenge).is_err());
    }
}
