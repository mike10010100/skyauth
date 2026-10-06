//! Round-trip, tamper-detection, AAD, and legacy-passthrough tests for [`skyauth::sealed::SealedBox`].

use skyauth::sealed::{SealedBox, SEALED_ENVELOPE_PREFIX};
use skyauth::CryptoError;

#[test]
fn test_seal_open_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let cipher = SealedBox::from_secret_passphrase("test-secret-passphrase-12345");
    let original = r#"{"access_token":"secret123","refresh_token":"refresh456"}"#;

    let sealed = cipher.seal(original.as_bytes())?;
    assert!(sealed.starts_with(SEALED_ENVELOPE_PREFIX));
    assert_ne!(sealed, original);

    let opened = cipher.open_string(&sealed)?;
    assert_eq!(opened, original);
    Ok(())
}

#[test]
fn test_seal_is_nondeterministic() -> Result<(), Box<dyn std::error::Error>> {
    let cipher = SealedBox::from_secret_passphrase("kdf-secret");
    let a = cipher.seal(b"same plaintext")?;
    let b = cipher.seal(b"same plaintext")?;
    assert_ne!(a, b, "Random nonces must produce distinct ciphertexts");
    assert_eq!(cipher.open_string(&a)?, cipher.open_string(&b)?);
    Ok(())
}

#[test]
fn test_open_legacy_plaintext_passthrough() -> Result<(), Box<dyn std::error::Error>> {
    let cipher = SealedBox::from_secret_passphrase("kdf-secret");
    let legacy = r#"{"access_token":"plain123"}"#;
    assert_eq!(cipher.open_string(legacy)?, legacy);
    Ok(())
}

#[test]
fn test_open_with_wrong_key_fails() -> Result<(), Box<dyn std::error::Error>> {
    let good = SealedBox::from_secret_passphrase("correct-key");
    let bad = SealedBox::from_secret_passphrase("wrong-key");
    let sealed = good.seal(b"top-secret-tokens")?;

    let err = bad.open(&sealed).expect_err("wrong key must fail");
    assert!(matches!(err, CryptoError::Open(_)));
    Ok(())
}

#[test]
fn test_tampered_ciphertext_fails_authentication() -> Result<(), Box<dyn std::error::Error>> {
    use base64::Engine;
    let cipher = SealedBox::from_secret_passphrase("kdf-secret");
    let sealed = cipher.seal(b"integrity-protected")?;

    let encoded = sealed
        .strip_prefix(SEALED_ENVELOPE_PREFIX)
        .expect("envelope prefix");
    let mut combined = base64::engine::general_purpose::STANDARD.decode(encoded)?;
    let last = combined.len() - 1;
    combined[last] ^= 0x01;
    let tampered = format!(
        "{SEALED_ENVELOPE_PREFIX}{}",
        base64::engine::general_purpose::STANDARD.encode(combined)
    );

    let err = cipher.open(&tampered).expect_err("tamper must fail");
    assert!(matches!(err, CryptoError::Open(_)));
    Ok(())
}

#[test]
fn test_aad_binds_context() -> Result<(), Box<dyn std::error::Error>> {
    let cipher = SealedBox::from_secret_passphrase("kdf-secret");
    let sealed = cipher.seal_with_aad(b"did-bound-session", b"did:plc:alice")?;

    let ok = cipher.open_string_with_aad(&sealed, b"did:plc:alice")?;
    assert_eq!(ok, "did-bound-session");

    let err = cipher
        .open_with_aad(&sealed, b"did:plc:mallory")
        .expect_err("mismatched AAD must fail");
    assert!(matches!(err, CryptoError::Open(_)));
    Ok(())
}

#[test]
fn test_truncated_envelope_rejected() {
    let cipher = SealedBox::from_secret_passphrase("kdf-secret");
    let truncated = format!("{SEALED_ENVELOPE_PREFIX}{}", "AAAA");
    let err = cipher.open(&truncated).expect_err("truncated must fail");
    assert!(matches!(err, CryptoError::InvalidEnvelope(_)));
}

#[test]
fn test_from_hex_valid_and_invalid() {
    let key = "ab".repeat(32);
    let cipher = SealedBox::from_hex(&key).expect("valid hex");
    let sealed = cipher.seal(b"payload").expect("seal");
    assert_eq!(cipher.open_string(&sealed).expect("open"), "payload");

    assert!(matches!(
        SealedBox::from_hex("zz"),
        Err(CryptoError::InvalidKey(_))
    ));
    assert!(matches!(
        SealedBox::from_hex(&"ab".repeat(31)),
        Err(CryptoError::InvalidKey(_))
    ));
}

#[test]
fn test_debug_redacts_key() {
    let cipher = SealedBox::new([7u8; 32]);
    let output = format!("{cipher:?}");
    assert!(output.contains("[REDACTED]"));
    assert!(!output.contains("7, 7"));
}

#[test]
fn test_cross_box_equivalence() {
    // Two independently-constructed boxes derived from the same passphrase must
    // agree: one via the passphrase KDF, one via an explicit key built by
    // hex-encoding that KDF's output (exercising `from_hex`).
    let passphrase = std::env::var("SKYAUTH_TEST_KDF_INPUT")
        .unwrap_or_else(|_| "cross-box-equivalence".to_string());
    let a = SealedBox::from_secret_passphrase(&passphrase);
    let digest = skyauth::crypto::sha256_digest(passphrase.as_bytes());
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    let b = SealedBox::from_hex(&hex).expect("hex roundtrip");
    let sealed = a.seal(b"same-key").expect("seal");
    assert_eq!(b.open_string(&sealed).expect("open"), "same-key");
}
