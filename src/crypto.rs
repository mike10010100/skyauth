//! Pure safe Rust cryptographic primitives and helper functions.
//!
//! This module provides cryptographic operations mandated by AT Protocol OAuth,
//! including ECDSA P-256 raw 64-byte IEEE P1363 signing/verification, SHA-256 hashing,
//! HMAC-SHA256, constant-time comparisons, Base64URL encoding/decoding, and RFC 7638
//! JWK Thumbprint calculation.

use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use hmac::{Hmac, Mac};
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::error::CryptoError;
pub use crate::kernels::ct_eq::constant_time_eq;

/// Computes the 256-bit SHA-256 cryptographic digest of arbitrary input data.
///
/// # Examples
///
/// ```
/// use skyauth::crypto::sha256_digest;
///
/// let hash = sha256_digest(b"hello world");
/// assert_eq!(hash.len(), 32);
/// ```
#[must_use]
pub fn sha256_digest(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Computes an HMAC-SHA256 message authentication code (RFC 2104).
///
/// # Errors
///
/// Returns [`CryptoError::Hmac`] if the key is invalid.
///
/// # Examples
///
/// ```
/// use skyauth::crypto::hmac_sha256;
///
/// let mac = hmac_sha256(b"my-secret-key", b"message content").expect("hmac generation");
/// assert_eq!(mac.len(), 32);
/// ```
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> Result<[u8; 32], CryptoError> {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|e| CryptoError::Hmac(format!("Failed to initialize HMAC: {e}")))?;
    mac.update(message);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    Ok(out)
}

/// Encodes binary data into an unpadded URL-safe Base64 string (RFC 4648 § 5).
///
/// # Examples
///
/// ```
/// use skyauth::crypto::base64url_encode;
///
/// let encoded = base64url_encode(&[0x00, 0x01, 0x02]);
/// assert_eq!(encoded, "AAEC");
/// ```
#[must_use]
pub fn base64url_encode(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

/// Decodes an unpadded or padded URL-safe Base64 string into bytes.
///
/// # Errors
///
/// Returns [`CryptoError::Base64Decode`] if the string contains invalid Base64 characters.
///
/// # Examples
///
/// ```
/// use skyauth::crypto::base64url_decode;
///
/// let decoded = base64url_decode("AAEC").expect("valid base64url");
/// assert_eq!(decoded, vec![0x00, 0x01, 0x02]);
/// ```
pub fn base64url_decode(input: &str) -> Result<Vec<u8>, CryptoError> {
    URL_SAFE_NO_PAD
        .decode(input.trim())
        .or_else(|_| URL_SAFE.decode(input.trim()))
        .map_err(|e| CryptoError::Base64Decode(format!("Invalid base64url data: {e}")))
}

/// Decodes a URL-safe Base64 string into a fixed-size byte array.
///
/// # Errors
///
/// Returns [`CryptoError::Base64Decode`] if decoding fails or the output size does not match `N`.
pub fn base64url_decode_fixed<const N: usize>(input: &str) -> Result<[u8; N], CryptoError> {
    let bytes = base64url_decode(input)?;
    if bytes.len() != N {
        return Err(CryptoError::Base64Decode(format!(
            "Expected {N} bytes after base64url decode, got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Signs an arbitrary message using ECDSA P-256 and outputs a 64-byte raw IEEE P1363 signature ($R || S$).
///
/// This format is mandated by RFC 7518 § 3.4 for the `ES256` algorithm.
///
/// # Errors
///
/// Returns [`CryptoError::EcdsaSign`] if signature creation fails.
pub fn sign_p256_raw(signing_key: &SigningKey, message: &[u8]) -> Result<[u8; 64], CryptoError> {
    let sig: Signature = signing_key.sign(message);
    let bytes = sig.to_bytes();
    if bytes.len() != 64 {
        return Err(CryptoError::EcdsaSign(format!(
            "Signature generated unexpected length {}, expected 64",
            bytes.len()
        )));
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Verifies a 64-byte raw IEEE P1363 ECDSA P-256 signature ($R || S$) against a verifying key.
///
/// # Errors
///
/// Returns [`CryptoError::EcdsaVerify`] if the signature length is not 64 bytes or if
/// the signature is cryptographically invalid.
pub fn verify_p256_raw(
    verifying_key: &VerifyingKey,
    message: &[u8],
    signature_bytes: &[u8],
) -> Result<(), CryptoError> {
    if signature_bytes.len() != 64 {
        return Err(CryptoError::EcdsaVerify(format!(
            "Invalid IEEE P1363 signature length: expected 64 bytes, got {}",
            signature_bytes.len()
        )));
    }

    let sig = Signature::from_slice(signature_bytes)
        .map_err(|e| CryptoError::EcdsaVerify(format!("Failed to parse signature: {e}")))?;

    verifying_key
        .verify(message, &sig)
        .map_err(|e| CryptoError::EcdsaVerify(format!("Signature verification failed: {e}")))
}

/// Constructs a NIST P-256 [`VerifyingKey`] from uncompressed affine coordinates (x, y).
///
/// # Errors
///
/// Returns [`CryptoError::InvalidPoint`] if the coordinates do not lie on the curve.
pub fn verifying_key_from_coordinates(
    x_bytes: &[u8; 32],
    y_bytes: &[u8; 32],
) -> Result<VerifyingKey, CryptoError> {
    let mut sec1 = [0u8; 65];
    sec1[0] = 0x04;
    sec1[1..33].copy_from_slice(x_bytes);
    sec1[33..65].copy_from_slice(y_bytes);

    VerifyingKey::from_sec1_bytes(&sec1)
        .map_err(|e| CryptoError::InvalidPoint(format!("Invalid P-256 public key point: {e}")))
}

/// Extracts uncompressed affine coordinates (x, y) as 32-byte arrays from a [`VerifyingKey`].
#[must_use]
pub fn verifying_key_to_coordinates(verifying_key: &VerifyingKey) -> ([u8; 32], [u8; 32]) {
    let encoded = verifying_key.to_encoded_point(false);
    let mut x_out = [0u8; 32];
    let mut y_out = [0u8; 32];

    if let Some(x) = encoded.x() {
        let len = x.len().min(32);
        x_out[32 - len..].copy_from_slice(&x[..len]);
    }
    if let Some(y) = encoded.y() {
        let len = y.len().min(32);
        y_out[32 - len..].copy_from_slice(&y[..len]);
    }

    (x_out, y_out)
}

/// Computes the RFC 7638 JSON Web Key (JWK) Thumbprint (`jkt`) for an EC P-256 key.
///
/// The canonical JSON object contains exactly the following fields in strict lexicographical order:
/// `{"crv":"P-256","kty":"EC","x":"<x>","y":"<y>"}`.
///
/// # Examples
///
/// ```
/// use skyauth::crypto::jwk_thumbprint_ec_p256;
///
/// let jkt = jwk_thumbprint_ec_p256(
///     "l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs",
///     "9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA",
/// );
/// assert_eq!(jkt, "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I");
/// ```
#[must_use]
pub fn jwk_thumbprint_ec_p256(x: &str, y: &str) -> String {
    let canonical_json = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
    let digest = sha256_digest(canonical_json.as_bytes());
    base64url_encode(&digest)
}

/// Computes the RFC 7638 JSON Web Key (JWK) Thumbprint (`jkt`) for an RSA key.
///
/// The canonical JSON object contains exactly the following fields in strict lexicographical order:
/// `{"e":"<e>","kty":"RSA","n":"<n>"}`.
///
/// # Examples
///
/// ```
/// use skyauth::crypto::jwk_thumbprint_rsa;
///
/// let jkt = jwk_thumbprint_rsa(
///     "AQAB",
///     "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
/// );
/// assert_eq!(jkt, "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
/// ```
#[must_use]
pub fn jwk_thumbprint_rsa(e: &str, n: &str) -> String {
    let canonical_json = format!(r#"{{"e":"{e}","kty":"RSA","n":"{n}"}}"#);
    let digest = sha256_digest(canonical_json.as_bytes());
    base64url_encode(&digest)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hello", b"hello world"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn test_sha256_digest() {
        let digest = sha256_digest(b"");
        assert_eq!(
            hex::encode(digest),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_hmac_sha256() {
        let key = b"key";
        let data = b"The quick brown fox jumps over the lazy dog";
        let result = hmac_sha256(key, data).unwrap();
        assert_eq!(
            hex::encode(result),
            "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
        );
    }

    #[test]
    fn test_base64url_roundtrip() {
        let data = b"Hello, AT Protocol OAuth 2.1!";
        let encoded = base64url_encode(data);
        let decoded = base64url_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_rfc7638_rsa_thumbprint_vector() {
        // RFC 7638 Section 3.1 Test Vector
        let n = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";
        let e = "AQAB";
        let jkt = jwk_thumbprint_rsa(e, n);
        assert_eq!(jkt, "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
    }

    #[test]
    fn test_rfc7638_ec_p256_thumbprint_vector() {
        // RFC 9449 Figure 8 / Figure 11 JWK Thumbprint
        let x = "l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs";
        let y = "9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA";
        let jkt = jwk_thumbprint_ec_p256(x, y);
        assert_eq!(jkt, "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I");
    }

    #[test]
    fn test_p256_raw_signing_and_verification() {
        let signing_key = SigningKey::random(&mut rand::thread_rng());
        let verifying_key = signing_key.verifying_key();
        let message = b"AT Protocol DPoP Proof Signing Input";

        let signature = sign_p256_raw(&signing_key, message).unwrap();
        assert_eq!(signature.len(), 64);

        assert!(verify_p256_raw(verifying_key, message, &signature).is_ok());

        assert!(verify_p256_raw(verifying_key, b"Tampered message", &signature).is_err());

        let mut tampered_sig = signature;
        tampered_sig[0] ^= 0xff;
        assert!(verify_p256_raw(verifying_key, message, &tampered_sig).is_err());
    }

    #[test]
    fn test_verifying_key_coordinates_roundtrip() {
        let signing_key = SigningKey::random(&mut rand::thread_rng());
        let verifying_key = signing_key.verifying_key();

        let (x, y) = verifying_key_to_coordinates(verifying_key);
        let reconstructed = verifying_key_from_coordinates(&x, &y).unwrap();

        assert_eq!(
            verifying_key.to_encoded_point(false),
            reconstructed.to_encoded_point(false)
        );
    }
}
