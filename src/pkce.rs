//! RFC 7636 Proof Key for Code Exchange (PKCE) primitives.
//!
//! This module implements PKCE code verifier generation, S256 code challenge derivation,
//! and constant-time verification according to <https://datatracker.ietf.org/doc/html/rfc7636>.

use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::crypto::{base64url_encode, constant_time_eq, sha256_digest};
use crate::error::PkceError;
use crate::policy::{pkce_byte_allowed, pkce_length_allowed};

/// The PKCE code challenge transformation method.
///
/// RFC 7636 and OAuth 2.1 mandate the use of [`PkceMethod::S256`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum PkceMethod {
    /// SHA-256 hash followed by unpadded URL-safe Base64 encoding.
    #[default]
    #[serde(rename = "S256")]
    S256,
}

impl PkceMethod {
    /// Returns the string representation of the PKCE method as defined in RFC 7636 § 4.3.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::S256 => "S256",
        }
    }
}

impl std::fmt::Display for PkceMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A cryptographic PKCE code verifier and derived code challenge pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PkcePair {
    /// High-entropy unreserved code verifier (43 to 128 characters).
    pub verifier: String,
    /// Derived S256 code challenge (43 characters).
    pub challenge: String,
    /// Code challenge transformation method (always [`PkceMethod::S256`]).
    pub method: PkceMethod,
}

impl PkcePair {
    /// Generates a fresh, cryptographically secure PKCE S256 verifier and challenge pair.
    ///
    /// The verifier is generated from 32 bytes (256 bits) of cryptographic entropy
    /// using unpadded URL-safe Base64 encoding, yielding a 43-character verifier string.
    ///
    /// # Examples
    ///
    /// ```
    /// use skyauth::pkce::PkcePair;
    ///
    /// let pkce = PkcePair::generate();
    /// assert_eq!(pkce.verifier.len(), 43);
    /// assert_eq!(pkce.challenge.len(), 43);
    /// assert!(pkce.verify(&pkce.verifier).is_ok());
    /// ```
    #[must_use]
    pub fn generate() -> Self {
        let mut entropy = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut entropy);
        let verifier = base64url_encode(&entropy);
        let challenge = derive_s256_challenge(&verifier);
        Self {
            verifier,
            challenge,
            method: PkceMethod::S256,
        }
    }

    /// Generates a PKCE pair from a custom number of entropy bytes.
    ///
    /// `entropy_bytes` must be between 32 and 96 bytes so the resulting Base64URL string
    /// falls within the RFC 7636 permitted range of 43 to 128 characters.
    ///
    /// # Errors
    ///
    /// Returns [`PkceError::InvalidVerifierLength`] if `entropy_bytes` produces an invalid string.
    pub fn generate_with_entropy_size(entropy_bytes: usize) -> Result<Self, PkceError> {
        if !(32..=96).contains(&entropy_bytes) {
            return Err(PkceError::InvalidVerifierLength {
                len: (entropy_bytes * 4).div_ceil(3),
                min: 43,
                max: 128,
            });
        }
        let mut bytes = vec![0u8; entropy_bytes];
        rand::thread_rng().fill_bytes(&mut bytes);
        let verifier = base64url_encode(&bytes);
        Self::from_verifier(verifier)
    }

    /// Creates a PKCE pair from an existing code verifier string.
    ///
    /// # Errors
    ///
    /// Returns [`PkceError::InvalidVerifierLength`] if `verifier` is shorter than 43 or
    /// longer than 128 characters.
    /// Returns [`PkceError::InvalidVerifierCharacter`] if `verifier` contains characters
    /// outside the RFC 7636 unreserved set `[A-Za-z0-9-._~]`.
    pub fn from_verifier(verifier: String) -> Result<Self, PkceError> {
        validate_verifier(&verifier)?;
        let challenge = derive_s256_challenge(&verifier);
        Ok(Self {
            verifier,
            challenge,
            method: PkceMethod::S256,
        })
    }

    /// Verifies a candidate code verifier against this PKCE pair's challenge in constant time.
    ///
    /// # Errors
    ///
    /// Returns [`PkceError`] if the verifier fails character/length validation or does
    /// not match the expected challenge.
    pub fn verify(&self, candidate_verifier: &str) -> Result<(), PkceError> {
        verify_pkce(candidate_verifier, &self.challenge)
    }
}

/// Derives the S256 code challenge from an ASCII code verifier string.
///
/// Computes `BASE64URL(SHA256(ASCII(verifier)))`.
#[must_use]
pub fn derive_s256_challenge(verifier: &str) -> String {
    let digest = sha256_digest(verifier.as_bytes());
    base64url_encode(&digest)
}

/// Validates that a code verifier conforms to RFC 7636 § 4.1.
///
/// Criteria:
/// - Length must be between 43 and 128 characters inclusive.
/// - Characters must belong to the unreserved set `[A-Za-z0-9-._~]`.
///
/// # Errors
///
/// Returns [`PkceError::InvalidVerifierLength`] or [`PkceError::InvalidVerifierCharacter`].
pub fn validate_verifier(verifier: &str) -> Result<(), PkceError> {
    let len = verifier.len();
    if !pkce_length_allowed(len) {
        return Err(PkceError::InvalidVerifierLength {
            len,
            min: 43,
            max: 128,
        });
    }

    for (position, byte) in verifier.bytes().enumerate() {
        if !pkce_byte_allowed(byte) {
            return Err(PkceError::InvalidVerifierCharacter {
                char: byte as char,
                position,
            });
        }
    }

    Ok(())
}

/// Verifies a code verifier against an expected S256 code challenge in constant time.
///
/// # Errors
///
/// Returns [`PkceError`] if the verifier is malformed or the derived challenge does not match.
///
/// # Examples
///
/// ```
/// use skyauth::pkce::verify_pkce;
///
/// // RFC 7636 Appendix B Test Vector
/// let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
/// let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
///
/// assert!(verify_pkce(verifier, challenge).is_ok());
/// ```
pub fn verify_pkce(verifier: &str, expected_challenge: &str) -> Result<(), PkceError> {
    validate_verifier(verifier)?;

    if expected_challenge.len() != 43 {
        return Err(PkceError::InvalidChallengeLength {
            len: expected_challenge.len(),
        });
    }

    let derived = derive_s256_challenge(verifier);
    if constant_time_eq(derived.as_bytes(), expected_challenge.as_bytes()) {
        Ok(())
    } else {
        Err(PkceError::ChallengeMismatch)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_rfc7636_appendix_b_vector() {
        // RFC 7636 Appendix B official test vector
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let expected_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

        let pkce = PkcePair::from_verifier(verifier.to_string()).unwrap();
        assert_eq!(pkce.challenge, expected_challenge);
        assert_eq!(pkce.method, PkceMethod::S256);

        assert!(verify_pkce(verifier, expected_challenge).is_ok());
    }

    #[test]
    fn test_pkce_generate_roundtrip() {
        let pkce = PkcePair::generate();
        assert_eq!(pkce.verifier.len(), 43);
        assert_eq!(pkce.challenge.len(), 43);
        assert!(pkce.verify(&pkce.verifier).is_ok());
        assert!(verify_pkce(&pkce.verifier, &pkce.challenge).is_ok());
    }

    #[test]
    fn test_invalid_verifier_length() {
        // Less than 43 chars
        let short = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjX"; // 42 chars
        assert_eq!(short.len(), 42);
        assert!(matches!(
            validate_verifier(short),
            Err(PkceError::InvalidVerifierLength { len: 42, .. })
        ));

        // Greater than 128 chars
        let long = "a".repeat(129);
        assert!(matches!(
            validate_verifier(&long),
            Err(PkceError::InvalidVerifierLength { len: 129, .. })
        ));
    }

    #[test]
    fn test_invalid_verifier_characters() {
        // Space
        let with_space = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEj k";
        assert!(matches!(
            validate_verifier(with_space),
            Err(PkceError::InvalidVerifierCharacter {
                char: ' ',
                position: 41
            })
        ));

        // Plus sign
        let with_plus = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEj+k";
        assert!(matches!(
            validate_verifier(with_plus),
            Err(PkceError::InvalidVerifierCharacter {
                char: '+',
                position: 41
            })
        ));

        // Equals sign
        let with_eq = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEj=k";
        assert!(matches!(
            validate_verifier(with_eq),
            Err(PkceError::InvalidVerifierCharacter {
                char: '=',
                position: 41
            })
        ));
    }

    #[test]
    fn test_challenge_mismatch() {
        let pkce = PkcePair::generate();
        let wrong_challenge = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        assert!(matches!(
            verify_pkce(&pkce.verifier, wrong_challenge),
            Err(PkceError::ChallengeMismatch)
        ));
    }

    proptest! {
        #[test]
        fn prop_valid_verifier_always_verifies(
            verifier in "[A-Za-z0-9\\-._~]{43,128}"
        ) {
            let challenge = derive_s256_challenge(&verifier);
            prop_assert!(verify_pkce(&verifier, &challenge).is_ok());
        }

        #[test]
        fn prop_mutated_challenge_fails_verification(
            verifier in "[A-Za-z0-9\\-._~]{43,128}",
            mutate_idx in 0usize..43
        ) {
            let mut challenge_chars: Vec<char> = derive_s256_challenge(&verifier).chars().collect();
            let original_char = challenge_chars[mutate_idx];
            let replacement = if original_char == 'A' { 'B' } else { 'A' };
            challenge_chars[mutate_idx] = replacement;
            let mutated_challenge: String = challenge_chars.into_iter().collect();

            prop_assert!(verify_pkce(&verifier, &mutated_challenge).is_err());
        }
    }
}
