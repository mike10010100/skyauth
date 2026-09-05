//! PKCE code-verifier validation kernels (byte-oriented).
//!
//! RFC 7636 § 4.1: the code verifier must be 43–128 characters from the
//! unreserved set `[A-Za-z0-9-._~]`. The byte-level core exists so symbolic
//! proof harnesses can verify the *shipped* validation logic without the UTF-8
//! unwind issues `&str` triggers under Kani; the `&str` production wrapper in
//! `pkce.rs` delegates here and is byte-for-byte equivalent (`&str` bytes are
//! validated char-class-wise over `bytes()`).

/// The minimum RFC 7636 code verifier length in characters/bytes.
pub const VERIFIER_MIN_LENGTH: usize = 43;
/// The maximum RFC 7636 code verifier length in characters/bytes.
pub const VERIFIER_MAX_LENGTH: usize = 128;

/// Returns `true` iff `byte` belongs to the RFC 7636 unreserved character set
/// `[A-Za-z0-9-._~]` (i.e. ASCII alphanumeric or one of `-._~`).
///
/// This is the single source of truth for the character domain; both the
/// production `&str` validator and the formal spec model delegate here.
#[must_use]
#[inline]
pub const fn is_unreserved_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'.' || byte == b'_' || byte == b'~'
}

/// Validates code-verifier length bounds.
#[must_use]
#[inline]
pub const fn is_valid_verifier_length(len: usize) -> bool {
    len >= VERIFIER_MIN_LENGTH && len <= VERIFIER_MAX_LENGTH
}

/// Byte-oriented code-verifier validation failure, with no sentinel ambiguity:
/// the all-256-byte-value adversarial test (tier5) proved that `0x00` is a
/// legitimate *character* byte that must be reported as a character violation,
/// so length violations cannot overload the offending-byte field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifierByteError {
    /// Length not in `[43, 128]`; carries the actual length.
    InvalidLength(usize),
    /// Disallowed byte at the given position.
    ///
    /// `byte`: the offending byte value. `position`: its index in the verifier.
    InvalidCharacter {
        /// The offending byte value (may be any of `0..=255`).
        byte: u8,
        /// The byte index at which the violation occurred.
        position: usize,
    },
}

/// Byte-oriented code-verifier validation core.
///
/// Returns `Ok(())` iff the length is in `[43, 128]` and every byte is in the
/// unreserved set; otherwise returns the first violation as a
/// [`VerifierByteError`]. The production `&str` wrapper maps these onto typed
/// `PkceError` variants.
///
/// # Errors
///
/// Returns [`VerifierByteError::InvalidLength`] for length violations and
/// [`VerifierByteError::InvalidCharacter`] for character violations.
pub fn validate_verifier_bytes(verifier: &[u8]) -> Result<(), VerifierByteError> {
    let len = verifier.len();
    if !is_valid_verifier_length(len) {
        return Err(VerifierByteError::InvalidLength(len));
    }

    for (position, byte) in verifier.iter().copied().enumerate() {
        if !is_unreserved_byte(byte) {
            return Err(VerifierByteError::InvalidCharacter { byte, position });
        }
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]
mod tests {
    use super::*;

    #[test]
    fn length_bounds() {
        assert!(is_valid_verifier_length(43));
        assert!(is_valid_verifier_length(128));
        assert!(!is_valid_verifier_length(42));
        assert!(!is_valid_verifier_length(129));
        assert!(!is_valid_verifier_length(0));
    }

    #[test]
    fn byte_domain() {
        for b in b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~" {
            assert!(is_unreserved_byte(*b), "byte {b:#x} must be unreserved");
        }
        for b in [b' ', b'+', b'=', b'/', b'?', 0x00, 0x80, 0xff] {
            assert!(!is_unreserved_byte(b), "byte {b:#x} must be reserved");
        }
    }

    #[test]
    fn validate_bytes_agrees_with_str_validator() {
        // Agreement check across boundary lengths and illegal characters: the
        // `&str` production wrapper must delegate to this kernel with identical
        // accept/reject decisions.
        for len in [0usize, 1, 42, 43, 64, 128, 129, 200] {
            let v = "a".repeat(len);
            assert_eq!(
                validate_verifier_bytes(v.as_bytes()).is_ok(),
                crate::pkce::validate_verifier(&v).is_ok(),
                "divergence at length {len}"
            );
        }
        let mut bad = "a".repeat(42);
        bad.push('+');
        assert!(validate_verifier_bytes(bad.as_bytes()).is_err());
        assert!(crate::pkce::validate_verifier(&bad).is_err());
    }

    #[test]
    fn error_position_is_reported() {
        let mut v = "a".repeat(42);
        v.push('+');
        v.push('b');
        assert_eq!(v.len(), 44);
        let err = validate_verifier_bytes(v.as_bytes()).unwrap_err();
        assert_eq!(
            err,
            VerifierByteError::InvalidCharacter {
                byte: b'+',
                position: 42
            }
        );
    }

    #[test]
    fn nul_byte_is_character_violation_not_length_sentinel() {
        // Regression: byte 0x00 inside a length-valid verifier must be reported
        // as a character violation — never confusable with a length error.
        let mut v = vec![b'a'; 43];
        v[20] = 0x00;
        assert_eq!(
            validate_verifier_bytes(&v).unwrap_err(),
            VerifierByteError::InvalidCharacter {
                byte: 0,
                position: 20
            }
        );
    }
}
