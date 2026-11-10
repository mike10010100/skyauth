//! ATProto Service Auth (`com.atproto.server.getServiceAuth`) Multikey & JOSE curve-binding kernels.
//!
//! This module uses the **dual-representation single-source pattern** (see
//! `VERIFICATION_UPGRADE_PLAN.md`):
//!
//! - Under Verus (`cfg(verus)`/`cfg(verus_keep_ghost)`): the functions are
//!   compiled inside `verus!{}` with `ensures` postconditions checked by the
//!   Z3-backed verifier — the proofs bind to these **shipped** functions.
//! - Under plain rustc: the same function bodies compile without any Verus
//!   syntax, so the crate has no `vstd` dependency.
//!
//! ## Security Invariants Proven
//!
//! 1. **Multikey Prefix & Length Disambiguation**:
//!    - 35-byte `[0xe7, 0x01, 0x02|0x03, ...]` is classified as `secp256k1` (`CURVE_SECP256K1 = 1`) with SEC1 offset `2`.
//!    - 34-byte `[0xe7, 0x02|0x03, ...]` is classified as legacy `secp256k1` (`CURVE_SECP256K1 = 1`) with SEC1 offset `1`.
//!    - 35-byte `[0x80, 0x24, 0x02|0x03, ...]` is classified as `P-256` (`CURVE_P256 = 2`) with SEC1 offset `2`.
//!    - Every other length, prefix, or non-compressed SEC1 tag (`!= 0x02 && != 0x03`) is rejected (`CURVE_NONE = 0`, offset `0`).
//! 2. **Strict Curve-to-JOSE-Algorithm Binding (Zero Cross-Curve Confusion)**:
//!    - `ES256K` (`ALG_ES256K = 1`) is accepted iff the DID document key is `secp256k1` (`CURVE_SECP256K1 = 1`).
//!    - `ES256` (`ALG_ES256 = 2`) is accepted iff the DID document key is `P-256` (`CURVE_P256 = 2`).
//!    - Cross-curve combinations (`(1, 2)` and `(2, 1)`) and unknown algorithms (`0`) are unconditionally rejected.
//! 3. **Overflow-Safe Expiration Window**:
//!    - `is_service_jwt_exp_valid(exp, now_secs, leeway_secs)` accepts iff `now_secs <= exp.saturating_add(leeway_secs)` without arithmetic overflow.

#[cfg(any(verus, verus_keep_ghost))]
use vstd::prelude::*;

#[cfg(any(verus, verus_keep_ghost))]
verus! {

/// Verus spec: `tag` is a valid SEC1 compressed elliptic-curve point tag (`0x02` even Y or `0x03` odd Y).
pub open spec fn spec_is_compressed_sec1_tag(tag: u8) -> bool {
    tag == 0x02 || tag == 0x03
}

/// Verus spec: classifies a Multikey byte payload header `(len, b0, b1, b2)` into
/// `0` (`CURVE_NONE`), `1` (`CURVE_SECP256K1`), or `2` (`CURVE_P256`).
pub open spec fn spec_classify_multikey_header(len: usize, b0: u8, b1: u8, b2: u8) -> u8 {
    if len == 35 && b0 == 0xe7 && b1 == 0x01 && spec_is_compressed_sec1_tag(b2) {
        1u8
    } else if len == 34 && b0 == 0xe7 && spec_is_compressed_sec1_tag(b1) {
        1u8
    } else if len == 35 && b0 == 0x80 && b1 == 0x24 && spec_is_compressed_sec1_tag(b2) {
        2u8
    } else {
        0u8
    }
}

/// Verus spec: returns the byte offset (`1` or `2`) of the 33-byte compressed SEC1 public key
/// within a valid Multikey payload, or `0` if invalid.
pub open spec fn spec_multikey_sec1_offset(len: usize, b0: u8, b1: u8, b2: u8) -> usize {
    if len == 35 && b0 == 0xe7 && b1 == 0x01 && spec_is_compressed_sec1_tag(b2) {
        2usize
    } else if len == 34 && b0 == 0xe7 && spec_is_compressed_sec1_tag(b1) {
        1usize
    } else if len == 35 && b0 == 0x80 && b1 == 0x24 && spec_is_compressed_sec1_tag(b2) {
        2usize
    } else {
        0usize
    }
}

/// Verus spec: strict curve-to-JOSE-algorithm binding predicate.
pub open spec fn spec_is_alg_bound_to_curve(curve_id: u8, alg_id: u8) -> bool {
    (curve_id == 1 && alg_id == 1) || (curve_id == 2 && alg_id == 2)
}

/// Verus spec: overflow-safe JWT expiration check (`now_secs <= exp + leeway_secs`).
pub open spec fn spec_is_service_jwt_exp_valid(exp: u64, now_secs: u64, leeway_secs: u64) -> bool {
    (now_secs as int) <= (exp as int) + (leeway_secs as int)
}

/// Verus spec: overflow-safe RFC 9068 § 4 access-token expiration check (`now_secs < exp + leeway_secs`).
/// At the exact boundary `now_secs == exp + leeway_secs`, the token is expired.
pub open spec fn spec_is_access_jwt_exp_valid(exp: u64, now_secs: u64, leeway_secs: u64) -> bool {
    (now_secs as int) < (exp as int) + (leeway_secs as int)
}

/// Returns `true` iff `tag` is a valid SEC1 compressed public key prefix (`0x02` or `0x03`).
#[must_use]
#[inline]
pub const fn is_compressed_sec1_tag(tag: u8) -> (r: bool)
    ensures r == spec_is_compressed_sec1_tag(tag)
{
    tag == 0x02 || tag == 0x03
}

/// Classifies a Multikey byte payload header `(len, b0, b1, b2)` into
/// `CURVE_SECP256K1` (`1`), `CURVE_P256` (`2`), or `CURVE_NONE` (`0`).
#[must_use]
#[inline]
pub const fn classify_multikey_header(len: usize, b0: u8, b1: u8, b2: u8) -> (r: u8)
    ensures r == spec_classify_multikey_header(len, b0, b1, b2)
{
    if (len == 35 && b0 == 0xe7 && b1 == 0x01 && (b2 == 0x02 || b2 == 0x03))
        || (len == 34 && b0 == 0xe7 && (b1 == 0x02 || b1 == 0x03))
    {
        1
    } else if len == 35 && b0 == 0x80 && b1 == 0x24 && (b2 == 0x02 || b2 == 0x03) {
        2
    } else {
        0
    }
}

/// Returns the byte offset (`1` or `2`) of the 33-byte SEC1 compressed public key
/// within a Multikey payload, or `0` if the header is invalid.
#[must_use]
#[inline]
pub const fn multikey_sec1_offset(len: usize, b0: u8, b1: u8, b2: u8) -> (r: usize)
    ensures r == spec_multikey_sec1_offset(len, b0, b1, b2)
{
    if len == 35
        && (b2 == 0x02 || b2 == 0x03)
        && ((b0 == 0xe7 && b1 == 0x01) || (b0 == 0x80 && b1 == 0x24))
    {
        2
    } else if len == 34 && b0 == 0xe7 && (b1 == 0x02 || b1 == 0x03) {
        1
    } else {
        0
    }
}

/// Returns `true` iff the JOSE algorithm identifier `alg_id` is strictly bound to `curve_id`.
#[must_use]
#[inline]
pub const fn is_alg_bound_to_curve(curve_id: u8, alg_id: u8) -> (r: bool)
    ensures r == spec_is_alg_bound_to_curve(curve_id, alg_id)
{
    (curve_id == 1 && alg_id == 1) || (curve_id == 2 && alg_id == 2)
}

/// Returns `true` iff `now_secs` is within `exp + leeway_secs` (overflow-safe).
#[must_use]
#[inline]
pub const fn is_service_jwt_exp_valid(exp: u64, now_secs: u64, leeway_secs: u64) -> (r: bool)
    ensures r == spec_is_service_jwt_exp_valid(exp, now_secs, leeway_secs)
{
    if exp > u64::MAX - leeway_secs {
        true
    } else {
        now_secs <= exp + leeway_secs
    }
}

/// Returns `true` iff `now_secs` is strictly before `exp + leeway_secs` (RFC 9068 § 4 / RFC 7519 § 4.1.4, overflow-safe).
#[must_use]
#[inline]
pub const fn is_access_jwt_exp_valid(exp: u64, now_secs: u64, leeway_secs: u64) -> (r: bool)
    ensures r == spec_is_access_jwt_exp_valid(exp, now_secs, leeway_secs)
{
    if exp > u64::MAX - leeway_secs {
        true
    } else {
        now_secs < exp + leeway_secs
    }
}

} // verus!

#[cfg(not(any(verus, verus_keep_ghost)))]
mod plain {
    /// Rejected / unrecognized Multikey curve identifier.
    pub const CURVE_NONE: u8 = 0;
    /// `secp256k1` (`ES256K`) curve identifier.
    pub const CURVE_SECP256K1: u8 = 1;
    /// NIST `P-256` (`ES256`) curve identifier.
    pub const CURVE_P256: u8 = 2;

    /// Unrecognized or unsupported JOSE `alg` identifier.
    pub const ALG_NONE: u8 = 0;
    /// Alias for unrecognized JOSE `alg` identifier.
    pub const ALG_UNKNOWN: u8 = 0;
    /// JOSE `ES256K` (`secp256k1`) algorithm identifier.
    pub const ALG_ES256K: u8 = 1;
    /// JOSE `ES256` (`P-256`) algorithm identifier.
    pub const ALG_ES256: u8 = 2;

    /// Returns `true` iff `tag` is a valid SEC1 compressed public key prefix (`0x02` or `0x03`).
    #[must_use]
    #[inline]
    pub const fn is_compressed_sec1_tag(tag: u8) -> bool {
        tag == 0x02 || tag == 0x03
    }

    /// Classifies a Multikey byte payload header `(len, b0, b1, b2)` into
    /// `CURVE_SECP256K1` (`1`), `CURVE_P256` (`2`), or `CURVE_NONE` (`0`).
    #[must_use]
    #[inline]
    pub const fn classify_multikey_header(len: usize, b0: u8, b1: u8, b2: u8) -> u8 {
        if (len == 35 && b0 == 0xe7 && b1 == 0x01 && (b2 == 0x02 || b2 == 0x03))
            || (len == 34 && b0 == 0xe7 && (b1 == 0x02 || b1 == 0x03))
        {
            1
        } else if len == 35 && b0 == 0x80 && b1 == 0x24 && (b2 == 0x02 || b2 == 0x03) {
            2
        } else {
            0
        }
    }

    /// Returns the byte offset (`1` or `2`) of the 33-byte SEC1 compressed public key
    /// within a Multikey payload, or `0` if the header is invalid.
    #[must_use]
    #[inline]
    pub const fn multikey_sec1_offset(len: usize, b0: u8, b1: u8, b2: u8) -> usize {
        if len == 35
            && (b2 == 0x02 || b2 == 0x03)
            && ((b0 == 0xe7 && b1 == 0x01) || (b0 == 0x80 && b1 == 0x24))
        {
            2
        } else if len == 34 && b0 == 0xe7 && (b1 == 0x02 || b1 == 0x03) {
            1
        } else {
            0
        }
    }

    /// Returns `true` iff the JOSE algorithm identifier `alg_id` is strictly bound to `curve_id`.
    #[must_use]
    #[inline]
    pub const fn is_alg_bound_to_curve(curve_id: u8, alg_id: u8) -> bool {
        (curve_id == 1 && alg_id == 1) || (curve_id == 2 && alg_id == 2)
    }

    /// Returns `true` iff `now_secs` is within `exp + leeway_secs` (overflow-safe).
    #[must_use]
    #[inline]
    pub const fn is_service_jwt_exp_valid(exp: u64, now_secs: u64, leeway_secs: u64) -> bool {
        if exp > u64::MAX - leeway_secs {
            true
        } else {
            now_secs <= exp + leeway_secs
        }
    }

    /// Returns `true` iff `now_secs` is strictly before `exp + leeway_secs` (RFC 9068 § 4 / RFC 7519 § 4.1.4, overflow-safe).
    #[must_use]
    #[inline]
    pub const fn is_access_jwt_exp_valid(exp: u64, now_secs: u64, leeway_secs: u64) -> bool {
        if exp > u64::MAX - leeway_secs {
            true
        } else {
            now_secs < exp + leeway_secs
        }
    }

    /// Adapter over [`classify_multikey_header`] and [`multikey_sec1_offset`] for a raw Multikey byte slice.
    ///
    /// Returns `Some((curve_id, sec1_33_byte_slice))` where `curve_id` is [`CURVE_SECP256K1`] or [`CURVE_P256`],
    /// or `None` if the prefix, length, or SEC1 compression tag byte is invalid.
    #[must_use]
    #[inline]
    pub fn classify_multikey_bytes(bytes: &[u8]) -> Option<(u8, &[u8])> {
        if bytes.len() < 3 {
            return None;
        }
        let len = bytes.len();
        let b0 = bytes[0];
        let b1 = bytes[1];
        let b2 = bytes[2];
        let curve = classify_multikey_header(len, b0, b1, b2);
        let offset = multikey_sec1_offset(len, b0, b1, b2);
        if curve == CURVE_NONE || offset == 0 {
            None
        } else {
            Some((curve, &bytes[offset..]))
        }
    }

    /// Maps a JOSE `alg` header string (`"ES256K"` or `"ES256"`) to its numeric kernel identifier.
    #[must_use]
    #[inline]
    pub fn alg_id_from_str(alg: &str) -> u8 {
        match alg {
            "ES256K" => ALG_ES256K,
            "ES256" => ALG_ES256,
            _ => ALG_NONE,
        }
    }
}

#[cfg(not(any(verus, verus_keep_ghost)))]
pub use plain::{
    alg_id_from_str, classify_multikey_bytes, classify_multikey_header, is_access_jwt_exp_valid,
    is_alg_bound_to_curve, is_compressed_sec1_tag, is_service_jwt_exp_valid, multikey_sec1_offset,
    ALG_ES256, ALG_ES256K, ALG_NONE, ALG_UNKNOWN, CURVE_NONE, CURVE_P256, CURVE_SECP256K1,
};

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]
mod tests {
    use super::*;

    #[test]
    fn sec1_tag_classification() {
        assert!(is_compressed_sec1_tag(0x02));
        assert!(is_compressed_sec1_tag(0x03));
        for b in [0x00u8, 0x01, 0x04, 0xff] {
            assert!(!is_compressed_sec1_tag(b));
        }
    }

    #[test]
    fn multikey_header_and_slice_classification() {
        // 35-byte 2-byte varint secp256k1
        let mut varint_k256 = [0u8; 35];
        varint_k256[0] = 0xe7;
        varint_k256[1] = 0x01;
        varint_k256[2] = 0x02;
        assert_eq!(
            classify_multikey_bytes(&varint_k256),
            Some((CURVE_SECP256K1, &varint_k256[2..]))
        );

        // 34-byte legacy 1-byte secp256k1
        let mut legacy_k256 = [0u8; 34];
        legacy_k256[0] = 0xe7;
        legacy_k256[1] = 0x03;
        assert_eq!(
            classify_multikey_bytes(&legacy_k256),
            Some((CURVE_SECP256K1, &legacy_k256[1..]))
        );

        // 35-byte 2-byte varint P-256
        let mut varint_p256 = [0u8; 35];
        varint_p256[0] = 0x80;
        varint_p256[1] = 0x24;
        varint_p256[2] = 0x02;
        assert_eq!(
            classify_multikey_bytes(&varint_p256),
            Some((CURVE_P256, &varint_p256[2..]))
        );

        // Invalid cases: short slice, uncompressed 0x04 tag, wrong length
        assert_eq!(classify_multikey_bytes(&[0xe7, 0x01]), None);
        varint_k256[2] = 0x04;
        assert_eq!(classify_multikey_bytes(&varint_k256), None);
        assert_eq!(
            classify_multikey_header(34, 0xe7, 0x01, 0x02),
            CURVE_NONE,
            "34-byte [0xe7, 0x01, ...] must not be accepted as a valid SEC1 compressed point"
        );
    }

    #[test]
    fn curve_to_alg_binding_rejects_cross_curve() {
        assert!(is_alg_bound_to_curve(CURVE_SECP256K1, ALG_ES256K));
        assert!(is_alg_bound_to_curve(CURVE_P256, ALG_ES256));
        assert!(!is_alg_bound_to_curve(CURVE_P256, ALG_ES256K));
        assert!(!is_alg_bound_to_curve(CURVE_SECP256K1, ALG_ES256));
        assert!(!is_alg_bound_to_curve(CURVE_SECP256K1, ALG_NONE));
        assert!(!is_alg_bound_to_curve(CURVE_NONE, ALG_ES256K));
        assert_eq!(alg_id_from_str("ES256K"), ALG_ES256K);
        assert_eq!(alg_id_from_str("ES256"), ALG_ES256);
        assert_eq!(alg_id_from_str("RS256"), ALG_NONE);
        assert_eq!(alg_id_from_str("none"), ALG_NONE);
    }

    #[test]
    fn jwt_exp_window_handles_overflow_and_boundaries() {
        assert!(is_service_jwt_exp_valid(1000, 1060, 60));
        assert!(!is_service_jwt_exp_valid(1000, 1061, 60));
        assert!(is_service_jwt_exp_valid(u64::MAX, u64::MAX, 60));
    }
}
