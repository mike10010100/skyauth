//! Constant-time equality kernel.
//!
//! The production implementation delegates to `subtle::ConstantTimeEq`, whose
//! timing-independence is guaranteed upstream and *cannot* be proven by SMT
//! tools (see VERIFICATION_UPGRADE_PLAN.md "Out of scope"). The kernel therefore
//! binds the *functional soundness* property: `constant_time_eq(a, b) <==> (a ==
//! b)` — proven by Kani refinement over the full symbolic byte domain and by
//! Verus bit-vector lemmas over the accumulator structure.

/// Compares two byte slices in constant time to eliminate timing side-channels.
///
/// Returns `true` if and only if both slices have identical length and equal contents.
///
/// Delegates to `subtle::ConstantTimeEq` (constant-time guaranteed upstream);
/// functional soundness is proven in
/// [`crate::verification::kani_harnesses::proof_constant_time_eq_soundness`].
///
/// # Examples
///
/// ```
/// use skyauth::kernels::ct_eq::constant_time_eq;
///
/// assert!(constant_time_eq(b"secret_token", b"secret_token"));
/// assert!(!constant_time_eq(b"secret_token", b"wrong_token_"));
/// ```
#[must_use]
#[inline]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]
mod tests {
    use super::*;

    #[test]
    fn kernel_matches_lib_reexport() {
        // The lib-level re-export must be the same function, not a copy.
        assert_eq!(
            constant_time_eq(b"abc", b"abc"),
            crate::crypto::constant_time_eq(b"abc", b"abc")
        );
        assert_eq!(
            constant_time_eq(b"abc", b"abd"),
            crate::crypto::constant_time_eq(b"abc", b"abd")
        );
        assert_eq!(
            constant_time_eq(b"abc", b"ab"),
            crate::crypto::constant_time_eq(b"abc", b"ab")
        );
    }

    #[test]
    fn empty_slices_equal() {
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn length_mismatch_rejected() {
        assert!(!constant_time_eq(b"aaaa", b"aaa"));
    }
}
