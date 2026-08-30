//! Formal Specification & Verification Modeling Suite for `skyauth`.
//!
//! This module provides mathematical models, executable Hoare-logic formal contracts,
//! and bounded model checking harnesses with mandatory anti-vacuity reachability gates.
//!
//! ## Verification Architecture
//!
//! The verification suite is organized into two foundational layers:
//!
//! 1. **Executable Formal Contracts & Mathematical Models ([`verus_contracts`])**:
//!    - Pure mathematical models of state machines, character sets, and IP address spaces.
//!    - Explicit preconditions (`requires`), postconditions (`ensures`), and inductive loop
//!      invariants verifying state transition safety, deterministic bounds, and cryptographic
//!      soundness.
//!    - Hoare-logic specifications for single-use OAuth state consumption, PKCE S256 bounds,
//!      constant-time equality comparisons, and SSRF restricted IP space rejection.
//!
//! 2. **Bounded Model Checking Proof Harnesses ([`kani_harnesses`])**:
//!    - Symbolic execution harnesses using `kani::any()` and `kani::assume()` tagged with
//!      `#[cfg_attr(kani, kani::proof)]`.
//!    - **Mandatory Anti-Vacuity**: Every proof harness includes `kani::cover!()` reachability
//!      predicates to formally prove that all valid operational pathways and rejection branches
//!      are reachable (preventing false proofs arising from contradictory assumptions).
//!    - Covers atomic single-use state consumption, SSRF boundary filter non-bypassability,
//!      PKCE verifier length/character domain validity, constant-time equality soundness,
//!      and DPoP target URI (`htu`) normalization invariants.
//!
//! ## Invariants Formally Modeled & Verified
//!
//! | Invariant | Description | Formal Contract Model | Model Checking Harness |
//! |---|---|---|---|
//! | **Single-Use State** | State token transitions from `Pending` to `Consumed` exactly once | [`verus_contracts::OAuthStateTransitionModel`] | [`kani_harnesses::proof_single_use_state_consumption`] |
//! | **SSRF Non-Bypassability** | No RFC 1918, link-local, or cloud metadata IP can pass filters | [`verus_contracts::SsrfFormalSpec`] | [`kani_harnesses::proof_ssrf_restricted_ip_rejection`] |
//! | **PKCE S256 Bounds** | $43 \le \text{len} \le 128$, unreserved character domain, 43-char challenge | [`verus_contracts::PkceFormalSpec`] | [`kani_harnesses::proof_pkce_s256_verifier_bounds`] |
//! | **Constant-Time Eq** | $\text{ct\_eq}(a, b) \iff a == b$ with data-independent execution time | [`verus_contracts::ConstantTimeEqSpec`] | [`kani_harnesses::proof_constant_time_eq_soundness`] |
//! | **DPoP HTU Invariants** | Strips query/fragment, normalizes case and default ports | [`verus_contracts::DPoPHtuFormalSpec`] | [`kani_harnesses::proof_dpop_htu_normalization_invariants`] |

pub mod kani_harnesses;
pub mod verus_contracts;

pub use kani_harnesses::{
    proof_constant_time_eq_soundness, proof_dpop_htu_normalization_invariants,
    proof_pkce_s256_verifier_bounds, proof_single_use_state_consumption,
    proof_ssrf_restricted_ip_rejection, AntiVacuityCoverage,
};
pub use verus_contracts::{
    ConstantTimeEqSpec, DPoPHtuFormalSpec, OAuthStateTransitionModel, PkceFormalSpec,
    SsrfFormalSpec, StateTransitionStatus,
};
