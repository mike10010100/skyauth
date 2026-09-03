//! Formal Specification & Verification Suite for `skyauth`.
//!
//! This module provides deductive verification specifications ([`verus_contracts`]),
//! executable state transition models ([`formal_models`]), and bounded model checking
//! harnesses ([`kani_harnesses`]) with mandatory anti-vacuity reachability gates.
//!
//! ## Verification Architecture
//!
//! The formal verification suite is organized into three foundational layers:
//!
//! 1. **Deductive Verification Proofs (`verus!`) ([`verus_contracts`])**:
//!    - Pure mathematical models and Hoare-logic contracts verified with the Verus SMT engine (Z3).
//!    - Formally proves state machine single-use invariants, post-consumption terminality,
//!      SSRF IP boundary containment, and PKCE length/character domain bounds.
//!
//! 2. **Executable Formal Contracts & Transition Models ([`formal_models`])**:
//!    - Pure mathematical models of state machines, character sets, and IP address spaces.
//!    - Explicit preconditions (`requires`), postconditions (`ensures`), and inductive loop
//!      invariants executable under standard Rust test suites.
//!
//! 3. **Bounded Model Checking Proof Harnesses ([`kani_harnesses`])**:
//!    - Symbolic execution harnesses using `kani::any()` and `kani::assume()` tagged with
//!      `#[cfg_attr(kani, kani::proof)]`.
//!    - **Mandatory Anti-Vacuity**: Every proof harness includes `kani::cover!()` reachability
//!      predicates to formally prove that all valid operational pathways and rejection branches
//!      are reachable (preventing false proofs arising from contradictory assumptions).
//!
//! ## Invariants Formally Modeled & Verified
//!
//! | Invariant | Description | Verus Deductive Proofs | Formal Model | Model Checking Harness |
//! |---|---|---|---|---|
//! | **Single-Use State** | State token transitions from `Pending` to `Consumed` exactly once | [`verus_contracts`] | [`formal_models::OAuthStateTransitionModel`] | [`kani_harnesses::proof_single_use_state_consumption`] |
//! | **SSRF Non-Bypassability** | No RFC 1918, link-local, or cloud metadata IP can pass filters (Verus proof covers the symbolic IPv4 model; the Kani harness additionally covers IPv6 classes and the acceptance path) | [`verus_contracts`] | [`formal_models::SsrfFormalSpec`] | [`kani_harnesses::proof_ssrf_restricted_ip_rejection`] |
//! | **PKCE S256 Bounds** | $43 \le \text{len} \le 128$, unreserved character domain, 43-char challenge | [`verus_contracts`] | [`formal_models::PkceFormalSpec`] | [`kani_harnesses::proof_pkce_s256_verifier_bounds`] |
//! | **Constant-Time Eq** | XOR/accumulator evaluation $\iff$ element-wise equality (over the symbolic two-octet model) | [`verus_contracts`] | [`formal_models::ConstantTimeEqSpec`] | [`kani_harnesses::proof_constant_time_eq_soundness`] |
//! | **DPoP HTU Invariants** | Strips query/fragment; protocol port/case rules (scheme-prefix and port checks only) | — (deductive proof omitted; symbolic execution hits an upstream Kani ICE)¹ | [`formal_models::DPoPHtuFormalSpec`] | [`kani_harnesses::proof_dpop_htu_normalization_invariants`]² |
//!
//! ¹ The HTU row intentionally has no Verus proof; the executable model covers the properties.
//! ² The HTU harness runs deterministically through `formal_verification_tests.rs`; symbolic
//!   execution is disabled due to an upstream Kani compiler ICE (see the harness doc comment).

pub mod formal_models;
pub mod kani_harnesses;
pub mod verus_contracts;

pub use formal_models::{
    ConstantTimeEqSpec, DPoPHtuFormalSpec, OAuthStateTransitionModel, PkceFormalSpec,
    SsrfFormalSpec, StateTransitionStatus,
};
pub use kani_harnesses::{
    proof_constant_time_eq_soundness, proof_dpop_htu_normalization_invariants,
    proof_pkce_s256_verifier_bounds, proof_single_use_state_consumption,
    proof_ssrf_restricted_ip_rejection, AntiVacuityCoverage,
};
