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
//! | **Single-Use State** | State token transitions from `Pending` to `Consumed` exactly once (replace-on-insert semantics matching the production store) | [`verus_contracts`] | [`formal_models::OAuthStateTransitionModel`] | [`kani_harnesses::proof_single_use_state_consumption`] |
//! | **SSRF Non-Bypassability (IPv4)** | No restricted IPv4 can pass — proven over the **shipped kernel** for every symbolic IPv4 address | [`verus_kernels`] (kernel-bound) + [`verus_contracts`] | [`formal_models::SsrfFormalSpec`] | [`kani_harnesses::proof_ssrf_restricted_ip_rejection`] |
//! | **SSRF Non-Bypassability (IPv6)** | Every IPv6 family theorem (mapped↔IPv4 reduction, 6to4 embedded parity, Teredo, ULA, link-local, multicast, documentation, unspecified/loopback) over the **shipped kernel** | [`verus_kernels`] (kernel-bound) | [`formal_models::SsrfFormalSpec`] | [`kani_harnesses::proof_ipv6_adapter_refinement`] |
//! | **PKCE S256 Bounds** | $43 \le \text{len} \le 128$, unreserved character domain, 43-char challenge | [`verus_contracts`] | [`formal_models::PkceFormalSpec`] | [`kani_harnesses::proof_pkce_s256_verifier_bounds`] + refinement over the shipped byte validator |
//! | **PKCE Validator Refinement** | Shipped byte-level validator ≡ formal spec (accept iff spec accepts), incl. violation-position accuracy | — | [`formal_models::PkceFormalSpec`] | [`kani_harnesses::proof_pkce_validator_refinement`] |
//! | **Constant-Time Eq** | XOR/accumulator evaluation $\iff$ element-wise equality (over the symbolic two-octet model) | [`verus_contracts`] | [`formal_models::ConstantTimeEqSpec`] | [`kani_harnesses::proof_constant_time_eq_soundness`] |
//! | **DPoP HTU Invariants** | Component-level assembly invariants (scheme-aware port rules, no query/fragment) — exhaustive over the concrete domain | — (String heap model makes CBMC cost explode; measured >20 GB, see harness docs)³ | [`formal_models::DPoPHtuFormalSpec`] | [`kani_harnesses::proof_dpop_htu_normalization_invariants`]³ |
//! | **DPoP `jti` Admission Bound** | Empty reject, >`MAX_JTI_LENGTH` reject, at-cap admit over the shipped bound constant | — | — | [`kani_harnesses::proof_jti_admission_bound`] |
//!
//! ³ The HTU harness runs deterministically through `formal_verification_tests.rs`, exhaustive
//!   over the concrete decision domain (both schemes × all port classes × boundary paths).
//!   Symbolic execution was attempted twice and is intentionally disabled: the `Url::parse`
//!   wrapper hits an upstream Kani compiler ICE, and the component kernel's `String` heap
//!   model explodes CBMC memory (measured: >20 GB symbolic port; >15 min at 4+ GB on an
//!   8-leaf concrete domain). See the harness doc comment and
//!   `VERIFICATION_UPGRADE_PLAN.md` Phase 3.
//!
//! The [`kernels`] module is the bridge between the empirical and formal layers: pure,
//! dependency-light functions extracted from `ssrf.rs`, `crypto.rs`, `pkce.rs`, `dpop.rs`,
//! and `client.rs` (re-exported at their original paths), compiled under both rustc and
//! Verus via the dual-representation pattern documented in `VERIFICATION_UPGRADE_PLAN.md`.

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
