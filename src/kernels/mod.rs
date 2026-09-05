//! Pure, dependency-light security kernels shared by `skyauth` and its formal
//! verification layers.
//!
//! Every function in this module is a *pure* function of its inputs with no I/O,
//! no async, and no heap allocation (except where explicitly noted), making the
//! module the direct target for deductive (Verus) and bounded-model-checking
//! (Kani) proofs over the **shipped production code** rather than over mirrored
//! spec copies.
//!
//! ## Design rules
//!
//! 1. **Verbatim preservation**: kernel bodies are moved verbatim from their
//!    original modules (`ssrf.rs`, `crypto.rs`, `pkce.rs`, `dpop.rs`,
//!    `client.rs`); the original modules re-export them so every public path is
//!    unchanged.
//! 2. **SMT-friendly cores**: where the natural Rust type (`Ipv4Addr`,
//!    `Ipv6Addr`) hides its representation behind non-`const` methods opaque to
//!    SMT solvers (`octets()`, `to_ipv4_mapped()`, `is_unspecified()`), the
//!    kernel exposes an octet/segment-level `const` core, and the std-type
//!    adapter is a thin, provably equivalent wrapper.
//! 3. **Fail-closed**: validation kernels reject on any anomaly (empty input,
//!    over-length input, disallowed characters).
//!
//! Proof layers referencing this module:
//! - [`crate::verification::kani_harnesses`] — bounded symbolic refinement proofs.
//! - [`crate::verification::verus_contracts`] — deductive spec + theorems.

pub mod ct_eq;
pub mod htu_components;
pub mod ip_filter;
pub mod nsid_bytes;
pub mod pkce_bytes;
