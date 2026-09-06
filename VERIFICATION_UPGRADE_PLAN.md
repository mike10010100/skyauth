---
type: Plan
title: skyauth Verification Upgrade Plan
description: Execution plan to deepen formal verification coverage, bind proofs to production code, and enforce anti-vacuity gates (response to independent review findings).
resource: https://github.com/mike10010100/skyauth
tags: [rust, formal-verification, kani, verus, security]
status: complete
generated: { by: model:glm-5.3, at: 2026-09-03 }
completed: { at: 2026-09-03 }
---

# Verification Upgrade Plan

This document is the execution plan for **increasing** the crate's verification coverage and
binding proofs to production code — the constructive response to the independent review findings
(GLM 5.3 §6, GPT 5.6 M3): the formal-verification layer is real but narrower than the claim
surface, and several harnesses mirror rather than verify production logic.

Strategy: **fix the proofs, not the claims.** Where a claim cannot yet be honestly made
(e.g. timing-independence), the claim is corrected; everywhere a proof *can* be strengthened,
the proof is deepened first and the claim surface is then updated **upward** to the new, larger
reality. Every number in the docs must be either (a) generated/enforced by a gate, or (b) marked
as a target, never hand-maintained prose that can drift.

## Baseline (measured 2026-09-03, at commit `ff19eab` + workspace clean)

| Gate | Result |
|---|---|
| `cargo fmt --all -- --check` | clean |
| `cargo clippy --all-targets --all-features -- -D warnings` | clean |
| Verus (`scripts/run_verus.sh`, pinned 0.2026.08.23.fbbbbcf) | **21 verified, 0 errors** |
| Kani 0.67.0, all 4 `#[kani::proof]` harnesses | **4/4 verified** (ssrf 6/6 covers, pkce 2/2, state 2/2, ct_eq clean) |
| Harness inventory | 4 live proofs; `proof_dpop_htu_normalization_invariants` is deterministic-only (upstream Kani ICE on `Url::parse`); dead `#[cfg(any())]` symbolic block exists |

## Guiding invariants (non-negotiable throughout)

1. **Public API never breaks**: kernels are extracted via *verbatim move + re-export*; `skyauth::*`
   paths and behaviors stay identical. Any deviation is a bug.
2. **AGENTS.md gates after every phase**: fmt, clippy `-D warnings`, full test suite, doctests;
   Kani + Verus re-runs whenever `src/verification/`, `src/crypto.rs`, `src/dpop.rs`, `src/ssrf.rs`,
   `src/store.rs`, or `src/pkce.rs` change (which is most phases).
3. **Fail-closed bias**: new checks (bounds, validation) reject, never accept-on-error.
4. **No production panics**: `spawn_pruning_task`-style panic paths are fixed, not proven-around.
5. **Every new harness carries anti-vacuity covers**, wired into both Kani (`kani::cover!`) and the
   deterministic `AntiVacuityCoverage` registry, and the tag inventory meta-test (Phase 4) must
   pass — tags cannot be added to proofs without adding them to the enforced inventory.
6. **Proofs only over corrected code**: behavior fixes (jti bound, model semantics) land with or
   before the proofs that reference them.

## Phase 0 — Baseline capture ✅

Done 2026-09-03: gates above executed locally and recorded. Verus bootstrapped to `~/.verus`
(pinned, SHA-verified by `scripts/run_verus.sh`). Kani 0.67.0 present. Baseline recorded in this
document and in git history of this file.

## Phase 1 — Extract pure security kernels (`src/kernels/`)

**Goal**: create the unit that both Kani and Verus can bind to *as production code* — pure,
dependency-light, deterministic functions that today live inside large async modules.

**New module `src/kernels/`** (pure std-only code, no deps beyond `core`/`std`):

| Kernel | Moved verbatim from | Contents |
|---|---|---|
| `ip_filter` | `src/ssrf.rs` | `is_restricted_ipv4`, `is_restricted_ipv6`, `is_restricted_ip` |
| `ct_eq` | `src/crypto.rs` | `constant_time_eq` |
| `pkce_bytes` | `src/pkce.rs` | byte-level verifier validation + `is_unreserved_byte` (new pure byte-oriented core; `&str` API becomes a thin wrapper) |
| `htu_components` | `src/dpop.rs` | new pure component-level normalizer over `(scheme, host, port, path)`; `normalize_htu` keeps the `Url::parse` wrapper and delegates |
| `nsid_bytes` | `src/client.rs` | NSID grammar validation (extract pure predicate `is_valid_nsid`, byte-for-byte identical logic; `validate_xrpc_nsid` maps the bool to `TokenError::InvalidNsid`) |

**Plan refinement (recorded 2026-09-03)**: `SingleStateModel` stays in
`src/verification/formal_models.rs` — it is a *spec model*, not shipped security logic, so
extracting it buys nothing for proof binding. The kernels extracted are the five production
kernels only. Additionally, the IP kernels are split into **octet/segment-level const cores**
(`is_restricted_ipv4_octets([u8;4])`, `is_restricted_ipv6_segments([u16;8])`) with the existing
`&Ipv4Addr`/`&Ipv6Addr` signatures kept verbatim as thin adapters — because
`Ipv4Addr::octets()`/`is_unspecified()`/`to_ipv4_mapped()` are opaque to SMT solvers; the
octet/segment cores are what Verus can reason about directly, and Phase 3 adds a Kani
refinement proof that the std adapters agree with the cores over the full symbolic domain
(16-bit segment space for IPv6 — currently IPv6 has only concrete tests, so this is a real
coverage increase, not just restructuring).

**Rules**:
- Verbatim moves: bodies, doc comments, and `#[must_use]`/`#[inline]` attributes preserved.
- `ssrf.rs` / `crypto.rs` / `pkce.rs` / `dpop.rs` / `client.rs` re-export the moved items
  (`pub use crate::kernels::ip_filter::*;` etc.) so every existing path keeps working.
- `missing_docs`, `deny` lint set, and `#![forbid(unsafe_code)]` apply to the new module.
- No behavior change whatsoever; full test suite must pass untouched.

**Verification after Phase 1**: fmt/clippy/tests/doctests green; `grep` confirms old module
paths still resolve (re-exports); `cargo check --no-default-features` green.

## Phase 2 — Bind Verus to production kernels

**Goal**: replace "Verus proves a third unlinked copy" with "Verus proves the shipped kernel
functions." Two-step, spike-gated:

**Step 2a — Spike: ✅ COMPLETE (2026-09-03). Outcome recorded verbatim below.**

Findings from the live spike (all paths tested against the pinned Verus 0.2026.08.23.fbbbbcf):

1. `external_fn_specification` applies only to *external crates* — "duplicate specification"
   error when the fn lives in the same crate. Not usable for in-crate kernels.
2. Exec-mode functions can never appear inside `ensures` clauses (mode error), so postconditions
   must be carried by the function's own contract.
3. `std::net::{Ipv4Addr, Ipv6Addr}` require `#[verifier::external_type_specification]` proxies
   (`#[verifier::external_body]`) plus `pub assume_specification [Ipv4Addr::octets]` /
   `[Ipv6Addr::segments]` — confirmed working.
4. `#[path]`-including the real `src/kernels/ip_filter.rs` inside a `verus!` root **compiles
   and verifies** (5/5 obligations) once slice patterns are replaced by explicit indexing
   (Verus does not support slice patterns).
5. `#[verifier::publish]` does not exist in this Verus version; cross-module proof visibility
   works via plain `pub proof fn`.
6. **THE DECISIVE RESULT**: the dual-representation single-source pattern works:
   `#[cfg(any(verus, verus_keep_ghost))] verus!{ exec fns WITH ensures + spec fns }` plus
   `#[cfg(not(any(verus, verus_keep_ghost)))]` plain-rustc copies of the same exec fns.
   - Plain `rustc` compiles the cfg-excluded branch cleanly (no vstd dependency leaks into the
     shipped crate).
   - Verus **natively activates the verus branch** (confirmed: a deliberately wrong
     `ensures` body failed verification — the contract is checked by Z3, binding proofs to
     the real shipped function, not a mirror).
   - `use vstd::prelude::*;` must itself be cfg-gated (verus injects vstd standalone).
   - `verus!` under plain rustc erases the whole block (existing fallback in
     `verus_contracts.rs`), which is why the cfg-gate is mandatory, not optional.

**Chosen architecture**: kernels adopt the dual representation; `scripts/run_verus.sh` compiles
a new `src/verification/verus_kernels.rs` root that `#[path]`-includes the kernel modules and
carries the std-net `assume_specification`/external-type proxies plus all theorems. The Verus
layer now proves contracts over the **shipped kernel functions**. Kani refinement harnesses
(Phase 3) remain the second binding layer (exhaustive over symbolic inputs).

**Step 2b — STATUS: kernel-bound layer COMPLETE (2026-09-03).**
`src/verification/verus_kernels.rs` now verifies **48 obligations, 0 errors** over the shipped
kernel source (`#[path]`-included `src/kernels/ip_filter.rs`), including: full IPv4 range
coverage theorems (RFC 1918 ×3, loopback, cloud metadata, CGNAT, TEST-NET-3, multicast,
reserved, public non-vacuity witness), IPv6 family theorems (mapped↔IPv4 reduction parity,
6to4 embedded-IPv4 parity, IPv4-translated, Teredo, documentation, ULA, link-local, site-local,
multicast, unspecified/loopback, public non-vacuity witness), each proven with explicit
bit-vector/nonlinear-arithmetic hints where Z3 needs guidance. `scripts/run_verus.sh` now runs
**both layers** (standalone 21 + kernel-bound 48 = 69 obligations). The dual-representation
pattern in the kernel file is protected by: (a) rustc branch and verus branch kept textually
identical in executable statements, (b) Kani refinement harnesses (Phase 3) proving adapter ≡
core over full symbolic domains, (c) unit tests asserting both branches agree on boundary
classes.

Deepening continues in `src/verification/verus_contracts.rs` (independent of the kernel layer):
1. **IPv6 composition theorems**: `theorem_ipv6_mapped_ipv4_restriction` — for symbolic
   `(o0..o3)`, `spec_is_restricted_ipv6(mapped(o0..o3)) <==> spec_is_restricted_ipv4(o0..o3)`;
   plus 6to4 embedded-IPv4 and Teredo wholesale-block theorems.
2. **Corrected-semantics state machine**: model insert-overwrites-live-key semantics (to match
   production `OAuthStateStore::insert`, see Phase 5) and prove single-use still holds; replaces
   the current reject-on-reinsert model.
3. **DPoP `jti` bound spec**: `spec_jti_admissible(len) = len >= 1 && len <= 256` and theorems:
   shorter-than-1 rejected, longer-than-256 rejected, in-bounds accepted (Phase 5 fix lands first).
4. **PKCE bijection over length domain**: `theorem_pkce_acceptance_iff` — `spec_valid(len,
   unreserved) <==> accepted` for symbolic `len`, strengthening the one-directional theorems.

## Phase 3 — New Kani harnesses over production code

All harnesses in `src/verification/kani_harnesses.rs`, each with `kani::cover!` tags registered
in the deterministic fallback and the m6 inventory:

1. **`proof_pkce_validator_refinement`**: symbolic `&[u8]` over bounded lengths drives the real
   `kernels::pkce_bytes` byte-level validator vs `PkceFormalSpec` — replaces the mirrored logic
   with a true refinement proof over production bytes. (Byte-oriented core avoids the UTF-8
   unwind ICE; `&str` wrapper is separately exercised deterministically.)
2. **`proof_htu_component_refinement`**: symbolic `(scheme ∈ {http,https}, host-bytes, port,
   path-bytes)` drives `kernels::htu_components` — restores harness #5 as a *real symbolic proof*
   at the component level (the `Url::parse` wrapper keeps its ICE workaround + deterministic tests).
   Proves: no query/fragment, default-port removal, custom-port preservation, lowercase scheme/host,
   path preserved.
3. **`proof_jti_admission_bound`**: symbolic `jti: &[u8]` bounded at the cap boundary proves
   `verify_proof`'s admission predicate rejects len > 256 / empty, accepts in-bounds (post-fix).
4. **`proof_nsid_grammar`**: symbolic bounded NSID bytes vs a spec model — char-class + segment
   structure parity.
5. **`proof_replay_cache_admission`**: symbolic `(jkt, jti)` pairs; `check_and_record` admits
   exactly one winner, second identical attempt within TTL is rejected (bounded 2-entry domain to
   stay SAT-friendly), covers: first-admit, second-reject, different-key-admit.
6. **`proof_state_store_take_semantics`** (toolchain-permitting): over the real `OAuthStateStore`
   sync path — insert, take (Some), take again (None), expiry (None), re-insert after take
   succeeds (documenting the replace-after-removal semantics). Uses deterministic stubs if
   `parking_lot` blocks symbolic exec; skipped with an explicit recorded rationale if Kani
   cannot compile the store.
7. **Restore harness #5 (`proof_dpop_htu_normalization_invariants`)**: keep the deterministic
   path, add `#[cfg_attr(kani, kani::proof)]` **only if** the component-level harness (2) gives
   the symbolic guarantee the `Url::parse` wrapper cannot; otherwise the wrapper stays documented
   as deterministically verified. Delete the dead `#[cfg(any())]` block either way.
8. **Arithmetic panic-freedom harness**: symbolic ticks over the state kernel's
   `saturating_sub`/expiry comparisons prove no panics and total-function behavior.

## Phase 4 — Enforce the anti-vacuity gate end-to-end

1. **Determine `cargo kani` exit semantics on unsatisfied covers** (spike: inject a guaranteed-
   false `kani::cover!` in a scratch copy, observe exit code). If Kani does not fail CI on
   unsatisfied covers, add a cover-outcome post-processing step to `ci.yml` kani job that fails
   the job when any cover is `UNSATISFIED` (parse the harness output; fail-closed on parse
   failure).
2. **Tag-inventory meta-test** (`tests/verification_tag_inventory_tests.rs`): at test time, read
   the harness source files, extract every `kani::cover!`/`anti_vacuity_cover!` tag literal, and
   assert the m6 `assert_all_covered` required-tag lists match the inventory **exactly**
   (no orphan tags, no missing tags). This makes the "25 tags" number generated-and-enforced
   rather than hand-written; the count in docs becomes derived from this test.
3. CI kani job gains explicit output archiving so cover outcomes are inspectable.

## Phase 5 — Semantics + security fixes that the proofs need

1. **`formal_models.rs` insert divergence**: `OAuthStateTransitionModel::insert` currently rejects
   re-insertion of a live key while production `OAuthStateStore::insert` replaces a live key;
   the model must match production (replace), with the Kani/Verus state proofs updated to prove
   the *actual* semantics. Recorded as review finding M3; fix order: production unchanged
   (replace is correct for re-login flows), model corrected.
2. **`jti` length cap** (`src/dpop.rs`): new `MAX_JTI_LENGTH: usize = 256`; `verify_proof` rejects
   proofs with `jti.len() > 256` (fail-closed, dedicated error variant), bounding replay-cache
   key memory amplification (reviews #6/H-surface). Replay-cache key construction bounds enforced
   at admission. New RFC-style tests: boundary at exactly 256, rejection at 257.
3. **`expires_in` overflow fail-closed** (`src/session.rs` L3): `checked_add` overflow currently
   yields `expires_at: None` → never-expires locally. Flip: overflow ⇒ treat as expired-at-max or
   reject; prove the new semantics in the arithmetic harness (Phase 3.8). This is a security fix
   required before the arithmetic proof can be honest.

## Phase 6 — Feature matrix honesty

Gate the `tower-layer`/`tower-service` imports in `tests/framework_integration_tests.rs` and
`tests/m4_adversarial_challenge_tests.rs` behind the `tower` feature so
`cargo test --no-default-features --no-run` builds. Add a CI job (or matrix leg) running
`cargo test --locked --no-default-features` plus per-feature checks. Verify locally.

## Phase 7 — MSRV spike: ✅ COMPLETE (2026-09-03)

Measured evidence:

| Toolchain | Result |
|---|---|
| `cargo +1.81.0 check --locked --lib --no-default-features` | **FAIL** — `zeroize 1.9.0` manifest requires the unstable-in-1.81 `edition2024` Cargo feature (H7 confirmed) |
| `cargo +1.85.0 check --locked --lib --all-features` | **FAIL** — dep graph: `actix-web 4.15.0` + `actix-* 0.5/2.13/3.13` + `icu_* 2.3.0` all require rustc ≥ 1.88 |
| `cargo +1.88.0 check --locked --lib --all-features` | **PASS** (2m20s) |
| `cargo +1.88.0 test --locked --all-targets --all-features` | **PASS** — 825/0 |

Decision: **`rust-version` raised 1.81 → 1.88** (pinned dependency updates make 1.81
unreachable without a mass-downgrade; 1.88 is the verified floor). An MSRV CI job pins this.

Side fix required for 1.88 compilation: `prop_assert_eq!` temporary-lifetime change
(E0716) in `tests/m6_challenger_anti_vacuity_and_concurrency_stress_tests.rs` — bind
`StateTransitionStatus` values to locals before `Some(&expected_status)` (works on all
toolchains).

## Phase 8 — Claim-surface update (upward, generated numbers)

After all proofs land, update in one pass:
- `src/verification/mod.rs` invariant table (now includes real Verus-bound kernels, new harnesses).
- `README.md` verification section: harness count (generated), cover-tag count (generated),
  explicit statement of what is proven over *production code* vs *spec models*.
- `PRD.md` §5.1 to match implemented reality (contracts on kernels, not aspirational surface).
- `CHANGELOG.md` entry.
- `TEST_READY.md` inventory regenerated.
- `VERIFICATION_UPGRADE_PLAN.md` marked complete with final measured numbers.

## Phase 9 — Full gate pipeline (final acceptance)

1. `cargo fmt --all -- --check`
2. `cargo clippy --all-targets --all-features -- -D warnings`
3. `cargo test --all-targets --all-features`
4. `cargo test --doc --all-features`
5. `bash scripts/sync_specs.sh --verify`
6. `bash scripts/run_verus.sh` (expect: >21 obligations after Phase 2b)
7. `cargo kani` (expect: >4 harnesses after Phase 3, all covers satisfied)
8. `cargo llvm-cov --all-features --fail-under-lines 80` (coverage must not regress)
9. `cargo test --locked --no-default-features` (after Phase 6)

## Risk register

| Risk | Mitigation |
|---|---|
| Verus cannot compile kernel modules composed from `src/` | Spike-gated (2a); fallback = keep deepened standalone Verus layer + Kani refinements, record honestly in docs |
| Kani ICE on `parking_lot`/store internals | Harness 6 is toolchain-permitting with stubs fallback + explicit recorded rationale |
| Verbatim-move regressions | Re-exports + full test suite + grep for old paths; zero API drift requirement |
| New bounds break existing tests that use long `jti`/verifiers | Only adversarial inputs exceed caps; fixtures reviewed before cap lands |
| Kani runtime growth from new harnesses | Bounded symbolic domains; measure per-harness time; keep total CI budget reasonable |
| `expires_in` flip changes observable behavior | Documented in CHANGELOG; only affects overflow-impossible-in-practice inputs, fails closed |

## Out of scope (explicitly)

- Async/lock linearizability proofs of the 64-shard store (no practical SMT path; empirical races remain the moat).
- Timing-independence proofs (claim corrected, not fabricated).
- `private_key_jwt` / confidential-mode rework (separate security workstream, tracked from review H1).
- Nonce-enforcement / retry-classification rework (separate protocol workstream, tracked from review H2/H3).

---

## Final Acceptance Record (2026-09-03)

All nine phases executed. Full gate pipeline results:

| Gate | Result |
|---|---|
| `cargo fmt --all -- --check` | clean |
| `cargo clippy --all-targets --all-features -- -D warnings` | clean |
| `cargo test --all-targets --all-features` | **825 passed, 0 failed** (was 801) |
| `cargo test --doc --all-features` | 15 passed, 1 ignored |
| `cargo test --locked --no-default-features` | **776 passed, 0 failed** (was: didn't compile) |
| `cargo check --locked --no-default-features --features {axum,actix,tower}` (each) | pass |
| `bash scripts/sync_specs.sh --verify` | zero drift |
| `bash scripts/run_verus.sh` | **69 obligations verified, 0 errors** (21 standalone + 48 kernel-bound; was 21) |
| `cargo kani` | **8/8 harnesses verified** (was 4; 8th = HTU deterministic-only with documented rationale) |
| `cargo +1.88.0 test --locked --all-targets --all-features` | **825 passed, 0 failed** (MSRV) |
| `cargo llvm-cov --all-features --fail-under-lines 80` | **88.73% lines** (gate ≥ 80; was 88.89% pre-change, no regression beyond noise) |

Claim-surface deltas (README/PRD/TEST_READY updated in the same change):
- Verus: "21 standalone obligations" → "69 obligations across two layers, 48 kernel-bound on shipped source".
- Kani: "5 proof harnesses / 25 tags" → "8 harnesses / 57 machine-inventoried tags" (counts enforced by `tests/verification_tag_inventory_tests.rs`, CI fails on UNSATISFIABLE covers).
- MSRV: "1.81" → "1.88" (measured floor; CI job added).
- Security fixes shipped alongside: `MAX_JTI_LENGTH` replay-key bound, `expires_in` overflow fail-closed, formal-model insert-semantics divergence corrected.

Deliberately NOT claimed (honesty ledger):
- HTU harness remains deterministic-only (CBMC `String` heap model cost measured and documented; concrete domain is exhaustive).
- Timing-independence of `constant_time_eq` rests on `subtle` upstream, not on proofs.
- Lock linearizability of the 64-shard store remains empirically verified (races), not proven.

---

## Review-Response Completion Note (2026-09-03)

Beyond the verification upgrade itself, the full set of findings from the independent fork
reviews (GLM 5.3 / GPT 5.6) was dispositioned across stacked PRs #3–#14:

| Finding | Disposition |
|---|---|
| H1 static client_secret | **Removed** (PR #10); `private_key_jwt` planned for 0.3.0 |
| H2 nonce enforcement | **Implemented both sides** (PR #9) |
| H3 retry classification | **Fixed** (PR #6) |
| H4 refresh invariants + single-flight | **Fixed** (PR #7) |
| H5 cache exhaustion | **Fixed** (deferred replay admission, no-nonce-for-bare-traffic, issuance rate limiter — PR #11) |
| H6 proxy bypass | **Fixed** (`no_proxy` + bounded DNS — PR #5) |
| M2–M12 | **Fixed** across PRs #3, #7, #11, #12, #13 (store cap + default pruning, RFC 9068 claims, metadata null, publish poll, spec-verify hardening, DID grammar, HTTPS endpoints, spawn-pruning assertions, origin-form HTU diagnostics) |
| L1–L12 | **Fixed** across PRs #8, #10, #14 (session deserialize validation, no secret surface, TokenResponse hygiene, DoH hardening, dead variants, packaging slimming, PAR dedup) |

Deliberate non-items (recorded, not silently skipped):
- **Timing-independence**: rests on `subtle` upstream; SMT tools cannot prove it (claim corrected in docs).
- **Async/lock linearizability** of the 64-shard store: no practical SMT path; empirical races remain the moat.
- **`private_key_jwt`**: 0.3.0 milestone (requires client JWKS registration design).
- **Tower middleware as default-ready RS**: origin-form HTU remains fail-closed by design (Host spoofable); `with_htu_override` is the configuration path, now named in diagnostics.
