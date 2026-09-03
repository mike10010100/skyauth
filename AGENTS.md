# 🤖 Agent Coding & Engineering Handover Guide

Welcome, Agent! This document is designed specifically for AI coding assistants (Antigravity, Claude, Cursor, Copilot, etc.) interacting with this codebase.

---

## 🎯 Repository Standards & Reference Blueprint

This project is built following the **Production-Grade Rust Best Practices & Architecture Standards** defined in the user's reference repository:
- **Reference Repo**: `rust-best-practices`
- **Architecture Guide**: `BEST_PRACTICES.md`
- **Tooling Blueprint**: `TOOLING.md`

When working in this repository:
- Treat every safety gate and architectural pattern as a strict non-negotiable requirement.
- Never lower quality gates, weaken lint rules, or bypass defensive error handling for convenience.
- Any new features, modules, or refactors must adhere to the same uncompromising resilience standard.

---

## 🛡️ Core Non-Negotiable Invariants

### 1. Zero Unsafe Code
The crate root ([`src/lib.rs`](src/lib.rs)) enforces:
```rust
#![forbid(unsafe_code)]
```
Never attempt to use `unsafe`, weaken this attribute, or introduce dependencies that circumvent compiler safety guarantees.

### 2. Strict Crate-Root Safety Guard
The crate root enforces the strict compiler lint safety guard:
```rust
#![deny(
    clippy::all,
    clippy::unwrap_used,     // Deny unwrap(), force explicit error handling
    clippy::expect_used,     // Deny expect(), force structured errors
    clippy::panic,           // Deny panic!, force error bubbling
    clippy::todo,            // Deny todo! placeholders in production
    clippy::unimplemented,   // Deny unimplemented! macros
    missing_docs,            // Enforce public API documentation
    rust_2018_idioms         // Use modern Rust idioms
)]
```

### 3. Zero Production Panics & Typed Errors
- **Banned in production**: `.unwrap()`, `.expect()`, `panic!`, `todo!`, `unimplemented!`.
- All fallible operations must return a strongly typed `Result<T, AtprotoOAuthError>` using variants defined in [`src/error.rs`](src/error.rs).
- Use `?`, `match`, or `if let` to propagate errors safely.
- In test modules (`#[cfg(test)]` and `tests/`), allow unwrap via `#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]`.

### 4. Defensive Concurrency, Locks & Time
- **Clock-Warp Safety**: Always compute elapsed time using `now.saturating_duration_since(earlier)` or `.saturating_sub(...)`. Never use raw `.duration_since()` without fallback as monotonic clocks can jump backwards under VM or NTP syncs.
- **Drift-Free Scheduling**: Recurring tasks (e.g. state pruning) must calculate next runs relative to the previous anchor timestamp or use `tokio::time::interval`, not relative `Instant::now() + delay`.
- **Never Hold Locks Across `.await` Points**: Synchronous mutex or `RwLock` guards must always be dropped before executing any `.await`, `sleep()`, or network I/O.
- **Sharded State Partitioning**: High-concurrency structures (`OAuthStateStore`) use **64 independent `RwLock` shards** to eliminate lock contention under multi-threaded load.
- **Task Leak Prevention & Cancellation**: All background tasks must be tracked in a managed `tokio::task::JoinSet` tied to a `CancellationToken`. On shutdown or timeout, tasks must be cleanly aborted and joined.

### 5. 100% Documentation Coverage
- All public structs, fields, constants, enums, modules, and functions must have descriptive documentation comments (`missing_docs` is denied).
- Bare URLs in documentation must be enclosed in angle brackets (e.g. `<https://bsky.social>`).

---

## ⚡ Mandatory Pre-Completion Checklist

Before reporting any work as complete, you **must execute and pass every step** of this verification pipeline:

```bash
# 1. Check code formatting
cargo fmt --all -- --check

# 2. Check strict clippy rules (must have 0 warnings with -D warnings)
cargo clippy --all-targets --all-features -- -D warnings

# 3. Run all unit and integration test suites
cargo test --all-targets --all-features

# 4. Verify specification drift
bash scripts/sync_specs.sh --verify

# 5. Run Verus deductive formal verification (SMT proofs)
bash scripts/run_verus.sh

# 6. Run Kani bounded model checking harnesses (must verify all harnesses with 0 failures
#    and all anti-vacuity cover properties satisfied)
cargo kani
```

Steps 5–6 are **non-optional for this repository**: the crate's headline guarantee is formal
verification, so changes to `src/verification/`, `src/crypto.rs`, `src/dpop.rs`, `src/ssrf.rs`,
`src/store.rs`, or `src/pkce.rs` without re-proving the corresponding invariants are incomplete.

### Formal Verification Toolchain Bootstrap

Neither Verus nor Kani is preinstalled on a fresh machine. Both self-bootstrap:

- **Verus**: `scripts/run_verus.sh` auto-downloads a pinned release into `~/.verus` on first run.
- **Kani**: `cargo install kani-verifier --locked` then `cargo kani setup` (installs a pinned
  nightly toolchain). Only needed once per environment.

If `cargo kani` cannot be run in an offline/CI-restricted environment, fall back to the
executable formal-model tests (`cargo test --test formal_verification_tests`) and **explicitly
state in the handoff report that the Kani gate could not run** — never silently skip it.

The same policy applies to the Verus gate: `scripts/run_verus.sh` exits non-zero unless Verus is
installed, or the environment variable `ALLOW_VERUS_FALLBACK=1` is set to run only the executable
model tests. Offline fallback for Verus requires the same explicit disclosure in the handoff
report — never silently skip it either.
