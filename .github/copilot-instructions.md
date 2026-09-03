# GitHub Copilot Code Review & Engineering Guidelines

This repository (`skyauth`) is a production-grade, formally verified AT Protocol OAuth 2.1 client library written in 100% Safe Rust (`#![forbid(unsafe_code)]`). When reviewing Pull Requests or generating code suggestions, strictly adhere to the following architecture and resilience invariants:

---

## 🛡️ Core Safety & Non-Negotiable Invariants

### 1. Zero Unsafe Code
- The crate root strictly enforces `#![forbid(unsafe_code)]`.
- **Block/Reject** any attempt to introduce `unsafe` blocks or dependencies that require unsafe exceptions.

### 2. Zero Production Panics & Typed Errors
- **Banned in production code**: `.unwrap()`, `.expect()`, `panic!`, `todo!`, `unimplemented!`.
- All fallible operations must return strongly typed `Result<T, AtprotoOAuthError>` using variants from `src/error.rs`.
- Use `?`, `match`, or `if let` for clean, defensive error propagation.

### 3. Defensive Concurrency & Lock Invariants
- **NEVER Hold Locks Across `.await` Points**: `parking_lot::RwLock` and `Mutex` guards must be dropped before executing any `.await`, network I/O, or asynchronous sleep/yield points.
- **64-Shard Partitioning**: Concurrency-sensitive structures (`OAuthStateStore`) must use 64 independent shards to prevent lock contention.

### 4. Monotonic Time & Clock-Warp Safety
- Monotonic clocks can warp under NTP adjustments or VM snapshots.
- Always compute elapsed durations using `now.saturating_duration_since(earlier)` or `.saturating_sub(...)`.
- Recurring background tasks must use `tokio::time::interval` or anchor-relative timestamps to prevent scheduling drift.

### 5. RFC 9449 DPoP & PAR Compliance
- DPoP proofs must use `typ = "dpop+jwt"`, `alg = "ES256"`, include RFC 7517 JWK with `x`, `y`, `crv = "P-256"`, `kty = "EC"`, canonical RFC 7638 thumbprint (`jkt`), normalized `htu`, and `ath` hash for access-token-bound calls.
- Automated retry loop on HTTP 400 `use_dpop_nonce` challenges must be transparent.

### 6. SSRF & Network Egress Defense
- Validate all outbound URLs with `SsrfFilter`.
- Block loopback (`127.0.0.1`, `::1`), private RFC 1918 networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local (`169.254.0.0/16`), and cloud metadata endpoints (`169.254.169.254`, `metadata.google.internal`).
- Outbound HTTP clients must disable redirects (`reqwest::redirect::Policy::none()`).

### 7. 100% Documentation Coverage
- All public types, functions, modules, and fields must have descriptive documentation comments (`missing_docs` is denied).
- Bare URLs in documentation must be enclosed in angle brackets (e.g. `<https://bsky.social>`).
