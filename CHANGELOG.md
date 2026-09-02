# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **Mandatory Issuer & Audience Matching (fail closed)**: `JwtAccessTokenValidator::verify_token_sync` now **rejects every token** unless both `with_expected_issuer` and `with_expected_audience` have been configured, returning `IntegrationError::AuthFailed` (a validator-misconfiguration error). Previously, issuer and audience matching were opt-in: a validator without `with_expected_audience` accepted tokens carrying any `aud`, leaving the RFC 9068 § 4 cross-resource-server audience-confusion path open. Tokens whose `iss`/`aud` do not match the configured values are still rejected with `IssuerMismatch`/`AudienceMismatch`.
- **`ReplayCacheSaturated` maps to HTTP 503 in Tower middleware**: DPoP replay-cache capacity exhaustion is a server-side resource-exhaustion condition, not a defective client proof. The Tower layer now responds `503 Service Unavailable` (with `Retry-After: 1`) instead of `401 invalid_dpop_proof`, matching the documented semantics of `DPoPError::ReplayCacheSaturated`.
- **Default absolute DPoP `htu` derivation in Tower middleware**: the default `htu` is now reconstructed as an absolute URI from the trusted connection scheme, the request authority, and the path/query, instead of using the raw request-URI string. HTTP/1.1 origin-form targets (`/xrpc/foo`) behind proxies are reconstructed (default ports stripped per RFC 9449 § 4.2), and requests with no usable authority fail closed with `401 invalid_dpop_proof` rather than verifying against a path-only `htu`. `with_htu_override` continues to take precedence for servers whose public origin differs from the inbound authority.
- **`sync_specs.sh --verify` fails when upstream is unreachable**: a failed upstream fetch is now reported as `[FETCH FAILED] … UNVERIFIED` and causes a non-zero exit, instead of being logged as offline-but-verified. Set `SYNC_SPECS_ALLOW_OFFLINE=1` to accept manifest-only verification for offline development; actual drift still fails regardless.

### Breaking Changes

- **`JwtAccessTokenValidator` requires expected issuer and audience**: validators built without `with_expected_issuer` and `with_expected_audience` reject all tokens with `IntegrationError::AuthFailed` instead of accepting them. Production validators were expected to configure both already (and the earlier presence checks rejected tokens with absent `iss`/`aud` claims); only call sites that relied on the permissive unset-configuration path are affected.

## [0.2.0] - 2026-08-30

### Added

- **Confidential Client Support (`client_secret_post`)**: `client_secret` is now automatically included in PAR, authorization-code exchange, and refresh-token requests (RFC 6749 § 2.3.1); `execute_par_request_with_credentials` exposes the same capability for custom credential parameters.
- **Tower `htu` Origin Override**: `OAuthAuthLayer::with_htu_override` / `OAuthAuthService::with_htu_override` reconstruct the absolute DPoP target URI for servers behind reverse proxies receiving origin-form request targets.
- **Single-Use Server Nonces**: `InMemoryServerNonceSource::with_single_use` enforces strict RFC 9449 § 8 semantics by atomically consuming nonces on first successful verification.
- **6to4 (`2002::/16`) and Teredo (`2001::/32`) SSRF Filtering**: Deprecated tunneling addresses are rejected. 6to4 addresses additionally re-evaluate the embedded IPv4 address, mirrored in the formal spec models (Verus/Kani equivalence).

### Fixed

- **SSRF Hostname Blocking in Test Mode**: `allow_insecure_localhost(true)` no longer disables cloud-metadata and `.internal` hostname blocking; only explicit loopback targets are exempted.
- **Bare `localhost` Hostname Blocked**: `is_blocked_hostname` now rejects `localhost` explicitly (previously only matched via IP checks).
- **Refresh Scope Revalidation**: Refresh responses whose scope drops the mandatory `atproto` scope are rejected, preventing silent scope narrowing on rotation.
- **Rotate-Time Zeroization**: `OAuthSession::rotate_tokens` zeroizes outgoing access/refresh tokens in memory before replacing them.
- **Redacted Debug for `ParParameters`**: `client_assertion` no longer leaks through `Debug` output.
- **Client Error-Deduplication**: Token endpoint request handling consolidated into a single shared routine with unified OAuth error-field parsing.

### Documentation

- `DPoPKey` documents the `ecdsa` crate's `ZeroizeOnDrop` guarantee for the private scalar and the sensitivity of string exports.
- `rust-version = "1.81"` MSRV declared in `Cargo.toml`.

### Breaking Changes

- **`DPoPKey` private-key exports return `Zeroizing` buffers**: `DPoPKey::to_bytes()` now returns `Zeroizing<[u8; 32]>` (previously `[u8; 32]`) and `DPoPKey::to_bytes_b64()` returns `Zeroizing<String>` (previously `String`). The returned buffers zeroize on drop, protecting copies of the private scalar from lingering in memory. Call sites that deref the value (`*buf`) or the string (`&*buf` / `buf.as_str()`) need no other change; code that stored the bare `[u8; 32]` or `String` type must now name the `Zeroizing<...>` wrapper. This lands together with the other 0.2.0 hardening before the release is consumed.

## [0.1.1] - 2026-08-30

### Fixed

- **Tower / Web Framework JWT Validation & `cnf.jkt` Binding**: Independently validate JWT signature, issuer, audience, temporal bounds, and enforce constant-time thumbprint binding.
- **DPoP Anti-Replay & Nonce Challenges**: 64-shard partitioned replay cache tracking `(jkt, jti)` pairs and server nonce challenges (`401 use_dpop_nonce`).
- **SSRF Defense & Transport Pinning**: Filter 15 RFC IP ranges, pin DNS-resolved sockets, disable automatic redirects, and stream bounded response bodies.
- **ATProto OAuth Specification Compliance**: Enforce single origin-only AS URLs, RFC 9207 `iss` callback verification, and mandatory `atproto` token scope.
- **Client State Storage Single-Use**: Guaranteed atomic single-use state consumption with clock-warp-safe expiration.
- **Formal Verification & Upstream Drift Guard**: SMT deductive theorems (Verus), symbolic bounded model checking (Kani), and live upstream Lexicon/RFC schema synchronization.
- **Secret Redaction & Memory Zeroization**: Redact sensitive credentials in `Debug` implementations and zeroize heap memory on drop.

### Breaking Changes

- **Manual `Drop` / Zeroization on Public Structs**: `StoredStateEntry` and `OAuthSession` now implement `Drop` and `ZeroizeOnDrop` to securely erase cryptographic secrets from memory. As a consequence of Rust's `Drop` semantics (E0509), partial moves of individual public fields out of these structs are prohibited; cloning or borrowing should be used instead.

## [0.1.0] - 2026-08-29

### Added
- Initial production release of **`skyauth`**: pure-Rust (`#![forbid(unsafe_code)]`), zero-panic OAuth 2.1 client library for the AT Protocol.
- **RFC 9449 DPoP (Demonstrating Proof-of-Possession)**: Ephemeral ECDSA P-256 key generation, RFC 7517 JWK formatting, RFC 7638 JWK Thumbprints (`jkt`), access token hash (`ath`), and transparent auto-nonce retry loops (RFC 9449 § 4.3).
- **RFC 9126 PAR (Pushed Authorization Requests)**: Direct back-channel pushing of authorization parameters with signed DPoP headers.
- **RFC 7636 PKCE (Proof Key for Code Exchange)**: S256 verifier/challenge generation and constant-time verification.
- **Decentralized Identity Discovery**: Handle resolution (DNS TXT `_atproto.<handle>` and HTTPS fallback), DID resolution (`did:plc`, `did:web`), RFC 9728 protected resource discovery, and RFC 8414 OAuth authorization server metadata discovery.
- **Strict SSRF & DNS Rebinding Security**: Full IP boundary filtering blocking RFC 1918 private IPs, loopback, link-local, cloud metadata (`169.254.169.254`), IPv6 ULA, and DNS socket pinning.
- **64-Shard Partitioned Concurrent State Store**: Lock-free scaling state storage across 64 independent `RwLock` shards with atomic single-use state consumption ([`OAuthStore::take_state`]) and drift-free background TTL pruning.
- **Web Framework Integrations**: Ready-to-use extractors, response generators, and middleware for **Axum 0.7**, **Actix-Web 4**, and **Tower**.
- **Formal Mathematical Verification**: Verified using Verus SMT deductive proofs, Kani bounded model checking with 53 mandatory anti-vacuity reachability checks, and executable formal transition models.
- **Dynamic Schema Invariants**: Bundled official ATProto Lexicons and RFC schemas with continuous automated upstream drift detection.
