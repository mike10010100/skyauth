# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
- **Formal Mathematical Verification**: Verified using executable formal transition models and **Kani** bounded model checking with 36 mandatory anti-vacuity reachability checks.
- **Dynamic Schema Invariants**: Bundled official ATProto Lexicons and RFC schemas with continuous automated upstream drift detection.
