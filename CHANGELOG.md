# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

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
