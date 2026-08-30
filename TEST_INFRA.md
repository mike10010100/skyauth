# `skyauth` Test Infrastructure & Mock Harness Blueprint

## Overview

The `skyauth` End-to-End (E2E) test infrastructure provides a fully hermetic, deterministic, opaque-box testing environment for validating decentralized OAuth 2.1 authentication workflows as specified in **RFC 9449 (DPoP)**, **RFC 9126 (PAR)**, **RFC 7636 (PKCE)**, **RFC 8414 (OAuth Server Metadata)**, **RFC 9728 (OAuth Protected Resource Metadata)**, and the **ATProto OAuth Specification**.

The test harness operates strictly without external network dependencies, spinning up ephemeral in-memory mock services and Wiremock HTTP servers on loopback interfaces.

---

## Harness Architecture (`tests/e2e_harness/`)

The test harness resides in `tests/e2e_harness/` and consists of five core modules:

```
tests/e2e_harness/
├── mod.rs          # Fixtures, test vectors, and MockOAuthEnvironment coordinator
├── mock_dns.rs     # In-memory Mock DNS resolver with TXT record extraction & NXDOMAIN handling
├── mock_plc.rs     # Wiremock PLC Directory simulating DID document resolution & fault injection
├── mock_pds.rs     # Wiremock Personal Data Server (PDS) for RFC 9728 & DPoP XRPC endpoints
└── mock_as.rs      # Wiremock OAuth 2.1 Authorization Server for RFC 8414, RFC 9126, & Token Exchange
```

### 1. Mock DNS Resolver (`mock_dns.rs`)
- **Structure**: Thread-safe in-memory map protected by `parking_lot::RwLock`.
- **Capabilities**:
  - `_atproto.<handle>` TXT record resolution with `did=` prefix extraction.
  - Case-insensitive handle normalization (e.g. `ALICE.BSKY.SOCIAL` -> `alice.bsky.social`).
  - Strict conflict detection (multiple conflicting DIDs return error).
  - Explicit NXDOMAIN simulation (`None`) to trigger HTTPS fallback resolution.
  - Network error simulation (SERVFAIL, timeouts).

### 2. Mock PLC Directory Server (`mock_plc.rs`)
- **Structure**: Ephemeral Wiremock HTTP server mounted on a random local port.
- **Capabilities**:
  - Serves standard ATProto DID documents (`id`, `alsoKnownAs`, and `#atproto_pds` service endpoints).
  - Simulates 404 Not Found for unindexed DIDs.
  - Injects mismatched handles in `alsoKnownAs` to test bidirectional verification security.
  - Injects SSRF payloads (private/loopback URLs in `serviceEndpoint`).
  - Injects 500 Internal Server Errors and corrupt JSON payloads.

### 3. Mock Personal Data Server (`mock_pds.rs`)
- **Structure**: Ephemeral Wiremock HTTP server simulating resource servers and identity fallbacks.
- **Capabilities**:
  - HTTPS handle fallback endpoint: `GET /.well-known/atproto-did`.
  - RFC 9728 OAuth Protected Resource Metadata: `GET /.well-known/oauth-protected-resource`.
  - Authenticated XRPC endpoints: `GET /xrpc/app.bsky.actor.getProfile` requiring `authorization` and `dpop` headers.
  - `use_dpop_nonce` error challenge injection with `DPoP-Nonce` header (single-use or persistent).
  - 500 server error injection for resilience testing.

### 4. Mock OAuth Authorization Server (`mock_as.rs`)
- **Structure**: Ephemeral Wiremock HTTP server simulating OAuth 2.1 AS.
- **Capabilities**:
  - RFC 8414 OAuth Authorization Server Metadata: `GET /.well-known/oauth-authorization-server`.
  - RFC 9126 Pushed Authorization Requests: `POST /oauth/par` with DPoP proof validation.
  - Token Exchange endpoint: `POST /oauth/token` supporting `authorization_code` and `refresh_token`.
  - JWKS public key set: `GET /oauth/jwks.json`.
  - `use_dpop_nonce` error challenges (`mount_par_nonce_challenge_once`, `mount_token_nonce_challenge_once`).
  - `invalid_grant` error responses for revoked or expired authorization codes and refresh tokens.

### 5. Unified Mock Environment (`MockOAuthEnvironment`)
- **Coordinator**: Instantiates and wires together all four mock servers for default test user `alice.bsky.social` (`did:plc:ewvi7nxzyoun6zhxrhs64oiz`).
- **Initialization**:
  ```rust
  let env = MockOAuthEnvironment::start_default().await;
  // Automatically mounts DNS TXT, PLC DID document, PDS metadata, AS metadata, and JWKS
  ```

---

## Authoritative RFC Test Vectors (`fixtures`)

The test suite incorporates authoritative test vectors directly from standard RFC specifications:

| Vector Name | RFC Source | Value / Identifier | Expected Output / Thumbprint |
|---|---|---|---|
| **PKCE Verifier / Challenge** | RFC 7636 Appendix B | `dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk` | `E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM` |
| **DPoP Access Token Hash (`ath`)** | RFC 9449 Figure 13 & 14 | `Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU` | `fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo` |
| **EC P-256 JWK Coordinates** | RFC 9449 Section 4.1 | `x: l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs`<br>`y: 9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA` | `jkt: 0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I` |
| **RSA JWK Thumbprint** | RFC 7638 Section 3.1 | Standard 2048-bit modulus `0vx7ago...` with `e: AQAB` | `jkt: NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs` |
| **HMAC-SHA256 Test Vector** | RFC 2104 / RFC 4231 | `key: "key"`, `data: "The quick brown fox..."` | `f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8` |

---

## Test Suite Execution

To execute the entire test infrastructure and verification suite (all six mandatory quality gates — fmt, clippy, tests, doc-tests, spec drift, Verus, and Kani — are defined in [`AGENTS.md`](AGENTS.md)):

```bash
# Run all integration test suites and unit tests
cargo test --all-targets --all-features

# Run rustdoc examples
cargo test --doc --all-features

# Run specific tiers
cargo test --test tier1_feature_tests   # Tier 1: 125 Feature Tests
cargo test --test tier2_boundary_tests  # Tier 2: 125 Boundary & Corner Tests
cargo test --test tier3_pairwise_tests  # Tier 3: 30 Pairwise Interaction Tests
cargo test --test tier4_workload_tests  # Tier 4: 5 Realistic Workload Tests
cargo test --test tier5_adversarial_tests  # Tier 5: 65 Adversarial & Attack-Path Tests

# Formal verification gates
bash scripts/run_verus.sh               # Verus SMT deductive proofs (self-bootstrapping)
cargo kani                              # Bounded model checking with anti-vacuity covers

# Coverage gate (≥ 80% lines)
cargo llvm-cov --all-features --fail-under-lines 80
```
