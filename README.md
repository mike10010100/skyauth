# 🔐 `skyauth`

[![crates.io](https://img.shields.io/crates/v/atproto-oauth.svg)](https://crates.io/crates/atproto-oauth)
[![docs.rs](https://docs.rs/atproto-oauth/badge.svg)](https://docs.rs/atproto-oauth)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)
[![Safety Guard](https://img.shields.io/badge/unsafe-forbidden-success.svg)](src/lib.rs)

> **Pure Safe Rust (`#![forbid(unsafe_code)]`), Zero-Panic AT Protocol OAuth 2.1 Client with RFC 9449 DPoP, RFC 9126 PAR, RFC 7636 PKCE, & Formal Mathematical Verification**

---

## 🌟 Highlights

- **100% Pure Safe Rust**: `#![forbid(unsafe_code)]` enforced crate-wide with 0 `unsafe` blocks and zero production panics.
- **RFC 9449 DPoP**: Ephemeral ECDSA P-256 key generation, RFC 7517 JWK formatting, RFC 7638 JWK Thumbprints (`jkt`), signed `dpop+jwt` proof tokens, access token hash (`ath`), and transparent auto-nonce retry negotiation.
- **RFC 9126 PAR (Pushed Authorization Requests)**: Direct back-channel pushing of authorization parameters with signed DPoP headers.
- **RFC 7636 PKCE**: High-entropy 43-character Base64URL verifier generation, SHA-256 S256 challenge derivation, and constant-time verification.
- **Decentralized Identity Discovery**: Handle normalization, DNS TXT resolution (`_atproto.<handle>`), HTTPS fallback (`/.well-known/atproto-did`), DID resolution (`did:plc`, `did:web`), and bidirectional `alsoKnownAs` verification.
- **RFC 8414 & RFC 9728 Discovery**: Protected Resource Metadata and Authorization Server Metadata discovery with automatic OIDC fallback.
- **Strict SSRF & DNS Rebinding Security**: Full IP boundary filtering blocking RFC 1918 private IPs, loopback, link-local, cloud metadata (`169.254.169.254`), IPv6 ULA, and DNS socket pinning.
- **64-Shard Partitioned State Store**: Lock-free scaling state storage across 64 independent `RwLock` shards with atomic single-use state consumption ([`OAuthStore::take_state`]) and drift-free background TTL pruning.
- **Web Framework Integrations**: Ready-to-use extractors, response generators, and middleware for **Axum 0.7**, **Actix-Web 4**, and **Tower**.
- **Formal Mathematical Verification**: Verified using executable formal contracts and **Kani** bounded model checking with 36 mandatory anti-vacuity reachability checks.
- **Dynamic Schema Invariants**: Bundled official ATProto Lexicons and RFC schemas with continuous automated upstream drift detection.

---

## 🚀 Quick Start

Add `atproto-oauth` to your `Cargo.toml`:

```toml
[dependencies]
atproto-oauth = "0.1"
```

### 1. DPoP Proof Generation & Verification

```rust
use skyauth::dpop::{DPoPKey, DPoPVerifier, compute_access_token_hash};
use skyauth::pkce::PkcePair;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Generate PKCE code challenge
    let pkce = PkcePair::generate();
    assert_eq!(pkce.verifier.len(), 43);

    // 2. Generate ephemeral DPoP keypair
    let dpop_key = DPoPKey::generate();
    let jkt = dpop_key.jwk_thumbprint();

    // 3. Create a DPoP proof for a token request
    let proof = dpop_key.create_proof(
        "POST",
        "https://pds.example.com/oauth/token",
        None,
        None,
    )?;

    // 4. Verify inbound DPoP proof
    let verifier = DPoPVerifier::new();
    let (claims, jwk) = verifier.verify_proof(
        &proof,
        "POST",
        "https://pds.example.com/oauth/token",
        None,
        None,
        None,
    )?;
    assert_eq!(claims.htm, "POST");

    Ok(())
}
```

### 2. Full OAuth Client Lifecycle

```rust
use skyauth::client::{AtprotoOAuthClient, OAuthClientMetadata};
use skyauth::store::OAuthStateStore;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let metadata = OAuthClientMetadata {
        client_id: "https://my-app.example.com/client-metadata.json".to_string(),
        client_name: Some("My ATProto App".to_string()),
        client_uri: Some("https://my-app.example.com".to_string()),
        redirect_uris: vec!["https://my-app.example.com/oauth/callback".to_string()],
        grant_types: vec!["authorization_code".to_string(), "refresh_token".to_string()],
        response_types: vec!["code".to_string()],
        scope: "atproto transition:generic".to_string(),
        token_endpoint_auth_method: "none".to_string(),
        dpop_bound_access_tokens: true,
        jwks_uri: None,
    };

    let state_store = Arc::new(OAuthStateStore::new());
    let client = AtprotoOAuthClient::builder()
        .metadata(metadata)
        .state_store(state_store)
        .build()?;

    // Initiate login with handle or DID
    let auth_req = client.authorize("alice.bsky.social").await?;
    println!("Redirect user to: {}", auth_req.authorization_url);

    Ok(())
}
```

---

## 🛡️ Formal Verification & Mathematical Invariants

`skyauth` incorporates a formal verification hierarchy to eliminate security vulnerabilities:

1. **Executable Formal Contracts**: Pure mathematical models and Hoare-logic specifications (preconditions `requires`, postconditions `ensures`, and inductive loop invariants) modeling session state transitions, constant-time comparisons, and PKCE deterministic bounds.
2. **Kani Bounded Model Checking (`kani::proof`)**: Exhaustive symbolic proof harnesses using `kani::any()` and `kani::assume()` for symbolic input verification.
3. **Anti-Vacuity Coverage (`kani::cover!`)**: 36 mandatory reachability checks ensuring harnesses actively exercise functional and error-handling code paths.

---

## 🧪 Running Tests, CI & Formal Proofs

```bash
# Run unit, integration, and RFC vector test suites
cargo test --all-targets --all-features

# Verify strict clippy compliance (0 warnings)
cargo clippy --all-targets --all-features -- -D warnings

# Verify specification drift against upstream canonical Lexicons & RFC schemas
bash scripts/sync_specs.sh --verify

# Run Kani bounded model checking harnesses
cargo kani --harness "proof_*"
```

---

## 📄 License

Dual-licensed under either:
- **MIT License** ([LICENSE-MIT](LICENSE-MIT))
- **Apache License, Version 2.0** ([LICENSE-APACHE](LICENSE-APACHE))
