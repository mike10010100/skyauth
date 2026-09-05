//! # `skyauth`
//!
//! A pure safe Rust (`#![forbid(unsafe_code)]`), zero-panic OAuth 2.1 client library
//! for the AT Protocol (Bluesky).
//!
//! ## Overview
//!
//! `skyauth` provides production-grade implementations of the foundational
//! security standards mandated by the AT Protocol OAuth 2.1 specification:
//!
//! - **RFC 9449 DPoP (Demonstrating Proof-of-Possession)**: Ephemeral ECDSA P-256 keypair
//!   generation, RFC 7517 JWK formatting, RFC 7638 JWK Thumbprints (`jkt`), unpadded Base64URL
//!   signing input formatting, 64-byte raw IEEE P1363 signatures, access token hashing (`ath`),
//!   inbound proof verification, and transparent auto-nonce retry loops.
//! - **RFC 7636 PKCE (Proof Key for Code Exchange)**: Cryptographic S256 verifier/challenge
//!   generation and constant-time verification.
//! - **RFC 9126 PAR (Pushed Authorization Requests)**: Back-channel parameter pushing with
//!   signed DPoP headers and authorization URL generation.
//! - **OAuth 2.1 Code Exchange & Refresh Token Rotation**: DPoP-bound code exchange, strict
//!   single-use refresh token rotation semantics, and authenticated [`OAuthSession`] management.
//! - **64-Shard Partitioned Concurrent State Store**: Lock-free scaling state storage across 64
//!   independent [`parking_lot::RwLock`] shards with atomic single-use state consumption ([`OAuthStore::take_state`])
//!   and drift-free background TTL pruning.
//! - **Web Framework Integrations**: Ready-to-use extractors, response generators, and middleware
//!   for Axum, Actix-web, and Tower.
//! - **Decentralized Identity & Handle Resolution**: Handle normalization, DNS TXT resolution
//!   (`_atproto.<handle>`), HTTPS fallback (`/.well-known/atproto-did`), DID resolution (`did:plc`, `did:web`),
//!   and bidirectional handle verification against `alsoKnownAs`.
//! - **OAuth 2.0 Discovery (RFC 8414 & RFC 9728)**: Protected Resource Metadata and Authorization
//!   Server Metadata discovery with automatic OIDC fallback and capability enforcement.
//! - **Strict SSRF & DNS Rebinding Security**: Full IP boundary filtering blocking RFC 1918 private IPs,
//!   loopback, link-local / cloud metadata (`169.254.169.254`), IPv6 ULA, deprecated 6to4 (`2002::/16`
//!   blocked when its embedded IPv4 address is restricted)
//!   and Teredo (`2001::/32`) tunneling prefixes, cloud-metadata/internal hostname blocking, and DNS socket pinning.
//! - **Pure Safe Cryptography**: ECDSA P-256 (`p256`), SHA-256 (`sha2`), HMAC-SHA256 (`hmac`),
//!   and constant-time equality comparisons (`subtle`).
//! - **Zero-Panic Invariant**: Every fallible operation returns strongly typed [`AtprotoOAuthError`].
//!
//! ## Quick Start
//!
//! ```rust
//! use skyauth::dpop::{DPoPKey, DPoPVerifier, compute_access_token_hash};
//! use skyauth::pkce::PkcePair;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // 1. Generate PKCE code challenge
//! let pkce = PkcePair::generate();
//! assert_eq!(pkce.verifier.len(), 43);
//!
//! // 2. Generate ephemeral DPoP keypair
//! let dpop_key = DPoPKey::generate();
//! let jkt = dpop_key.jwk_thumbprint();
//!
//! // 3. Create a DPoP proof for a token request
//! let proof = dpop_key.create_proof("POST", "https://pds.example.com/oauth/token", None, None)?;
//!
//! // 4. Verify inbound DPoP proof
//! let verifier = DPoPVerifier::new();
//! let (claims, _jwk) = verifier.verify_proof(
//!     &proof,
//!     "POST",
//!     "https://pds.example.com/oauth/token",
//!     None,
//!     None,
//!     None,
//! )?;
//! assert_eq!(claims.htm, "POST");
//! # Ok(())
//! # }
//! ```
//!
//! ### OAuth Client Lifecycle
//!
//! ```rust,no_run
//! use skyauth::client::{AtprotoOAuthClient, CallbackParams, OAuthClientMetadata};
//! use skyauth::store::OAuthStateStore;
//! use std::sync::Arc;
//! use std::time::Duration;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let metadata = OAuthClientMetadata::new(
//!     "https://my-app.example.com/client-metadata.json",
//!     "https://my-app.example.com/oauth/callback",
//! )
//! .with_client_name("My ATProto App")
//! .with_scope("atproto transition:generic");
//!
//! let state_store = Arc::new(OAuthStateStore::new(Duration::from_secs(300)));
//! let client = AtprotoOAuthClient::builder()
//!     .metadata(metadata)
//!     .state_store(state_store)
//!     .state_ttl(Duration::from_secs(300))
//!     .build()?;
//!
//! // Initiate login with user handle or DID
//! let auth_req = client.authorize("alice.bsky.social").await?;
//!
//! // Handle callback with code and state (atomically consumed)
//! let callback_params = CallbackParams::new("auth_code", &auth_req.state)
//!     .with_iss("https://bsky.social");
//! let session = client.handle_callback(&callback_params).await?;
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
#![deny(
    clippy::all,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented,
    missing_docs,
    rust_2018_idioms
)]

pub mod client;
pub mod crypto;
pub mod discovery;
pub mod dpop;
pub mod error;
pub mod identity;
pub mod integrations;
pub mod kernels;
pub mod par;
pub mod pkce;
pub mod session;
pub mod ssrf;
pub mod store;
pub mod verification;

pub use client::{
    AtprotoOAuthClient, AtprotoOAuthClientBuilder, AuthorizationRequest, CallbackParams,
    OAuthClientMetadata, StoredStateEntry, TokenResponse,
};
pub use crypto::{
    base64url_decode, base64url_decode_fixed, base64url_encode, constant_time_eq, hmac_sha256,
    jwk_thumbprint_ec_p256, jwk_thumbprint_rsa, sha256_digest, sign_p256_raw, verify_p256_raw,
    verifying_key_from_coordinates, verifying_key_to_coordinates,
};
pub use discovery::{
    discover_oauth_endpoints, fetch_auth_server_metadata, fetch_protected_resource_metadata,
    validate_auth_server_capabilities, AuthorizationServerMetadata, DiscoveredAuthEndpoints,
    ProtectedResourceMetadata,
};
pub use dpop::{
    compute_access_token_hash, extract_dpop_nonce, normalize_htu, DPoPKey, DPoPNonceCache,
    DPoPProofClaims, DPoPReplayCache, DPoPServerNonceSource, DPoPVerifier,
    InMemoryServerNonceSource, JwkEc, DEFAULT_CLOCK_SKEW_LEEWAY, DEFAULT_MAX_PROOF_AGE,
};
pub use error::{
    AtprotoOAuthError, CryptoError, DPoPError, DiscoveryError, IdentityError, IntegrationError,
    ParError, PkceError, SsrfError, StoreError, TokenError,
};
pub use identity::{
    normalize_handle, validate_did_syntax, DidDocument, DidMethod, DidService, DnsTxtResolver,
    IdentityResolver, IdentityResolverBuilder, ResolvedIdentity, StandardDnsResolver,
    VerificationMethod, DEFAULT_PLC_DIRECTORY,
};
pub use integrations::{
    AccessTokenValidator, AuthenticatedUser, CnfClaim, InMemoryTokenValidator,
    JwtAccessTokenClaims, JwtAccessTokenValidator, OAuthCallbackQuery, OAuthSessionExtension,
    RegisteredToken,
};
pub use par::{build_authorization_url, execute_par_request, ParParameters, ParResponse};
pub use pkce::{derive_s256_challenge, validate_verifier, verify_pkce, PkceMethod, PkcePair};
pub use session::OAuthSession;
pub use ssrf::{
    is_blocked_hostname, is_restricted_ip, is_restricted_ipv4, is_restricted_ipv6,
    read_bounded_body, SsrfFilter, MAX_OAUTH_RESPONSE_BYTES,
};
pub use store::{OAuthStateStore, OAuthStore, DEFAULT_STATE_TTL, NUM_SHARDS};
pub use verification::{
    ConstantTimeEqSpec, DPoPHtuFormalSpec, OAuthStateTransitionModel, PkceFormalSpec,
    SsrfFormalSpec, StateTransitionStatus,
};
