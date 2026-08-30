//! # SkyAuth
//!
//! SkyAuth implements the public-client path of the current AT Protocol OAuth profile. It includes
//! identity and strict metadata discovery, RFC 7636 PKCE, RFC 9126 PAR, RFC 9449 DPoP, atomic
//! authorization state, serialized refresh rotation, granular scopes, and protected XRPC calls.
//!
//! All outbound requests use a bounded transport with address validation, socket pinning, and
//! explicit redirect rules. The in-memory state store uses 64 independent shards. Axum, Actix, and
//! Tower integrations are opt-in features.
//!
//! ```no_run
//! use skyauth::client::{AtprotoOAuthClient, OAuthClientMetadata};
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let client = AtprotoOAuthClient::builder()
//!     .client_metadata(OAuthClientMetadata::new(
//!         "https://app.example.com/oauth-client-metadata.json",
//!         "https://app.example.com/oauth/callback",
//!     ))
//!     .in_memory_state_store()
//!     .build()?;
//!
//! let request = client.initiate_login("alice.example.com").await?;
//! println!("{}", request.authorization_url());
//! # Ok(())
//! # }
//! ```
//!
//! The formal gate checks documented policy properties with pinned Verus and Kani versions. It does
//! not prove cryptographic primitives, the network stack, clocks, or external server data. See
//! `docs/formal-verification.md` in the repository for the proof inventory and bounds.

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
pub mod par;
pub mod permission;
pub mod pkce;
/// Pure policy decisions shared by runtime code and proof targets.
pub mod policy;
pub mod scope;
mod secret;
pub mod session;
pub mod ssrf;
pub mod store;
#[cfg(kani)]
mod verification;

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
    DPoPProofClaims, DPoPVerifier, JwkEc, DEFAULT_CLOCK_SKEW_LEEWAY, DEFAULT_MAX_PROOF_AGE,
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
pub use integrations::{AuthenticatedUser, OAuthCallbackQuery, OAuthSessionExtension};
pub use par::{build_authorization_url, execute_par_request, ParParameters, ParResponse};
pub use pkce::{derive_s256_challenge, validate_verifier, verify_pkce, PkceMethod, PkcePair};
pub use session::OAuthSession;
pub use ssrf::{
    is_blocked_hostname, is_restricted_ip, is_restricted_ipv4, is_restricted_ipv6, SsrfFilter,
};
pub use store::{OAuthStateStore, OAuthStore, DEFAULT_STATE_TTL, NUM_SHARDS};
