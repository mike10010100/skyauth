//! Cryptographic signature verification for ATProto Service Auth JWTs (`com.atproto.server.getServiceAuth`).
//!
//! # Overview
//!
//! When an ATProto service or Bluesky `AppView` queries a custom feed generator, labeler,
//! or sovereign XRPC endpoint on behalf of a user, it attaches an `Authorization: Bearer <jwt>`
//! header signed with the requesting account's `#atproto` verification method published in their
//! DID document (`did:plc` via PLC directory or `did:web` via `/.well-known/did.json`).
//!
//! Per the [ATProto Cryptography Specification](https://atproto.com/specs/cryptography#public-key-encoding),
//! `#atproto` verification methods use `Multikey` (`publicKeyMultibase`) encoding with either:
//! - **secp256k1** (`ES256K`): 2-byte unsigned varint prefix `[0xe7, 0x01]` (`zQ3sh...`) or legacy 1-byte `0xe7`
//!   followed by the 33-byte compressed SEC1 public key.
//! - **NIST P-256** (`ES256`): 2-byte unsigned varint prefix `[0x80, 0x24]` (`zDna...`)
//!   followed by the 33-byte compressed SEC1 public key.
//!
//! This module provides [`ServiceAuthVerifier`] and [`DidKeyCache`] (a 64-shard bounded TTL cache
//! that automatically invalidates cached keys on signature failure to handle live DID key rotations).

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use ahash::AHasher;
use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use k256::ecdsa::signature::Verifier as _;
use k256::ecdsa::{Signature as Secp256k1Signature, VerifyingKey as Secp256k1VerifyingKey};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::error::{AtprotoOAuthError, CryptoError, IdentityError, TokenError};
use crate::identity::{DidDocument, IdentityResolver, IdentityResolverBuilder};
use crate::kernels::service_auth_bytes::{
    alg_id_from_str, classify_multikey_bytes, is_alg_bound_to_curve, is_service_jwt_exp_valid,
    ALG_NONE, CURVE_P256, CURVE_SECP256K1,
};
use crate::ssrf::SsrfFilter;
use crate::store::NUM_SHARDS;

/// Default TTL in seconds for cached DID-document `#atproto` signing keys (15 minutes).
pub const DID_KEY_CACHE_TTL_SECS: u64 = 15 * 60;

/// Number of shards in [`DidKeyCache`] (64 shards matching `OAuthStateStore`).
pub const DID_KEY_CACHE_SHARDS: usize = NUM_SHARDS;

/// Maximum entries per shard in [`DidKeyCache`] before expired-first / oldest-entry eviction.
pub const MAX_DID_KEY_CACHE_PER_SHARD: usize = 512;

/// Default clock skew leeway in seconds for Service Auth JWT `exp` validation (60 seconds).
pub const SERVICE_JWT_CLOCK_SKEW_LEEWAY_SECS: u64 = 60;

/// Multikey 2-byte unsigned varint prefix for secp256k1 compressed public keys (`0xe7` = `[0xe7, 0x01]`, `zQ3sh...`).
pub const MULTIKEY_SECP256K1_VARINT: [u8; 2] = [0xe7, 0x01];

/// Legacy 1-byte prefix for secp256k1 compressed public keys (`0xe7`).
pub const MULTIKEY_SECP256K1_LEGACY_PREFIX: u8 = 0xe7;

/// Multikey 2-byte unsigned varint prefix for NIST P-256 compressed public keys (`0x1200` = `[0x80, 0x24]`, `zDna...`).
pub const MULTIKEY_P256_VARINT: [u8; 2] = [0x80, 0x24];

/// Length in bytes of a compressed SEC1 elliptic-curve public key (secp256k1 or P-256).
pub const COMPRESSED_EC_PUBLIC_KEY_LEN: usize = 33;

/// Primary JOSE `alg` value for ATProto Service Auth JWTs (`secp256k1`).
pub const ES256K_SERVICE_AUTH_ALG: &str = "ES256K";

/// Secondary JOSE `alg` value permitted by the ATProto Cryptography Specification (`P-256`).
pub const ES256_SERVICE_AUTH_ALG: &str = "ES256";

/// Verified ATProto signing key extracted from a DID document's `#atproto` verification method.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AtprotoVerifyingKey {
    /// secp256k1 verifying key (`ES256K`, multicodec `0xe7` / varint `[0xe7, 0x01]`).
    Secp256k1(Secp256k1VerifyingKey),
    /// NIST P-256 verifying key (`ES256`, multicodec `0x1200` / varint `[0x80, 0x24]`).
    P256(p256::ecdsa::VerifyingKey),
}

impl AtprotoVerifyingKey {
    /// Returns the formal verification curve tag (`CURVE_SECP256K1` or `CURVE_P256`).
    #[must_use]
    pub const fn curve_id(&self) -> u8 {
        match self {
            Self::Secp256k1(_) => CURVE_SECP256K1,
            Self::P256(_) => CURVE_P256,
        }
    }
}

/// Raw JOSE header fields of an ATProto Service Auth JWT.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceJwtHeader {
    /// Signature algorithm (`ES256K` or `ES256`).
    pub alg: String,
    /// Optional token type (`JWT`).
    #[serde(default)]
    pub typ: Option<String>,
}

/// Claims payload of an ATProto Service Auth JWT (`com.atproto.server.getServiceAuth`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceJwtClaims {
    /// Issuer DID of the requesting actor (`did:plc:...` or `did:web:...`).
    #[serde(default)]
    pub iss: Option<String>,
    /// Optional subject DID fallback.
    #[serde(default)]
    pub sub: Option<String>,
    /// Target service DID audience (`aud`).
    #[serde(default)]
    pub aud: Option<String>,
    /// Lexicon method NSID bound to the token (`lxm`), if restricted.
    #[serde(default)]
    pub lxm: Option<String>,
    /// Expiration timestamp in seconds since Unix epoch.
    #[serde(default)]
    pub exp: Option<u64>,
    /// Issued-at timestamp in seconds since Unix epoch.
    #[serde(default)]
    pub iat: Option<u64>,
    /// Unique JWT nonce (`jti`).
    #[serde(default)]
    pub jti: Option<String>,
}

impl ServiceJwtClaims {
    /// Returns the validated viewer DID (`iss` preferred, `sub` fallback).
    #[must_use]
    pub fn viewer_did(&self) -> Option<&str> {
        self.iss
            .as_deref()
            .or(self.sub.as_deref())
            .filter(|did| is_valid_service_did(did))
    }
}

/// Validates whether a string is a syntactically valid AT Protocol DID (`did:plc:...` or `did:web:...`).
///
/// Accepts `did:plc:<id>` (1..=64 lowercase ASCII alphanumeric, `_`, or `-` characters) and
/// `did:web:<hostname>` (standard RFC 1035 DNS labels, optionally with `:`-separated path components).
#[must_use]
pub fn is_valid_service_did(did: &str) -> bool {
    if let Some(id) = did.strip_prefix("did:plc:") {
        return !id.is_empty()
            && id.len() <= 64
            && !id.contains(':')
            && id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-');
    }
    if let Some(rest) = did.strip_prefix("did:web:") {
        let mut segments = rest.split(':');
        let host_raw = segments.next().unwrap_or("");
        let host = host_raw.replace("%3A", ":").replace("%3a", ":");
        let host_name = host.split(':').next().unwrap_or("");
        let host_ok = !host_name.is_empty()
            && host_name.len() <= 253
            && host_name.split('.').all(|l| {
                !l.is_empty()
                    && l.len() <= 63
                    && !l.starts_with('-')
                    && !l.ends_with('-')
                    && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            });
        let path_ok = segments.all(|seg| {
            !seg.is_empty()
                && seg != "."
                && seg != ".."
                && !seg.contains("..")
                && seg.bytes().all(|b| {
                    b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_' || b == b'%'
                })
        });
        return host_ok && path_ok;
    }
    false
}

/// Cached DID-document signing key entry with resolution timestamp.
#[derive(Clone, Debug)]
pub struct CachedSigningKey {
    /// The secp256k1 verifying key if the `#atproto` key uses secp256k1.
    pub verifying_key: Option<Arc<Secp256k1VerifyingKey>>,
    /// The curve-typed ATProto verifying key (`Secp256k1` or `P256`).
    pub atproto_key: Arc<AtprotoVerifyingKey>,
    /// Unix timestamp in seconds when this key was resolved and cached.
    pub resolved_at_secs: u64,
}

/// 64-shard bounded TTL cache of resolved DID-document `#atproto` signing keys.
#[derive(Debug)]
pub struct DidKeyCache {
    shards: [RwLock<HashMap<String, CachedSigningKey>>; DID_KEY_CACHE_SHARDS],
    ttl_secs: u64,
}

impl Default for DidKeyCache {
    fn default() -> Self {
        Self::new(DID_KEY_CACHE_TTL_SECS)
    }
}

impl DidKeyCache {
    /// Creates a new 64-shard `DidKeyCache` with the specified entry TTL in seconds.
    #[must_use]
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            shards: std::array::from_fn(|_| RwLock::new(HashMap::new())),
            ttl_secs,
        }
    }

    /// Returns the configured TTL in seconds.
    #[must_use]
    pub const fn ttl_secs(&self) -> u64 {
        self.ttl_secs
    }

    fn shard_idx(did: &str) -> usize {
        let mut hasher = AHasher::default();
        did.hash(&mut hasher);
        (hasher.finish() as usize) & (DID_KEY_CACHE_SHARDS - 1)
    }

    /// Returns the cached secp256k1 verifying key for `did` if present and unexpired.
    #[must_use]
    pub fn get(&self, did: &str, now_secs: u64) -> Option<Arc<Secp256k1VerifyingKey>> {
        let shard = &self.shards[Self::shard_idx(did)];
        let guard = shard.read();
        let entry = guard.get(did)?;
        if now_secs.saturating_sub(entry.resolved_at_secs) >= self.ttl_secs {
            return None;
        }
        entry.verifying_key.as_ref().map(Arc::clone)
    }

    /// Returns the cached curve-typed [`AtprotoVerifyingKey`] for `did` if present and unexpired.
    #[must_use]
    pub fn get_atproto_key(&self, did: &str, now_secs: u64) -> Option<Arc<AtprotoVerifyingKey>> {
        let shard = &self.shards[Self::shard_idx(did)];
        let guard = shard.read();
        let entry = guard.get(did)?;
        if now_secs.saturating_sub(entry.resolved_at_secs) >= self.ttl_secs {
            return None;
        }
        Some(Arc::clone(&entry.atproto_key))
    }

    /// Inserts a resolved secp256k1 verifying key for `did`.
    pub fn insert(&self, did: &str, key: Secp256k1VerifyingKey, now_secs: u64) {
        self.insert_atproto_key(did, AtprotoVerifyingKey::Secp256k1(key), now_secs);
    }

    /// Inserts a resolved [`AtprotoVerifyingKey`] for `did`, bounding per-shard capacity.
    pub fn insert_atproto_key(&self, did: &str, key: AtprotoVerifyingKey, now_secs: u64) {
        let shard = &self.shards[Self::shard_idx(did)];
        let mut guard = shard.write();
        if guard.len() >= MAX_DID_KEY_CACHE_PER_SHARD && !guard.contains_key(did) {
            let ttl = self.ttl_secs;
            guard.retain(|_, v| now_secs.saturating_sub(v.resolved_at_secs) < ttl);
            if guard.len() >= MAX_DID_KEY_CACHE_PER_SHARD {
                if let Some(oldest_did) = guard
                    .iter()
                    .min_by_key(|(_, v)| v.resolved_at_secs)
                    .map(|(k, _)| k.clone())
                {
                    guard.remove(&oldest_did);
                }
            }
        }
        let verifying_key = match &key {
            AtprotoVerifyingKey::Secp256k1(k) => Some(Arc::new(*k)),
            AtprotoVerifyingKey::P256(_) => None,
        };
        guard.insert(
            did.to_string(),
            CachedSigningKey {
                verifying_key,
                atproto_key: Arc::new(key),
                resolved_at_secs: now_secs,
            },
        );
    }

    /// Invalidates the cached key for `did` (e.g. after a signature verification failure).
    pub fn invalidate(&self, did: &str) {
        let shard = &self.shards[Self::shard_idx(did)];
        shard.write().remove(did);
    }

    /// Returns the total number of cached keys across all 64 shards.
    #[must_use]
    pub fn len(&self) -> usize {
        self.shards.iter().map(|s| s.read().len()).sum()
    }

    /// Returns `true` if no keys are cached.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Clears all cached entries across all shards.
    pub fn clear(&self) {
        for shard in &self.shards {
            shard.write().clear();
        }
    }
}

/// Verifies ATProto Service Auth JWT signatures against issuer DID documents.
#[derive(Clone)]
pub struct ServiceAuthVerifier {
    resolver: Arc<IdentityResolver>,
    key_cache: Arc<DidKeyCache>,
}

impl std::fmt::Debug for ServiceAuthVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceAuthVerifier")
            .field("key_cache_ttl_secs", &self.key_cache.ttl_secs)
            .field("cache_entries", &self.key_cache.len())
            .finish()
    }
}

impl Default for ServiceAuthVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl ServiceAuthVerifier {
    /// Creates a new verifier resolving DID documents via `https://plc.directory` with SSRF protection enabled.
    #[must_use]
    pub fn new() -> Self {
        Self::with_resolver(Arc::new(IdentityResolver::new(SsrfFilter::new(false))))
    }

    /// Creates a verifier backed by a custom [`IdentityResolver`].
    #[must_use]
    pub fn with_resolver(resolver: Arc<IdentityResolver>) -> Self {
        Self {
            resolver,
            key_cache: Arc::new(DidKeyCache::default()),
        }
    }

    /// Creates a verifier backed by a custom [`IdentityResolver`] and [`DidKeyCache`].
    #[must_use]
    pub fn with_resolver_and_cache(
        resolver: Arc<IdentityResolver>,
        key_cache: Arc<DidKeyCache>,
    ) -> Self {
        Self {
            resolver,
            key_cache,
        }
    }

    /// Creates a verifier configured with a custom PLC directory URL.
    #[must_use]
    pub fn with_plc_url(plc_url: impl Into<String>, allow_insecure_localhost: bool) -> Self {
        let resolver = IdentityResolverBuilder::new()
            .allow_insecure_localhost(allow_insecure_localhost)
            .plc_directory_url(plc_url)
            .build();
        Self::with_resolver(Arc::new(resolver))
    }

    /// Returns a reference to the underlying [`DidKeyCache`].
    #[must_use]
    pub fn key_cache(&self) -> &Arc<DidKeyCache> {
        &self.key_cache
    }

    /// Returns a reference to the underlying [`IdentityResolver`].
    #[must_use]
    pub fn resolver(&self) -> &Arc<IdentityResolver> {
        &self.resolver
    }

    /// Extracts a secp256k1 verifying key from an ATProto [`DidDocument`].
    ///
    /// # Errors
    /// Returns [`AtprotoOAuthError`] if `#atproto` is missing, malformed, or uses P-256 instead of secp256k1.
    pub fn extract_signing_key_from_document(
        doc: &DidDocument,
    ) -> Result<Secp256k1VerifyingKey, AtprotoOAuthError> {
        match Self::extract_atproto_key_from_document(doc)? {
            AtprotoVerifyingKey::Secp256k1(key) => Ok(key),
            AtprotoVerifyingKey::P256(_) => Err(CryptoError::InvalidKey(format!(
                "Verification method in '{}' is a P-256 Multikey, not a secp256k1 Multikey",
                doc.id
            ))
            .into()),
        }
    }

    /// Extracts either a `secp256k1` (`[0xe7, 0x01]` / `[0xe7]`) or `P-256` (`[0x80, 0x24]`)
    /// verifying key from an ATProto [`DidDocument`]'s `#atproto` verification method.
    ///
    /// # Errors
    /// Returns [`AtprotoOAuthError`] if `#atproto` is absent, has no `publicKeyMultibase`, or fails decoding.
    pub fn extract_atproto_key_from_document(
        doc: &DidDocument,
    ) -> Result<AtprotoVerifyingKey, AtprotoOAuthError> {
        let method = doc.extract_signing_key().ok_or_else(|| {
            IdentityError::MalformedDidDocument(format!(
                "DID document '{}' has no #atproto verification method",
                doc.id
            ))
        })?;

        let raw = method.public_key_multibase.as_deref().ok_or_else(|| {
            IdentityError::MalformedDidDocument(format!(
                "Verification method '{}' carries no publicKeyMultibase",
                method.id
            ))
        })?;

        let key_bytes = decode_multikey(raw)?;

        // Formal verification kernel (`src/kernels/service_auth_bytes.rs`):
        // Classifies the Multikey prefix/length and returns `(curve_id, sec1_33_byte_slice)`.
        if let Some((curve_id, sec1_bytes)) = classify_multikey_bytes(&key_bytes) {
            if curve_id == CURVE_SECP256K1 {
                let key = Secp256k1VerifyingKey::from_sec1_bytes(sec1_bytes).map_err(|e| {
                    CryptoError::InvalidKey(format!(
                        "Invalid secp256k1 public key in '{}': {e}",
                        method.id
                    ))
                })?;
                return Ok(AtprotoVerifyingKey::Secp256k1(key));
            }
            if curve_id == CURVE_P256 {
                let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(sec1_bytes).map_err(|e| {
                    CryptoError::InvalidKey(format!(
                        "Invalid P-256 public key in '{}': {e}",
                        method.id
                    ))
                })?;
                return Ok(AtprotoVerifyingKey::P256(key));
            }
        }

        // Preserve explicit elliptic-curve parse error when prefix+len match a valid multicodec
        // (`[0xe7, 0x01]`, `[0xe7]`, or `[0x80, 0x24]`) but the SEC1 tag byte is not `0x02`/`0x03`.
        if (key_bytes.starts_with(&MULTIKEY_SECP256K1_VARINT)
            && key_bytes.len() == MULTIKEY_SECP256K1_VARINT.len() + COMPRESSED_EC_PUBLIC_KEY_LEN)
            || (key_bytes.first().copied() == Some(MULTIKEY_SECP256K1_LEGACY_PREFIX)
                && key_bytes.len() == 1 + COMPRESSED_EC_PUBLIC_KEY_LEN)
        {
            return Err(CryptoError::InvalidKey(format!(
                "Invalid secp256k1 public key in '{}': invalid compressed SEC1 tag byte",
                method.id
            ))
            .into());
        }
        if key_bytes.starts_with(&MULTIKEY_P256_VARINT)
            && key_bytes.len() == MULTIKEY_P256_VARINT.len() + COMPRESSED_EC_PUBLIC_KEY_LEN
        {
            return Err(CryptoError::InvalidKey(format!(
                "Invalid P-256 public key in '{}': invalid compressed SEC1 tag byte",
                method.id
            ))
            .into());
        }

        Err(CryptoError::InvalidKey(format!(
            "Verification method '{}' is not a secp256k1 or P-256 Multikey (len {}, prefix {:?})",
            method.id,
            key_bytes.len(),
            key_bytes.get(..2).unwrap_or(&key_bytes)
        ))
        .into())
    }

    /// Resolves (with cache) the secp256k1 signing key for `did`.
    ///
    /// # Errors
    /// Returns [`AtprotoOAuthError`] if resolution fails or the DID uses a P-256 key.
    pub async fn resolve_signing_key(
        &self,
        did: &str,
        now_secs: u64,
    ) -> Result<Arc<Secp256k1VerifyingKey>, AtprotoOAuthError> {
        match &*self.resolve_atproto_key(did, now_secs).await? {
            AtprotoVerifyingKey::Secp256k1(key) => Ok(Arc::new(*key)),
            AtprotoVerifyingKey::P256(_) => Err(CryptoError::InvalidKey(format!(
                "DID '{did}' uses a P-256 signing key, not secp256k1"
            ))
            .into()),
        }
    }

    /// Resolves (with cache) the curve-typed [`AtprotoVerifyingKey`] for `did`.
    ///
    /// # Errors
    /// Returns [`AtprotoOAuthError`] if the DID syntax is invalid, DID resolution fails,
    /// or the DID document has no valid `#atproto` key.
    pub async fn resolve_atproto_key(
        &self,
        did: &str,
        now_secs: u64,
    ) -> Result<Arc<AtprotoVerifyingKey>, AtprotoOAuthError> {
        if !is_valid_service_did(did) {
            return Err(
                IdentityError::InvalidDidSyntax(format!("Invalid issuer DID: '{did}'")).into(),
            );
        }

        if let Some(key) = self.key_cache.get_atproto_key(did, now_secs) {
            return Ok(key);
        }

        let doc = self.resolver.resolve_did(did).await?;
        let key = Self::extract_atproto_key_from_document(&doc)?;
        self.key_cache
            .insert_atproto_key(did, key.clone(), now_secs);
        Ok(Arc::new(key))
    }

    /// Verifies an ATProto Service Auth JWT (`Authorization: Bearer <jwt>` or raw `<jwt>`)
    /// against the issuer's DID document and returns the verified [`ServiceJwtClaims`].
    ///
    /// # Errors
    /// Returns [`AtprotoOAuthError`] if the token is malformed, uses an unsupported algorithm,
    /// fails ECDSA signature verification, is expired beyond `leeway_secs`, or mismatches `expected_audiences`.
    pub async fn verify_service_jwt_claims(
        &self,
        auth_header_or_token: &str,
        expected_audiences: &[&str],
        now_secs: u64,
        leeway_secs: u64,
    ) -> Result<ServiceJwtClaims, AtprotoOAuthError> {
        let token = extract_bearer_token(auth_header_or_token)?;

        let mut segments = token.split('.');
        let header_b64 = segments
            .next()
            .ok_or_else(|| TokenError::MalformedToken("Missing JWT header segment".into()))?;
        let payload_b64 = segments
            .next()
            .ok_or_else(|| TokenError::MalformedToken("Missing JWT payload segment".into()))?;
        let signature_b64 = segments
            .next()
            .ok_or_else(|| TokenError::MalformedToken("Missing JWT signature segment".into()))?;
        if segments.next().is_some() {
            return Err(TokenError::MalformedToken("Too many segments in JWT".into()).into());
        }

        let header_bytes = URL_SAFE_NO_PAD
            .decode(header_b64)
            .or_else(|_| URL_SAFE.decode(header_b64))
            .map_err(|e| TokenError::MalformedToken(format!("JWT header base64 error: {e}")))?;
        let header: ServiceJwtHeader = serde_json::from_slice(&header_bytes)
            .map_err(|e| TokenError::MalformedToken(format!("JWT header JSON error: {e}")))?;

        let alg_id = alg_id_from_str(&header.alg);
        if alg_id == ALG_NONE {
            return Err(TokenError::MalformedToken(format!(
                "Unsupported JWT algorithm '{}': ATProto Service Auth requires {ES256K_SERVICE_AUTH_ALG} or {ES256_SERVICE_AUTH_ALG}",
                header.alg
            ))
            .into());
        }

        let claims = parse_service_jwt_claims_unverified(token)?;
        let issuer = claims
            .iss
            .as_deref()
            .ok_or(TokenError::MissingIssuer)?
            .to_string();

        let signing_key = self.resolve_atproto_key(&issuer, now_secs).await?;
        if !is_alg_bound_to_curve(signing_key.curve_id(), alg_id) {
            return match &*signing_key {
                AtprotoVerifyingKey::Secp256k1(_) => Err(TokenError::MalformedToken(format!(
                    "Unsupported JWT algorithm '{}' for secp256k1 DID key: requires {ES256K_SERVICE_AUTH_ALG}",
                    header.alg
                ))
                .into()),
                AtprotoVerifyingKey::P256(_) => Err(TokenError::MalformedToken(format!(
                    "Unsupported JWT algorithm '{}' for P-256 DID key: requires {ES256_SERVICE_AUTH_ALG}",
                    header.alg
                ))
                .into()),
            };
        }

        let signing_input = format!("{header_b64}.{payload_b64}");
        let signature_bytes = URL_SAFE_NO_PAD
            .decode(signature_b64)
            .or_else(|_| URL_SAFE.decode(signature_b64))
            .map_err(|e| TokenError::MalformedToken(format!("JWT signature base64 error: {e}")))?;

        let sig_ok = match &*signing_key {
            AtprotoVerifyingKey::Secp256k1(vk) => {
                let signature = Secp256k1Signature::from_slice(&signature_bytes).map_err(|_| {
                    TokenError::MalformedToken("Malformed secp256k1 ECDSA signature".into())
                })?;
                vk.verify(signing_input.as_bytes(), &signature).is_ok()
            }
            AtprotoVerifyingKey::P256(vk) => {
                let signature =
                    p256::ecdsa::Signature::from_slice(&signature_bytes).map_err(|_| {
                        TokenError::MalformedToken("Malformed P-256 ECDSA signature".into())
                    })?;
                vk.verify(signing_input.as_bytes(), &signature).is_ok()
            }
        };

        if !sig_ok {
            self.key_cache.invalidate(&issuer);
            return Err(TokenError::InvalidSignature.into());
        }

        let exp = claims.exp.ok_or_else(|| {
            TokenError::MalformedToken("Missing mandatory 'exp' claim in Service Auth JWT".into())
        })?;
        if !is_service_jwt_exp_valid(exp, now_secs, leeway_secs) {
            return Err(TokenError::Expired { exp, now: now_secs }.into());
        }

        if !expected_audiences.is_empty() {
            let aud = claims.aud.as_ref().ok_or(TokenError::MissingAudience)?;
            if !expected_audiences.iter().any(|expected| *expected == aud) {
                return Err(TokenError::AudienceMismatch {
                    expected: expected_audiences.join(" | "),
                    actual: aud.clone(),
                }
                .into());
            }
        }

        if claims.iss.is_none() || claims.viewer_did().is_none() {
            return Err(TokenError::MissingDid.into());
        }

        Ok(claims)
    }

    /// Convenience wrapper verifying an `Authorization: Bearer <jwt>` header and returning the authenticated issuer DID.
    ///
    /// # Errors
    /// Returns [`AtprotoOAuthError`] if verification fails.
    pub async fn verify_service_jwt(
        &self,
        auth_header: &str,
        expected_audience: Option<&str>,
        now_secs: u64,
    ) -> Result<String, AtprotoOAuthError> {
        let audiences: Vec<&str> = expected_audience.into_iter().collect();
        let claims = self
            .verify_service_jwt_claims(
                auth_header,
                &audiences,
                now_secs,
                SERVICE_JWT_CLOCK_SKEW_LEEWAY_SECS,
            )
            .await?;
        claims.iss.ok_or_else(|| TokenError::MissingDid.into())
    }

    /// Returns the number of cached DID signing keys across all shards.
    #[must_use]
    pub fn cache_len(&self) -> usize {
        self.key_cache.len()
    }

    /// Clears all cached DID signing keys.
    pub fn clear_cache(&self) {
        self.key_cache.clear();
    }
}

/// Extracts the compact JWT from an `Authorization: Bearer <jwt>` header or returns a raw JWT string.
///
/// # Errors
/// Returns [`TokenError::InvalidScheme`] or [`TokenError::MalformedToken`] if the header is empty or uses a non-Bearer scheme.
pub fn extract_bearer_token(auth_header_or_token: &str) -> Result<&str, AtprotoOAuthError> {
    let trimmed = auth_header_or_token.trim();
    if trimmed.is_empty() {
        return Err(TokenError::MissingHeader.into());
    }
    if trimmed.eq_ignore_ascii_case("Bearer") {
        return Err(TokenError::MalformedToken("Empty Bearer token".into()).into());
    }
    if let Some((scheme, rest)) = trimmed.split_once(char::is_whitespace) {
        if !scheme.eq_ignore_ascii_case("Bearer") {
            return Err(TokenError::InvalidScheme {
                expected: "Bearer".into(),
                actual: scheme.to_string(),
            }
            .into());
        }
        let token = rest.trim();
        if token.is_empty() {
            return Err(TokenError::MalformedToken("Empty Bearer token".into()).into());
        }
        Ok(token)
    } else {
        Ok(trimmed)
    }
}

/// Decodes the unverified payload claims of a 3-segment JWT.
///
/// # Security Warning
/// Do not trust the returned claims for authentication until the signature has been verified via [`ServiceAuthVerifier`].
///
/// # Errors
/// Returns [`AtprotoOAuthError`] if the JWT does not have 3 segments, has invalid Base64URL encoding, or fails JSON parsing.
pub fn parse_service_jwt_claims_unverified(
    token: &str,
) -> Result<ServiceJwtClaims, AtprotoOAuthError> {
    let mut parts = token.trim().split('.');
    let _header = parts
        .next()
        .ok_or_else(|| TokenError::MalformedToken("Missing JWT header".into()))?;
    let payload_b64 = parts
        .next()
        .ok_or_else(|| TokenError::MalformedToken("Missing JWT payload".into()))?;
    let sig_b64 = parts
        .next()
        .ok_or_else(|| TokenError::MalformedToken("Missing JWT signature".into()))?;
    if parts.next().is_some() || sig_b64.is_empty() {
        return Err(TokenError::MalformedToken(
            "Invalid JWT format: must have 3 non-empty segments".into(),
        )
        .into());
    }

    let decoded = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .or_else(|_| URL_SAFE.decode(payload_b64))
        .map_err(|e| TokenError::MalformedToken(format!("Base64 decode error: {e}")))?;

    serde_json::from_slice::<ServiceJwtClaims>(&decoded)
        .map_err(|e| TokenError::MalformedToken(format!("JSON payload parse error: {e}")).into())
}

/// Decodes an ATProto `Multikey` (`publicKeyMultibase`) string (`z...` base58btc or `u...` base64url) into raw bytes.
///
/// # Errors
/// Returns [`AtprotoOAuthError`] on unsupported multibase prefixes or invalid base58btc/base64url characters.
pub fn decode_multikey(multibase: &str) -> Result<Vec<u8>, AtprotoOAuthError> {
    let bytes = multibase.as_bytes();
    if bytes.len() < 2 {
        return Err(CryptoError::InvalidKey("Malformed multibase key: too short".into()).into());
    }

    let decoded = match bytes[0] {
        b'z' => bs58_decode(&multibase[1..])?,
        b'u' => URL_SAFE_NO_PAD.decode(&multibase[1..]).map_err(|e| {
            CryptoError::Base64Decode(format!("Malformed base64url multibase: {e}"))
        })?,
        other => {
            return Err(CryptoError::InvalidKey(format!(
                "Unsupported multibase prefix byte {other:#04x}"
            ))
            .into())
        }
    };

    if decoded.first().copied() == Some(0x00) {
        Ok(decoded[1..].to_vec())
    } else {
        Ok(decoded)
    }
}

/// Encodes a secp256k1 verifying key as a canonical ATProto `zQ3sh...` `publicKeyMultibase` string
/// using the standard 2-byte unsigned varint prefix `[0xe7, 0x01]`.
#[must_use]
pub fn encode_multikey_secp256k1(key: &Secp256k1VerifyingKey) -> String {
    let sec1 = key.to_sec1_point(true);
    let mut raw = Vec::with_capacity(2 + COMPRESSED_EC_PUBLIC_KEY_LEN);
    raw.extend_from_slice(&MULTIKEY_SECP256K1_VARINT);
    raw.extend_from_slice(sec1.as_bytes());
    format!("z{}", bs58_encode(&raw))
}

/// Encodes a NIST P-256 verifying key as a canonical ATProto `zDna...` `publicKeyMultibase` string
/// using the standard 2-byte unsigned varint prefix `[0x80, 0x24]`.
#[must_use]
pub fn encode_multikey_p256(key: &p256::ecdsa::VerifyingKey) -> String {
    let sec1 = key.to_sec1_point(true);
    let mut raw = Vec::with_capacity(2 + COMPRESSED_EC_PUBLIC_KEY_LEN);
    raw.extend_from_slice(&MULTIKEY_P256_VARINT);
    raw.extend_from_slice(sec1.as_bytes());
    format!("z{}", bs58_encode(&raw))
}

fn bs58_decode(input: &str) -> Result<Vec<u8>, AtprotoOAuthError> {
    const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    if input.is_empty() {
        return Ok(Vec::new());
    }
    if input.starts_with('1') {
        return Err(
            CryptoError::InvalidKey("Malformed base58 key: leading zero byte".into()).into(),
        );
    }

    let mut out: Vec<u8> = Vec::with_capacity(input.len());
    for byte in input.bytes() {
        let digit = ALPHABET.iter().position(|&c| c == byte).ok_or_else(|| {
            CryptoError::InvalidKey(format!("Invalid base58 character {byte:#04x}"))
        })?;
        let mut carry = digit as u32;
        for b in &mut out {
            let acc = (*b as u32) * 58 + carry;
            *b = (acc & 0xff) as u8;
            carry = acc >> 8;
        }
        while carry > 0 {
            out.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }

    out.reverse();
    Ok(out)
}

fn bs58_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut digits = vec![0u8];
    for &b in bytes {
        let mut carry = u32::from(b);
        for d in &mut digits {
            let val = u32::from(*d) * 256 + carry;
            *d = (val % 58) as u8;
            carry = val / 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut out = String::with_capacity(digits.len());
    for &b in bytes.iter().take_while(|&&b| b == 0) {
        let _ = b;
        out.push('1');
    }
    for &d in digits.iter().rev() {
        out.push(ALPHABET[d as usize] as char);
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]
mod tests {
    use super::*;
    use k256::ecdsa::signature::Signer as _;
    use k256::ecdsa::SigningKey as Secp256k1SigningKey;
    use p256::ecdsa::SigningKey as P256SigningKey;

    fn sample_did_doc(did: &str, multibase: &str) -> DidDocument {
        serde_json::from_value(serde_json::json!({
            "id": did,
            "alsoKnownAs": ["at://alice.bsky.social"],
            "verificationMethod": [{
                "id": format!("{did}#atproto"),
                "type": "Multikey",
                "controller": did,
                "publicKeyMultibase": multibase
            }],
            "service": [{
                "id": "#atproto_pds",
                "type": "AtprotoPersonalDataServer",
                "serviceEndpoint": "https://bsky.social"
            }]
        }))
        .unwrap()
    }

    #[test]
    fn test_secp256k1_and_p256_multikey_roundtrip() {
        let k256_sk = Secp256k1SigningKey::from_bytes((&[0x11u8; 32]).into()).unwrap();
        let k256_vk = *k256_sk.verifying_key();
        let mb_k256 = encode_multikey_secp256k1(&k256_vk);
        assert!(mb_k256.starts_with("zQ3sh"));

        let doc_k256 = sample_did_doc("did:plc:alice123", &mb_k256);
        let extracted_k256 =
            ServiceAuthVerifier::extract_signing_key_from_document(&doc_k256).unwrap();
        assert_eq!(extracted_k256, k256_vk);

        let p256_sk = P256SigningKey::from_bytes((&[0x22u8; 32]).into()).unwrap();
        let p256_vk = *p256_sk.verifying_key();
        let mb_p256 = encode_multikey_p256(&p256_vk);
        assert!(mb_p256.starts_with("zDna"));

        let doc_p256 = sample_did_doc("did:plc:bob123", &mb_p256);
        let extracted_p256 =
            ServiceAuthVerifier::extract_atproto_key_from_document(&doc_p256).unwrap();
        assert_eq!(extracted_p256, AtprotoVerifyingKey::P256(p256_vk));
        assert!(ServiceAuthVerifier::extract_signing_key_from_document(&doc_p256).is_err());
    }

    #[tokio::test]
    async fn test_verify_service_jwt_es256k_and_es256_and_rotation() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let plc_server = MockServer::start().await;
        let k256_sk = Secp256k1SigningKey::from_bytes((&[0x33u8; 32]).into()).unwrap();
        let k256_vk = *k256_sk.verifying_key();
        let did = "did:plc:ewvi7nxzyoun6zhxrhs64oiz";
        let doc = sample_did_doc(did, &encode_multikey_secp256k1(&k256_vk));

        Mock::given(method("GET"))
            .and(path(format!("/{did}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(&doc))
            .mount(&plc_server)
            .await;

        let verifier = ServiceAuthVerifier::with_plc_url(plc_server.uri(), true);

        let header_b64 = URL_SAFE_NO_PAD.encode(r#"{"alg":"ES256K","typ":"JWT"}"#);
        let payload_b64 = URL_SAFE_NO_PAD.encode(
            serde_json::json!({
                "iss": did,
                "aud": "did:web:feed.example.com",
                "exp": 2_000_000_000u64,
                "iat": 1_999_999_900u64
            })
            .to_string(),
        );
        let signing_input = format!("{header_b64}.{payload_b64}");
        let sig: Secp256k1Signature = k256_sk.sign(signing_input.as_bytes());
        let token = format!(
            "Bearer {signing_input}.{}",
            URL_SAFE_NO_PAD.encode(sig.to_bytes())
        );

        let verified_did = verifier
            .verify_service_jwt(&token, Some("did:web:feed.example.com"), 1_999_999_950)
            .await
            .unwrap();
        assert_eq!(verified_did, did);
        assert_eq!(verifier.cache_len(), 1);

        // Audience mismatch rejected
        assert!(verifier
            .verify_service_jwt(&token, Some("did:web:wrong.example.com"), 1_999_999_950)
            .await
            .is_err());

        // Missing exp claim rejected
        let no_exp_payload_b64 = URL_SAFE_NO_PAD.encode(
            serde_json::json!({
                "iss": did,
                "aud": "did:web:feed.example.com",
                "iat": 1_999_999_900u64
            })
            .to_string(),
        );
        let no_exp_input = format!("{header_b64}.{no_exp_payload_b64}");
        let no_exp_sig: Secp256k1Signature = k256_sk.sign(no_exp_input.as_bytes());
        let no_exp_token = format!(
            "Bearer {no_exp_input}.{}",
            URL_SAFE_NO_PAD.encode(no_exp_sig.to_bytes())
        );
        assert!(matches!(
            verifier
                .verify_service_jwt(
                    &no_exp_token,
                    Some("did:web:feed.example.com"),
                    1_999_999_950
                )
                .await,
            Err(AtprotoOAuthError::Token(TokenError::MalformedToken(_)))
        ));

        // Missing aud claim rejected when expected_audience is required
        let no_aud_payload_b64 = URL_SAFE_NO_PAD.encode(
            serde_json::json!({
                "iss": did,
                "exp": 2_000_000_000u64,
                "iat": 1_999_999_900u64
            })
            .to_string(),
        );
        let no_aud_input = format!("{header_b64}.{no_aud_payload_b64}");
        let no_aud_sig: Secp256k1Signature = k256_sk.sign(no_aud_input.as_bytes());
        let no_aud_token = format!(
            "Bearer {no_aud_input}.{}",
            URL_SAFE_NO_PAD.encode(no_aud_sig.to_bytes())
        );
        assert!(matches!(
            verifier
                .verify_service_jwt(
                    &no_aud_token,
                    Some("did:web:feed.example.com"),
                    1_999_999_950
                )
                .await,
            Err(AtprotoOAuthError::Token(TokenError::MissingAudience))
        ));

        // Expired token rejected
        assert!(verifier
            .verify_service_jwt(&token, Some("did:web:feed.example.com"), 2_000_000_100)
            .await
            .is_err());

        // Forged signature invalidates cache
        let forged_sk = Secp256k1SigningKey::from_bytes((&[0x44u8; 32]).into()).unwrap();
        let forged_sig: Secp256k1Signature = forged_sk.sign(signing_input.as_bytes());
        let forged_token = format!(
            "Bearer {signing_input}.{}",
            URL_SAFE_NO_PAD.encode(forged_sig.to_bytes())
        );
        assert!(verifier
            .verify_service_jwt(
                &forged_token,
                Some("did:web:feed.example.com"),
                1_999_999_950
            )
            .await
            .is_err());
        assert_eq!(verifier.cache_len(), 0);
    }

    #[test]
    fn test_did_key_cache_operations_and_eviction() {
        let cache = DidKeyCache::new(60);
        assert!(cache.is_empty());
        assert_eq!(cache.ttl_secs(), 60);

        let sk = Secp256k1SigningKey::from_bytes((&[0x55u8; 32]).into()).unwrap();
        let vk = *sk.verifying_key();
        cache.insert("did:plc:test1", vk, 100);
        assert_eq!(cache.len(), 1);
        assert!(cache.get("did:plc:test1", 120).is_some());
        assert!(cache.get("did:plc:test1", 165).is_none());

        cache.invalidate("did:plc:test1");
        assert!(cache.is_empty());
    }

    #[test]
    fn test_is_valid_service_did_and_extract_bearer_token_and_multikey_edge_cases() {
        assert!(is_valid_service_did("did:plc:ewvi7nxzyoun6zhxrhs64oiz"));
        assert!(is_valid_service_did("did:web:feed.example.com"));
        assert!(is_valid_service_did("did:web:example.com:user:alice"));
        assert!(!is_valid_service_did("did:plc:"));
        assert!(!is_valid_service_did("did:plc:UPPERCASE"));
        assert!(!is_valid_service_did("did:web:"));
        assert!(!is_valid_service_did("did:web:-bad.example.com"));
        assert!(!is_valid_service_did("did:web:bad-.example.com"));
        assert!(!is_valid_service_did("did:key:zQ3sh"));

        assert_eq!(
            extract_bearer_token("Bearer abc.def.ghi").unwrap(),
            "abc.def.ghi"
        );
        assert_eq!(
            extract_bearer_token("bearer   abc.def.ghi  ").unwrap(),
            "abc.def.ghi"
        );
        assert_eq!(extract_bearer_token("abc.def.ghi").unwrap(), "abc.def.ghi");
        assert!(extract_bearer_token("   ").is_err());
        assert!(extract_bearer_token("Bearer   ").is_err());
        assert!(extract_bearer_token("DPoP abc.def.ghi").is_err());

        // decode_multikey & bs58 edge cases
        assert!(decode_multikey("").is_err());
        assert!(decode_multikey("z").is_err());
        assert!(decode_multikey("mAAAA").is_err());
        assert!(decode_multikey("z1abc").is_err());
        assert!(decode_multikey("z0OIl").is_err());
        assert!(decode_multikey("u!!!").is_err());

        let u_encoded = format!("u{}", URL_SAFE_NO_PAD.encode([0x00, 0xe7, 0x01, 0x02]));
        assert_eq!(decode_multikey(&u_encoded).unwrap(), vec![0xe7, 0x01, 0x02]);
        assert_eq!(bs58_decode("").unwrap(), Vec::<u8>::new());
        assert!(bs58_encode(&[0x00, 0x01, 0x02]).starts_with('1'));

        // Legacy 1-byte 0xe7 secp256k1 Multikey + error branches
        let k256_sk = Secp256k1SigningKey::from_bytes((&[0x19u8; 32]).into()).unwrap();
        let k256_vk = *k256_sk.verifying_key();
        let mut legacy_raw = vec![MULTIKEY_SECP256K1_LEGACY_PREFIX];
        legacy_raw.extend_from_slice(k256_vk.to_sec1_point(true).as_bytes());
        let legacy_mb = format!("z{}", bs58_encode(&legacy_raw));
        let legacy_doc = sample_did_doc("did:plc:legacy123", &legacy_mb);
        assert_eq!(
            ServiceAuthVerifier::extract_atproto_key_from_document(&legacy_doc).unwrap(),
            AtprotoVerifyingKey::Secp256k1(k256_vk)
        );

        // Invalid SEC1 tag bytes and curve point bytes
        let mut bad_tag_k256 = vec![0xe7, 0x01, 0x04];
        bad_tag_k256.extend_from_slice(&[0x11u8; 32]);
        let bad_tag_doc = sample_did_doc(
            "did:plc:badtag1",
            &format!("z{}", bs58_encode(&bad_tag_k256)),
        );
        assert!(ServiceAuthVerifier::extract_atproto_key_from_document(&bad_tag_doc).is_err());

        let mut bad_tag_p256 = vec![0x80, 0x24, 0x04];
        bad_tag_p256.extend_from_slice(&[0x11u8; 32]);
        let bad_tag_p256_doc = sample_did_doc(
            "did:plc:badtag2",
            &format!("z{}", bs58_encode(&bad_tag_p256)),
        );
        assert!(ServiceAuthVerifier::extract_atproto_key_from_document(&bad_tag_p256_doc).is_err());

        // Valid 0x02 tag but X >= field prime is not on P-256 curve
        let mut off_curve_p256 = vec![0x80, 0x24, 0x02];
        off_curve_p256.extend_from_slice(&[0xffu8; 32]);
        let off_curve_p256_doc = sample_did_doc(
            "did:plc:offcurvep256",
            &format!("z{}", bs58_encode(&off_curve_p256)),
        );
        assert!(
            ServiceAuthVerifier::extract_atproto_key_from_document(&off_curve_p256_doc).is_err()
        );

        // Valid 0x02 tag but X >= field prime is not on secp256k1 curve
        let mut off_curve_k256 = vec![0xe7, 0x01, 0x02];
        off_curve_k256.extend_from_slice(&[0xffu8; 32]);
        let off_curve_k256_doc = sample_did_doc(
            "did:plc:offcurvek256",
            &format!("z{}", bs58_encode(&off_curve_k256)),
        );
        assert!(
            ServiceAuthVerifier::extract_atproto_key_from_document(&off_curve_k256_doc).is_err()
        );

        // Wrong prefix / length
        let wrong_prefix_doc = sample_did_doc(
            "did:plc:wrongprefix",
            &format!("z{}", bs58_encode(&[0x99, 0x01, 0x02, 0x03])),
        );
        assert!(ServiceAuthVerifier::extract_atproto_key_from_document(&wrong_prefix_doc).is_err());

        // Missing #atproto verificationMethod and missing publicKeyMultibase
        let empty_doc: DidDocument = serde_json::from_value(serde_json::json!({
            "id": "did:plc:empty",
            "verificationMethod": []
        }))
        .unwrap();
        assert!(ServiceAuthVerifier::extract_atproto_key_from_document(&empty_doc).is_err());

        let no_mb_doc: DidDocument = serde_json::from_value(serde_json::json!({
            "id": "did:plc:nomb",
            "verificationMethod": [{
                "id": "did:plc:nomb#atproto",
                "type": "Multikey",
                "controller": "did:plc:nomb"
            }]
        }))
        .unwrap();
        assert!(ServiceAuthVerifier::extract_atproto_key_from_document(&no_mb_doc).is_err());
    }

    #[test]
    fn test_did_key_cache_shard_eviction_and_verifier_accessors() {
        let cache = DidKeyCache::default();
        assert_eq!(cache.ttl_secs(), DID_KEY_CACHE_TTL_SECS);
        let sk = Secp256k1SigningKey::from_bytes((&[0x66u8; 32]).into()).unwrap();
        let vk = *sk.verifying_key();

        // Populate a single shard up to MAX_DID_KEY_CACHE_PER_SHARD + 2 to exercise both
        // expired-entry retention pruning and oldest-entry eviction.
        let target_shard = DidKeyCache::shard_idx("did:plc:shard0");
        let mut same_shard_dids = Vec::new();
        let mut i = 0usize;
        while same_shard_dids.len() <= MAX_DID_KEY_CACHE_PER_SHARD + 2 {
            let candidate = format!("did:plc:cand{i}");
            if DidKeyCache::shard_idx(&candidate) == target_shard {
                same_shard_dids.push(candidate);
            }
            i += 1;
        }

        // Insert MAX_DID_KEY_CACHE_PER_SHARD entries with fresh timestamps, then 1 more to trigger oldest eviction
        for (idx, d) in same_shard_dids
            .iter()
            .take(MAX_DID_KEY_CACHE_PER_SHARD)
            .enumerate()
        {
            cache.insert(d, vk, 1_000 + idx as u64);
        }
        assert_eq!(cache.len(), MAX_DID_KEY_CACHE_PER_SHARD);
        cache.insert(
            &same_shard_dids[MAX_DID_KEY_CACHE_PER_SHARD],
            vk,
            1_000 + MAX_DID_KEY_CACHE_PER_SHARD as u64,
        );
        assert_eq!(cache.len(), MAX_DID_KEY_CACHE_PER_SHARD);
        assert!(cache.get(&same_shard_dids[0], 1_005).is_none());

        // Trigger expired-entry pruning on insert when timestamps advance past TTL
        cache.insert(
            &same_shard_dids[MAX_DID_KEY_CACHE_PER_SHARD + 1],
            vk,
            10_000,
        );
        assert_eq!(cache.len(), 1);
        assert!(cache
            .get_atproto_key(
                &same_shard_dids[MAX_DID_KEY_CACHE_PER_SHARD + 1],
                10_000 + DID_KEY_CACHE_TTL_SECS + 1
            )
            .is_none());

        cache.clear();
        assert!(cache.is_empty());

        let verifier = ServiceAuthVerifier::default();
        let _ = ServiceAuthVerifier::new();
        let custom = ServiceAuthVerifier::with_resolver_and_cache(
            Arc::clone(verifier.resolver()),
            Arc::clone(verifier.key_cache()),
        );
        assert_eq!(custom.cache_len(), 0);
        assert!(format!("{custom:?}").contains("ServiceAuthVerifier"));
        custom.clear_cache();
    }

    #[tokio::test]
    async fn test_verify_service_jwt_p256_and_cross_curve_and_malformed_rejections() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let plc_server = MockServer::start().await;
        let p256_sk = P256SigningKey::from_bytes((&[0x77u8; 32]).into()).unwrap();
        let p256_vk = *p256_sk.verifying_key();
        let p256_did = "did:plc:p256issuer12345678901234";
        let p256_doc = sample_did_doc(p256_did, &encode_multikey_p256(&p256_vk));

        let k256_sk = Secp256k1SigningKey::from_bytes((&[0x88u8; 32]).into()).unwrap();
        let k256_vk = *k256_sk.verifying_key();
        let k256_did = "did:plc:k256issuer12345678901234";
        let k256_doc = sample_did_doc(k256_did, &encode_multikey_secp256k1(&k256_vk));

        Mock::given(method("GET"))
            .and(path(format!("/{p256_did}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(&p256_doc))
            .mount(&plc_server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/{k256_did}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(&k256_doc))
            .mount(&plc_server)
            .await;

        let verifier = ServiceAuthVerifier::with_plc_url(plc_server.uri(), true);

        // resolve_signing_key succeeds for k256 and fails for p256; invalid DID syntax rejected
        assert!(verifier.resolve_signing_key(k256_did, 100).await.is_ok());
        assert!(verifier.resolve_signing_key(p256_did, 100).await.is_err());
        assert!(verifier
            .resolve_atproto_key("did:invalid:syntax", 100)
            .await
            .is_err());

        // Valid ES256 token signed by P-256 DID key
        let es256_hdr = URL_SAFE_NO_PAD.encode(r#"{"alg":"ES256","typ":"JWT"}"#);
        let p256_payload = URL_SAFE_NO_PAD.encode(
            serde_json::json!({
                "iss": p256_did,
                "aud": "did:web:feed.example.com",
                "lxm": "app.bsky.feed.getFeedSkeleton",
                "exp": 2_000_000_000u64
            })
            .to_string(),
        );
        let p256_input = format!("{es256_hdr}.{p256_payload}");
        let p256_sig: p256::ecdsa::Signature = p256_sk.sign(p256_input.as_bytes());
        let p256_token = format!(
            "{p256_input}.{}",
            URL_SAFE_NO_PAD.encode(p256_sig.to_bytes())
        );
        let claims = verifier
            .verify_service_jwt_claims(
                &p256_token,
                &["did:web:feed.example.com"],
                1_999_999_900,
                60,
            )
            .await
            .unwrap();
        assert_eq!(claims.viewer_did(), Some(p256_did));

        // Cross-curve confusion: ES256K header on P-256 DID key -> rejected
        let es256k_hdr = URL_SAFE_NO_PAD.encode(r#"{"alg":"ES256K","typ":"JWT"}"#);
        let cross_p256_token = format!(
            "{es256k_hdr}.{p256_payload}.{}",
            URL_SAFE_NO_PAD.encode(p256_sig.to_bytes())
        );
        assert!(verifier
            .verify_service_jwt(&cross_p256_token, None, 1_999_999_900)
            .await
            .is_err());

        // Cross-curve confusion: ES256 header on secp256k1 DID key -> rejected
        let k256_payload = URL_SAFE_NO_PAD.encode(
            serde_json::json!({
                "iss": k256_did,
                "exp": 2_000_000_000u64
            })
            .to_string(),
        );
        let cross_k256_token = format!(
            "{es256_hdr}.{k256_payload}.{}",
            URL_SAFE_NO_PAD.encode(p256_sig.to_bytes())
        );
        assert!(verifier
            .verify_service_jwt(&cross_k256_token, None, 1_999_999_900)
            .await
            .is_err());

        // Unsupported algorithm RS256 and malformed tokens
        let rs256_hdr = URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256"}"#);
        assert!(verifier
            .verify_service_jwt(&format!("{rs256_hdr}.{k256_payload}.AAAA"), None, 100)
            .await
            .is_err());
        assert!(verifier
            .verify_service_jwt("only_one_segment", None, 100)
            .await
            .is_err());
        assert!(verifier
            .verify_service_jwt("a.b.c.d", None, 100)
            .await
            .is_err());
        assert!(verifier
            .verify_service_jwt("!!!.b.c", None, 100)
            .await
            .is_err());
        assert!(verifier
            .verify_service_jwt(
                &format!("{}.{k256_payload}.AAAA", URL_SAFE_NO_PAD.encode("not-json")),
                None,
                100
            )
            .await
            .is_err());
        assert!(parse_service_jwt_claims_unverified("a.b").is_err());
        assert!(parse_service_jwt_claims_unverified("a.b.").is_err());
        assert!(parse_service_jwt_claims_unverified("a.!!!.c").is_err());
        assert!(parse_service_jwt_claims_unverified(&format!(
            "a.{}.c",
            URL_SAFE_NO_PAD.encode("not-json")
        ))
        .is_err());
    }
}
