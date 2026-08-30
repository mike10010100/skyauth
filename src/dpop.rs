//! RFC 9449 Demonstrating Proof-of-Possession (DPoP) at the Application Layer.
//!
//! This module implements DPoP proof generation, cryptographic binding to asymmetric keys,
//! access token hash (`ath`) derivation, target URI (`htu`) normalization, and inbound
//! proof verification with clock-skew and nonce enforcement according to
//! <https://datatracker.ietf.org/doc/html/rfc9449>.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ahash::AHasher;
use p256::ecdsa::{SigningKey, VerifyingKey};
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
use parking_lot::RwLock;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use url::Url;
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{
    base64url_decode, base64url_decode_fixed, base64url_encode, constant_time_eq,
    jwk_thumbprint_ec_p256, sha256_digest, sign_p256_raw, verify_p256_raw,
    verifying_key_from_coordinates, verifying_key_to_coordinates,
};
use crate::error::{CryptoError, DPoPError};
use crate::store::NUM_SHARDS;

/// Default maximum permitted proof age (300 seconds / 5 minutes).
pub const DEFAULT_MAX_PROOF_AGE: Duration = Duration::from_secs(300);

/// Default allowed clock skew leeway window (60 seconds).
pub const DEFAULT_CLOCK_SKEW_LEEWAY: Duration = Duration::from_secs(60);

/// Elliptic Curve P-256 JSON Web Key (RFC 7517 / RFC 9449 § 4.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JwkEc {
    /// Key type (must be `"EC"`).
    pub kty: String,
    /// Curve designation (must be `"P-256"`).
    pub crv: String,
    /// Uncompressed X coordinate encoded as unpadded Base64URL.
    pub x: String,
    /// Uncompressed Y coordinate encoded as unpadded Base64URL.
    pub y: String,
}

impl JwkEc {
    /// Computes the RFC 7638 SHA-256 canonical JWK Thumbprint (`jkt`).
    ///
    /// # Examples
    ///
    /// ```
    /// use skyauth::dpop::JwkEc;
    ///
    /// let jwk = JwkEc {
    ///     kty: "EC".to_string(),
    ///     crv: "P-256".to_string(),
    ///     x: "l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs".to_string(),
    ///     y: "9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA".to_string(),
    /// };
    /// assert_eq!(jwk.thumbprint(), "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I");
    /// ```
    #[must_use]
    pub fn thumbprint(&self) -> String {
        jwk_thumbprint_ec_p256(&self.x, &self.y)
    }

    /// Reconstructs the [`VerifyingKey`] from the JWK (x, y) coordinates.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidPoint`] or [`CryptoError::Base64Decode`] if the
    /// coordinates are invalid.
    pub fn to_verifying_key(&self) -> Result<VerifyingKey, CryptoError> {
        let x_bytes: [u8; 32] = base64url_decode_fixed(&self.x)?;
        let y_bytes: [u8; 32] = base64url_decode_fixed(&self.y)?;
        verifying_key_from_coordinates(&x_bytes, &y_bytes)
    }
}

/// An ephemeral or persistent ECDSA P-256 keypair for DPoP proof signing.
#[derive(Clone)]
pub struct DPoPKey {
    signing_key: SigningKey,
}

impl PartialEq for DPoPKey {
    fn eq(&self, other: &Self) -> bool {
        self.signing_key.to_bytes() == other.signing_key.to_bytes()
    }
}

impl Eq for DPoPKey {}

impl std::fmt::Debug for DPoPKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DPoPKey")
            .field("thumbprint", &self.jwk_thumbprint())
            .finish()
    }
}

impl serde::Serialize for DPoPKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let pem = self.to_pkcs8_pem().map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(&pem)
    }
}

impl<'de> serde::Deserialize<'de> for DPoPKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::from_pkcs8_pem(&s).map_err(serde::de::Error::custom)
    }
}

impl DPoPKey {
    /// Generates a fresh, cryptographically secure random ECDSA P-256 keypair.
    ///
    /// # Examples
    ///
    /// ```
    /// use skyauth::dpop::DPoPKey;
    ///
    /// let key = DPoPKey::generate();
    /// let jwk = key.public_jwk();
    /// assert_eq!(jwk.kty, "EC");
    /// assert_eq!(jwk.crv, "P-256");
    /// ```
    #[must_use]
    pub fn generate() -> Self {
        Self {
            signing_key: SigningKey::random(&mut rand::thread_rng()),
        }
    }

    /// Imports an ECDSA P-256 private key from PKCS#8 DER bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidKey`] if the bytes cannot be parsed.
    pub fn from_pkcs8_der(der_bytes: &[u8]) -> Result<Self, CryptoError> {
        let signing_key = SigningKey::from_pkcs8_der(der_bytes)
            .map_err(|e| CryptoError::InvalidKey(format!("Invalid PKCS#8 DER key: {e}")))?;
        Ok(Self { signing_key })
    }

    /// Imports an ECDSA P-256 private key from a PKCS#8 PEM string.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Pem`] if the PEM string is invalid.
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self, CryptoError> {
        let signing_key = SigningKey::from_pkcs8_pem(pem)
            .map_err(|e| CryptoError::Pem(format!("Invalid PKCS#8 PEM key: {e}")))?;
        Ok(Self { signing_key })
    }

    /// Exports the private key as a PKCS#8 PEM formatted string.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Pem`] if encoding fails.
    pub fn to_pkcs8_pem(&self) -> Result<String, CryptoError> {
        self.signing_key
            .to_pkcs8_pem(LineEnding::LF)
            .map(|zeroizing| zeroizing.as_str().to_string())
            .map_err(|e| CryptoError::Pem(format!("Failed to export PKCS#8 PEM: {e}")))
    }

    /// Exports the private key scalar as a raw 32-byte array.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(&self.signing_key.to_bytes());
        *out
    }

    /// Exports the private key as an unpadded Base64URL string.
    #[must_use]
    pub fn to_bytes_b64(&self) -> String {
        let mut raw = Zeroizing::new([0u8; 32]);
        raw.copy_from_slice(&self.signing_key.to_bytes());
        base64url_encode(&*raw)
    }

    /// Imports an ECDSA P-256 private key from raw 32-byte scalar bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidKey`] if the bytes cannot be parsed into a valid P-256 scalar.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, CryptoError> {
        let signing_key = SigningKey::from_slice(bytes)
            .map_err(|e| CryptoError::InvalidKey(format!("Invalid P-256 scalar bytes: {e}")))?;
        Ok(Self { signing_key })
    }

    /// Imports an ECDSA P-256 private key from a Base64URL-encoded scalar string.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] if decoding or key parsing fails.
    pub fn from_bytes_b64(b64: &str) -> Result<Self, CryptoError> {
        let mut bytes = base64url_decode(b64)?;
        let res = Self::from_slice(&bytes);
        bytes.zeroize();
        res
    }

    /// Derives the public [`JwkEc`] representation corresponding to this keypair.
    #[must_use]
    pub fn public_jwk(&self) -> JwkEc {
        let verifying_key = self.signing_key.verifying_key();
        let (x_bytes, y_bytes) = verifying_key_to_coordinates(verifying_key);
        JwkEc {
            kty: "EC".to_string(),
            crv: "P-256".to_string(),
            x: base64url_encode(&x_bytes),
            y: base64url_encode(&y_bytes),
        }
    }

    /// Computes the RFC 7638 SHA-256 JWK Thumbprint (`jkt`) for this key's public component.
    #[must_use]
    pub fn jwk_thumbprint(&self) -> String {
        self.public_jwk().thumbprint()
    }

    /// Signs an RFC 9449 DPoP proof JWT for an outgoing HTTP request.
    ///
    /// # Parameters
    ///
    /// - `htm`: The HTTP request method (e.g. `"POST"` or `"GET"`). Automatically normalized to uppercase.
    /// - `htu`: The HTTP request target URI. Automatically normalized per RFC 9449 § 4.2.
    /// - `nonce`: Optional server-provided challenge nonce.
    /// - `ath`: Optional access token hash (computed via [`compute_access_token_hash`]).
    ///
    /// # Errors
    ///
    /// Returns [`DPoPError`] if the URI is invalid, serialization fails, or signing fails.
    pub fn create_proof(
        &self,
        htm: &str,
        htu: &str,
        nonce: Option<&str>,
        ath: Option<&str>,
    ) -> Result<String, DPoPError> {
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| DPoPError::ClockSkew(e.to_string()))?
            .as_secs();

        self.create_proof_internal(htm, htu, nonce, ath, now_secs, None)
    }

    /// Internal helper allowing deterministic injection of timestamp and `jti` (for testing/RFC vectors).
    pub(crate) fn create_proof_internal(
        &self,
        htm: &str,
        htu: &str,
        nonce: Option<&str>,
        ath: Option<&str>,
        iat_secs: u64,
        jti_override: Option<&str>,
    ) -> Result<String, DPoPError> {
        let jti = match jti_override {
            Some(j) => j.to_string(),
            None => {
                let mut jti_bytes = [0u8; 16];
                rand::thread_rng().fill_bytes(&mut jti_bytes);
                base64url_encode(&jti_bytes)
            }
        };

        let normalized_htm = htm.trim().to_uppercase();
        let normalized_htu = normalize_htu(htu)?;

        let header = serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "ES256",
            "jwk": self.public_jwk()
        });

        let mut payload = serde_json::Map::new();
        payload.insert("jti".to_string(), serde_json::Value::String(jti));
        payload.insert("htm".to_string(), serde_json::Value::String(normalized_htm));
        payload.insert("htu".to_string(), serde_json::Value::String(normalized_htu));
        payload.insert(
            "iat".to_string(),
            serde_json::Value::Number(iat_secs.into()),
        );

        if let Some(n) = nonce {
            if !n.trim().is_empty() {
                payload.insert(
                    "nonce".to_string(),
                    serde_json::Value::String(n.trim().to_string()),
                );
            }
        }

        if let Some(a) = ath {
            if !a.trim().is_empty() {
                payload.insert(
                    "ath".to_string(),
                    serde_json::Value::String(a.trim().to_string()),
                );
            }
        }

        let header_str =
            serde_json::to_string(&header).map_err(|e| DPoPError::Serialization(e.to_string()))?;
        let payload_str = serde_json::to_string(&serde_json::Value::Object(payload))
            .map_err(|e| DPoPError::Serialization(e.to_string()))?;

        let header_b64 = base64url_encode(header_str.as_bytes());
        let payload_b64 = base64url_encode(payload_str.as_bytes());

        let signing_input = format!("{header_b64}.{payload_b64}");
        let sig_bytes = sign_p256_raw(&self.signing_key, signing_input.as_bytes())?;
        let sig_b64 = base64url_encode(&sig_bytes);

        Ok(format!("{signing_input}.{sig_b64}"))
    }
}

/// Decoded and validated claims from an RFC 9449 DPoP proof payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DPoPProofClaims {
    /// Unique JWT identifier preventing replay attacks.
    pub jti: String,
    /// HTTP method of the request (`"POST"`, `"GET"`, etc.).
    pub htm: String,
    /// Normalized HTTP target URI without query string or fragment.
    pub htu: String,
    /// Proof creation timestamp in seconds since UNIX epoch.
    pub iat: u64,
    /// Optional proof expiration timestamp in seconds since UNIX epoch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<u64>,
    /// Optional server-provided challenge nonce.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// Optional base64url-encoded access token hash.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ath: Option<String>,
}

/// DPoP proof validator for inbound OAuth requests and Protected Resources.
#[derive(Debug, Clone)]
pub struct DPoPVerifier {
    max_clock_skew: Duration,
    max_proof_age: Duration,
    replay_cache: Option<DPoPReplayCache>,
}

impl Default for DPoPVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl DPoPVerifier {
    /// Creates a new DPoP verifier with default timing tolerances (60s skew, 300s age)
    /// and built-in anti-replay protection.
    #[must_use]
    pub fn new() -> Self {
        Self {
            max_clock_skew: DEFAULT_CLOCK_SKEW_LEEWAY,
            max_proof_age: DEFAULT_MAX_PROOF_AGE,
            replay_cache: Some(DPoPReplayCache::new()),
        }
    }

    /// Sets the maximum allowable clock skew leeway.
    #[must_use]
    pub fn with_max_clock_skew(mut self, skew: Duration) -> Self {
        self.max_clock_skew = skew;
        self
    }

    /// Sets the maximum allowable proof age.
    #[must_use]
    pub fn with_max_proof_age(mut self, age: Duration) -> Self {
        self.max_proof_age = age;
        self
    }

    /// Sets a custom or shared [`DPoPReplayCache`].
    #[must_use]
    pub fn with_replay_cache(mut self, cache: DPoPReplayCache) -> Self {
        self.replay_cache = Some(cache);
        self
    }

    /// Configures whether anti-replay protection is enabled for this verifier.
    #[must_use]
    pub fn with_replay_prevention(mut self, enabled: bool) -> Self {
        if enabled {
            if self.replay_cache.is_none() {
                self.replay_cache = Some(DPoPReplayCache::new());
            }
        } else {
            self.replay_cache = None;
        }
        self
    }

    /// Returns a reference to the active [`DPoPReplayCache`], if enabled.
    #[must_use]
    pub fn replay_cache(&self) -> Option<&DPoPReplayCache> {
        self.replay_cache.as_ref()
    }

    /// Verifies an inbound RFC 9449 DPoP proof JWT against expected request parameters.
    ///
    /// # Checks Performed
    ///
    /// 1. Compact JWT format: exactly three period-separated parts.
    /// 2. Header `typ`: must be case-insensitively equal to `"dpop+jwt"`.
    /// 3. Header `alg`: must be `"ES256"`.
    /// 4. Header `jwk`: must be an EC P-256 public key without private key coordinates (`d`).
    /// 5. Cryptographic signature: verifies raw 64-byte IEEE P1363 signature over header and payload.
    /// 6. Method `htm`: case-insensitive match with `expected_htm`.
    /// 7. Target URI `htu`: normalized match with `expected_htu`.
    /// 8. Nonce: if `expected_nonce` is supplied, asserts exact constant-time equality.
    /// 9. Access token hash `ath`: if `expected_ath` is supplied, asserts exact constant-time equality.
    /// 10. Temporal validity: validates `iat` within clock skew and max age, and `exp` if present.
    ///
    /// # Errors
    ///
    /// Returns a specific [`DPoPError`] variant if any validation step fails.
    pub fn verify_proof(
        &self,
        proof_jwt: &str,
        expected_htm: &str,
        expected_htu: &str,
        expected_nonce: Option<&str>,
        expected_ath: Option<&str>,
        now_override: Option<SystemTime>,
    ) -> Result<(DPoPProofClaims, JwkEc), DPoPError> {
        let parts: Vec<&str> = proof_jwt.trim().split('.').collect();
        if parts.len() != 3 {
            return Err(DPoPError::MalformedJwt(format!(
                "Expected 3 parts in compact JWT, got {}",
                parts.len()
            )));
        }

        let header_bytes = base64url_decode(parts[0])?;
        let payload_bytes = base64url_decode(parts[1])?;
        let signature_bytes = base64url_decode(parts[2])?;

        // 1. Validate Header
        let header_val: serde_json::Value = serde_json::from_slice(&header_bytes)
            .map_err(|e| DPoPError::MalformedJwt(format!("Failed to parse header JSON: {e}")))?;

        let typ = header_val
            .get("typ")
            .and_then(|v| v.as_str())
            .ok_or_else(|| DPoPError::InvalidHeaderTyp("Missing 'typ' header".to_string()))?;

        if !typ.eq_ignore_ascii_case("dpop+jwt") {
            return Err(DPoPError::InvalidHeaderTyp(typ.to_string()));
        }

        let alg = header_val
            .get("alg")
            .and_then(|v| v.as_str())
            .ok_or_else(|| DPoPError::UnsupportedAlgorithm("Missing 'alg' header".to_string()))?;

        if alg != "ES256" {
            return Err(DPoPError::UnsupportedAlgorithm(alg.to_string()));
        }

        let jwk_val = header_val.get("jwk").ok_or(DPoPError::MissingJwk)?;

        // Ensure JWK does not contain private key material (RFC 9449 § 4.3 item 7)
        if jwk_val.get("d").is_some() {
            return Err(DPoPError::PrivateKeyInJwk);
        }

        let jwk: JwkEc = serde_json::from_value(jwk_val.clone())
            .map_err(|e| DPoPError::InvalidJwk(e.to_string()))?;

        if jwk.kty != "EC" {
            return Err(DPoPError::InvalidJwk(format!(
                "Expected kty 'EC', got '{}'",
                jwk.kty
            )));
        }
        if jwk.crv != "P-256" {
            return Err(DPoPError::InvalidJwk(format!(
                "Expected crv 'P-256', got '{}'",
                jwk.crv
            )));
        }

        // 2. Verify Cryptographic Signature
        let verifying_key = jwk.to_verifying_key()?;
        let signing_input = format!("{}.{}", parts[0], parts[1]);

        verify_p256_raw(&verifying_key, signing_input.as_bytes(), &signature_bytes)
            .map_err(|_| DPoPError::SignatureVerificationFailed)?;

        // 3. Validate Payload Claims
        let claims: DPoPProofClaims = serde_json::from_slice(&payload_bytes)
            .map_err(|e| DPoPError::MalformedJwt(format!("Failed to parse payload JSON: {e}")))?;

        if claims.jti.trim().is_empty() {
            return Err(DPoPError::MissingClaim("jti"));
        }

        // Method verification (case-insensitive)
        if !claims.htm.eq_ignore_ascii_case(expected_htm) {
            return Err(DPoPError::MethodMismatch {
                expected: expected_htm.to_uppercase(),
                actual: claims.htm,
            });
        }

        // URI verification (normalized comparison)
        let norm_expected_htu = normalize_htu(expected_htu)?;
        let norm_claims_htu = normalize_htu(&claims.htu)?;
        if norm_claims_htu != norm_expected_htu {
            return Err(DPoPError::UriMismatch {
                expected: norm_expected_htu,
                actual: claims.htu,
            });
        }

        // Nonce verification
        if let Some(exp_nonce) = expected_nonce {
            match &claims.nonce {
                Some(actual_nonce) => {
                    if !constant_time_eq(exp_nonce.as_bytes(), actual_nonce.as_bytes()) {
                        return Err(DPoPError::NonceMismatch {
                            expected: exp_nonce.to_string(),
                            actual: actual_nonce.clone(),
                        });
                    }
                }
                None => return Err(DPoPError::MissingNonce),
            }
        }

        // Access token hash (ath) verification
        if let Some(exp_ath) = expected_ath {
            match &claims.ath {
                Some(actual_ath) => {
                    if !constant_time_eq(exp_ath.as_bytes(), actual_ath.as_bytes()) {
                        return Err(DPoPError::AthMismatch {
                            expected: exp_ath.to_string(),
                            actual: actual_ath.clone(),
                        });
                    }
                }
                None => return Err(DPoPError::MissingAth),
            }
        }

        // Timing validations
        let now = match now_override {
            Some(time) => time
                .duration_since(UNIX_EPOCH)
                .map_err(|e| DPoPError::ClockSkew(e.to_string()))?
                .as_secs(),
            None => SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| DPoPError::ClockSkew(e.to_string()))?
                .as_secs(),
        };

        let skew_secs = self.max_clock_skew.as_secs();
        let max_age_secs = self.max_proof_age.as_secs();

        // Check if iat is in future beyond clock skew leeway
        if claims.iat > now.saturating_add(skew_secs) {
            return Err(DPoPError::FutureProof {
                iat: claims.iat,
                now,
                leeway: skew_secs,
            });
        }

        // Check proof age
        if now.saturating_sub(claims.iat) > max_age_secs {
            return Err(DPoPError::ProofTooOld {
                iat: claims.iat,
                now,
                max_age_secs,
            });
        }

        // Check optional exp claim
        if let Some(exp) = claims.exp {
            if exp.saturating_add(skew_secs) < now {
                return Err(DPoPError::ExpiredProof { exp, now });
            }
        }

        // Anti-Replay Check (RFC 9449 § 4.3 item 4 & § 11.1)
        if let Some(ref cache) = self.replay_cache {
            let jkt = jwk.thumbprint();
            let base_validity = claims
                .exp
                .unwrap_or_else(|| claims.iat.saturating_add(max_age_secs));
            let expires_at = base_validity.saturating_add(skew_secs);

            cache.check_and_record(&jkt, &claims.jti, expires_at, now)?;
        }

        Ok((claims, jwk))
    }
}

/// Computes the RFC 9449 Access Token Hash (`ath`) claim.
///
/// `ath` is the unpadded URL-safe Base64 encoding of the SHA-256 hash of the ASCII access token.
///
/// # Examples
///
/// ```
/// use skyauth::dpop::compute_access_token_hash;
///
/// // RFC 9449 Section 7.1 Test Vector
/// let token = "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU";
/// let ath = compute_access_token_hash(token);
/// assert_eq!(ath, "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo");
/// ```
#[must_use]
pub fn compute_access_token_hash(access_token: &str) -> String {
    let digest = sha256_digest(access_token.as_bytes());
    base64url_encode(&digest)
}

/// Normalizes an HTTP target URI (`htu`) according to RFC 9449 § 4.2.
///
/// Transformation rules:
/// - Strips any query component (`?...`).
/// - Strips any fragment component (`#...`).
/// - Lowercases scheme and host.
/// - Removes default ports (HTTP 80, HTTPS 443).
/// - Preserves path casing and normalizes empty path to `/` if appropriate.
///
/// # Errors
///
/// Returns [`DPoPError::InvalidUri`] if the input is not a valid absolute HTTP/HTTPS URI.
pub fn normalize_htu(uri_str: &str) -> Result<String, DPoPError> {
    let trimmed = uri_str.trim();
    if trimmed.is_empty() {
        return Err(DPoPError::InvalidUri(
            "URI string cannot be empty".to_string(),
        ));
    }

    let parsed = Url::parse(trimmed)
        .map_err(|e| DPoPError::InvalidUri(format!("Malformed URI '{trimmed}': {e}")))?;

    let scheme = parsed.scheme().to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return Err(DPoPError::InvalidUri(format!(
            "URI scheme must be 'http' or 'https', got '{scheme}'"
        )));
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| DPoPError::InvalidUri("URI is missing host".to_string()))?
        .to_ascii_lowercase();

    let port_str = match (scheme.as_str(), parsed.port()) {
        ("http", Some(80)) | ("https", Some(443)) | (_, None) => String::new(),
        (_, Some(p)) => format!(":{p}"),
    };

    let path = parsed.path();
    let normalized_path = if path.is_empty() { "/" } else { path };

    Ok(format!("{scheme}://{host}{port_str}{normalized_path}"))
}

/// Extracts a server-issued challenge nonce from an optional header string.
///
/// Trims whitespace and returns `Some(nonce)` if non-empty, or `None` if absent or whitespace-only.
///
/// # Examples
///
/// ```
/// use skyauth::dpop::extract_dpop_nonce;
///
/// assert_eq!(extract_dpop_nonce(Some("nonce-xyz")), Some("nonce-xyz".to_string()));
/// assert_eq!(extract_dpop_nonce(None), None);
/// assert_eq!(extract_dpop_nonce(Some("   ")), None);
/// ```
#[must_use]
pub fn extract_dpop_nonce(header_val: Option<&str>) -> Option<String> {
    header_val.and_then(|v| {
        let trimmed = v.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

/// Origin-keyed in-memory cache for server-issued DPoP challenge nonces.
///
/// Automatically tracks and updates the latest nonce for each Authorization Server
/// and Protected Resource origin.
#[derive(Debug, Default, Clone)]
pub struct DPoPNonceCache {
    cache: Arc<RwLock<HashMap<String, String>>>,
}

impl DPoPNonceCache {
    /// Creates a new empty DPoP nonce cache.
    #[must_use]
    pub fn new() -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Stores a server-issued challenge nonce for an origin URL.
    pub fn set_nonce(&self, origin: &str, nonce: impl Into<String>) {
        let mut guard = self.cache.write();
        guard.insert(origin.trim().to_ascii_lowercase(), nonce.into());
    }

    /// Retrieves the current challenge nonce for an origin URL, if available.
    #[must_use]
    pub fn get_nonce(&self, origin: &str) -> Option<String> {
        let guard = self.cache.read();
        guard.get(&origin.trim().to_ascii_lowercase()).cloned()
    }

    /// Clears the cached nonce for an origin URL.
    pub fn clear_nonce(&self, origin: &str) {
        let mut guard = self.cache.write();
        guard.remove(&origin.trim().to_ascii_lowercase());
    }
}

/// In-memory 64-shard partitioned concurrent cache for tracking consumed DPoP `jti` identifiers.
///
/// Prevents DPoP proof replay attacks within the acceptance time window per RFC 9449 § 4.3 and § 11.1.
/// Keyed on `(jkt, jti)` composite identifiers to enforce uniqueness per public key thumbprint.
#[derive(Debug, Clone)]
pub struct DPoPReplayCache {
    shards: Arc<[RwLock<HashMap<String, u64>>; NUM_SHARDS]>,
}

impl Default for DPoPReplayCache {
    fn default() -> Self {
        Self::new()
    }
}

impl DPoPReplayCache {
    /// Creates a new empty `DPoPReplayCache` partitioned across 64 independent `RwLock` shards.
    #[must_use]
    pub fn new() -> Self {
        let shards = std::array::from_fn(|_| RwLock::new(HashMap::new()));
        Self {
            shards: Arc::new(shards),
        }
    }

    #[inline]
    fn shard_for(&self, key: &str) -> &RwLock<HashMap<String, u64>> {
        use std::hash::{Hash, Hasher};
        let mut hasher = AHasher::default();
        key.hash(&mut hasher);
        let idx = (hasher.finish() as usize) % NUM_SHARDS;
        &self.shards[idx]
    }

    /// Checks if a `(jkt, jti)` pair has already been consumed and is still valid (not expired).
    ///
    /// If not consumed, atomically records the entry with expiration timestamp `expires_at_secs`.
    ///
    /// # Errors
    ///
    /// Returns [`DPoPError::ReplayDetected`] if the `jti` was already consumed and has not yet expired.
    pub fn check_and_record(
        &self,
        jkt: &str,
        jti: &str,
        expires_at_secs: u64,
        now_secs: u64,
    ) -> Result<(), DPoPError> {
        let composite_key = format!("{jkt}:{jti}");
        let shard = self.shard_for(&composite_key);
        let mut guard = shard.write();

        // 1. Check if key already exists and is unexpired
        if let Some(&existing_exp) = guard.get(&composite_key) {
            if existing_exp > now_secs {
                return Err(DPoPError::ReplayDetected {
                    jti: jti.to_string(),
                });
            }
        }

        // 2. Perform lazy pruning if shard has grown large (> 1024 entries)
        if guard.len() > 1024 {
            guard.retain(|_, &mut exp| exp > now_secs);
        }

        // 3. Record the consumed JTI
        guard.insert(composite_key, expires_at_secs);
        Ok(())
    }

    /// Checks if a `(jkt, jti)` has been consumed without modifying state.
    #[must_use]
    pub fn is_consumed(&self, jkt: &str, jti: &str, now_secs: u64) -> bool {
        let composite_key = format!("{jkt}:{jti}");
        let shard = self.shard_for(&composite_key);
        let guard = shard.read();
        if let Some(&exp) = guard.get(&composite_key) {
            exp > now_secs
        } else {
            false
        }
    }

    /// Explicitly prunes all expired entries across all shards.
    pub fn prune_expired(&self, now_secs: u64) {
        for shard in self.shards.iter() {
            let mut guard = shard.write();
            guard.retain(|_, &mut exp| exp > now_secs);
        }
    }

    /// Returns the total number of cached entries across all shards.
    #[must_use]
    pub fn len(&self) -> usize {
        self.shards.iter().map(|s| s.read().len()).sum()
    }

    /// Returns `true` if the cache contains no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Clears all entries from the cache.
    pub fn clear(&self) {
        for shard in self.shards.iter() {
            let mut guard = shard.write();
            guard.clear();
        }
    }
}

/// Server-side DPoP challenge nonce generation and verification per RFC 9449 § 8.
pub trait DPoPServerNonceSource: Send + Sync + 'static {
    /// Generates a fresh challenge nonce.
    fn generate_nonce(&self) -> String;
    /// Verifies whether the presented nonce is valid and active.
    fn verify_nonce(&self, nonce: &str) -> bool;
}

impl<T: DPoPServerNonceSource + ?Sized> DPoPServerNonceSource for Arc<T> {
    fn generate_nonce(&self) -> String {
        (**self).generate_nonce()
    }

    fn verify_nonce(&self, nonce: &str) -> bool {
        (**self).verify_nonce(nonce)
    }
}

/// In-memory implementation of [`DPoPServerNonceSource`] tracking nonces with time-to-live.
#[derive(Debug, Clone)]
pub struct InMemoryServerNonceSource {
    nonces: Arc<RwLock<HashMap<String, u64>>>,
    ttl: Duration,
}

impl InMemoryServerNonceSource {
    /// Creates a new `InMemoryServerNonceSource` with the specified nonce time-to-live.
    #[must_use]
    pub fn new(ttl: Duration) -> Self {
        Self {
            nonces: Arc::new(RwLock::new(HashMap::new())),
            ttl,
        }
    }

    /// Prunes expired nonces from memory.
    pub fn prune_expired(&self, now_secs: u64) {
        let mut guard = self.nonces.write();
        guard.retain(|_, &mut exp| exp > now_secs);
    }
}

impl DPoPServerNonceSource for InMemoryServerNonceSource {
    fn generate_nonce(&self) -> String {
        let mut raw = [0u8; 24];
        rand::thread_rng().fill_bytes(&mut raw);
        let nonce = base64url_encode(&raw);

        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let exp = now_secs.saturating_add(self.ttl.as_secs());

        let mut guard = self.nonces.write();
        if guard.len() > 1024 {
            guard.retain(|_, &mut e| e > now_secs);
        }
        guard.insert(nonce.clone(), exp);
        nonce
    }

    fn verify_nonce(&self, nonce: &str) -> bool {
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let guard = self.nonces.read();
        if let Some(&exp) = guard.get(nonce.trim()) {
            exp > now_secs
        } else {
            false
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]
mod tests {
    use super::*;

    #[test]
    fn test_rfc9449_figure2_token_request_vector() {
        // RFC 9449 Section 5.1 / Figure 2 Official Vector
        let raw_jwt = "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiItQndDM0VTYzZhY2MybFRjIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHBzOi8vc2VydmVyLmV4YW1wbGUuY29tL3Rva2VuIiwiaWF0IjoxNTYyMjYyNjE2fQ.2-GxA6T8lP4vfrg8v-FdWP0A0zdrj8igiMLvqRMUvwnQg4PtFLbdLXiOSsX0x7NVY-FNyJK70nfbV37xRZT3Lg";

        let verifier = DPoPVerifier::new()
            .with_max_clock_skew(Duration::from_secs(3600 * 24 * 365 * 10))
            .with_max_proof_age(Duration::from_secs(3600 * 24 * 365 * 10));

        let (claims, jwk) = verifier
            .verify_proof(
                raw_jwt,
                "POST",
                "https://server.example.com/token",
                None,
                None,
                Some(UNIX_EPOCH + Duration::from_secs(1562262616)),
            )
            .unwrap();

        assert_eq!(claims.jti, "-BwC3ESc6acc2lTc");
        assert_eq!(claims.htm, "POST");
        assert_eq!(claims.htu, "https://server.example.com/token");
        assert_eq!(claims.iat, 1562262616);
        assert_eq!(
            jwk.thumbprint(),
            "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
        );
    }

    #[test]
    fn test_rfc9449_figure13_protected_resource_vector() {
        // RFC 9449 Section 7.1 / Figure 13 Official Vector with Access Token Hash (ath)
        let raw_jwt = "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiJlMWozVl9iS2ljOC1MQUVCIiwiaHRtIjoiR0VUIiwiaHR1IjoiaHR0cHM6Ly9yZXNvdXJjZS5leGFtcGxlLm9yZy9wcm90ZWN0ZWRyZXNvdXJjZSIsImlhdCI6MTU2MjI2MjYxOCwiYXRoIjoiZlVIeU8ycjJaM0RaNTNFc05yV0JiMHhXWG9hTnk1OUlpS0NBcWtzbVFFbyJ9.2oW9RP35yRqzhrtNP86L-Ey71EOptxRimPPToA1plemAgR6pxHF8y6-yqyVnmcw6Fy1dqd-jfxSYoMxhAJpLjA";

        let access_token = "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU";
        let ath = compute_access_token_hash(access_token);
        assert_eq!(ath, "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo");

        let verifier = DPoPVerifier::new()
            .with_max_clock_skew(Duration::from_secs(3600 * 24 * 365 * 10))
            .with_max_proof_age(Duration::from_secs(3600 * 24 * 365 * 10));

        let (claims, jwk) = verifier
            .verify_proof(
                raw_jwt,
                "GET",
                "https://resource.example.org/protectedresource",
                None,
                Some(&ath),
                Some(UNIX_EPOCH + Duration::from_secs(1562262618)),
            )
            .unwrap();

        assert_eq!(claims.jti, "e1j3V_bKic8-LAEB");
        assert_eq!(claims.htm, "GET");
        assert_eq!(claims.htu, "https://resource.example.org/protectedresource");
        assert_eq!(claims.iat, 1562262618);
        assert_eq!(
            claims.ath.as_deref(),
            Some("fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo")
        );
        assert_eq!(
            jwk.thumbprint(),
            "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
        );
    }

    #[test]
    fn test_dpop_proof_generation_and_verification_roundtrip() {
        let key = DPoPKey::generate();
        let uri = "https://pds.example.com/oauth/token?grant_type=authorization_code#frag";
        let nonce = "test-nonce-123";
        let token = "some_sample_access_token";
        let ath = compute_access_token_hash(token);

        let proof = key
            .create_proof("POST", uri, Some(nonce), Some(&ath))
            .unwrap();

        let verifier = DPoPVerifier::new();
        let (claims, jwk) = verifier
            .verify_proof(
                &proof,
                "post",
                "https://pds.example.com/oauth/token",
                Some(nonce),
                Some(&ath),
                None,
            )
            .unwrap();

        assert_eq!(claims.htm, "POST");
        assert_eq!(claims.htu, "https://pds.example.com/oauth/token");
        assert_eq!(claims.nonce.as_deref(), Some(nonce));
        assert_eq!(claims.ath.as_deref(), Some(ath.as_str()));
        assert_eq!(jwk, key.public_jwk());
    }

    #[test]
    fn test_htu_normalization() {
        assert_eq!(
            normalize_htu("https://EXAMPLE.COM:443/oauth/token?foo=bar#baz").unwrap(),
            "https://example.com/oauth/token"
        );
        assert_eq!(
            normalize_htu("http://example.com:80/").unwrap(),
            "http://example.com/"
        );
        assert_eq!(
            normalize_htu("https://example.com:8443/custom/path").unwrap(),
            "https://example.com:8443/custom/path"
        );
    }

    #[test]
    fn test_private_key_in_jwk_rejected() {
        let header = serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "ES256",
            "jwk": {
                "kty": "EC",
                "crv": "P-256",
                "x": "l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs",
                "y": "9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA",
                "d": "some_private_key_coordinate"
            }
        });
        let payload = serde_json::json!({
            "jti": "test-jti",
            "htm": "POST",
            "htu": "https://example.com/token",
            "iat": 1000
        });
        let h_b64 = base64url_encode(header.to_string().as_bytes());
        let p_b64 = base64url_encode(payload.to_string().as_bytes());
        let fake_jwt = format!("{h_b64}.{p_b64}.AAAA");

        let verifier = DPoPVerifier::new();
        let res = verifier.verify_proof(
            &fake_jwt,
            "POST",
            "https://example.com/token",
            None,
            None,
            Some(UNIX_EPOCH + Duration::from_secs(1000)),
        );
        assert!(matches!(res, Err(DPoPError::PrivateKeyInJwk)));
    }

    #[test]
    fn test_extract_dpop_nonce() {
        assert_eq!(
            extract_dpop_nonce(Some("server-issued-nonce-xyz")),
            Some("server-issued-nonce-xyz".to_string())
        );
        assert_eq!(extract_dpop_nonce(None), None);
        assert_eq!(extract_dpop_nonce(Some("   ")), None);
    }

    #[test]
    fn test_dpop_nonce_cache() {
        let cache = DPoPNonceCache::new();
        cache.set_nonce("https://pds.example.com", "nonce-1".to_string());
        assert_eq!(
            cache.get_nonce("https://pds.example.com"),
            Some("nonce-1".to_string())
        );
        cache.set_nonce("https://pds.example.com", "nonce-2".to_string());
        assert_eq!(
            cache.get_nonce("https://pds.example.com"),
            Some("nonce-2".to_string())
        );
        cache.clear_nonce("https://pds.example.com");
        assert_eq!(cache.get_nonce("https://pds.example.com"), None);
    }

    #[test]
    fn test_pkcs8_pem_roundtrip() {
        let key = DPoPKey::generate();
        let pem = key.to_pkcs8_pem().unwrap();
        assert!(pem.contains("BEGIN PRIVATE KEY"));
        let imported = DPoPKey::from_pkcs8_pem(&pem).unwrap();
        assert_eq!(key.public_jwk(), imported.public_jwk());
    }

    #[test]
    fn test_dpop_verifier_replay_detection() {
        let key = DPoPKey::generate();
        let uri = "https://pds.example.com/xrpc/test";
        let proof = key.create_proof("GET", uri, None, None).unwrap();

        let verifier = DPoPVerifier::new();

        // First verification succeeds
        let (claims, jwk) = verifier
            .verify_proof(&proof, "GET", uri, None, None, None)
            .unwrap();
        assert_eq!(jwk.thumbprint(), key.jwk_thumbprint());

        // Replaying the exact same proof fails with ReplayDetected
        let err = verifier
            .verify_proof(&proof, "GET", uri, None, None, None)
            .unwrap_err();
        assert!(matches!(
            err,
            DPoPError::ReplayDetected { ref jti } if jti == &claims.jti
        ));
    }

    #[test]
    fn test_dpop_replay_cache_sharding_and_expiry() {
        let cache = DPoPReplayCache::new();
        let jkt = "test_jkt_123";
        let jti = "test_jti_456";

        assert!(!cache.is_consumed(jkt, jti, 1000));
        assert!(cache.check_and_record(jkt, jti, 1500, 1000).is_ok());
        assert!(cache.is_consumed(jkt, jti, 1000));

        // Replay at t=1200 fails
        let err = cache.check_and_record(jkt, jti, 1500, 1200).unwrap_err();
        assert!(matches!(err, DPoPError::ReplayDetected { .. }));

        // After expiry at t=1600, key is no longer active
        assert!(!cache.is_consumed(jkt, jti, 1600));
        // And can be consumed again
        assert!(cache.check_and_record(jkt, jti, 2000, 1600).is_ok());
    }

    #[test]
    fn test_in_memory_server_nonce_source_lifecycle() {
        let source = InMemoryServerNonceSource::new(Duration::from_secs(60));
        let nonce = source.generate_nonce();
        assert!(source.verify_nonce(&nonce));
        assert!(!source.verify_nonce("invalid-nonce-xyz"));
    }
}
