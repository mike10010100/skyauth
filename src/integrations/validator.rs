//! Access token validation abstractions, JWT validation, and DPoP binding enforcement.
//!
//! Provides:
//! - [`AccessTokenValidator`]: Asynchronous trait for validating access tokens and enforcing RFC 9449 `cnf.jkt` binding.
//! - [`JwtAccessTokenValidator`]: Production-grade RFC 9068 / RFC 9449 cryptographic JWT access token validator.
//! - [`InMemoryTokenValidator`]: In-memory token registry for stateful token validation and testing.
//! - [`JwtAccessTokenClaims`]: Strongly typed RFC 9068 / AT Protocol JWT access token claims.
//! - [`CnfClaim`]: RFC 7800 / RFC 9449 confirmation claim (`cnf.jkt`).

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use p256::ecdsa::VerifyingKey;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use super::AuthenticatedUser;
use crate::crypto::{
    base64url_decode, base64url_encode, constant_time_eq, sha256_digest, sign_p256_raw,
    verify_p256_raw,
};
use crate::error::{CryptoError, IntegrationError, TokenError};
use crate::session::OAuthSession;

/// RFC 7800 / RFC 9449 Confirmation claim (`cnf`) containing the JWK thumbprint (`jkt`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CnfClaim {
    /// RFC 7638 SHA-256 JWK Thumbprint (`jkt`) of the bound DPoP public key.
    pub jkt: String,
}

impl CnfClaim {
    /// Creates a new `CnfClaim` with the given JWK thumbprint.
    #[must_use]
    pub fn new(jkt: impl Into<String>) -> Self {
        Self { jkt: jkt.into() }
    }

    /// Returns a reference to the JWK thumbprint string.
    #[must_use]
    pub fn jkt(&self) -> &str {
        &self.jkt
    }
}

/// Standard claims extracted from an RFC 9068 / AT Protocol JWT Access Token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JwtAccessTokenClaims {
    /// Issuer URL of the Authorization Server (`iss`).
    pub iss: String,
    /// Subject Decentralized Identifier (`sub`), e.g. `did:plc:...` or `did:web:...`.
    pub sub: String,
    /// Target audience / Resource Server identifier (`aud`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<serde_json::Value>,
    /// Expiration timestamp in seconds since epoch (`exp`).
    pub exp: u64,
    /// Not-before timestamp in seconds since epoch (`nbf`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<u64>,
    /// Issued-at timestamp in seconds since epoch (`iat`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<u64>,
    /// Unique token identifier (`jti`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    /// Granted OAuth scopes (`scope`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Confirmation claim binding this token to a DPoP key (`cnf`).
    pub cnf: CnfClaim,
}

impl JwtAccessTokenClaims {
    /// Creates a new `JwtAccessTokenClaims` builder with mandatory claims.
    #[must_use]
    pub fn new(
        iss: impl Into<String>,
        sub: impl Into<String>,
        exp: u64,
        dpop_thumbprint: impl Into<String>,
    ) -> Self {
        Self {
            iss: iss.into(),
            sub: sub.into(),
            aud: None,
            exp,
            nbf: None,
            iat: None,
            jti: None,
            scope: None,
            cnf: CnfClaim::new(dpop_thumbprint),
        }
    }

    /// Sets the audience claim (`aud`).
    #[must_use]
    pub fn with_audience(mut self, aud: impl Into<String>) -> Self {
        self.aud = Some(serde_json::Value::String(aud.into()));
        self
    }

    /// Sets the scope claim (`scope`).
    #[must_use]
    pub fn with_scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = Some(scope.into());
        self
    }

    /// Sets the not-before claim (`nbf`).
    #[must_use]
    pub fn with_nbf(mut self, nbf: u64) -> Self {
        self.nbf = Some(nbf);
        self
    }

    /// Sets the issued-at claim (`iat`).
    #[must_use]
    pub fn with_iat(mut self, iat: u64) -> Self {
        self.iat = Some(iat);
        self
    }

    /// Sets the token identifier claim (`jti`).
    #[must_use]
    pub fn with_jti(mut self, jti: impl Into<String>) -> Self {
        self.jti = Some(jti.into());
        self
    }

    /// Signs this claims payload with an ECDSA P-256 [`p256::ecdsa::SigningKey`] to produce a compact JWT access token.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] if serialization or signing fails.
    pub fn sign_jwt(
        &self,
        signing_key: &p256::ecdsa::SigningKey,
        kid: Option<&str>,
    ) -> Result<String, CryptoError> {
        let mut header_map = serde_json::Map::new();
        header_map.insert(
            "alg".to_string(),
            serde_json::Value::String("ES256".to_string()),
        );
        header_map.insert(
            "typ".to_string(),
            serde_json::Value::String("at+jwt".to_string()),
        );
        if let Some(k) = kid {
            header_map.insert("kid".to_string(), serde_json::Value::String(k.to_string()));
        }

        let header_str = serde_json::to_string(&serde_json::Value::Object(header_map))
            .map_err(|e| CryptoError::Json(e.to_string()))?;
        let payload_str =
            serde_json::to_string(self).map_err(|e| CryptoError::Json(e.to_string()))?;

        let header_b64 = base64url_encode(header_str.as_bytes());
        let payload_b64 = base64url_encode(payload_str.as_bytes());

        let signing_input = format!("{header_b64}.{payload_b64}");
        let signature_bytes = sign_p256_raw(signing_key, signing_input.as_bytes())?;
        let sig_b64 = base64url_encode(&signature_bytes);

        Ok(format!("{signing_input}.{sig_b64}"))
    }
}

/// Asynchronous trait for validating access tokens and enforcing DPoP cryptographic binding.
pub trait AccessTokenValidator: Send + Sync + 'static {
    /// Validates the presented access token against the DPoP public key thumbprint.
    ///
    /// # Arguments
    ///
    /// - `token`: The raw access token string presented in `Authorization: DPoP <token>`.
    /// - `dpop_thumbprint`: The RFC 7638 SHA-256 JWK thumbprint (`jkt`) of the public key extracted
    ///   from the verified DPoP proof.
    ///
    /// # Returns
    ///
    /// Returns the authenticated user session details [`AuthenticatedUser`] on success.
    ///
    /// # Errors
    ///
    /// Returns [`IntegrationError`] if the token is invalid, expired, untrusted,
    /// or if its `cnf.jkt` binding does not match `dpop_thumbprint`.
    fn validate_access_token(
        &self,
        token: &str,
        dpop_thumbprint: &str,
    ) -> Pin<Box<dyn Future<Output = Result<AuthenticatedUser, IntegrationError>> + Send>>;
}

impl<T: AccessTokenValidator + ?Sized> AccessTokenValidator for Arc<T> {
    fn validate_access_token(
        &self,
        token: &str,
        dpop_thumbprint: &str,
    ) -> Pin<Box<dyn Future<Output = Result<AuthenticatedUser, IntegrationError>> + Send>> {
        (**self).validate_access_token(token, dpop_thumbprint)
    }
}

/// Production-grade JWT access token validator enforcing RFC 9068, RFC 9449, and AT Protocol token binding.
#[derive(Debug, Clone)]
pub struct JwtAccessTokenValidator {
    trusted_keys: HashMap<String, VerifyingKey>,
    default_key: Option<VerifyingKey>,
    expected_issuer: Option<String>,
    expected_audience: Option<String>,
    expected_subject: Option<String>,
    required_scopes: Vec<String>,
    clock_skew_leeway: Duration,
}

impl Default for JwtAccessTokenValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl JwtAccessTokenValidator {
    /// Creates a new `JwtAccessTokenValidator` with default clock skew tolerance (60 seconds).
    #[must_use]
    pub fn new() -> Self {
        Self {
            trusted_keys: HashMap::new(),
            default_key: None,
            expected_issuer: None,
            expected_audience: None,
            expected_subject: None,
            required_scopes: Vec::new(),
            clock_skew_leeway: Duration::from_secs(60),
        }
    }

    /// Adds a trusted verifying key associated with a specific key ID (`kid`).
    #[must_use]
    pub fn with_trusted_key(mut self, kid: impl Into<String>, key: VerifyingKey) -> Self {
        self.trusted_keys.insert(kid.into(), key);
        self
    }

    /// Sets the default verifying key used when tokens omit a `kid` header or when a single key is configured.
    #[must_use]
    pub fn with_verifying_key(mut self, key: VerifyingKey) -> Self {
        self.default_key = Some(key);
        self
    }

    /// Sets the expected authorization server issuer URL (`iss`).
    #[must_use]
    pub fn with_expected_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.expected_issuer = Some(issuer.into());
        self
    }

    /// Sets the expected target resource server audience (`aud`).
    #[must_use]
    pub fn with_expected_audience(mut self, audience: impl Into<String>) -> Self {
        self.expected_audience = Some(audience.into());
        self
    }

    /// Sets the expected subject DID (`sub`).
    #[must_use]
    pub fn with_expected_subject(mut self, subject: impl Into<String>) -> Self {
        self.expected_subject = Some(subject.into());
        self
    }

    /// Adds a required OAuth scope that must be present in the token's `scope` claim.
    #[must_use]
    pub fn with_required_scope(mut self, scope: impl Into<String>) -> Self {
        self.required_scopes.push(scope.into());
        self
    }

    /// Configures the allowable clock skew leeway.
    #[must_use]
    pub fn with_clock_skew(mut self, leeway: Duration) -> Self {
        self.clock_skew_leeway = leeway;
        self
    }

    /// Synchronously verifies and decodes a JWT access token against the given DPoP thumbprint.
    ///
    /// # Errors
    ///
    /// Returns [`IntegrationError`] or [`TokenError`] if token verification fails.
    pub fn verify_token_sync(
        &self,
        token: &str,
        dpop_thumbprint: &str,
    ) -> Result<AuthenticatedUser, IntegrationError> {
        let parts: Vec<&str> = token.trim().split('.').collect();
        if parts.len() != 3 {
            return Err(IntegrationError::Token(TokenError::MalformedToken(
                format!("Expected 3 parts in compact JWT, got {}", parts.len()),
            )));
        }

        let header_bytes = base64url_decode(parts[0])
            .map_err(|e| IntegrationError::Token(TokenError::MalformedToken(e.to_string())))?;
        let payload_bytes = base64url_decode(parts[1])
            .map_err(|e| IntegrationError::Token(TokenError::MalformedToken(e.to_string())))?;
        let signature_bytes = base64url_decode(parts[2])
            .map_err(|e| IntegrationError::Token(TokenError::MalformedToken(e.to_string())))?;

        // 1. Parse header
        let header_val: serde_json::Value = serde_json::from_slice(&header_bytes)
            .map_err(|e| IntegrationError::Token(TokenError::MalformedToken(e.to_string())))?;

        let alg = header_val
            .get("alg")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                IntegrationError::Token(TokenError::MalformedToken(
                    "Missing alg header".to_string(),
                ))
            })?;

        if alg != "ES256" {
            return Err(IntegrationError::Token(TokenError::MalformedToken(
                format!("Unsupported alg in access token: expected 'ES256', got '{alg}'"),
            )));
        }

        let typ = header_val.get("typ").and_then(|v| v.as_str());
        if !typ
            .map(|t| {
                t.eq_ignore_ascii_case("at+jwt") || t.eq_ignore_ascii_case("application/at+jwt")
            })
            .unwrap_or(false)
        {
            return Err(IntegrationError::Token(TokenError::MalformedToken(
                format!(
                    "Unsupported typ in access token: expected 'at+jwt', got {:?}",
                    typ
                ),
            )));
        }

        let kid = header_val.get("kid").and_then(|v| v.as_str());

        // 2. Resolve verifying key
        let verifying_key = if let Some(k) = kid {
            match self.trusted_keys.get(k) {
                Some(key) => Some(key),
                None if self.trusted_keys.is_empty() => self.default_key.as_ref(),
                None => None,
            }
        } else if let Some(ref default_k) = self.default_key {
            Some(default_k)
        } else if self.trusted_keys.len() == 1 {
            self.trusted_keys.values().next()
        } else {
            None
        }
        .ok_or_else(|| {
            IntegrationError::AuthFailed(
                "No matching trusted verifying key found for access token".to_string(),
            )
        })?;

        // 3. Cryptographic signature check
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        verify_p256_raw(verifying_key, signing_input.as_bytes(), &signature_bytes)
            .map_err(|_| IntegrationError::Token(TokenError::InvalidSignature))?;

        // 4. Parse payload
        let claims: JwtAccessTokenClaims = serde_json::from_slice(&payload_bytes)
            .map_err(|e| IntegrationError::Token(TokenError::MalformedToken(e.to_string())))?;

        // 5. Check timestamps
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| IntegrationError::Internal(e.to_string()))?
            .as_secs();
        let leeway_secs = self.clock_skew_leeway.as_secs();

        if now_secs > claims.exp.saturating_add(leeway_secs) {
            return Err(IntegrationError::Token(TokenError::Expired {
                exp: claims.exp,
                now: now_secs,
            }));
        }

        if let Some(nbf) = claims.nbf {
            if nbf > now_secs.saturating_add(leeway_secs) {
                return Err(IntegrationError::Token(TokenError::NotYetValid {
                    nbf,
                    now: now_secs,
                }));
            }
        }

        // 6. Check Issuer
        if claims.iss.trim().is_empty() {
            return Err(IntegrationError::Token(TokenError::MissingIssuer));
        }
        if let Some(ref exp_iss) = self.expected_issuer {
            let norm_expected = exp_iss.trim().trim_end_matches('/');
            let norm_actual = claims.iss.trim().trim_end_matches('/');
            if norm_expected != norm_actual {
                return Err(IntegrationError::Token(TokenError::IssuerMismatch {
                    expected: exp_iss.clone(),
                    actual: claims.iss.clone(),
                }));
            }
        }

        // 7. Check Audience
        if claims.aud.is_none() {
            return Err(IntegrationError::Token(TokenError::MissingAudience));
        }
        if let Some(ref exp_aud) = self.expected_audience {
            let matches_aud = match &claims.aud {
                Some(serde_json::Value::String(s)) => s == exp_aud,
                Some(serde_json::Value::Array(arr)) => arr
                    .iter()
                    .any(|item| item.as_str().map(|s| s == exp_aud).unwrap_or(false)),
                _ => false,
            };
            if !matches_aud {
                return Err(IntegrationError::Token(TokenError::AudienceMismatch {
                    expected: exp_aud.clone(),
                    actual: claims
                        .aud
                        .as_ref()
                        .map(ToString::to_string)
                        .unwrap_or_else(|| "none".to_string()),
                }));
            }
        }

        // 8. Check Subject (DID)
        if claims.sub.trim().is_empty() {
            return Err(IntegrationError::Token(TokenError::MissingDid));
        }

        if let Some(ref exp_sub) = self.expected_subject {
            if &claims.sub != exp_sub {
                return Err(IntegrationError::Token(TokenError::SubMismatch {
                    expected: exp_sub.clone(),
                    actual: claims.sub.clone(),
                }));
            }
        }

        // 9. Check Scopes
        if !self.required_scopes.is_empty() {
            let granted_scopes: Vec<&str> = claims
                .scope
                .as_deref()
                .unwrap_or("")
                .split_whitespace()
                .collect();
            for required in &self.required_scopes {
                if !granted_scopes.contains(&required.as_str()) {
                    return Err(IntegrationError::Token(TokenError::MissingAtprotoScope(
                        claims.scope.unwrap_or_default(),
                    )));
                }
            }
        }

        // 10. Check cnf.jkt DPoP Key Binding (RFC 9449 § 6.1 item 4)
        if !constant_time_eq(claims.cnf.jkt.as_bytes(), dpop_thumbprint.as_bytes()) {
            return Err(IntegrationError::Token(TokenError::CnfThumbprintMismatch {
                expected_jkt: claims.cnf.jkt,
                actual_jkt: dpop_thumbprint.to_string(),
            }));
        }

        Ok(AuthenticatedUser {
            did: claims.sub,
            access_token: token.to_string(),
            dpop_thumbprint: dpop_thumbprint.to_string(),
            scope: claims.scope,
        })
    }
}

impl AccessTokenValidator for JwtAccessTokenValidator {
    fn validate_access_token(
        &self,
        token: &str,
        dpop_thumbprint: &str,
    ) -> Pin<Box<dyn Future<Output = Result<AuthenticatedUser, IntegrationError>> + Send>> {
        let res = self.verify_token_sync(token, dpop_thumbprint);
        Box::pin(std::future::ready(res))
    }
}

/// In-memory registry for active access tokens and sessions with DPoP binding enforcement.
#[derive(Debug, Clone, Default)]
pub struct InMemoryTokenValidator {
    tokens: Arc<RwLock<HashMap<[u8; 32], RegisteredToken>>>,
}

/// Metadata for a registered access token in [`InMemoryTokenValidator`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredToken {
    /// Subject DID (e.g. `did:plc:...`).
    pub did: String,
    /// Bound DPoP public key JWK thumbprint (`jkt`).
    pub dpop_thumbprint: String,
    /// Granted scopes.
    pub scope: Option<String>,
    /// Optional expiration timestamp.
    pub expires_at: Option<SystemTime>,
}

impl InMemoryTokenValidator {
    /// Creates a new empty `InMemoryTokenValidator`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            tokens: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Registers an active token along with its subject DID and bound DPoP key thumbprint.
    pub fn register_token(
        &self,
        token: impl AsRef<[u8]>,
        did: impl Into<String>,
        dpop_thumbprint: impl Into<String>,
        scope: Option<String>,
        expires_at: Option<SystemTime>,
    ) {
        let digest = sha256_digest(token.as_ref());
        let mut guard = self.tokens.write();
        guard.insert(
            digest,
            RegisteredToken {
                did: did.into(),
                dpop_thumbprint: dpop_thumbprint.into(),
                scope,
                expires_at,
            },
        );
    }

    /// Registers a token directly from an [`OAuthSession`].
    pub fn register_session(&self, session: &OAuthSession) {
        self.register_token(
            &session.access_token,
            &session.sub,
            session.dpop_key.jwk_thumbprint(),
            session.scope.clone(),
            session.expires_at,
        );
    }

    /// Revokes/removes a registered token.
    pub fn revoke_token(&self, token: &str) {
        let digest = sha256_digest(token.as_bytes());
        let mut guard = self.tokens.write();
        guard.remove(&digest);
    }

    /// Validates a presented token synchronously.
    ///
    /// # Errors
    ///
    /// Returns [`IntegrationError`] if the token is not found, expired, or bound to a different key.
    pub fn validate_sync(
        &self,
        token: &str,
        dpop_thumbprint: &str,
    ) -> Result<AuthenticatedUser, IntegrationError> {
        let digest = sha256_digest(token.as_bytes());
        let guard = self.tokens.read();
        let entry = guard.get(&digest).ok_or_else(|| {
            IntegrationError::Token(TokenError::MalformedToken(
                "Access token is not registered or has been revoked".to_string(),
            ))
        })?;

        if let Some(exp) = entry.expires_at {
            let now = SystemTime::now();
            if now > exp {
                let exp_secs = exp
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let now_secs = now
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                return Err(IntegrationError::Token(TokenError::Expired {
                    exp: exp_secs,
                    now: now_secs,
                }));
            }
        }

        // Validate DPoP key binding
        if !constant_time_eq(entry.dpop_thumbprint.as_bytes(), dpop_thumbprint.as_bytes()) {
            return Err(IntegrationError::Token(TokenError::CnfThumbprintMismatch {
                expected_jkt: entry.dpop_thumbprint.clone(),
                actual_jkt: dpop_thumbprint.to_string(),
            }));
        }

        Ok(AuthenticatedUser {
            did: entry.did.clone(),
            access_token: token.to_string(),
            dpop_thumbprint: dpop_thumbprint.to_string(),
            scope: entry.scope.clone(),
        })
    }
}

impl AccessTokenValidator for InMemoryTokenValidator {
    fn validate_access_token(
        &self,
        token: &str,
        dpop_thumbprint: &str,
    ) -> Pin<Box<dyn Future<Output = Result<AuthenticatedUser, IntegrationError>> + Send>> {
        let res = self.validate_sync(token, dpop_thumbprint);
        Box::pin(std::future::ready(res))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]
mod tests {
    use super::*;
    use crate::dpop::DPoPKey;
    use p256::ecdsa::SigningKey;
    use rand::thread_rng;

    #[test]
    fn test_jwt_access_token_signing_and_validation_roundtrip() {
        let auth_key = SigningKey::random(&mut thread_rng());
        let auth_verifying_key = *auth_key.verifying_key();

        let client_dpop_key = DPoPKey::generate();
        let client_jkt = client_dpop_key.jwk_thumbprint();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let claims = JwtAccessTokenClaims::new(
            "https://auth.example.com",
            "did:plc:alice123",
            now + 3600,
            &client_jkt,
        )
        .with_audience("https://pds.example.com")
        .with_scope("atproto transition:generic");

        let jwt = claims.sign_jwt(&auth_key, None).unwrap();

        let validator = JwtAccessTokenValidator::new()
            .with_verifying_key(auth_verifying_key)
            .with_expected_issuer("https://auth.example.com")
            .with_expected_audience("https://pds.example.com")
            .with_required_scope("atproto");

        let user = validator.verify_token_sync(&jwt, &client_jkt).unwrap();
        assert_eq!(user.did, "did:plc:alice123");
        assert_eq!(user.access_token, jwt);
        assert_eq!(user.dpop_thumbprint, client_jkt);
        assert_eq!(user.scope.as_deref(), Some("atproto transition:generic"));
    }

    #[test]
    fn test_jwt_access_token_cnf_jkt_mismatch_fails() {
        let auth_key = SigningKey::random(&mut thread_rng());
        let auth_verifying_key = *auth_key.verifying_key();

        let alice_dpop_key = DPoPKey::generate();
        let attacker_dpop_key = DPoPKey::generate();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Token issued to Alice's DPoP key
        let claims = JwtAccessTokenClaims::new(
            "https://auth.example.com",
            "did:plc:alice123",
            now + 3600,
            alice_dpop_key.jwk_thumbprint(),
        )
        .with_audience("https://pds.example.com");

        let jwt = claims.sign_jwt(&auth_key, None).unwrap();

        let validator = JwtAccessTokenValidator::new().with_verifying_key(auth_verifying_key);

        // Attacker presents Alice's token with Attacker's DPoP proof key
        let err = validator
            .verify_token_sync(&jwt, &attacker_dpop_key.jwk_thumbprint())
            .unwrap_err();

        assert!(matches!(
            err,
            IntegrationError::Token(TokenError::CnfThumbprintMismatch { .. })
        ));
    }

    #[test]
    fn test_jwt_access_token_expired_fails() {
        let auth_key = SigningKey::random(&mut thread_rng());
        let auth_verifying_key = *auth_key.verifying_key();
        let client_dpop_key = DPoPKey::generate();
        let jkt = client_dpop_key.jwk_thumbprint();

        // Expired 1000s ago
        let claims =
            JwtAccessTokenClaims::new("https://auth.example.com", "did:plc:alice123", 1000, &jkt)
                .with_audience("https://pds.example.com");

        let jwt = claims.sign_jwt(&auth_key, None).unwrap();
        let validator = JwtAccessTokenValidator::new()
            .with_verifying_key(auth_verifying_key)
            .with_clock_skew(Duration::ZERO);

        let err = validator.verify_token_sync(&jwt, &jkt).unwrap_err();
        assert!(matches!(
            err,
            IntegrationError::Token(TokenError::Expired { .. })
        ));
    }

    #[test]
    fn test_jwt_access_token_issuer_mismatch_fails() {
        let auth_key = SigningKey::random(&mut thread_rng());
        let auth_verifying_key = *auth_key.verifying_key();
        let client_dpop_key = DPoPKey::generate();
        let jkt = client_dpop_key.jwk_thumbprint();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let claims = JwtAccessTokenClaims::new(
            "https://malicious-issuer.example.com",
            "did:plc:alice123",
            now + 3600,
            &jkt,
        )
        .with_audience("https://pds.example.com");

        let jwt = claims.sign_jwt(&auth_key, None).unwrap();
        let validator = JwtAccessTokenValidator::new()
            .with_verifying_key(auth_verifying_key)
            .with_expected_issuer("https://auth.example.com");

        let err = validator.verify_token_sync(&jwt, &jkt).unwrap_err();
        assert!(matches!(
            err,
            IntegrationError::Token(TokenError::IssuerMismatch { .. })
        ));
    }

    #[test]
    fn test_jwt_access_token_audience_mismatch_fails() {
        let auth_key = SigningKey::random(&mut thread_rng());
        let auth_verifying_key = *auth_key.verifying_key();
        let client_dpop_key = DPoPKey::generate();
        let jkt = client_dpop_key.jwk_thumbprint();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let claims = JwtAccessTokenClaims::new(
            "https://auth.example.com",
            "did:plc:alice123",
            now + 3600,
            &jkt,
        )
        .with_audience("https://other-resource.example.com");

        let jwt = claims.sign_jwt(&auth_key, None).unwrap();
        let validator = JwtAccessTokenValidator::new()
            .with_verifying_key(auth_verifying_key)
            .with_expected_audience("https://pds.example.com");

        let err = validator.verify_token_sync(&jwt, &jkt).unwrap_err();
        assert!(matches!(
            err,
            IntegrationError::Token(TokenError::AudienceMismatch { .. })
        ));
    }

    #[test]
    fn test_in_memory_token_validator_lifecycle() {
        let validator = InMemoryTokenValidator::new();
        let token = "active_session_token_xyz";
        let did = "did:plc:carol789";
        let dpop_key = DPoPKey::generate();
        let jkt = dpop_key.jwk_thumbprint();

        validator.register_token(token, did, &jkt, Some("atproto".to_string()), None);

        // Valid presentation
        let user = validator.validate_sync(token, &jkt).unwrap();
        assert_eq!(user.did, did);
        assert_eq!(user.dpop_thumbprint, jkt);

        // Presented with wrong DPoP key
        let wrong_key = DPoPKey::generate();
        let err = validator
            .validate_sync(token, &wrong_key.jwk_thumbprint())
            .unwrap_err();
        assert!(matches!(
            err,
            IntegrationError::Token(TokenError::CnfThumbprintMismatch { .. })
        ));

        // Revoke token
        validator.revoke_token(token);
        let err_revoked = validator.validate_sync(token, &jkt).unwrap_err();
        assert!(matches!(
            err_revoked,
            IntegrationError::Token(TokenError::MalformedToken(_))
        ));
    }
}
