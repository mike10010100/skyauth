//! Authenticated OAuth Session representation and token management.
//!
//! Stores user DID subject, access token, single-use refresh token, case-insensitive
//! "DPoP" token type, scopes, session expiration, and bound [`DPoPKey`].
//! Enforces single-use refresh token rotation semantics according to ATProto OAuth 2.1.

use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

use crate::dpop::{compute_access_token_hash, DPoPKey};
use crate::error::{AtprotoOAuthError, DPoPError, TokenError};

use zeroize::{Zeroize, ZeroizeOnDrop};

/// An authenticated AT Protocol OAuth session.
///
/// Holds the authenticated user's DID, DPoP-bound access token, single-use refresh token,
/// session expiration time, and cryptographic [`DPoPKey`] for signing subsequent XRPC requests.
///
/// # Memory Zeroization & Partial Moves
/// This struct implements [`Drop`] and [`ZeroizeOnDrop`] to securely zeroize sensitive
/// credentials (`access_token` and `refresh_token`) from memory on destruction. As a consequence
/// of Rust's [`Drop`] safety rules (E0509), partial moves of individual fields out of
/// this struct are prohibited; callers should borrow fields or clone the structure.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuthSession {
    /// Authenticated subject DID (e.g. `did:plc:...`).
    pub sub: String,
    /// DPoP-bound access token string.
    pub access_token: String,
    /// Single-use refresh token for session renewal.
    pub refresh_token: Option<String>,
    /// Token type (must be case-insensitively `"DPoP"`).
    pub token_type: String,
    /// Granted OAuth scopes (e.g. `"atproto transition:generic"`).
    pub scope: Option<String>,
    /// Absolute expiration timestamp.
    pub expires_at: Option<SystemTime>,
    /// Cryptographic ECDSA P-256 keypair bound to this session's tokens.
    pub dpop_key: DPoPKey,
    /// User's Personal Data Server (PDS) endpoint origin, if known.
    pub pds_endpoint: Option<String>,
    /// Authorization server issuer URL, if known.
    pub auth_server_issuer: Option<String>,
    /// Authorization server token endpoint URL, if known.
    pub token_endpoint: Option<String>,
    /// Timestamp when this session was initially created or exchanged.
    pub created_at: SystemTime,
}

impl std::fmt::Debug for OAuthSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthSession")
            .field("sub", &self.sub)
            .field("access_token", &"[REDACTED]")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("token_type", &self.token_type)
            .field("scope", &self.scope)
            .field("expires_at", &self.expires_at)
            .field("dpop_key", &self.dpop_key)
            .field("pds_endpoint", &self.pds_endpoint)
            .field("auth_server_issuer", &self.auth_server_issuer)
            .field("token_endpoint", &self.token_endpoint)
            .field("created_at", &self.created_at)
            .finish()
    }
}

impl Zeroize for OAuthSession {
    fn zeroize(&mut self) {
        self.access_token.zeroize();
        if let Some(ref mut rt) = self.refresh_token {
            rt.zeroize();
        }
    }
}

impl Drop for OAuthSession {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for OAuthSession {}

impl OAuthSession {
    /// Creates a new `OAuthSession` after validating that `token_type` is case-insensitively `"DPoP"`.
    ///
    /// # Errors
    ///
    /// Returns [`TokenError::InvalidTokenType`] if `token_type` is not `"DPoP"`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sub: impl Into<String>,
        access_token: impl Into<String>,
        refresh_token: Option<String>,
        token_type: impl Into<String>,
        scope: Option<String>,
        expires_in_secs: Option<u64>,
        dpop_key: DPoPKey,
        pds_endpoint: Option<String>,
        auth_server_issuer: Option<String>,
        token_endpoint: Option<String>,
    ) -> Result<Self, AtprotoOAuthError> {
        let ttype = token_type.into();
        if !ttype.eq_ignore_ascii_case("DPoP") {
            return Err(TokenError::InvalidTokenType(ttype).into());
        }

        let now = SystemTime::now();
        // Fail closed on overflow: if `now + expires_in` overflows `SystemTime`
        // (possible for absurd `expires_in` values from a compromised/malicious
        // AS), treat the session as already expired rather than never-expiring
        // (`None` previously meant "no local expiry", an attacker-usable
        // fail-open; independent review finding L3).
        let expires_at =
            expires_in_secs.and_then(|secs| now.checked_add(Duration::from_secs(secs)));
        if expires_in_secs.is_some() && expires_at.is_none() {
            return Err(TokenError::Http(
                "expires_in value overflows session expiry timestamp; refusing to issue a never-expiring session (fail-closed)"
                    .to_string(),
            )
            .into());
        }

        Ok(Self {
            sub: sub.into(),
            access_token: access_token.into(),
            refresh_token,
            token_type: ttype,
            scope,
            expires_at,
            dpop_key,
            pds_endpoint,
            auth_server_issuer,
            token_endpoint,
            created_at: now,
        })
    }

    /// Checks whether the access token is expired based on current system time.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.is_expired_with_leeway(Duration::ZERO)
    }

    /// Checks whether the access token is expired, with an additional clock leeway window.
    ///
    /// Returns `true` if `expires_at` is present and less than or equal to `now + leeway`.
    #[must_use]
    pub fn is_expired_with_leeway(&self, leeway: Duration) -> bool {
        match self.expires_at {
            Some(exp) => {
                let now = SystemTime::now();
                match now.checked_add(leeway) {
                    Some(now_with_leeway) => exp <= now_with_leeway,
                    None => true,
                }
            }
            None => false,
        }
    }

    /// Atomically rotates the session tokens upon successful refresh token exchange.
    ///
    /// Updates `access_token`, `refresh_token`, and recalculates `expires_at` based on current time.
    /// Outgoing token strings are zeroized in memory before being replaced.
    pub fn rotate_tokens(
        &mut self,
        access_token: impl Into<String>,
        refresh_token: Option<String>,
        expires_in_secs: Option<u64>,
    ) {
        // Explicitly zeroize outgoing credentials before overwriting so the previous
        // secrets are scrubbed rather than simply dropped unzeroed.
        self.access_token.zeroize();
        if let Some(ref mut rt) = self.refresh_token {
            rt.zeroize();
        }

        self.access_token = access_token.into();
        self.refresh_token = refresh_token;
        let now = SystemTime::now();
        // Fail closed on overflow (same rationale as `new`): an overflowing
        // `expires_in` must not yield a never-expiring session.
        let expires_at =
            expires_in_secs.and_then(|secs| now.checked_add(Duration::from_secs(secs)));
        if expires_in_secs.is_some() && expires_at.is_none() {
            // Overflow: mark the session expired at `now` (fail-closed) — the
            // rotation itself has already zeroized and replaced the tokens, so
            // surfacing the anomaly here keeps local expiry semantics safe.
            self.expires_at = Some(now);
            return;
        }
        self.expires_at = expires_at;
    }

    /// Generates a signed RFC 9449 DPoP proof for this session, bound to the current access token.
    ///
    /// Computes the access token hash (`ath`) and includes it in the DPoP proof claims.
    ///
    /// # Errors
    ///
    /// Returns [`DPoPError`] if proof generation fails.
    pub fn create_dpop_proof(
        &self,
        htm: &str,
        htu: &str,
        nonce: Option<&str>,
    ) -> Result<String, DPoPError> {
        let ath = compute_access_token_hash(&self.access_token);
        self.dpop_key
            .create_proof(htm, htu, nonce, Some(ath.as_str()))
    }

    /// Returns the standard HTTP `Authorization` header value (`DPoP <access_token>`).
    #[must_use]
    pub fn dpop_auth_header(&self) -> String {
        format!("DPoP {}", self.access_token)
    }

    /// Returns a reference to the subject DID.
    #[must_use]
    pub fn sub(&self) -> &str {
        &self.sub
    }

    /// Returns a reference to the current access token string.
    #[must_use]
    pub fn access_token(&self) -> &str {
        &self.access_token
    }

    /// Returns a reference to the current refresh token string, if any.
    #[must_use]
    pub fn refresh_token(&self) -> Option<&str> {
        self.refresh_token.as_deref()
    }

    /// Returns a reference to the token type.
    #[must_use]
    pub fn token_type(&self) -> &str {
        &self.token_type
    }

    /// Returns a reference to the granted scope string, if any.
    #[must_use]
    pub fn scope(&self) -> Option<&str> {
        self.scope.as_deref()
    }

    /// Returns the session expiration timestamp, if known.
    #[must_use]
    pub fn expires_at(&self) -> Option<SystemTime> {
        self.expires_at
    }

    /// Returns a reference to the bound [`DPoPKey`].
    #[must_use]
    pub fn dpop_key(&self) -> &DPoPKey {
        &self.dpop_key
    }

    /// Returns a reference to the PDS endpoint origin, if known.
    #[must_use]
    pub fn pds_endpoint(&self) -> Option<&str> {
        self.pds_endpoint.as_deref()
    }

    /// Returns a reference to the authorization server issuer URL, if known.
    #[must_use]
    pub fn auth_server_issuer(&self) -> Option<&str> {
        self.auth_server_issuer.as_deref()
    }

    /// Returns a reference to the token endpoint URL, if known.
    #[must_use]
    pub fn token_endpoint(&self) -> Option<&str> {
        self.token_endpoint.as_deref()
    }

    /// Returns the timestamp when this session was created.
    #[must_use]
    pub fn created_at(&self) -> SystemTime {
        self.created_at
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]
mod tests {
    use super::*;
    use crate::dpop::DPoPVerifier;

    #[test]
    fn test_session_creation_valid() {
        let key = DPoPKey::generate();
        let session = OAuthSession::new(
            "did:plc:alice123",
            "at_sample_access_token",
            Some("rt_sample_refresh_token".to_string()),
            "DPoP",
            Some("atproto transition:generic".to_string()),
            Some(3600),
            key.clone(),
            Some("https://pds.example.com".to_string()),
            Some("https://auth.example.com".to_string()),
            Some("https://auth.example.com/oauth/token".to_string()),
        )
        .unwrap();

        assert_eq!(session.sub(), "did:plc:alice123");
        assert_eq!(session.access_token(), "at_sample_access_token");
        assert_eq!(session.refresh_token(), Some("rt_sample_refresh_token"));
        assert_eq!(session.token_type(), "DPoP");
        assert_eq!(session.scope(), Some("atproto transition:generic"));
        assert!(!session.is_expired());
        assert_eq!(session.dpop_auth_header(), "DPoP at_sample_access_token");
    }

    #[test]
    fn test_session_creation_case_insensitive_dpop() {
        let key = DPoPKey::generate();
        let session = OAuthSession::new(
            "did:plc:alice123",
            "at_123",
            None,
            "dpop",
            None,
            None,
            key,
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(session.token_type(), "dpop");
    }

    #[test]
    fn test_session_creation_bearer_rejected() {
        let key = DPoPKey::generate();
        let res = OAuthSession::new(
            "did:plc:alice123",
            "at_123",
            None,
            "Bearer",
            None,
            None,
            key,
            None,
            None,
            None,
        );
        assert!(matches!(
            res,
            Err(AtprotoOAuthError::Token(TokenError::InvalidTokenType(_)))
        ));
    }

    #[test]
    fn test_session_token_rotation() {
        let key = DPoPKey::generate();
        let mut session = OAuthSession::new(
            "did:plc:alice123",
            "at_initial",
            Some("rt_initial".to_string()),
            "DPoP",
            None,
            Some(300),
            key,
            None,
            None,
            None,
        )
        .unwrap();

        assert_eq!(session.access_token(), "at_initial");
        assert_eq!(session.refresh_token(), Some("rt_initial"));

        session.rotate_tokens("at_rotated", Some("rt_rotated".to_string()), Some(600));

        assert_eq!(session.access_token(), "at_rotated");
        assert_eq!(session.refresh_token(), Some("rt_rotated"));
        assert!(!session.is_expired());
    }

    #[test]
    fn test_session_dpop_proof_generation_with_ath() {
        let key = DPoPKey::generate();
        let access_token = "at_alice_secret_token";
        let session = OAuthSession::new(
            "did:plc:alice123",
            access_token,
            None,
            "DPoP",
            None,
            Some(3600),
            key.clone(),
            None,
            None,
            None,
        )
        .unwrap();

        let htu = "https://pds.example.com/xrpc/app.bsky.actor.getProfile";
        let proof = session.create_dpop_proof("GET", htu, None).unwrap();

        let expected_ath = compute_access_token_hash(access_token);
        let verifier = DPoPVerifier::new();
        let (claims, jwk) = verifier
            .verify_proof(&proof, "GET", htu, None, Some(&expected_ath), None)
            .unwrap();

        assert_eq!(claims.htm, "GET");
        assert_eq!(claims.ath.as_deref(), Some(expected_ath.as_str()));
        assert_eq!(jwk.thumbprint(), key.jwk_thumbprint());
    }
}
