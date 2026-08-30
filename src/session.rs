//! Authenticated OAuth Session representation and token management.
//!
//! Stores user DID subject, access token, single-use refresh token, case-insensitive
//! "DPoP" token type, scopes, session expiration, and bound [`DPoPKey`].
//! Enforces single-use refresh token rotation semantics according to ATProto OAuth 2.1.

use std::time::{Duration, SystemTime};

use zeroize::Zeroizing;

use crate::crypto::base64url_encode;
use crate::dpop::{compute_access_token_hash, DPoPKey};
use crate::error::{AtprotoOAuthError, DPoPError, TokenError};
use crate::scope::ScopeSet;
use crate::secret::SecretString;

/// An authenticated AT Protocol OAuth session.
///
/// Holds the authenticated user's DID, DPoP-bound access token, single-use refresh token,
/// session expiration time, and cryptographic [`DPoPKey`] for signing subsequent XRPC requests.
#[derive(Clone)]
pub struct OAuthSession {
    session_id: String,
    generation: u64,
    sub: String,
    access_token: SecretString,
    refresh_token: Option<SecretString>,
    token_type: String,
    scope: Option<String>,
    expires_at: Option<SystemTime>,
    dpop_key: DPoPKey,
    pds_endpoint: Option<String>,
    auth_server_issuer: Option<String>,
    token_endpoint: Option<String>,
    created_at: SystemTime,
}

impl std::fmt::Debug for OAuthSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OAuthSession")
            .field("session_id", &self.session_id)
            .field("generation", &self.generation)
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

/// Explicit authorization to export a session for protected persistence.
#[derive(Debug, Clone, Copy)]
pub struct SecretExportPermit(());

impl SecretExportPermit {
    /// Acknowledges that the exported bytes must be encrypted before storage.
    #[must_use]
    pub const fn for_encrypted_persistence() -> Self {
        Self(())
    }

    /// Acknowledges a controlled test fixture that must sign deliberately malformed material.
    ///
    /// This authority is compiled only for unit tests or the internal `test-export` feature used
    /// by adversarial integration tests. It must not be used for persistent storage.
    #[cfg(any(test, feature = "test-export"))]
    #[doc(hidden)]
    #[must_use]
    pub const fn for_test_signing() -> Self {
        Self(())
    }
}

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
        let expires_at =
            expires_in_secs.and_then(|secs| now.checked_add(Duration::from_secs(secs)));

        let access_token = access_token.into();
        if access_token.is_empty() {
            return Err(TokenError::MissingField("access_token").into());
        }
        if let Some(scope_value) = scope.as_deref() {
            ScopeSet::parse(scope_value)?;
        }

        let mut session_id_bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut session_id_bytes);

        Ok(Self {
            session_id: base64url_encode(&session_id_bytes),
            generation: 0,
            sub: sub.into(),
            access_token: SecretString::new(access_token),
            refresh_token: refresh_token.map(SecretString::new),
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
    pub fn rotate_tokens(
        &mut self,
        access_token: impl Into<String>,
        refresh_token: Option<String>,
        scope: Option<String>,
        expires_in_secs: Option<u64>,
    ) -> Result<(), AtprotoOAuthError> {
        let access_token = access_token.into();
        if access_token.is_empty() {
            return Err(TokenError::MissingField("access_token").into());
        }
        if let Some(scope_value) = scope.as_deref() {
            ScopeSet::parse(scope_value)?;
        }
        let generation = self
            .generation
            .checked_add(1)
            .ok_or(TokenError::SessionGenerationExhausted)?;
        self.access_token = SecretString::new(access_token);
        self.refresh_token = refresh_token.map(SecretString::new);
        self.scope = scope;
        let now = SystemTime::now();
        self.expires_at =
            expires_in_secs.and_then(|secs| now.checked_add(Duration::from_secs(secs)));
        self.generation = generation;
        Ok(())
    }

    /// Returns the stable identifier used by session stores.
    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Returns the current token-set generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
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
        let ath = compute_access_token_hash(self.access_token.expose());
        self.dpop_key
            .create_proof(htm, htu, nonce, Some(ath.as_str()))
    }

    /// Returns the standard HTTP `Authorization` header value (`DPoP <access_token>`).
    #[must_use]
    pub fn dpop_auth_header(&self) -> String {
        format!("DPoP {}", self.access_token.expose())
    }

    /// Returns a reference to the subject DID.
    #[must_use]
    pub fn sub(&self) -> &str {
        &self.sub
    }

    /// Returns a reference to the current access token string.
    #[must_use]
    pub fn expose_access_token(&self) -> &str {
        self.access_token.expose()
    }

    /// Returns a reference to the current refresh token string, if any.
    #[must_use]
    pub fn expose_refresh_token(&self) -> Option<&str> {
        self.refresh_token.as_ref().map(SecretString::expose)
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

    /// Exports a versioned session payload for caller-managed encrypted persistence.
    ///
    /// # Errors
    ///
    /// Returns [`TokenError::Persistence`] if a timestamp cannot be represented.
    pub fn export_for_persistence(
        &self,
        _permit: SecretExportPermit,
    ) -> Result<Zeroizing<Vec<u8>>, AtprotoOAuthError> {
        let capacity = self.persistence_payload_size()?;
        let mut bytes = Vec::with_capacity(capacity);
        bytes.extend_from_slice(b"SKYAUTH2");
        let mut output = Zeroizing::new(bytes);
        write_string(&mut output, &self.session_id)?;
        output.extend_from_slice(&self.generation.to_be_bytes());
        write_string(&mut output, &self.sub)?;
        write_string(&mut output, self.access_token.expose())?;
        write_optional_string(
            &mut output,
            self.refresh_token.as_ref().map(SecretString::expose),
        )?;
        write_string(&mut output, &self.token_type)?;
        write_optional_string(&mut output, self.scope.as_deref())?;
        write_optional_time(&mut output, self.expires_at)?;
        output.extend_from_slice(self.dpop_key.export_private_scalar().as_ref());
        write_optional_string(&mut output, self.pds_endpoint.as_deref())?;
        write_optional_string(&mut output, self.auth_server_issuer.as_deref())?;
        write_optional_string(&mut output, self.token_endpoint.as_deref())?;
        write_time(&mut output, self.created_at)?;
        Ok(output)
    }

    /// Computes the exact framed persistence payload size without exposing secrets.
    fn persistence_payload_size(&self) -> Result<usize, TokenError> {
        let mut size = 8usize;
        for value in [
            self.session_id.as_str(),
            self.sub.as_str(),
            self.access_token.expose(),
            self.token_type.as_str(),
        ] {
            size = checked_payload_add(size, encoded_string_size(value)?)?;
        }
        size = checked_payload_add(size, 8)?;
        for value in [
            self.refresh_token.as_ref().map(SecretString::expose),
            self.scope.as_deref(),
            self.pds_endpoint.as_deref(),
            self.auth_server_issuer.as_deref(),
            self.token_endpoint.as_deref(),
        ] {
            size = checked_payload_add(size, 1)?;
            if let Some(value) = value {
                size = checked_payload_add(size, encoded_string_size(value)?)?;
            }
        }
        size = checked_payload_add(size, 1)?;
        if self.expires_at.is_some() {
            size = checked_payload_add(size, 8)?;
        }
        size = checked_payload_add(size, 32)?;
        checked_payload_add(size, 8)
    }

    /// Imports a session payload produced by [`Self::export_for_persistence`].
    ///
    /// # Errors
    ///
    /// Returns [`TokenError::Persistence`] for malformed or unsupported payloads.
    pub fn import_from_persistence(bytes: &[u8]) -> Result<Self, AtprotoOAuthError> {
        let mut reader = PersistenceReader::new(bytes)?;
        let session_id = reader.string()?;
        if session_id.is_empty() {
            return Err(TokenError::Persistence.into());
        }
        let generation = reader.u64()?;
        let sub = reader.string()?;
        let access_token = reader.string()?;
        let refresh_token = reader.optional_string()?;
        let token_type = reader.string()?;
        let scope = reader.optional_string()?;
        let expires_at = reader.optional_time()?;
        let key_bytes = reader.fixed_32()?;
        let dpop_key = DPoPKey::from_slice(&key_bytes[..])?;
        let pds_endpoint = reader.optional_string()?;
        let auth_server_issuer = reader.optional_string()?;
        let token_endpoint = reader.optional_string()?;
        let created_at = reader.time()?;
        reader.finish()?;
        if !token_type.eq_ignore_ascii_case("DPoP") {
            return Err(TokenError::InvalidTokenType(token_type).into());
        }
        if let Some(scope_value) = scope.as_deref() {
            ScopeSet::parse(scope_value)?;
        }
        Ok(Self {
            session_id,
            generation,
            sub,
            access_token: SecretString::new(access_token),
            refresh_token: refresh_token.map(SecretString::new),
            token_type,
            scope,
            expires_at,
            dpop_key,
            pds_endpoint,
            auth_server_issuer,
            token_endpoint,
            created_at,
        })
    }
}

/// Computes the length-prefixed encoding size for one string.
fn encoded_string_size(value: &str) -> Result<usize, TokenError> {
    u32::try_from(value.len()).map_err(|_| TokenError::Persistence)?;
    checked_payload_add(4, value.len())
}

/// Adds payload lengths while mapping overflow to a typed token error.
fn checked_payload_add(left: usize, right: usize) -> Result<usize, TokenError> {
    left.checked_add(right).ok_or(TokenError::Persistence)
}

/// Writes one length-prefixed UTF-8 string into a reserved payload.
fn write_string(output: &mut Vec<u8>, value: &str) -> Result<(), TokenError> {
    let length = u32::try_from(value.len()).map_err(|_| TokenError::Persistence)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

/// Writes an optional length-prefixed UTF-8 string.
fn write_optional_string(output: &mut Vec<u8>, value: Option<&str>) -> Result<(), TokenError> {
    match value {
        Some(value) => {
            output.push(1);
            write_string(output, value)
        }
        None => {
            output.push(0);
            Ok(())
        }
    }
}

/// Writes a system timestamp as seconds from the Unix epoch.
fn write_time(output: &mut Vec<u8>, value: SystemTime) -> Result<(), TokenError> {
    let seconds = value
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| TokenError::Persistence)?
        .as_secs();
    output.extend_from_slice(&seconds.to_be_bytes());
    Ok(())
}

/// Writes an optional system timestamp.
fn write_optional_time(output: &mut Vec<u8>, value: Option<SystemTime>) -> Result<(), TokenError> {
    match value {
        Some(value) => {
            output.push(1);
            write_time(output, value)
        }
        None => {
            output.push(0);
            Ok(())
        }
    }
}

struct PersistenceReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> PersistenceReader<'a> {
    /// Creates a reader after checking the persistence format prefix.
    fn new(bytes: &'a [u8]) -> Result<Self, TokenError> {
        if !bytes.starts_with(b"SKYAUTH2") {
            return Err(TokenError::Persistence);
        }
        Ok(Self { bytes, offset: 8 })
    }

    /// Consumes an exact number of bytes from the remaining payload.
    fn take(&mut self, length: usize) -> Result<&'a [u8], TokenError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(TokenError::Persistence)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(TokenError::Persistence)?;
        self.offset = end;
        Ok(value)
    }

    fn string(&mut self) -> Result<String, TokenError> {
        let length_bytes: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| TokenError::Persistence)?;
        let length = u32::from_be_bytes(length_bytes) as usize;
        let value = self.take(length)?;
        std::str::from_utf8(value)
            .map(ToString::to_string)
            .map_err(|_| TokenError::Persistence)
    }

    fn optional_string(&mut self) -> Result<Option<String>, TokenError> {
        match self.take(1)?[0] {
            0 => Ok(None),
            1 => self.string().map(Some),
            _ => Err(TokenError::Persistence),
        }
    }

    fn time(&mut self) -> Result<SystemTime, TokenError> {
        SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_secs(self.u64()?))
            .ok_or(TokenError::Persistence)
    }

    fn u64(&mut self) -> Result<u64, TokenError> {
        let raw: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_| TokenError::Persistence)?;
        Ok(u64::from_be_bytes(raw))
    }

    fn optional_time(&mut self) -> Result<Option<SystemTime>, TokenError> {
        match self.take(1)?[0] {
            0 => Ok(None),
            1 => self.time().map(Some),
            _ => Err(TokenError::Persistence),
        }
    }

    fn fixed_32(&mut self) -> Result<Zeroizing<[u8; 32]>, TokenError> {
        let mut output = Zeroizing::new([0u8; 32]);
        output.copy_from_slice(self.take(32)?);
        Ok(output)
    }

    /// Requires the payload to end exactly after the final field.
    fn finish(self) -> Result<(), TokenError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(TokenError::Persistence)
        }
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
        assert_eq!(session.expose_access_token(), "at_sample_access_token");
        assert_eq!(
            session.expose_refresh_token(),
            Some("rt_sample_refresh_token")
        );
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

        assert_eq!(session.expose_access_token(), "at_initial");
        assert_eq!(session.expose_refresh_token(), Some("rt_initial"));

        session
            .rotate_tokens(
                "at_rotated",
                Some("rt_rotated".to_string()),
                Some("atproto".to_string()),
                Some(600),
            )
            .unwrap();

        assert_eq!(session.expose_access_token(), "at_rotated");
        assert_eq!(session.expose_refresh_token(), Some("rt_rotated"));
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
