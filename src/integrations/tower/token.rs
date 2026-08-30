use std::collections::{BTreeSet, HashMap};
use std::fmt::Debug;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use url::Url;

use crate::crypto::{base64url_decode, verify_p256_raw};
use crate::dpop::JwkEc;
use crate::error::TokenError;
use crate::identity::validate_did_syntax;
use crate::scope::ScopeSet;

mod private {
    pub trait Sealed {}
}

/// Independently validates supported access-token formats.
pub trait AccessTokenValidator: private::Sealed + Debug + Send + Sync + 'static {
    /// Validates one serialized access token at the supplied time.
    ///
    /// # Errors
    ///
    /// Returns [`TokenError`] when authenticity or required claims cannot be established.
    fn validate(
        &self,
        access_token: &str,
        now: SystemTime,
    ) -> Result<ValidatedAccessToken, TokenError>;
}

/// Trusted keys and audiences for one token issuer.
#[derive(Debug, Clone)]
pub struct JwtTrustedIssuer {
    issuer: String,
    audiences: BTreeSet<String>,
    signing_keys: HashMap<String, JwkEc>,
}

impl JwtTrustedIssuer {
    /// Creates issuer configuration with at least one accepted audience.
    ///
    /// # Errors
    ///
    /// Returns [`TokenError`] for a non-canonical issuer or empty audience set.
    pub fn new(
        issuer: impl Into<String>,
        audiences: impl IntoIterator<Item = String>,
    ) -> Result<Self, TokenError> {
        let issuer = canonical_issuer(&issuer.into())?;
        let audiences = audiences
            .into_iter()
            .filter(|audience| !audience.trim().is_empty())
            .collect::<BTreeSet<_>>();
        if audiences.is_empty() {
            return Err(TokenError::MissingField("aud"));
        }
        Ok(Self {
            issuer,
            audiences,
            signing_keys: HashMap::new(),
        })
    }

    /// Adds a pinned ES256 verification key.
    ///
    /// # Errors
    ///
    /// Returns [`TokenError`] when the identifier or public key is invalid.
    pub fn add_signing_key(
        mut self,
        kid: impl Into<String>,
        jwk: JwkEc,
    ) -> Result<Self, TokenError> {
        let kid = kid.into();
        if kid.trim().is_empty() {
            return Err(TokenError::MissingField("kid"));
        }
        if jwk.kty != "EC" || jwk.crv != "P-256" || jwk.to_verifying_key().is_err() {
            return Err(TokenError::MalformedToken(
                "invalid ES256 verification key".to_string(),
            ));
        }
        self.signing_keys.insert(kid, jwk);
        Ok(self)
    }
}

/// Validator for RFC 9068-style ES256 JWT access tokens.
#[derive(Debug, Clone)]
pub struct JwtAccessTokenValidator {
    issuers: HashMap<String, JwtTrustedIssuer>,
    clock_skew: Duration,
}

impl JwtAccessTokenValidator {
    /// Creates a validator from pinned issuer configurations.
    ///
    /// # Errors
    ///
    /// Returns [`TokenError`] when no issuer or signing key is configured.
    pub fn new(issuers: impl IntoIterator<Item = JwtTrustedIssuer>) -> Result<Self, TokenError> {
        let issuers = issuers
            .into_iter()
            .map(|issuer| (issuer.issuer.clone(), issuer))
            .collect::<HashMap<_, _>>();
        if issuers.is_empty() {
            return Err(TokenError::MissingField("iss"));
        }
        if issuers
            .values()
            .any(|issuer| issuer.signing_keys.is_empty())
        {
            return Err(TokenError::MissingField("kid"));
        }
        Ok(Self {
            issuers,
            clock_skew: Duration::from_secs(60),
        })
    }

    /// Sets the permitted token clock skew.
    #[must_use]
    pub fn with_clock_skew(mut self, clock_skew: Duration) -> Self {
        self.clock_skew = clock_skew;
        self
    }
}

impl private::Sealed for JwtAccessTokenValidator {}

impl AccessTokenValidator for JwtAccessTokenValidator {
    fn validate(
        &self,
        access_token: &str,
        now: SystemTime,
    ) -> Result<ValidatedAccessToken, TokenError> {
        let mut segments = access_token.split('.');
        let header_segment = segments
            .next()
            .ok_or_else(|| malformed("missing JWT header"))?;
        let claims_segment = segments
            .next()
            .ok_or_else(|| malformed("missing JWT claims"))?;
        let signature_segment = segments
            .next()
            .ok_or_else(|| malformed("missing JWT signature"))?;
        if segments.next().is_some()
            || header_segment.is_empty()
            || claims_segment.is_empty()
            || signature_segment.is_empty()
        {
            return Err(malformed("invalid compact JWT"));
        }

        let header: JwtHeader = serde_json::from_slice(&base64url_decode(header_segment)?)
            .map_err(|_| malformed("invalid JWT header"))?;
        let access_token_type = header.typ.eq_ignore_ascii_case("at+jwt")
            || header.typ.eq_ignore_ascii_case("application/at+jwt");
        if !access_token_type || header.alg != "ES256" || header.kid.trim().is_empty() {
            return Err(malformed("unsupported JWT header"));
        }

        let claims: JwtClaims = serde_json::from_slice(&base64url_decode(claims_segment)?)
            .map_err(|_| malformed("invalid JWT claims"))?;
        let canonical_claim_issuer = canonical_issuer(&claims.iss)?;
        let trusted = self.issuers.get(&canonical_claim_issuer).ok_or_else(|| {
            TokenError::IssuerMismatch {
                expected: "configured issuer".to_string(),
                actual: canonical_claim_issuer.clone(),
            }
        })?;
        let key = trusted
            .signing_keys
            .get(&header.kid)
            .ok_or(TokenError::InvalidSignature)?;
        let signature = base64url_decode(signature_segment)?;
        let signing_input = format!("{header_segment}.{claims_segment}");
        verify_p256_raw(
            &key.to_verifying_key()?,
            signing_input.as_bytes(),
            &signature,
        )
        .map_err(|_| TokenError::InvalidSignature)?;

        let now = now
            .duration_since(UNIX_EPOCH)
            .map_err(|_| malformed("system time precedes UNIX epoch"))?
            .as_secs();
        let skew = self.clock_skew.as_secs();
        if claims.exp.saturating_add(skew) < now {
            return Err(TokenError::Expired {
                exp: claims.exp,
                now,
            });
        }
        if claims.iat > now.saturating_add(skew) {
            return Err(TokenError::NotYetValid {
                nbf: claims.iat,
                now,
            });
        }
        if let Some(nbf) = claims.nbf {
            if nbf > now.saturating_add(skew) {
                return Err(TokenError::NotYetValid { nbf, now });
            }
        }
        validate_did_syntax(&claims.sub).map_err(|_| TokenError::MissingDid)?;

        let audiences = claims.aud.into_set();
        if audiences.is_empty() || audiences.is_disjoint(&trusted.audiences) {
            return Err(TokenError::AudienceMismatch {
                expected: trusted
                    .audiences
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(" "),
                actual: audiences.iter().cloned().collect::<Vec<_>>().join(" "),
            });
        }
        let parsed_scope = ScopeSet::parse(&claims.scope)
            .map_err(|_| TokenError::MissingAtprotoScope("invalid scope set".to_string()))?;
        let scopes = parsed_scope
            .as_str()
            .split_ascii_whitespace()
            .map(str::to_string)
            .collect::<BTreeSet<_>>();
        if claims.jti.trim().is_empty() {
            return Err(TokenError::MissingField("jti"));
        }
        if claims.cnf.jkt.trim().is_empty() {
            return Err(TokenError::MissingField("cnf.jkt"));
        }

        Ok(ValidatedAccessToken {
            issuer: canonical_claim_issuer,
            subject: claims.sub,
            audiences,
            expires_at: claims.exp,
            scopes,
            token_identifier: claims.jti,
            confirmation_thumbprint: claims.cnf.jkt,
        })
    }
}

/// Independently validated access-token claims.
///
/// ```compile_fail
/// use skyauth::integrations::tower::ValidatedAccessToken;
///
/// fn forge(token: ValidatedAccessToken) {
///     let ValidatedAccessToken { subject, .. } = token;
///     drop(subject);
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedAccessToken {
    issuer: String,
    subject: String,
    audiences: BTreeSet<String>,
    expires_at: u64,
    scopes: BTreeSet<String>,
    token_identifier: String,
    confirmation_thumbprint: String,
}

impl ValidatedAccessToken {
    /// Returns the canonical token issuer.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Returns the validated subject DID.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Returns the validated token audiences.
    #[must_use]
    pub fn audiences(&self) -> &BTreeSet<String> {
        &self.audiences
    }

    /// Returns the expiration timestamp in seconds since the UNIX epoch.
    #[must_use]
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Returns the validated scope set.
    #[must_use]
    pub fn scopes(&self) -> &BTreeSet<String> {
        &self.scopes
    }

    /// Returns the token identifier.
    #[must_use]
    pub fn token_identifier(&self) -> &str {
        &self.token_identifier
    }

    /// Returns the validated DPoP confirmation thumbprint.
    #[must_use]
    pub fn confirmation_thumbprint(&self) -> &str {
        &self.confirmation_thumbprint
    }
}

#[derive(Debug, Deserialize)]
struct JwtHeader {
    typ: String,
    alg: String,
    kid: String,
}

#[derive(Debug, Deserialize)]
struct JwtClaims {
    iss: String,
    sub: String,
    aud: JwtAudience,
    exp: u64,
    iat: u64,
    #[serde(default)]
    nbf: Option<u64>,
    scope: String,
    jti: String,
    cnf: ConfirmationClaim,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum JwtAudience {
    One(String),
    Many(Vec<String>),
}

impl JwtAudience {
    fn into_set(self) -> BTreeSet<String> {
        match self {
            Self::One(value) => [value].into_iter().collect(),
            Self::Many(values) => values.into_iter().collect(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct ConfirmationClaim {
    jkt: String,
}

fn canonical_issuer(value: &str) -> Result<String, TokenError> {
    let parsed = Url::parse(value).map_err(|_| malformed("invalid token issuer"))?;
    if parsed.scheme() != "https"
        || parsed.username() != ""
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || (parsed.path() != "/" && !parsed.path().is_empty())
    {
        return Err(malformed("token issuer must be a canonical HTTPS origin"));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| malformed("token issuer is missing a host"))?;
    let port = parsed
        .port()
        .map_or_else(String::new, |value| format!(":{value}"));
    Ok(format!("https://{}{port}", host.to_ascii_lowercase()))
}

fn malformed(message: &str) -> TokenError {
    TokenError::MalformedToken(message.to_string())
}
