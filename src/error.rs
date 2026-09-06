//! Strongly-typed error definitions for `skyauth`.
//!
//! This module provides the central [`AtprotoOAuthError`] hierarchy along with
//! specialized error types for cryptography, DPoP (RFC 9449), PKCE (RFC 7636),
//! and session/token validation.

use thiserror::Error;

/// Root error type encompassing all failure modes across the `skyauth` library.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AtprotoOAuthError {
    /// Low-level cryptographic primitive failure.
    #[error("Cryptographic error: {0}")]
    Crypto(#[from] CryptoError),

    /// RFC 9449 Demonstrating Proof-of-Possession (DPoP) failure.
    #[error("DPoP error: {0}")]
    DPoP(#[from] DPoPError),

    /// RFC 7636 Proof Key for Code Exchange (PKCE) failure.
    #[error("PKCE error: {0}")]
    Pkce(#[from] PkceError),

    /// Token, session, or authentication scheme validation failure.
    #[error("Token error: {0}")]
    Token(#[from] TokenError),

    /// RFC 9126 Pushed Authorization Requests (PAR) failure.
    #[error("PAR error: {0}")]
    Par(#[from] ParError),

    /// Server-Side Request Forgery (SSRF) security filter violation.
    #[error("SSRF error: {0}")]
    Ssrf(#[from] SsrfError),

    /// Decentralized identity and handle resolution error.
    #[error("Identity error: {0}")]
    Identity(#[from] IdentityError),

    /// OAuth 2.0 / RFC 8414 / RFC 9728 discovery error.
    #[error("Discovery error: {0}")]
    Discovery(#[from] DiscoveryError),

    /// State storage and persistence error.
    #[error("Store error: {0}")]
    Store(#[from] StoreError),

    /// Framework integration and extractor error.
    #[error("Integration error: {0}")]
    Integration(#[from] IntegrationError),
}

/// Errors originating from cryptographic operations and primitive transformations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// Failure during ECDSA P-256 signature generation.
    #[error("ECDSA P-256 signature generation error: {0}")]
    EcdsaSign(String),

    /// Failure during ECDSA P-256 signature verification.
    #[error("ECDSA P-256 signature verification failed: {0}")]
    EcdsaVerify(String),

    /// The provided key data or PEM/DER encoding is invalid.
    #[error("Invalid cryptographic key: {0}")]
    InvalidKey(String),

    /// The elliptic curve point coordinates are invalid or not on curve NIST P-256.
    #[error("Invalid elliptic curve point: {0}")]
    InvalidPoint(String),

    /// Base64 decoding failed due to malformed characters or padding.
    #[error("Base64 decode error: {0}")]
    Base64Decode(String),

    /// JSON serialization or deserialization failed.
    #[error("JSON serialization/deserialization error: {0}")]
    Json(String),

    /// The cryptographic random number generator failed.
    #[error("Random number generator error: {0}")]
    Rng(String),

    /// HMAC key initialization or digest computation failed.
    #[error("HMAC error: {0}")]
    Hmac(String),

    /// PEM certificate/key decoding error.
    #[error("PEM decoding error: {0}")]
    Pem(String),
}

/// Errors arising from RFC 9449 DPoP proof generation, serialization, or verification.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DPoPError {
    /// Malformed compact JWT structure (must contain exactly three period-separated parts).
    #[error("Malformed JWT structure: {0}")]
    MalformedJwt(String),

    /// Invalid JOSE header `typ` parameter (RFC 9449 § 4.2 requires `dpop+jwt`).
    #[error("Invalid JOSE header typ parameter: expected 'dpop+jwt', got '{0}'")]
    InvalidHeaderTyp(String),

    /// Unsupported JOSE header `alg` algorithm (must be `ES256`).
    #[error("Unsupported JOSE algorithm: expected 'ES256', got '{0}'")]
    UnsupportedAlgorithm(String),

    /// The JOSE header is missing the mandatory public JWK parameter.
    #[error("Missing JWK in JOSE header")]
    MissingJwk,

    /// The JWK in the JOSE header is invalid or contains unexpected parameters.
    #[error("Invalid JWK parameter: {0}")]
    InvalidJwk(String),

    /// Security violation: The JWK contains private key coordinates (RFC 9449 § 4.3 item 7).
    #[error("Security violation: JWK must not contain private key parameters")]
    PrivateKeyInJwk,

    /// A required claim was absent from the DPoP payload.
    #[error("Missing required DPoP claim: {0}")]
    MissingClaim(&'static str),

    /// The `jti` claim exceeds the maximum admissible length
    /// ([`crate::dpop::MAX_JTI_LENGTH`]). Unbounded `jti` values would become
    /// replay-cache keys, enabling memory-amplification attacks on the verifier
    /// (independent review finding; bounded fail-closed).
    #[error("DPoP jti claim exceeds maximum length of {max} bytes (got {actual})")]
    JtiTooLong {
        /// The maximum permitted `jti` length in bytes.
        max: usize,
        /// The actual `jti` length in bytes.
        actual: usize,
    },

    /// The HTTP method in the `htm` claim does not match the actual HTTP request method.
    #[error("HTTP method mismatch: expected '{expected}', got '{actual}'")]
    MethodMismatch {
        /// The expected HTTP method.
        expected: String,
        /// The actual HTTP method found in the claim.
        actual: String,
    },

    /// The HTTP target URI in the `htu` claim does not match the actual target URI.
    #[error("HTTP URI mismatch: expected '{expected}', got '{actual}'")]
    UriMismatch {
        /// The expected normalized URI.
        expected: String,
        /// The actual normalized URI found in the claim.
        actual: String,
    },

    /// The target URI cannot be parsed or normalized according to RFC 3986 / RFC 9449.
    #[error("Invalid URI: {0}")]
    InvalidUri(String),

    /// The DPoP proof has expired according to its `exp` claim.
    #[error("DPoP proof expired: exp {exp} < now {now}")]
    ExpiredProof {
        /// Expiration timestamp in seconds since epoch.
        exp: u64,
        /// Current timestamp in seconds since epoch.
        now: u64,
    },

    /// The DPoP proof `iat` claim is too far in the future (exceeds clock skew allowance).
    #[error("DPoP proof creation time in future: iat {iat} > now {now} (+{leeway}s leeway)")]
    FutureProof {
        /// Creation timestamp in seconds since epoch.
        iat: u64,
        /// Current timestamp in seconds since epoch.
        now: u64,
        /// Allowed clock skew leeway in seconds.
        leeway: u64,
    },

    /// The proof age exceeds the maximum allowed age limit.
    #[error("DPoP proof too old: iat {iat} older than maximum age {max_age_secs}s at now {now}")]
    ProofTooOld {
        /// Creation timestamp in seconds since epoch.
        iat: u64,
        /// Current timestamp in seconds since epoch.
        now: u64,
        /// Maximum permitted proof age in seconds.
        max_age_secs: u64,
    },

    /// The `nonce` claim does not match the server-issued challenge nonce.
    #[error("DPoP nonce mismatch: expected '{expected}', got '{actual}'")]
    NonceMismatch {
        /// The expected nonce issued by the server.
        expected: String,
        /// The actual nonce provided in the proof.
        actual: String,
    },

    /// The server requires a DPoP nonce, but none was supplied in the proof.
    #[error("Missing server-required DPoP nonce")]
    MissingNonce,

    /// The access token hash (`ath`) claim does not match the SHA-256 hash of the presented access token.
    #[error("Access token hash (ath) mismatch: expected '{expected}', got '{actual}'")]
    AthMismatch {
        /// The expected access token hash.
        expected: String,
        /// The actual access token hash in the proof.
        actual: String,
    },

    /// An access token was presented against a protected resource without an `ath` claim in the DPoP proof.
    #[error("Missing access token hash (ath) claim for protected resource access")]
    MissingAth,

    /// The cryptographic ECDSA P-256 signature on the DPoP proof is invalid.
    #[error("Cryptographic signature verification failed")]
    SignatureVerificationFailed,

    /// A duplicate `jti` token identifier was presented, indicating a potential replay attack.
    #[error("DPoP proof replay detected: jti '{jti}' already consumed")]
    ReplayDetected {
        /// The duplicated JWT unique identifier.
        jti: String,
    },

    /// Automatic nonce retry loop exceeded the maximum allowed attempts (1 retry).
    #[error("DPoP nonce retry limit exceeded")]
    NonceRetryLimitExceeded,

    /// The DPoP replay cache has reached capacity with live (unexpired) proofs.
    ///
    /// This is a server-side resource-exhaustion condition, not a defective client
    /// proof; callers should map it to an HTTP 503-class response, not 401.
    #[error(
        "DPoP replay cache capacity saturated with active proofs (server-side resource exhaustion)"
    )]
    ReplayCacheSaturated,

    /// The DPoP server-nonce cache has reached capacity with live (unexpired) nonces.
    ///
    /// Like [`DPoPError::ReplayCacheSaturated`], this is a server-side resource-
    /// exhaustion condition; callers should map it to an HTTP 503-class response.
    #[error(
        "DPoP nonce cache capacity saturated with active nonces (server-side resource exhaustion)"
    )]
    NonceCacheSaturated,

    /// JSON or byte serialization failed.
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// System clock error or excessive clock skew.
    #[error("Clock skew error: {0}")]
    ClockSkew(String),

    /// Underlying cryptographic primitive error.
    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),
}

/// Errors originating from RFC 7636 PKCE code verifier or challenge generation/verification.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PkceError {
    /// The code verifier length is out of the RFC 7636 range (43 to 128 characters).
    #[error("Invalid code_verifier length: {len} (must be between {min} and {max} characters)")]
    InvalidVerifierLength {
        /// Provided verifier character length.
        len: usize,
        /// Minimum permitted length (43).
        min: usize,
        /// Maximum permitted length (128).
        max: usize,
    },

    /// The code verifier contains an illegal character outside `[A-Za-z0-9-._~]`.
    #[error("Invalid character '{char}' at position {position} in code_verifier")]
    InvalidVerifierCharacter {
        /// The forbidden character encountered.
        char: char,
        /// Zero-based byte index where the character was found.
        position: usize,
    },

    /// The code challenge length is invalid (RFC 7636 S256 requires 43 characters).
    #[error("Invalid code_challenge length: {len} (must be 43 characters)")]
    InvalidChallengeLength {
        /// Provided challenge character length.
        len: usize,
    },

    /// An unsupported transformation method was requested (only `S256` is permitted).
    #[error("Unsupported code_challenge_method: expected 'S256', got '{0}'")]
    UnsupportedMethod(String),

    /// The code verifier does not match the expected code challenge.
    #[error("PKCE code challenge verification failed")]
    ChallengeMismatch,

    /// Underlying cryptographic primitive error.
    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),
}

/// Errors related to access tokens, refresh tokens, and session credentials.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TokenError {
    /// The HTTP Authorization header is missing.
    #[error("Missing Authorization header")]
    MissingHeader,

    /// The HTTP Authorization scheme is invalid (must be `DPoP` or `Bearer`).
    #[error("Invalid authentication scheme: expected '{expected}', got '{actual}'")]
    InvalidScheme {
        /// The expected scheme.
        expected: String,
        /// The actual scheme provided.
        actual: String,
    },

    /// The token has expired.
    #[error("Token expired: exp {exp} < now {now}")]
    Expired {
        /// Expiration timestamp in seconds since epoch.
        exp: u64,
        /// Current timestamp in seconds since epoch.
        now: u64,
    },

    /// The token is not yet valid (`nbf` claim in future).
    #[error("Token not yet valid: nbf {nbf} > now {now}")]
    NotYetValid {
        /// Not-before timestamp in seconds since epoch.
        nbf: u64,
        /// Current timestamp in seconds since epoch.
        now: u64,
    },

    /// The token audience does not match the expected client ID or resource server.
    #[error("Audience mismatch: expected '{expected}', got '{actual}'")]
    AudienceMismatch {
        /// Expected audience string.
        expected: String,
        /// Actual audience found in token.
        actual: String,
    },

    /// The token issuer does not match the expected authorization server.
    #[error("Issuer mismatch: expected '{expected}', got '{actual}'")]
    IssuerMismatch {
        /// Expected issuer string.
        expected: String,
        /// Actual issuer found in token.
        actual: String,
    },

    /// The cryptographic signature on the token is invalid.
    #[error("Invalid token signature")]
    InvalidSignature,

    /// The access token is missing the required confirmation (`cnf.jkt`) claim.
    #[error("Missing cnf.jkt confirmation claim in access token")]
    MissingCnf,

    /// The access token `cnf.jkt` binding does not match the presented DPoP key thumbprint.
    #[error(
        "DPoP key thumbprint mismatch: token cnf.jkt '{expected_jkt}' does not match proof jkt '{actual_jkt}'"
    )]
    CnfThumbprintMismatch {
        /// Expected JWK thumbprint declared in token `cnf.jkt`.
        expected_jkt: String,
        /// Actual JWK thumbprint computed from the DPoP proof public key.
        actual_jkt: String,
    },

    /// The access token is missing a required audience (`aud`) claim.
    #[error("Missing required audience (aud) claim in access token")]
    MissingAudience,

    /// The access token is missing a required issuer (`iss`) claim.
    #[error("Missing required issuer (iss) claim in access token")]
    MissingIssuer,

    /// The token is missing the required Decentralized Identifier (`did`) subject.
    #[error("Missing or invalid subject/issuer DID")]
    MissingDid,

    /// The server challenged the client with a DPoP nonce requirement (`use_dpop_nonce`).
    #[error("Server requires DPoP nonce challenge (use_dpop_nonce)")]
    UseDPoPNonce {
        /// New nonce value provided by the server, if any.
        nonce: Option<String>,
    },

    /// The token format or claims payload is malformed.
    #[error("Malformed token: {0}")]
    MalformedToken(String),

    /// The XRPC NSID fails ATProto NSID grammar validation.
    #[error(
        "Invalid NSID '{0}': must be a reverse-DNS, dot-separated identifier of at least three segments (total <=317 chars, each segment <=63 chars, ASCII alphanumerics and internal hyphens only, no leading/trailing hyphens, first segment starting with a letter, final name segment letters and digits only with no leading digit)"
    )]
    InvalidNsid(String),

    /// The configured authorization state TTL is not a whole number of seconds.
    #[error(
        "Invalid state TTL {0:?}: must be a whole number of seconds (sub-second TTLs cannot be represented in StoredStateEntry)"
    )]
    InvalidStateTtl(std::time::Duration),

    /// Invalid token_type (must be case-insensitively "DPoP").
    #[error("Invalid token_type: expected 'DPoP', got '{0}'")]
    InvalidTokenType(String),

    /// A required field was missing from the token response.
    #[error("Missing required token response field: {0}")]
    MissingField(&'static str),

    /// The subject DID does not match the expected DID.
    #[error("Subject DID mismatch: expected '{expected}', got '{actual}'")]
    SubMismatch {
        /// Expected DID subject.
        expected: String,
        /// Actual DID subject in token response.
        actual: String,
    },

    /// The token response is missing the mandatory `atproto` scope.
    #[error("Token scope '{0}' is missing mandatory 'atproto' scope")]
    MissingAtprotoScope(String),

    /// The token endpoint rejected the request.
    #[error("Token request failed with HTTP status {status}: {error} ({description:?})")]
    RequestFailed {
        /// HTTP status code.
        status: u16,
        /// Error code returned by server (e.g. `invalid_grant`).
        error: String,
        /// Optional descriptive explanation.
        description: Option<String>,
    },

    /// The session does not have a refresh token to perform rotation.
    #[error("Session is missing a refresh token for rotation")]
    MissingRefreshToken,

    /// The callback state parameter is invalid or missing.
    #[error("Invalid or missing OAuth state parameter: {0}")]
    InvalidState(String),

    /// The OAuth state entry has expired.
    #[error("OAuth state entry has expired")]
    StateExpired,

    /// The callback query is missing the mandatory RFC 9207 `iss` issuer parameter.
    #[error("Callback query is missing mandatory RFC 9207 'iss' issuer parameter")]
    MissingCallbackIssuer,

    /// The token response is missing the mandatory `scope` field.
    #[error("Token response is missing mandatory 'scope' field")]
    MissingScope,

    /// HTTP error during token exchange or refresh.
    #[error("HTTP error during token operation: {0}")]
    Http(String),

    /// JSON error during token operation.
    #[error("JSON error during token operation: {0}")]
    Json(String),

    /// DPoP error during token operation.
    #[error("DPoP error during token operation: {0}")]
    DPoP(#[from] DPoPError),

    /// SSRF error during token operation.
    #[error("SSRF error during token operation: {0}")]
    Ssrf(#[from] SsrfError),

    /// Underlying cryptographic primitive error.
    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),
}

/// Errors originating from RFC 9126 Pushed Authorization Requests (PAR).
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ParError {
    /// The authorization server rejected the PAR request with an HTTP error.
    #[error("PAR request failed with HTTP status {status}: {error} ({description:?})")]
    RequestFailed {
        /// HTTP status code.
        status: u16,
        /// Error code returned by server (e.g. `invalid_request`).
        error: String,
        /// Optional descriptive error explanation.
        description: Option<String>,
    },

    /// The PAR response is missing a required parameter.
    #[error("Missing required PAR response field: {0}")]
    MissingField(&'static str),

    /// The returned `request_uri` is invalid or malformed.
    #[error("Invalid request_uri returned from PAR: '{0}'")]
    InvalidRequestUri(String),

    /// The PAR endpoint URL is invalid or malformed.
    #[error("Invalid PAR endpoint URL: {0}")]
    InvalidEndpoint(String),

    /// Low-level HTTP transport or connection error.
    #[error("HTTP error during PAR: {0}")]
    Http(String),

    /// JSON serialization or deserialization error.
    #[error("JSON error during PAR: {0}")]
    Json(String),

    /// RFC 9449 DPoP proof error during PAR.
    #[error("DPoP error during PAR: {0}")]
    DPoP(#[from] DPoPError),

    /// SSRF security filter violation during PAR.
    #[error("SSRF violation during PAR: {0}")]
    Ssrf(#[from] SsrfError),
}

/// Errors arising from Server-Side Request Forgery (SSRF) and IP boundary filtering.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SsrfError {
    /// An outbound request targeted a forbidden/restricted IP address.
    #[error("SSRF violation: blocked attempt to connect to restricted IP {0}")]
    BlockedIp(String),

    /// An outbound request targeted a forbidden cloud metadata or internal hostname.
    #[error("SSRF violation: blocked attempt to connect to restricted host '{0}'")]
    BlockedHost(String),

    /// An insecure URL scheme was encountered (HTTPS is required in production).
    #[error("SSRF violation: insecure URL scheme in '{0}' (HTTPS required)")]
    InsecureScheme(String),

    /// DNS resolution failed for the target hostname.
    #[error("DNS resolution failed: {0}")]
    DnsResolutionFailed(String),

    /// The provided URL is malformed or invalid.
    #[error("Invalid URL: {0}")]
    InvalidUrl(String),

    /// Redirect chain exceeded the maximum allowed depth limit.
    #[error("Too many redirects: exceeded maximum permitted redirect limit")]
    TooManyRedirects,

    /// Response body exceeded the maximum permitted size limit.
    #[error(
        "Response body too large: max {max_bytes} bytes allowed, received {actual_bytes} bytes"
    )]
    ResponseTooLarge {
        /// Maximum permitted byte size.
        max_bytes: usize,
        /// Actual received byte size.
        actual_bytes: usize,
    },

    /// HTTP response returned an unsuccessful status code.
    #[error("HTTP status {0}: {1}")]
    HttpStatus(u16, String),

    /// Low-level HTTP transport or connection error.
    #[error("HTTP transport error: {0}")]
    Http(String),

    /// I/O or network socket error.
    #[error("I/O error: {0}")]
    Io(String),

    /// JSON serialization or deserialization error.
    #[error("JSON error: {0}")]
    Json(String),
}

/// Errors originating from decentralized identity (DID) and handle resolution.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum IdentityError {
    /// Handle does not conform to ATProto syntax requirements.
    #[error("Invalid handle syntax: {0}")]
    InvalidHandleSyntax(String),

    /// Handle uses a disallowed or restricted top-level domain (TLD).
    #[error("Disallowed handle TLD: {0}")]
    DisallowedHandleTld(String),

    /// Handle resolution failed via all configured mechanisms.
    #[error("Handle resolution failed for '{0}'")]
    HandleResolutionFailed(String),

    /// DNS TXT resolution returned multiple conflicting DID records.
    #[error("Ambiguous handle resolution: multiple conflicting DIDs found for '{0}'")]
    AmbiguousHandleResolution(String),

    /// Resolved DID document `alsoKnownAs` does not match the claimed handle.
    #[error(
        "Bidirectional verification failed: handle '{0}' does not match DID document alsoKnownAs"
    )]
    HandleDidMismatch(String),

    /// The provided DID string is malformed or has an invalid syntax.
    #[error("Invalid DID syntax: {0}")]
    InvalidDidSyntax(String),

    /// The DID method is unsupported (only `did:plc` and `did:web` are supported).
    #[error("Unsupported DID method: {0}")]
    UnsupportedDidMethod(String),

    /// The queried DID was not found in the directory or host.
    #[error("DID not found: {0}")]
    DidNotFound(String),

    /// The returned DID document JSON is malformed or missing mandatory fields.
    #[error("Malformed DID document: {0}")]
    MalformedDidDocument(String),

    /// The DID document `id` field does not match the queried DID.
    #[error("DID document ID mismatch: expected '{expected}', found '{actual}'")]
    DidDocumentIdMismatch {
        /// The expected DID identifier.
        expected: String,
        /// The actual DID identifier in the document.
        actual: String,
    },

    /// The DID document is missing the mandatory `#atproto_pds` service endpoint.
    #[error("DID document missing '#atproto_pds' service endpoint for DID '{0}'")]
    MissingPdsEndpoint(String),

    /// The `#atproto_pds` service endpoint URL is invalid or malformed.
    #[error("Invalid PDS endpoint URL: {0}")]
    InvalidPdsEndpoint(String),

    /// SSRF security violation during identity resolution.
    #[error("SSRF violation during identity resolution: {0}")]
    Ssrf(#[from] SsrfError),

    /// HTTP error during identity resolution.
    #[error("HTTP error during identity resolution: {0}")]
    Http(String),

    /// JSON error during identity resolution.
    #[error("JSON error during identity resolution: {0}")]
    Json(String),

    /// DNS resolution error during handle resolution.
    #[error("DNS error during handle resolution: {0}")]
    Dns(String),
}

/// Errors originating from RFC 8414 and RFC 9728 OAuth discovery.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DiscoveryError {
    /// Protected Resource Metadata discovery failed (RFC 9728).
    #[error("Protected resource metadata discovery failed: {0}")]
    ProtectedResourceDiscoveryFailed(String),

    /// Protected Resource Metadata does not list any authorization servers.
    #[error("No authorization servers listed in protected resource metadata for PDS '{0}'")]
    MissingAuthorizationServers(String),

    /// Protected Resource Metadata listed multiple authorization servers (ATProto requires exactly one).
    #[error(
        "Protected resource metadata declared {0} authorization servers; ATProto requires exactly one"
    )]
    MultipleAuthorizationServers(usize),

    /// Authorization server URL in Protected Resource Metadata is not a valid origin.
    #[error("Authorization server URL '{0}' is not a valid origin")]
    InvalidAuthorizationServerUrl(String),

    /// Protected Resource Metadata `resource` does not match the queried PDS origin.
    #[error(
        "Protected resource metadata resource '{actual}' does not match expected PDS origin '{expected}'"
    )]
    ResourceMismatch {
        /// Expected PDS endpoint/origin.
        expected: String,
        /// Actual resource declared in metadata.
        actual: String,
    },

    /// Authorization Server Metadata discovery failed (RFC 8414).
    #[error("Authorization server metadata discovery failed: {0}")]
    AuthServerDiscoveryFailed(String),

    /// Authorization Server Metadata `issuer` does not match the expected origin.
    #[error("Authorization server issuer mismatch: expected '{expected}', found '{actual}'")]
    IssuerMismatch {
        /// The expected authorization server origin.
        expected: String,
        /// The actual issuer string declared in the metadata.
        actual: String,
    },

    /// Authorization server is missing required `ES256` DPoP signing algorithm support.
    #[error("Authorization server '{0}' is missing required ES256 DPoP algorithm support")]
    MissingDpopAlgorithm(String),

    /// Authorization server is missing required `S256` PKCE code challenge method support.
    #[error("Authorization server '{0}' is missing required S256 PKCE method support")]
    MissingPkceMethod(String),

    /// Authorization server metadata is missing the required PAR endpoint.
    #[error(
        "Authorization server '{0}' is missing required pushed_authorization_request_endpoint"
    )]
    MissingParEndpoint(String),

    /// Authorization server metadata does not mandate pushed authorization requests (`require_pushed_authorization_requests` must be true).
    #[error(
        "Authorization server '{0}' does not mandate pushed authorization requests (require_pushed_authorization_requests must be true)"
    )]
    ParNotRequired(String),

    /// Authorization server explicitly disabled RFC 9126 request_uri registration (`require_request_uri_registration` must not be false).
    #[error(
        "Authorization server '{0}' explicitly disabled require_request_uri_registration; the ATProto OAuth profile mandates it"
    )]
    MissingRequestUriRegistration(String),

    /// Authorization server metadata is missing the required 'code' response type.
    #[error("Authorization server '{0}' is missing required 'code' response type support")]
    MissingResponseType(String),

    /// Authorization server metadata is missing a required grant type (`authorization_code` or `refresh_token`).
    #[error("Authorization server '{auth_server}' is missing required '{missing}' grant type")]
    MissingGrantType {
        /// Authorization server URL.
        auth_server: String,
        /// Missing grant type name.
        missing: String,
    },

    /// Authorization server metadata is missing required token endpoint authentication methods (`none` AND `private_key_jwt`).
    #[error(
        "Authorization server '{0}' must advertise both required token endpoint authentication methods ('none' and 'private_key_jwt')"
    )]
    MissingTokenAuthMethod(String),

    /// Authorization server is missing required `ES256` token endpoint authentication signing algorithm support.
    #[error(
        "Authorization server '{0}' is missing required ES256 in token_endpoint_auth_signing_alg_values_supported"
    )]
    MissingTokenAuthSigningAlg(String),

    /// Authorization server advertised forbidden 'none' in token_endpoint_auth_signing_alg_values_supported.
    #[error(
        "Authorization server '{0}' advertised forbidden 'none' in token_endpoint_auth_signing_alg_values_supported"
    )]
    InvalidTokenAuthSigningAlg(String),

    /// Authorization server metadata is missing required `atproto` scope in `scopes_supported`.
    #[error("Authorization server '{0}' is missing required 'atproto' scope in scopes_supported")]
    MissingAtprotoScope(String),

    /// Authorization server metadata does not support RFC 9207 `iss` response parameter (`authorization_response_iss_parameter_supported` must be true).
    #[error(
        "Authorization server '{0}' does not support RFC 9207 authorization_response_iss_parameter_supported"
    )]
    MissingIssParameterSupport(String),

    /// Authorization server metadata does not support client metadata document resolution (`client_id_metadata_document_supported` must be true).
    #[error("Authorization server '{0}' does not support client_id_metadata_document_supported")]
    MissingClientMetadataSupport(String),

    /// Authorization server metadata is missing the required token endpoint.
    #[error("Authorization server '{0}' is missing required token_endpoint")]
    MissingTokenEndpoint(String),

    /// Authorization server metadata is missing the required authorization endpoint.
    #[error("Authorization server '{0}' is missing required authorization_endpoint")]
    MissingAuthorizationEndpoint(String),

    /// An endpoint URL in the metadata is invalid.
    #[error("Invalid endpoint URL in discovery metadata: {0}")]
    InvalidEndpointUrl(String),

    /// Identity resolution error during discovery.
    #[error("Identity resolution error during discovery: {0}")]
    Identity(#[from] IdentityError),

    /// SSRF security violation during discovery.
    #[error("SSRF violation during discovery: {0}")]
    Ssrf(#[from] SsrfError),

    /// HTTP error during discovery.
    #[error("HTTP error during discovery: {0}")]
    Http(String),

    /// JSON error during discovery.
    #[error("JSON error during discovery: {0}")]
    Json(String),
}

/// Errors originating from OAuth state and session storage backends.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum StoreError {
    /// The requested authorization state token has expired.
    #[error("State token has expired: '{0}'")]
    StateExpired(String),

    /// The requested authorization state token was not found (or already consumed).
    #[error("State token not found or already consumed: '{0}'")]
    StateNotFound(String),

    /// An error occurred in the underlying storage backend.
    #[error("Storage backend error: {0}")]
    Backend(String),

    /// State serialization or deserialization failed.
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// A lock acquisition or concurrency invariant violation occurred.
    #[error("Lock acquisition or concurrency error: {0}")]
    Lock(String),
}

/// Errors originating from web framework integrations and extractors.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum IntegrationError {
    /// The callback request query is missing the mandatory `code` parameter.
    #[error("Missing OAuth code parameter in callback query")]
    MissingCode,

    /// The callback request query is missing the mandatory `state` parameter.
    #[error("Missing OAuth state parameter in callback query")]
    MissingState,

    /// An OAuth error code and description returned by the authorization server.
    #[error("OAuth authorization server error: {error} ({description})")]
    OAuthError {
        /// Standard OAuth error code (e.g. `access_denied`, `invalid_request`).
        error: String,
        /// Optional human-readable error description.
        description: String,
    },

    /// The request is missing the required `Authorization` header.
    #[error("Missing or malformed Authorization header")]
    MissingAuthHeader,

    /// The `Authorization` header scheme is invalid (expected `DPoP`).
    #[error("Invalid Authorization header scheme: expected 'DPoP', got '{0}'")]
    InvalidAuthScheme(String),

    /// The request is missing the required `DPoP` proof header.
    #[error("Missing DPoP proof header")]
    MissingDPoPProofHeader,

    /// The requested authenticated session was not found or has expired.
    #[error("Session not found or expired")]
    SessionNotFound,

    /// Inbound request authentication failed.
    #[error("Authentication failed: {0}")]
    AuthFailed(String),

    /// Internal framework integration or response generation failure.
    #[error("Internal framework error: {0}")]
    Internal(String),

    /// Underlying store error.
    #[error("Store error: {0}")]
    Store(#[from] StoreError),

    /// Underlying DPoP validation error.
    #[error("DPoP error: {0}")]
    DPoP(#[from] DPoPError),

    /// Underlying token error.
    #[error("Token error: {0}")]
    Token(#[from] TokenError),
}
