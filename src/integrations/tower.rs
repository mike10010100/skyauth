//! Tower middleware layer and service for DPoP-bound OAuth request authentication.
//!
//! Provides:
//! - [`OAuthAuthLayer`]: Tower [`tower_layer::Layer`] applying DPoP and token authentication to any compatible service.
//! - [`OAuthAuthService`]: Tower [`tower_service::Service`] extracting, validating, and injecting authenticated sessions.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use http::{header, HeaderValue, Request, Response, StatusCode};
use tower_layer::Layer;
use tower_service::Service;

use super::validator::{AccessTokenValidator, InMemoryTokenValidator, JwtAccessTokenValidator};
use super::OAuthSessionExtension;
use crate::dpop::{
    compute_access_token_hash, DPoPServerNonceSource, DPoPVerifier, InMemoryServerNonceSource,
};
use crate::error::DPoPError;

/// Hook reconstructing the externally visible absolute `htu` from a request URI
/// (used when the server sits behind a reverse proxy).
pub type HtuOverrideFn = Arc<dyn Fn(&http::Uri) -> String + Send + Sync>;

/// Tower layer that enforces AT Protocol DPoP OAuth authentication on inbound HTTP requests.
///
/// Inspects the `Authorization: DPoP <access_token>` and `DPoP: <proof_jwt>` headers,
/// verifies the cryptographic DPoP proof against the HTTP method and URI, validates
/// the access token and its `cnf.jkt` binding via the configured [`AccessTokenValidator`],
/// prevents proof replay attacks via [`crate::dpop::DPoPReplayCache`], and attaches
/// [`OAuthSessionExtension`] and [`super::AuthenticatedUser`] to request extensions.
#[derive(Clone)]
pub struct OAuthAuthLayer {
    verifier: Arc<DPoPVerifier>,
    token_validator: Arc<dyn AccessTokenValidator>,
    nonce_source: Option<Arc<dyn DPoPServerNonceSource>>,
    require_ath: bool,
    htu_override: Option<HtuOverrideFn>,
}

impl std::fmt::Debug for OAuthAuthLayer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthAuthLayer")
            .field("verifier", &self.verifier)
            .field("require_ath", &self.require_ath)
            .finish()
    }
}

impl OAuthAuthLayer {
    /// Creates a new `OAuthAuthLayer` with the provided [`DPoPVerifier`] and [`AccessTokenValidator`].
    #[must_use]
    pub fn new(
        verifier: Arc<DPoPVerifier>,
        token_validator: Arc<dyn AccessTokenValidator>,
    ) -> Self {
        Self {
            verifier,
            token_validator,
            nonce_source: None,
            require_ath: true,
            htu_override: None,
        }
    }

    /// Creates a new `OAuthAuthLayer` using a [`JwtAccessTokenValidator`].
    #[must_use]
    pub fn from_jwt_validator(
        verifier: Arc<DPoPVerifier>,
        jwt_validator: JwtAccessTokenValidator,
    ) -> Self {
        Self::new(verifier, Arc::new(jwt_validator))
    }

    /// Creates a new `OAuthAuthLayer` using an [`InMemoryTokenValidator`].
    #[must_use]
    pub fn from_token_store(
        verifier: Arc<DPoPVerifier>,
        token_validator: InMemoryTokenValidator,
    ) -> Self {
        Self::new(verifier, Arc::new(token_validator))
    }

    /// Creates a new `OAuthAuthLayer` with a concrete validator implementing [`AccessTokenValidator`].
    #[must_use]
    pub fn from_validator<V: AccessTokenValidator>(
        verifier: Arc<DPoPVerifier>,
        validator: V,
    ) -> Self {
        Self::new(verifier, Arc::new(validator))
    }

    /// Configures an optional [`DPoPServerNonceSource`] to enforce server-provided challenge nonces per RFC 9449 § 8.
    #[must_use]
    pub fn with_nonce_source(mut self, nonce_source: Arc<dyn DPoPServerNonceSource>) -> Self {
        self.nonce_source = Some(nonce_source);
        self
    }

    /// Configures in-memory server challenge nonces with the specified time-to-live per RFC 9449 § 8.
    #[must_use]
    pub fn with_server_nonces(mut self, ttl: Duration) -> Self {
        self.nonce_source = Some(Arc::new(InMemoryServerNonceSource::new(ttl)));
        self
    }

    /// Configures whether the access token hash (`ath`) claim is strictly required in DPoP proofs.
    #[must_use]
    pub fn with_require_ath(mut self, require_ath: bool) -> Self {
        self.require_ath = require_ath;
        self
    }

    /// Overrides how the DPoP target URI (`htu`) is derived from inbound request URIs.
    ///
    /// By default the raw request URI string is used as `htu`. HTTP servers behind reverse
    /// proxies or load balancers typically receive origin-form request targets (e.g.
    /// `/xrpc/foo`) while clients sign the absolute URI (e.g.
    /// `https://pds.example.com/xrpc/foo`). Configure this hook to reconstruct the
    /// externally visible absolute URL:
    ///
    /// ```ignore
    /// layer.with_htu_override(|uri| {
    ///     let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    ///     format!("https://pds.example.com{path_and_query}")
    /// })
    /// ```
    #[must_use]
    pub fn with_htu_override<F>(mut self, f: F) -> Self
    where
        F: Fn(&http::Uri) -> String + Send + Sync + 'static,
    {
        self.htu_override = Some(Arc::new(f));
        self
    }
}

impl<S> Layer<S> for OAuthAuthLayer {
    type Service = OAuthAuthService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        OAuthAuthService {
            inner,
            verifier: Arc::clone(&self.verifier),
            token_validator: Arc::clone(&self.token_validator),
            nonce_source: self.nonce_source.clone(),
            require_ath: self.require_ath,
            htu_override: self.htu_override.clone(),
        }
    }
}

/// Tower service that validates DPoP authentication headers and access tokens on inbound requests.
#[derive(Clone)]
pub struct OAuthAuthService<S> {
    inner: S,
    verifier: Arc<DPoPVerifier>,
    token_validator: Arc<dyn AccessTokenValidator>,
    nonce_source: Option<Arc<dyn DPoPServerNonceSource>>,
    require_ath: bool,
    htu_override: Option<HtuOverrideFn>,
}

impl<S: std::fmt::Debug> std::fmt::Debug for OAuthAuthService<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthAuthService")
            .field("inner", &self.inner)
            .field("verifier", &self.verifier)
            .field("require_ath", &self.require_ath)
            .finish()
    }
}

impl<S> OAuthAuthService<S> {
    /// Creates a new `OAuthAuthService` wrapping an inner service with a DPoP verifier and token validator.
    pub fn new(
        inner: S,
        verifier: Arc<DPoPVerifier>,
        token_validator: Arc<dyn AccessTokenValidator>,
    ) -> Self {
        Self {
            inner,
            verifier,
            token_validator,
            nonce_source: None,
            require_ath: true,
            htu_override: None,
        }
    }

    /// Configures an optional [`DPoPServerNonceSource`] to enforce server challenge nonces.
    #[must_use]
    pub fn with_nonce_source(mut self, nonce_source: Arc<dyn DPoPServerNonceSource>) -> Self {
        self.nonce_source = Some(nonce_source);
        self
    }

    /// Configures in-memory server challenge nonces with the specified time-to-live.
    #[must_use]
    pub fn with_server_nonces(mut self, ttl: Duration) -> Self {
        self.nonce_source = Some(Arc::new(InMemoryServerNonceSource::new(ttl)));
        self
    }

    /// Configures whether the access token hash (`ath`) is strictly required in DPoP proofs.
    #[must_use]
    pub fn with_require_ath(mut self, require_ath: bool) -> Self {
        self.require_ath = require_ath;
        self
    }

    /// Overrides how the DPoP target URI (`htu`) is derived from inbound request URIs.
    ///
    /// See [`OAuthAuthLayer::with_htu_override`] for details.
    #[must_use]
    pub fn with_htu_override<F>(mut self, f: F) -> Self
    where
        F: Fn(&http::Uri) -> String + Send + Sync + 'static,
    {
        self.htu_override = Some(Arc::new(f));
        self
    }
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for OAuthAuthService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    ReqBody: Send + 'static,
    ResBody: Default + Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<ReqBody>) -> Self::Future {
        // 1. Extract Authorization: DPoP <access_token>
        let auth_header = match req.headers().get(header::AUTHORIZATION) {
            Some(h) => match h.to_str() {
                Ok(s) => s,
                Err(_) => {
                    return Box::pin(async {
                        Ok(unauthorized_response("invalid_token", None, None))
                    })
                }
            },
            None => {
                return Box::pin(async { Ok(unauthorized_response("missing_token", None, None)) })
            }
        };

        // RFC 7235 § 2.1 / RFC 9449 § 7.1: the auth-scheme token is case-insensitive.
        let access_token = match auth_header.split_once(' ') {
            Some((scheme, cred)) if scheme.eq_ignore_ascii_case("DPoP") => cred.trim(),
            _ => {
                return Box::pin(async { Ok(unauthorized_response("invalid_scheme", None, None)) });
            }
        };

        // 2. Extract DPoP proof header
        let dpop_header = match req
            .headers()
            .get("DPoP")
            .or_else(|| req.headers().get("dpop"))
        {
            Some(h) => match h.to_str() {
                Ok(s) => s,
                Err(_) => {
                    return Box::pin(async {
                        Ok(unauthorized_response("invalid_dpop_proof", None, None))
                    })
                }
            },
            None => {
                let fresh_nonce = self.nonce_source.as_ref().map(|s| s.generate_nonce());
                return Box::pin(async move {
                    Ok(unauthorized_response(
                        "missing_dpop_proof",
                        None,
                        fresh_nonce.as_deref(),
                    ))
                });
            }
        };

        // 3. Compute expected values
        let htm = req.method().as_str();
        let htu = match self.htu_override.as_ref() {
            Some(f) => f(req.uri()),
            None => req.uri().to_string(),
        };
        let ath = if self.require_ath {
            Some(compute_access_token_hash(access_token))
        } else {
            None
        };

        // 4. Verify DPoP proof with anti-replay check
        let verification_result =
            self.verifier
                .verify_proof(dpop_header, htm, &htu, None, ath.as_deref(), None);

        let (claims, jwk) = match verification_result {
            Ok(res) => res,
            Err(DPoPError::ReplayDetected { jti }) => {
                tracing::debug!("DPoP proof replay detected in Tower middleware for jti: {jti}");
                return Box::pin(async move {
                    Ok(unauthorized_response(
                        "invalid_dpop_proof",
                        Some("DPoP proof replay detected"),
                        None,
                    ))
                });
            }
            Err(err) => {
                tracing::debug!("DPoP proof verification failed in Tower middleware: {err}");
                let fresh_nonce = self.nonce_source.as_ref().map(|s| s.generate_nonce());
                return Box::pin(async move {
                    Ok(unauthorized_response(
                        "invalid_dpop_proof",
                        None,
                        fresh_nonce.as_deref(),
                    ))
                });
            }
        };

        // 5. Server Nonce Validation (RFC 9449 § 8)
        if let Some(ref nonce_source) = self.nonce_source {
            let valid_nonce = claims
                .nonce
                .as_deref()
                .map(|n| nonce_source.verify_nonce(n))
                .unwrap_or(false);

            if !valid_nonce {
                let fresh_nonce = nonce_source.generate_nonce();
                return Box::pin(async move {
                    Ok(unauthorized_response(
                        "use_dpop_nonce",
                        Some("Resource server requires fresh DPoP nonce"),
                        Some(&fresh_nonce),
                    ))
                });
            }
        }

        let dpop_thumbprint = jwk.thumbprint();
        let validator = Arc::clone(&self.token_validator);
        let access_token_owned = access_token.to_string();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            // 6. Independently validate access token and its cnf.jkt binding to the DPoP key
            let user = match validator
                .validate_access_token(&access_token_owned, &dpop_thumbprint)
                .await
            {
                Ok(u) => u,
                Err(err) => {
                    tracing::debug!("Access token validation failed in Tower middleware: {err}");
                    return Ok(unauthorized_response("invalid_token", None, None));
                }
            };

            let ext = OAuthSessionExtension::new(user.clone());
            req.extensions_mut().insert(ext);
            req.extensions_mut().insert(user);

            // 7. Forward to inner service
            inner.call(req).await
        })
    }
}

/// Helper generating standard HTTP 401 Unauthorized responses with DPoP WWW-Authenticate and optional DPoP-Nonce header.
fn unauthorized_response<ResBody: Default>(
    error_code: &str,
    description: Option<&str>,
    nonce: Option<&str>,
) -> Response<ResBody> {
    let mut resp = Response::new(ResBody::default());
    *resp.status_mut() = StatusCode::UNAUTHORIZED;

    let auth_header_val = match description {
        Some(desc) => format!("DPoP error=\"{error_code}\", error_description=\"{desc}\""),
        None => format!("DPoP error=\"{error_code}\""),
    };
    if let Ok(val) = HeaderValue::from_str(&auth_header_val) {
        resp.headers_mut().insert(header::WWW_AUTHENTICATE, val);
    }
    if let Some(n) = nonce {
        if let Ok(val) = HeaderValue::from_str(n) {
            if let Ok(hdr) = http::header::HeaderName::from_lowercase(b"dpop-nonce") {
                resp.headers_mut().insert(hdr, val);
            }
        }
    }
    resp
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]
mod tests {
    use super::*;
    use crate::dpop::DPoPKey;
    use crate::integrations::validator::JwtAccessTokenClaims;
    use crate::integrations::AuthenticatedUser;
    use p256::ecdsa::SigningKey;
    use rand::thread_rng;
    use std::convert::Infallible;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tower::service_fn;
    use tower_service::Service;

    #[tokio::test]
    async fn test_tower_jwt_dpop_auth_success() {
        let auth_key = SigningKey::random(&mut thread_rng());
        let auth_verifying_key = *auth_key.verifying_key();

        let client_key = DPoPKey::generate();
        let client_jkt = client_key.jwk_thumbprint();
        let uri = "https://pds.example.com/xrpc/app.bsky.actor.getProfile";

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Mint valid JWT access token bound to client_jkt
        let claims = JwtAccessTokenClaims::new(
            "https://auth.example.com",
            "did:plc:alice123",
            now + 3600,
            &client_jkt,
        )
        .with_audience("https://pds.example.com")
        .with_scope("atproto transition:generic");

        let access_token = claims.sign_jwt(&auth_key, None).unwrap();
        let ath = compute_access_token_hash(&access_token);

        let proof = client_key
            .create_proof("GET", uri, None, Some(&ath))
            .unwrap();

        let verifier = Arc::new(DPoPVerifier::new());
        let token_validator = JwtAccessTokenValidator::new()
            .with_verifying_key(auth_verifying_key)
            .with_expected_issuer("https://auth.example.com")
            .with_expected_audience("https://pds.example.com");

        let layer = OAuthAuthLayer::from_jwt_validator(verifier, token_validator);

        let target_jkt = client_jkt.clone();
        let inner_service = service_fn(move |req: Request<()>| {
            let expected_jkt = target_jkt.clone();
            async move {
                let user = req.extensions().get::<AuthenticatedUser>().cloned();
                assert!(user.is_some());
                let user = user.unwrap();
                assert_eq!(user.did, "did:plc:alice123");
                assert_eq!(user.dpop_thumbprint, expected_jkt);
                assert_eq!(user.scope.as_deref(), Some("atproto transition:generic"));
                Ok::<Response<String>, Infallible>(Response::new("OK".to_string()))
            }
        });

        let mut service = layer.layer(inner_service);

        let req = Request::builder()
            .method("GET")
            .uri(uri)
            .header(header::AUTHORIZATION, format!("DPoP {access_token}"))
            .header("DPoP", proof)
            .body(())
            .unwrap();

        let resp = service.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.body(), "OK");
    }

    #[tokio::test]
    async fn test_tower_rejects_replayed_dpop_proof() {
        let key = DPoPKey::generate();
        let jkt = key.jwk_thumbprint();
        let access_token = "valid_replay_test_token_xyz";
        let ath = compute_access_token_hash(access_token);
        let uri = "https://pds.example.com/xrpc/test";

        let proof = key.create_proof("GET", uri, None, Some(&ath)).unwrap();

        let store = InMemoryTokenValidator::new();
        store.register_token(
            access_token,
            "did:plc:alice123",
            &jkt,
            Some("atproto".to_string()),
            None,
        );

        let verifier = Arc::new(DPoPVerifier::new());
        let layer = OAuthAuthLayer::from_token_store(verifier, store);

        let inner_service = service_fn(|_req: Request<()>| async move {
            Ok::<Response<String>, Infallible>(Response::new("OK".to_string()))
        });

        let mut service = layer.layer(inner_service);

        // First presentation succeeds
        let req1 = Request::builder()
            .method("GET")
            .uri(uri)
            .header(header::AUTHORIZATION, format!("DPoP {access_token}"))
            .header("DPoP", proof.clone())
            .body(())
            .unwrap();

        let resp1 = service.call(req1).await.unwrap();
        assert_eq!(resp1.status(), StatusCode::OK);

        // Second presentation of the exact same proof (replay) fails with 401
        let req2 = Request::builder()
            .method("GET")
            .uri(uri)
            .header(header::AUTHORIZATION, format!("DPoP {access_token}"))
            .header("DPoP", proof)
            .body(())
            .unwrap();

        let resp2 = service.call(req2).await.unwrap();
        assert_eq!(resp2.status(), StatusCode::UNAUTHORIZED);
        let www_auth = resp2
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(www_auth.contains("invalid_dpop_proof"));
        assert!(www_auth.contains("replay detected"));
    }

    #[tokio::test]
    async fn test_tower_server_nonce_challenge_workflow() {
        let key = DPoPKey::generate();
        let jkt = key.jwk_thumbprint();
        let access_token = "valid_nonce_test_token_456";
        let ath = compute_access_token_hash(access_token);
        let uri = "https://pds.example.com/xrpc/test";

        let store = InMemoryTokenValidator::new();
        store.register_token(
            access_token,
            "did:plc:alice123",
            &jkt,
            Some("atproto".to_string()),
            None,
        );

        let verifier = Arc::new(DPoPVerifier::new());
        let layer = OAuthAuthLayer::from_token_store(verifier, store)
            .with_server_nonces(Duration::from_secs(60));

        let inner_service = service_fn(|_req: Request<()>| async move {
            Ok::<Response<String>, Infallible>(Response::new("OK".to_string()))
        });

        let mut service = layer.layer(inner_service);

        // 1. Initial request without server nonce receives 401 with DPoP-Nonce
        let proof_no_nonce = key.create_proof("GET", uri, None, Some(&ath)).unwrap();
        let req1 = Request::builder()
            .method("GET")
            .uri(uri)
            .header(header::AUTHORIZATION, format!("DPoP {access_token}"))
            .header("DPoP", proof_no_nonce)
            .body(())
            .unwrap();

        let resp1 = service.call(req1).await.unwrap();
        assert_eq!(resp1.status(), StatusCode::UNAUTHORIZED);
        let issued_nonce = resp1
            .headers()
            .get("dpop-nonce")
            .expect("Must return DPoP-Nonce header")
            .to_str()
            .unwrap()
            .to_string();

        // 2. Client retries with the issued challenge nonce
        let proof_with_nonce = key
            .create_proof("GET", uri, Some(&issued_nonce), Some(&ath))
            .unwrap();
        let req2 = Request::builder()
            .method("GET")
            .uri(uri)
            .header(header::AUTHORIZATION, format!("DPoP {access_token}"))
            .header("DPoP", proof_with_nonce)
            .body(())
            .unwrap();

        let resp2 = service.call(req2).await.unwrap();
        assert_eq!(resp2.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_tower_rejects_invented_token_credentials() {
        let auth_key = SigningKey::random(&mut thread_rng());
        let auth_verifying_key = *auth_key.verifying_key();

        // Attacker creates a fresh DPoP key and invents a token string
        let attacker_key = DPoPKey::generate();
        let invented_token = "fabricated_random_access_token_12345";
        let ath = compute_access_token_hash(invented_token);
        let uri = "https://pds.example.com/xrpc/app.bsky.actor.getProfile";

        // DPoP proof signed with attacker's key hashing the invented token
        let proof = attacker_key
            .create_proof("GET", uri, None, Some(&ath))
            .unwrap();

        let verifier = Arc::new(DPoPVerifier::new());
        let token_validator = JwtAccessTokenValidator::new().with_verifying_key(auth_verifying_key);
        let layer = OAuthAuthLayer::from_jwt_validator(verifier, token_validator);

        let inner_service = service_fn(|_req: Request<()>| async move {
            Ok::<Response<String>, Infallible>(Response::new("SHOULD_NOT_REACH".to_string()))
        });

        let mut service = layer.layer(inner_service);

        let req = Request::builder()
            .method("GET")
            .uri(uri)
            .header(header::AUTHORIZATION, format!("DPoP {invented_token}"))
            .header("DPoP", proof)
            .body(())
            .unwrap();

        let resp = service.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let www_auth = resp
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(www_auth.contains("invalid_token"));
    }

    #[tokio::test]
    async fn test_tower_rejects_stolen_token_with_attacker_dpop_proof_cnf_mismatch() {
        let auth_key = SigningKey::random(&mut thread_rng());
        let auth_verifying_key = *auth_key.verifying_key();

        let alice_key = DPoPKey::generate();
        let alice_jkt = alice_key.jwk_thumbprint();

        let attacker_key = DPoPKey::generate();
        let uri = "https://pds.example.com/xrpc/app.bsky.actor.getProfile";

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Legitimate token issued to Alice
        let claims = JwtAccessTokenClaims::new(
            "https://auth.example.com",
            "did:plc:alice123",
            now + 3600,
            &alice_jkt,
        )
        .with_audience("https://pds.example.com");

        let alice_token = claims.sign_jwt(&auth_key, None).unwrap();
        let ath = compute_access_token_hash(&alice_token);

        // Attacker presents Alice's token, but signs DPoP proof with Attacker's key
        let attacker_proof = attacker_key
            .create_proof("GET", uri, None, Some(&ath))
            .unwrap();

        let verifier = Arc::new(DPoPVerifier::new());
        let token_validator = JwtAccessTokenValidator::new()
            .with_verifying_key(auth_verifying_key)
            .with_expected_audience("https://pds.example.com");
        let layer = OAuthAuthLayer::from_jwt_validator(verifier, token_validator);

        let inner_service = service_fn(|_req: Request<()>| async move {
            Ok::<Response<String>, Infallible>(Response::new("SHOULD_NOT_REACH".to_string()))
        });

        let mut service = layer.layer(inner_service);

        let req = Request::builder()
            .method("GET")
            .uri(uri)
            .header(header::AUTHORIZATION, format!("DPoP {alice_token}"))
            .header("DPoP", attacker_proof)
            .body(())
            .unwrap();

        let resp = service.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let www_auth = resp
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .expect("401 must carry WWW-Authenticate header")
            .to_str()
            .unwrap();
        assert!(
            www_auth.contains("invalid_token"),
            "expected cnf.jkt binding rejection (invalid_token), got: {www_auth}"
        );
    }

    #[tokio::test]
    async fn test_tower_stolen_token_positive_control_with_own_proof() {
        // Positive control: the identical token authenticates when presented with
        // Alice's own DPoP key's proof, proving the previous rejection came from the
        // cnf.jkt binding check rather than an unrelated validation failure.
        let auth_key = SigningKey::random(&mut thread_rng());
        let alice_key = DPoPKey::generate();
        let alice_jkt = alice_key.jwk_thumbprint();

        let claims = {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            JwtAccessTokenClaims::new(
                "https://auth.example.com",
                "did:plc:alice123",
                now + 3600,
                &alice_jkt,
            )
            .with_audience("https://pds.example.com")
        };
        let alice_token = claims.sign_jwt(&auth_key, None).unwrap();
        let ath = compute_access_token_hash(&alice_token);

        let uri = "https://pds.example.com/xrpc/app.bsky.actor.getProfile";
        let alice_proof = alice_key
            .create_proof("GET", uri, None, Some(&ath))
            .unwrap();

        let verifier = Arc::new(DPoPVerifier::new());
        let token_validator = JwtAccessTokenValidator::new()
            .with_verifying_key(*auth_key.verifying_key())
            .with_expected_audience("https://pds.example.com");
        let layer = OAuthAuthLayer::from_jwt_validator(verifier, token_validator);

        let inner_service = service_fn(|req: Request<()>| async move {
            let user = req.extensions().get::<AuthenticatedUser>().cloned();
            assert!(user.is_some(), "positive control must authenticate");
            Ok::<Response<String>, Infallible>(Response::new("OK".to_string()))
        });

        let mut service = layer.layer(inner_service);

        let req = Request::builder()
            .method("GET")
            .uri(uri)
            .header(header::AUTHORIZATION, format!("DPoP {alice_token}"))
            .header("DPoP", alice_proof)
            .body(())
            .unwrap();

        let resp = service.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_tower_in_memory_token_store_lifecycle() {
        let key = DPoPKey::generate();
        let jkt = key.jwk_thumbprint();
        let access_token = "registered_opaque_token_987";
        let ath = compute_access_token_hash(access_token);
        let uri = "https://pds.example.com/xrpc/test";

        let proof = key.create_proof("GET", uri, None, Some(&ath)).unwrap();

        let store = InMemoryTokenValidator::new();
        store.register_token(
            access_token,
            "did:plc:bob456",
            &jkt,
            Some("atproto".to_string()),
            None,
        );

        let verifier = Arc::new(DPoPVerifier::new());
        let layer = OAuthAuthLayer::from_token_store(verifier, store);

        let inner_service = service_fn(move |req: Request<()>| async move {
            let user = req
                .extensions()
                .get::<AuthenticatedUser>()
                .cloned()
                .unwrap();
            assert_eq!(user.did, "did:plc:bob456");
            Ok::<Response<String>, Infallible>(Response::new("OK".to_string()))
        });

        let mut service = layer.layer(inner_service);

        let req = Request::builder()
            .method("GET")
            .uri(uri)
            .header(header::AUTHORIZATION, format!("DPoP {access_token}"))
            .header("DPoP", proof)
            .body(())
            .unwrap();

        let resp = service.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_tower_missing_dpop_proof_returns_401() {
        let verifier = Arc::new(DPoPVerifier::new());
        let validator = InMemoryTokenValidator::new();
        let layer = OAuthAuthLayer::from_token_store(verifier, validator);

        let inner_service = service_fn(|_req: Request<()>| async move {
            Ok::<Response<String>, Infallible>(Response::new("OK".to_string()))
        });

        let mut service = layer.layer(inner_service);

        let req = Request::builder()
            .method("GET")
            .uri("https://pds.example.com/xrpc/app.bsky.feed.getTimeline")
            .header(header::AUTHORIZATION, "DPoP token_without_proof")
            .body(())
            .unwrap();

        let resp = service.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(resp.headers().contains_key(header::WWW_AUTHENTICATE));
    }

    #[tokio::test]
    async fn test_tower_htu_override_for_proxied_origin_form_requests() {
        let key = DPoPKey::generate();
        let jkt = key.jwk_thumbprint();
        let access_token = "proxied_request_token_abc";
        let ath = compute_access_token_hash(access_token);

        // Client signs the externally visible absolute URL...
        let public_uri = "https://pds.example.com/xrpc/test";

        let proof = key
            .create_proof("GET", public_uri, None, Some(&ath))
            .unwrap();

        let store = InMemoryTokenValidator::new();
        store.register_token(
            access_token,
            "did:plc:proxy",
            &jkt,
            Some("atproto".to_string()),
            None,
        );

        let verifier = Arc::new(DPoPVerifier::new());
        let layer = OAuthAuthLayer::from_token_store(verifier, store).with_htu_override(|uri| {
            // ...while the proxy delivers origin-form targets to the service.
            let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
            format!("https://pds.example.com{path_and_query}")
        });

        let inner_service = service_fn(|_req: Request<()>| async move {
            Ok::<Response<String>, Infallible>(Response::new("OK".to_string()))
        });

        let mut service = layer.layer(inner_service);

        let req = Request::builder()
            .method("GET")
            .uri("/xrpc/test")
            .header(header::AUTHORIZATION, format!("DPoP {access_token}"))
            .header("DPoP", proof)
            .body(())
            .unwrap();

        let resp = service.call(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "origin-form request must authenticate using the overridden absolute htu"
        );
    }
}
