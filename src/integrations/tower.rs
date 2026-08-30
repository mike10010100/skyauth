//! Tower middleware layer and service for DPoP-bound OAuth request authentication.
//!
//! Provides:
//! - [`OAuthAuthLayer`]: Tower [`tower_layer::Layer`] applying DPoP and token authentication to any compatible service.
//! - [`OAuthAuthService`]: Tower [`tower_service::Service`] extracting, validating, and injecting authenticated sessions.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use http::{header, HeaderValue, Request, Response, StatusCode};
use tower_layer::Layer;
use tower_service::Service;

use super::validator::{AccessTokenValidator, InMemoryTokenValidator, JwtAccessTokenValidator};
use super::OAuthSessionExtension;
use crate::dpop::{compute_access_token_hash, DPoPVerifier};

/// Tower layer that enforces AT Protocol DPoP OAuth authentication on inbound HTTP requests.
///
/// Inspects the `Authorization: DPoP <access_token>` and `DPoP: <proof_jwt>` headers,
/// verifies the cryptographic DPoP proof against the HTTP method and URI, validates
/// the access token and its `cnf.jkt` binding via the configured [`AccessTokenValidator`],
/// and attaches [`OAuthSessionExtension`] and [`AuthenticatedUser`] to request extensions.
#[derive(Clone)]
pub struct OAuthAuthLayer {
    verifier: Arc<DPoPVerifier>,
    token_validator: Arc<dyn AccessTokenValidator>,
    require_ath: bool,
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
            require_ath: true,
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

    /// Configures whether the access token hash (`ath`) claim is strictly required in DPoP proofs.
    #[must_use]
    pub fn with_require_ath(mut self, require_ath: bool) -> Self {
        self.require_ath = require_ath;
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
            require_ath: self.require_ath,
        }
    }
}

/// Tower service that validates DPoP authentication headers and access tokens on inbound requests.
#[derive(Clone)]
pub struct OAuthAuthService<S> {
    inner: S,
    verifier: Arc<DPoPVerifier>,
    token_validator: Arc<dyn AccessTokenValidator>,
    require_ath: bool,
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
            require_ath: true,
        }
    }

    /// Configures whether the access token hash (`ath`) is strictly required in DPoP proofs.
    #[must_use]
    pub fn with_require_ath(mut self, require_ath: bool) -> Self {
        self.require_ath = require_ath;
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
                Err(_) => return Box::pin(async { Ok(unauthorized_response("invalid_token")) }),
            },
            None => return Box::pin(async { Ok(unauthorized_response("missing_token")) }),
        };

        let access_token = if let Some(token) = auth_header.strip_prefix("DPoP ") {
            token.trim()
        } else if let Some(token) = auth_header.strip_prefix("dpop ") {
            token.trim()
        } else {
            return Box::pin(async { Ok(unauthorized_response("invalid_scheme")) });
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
                    return Box::pin(async { Ok(unauthorized_response("invalid_dpop_proof")) })
                }
            },
            None => return Box::pin(async { Ok(unauthorized_response("missing_dpop_proof")) }),
        };

        // 3. Compute expected values
        let htm = req.method().as_str();
        let htu = req.uri().to_string();
        let ath = if self.require_ath {
            Some(compute_access_token_hash(access_token))
        } else {
            None
        };

        // 4. Verify DPoP proof
        let (_claims, jwk) =
            match self
                .verifier
                .verify_proof(dpop_header, htm, &htu, None, ath.as_deref(), None)
            {
                Ok(res) => res,
                Err(err) => {
                    tracing::debug!("DPoP proof verification failed in Tower middleware: {err}");
                    return Box::pin(async { Ok(unauthorized_response("invalid_dpop_proof")) });
                }
            };

        let dpop_thumbprint = jwk.thumbprint();
        let validator = Arc::clone(&self.token_validator);
        let access_token_owned = access_token.to_string();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            // 5. Independently validate access token and its cnf.jkt binding to the DPoP key
            let user = match validator
                .validate_access_token(&access_token_owned, &dpop_thumbprint)
                .await
            {
                Ok(u) => u,
                Err(err) => {
                    tracing::debug!("Access token validation failed in Tower middleware: {err}");
                    return Ok(unauthorized_response("invalid_token"));
                }
            };

            let ext = OAuthSessionExtension::new(user.clone());
            req.extensions_mut().insert(ext);
            req.extensions_mut().insert(user);

            // 6. Forward to inner service
            inner.call(req).await
        })
    }
}

/// Helper generating standard HTTP 401 Unauthorized responses with DPoP WWW-Authenticate header.
fn unauthorized_response<ResBody: Default>(error_code: &str) -> Response<ResBody> {
    let mut resp = Response::new(ResBody::default());
    *resp.status_mut() = StatusCode::UNAUTHORIZED;
    let auth_header_val = format!("DPoP error=\"{error_code}\"");
    if let Ok(val) = HeaderValue::from_str(&auth_header_val) {
        resp.headers_mut().insert(header::WWW_AUTHENTICATE, val);
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
}
