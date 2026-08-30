//! Tower authentication for DPoP-bound access tokens.

use std::collections::BTreeSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

use http::{header, HeaderValue, Method, Request, Response, StatusCode, Uri};
use tower_layer::Layer;
use tower_service::Service;
use url::Url;

use super::{AuthenticatedUser, OAuthSessionExtension};
use crate::crypto::constant_time_eq;
use crate::dpop::{compute_access_token_hash, DPoPVerifier};
use crate::error::IntegrationError;
use crate::policy::{dpop_authorization_accepts, scope_policy_accepts};

mod state;
mod token;

pub use state::{
    DPoPNonceDecision, DPoPNonceStore, DPoPReplayStore, InMemoryDPoPNonceStore,
    InMemoryDPoPReplayStore,
};
pub use token::{
    AccessTokenValidator, JwtAccessTokenValidator, JwtTrustedIssuer, ValidatedAccessToken,
};

/// Determines how a protected route uses DPoP nonces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoncePolicy {
    /// The route does not require a server nonce.
    Disabled,
    /// The first accepted request receives the nonce required by later requests.
    Bootstrap,
    /// The first request receives a nonce challenge before it can proceed.
    Required,
}

/// Scope and nonce requirements for one method and path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteAuthorization {
    method: Method,
    path: String,
    scopes: BTreeSet<String>,
    nonce_policy: NoncePolicy,
}

impl RouteAuthorization {
    /// Creates an exact method-and-path authorization rule.
    #[must_use]
    pub fn new(
        method: Method,
        path: impl Into<String>,
        scopes: impl IntoIterator<Item = String>,
        nonce_policy: NoncePolicy,
    ) -> Self {
        Self {
            method,
            path: path.into(),
            scopes: scopes.into_iter().collect(),
            nonce_policy,
        }
    }
}

/// Route authorization policy evaluated after token and proof validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteScopePolicy {
    default_scopes: BTreeSet<String>,
    default_nonce_policy: NoncePolicy,
    routes: Vec<RouteAuthorization>,
}

impl RouteScopePolicy {
    /// Creates a policy for routes without an exact override.
    #[must_use]
    pub fn new(
        default_scopes: impl IntoIterator<Item = String>,
        default_nonce_policy: NoncePolicy,
    ) -> Self {
        Self {
            default_scopes: default_scopes.into_iter().collect(),
            default_nonce_policy,
            routes: Vec::new(),
        }
    }

    /// Adds an exact route override.
    #[must_use]
    pub fn with_route(mut self, route: RouteAuthorization) -> Self {
        self.routes.push(route);
        self
    }

    fn requirements(&self, method: &Method, path: &str) -> (&BTreeSet<String>, NoncePolicy) {
        self.routes
            .iter()
            .find(|route| route.method == *method && route.path == path)
            .map_or((&self.default_scopes, self.default_nonce_policy), |route| {
                (&route.scopes, route.nonce_policy)
            })
    }
}

/// Accepted token issuers, audiences, and route requirements.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationPolicy {
    issuers: BTreeSet<String>,
    audiences: BTreeSet<String>,
    routes: RouteScopePolicy,
}

impl AuthorizationPolicy {
    /// Creates an authorization policy.
    ///
    /// # Errors
    ///
    /// Returns [`IntegrationError`] when an issuer or audience set is empty.
    pub fn new(
        issuers: impl IntoIterator<Item = String>,
        audiences: impl IntoIterator<Item = String>,
        routes: RouteScopePolicy,
    ) -> Result<Self, IntegrationError> {
        let issuers = issuers.into_iter().collect::<BTreeSet<_>>();
        let audiences = audiences.into_iter().collect::<BTreeSet<_>>();
        if issuers.is_empty() || audiences.is_empty() {
            return Err(IntegrationError::AuthFailed(
                "authorization policy requires issuer and audience".to_string(),
            ));
        }
        Ok(Self {
            issuers,
            audiences,
            routes,
        })
    }

    fn accepts_token(&self, token: &ValidatedAccessToken) -> bool {
        self.issuers.contains(token.issuer())
            && !self.audiences.is_disjoint(token.audiences())
            && token.scopes().contains("atproto")
    }
}

/// Trusted reconstruction rule for the externally visible request URL.
#[derive(Debug, Clone)]
pub enum ExternalUrlPolicy {
    /// Reconstruct every request below a fixed HTTPS origin.
    FixedOrigin(Url),
    /// Require an absolute-form request target supplied by a trusted server adapter.
    AbsoluteForm,
}

impl ExternalUrlPolicy {
    /// Creates a fixed-origin policy.
    ///
    /// # Errors
    ///
    /// Returns [`IntegrationError`] unless the value is a canonical HTTPS origin.
    pub fn fixed_origin(origin: &str) -> Result<Self, IntegrationError> {
        let parsed = Url::parse(origin)
            .map_err(|_| IntegrationError::AuthFailed("invalid external origin".to_string()))?;
        if parsed.scheme() != "https"
            || parsed.username() != ""
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || (parsed.path() != "/" && !parsed.path().is_empty())
        {
            return Err(IntegrationError::AuthFailed(
                "external origin must be a canonical HTTPS origin".to_string(),
            ));
        }
        Ok(Self::FixedOrigin(parsed))
    }

    fn request_url(&self, uri: &Uri) -> Result<String, IntegrationError> {
        match self {
            Self::FixedOrigin(origin) => {
                let mut resolved = origin.clone();
                resolved.set_path(uri.path());
                resolved.set_query(uri.query());
                Ok(resolved.to_string())
            }
            Self::AbsoluteForm => {
                if uri.scheme().is_none() || uri.authority().is_none() {
                    return Err(IntegrationError::AuthFailed(
                        "absolute request target required".to_string(),
                    ));
                }
                Ok(uri.to_string())
            }
        }
    }
}

/// Tower layer for validated DPoP authentication.
#[derive(Debug, Clone)]
pub struct OAuthAuthLayer {
    verifier: Arc<DPoPVerifier>,
    token_validator: Arc<dyn AccessTokenValidator>,
    replay_store: Arc<dyn DPoPReplayStore>,
    nonce_store: Arc<dyn DPoPNonceStore>,
    external_url: ExternalUrlPolicy,
    authorization: AuthorizationPolicy,
}

impl OAuthAuthLayer {
    /// Creates a layer with all authentication trust boundaries supplied explicitly.
    #[must_use]
    pub fn new(
        verifier: Arc<DPoPVerifier>,
        token_validator: Arc<dyn AccessTokenValidator>,
        replay_store: Arc<dyn DPoPReplayStore>,
        nonce_store: Arc<dyn DPoPNonceStore>,
        external_url: ExternalUrlPolicy,
        authorization: AuthorizationPolicy,
    ) -> Self {
        Self {
            verifier,
            token_validator,
            replay_store,
            nonce_store,
            external_url,
            authorization,
        }
    }
}

impl<S> Layer<S> for OAuthAuthLayer {
    type Service = OAuthAuthService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        OAuthAuthService {
            inner,
            verifier: Arc::clone(&self.verifier),
            token_validator: Arc::clone(&self.token_validator),
            replay_store: Arc::clone(&self.replay_store),
            nonce_store: Arc::clone(&self.nonce_store),
            external_url: self.external_url.clone(),
            authorization: self.authorization.clone(),
        }
    }
}

/// Tower service produced by [`OAuthAuthLayer`].
#[derive(Debug, Clone)]
pub struct OAuthAuthService<S> {
    inner: S,
    verifier: Arc<DPoPVerifier>,
    token_validator: Arc<dyn AccessTokenValidator>,
    replay_store: Arc<dyn DPoPReplayStore>,
    nonce_store: Arc<dyn DPoPNonceStore>,
    external_url: ExternalUrlPolicy,
    authorization: AuthorizationPolicy,
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
        let access_token =
            match unique_header(req.headers(), header::AUTHORIZATION, "missing_token")
                .and_then(parse_dpop_authorization)
            {
                Ok(value) => value,
                Err(code) => return Box::pin(async move { Ok(auth_response(code, None)) }),
            };
        let proof = match unique_header(
            req.headers(),
            http::HeaderName::from_static("dpop"),
            "invalid_dpop_proof",
        ) {
            Ok(value) => value,
            Err(code) => return Box::pin(async move { Ok(auth_response(code, None)) }),
        };
        let request_url = match self.external_url.request_url(req.uri()) {
            Ok(value) => value,
            Err(_) => {
                return Box::pin(async { Ok(auth_response("invalid_dpop_proof", None)) });
            }
        };
        let method = req.method().clone();
        let path = req.uri().path().to_string();
        let verifier = Arc::clone(&self.verifier);
        let token_validator = Arc::clone(&self.token_validator);
        let replay_store = Arc::clone(&self.replay_store);
        let nonce_store = Arc::clone(&self.nonce_store);
        let authorization = self.authorization.clone();
        let replacement = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, replacement);

        Box::pin(async move {
            let now = SystemTime::now();
            let token = match token_validator.validate(&access_token, now) {
                Ok(value) => value,
                Err(_) => return Ok(auth_response("invalid_token", None)),
            };
            if !authorization.accepts_token(&token) {
                return Ok(auth_response("invalid_token", None));
            }

            let ath = compute_access_token_hash(&access_token);
            let (claims, proof_jwk) = match verifier.verify_proof(
                &proof,
                method.as_str(),
                &request_url,
                None,
                Some(&ath),
                Some(now),
            ) {
                Ok(value) => value,
                Err(_) => return Ok(auth_response("invalid_dpop_proof", None)),
            };
            let thumbprint = proof_jwk.thumbprint();
            let binding_equal = constant_time_eq(
                thumbprint.as_bytes(),
                token.confirmation_thumbprint().as_bytes(),
            );
            if !dpop_authorization_accepts(true, true, binding_equal) {
                return Ok(auth_response("invalid_token", None));
            }

            let (required_scopes, nonce_policy) = authorization.routes.requirements(&method, &path);
            if !scope_policy_accepts(
                token.scopes().contains("atproto"),
                required_scopes.is_subset(token.scopes()),
            ) {
                return Ok(forbidden_response());
            }
            let now_secs = match now.duration_since(UNIX_EPOCH) {
                Ok(value) => value.as_secs(),
                Err(_) => return Ok(auth_response("invalid_dpop_proof", None)),
            };
            if replay_store
                .insert_once(
                    token.issuer(),
                    token.token_identifier(),
                    &thumbprint,
                    &claims.jti,
                    now_secs,
                    now_secs.saturating_add(verifier.replay_ttl().as_secs()),
                )
                .is_err()
            {
                return Ok(auth_response("invalid_dpop_proof", None));
            }

            let next_nonce = match nonce_policy {
                NoncePolicy::Disabled => None,
                NoncePolicy::Bootstrap | NoncePolicy::Required => {
                    match nonce_store.evaluate_and_rotate(
                        token.issuer(),
                        token.token_identifier(),
                        &thumbprint,
                        claims.nonce.as_deref(),
                        nonce_policy == NoncePolicy::Required,
                        now_secs,
                    ) {
                        Ok(DPoPNonceDecision::Accepted(nonce)) => Some(nonce),
                        Ok(DPoPNonceDecision::Challenge(nonce)) => {
                            return Ok(auth_response("use_dpop_nonce", Some(&nonce)));
                        }
                        Err(_) => return Ok(auth_response("invalid_dpop_proof", None)),
                    }
                }
            };

            let user = AuthenticatedUser {
                did: token.subject().to_string(),
                dpop_thumbprint: thumbprint,
                scope: Some(token.scopes().iter().cloned().collect::<Vec<_>>().join(" ")),
            };
            req.extensions_mut()
                .insert(OAuthSessionExtension::new(user.clone()));
            req.extensions_mut().insert(user);
            let mut response = inner.call(req).await?;
            if let Some(nonce) = next_nonce {
                if let Ok(value) = HeaderValue::from_str(&nonce) {
                    response
                        .headers_mut()
                        .insert(http::HeaderName::from_static("dpop-nonce"), value);
                }
            }
            Ok(response)
        })
    }
}

fn unique_header(
    headers: &http::HeaderMap,
    name: http::HeaderName,
    missing_error: &'static str,
) -> Result<String, &'static str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next().ok_or(missing_error)?;
    if values.next().is_some() {
        return Err("invalid_request");
    }
    value
        .to_str()
        .map(str::to_string)
        .map_err(|_| "invalid_request")
}

fn parse_dpop_authorization(value: String) -> Result<String, &'static str> {
    let mut parts = value.split_ascii_whitespace();
    let scheme = parts.next().ok_or("invalid_scheme")?;
    let token = parts.next().ok_or("invalid_scheme")?;
    if !scheme.eq_ignore_ascii_case("DPoP") || parts.next().is_some() || token.is_empty() {
        return Err("invalid_scheme");
    }
    Ok(token.to_string())
}

fn auth_response<ResBody: Default>(error_code: &str, nonce: Option<&str>) -> Response<ResBody> {
    let mut response = Response::new(ResBody::default());
    *response.status_mut() = StatusCode::UNAUTHORIZED;
    let challenge = format!("DPoP error=\"{error_code}\"");
    if let Ok(value) = HeaderValue::from_str(&challenge) {
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, value);
    }
    if let Some(nonce) = nonce {
        if let Ok(value) = HeaderValue::from_str(nonce) {
            response
                .headers_mut()
                .insert(http::HeaderName::from_static("dpop-nonce"), value);
        }
    }
    response
}

fn forbidden_response<ResBody: Default>() -> Response<ResBody> {
    let mut response = Response::new(ResBody::default());
    *response.status_mut() = StatusCode::FORBIDDEN;
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("DPoP error=\"insufficient_scope\""),
    );
    response
}
