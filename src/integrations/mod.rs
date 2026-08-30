//! Framework integrations and middleware for Axum, Actix-web, and Tower.
//!
//! Provides idiomatic extractors, authentication middleware, and response helpers
//! for handling AT Protocol OAuth authorization callbacks and DPoP-authenticated requests.
//!
//! ## Modules
//!
//! - [`axum`]: Axum 0.7 extractors ([`OAuthCallbackQuery`], [`AuthenticatedUser`]), middleware layers, and redirect generators.
//! - [`actix`]: Actix-web `FromRequest` extractors and HTTP response generators.
//! - [`tower`]: Tower [`tower::OAuthAuthLayer`] and [`tower::OAuthAuthService`] for DPoP authentication.

use serde::{Deserialize, Serialize};

use crate::client::CallbackParams;
use crate::error::IntegrationError;
use crate::session::OAuthSession;

#[cfg(feature = "axum")]
pub mod axum;

#[cfg(feature = "actix")]
pub mod actix;

#[cfg(feature = "tower")]
pub mod tower;

pub mod validator;

pub use validator::{
    AccessTokenValidator, CnfClaim, InMemoryTokenValidator, JwtAccessTokenClaims,
    JwtAccessTokenValidator, RegisteredToken,
};

/// Parsed query parameters received at the OAuth redirect URI callback endpoint.
///
/// Handles both successful authorizations (providing `code` and `state`) and error
/// responses returned by the authorization server (e.g. `error=access_denied`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuthCallbackQuery {
    /// The authorization code issued by the authorization server.
    pub code: Option<String>,
    /// The state parameter originally passed to the authorization endpoint.
    pub state: Option<String>,
    /// The authorization server issuer identifier (RFC 9207 `iss` parameter).
    pub iss: Option<String>,
    /// Error code if the user or authorization server rejected the request.
    pub error: Option<String>,
    /// Human-readable description of the error.
    pub error_description: Option<String>,
}

impl OAuthCallbackQuery {
    /// Creates a new successful `OAuthCallbackQuery` with `code` and `state`.
    #[must_use]
    pub fn new(code: impl Into<String>, state: impl Into<String>) -> Self {
        Self {
            code: Some(code.into()),
            state: Some(state.into()),
            iss: None,
            error: None,
            error_description: None,
        }
    }

    /// Creates an error `OAuthCallbackQuery`.
    #[must_use]
    pub fn new_error(error: impl Into<String>, description: Option<String>) -> Self {
        Self {
            code: None,
            state: None,
            iss: None,
            error: Some(error.into()),
            error_description: description,
        }
    }

    /// Sets the optional authorization server issuer.
    #[must_use]
    pub fn with_iss(mut self, iss: impl Into<String>) -> Self {
        self.iss = Some(iss.into());
        self
    }

    /// Validates this callback query and converts it into [`CallbackParams`].
    ///
    /// # Errors
    ///
    /// - Returns [`IntegrationError::OAuthError`] if the server returned an error.
    /// - Returns [`IntegrationError::MissingCode`] if `code` is absent.
    /// - Returns [`IntegrationError::MissingState`] if `state` is absent.
    pub fn to_callback_params(&self) -> Result<CallbackParams, IntegrationError> {
        if let Some(err) = &self.error {
            return Err(IntegrationError::OAuthError {
                error: err.clone(),
                description: self.error_description.clone().unwrap_or_default(),
            });
        }

        let code = self
            .code
            .as_ref()
            .ok_or(IntegrationError::MissingCode)?
            .clone();

        let state = self
            .state
            .as_ref()
            .ok_or(IntegrationError::MissingState)?
            .clone();

        let mut params = CallbackParams::new(code, state);
        if let Some(iss) = &self.iss {
            params = params.with_iss(iss.clone());
        }
        Ok(params)
    }
}

use zeroize::{Zeroize, ZeroizeOnDrop};

/// An authenticated user extracted from an inbound DPoP-authenticated HTTP request.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticatedUser {
    /// The subject Decentralized Identifier (`did:plc:...` or `did:web:...`).
    pub did: String,
    /// The DPoP-bound access token string (skipped during serialization to prevent leakage).
    #[serde(skip_serializing, default)]
    pub access_token: String,
    /// RFC 7638 JWK thumbprint (`jkt`) of the bound public key.
    pub dpop_thumbprint: String,
    /// Granted OAuth scopes, if known.
    pub scope: Option<String>,
}

impl std::fmt::Debug for AuthenticatedUser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthenticatedUser")
            .field("did", &self.did)
            .field("access_token", &"[REDACTED]")
            .field("dpop_thumbprint", &self.dpop_thumbprint)
            .field("scope", &self.scope)
            .finish()
    }
}

impl Zeroize for AuthenticatedUser {
    fn zeroize(&mut self) {
        self.access_token.zeroize();
    }
}

impl Drop for AuthenticatedUser {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for AuthenticatedUser {}

impl AuthenticatedUser {
    /// Creates a new `AuthenticatedUser`.
    #[must_use]
    pub fn new(
        did: impl Into<String>,
        access_token: impl Into<String>,
        dpop_thumbprint: impl Into<String>,
    ) -> Self {
        Self {
            did: did.into(),
            access_token: access_token.into(),
            dpop_thumbprint: dpop_thumbprint.into(),
            scope: None,
        }
    }

    /// Sets the optional granted scopes.
    #[must_use]
    pub fn with_scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = Some(scope.into());
        self
    }

    /// Returns the subject DID.
    #[must_use]
    pub fn did(&self) -> &str {
        &self.did
    }

    /// Returns the access token.
    #[must_use]
    pub fn access_token(&self) -> &str {
        &self.access_token
    }

    /// Returns the DPoP key thumbprint.
    #[must_use]
    pub fn dpop_thumbprint(&self) -> &str {
        &self.dpop_thumbprint
    }

    /// Returns the scope string, if present.
    #[must_use]
    pub fn scope(&self) -> Option<&str> {
        self.scope.as_deref()
    }
}

/// Request extension payload storing authentication and session context.
#[derive(Debug, Clone)]
pub struct OAuthSessionExtension {
    /// Authenticated user credentials and DID.
    pub user: AuthenticatedUser,
    /// Full authenticated session, if available.
    pub session: Option<OAuthSession>,
}

impl OAuthSessionExtension {
    /// Creates a new session extension from an [`AuthenticatedUser`].
    #[must_use]
    pub fn new(user: AuthenticatedUser) -> Self {
        Self {
            user,
            session: None,
        }
    }

    /// Creates a new session extension with a full [`OAuthSession`].
    #[must_use]
    pub fn from_session(session: OAuthSession) -> Self {
        let user = AuthenticatedUser {
            did: session.sub.clone(),
            access_token: session.access_token.clone(),
            dpop_thumbprint: session.dpop_key.jwk_thumbprint(),
            scope: session.scope.clone(),
        };
        Self {
            user,
            session: Some(session),
        }
    }
}
