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
#[cfg(any(feature = "actix", feature = "axum"))]
use crate::client::OAuthClientMetadata;
use crate::error::{sanitize_oauth_error_code, IntegrationError};
use crate::session::OAuthSession;

#[cfg(any(feature = "actix", feature = "axum"))]
fn client_metadata_payload(metadata: &OAuthClientMetadata) -> serde_json::Value {
    let mut grant_types = vec!["authorization_code"];
    if metadata.refresh_tokens() {
        grant_types.push("refresh_token");
    }
    serde_json::json!({
        "client_id": metadata.client_id(),
        "client_name": metadata.client_name(),
        "client_uri": metadata.client_id(),
        "application_type": metadata.application_type().as_str(),
        "redirect_uris": [metadata.redirect_uri()],
        "grant_types": grant_types,
        "response_types": ["code"],
        "scope": metadata.scope(),
        "token_endpoint_auth_method": "none",
        "dpop_bound_access_tokens": true
    })
}

#[cfg(feature = "axum")]
pub mod axum;

#[cfg(feature = "actix")]
pub mod actix;

#[cfg(feature = "tower")]
pub mod tower;

/// Parsed query parameters received at the OAuth redirect URI callback endpoint.
///
/// Handles both successful authorizations (providing `code` and `state`) and error
/// responses returned by the authorization server (e.g. `error=access_denied`).
#[derive(Clone, PartialEq, Eq, Deserialize)]
pub struct OAuthCallbackQuery {
    /// The authorization code issued by the authorization server.
    code: Option<String>,
    /// The state parameter originally passed to the authorization endpoint.
    state: Option<String>,
    /// The authorization server issuer identifier (RFC 9207 `iss` parameter).
    iss: Option<String>,
    /// Error code if the user or authorization server rejected the request.
    error: Option<String>,
    /// Human-readable description of the error.
    error_description: Option<String>,
}

impl std::fmt::Debug for OAuthCallbackQuery {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OAuthCallbackQuery")
            .field("code", &self.code.as_ref().map(|_| "[REDACTED]"))
            .field("state", &self.state.as_ref().map(|_| "[REDACTED]"))
            .field("iss", &self.iss)
            .field("error", &self.error)
            .field(
                "error_description",
                &self.error_description.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
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

    /// Explicitly exposes the returned authorization code, when present.
    #[must_use]
    pub fn expose_code(&self) -> Option<&str> {
        self.code.as_deref()
    }

    /// Explicitly exposes the callback state, when present.
    #[must_use]
    pub fn expose_state(&self) -> Option<&str> {
        self.state.as_deref()
    }

    /// Returns the authorization response issuer, when present.
    #[must_use]
    pub fn issuer(&self) -> Option<&str> {
        self.iss.as_deref()
    }

    /// Returns the OAuth error code, when present.
    #[must_use]
    pub fn error_code(&self) -> Option<&str> {
        self.error.as_deref()
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
                error: sanitize_oauth_error_code(Some(err), "authorization_error"),
                description: String::new(),
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

/// An authenticated user extracted from an inbound DPoP-authenticated HTTP request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticatedUser {
    did: String,
    dpop_thumbprint: String,
    scope: Option<String>,
}

impl AuthenticatedUser {
    /// Creates a new `AuthenticatedUser`.
    #[must_use]
    pub fn new(did: impl Into<String>, dpop_thumbprint: impl Into<String>) -> Self {
        Self {
            did: did.into(),
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
            did: session.sub().to_string(),
            dpop_thumbprint: session.dpop_key().jwk_thumbprint(),
            scope: session.scope().map(ToString::to_string),
        };
        Self {
            user,
            session: Some(session),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]
mod tests {
    use super::*;

    #[test]
    fn preserves_unsupported_response_type_callback_error() {
        let query = OAuthCallbackQuery::new_error("unsupported_response_type", None);
        assert!(matches!(
            query.to_callback_params(),
            Err(IntegrationError::OAuthError { error, .. })
                if error == "unsupported_response_type"
        ));
    }
}
