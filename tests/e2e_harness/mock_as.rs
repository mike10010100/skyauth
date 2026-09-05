//! Mock OAuth 2.1 Authorization Server harness for RFC 8414, RFC 9126 PAR, and token exchange.
//!
//! Simulates RFC 8414 metadata discovery, RFC 9126 Pushed Authorization Requests,
//! code exchange, refresh token rotation, and `use_dpop_nonce` error challenges.

use serde_json::json;
use wiremock::matchers::{header_exists, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Mock OAuth Authorization Server wrapper.
pub struct MockAuthServer {
    /// Underlying wiremock server.
    pub server: MockServer,
}

impl MockAuthServer {
    /// Starts a fresh mock Authorization Server on a random local port.
    pub async fn start() -> Self {
        let server = MockServer::start().await;
        Self { server }
    }

    /// Returns the base URL of the mock Authorization Server.
    #[must_use]
    pub fn uri(&self) -> String {
        self.server.uri()
    }

    /// Mounts the RFC 8414 OAuth Authorization Server Metadata endpoint.
    pub async fn mount_authorization_server_metadata(&self) {
        let as_uri = self.uri();
        let metadata = json!({
            "issuer": as_uri,
            "authorization_endpoint": format!("{as_uri}/oauth/authorize"),
            "pushed_authorization_request_endpoint": format!("{as_uri}/oauth/par"),
            "token_endpoint": format!("{as_uri}/oauth/token"),
            "jwks_uri": format!("{as_uri}/oauth/jwks.json"),
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "dpop_signing_alg_values_supported": ["ES256"],
            "require_pushed_authorization_requests": true,
            "token_endpoint_auth_methods_supported": ["none", "private_key_jwt"],
            "token_endpoint_auth_signing_alg_values_supported": ["ES256"],
            "scopes_supported": ["atproto", "transition:generic"],
            "authorization_response_iss_parameter_supported": true,
            "client_id_metadata_document_supported": true
        });

        Mock::given(method("GET"))
            .and(path("/.well-known/oauth-authorization-server"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/json")
                    .set_body_json(metadata),
            )
            .mount(&self.server)
            .await;
    }

    /// Mounts the RFC 9126 PAR endpoint (`POST /oauth/par`) returning a valid `request_uri`.
    pub async fn mount_par_success(&self, request_uri: &str, expires_in_secs: u64) {
        let response = json!({
            "request_uri": request_uri,
            "expires_in": expires_in_secs
        });

        Mock::given(method("POST"))
            .and(path("/oauth/par"))
            .and(header_exists("dpop"))
            .respond_with(
                ResponseTemplate::new(201)
                    .insert_header("content-type", "application/json")
                    // ATProto profile: every DPoP-authenticated response MUST carry a
                    // DPoP-Nonce (review H2; client enforces).
                    .insert_header("dpop-nonce", "as-par-nonce")
                    .set_body_json(response),
            )
            .mount(&self.server)
            .await;
    }

    /// Mounts a PAR `use_dpop_nonce` error challenge response that triggers at most once.
    pub async fn mount_par_nonce_challenge_once(&self, fresh_nonce: &str) {
        Mock::given(method("POST"))
            .and(path("/oauth/par"))
            .respond_with(
                ResponseTemplate::new(400)
                    .insert_header("content-type", "application/json")
                    .insert_header("dpop-nonce", fresh_nonce)
                    .set_body_json(json!({
                        "error": "use_dpop_nonce",
                        "error_description": "Authorization server requires a valid DPoP-Nonce"
                    })),
            )
            .up_to_n_times(1)
            .mount(&self.server)
            .await;
    }

    /// Mounts a PAR `use_dpop_nonce` error challenge response.
    pub async fn mount_par_nonce_challenge(&self, fresh_nonce: &str) {
        Mock::given(method("POST"))
            .and(path("/oauth/par"))
            .respond_with(
                ResponseTemplate::new(400)
                    .insert_header("content-type", "application/json")
                    .insert_header("dpop-nonce", fresh_nonce)
                    .set_body_json(json!({
                        "error": "use_dpop_nonce",
                        "error_description": "Authorization server requires a valid DPoP-Nonce"
                    })),
            )
            .mount(&self.server)
            .await;
    }

    /// Mounts the OAuth token exchange endpoint returning valid access and refresh tokens.
    pub async fn mount_token_exchange_success(
        &self,
        access_token: &str,
        refresh_token: &str,
        sub_did: &str,
        expires_in_secs: u64,
    ) {
        let response = json!({
            "access_token": access_token,
            "token_type": "DPoP",
            "expires_in": expires_in_secs,
            "refresh_token": refresh_token,
            "scope": "atproto transition:generic",
            "sub": sub_did
        });

        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .and(header_exists("dpop"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/json")
                    // ATProto profile: every DPoP-authenticated response MUST carry a
                    // DPoP-Nonce (review H2; client enforces).
                    .insert_header("dpop-nonce", "as-token-nonce")
                    .set_body_json(response),
            )
            .mount(&self.server)
            .await;
    }

    /// Mounts a Token endpoint `use_dpop_nonce` challenge that triggers at most once.
    pub async fn mount_token_nonce_challenge_once(&self, fresh_nonce: &str) {
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(
                ResponseTemplate::new(400)
                    .insert_header("content-type", "application/json")
                    .insert_header("dpop-nonce", fresh_nonce)
                    .set_body_json(json!({
                        "error": "use_dpop_nonce",
                        "error_description": "Token endpoint requires a valid DPoP-Nonce"
                    })),
            )
            .up_to_n_times(1)
            .mount(&self.server)
            .await;
    }

    /// Mounts a Token endpoint `use_dpop_nonce` challenge.
    pub async fn mount_token_nonce_challenge(&self, fresh_nonce: &str) {
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(
                ResponseTemplate::new(400)
                    .insert_header("content-type", "application/json")
                    .insert_header("dpop-nonce", fresh_nonce)
                    .set_body_json(json!({
                        "error": "use_dpop_nonce",
                        "error_description": "Token endpoint requires a valid DPoP-Nonce"
                    })),
            )
            .mount(&self.server)
            .await;
    }

    /// Mounts an invalid grant error (e.g. invalid code or expired refresh token).
    pub async fn mount_token_invalid_grant(&self) {
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(
                ResponseTemplate::new(400)
                    .insert_header("content-type", "application/json")
                    .set_body_json(json!({
                        "error": "invalid_grant",
                        "error_description": "The provided authorization grant is invalid or expired"
                    })),
            )
            .mount(&self.server)
            .await;
    }

    /// Mounts the JWKS public keys endpoint (`/oauth/jwks.json`).
    pub async fn mount_jwks(&self) {
        let jwks = json!({
            "keys": [
                {
                    "kty": "EC",
                    "use": "sig",
                    "crv": "P-256",
                    "kid": "auth-server-key-1",
                    "x": "l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs",
                    "y": "9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA"
                }
            ]
        });

        Mock::given(method("GET"))
            .and(path("/oauth/jwks.json"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/json")
                    .set_body_json(jwks),
            )
            .mount(&self.server)
            .await;
    }
}
