//! Mock Personal Data Server (PDS) harness for identity fallback, protected resource metadata, and XRPC.
//!
//! Implements RFC 9728 Protected Resource Metadata, HTTPS handle fallback resolution
//! (`/.well-known/atproto-did`), and DPoP-bound authenticated XRPC endpoints.

use serde_json::json;
use wiremock::matchers::{header_exists, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Mock Personal Data Server (PDS) wrapper.
pub struct MockPds {
    /// Underlying wiremock server.
    pub server: MockServer,
}

impl MockPds {
    /// Starts a fresh mock PDS on a random local port.
    pub async fn start() -> Self {
        let server = MockServer::start().await;
        Self { server }
    }

    /// Returns the base URL of the mock PDS.
    #[must_use]
    pub fn uri(&self) -> String {
        self.server.uri()
    }

    /// Mounts the HTTPS handle fallback endpoint (`/.well-known/atproto-did`).
    pub async fn mount_https_did_fallback(&self, did: &str) {
        Mock::given(method("GET"))
            .and(path("/.well-known/atproto-did"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/plain; charset=utf-8")
                    .set_body_string(did.to_string()),
            )
            .mount(&self.server)
            .await;
    }

    /// Mounts the RFC 9728 Protected Resource Metadata endpoint (`/.well-known/oauth-protected-resource`).
    pub async fn mount_protected_resource_metadata(&self, auth_server_uri: &str) {
        let pds_uri = self.uri();
        let metadata = json!({
            "resource": pds_uri,
            "authorization_servers": [auth_server_uri],
            "bearer_methods_supported": ["header"],
            "resource_documentation": format!("{pds_uri}/docs")
        });

        Mock::given(method("GET"))
            .and(path("/.well-known/oauth-protected-resource"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/json")
                    .set_body_json(metadata),
            )
            .mount(&self.server)
            .await;
    }

    /// Mounts a protected XRPC endpoint that requires valid DPoP proof and token.
    pub async fn mount_xrpc_get_profile(&self, actor_did: &str, handle: &str) {
        let profile_response = json!({
            "did": actor_did,
            "handle": handle,
            "displayName": "Alice Test",
            "description": "Authenticated ATProto OAuth user",
            "followsCount": 42,
            "followersCount": 108
        });

        Mock::given(method("GET"))
            .and(path("/xrpc/app.bsky.actor.getProfile"))
            .and(header_exists("authorization"))
            .and(header_exists("dpop"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/json")
                    .insert_header("dpop-nonce", "pds-success-nonce")
                    .set_body_json(profile_response),
            )
            .mount(&self.server)
            .await;
    }

    /// Mounts a DPoP nonce challenge response (`use_dpop_nonce` error) with a fresh nonce header that triggers at most once.
    pub async fn mount_xrpc_dpop_nonce_challenge_once(&self, fresh_nonce: &str) {
        Mock::given(method("GET"))
            .and(path("/xrpc/app.bsky.actor.getProfile"))
            .respond_with(
                ResponseTemplate::new(401)
                    .insert_header(
                        "www-authenticate",
                        "DPoP error=\"use_dpop_nonce\", error_description=\"Authorization server requires DPoP nonce\"",
                    )
                    .insert_header("dpop-nonce", fresh_nonce)
                    .set_body_json(json!({
                        "error": "use_dpop_nonce",
                        "message": "Authorization server requires DPoP nonce"
                    })),
            )
            .up_to_n_times(1)
            .mount(&self.server)
            .await;
    }

    /// Mounts a DPoP nonce challenge response (`use_dpop_nonce` error) with a fresh nonce header.
    pub async fn mount_xrpc_dpop_nonce_challenge(&self, fresh_nonce: &str) {
        Mock::given(method("GET"))
            .and(path("/xrpc/app.bsky.actor.getProfile"))
            .respond_with(
                ResponseTemplate::new(401)
                    .insert_header(
                        "www-authenticate",
                        "DPoP error=\"use_dpop_nonce\", error_description=\"Authorization server requires DPoP nonce\"",
                    )
                    .insert_header("dpop-nonce", fresh_nonce)
                    .set_body_json(json!({
                        "error": "use_dpop_nonce",
                        "message": "Authorization server requires DPoP nonce"
                    })),
            )
            .mount(&self.server)
            .await;
    }

    /// Mounts a 500 Internal Server Error response for protected resource metadata.
    pub async fn mount_metadata_error(&self) {
        Mock::given(method("GET"))
            .and(path("/.well-known/oauth-protected-resource"))
            .respond_with(
                ResponseTemplate::new(500)
                    .insert_header("content-type", "text/plain")
                    .set_body_string("Internal server error fetching resource metadata"),
            )
            .mount(&self.server)
            .await;
    }
}
