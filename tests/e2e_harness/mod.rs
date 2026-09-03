//! Comprehensive E2E mock testing harness for `skyauth`.
//!
//! Provides opaque-box mock network servers (DNS, PLC Directory, PDS, Authorization Server)
//! with fault injection, RFC test vectors, and standard ATProto test scenarios.

#![allow(dead_code, unused_imports, missing_docs)]

pub mod mock_as;
pub mod mock_dns;
pub mod mock_pds;
pub mod mock_plc;

pub use mock_as::MockAuthServer;
pub use mock_dns::MockDnsResolver;
pub use mock_pds::MockPds;
pub use mock_plc::MockPlcDirectory;

/// Standard test constants and RFC test fixtures.
pub mod fixtures {
    /// Standard test user handle.
    pub const TEST_ALICE_HANDLE: &str = "alice.bsky.social";
    /// Standard test user DID.
    pub const TEST_ALICE_DID: &str = "did:plc:ewvi7nxzyoun6zhxrhs64oiz";

    /// Secondary test user handle.
    pub const TEST_BOB_HANDLE: &str = "bob.example.com";
    /// Secondary test user DID.
    pub const TEST_BOB_DID: &str = "did:plc:444444444444444444444444";

    /// Standard did:web identifier.
    pub const TEST_WEB_DID: &str = "did:web:auth.example.com";

    /// OAuth client ID (metadata document URI).
    pub const TEST_CLIENT_ID: &str = "https://app.example.com/oauth/client-metadata.json";
    /// OAuth redirect callback URI.
    pub const TEST_REDIRECT_URI: &str = "https://app.example.com/oauth/callback";

    /// RFC 7636 Appendix B test code verifier.
    pub const RFC7636_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    /// RFC 7636 Appendix B expected S256 code challenge.
    pub const RFC7636_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    /// RFC 9449 Figure 13 test access token.
    pub const RFC9449_ACCESS_TOKEN: &str = "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU";
    /// RFC 9449 Figure 14 expected access token hash (ath).
    pub const RFC9449_ATH: &str = "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo";

    /// RFC 9449 EC P-256 test public key X coordinate.
    pub const RFC9449_JWK_X: &str = "l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs";
    /// RFC 9449 EC P-256 test public key Y coordinate.
    pub const RFC9449_JWK_Y: &str = "9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA";
    /// RFC 9449 / RFC 7638 expected JWK Thumbprint (jkt).
    pub const RFC9449_JWK_JKT: &str = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I";
}

/// Unified mock OAuth environment orchestrating DNS, PLC, PDS, and AS.
pub struct MockOAuthEnvironment {
    /// Mock DNS resolver.
    pub dns: MockDnsResolver,
    /// Mock PLC Directory.
    pub plc: MockPlcDirectory,
    /// Mock Personal Data Server.
    pub pds: MockPds,
    /// Mock Authorization Server.
    pub auth_server: MockAuthServer,
}

impl MockOAuthEnvironment {
    /// Starts all mock servers and connects standard endpoints for `alice.bsky.social`.
    pub async fn start_default() -> Self {
        let dns = MockDnsResolver::new();
        let plc = MockPlcDirectory::start().await;
        let pds = MockPds::start().await;
        let auth_server = MockAuthServer::start().await;

        let handle = fixtures::TEST_ALICE_HANDLE;
        let did = fixtures::TEST_ALICE_DID;

        dns.register_handle_did(handle, did);

        plc.mount_did_document(did, handle, &pds.uri()).await;

        pds.mount_https_did_fallback(did).await;
        pds.mount_protected_resource_metadata(&auth_server.uri())
            .await;
        pds.mount_xrpc_get_profile(did, handle).await;

        auth_server.mount_authorization_server_metadata().await;
        auth_server.mount_jwks().await;

        Self {
            dns,
            plc,
            pds,
            auth_server,
        }
    }
}
