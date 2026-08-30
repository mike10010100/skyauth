//! Comprehensive Milestone 2 Integration & Unit Tests:
//! Identity Resolution, OAuth Discovery, and Strict SSRF Boundary Filtering.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use url::Url;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use skyauth::discovery::{
    discover_oauth_endpoints, fetch_auth_server_metadata, fetch_protected_resource_metadata,
    validate_auth_server_capabilities, AuthorizationServerMetadata,
};
use skyauth::error::{DiscoveryError, IdentityError};
use skyauth::identity::{
    normalize_handle, DidDocument, DidService, DnsTxtResolver, IdentityResolver,
};
use skyauth::ssrf::{is_blocked_hostname, SsrfFilter};

#[path = "e2e_harness/mod.rs"]
mod e2e_harness;
use e2e_harness::{fixtures::*, MockDnsResolver, MockOAuthEnvironment};

// =========================================================================
// SECTION 1: SSRF IP & HOSTNAME FILTERING TESTS
// =========================================================================

#[test]
fn test_ssrf_all_ipv4_private_rfc1918() {
    let filter = SsrfFilter::new(false);

    // Class A (10.0.0.0/8)
    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0))));
    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(10, 255, 255, 255))));

    // Class B (172.16.0.0/12)
    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 0))));
    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(172, 20, 10, 5))));
    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(172, 31, 255, 255))));
    assert!(!filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(172, 15, 255, 255))));
    assert!(!filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(172, 32, 0, 0))));

    // Class C (192.168.0.0/16)
    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0))));
    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(192, 168, 255, 255))));
    assert!(!filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(192, 169, 0, 1))));
}

#[test]
fn test_ssrf_loopback_and_insecure_localhost() {
    let strict = SsrfFilter::new(false);
    assert!(strict.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
    assert!(strict.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(127, 255, 255, 255))));
    assert!(strict.is_ip_restricted(IpAddr::V6(Ipv6Addr::LOCALHOST)));

    let local_allowed = SsrfFilter::new(true);
    assert!(!local_allowed.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
    assert!(!local_allowed.is_ip_restricted(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    // But 10.0.0.1 is still restricted even in test mode
    assert!(local_allowed.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
}

#[test]
fn test_ssrf_cloud_metadata_link_local() {
    let filter = SsrfFilter::new(false);
    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))));
    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(169, 254, 170, 2))));
    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(169, 254, 0, 1))));
}

#[test]
fn test_ssrf_special_purpose_ipv4() {
    let filter = SsrfFilter::new(false);
    // 0.0.0.0/8
    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))));
    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(0, 255, 255, 255))));
    // CGNAT 100.64.0.0/10
    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))));
    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(100, 127, 255, 255))));
    assert!(!filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(100, 128, 0, 1))));
    // IETF Protocol 192.0.0.0/24
    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(192, 0, 0, 1))));
    // TEST-NET-1 192.0.2.0/24
    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))));
    // 6to4 192.88.99.0/24
    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(192, 88, 99, 1))));
    // Benchmarking 198.18.0.0/15
    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1))));
    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(198, 19, 255, 255))));
    // TEST-NET-2 198.51.100.0/24
    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))));
    // TEST-NET-3 203.0.113.0/24
    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))));
    // Multicast 224.0.0.0/4
    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1))));
    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(239, 255, 255, 255))));
    // Class E 240.0.0.0/4 and broadcast 255.255.255.255
    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(240, 0, 0, 1))));
    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255))));
}

#[test]
fn test_ssrf_ipv6_special_ranges() {
    let filter = SsrfFilter::new(false);
    // Unspecified
    assert!(filter.is_ip_restricted(IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
    // Loopback
    assert!(filter.is_ip_restricted(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    // ULA fc00::/7
    assert!(filter.is_ip_restricted(IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1))));
    assert!(filter.is_ip_restricted(IpAddr::V6(Ipv6Addr::new(0xfdff, 0, 0, 0, 0, 0, 0, 1))));
    // Link-local fe80::/10
    assert!(filter.is_ip_restricted(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1))));
    assert!(filter.is_ip_restricted(IpAddr::V6(Ipv6Addr::new(0xfebf, 0, 0, 0, 0, 0, 0, 1))));
    // Site-local fec0::/10
    assert!(filter.is_ip_restricted(IpAddr::V6(Ipv6Addr::new(0xfec0, 0, 0, 0, 0, 0, 0, 1))));
    // Documentation 2001:db8::/32
    assert!(filter.is_ip_restricted(IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1))));
    // Multicast ff00::/8
    assert!(filter.is_ip_restricted(IpAddr::V6(Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 1))));
    assert!(filter.is_ip_restricted(IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1))));
}

#[test]
fn test_ssrf_ipv4_mapped_ipv6_unpacking() {
    let filter = SsrfFilter::new(false);
    // ::ffff:127.0.0.1
    let mapped_loopback = IpAddr::V6(Ipv4Addr::new(127, 0, 0, 1).to_ipv6_mapped());
    assert!(filter.is_ip_restricted(mapped_loopback));

    // ::ffff:169.254.169.254
    let mapped_meta = IpAddr::V6(Ipv4Addr::new(169, 254, 169, 254).to_ipv6_mapped());
    assert!(filter.is_ip_restricted(mapped_meta));

    // ::ffff:192.168.1.1
    let mapped_priv = IpAddr::V6(Ipv4Addr::new(192, 168, 1, 1).to_ipv6_mapped());
    assert!(filter.is_ip_restricted(mapped_priv));

    // ::ffff:8.8.8.8
    let mapped_public = IpAddr::V6(Ipv4Addr::new(8, 8, 8, 8).to_ipv6_mapped());
    assert!(!filter.is_ip_restricted(mapped_public));
}

#[test]
fn test_ssrf_blocked_hostnames() {
    assert!(is_blocked_hostname("metadata.google.internal"));
    assert!(is_blocked_hostname("instance-data"));
    assert!(is_blocked_hostname("metadata.internal"));
    assert!(is_blocked_hostname("169.254.169.254"));
    assert!(is_blocked_hostname("service.internal"));
    assert!(is_blocked_hostname("router.local"));
    assert!(is_blocked_hostname("host.localhost"));
    assert!(!is_blocked_hostname("bsky.social"));
    assert!(!is_blocked_hostname("plc.directory"));
}

// =========================================================================
// SECTION 2: HANDLE RESOLUTION & SYNTAX TESTS
// =========================================================================

#[test]
fn test_handle_normalization_and_syntax() {
    // Normalization
    assert_eq!(
        normalize_handle("alice.bsky.social").unwrap(),
        "alice.bsky.social"
    );
    assert_eq!(
        normalize_handle("@alice.bsky.social").unwrap(),
        "alice.bsky.social"
    );
    assert_eq!(
        normalize_handle("  @ALICE.BSKY.SOCIAL  ").unwrap(),
        "alice.bsky.social"
    );

    // Exact max length bounds (244 chars)
    let label = "a".repeat(60);
    let valid_long = format!("{label}.{label}.{label}.com");
    assert!(valid_long.len() <= 244);
    assert!(normalize_handle(&valid_long).is_ok());

    let too_long = "a".repeat(245) + ".com";
    assert!(matches!(
        normalize_handle(&too_long),
        Err(IdentityError::InvalidHandleSyntax(_))
    ));

    // Disallowed TLDs
    for tld in &[
        "alt",
        "arpa",
        "example",
        "internal",
        "invalid",
        "local",
        "localhost",
        "onion",
    ] {
        let h = format!("user.{tld}");
        assert!(matches!(
            normalize_handle(&h),
            Err(IdentityError::DisallowedHandleTld(_))
        ));
    }
    assert!(matches!(
        normalize_handle("handle.invalid"),
        Err(IdentityError::DisallowedHandleTld(_))
    ));

    // Hyphen bounds
    assert!(matches!(
        normalize_handle("-user.bsky.social"),
        Err(IdentityError::InvalidHandleSyntax(_))
    ));
    assert!(matches!(
        normalize_handle("user-.bsky.social"),
        Err(IdentityError::InvalidHandleSyntax(_))
    ));

    // Raw IP addresses
    assert!(matches!(
        normalize_handle("192.168.1.1"),
        Err(IdentityError::InvalidHandleSyntax(_))
    ));
    assert!(matches!(
        normalize_handle("[::1]"),
        Err(IdentityError::InvalidHandleSyntax(_))
    ));
}

// Mock resolver bridge for testing IdentityResolver with MockDnsResolver
#[derive(Debug)]
struct MockDnsBridge(MockDnsResolver);

impl DnsTxtResolver for MockDnsBridge {
    fn resolve_txt<'a>(
        &'a self,
        query_name: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<String>, IdentityError>> + Send + 'a>,
    > {
        let result = self.0.query_txt(query_name);
        Box::pin(async move {
            match result {
                e2e_harness::mock_dns::MockDnsResult::Records(r) => Ok(r),
                e2e_harness::mock_dns::MockDnsResult::NxDomain => Ok(Vec::new()),
                e2e_harness::mock_dns::MockDnsResult::ServFail => {
                    Err(IdentityError::Dns("SERVFAIL".to_string()))
                }
                e2e_harness::mock_dns::MockDnsResult::Timeout => {
                    Err(IdentityError::Dns("Timeout".to_string()))
                }
            }
        })
    }
}

#[tokio::test]
async fn test_identity_resolver_dns_txt_and_https_fallback() {
    let env = MockOAuthEnvironment::start_default().await;

    // 1. DNS TXT Resolution
    let resolver = IdentityResolver::builder()
        .allow_insecure_localhost(true)
        .plc_directory_url(env.plc.uri())
        .dns_resolver(Arc::new(MockDnsBridge(env.dns.clone())))
        .build();

    let did = resolver.resolve_handle(TEST_ALICE_HANDLE).await.unwrap();
    assert_eq!(did, TEST_ALICE_DID);

    // 2. HTTPS Fallback (when DNS has no record)
    let fallback_resolver = IdentityResolver::builder()
        .allow_insecure_localhost(true)
        .plc_directory_url(env.plc.uri())
        .dns_resolver(Arc::new(MockDnsBridge(MockDnsResolver::new()))) // Empty DNS
        .build();

    // Verify resolve_handle falls back to HTTPS
    // With empty DNS, resolving alice falls back to HTTPS /.well-known/atproto-did
    // Point Alice to pds uri
    let pds_url = Url::parse(&env.pds.uri()).unwrap();
    let port = pds_url.port().unwrap();

    let did_doc = DidDocument {
        id: format!("did:web:127.0.0.1%3A{port}"),
        also_known_as: vec![format!("at://{TEST_ALICE_HANDLE}")],
        verification_method: vec![],
        service: vec![DidService {
            id: "#atproto_pds".to_string(),
            service_type: "AtprotoPersonalDataServer".to_string(),
            service_endpoint: env.pds.uri(),
        }],
    };

    // Mount /.well-known/did.json on PDS
    let did_json_body = serde_json::to_string(&did_doc).unwrap();
    Mock::given(method("GET"))
        .and(path("/.well-known/did.json"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_string(did_json_body),
        )
        .mount(&env.pds.server)
        .await;

    let resolved = fallback_resolver
        .resolve_did_web(&format!("did:web:127.0.0.1%3A{port}"))
        .await
        .unwrap();

    assert_eq!(resolved.id, format!("did:web:127.0.0.1%3A{port}"));
    assert_eq!(resolved.extract_pds_endpoint().unwrap(), env.pds.uri());
}

#[tokio::test]
async fn test_identity_resolver_ambiguous_dns_records_rejected() {
    let mock_dns = MockDnsResolver::new();
    mock_dns.register_multiple_records(
        "alice.bsky.social",
        vec![
            "did=did:plc:alice111111111111111111".to_string(),
            "did=did:plc:imposter222222222222222".to_string(),
        ],
    );

    let resolver = IdentityResolver::builder()
        .allow_insecure_localhost(true)
        .dns_resolver(Arc::new(MockDnsBridge(mock_dns)))
        .build();

    let res = resolver.resolve_handle("alice.bsky.social").await;
    assert!(matches!(
        res,
        Err(IdentityError::AmbiguousHandleResolution(_))
    ));
}

// =========================================================================
// SECTION 3: DID RESOLUTION & BIDIRECTIONAL VERIFICATION TESTS
// =========================================================================

#[tokio::test]
async fn test_did_plc_resolution_and_pds_extraction() {
    let env = MockOAuthEnvironment::start_default().await;

    let resolver = IdentityResolver::builder()
        .allow_insecure_localhost(true)
        .plc_directory_url(env.plc.uri())
        .build();

    let doc = resolver.resolve_did(TEST_ALICE_DID).await.unwrap();
    assert_eq!(doc.id, TEST_ALICE_DID);
    assert!(doc.matches_handle(TEST_ALICE_HANDLE));
    assert_eq!(doc.extract_pds_endpoint().unwrap(), env.pds.uri());
}

#[tokio::test]
async fn test_did_web_resolution() {
    let env = MockOAuthEnvironment::start_default().await;

    let pds_url = Url::parse(&env.pds.uri()).unwrap();
    let port = pds_url.port().unwrap();

    let did_doc = DidDocument {
        id: format!("did:web:127.0.0.1%3A{port}"),
        also_known_as: vec!["at://alice.bsky.social".to_string()],
        verification_method: vec![],
        service: vec![DidService {
            id: "#atproto_pds".to_string(),
            service_type: "AtprotoPersonalDataServer".to_string(),
            service_endpoint: env.pds.uri(),
        }],
    };

    // Mount /.well-known/did.json on PDS
    let did_json_body = serde_json::to_string(&did_doc).unwrap();
    Mock::given(method("GET"))
        .and(path("/.well-known/did.json"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_string(did_json_body),
        )
        .mount(&env.pds.server)
        .await;

    let resolver = IdentityResolver::builder()
        .allow_insecure_localhost(true)
        .build();

    let resolved = resolver
        .resolve_did_web(&format!("did:web:127.0.0.1%3A{port}"))
        .await
        .unwrap();

    assert_eq!(resolved.id, format!("did:web:127.0.0.1%3A{port}"));
    assert_eq!(resolved.extract_pds_endpoint().unwrap(), env.pds.uri());
}

#[tokio::test]
async fn test_bidirectional_handle_mismatch_fails() {
    let env = MockOAuthEnvironment::start_default().await;

    // Start a dedicated mock PLC directory for mismatch testing
    let mock_plc = e2e_harness::MockPlcDirectory::start().await;
    mock_plc
        .mount_did_document(TEST_ALICE_DID, "attacker.com", &env.pds.uri())
        .await;

    let resolver = IdentityResolver::builder()
        .allow_insecure_localhost(true)
        .plc_directory_url(mock_plc.uri())
        .dns_resolver(Arc::new(MockDnsBridge(env.dns.clone())))
        .build();

    let res = resolver.resolve_ident(TEST_ALICE_HANDLE).await;
    assert!(matches!(res, Err(IdentityError::HandleDidMismatch(_))));
}

// =========================================================================
// SECTION 4: OAUTH DISCOVERY & ENDPOINT VALIDATION TESTS
// =========================================================================

#[tokio::test]
async fn test_full_oauth_discovery_pipeline_success() {
    let env = MockOAuthEnvironment::start_default().await;

    let resolver = IdentityResolver::builder()
        .allow_insecure_localhost(true)
        .plc_directory_url(env.plc.uri())
        .dns_resolver(Arc::new(MockDnsBridge(env.dns.clone())))
        .build();

    let endpoints = discover_oauth_endpoints(&resolver, TEST_ALICE_HANDLE)
        .await
        .expect("discovery succeeds");

    assert_eq!(endpoints.did, TEST_ALICE_DID);
    assert_eq!(endpoints.handle, Some(TEST_ALICE_HANDLE.to_string()));
    assert_eq!(endpoints.pds_endpoint, env.pds.uri());
    assert_eq!(endpoints.auth_server_issuer, env.auth_server.uri());
    assert_eq!(
        endpoints.par_endpoint,
        format!("{}/oauth/par", env.auth_server.uri())
    );
    assert_eq!(
        endpoints.token_endpoint,
        format!("{}/oauth/token", env.auth_server.uri())
    );
    assert!(endpoints.dpop_algs.contains(&"ES256".to_string()));
    assert!(endpoints.scopes.contains(&"atproto".to_string()));
}

#[tokio::test]
async fn test_discovery_oidc_fallback() {
    let env = MockOAuthEnvironment::start_default().await;

    // Mount 404 on /.well-known/oauth-authorization-server, but 200 on /.well-known/openid-configuration
    Mock::given(method("GET"))
        .and(path("/.well-known/oauth-authorization-server"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&env.auth_server.server)
        .await;

    let oidc_metadata = serde_json::json!({
        "issuer": env.auth_server.uri(),
        "authorization_endpoint": format!("{}/oauth/authorize", env.auth_server.uri()),
        "token_endpoint": format!("{}/oauth/token", env.auth_server.uri()),
        "pushed_authorization_request_endpoint": format!("{}/oauth/par", env.auth_server.uri()),
        "require_pushed_authorization_requests": true,
        "dpop_signing_alg_values_supported": ["ES256"],
        "code_challenge_methods_supported": ["S256"],
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["none", "private_key_jwt"],
        "scopes_supported": ["atproto"],
        "authorization_response_iss_parameter_supported": true,
        "client_id_metadata_document_supported": true
    });

    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_json(oidc_metadata),
        )
        .mount(&env.auth_server.server)
        .await;

    let filter = SsrfFilter::new(true);
    let meta = fetch_auth_server_metadata(&filter, &env.auth_server.uri())
        .await
        .expect("OIDC fallback succeeds");

    assert_eq!(meta.issuer, env.auth_server.uri());
    assert_eq!(
        meta.pushed_authorization_request_endpoint,
        format!("{}/oauth/par", env.auth_server.uri())
    );
}

#[test]
fn test_auth_server_capability_violations() {
    // Valid baseline
    let valid_base = AuthorizationServerMetadata {
        issuer: "https://auth.example.com".to_string(),
        authorization_endpoint: "https://auth.example.com/oauth/authorize".to_string(),
        token_endpoint: "https://auth.example.com/oauth/token".to_string(),
        pushed_authorization_request_endpoint: "https://auth.example.com/oauth/par".to_string(),
        require_pushed_authorization_requests: true,
        dpop_signing_alg_values_supported: vec!["ES256".to_string()],
        code_challenge_methods_supported: vec!["S256".to_string()],
        response_types_supported: vec!["code".to_string()],
        grant_types_supported: vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
        ],
        token_endpoint_auth_methods_supported: vec![
            "none".to_string(),
            "private_key_jwt".to_string(),
        ],
        token_endpoint_auth_signing_alg_values_supported: vec![],
        scopes_supported: vec!["atproto".to_string()],
        authorization_response_iss_parameter_supported: true,
        client_id_metadata_document_supported: true,
    };
    assert!(validate_auth_server_capabilities(&valid_base, "https://auth.example.com").is_ok());

    // Missing ES256
    let no_es256 = AuthorizationServerMetadata {
        dpop_signing_alg_values_supported: vec!["RS256".to_string()],
        ..valid_base.clone()
    };
    assert!(matches!(
        validate_auth_server_capabilities(&no_es256, "https://auth.example.com"),
        Err(DiscoveryError::MissingDpopAlgorithm(_))
    ));

    // Missing S256 PKCE
    let no_s256 = AuthorizationServerMetadata {
        code_challenge_methods_supported: vec!["plain".to_string()],
        ..valid_base.clone()
    };
    assert!(matches!(
        validate_auth_server_capabilities(&no_s256, "https://auth.example.com"),
        Err(DiscoveryError::MissingPkceMethod(_))
    ));

    // Missing PAR Endpoint
    let no_par = AuthorizationServerMetadata {
        pushed_authorization_request_endpoint: String::new(),
        ..valid_base.clone()
    };
    assert!(matches!(
        validate_auth_server_capabilities(&no_par, "https://auth.example.com"),
        Err(DiscoveryError::MissingParEndpoint(_))
    ));

    // PAR not required
    let par_false = AuthorizationServerMetadata {
        require_pushed_authorization_requests: false,
        ..valid_base.clone()
    };
    assert!(matches!(
        validate_auth_server_capabilities(&par_false, "https://auth.example.com"),
        Err(DiscoveryError::ParNotRequired(_))
    ));

    // Missing response type "code"
    let no_code = AuthorizationServerMetadata {
        response_types_supported: vec!["token".to_string()],
        ..valid_base.clone()
    };
    assert!(matches!(
        validate_auth_server_capabilities(&no_code, "https://auth.example.com"),
        Err(DiscoveryError::MissingResponseType(_))
    ));

    // Missing grant type "authorization_code"
    let no_auth_code = AuthorizationServerMetadata {
        grant_types_supported: vec!["refresh_token".to_string()],
        ..valid_base.clone()
    };
    assert!(matches!(
        validate_auth_server_capabilities(&no_auth_code, "https://auth.example.com"),
        Err(DiscoveryError::MissingGrantType { .. })
    ));

    // Missing token auth method
    let no_auth_method = AuthorizationServerMetadata {
        token_endpoint_auth_methods_supported: vec!["client_secret_basic".to_string()],
        ..valid_base.clone()
    };
    assert!(matches!(
        validate_auth_server_capabilities(&no_auth_method, "https://auth.example.com"),
        Err(DiscoveryError::MissingTokenAuthMethod(_))
    ));

    // Missing "atproto" scope
    let no_atproto_scope = AuthorizationServerMetadata {
        scopes_supported: vec!["email".to_string(), "profile".to_string()],
        ..valid_base.clone()
    };
    assert!(matches!(
        validate_auth_server_capabilities(&no_atproto_scope, "https://auth.example.com"),
        Err(DiscoveryError::MissingAtprotoScope(_))
    ));

    // Missing iss support
    let no_iss = AuthorizationServerMetadata {
        authorization_response_iss_parameter_supported: false,
        ..valid_base.clone()
    };
    assert!(matches!(
        validate_auth_server_capabilities(&no_iss, "https://auth.example.com"),
        Err(DiscoveryError::MissingIssParameterSupport(_))
    ));

    // Missing client metadata support
    let no_client_meta = AuthorizationServerMetadata {
        client_id_metadata_document_supported: false,
        ..valid_base.clone()
    };
    assert!(matches!(
        validate_auth_server_capabilities(&no_client_meta, "https://auth.example.com"),
        Err(DiscoveryError::MissingClientMetadataSupport(_))
    ));

    // Issuer Mismatch
    let issuer_mismatch = AuthorizationServerMetadata {
        issuer: "https://imposter.example.com".to_string(),
        ..valid_base.clone()
    };
    assert!(matches!(
        validate_auth_server_capabilities(&issuer_mismatch, "https://auth.example.com"),
        Err(DiscoveryError::IssuerMismatch { .. })
    ));

    // Issuer with subpath (not origin-only)
    let issuer_subpath = AuthorizationServerMetadata {
        issuer: "https://auth.example.com/oauth".to_string(),
        ..valid_base
    };
    assert!(matches!(
        validate_auth_server_capabilities(&issuer_subpath, "https://auth.example.com/oauth"),
        Err(DiscoveryError::InvalidAuthorizationServerUrl(_))
    ));
}

#[tokio::test]
async fn test_protected_resource_capability_violations() {
    let mock_pds = MockServer::start().await;
    let filter = SsrfFilter::new(true);

    // 1. Multiple authorization servers (must be rejected, exactly 1 required)
    Mock::given(method("GET"))
        .and(path("/.well-known/oauth-protected-resource"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_json(serde_json::json!({
                    "resource": mock_pds.uri(),
                    "authorization_servers": [
                        "https://auth1.example.com",
                        "https://auth2.example.com"
                    ]
                })),
        )
        .mount(&mock_pds)
        .await;

    let res_multiple = fetch_protected_resource_metadata(&filter, &mock_pds.uri()).await;
    assert!(
        matches!(
            res_multiple,
            Err(DiscoveryError::MultipleAuthorizationServers(2))
        ),
        "Multiple authorization servers must fail with MultipleAuthorizationServers"
    );

    // 2. Authorization server URL with subpath (not origin-only)
    mock_pds.reset().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/oauth-protected-resource"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_json(serde_json::json!({
                    "resource": mock_pds.uri(),
                    "authorization_servers": [
                        "https://auth.example.com/oauth/as"
                    ]
                })),
        )
        .mount(&mock_pds)
        .await;

    let res_subpath = fetch_protected_resource_metadata(&filter, &mock_pds.uri()).await;
    assert!(
        matches!(
            res_subpath,
            Err(DiscoveryError::InvalidAuthorizationServerUrl(_))
        ),
        "AS URL with subpath must fail with InvalidAuthorizationServerUrl"
    );

    // 3. Resource mismatch (resource does not match PDS origin)
    mock_pds.reset().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/oauth-protected-resource"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_json(serde_json::json!({
                    "resource": "https://different-pds.example.com",
                    "authorization_servers": [
                        "https://auth.example.com"
                    ]
                })),
        )
        .mount(&mock_pds)
        .await;

    let res_mismatch = fetch_protected_resource_metadata(&filter, &mock_pds.uri()).await;
    assert!(
        matches!(res_mismatch, Err(DiscoveryError::ResourceMismatch { .. })),
        "Mismatched resource must fail with ResourceMismatch"
    );
}
