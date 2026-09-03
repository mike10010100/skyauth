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

#[test]
fn test_ssrf_all_ipv4_private_rfc1918() {
    let filter = SsrfFilter::new(false);

    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0))));
    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(10, 255, 255, 255))));

    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 0))));
    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(172, 20, 10, 5))));
    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(172, 31, 255, 255))));
    assert!(!filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(172, 15, 255, 255))));
    assert!(!filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(172, 32, 0, 0))));

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
    assert!(local_allowed.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));

    let url_loopback = Url::parse("http://localhost:8080/xrpc").unwrap();
    assert!(local_allowed.validate_url(&url_loopback).is_ok());

    let suffixes = [
        "http://metadata.google.internal/xrpc",
        "http://evil.internal/xrpc",
        "http://box.local/xrpc",
        "http://app.localhost/xrpc",
    ];
    for u in suffixes {
        let parsed = Url::parse(u).unwrap();
        assert!(
            local_allowed.validate_url(&parsed).is_err(),
            "test mode must keep blocking {u}"
        );
        assert!(strict.validate_url(&parsed).is_err());
    }
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
    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))));
    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(0, 255, 255, 255))));
    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))));
    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(100, 127, 255, 255))));
    assert!(!filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(100, 128, 0, 1))));
    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(192, 0, 0, 1))));
    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))));
    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(192, 88, 99, 1))));
    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1))));
    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(198, 19, 255, 255))));
    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))));
    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))));
    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1))));
    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(239, 255, 255, 255))));
    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(240, 0, 0, 1))));
    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255))));
}

#[test]
fn test_ssrf_ipv6_special_ranges() {
    let filter = SsrfFilter::new(false);
    assert!(filter.is_ip_restricted(IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
    assert!(filter.is_ip_restricted(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    assert!(filter.is_ip_restricted(IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1))));
    assert!(filter.is_ip_restricted(IpAddr::V6(Ipv6Addr::new(0xfdff, 0, 0, 0, 0, 0, 0, 1))));
    assert!(filter.is_ip_restricted(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1))));
    assert!(filter.is_ip_restricted(IpAddr::V6(Ipv6Addr::new(0xfebf, 0, 0, 0, 0, 0, 0, 1))));
    assert!(filter.is_ip_restricted(IpAddr::V6(Ipv6Addr::new(0xfec0, 0, 0, 0, 0, 0, 0, 1))));
    assert!(filter.is_ip_restricted(IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1))));
    assert!(filter.is_ip_restricted(IpAddr::V6(Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 1))));
    assert!(filter.is_ip_restricted(IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1))));
}

#[test]
fn test_ssrf_ipv4_mapped_ipv6_unpacking() {
    let filter = SsrfFilter::new(false);
    let mapped_loopback = IpAddr::V6(Ipv4Addr::new(127, 0, 0, 1).to_ipv6_mapped());
    assert!(filter.is_ip_restricted(mapped_loopback));

    let mapped_meta = IpAddr::V6(Ipv4Addr::new(169, 254, 169, 254).to_ipv6_mapped());
    assert!(filter.is_ip_restricted(mapped_meta));

    let mapped_priv = IpAddr::V6(Ipv4Addr::new(192, 168, 1, 1).to_ipv6_mapped());
    assert!(filter.is_ip_restricted(mapped_priv));

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

#[test]
fn test_handle_normalization_and_syntax() {
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

    let label = "a".repeat(60);
    let valid_long = format!("{label}.{label}.{label}.com");
    assert!(valid_long.len() <= 244);
    assert!(normalize_handle(&valid_long).is_ok());

    let too_long = "a".repeat(245) + ".com";
    assert!(matches!(
        normalize_handle(&too_long),
        Err(IdentityError::InvalidHandleSyntax(_))
    ));

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

    assert!(matches!(
        normalize_handle("-user.bsky.social"),
        Err(IdentityError::InvalidHandleSyntax(_))
    ));
    assert!(matches!(
        normalize_handle("user-.bsky.social"),
        Err(IdentityError::InvalidHandleSyntax(_))
    ));

    assert!(matches!(
        normalize_handle("192.168.1.1"),
        Err(IdentityError::InvalidHandleSyntax(_))
    ));
    assert!(matches!(
        normalize_handle("[::1]"),
        Err(IdentityError::InvalidHandleSyntax(_))
    ));
}

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

    let resolver = IdentityResolver::builder()
        .allow_insecure_localhost(true)
        .plc_directory_url(env.plc.uri())
        .dns_resolver(Arc::new(MockDnsBridge(env.dns.clone())))
        .build();

    let did = resolver.resolve_handle(TEST_ALICE_HANDLE).await.unwrap();
    assert_eq!(did, TEST_ALICE_DID);

    let fallback_resolver = IdentityResolver::builder()
        .allow_insecure_localhost(true)
        .plc_directory_url(env.plc.uri())
        .dns_resolver(Arc::new(MockDnsBridge(MockDnsResolver::new())))
        .build();

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
        "token_endpoint_auth_signing_alg_values_supported": ["ES256"],
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
        token_endpoint_auth_signing_alg_values_supported: vec!["ES256".to_string()],
        scopes_supported: vec!["atproto".to_string()],
        authorization_response_iss_parameter_supported: true,
        client_id_metadata_document_supported: true,
    };
    assert!(validate_auth_server_capabilities(&valid_base, "https://auth.example.com").is_ok());

    let no_es256 = AuthorizationServerMetadata {
        dpop_signing_alg_values_supported: vec!["RS256".to_string()],
        ..valid_base.clone()
    };
    assert!(matches!(
        validate_auth_server_capabilities(&no_es256, "https://auth.example.com"),
        Err(DiscoveryError::MissingDpopAlgorithm(_))
    ));

    let no_s256 = AuthorizationServerMetadata {
        code_challenge_methods_supported: vec!["plain".to_string()],
        ..valid_base.clone()
    };
    assert!(matches!(
        validate_auth_server_capabilities(&no_s256, "https://auth.example.com"),
        Err(DiscoveryError::MissingPkceMethod(_))
    ));

    let no_par = AuthorizationServerMetadata {
        pushed_authorization_request_endpoint: String::new(),
        ..valid_base.clone()
    };
    assert!(matches!(
        validate_auth_server_capabilities(&no_par, "https://auth.example.com"),
        Err(DiscoveryError::MissingParEndpoint(_))
    ));

    let par_false = AuthorizationServerMetadata {
        require_pushed_authorization_requests: false,
        ..valid_base.clone()
    };
    assert!(matches!(
        validate_auth_server_capabilities(&par_false, "https://auth.example.com"),
        Err(DiscoveryError::ParNotRequired(_))
    ));

    let no_code = AuthorizationServerMetadata {
        response_types_supported: vec!["token".to_string()],
        ..valid_base.clone()
    };
    assert!(matches!(
        validate_auth_server_capabilities(&no_code, "https://auth.example.com"),
        Err(DiscoveryError::MissingResponseType(_))
    ));

    let no_auth_code = AuthorizationServerMetadata {
        grant_types_supported: vec!["refresh_token".to_string()],
        ..valid_base.clone()
    };
    assert!(matches!(
        validate_auth_server_capabilities(&no_auth_code, "https://auth.example.com"),
        Err(DiscoveryError::MissingGrantType { .. })
    ));

    let no_auth_method = AuthorizationServerMetadata {
        token_endpoint_auth_methods_supported: vec!["client_secret_basic".to_string()],
        ..valid_base.clone()
    };
    assert!(matches!(
        validate_auth_server_capabilities(&no_auth_method, "https://auth.example.com"),
        Err(DiscoveryError::MissingTokenAuthMethod(_))
    ));

    let no_signing_alg = AuthorizationServerMetadata {
        token_endpoint_auth_signing_alg_values_supported: vec!["RS256".to_string()],
        ..valid_base.clone()
    };
    assert!(matches!(
        validate_auth_server_capabilities(&no_signing_alg, "https://auth.example.com"),
        Err(DiscoveryError::MissingTokenAuthSigningAlg(_))
    ));

    let none_signing_alg = AuthorizationServerMetadata {
        token_endpoint_auth_signing_alg_values_supported: vec![
            "ES256".to_string(),
            "none".to_string(),
        ],
        ..valid_base.clone()
    };
    assert!(matches!(
        validate_auth_server_capabilities(&none_signing_alg, "https://auth.example.com"),
        Err(DiscoveryError::InvalidTokenAuthSigningAlg(_))
    ));

    let no_atproto_scope = AuthorizationServerMetadata {
        scopes_supported: vec!["email".to_string(), "profile".to_string()],
        ..valid_base.clone()
    };
    assert!(matches!(
        validate_auth_server_capabilities(&no_atproto_scope, "https://auth.example.com"),
        Err(DiscoveryError::MissingAtprotoScope(_))
    ));

    let no_iss = AuthorizationServerMetadata {
        authorization_response_iss_parameter_supported: false,
        ..valid_base.clone()
    };
    assert!(matches!(
        validate_auth_server_capabilities(&no_iss, "https://auth.example.com"),
        Err(DiscoveryError::MissingIssParameterSupport(_))
    ));

    let no_client_meta = AuthorizationServerMetadata {
        client_id_metadata_document_supported: false,
        ..valid_base.clone()
    };
    assert!(matches!(
        validate_auth_server_capabilities(&no_client_meta, "https://auth.example.com"),
        Err(DiscoveryError::MissingClientMetadataSupport(_))
    ));

    let issuer_mismatch = AuthorizationServerMetadata {
        issuer: "https://imposter.example.com".to_string(),
        ..valid_base.clone()
    };
    assert!(matches!(
        validate_auth_server_capabilities(&issuer_mismatch, "https://auth.example.com"),
        Err(DiscoveryError::IssuerMismatch { .. })
    ));

    let issuer_subpath = AuthorizationServerMetadata {
        issuer: "https://auth.example.com/oauth".to_string(),
        ..valid_base.clone()
    };
    assert!(matches!(
        validate_auth_server_capabilities(&issuer_subpath, "https://auth.example.com/oauth"),
        Err(DiscoveryError::InvalidAuthorizationServerUrl(_))
    ));

    let issuer_port = AuthorizationServerMetadata {
        issuer: "https://auth.example.com:443".to_string(),
        ..valid_base
    };
    assert!(matches!(
        validate_auth_server_capabilities(&issuer_port, "https://auth.example.com"),
        Err(DiscoveryError::InvalidAuthorizationServerUrl(_))
    ));
}

#[tokio::test]
async fn test_protected_resource_capability_violations() {
    let mock_pds = MockServer::start().await;
    let filter = SsrfFilter::new(true);

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

    mock_pds.reset().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/oauth-protected-resource"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_json(serde_json::json!({
                    "resource": mock_pds.uri(),
                    "authorization_servers": [
                        "https://auth.example.com:443"
                    ]
                })),
        )
        .mount(&mock_pds)
        .await;

    let res_port = fetch_protected_resource_metadata(&filter, &mock_pds.uri()).await;
    assert!(
        matches!(
            res_port,
            Err(DiscoveryError::InvalidAuthorizationServerUrl(_))
        ),
        "AS URL with explicit :443 must fail with InvalidAuthorizationServerUrl"
    );

    mock_pds.reset().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/oauth-protected-resource"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_json(serde_json::json!({
                    "resource": format!("{}/evil", mock_pds.uri()),
                    "authorization_servers": [
                        "https://auth.example.com"
                    ]
                })),
        )
        .mount(&mock_pds)
        .await;

    let res_same_origin_path = fetch_protected_resource_metadata(&filter, &mock_pds.uri()).await;
    assert!(
        matches!(
            res_same_origin_path,
            Err(DiscoveryError::ResourceMismatch { .. })
        ),
        "Same-origin resource with a path must fail with ResourceMismatch"
    );

    mock_pds.reset().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/oauth-protected-resource"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_json(serde_json::json!({
                    "resource": format!("{}?backdoor=1", mock_pds.uri()),
                    "authorization_servers": [
                        "https://auth.example.com"
                    ]
                })),
        )
        .mount(&mock_pds)
        .await;

    let res_same_origin_query = fetch_protected_resource_metadata(&filter, &mock_pds.uri()).await;
    assert!(
        matches!(
            res_same_origin_query,
            Err(DiscoveryError::ResourceMismatch { .. })
        ),
        "Same-origin resource with a query must fail with ResourceMismatch"
    );
}
