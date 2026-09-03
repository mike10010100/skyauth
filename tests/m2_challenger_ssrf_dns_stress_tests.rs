//! Challenger 1 Stress Harness: Milestone 2 SSRF, DNS Rebinding & Redirect Fuzzing.
//!
//! Empirical adversarial test suite verifying:
//! 1. SSRF boundary evasion: 0.0.0.0, 127.0.0.1, 127.1, 0177.0.0.1, hex/octal representations,
//!    decimal integer representations, mapped IPv6 (`::ffff:127.0.0.1`), cloud metadata
//!    (`169.254.169.254`, `169.254.170.2`, `fe80::1`), and AWS/GCP/Azure endpoints.
//! 2. DNS rebinding stress: multiple resolved IPs with mixed public/private addresses,
//!    fast-flux simulations, socket pinning.
//! 3. HTTP redirect stress: redirect loops, redirects targeting private endpoints,
//!    redirect depth limits, and response size limits.

#![allow(
    clippy::all,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    missing_docs
)]

use proptest::prelude::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use url::Url;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use skyauth::error::SsrfError;
use skyauth::ssrf::{
    is_blocked_hostname, is_restricted_ip, is_restricted_ipv4, is_restricted_ipv6, SsrfFilter,
};

#[test]
fn test_ssrf_zero_network_and_broadcast_boundaries() {
    let filter = SsrfFilter::new(false);

    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))));
    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 1))));
    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(0, 128, 0, 1))));
    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(0, 255, 255, 255))));
    assert!(is_restricted_ipv4(&Ipv4Addr::new(0, 0, 0, 0)));

    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(240, 0, 0, 0))));
    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(240, 0, 0, 1))));
    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(250, 1, 2, 3))));
    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 254))));
    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255))));
}

#[test]
fn test_ssrf_loopback_boundaries_exhaustive() {
    let filter = SsrfFilter::new(false);

    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0))));
    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 254))));
    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(127, 1, 1, 1))));
    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(127, 255, 255, 255))));

    assert!(filter.is_ip_restricted(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    assert!(filter.is_ip_restricted(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))));
    assert!(is_restricted_ipv6(&Ipv6Addr::LOCALHOST));
}

#[test]
fn test_ssrf_rfc1918_private_blocks_boundaries() {
    let filter = SsrfFilter::new(false);

    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0))));
    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(10, 255, 255, 255))));
    assert!(!filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(9, 255, 255, 255))));
    assert!(!filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(11, 0, 0, 0))));

    assert!(!filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(172, 15, 255, 255))));
    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 0))));
    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(172, 20, 100, 50))));
    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(172, 31, 255, 255))));
    assert!(!filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(172, 32, 0, 0))));

    assert!(!filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(192, 167, 255, 255))));
    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0))));
    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(192, 168, 255, 255))));
    assert!(!filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(192, 169, 0, 0))));
}

#[test]
fn test_ssrf_cloud_metadata_link_local_and_cgnat() {
    let filter = SsrfFilter::new(false);

    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(169, 254, 0, 0))));
    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))));
    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(169, 254, 170, 2))));
    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(169, 254, 255, 255))));
    assert!(!filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(169, 253, 255, 255))));
    assert!(!filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(169, 255, 0, 0))));

    assert!(!filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(100, 63, 255, 255))));
    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 0))));
    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(100, 96, 1, 1))));
    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(100, 100, 100, 200))));
    assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(100, 127, 255, 255))));
    assert!(!filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(100, 128, 0, 0))));
}

#[test]
fn test_ssrf_url_parsers_short_octal_hex_decimal_ip_notations() {
    let filter = SsrfFilter::new(false);

    let url_127_1 = Url::parse("https://127.1").unwrap();
    assert!(matches!(
        filter.validate_url(&url_127_1),
        Err(SsrfError::BlockedIp(_)) | Err(SsrfError::BlockedHost(_))
    ));

    let url_10_1 = Url::parse("https://10.1").unwrap();
    assert!(matches!(
        filter.validate_url(&url_10_1),
        Err(SsrfError::BlockedIp(_)) | Err(SsrfError::BlockedHost(_))
    ));

    let url_172_1 = Url::parse("https://172.16.1").unwrap();
    assert!(matches!(
        filter.validate_url(&url_172_1),
        Err(SsrfError::BlockedIp(_)) | Err(SsrfError::BlockedHost(_))
    ));

    let url_192_1 = Url::parse("https://192.168.1").unwrap();
    assert!(matches!(
        filter.validate_url(&url_192_1),
        Err(SsrfError::BlockedIp(_)) | Err(SsrfError::BlockedHost(_))
    ));

    let url_octal_127 = Url::parse("https://0177.0.0.1").unwrap();
    assert!(matches!(
        filter.validate_url(&url_octal_127),
        Err(SsrfError::BlockedIp(_)) | Err(SsrfError::BlockedHost(_))
    ));

    let url_octal_10 = Url::parse("https://012.0.0.1").unwrap();
    assert!(matches!(
        filter.validate_url(&url_octal_10),
        Err(SsrfError::BlockedIp(_)) | Err(SsrfError::BlockedHost(_))
    ));

    let url_octal_meta = Url::parse("https://0251.0376.0251.0376").unwrap();
    assert!(matches!(
        filter.validate_url(&url_octal_meta),
        Err(SsrfError::BlockedIp(_)) | Err(SsrfError::BlockedHost(_))
    ));

    let url_hex_dotted = Url::parse("https://0x7f.0.0.1").unwrap();
    assert!(matches!(
        filter.validate_url(&url_hex_dotted),
        Err(SsrfError::BlockedIp(_)) | Err(SsrfError::BlockedHost(_))
    ));

    let url_hex_dword = Url::parse("https://0x7f000001").unwrap();
    assert!(matches!(
        filter.validate_url(&url_hex_dword),
        Err(SsrfError::BlockedIp(_)) | Err(SsrfError::BlockedHost(_))
    ));

    let url_hex_meta = Url::parse("https://0xa9fea9fe").unwrap();
    assert!(matches!(
        filter.validate_url(&url_hex_meta),
        Err(SsrfError::BlockedIp(_)) | Err(SsrfError::BlockedHost(_))
    ));

    let url_dec_127 = Url::parse("https://2130706433").unwrap();
    assert!(matches!(
        filter.validate_url(&url_dec_127),
        Err(SsrfError::BlockedIp(_)) | Err(SsrfError::BlockedHost(_))
    ));

    let url_dec_10 = Url::parse("https://167772161").unwrap();
    assert!(matches!(
        filter.validate_url(&url_dec_10),
        Err(SsrfError::BlockedIp(_)) | Err(SsrfError::BlockedHost(_))
    ));

    let url_dec_172 = Url::parse("https://2886729729").unwrap();
    assert!(matches!(
        filter.validate_url(&url_dec_172),
        Err(SsrfError::BlockedIp(_)) | Err(SsrfError::BlockedHost(_))
    ));

    let url_dec_192 = Url::parse("https://3232235521").unwrap();
    assert!(matches!(
        filter.validate_url(&url_dec_192),
        Err(SsrfError::BlockedIp(_)) | Err(SsrfError::BlockedHost(_))
    ));

    let url_dec_meta = Url::parse("https://2852039166").unwrap();
    assert!(matches!(
        filter.validate_url(&url_dec_meta),
        Err(SsrfError::BlockedIp(_)) | Err(SsrfError::BlockedHost(_))
    ));
}

#[test]
fn test_ssrf_ipv4_mapped_ipv6_exhaustive() {
    let filter = SsrfFilter::new(false);

    let ip1: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
    assert!(filter.is_ip_restricted(ip1));

    let ip2: IpAddr = "::ffff:7f00:1".parse().unwrap();
    assert!(filter.is_ip_restricted(ip2));

    let ip_meta1: IpAddr = "::ffff:169.254.169.254".parse().unwrap();
    let ip_meta2: IpAddr = "::ffff:a9fe:a9fe".parse().unwrap();
    assert!(filter.is_ip_restricted(ip_meta1));
    assert!(filter.is_ip_restricted(ip_meta2));

    let ip_priv1: IpAddr = "::ffff:10.0.0.1".parse().unwrap();
    let ip_priv2: IpAddr = "::ffff:192.168.1.1".parse().unwrap();
    assert!(filter.is_ip_restricted(ip_priv1));
    assert!(filter.is_ip_restricted(ip_priv2));

    let ip_zero: IpAddr = "::ffff:0.0.0.0".parse().unwrap();
    let ip_bcast: IpAddr = "::ffff:255.255.255.255".parse().unwrap();
    assert!(filter.is_ip_restricted(ip_zero));
    assert!(filter.is_ip_restricted(ip_bcast));

    let ip_public: IpAddr = "::ffff:8.8.8.8".parse().unwrap();
    assert!(!filter.is_ip_restricted(ip_public));
}

#[tokio::test]
async fn test_ssrf_ipv4_mapped_ipv6_resolve_and_pin_blocked() {
    let filter = SsrfFilter::new(false);

    let url_mapped_127 = Url::parse("https://[::ffff:127.0.0.1]").unwrap();
    let res = filter.resolve_and_pin(&url_mapped_127).await;
    assert!(res.is_err(), "resolve_and_pin must reject ::ffff:127.0.0.1");

    let url_mapped_meta = Url::parse("https://[::ffff:169.254.169.254]").unwrap();
    let res_meta = filter.resolve_and_pin(&url_mapped_meta).await;
    assert!(
        res_meta.is_err(),
        "resolve_and_pin must reject ::ffff:169.254.169.254"
    );
}

#[test]
fn test_ssrf_ipv6_special_ranges_exhaustive() {
    let filter = SsrfFilter::new(false);

    assert!(filter.is_ip_restricted(IpAddr::V6(Ipv6Addr::UNSPECIFIED)));

    assert!(filter.is_ip_restricted(IpAddr::V6(Ipv6Addr::LOCALHOST)));

    assert!(filter.is_ip_restricted(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1))));
    assert!(filter.is_ip_restricted(IpAddr::V6(Ipv6Addr::new(
        0xfe80, 0, 0, 0, 0xa9fe, 0xa9fe, 0, 1
    ))));
    assert!(filter.is_ip_restricted(IpAddr::V6(Ipv6Addr::new(
        0xfebf, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff
    ))));

    assert!(filter.is_ip_restricted(IpAddr::V6(Ipv6Addr::new(0xfec0, 0, 0, 0, 0, 0, 0, 1))));

    assert!(filter.is_ip_restricted(IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1))));
    assert!(filter.is_ip_restricted(IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1))));
    assert!(filter.is_ip_restricted(IpAddr::V6(Ipv6Addr::new(
        0xfd12, 0x3456, 0x789a, 0, 0, 0, 0, 1
    ))));

    assert!(filter.is_ip_restricted(IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1))));

    assert!(filter.is_ip_restricted(IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1))));
    assert!(filter.is_ip_restricted(IpAddr::V6(Ipv6Addr::new(0xff05, 0, 0, 0, 0, 0, 0, 2))));

    assert!(!filter.is_ip_restricted(IpAddr::V6(Ipv6Addr::new(
        0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111
    ))));
}

#[test]
fn test_ssrf_cloud_metadata_hostnames_and_internal_domains() {
    let blocked = [
        "metadata.google.internal",
        "metadata.google.internal.",
        "METADATA.GOOGLE.INTERNAL",
        "instance-data",
        "INSTANCE-DATA",
        "metadata.internal",
        "169.254.169.254",
        "aws.metadata.internal",
        "azure.metadata.internal",
        "kubernetes.default.svc.internal",
        "gateway.local",
        "router.local.",
        "myhost.localhost",
    ];

    for host in &blocked {
        assert!(
            is_blocked_hostname(host),
            "Host '{host}' should be identified as blocked"
        );
        let url = Url::parse(&format!("https://{host}")).unwrap();
        let filter = SsrfFilter::new(false);
        assert!(
            matches!(
                filter.validate_url(&url),
                Err(SsrfError::BlockedHost(_)) | Err(SsrfError::BlockedIp(_))
            ),
            "URL https://{host} should be rejected"
        );
    }

    let allowed = [
        "bsky.social",
        "plc.directory",
        "auth.example.com",
        "pds.my-domain.net",
    ];

    for host in &allowed {
        assert!(!is_blocked_hostname(host));
    }
}

proptest! {
    #[test]
    fn prop_ssrf_all_10_x_x_x_blocked(b: u8, c: u8, d: u8) {
        let ip = IpAddr::V4(Ipv4Addr::new(10, b, c, d));
        prop_assert!(is_restricted_ip(ip));
    }

    #[test]
    fn prop_ssrf_all_127_x_x_x_blocked(b: u8, c: u8, d: u8) {
        let ip = IpAddr::V4(Ipv4Addr::new(127, b, c, d));
        prop_assert!(is_restricted_ip(ip));
    }

    #[test]
    fn prop_ssrf_all_169_254_x_x_blocked(c: u8, d: u8) {
        let ip = IpAddr::V4(Ipv4Addr::new(169, 254, c, d));
        prop_assert!(is_restricted_ip(ip));
    }

    #[test]
    fn prop_ssrf_all_192_168_x_x_blocked(c: u8, d: u8) {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, c, d));
        prop_assert!(is_restricted_ip(ip));
    }

    #[test]
    fn prop_ssrf_all_172_16_to_31_blocked(b in 16u8..=31u8, c: u8, d: u8) {
        let ip = IpAddr::V4(Ipv4Addr::new(172, b, c, d));
        prop_assert!(is_restricted_ip(ip));
    }

    #[test]
    fn prop_ssrf_all_ipv4_mapped_private_blocked(c: u8, d: u8) {
        let v4 = Ipv4Addr::new(10, 0, c, d);
        let v6 = IpAddr::V6(v4.to_ipv6_mapped());
        prop_assert!(is_restricted_ip(v6));
    }
}

#[test]
fn test_dns_rebinding_mixed_ip_rejection_logic() {
    let filter = SsrfFilter::new(false);

    let mixed_a = vec![
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443),
    ];
    let res_a = mixed_a
        .iter()
        .try_for_each(|addr| filter.validate_ip(addr.ip()));
    assert!(matches!(res_a, Err(SsrfError::BlockedIp(_))));

    let mixed_b = vec![
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 443),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 443),
    ];
    let res_b = mixed_b
        .iter()
        .try_for_each(|addr| filter.validate_ip(addr.ip()));
    assert!(matches!(res_b, Err(SsrfError::BlockedIp(_))));

    let mixed_c = vec![
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)), 443),
    ];
    let res_c = mixed_c
        .iter()
        .try_for_each(|addr| filter.validate_ip(addr.ip()));
    assert!(matches!(res_c, Err(SsrfError::BlockedIp(_))));

    let mixed_d = vec![
        SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)),
            443,
        ),
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 443),
    ];
    let res_d = mixed_d
        .iter()
        .try_for_each(|addr| filter.validate_ip(addr.ip()));
    assert!(matches!(res_d, Err(SsrfError::BlockedIp(_))));

    let mixed_e = vec![
        SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)),
            443,
        ),
        SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)), 443),
    ];
    let res_e = mixed_e
        .iter()
        .try_for_each(|addr| filter.validate_ip(addr.ip()));
    assert!(matches!(res_e, Err(SsrfError::BlockedIp(_))));

    let mixed_f = vec![
        SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)),
            443,
        ),
        SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)), 443),
    ];
    let res_f = mixed_f
        .iter()
        .try_for_each(|addr| filter.validate_ip(addr.ip()));
    assert!(matches!(res_f, Err(SsrfError::BlockedIp(_))));

    let pure_public = vec![
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 443),
    ];
    let res_g = pure_public
        .iter()
        .try_for_each(|addr| filter.validate_ip(addr.ip()));
    assert!(res_g.is_ok());
}

#[tokio::test]
async fn test_redirect_to_private_ip_blocked() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/start"))
        .respond_with(
            ResponseTemplate::new(302).insert_header("Location", "http://10.0.0.1:8080/admin"),
        )
        .mount(&mock_server)
        .await;

    let filter = SsrfFilter::new(true);
    let start_url = format!("{}/start", mock_server.uri());

    let res = filter.safe_get(&start_url, 1024 * 1024).await;
    assert!(
        matches!(
            res,
            Err(SsrfError::BlockedIp(_)) | Err(SsrfError::InsecureScheme(_))
        ),
        "Redirect to private IP 10.0.0.1 should be blocked"
    );
}

#[tokio::test]
async fn test_redirect_to_cloud_metadata_blocked() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/start"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("Location", "http://169.254.169.254/latest/meta-data"),
        )
        .mount(&mock_server)
        .await;

    let filter = SsrfFilter::new(true);
    let start_url = format!("{}/start", mock_server.uri());

    let res = filter.safe_get(&start_url, 1024 * 1024).await;
    assert!(
        matches!(
            res,
            Err(SsrfError::BlockedIp(_)) | Err(SsrfError::InsecureScheme(_))
        ),
        "Redirect to metadata IP 169.254.169.254 should be blocked"
    );
}

#[tokio::test]
async fn test_redirect_to_blocked_internal_hostname() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/start"))
        .respond_with(ResponseTemplate::new(302).insert_header(
            "Location",
            "https://metadata.google.internal/computeMetadata/v1/",
        ))
        .mount(&mock_server)
        .await;

    let filter = SsrfFilter::new(false);
    let start_url = format!("{}/start", mock_server.uri());

    let res = filter.safe_get(&start_url, 1024 * 1024).await;
    assert!(
        matches!(
            res,
            Err(SsrfError::BlockedHost(_))
                | Err(SsrfError::BlockedIp(_))
                | Err(SsrfError::InsecureScheme(_))
        ),
        "Redirect to metadata.google.internal should be blocked"
    );
}

#[tokio::test]
async fn test_redirect_self_referential_loop() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/loop"))
        .respond_with(ResponseTemplate::new(302).insert_header("Location", "/loop"))
        .mount(&mock_server)
        .await;

    let filter = SsrfFilter::new(true);
    let loop_url = format!("{}/loop", mock_server.uri());

    let res = filter.safe_get(&loop_url, 1024 * 1024).await;
    assert!(
        matches!(res, Err(SsrfError::TooManyRedirects)),
        "Infinite self-redirect loop must fail with TooManyRedirects"
    );
}

#[tokio::test]
async fn test_redirect_chain_exceeding_max_depth() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/hop1"))
        .respond_with(ResponseTemplate::new(302).insert_header("Location", "/hop2"))
        .mount(&mock_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/hop2"))
        .respond_with(ResponseTemplate::new(302).insert_header("Location", "/hop3"))
        .mount(&mock_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/hop3"))
        .respond_with(ResponseTemplate::new(302).insert_header("Location", "/hop4"))
        .mount(&mock_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/hop4"))
        .respond_with(ResponseTemplate::new(302).insert_header("Location", "/hop5"))
        .mount(&mock_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/hop5"))
        .respond_with(ResponseTemplate::new(200).set_body_string("final payload"))
        .mount(&mock_server)
        .await;

    let filter = SsrfFilter::new(true);
    let start_url = format!("{}/hop1", mock_server.uri());

    let res = filter.safe_get(&start_url, 1024 * 1024).await;
    assert!(
        matches!(res, Err(SsrfError::TooManyRedirects)),
        "Redirect chain of 4 hops must exceed 3 redirects limit and fail with TooManyRedirects"
    );
}

#[tokio::test]
async fn test_valid_redirect_chain_within_depth_limit() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/step1"))
        .respond_with(ResponseTemplate::new(302).insert_header("Location", "/step2"))
        .mount(&mock_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/step2"))
        .respond_with(ResponseTemplate::new(302).insert_header("Location", "/final"))
        .mount(&mock_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/final"))
        .respond_with(ResponseTemplate::new(200).set_body_string("{\"success\":true}"))
        .mount(&mock_server)
        .await;

    let filter = SsrfFilter::new(true);
    let start_url = format!("{}/step1", mock_server.uri());

    let res: Result<serde_json::Value, SsrfError> =
        filter.safe_get_json(&start_url, 1024 * 1024).await;
    assert!(res.is_ok(), "Valid 2-hop redirect should succeed");
    let json = res.unwrap();
    assert_eq!(json["success"], true);
}

#[tokio::test]
async fn test_response_size_bounding_exceeded() {
    let mock_server = MockServer::start().await;

    let huge_body = "A".repeat(100_000);
    Mock::given(method("GET"))
        .and(path("/huge"))
        .respond_with(ResponseTemplate::new(200).set_body_string(huge_body))
        .mount(&mock_server)
        .await;

    let filter = SsrfFilter::new(true);
    let url = format!("{}/huge", mock_server.uri());

    let res = filter.safe_get(&url, 10_000).await;
    assert!(
        matches!(
            res,
            Err(SsrfError::ResponseTooLarge {
                max_bytes: 10_000,
                actual_bytes: 100_000
            })
        ),
        "Response exceeding max_bytes must fail with ResponseTooLarge"
    );
}

#[test]
fn test_ssrf_disallowed_schemes_exhaustive() {
    let filter = SsrfFilter::new(false);
    let schemes = [
        "file:///etc/passwd",
        "gopher://127.0.0.1:70/_",
        "dict://127.0.0.1:11211/stats",
        "ftp://example.com/file.txt",
        "sftp://example.com/file.txt",
        "ws://example.com/socket",
        "wss://example.com/socket",
        "ldap://127.0.0.1:389/dc=example,dc=com",
        "tftp://10.0.0.1/boot",
    ];

    for s in &schemes {
        let url = Url::parse(s).unwrap();
        let res = filter.validate_url(&url);
        assert!(res.is_err(), "Scheme '{s}' should be rejected");
    }
}

#[test]
fn test_ssrf_urls_with_embedded_credentials() {
    let filter = SsrfFilter::new(false);

    let url_userinfo_loopback = Url::parse("https://admin:secret@127.0.0.1:8443/config").unwrap();
    assert!(matches!(
        filter.validate_url(&url_userinfo_loopback),
        Err(SsrfError::BlockedIp(_))
    ));

    let url_userinfo_meta = Url::parse("https://root:toor@169.254.169.254/latest").unwrap();
    assert!(matches!(
        filter.validate_url(&url_userinfo_meta),
        Err(SsrfError::BlockedHost(_)) | Err(SsrfError::BlockedIp(_))
    ));

    let url_userinfo_internal =
        Url::parse("https://user:pass@metadata.google.internal/v1").unwrap();
    assert!(matches!(
        filter.validate_url(&url_userinfo_internal),
        Err(SsrfError::BlockedHost(_))
    ));
}

#[tokio::test]
async fn test_did_web_with_private_ip_rejected_in_strict_mode() {
    use skyauth::identity::IdentityResolver;

    let resolver = IdentityResolver::builder()
        .allow_insecure_localhost(false)
        .build();

    let res = resolver.resolve_did_web("did:web:127.0.0.1").await;
    assert!(
        res.is_err(),
        "did:web:127.0.0.1 must be rejected in strict mode"
    );

    let res_meta = resolver.resolve_did_web("did:web:169.254.169.254").await;
    assert!(
        res_meta.is_err(),
        "did:web:169.254.169.254 must be rejected in strict mode"
    );

    let res_gcp = resolver
        .resolve_did_web("did:web:metadata.google.internal")
        .await;
    assert!(
        res_gcp.is_err(),
        "did:web:metadata.google.internal must be rejected"
    );
}

#[tokio::test]
async fn test_pds_discovery_malicious_private_endpoint_blocked() {
    use skyauth::discovery::fetch_protected_resource_metadata;

    let filter = SsrfFilter::new(false);

    let res = fetch_protected_resource_metadata(&filter, "https://169.254.169.254").await;
    assert!(
        res.is_err(),
        "Protected resource fetch to 169.254.169.254 must fail SSRF check"
    );

    let res_priv = fetch_protected_resource_metadata(&filter, "https://10.0.0.1").await;
    assert!(
        res_priv.is_err(),
        "Protected resource fetch to 10.0.0.1 must fail SSRF check"
    );
}

#[tokio::test]
async fn test_auth_server_discovery_malicious_as_endpoint_blocked() {
    use skyauth::discovery::fetch_auth_server_metadata;

    let filter = SsrfFilter::new(false);

    let res = fetch_auth_server_metadata(&filter, "https://metadata.google.internal").await;
    assert!(
        res.is_err(),
        "Auth server fetch to metadata.google.internal must fail SSRF check"
    );

    let res_loop = fetch_auth_server_metadata(&filter, "https://127.0.0.1:9090").await;
    assert!(
        res_loop.is_err(),
        "Auth server fetch to 127.0.0.1 must fail SSRF check"
    );
}

#[tokio::test]
async fn test_par_endpoint_ssrf_and_redirect_blocked() {
    use skyauth::dpop::{DPoPKey, DPoPNonceCache};
    use skyauth::par::{execute_par_request, ParParameters};

    let filter = SsrfFilter::new(false);
    let key = DPoPKey::generate();
    let cache = DPoPNonceCache::new();
    let params = ParParameters::new(
        "https://app.example.com/client.json",
        "https://app.example.com/callback",
        "atproto",
        "state123",
        "challenge_xyz",
    );

    let res_ssrf = execute_par_request(
        &filter,
        "https://169.254.169.254/par",
        &params,
        &key,
        &cache,
    )
    .await;
    assert!(
        matches!(
            res_ssrf,
            Err(skyauth::error::AtprotoOAuthError::Par(
                skyauth::error::ParError::Ssrf(
                    skyauth::error::SsrfError::BlockedIp(_)
                        | skyauth::error::SsrfError::BlockedHost(_)
                )
            ))
        ),
        "PAR endpoint on a link-local address must be rejected as a blocked IP or host, got {res_ssrf:?}"
    );

    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/par_redirect"))
        .respond_with(
            ResponseTemplate::new(307).insert_header("Location", "http://169.254.169.254/latest/"),
        )
        .mount(&mock_server)
        .await;

    let local_filter = SsrfFilter::new(true);
    let par_url = format!("{}/par_redirect", mock_server.uri());
    let res_redir = execute_par_request(&local_filter, &par_url, &params, &key, &cache).await;
    match res_redir {
        Err(skyauth::error::AtprotoOAuthError::Par(skyauth::error::ParError::RequestFailed {
            status,
            ref description,
            ..
        })) => {
            assert_eq!(status, 307);
            assert_eq!(
                description.as_deref(),
                Some("Redirects are not permitted for PAR endpoints")
            );
        }
        other => panic!("PAR 307 must be rejected as a redirect, got {other:?}"),
    }
}

#[tokio::test]
async fn test_token_endpoint_ssrf_and_redirect_blocked() {
    use skyauth::client::AtprotoOAuthClient;
    use skyauth::session::OAuthSession;

    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token_redirect"))
        .respond_with(
            ResponseTemplate::new(308).insert_header("Location", "http://169.254.169.254/leak/"),
        )
        .mount(&mock_server)
        .await;

    let client = AtprotoOAuthClient::builder()
        .client_metadata(skyauth::client::OAuthClientMetadata::new(
            "https://app.example.com/client.json",
            "https://app.example.com/callback",
        ))
        .allow_insecure_localhost(true)
        .build()
        .unwrap();

    let mut session = OAuthSession::new(
        "did:plc:test1234",
        "access_token_456",
        Some("refresh_token_secret_123".to_string()),
        "DPoP",
        Some("atproto".to_string()),
        Some(3600),
        skyauth::dpop::DPoPKey::generate(),
        Some("https://pds.example.com".to_string()),
        Some("https://auth.example.com".to_string()),
        Some(format!("{}/token_redirect", mock_server.uri())),
    )
    .unwrap();

    let res = client.refresh_session(&mut session).await;
    match res {
        Err(skyauth::error::AtprotoOAuthError::Token(
            skyauth::error::TokenError::RequestFailed {
                status,
                ref description,
                ..
            },
        )) => {
            assert_eq!(status, 308);
            assert_eq!(
                description.as_deref(),
                Some("Redirects are not permitted for token endpoints")
            );
        }
        other => panic!("Token refresh 308 must be rejected as a redirect, got {other:?}"),
    }
}
