//! Server-Side Request Forgery (SSRF) boundary filtering and DNS rebinding defense.
//!
//! This module provides strict, production-grade IP address filtering and socket
//! connection pinning to prevent SSRF and DNS rebinding attacks across all outbound
//! identity and discovery network requests in `skyauth`.
//!
//! ## Threat Model & Defense Strategy
//!
//! 1. **Exhaustive IP Range Filtering**: Evaluates every resolved IP against RFC 1918,
//!    loopback (RFC 1122), link-local / cloud metadata (RFC 3927), CGNAT (RFC 6598),
//!    documentation prefixes (RFC 5737, RFC 3849), IPv6 ULA (RFC 4193), multicast,
//!    and unpacked IPv4-mapped IPv6 addresses (RFC 4291).
//! 2. **DNS Rebinding Prevention**: Resolves DNS records ahead-of-time, validates
//!    *all* returned addresses, and pins the HTTP socket connection to a verified IP.
//! 3. **Redirect Depth & Scope Bounding**: Intercepts HTTP redirects (301/302/307/308),
//!    validating target URLs and IPs at each hop with bounded depth.
//! 4. **Response Size Capping**: Limits stream reads to prevent memory exhaustion
//!    or decompression bombs.

use std::net::{IpAddr, SocketAddr};
#[cfg(test)]
use std::net::{Ipv4Addr, Ipv6Addr};
use url::Url;

use crate::error::SsrfError;
pub use crate::kernels::ip_filter::{
    is_restricted_ip, is_restricted_ipv4, is_restricted_ipv4_octets, is_restricted_ipv6,
    is_restricted_ipv6_segments,
};

/// Checks if a hostname matches any cloud metadata or internal hostnames.
///
/// Bare `localhost` is also blocked; test/dev environments should use an explicit
/// loopback IP literal (e.g. `127.0.0.1` or `::1`) instead, which [`SsrfFilter`]
/// handles via `allow_insecure_localhost`.
#[must_use]
pub fn is_blocked_hostname(host: &str) -> bool {
    let lower = host.to_ascii_lowercase();
    let trimmed = lower.trim_end_matches('.');
    trimmed == "localhost"
        || trimmed == "metadata.google.internal"
        || trimmed == "instance-data"
        || trimmed == "metadata.internal"
        || trimmed == "169.254.169.254"
        || trimmed.ends_with(".internal")
        || trimmed.ends_with(".local")
        || trimmed.ends_with(".localhost")
}

/// Configurable SSRF boundary filter for outbound HTTP and DNS requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SsrfFilter {
    /// Whether insecure HTTP and loopback addresses (`127.0.0.1`, `::1`, `localhost`)
    /// are permitted for local integration testing. Defaults to `false` (strictly enforced).
    pub allow_insecure_localhost: bool,
}

impl SsrfFilter {
    /// Creates a new SSRF filter.
    #[must_use]
    pub const fn new(allow_insecure_localhost: bool) -> Self {
        Self {
            allow_insecure_localhost,
        }
    }

    /// Checks whether an IP address is restricted under the current filter configuration.
    #[must_use]
    pub fn is_ip_restricted(&self, ip: IpAddr) -> bool {
        if self.allow_insecure_localhost && ip.is_loopback() {
            return false;
        }
        is_restricted_ip(ip)
    }

    /// Validates that an IP address is not restricted.
    ///
    /// # Errors
    /// Returns [`SsrfError::BlockedIp`] if the IP address is in a restricted range.
    pub fn validate_ip(&self, ip: IpAddr) -> Result<(), SsrfError> {
        if self.is_ip_restricted(ip) {
            Err(SsrfError::BlockedIp(ip.to_string()))
        } else {
            Ok(())
        }
    }

    /// Validates a URL against scheme, hostname, and SSRF restrictions.
    ///
    /// # Errors
    /// - Returns [`SsrfError::InsecureScheme`] if the scheme is not `https` (or `http` on localhost in test mode).
    /// - Returns [`SsrfError::BlockedHost`] if the hostname is a blocked internal/cloud metadata name.
    /// - Returns [`SsrfError::BlockedIp`] if the hostname is an IP literal in a restricted range.
    pub fn validate_url(&self, url: &Url) -> Result<(), SsrfError> {
        let scheme = url.scheme();
        let host = url
            .host_str()
            .ok_or_else(|| SsrfError::InvalidUrl("Missing hostname in URL".to_string()))?;

        if scheme != "https" {
            if scheme == "http" {
                if !self.allow_insecure_localhost {
                    return Err(SsrfError::InsecureScheme(url.to_string()));
                }
                let is_local =
                    host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "[::1]";
                if !is_local {
                    return Err(SsrfError::InsecureScheme(url.to_string()));
                }
            } else {
                return Err(SsrfError::InsecureScheme(url.to_string()));
            }
        }

        if !self.allow_insecure_localhost && is_blocked_hostname(host) {
            return Err(SsrfError::BlockedHost(host.to_string()));
        }

        // Test mode exempts only explicit loopback; metadata, `.internal`, `.local`, and `.localhost` hosts stay blocked.
        if self.allow_insecure_localhost {
            let lower_host = host.to_ascii_lowercase();
            let trimmed_host = lower_host.trim_end_matches('.');
            let metadata_or_internal = trimmed_host == "metadata.google.internal"
                || trimmed_host == "instance-data"
                || trimmed_host == "metadata.internal"
                || trimmed_host == "169.254.169.254"
                || trimmed_host.ends_with(".internal")
                || trimmed_host.ends_with(".local")
                || trimmed_host.ends_with(".localhost");
            if metadata_or_internal {
                return Err(SsrfError::BlockedHost(host.to_string()));
            }
        }

        if let Ok(ip) = host.parse::<IpAddr>() {
            self.validate_ip(ip)?;
        }

        Ok(())
    }

    /// Resolves the hostname in `url` to IP addresses, validates all resolved IPs against
    /// SSRF rules, and returns a validated [`SocketAddr`] along with the target host header.
    ///
    /// # Security Invariant
    /// If ANY resolved IP address for the hostname is restricted, the entire resolution
    /// fails immediately with [`SsrfError::BlockedIp`], neutralizing multi-homed DNS
    /// rebinding attacks.
    pub async fn resolve_and_pin(&self, url: &Url) -> Result<(SocketAddr, String), SsrfError> {
        self.validate_url(url)?;

        let host = url
            .host_str()
            .ok_or_else(|| SsrfError::InvalidUrl("Missing host in URL".to_string()))?;
        let port = url.port_or_known_default().unwrap_or(443);
        let host_header = if let Some(p) = url.port() {
            format!("{host}:{p}")
        } else {
            host.to_string()
        };

        if let Ok(ip) = host.parse::<IpAddr>() {
            self.validate_ip(ip)?;
            return Ok((SocketAddr::new(ip, port), host_header));
        }

        let lookup_target = format!("{host}:{port}");
        // Bound the system DNS lookup explicitly: the reqwest client's connect
        // timeout does not cover this pre-resolution step, and an unbounded
        // lookup would let a slow/stalled resolver hang callers (review H6).
        // 5s matches the pinned client's connect timeout.
        let mut addrs: Vec<SocketAddr> = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            tokio::net::lookup_host(&lookup_target),
        )
        .await
        .map_err(|_| {
            SsrfError::DnsResolutionFailed(format!("DNS resolution for {host} timed out after 5s"))
        })?
        .map_err(|e| SsrfError::DnsResolutionFailed(format!("{host}: {e}")))?
        .collect();

        if addrs.is_empty() {
            return Err(SsrfError::DnsResolutionFailed(format!(
                "No DNS records returned for {host}"
            )));
        }

        // Validate EVERY returned address: one clean IP must not mask a restricted one (multi-IP rebinding).
        for addr in &addrs {
            self.validate_ip(addr.ip())?;
        }

        // Prefer IPv4 in test mode: wiremock and local servers typically bind 127.0.0.1, not ::1.
        if self.allow_insecure_localhost {
            addrs.sort_by_key(|a| if a.is_ipv4() { 0 } else { 1 });
        }

        Ok((addrs[0], host_header))
    }

    /// Validates a URL and resolves all DNS records, ensuring no resolved IP is restricted.
    ///
    /// # Errors
    /// Returns [`SsrfError`] if the URL syntax is invalid, DNS resolution fails, or any resolved IP is restricted.
    pub async fn validate_url_and_dns(&self, url: &Url) -> Result<SocketAddr, SsrfError> {
        let (pinned_addr, _host_header) = self.resolve_and_pin(url).await?;
        Ok(pinned_addr)
    }

    /// Constructs an SSRF-safe, DNS-pinned [`reqwest::Client`] configured with disabled automatic redirects
    /// (`Policy::none()`), connection/request timeouts, and socket pinning to a verified IP address.
    ///
    /// # Security Invariants
    /// 1. Resolves all DNS records for the URL's hostname.
    /// 2. Validates *every* resolved IP address against restricted and private ranges.
    /// 3. Binds the HTTP client connection directly to the verified socket address via `.resolve()`.
    /// 4. Disables automatic redirects to prevent credential / token forwarding.
    ///
    /// # Errors
    /// Returns [`SsrfError`] if DNS resolution fails, an IP is blocked, or the client cannot be built.
    pub async fn build_pinned_client(
        &self,
        url: &Url,
    ) -> Result<(reqwest::Client, SocketAddr, String), SsrfError> {
        let (pinned_addr, host_header) = self.resolve_and_pin(url).await?;
        let host_only = url.host_str().unwrap_or("localhost");

        let mut builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(10))
            // Hard-disable environment proxies (`HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`):
            // with an HTTPS proxy the TCP connection terminates at the proxy and the
            // target hostname is sent via CONNECT, so proxy-side DNS — not the locally
            // validated and pinned address — would select the destination. That
            // silently invalidates the socket pin below and re-opens split-DNS /
            // proxy-side rebinding paths (independent review H6). Pinned transport
            // and proxies are mutually exclusive trust models; if proxied egress is
            // ever needed it requires a separate, explicitly-constructed client.
            .no_proxy();

        if host_only.parse::<IpAddr>().is_err() {
            builder = builder.resolve(host_only, pinned_addr);
        }

        let client = builder
            .build()
            .map_err(|e| SsrfError::Http(e.to_string()))?;

        Ok((client, pinned_addr, host_header))
    }

    /// Executes a safe HTTP GET request with SSRF validation, DNS pinning, redirect depth bounding,
    /// and streaming response size limits.
    ///
    /// # Arguments
    /// - `url_str`: The target URL string.
    /// - `max_bytes`: Maximum allowed response body size in bytes.
    pub async fn safe_get(&self, url_str: &str, max_bytes: usize) -> Result<Vec<u8>, SsrfError> {
        let mut current_url = Url::parse(url_str)
            .map_err(|e| SsrfError::InvalidUrl(format!("Failed to parse URL '{url_str}': {e}")))?;

        let mut redirects_remaining = 3usize;

        loop {
            let (client, _pinned_addr, host_header) =
                self.build_pinned_client(&current_url).await?;

            let resp = client
                .get(current_url.as_str())
                .header(reqwest::header::HOST, host_header)
                .header(reqwest::header::ACCEPT, "application/json, text/plain, */*")
                .send()
                .await
                .map_err(|e| SsrfError::Http(e.to_string()))?;

            let status = resp.status();
            if status.is_redirection() {
                if redirects_remaining == 0 {
                    return Err(SsrfError::TooManyRedirects);
                }
                redirects_remaining = redirects_remaining.saturating_sub(1);

                let location = resp
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .ok_or_else(|| SsrfError::Http("Redirect missing Location header".to_string()))?
                    .to_str()
                    .map_err(|e| SsrfError::Http(format!("Invalid Location header: {e}")))?;

                let next_url = current_url.join(location).map_err(|e| {
                    SsrfError::InvalidUrl(format!("Invalid redirect location '{location}': {e}"))
                })?;

                current_url = next_url;
                continue;
            }

            if !status.is_success() {
                return Err(SsrfError::HttpStatus(
                    status.as_u16(),
                    format!("HTTP status {status} from {current_url}"),
                ));
            }

            let bytes = read_bounded_body(resp, max_bytes).await?;
            return Ok(bytes);
        }
    }

    /// Fetches JSON from a URL with full SSRF safety checks.
    ///
    /// # Arguments
    /// - `url_str`: The target URL string.
    /// - `max_bytes`: Maximum permitted response byte size.
    pub async fn safe_get_json<T: serde::de::DeserializeOwned>(
        &self,
        url_str: &str,
        max_bytes: usize,
    ) -> Result<T, SsrfError> {
        let bytes = self.safe_get(url_str, max_bytes).await?;
        serde_json::from_slice(&bytes).map_err(|e| SsrfError::Json(e.to_string()))
    }
}

/// Maximum allowable HTTP response body size for OAuth and discovery endpoints (1 MiB = 1,048,576 bytes).
pub const MAX_OAUTH_RESPONSE_BYTES: usize = 1_048_576;

/// Reads an HTTP response body incrementally chunk-by-chunk, aborting immediately
/// if the accumulated size exceeds `max_bytes` to prevent memory exhaustion / DoS.
///
/// # Errors
/// - Returns [`SsrfError::ResponseTooLarge`] as soon as `max_bytes` is exceeded.
/// - Returns [`SsrfError::Http`] if a network stream error occurs.
pub async fn read_bounded_body(
    mut resp: reqwest::Response,
    max_bytes: usize,
) -> Result<Vec<u8>, SsrfError> {
    if let Some(content_length) = resp.content_length() {
        if content_length > max_bytes as u64 {
            return Err(SsrfError::ResponseTooLarge {
                max_bytes,
                actual_bytes: content_length as usize,
            });
        }
    }

    let mut buffer = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| SsrfError::Http(e.to_string()))?
    {
        if buffer.len().saturating_add(chunk.len()) > max_bytes {
            let actual = resp
                .content_length()
                .map(|cl| cl as usize)
                .unwrap_or_else(|| buffer.len().saturating_add(chunk.len()));
            return Err(SsrfError::ResponseTooLarge {
                max_bytes,
                actual_bytes: actual,
            });
        }
        buffer.extend_from_slice(&chunk);
    }
    Ok(buffer)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]
mod tests {
    use super::*;

    #[test]
    fn test_loopback_ipv4() {
        let filter = SsrfFilter::new(false);
        assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(127, 255, 255, 254))));

        let local_filter = SsrfFilter::new(true);
        assert!(!local_filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
    }

    #[test]
    fn test_rfc1918_private_ipv4() {
        let filter = SsrfFilter::new(false);
        assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(10, 255, 255, 255))));
        assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
        assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(172, 31, 255, 255))));
        assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(192, 168, 255, 255))));
        assert!(!filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(172, 32, 0, 1))));
    }

    #[test]
    fn test_link_local_and_cloud_metadata() {
        let filter = SsrfFilter::new(false);
        assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))));
        assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(169, 254, 170, 2))));
    }

    #[test]
    fn test_cgnat_shared_space() {
        let filter = SsrfFilter::new(false);
        assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))));
        assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(100, 127, 255, 254))));
        assert!(!filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(100, 63, 255, 255))));
    }

    #[test]
    fn test_documentation_and_benchmarking_ranges() {
        let filter = SsrfFilter::new(false);
        assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))));
        assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))));
        assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))));
        assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1))));
        assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(192, 88, 99, 1))));
    }

    #[test]
    fn test_multicast_and_reserved_class_e() {
        let filter = SsrfFilter::new(false);
        assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))));
        assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1))));
        assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(240, 0, 0, 1))));
        assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255))));
    }

    #[test]
    fn test_ipv6_ranges() {
        let filter = SsrfFilter::new(false);
        assert!(filter.is_ip_restricted(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(filter.is_ip_restricted(IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
        assert!(filter.is_ip_restricted(IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1))));
        assert!(filter.is_ip_restricted(IpAddr::V6(Ipv6Addr::new(0xfd12, 0, 0, 0, 0, 0, 0, 1))));
        assert!(filter.is_ip_restricted(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1))));
        assert!(
            filter.is_ip_restricted(IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)))
        );
        assert!(filter.is_ip_restricted(IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1))));
    }

    #[test]
    fn test_ipv4_mapped_ipv6() {
        let filter = SsrfFilter::new(false);
        let mapped_loopback = IpAddr::V6(Ipv4Addr::new(127, 0, 0, 1).to_ipv6_mapped());
        assert!(filter.is_ip_restricted(mapped_loopback));

        let mapped_metadata = IpAddr::V6(Ipv4Addr::new(169, 254, 169, 254).to_ipv6_mapped());
        assert!(filter.is_ip_restricted(mapped_metadata));

        let mapped_private = IpAddr::V6(Ipv4Addr::new(10, 0, 0, 1).to_ipv6_mapped());
        assert!(filter.is_ip_restricted(mapped_private));

        let mapped_public = IpAddr::V6(Ipv4Addr::new(8, 8, 8, 8).to_ipv6_mapped());
        assert!(!filter.is_ip_restricted(mapped_public));
    }

    #[test]
    fn test_public_ips_allowed() {
        let filter = SsrfFilter::new(false);
        assert!(!filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
        assert!(!filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(!filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))));
        assert!(!filter.is_ip_restricted(IpAddr::V6(Ipv6Addr::new(
            0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111
        ))));
    }

    #[test]
    fn test_validate_url() {
        let filter = SsrfFilter::new(false);
        assert!(filter
            .validate_url(&Url::parse("https://bsky.social").unwrap())
            .is_ok());
        assert!(filter
            .validate_url(&Url::parse("http://bsky.social").unwrap())
            .is_err());
        assert!(filter
            .validate_url(&Url::parse("ftp://example.com").unwrap())
            .is_err());
        assert!(filter
            .validate_url(&Url::parse("https://127.0.0.1").unwrap())
            .is_err());
        assert!(filter
            .validate_url(&Url::parse("https://169.254.169.254").unwrap())
            .is_err());
        assert!(filter
            .validate_url(&Url::parse("https://metadata.google.internal").unwrap())
            .is_err());

        let local_filter = SsrfFilter::new(true);
        assert!(local_filter
            .validate_url(&Url::parse("http://localhost:8080").unwrap())
            .is_ok());
        assert!(local_filter
            .validate_url(&Url::parse("http://127.0.0.1:8080").unwrap())
            .is_ok());
        assert!(local_filter
            .validate_url(&Url::parse("http://10.0.0.1:8080").unwrap())
            .is_err());
    }

    #[test]
    fn test_test_mode_still_blocks_metadata_and_internal_hosts() {
        let local_filter = SsrfFilter::new(true);
        assert!(local_filter
            .validate_url(&Url::parse("http://metadata.google.internal").unwrap())
            .is_err());
        assert!(local_filter
            .validate_url(&Url::parse("https://instance-data").unwrap())
            .is_err());
        assert!(local_filter
            .validate_url(&Url::parse("https://service.internal").unwrap())
            .is_err());
        assert!(local_filter
            .validate_url(&Url::parse("https://169.254.169.254").unwrap())
            .is_err());
    }

    #[test]
    fn test_is_blocked_hostname_includes_bare_localhost() {
        assert!(is_blocked_hostname("localhost"));
        assert!(is_blocked_hostname("LOCALHOST"));
        assert!(is_blocked_hostname("localhost."));
    }

    #[test]
    fn test_6to4_embedded_ipv4_restriction() {
        let v6 = Ipv6Addr::new(0x2002, 0x0a00, 0x0001, 0, 0, 0, 0, 1);
        assert!(is_restricted_ipv6(&v6));

        let public_6to4 = Ipv6Addr::new(0x2002, 0xc68c, 0x2174, 0, 0, 0, 0, 1);
        assert!(!is_restricted_ipv6(&public_6to4));
    }

    #[test]
    fn test_teredo_prefix_blocked() {
        let teredo = Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0xf7f7, 0xf7f7);
        assert!(is_restricted_ipv6(&teredo));

        let teredo_plain = Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 0);
        assert!(is_restricted_ipv6(&teredo_plain));
    }
}
