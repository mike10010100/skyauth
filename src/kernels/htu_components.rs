//! DPoP target-URI (`htu`) normalization components (RFC 9449 § 4.2).
//!
//! The component core operates on already-parsed URI pieces
//! `(scheme, host, port, path)` — the representation SMT tools can reason about
//! symbolically. The production `normalize_htu` in `dpop.rs` keeps the
//! `Url::parse` wrapper (symbolic execution of which hits an upstream Kani ICE)
//! and delegates assembly to [`build_normalized_htu`], which is exhaustively
//! proven by the Kani refinement harness.

/// URI scheme after case normalization, restricted to the RFC 9449 set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HtuScheme {
    /// Plain HTTP (default port 80).
    Http,
    /// HTTP over TLS (default port 443).
    Https,
}

impl HtuScheme {
    /// Lowercase scheme string as it must appear in the normalized `htu`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }

    /// The URI default port for this scheme (RFC 3986 § 3.2.3).
    #[must_use]
    pub const fn default_port(self) -> u16 {
        match self {
            Self::Http => 80,
            Self::Https => 443,
        }
    }

    /// Parses a raw scheme string case-insensitively; `None` for non-HTTP(S).
    #[must_use]
    pub fn parse(scheme: &str) -> Option<Self> {
        match scheme.to_ascii_lowercase().as_str() {
            "http" => Some(Self::Http),
            "https" => Some(Self::Https),
            _ => None,
        }
    }
}

/// Assembles the normalized `htu` from parsed URI components.
///
/// Rules (RFC 9449 § 4.2, mirroring the production `normalize_htu`):
/// - scheme and host lowercased,
/// - default ports (`http:80`, `https:443`) and absent ports omitted,
/// - custom ports preserved,
/// - path preserved verbatim (empty path normalized to `/` by the caller,
///   mirroring `Url::path()` semantics which return `"/"` for rootless URLs).
///
/// # Errors
///
/// Returns `None` when `port` is present but not representable as decimal —
/// unreachable through `Url::parse` (which validates ports), retained so the
/// kernel remains total over all `u16` inputs.
#[must_use]
pub fn build_normalized_htu(
    scheme: HtuScheme,
    host: &str,
    port: Option<u16>,
    path: &str,
) -> String {
    let port_str = match port {
        Some(p) if p == scheme.default_port() => String::new(),
        Some(p) => decimal_port_str(p),
        None => String::new(),
    };

    let normalized_path = if path.is_empty() { "/" } else { path };

    let mut out = String::with_capacity(
        scheme.as_str().len() + 3 + host.len() + port_str.len() + normalized_path.len(),
    );
    out.push_str(scheme.as_str());
    out.push_str("://");
    out.push_str(host);
    out.push_str(&port_str);
    out.push_str(normalized_path);
    out
}

/// Component-level validation invariants every normalized `htu` must satisfy.
///
/// These are *scheme-aware* (unlike the string-scanning spec predicates in
/// `formal_models::DPoPHtuFormalSpec`, which cannot distinguish `http:443` from
/// `https:443`): the port is omitted iff absent or equal to the scheme default,
/// and preserved (in decimal) otherwise.
#[must_use]
pub fn invariants_hold(
    scheme: HtuScheme,
    host: &str,
    port: Option<u16>,
    path: &str,
    out: &str,
) -> bool {
    let expected = build_normalized_htu(scheme, host, port, path);
    if out != expected {
        return false;
    }
    // Structural no-query/no-fragment check performed on the *components*
    // (the assembled output equals `expected`, whose scheme is an enum and
    // whose host/path are the caller's inputs): if the host/path carried
    // '?', '#', or ':' the assembly could not satisfy the port placement
    // rules below, and callers reaching this kernel have already been
    // through `Url::parse`, which rejects stray '?'/'#' outside their
    // structural positions. Keeping the check component-level avoids
    // unicode-aware string scans that are unbounded under symbolic input.
    // Byte-level scans: '?', '#', ':' are ASCII, so byte equality is exact.
    if host.bytes().any(|b| b == b'?' || b == b'#') || path.bytes().any(|b| b == b'?' || b == b'#')
    {
        return false;
    }
    let prefix = format!("{}://", scheme.as_str());
    let lower_host = host.to_ascii_lowercase();
    if !out.starts_with(&prefix) || !out[prefix.len()..].starts_with(&lower_host) {
        return false;
    }
    let after_host = &out[prefix.len() + lower_host.len()..];
    match port {
        // Default/absent port: no explicit `:<digits>` port may appear.
        None => !starts_with_explicit_port(after_host),
        Some(p) if p == scheme.default_port() => !starts_with_explicit_port(after_host),
        // Custom port: must appear verbatim in decimal directly after the host.
        Some(p) => after_host.starts_with(&decimal_port_str(p)),
    }
}

/// Renders `:<port>` in decimal without `format!` — ASCII-digit assembly
/// keeps the kernel free of `core::fmt` machinery (which is unbounded to
/// symbolically execute under CBMC/Kani).
#[must_use]
fn decimal_port_str(port: u16) -> String {
    let mut buf = [b'0'; 6];
    let mut len = 0;
    let mut n = port;
    if n == 0 {
        buf[0] = b'0';
        len = 1;
    }
    while n > 0 {
        buf[len] = b'0' + (n % 10) as u8;
        n /= 10;
        len += 1;
    }
    let mut out = String::with_capacity(len + 1);
    out.push(':');
    for b in buf[..len].iter().rev() {
        out.push(*b as char);
    }
    out
}

/// Returns `true` if `s` begins with `:<digits>` — an explicit port suffix.
#[must_use]
fn starts_with_explicit_port(s: &str) -> bool {
    let b = s.as_bytes();
    if b.first() != Some(&b':') {
        return false;
    }
    matches!(b.get(1), Some(c) if c.is_ascii_digit())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]
mod tests {
    use super::*;

    #[test]
    fn default_ports_stripped() {
        assert_eq!(
            build_normalized_htu(HtuScheme::Https, "example.com", Some(443), "/oauth/token"),
            "https://example.com/oauth/token"
        );
        assert_eq!(
            build_normalized_htu(HtuScheme::Http, "example.com", Some(80), "/"),
            "http://example.com/"
        );
    }

    #[test]
    fn custom_ports_preserved() {
        assert_eq!(
            build_normalized_htu(HtuScheme::Https, "example.com", Some(8443), "/x"),
            "https://example.com:8443/x"
        );
    }

    #[test]
    fn absent_port_omitted() {
        assert_eq!(
            build_normalized_htu(HtuScheme::Https, "example.com", None, "/p"),
            "https://example.com/p"
        );
    }

    #[test]
    fn scheme_parse_case_insensitive_and_strict() {
        assert_eq!(HtuScheme::parse("HTTPS"), Some(HtuScheme::Https));
        assert_eq!(HtuScheme::parse("http"), Some(HtuScheme::Http));
        assert_eq!(HtuScheme::parse("ftp"), None);
        assert_eq!(HtuScheme::parse(""), None);
    }

    #[test]
    fn invariants_hold_conservatively() {
        for scheme in [HtuScheme::Http, HtuScheme::Https] {
            for port in [None, Some(80), Some(443), Some(8443), Some(1)] {
                for path in ["/", "/a/b", "/Token/Path"] {
                    let out = build_normalized_htu(scheme, "auth.example.com", port, path);
                    assert!(
                        invariants_hold(scheme, "auth.example.com", port, path, &out),
                        "invariants violated for {out}"
                    );
                }
            }
        }
    }
}
