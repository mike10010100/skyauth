//! IPv4/IPv6 restricted-range classification kernels.
//!
//! This module uses the **dual-representation single-source pattern** (validated
//! by the Phase 2a spike, see `VERIFICATION_UPGRADE_PLAN.md`):
//!
//! - Under Verus (`cfg(verus)`/`cfg(verus_keep_ghost)`): the functions are
//!   compiled inside `verus!{}` with `ensures` postconditions checked by the
//!   Z3-backed verifier — the proofs bind to these **shipped** functions.
//! - Under plain rustc: the same function bodies compile without any Verus
//!   syntax, so the crate has no `vstd` dependency.
//!
//! The `const` octet/segment cores are the SMT-reasonable representation; the
//! `&Ipv4Addr`/`&Ipv6Addr` adapters preserve the exact production signatures
//! from `ssrf.rs` and delegate to the cores.

#[cfg(any(verus, verus_keep_ghost))]
use vstd::prelude::*;

#[cfg(any(verus, verus_keep_ghost))]
verus! {

/// Verus spec: IPv4 restricted-range predicate over the four octets.
pub open spec fn spec_is_restricted_ipv4_octets(octets: [u8; 4]) -> bool {
    let o0 = octets[0];
    let o1 = octets[1];
    let o2 = octets[2];
    o0 == 0
        || o0 == 10
        || (o0 == 100 && (o1 & 0xC0) == 64)
        || o0 == 127
        || (o0 == 169 && o1 == 254)
        || (o0 == 172 && o1 >= 16 && o1 <= 31)
        || (o0 == 192 && o1 == 0 && o2 == 0)
        || (o0 == 192 && o1 == 0 && o2 == 2)
        || (o0 == 192 && o1 == 88 && o2 == 99)
        || (o0 == 192 && o1 == 168)
        || (o0 == 198 && (o1 == 18 || o1 == 19))
        || (o0 == 198 && o1 == 51 && o2 == 100)
        || (o0 == 203 && o1 == 0 && o2 == 113)
        || (o0 >= 224 && o0 <= 239)
        || (o0 >= 240)
}

/// Verus spec: IPv6 restricted-range predicate over the eight 16-bit segments.
pub open spec fn spec_is_restricted_ipv6_segments(segments: [u16; 8]) -> bool {
    let s0 = segments[0];
    let s1 = segments[1];
    let s2 = segments[2];
    let s3 = segments[3];
    let s4 = segments[4];
    let s5 = segments[5];
    let s6 = segments[6];
    let s7 = segments[7];
    // ::/128 Unspecified
    (s0 == 0 && s1 == 0 && s2 == 0 && s3 == 0 && s4 == 0 && s5 == 0 && s6 == 0 && s7 == 0)
    // ::1/128 Loopback
    || (s0 == 0 && s1 == 0 && s2 == 0 && s3 == 0 && s4 == 0 && s5 == 0 && s6 == 0 && s7 == 1)
    // ::ffff:0:0/96 IPv4-mapped — unpack the embedded IPv4 and re-evaluate.
    || (s0 == 0 && s1 == 0 && s2 == 0 && s3 == 0 && s4 == 0 && s5 == 0xffff
        && spec_is_restricted_ipv4_octets([
            ((s6 >> 8) & 0xff) as u8,
            (s6 & 0xff) as u8,
            ((s7 >> 8) & 0xff) as u8,
            (s7 & 0xff) as u8,
        ]))
    // ::ffff:0:0:0/96 IPv4-translated (RFC 6052)
    || (s0 == 0 && s1 == 0 && s2 == 0 && s3 == 0 && s4 == 0xffff && s5 == 0)
    // 64:ff9b::/96 Well-Known translation prefix
    || (s0 == 0x0064 && s1 == 0xff9b && s2 == 0 && s3 == 0 && s4 == 0 && s5 == 0)
    // 2001:db8::/32 Documentation
    || (s0 == 0x2001 && s1 == 0x0db8)
    // 2001::/32 Teredo (embedded IPv4 is XOR-0xffff obfuscated, block wholesale)
    || (s0 == 0x2001 && s1 == 0)
    // 2002::/16 6to4 — re-evaluate the embedded IPv4.
    || (s0 == 0x2002
        && spec_is_restricted_ipv4_octets([
            ((s1 >> 8) & 0xff) as u8,
            (s1 & 0xff) as u8,
            ((s2 >> 8) & 0xff) as u8,
            (s2 & 0xff) as u8,
        ]))
    // fc00::/7 ULA
    || ((s0 & 0xfe00) == 0xfc00)
    // fe80::/10 Link-Local
    || ((s0 & 0xffc0) == 0xfe80)
    // fec0::/10 Deprecated Site-Local
    || ((s0 & 0xffc0) == 0xfec0)
    // ff00::/8 Multicast
    || ((s0 & 0xff00) == 0xff00)
}

/// Determines if an IPv4 address (given as its four octets) belongs to a
/// restricted, private, or special-purpose range.
///
/// # Filtered Ranges (RFC Compliance):
/// - `0.0.0.0/8`: Current network / broadcast ("This host") (RFC 1122)
/// - `10.0.0.0/8`: Private-Use (RFC 1918)
/// - `100.64.0.0/10`: Shared Address Space / CGNAT (RFC 6598)
/// - `127.0.0.0/8`: Loopback (RFC 1122)
/// - `169.254.0.0/16`: Link-Local, includes AWS/GCP/Azure metadata `169.254.169.254` (RFC 3927)
/// - `172.16.0.0/12`: Private-Use (RFC 1918: `172.16.0.0` - `172.31.255.255`)
/// - `192.0.0.0/24`: IETF Protocol Assignments (RFC 6890)
/// - `192.0.2.0/24`: Documentation TEST-NET-1 (RFC 5737)
/// - `192.88.99.0/24`: 6to4 Relay Anycast (RFC 7526)
/// - `192.168.0.0/16`: Private-Use (RFC 1918)
/// - `198.18.0.0/15`: Benchmarking (RFC 2544: `198.18.0.0` - `198.19.255.255`)
/// - `198.51.100.0/24`: Documentation TEST-NET-2 (RFC 5737)
/// - `203.0.113.0/24`: Documentation TEST-NET-3 (RFC 5737)
/// - `224.0.0.0/4`: Multicast (RFC 5771)
/// - `240.0.0.0/4`: Reserved / Class E, includes limited broadcast `255.255.255.255` (RFC 1112)
#[must_use]
#[inline]
pub const fn is_restricted_ipv4_octets(octets: [u8; 4]) -> (r: bool)
    ensures r == spec_is_restricted_ipv4_octets(octets)
{
    let o0 = octets[0];
    let o1 = octets[1];
    let o2 = octets[2];
    o0 == 0
        || o0 == 10
        || (o0 == 100 && (o1 & 0xC0) == 64)
        || o0 == 127
        || (o0 == 169 && o1 == 254)
        || (o0 == 172 && o1 >= 16 && o1 <= 31)
        || (o0 == 192 && o1 == 0 && o2 == 0)
        || (o0 == 192 && o1 == 0 && o2 == 2)
        || (o0 == 192 && o1 == 88 && o2 == 99)
        || (o0 == 192 && o1 == 168)
        || (o0 == 198 && (o1 == 18 || o1 == 19))
        || (o0 == 198 && o1 == 51 && o2 == 100)
        || (o0 == 203 && o1 == 0 && o2 == 113)
        || (o0 >= 224 && o0 <= 239)
        || (o0 >= 240)
}

/// Determines if an IPv6 address (given as its eight 16-bit segments) belongs to
/// a restricted, private, or special-purpose range.
///
/// # Filtered Ranges (RFC Compliance):
/// - `::/128`: Unspecified address (RFC 4291)
/// - `::1/128`: Loopback address (RFC 4291)
/// - `::ffff:0:0/96`: IPv4-mapped IPv6 (RFC 4291) — unpacked and re-evaluated via
///   [`is_restricted_ipv4_octets`]
/// - `::ffff:0:0:0/96`: IPv4-translated (RFC 6052)
/// - `64:ff9b::/96`: Well-Known IPv4/IPv6 translation prefix (RFC 6052)
/// - `2001:db8::/32`: Documentation prefix (RFC 3849)
/// - `2001::/32`: Teredo tunneling (RFC 4380, deprecated per RFC 8194), unconditionally blocked
/// - `2002::/16`: 6to4 tunneling (RFC 7526, deprecated) with embedded IPv4 re-evaluated via
///   [`is_restricted_ipv4_octets`]
/// - `fc00::/7`: Unique Local Address (ULA) (RFC 4193: `fc00::/8`, `fd00::/8`)
/// - `fe80::/10`: Link-Local Unicast (RFC 4291)
/// - `fec0::/10`: Deprecated Site-Local Unicast (RFC 3879)
/// - `ff00::/8`: Multicast (RFC 4291)
#[must_use]
#[inline]
#[allow(clippy::const_is_empty)]
pub const fn is_restricted_ipv6_segments(segments: [u16; 8]) -> (r: bool)
    ensures r == spec_is_restricted_ipv6_segments(segments)
{
    let seg = segments;
    let s0 = seg[0];
    let s1 = seg[1];
    let s2 = seg[2];
    let s3 = seg[3];
    let s4 = seg[4];
    let s5 = seg[5];
    let s6 = seg[6];
    let s7 = seg[7];

    // ::/128 Unspecified
    (s0 == 0
        && s1 == 0
        && s2 == 0
        && s3 == 0
        && s4 == 0
        && s5 == 0
        && s6 == 0
        && s7 == 0)
    // ::1/128 Loopback
    || (s0 == 0
        && s1 == 0
        && s2 == 0
        && s3 == 0
        && s4 == 0
        && s5 == 0
        && s6 == 0
        && s7 == 1)
    // ::ffff:0:0/96 IPv4-mapped — unpack the embedded IPv4 and re-evaluate.
    || (s0 == 0
        && s1 == 0
        && s2 == 0
        && s3 == 0
        && s4 == 0
        && s5 == 0xffff
        && is_restricted_ipv4_octets([
            ((s6 >> 8) & 0xff) as u8,
            (s6 & 0xff) as u8,
            ((s7 >> 8) & 0xff) as u8,
            (s7 & 0xff) as u8,
        ]))
    // ::ffff:0:0:0/96 IPv4-translated (RFC 6052)
    || (s0 == 0
        && s1 == 0
        && s2 == 0
        && s3 == 0
        && s4 == 0xffff
        && s5 == 0)
    // 64:ff9b::/96 Well-Known translation prefix
    || (s0 == 0x0064
        && s1 == 0xff9b
        && s2 == 0
        && s3 == 0
        && s4 == 0
        && s5 == 0)
    // 2001:db8::/32 Documentation
    || (s0 == 0x2001 && s1 == 0x0db8)
    // 2001::/32 Teredo (embedded IPv4 is XOR-0xffff obfuscated, block wholesale)
    || (s0 == 0x2001 && s1 == 0)
    // 2002::/16 6to4 — re-evaluate the embedded IPv4.
    || (s0 == 0x2002
        && is_restricted_ipv4_octets([
            ((s1 >> 8) & 0xff) as u8,
            (s1 & 0xff) as u8,
            ((s2 >> 8) & 0xff) as u8,
            (s2 & 0xff) as u8,
        ]))
    // fc00::/7 ULA
    || ((s0 & 0xfe00) == 0xfc00)
    // fe80::/10 Link-Local
    || ((s0 & 0xffc0) == 0xfe80)
    // fec0::/10 Deprecated Site-Local
    || ((s0 & 0xffc0) == 0xfec0)
    // ff00::/8 Multicast
    || ((s0 & 0xff00) == 0xff00)
}

} // verus!

#[cfg(not(any(verus, verus_keep_ghost)))]
mod plain {

    /// Determines if an IPv4 address (given as its four octets) belongs to a
    /// restricted, private, or special-purpose range.
    ///
    /// Plain-rustc twin of the Verus-verified core; the two branches must be kept
    /// textually identical in their executable statements.
    ///
    /// # Filtered Ranges (RFC Compliance):
    /// - `0.0.0.0/8`: Current network / broadcast ("This host") (RFC 1122)
    /// - `10.0.0.0/8`: Private-Use (RFC 1918)
    /// - `100.64.0.0/10`: Shared Address Space / CGNAT (RFC 6598)
    /// - `127.0.0.0/8`: Loopback (RFC 1122)
    /// - `169.254.0.0/16`: Link-Local, includes AWS/GCP/Azure metadata `169.254.169.254` (RFC 3927)
    /// - `172.16.0.0/12`: Private-Use (RFC 1918: `172.16.0.0` - `172.31.255.255`)
    /// - `192.0.0.0/24`: IETF Protocol Assignments (RFC 6890)
    /// - `192.0.2.0/24`: Documentation TEST-NET-1 (RFC 5737)
    /// - `192.88.99.0/24`: 6to4 Relay Anycast (RFC 7526)
    /// - `192.168.0.0/16`: Private-Use (RFC 1918)
    /// - `198.18.0.0/15`: Benchmarking (RFC 2544: `198.18.0.0` - `198.19.255.255`)
    /// - `198.51.100.0/24`: Documentation TEST-NET-2 (RFC 5737)
    /// - `203.0.113.0/24`: Documentation TEST-NET-3 (RFC 5737)
    /// - `224.0.0.0/4`: Multicast (RFC 5771)
    /// - `240.0.0.0/4`: Reserved / Class E, includes limited broadcast `255.255.255.255` (RFC 1112)
    #[must_use]
    #[inline]
    pub const fn is_restricted_ipv4_octets(octets: [u8; 4]) -> bool {
        let o0 = octets[0];
        let o1 = octets[1];
        let o2 = octets[2];
        o0 == 0
            || o0 == 10
            || (o0 == 100 && (o1 & 0xC0) == 64)
            || o0 == 127
            || (o0 == 169 && o1 == 254)
            || (o0 == 172 && o1 >= 16 && o1 <= 31)
            || (o0 == 192 && o1 == 0 && o2 == 0)
            || (o0 == 192 && o1 == 0 && o2 == 2)
            || (o0 == 192 && o1 == 88 && o2 == 99)
            || (o0 == 192 && o1 == 168)
            || (o0 == 198 && (o1 == 18 || o1 == 19))
            || (o0 == 198 && o1 == 51 && o2 == 100)
            || (o0 == 203 && o1 == 0 && o2 == 113)
            || (o0 >= 224 && o0 <= 239)
            || (o0 >= 240)
    }

    /// Determines if an IPv6 address (given as its eight 16-bit segments) belongs to
    /// a restricted, private, or special-purpose range.
    ///
    /// Plain-rustc twin of the Verus-verified core; the two branches must be kept
    /// textually identical in their executable statements.
    ///
    /// # Filtered Ranges (RFC Compliance):
    /// - `::/128`: Unspecified address (RFC 4291)
    /// - `::1/128`: Loopback address (RFC 4291)
    /// - `::ffff:0:0/96`: IPv4-mapped IPv6 (RFC 4291) — unpacked and re-evaluated via
    ///   [`is_restricted_ipv4_octets`]
    /// - `::ffff:0:0:0/96`: IPv4-translated (RFC 6052)
    /// - `64:ff9b::/96`: Well-Known IPv4/IPv6 translation prefix (RFC 6052)
    /// - `2001:db8::/32`: Documentation prefix (RFC 3849)
    /// - `2001::/32`: Teredo tunneling (RFC 4380, deprecated per RFC 8194), unconditionally blocked
    /// - `2002::/16`: 6to4 tunneling (RFC 7526, deprecated) with embedded IPv4 re-evaluated via
    ///   [`is_restricted_ipv4_octets`]
    /// - `fc00::/7`: Unique Local Address (ULA) (RFC 4193: `fc00::/8`, `fd00::/8`)
    /// - `fe80::/10`: Link-Local Unicast (RFC 4291)
    /// - `fec0::/10`: Deprecated Site-Local Unicast (RFC 3879)
    /// - `ff00::/8`: Multicast (RFC 4291)
    #[must_use]
    #[inline]
    pub const fn is_restricted_ipv6_segments(segments: [u16; 8]) -> bool {
        let seg = segments;
        let s0 = seg[0];
        let s1 = seg[1];
        let s2 = seg[2];
        let s3 = seg[3];
        let s4 = seg[4];
        let s5 = seg[5];
        let s6 = seg[6];
        let s7 = seg[7];

        // ::/128 Unspecified
        (s0 == 0
        && s1 == 0
        && s2 == 0
        && s3 == 0
        && s4 == 0
        && s5 == 0
        && s6 == 0
        && s7 == 0)
    // ::1/128 Loopback
    || (s0 == 0
        && s1 == 0
        && s2 == 0
        && s3 == 0
        && s4 == 0
        && s5 == 0
        && s6 == 0
        && s7 == 1)
    // ::ffff:0:0/96 IPv4-mapped — unpack the embedded IPv4 and re-evaluate.
    || (s0 == 0
        && s1 == 0
        && s2 == 0
        && s3 == 0
        && s4 == 0
        && s5 == 0xffff
        && is_restricted_ipv4_octets([
            ((s6 >> 8) & 0xff) as u8,
            (s6 & 0xff) as u8,
            ((s7 >> 8) & 0xff) as u8,
            (s7 & 0xff) as u8,
        ]))
    // ::ffff:0:0:0/96 IPv4-translated (RFC 6052)
    || (s0 == 0
        && s1 == 0
        && s2 == 0
        && s3 == 0
        && s4 == 0xffff
        && s5 == 0)
    // 64:ff9b::/96 Well-Known translation prefix
    || (s0 == 0x0064
        && s1 == 0xff9b
        && s2 == 0
        && s3 == 0
        && s4 == 0
        && s5 == 0)
    // 2001:db8::/32 Documentation
    || (s0 == 0x2001 && s1 == 0x0db8)
    // 2001::/32 Teredo (embedded IPv4 is XOR-0xffff obfuscated, block wholesale)
    || (s0 == 0x2001 && s1 == 0)
    // 2002::/16 6to4 — re-evaluate the embedded IPv4.
    || (s0 == 0x2002
        && is_restricted_ipv4_octets([
            ((s1 >> 8) & 0xff) as u8,
            (s1 & 0xff) as u8,
            ((s2 >> 8) & 0xff) as u8,
            (s2 & 0xff) as u8,
        ]))
    // fc00::/7 ULA
    || ((s0 & 0xfe00) == 0xfc00)
    // fe80::/10 Link-Local
    || ((s0 & 0xffc0) == 0xfe80)
    // fec0::/10 Deprecated Site-Local
    || ((s0 & 0xffc0) == 0xfec0)
    // ff00::/8 Multicast
    || ((s0 & 0xff00) == 0xff00)
    }
} // mod plain

#[cfg(not(any(verus, verus_keep_ghost)))]
pub use plain::{is_restricted_ipv4_octets, is_restricted_ipv6_segments};

/// Determines if an IPv4 address belongs to a restricted, private, or special-purpose range.
///
/// Adapter over [`is_restricted_ipv4_octets`] preserving the exact production
/// signature from `ssrf.rs`. The `octets()` call is bound in Verus via
/// `assume_specification` (see `verus_kernels.rs`).
///
/// # Filtered Ranges (RFC Compliance):
/// - `0.0.0.0/8`: Current network / broadcast ("This host") (RFC 1122)
/// - `10.0.0.0/8`: Private-Use (RFC 1918)
/// - `100.64.0.0/10`: Shared Address Space / CGNAT (RFC 6598)
/// - `127.0.0.0/8`: Loopback (RFC 1122)
/// - `169.254.0.0/16`: Link-Local, includes AWS/GCP/Azure metadata `169.254.169.254` (RFC 3927)
/// - `172.16.0.0/12`: Private-Use (RFC 1918: `172.16.0.0` - `172.31.255.255`)
/// - `192.0.0.0/24`: IETF Protocol Assignments (RFC 6890)
/// - `192.0.2.0/24`: Documentation TEST-NET-1 (RFC 5737)
/// - `192.88.99.0/24`: 6to4 Relay Anycast (RFC 7526)
/// - `192.168.0.0/16`: Private-Use (RFC 1918)
/// - `198.18.0.0/15`: Benchmarking (RFC 2544: `198.18.0.0` - `198.19.255.255`)
/// - `198.51.100.0/24`: Documentation TEST-NET-2 (RFC 5737)
/// - `203.0.113.0/24`: Documentation TEST-NET-3 (RFC 5737)
/// - `224.0.0.0/4`: Multicast (RFC 5771)
/// - `240.0.0.0/4`: Reserved / Class E, includes limited broadcast `255.255.255.255` (RFC 1112)
#[must_use]
#[inline]
pub fn is_restricted_ipv4(ip: &std::net::Ipv4Addr) -> bool {
    is_restricted_ipv4_octets(ip.octets())
}

/// Determines if an IPv6 address belongs to a restricted, private, or special-purpose range.
///
/// Adapter over [`is_restricted_ipv6_segments`] preserving the exact production
/// signature from `ssrf.rs`. The `segments()` call is bound in Verus via
/// `assume_specification` (see `verus_kernels.rs`).
///
/// # Filtered Ranges (RFC Compliance):
/// - `::/128`: Unspecified address (RFC 4291)
/// - `::1/128`: Loopback address (RFC 4291)
/// - `::ffff:0:0/96`: IPv4-mapped IPv6 (RFC 4291) — unpacked and re-evaluated via
///   [`is_restricted_ipv4_octets`]
/// - `::ffff:0:0:0/96`: IPv4-translated (RFC 6052)
/// - `64:ff9b::/96`: Well-Known IPv4/IPv6 translation prefix (RFC 6052)
/// - `2001:db8::/32`: Documentation prefix (RFC 3849)
/// - `2001::/32`: Teredo tunneling (RFC 4380, deprecated per RFC 8194), unconditionally blocked
/// - `2002::/16`: 6to4 tunneling (RFC 7526, deprecated) with embedded IPv4 re-evaluated via
///   [`is_restricted_ipv4_octets`]
/// - `fc00::/7`: Unique Local Address (ULA) (RFC 4193: `fc00::/8`, `fd00::/8`)
/// - `fe80::/10`: Link-Local Unicast (RFC 4291)
/// - `fec0::/10`: Deprecated Site-Local Unicast (RFC 3879)
/// - `ff00::/8`: Multicast (RFC 4291)
#[must_use]
#[inline]
pub fn is_restricted_ipv6(ip: &std::net::Ipv6Addr) -> bool {
    is_restricted_ipv6_segments(ip.segments())
}

/// Determines if an IP address (IPv4 or IPv6) belongs to a restricted/private range.
#[must_use]
#[inline]
pub fn is_restricted_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => is_restricted_ipv4(&v4),
        std::net::IpAddr::V6(v6) => is_restricted_ipv6(&v6),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn ipv4_octets_core_matches_std_adapter_exhaustively_sampled() {
        // Boundary sweep of every /8 boundary plus interior points; the
        // full 2^32 domain is covered by the Kani refinement harness.
        let mut o0 = 0u16;
        while o0 <= 255 {
            for o1 in [
                0u8, 1, 15, 16, 31, 63, 64, 100, 127, 128, 169, 191, 192, 254,
            ] {
                let ip = Ipv4Addr::new(o0 as u8, o1, 7, 9);
                assert_eq!(
                    is_restricted_ipv4(&ip),
                    is_restricted_ipv4_octets(ip.octets()),
                    "adapter/core divergence at {ip}"
                );
            }
            o0 += 1;
        }
    }

    #[test]
    fn ipv6_segments_core_matches_std_adapter_on_boundary_classes() {
        let cases: [Ipv6Addr; 12] = [
            Ipv6Addr::UNSPECIFIED,
            Ipv6Addr::LOCALHOST,
            Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x0a00, 0x0001),
            Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x0808, 0x0808),
            Ipv6Addr::new(0, 0, 0, 0, 0xffff, 0, 0, 0),
            Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0x2001, 0, 0xdead, 0xbeef, 0, 0, 0, 1),
            Ipv6Addr::new(0x2002, 0x0a00, 0x0001, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0x2002, 0x0808, 0x0808, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
        ];
        for ip in &cases {
            assert_eq!(
                is_restricted_ipv6(ip),
                is_restricted_ipv6_segments(ip.segments()),
                "adapter/core divergence at {ip}"
            );
        }
    }

    #[test]
    fn ipv6_mapped_embedded_ipv4_matches_ipv4_core() {
        for o0 in [0u8, 10, 127, 169, 172, 192, 8] {
            for o1 in [0u8, 0, 254, 16, 168, 8] {
                let mapped = Ipv4Addr::new(o0, o1, 3, 4).to_ipv6_mapped();
                assert_eq!(
                    is_restricted_ipv6(&mapped),
                    is_restricted_ipv4_octets([o0, o1, 3, 4]),
                    "mapped/embedded divergence for {o0}.{o1}.3.4"
                );
            }
        }
    }

    #[test]
    fn dispatch_kernel_matches_component_kernels() {
        assert!(is_restricted_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(is_restricted_ip(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(!is_restricted_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(!is_restricted_ip(IpAddr::V6(Ipv6Addr::new(
            0x2606, 0x4700, 0, 0, 0, 0, 0, 0x1111
        ))));
    }
}
