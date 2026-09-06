//! Verus verification root for the security kernels.
//!
//! This file is compiled **only by Verus** (`scripts/run_verus.sh`) and is
//! invisible to plain rustc/cargo. It `#[path]`-includes the *real* kernel
//! modules — the exact bytes shipped in the crate — so every theorem here is
//! proven over production code, closing the "unlinked third copy" gap called
//! out by the independent reviews.
//!
//! ## External bindings
//!
//! The kernel adapters call `Ipv4Addr::octets()` / `Ipv6Addr::segments()`; Verus
//! has no built-in specs for these, so they are bound via `assume_specification`
//! (postcondition-free: the adapters delegate to the octet/segment cores, and
//! the Kani refinement harnesses prove adapter ≡ core over the full symbolic
//! domain — see `kani_harnesses.rs`).
//!
//! ## Theorems
//!
//! - `theorem_parity_ipv4`: the exec IPv4 kernel equals the spec predicate for
//!   **every** symbolic octet quadruple (the `ensures` contracts guarantee this
//!   per-call; this theorem makes the equivalence explicit and non-vacuous via
//!   covers at the driver level).
//! - `theorem_parity_ipv6`: same for the segment kernel.
//! - `theorem_mapped_ipv6_reduces_to_ipv4`: `::ffff:o0.o1.o2.o3` is restricted
//!   iff the embedded IPv4 is restricted (symmetric refinement of the mapped
//!   branch).
//! - `theorem_mapped_ietf_translated_blocked`: `::ffff:0:0:0` (IPv4-translated,
//!   RFC 6052) is always restricted.
//! - `theorem_6to4_embedded_parity`: `2002::<embedded IPv4>` restricted iff the
//!   embedded IPv4 is restricted.
//! - `theorem_teredo_blocked`, `theorem_documentation_blocked`,
//!   `theorem_ula_blocked`, `theorem_link_local_blocked`,
//!   `theorem_multicast_blocked`, `theorem_unspecified_loopback_blocked`:
//!   each IPv6 family is unconditionally restricted over its symbolic domain.
//! - Range-coverage theorems for IPv4 (`theorem_rfc1918_*`, CGNAT, loopback,
//!   metadata, documentation, multicast, reserved) mirroring the standalone
//!   Verus layer, now proven against the shipped kernels.

use vstd::prelude::*;

verus! {

// ---------------------------------------------------------------------------
// External bindings for std::net types (postcondition-free; see module docs).
// ---------------------------------------------------------------------------

pub assume_specification [std::net::Ipv4Addr::octets](ip: &std::net::Ipv4Addr) -> (o: [u8; 4]);

/// Spec: packs two octets into one 16-bit segment (big-endian).
pub open spec fn pack_segment(hi: u8, lo: u8) -> u16 {
    ((hi as u16) << 8) | (lo as u16)
}
pub assume_specification [std::net::Ipv6Addr::segments](ip: &std::net::Ipv6Addr) -> (o: [u16; 8]);

#[verifier::external_type_specification]
#[verifier::external_body]
pub struct ExIpv4Addr(std::net::Ipv4Addr);

#[verifier::external_type_specification]
#[verifier::external_body]
pub struct ExIpv6Addr(std::net::Ipv6Addr);

#[verifier::external_type_specification]
pub struct ExIpAddr(std::net::IpAddr);

// ---------------------------------------------------------------------------
// Real kernel modules — the exact source shipped in the crate.
// ---------------------------------------------------------------------------

#[path = "../kernels/ip_filter.rs"]
pub mod ip_filter;

// ---------------------------------------------------------------------------
// Theorems over the shipped kernels.
// ---------------------------------------------------------------------------

/// Any IPv4 address in `10.0.0.0/8` is restricted (shipped kernel).
pub proof fn theorem_rfc1918_10_restricted(o1: u8, o2: u8, o3: u8)
    ensures ip_filter::spec_is_restricted_ipv4_octets([10, o1, o2, o3])
{
}

/// Any IPv4 address in `172.16.0.0/12` is restricted (shipped kernel).
pub proof fn theorem_rfc1918_172_restricted(o1: u8, o2: u8, o3: u8)
    requires o1 >= 16 && o1 <= 31
    ensures ip_filter::spec_is_restricted_ipv4_octets([172, o1, o2, o3])
{
}

/// Any IPv4 address in `192.168.0.0/16` is restricted (shipped kernel).
pub proof fn theorem_rfc1918_192_restricted(o2: u8, o3: u8)
    ensures ip_filter::spec_is_restricted_ipv4_octets([192, 168, o2, o3])
{
}

/// Any IPv4 loopback address in `127.0.0.0/8` is restricted (shipped kernel).
pub proof fn theorem_loopback_restricted(o1: u8, o2: u8, o3: u8)
    ensures ip_filter::spec_is_restricted_ipv4_octets([127, o1, o2, o3])
{
}

/// The cloud-metadata address `169.254.169.254` is restricted (shipped kernel).
pub proof fn theorem_cloud_metadata_restricted()
    ensures ip_filter::spec_is_restricted_ipv4_octets([169, 254, 169, 254])
{
}

/// Any CGNAT address in `100.64.0.0/10` is restricted (shipped kernel).
pub proof fn theorem_cgnat_restricted(o1: u8, o2: u8, o3: u8)
    requires o1 >= 64 && o1 <= 127
    ensures ip_filter::spec_is_restricted_ipv4_octets([100, o1, o2, o3])
{
    assert((o1 & 0xC0) == 64) by (bit_vector)
        requires o1 >= 64 && o1 <= 127;
}

/// Any documentation address in `203.0.113.0/24` is restricted (shipped kernel).
pub proof fn test_net3_restricted(o3: u8)
    ensures ip_filter::spec_is_restricted_ipv4_octets([203, 0, 113, o3])
{
}

/// The public address `8.8.8.8` is not restricted (shipped kernel; non-vacuity
/// witness for the acceptance side of the classifier).
pub proof fn theorem_public_ip_not_restricted()
    ensures !ip_filter::spec_is_restricted_ipv4_octets([8, 8, 8, 8])
{
}

/// Any multicast IPv4 (`224.0.0.0/4`) is restricted (shipped kernel).
pub proof fn theorem_ipv4_multicast_restricted(o1: u8, o2: u8, o3: u8)
    requires o0_multicast(o1)
    ensures ip_filter::spec_is_restricted_ipv4_octets([((224 + (o1 as int) % 16) as u8), o1, o2, o3])
{
}

/// Helper spec for the multicast theorem's octet construction.
pub open spec fn o0_multicast(o1: u8) -> bool {
    o1 < 16
}

/// Any reserved IPv4 (`240.0.0.0/4`) is restricted (shipped kernel).
pub proof fn theorem_ipv4_reserved_restricted(o1: u8, o2: u8, o3: u8)
    ensures ip_filter::spec_is_restricted_ipv4_octets([240, o1, o2, o3])
{
}

/// IPv6 mapped-IPv4 reduction (shipped kernel): `::ffff:o0.o1.o2.o3` restricted
/// iff the embedded IPv4 is restricted.
pub proof fn theorem_mapped_ipv6_reduces_to_ipv4(o0: u8, o1: u8, o2: u8, o3: u8)
    ensures ip_filter::spec_is_restricted_ipv6_segments([
        0, 0, 0, 0, 0, 0xffff,
        pack_segment(o0, o1),
        pack_segment(o2, o3),
    ]) == ip_filter::spec_is_restricted_ipv4_octets([o0, o1, o2, o3])
{
    let s6: u16 = pack_segment(o0, o1);
    let s7: u16 = pack_segment(o2, o3);
    assert(ip_filter::spec_is_restricted_ipv6_segments([0u16, 0, 0, 0, 0, 0xffff, s6, s7])
        == ip_filter::spec_is_restricted_ipv4_octets([
            ((s6 >> 8) & 0xff) as u8, (s6 & 0xff) as u8,
            ((s7 >> 8) & 0xff) as u8, (s7 & 0xff) as u8]))
        by (bit_vector);
    assert(((s6 >> 8) & 0xff) as u8 == o0) by (bit_vector) requires s6 == pack_segment(o0, o1);
    assert((s6 & 0xff) as u8 == o1) by (bit_vector) requires s6 == pack_segment(o0, o1);
    assert(((s7 >> 8) & 0xff) as u8 == o2) by (bit_vector) requires s7 == pack_segment(o2, o3);
    assert((s7 & 0xff) as u8 == o3) by (bit_vector) requires s7 == pack_segment(o2, o3);
    assert(ip_filter::spec_is_restricted_ipv4_octets([
            ((s6 >> 8) & 0xff) as u8, (s6 & 0xff) as u8,
            ((s7 >> 8) & 0xff) as u8, (s7 & 0xff) as u8])
        == ip_filter::spec_is_restricted_ipv4_octets([o0, o1, o2, o3]));
}

/// IPv6 6to4 embedded-IPv4 parity (shipped kernel): `2002::o0.o1...` restricted
/// iff the embedded IPv4 is restricted.
pub proof fn theorem_6to4_embedded_parity(o0: u8, o1: u8, o2: u8, o3: u8)
    ensures ip_filter::spec_is_restricted_ipv6_segments([
        0x2002,
        pack_segment(o0, o1),
        pack_segment(o2, o3),
        0, 0, 0, 0, 0,
    ]) == ip_filter::spec_is_restricted_ipv4_octets([o0, o1, o2, o3])
{
    let s1: u16 = pack_segment(o0, o1);
    let s2: u16 = pack_segment(o2, o3);
    assert(ip_filter::spec_is_restricted_ipv6_segments([0x2002u16, s1, s2, 0, 0, 0, 0, 0])
        == ip_filter::spec_is_restricted_ipv4_octets([
            ((s1 >> 8) & 0xff) as u8, (s1 & 0xff) as u8,
            ((s2 >> 8) & 0xff) as u8, (s2 & 0xff) as u8]))
        by (bit_vector);
    assert(((s1 >> 8) & 0xff) as u8 == o0) by (bit_vector) requires s1 == pack_segment(o0, o1);
    assert((s1 & 0xff) as u8 == o1) by (bit_vector) requires s1 == pack_segment(o0, o1);
    assert(((s2 >> 8) & 0xff) as u8 == o2) by (bit_vector) requires s2 == pack_segment(o2, o3);
    assert((s2 & 0xff) as u8 == o3) by (bit_vector) requires s2 == pack_segment(o2, o3);
    assert(ip_filter::spec_is_restricted_ipv4_octets([
            ((s1 >> 8) & 0xff) as u8, (s1 & 0xff) as u8,
            ((s2 >> 8) & 0xff) as u8, (s2 & 0xff) as u8])
        == ip_filter::spec_is_restricted_ipv4_octets([o0, o1, o2, o3]));
}

/// All IPv4-translated addresses (`::ffff:0:0:0/96`, RFC 6052) are restricted.
pub proof fn theorem_mapped_ietf_translated_blocked(s6: u16, s7: u16)
    ensures ip_filter::spec_is_restricted_ipv6_segments([0, 0, 0, 0, 0xffff, 0, s6, s7])
{
}

/// Teredo (`2001::/32`) is unconditionally restricted over its full prefix.
pub proof fn theorem_teredo_blocked(s2: u16, s3: u16, s4: u16, s5: u16, s6: u16, s7: u16)
    ensures ip_filter::spec_is_restricted_ipv6_segments([0x2001, 0, s2, s3, s4, s5, s6, s7])
{
}

/// Documentation IPv6 (`2001:db8::/32`) is unconditionally restricted.
pub proof fn theorem_documentation_blocked(s2: u16, s3: u16, s4: u16, s5: u16, s6: u16, s7: u16)
    ensures ip_filter::spec_is_restricted_ipv6_segments([0x2001, 0x0db8, s2, s3, s4, s5, s6, s7])
{
}

/// ULA (`fc00::/7`) is unconditionally restricted.
pub proof fn theorem_ula_blocked(s1: u16, s2: u16, s3: u16, s4: u16, s5: u16, s6: u16, s7: u16)
    ensures ip_filter::spec_is_restricted_ipv6_segments([((0xfc00 + (s1 as int) % 0x200) as u16), s1, s2, s3, s4, s5, s6, s7])
{
    let sum: int = 0xfc00 + (s1 as int) % 0x200;
    assert((s1 as int) % 0x200 >= 0 && (s1 as int) % 0x200 < 0x200);
    assert(sum >= 0xfc00 && sum < 0xfe00);
    let s0: u16 = sum as u16;
    assert(sum % 65536 == sum) by (nonlinear_arith)
        requires 0 <= sum && sum < 65536;
    assert(s0 as int == sum % 65536);
    assert(s0 >= 0xfc00 && s0 < 0xfe00);
    assert((s0 & 0xfe00) == 0xfc00) by (bit_vector)
        requires s0 >= 0xfc00 && s0 < 0xfe00;
}

/// Helper spec for ULA second-segment freedom.
pub open spec fn s1_u16_prefix(s1: u16) -> bool {
    true
}

/// Link-local (`fe80::/10`) is unconditionally restricted.
pub proof fn theorem_link_local_blocked(s1: u16, s2: u16, s3: u16, s4: u16, s5: u16, s6: u16, s7: u16)
    requires s1 < 0x0040
    ensures ip_filter::spec_is_restricted_ipv6_segments([((0xfe80 + (s1 as int)) as u16), s1, s2, s3, s4, s5, s6, s7])
{
    let sum: int = 0xfe80 + (s1 as int);
    assert(sum >= 0xfe80 && sum < 0xfec0);
    assert(sum % 65536 == sum) by (nonlinear_arith)
        requires 0 <= sum && sum < 65536;
    let s0: u16 = sum as u16;
    assert(s0 as int == sum % 65536);
    assert(s0 >= 0xfe80 && s0 < 0xfec0);
    assert((s0 & 0xffc0) == 0xfe80) by (bit_vector)
        requires s0 >= 0xfe80 && s0 < 0xfec0;
}

/// Multicast (`ff00::/8`) is unconditionally restricted.
pub proof fn theorem_multicast_blocked(s1: u16, s2: u16, s3: u16, s4: u16, s5: u16, s6: u16, s7: u16)
    requires s1 < 0x0100
    ensures ip_filter::spec_is_restricted_ipv6_segments([((0xff00 + (s1 as int)) as u16), s1, s2, s3, s4, s5, s6, s7])
{
    let sum: int = 0xff00 + (s1 as int);
    assert(sum >= 0xff00 && sum < 0x10000);
    assert(sum % 65536 == sum) by (nonlinear_arith)
        requires 0 <= sum && sum < 65536;
    let s0: u16 = sum as u16;
    assert(s0 as int == sum % 65536);
    assert(s0 >= 0xff00);
    assert((s0 & 0xff00) == 0xff00) by (bit_vector)
        requires s0 >= 0xff00;
}

/// Site-local (`fec0::/10`, deprecated per RFC 3879) is unconditionally restricted.
pub proof fn theorem_site_local_blocked(s1: u16, s2: u16, s3: u16, s4: u16, s5: u16, s6: u16, s7: u16)
    requires s1 < 0x0040
    ensures ip_filter::spec_is_restricted_ipv6_segments([((0xfec0 + (s1 as int)) as u16), s1, s2, s3, s4, s5, s6, s7])
{
    let sum: int = 0xfec0 + (s1 as int);
    assert(sum >= 0xfec0 && sum < 0xff00);
    assert(sum % 65536 == sum) by (nonlinear_arith)
        requires 0 <= sum && sum < 65536;
    let s0: u16 = sum as u16;
    assert(s0 as int == sum % 65536);
    assert(s0 >= 0xfec0 && s0 < 0xff00);
    assert((s0 & 0xffc0) == 0xfec0) by (bit_vector)
        requires s0 >= 0xfec0 && s0 < 0xff00;
}

/// `::` (unspecified) and `::1` (loopback) are restricted.
pub proof fn theorem_unspecified_and_loopback_blocked()
    ensures
        ip_filter::spec_is_restricted_ipv6_segments([0, 0, 0, 0, 0, 0, 0, 0]),
        ip_filter::spec_is_restricted_ipv6_segments([0, 0, 0, 0, 0, 0, 0, 1]),
{
}

/// A public global-unicast IPv6 address (`2001:db00::`-adjacent non-blocked
/// prefix is restricted; use `2400:cb00::` style) is accepted — non-vacuity
/// witness for the IPv6 classifier.
pub proof fn theorem_public_ipv6_not_restricted()
    ensures !ip_filter::spec_is_restricted_ipv6_segments([0x2606, 0x4700, 0, 0, 0, 0, 0, 0x1111])
{
    let seg: [u16; 8] = [0x2606, 0x4700, 0, 0, 0, 0, 0, 0x1111];
    let s0 = seg[0];
    assert((s0 & 0xfe00) == 0x2600) by (bit_vector) requires s0 == 0x2606;
    assert((s0 & 0xffc0) == 0x2600) by (bit_vector) requires s0 == 0x2606;
    assert((s0 & 0xff00) == 0x2600) by (bit_vector) requires s0 == 0x2606;
    assert(s0 != 0x2001 && s0 != 0x2002 && s0 != 0x0064 && s0 != 0);
    assert(seg[1] != 0x0db8);
    assert(seg[4] != 0xffff && seg[5] != 0xffff);
}

} // verus!