use std::net::{Ipv4Addr, Ipv6Addr};

use crate::crypto::constant_time_eq;
use crate::policy::{
    dpop_authorization_accepts, metadata_profile_accepts, nonce_accepts, pkce_byte_allowed,
    pkce_length_allowed, replay_insert_accepts, saturating_elapsed, scope_policy_accepts,
    shard_index_for, state_insert_accepts, state_take_accepts, time_window_expired,
};
use crate::ssrf::{is_restricted_ipv4, is_restricted_ipv6};

/// Proves bounded OAuth-state decisions and terminal single consumption.
///
/// Domain: all Boolean state predicates. Excludes storage adapter failures. Unwind bound: 1.
#[kani::proof]
#[kani::unwind(1)]
fn state_lifecycle_is_single_use() {
    let already_present: bool = kani::any();
    let state_nonempty: bool = kani::any();
    let ttl_nonzero: bool = kani::any();
    let inserted = state_insert_accepts(already_present, state_nonempty, ttl_nonzero);
    assert_eq!(inserted, !already_present && state_nonempty && ttl_nonzero);
    kani::cover!(inserted, "pending insertion is reachable");
    kani::cover!(
        !inserted && already_present,
        "collision rejection is reachable"
    );
    kani::cover!(
        !inserted && !state_nonempty,
        "empty state rejection is reachable"
    );
    kani::cover!(!inserted && !ttl_nonzero, "zero TTL rejection is reachable");

    let present: bool = kani::any();
    let expired: bool = kani::any();
    let consumed = state_take_accepts(present, expired);
    assert_eq!(consumed, present && !expired);
    let present_after_consumption = present && !consumed;
    assert!(!consumed || !state_take_accepts(present_after_consumption, false));
    kani::cover!(consumed, "live consumption is reachable");
    kani::cover!(!consumed && !present, "absent rejection is reachable");
    kani::cover!(!consumed && expired, "expired rejection is reachable");
}

/// Proves saturating time-window decisions across all `u64` timestamps.
///
/// Domain: all `u64` times and lifetimes. Excludes wall-clock acquisition. Unwind bound: 1.
#[kani::proof]
#[kani::unwind(1)]
fn time_window_uses_saturating_elapsed() {
    let now: u64 = kani::any();
    let created_at: u64 = kani::any();
    let ttl: u64 = kani::any();
    let elapsed = saturating_elapsed(now, created_at);
    if now >= created_at {
        assert_eq!(elapsed, now - created_at);
    } else {
        assert_eq!(elapsed, 0);
    }
    assert_eq!(time_window_expired(now, created_at, ttl), elapsed >= ttl);
    kani::cover!(now < created_at && ttl > 0, "backward time is reachable");
    kani::cover!(elapsed < ttl, "live window is reachable");
    kani::cover!(elapsed >= ttl, "expired window is reachable");
}

/// Proves shard selection for every hash and bounded nonzero shard count.
///
/// Domain: all hashes and shard counts from 1 through 64. Unwind bound: 1.
#[kani::proof]
#[kani::unwind(1)]
fn shard_selection_is_total_and_in_bounds() {
    let hash_value: usize = kani::any();
    let shard_count: usize = kani::any();
    kani::assume((1..=64).contains(&shard_count));
    let selected = shard_index_for(hash_value, shard_count);
    assert!(selected < shard_count);
    kani::cover!(selected == 0, "first shard is reachable");
    kani::cover!(selected > 0, "nonzero shard is reachable");
}

/// Proves that metadata acceptance implies every profile predicate.
///
/// Domain: all combinations of fourteen profile predicates. Unwind bound: 1.
#[kani::proof]
#[kani::unwind(1)]
fn metadata_acceptance_requires_every_predicate() {
    let issuer: bool = kani::any();
    let endpoints: bool = kani::any();
    let dpop: bool = kani::any();
    let pkce: bool = kani::any();
    let code: bool = kani::any();
    let authorization_code: bool = kani::any();
    let refresh: bool = kani::any();
    let client_auth: bool = kani::any();
    let assertion_alg: bool = kani::any();
    let atproto: bool = kani::any();
    let response_iss: bool = kani::any();
    let par: bool = kani::any();
    let client_metadata: bool = kani::any();
    let request_uri_registration: bool = kani::any();
    let accepted = metadata_profile_accepts(
        issuer,
        endpoints,
        dpop,
        pkce,
        code,
        authorization_code,
        refresh,
        client_auth,
        assertion_alg,
        atproto,
        response_iss,
        par,
        client_metadata,
        request_uri_registration,
    );
    assert_eq!(
        accepted,
        issuer
            && endpoints
            && dpop
            && pkce
            && code
            && authorization_code
            && refresh
            && client_auth
            && assertion_alg
            && atproto
            && response_iss
            && par
            && client_metadata
            && request_uri_registration
    );
    kani::cover!(accepted, "metadata acceptance is reachable");
    kani::cover!(!issuer, "issuer rejection is reachable");
    kani::cover!(!endpoints, "endpoint rejection is reachable");
    kani::cover!(!dpop, "DPoP algorithm rejection is reachable");
    kani::cover!(!pkce, "PKCE rejection is reachable");
    kani::cover!(!code, "response type rejection is reachable");
    kani::cover!(
        !authorization_code,
        "authorization grant rejection is reachable"
    );
    kani::cover!(!refresh, "refresh grant rejection is reachable");
    kani::cover!(!client_auth, "client authentication rejection is reachable");
    kani::cover!(!assertion_alg, "assertion algorithm rejection is reachable");
    kani::cover!(!atproto, "mandatory scope rejection is reachable");
    kani::cover!(!response_iss, "response issuer rejection is reachable");
    kani::cover!(!par, "PAR rejection is reachable");
    kani::cover!(!client_metadata, "client metadata rejection is reachable");
    kani::cover!(
        !request_uri_registration,
        "request URI registration rejection is reachable"
    );
}

/// Proves DPoP binding and scope decisions for all bounded inputs.
///
/// Domain: all Boolean validation predicates and two four-byte binding values. Unwind bound: 5.
#[kani::proof]
#[kani::unwind(5)]
fn dpop_and_scope_acceptance_require_all_inputs() {
    let token_validated: bool = kani::any();
    let proof_validated: bool = kani::any();
    let token_binding: [u8; 4] = kani::any();
    let proof_binding: [u8; 4] = kani::any();
    let binding_equal = constant_time_eq(&token_binding, &proof_binding);
    assert_eq!(binding_equal, token_binding == proof_binding);
    let accepted = dpop_authorization_accepts(token_validated, proof_validated, binding_equal);
    assert_eq!(
        accepted,
        token_validated && proof_validated && binding_equal
    );
    kani::cover!(accepted, "bound DPoP acceptance is reachable");
    kani::cover!(!token_validated, "unvalidated token rejection is reachable");
    kani::cover!(!proof_validated, "invalid proof rejection is reachable");
    kani::cover!(!binding_equal, "binding mismatch rejection is reachable");

    let has_atproto: bool = kani::any();
    let has_all_route_scopes: bool = kani::any();
    let scope_accepted = scope_policy_accepts(has_atproto, has_all_route_scopes);
    assert_eq!(scope_accepted, has_atproto && has_all_route_scopes);
    kani::cover!(scope_accepted, "scope acceptance is reachable");
    kani::cover!(!has_atproto, "mandatory scope rejection is reachable");
    kani::cover!(
        has_atproto && !has_all_route_scopes,
        "route scope rejection is reachable"
    );
}

/// Proves replay and nonce transition behavior for all bounded state combinations.
///
/// Domain: all Boolean replay and nonce transition inputs. Unwind bound: 1.
#[kani::proof]
#[kani::unwind(1)]
fn replay_and_nonce_transitions_are_single_use() {
    let already_live: bool = kani::any();
    let capacity_available: bool = kani::any();
    let replay_accepted = replay_insert_accepts(already_live, capacity_available);
    assert_eq!(replay_accepted, !already_live && capacity_available);
    kani::cover!(replay_accepted, "first replay insertion is reachable");
    kani::cover!(
        already_live && !replay_accepted,
        "duplicate replay rejection is reachable"
    );
    kani::cover!(
        !already_live && !capacity_available && !replay_accepted,
        "capacity rejection is reachable"
    );

    let has_current: bool = kani::any();
    let presented: bool = kani::any();
    let matches: bool = kani::any();
    let require_initial: bool = kani::any();
    let nonce_accepted = nonce_accepts(has_current, presented, matches, require_initial);
    if has_current && nonce_accepted {
        assert!(presented && matches);
    }
    kani::cover!(nonce_accepted, "nonce acceptance is reachable");
    kani::cover!(
        has_current && presented && !matches,
        "stale nonce rejection is reachable"
    );
    kani::cover!(
        !has_current && require_initial && !presented,
        "initial nonce challenge is reachable"
    );
}

/// Proves IPv4 and IPv6 adapters against the production classification kernel.
///
/// Domain: all IPv4 octets and all IPv6 segments. Unwind bound: 1.
#[kani::proof]
#[kani::unwind(1)]
fn special_use_ip_classification_covers_complete_addresses() {
    let a: u8 = kani::any();
    let b: u8 = kani::any();
    let c: u8 = kani::any();
    let d: u8 = kani::any();
    let ipv4 = Ipv4Addr::new(a, b, c, d);
    let restricted_v4 = is_restricted_ipv4(&ipv4);
    kani::cover!(restricted_v4, "restricted IPv4 is reachable");
    kani::cover!(!restricted_v4, "public IPv4 is reachable");
    assert!(a != 10 || restricted_v4);
    assert!(a != 127 || restricted_v4);
    assert!(!(a == 192 && b == 168) || restricted_v4);

    let s0: u16 = kani::any();
    let s1: u16 = kani::any();
    let s2: u16 = kani::any();
    let s3: u16 = kani::any();
    let s4: u16 = kani::any();
    let s5: u16 = kani::any();
    let s6: u16 = kani::any();
    let s7: u16 = kani::any();
    let ipv6 = Ipv6Addr::new(s0, s1, s2, s3, s4, s5, s6, s7);
    let restricted_v6 = is_restricted_ipv6(&ipv6);
    kani::cover!(restricted_v6, "restricted IPv6 is reachable");
    kani::cover!(!restricted_v6, "public IPv6 is reachable");
    assert!(!(s0 >= 0xfc00 && s0 <= 0xfdff) || restricted_v6);
    assert!(!(s0 >= 0xfe80 && s0 <= 0xfebf) || restricted_v6);
    assert!(s0 < 0xff00 || restricted_v6);
}

/// Proves PKCE byte and length boundaries for all primitive inputs.
///
/// Domain: every byte and lengths from 0 through 160. Excludes SHA-256 properties. Unwind bound: 1.
#[kani::proof]
#[kani::unwind(1)]
fn pkce_boundaries_are_exact() {
    let byte: u8 = kani::any();
    let allowed = pkce_byte_allowed(byte);
    let expected = byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~');
    assert_eq!(allowed, expected);
    kani::cover!(allowed, "allowed PKCE byte is reachable");
    kani::cover!(!allowed, "rejected PKCE byte is reachable");

    let len: usize = kani::any();
    kani::assume(len <= 160);
    assert_eq!(pkce_length_allowed(len), (43..=128).contains(&len));
    kani::cover!(
        pkce_length_allowed(len),
        "accepted PKCE length is reachable"
    );
    kani::cover!(len < 43, "short PKCE rejection is reachable");
    kani::cover!(len > 128, "long PKCE rejection is reachable");
}

/// Deliberately false binding claim used only by the mutation gate.
#[cfg(feature = "proof-mutations")]
#[kani::proof]
#[kani::unwind(1)]
fn mutation_dpop_binding_is_ignored() {
    let token_binding: bool = kani::any();
    let proof_binding: bool = kani::any();
    assert!(dpop_authorization_accepts(
        true,
        true,
        token_binding == proof_binding
    ));
}
