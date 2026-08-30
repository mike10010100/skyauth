/// Returns whether DPoP authorization prerequisites all hold.
#[must_use]
#[cfg_attr(verus_keep_ghost, verus_verify(dual_spec))]
#[cfg_attr(
    verus_keep_ghost,
    verus_spec(returns token_validated && proof_validated && binding_equal)
)]
pub const fn dpop_authorization_accepts(
    token_validated: bool,
    proof_validated: bool,
    binding_equal: bool,
) -> bool {
    token_validated && proof_validated && binding_equal
}

/// Returns whether a state insertion may create a pending entry.
#[must_use]
#[cfg_attr(verus_keep_ghost, verus_verify(dual_spec))]
#[cfg_attr(
    verus_keep_ghost,
    verus_spec(returns !already_present && state_nonempty && ttl_nonzero)
)]
pub const fn state_insert_accepts(
    already_present: bool,
    state_nonempty: bool,
    ttl_nonzero: bool,
) -> bool {
    !already_present && state_nonempty && ttl_nonzero
}

/// Returns whether an existing state entry may be consumed.
#[must_use]
#[cfg_attr(verus_keep_ghost, verus_verify(dual_spec))]
#[cfg_attr(verus_keep_ghost, verus_spec(returns present && !expired))]
pub const fn state_take_accepts(present: bool, expired: bool) -> bool {
    present && !expired
}

/// Returns whether a replay identifier can be inserted atomically.
#[must_use]
#[cfg_attr(verus_keep_ghost, verus_verify(dual_spec))]
#[cfg_attr(
    verus_keep_ghost,
    verus_spec(returns !already_live && capacity_available)
)]
pub const fn replay_insert_accepts(already_live: bool, capacity_available: bool) -> bool {
    !already_live && capacity_available
}

/// Returns whether a presented nonce satisfies current nonce state.
#[must_use]
#[cfg_attr(verus_keep_ghost, verus_verify(dual_spec))]
#[cfg_attr(
    verus_keep_ghost,
    verus_spec(returns
        if has_current_nonce {
            presented_nonce && nonce_matches
        } else {
            !require_initial_nonce && !presented_nonce
        }
    )
)]
pub const fn nonce_accepts(
    has_current_nonce: bool,
    presented_nonce: bool,
    nonce_matches: bool,
    require_initial_nonce: bool,
) -> bool {
    if has_current_nonce {
        presented_nonce && nonce_matches
    } else {
        !require_initial_nonce && !presented_nonce
    }
}

/// Computes elapsed logical time without underflow.
#[must_use]
#[cfg_attr(verus_keep_ghost, verus_verify(dual_spec))]
#[cfg_attr(
    verus_keep_ghost,
    verus_spec(returns if now >= earlier { (now - earlier) as u64 } else { 0u64 })
)]
pub const fn saturating_elapsed(now: u64, earlier: u64) -> u64 {
    now.saturating_sub(earlier)
}

/// Returns whether a logical lifetime has elapsed.
#[must_use]
#[cfg_attr(verus_keep_ghost, verus_verify(dual_spec))]
#[cfg_attr(
    verus_keep_ghost,
    verus_spec(returns saturating_elapsed(now, created_at) >= ttl)
)]
pub const fn time_window_expired(now: u64, created_at: u64, ttl: u64) -> bool {
    saturating_elapsed(now, created_at) >= ttl
}

/// Maps a hash to one shard, returning zero for an unusable shard count.
#[must_use]
#[cfg_attr(verus_keep_ghost, verus_verify(dual_spec))]
#[cfg_attr(
    verus_keep_ghost,
    verus_spec(
        requires shard_count > 0,
        returns hash_value % shard_count
    )
)]
pub const fn shard_index_for(hash_value: usize, shard_count: usize) -> usize {
    if shard_count == 0 {
        0
    } else {
        hash_value % shard_count
    }
}

/// Returns whether every mandatory metadata predicate holds.
#[must_use]
#[allow(clippy::too_many_arguments)]
#[cfg_attr(verus_keep_ghost, verus_verify(dual_spec))]
#[cfg_attr(
    verus_keep_ghost,
    verus_spec(returns
        issuer_matches
            && endpoints_valid
            && dpop_es256
            && pkce_s256
            && response_code
            && authorization_code_grant
            && refresh_grant
            && client_auth_methods
            && client_assertion_es256
            && atproto_scope
            && authorization_response_iss
            && par_required
            && client_id_metadata_supported
            && request_uri_registration_required
    )
)]
pub const fn metadata_profile_accepts(
    issuer_matches: bool,
    endpoints_valid: bool,
    dpop_es256: bool,
    pkce_s256: bool,
    response_code: bool,
    authorization_code_grant: bool,
    refresh_grant: bool,
    client_auth_methods: bool,
    client_assertion_es256: bool,
    atproto_scope: bool,
    authorization_response_iss: bool,
    par_required: bool,
    client_id_metadata_supported: bool,
    request_uri_registration_required: bool,
) -> bool {
    issuer_matches
        && endpoints_valid
        && dpop_es256
        && pkce_s256
        && response_code
        && authorization_code_grant
        && refresh_grant
        && client_auth_methods
        && client_assertion_es256
        && atproto_scope
        && authorization_response_iss
        && par_required
        && client_id_metadata_supported
        && request_uri_registration_required
}

/// Returns whether the mandatory and route-specific scopes are present.
#[must_use]
#[cfg_attr(verus_keep_ghost, verus_verify(dual_spec))]
#[cfg_attr(
    verus_keep_ghost,
    verus_spec(returns has_atproto && has_all_route_scopes)
)]
pub const fn scope_policy_accepts(has_atproto: bool, has_all_route_scopes: bool) -> bool {
    has_atproto && has_all_route_scopes
}

/// Returns whether an IPv4 address is in a denied special-use range.
#[must_use]
#[allow(clippy::many_single_char_names)]
#[cfg_attr(verus_keep_ghost, verus_verify(dual_spec))]
#[cfg_attr(verus_keep_ghost, verus_spec(returns
    a == 0
        || a == 10
        || (a == 100 && b >= 64 && b <= 127)
        || a == 127
        || (a == 169 && b == 254)
        || (a == 172 && b >= 16 && b <= 31)
        || (a == 192 && b == 0 && ((c == 0 && d != 9 && d != 10) || c == 2))
        || (a == 192 && b == 31 && c == 196)
        || (a == 192 && b == 52 && c == 193)
        || (a == 192 && b == 88 && c == 99)
        || (a == 192 && b == 168)
        || (a == 192 && b == 175 && c == 48)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || a >= 224
))]
pub const fn ipv4_is_restricted(a: u8, b: u8, c: u8, d: u8) -> bool {
    a == 0
        || a == 10
        || (a == 100 && b >= 64 && b <= 127)
        || a == 127
        || (a == 169 && b == 254)
        || (a == 172 && b >= 16 && b <= 31)
        || (a == 192 && b == 0 && ((c == 0 && d != 9 && d != 10) || c == 2))
        || (a == 192 && b == 31 && c == 196)
        || (a == 192 && b == 52 && c == 193)
        || (a == 192 && b == 88 && c == 99)
        || (a == 192 && b == 168)
        || (a == 192 && b == 175 && c == 48)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || a >= 224
}

/// Returns whether an IPv6 address is in a denied special-use range.
#[must_use]
#[allow(clippy::too_many_arguments, clippy::many_single_char_names)]
#[cfg_attr(verus_keep_ghost, verus_verify(dual_spec))]
#[cfg_attr(verus_keep_ghost, verus_spec(returns
    (a == 0 && b == 0 && c == 0 && d == 0 && e == 0 && f == 0 && g == 0 && (h == 0 || h == 1))
        || (a == 0 && b == 0 && c == 0 && d == 0 && e == 0xffff && f == 0)
        || (a == 0x0064 && b == 0xff9b && c == 0 && d == 0 && e == 0 && f == 0)
        || (a == 0x0064 && b == 0xff9b && c == 1)
        || (a == 0x0100 && b == 0 && c == 0 && d == 0)
        || (a == 0x0100 && b == 0 && c == 0 && d == 1)
        || (a == 0x2001 && b <= 0x01ff)
        || (a == 0x2001 && b == 0x0db8)
        || a == 0x2002
        || (a >= 0x3ff0 && a <= 0x3fff)
        || a == 0x5f00
        || (a == 0x2620 && b == 0x004f && c == 0x8000)
        || (a >= 0xfc00 && a <= 0xfdff)
        || (a >= 0xfe80 && a <= 0xfebf)
        || (a >= 0xfec0 && a <= 0xfeff)
        || a >= 0xff00
        || (a == 0 && b == 0 && c == 0 && d == 0 && e == 0 && f == 0xffff
            && ipv4_is_restricted((g >> 8) as u8, g as u8, (h >> 8) as u8, h as u8))
))]
pub const fn ipv6_is_restricted(
    a: u16,
    b: u16,
    c: u16,
    d: u16,
    e: u16,
    f: u16,
    g: u16,
    h: u16,
) -> bool {
    (a == 0 && b == 0 && c == 0 && d == 0 && e == 0 && f == 0 && g == 0 && (h == 0 || h == 1))
        || (a == 0 && b == 0 && c == 0 && d == 0 && e == 0xffff && f == 0)
        || (a == 0x0064 && b == 0xff9b && c == 0 && d == 0 && e == 0 && f == 0)
        || (a == 0x0064 && b == 0xff9b && c == 1)
        || (a == 0x0100 && b == 0 && c == 0 && d == 0)
        || (a == 0x0100 && b == 0 && c == 0 && d == 1)
        || (a == 0x2001 && b <= 0x01ff)
        || (a == 0x2001 && b == 0x0db8)
        || a == 0x2002
        || (a >= 0x3ff0 && a <= 0x3fff)
        || a == 0x5f00
        || (a == 0x2620 && b == 0x004f && c == 0x8000)
        || (a >= 0xfc00 && a <= 0xfdff)
        || (a >= 0xfe80 && a <= 0xfebf)
        || (a >= 0xfec0 && a <= 0xfeff)
        || a >= 0xff00
        || (a == 0
            && b == 0
            && c == 0
            && d == 0
            && e == 0
            && f == 0xffff
            && ipv4_is_restricted((g >> 8) as u8, g as u8, (h >> 8) as u8, h as u8))
}

/// Returns whether one byte is valid in a PKCE verifier.
#[must_use]
#[cfg_attr(verus_keep_ghost, verus_verify(dual_spec))]
#[cfg_attr(verus_keep_ghost, verus_spec(returns
    (byte >= b'a' && byte <= b'z')
        || (byte >= b'A' && byte <= b'Z')
        || (byte >= b'0' && byte <= b'9')
        || byte == b'-'
        || byte == b'.'
        || byte == b'_'
        || byte == b'~'
))]
pub const fn pkce_byte_allowed(byte: u8) -> bool {
    (byte >= b'a' && byte <= b'z')
        || (byte >= b'A' && byte <= b'Z')
        || (byte >= b'0' && byte <= b'9')
        || byte == b'-'
        || byte == b'.'
        || byte == b'_'
        || byte == b'~'
}

/// Returns whether a PKCE verifier length is accepted.
#[must_use]
#[cfg_attr(verus_keep_ghost, verus_verify(dual_spec))]
#[cfg_attr(verus_keep_ghost, verus_spec(returns len >= 43 && len <= 128))]
pub const fn pkce_length_allowed(len: usize) -> bool {
    len >= 43 && len <= 128
}
