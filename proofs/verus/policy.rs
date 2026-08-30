use vstd::prelude::*;

include!("../../src/policy.rs");

verus! {

proof fn dpop_acceptance_implies_all_prerequisites(
    token_validated: bool,
    proof_validated: bool,
    binding_equal: bool,
)
    ensures
        dpop_authorization_accepts(token_validated, proof_validated, binding_equal)
            ==> token_validated && proof_validated && binding_equal,
{
}

proof fn state_consumption_is_terminal(present: bool, expired: bool)
    ensures
        state_take_accepts(present, expired)
            ==> !state_take_accepts(false, expired),
{
}

proof fn expired_or_absent_state_is_never_consumed(present: bool, expired: bool)
    requires
        !present || expired,
    ensures
        !state_take_accepts(present, expired),
{
}

proof fn replay_identifier_is_accepted_at_most_once(capacity_available: bool)
    ensures
        replay_insert_accepts(false, capacity_available)
            ==> !replay_insert_accepts(true, capacity_available),
{
}

proof fn nonce_acceptance_requires_current_match(
    presented_nonce: bool,
    nonce_matches: bool,
    require_initial_nonce: bool,
)
    ensures
        nonce_accepts(true, presented_nonce, nonce_matches, require_initial_nonce)
            ==> presented_nonce && nonce_matches,
{
}

proof fn backward_time_does_not_expire_live_entry(now: u64, created_at: u64, ttl: u64)
    requires
        now < created_at,
        ttl > 0,
    ensures
        !time_window_expired(now, created_at, ttl),
{
}

proof fn elapsed_ttl_is_expired(now: u64, created_at: u64, ttl: u64)
    requires
        now >= created_at,
        now - created_at >= ttl,
    ensures
        time_window_expired(now, created_at, ttl),
{
}

proof fn shard_selection_is_in_bounds(hash_value: usize, shard_count: usize)
    requires
        shard_count > 0,
    ensures
        shard_index_for(hash_value, shard_count) < shard_count,
{
}

proof fn accepted_metadata_has_every_required_predicate(
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
)
    ensures
        metadata_profile_accepts(
            issuer_matches,
            endpoints_valid,
            dpop_es256,
            pkce_s256,
            response_code,
            authorization_code_grant,
            refresh_grant,
            client_auth_methods,
            client_assertion_es256,
            atproto_scope,
            authorization_response_iss,
            par_required,
            client_id_metadata_supported,
            request_uri_registration_required,
        ) ==> issuer_matches
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
            && request_uri_registration_required,
{
}

proof fn accepted_scope_has_mandatory_and_route_permissions(
    has_atproto: bool,
    has_all_route_scopes: bool,
)
    ensures
        scope_policy_accepts(has_atproto, has_all_route_scopes)
            ==> has_atproto && has_all_route_scopes,
{
}

proof fn every_private_ipv4_range_is_rejected(a: u8, b: u8, c: u8, d: u8)
    ensures
        (a == 10
            || (a == 172 && b >= 16 && b <= 31)
            || (a == 192 && b == 168)
            || (a == 100 && b >= 64 && b <= 127))
            ==> ipv4_is_restricted(a, b, c, d),
{
}

proof fn every_selected_ipv6_prefix_is_rejected(
    a: u16,
    b: u16,
    c: u16,
    d: u16,
    e: u16,
    f: u16,
    g: u16,
    h: u16,
)
    ensures
        ((a >= 0xfc00 && a <= 0xfdff)
            || (a >= 0xfe80 && a <= 0xfebf)
            || (a >= 0xfec0 && a <= 0xfeff)
            || a >= 0xff00
            || (a == 0x2001 && b == 0x0db8))
            ==> ipv6_is_restricted(a, b, c, d, e, f, g, h),
{
}

proof fn pkce_length_boundaries_are_exact(len: usize)
    ensures
        pkce_length_allowed(len) <==> len >= 43 && len <= 128,
{
}

spec fn prefix_allows(bytes: Seq<u8>, count: nat) -> bool
    recommends
        count <= bytes.len(),
    decreases count,
{
    if count == 0 {
        true
    } else {
        prefix_allows(bytes, (count - 1) as nat)
            && pkce_byte_allowed(bytes[(count - 1) as int])
    }
}

fn count_allowed_bytes(bytes: &Vec<u8>) -> (count: usize)
    ensures
        count <= bytes@.len(),
{
    let mut index = 0usize;
    let mut count = 0usize;
    while index < bytes.len()
        invariant
            index <= bytes@.len(),
            count <= index,
        decreases bytes@.len() - index,
    {
        if pkce_byte_allowed(bytes[index]) {
            count = count + 1;
        }
        index = index + 1;
    }
    count
}

fn main() {
    let values = vec![b'a', b'Z', b'0', b'-', b' '];
    let count = count_allowed_bytes(&values);
    assert(count <= values.len());
}

}
