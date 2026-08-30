use vstd::prelude::*;

include!("../../src/policy.rs");

verus! {

proof fn mutation_binding_is_not_required(
    token_validated: bool,
    proof_validated: bool,
    binding_equal: bool,
)
    ensures
        token_validated && proof_validated
            ==> dpop_authorization_accepts(token_validated, proof_validated, binding_equal),
{
}

fn main() {
}

}
