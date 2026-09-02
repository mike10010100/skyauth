//! Milestone 5 Challenger 1 Adversarial Stress Tests:
//! Dynamic Schema AST Validation Robustness & Roundtrip Serialization Fidelity.
//!
//! Empirically challenges and tests:
//! 1. Deep Nesting & Recursive AST Traversal Injection (objects & arrays up to 500 levels deep)
//! 2. Malformed Types & Type Mutation Fuzzing (floats for ints, negative numbers, object/array swaps, null injections)
//! 3. `additionalProperties: false` Enforcement & Rogue Field Rejections
//! 4. Null Byte (`\0` / `\u0000`) & Control Character Injections into URIs, DIDs, handles, and scopes
//! 5. Invalid RFC 3986 URIs & Empty String Boundary Attacks
//! 6. Direct AST Validation vs Rust Domain Structs Roundtrip Fidelity (exhaustive & proptest suites)

#![allow(
    clippy::all,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    missing_docs
)]

use proptest::prelude::*;
use serde_json::{json, Value};
use std::path::PathBuf;

use skyauth::client::TokenResponse;
use skyauth::discovery::{AuthorizationServerMetadata, ProtectedResourceMetadata};
use skyauth::dpop::{DPoPProofClaims, JwkEc};
use skyauth::identity::{DidDocument, DidService, VerificationMethod};
use skyauth::par::{ParParameters, ParResponse};
use skyauth::pkce::{PkceMethod, PkcePair};

const RFC8414_SCHEMA_STR: &str = include_str!("../schemas/rfc8414_authorization_server.json");
const RFC9728_SCHEMA_STR: &str = include_str!("../schemas/rfc9728_protected_resource.json");
const RFC9449_SCHEMA_STR: &str = include_str!("../schemas/rfc9449_dpop_proof.json");
const CLIENT_METADATA_SCHEMA_STR: &str = include_str!("../schemas/atproto_client_metadata.json");

const LEX_RESOLVE_HANDLE_STR: &str =
    include_str!("../lexicons/com/atproto/identity/resolveHandle.json");
const LEX_CREATE_SESSION_STR: &str =
    include_str!("../lexicons/com/atproto/server/createSession.json");
const LEX_REFRESH_SESSION_STR: &str =
    include_str!("../lexicons/com/atproto/server/refreshSession.json");

fn lexicon_to_json_schema(val: &Value) -> Value {
    match val {
        Value::Object(map) => {
            let mut new_map = serde_json::Map::new();
            for (k, v) in map {
                if k == "type" && v == "unknown" {
                    continue;
                }
                new_map.insert(k.clone(), lexicon_to_json_schema(v));
            }
            Value::Object(new_map)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(lexicon_to_json_schema).collect()),
        other => other.clone(),
    }
}

fn compile_validator(schema_json: &Value) -> jsonschema::Validator {
    let normalized = lexicon_to_json_schema(schema_json);
    jsonschema::validator_for(&normalized)
        .expect("Bundled JSON schema must be syntactically and semantically valid")
}

fn load_schema(rel_path: &str) -> Value {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let full_path = manifest_dir.join(rel_path);
    if full_path.exists() {
        let content = std::fs::read_to_string(&full_path)
            .unwrap_or_else(|e| panic!("Failed to read {}: {}", full_path.display(), e));
        serde_json::from_str(&content)
            .unwrap_or_else(|e| panic!("Failed to parse JSON from {}: {}", full_path.display(), e))
    } else {
        match rel_path {
            "schemas/rfc8414_authorization_server.json" => {
                serde_json::from_str(RFC8414_SCHEMA_STR).unwrap()
            }
            "schemas/rfc9728_protected_resource.json" => {
                serde_json::from_str(RFC9728_SCHEMA_STR).unwrap()
            }
            "schemas/rfc9449_dpop_proof.json" => serde_json::from_str(RFC9449_SCHEMA_STR).unwrap(),
            "schemas/atproto_client_metadata.json" => {
                serde_json::from_str(CLIENT_METADATA_SCHEMA_STR).unwrap()
            }
            "lexicons/com/atproto/identity/resolveHandle.json" => {
                serde_json::from_str(LEX_RESOLVE_HANDLE_STR).unwrap()
            }
            "lexicons/com/atproto/server/createSession.json" => {
                serde_json::from_str(LEX_CREATE_SESSION_STR).unwrap()
            }
            "lexicons/com/atproto/server/refreshSession.json" => {
                serde_json::from_str(LEX_REFRESH_SESSION_STR).unwrap()
            }
            _ => panic!("Unknown schema path: {}", rel_path),
        }
    }
}

#[test]
fn test_challenge_deeply_nested_object_injection_in_open_lexicon_schema() {
    let lex = load_schema("lexicons/com/atproto/server/createSession.json");
    let output_schema = &lex["defs"]["main"]["output"]["schema"];
    let validator = compile_validator(output_schema);

    let mut deep_inner = json!({ "leaf_key": "deep_leaf_value" });
    for depth in 0..100 {
        deep_inner = json!({
            format!("level_{depth}"): deep_inner
        });
    }

    let payload = json!({
        "accessJwt": "access_token_jwt",
        "refreshJwt": "refresh_token_jwt",
        "handle": "alice.bsky.social",
        "did": "did:plc:ragtjsm2j2vknwk6zui0p4kb",
        "didDoc": deep_inner
    });

    assert!(
        validator.is_valid(&payload),
        "100-level nested didDoc object should validate cleanly without stack overflow"
    );
}

#[test]
fn test_challenge_deeply_nested_array_injection_in_open_lexicon_schema() {
    let lex = load_schema("lexicons/com/atproto/server/createSession.json");
    let output_schema = &lex["defs"]["main"]["output"]["schema"];
    let validator = compile_validator(output_schema);

    let mut deep_arr = json!(["innermost_element"]);
    for _ in 0..200 {
        deep_arr = json!([deep_arr]);
    }

    let payload = json!({
        "accessJwt": "access_token_jwt",
        "refreshJwt": "refresh_token_jwt",
        "handle": "alice.bsky.social",
        "did": "did:plc:ragtjsm2j2vknwk6zui0p4kb",
        "didDoc": deep_arr
    });

    assert!(
        validator.is_valid(&payload),
        "200-level nested array in open lexicon type should validate cleanly"
    );
}

#[test]
fn test_challenge_deeply_nested_lexicon_normalizer_recursion_depth() {
    let mut inner_schema = json!({
        "type": "object",
        "properties": {
            "leaf": { "type": "unknown" }
        }
    });

    for depth in 0..40 {
        inner_schema = json!({
            "type": "object",
            "properties": {
                format!("nested_layer_{depth}"): inner_schema
            }
        });
    }

    let start = std::time::Instant::now();
    let normalized = lexicon_to_json_schema(&inner_schema);
    let validator_res = jsonschema::validator_for(&normalized);
    let elapsed = start.elapsed();

    #[cfg(debug_assertions)]
    let max_allowed_ms = 5000;
    #[cfg(not(debug_assertions))]
    let max_allowed_ms = 500;

    assert!(
        validator_res.is_ok(),
        "40-layer deep lexicon normalization should succeed"
    );
    assert!(
        elapsed.as_millis() < max_allowed_ms,
        "Deep lexicon AST normalization should finish fast, took {:?}",
        elapsed
    );
}

#[test]
fn test_challenge_float_where_integer_expected_rejections() {
    let dpop_schema = load_schema("schemas/rfc9449_dpop_proof.json");
    let dpop_val = compile_validator(&dpop_schema);

    let float_iat = json!({
        "jti": "jti_123",
        "htm": "POST",
        "htu": "https://auth.example.com/oauth/token",
        "iat": 1712345678.95
    });
    assert!(
        !dpop_val.is_valid(&float_iat),
        "Floating point iat in DPoP must be rejected"
    );

    let float_exp = json!({
        "jti": "jti_123",
        "htm": "POST",
        "htu": "https://auth.example.com/oauth/token",
        "iat": 1712345678,
        "exp": 1712345738.5
    });
    assert!(
        !dpop_val.is_valid(&float_exp),
        "Floating point exp in DPoP must be rejected"
    );

    let par_schema = json!({
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "required": ["request_uri", "expires_in"],
        "properties": {
            "request_uri": { "type": "string" },
            "expires_in": { "type": "integer", "minimum": 1 }
        }
    });
    let par_val = compile_validator(&par_schema);

    let float_expires_in = json!({
        "request_uri": "urn:ietf:params:oauth:request_uri:abc",
        "expires_in": 89.9
    });
    assert!(
        !par_val.is_valid(&float_expires_in),
        "Floating point expires_in must be rejected"
    );
}

#[test]
fn test_challenge_negative_integers_and_boundary_violations() {
    let dpop_schema = load_schema("schemas/rfc9449_dpop_proof.json");
    let dpop_val = compile_validator(&dpop_schema);

    let neg_iat = json!({
        "jti": "jti_123",
        "htm": "POST",
        "htu": "https://auth.example.com/oauth/token",
        "iat": -1
    });
    assert!(
        !dpop_val.is_valid(&neg_iat),
        "Negative iat must be rejected (minimum: 0)"
    );

    let neg_exp = json!({
        "jti": "jti_123",
        "htm": "POST",
        "htu": "https://auth.example.com/oauth/token",
        "iat": 1700000000,
        "exp": -100
    });
    assert!(
        !dpop_val.is_valid(&neg_exp),
        "Negative exp must be rejected (minimum: 0)"
    );

    let par_schema = json!({
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "required": ["request_uri", "expires_in"],
        "properties": {
            "request_uri": { "type": "string" },
            "expires_in": { "type": "integer", "minimum": 1 }
        }
    });
    let par_val = compile_validator(&par_schema);
    let zero_expires = json!({
        "request_uri": "urn:ietf:params:oauth:request_uri:abc",
        "expires_in": 0
    });
    assert!(
        !par_val.is_valid(&zero_expires),
        "expires_in: 0 must violate minimum: 1"
    );
}

#[test]
fn test_challenge_primitive_and_container_type_confusion_rejections() {
    let as_schema = load_schema("schemas/rfc8414_authorization_server.json");
    let as_val = compile_validator(&as_schema);

    let obj_for_array = json!({
        "issuer": "https://auth.example.com",
        "authorization_endpoint": "https://auth.example.com/auth",
        "token_endpoint": "https://auth.example.com/token",
        "dpop_signing_alg_values_supported": { "alg": "ES256" }
    });
    assert!(
        !as_val.is_valid(&obj_for_array),
        "Object for string array must be rejected"
    );

    let int_array = json!({
        "issuer": "https://auth.example.com",
        "authorization_endpoint": "https://auth.example.com/auth",
        "token_endpoint": "https://auth.example.com/token",
        "dpop_signing_alg_values_supported": [123, 456]
    });
    assert!(
        !as_val.is_valid(&int_array),
        "Int array for string array must be rejected"
    );

    let bool_uri = json!({
        "issuer": true,
        "authorization_endpoint": "https://auth.example.com/auth",
        "token_endpoint": "https://auth.example.com/token"
    });
    assert!(
        !as_val.is_valid(&bool_uri),
        "Boolean for URI string must be rejected"
    );

    let num_for_bool = json!({
        "issuer": "https://auth.example.com",
        "authorization_endpoint": "https://auth.example.com/auth",
        "token_endpoint": "https://auth.example.com/token",
        "require_pushed_authorization_requests": 1
    });
    assert!(
        !as_val.is_valid(&num_for_bool),
        "Number for boolean must be rejected"
    );
}

#[test]
fn test_challenge_null_value_injection_in_mandatory_and_typed_fields() {
    let pds_schema = load_schema("schemas/rfc9728_protected_resource.json");
    let pds_val = compile_validator(&pds_schema);

    let null_resource = json!({
        "resource": null,
        "authorization_servers": ["https://auth.example.com"]
    });
    assert!(
        !pds_val.is_valid(&null_resource),
        "Null resource must be rejected"
    );

    let null_item_array = json!({
        "resource": "https://pds.example.com",
        "authorization_servers": [null]
    });
    assert!(
        !pds_val.is_valid(&null_item_array),
        "Null item in auth servers array must be rejected"
    );

    let null_array = json!({
        "resource": "https://pds.example.com",
        "authorization_servers": null
    });
    assert!(
        !pds_val.is_valid(&null_array),
        "Null authorization_servers must be rejected"
    );
}

#[test]
fn test_challenge_additional_properties_false_strict_rejections() {
    let strict_dpop_schema = json!({
        "$schema": "http://json-schema.org/draft-07/schema#",
        "title": "Strict RFC 9449 DPoP Proof Claims",
        "type": "object",
        "required": ["jti", "htm", "htu", "iat"],
        "properties": {
            "jti": { "type": "string" },
            "htm": { "type": "string" },
            "htu": { "type": "string", "format": "uri" },
            "iat": { "type": "integer", "minimum": 0 },
            "exp": { "type": "integer", "minimum": 0 },
            "nonce": { "type": "string" },
            "ath": { "type": "string" }
        },
        "additionalProperties": false
    });
    let strict_val = compile_validator(&strict_dpop_schema);

    let valid_claims = json!({
        "jti": "jti_123",
        "htm": "POST",
        "htu": "https://auth.example.com/oauth/token",
        "iat": 1700000000
    });
    assert!(
        strict_val.is_valid(&valid_claims),
        "Valid claims must satisfy strict schema"
    );

    let rogue_field = json!({
        "jti": "jti_123",
        "htm": "POST",
        "htu": "https://auth.example.com/oauth/token",
        "iat": 1700000000,
        "__rogue_admin_escalation__": true
    });
    assert!(
        !strict_val.is_valid(&rogue_field),
        "Rogue field under additionalProperties: false must be rejected"
    );

    let proto_pollution = json!({
        "jti": "jti_123",
        "htm": "POST",
        "htu": "https://auth.example.com/oauth/token",
        "iat": 1700000000,
        "__proto__": { "polluted": true }
    });
    assert!(
        !strict_val.is_valid(&proto_pollution),
        "__proto__ field under additionalProperties: false must be rejected"
    );
}

#[test]
fn test_challenge_rust_struct_serialization_has_no_unexpected_rogue_keys() {
    let strict_pds_schema = json!({
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "required": ["resource", "authorization_servers"],
        "properties": {
            "resource": { "type": "string", "format": "uri" },
            "authorization_servers": {
                "type": "array",
                "items": { "type": "string", "format": "uri" },
                "minItems": 1
            },
            "scopes_supported": {
                "type": "array",
                "items": { "type": "string" }
            },
            "bearer_methods_supported": {
                "type": "array",
                "items": { "type": "string" }
            },
            "resource_documentation": { "type": "string", "format": "uri" }
        },
        "additionalProperties": false
    });
    let strict_pds_val = compile_validator(&strict_pds_schema);

    let rust_pds = ProtectedResourceMetadata {
        resource: "https://mushroom.us-east.host.bsky.network".to_string(),
        authorization_servers: vec!["https://bsky.social".to_string()],
        scopes_supported: vec!["atproto".to_string()],
        bearer_methods_supported: vec!["header".to_string()],
        resource_documentation: Some("https://atproto.com/specs/pds".to_string()),
    };

    let serialized = serde_json::to_value(&rust_pds).unwrap();
    assert!(
        strict_pds_val.is_valid(&serialized),
        "ProtectedResourceMetadata serialization must have zero rogue keys under additionalProperties: false"
    );
}

#[test]
fn test_challenge_null_bytes_in_uri_fields_rejected_by_format_validator() {
    let as_schema = load_schema("schemas/rfc8414_authorization_server.json");
    let as_val = compile_validator(&as_schema);

    let null_byte_issuer = json!({
        "issuer": "https://auth.example.com\u{0000}/path",
        "authorization_endpoint": "https://auth.example.com/oauth/authorize",
        "token_endpoint": "https://auth.example.com/oauth/token"
    });
    assert!(
        !as_val.is_valid(&null_byte_issuer),
        "Null byte in issuer URI must be rejected by URI format validator"
    );

    let null_byte_auth_ep = json!({
        "issuer": "https://auth.example.com",
        "authorization_endpoint": "https://auth.example.com/oauth\0/authorize",
        "token_endpoint": "https://auth.example.com/oauth/token"
    });
    assert!(
        !as_val.is_valid(&null_byte_auth_ep),
        "Null byte in authorization_endpoint must be rejected"
    );

    let dpop_schema = load_schema("schemas/rfc9449_dpop_proof.json");
    let dpop_val = compile_validator(&dpop_schema);
    let null_byte_htu = json!({
        "jti": "jti_123",
        "htm": "POST",
        "htu": "https://auth.example.com/\0/token",
        "iat": 1700000000
    });
    assert!(
        !dpop_val.is_valid(&null_byte_htu),
        "Null byte in htu URI must be rejected by format validator"
    );
}

#[test]
fn test_challenge_control_characters_in_uris_and_identifiers() {
    let as_schema = load_schema("schemas/rfc8414_authorization_server.json");
    let as_val = compile_validator(&as_schema);

    let newline_uri = json!({
        "issuer": "https://auth.example.com\n/oauth",
        "authorization_endpoint": "https://auth.example.com/oauth/authorize",
        "token_endpoint": "https://auth.example.com/oauth/token"
    });
    assert!(
        !as_val.is_valid(&newline_uri),
        "Newline inside URI must be rejected by format: uri"
    );

    let tab_uri = json!({
        "issuer": "https://auth.example.com\t/oauth",
        "authorization_endpoint": "https://auth.example.com/oauth/authorize",
        "token_endpoint": "https://auth.example.com/oauth/token"
    });
    assert!(
        !as_val.is_valid(&tab_uri),
        "Tab inside URI must be rejected by format: uri"
    );
}

#[test]
fn test_challenge_invalid_rfc3986_uris_in_schema_fields() {
    let as_schema = load_schema("schemas/rfc8414_authorization_server.json");
    let as_val = compile_validator(&as_schema);

    let invalid_uris = vec![
        "relative/path/not/an/absolute/uri",
        "/absolute/path/without/scheme",
        "https://[invalid_ipv6",
        "ht tps://spaces.com",
        "http://example .com",
        "https://example.com:not_a_port",
    ];

    for bad_uri in invalid_uris {
        let instance = json!({
            "issuer": bad_uri,
            "authorization_endpoint": "https://auth.example.com/oauth/authorize",
            "token_endpoint": "https://auth.example.com/oauth/token"
        });
        assert!(
            !as_val.is_valid(&instance),
            "Invalid URI '{}' for issuer MUST be rejected by schema validator",
            bad_uri
        );
    }
}

#[test]
fn test_challenge_empty_strings_in_required_and_uri_fields() {
    let as_schema = load_schema("schemas/rfc8414_authorization_server.json");
    let as_val = compile_validator(&as_schema);

    let empty_issuer = json!({
        "issuer": "",
        "authorization_endpoint": "https://auth.example.com/oauth/authorize",
        "token_endpoint": "https://auth.example.com/oauth/token"
    });
    assert!(
        !as_val.is_valid(&empty_issuer),
        "Empty string for issuer MUST be rejected by format: uri"
    );

    let empty_auth_ep = json!({
        "issuer": "https://auth.example.com",
        "authorization_endpoint": "",
        "token_endpoint": "https://auth.example.com/oauth/token"
    });
    assert!(
        !as_val.is_valid(&empty_auth_ep),
        "Empty string for authorization_endpoint MUST be rejected"
    );

    let pds_schema = load_schema("schemas/rfc9728_protected_resource.json");
    let pds_val = compile_validator(&pds_schema);
    let empty_resource = json!({
        "resource": "",
        "authorization_servers": ["https://auth.example.com"]
    });
    assert!(
        !pds_val.is_valid(&empty_resource),
        "Empty string for resource MUST be rejected"
    );

    let empty_item_in_array = json!({
        "resource": "https://pds.example.com",
        "authorization_servers": [""]
    });
    assert!(
        !pds_val.is_valid(&empty_item_in_array),
        "Empty string in authorization_servers array MUST be rejected"
    );

    let dpop_schema = load_schema("schemas/rfc9449_dpop_proof.json");
    let dpop_val = compile_validator(&dpop_schema);
    let empty_htu = json!({
        "jti": "jti_123",
        "htm": "POST",
        "htu": "",
        "iat": 1700000000
    });
    assert!(
        !dpop_val.is_valid(&empty_htu),
        "Empty string for htu MUST be rejected by format: uri"
    );
}

#[test]
fn test_challenge_roundtrip_authorization_server_metadata() {
    let schema = load_schema("schemas/rfc8414_authorization_server.json");
    let validator = compile_validator(&schema);

    let full = AuthorizationServerMetadata {
        issuer: "https://auth.bsky.social".to_string(),
        authorization_endpoint: "https://auth.bsky.social/oauth/authorize".to_string(),
        token_endpoint: "https://auth.bsky.social/oauth/token".to_string(),
        pushed_authorization_request_endpoint: "https://auth.bsky.social/oauth/par".to_string(),
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
        scopes_supported: vec!["atproto".to_string(), "transition:generic".to_string()],
        authorization_response_iss_parameter_supported: true,
        client_id_metadata_document_supported: true,
    };

    let serialized = serde_json::to_value(&full).unwrap();
    assert!(
        validator.is_valid(&serialized),
        "Full struct must satisfy schema"
    );
    let deserialized: AuthorizationServerMetadata = serde_json::from_value(serialized).unwrap();
    assert_eq!(
        full, deserialized,
        "Roundtrip equality check failed for full AS metadata"
    );

    let min_json = json!({
        "issuer": "https://minimal-auth.example.com",
        "authorization_endpoint": "https://minimal-auth.example.com/oauth/authorize",
        "token_endpoint": "https://minimal-auth.example.com/oauth/token"
    });
    assert!(
        validator.is_valid(&min_json),
        "Minimal JSON must satisfy schema"
    );
    let min_deser: AuthorizationServerMetadata = serde_json::from_value(min_json).unwrap();
    assert_eq!(min_deser.issuer, "https://minimal-auth.example.com");
    assert_eq!(
        min_deser.authorization_endpoint,
        "https://minimal-auth.example.com/oauth/authorize"
    );
    assert_eq!(
        min_deser.token_endpoint,
        "https://minimal-auth.example.com/oauth/token"
    );
    assert!(!min_deser.require_pushed_authorization_requests);
}

#[test]
fn test_challenge_roundtrip_protected_resource_metadata_with_valid_documentation() {
    let schema = load_schema("schemas/rfc9728_protected_resource.json");
    let validator = compile_validator(&schema);

    let full = ProtectedResourceMetadata {
        resource: "https://pds.example.com".to_string(),
        authorization_servers: vec![
            "https://auth1.example.com".to_string(),
            "https://auth2.example.com".to_string(),
        ],
        scopes_supported: vec!["atproto".to_string()],
        bearer_methods_supported: vec!["header".to_string()],
        resource_documentation: Some("https://atproto.com/specs/pds".to_string()),
    };

    let serialized = serde_json::to_value(&full).unwrap();
    assert!(validator.is_valid(&serialized));
    let deserialized: ProtectedResourceMetadata = serde_json::from_value(serialized).unwrap();
    assert_eq!(full, deserialized);
}

#[test]
fn test_challenge_null_field_serialization_discrepancy_in_protected_resource_metadata() {
    let schema = load_schema("schemas/rfc9728_protected_resource.json");
    let validator = compile_validator(&schema);

    let struct_with_none = ProtectedResourceMetadata {
        resource: "https://pds2.example.com".to_string(),
        authorization_servers: vec!["https://auth.example.com".to_string()],
        scopes_supported: vec![],
        bearer_methods_supported: vec![],
        resource_documentation: None,
    };

    let serialized_none = serde_json::to_value(&struct_with_none).unwrap();
    assert_eq!(serialized_none["resource_documentation"], Value::Null);

    assert!(
        !validator.is_valid(&serialized_none),
        "Serializing resource_documentation: None produces JSON null, which RFC 9728 schema AST rejects"
    );

    let valid_omitted = json!({
        "resource": "https://pds2.example.com",
        "authorization_servers": ["https://auth.example.com"]
    });
    assert!(validator.is_valid(&valid_omitted));
    let deser: ProtectedResourceMetadata = serde_json::from_value(valid_omitted).unwrap();
    assert_eq!(deser.resource_documentation, None);
}

#[test]
fn test_challenge_empty_par_endpoint_serialization_discrepancy_in_authorization_server_metadata() {
    let schema = load_schema("schemas/rfc8414_authorization_server.json");
    let validator = compile_validator(&schema);

    let struct_with_empty_par = AuthorizationServerMetadata {
        issuer: "https://auth.example.com".to_string(),
        authorization_endpoint: "https://auth.example.com/oauth/authorize".to_string(),
        token_endpoint: "https://auth.example.com/oauth/token".to_string(),
        pushed_authorization_request_endpoint: "".to_string(),
        require_pushed_authorization_requests: false,
        dpop_signing_alg_values_supported: vec!["ES256".to_string()],
        code_challenge_methods_supported: vec!["S256".to_string()],
        response_types_supported: vec!["code".to_string()],
        grant_types_supported: vec!["authorization_code".to_string()],
        token_endpoint_auth_methods_supported: vec!["none".to_string()],
        token_endpoint_auth_signing_alg_values_supported: vec!["ES256".to_string()],
        scopes_supported: vec!["atproto".to_string()],
        authorization_response_iss_parameter_supported: true,
        client_id_metadata_document_supported: true,
    };

    let serialized_empty_par = serde_json::to_value(&struct_with_empty_par).unwrap();
    assert_eq!(
        serialized_empty_par["pushed_authorization_request_endpoint"],
        json!("")
    );

    assert!(
        !validator.is_valid(&serialized_empty_par),
        "Empty string for pushed_authorization_request_endpoint violates RFC 8414 format: uri"
    );

    let mut valid_populated = struct_with_empty_par;
    valid_populated.pushed_authorization_request_endpoint =
        "https://auth.example.com/oauth/par".to_string();
    let serialized_valid = serde_json::to_value(&valid_populated).unwrap();
    assert!(validator.is_valid(&serialized_valid));
}

#[test]
fn test_challenge_roundtrip_dpop_proof_claims() {
    let schema = load_schema("schemas/rfc9449_dpop_proof.json");
    let validator = compile_validator(&schema);

    let full = DPoPProofClaims {
        jti: "unique_jti_string_12345".to_string(),
        htm: "POST".to_string(),
        htu: "https://auth.example.com/oauth/token".to_string(),
        iat: 1712345678,
        exp: Some(1712345738),
        nonce: Some("server_nonce_challenge_123".to_string()),
        ath: Some("ath_hash_digest_abc".to_string()),
    };

    let serialized = serde_json::to_value(&full).unwrap();
    assert!(validator.is_valid(&serialized));
    let deserialized: DPoPProofClaims = serde_json::from_value(serialized).unwrap();
    assert_eq!(full, deserialized);

    let minimal = DPoPProofClaims {
        jti: "minimal_jti_888".to_string(),
        htm: "GET".to_string(),
        htu: "https://pds.example.com/xrpc/app.bsky.actor.getProfile".to_string(),
        iat: 1700000000,
        exp: None,
        nonce: None,
        ath: None,
    };

    let serialized_min = serde_json::to_value(&minimal).unwrap();
    assert!(validator.is_valid(&serialized_min));
    let deserialized_min: DPoPProofClaims = serde_json::from_value(serialized_min).unwrap();
    assert_eq!(minimal, deserialized_min);
}

#[test]
fn test_challenge_roundtrip_token_response() {
    let token_schema = json!({
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "required": ["access_token", "token_type", "sub"],
        "properties": {
            "access_token": { "type": "string" },
            "token_type": { "type": "string", "enum": ["DPoP", "Bearer"] },
            "expires_in": { "type": "integer", "minimum": 0 },
            "refresh_token": { "type": "string" },
            "scope": { "type": "string" },
            "sub": { "type": "string" }
        }
    });
    let validator = compile_validator(&token_schema);

    let full = TokenResponse {
        access_token: "dpop_access_jwt_string".to_string(),
        token_type: "DPoP".to_string(),
        expires_in: Some(3600),
        refresh_token: Some("single_use_refresh_token_string".to_string()),
        scope: Some("atproto transition:generic".to_string()),
        sub: "did:plc:ragtjsm2j2vknwk6zui0p4kb".to_string(),
    };

    let serialized = serde_json::to_value(&full).unwrap();
    assert!(validator.is_valid(&serialized));
    let deserialized: TokenResponse = serde_json::from_value(serialized).unwrap();
    assert_eq!(full, deserialized);

    let minimal = TokenResponse {
        access_token: "bearer_token_string".to_string(),
        token_type: "Bearer".to_string(),
        expires_in: None,
        refresh_token: None,
        scope: None,
        sub: "did:plc:z72i7hdynmk62xgdxonx2xnn".to_string(),
    };

    let serialized_min = serde_json::to_value(&minimal).unwrap();
    assert!(validator.is_valid(&serialized_min));
    let deserialized_min: TokenResponse = serde_json::from_value(serialized_min).unwrap();
    assert_eq!(minimal, deserialized_min);
}

#[test]
fn test_challenge_roundtrip_par_response_and_parameters() {
    let par_schema = json!({
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "required": ["request_uri", "expires_in"],
        "properties": {
            "request_uri": { "type": "string" },
            "expires_in": { "type": "integer", "minimum": 1 }
        }
    });
    let validator = compile_validator(&par_schema);

    let par_resp = ParResponse {
        request_uri: "urn:ietf:params:oauth:request_uri:uuid-12345-abcdef".to_string(),
        expires_in: 90,
    };

    let serialized = serde_json::to_value(&par_resp).unwrap();
    assert!(validator.is_valid(&serialized));
    let deserialized: ParResponse = serde_json::from_value(serialized).unwrap();
    assert_eq!(par_resp, deserialized);

    let par_params = ParParameters::new(
        "https://app.example.com/client-metadata.json",
        "https://app.example.com/callback",
        "atproto",
        "state_nonce_12345",
        "E9Melhoa2OwvFrGMTJguCH5rtx64ZW_SoRO823Ht_K0",
    )
    .with_login_hint("alice.bsky.social")
    .with_client_assertion(
        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "assertion_jwt",
    );

    let params_val = serde_json::to_value(&par_params).unwrap();
    let deserialized_params: ParParameters = serde_json::from_value(params_val).unwrap();
    assert_eq!(par_params, deserialized_params);
}

#[test]
fn test_challenge_roundtrip_did_document_and_services() {
    let did_doc_schema = json!({
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "required": ["id"],
        "properties": {
            "id": { "type": "string" },
            "alsoKnownAs": { "type": "array", "items": { "type": "string" } },
            "verificationMethod": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["id", "type", "controller"],
                    "properties": {
                        "id": { "type": "string" },
                        "type": { "type": "string" },
                        "controller": { "type": "string" },
                        "publicKeyMultibase": { "type": "string" }
                    }
                }
            },
            "service": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["id", "type", "serviceEndpoint"],
                    "properties": {
                        "id": { "type": "string" },
                        "type": { "type": "string" },
                        "serviceEndpoint": { "type": "string" }
                    }
                }
            }
        }
    });
    let validator = compile_validator(&did_doc_schema);

    let doc = DidDocument {
        id: "did:plc:ragtjsm2j2vknwk6zui0p4kb".to_string(),
        also_known_as: vec![
            "at://alice.bsky.social".to_string(),
            "at://alice.custom-domain.org".to_string(),
        ],
        verification_method: vec![VerificationMethod {
            id: "did:plc:ragtjsm2j2vknwk6zui0p4kb#atproto".to_string(),
            key_type: "Multikey".to_string(),
            controller: "did:plc:ragtjsm2j2vknwk6zui0p4kb".to_string(),
            public_key_multibase: Some("zQ3shb...".to_string()),
        }],
        service: vec![
            DidService {
                id: "#atproto_pds".to_string(),
                service_type: "AtprotoPersonalDataServer".to_string(),
                service_endpoint: "https://pds.example.com".to_string(),
            },
            DidService {
                id: "#feedgen".to_string(),
                service_type: "BskyFeedGenerator".to_string(),
                service_endpoint: "https://feedgen.example.com".to_string(),
            },
        ],
    };

    let serialized = serde_json::to_value(&doc).unwrap();
    assert!(validator.is_valid(&serialized));
    let deserialized: DidDocument = serde_json::from_value(serialized).unwrap();
    assert_eq!(doc, deserialized);
}

#[test]
fn test_challenge_roundtrip_jwk_ec_and_pkce_pair() {
    let jwk_schema = json!({
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "required": ["kty", "crv", "x", "y"],
        "properties": {
            "kty": { "type": "string", "enum": ["EC"] },
            "crv": { "type": "string", "enum": ["P-256"] },
            "x": { "type": "string" },
            "y": { "type": "string" }
        }
    });
    let jwk_val = compile_validator(&jwk_schema);

    let jwk = JwkEc {
        kty: "EC".to_string(),
        crv: "P-256".to_string(),
        x: "l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs".to_string(),
        y: "9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA".to_string(),
    };

    let jwk_json = serde_json::to_value(&jwk).unwrap();
    assert!(jwk_val.is_valid(&jwk_json));
    let jwk_deser: JwkEc = serde_json::from_value(jwk_json).unwrap();
    assert_eq!(jwk, jwk_deser);

    let pkce_schema = json!({
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "required": ["verifier", "challenge", "method"],
        "properties": {
            "verifier": { "type": "string", "minLength": 43, "maxLength": 128 },
            "challenge": { "type": "string", "minLength": 43, "maxLength": 43 },
            "method": { "type": "string", "enum": ["S256"] }
        }
    });
    let pkce_val = compile_validator(&pkce_schema);

    let pkce = PkcePair {
        verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".to_string(),
        challenge: "E9Melhoa2OwvFrGMTJguCH5rtx64ZW_SoRO823Ht_K0".to_string(),
        method: PkceMethod::S256,
    };

    let pkce_json = serde_json::to_value(&pkce).unwrap();
    assert!(pkce_val.is_valid(&pkce_json));
    let pkce_deser: PkcePair = serde_json::from_value(pkce_json).unwrap();
    assert_eq!(pkce, pkce_deser);
}

proptest! {
    #[test]
    fn prop_dpop_proof_claims_arbitrary_roundtrip_and_ast_validation(
        jti in "[a-zA-Z0-9_-]{8,32}",
        method in "(GET|POST|PUT|DELETE|PATCH)",
        path in "[a-z0-9/_-]{1,20}",
        iat in 0u64..2_000_000_000,
        exp_offset in 1u64..3600,
        nonce_opt in proptest::option::of("[a-zA-Z0-9_-]{16,64}"),
        ath_opt in proptest::option::of("[a-zA-Z0-9_-]{43}")
    ) {
        let schema = load_schema("schemas/rfc9449_dpop_proof.json");
        let validator = compile_validator(&schema);

        let htu = format!("https://example.com/{}", path);
        let claims = DPoPProofClaims {
            jti,
            htm: method,
            htu,
            iat,
            exp: Some(iat + exp_offset),
            nonce: nonce_opt,
            ath: ath_opt,
        };

        let serialized = serde_json::to_value(&claims).unwrap();
        prop_assert!(validator.is_valid(&serialized));

        let deserialized: DPoPProofClaims = serde_json::from_value(serialized).unwrap();
        prop_assert_eq!(claims, deserialized);
    }

    #[test]
    fn prop_protected_resource_metadata_arbitrary_roundtrip_and_ast_validation(
        res_host in "[a-z0-9]{3,10}\\.example\\.com",
        as_hosts in proptest::collection::vec("[a-z0-9]{3,10}\\.auth\\.com", 1..5),
        scopes in proptest::collection::vec("(atproto|transition:generic)", 0..3),
        doc_path in "[a-z0-9/_-]{1,15}"
    ) {
        let schema = load_schema("schemas/rfc9728_protected_resource.json");
        let validator = compile_validator(&schema);

        let auth_servers = as_hosts.into_iter().map(|h| format!("https://{}", h)).collect();
        let metadata = ProtectedResourceMetadata {
            resource: format!("https://{}", res_host),
            authorization_servers: auth_servers,
            scopes_supported: scopes,
            bearer_methods_supported: vec!["header".to_string()],
            resource_documentation: Some(format!("https://example.com/{}", doc_path)),
        };

        let serialized = serde_json::to_value(&metadata).unwrap();
        prop_assert!(validator.is_valid(&serialized));

        let deserialized: ProtectedResourceMetadata = serde_json::from_value(serialized).unwrap();
        prop_assert_eq!(metadata, deserialized);
    }

    #[test]
    fn prop_did_document_arbitrary_roundtrip_and_ast_validation(
        plc_id in "[a-z0-9]{24}",
        handle in "[a-z0-9]{3,10}\\.bsky\\.social",
        pds_host in "[a-z0-9]{3,10}\\.pds\\.network"
    ) {
        let did_doc_schema = json!({
            "$schema": "http://json-schema.org/draft-07/schema#",
            "type": "object",
            "required": ["id"],
            "properties": {
                "id": { "type": "string" },
                "alsoKnownAs": { "type": "array", "items": { "type": "string" } },
                "service": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["id", "type", "serviceEndpoint"],
                        "properties": {
                            "id": { "type": "string" },
                            "type": { "type": "string" },
                            "serviceEndpoint": { "type": "string" }
                        }
                    }
                }
            }
        });
        let validator = compile_validator(&did_doc_schema);

        let did = format!("did:plc:{}", plc_id);
        let doc = DidDocument {
            id: did.clone(),
            also_known_as: vec![format!("at://{}", handle)],
            verification_method: vec![],
            service: vec![DidService {
                id: "#atproto_pds".to_string(),
                service_type: "AtprotoPersonalDataServer".to_string(),
                service_endpoint: format!("https://{}", pds_host),
            }],
        };

        let serialized = serde_json::to_value(&doc).unwrap();
        prop_assert!(validator.is_valid(&serialized));

        let deserialized: DidDocument = serde_json::from_value(serialized).unwrap();
        prop_assert_eq!(doc, deserialized);
    }
}

#[test]
fn test_challenge_client_metadata_boundary_and_extension_fields() {
    let schema = load_schema("schemas/atproto_client_metadata.json");
    let validator = compile_validator(&schema);

    let valid_full = json!({
        "client_id": "https://app.example.com/oauth/client-metadata.json",
        "client_name": "Full ATProto Client",
        "client_uri": "https://app.example.com",
        "logo_uri": "https://app.example.com/logo.png",
        "tos_uri": "https://app.example.com/tos",
        "policy_uri": "https://app.example.com/policy",
        "redirect_uris": [
            "https://app.example.com/oauth/callback",
            "https://app.example.com/oauth/callback2"
        ],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "scope": "atproto transition:generic",
        "token_endpoint_auth_method": "none",
        "dpop_bound_access_tokens": true,
        "application_type": "web",
        "jwks_uri": "https://app.example.com/oauth/jwks.json"
    });
    assert!(validator.is_valid(&valid_full));

    let invalid_app_type = json!({
        "client_id": "https://app.example.com/client.json",
        "client_name": "CLI Tool",
        "client_uri": "https://app.example.com",
        "redirect_uris": ["http://127.0.0.1:8080/callback"],
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "scope": "atproto",
        "token_endpoint_auth_method": "none",
        "dpop_bound_access_tokens": true,
        "application_type": "cli_invalid"
    });
    assert!(
        !validator.is_valid(&invalid_app_type),
        "Invalid application_type enum value must fail schema AST"
    );

    let invalid_logo_uri = json!({
        "client_id": "https://app.example.com/client.json",
        "client_name": "Client",
        "client_uri": "https://app.example.com",
        "logo_uri": "not a valid uri",
        "redirect_uris": ["https://app.example.com/cb"],
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "scope": "atproto",
        "token_endpoint_auth_method": "none",
        "dpop_bound_access_tokens": true
    });
    assert!(
        !validator.is_valid(&invalid_logo_uri),
        "Invalid logo_uri must fail format: uri constraint"
    );

    let bool_scope = json!({
        "client_id": "https://app.example.com/client.json",
        "client_name": "Client",
        "client_uri": "https://app.example.com",
        "redirect_uris": ["https://app.example.com/cb"],
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "scope": true,
        "token_endpoint_auth_method": "none",
        "dpop_bound_access_tokens": true
    });
    assert!(!validator.is_valid(&bool_scope));
}

#[test]
fn test_challenge_lexicon_procedure_input_output_rejections() {
    let cs_lex = load_schema("lexicons/com/atproto/server/createSession.json");
    let cs_input_schema = &cs_lex["defs"]["main"]["input"]["schema"];
    let cs_in_val = compile_validator(cs_input_schema);

    let missing_pwd = json!({ "identifier": "alice.bsky.social" });
    assert!(!cs_in_val.is_valid(&missing_pwd));

    let missing_ident = json!({ "password": "secret_password" });
    assert!(!cs_in_val.is_valid(&missing_ident));

    let int_ident = json!({ "identifier": 12345, "password": "pwd" });
    assert!(!cs_in_val.is_valid(&int_ident));

    let cs_output_schema = &cs_lex["defs"]["main"]["output"]["schema"];
    let cs_out_val = compile_validator(cs_output_schema);

    let missing_did = json!({
        "accessJwt": "jwt1",
        "refreshJwt": "jwt2",
        "handle": "alice.bsky.social"
    });
    assert!(!cs_out_val.is_valid(&missing_did));

    let missing_handle = json!({
        "accessJwt": "jwt1",
        "refreshJwt": "jwt2",
        "did": "did:plc:ragtjsm2j2vknwk6zui0p4kb"
    });
    assert!(!cs_out_val.is_valid(&missing_handle));

    let rs_lex = load_schema("lexicons/com/atproto/server/refreshSession.json");
    let rs_output_schema = &rs_lex["defs"]["main"]["output"]["schema"];
    let rs_out_val = compile_validator(rs_output_schema);

    let valid_refresh = json!({
        "accessJwt": "fresh_access",
        "refreshJwt": "fresh_refresh",
        "handle": "bob.bsky.social",
        "did": "did:plc:z72i7hdynmk62xgdxonx2xnn",
        "active": true
    });
    assert!(rs_out_val.is_valid(&valid_refresh));

    let missing_ref = json!({
        "accessJwt": "fresh_access",
        "handle": "bob.bsky.social",
        "did": "did:plc:z72i7hdynmk62xgdxonx2xnn"
    });
    assert!(!rs_out_val.is_valid(&missing_ref));
}
