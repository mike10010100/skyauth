//! Dynamic Lexicon & RFC Schema Engine with Upstream Drift Guard Compliance Tests.
//!
//! Verifies:
//! 1. Dynamic runtime compilation of bundled RFC JSON Schemas and ATProto Lexicons using `jsonschema`.
//! 2. Direct AST validation of serialized Rust domain models against compiled schemas.
//! 3. Comprehensive rejection of missing fields, type corruptions, casing mismatches, and schema violations.
//! 4. In-memory and disk-based schema loading resilience.
//! 5. Automated upstream drift script verification execution (`scripts/sync_specs.sh --verify`).

#![allow(
    dead_code,
    unused_imports,
    missing_docs,
    clippy::all,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{json, Value};

use skyauth::client::{OAuthClientMetadata, TokenResponse};
use skyauth::crypto::sha256_digest;
use skyauth::discovery::{AuthorizationServerMetadata, ProtectedResourceMetadata};
use skyauth::dpop::DPoPProofClaims;
use skyauth::identity::{DidDocument, DidService, VerificationMethod};
use skyauth::par::ParResponse;

// Static bundled schema includes for zero-IO fallback & compile-time inclusion
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

/// Helper to convert ATProto Lexicon schema definitions into standard JSON Schema draft-07 ASTs.
fn lexicon_to_json_schema(val: &Value) -> Value {
    match val {
        Value::Object(map) => {
            let mut new_map = serde_json::Map::new();
            for (k, v) in map {
                if k == "type" && v == "unknown" {
                    // In JSON Schema, unknown is represented by omitting type constraint
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

/// Helper to compile a JSON schema Value into a jsonschema validator.
fn compile_validator(schema_json: &Value) -> jsonschema::Validator {
    let normalized = lexicon_to_json_schema(schema_json);
    jsonschema::validator_for(&normalized)
        .expect("Bundled JSON schema must be syntactically and semantically valid")
}

/// Helper to load a schema from disk or fallback to bundled constants.
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

// =========================================================================
// GROUP 1: RFC 8414 Authorization Server Metadata Schema Compliance
// =========================================================================

#[test]
fn test_rfc8414_schema_compilation_and_valid_structure() {
    let schema = load_schema("schemas/rfc8414_authorization_server.json");
    let validator = compile_validator(&schema);

    let sample_as = json!({
        "issuer": "https://auth.example.com",
        "authorization_endpoint": "https://auth.example.com/oauth/authorize",
        "token_endpoint": "https://auth.example.com/oauth/token",
        "pushed_authorization_request_endpoint": "https://auth.example.com/oauth/par",
        "require_pushed_authorization_requests": true,
        "dpop_signing_alg_values_supported": ["ES256"],
        "code_challenge_methods_supported": ["S256"],
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["none", "private_key_jwt"],
        "scopes_supported": ["atproto", "transition:generic"]
    });

    assert!(
        validator.is_valid(&sample_as),
        "Valid RFC 8414 payload must satisfy schema AST"
    );
}

#[test]
fn test_rfc8414_rust_struct_serialization_compliance() {
    let schema = load_schema("schemas/rfc8414_authorization_server.json");
    let validator = compile_validator(&schema);

    let rust_metadata = AuthorizationServerMetadata {
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
        token_endpoint_auth_methods_supported: vec!["none".to_string()],
        token_endpoint_auth_signing_alg_values_supported: vec!["ES256".to_string()],
        scopes_supported: vec!["atproto".to_string()],
        authorization_response_iss_parameter_supported: true,
        client_id_metadata_document_supported: true,
        require_request_uri_registration: Some(true),
    };

    let serialized = serde_json::to_value(&rust_metadata)
        .expect("AuthorizationServerMetadata must serialize cleanly to JSON");

    assert!(
        validator.is_valid(&serialized),
        "Serialized AuthorizationServerMetadata must strictly match RFC 8414 JSON schema AST"
    );
}

#[test]
fn test_rfc8414_missing_required_fields_rejection() {
    let schema = load_schema("schemas/rfc8414_authorization_server.json");
    let validator = compile_validator(&schema);

    // Missing issuer
    let missing_issuer = json!({
        "authorization_endpoint": "https://auth.example.com/oauth/authorize",
        "token_endpoint": "https://auth.example.com/oauth/token"
    });
    assert!(!validator.is_valid(&missing_issuer));

    // Missing authorization_endpoint
    let missing_auth_ep = json!({
        "issuer": "https://auth.example.com",
        "token_endpoint": "https://auth.example.com/oauth/token"
    });
    assert!(!validator.is_valid(&missing_auth_ep));

    // Missing token_endpoint
    let missing_token_ep = json!({
        "issuer": "https://auth.example.com",
        "authorization_endpoint": "https://auth.example.com/oauth/authorize"
    });
    assert!(!validator.is_valid(&missing_token_ep));
}

#[test]
fn test_rfc8414_invalid_field_types_rejection() {
    let schema = load_schema("schemas/rfc8414_authorization_server.json");
    let validator = compile_validator(&schema);

    // issuer as integer
    let invalid_issuer_type = json!({
        "issuer": 12345,
        "authorization_endpoint": "https://auth.example.com/auth",
        "token_endpoint": "https://auth.example.com/token"
    });
    assert!(!validator.is_valid(&invalid_issuer_type));

    // dpop_signing_alg_values_supported as string instead of array
    let invalid_dpop_type = json!({
        "issuer": "https://auth.example.com",
        "authorization_endpoint": "https://auth.example.com/auth",
        "token_endpoint": "https://auth.example.com/token",
        "dpop_signing_alg_values_supported": "ES256"
    });
    assert!(!validator.is_valid(&invalid_dpop_type));

    // require_pushed_authorization_requests as string instead of boolean
    let invalid_par_type = json!({
        "issuer": "https://auth.example.com",
        "authorization_endpoint": "https://auth.example.com/auth",
        "token_endpoint": "https://auth.example.com/token",
        "require_pushed_authorization_requests": "true"
    });
    assert!(!validator.is_valid(&invalid_par_type));
}

#[test]
fn test_rfc8414_casing_mismatches_rejection() {
    let schema = load_schema("schemas/rfc8414_authorization_server.json");
    let validator = compile_validator(&schema);

    // camelCase authorizationEndpoint instead of snake_case authorization_endpoint
    let camel_case = json!({
        "issuer": "https://auth.example.com",
        "authorizationEndpoint": "https://auth.example.com/auth",
        "token_endpoint": "https://auth.example.com/token"
    });
    assert!(
        !validator.is_valid(&camel_case),
        "camelCase fields must be rejected by snake_case RFC 8414 schema"
    );
}

// =========================================================================
// GROUP 2: RFC 9728 Protected Resource Metadata Schema Compliance
// =========================================================================

#[test]
fn test_rfc9728_schema_compilation_and_valid_structure() {
    let schema = load_schema("schemas/rfc9728_protected_resource.json");
    let validator = compile_validator(&schema);

    let sample_pds = json!({
        "resource": "https://pds.example.com",
        "authorization_servers": ["https://auth.example.com"],
        "scopes_supported": ["atproto"],
        "bearer_methods_supported": ["header"],
        "resource_documentation": "https://atproto.com/specs/pds"
    });

    assert!(
        validator.is_valid(&sample_pds),
        "Valid RFC 9728 payload must satisfy schema AST"
    );
}

#[test]
fn test_rfc9728_rust_struct_serialization_compliance() {
    let schema = load_schema("schemas/rfc9728_protected_resource.json");
    let validator = compile_validator(&schema);

    let rust_pds = ProtectedResourceMetadata {
        resource: "https://mushroom.us-east.host.bsky.network".to_string(),
        authorization_servers: vec!["https://bsky.social".to_string()],
        scopes_supported: vec!["atproto".to_string()],
        bearer_methods_supported: vec!["header".to_string()],
        resource_documentation: Some("https://atproto.com".to_string()),
    };

    let serialized = serde_json::to_value(&rust_pds)
        .expect("ProtectedResourceMetadata must serialize cleanly to JSON");

    assert!(
        validator.is_valid(&serialized),
        "Serialized ProtectedResourceMetadata must strictly match RFC 9728 schema AST"
    );
}

#[test]
fn test_rfc9728_missing_required_fields_rejection() {
    let schema = load_schema("schemas/rfc9728_protected_resource.json");
    let validator = compile_validator(&schema);

    // Missing resource
    let missing_resource = json!({
        "authorization_servers": ["https://auth.example.com"]
    });
    assert!(!validator.is_valid(&missing_resource));

    // Missing authorization_servers
    let missing_auth_servers = json!({
        "resource": "https://pds.example.com"
    });
    assert!(!validator.is_valid(&missing_auth_servers));
}

#[test]
fn test_rfc9728_empty_authorization_servers_rejection() {
    let schema = load_schema("schemas/rfc9728_protected_resource.json");
    let validator = compile_validator(&schema);

    let empty_auth_servers = json!({
        "resource": "https://pds.example.com",
        "authorization_servers": []
    });
    assert!(
        !validator.is_valid(&empty_auth_servers),
        "Empty authorization_servers array must be rejected (minItems: 1)"
    );
}

#[test]
fn test_rfc9728_type_mismatches_rejection() {
    let schema = load_schema("schemas/rfc9728_protected_resource.json");
    let validator = compile_validator(&schema);

    // authorization_servers as string instead of array
    let invalid_type = json!({
        "resource": "https://pds.example.com",
        "authorization_servers": "https://auth.example.com"
    });
    assert!(!validator.is_valid(&invalid_type));

    // resource as boolean
    let bool_resource = json!({
        "resource": true,
        "authorization_servers": ["https://auth.example.com"]
    });
    assert!(!validator.is_valid(&bool_resource));
}

// =========================================================================
// GROUP 3: RFC 9449 DPoP Proof Claims Schema Compliance
// =========================================================================

#[test]
fn test_rfc9449_schema_compilation_and_valid_structure() {
    let schema = load_schema("schemas/rfc9449_dpop_proof.json");
    let validator = compile_validator(&schema);

    let minimal_payload = json!({
        "jti": "jti_1234567890abcdef",
        "htm": "POST",
        "htu": "https://auth.example.com/oauth/token",
        "iat": 1700000000
    });

    assert!(
        validator.is_valid(&minimal_payload),
        "Minimal RFC 9449 payload must satisfy schema AST"
    );
}

#[test]
fn test_rfc9449_full_claims_with_nonce_and_ath_compliance() {
    let schema = load_schema("schemas/rfc9449_dpop_proof.json");
    let validator = compile_validator(&schema);

    let rust_claims = DPoPProofClaims {
        jti: "unique_token_jti_999".to_string(),
        htm: "POST".to_string(),
        htu: "https://pds.example.com/xrpc/com.atproto.server.createSession".to_string(),
        iat: 1712345678,
        exp: Some(1712345738),
        nonce: Some("server_nonce_challenge_xyz".to_string()),
        ath: Some("f7Vp3...ath_hash...".to_string()),
    };

    let serialized =
        serde_json::to_value(&rust_claims).expect("DPoPProofClaims must serialize cleanly to JSON");

    assert!(
        validator.is_valid(&serialized),
        "Full DPoPProofClaims with nonce, ath, and exp must satisfy RFC 9449 schema AST"
    );
}

#[test]
fn test_rfc9449_missing_required_fields_rejection() {
    let schema = load_schema("schemas/rfc9449_dpop_proof.json");
    let validator = compile_validator(&schema);

    let missing_jti = json!({
        "htm": "POST",
        "htu": "https://auth.example.com/oauth/token",
        "iat": 1700000000
    });
    assert!(!validator.is_valid(&missing_jti));

    let missing_htm = json!({
        "jti": "jti_123",
        "htu": "https://auth.example.com/oauth/token",
        "iat": 1700000000
    });
    assert!(!validator.is_valid(&missing_htm));

    let missing_htu = json!({
        "jti": "jti_123",
        "htm": "POST",
        "iat": 1700000000
    });
    assert!(!validator.is_valid(&missing_htu));

    let missing_iat = json!({
        "jti": "jti_123",
        "htm": "POST",
        "htu": "https://auth.example.com/oauth/token"
    });
    assert!(!validator.is_valid(&missing_iat));
}

#[test]
fn test_rfc9449_negative_timestamps_and_invalid_types() {
    let schema = load_schema("schemas/rfc9449_dpop_proof.json");
    let validator = compile_validator(&schema);

    // iat as string instead of integer
    let string_iat = json!({
        "jti": "jti_123",
        "htm": "POST",
        "htu": "https://auth.example.com/oauth/token",
        "iat": "1700000000"
    });
    assert!(!validator.is_valid(&string_iat));

    // iat as negative number
    let negative_iat = json!({
        "jti": "jti_123",
        "htm": "POST",
        "htu": "https://auth.example.com/oauth/token",
        "iat": -50
    });
    assert!(!validator.is_valid(&negative_iat));
}

// =========================================================================
// GROUP 4: ATProto OAuth Client Metadata Document Schema Compliance
// =========================================================================

#[test]
fn test_client_metadata_schema_compilation_and_valid_structure() {
    let schema = load_schema("schemas/atproto_client_metadata.json");
    let validator = compile_validator(&schema);

    let client_doc = json!({
        "client_id": "https://app.example.com/oauth/client-metadata.json",
        "client_name": "Example ATProto Client",
        "client_uri": "https://app.example.com",
        "logo_uri": "https://app.example.com/logo.png",
        "tos_uri": "https://app.example.com/tos",
        "policy_uri": "https://app.example.com/policy",
        "redirect_uris": ["https://app.example.com/oauth/callback"],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "scope": "atproto",
        "token_endpoint_auth_method": "none",
        "dpop_bound_access_tokens": true,
        "application_type": "web"
    });

    assert!(
        validator.is_valid(&client_doc),
        "Valid ATProto Client Metadata document must satisfy schema AST"
    );
}

#[test]
fn test_client_metadata_missing_mandatory_fields_rejection() {
    let schema = load_schema("schemas/atproto_client_metadata.json");
    let validator = compile_validator(&schema);

    // Missing client_id
    let missing_client_id = json!({
        "client_name": "Example Client",
        "client_uri": "https://app.example.com",
        "redirect_uris": ["https://app.example.com/callback"],
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "scope": "atproto",
        "token_endpoint_auth_method": "none",
        "dpop_bound_access_tokens": true
    });
    assert!(!validator.is_valid(&missing_client_id));

    // Missing redirect_uris
    let missing_redirect_uris = json!({
        "client_id": "https://app.example.com/client.json",
        "client_name": "Example Client",
        "client_uri": "https://app.example.com",
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "scope": "atproto",
        "token_endpoint_auth_method": "none",
        "dpop_bound_access_tokens": true
    });
    assert!(!validator.is_valid(&missing_redirect_uris));
}

#[test]
fn test_client_metadata_empty_redirect_uris_rejection() {
    let schema = load_schema("schemas/atproto_client_metadata.json");
    let validator = compile_validator(&schema);

    let empty_uris = json!({
        "client_id": "https://app.example.com/client.json",
        "client_name": "Example Client",
        "client_uri": "https://app.example.com",
        "redirect_uris": [],
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "scope": "atproto",
        "token_endpoint_auth_method": "none",
        "dpop_bound_access_tokens": true
    });
    assert!(
        !validator.is_valid(&empty_uris),
        "Empty redirect_uris array must be rejected (minItems: 1)"
    );
}

#[test]
fn test_client_metadata_invalid_auth_method_enum_rejection() {
    let schema = load_schema("schemas/atproto_client_metadata.json");
    let validator = compile_validator(&schema);

    let invalid_method = json!({
        "client_id": "https://app.example.com/client.json",
        "client_name": "Example Client",
        "client_uri": "https://app.example.com",
        "redirect_uris": ["https://app.example.com/callback"],
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "scope": "atproto",
        "token_endpoint_auth_method": "unsupported_method_xyz",
        "dpop_bound_access_tokens": true
    });
    assert!(
        !validator.is_valid(&invalid_method),
        "Unsupported token_endpoint_auth_method must fail enum constraint"
    );
}

// =========================================================================
// GROUP 5: ATProto Canonical Lexicons Compliance
// =========================================================================

#[test]
fn test_resolve_handle_lexicon_structure() {
    let lex = load_schema("lexicons/com/atproto/identity/resolveHandle.json");
    assert_eq!(lex["lexicon"], 1);
    assert_eq!(lex["id"], "com.atproto.identity.resolveHandle");
    assert_eq!(lex["defs"]["main"]["type"], "query");

    // Extract parameters schema and validate runtime query params
    let params_def = &lex["defs"]["main"]["parameters"];
    let param_props = &params_def["properties"];
    assert!(param_props.get("handle").is_some());

    // Extract output schema and validate runtime response
    let output_schema = &lex["defs"]["main"]["output"]["schema"];
    let validator = compile_validator(output_schema);

    let valid_response = json!({ "did": "did:plc:ragtjsm2j2vknwk6zui0p4kb" });
    assert!(
        validator.is_valid(&valid_response),
        "Valid resolveHandle response must satisfy output schema AST"
    );

    let invalid_response = json!({ "handle": "alice.bsky.social" });
    assert!(
        !validator.is_valid(&invalid_response),
        "Response missing 'did' must be rejected"
    );
}

#[test]
fn test_create_session_lexicon_structure() {
    let lex = load_schema("lexicons/com/atproto/server/createSession.json");
    assert_eq!(lex["lexicon"], 1);
    assert_eq!(lex["id"], "com.atproto.server.createSession");
    assert_eq!(lex["defs"]["main"]["type"], "procedure");

    // Validate Input Schema
    let input_schema = &lex["defs"]["main"]["input"]["schema"];
    let input_validator = compile_validator(input_schema);

    let valid_input = json!({
        "identifier": "alice.bsky.social",
        "password": "hunter2_super_secret"
    });
    assert!(input_validator.is_valid(&valid_input));

    let invalid_input = json!({ "identifier": "alice.bsky.social" });
    assert!(!input_validator.is_valid(&invalid_input));

    // Validate Output Schema
    let output_schema = &lex["defs"]["main"]["output"]["schema"];
    let output_validator = compile_validator(output_schema);

    let valid_output = json!({
        "accessJwt": "header.payload.signature_access",
        "refreshJwt": "header.payload.signature_refresh",
        "handle": "alice.bsky.social",
        "did": "did:plc:ragtjsm2j2vknwk6zui0p4kb",
        "active": true
    });
    assert!(output_validator.is_valid(&valid_output));

    let missing_refresh = json!({
        "accessJwt": "header.payload.signature_access",
        "handle": "alice.bsky.social",
        "did": "did:plc:ragtjsm2j2vknwk6zui0p4kb"
    });
    assert!(!output_validator.is_valid(&missing_refresh));
}

#[test]
fn test_refresh_session_lexicon_structure() {
    let lex = load_schema("lexicons/com/atproto/server/refreshSession.json");
    assert_eq!(lex["lexicon"], 1);
    assert_eq!(lex["id"], "com.atproto.server.refreshSession");
    assert_eq!(lex["defs"]["main"]["type"], "procedure");

    let output_schema = &lex["defs"]["main"]["output"]["schema"];
    let output_validator = compile_validator(output_schema);

    let valid_refresh = json!({
        "accessJwt": "fresh_access_jwt_token",
        "refreshJwt": "fresh_refresh_jwt_token",
        "handle": "bob.bsky.social",
        "did": "did:plc:z72i7hdynmk62xgdxonx2xnn"
    });
    assert!(output_validator.is_valid(&valid_refresh));
}

// =========================================================================
// GROUP 6: Extended Protocol Payloads & Model Integration
// =========================================================================

#[test]
fn test_par_response_schema_compliance() {
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

    let rust_par = ParResponse {
        request_uri: "urn:ietf:params:oauth:request_uri:req-6b4129b8-b1fc".to_string(),
        expires_in: 90,
    };
    let serialized = serde_json::to_value(&rust_par).unwrap();
    assert!(validator.is_valid(&serialized));

    let zero_expires = json!({
        "request_uri": "urn:ietf:params:oauth:request_uri:abc",
        "expires_in": 0
    });
    assert!(!validator.is_valid(&zero_expires));
}

#[test]
fn test_token_response_schema_compliance() {
    let token_schema = json!({
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "required": ["access_token", "token_type", "sub"],
        "properties": {
            "access_token": { "type": "string" },
            "token_type": { "type": "string", "enum": ["DPoP", "Bearer"] },
            "expires_in": { "type": "integer" },
            "refresh_token": { "type": "string" },
            "scope": { "type": "string" },
            "sub": { "type": "string" }
        }
    });
    let validator = compile_validator(&token_schema);

    let wire_token = json!({
        "access_token": "dpop_access_token_value",
        "token_type": "DPoP",
        "expires_in": 3600,
        "refresh_token": "refresh_token_value",
        "scope": "atproto",
        "sub": "did:plc:ragtjsm2j2vknwk6zui0p4kb"
    });
    assert!(validator.is_valid(&wire_token));
    let parsed: TokenResponse = serde_json::from_value(wire_token).unwrap();
    assert_eq!(parsed.token_type(), "DPoP");

    let invalid_token_type = json!({
        "access_token": "token",
        "token_type": "Basic",
        "sub": "did:plc:123"
    });
    assert!(!validator.is_valid(&invalid_token_type));
}

#[test]
fn test_did_document_schema_compliance() {
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

    let did_doc = DidDocument {
        id: "did:plc:ragtjsm2j2vknwk6zui0p4kb".to_string(),
        also_known_as: vec!["at://alice.bsky.social".to_string()],
        verification_method: vec![VerificationMethod {
            id: "did:plc:ragtjsm2j2vknwk6zui0p4kb#atproto".to_string(),
            key_type: "Multikey".to_string(),
            controller: "did:plc:ragtjsm2j2vknwk6zui0p4kb".to_string(),
            public_key_multibase: Some("zQ3shb...".to_string()),
        }],
        service: vec![DidService {
            id: "#atproto_pds".to_string(),
            service_type: "AtprotoPersonalDataServer".to_string(),
            service_endpoint: "https://pds.example.com".to_string(),
        }],
    };

    let serialized = serde_json::to_value(&did_doc).unwrap();
    assert!(validator.is_valid(&serialized));
}

// =========================================================================
// GROUP 7: Performance, Batch Validation & Drift Script Verification
// =========================================================================

#[test]
fn test_batch_schema_ast_validation_throughput() {
    let schema = load_schema("schemas/rfc8414_authorization_server.json");
    let validator = compile_validator(&schema);

    let instance = json!({
        "issuer": "https://auth.example.com",
        "authorization_endpoint": "https://auth.example.com/oauth/authorize",
        "token_endpoint": "https://auth.example.com/oauth/token",
        "pushed_authorization_request_endpoint": "https://auth.example.com/oauth/par",
        "require_pushed_authorization_requests": true,
        "dpop_signing_alg_values_supported": ["ES256"],
        "code_challenge_methods_supported": ["S256"],
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"]
    });

    let start = std::time::Instant::now();
    for _ in 0..1000 {
        assert!(validator.is_valid(&instance));
    }
    let elapsed = start.elapsed();
    assert!(
        elapsed.as_millis() < 200,
        "1000 AST validations should take < 200ms, took {:?}",
        elapsed
    );
}

#[test]
fn test_sync_specs_script_execution_and_drift_verification() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let script_path = manifest_dir.join("scripts/sync_specs.sh");

    assert!(
        script_path.exists(),
        "scripts/sync_specs.sh must exist in the workspace"
    );

    let output = Command::new(&script_path)
        .arg("--verify")
        .current_dir(&manifest_dir)
        .output()
        .expect("Failed to execute scripts/sync_specs.sh --verify");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    println!("sync_specs stdout: {}", stdout);
    println!("sync_specs stderr: {}", stderr);

    assert!(
        output.status.success(),
        "scripts/sync_specs.sh --verify must exit with code 0. Output: {}\nError: {}",
        stdout,
        stderr
    );
    assert!(
        stdout.contains("local specification integrity verified"),
        "Script output must confirm local integrity"
    );
}

#[test]
fn test_all_bundled_files_integrity_and_checksum_manifest() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let manifest_path = manifest_dir.join("schemas/.checksums.sha256");

    assert!(
        manifest_path.exists(),
        "schemas/.checksums.sha256 manifest must exist"
    );

    let manifest_content = std::fs::read_to_string(&manifest_path).unwrap();
    for line in manifest_content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        assert_eq!(parts.len(), 2, "Manifest line must be '<sha256> <path>'");

        let expected_hash = parts[0];
        let file_rel_path = parts[1];
        let full_path = manifest_dir.join(file_rel_path);

        assert!(
            full_path.exists(),
            "File referenced in manifest does not exist: {}",
            file_rel_path
        );

        let file_bytes = std::fs::read(&full_path).unwrap();
        let actual_hash = hex::encode(sha256_digest(&file_bytes));

        assert_eq!(
            expected_hash, actual_hash,
            "SHA-256 mismatch for {}",
            file_rel_path
        );
    }
}

// =========================================================================
// GROUP 8: Advanced Schema Edge Cases & Error Introspection
// =========================================================================

#[test]
fn test_error_paths_and_introspectable_validation_errors() {
    let schema = load_schema("schemas/rfc8414_authorization_server.json");
    let validator = compile_validator(&schema);

    let invalid_instance = json!({
        "issuer": "https://auth.example.com"
        // missing authorization_endpoint and token_endpoint
    });

    assert!(!validator.is_valid(&invalid_instance));

    let mut error_messages = Vec::new();
    for err in validator.iter_errors(&invalid_instance) {
        error_messages.push(err.to_string());
    }

    assert!(
        !error_messages.is_empty(),
        "Validation errors must be generated with detailed error messages"
    );
    let all_err_str = error_messages.join(", ");
    assert!(
        all_err_str.contains("authorization_endpoint") || all_err_str.contains("token_endpoint"),
        "Error message should mention missing properties: {}",
        all_err_str
    );
}

#[test]
fn test_create_session_with_full_optional_profile_fields() {
    let lex = load_schema("lexicons/com/atproto/server/createSession.json");
    let output_schema = &lex["defs"]["main"]["output"]["schema"];
    let validator = compile_validator(output_schema);

    let full_session = json!({
        "accessJwt": "eyJhbGciOiJFUzI1NiIsInR5cCI6ImF0K2p3dCJ9.access",
        "refreshJwt": "eyJhbGciOiJFUzI1NiIsInR5cCI6InJlZnJlc2gifQ.refresh",
        "handle": "carol.bsky.social",
        "did": "did:plc:ragtjsm2j2vknwk6zui0p4kb",
        "email": "carol@example.com",
        "emailConfirmed": true,
        "emailAuthFactor": false,
        "active": true,
        "status": "active",
        "didDoc": {
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "did:plc:ragtjsm2j2vknwk6zui0p4kb",
            "alsoKnownAs": ["at://carol.bsky.social"]
        }
    });

    assert!(
        validator.is_valid(&full_session),
        "Full createSession response with optional profile fields must pass validation"
    );
}

#[test]
fn test_client_metadata_native_and_jwks_extensions() {
    let schema = load_schema("schemas/atproto_client_metadata.json");
    let validator = compile_validator(&schema);

    let native_client = json!({
        "client_id": "https://native.example.com/oauth/client-metadata.json",
        "client_name": "Native Mobile App",
        "client_uri": "https://native.example.com",
        "redirect_uris": ["org.example.app:/oauth/callback"],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "scope": "atproto",
        "token_endpoint_auth_method": "none",
        "dpop_bound_access_tokens": true,
        "application_type": "native",
        "jwks_uri": "https://native.example.com/oauth/jwks.json"
    });

    assert!(
        validator.is_valid(&native_client),
        "Native client metadata with custom redirect URI scheme and jwks_uri must pass"
    );
}

#[test]
fn test_dpop_proof_claims_optional_field_permutations() {
    let schema = load_schema("schemas/rfc9449_dpop_proof.json");
    let validator = compile_validator(&schema);

    // With ath only
    let with_ath = json!({
        "jti": "jti_1",
        "htm": "GET",
        "htu": "https://pds.example.com/xrpc/app.bsky.actor.getProfile",
        "iat": 1700000000,
        "ath": "f7Vp3..."
    });
    assert!(validator.is_valid(&with_ath));

    // With nonce only
    let with_nonce = json!({
        "jti": "jti_2",
        "htm": "POST",
        "htu": "https://auth.example.com/oauth/token",
        "iat": 1700000000,
        "nonce": "server_nonce_challenge"
    });
    assert!(validator.is_valid(&with_nonce));

    // With exp only
    let with_exp = json!({
        "jti": "jti_3",
        "htm": "POST",
        "htu": "https://auth.example.com/oauth/token",
        "iat": 1700000000,
        "exp": 1700000060
    });
    assert!(validator.is_valid(&with_exp));
}
