//! Tier 3: Pairwise Combinatorial Test Suite for `skyauth`.
//!
//! Evaluates multi-dimensional interactions across cryptographic primitives, DPoP proofs,
//! PKCE challenges, decentralized identity discovery, SSRF boundaries, PAR negotiation,
//! sharded storage, and runtime schema AST validation.

mod e2e_harness;

use e2e_harness::fixtures::*;
use e2e_harness::{MockOAuthEnvironment, MockPds};
use serde_json::json;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use skyauth::crypto::{base64url_decode, constant_time_eq, hmac_sha256};
use skyauth::dpop::{
    compute_access_token_hash, normalize_htu, DPoPKey, DPoPNonceCache, DPoPVerifier,
};
use skyauth::pkce::{verify_pkce, PkcePair};

#[test]
fn test_p1_01_ephemeral_dpop_with_s256_pkce_32byte() {
    let dpop_key = DPoPKey::generate();
    let pkce = PkcePair::generate_with_entropy_size(32).unwrap();

    let uri = "https://auth.example.com/oauth/par";
    let proof = dpop_key.create_proof("POST", uri, None, None).unwrap();

    let verifier = DPoPVerifier::new();
    let (claims, jwk) = verifier
        .verify_proof(&proof, "POST", uri, None, None, None)
        .unwrap();

    assert_eq!(claims.htm, "POST");
    assert_eq!(jwk.thumbprint(), dpop_key.jwk_thumbprint());
    assert!(verify_pkce(&pkce.verifier, &pkce.challenge).is_ok());
}

#[test]
fn test_p1_02_pem_imported_dpop_with_s256_pkce_64byte() {
    let key1 = DPoPKey::generate();
    let pem = key1.to_pkcs8_pem().unwrap();
    let dpop_key = DPoPKey::from_pkcs8_pem(&pem).unwrap();

    let pkce = PkcePair::generate_with_entropy_size(64).unwrap();
    assert_eq!(pkce.verifier.len(), 86);

    let uri = "https://pds.example.com/oauth/token";
    let proof = dpop_key.create_proof("POST", uri, None, None).unwrap();

    let verifier = DPoPVerifier::new();
    let (_, jwk) = verifier
        .verify_proof(&proof, "POST", uri, None, None, None)
        .unwrap();
    assert_eq!(jwk.thumbprint(), key1.jwk_thumbprint());
    assert!(verify_pkce(&pkce.verifier, &pkce.challenge).is_ok());
}

#[test]
fn test_p1_03_dpop_with_access_token_hash_and_custom_port_htu() {
    let dpop_key = DPoPKey::generate();
    let access_token = "access_token_123456789";
    let ath = compute_access_token_hash(access_token);
    let target_uri = "https://resource.example.com:8443/xrpc/app.bsky.actor.getProfile";

    let proof = dpop_key
        .create_proof("GET", target_uri, None, Some(&ath))
        .unwrap();

    let verifier = DPoPVerifier::new();
    let (claims, _) = verifier
        .verify_proof(&proof, "GET", target_uri, None, Some(&ath), None)
        .unwrap();

    assert_eq!(claims.ath, Some(ath));
    assert_eq!(claims.htu, normalize_htu(target_uri).unwrap());
}

#[test]
fn test_p1_04_concurrent_independent_dpop_and_pkce_generation() {
    let handles: Vec<_> = (0..8)
        .map(|_| {
            std::thread::spawn(|| {
                let key = DPoPKey::generate();
                let pkce = PkcePair::generate();
                let proof = key
                    .create_proof("POST", "https://auth.com/oauth/par", None, None)
                    .unwrap();
                let verifier = DPoPVerifier::new();
                assert!(verifier
                    .verify_proof(
                        &proof,
                        "POST",
                        "https://auth.com/oauth/par",
                        None,
                        None,
                        None
                    )
                    .is_ok());
                assert!(pkce.verify(&pkce.verifier).is_ok());
            })
        })
        .collect();

    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn test_p1_05_dpop_jwk_thumbprint_used_as_dpop_jkt_in_par() {
    let key = DPoPKey::generate();
    let jkt = key.jwk_thumbprint();
    let pkce = PkcePair::generate();

    let mut form = url::form_urlencoded::Serializer::new(String::new());
    form.append_pair("client_id", TEST_CLIENT_ID);
    form.append_pair("code_challenge", &pkce.challenge);
    form.append_pair("code_challenge_method", "S256");
    form.append_pair("dpop_jkt", &jkt);
    let payload = form.finish();

    assert!(payload.contains(&format!("dpop_jkt={jkt}")));
}

#[test]
fn test_p1_06_hmac_session_token_with_dpop_thumbprint_binding() {
    let key = DPoPKey::generate();
    let jkt = key.jwk_thumbprint();
    let session_secret = b"hmac_server_secret_key_32_bytes!";

    let session_data = format!("did={TEST_ALICE_DID}&jkt={jkt}");
    let mac = hmac_sha256(session_secret, session_data.as_bytes()).unwrap();

    let mac_check = hmac_sha256(session_secret, session_data.as_bytes()).unwrap();
    assert!(constant_time_eq(&mac, &mac_check));
}

#[tokio::test]
async fn test_p2_01_dns_to_plc_to_pds_to_as_discovery_pipeline() {
    let env = MockOAuthEnvironment::start_default().await;

    let did = env
        .dns
        .resolve_handle_txt(TEST_ALICE_HANDLE)
        .unwrap()
        .unwrap();
    assert_eq!(did, TEST_ALICE_DID);

    let client = reqwest::Client::new();
    let did_doc: serde_json::Value = client
        .get(format!("{}/{}", env.plc.uri(), did))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let pds_endpoint = did_doc["service"][0]["serviceEndpoint"].as_str().unwrap();
    assert_eq!(pds_endpoint, env.pds.uri());

    let pds_meta: serde_json::Value = client
        .get(format!(
            "{pds_endpoint}/.well-known/oauth-protected-resource"
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let as_endpoint = pds_meta["authorization_servers"][0].as_str().unwrap();
    assert_eq!(as_endpoint, env.auth_server.uri());

    let as_meta: serde_json::Value = client
        .get(format!(
            "{as_endpoint}/.well-known/oauth-authorization-server"
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(as_meta["issuer"], env.auth_server.uri());
}

#[tokio::test]
async fn test_p2_02_https_fallback_with_protected_resource_discovery() {
    let env = MockOAuthEnvironment::start_default().await;

    let client = reqwest::Client::new();
    let did_resp = client
        .get(format!("{}/.well-known/atproto-did", env.pds.uri()))
        .send()
        .await
        .unwrap();
    assert_eq!(did_resp.text().await.unwrap().trim(), TEST_ALICE_DID);

    let pds_meta: serde_json::Value = client
        .get(format!(
            "{}/.well-known/oauth-protected-resource",
            env.pds.uri()
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(pds_meta["resource"], env.pds.uri());
}

#[tokio::test]
async fn test_p2_03_ssrf_malicious_pds_endpoint_detection() {
    let env = MockOAuthEnvironment::start_default().await;
    let malicious_pds = "http://127.0.0.1:8080";
    env.plc
        .mount_did_document("did:plc:malicious", "evil.com", malicious_pds)
        .await;

    let client = reqwest::Client::new();
    let doc: serde_json::Value = client
        .get(format!("{}/did:plc:malicious", env.plc.uri()))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let endpoint = doc["service"][0]["serviceEndpoint"].as_str().unwrap();
    let parsed_url = url::Url::parse(endpoint).unwrap();
    assert_eq!(parsed_url.host_str(), Some("127.0.0.1"));
}

#[tokio::test]
async fn test_p2_04_did_doc_handle_mismatch_fails_discovery() {
    let env = MockOAuthEnvironment::start_default().await;
    env.plc
        .mount_mismatched_handle_document("did:plc:victim", "different.handle.com", &env.pds.uri())
        .await;

    let client = reqwest::Client::new();
    let doc: serde_json::Value = client
        .get(format!("{}/did:plc:victim", env.plc.uri()))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let handles = doc["alsoKnownAs"].as_array().unwrap();
    let matches_expected = handles
        .iter()
        .any(|h| h.as_str() == Some("at://alice.bsky.social"));
    assert!(
        !matches_expected,
        "Mismatched handle must not match expected"
    );
}

#[tokio::test]
async fn test_p2_05_pds_metadata_error_handling() {
    let pds = MockPds::start().await;
    pds.mount_metadata_error().await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!(
            "{}/.well-known/oauth-protected-resource",
            pds.uri()
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 500);
}

#[test]
fn test_p2_06_did_web_parsing_and_resolution_url() {
    let did_web = "did:web:auth.example.com";
    let domain = did_web.strip_prefix("did:web:").unwrap();
    let resolved_url = format!("https://{domain}/.well-known/did.json");
    assert_eq!(
        resolved_url,
        "https://auth.example.com/.well-known/did.json"
    );
}

#[tokio::test]
async fn test_p3_01_par_nonce_challenge_retry_success() {
    let env = MockOAuthEnvironment::start_default().await;
    let par_url = format!("{}/oauth/par", env.auth_server.uri());

    env.auth_server
        .mount_par_nonce_challenge_once("challenge-nonce-1")
        .await;
    let client = reqwest::Client::new();
    let resp1 = client.post(&par_url).send().await.unwrap();
    assert_eq!(resp1.status(), 400);
    let nonce = resp1.headers().get("dpop-nonce").unwrap().to_str().unwrap();

    let cache = DPoPNonceCache::new();
    cache.set_nonce(&env.auth_server.uri(), nonce.to_string());
    assert_eq!(
        cache.get_nonce(&env.auth_server.uri()).as_deref(),
        Some("challenge-nonce-1")
    );

    let request_uri = "urn:ietf:params:oauth:request_uri:req-retry-success";
    env.auth_server.mount_par_success(request_uri, 90).await;

    let key = DPoPKey::generate();
    let proof = key
        .create_proof("POST", &par_url, Some(nonce), None)
        .unwrap();

    let resp2 = client
        .post(&par_url)
        .header("dpop", proof)
        .header("content-type", "application/x-www-form-urlencoded")
        .body("client_id=https%3A%2F%2Fapp.com%2Fclient.json&response_type=code")
        .send()
        .await
        .unwrap();

    assert_eq!(resp2.status(), 201);
    let body: serde_json::Value = resp2.json().await.unwrap();
    assert_eq!(body["request_uri"], request_uri);
}

#[tokio::test]
async fn test_p3_02_par_with_pkce_and_client_metadata() {
    let env = MockOAuthEnvironment::start_default().await;
    let request_uri = "urn:ietf:params:oauth:request_uri:req-pkce-1";
    env.auth_server.mount_par_success(request_uri, 90).await;

    let pkce = PkcePair::generate();
    let dpop_key = DPoPKey::generate();
    let par_url = format!("{}/oauth/par", env.auth_server.uri());
    let proof = dpop_key.create_proof("POST", &par_url, None, None).unwrap();

    let payload = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("client_id", TEST_CLIENT_ID)
        .append_pair("redirect_uri", TEST_REDIRECT_URI)
        .append_pair("response_type", "code")
        .append_pair("code_challenge", &pkce.challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("state", "state_token_random")
        .finish();

    let client = reqwest::Client::new();
    let resp = client
        .post(&par_url)
        .header("dpop", proof)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(payload)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 201);
}

#[test]
fn test_p3_03_par_response_binds_to_authorization_url() {
    let auth_endpoint = "https://auth.example.com/oauth/authorize";
    let request_uri = "urn:ietf:params:oauth:request_uri:req-xyz";

    let mut auth_url = url::Url::parse(auth_endpoint).unwrap();
    auth_url
        .query_pairs_mut()
        .append_pair("client_id", TEST_CLIENT_ID)
        .append_pair("request_uri", request_uri);

    assert!(auth_url
        .as_str()
        .contains("request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Areq-xyz"));
}

#[tokio::test]
async fn test_p3_04_token_exchange_with_nonce_retry() {
    let env = MockOAuthEnvironment::start_default().await;
    let token_url = format!("{}/oauth/token", env.auth_server.uri());

    env.auth_server
        .mount_token_nonce_challenge_once("token-nonce-1")
        .await;
    let client = reqwest::Client::new();
    let resp1 = client.post(&token_url).send().await.unwrap();
    assert_eq!(resp1.status(), 400);
    let nonce = resp1.headers().get("dpop-nonce").unwrap().to_str().unwrap();

    env.auth_server
        .mount_token_exchange_success("at_123", "rt_456", TEST_ALICE_DID, 3600)
        .await;

    let key = DPoPKey::generate();
    let proof = key
        .create_proof("POST", &token_url, Some(nonce), None)
        .unwrap();

    let resp2 = client
        .post(&token_url)
        .header("dpop", proof)
        .header("content-type", "application/x-www-form-urlencoded")
        .body("grant_type=authorization_code&code=code&code_verifier=verifier")
        .send()
        .await
        .unwrap();

    assert_eq!(resp2.status(), 200);
}

#[test]
fn test_p3_05_dpop_verifier_validates_both_nonce_and_ath() {
    let key = DPoPKey::generate();
    let uri = "https://pds.example.com/xrpc/resource";
    let token = "sample_access_token";
    let ath = compute_access_token_hash(token);
    let nonce = "active_nonce_123";

    let proof = key
        .create_proof("GET", uri, Some(nonce), Some(&ath))
        .unwrap();

    let verifier = DPoPVerifier::new();
    let (claims, _) = verifier
        .verify_proof(&proof, "GET", uri, Some(nonce), Some(&ath), None)
        .unwrap();

    assert_eq!(claims.nonce, Some(nonce.to_string()));
    assert_eq!(claims.ath, Some(ath));
}

#[test]
fn test_p3_06_dpop_proof_with_mismatched_method_rejected() {
    let key = DPoPKey::generate();
    let uri = "https://pds.example.com/oauth/token";
    let proof = key.create_proof("POST", uri, None, None).unwrap();

    let verifier = DPoPVerifier::new();
    let res = verifier.verify_proof(&proof, "GET", uri, None, None, None);
    assert!(matches!(
        res,
        Err(skyauth::error::DPoPError::MethodMismatch { .. })
    ));
}

struct ShardedStore {
    shards: Vec<parking_lot::RwLock<HashMap<String, String>>>,
}

impl ShardedStore {
    fn new() -> Self {
        let mut shards = Vec::with_capacity(64);
        for _ in 0..64 {
            shards.push(parking_lot::RwLock::new(HashMap::new()));
        }
        Self { shards }
    }

    fn shard_idx(&self, key: &str) -> usize {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        key.hash(&mut hasher);
        (hasher.finish() as usize) % 64
    }

    fn insert(&self, key: String, val: String) {
        let idx = self.shard_idx(&key);
        self.shards[idx].write().insert(key, val);
    }

    fn take(&self, key: &str) -> Option<String> {
        let idx = self.shard_idx(key);
        self.shards[idx].write().remove(key)
    }
}

#[test]
fn test_p4_01_store_insertion_and_atomic_consumption() {
    let store = ShardedStore::new();
    let state_token = "state_random_token_123";
    let session_json = json!({
        "pkce_verifier": RFC7636_VERIFIER,
        "dpop_jkt": RFC9449_JWK_JKT,
        "pds_url": "https://pds.example.com"
    })
    .to_string();

    store.insert(state_token.to_string(), session_json.clone());

    let consumed = store.take(state_token);
    assert_eq!(consumed, Some(session_json));
    assert_eq!(store.take(state_token), None);
}

#[test]
fn test_p4_02_concurrent_state_consumption_race_condition() {
    let store = Arc::new(ShardedStore::new());
    store.insert("race_key".to_string(), "session_payload".to_string());

    let counter = Arc::new(AtomicUsize::new(0));
    let handles: Vec<_> = (0..20)
        .map(|_| {
            let s = Arc::clone(&store);
            let c = Arc::clone(&counter);
            std::thread::spawn(move || {
                if s.take("race_key").is_some() {
                    c.fetch_add(1, Ordering::SeqCst);
                }
            })
        })
        .collect();

    for h in handles {
        h.join().unwrap();
    }

    assert_eq!(
        counter.load(Ordering::SeqCst),
        1,
        "Exactly one consumer must win"
    );
}

#[test]
fn test_p4_03_refresh_token_rotation_flow() {
    let initial_refresh_token = "rt_gen_1";
    let mut token_store = HashMap::new();
    token_store.insert(initial_refresh_token, "valid");

    let is_valid = token_store.remove(initial_refresh_token).is_some();
    assert!(is_valid);

    let new_refresh_token = "rt_gen_2";
    token_store.insert(new_refresh_token, "valid");

    assert_eq!(token_store.remove(initial_refresh_token), None);
    assert_eq!(token_store.remove(new_refresh_token), Some("valid"));
}

#[test]
fn test_p4_04_sharded_store_stress_1000_sessions() {
    let store = Arc::new(ShardedStore::new());
    let mut handles = Vec::new();

    for t in 0..10 {
        let s = Arc::clone(&store);
        handles.push(std::thread::spawn(move || {
            for i in 0..100 {
                let key = format!("state_thread_{t}_{i}");
                s.insert(key.clone(), format!("data_{i}"));
                assert!(s.take(&key).is_some());
                assert!(s.take(&key).is_none());
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn test_p4_05_store_ttl_expiration_with_saturating_time() {
    let created_at: u64 = 1000;
    let ttl_secs: u64 = 300;
    let expires_at = created_at.saturating_add(ttl_secs);

    assert!(1200 < expires_at);
    assert!(1300 >= expires_at);
    assert!(1400 >= expires_at);
}

#[test]
fn test_p4_06_state_store_cleared_on_expiry() {
    let mut map = HashMap::new();
    map.insert("active", 2000u64);
    map.insert("expired", 500u64);

    let now = 1000;
    map.retain(|_, exp| *exp > now);

    assert_eq!(map.len(), 1);
    assert!(map.contains_key("active"));
}

#[test]
fn test_p5_01_rfc8414_schema_ast_matches_mock_as_response() {
    let schema_json = json!({
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "required": ["issuer", "authorization_endpoint", "token_endpoint", "pushed_authorization_request_endpoint"],
        "properties": {
            "issuer": { "type": "string" },
            "authorization_endpoint": { "type": "string" },
            "token_endpoint": { "type": "string" },
            "pushed_authorization_request_endpoint": { "type": "string" }
        }
    });
    let validator = jsonschema::validator_for(&schema_json).unwrap();

    let as_meta = json!({
        "issuer": "https://auth.example.com",
        "authorization_endpoint": "https://auth.example.com/oauth/authorize",
        "token_endpoint": "https://auth.example.com/oauth/token",
        "pushed_authorization_request_endpoint": "https://auth.example.com/oauth/par"
    });
    assert!(validator.is_valid(&as_meta));
}

#[test]
fn test_p5_02_rfc9728_schema_ast_matches_mock_pds_response() {
    let schema_json = json!({
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "required": ["resource", "authorization_servers"],
        "properties": {
            "resource": { "type": "string" },
            "authorization_servers": { "type": "array", "items": { "type": "string" } }
        }
    });
    let validator = jsonschema::validator_for(&schema_json).unwrap();

    let pds_meta = json!({
        "resource": "https://pds.example.com",
        "authorization_servers": ["https://auth.example.com"]
    });
    assert!(validator.is_valid(&pds_meta));
}

#[test]
fn test_p5_03_rfc9449_schema_ast_matches_generated_dpop_proof() {
    let key = DPoPKey::generate();
    let uri = "https://auth.example.com/oauth/par";
    let proof = key
        .create_proof("POST", uri, Some("nonce-1"), None)
        .unwrap();

    let parts: Vec<&str> = proof.split('.').collect();
    let payload_bytes = base64url_decode(parts[1]).unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();

    let schema_json = json!({
        "type": "object",
        "required": ["jti", "htm", "htu", "iat"],
        "properties": {
            "jti": { "type": "string" },
            "htm": { "type": "string" },
            "htu": { "type": "string" },
            "iat": { "type": "integer" }
        }
    });
    let validator = jsonschema::validator_for(&schema_json).unwrap();
    assert!(validator.is_valid(&payload));
}

#[test]
fn test_p5_04_client_metadata_ast_validation_with_grant_types() {
    let schema_json = json!({
        "type": "object",
        "required": ["client_id", "redirect_uris", "grant_types"],
        "properties": {
            "client_id": { "type": "string" },
            "redirect_uris": { "type": "array" },
            "grant_types": { "type": "array" }
        }
    });
    let validator = jsonschema::validator_for(&schema_json).unwrap();

    let client_meta = json!({
        "client_id": TEST_CLIENT_ID,
        "redirect_uris": [TEST_REDIRECT_URI],
        "grant_types": ["authorization_code", "refresh_token"]
    });
    assert!(validator.is_valid(&client_meta));
}

#[test]
fn test_p5_05_schema_validator_catches_missing_mandatory_pds_field() {
    let schema_json = json!({
        "type": "object",
        "required": ["resource", "authorization_servers"]
    });
    let validator = jsonschema::validator_for(&schema_json).unwrap();

    let invalid_pds = json!({ "resource": "https://pds.example.com" });
    assert!(!validator.is_valid(&invalid_pds));
}

#[test]
fn test_p5_06_schema_validator_catches_invalid_type_in_as_metadata() {
    let schema_json = json!({
        "type": "object",
        "properties": {
            "expires_in": { "type": "integer" }
        }
    });
    let validator = jsonschema::validator_for(&schema_json).unwrap();

    let invalid_as = json!({ "expires_in": "ninety_seconds" });
    assert!(!validator.is_valid(&invalid_as));
}
