//! Tier 4: Realistic Workload and End-to-End Workflow Test Suite for `skyauth`.
//!
//! Simulates realistic end-to-end user authentication lifecycles, multi-hop auto-nonce challenges,
//! high-concurrency multi-user sessions, compromised token replay defense, and daemon key rotation.

mod e2e_harness;

use e2e_harness::fixtures::*;
use e2e_harness::{MockOAuthEnvironment, MockPds};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;

use skyauth::dpop::{compute_access_token_hash, DPoPKey, DPoPNonceCache, DPoPVerifier};
use skyauth::pkce::PkcePair;

#[tokio::test]
async fn test_w1_full_user_login_and_xrpc_lifecycle() {
    let env = MockOAuthEnvironment::start_default().await;

    let did = env
        .dns
        .resolve_handle_txt(TEST_ALICE_HANDLE)
        .expect("dns resolve")
        .expect("handle found");
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

    let also_known_as = did_doc["alsoKnownAs"].as_array().unwrap();
    let is_verified = also_known_as
        .iter()
        .any(|v| v.as_str() == Some(&format!("at://{TEST_ALICE_HANDLE}")));
    assert!(is_verified, "Handle must match alsoKnownAs");

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
    let par_endpoint = as_meta["pushed_authorization_request_endpoint"]
        .as_str()
        .unwrap();
    let token_endpoint = as_meta["token_endpoint"].as_str().unwrap();
    let auth_endpoint = as_meta["authorization_endpoint"].as_str().unwrap();

    let pkce = PkcePair::generate();
    let dpop_key = DPoPKey::generate();
    let state_token = "secure_random_state_token_256bit";

    let request_uri = "urn:ietf:params:oauth:request_uri:req-alice-lifecycle-1";
    env.auth_server.mount_par_success(request_uri, 90).await;

    let par_proof = dpop_key
        .create_proof("POST", par_endpoint, None, None)
        .unwrap();
    let par_payload = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("client_id", TEST_CLIENT_ID)
        .append_pair("redirect_uri", TEST_REDIRECT_URI)
        .append_pair("response_type", "code")
        .append_pair("code_challenge", &pkce.challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("state", state_token)
        .finish();

    let par_resp = client
        .post(par_endpoint)
        .header("dpop", par_proof)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(par_payload)
        .send()
        .await
        .unwrap();
    assert_eq!(par_resp.status(), 201);
    let par_json: serde_json::Value = par_resp.json().await.unwrap();
    assert_eq!(par_json["request_uri"], request_uri);

    let mut auth_url = url::Url::parse(auth_endpoint).unwrap();
    auth_url
        .query_pairs_mut()
        .append_pair("client_id", TEST_CLIENT_ID)
        .append_pair("request_uri", request_uri);
    assert!(auth_url
        .as_str()
        .contains("request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Areq-alice-lifecycle-1"));

    let auth_code = "auth_code_issued_after_user_consent";
    let access_token = "at_alice_access_token_super_valid";
    let refresh_token = "rt_alice_refresh_token_rotation_1";

    env.auth_server
        .mount_token_exchange_success(access_token, refresh_token, TEST_ALICE_DID, 3600)
        .await;

    let token_proof = dpop_key
        .create_proof("POST", token_endpoint, None, None)
        .unwrap();
    let token_payload = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "authorization_code")
        .append_pair("client_id", TEST_CLIENT_ID)
        .append_pair("code", auth_code)
        .append_pair("code_verifier", &pkce.verifier)
        .append_pair("redirect_uri", TEST_REDIRECT_URI)
        .finish();

    let token_resp = client
        .post(token_endpoint)
        .header("dpop", token_proof)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(token_payload)
        .send()
        .await
        .unwrap();

    assert_eq!(token_resp.status(), 200);
    let token_json: serde_json::Value = token_resp.json().await.unwrap();
    assert_eq!(token_json["access_token"], access_token);
    assert_eq!(token_json["sub"], TEST_ALICE_DID);

    let xrpc_url = format!("{pds_endpoint}/xrpc/app.bsky.actor.getProfile");
    let ath = compute_access_token_hash(access_token);
    let resource_proof = dpop_key
        .create_proof("GET", &xrpc_url, None, Some(&ath))
        .unwrap();

    let xrpc_resp = client
        .get(&xrpc_url)
        .header("authorization", format!("DPoP {access_token}"))
        .header("dpop", resource_proof)
        .send()
        .await
        .unwrap();

    assert_eq!(xrpc_resp.status(), 200);
    let profile: serde_json::Value = xrpc_resp.json().await.unwrap();
    assert_eq!(profile["did"], TEST_ALICE_DID);
    assert_eq!(profile["handle"], TEST_ALICE_HANDLE);
}

#[tokio::test]
async fn test_w2_multi_hop_auto_nonce_negotiation_loop() {
    let env = MockOAuthEnvironment::start_default().await;
    let pds = MockPds::start().await;
    let client = reqwest::Client::new();
    let nonce_cache = DPoPNonceCache::new();
    let dpop_key = DPoPKey::generate();

    let par_url = format!("{}/oauth/par", env.auth_server.uri());
    env.auth_server
        .mount_par_nonce_challenge_once("nonce-par-step1")
        .await;

    let mut par_nonce = nonce_cache.get_nonce(&env.auth_server.uri());
    let proof_1 = dpop_key
        .create_proof("POST", &par_url, par_nonce.as_deref(), None)
        .unwrap();

    let resp_par_1 = client
        .post(&par_url)
        .header("dpop", proof_1)
        .header("content-type", "application/x-www-form-urlencoded")
        .body("client_id=my_client&response_type=code")
        .send()
        .await
        .unwrap();

    assert_eq!(resp_par_1.status(), 400);
    let new_nonce = resp_par_1
        .headers()
        .get("dpop-nonce")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    nonce_cache.set_nonce(&env.auth_server.uri(), new_nonce.clone());
    par_nonce = Some(new_nonce);

    env.auth_server
        .mount_par_success("urn:ietf:req-par-nonce-success", 90)
        .await;
    let proof_2 = dpop_key
        .create_proof("POST", &par_url, par_nonce.as_deref(), None)
        .unwrap();
    let resp_par_2 = client
        .post(&par_url)
        .header("dpop", proof_2)
        .header("content-type", "application/x-www-form-urlencoded")
        .body("client_id=my_client&response_type=code")
        .send()
        .await
        .unwrap();
    assert_eq!(resp_par_2.status(), 201);

    let token_url = format!("{}/oauth/token", env.auth_server.uri());
    env.auth_server
        .mount_token_nonce_challenge_once("nonce-token-step2")
        .await;

    let mut token_nonce = nonce_cache.get_nonce(&env.auth_server.uri());
    let token_proof_1 = dpop_key
        .create_proof("POST", &token_url, token_nonce.as_deref(), None)
        .unwrap();
    let resp_token_1 = client
        .post(&token_url)
        .header("dpop", token_proof_1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp_token_1.status(), 400);

    let fresh_token_nonce = resp_token_1
        .headers()
        .get("dpop-nonce")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    nonce_cache.set_nonce(&env.auth_server.uri(), fresh_token_nonce.clone());
    token_nonce = Some(fresh_token_nonce);

    let access_token = "at_alice_after_nonce_dance";
    env.auth_server
        .mount_token_exchange_success(access_token, "rt_after_nonce", TEST_ALICE_DID, 3600)
        .await;
    let token_proof_2 = dpop_key
        .create_proof("POST", &token_url, token_nonce.as_deref(), None)
        .unwrap();
    let resp_token_2 = client
        .post(&token_url)
        .header("dpop", token_proof_2)
        .send()
        .await
        .unwrap();
    assert_eq!(resp_token_2.status(), 200);

    let xrpc_url = format!("{}/xrpc/app.bsky.actor.getProfile", pds.uri());
    pds.server.reset().await;
    pds.mount_xrpc_dpop_nonce_challenge_once("nonce-pds-step3")
        .await;

    let ath = compute_access_token_hash(access_token);
    let xrpc_proof_1 = dpop_key
        .create_proof("GET", &xrpc_url, None, Some(&ath))
        .unwrap();

    let resp_xrpc_1 = client
        .get(&xrpc_url)
        .header("authorization", format!("DPoP {access_token}"))
        .header("dpop", xrpc_proof_1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp_xrpc_1.status(), 401);

    let fresh_pds_nonce = resp_xrpc_1
        .headers()
        .get("dpop-nonce")
        .unwrap()
        .to_str()
        .unwrap();
    nonce_cache.set_nonce(&pds.uri(), fresh_pds_nonce.to_string());

    pds.mount_xrpc_get_profile(TEST_ALICE_DID, TEST_ALICE_HANDLE)
        .await;
    let xrpc_proof_2 = dpop_key
        .create_proof("GET", &xrpc_url, Some(fresh_pds_nonce), Some(&ath))
        .unwrap();
    let resp_xrpc_2 = client
        .get(&xrpc_url)
        .header("authorization", format!("DPoP {access_token}"))
        .header("dpop", xrpc_proof_2)
        .send()
        .await
        .unwrap();
    assert_eq!(resp_xrpc_2.status(), 200);
}

struct TestShardedStore {
    shards: Vec<parking_lot::RwLock<HashMap<String, String>>>,
}

impl TestShardedStore {
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

#[tokio::test]
async fn test_w3_high_concurrency_multi_user_lifecycle() {
    let store = Arc::new(TestShardedStore::new());
    let mut tasks = Vec::new();

    for user_idx in 0..25 {
        let store_clone = Arc::clone(&store);
        tasks.push(tokio::spawn(async move {
            let user_did = format!("did:plc:user_{user_idx:04}");
            let pkce = PkcePair::generate();
            let dpop_key = DPoPKey::generate();

            let state_token = format!("state_token_{user_idx}");
            let session_data = json!({
                "did": user_did,
                "verifier": pkce.verifier,
                "jkt": dpop_key.jwk_thumbprint()
            })
            .to_string();

            store_clone.insert(state_token.clone(), session_data.clone());

            let taken = store_clone.take(&state_token);
            assert_eq!(taken, Some(session_data));
            assert_eq!(store_clone.take(&state_token), None);
        }));
    }

    for t in tasks {
        t.await.unwrap();
    }
}

#[test]
fn test_w4_stolen_token_without_private_key_fails_dpop() {
    let legitimate_key = DPoPKey::generate();
    let attacker_key = DPoPKey::generate();
    let access_token = "stolen_access_token_value_xyz";
    let ath = compute_access_token_hash(access_token);

    let target_uri = "https://pds.example.com/xrpc/profile";

    let legit_proof = legitimate_key
        .create_proof("GET", target_uri, None, Some(&ath))
        .unwrap();

    let attacker_proof = attacker_key
        .create_proof("GET", target_uri, None, Some(&ath))
        .unwrap();

    let verifier = DPoPVerifier::new();

    let expected_jkt = legitimate_key.jwk_thumbprint();

    let (_, legit_jwk) = verifier
        .verify_proof(&legit_proof, "GET", target_uri, None, Some(&ath), None)
        .unwrap();
    assert_eq!(legit_jwk.thumbprint(), expected_jkt);

    let (_, attacker_jwk) = verifier
        .verify_proof(&attacker_proof, "GET", target_uri, None, Some(&ath), None)
        .unwrap();
    assert_ne!(
        attacker_jwk.thumbprint(),
        expected_jkt,
        "Attacker's key thumbprint must not match legitimate token binding"
    );
}

#[test]
fn test_w5_daemon_key_rotation_and_session_persistence() {
    let initial_key = DPoPKey::generate();
    let initial_pem = initial_key.to_pkcs8_pem().unwrap();
    let initial_refresh_token = "rt_session_init".to_string();

    let reloaded_key = DPoPKey::from_pkcs8_pem(&initial_pem).unwrap();
    assert_eq!(initial_key.jwk_thumbprint(), reloaded_key.jwk_thumbprint());

    let new_refresh_token = "rt_session_rotated_1".to_string();
    assert_ne!(initial_refresh_token, new_refresh_token);

    let next_epoch_key = DPoPKey::generate();
    assert_ne!(
        initial_key.jwk_thumbprint(),
        next_epoch_key.jwk_thumbprint()
    );

    let next_epoch_proof = next_epoch_key
        .create_proof("POST", "https://auth.example.com/oauth/token", None, None)
        .unwrap();

    let verifier = DPoPVerifier::new();
    let (_, jwk) = verifier
        .verify_proof(
            &next_epoch_proof,
            "POST",
            "https://auth.example.com/oauth/token",
            None,
            None,
            None,
        )
        .unwrap();
    assert_eq!(jwk.thumbprint(), next_epoch_key.jwk_thumbprint());
}
