//! Credential observability and explicit persistence tests.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

use skyauth::client::{CallbackParams, StoredStateEntry, TokenResponse};
use skyauth::dpop::DPoPKey;
use skyauth::integrations::OAuthCallbackQuery;
use skyauth::par::ParParameters;
use skyauth::session::{OAuthSession, SecretExportPermit};
use static_assertions::assert_not_impl_any;

assert_not_impl_any!(OAuthSession: serde::Serialize, serde::de::DeserializeOwned);
assert_not_impl_any!(DPoPKey: serde::Serialize, serde::de::DeserializeOwned);
assert_not_impl_any!(TokenResponse: serde::Serialize);
assert_not_impl_any!(ParParameters: serde::Serialize, serde::de::DeserializeOwned);

#[test]
fn debug_output_redacts_transaction_and_session_credentials() {
    let access = "canary-access-token-0f90";
    let refresh = "canary-refresh-token-31a2";
    let state = "canary-state-b173";
    let code = "canary-code-f987";
    let verifier = "canary-verifier-9dc4_abcdefghijklmnopqrstuvwxyz";

    let token: TokenResponse = serde_json::from_value(serde_json::json!({
        "access_token": access,
        "refresh_token": refresh,
        "token_type": "DPoP",
        "scope": "atproto",
        "sub": "did:plc:alice123"
    }))
    .unwrap();
    let session = OAuthSession::new(
        "did:plc:alice123",
        access,
        Some(refresh.to_string()),
        "DPoP",
        Some("atproto".to_string()),
        Some(300),
        DPoPKey::generate(),
        Some("https://pds.example.com".to_string()),
        Some("https://auth.example.com".to_string()),
        Some("https://auth.example.com/token".to_string()),
    )
    .unwrap();
    let transaction = StoredStateEntry::builder(state, DPoPKey::generate())
        .client_id("https://app.example.com/client.json")
        .code_verifier(verifier)
        .issuer("https://auth.example.com")
        .identity(Some("did:plc:alice123".to_string()), None)
        .redirect_uri("https://app.example.com/callback")
        .pds_endpoint("https://pds.example.com")
        .token_endpoint("https://auth.example.com/token")
        .scopes("atproto")
        .build()
        .unwrap();
    let callback = CallbackParams::new(code, state).with_iss("https://auth.example.com");
    let assertion = "canary-client-assertion-c724";
    let par = ParParameters::new(
        "https://app.example.com/client.json",
        "https://app.example.com/callback",
        "atproto",
        state,
        "E9Melhoa2OwvFrGMTJguCH5rtx64ZW_SoRO823Ht_K0",
    )
    .with_client_assertion(
        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        assertion,
    );

    let combined = format!("{token:?} {session:?} {transaction:?} {callback:?} {par:?}");
    for canary in [access, refresh, state, code, verifier, assertion] {
        assert!(!combined.contains(canary), "debug output exposed {canary}");
    }
}

#[test]
fn persistence_requires_explicit_export_and_round_trips() {
    let key = DPoPKey::generate();
    let expected_thumbprint = key.jwk_thumbprint();
    let session = OAuthSession::new(
        "did:plc:alice123",
        "persisted-access-canary",
        Some("persisted-refresh-canary".to_string()),
        "DPoP",
        Some("atproto repo:app.example.post".to_string()),
        Some(300),
        key,
        Some("https://pds.example.com".to_string()),
        Some("https://auth.example.com".to_string()),
        Some("https://auth.example.com/token".to_string()),
    )
    .unwrap();

    let exported = session
        .export_for_persistence(SecretExportPermit::for_encrypted_persistence())
        .unwrap();
    let imported = OAuthSession::import_from_persistence(&exported).unwrap();

    assert_eq!(imported.session_id(), session.session_id());
    assert_eq!(imported.generation(), session.generation());
    assert_eq!(imported.sub(), session.sub());
    assert_eq!(
        imported.expose_access_token(),
        session.expose_access_token()
    );
    assert_eq!(
        imported.expose_refresh_token(),
        session.expose_refresh_token()
    );
    assert_eq!(imported.scope(), session.scope());
    assert_eq!(imported.pds_endpoint(), session.pds_endpoint());
    assert_eq!(imported.auth_server_issuer(), session.auth_server_issuer());
    assert_eq!(imported.token_endpoint(), session.token_endpoint());
    assert_eq!(
        imported
            .expires_at()
            .unwrap()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        session
            .expires_at()
            .unwrap()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    );
    assert_eq!(
        imported
            .created_at()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        session
            .created_at()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    );
    assert_eq!(imported.dpop_key().jwk_thumbprint(), expected_thumbprint);
}

#[test]
fn callback_error_text_is_not_observable() {
    let canary = "canary-server-error-890d";
    let query = OAuthCallbackQuery::new_error("invalid_request", Some(canary.to_string()));
    let error = query.to_callback_params().unwrap_err();
    assert!(!format!("{error:?} {error}").contains(canary));
}
