//! Secret redaction and zeroization verification tests.
use skyauth::client::{OAuthClientMetadata, StoredStateEntry};
use skyauth::dpop::DPoPKey;
use skyauth::integrations::AuthenticatedUser;
use skyauth::session::OAuthSession;
use std::time::SystemTime;
use zeroize::Zeroize;

#[test]
fn test_oauth_session_debug_redacts_tokens() -> Result<(), Box<dyn std::error::Error>> {
    let key = DPoPKey::generate();
    let session = OAuthSession::new(
        "did:plc:testuser12345",
        "super_secret_access_token_xyz987",
        Some("super_secret_refresh_token_abc123".to_string()),
        "DPoP",
        Some("atproto".to_string()),
        Some(3600),
        key,
        Some("https://pds.example.com".to_string()),
        Some("https://bsky.social".to_string()),
        Some("https://bsky.social/oauth/token".to_string()),
    )?;

    let debug_output = format!("{session:?}");
    assert!(!debug_output.contains("super_secret_access_token_xyz987"));
    assert!(!debug_output.contains("super_secret_refresh_token_abc123"));
    assert!(debug_output.contains("[REDACTED]"));
    assert!(debug_output.contains("did:plc:testuser12345"));
    Ok(())
}

#[test]
fn test_authenticated_user_debug_redacts_access_token() {
    let user = AuthenticatedUser::new(
        "did:plc:testuser12345",
        "super_secret_bearer_token_999",
        "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I",
    );

    let debug_output = format!("{user:?}");
    assert!(!debug_output.contains("super_secret_bearer_token_999"));
    assert!(debug_output.contains("[REDACTED]"));
    assert!(debug_output.contains("did:plc:testuser12345"));
}

#[test]
fn test_authenticated_user_serialization_omits_access_token(
) -> Result<(), Box<dyn std::error::Error>> {
    let user = AuthenticatedUser::new(
        "did:plc:testuser12345",
        "super_secret_bearer_token_999",
        "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I",
    );

    let json = serde_json::to_string(&user)?;
    assert!(!json.contains("super_secret_bearer_token_999"));
    assert!(!json.contains("access_token"));
    assert!(json.contains("did:plc:testuser12345"));
    assert!(json.contains("0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"));

    // Fail-closed deserialization: a serialized view omits the token, so it
    // cannot be deserialized back into a credential-bearing AuthenticatedUser.
    assert!(serde_json::from_str::<AuthenticatedUser>(&json).is_err());

    // A present-but-empty token is rejected outright.
    let empty_token_json =
        r#"{"did":"did:plc:x","access_token":"","dpop_thumbprint":"jkt","scope":null}"#;
    assert!(serde_json::from_str::<AuthenticatedUser>(empty_token_json).is_err());

    // A properly-supplied non-empty token deserializes fine.
    let full_json =
        r#"{"did":"did:plc:x","access_token":"real_token","dpop_thumbprint":"jkt","scope":null}"#;
    let parsed: AuthenticatedUser = serde_json::from_str(full_json)?;
    assert_eq!(parsed.access_token(), "real_token");
    Ok(())
}

#[test]
fn test_stored_state_entry_debug_redacts_code_verifier() {
    let key = DPoPKey::generate();
    let entry = StoredStateEntry {
        state: "state_token_123".to_string(),
        client_id: "https://app.example.com/client-metadata.json".to_string(),
        code_verifier: "secret_pkce_code_verifier_long_random_string_123456789".to_string(),
        dpop_key: key,
        issuer: "https://bsky.social".to_string(),
        did: Some("did:plc:alice".to_string()),
        handle: Some("alice.bsky.social".to_string()),
        redirect_uri: "https://app.example.com/callback".to_string(),
        pds_endpoint: "https://pds.example.com".to_string(),
        token_endpoint: "https://bsky.social/oauth/token".to_string(),
        scopes: "atproto".to_string(),
        created_at: SystemTime::now(),
        expires_in_secs: 300,
    };

    let debug_output = format!("{entry:?}");
    assert!(!debug_output.contains("secret_pkce_code_verifier_long_random_string_123456789"));
    assert!(debug_output.contains("[REDACTED]"));
    assert!(debug_output.contains("state_token_123"));
}

#[test]
fn test_oauth_client_metadata_debug_redacts_client_secret() {
    let metadata = OAuthClientMetadata::new(
        "https://app.example.com/client-metadata.json",
        "https://app.example.com/callback",
    )
    .with_client_secret("top_secret_confidential_client_key_999");

    let debug_output = format!("{metadata:?}");
    assert!(!debug_output.contains("top_secret_confidential_client_key_999"));
    assert!(debug_output.contains("[REDACTED]"));
}

#[test]
fn test_dpop_key_debug_redacts_private_scalar() -> Result<(), Box<dyn std::error::Error>> {
    let key = DPoPKey::generate();
    let debug_output = format!("{key:?}");
    let raw_b64 = key.to_bytes_b64();
    let raw_hex = hex::encode(key.to_bytes().as_slice());

    assert!(debug_output.contains("DPoPKey"));
    assert!(debug_output.contains("thumbprint"));
    assert!(!debug_output.contains(raw_b64.as_str()));
    assert!(!debug_output.contains(&raw_hex));
    assert!(!debug_output.contains("signing_key"));
    assert!(!debug_output.contains("private_key"));
    Ok(())
}

#[test]
fn test_zeroize_clears_session_and_state_tokens() -> Result<(), Box<dyn std::error::Error>> {
    let mut session = OAuthSession::new(
        "did:plc:testuser12345",
        "sensitive_access_token",
        Some("sensitive_refresh_token".to_string()),
        "DPoP",
        Some("atproto".to_string()),
        Some(3600),
        DPoPKey::generate(),
        None,
        None,
        None,
    )?;

    assert_eq!(session.access_token, "sensitive_access_token");
    assert_eq!(
        session.refresh_token.as_deref(),
        Some("sensitive_refresh_token")
    );

    session.zeroize();

    assert!(session.access_token.is_empty() || session.access_token.chars().all(|c| c == '\0'));
    if let Some(ref rt) = session.refresh_token {
        assert!(rt.is_empty() || rt.chars().all(|c| c == '\0'));
    }
    Ok(())
}
