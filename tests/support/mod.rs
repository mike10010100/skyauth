#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    dead_code,
    missing_docs
)]

#[cfg(feature = "tower")]
use std::sync::Arc;
#[cfg(feature = "tower")]
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(feature = "tower")]
use p256::ecdsa::SigningKey;
#[cfg(feature = "tower")]
use rand::RngCore;
#[cfg(feature = "tower")]
use serde_json::json;
#[cfg(feature = "tower")]
use skyauth::crypto::{base64url_encode, sign_p256_raw, verifying_key_to_coordinates};
#[cfg(feature = "tower")]
use skyauth::dpop::{DPoPVerifier, JwkEc};
#[cfg(feature = "tower")]
use skyauth::integrations::tower::{
    AuthorizationPolicy, ExternalUrlPolicy, InMemoryDPoPNonceStore, InMemoryDPoPReplayStore,
    JwtAccessTokenValidator, JwtTrustedIssuer, NoncePolicy, OAuthAuthLayer, RouteScopePolicy,
};

#[cfg(feature = "tower")]
pub struct TestTokenAuthority {
    signing_key: SigningKey,
    validator: Arc<JwtAccessTokenValidator>,
}

#[cfg(feature = "tower")]
impl TestTokenAuthority {
    pub fn new() -> Self {
        let signing_key = SigningKey::random(&mut rand::thread_rng());
        let (x, y) = verifying_key_to_coordinates(signing_key.verifying_key());
        let jwk = JwkEc {
            kty: "EC".to_string(),
            crv: "P-256".to_string(),
            x: base64url_encode(&x),
            y: base64url_encode(&y),
        };
        let issuer = JwtTrustedIssuer::new(
            "https://issuer.example.com",
            ["https://pds.example.com".to_string()],
        )
        .unwrap()
        .add_signing_key("test-key", jwk)
        .unwrap();
        let validator = JwtAccessTokenValidator::new([issuer]).unwrap();
        Self {
            signing_key,
            validator: Arc::new(validator),
        }
    }

    pub fn issue(&self, confirmation_thumbprint: &str) -> String {
        self.issue_with_typ_and_claims(
            confirmation_thumbprint,
            "at+jwt",
            "did:plc:abcdefgh",
            "atproto transition:generic",
            "https://issuer.example.com",
            "https://pds.example.com",
            300,
        )
    }

    pub fn issue_with_claims(
        &self,
        confirmation_thumbprint: &str,
        subject: &str,
        scope: &str,
        issuer: &str,
        audience: &str,
        lifetime_secs: i64,
    ) -> String {
        self.issue_with_typ_and_claims(
            confirmation_thumbprint,
            "at+jwt",
            subject,
            scope,
            issuer,
            audience,
            lifetime_secs,
        )
    }

    pub fn issue_with_typ(&self, confirmation_thumbprint: &str, typ: &str) -> String {
        self.issue_with_typ_and_claims(
            confirmation_thumbprint,
            typ,
            "did:plc:abcdefgh",
            "atproto transition:generic",
            "https://issuer.example.com",
            "https://pds.example.com",
            300,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn issue_with_typ_and_claims(
        &self,
        confirmation_thumbprint: &str,
        typ: &str,
        subject: &str,
        scope: &str,
        issuer: &str,
        audience: &str,
        lifetime_secs: i64,
    ) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let exp = if lifetime_secs.is_negative() {
            now.saturating_sub(lifetime_secs.unsigned_abs())
        } else {
            now.saturating_add(lifetime_secs.unsigned_abs())
        };
        let mut jti_bytes = [0_u8; 16];
        rand::thread_rng().fill_bytes(&mut jti_bytes);
        let header = json!({"typ": typ, "alg": "ES256", "kid": "test-key"});
        let claims = json!({
            "iss": issuer,
            "sub": subject,
            "aud": audience,
            "exp": exp,
            "iat": now,
            "scope": scope,
            "jti": base64url_encode(&jti_bytes),
            "cnf": {"jkt": confirmation_thumbprint}
        });
        let header = base64url_encode(serde_json::to_string(&header).unwrap().as_bytes());
        let claims = base64url_encode(serde_json::to_string(&claims).unwrap().as_bytes());
        let signing_input = format!("{header}.{claims}");
        let signature = sign_p256_raw(&self.signing_key, signing_input.as_bytes()).unwrap();
        format!("{signing_input}.{}", base64url_encode(&signature))
    }

    pub fn layer(&self, verifier: Arc<DPoPVerifier>) -> OAuthAuthLayer {
        self.layer_with_policy(
            verifier,
            RouteScopePolicy::new(Vec::<String>::new(), NoncePolicy::Disabled),
        )
    }

    pub fn layer_with_policy(
        &self,
        verifier: Arc<DPoPVerifier>,
        routes: RouteScopePolicy,
    ) -> OAuthAuthLayer {
        OAuthAuthLayer::new(
            verifier,
            self.validator.clone(),
            Arc::new(InMemoryDPoPReplayStore::new(4096).unwrap()),
            Arc::new(InMemoryDPoPNonceStore::new(4096, Duration::from_secs(300)).unwrap()),
            ExternalUrlPolicy::fixed_origin("https://pds.example.com").unwrap(),
            AuthorizationPolicy::new(
                ["https://issuer.example.com".to_string()],
                ["https://pds.example.com".to_string()],
                routes,
            )
            .unwrap(),
        )
    }
}
