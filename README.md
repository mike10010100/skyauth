# SkyAuth

SkyAuth is a Rust library for the current AT Protocol OAuth profile. It provides strict identity
and metadata discovery, PKCE, PAR, DPoP-bound token exchange and refresh, protected XRPC requests,
single-use authorization state, granular scope parsing, and optional framework integrations.

The crate itself forbids unsafe code. Network access is routed through one transport that resolves
and validates every address, pins the selected destination, disables implicit redirects, and bounds
response bodies. Framework features are opt-in.

## Status

Version `0.2.0` is a breaking hardening release. It supports public AT Protocol clients. A
confidential-client configuration is rejected until `private_key_jwt` support is complete.

The supported minimum Rust version is 1.85.

## Installation

```toml
[dependencies]
skyauth = "0.2"
```

Enable only the framework adapters you use:

```toml
skyauth = { version = "0.2", features = ["axum", "tower"] }
```

## OAuth client

```no_run
use skyauth::client::{AtprotoOAuthClient, CallbackParams, OAuthClientMetadata};

# async fn run() -> Result<(), Box<dyn std::error::Error>> {
let metadata = OAuthClientMetadata::new(
    "https://app.example.com/oauth-client-metadata.json",
    "https://app.example.com/oauth/callback",
);

let client = AtprotoOAuthClient::builder()
    .client_metadata(metadata)
    .in_memory_state_store()
    .build()?;

let request = client.initiate_login("alice.example.com").await?;
println!("redirect the browser to {}", request.authorization_url());

let callback = CallbackParams::new("authorization-code", request.expose_state())
    .with_iss("https://issuer.example.com");
let session = client.handle_callback(&callback).await?;

let response = client
    .send_dpop_request(
        session.dpop_key(),
        reqwest::Method::GET,
        "https://pds.example.com/xrpc/app.bsky.actor.getProfile?actor=alice.example.com",
        Some(session.expose_access_token()),
        None,
        None,
    )
    .await?;
assert!(response.status().is_success());
# Ok(())
# }
```

The builder requires an explicit state store. `.in_memory_state_store()` selects the bundled
64-shard store. A distributed `OAuthStore` implementation must preserve atomic insert, consume,
refresh lease, and refresh commit semantics.

## Inbound Tower authorization

The `tower` feature requires an `AccessTokenValidator`, a bounded replay store, a nonce manager,
trusted external URL configuration, issuer and audience policy, and route scopes. A DPoP proof is
accepted only with an independently validated access token whose `cnf.jkt` matches the proof key.
See the public types in `skyauth::integrations::tower` and the integration tests for complete setup.

## Permissions

`ScopeSet` parses the current AT Protocol permission grammar, including `repo`, `rpc`, `blob`,
`account`, `identity`, and `include` entries. Permission-set expansion is available through an
`AuthenticatedLexiconResolver`; implementations are responsible for authenticated DNS, DID,
repository, commit, MST, collection, record-key, and CID verification.

## Session persistence

Sessions do not implement generic Serde traits. Credential persistence is explicit:

```no_run
use skyauth::session::SecretExportPermit;
# use skyauth::session::OAuthSession;
# fn save(session: &OAuthSession) -> Result<(), Box<dyn std::error::Error>> {
let bytes = session.export_for_persistence(
    SecretExportPermit::for_encrypted_persistence(),
)?;
// Encrypt `bytes` before writing them to durable storage.
# drop(bytes);
# Ok(())
# }
```

## Verification

The required local gate is:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
bash scripts/sync_specs.sh --verify
```

Additional release gates include rustdoc, doctests, feature combinations, the Rust 1.85 MSRV,
`cargo deny`, `cargo package`, Kani, and Verus. The exact proof inventory, bounds, tool versions,
and exclusions are in [docs/formal-verification.md](docs/formal-verification.md).

`scripts/sync_specs.sh --verify` checks local integrity without network access.
`scripts/sync_specs.sh --check-upstream` separately checks the recorded authoritative sources.

## Protocol references

- <https://atproto.com/specs/oauth>
- <https://atproto.com/specs/permission>
- <https://atproto.com/specs/lexicon>
- <https://www.rfc-editor.org/rfc/rfc7636.html>
- <https://www.rfc-editor.org/rfc/rfc9126.html>
- <https://www.rfc-editor.org/rfc/rfc9449.html>
- <https://www.rfc-editor.org/rfc/rfc9728.html>

Licensed under MIT or Apache-2.0.
