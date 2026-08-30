# Changelog

## 0.2.0

- Enforce current AT Protocol protected-resource, authorization-server, client metadata, callback,
  token, redirect, scope, and permission-set rules.
- Route all outbound traffic through bounded, DNS-pinned transport with explicit redirect policy.
- Make authorization state client-owned, collision-safe, expiring, and atomically single-use.
- Serialize refresh rotation through the configured store and commit complete replacement sessions.
- Require independent access-token validation, DPoP key binding, replay storage, nonces, trusted URL
  reconstruction, and route scopes for Tower authorization.
- Partition client nonce state by DPoP key and origin.
- Make credential-bearing fields private and redacted, and require explicit session/key export.
- Replace proof-like tests with pinned Verus proofs and symbolic Kani harnesses over production policy.
- Separate offline specification integrity from upstream freshness and record source provenance.
- Declare Rust 1.85 as the MSRV, make framework features opt-in, and add release-quality CI gates.

### Migration from 0.1

- Add `.in_memory_state_store()` or `.state_store(...)` to every client builder.
- Pass only `CallbackParams` to `handle_callback`; pending state is loaded and consumed internally.
- Use getters and the `StoredStateEntry` builder instead of public fields.
- Use `expose_access_token()` and `expose_refresh_token()` only at credential use sites.
- Pass `SecretExportPermit::for_encrypted_persistence()` to private-key or session export methods.
- Update DPoP nonce-cache calls to include the session DPoP key.
- Configure a complete Tower validation policy; permissive proof-only construction is unavailable.
- Explicitly enable `axum`, `actix`, or `tower` features when needed.

## 0.1.0

- Initial experimental release.
