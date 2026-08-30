# SkyAuth product requirements

## Scope

SkyAuth is a safe-Rust client library for the current AT Protocol OAuth public-client profile. The
`0.2.x` line covers identity resolution, protected-resource and authorization-server discovery,
client metadata validation, PKCE, PAR, DPoP, callback exchange, rotating refresh tokens, protected
XRPC requests, scope parsing, permission-set resolution boundaries, and optional web integrations.

Confidential clients are intentionally unsupported until a complete `private_key_jwt` lifecycle is
available. Configuration that requests confidential authentication must fail closed.

## Required behavior

1. All network requests use one bounded transport. It validates every resolved address, pins the
   connection destination while retaining TLS hostname verification, disables implicit redirects,
   bounds response bodies and headers, and applies request timeouts.
2. Discovery accepts only metadata satisfying the current AT Protocol profile. OIDC fallback is not
   part of strict mode.
3. The client creates and stores each pending transaction before browser redirection. Callback state
   is atomically consumed once and cannot be supplied as a prevalidated transaction by the caller.
4. Every DPoP-bearing response supplies a valid `DPoP-Nonce`. A nonce challenge receives at most one
   retry, and client nonce state is partitioned by DPoP key and server origin.
5. Refresh rotation is serialized through `OAuthStore`. One request spends a generation; all
   concurrent waiters receive the same fully committed replacement, or all observe an uncertain
   outcome that requires recovery.
6. Token responses preserve the exact granted scopes, require `atproto`, reject escalation, and
   re-resolve configured permission sets after refresh.
7. Tower authorization requires an independently validated token, proof-to-token key binding,
   request URL policy, route scopes, replay storage, and nonce state. Authentication principals are
   derived from validated token claims.
8. Credentials and private key material use private, redacted types. Generic session serialization
   is unavailable; explicit persistence export requires an acknowledgement permit.
9. Framework integrations are optional Cargo features. The core crate has no default features.
10. The crate compiles on Rust 1.85 and forbids unsafe code in SkyAuth source.

## Permission sets

SkyAuth parses `include` scopes and provides `AuthenticatedLexiconResolver` as the trust boundary for
expansion. Resolver implementations must authenticate Lexicon discovery and repository data,
including DNS or DID authority, commit, MST, collection, record key, and CID. The bounded cache uses
24-hour freshness and 90-day expiry; stale authenticated values may be used during a resolution
outage, while new and expired values fail closed.

## Verification model

Runtime and adversarial tests cover cryptography adapters, HTTP behavior, protocol fixtures,
concurrency, persistence, and framework integration. Verus proves selected unbounded policy
properties, while Kani symbolically checks bounded production policy paths with reachable covers.
The precise proof inventory and exclusions are in `docs/formal-verification.md`.

No claim is made that the network stack, cryptographic dependencies, system clock, external server
data, or the complete OAuth implementation is formally verified.

## Release acceptance

The release candidate must pass the mandatory repository gate five consecutive times under default
parallelism, plus rustdoc, doctests, feature combinations, Rust 1.85, `cargo deny`, package
inspection, Verus, Kani, local specification integrity, and live read-only discovery where network
access is available.
