# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Kernel-Bound Verus Verification Layer (48 obligations)**: new `src/kernels/` module extracts the pure security cores (IP restricted-range classification, constant-time equality, byte-level PKCE validation, HTU component assembly, NSID grammar) into dual-representation single-source files — plain rustc for shipping, `verus!`-wrapped with `ensures` contracts for verification (cfg-gated). `src/verification/verus_kernels.rs` `#[path]`-includes the shipped kernel source so deductive proofs bind to production code: 48 obligations verified (IPv4 full-range coverage theorems, IPv6 family theorems including mapped↔IPv4 reduction parity and 6to4 embedded-IPv4 parity, public non-vacuity witnesses). `scripts/run_verus.sh` now verifies both layers (21 standalone + 48 kernel-bound = 69 obligations).
- **Three New Kani Refinement Harnesses (7 total, up from 4)**: `proof_pkce_validator_refinement` (shipped byte-level PKCE validator ≡ formal spec over a bounded symbolic domain, including one-byte-violation position accuracy), `proof_ipv6_adapter_refinement` (std `Ipv6Addr` adapter ≡ segment core over the full symbolic 16-bit segment space — the IPv6 classifier previously had only concrete-vector tests), and `proof_jti_admission_bound` (the shipped `MAX_JTI_LENGTH` bound: empty reject, over-cap reject, at-cap admit).
- **Anti-Vacuity Tag Inventory Meta-Test** (`tests/verification_tag_inventory_tests.rs`): parses the harness sources at test time and enforces a bidirectional exact match between cover-tag literals in proofs and the tags enforced by the m6 `assert_all_covered` lists (57 tags as of this change). Tag counts are now generated and machine-checked — they cannot drift from the docs.
- **CI Kani Cover Gate**: measured that unsatisfied `kani::cover!` properties do NOT fail plain `cargo kani` (exit 0 on UNSATISFIABLE). The CI Kani job now runs with `--coverage` and a fail-closed gate step errors on any UNSATISFIABLE cover or missing summary.
- **MSRV CI Job**: `rust-version` raised honestly from 1.81 to 1.88 after measurement (`zeroize 1.9.0` requires Edition-2024 cargo, unreachable from 1.81; `actix-web 4.15` / `icu 2.3` require rustc ≥ 1.88). New CI job pins `cargo +1.88.0 check --locked --lib --all-features` and gates publish.

### Removed

- **Static `client_secret` Confidential-Client Mode** (review H1, **Breaking**): ATProto OAuth has no shared client secret — confidential clients authenticate with `private_key_jwt` (ES256 client assertions). The previous `OAuthClientMetadata::with_client_secret` path sent the static secret to a **user-selected** authorization server in the first PAR request, an unconditional credential-disclosure path for any malicious identity. `client_secret` is removed from `OAuthClientMetadata`, `with_client_secret`/`execute_par_request_with_credentials` are gone, and generated framework metadata now advertises `token_endpoint_auth_method: "none"` exclusively. `private_key_jwt` support is planned for 0.3.0.

### Fixed

- **DPoP-Nonce Enforcement on Both Sides of the Wire** (review H2): the client now **rejects success responses to DPoP-authenticated requests that omit the `DPoP-Nonce` header** (new `DPoPError::ResponseMissingDpopNonce`) — previously it silently accepted them, degrading replay protection for subsequent requests (ATProto profile violation at PAR, token, refresh, and XRPC success paths, including auto-nonce retries). The Tower server middleware now **attaches a fresh `DPoP-Nonce` to every success response** when a nonce source is configured (nonce-source exhaustion maps to 503, consistent with replay-cache saturation). Mock fixtures updated to be profile-compliant; two regression tests pin both directions.
- **`OAuthSession` Deserialization Validates the Constructor Contract** (review #1/L1): the derived `Deserialize` bypassed `OAuthSession::new` validation entirely, so a compromised persistence round-trip could produce a session with `token_type: "Bearer"` (silently disabling the DPoP binding) or empty credentials. A hand-written `Deserialize` impl now re-applies the same invariants — DPoP token type, non-empty `sub`, non-empty `access_token` — and rejects tampered payloads with descriptive errors. Valid round-trips are unaffected; `AuthenticatedUser`'s fail-closed pattern is mirrored.
- **Refresh Invariants Restored** (review H4): refresh-token exchange now (1) **requires a non-empty `sub`** in the response — an empty `sub` is a protocol violation and no longer silently accepted; (2) **rejects scope expansion** (`TokenError::ScopeExpansion`) per RFC 6749 § 6 — privileges cannot silently accumulate; (3) **persists the returned scope atomically** with the rotated tokens (`rotate_tokens_with_scope`) so authorization decisions cannot use stale grants; and (4) **serializes refreshes per subject** (`RefreshSingleFlight`, mirroring `@atproto/oauth-client-node`'s per-DID `requestLock`) so concurrent callers never race the single-use refresh token. Test fixtures updated to echo the granted scope (a mock AS expanding scope on refresh is precisely the violation the client now refuses). Regression tests cover empty-`sub` rejection, expansion rejection, scope persistence, and upstream serialization (max concurrent refresh requests == 1).
- **DPoP Auto-Retry Restricted to Explicit `use_dpop_nonce` Challenges** (review H3): `send_dpop_request` no longer replays request bodies on any 400/401 that merely carries a `DPoP-Nonce` header (conforming Resource Servers attach one to *every* DPoP response). The client now retries only when the response is an explicit nonce challenge — `WWW-Authenticate: DPoP error="use_dpop_nonce"` (RFC 9449 § 8.4) or the JSON `error: "use_dpop_nonce"` body (dual-check mirroring the reference client) — so non-idempotent POST/PATCH/DELETE bodies can no longer execute twice on unrelated errors like `invalid_token`. Non-challenge error responses are reconstructed byte-for-byte and returned to the caller. Regression tests cover both directions.
- **SSRF Pinned Transport Ignores Environment Proxies** (review H6): `SsrfFilter::build_pinned_client` now calls `reqwest::ClientBuilder::no_proxy()`. Previously the pinned client honored `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`; with an HTTPS proxy the connection terminates at the proxy and the target hostname is sent via CONNECT, so proxy-side DNS — not the locally validated, pinned address — selected the destination, silently invalidating the socket pin and re-opening split-DNS/proxy-side rebinding paths. The standard DoH resolver (`StandardDnsResolver`) is also `no_proxy()` for the same trust-model reason. Regression test proves the pinned request succeeds with hostile proxy env set (and fails without the fix — verified by temporary revert).
- **Bounded System DNS Resolution** (review H6): the pre-resolution `tokio::net::lookup_host` inside `resolve_and_pin` is now wrapped in an explicit 5s timeout (matching the pinned client's connect timeout); previously it sat outside the reqwest timeout, letting a stalled resolver hang callers indefinitely.
- **DPoP `jti` Memory-Amplification Defense**: `verify_proof` now rejects proofs whose `jti` claim exceeds `MAX_JTI_LENGTH` (256 bytes) with the new `DPoPError::JtiTooLong` variant, bounding replay-cache key size against attacker-minted multi-kilobyte `jti` values (~1:1 memory amplification previously).
- **`expires_in` Overflow Fails Closed** (review L3): `OAuthSession::new` now rejects an `expires_in` whose `checked_add` overflows `SystemTime` instead of silently issuing a never-expiring local session; `rotate_tokens` clamps overflow to already-expired.
- **Formal Model Insert Divergence** (review M3): `OAuthStateTransitionModel::insert` now *replaces* a live pending entry (matching production `OAuthStateStore::insert_state_sync` `HashMap::insert` semantics) instead of rejecting re-insertion; the model previously could not refine the production store.
- **`HTU` Kernel Assembly**: `build_normalized_htu` assembles via byte concatenation with a manual decimal port renderer (no `format!`/`core::fmt` in the proof surface); component-level invariants (`invariants_hold`) are scheme-aware and byte-scanned (ASCII-exact for `?`/`#`), avoiding unicode-table scans that are unbounded under symbolic execution.

### Fixed

- **XRPC NSID Validation**: `send_xrpc_request` validates the NSID against the full ATProto NSID grammar (≤317 chars total, ≤63 per segment, ≥3 segments, digit-start authority segments legal, name segment letters/digits only with no leading digit or hyphen) and rejects path-traversal payloads (`../../admin`) with `TokenError::InvalidNsid` before URL construction. Validated against the upstream `bluesky-social/atproto` interop vectors.
- **`require_request_uri_registration` Enforcement**: `AuthorizationServerMetadata` now deserializes the field (defaulting to `true` on omission), and `validate_auth_server_capabilities` rejects an explicit `false` with `DiscoveryError::MissingRequestUriRegistration`, per the ATProto OAuth profile ("must not be false").
- **DPoP Nonce Saturation Error**: `DPoPServerNonceSource::generate_nonce` now returns `Result<String, DPoPError>`; nonce-cache capacity exhaustion returns `DPoPError::NonceCacheSaturated` (mapped to HTTP 503 by the Tower middleware) instead of an empty-string nonce. **Breaking**: custom `DPoPServerNonceSource` implementations must update `generate_nonce`'s signature.
- **`AuthenticatedUser` owned accessors**: `into_did()`, `into_access_token()`, `into_dpop_thumbprint()`, and `into_parts()` consume the user and return fields by value — the `Drop`/zeroization implementation forbids direct field moves (E0509), and these accessors provide the by-value escape hatch.

### Fixed

- **Mandatory Issuer & Audience Matching (fail closed)**: `JwtAccessTokenValidator::verify_token_sync` now **rejects every token** unless both `with_expected_issuer` and `with_expected_audience` have been configured, returning `IntegrationError::AuthFailed` (a validator-misconfiguration error). Previously, issuer and audience matching were opt-in: a validator without `with_expected_audience` accepted tokens carrying any `aud`, leaving the RFC 9068 § 4 cross-resource-server audience-confusion path open. Tokens whose `iss`/`aud` do not match the configured values are still rejected with `IssuerMismatch`/`AudienceMismatch`.
- **`ReplayCacheSaturated` maps to HTTP 503 in Tower middleware**: DPoP replay-cache capacity exhaustion is a server-side resource-exhaustion condition, not a defective client proof. The Tower layer now responds `503 Service Unavailable` (with `Retry-After: 1`) instead of `401 invalid_dpop_proof`, matching the documented semantics of `DPoPError::ReplayCacheSaturated`.
- **Default absolute DPoP `htu` derivation in Tower middleware**: the default `htu` is now reconstructed as an absolute URI from the trusted connection scheme, the request authority, and the path/query, instead of using the raw request-URI string. HTTP/1.1 origin-form targets (`/xrpc/foo`) behind proxies are reconstructed (default ports stripped per RFC 9449 § 4.2), and requests with no usable authority fail closed with `401 invalid_dpop_proof` rather than verifying against a path-only `htu`. `with_htu_override` continues to take precedence for servers whose public origin differs from the inbound authority.
- **`sync_specs.sh --verify` fails when upstream is unreachable**: a failed upstream fetch exits `3` (distinct from drift's `1`) and strict verification fails; `SYNC_SPECS_ALLOW_OFFLINE=1` accepts manifest-only verification for offline development. The escape hatch is driven by the exit code rather than function-local counters, so the offline path can no longer mask real drift.
- **Strict origin-port parsing in discovery**: `is_origin_only` parses explicit ports numerically, so leading-zero default-port spellings (`:0443`, `:0080`) and malformed ports (including trailing backslash) are rejected instead of slipping past the default-port check.
- **Protected-resource identifier strictness (RFC 9728)**: a `resource` value at the correct origin but carrying a path, query, or fragment is rejected with `ResourceMismatch` — origin-scoped resource identifiers must be bare origins.
- **Test-mode SSRF hostname blocking**: `allow_insecure_localhost(true)` now also keeps `.local` and `.localhost` hostname suffixes blocked (previously only `.internal` and metadata hosts were re-checked in test mode).
- **Protected-resource userinfo rejection (RFC 9728)**: a `resource` value carrying userinfo (`https://user:pass@host/`) is rejected with `ResourceMismatch`; origin comparison strips userinfo, so previously the credentials were silently ignored.
- **Mutation CI gate correctness**: the mutation sweep tolerates `cargo-mutants` exit codes 2 (missed mutants) and 3 (timeouts) so the kill-rate gate always runs, and the gate now parses the actual `outcomes.json` schema (`outcomes` array with `summary` classification, baseline scenarios excluded, survivor metadata read from `scenario["Mutant"]`) — the previous parser iterated top-level report keys and would crash.
- **`sync_specs.sh` fail-closed hardening**: a missing checksum manifest now fails `--verify` (manifest creation is reserved for `--generate-manifest`); `validate_json` fails when no JSON tool is available instead of accepting any non-empty file (which let `--sync` replace local specs with unvalidated payloads); `verify_specs` returns status 3 instead of exiting the shell; errexit is scoped so `format_json`/`generate_manifest` failures abort `--sync` before reporting success.
- **Kani SSRF harness acceptance-side proof**: the IPv4 harness now also proves that every permitted symbolic IPv4 is accepted by `SsrfFilter::validate_ip` (no false rejects), with a `public_ip_allowed` cover point.
- **CI workflow fixes**: the Mutation Sweep job name now references `matrix.shard.name` (the bare `matrix.shard` object rendered as garbage in the job name), and `actions/upload-artifact` is SHA-pinned like every other action reference.
- **m7 concurrency test now exercises the real single-use path**: the 50-task callback race drives `handle_callback` against a client sharing the test's `OAuthStateStore` (previously the test won `take_state` manually and called `handle_callback_with_entry`, bypassing the composed single-use path; the client also silently built its own state store).

### Documentation

- Corrected the Verus bootstrap description in `AGENTS.md` (pinned release, not latest), `TEST_INFRA.md` gate enumeration, `TEST_READY.md` execution command (`--all-features`) and test-count totals, `PRD.md` release checklist target (v0.2.0), and the `lib.rs` 6to4 doc wording (conditional on the embedded IPv4 address).

### Breaking Changes

- **`AuthorizationServerMetadata` gains `require_request_uri_registration`**: adding the field (defaulting to `true` on deserialization omission) breaks downstream struct literals, which must now set it. `validate_auth_server_capabilities` rejects an explicit `false`.
- **`AtprotoOAuthClientBuilder::build` rejects sub-second `state_ttl`**: `StoredStateEntry::expires_in_secs` truncates sub-second TTLs to zero (making entries appear instantly expired while the store still holds them); the builder now returns `TokenError::InvalidStateTtl` for non-whole-second durations.
- **`JwtAccessTokenValidator` requires expected issuer and audience**: validators built without `with_expected_issuer` and `with_expected_audience` reject all tokens with `IntegrationError::AuthFailed` instead of accepting them. Production validators were expected to configure both already (and the earlier presence checks rejected tokens with absent `iss`/`aud` claims); only call sites that relied on the permissive unset-configuration path are affected.
- **`DPoPServerNonceSource::generate_nonce` returns `Result`**: implementations must return `Result<String, DPoPError>`; saturation surfaces as `DPoPError::NonceCacheSaturated` instead of an empty string.

## [0.2.0] - 2026-08-30

### Added

- **Confidential Client Support (`client_secret_post`)**: `client_secret` is now automatically included in PAR, authorization-code exchange, and refresh-token requests (RFC 6749 § 2.3.1); `execute_par_request_with_credentials` exposes the same capability for custom credential parameters.
- **Tower `htu` Origin Override**: `OAuthAuthLayer::with_htu_override` / `OAuthAuthService::with_htu_override` reconstruct the absolute DPoP target URI for servers behind reverse proxies receiving origin-form request targets.
- **Single-Use Server Nonces**: `InMemoryServerNonceSource::with_single_use` enforces strict RFC 9449 § 8 semantics by atomically consuming nonces on first successful verification.
- **6to4 (`2002::/16`) and Teredo (`2001::/32`) SSRF Filtering**: Deprecated tunneling addresses are rejected. 6to4 addresses additionally re-evaluate the embedded IPv4 address, mirrored in the formal spec models (Verus/Kani equivalence).

### Fixed

- **SSRF Hostname Blocking in Test Mode**: `allow_insecure_localhost(true)` no longer disables cloud-metadata and `.internal` hostname blocking; only explicit loopback targets are exempted.
- **Bare `localhost` Hostname Blocked**: `is_blocked_hostname` now rejects `localhost` explicitly (previously only matched via IP checks).
- **Refresh Scope Revalidation**: Refresh responses whose scope drops the mandatory `atproto` scope are rejected, preventing silent scope narrowing on rotation.
- **Rotate-Time Zeroization**: `OAuthSession::rotate_tokens` zeroizes outgoing access/refresh tokens in memory before replacing them.
- **Redacted Debug for `ParParameters`**: `client_assertion` no longer leaks through `Debug` output.
- **Client Error-Deduplication**: Token endpoint request handling consolidated into a single shared routine with unified OAuth error-field parsing.

### Documentation

- `DPoPKey` documents the `ecdsa` crate's `ZeroizeOnDrop` guarantee for the private scalar and the sensitivity of string exports.
- `rust-version = "1.81"` MSRV declared in `Cargo.toml`.

### Breaking Changes

- **`DPoPKey` private-key exports return `Zeroizing` buffers**: `DPoPKey::to_bytes()` now returns `Zeroizing<[u8; 32]>` (previously `[u8; 32]`) and `DPoPKey::to_bytes_b64()` returns `Zeroizing<String>` (previously `String`). The returned buffers zeroize on drop, protecting copies of the private scalar from lingering in memory. Call sites that deref the value (`*buf`) or the string (`&*buf` / `buf.as_str()`) need no other change; code that stored the bare `[u8; 32]` or `String` type must now name the `Zeroizing<...>` wrapper. This lands together with the other 0.2.0 hardening before the release is consumed.

## [0.1.1] - 2026-08-30

### Fixed

- **Tower / Web Framework JWT Validation & `cnf.jkt` Binding**: Independently validate JWT signature, issuer, audience, temporal bounds, and enforce constant-time thumbprint binding.
- **DPoP Anti-Replay & Nonce Challenges**: 64-shard partitioned replay cache tracking `(jkt, jti)` pairs and server nonce challenges (`401 use_dpop_nonce`).
- **SSRF Defense & Transport Pinning**: Filter 15 RFC IP ranges, pin DNS-resolved sockets, disable automatic redirects, and stream bounded response bodies.
- **ATProto OAuth Specification Compliance**: Enforce single origin-only AS URLs, RFC 9207 `iss` callback verification, and mandatory `atproto` token scope.
- **Client State Storage Single-Use**: Guaranteed atomic single-use state consumption with clock-warp-safe expiration.
- **Formal Verification & Upstream Drift Guard**: SMT deductive theorems (Verus), symbolic bounded model checking (Kani), and live upstream Lexicon/RFC schema synchronization.
- **Secret Redaction & Memory Zeroization**: Redact sensitive credentials in `Debug` implementations and zeroize heap memory on drop.

### Breaking Changes

- **Manual `Drop` / Zeroization on Public Structs**: `StoredStateEntry` and `OAuthSession` now implement `Drop` and `ZeroizeOnDrop` to securely erase cryptographic secrets from memory. As a consequence of Rust's `Drop` semantics (E0509), partial moves of individual public fields out of these structs are prohibited; cloning or borrowing should be used instead.

## [0.1.0] - 2026-08-29

### Added
- Initial production release of **`skyauth`**: pure-Rust (`#![forbid(unsafe_code)]`), zero-panic OAuth 2.1 client library for the AT Protocol.
- **RFC 9449 DPoP (Demonstrating Proof-of-Possession)**: Ephemeral ECDSA P-256 key generation, RFC 7517 JWK formatting, RFC 7638 JWK Thumbprints (`jkt`), access token hash (`ath`), and transparent auto-nonce retry loops (RFC 9449 § 4.3).
- **RFC 9126 PAR (Pushed Authorization Requests)**: Direct back-channel pushing of authorization parameters with signed DPoP headers.
- **RFC 7636 PKCE (Proof Key for Code Exchange)**: S256 verifier/challenge generation and constant-time verification.
- **Decentralized Identity Discovery**: Handle resolution (DNS TXT `_atproto.<handle>` and HTTPS fallback), DID resolution (`did:plc`, `did:web`), RFC 9728 protected resource discovery, and RFC 8414 OAuth authorization server metadata discovery.
- **Strict SSRF & DNS Rebinding Security**: Full IP boundary filtering blocking RFC 1918 private IPs, loopback, link-local, cloud metadata (`169.254.169.254`), IPv6 ULA, and DNS socket pinning.
- **64-Shard Partitioned Concurrent State Store**: Lock-free scaling state storage across 64 independent `RwLock` shards with atomic single-use state consumption ([`OAuthStore::take_state`]) and drift-free background TTL pruning.
- **Web Framework Integrations**: Ready-to-use extractors, response generators, and middleware for **Axum 0.7**, **Actix-Web 4**, and **Tower**.
- **Formal Mathematical Verification**: Verified using Verus SMT deductive proofs, Kani bounded model checking with 25 mandatory anti-vacuity reachability tags, and executable formal transition models.
- **Dynamic Schema Invariants**: Bundled official ATProto Lexicons and RFC schemas with continuous automated upstream drift detection.
