# Test readiness

The release test target is the exact public behavior documented in `README.md` and `PRD.md`.

## Mandatory gate

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
bash scripts/sync_specs.sh --verify
```

Run the full test command five consecutive times before release. Tests must use unique temporary
directories and default parallelism; serial execution is not release evidence.

## Additional gates

```bash
RUSTDOCFLAGS="-D warnings" cargo doc --all-features --no-deps
cargo test --doc --all-features
cargo deny check
cargo package
bash scripts/verify_formal.sh
```

The CI matrix also checks no-default-features, each framework feature, all features, stable Rust,
and Rust 1.85. Scheduled upstream freshness uses `scripts/sync_specs.sh --check-upstream`; pull
requests use the offline `--verify` command.

## Runtime coverage

- real TCP servers exercise DNS pinning, redirect rejection, bounded fixed/chunked/compressed bodies,
  content types, timeouts, and connection policy;
- mock authorization-server and PDS processes exercise discovery, PAR, callback exchange, nonce
  retry, refresh rotation, and protected XRPC calls over HTTP;
- Tower tests exercise validated token claims, DPoP binding, replay, nonce, trusted URL, and scopes;
- concurrency tests race callbacks, refresh waiters, replay insertion, pruning, and shard access;
- a read-only live discovery example is run separately where internet access is available;
- real pinned Verus and Kani binaries produce proof logs and reject deliberate mutations.

Tests which intentionally reject malformed inputs must assert the first relevant typed error rather
than relying on a later parser or transport failure.
