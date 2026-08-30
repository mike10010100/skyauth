# Test infrastructure

## Local protocol environment

`tests/e2e_harness` starts isolated WireMock servers for DNS fixtures, PLC resolution, PDS metadata,
authorization-server metadata, PAR, token exchange, refresh, and XRPC. Each test owns its server and
state. DPoP-bearing mock responses include `DPoP-Nonce` unless omission is the behavior under test.

`tests/transport_runtime_tests.rs` uses raw local TCP servers to inspect the actual HTTP transport.
It covers address validation and pinning, redirects, response limits, encoding, and timeouts without
depending on internet services.

## Specification fixtures

Checked-in files and `schemas/.checksums.sha256` are local release inputs.

- `bash scripts/sync_specs.sh --verify` performs offline integrity validation and never rewrites data.
- `bash scripts/sync_specs.sh --check-upstream` compares normalized authoritative sources with the
  recorded provenance.
- `SKYAUTH_UPSTREAM_FIXTURE_DIR` supplies deterministic changed-upstream fixtures in tests.
- `bash scripts/sync_specs.sh --sync` stages every managed artifact and publishes the set atomically.

## Formal tools

`bash scripts/verify_formal.sh` invokes Kani 0.67.0 and Verus
`0.2026.08.09.92f466f`. It writes logs under `target/proof-logs` by default (CI overrides this with
`PROOF_LOG_DIR=proof-artifacts`), checks required covers, and requires
deliberately false proof mutations to fail. See `docs/formal-verification.md` for claims and bounds.

## Reproducibility

The repository does not require a shared port, fixed temporary directory, real user credential, or
browser session for deterministic tests. Live discovery is supplementary evidence and is not a
substitute for the hermetic suite.
