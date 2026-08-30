# Formal verification inventory

The proof gate checks the pure policy functions that production code calls. Verus consumes the
same [`src/policy.rs`](../src/policy.rs) source through `dual_spec`; Kani calls those production
functions directly with symbolic inputs.

Pinned tools:

- Verus `0.2026.08.09.92f466f`, toolchain `1.97.1-x86_64-unknown-linux-gnu`
- Kani `0.67.0`, default unwind bound 5 with tighter per-harness bounds

Verified claims:

- state insertion, expiration, single consumption, replay insertion, and nonce transitions;
- saturating time behavior and 64-shard index bounds;
- conjunction of every mandatory metadata predicate;
- DPoP authorization implies independent token validation, proof validation, and key binding;
- mandatory `atproto` and route-scope predicates;
- selected IPv4 and IPv6 special-use range classification over complete address values;
- PKCE verifier length and byte-domain boundaries.

The proofs do not claim cryptographic primitive correctness, SHA-256 collision resistance,
network-stack correctness, wall-clock correctness, runtime constant-time behavior, or correctness
of external authorization-server data. Integration, concurrency, protocol-vector, and live-server
tests cover those adapters where practical.

Run the gate with:

```bash
bash scripts/verify_formal.sh
```

The gate also runs deliberately false Verus and Kani mutations and requires both tools to reject
them. Local runs write logs under `target/proof-logs` by default; set `PROOF_LOG_DIR` to choose a
different directory. CI sets `PROOF_LOG_DIR=proof-artifacts` and uploads that directory.
