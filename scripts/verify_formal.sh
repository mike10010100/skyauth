#!/usr/bin/env bash
set -euo pipefail

VERUS_VERSION="0.2026.08.09.92f466f"
KANI_VERSION="0.67.0"
VERUS_COMMAND="${VERUS_BIN:-verus}"
PROOF_OUTPUT_DIR="${PROOF_LOG_DIR:-target/proof-logs}"

mkdir -p "${PROOF_OUTPUT_DIR}"

"${VERUS_COMMAND}" --version | tee "${PROOF_OUTPUT_DIR}/verus-version.log"
grep -Fq "Version: ${VERUS_VERSION}" "${PROOF_OUTPUT_DIR}/verus-version.log"
cargo kani --version | tee "${PROOF_OUTPUT_DIR}/kani-version.log"
grep -Fq "cargo-kani ${KANI_VERSION}" "${PROOF_OUTPUT_DIR}/kani-version.log"

"${VERUS_COMMAND}" proofs/verus/policy.rs --no-cheating 2>&1 \
    | tee "${PROOF_OUTPUT_DIR}/verus-policy.log"
cargo kani --fail-fast --output-format=terse 2>&1 \
    | tee "${PROOF_OUTPUT_DIR}/kani-policy.log"

if "${VERUS_COMMAND}" proofs/verus/mutation.rs --no-cheating \
    >"${PROOF_OUTPUT_DIR}/verus-mutation.log" 2>&1; then
    echo "Verus mutation was not rejected" >&2
    exit 1
fi

if cargo kani --features proof-mutations \
    --harness mutation_dpop_binding_is_ignored \
    --fail-fast --output-format=terse \
    >"${PROOF_OUTPUT_DIR}/kani-mutation.log" 2>&1; then
    echo "Kani mutation was not rejected" >&2
    exit 1
fi

grep -Fq "postcondition not satisfied" "${PROOF_OUTPUT_DIR}/verus-mutation.log"
grep -Fq "VERIFICATION:- FAILED" "${PROOF_OUTPUT_DIR}/kani-mutation.log"
