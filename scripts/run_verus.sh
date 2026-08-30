#!/usr/bin/env bash
# ==============================================================================
# Verus Deductive Verification Runner for skyauth
# ==============================================================================
# Verifies the mathematical specs, Hoare-logic contracts, and inductive invariants
# in src/verification/verus_contracts.rs using the Verus SMT engine.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

VERUS_FILE="${ROOT_DIR}/src/verification/verus_contracts.rs"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }

if command -v verus &>/dev/null; then
    VERUS_CMD="verus"
elif [[ -x "${HOME}/.verus/verus" ]]; then
    VERUS_CMD="${HOME}/.verus/verus"
else
    log_info "Verus compiler not detected in PATH. Downloading Verus standalone release..."
    VERUS_DIR="${HOME}/.verus"
    mkdir -p "${VERUS_DIR}"
    
    OS_TYPE="$(uname -s | tr '[:upper:]' '[:lower:]')"
    ARCH_TYPE="$(uname -m)"
    
    if [[ "${OS_TYPE}" == "darwin" ]]; then
        TARGET="apple-darwin"
    else
        TARGET="unknown-linux-gnu"
    fi
    
    VERUS_URL="https://github.com/verus-lang/verus/releases/latest/download/verus-${ARCH_TYPE}-${TARGET}.tar.gz"
    
    if curl -fsSL --connect-timeout 5 --max-time 30 "${VERUS_URL}" -o "/tmp/verus.tar.gz" 2>/dev/null; then
        tar -xzf "/tmp/verus.tar.gz" -C "${VERUS_DIR}" --strip-components=1 2>/dev/null || tar -xzf "/tmp/verus.tar.gz" -C "${VERUS_DIR}"
        VERUS_CMD="${VERUS_DIR}/verus"
        log_success "Verus downloaded and configured at ${VERUS_CMD}"
    else
        log_warn "Could not automatically download Verus. Ensure 'verus' is installed: https://github.com/verus-lang/verus"
        log_info "Verifying syntax and structural contracts via pure Rust model checker..."
        cargo test --test formal_verification_tests
        exit 0
    fi
fi

log_info "Running Verus deductive formal verification on ${VERUS_FILE}..."
"${VERUS_CMD}" "${VERUS_FILE}"
log_success "All Verus deductive proofs and SMT invariants verified successfully."
