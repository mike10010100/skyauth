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
    log_info "Verus compiler not detected in PATH. Downloading Verus release..."
    VERUS_DIR="${HOME}/.verus"
    mkdir -p "${VERUS_DIR}"
    
    OS_TYPE="$(uname -s | tr '[:upper:]' '[:lower:]')"
    ARCH_TYPE="$(uname -m)"
    
    case "${OS_TYPE}" in
        darwin)
            PLATFORM="macos"
            ;;
        linux)
            PLATFORM="linux"
            ;;
        *)
            PLATFORM="linux"
            ;;
    esac

    case "${ARCH_TYPE}" in
        x86_64|amd64)
            ARCH="x86"
            ;;
        arm64|aarch64)
            ARCH="arm64"
            ;;
        *)
            ARCH="x86"
            ;;
    esac
    
    TMP_DIR=$(mktemp -d 2>/dev/null || mktemp -d -t 'verus_download')
    trap 'rm -rf "${TMP_DIR}"' EXIT
    
    VERUS_ZIP="${TMP_DIR}/verus.zip"
    VERUS_URL="https://github.com/verus-lang/verus/releases/latest/download/verus-${ARCH}-${PLATFORM}.zip"
    
    log_info "Downloading Verus from ${VERUS_URL}..."
    if curl -fsSL --connect-timeout 8 --max-time 60 "${VERUS_URL}" -o "${VERUS_ZIP}" 2>/dev/null && [[ -s "${VERUS_ZIP}" ]]; then
        unzip -q "${VERUS_ZIP}" -d "${TMP_DIR}/extracted" 2>/dev/null || unzip -q "${VERUS_ZIP}" -d "${VERUS_DIR}"
        if [[ -d "${TMP_DIR}/extracted" ]]; then
            find "${TMP_DIR}/extracted" -type f -name "verus" -exec cp {} "${VERUS_DIR}/verus" \;
            find "${TMP_DIR}/extracted" -type f -name "z3" -exec cp {} "${VERUS_DIR}/z3" \; 2>/dev/null || true
            find "${TMP_DIR}/extracted" -name "*vstd*" -exec cp -r {} "${VERUS_DIR}/" \; 2>/dev/null || true
        fi
        chmod +x "${VERUS_DIR}/verus" 2>/dev/null || true
        if [[ -x "${VERUS_DIR}/verus" ]]; then
            VERUS_CMD="${VERUS_DIR}/verus"
            log_success "Verus downloaded and configured at ${VERUS_CMD}"
        fi
    fi

    if [[ -z "${VERUS_CMD:-}" ]]; then
        if [[ "${ALLOW_VERUS_FALLBACK:-0}" == "1" ]]; then
            log_warn "Verus not found. ALLOW_VERUS_FALLBACK=1 enabled; verifying executable model contracts..."
            cargo test --test formal_verification_tests
            exit 0
        else
            log_error "Verus deductive verifier is required but could not be downloaded/executed."
            log_error "Install Verus from https://github.com/verus-lang/verus or set ALLOW_VERUS_FALLBACK=1 for offline development."
            exit 1
        fi
    fi
fi

log_info "Running Verus deductive formal verification on ${VERUS_FILE}..."
"${VERUS_CMD}" "${VERUS_FILE}"
log_success "All Verus deductive proofs and SMT invariants verified successfully."
