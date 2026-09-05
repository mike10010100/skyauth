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

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }

# Pinned Verus release (supply-chain pinning, mirroring SHA-pinned GitHub Actions).
# Version + per-platform asset SHA-256 digests recorded at pin time; the downloaded
# archive is verified against this manifest before anything is executed.
VERUS_PINNED_VERSION="0.2026.08.23.fbbbbcf"
VERUS_PINNED_TAG="release/0.2026.08.23.fbbbbcf"
# bash-3.2 compatible (no associative arrays): digest resolved per platform/arch below.
verus_pinned_sha_for() {
    case "$1" in
        "x86-macos")     echo "724efff85ccb71c958e251dda33e7663796d394ba81bfc231d407e2b4413e81c" ;;
        "arm64-macos")   echo "7075f6e1ac137143da47265691b9c8f376867708eb21480d4e751eb814806aea" ;;
        "x86-linux")     echo "b65483714e6bf2ae72bfe7c7199e1c608495a941306b979260e9ed585d5899c9" ;;
        # No official arm64-linux Verus asset exists for the pinned release; fail
        # closed rather than downloading and executing an unverified archive.
        "arm64-linux")   echo "" ;;
        *)               echo "" ;;
    esac
}

if command -v verus &>/dev/null; then
    VERUS_CMD="verus"
elif [[ -x "${HOME}/.verus/verus" ]]; then
    VERUS_CMD="${HOME}/.verus/verus"
else
    log_info "Verus compiler not detected in PATH. Downloading pinned Verus release ${VERUS_PINNED_VERSION}..."
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
    VERUS_URL="https://github.com/verus-lang/verus/releases/download/${VERUS_PINNED_TAG//\//%2F}/verus-${VERUS_PINNED_VERSION}-${ARCH}-${PLATFORM}.zip"
    EXPECTED_SHA=$(verus_pinned_sha_for "${ARCH}-${PLATFORM}")
    
    log_info "Downloading Verus from ${VERUS_URL}..."
    if curl -fSL --connect-timeout 15 --max-time 120 "${VERUS_URL}" -o "${VERUS_ZIP}" 2>/dev/null && [[ -s "${VERUS_ZIP}" ]]; then
        if [[ -n "${EXPECTED_SHA}" && "${EXPECTED_SHA}" != PLACEHOLDER* ]]; then
            ACTUAL_SHA=$(shasum -a 256 "${VERUS_ZIP}" 2>/dev/null | awk '{print $1}')
            if [[ "${ACTUAL_SHA}" != "${EXPECTED_SHA}" ]]; then
                log_error "Verus release integrity check FAILED for ${ARCH}-${PLATFORM}:"
                log_error "  expected ${EXPECTED_SHA}"
                log_error "  actual   ${ACTUAL_SHA}"
                exit 1
            fi
            log_success "Verus release integrity verified (SHA-256 match)."
        else
            log_error "No pinned SHA-256 digest recorded for verus-${ARCH}-${PLATFORM}; refusing to execute an unverified binary."
            log_error "Record the digest in verus_pinned_sha_for() (scripts/run_verus.sh) to enable ${ARCH}-${PLATFORM}."
            exit 1
        fi
        unzip -q "${VERUS_ZIP}" -d "${TMP_DIR}/extracted" 2>/dev/null || true
        VERUS_EXTRACTED_DIR=$(find "${TMP_DIR}/extracted" -type f -name "verus" -exec dirname {} \; | head -n 1)
        if [[ -n "${VERUS_EXTRACTED_DIR}" && -d "${VERUS_EXTRACTED_DIR}" ]]; then
            cp -R "${VERUS_EXTRACTED_DIR}/." "${VERUS_DIR}/"
        fi
        chmod +x "${VERUS_DIR}/verus" "${VERUS_DIR}/rust_verify" "${VERUS_DIR}/z3" 2>/dev/null || true
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

VERUS_LOG=$(mktemp 2>/dev/null || mktemp -t 'verus_err')
trap 'rm -f "${VERUS_LOG}"; rm -rf "${TMP_DIR:-}"' EXIT

# Layer 1: standalone deductive specification layer (models + theorems).
log_info "Running Verus deductive formal verification on ${VERUS_FILE}..."
if ! "${VERUS_CMD}" --crate-type=lib "${VERUS_FILE}" 2>"${VERUS_LOG}"; then
    VERUS_OUTPUT=$(cat "${VERUS_LOG}" | sed -e 's/\x1b\[[0-9;]*m//g' | tr -d '\r')
    echo "${VERUS_OUTPUT}" >&2
    if echo "${VERUS_OUTPUT}" | grep -q "rustup.*install" && command -v rustup &>/dev/null; then
        REQUIRED_TOOLCHAIN=$(echo "${VERUS_OUTPUT}" | grep -o 'rustup \(toolchain \)\?install [^ `]*' | head -n 1 | awk '{print $NF}' | tr -d '`')
        if [[ -n "${REQUIRED_TOOLCHAIN}" ]]; then
            log_info "Installing required Rust toolchain ${REQUIRED_TOOLCHAIN} for Verus..."
            rustup toolchain install "${REQUIRED_TOOLCHAIN}" --profile minimal || rustup install "${REQUIRED_TOOLCHAIN}" || true
            VERSION_ONLY=$(echo "${REQUIRED_TOOLCHAIN}" | cut -d'-' -f1)
            if [[ "${VERSION_ONLY}" =~ ^[0-9]+\.[0-9]+\.[0-9]+ ]]; then
                rustup toolchain install "${VERSION_ONLY}" --profile minimal || true
            fi
            log_info "Retrying Verus verification..."
            "${VERUS_CMD}" --crate-type=lib "${VERUS_FILE}"
        else
            exit 1
        fi
    else
        exit 1
    fi
fi
log_success "Standalone Verus layer verified."

# Layer 2: kernel-bound verification — proofs over the SHIPPED kernel source
# (src/kernels/*) via #[path] inclusion. These contracts bind the same bytes
# that compile into the published crate.
VERUS_KERNELS_FILE="${ROOT_DIR}/src/verification/verus_kernels.rs"
log_info "Running Verus kernel-bound verification on ${VERUS_KERNELS_FILE}..."
if ! "${VERUS_CMD}" --crate-type=lib "${VERUS_KERNELS_FILE}" 2>"${VERUS_LOG}"; then
    VERUS_OUTPUT=$(cat "${VERUS_LOG}" | sed -e 's/\x1b\[[0-9;]*m//g' | tr -d '\r')
    echo "${VERUS_OUTPUT}" >&2
    exit 1
fi
log_success "Kernel-bound Verus layer verified (proofs over shipped source)."

log_success "All Verus deductive proofs and SMT invariants verified successfully."
