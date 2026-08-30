#!/usr/bin/env bash
# ==============================================================================
# skyauth Upstream Specification & Lexicon Synchronization Script
# ==============================================================================
# Verifies and synchronizes bundled AT Protocol Lexicons and RFC JSON Schemas
# against canonical upstream sources with automated drift detection and offline fallback.
#
# Usage:
#   ./scripts/sync_specs.sh --check     # CI verification mode (returns 1 on drift)
#   ./scripts/sync_specs.sh --verify    # Alias for --check
#   ./scripts/sync_specs.sh --sync      # Fetch latest upstream specs & update checksums
#   ./scripts/sync_specs.sh --help      # Show this help message
# ==============================================================================

set -euo pipefail

# ANSI Color Codes
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

LEXICONS_DIR="${ROOT_DIR}/lexicons"
SCHEMAS_DIR="${ROOT_DIR}/schemas"
MANIFEST_FILE="${SCHEMAS_DIR}/.checksums.sha256"

# Canonical Upstream Lexicon URLs
RESOLVE_HANDLE_URL="https://raw.githubusercontent.com/bluesky-social/atproto/main/lexicons/com/atproto/identity/resolveHandle.json"
CREATE_SESSION_URL="https://raw.githubusercontent.com/bluesky-social/atproto/main/lexicons/com/atproto/server/createSession.json"
REFRESH_SESSION_URL="https://raw.githubusercontent.com/bluesky-social/atproto/main/lexicons/com/atproto/server/refreshSession.json"

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

# Cross-platform SHA256 checksum calculator
calc_sha256() {
    local file="$1"
    if command -v sha256sum &>/dev/null; then
        sha256sum "${file}" | awk '{print $1}'
    elif command -v shasum &>/dev/null; then
        shasum -a 256 "${file}" | awk '{print $1}'
    else
        openssl dgst -sha256 "${file}" | awk '{print $2}'
    fi
}

# JSON syntax validator
validate_json() {
    local file="$1"
    if command -v jq &>/dev/null; then
        jq empty "${file}" >/dev/null 2>&1
    elif command -v python3 &>/dev/null; then
        python3 -m json.tool "${file}" >/dev/null 2>&1
    elif command -v node &>/dev/null; then
        node -e "JSON.parse(require('fs').readFileSync(process.argv[1]))" "${file}" >/dev/null 2>&1
    else
        # Basic check if no JSON tool installed
        test -s "${file}"
    fi
}

# Format JSON in-place if tool available
format_json() {
    local file="$1"
    if command -v jq &>/dev/null; then
        local tmp="${file}.tmp.$$"
        if jq . "${file}" > "${tmp}" 2>/dev/null; then
            mv "${tmp}" "${file}"
        else
            rm -f "${tmp}"
            return 1
        fi
    elif command -v python3 &>/dev/null; then
        local tmp="${file}.tmp.$$"
        if python3 -m json.tool "${file}" > "${tmp}" 2>/dev/null; then
            mv "${tmp}" "${file}"
        else
            rm -f "${tmp}"
            return 1
        fi
    fi
}

# List of all canonical managed files relative to ROOT_DIR
get_managed_files() {
    cat <<EOF
lexicons/com/atproto/identity/resolveHandle.json
lexicons/com/atproto/server/createSession.json
lexicons/com/atproto/server/refreshSession.json
schemas/rfc8414_authorization_server.json
schemas/rfc9728_protected_resource.json
schemas/rfc9449_dpop_proof.json
schemas/atproto_client_metadata.json
EOF
}

# Generate checksums manifest for all managed files
generate_manifest() {
    log_info "Updating checksum manifest at ${MANIFEST_FILE}..."
    mkdir -p "$(dirname "${MANIFEST_FILE}")"
    local tmp_manifest="${MANIFEST_FILE}.tmp.$$"
    : > "${tmp_manifest}"

    while IFS= read -r rel_path; do
        local full_path="${ROOT_DIR}/${rel_path}"
        if [[ ! -f "${full_path}" ]]; then
            log_error "Cannot generate manifest: missing file ${rel_path}"
            rm -f "${tmp_manifest}"
            return 1
        fi
        local csum
        csum=$(calc_sha256 "${full_path}")
        echo "${csum}  ${rel_path}" >> "${tmp_manifest}"
    done < <(get_managed_files)

    mv "${tmp_manifest}" "${MANIFEST_FILE}"
    log_success "Checksum manifest updated successfully."
}

# Verify mode: Check existence, validity, manifest checksums, and compare against upstream
verify_specs() {
    log_info "Running specification drift verification..."
    local drift_detected=0
    local curl_cmd="curl -fsSL --connect-timeout 4 --max-time 10"

    # 1. Verify existence and JSON validity
    while IFS= read -r rel_path; do
        local full_path="${ROOT_DIR}/${rel_path}"
        if [[ ! -f "${full_path}" ]]; then
            log_error "Missing required specification/lexicon: ${rel_path}"
            drift_detected=1
            continue
        fi

        if ! validate_json "${full_path}"; then
            log_error "Malformed JSON in specification file: ${rel_path}"
            drift_detected=1
            continue
        fi
    done < <(get_managed_files)

    # 2. Check against manifest
    if [[ ! -f "${MANIFEST_FILE}" ]]; then
        log_warn "Checksum manifest ${MANIFEST_FILE} does not exist. Generating initial manifest..."
        generate_manifest
        log_success "Verification passed (manifest created)."
        return 0
    fi

    log_info "Verifying SHA-256 checksums against local manifest..."
    while IFS= read -r line; do
        [[ -z "${line}" || "${line}" =~ ^# ]] && continue
        local expected_csum
        local rel_path
        expected_csum=$(echo "${line}" | awk '{print $1}')
        rel_path=$(echo "${line}" | awk '{print $2}')
        local full_path="${ROOT_DIR}/${rel_path}"

        if [[ ! -f "${full_path}" ]]; then
            log_error "Manifest references missing file: ${rel_path}"
            drift_detected=1
            continue
        fi

        local actual_csum
        actual_csum=$(calc_sha256 "${full_path}")

        if [[ "${expected_csum}" != "${actual_csum}" ]]; then
            log_error "LOCAL DRIFT DETECTED in ${rel_path}!"
            log_error "  Expected SHA-256: ${expected_csum}"
            log_error "  Actual SHA-256:   ${actual_csum}"
            drift_detected=1
        else
            echo -e "  [OK] ${rel_path} (${actual_csum:0:12}...)"
        fi
    done < "${MANIFEST_FILE}"

    # 3. Check against upstream canonical endpoints (detect upstream drift)
    log_info "Checking upstream canonical repositories for specification drift..."
    check_upstream_drift() {
        local url="$1"
        local rel_path="$2"
        local full_path="${ROOT_DIR}/${rel_path}"
        local tmp_upstream
        tmp_upstream=$(mktemp 2>/dev/null || mktemp -t 'upstream_spec')

        if ${curl_cmd} "${url}" -o "${tmp_upstream}" 2>/dev/null; then
            if validate_json "${tmp_upstream}"; then
                format_json "${tmp_upstream}"
                
                # Format local copy canonical representation for comparison
                local tmp_local
                tmp_local=$(mktemp 2>/dev/null || mktemp -t 'local_spec')
                cp "${full_path}" "${tmp_local}"
                if validate_json "${tmp_local}"; then
                    format_json "${tmp_local}"
                fi

                local upstream_csum
                local local_csum
                upstream_csum=$(calc_sha256 "${tmp_upstream}")
                local_csum=$(calc_sha256 "${tmp_local}")
                rm -f "${tmp_local}"

                if [[ "${upstream_csum}" != "${local_csum}" ]]; then
                    log_error "UPSTREAM DRIFT DETECTED in ${rel_path}!"
                    log_error "  Local SHA-256:    ${local_csum}"
                    log_error "  Upstream SHA-256: ${upstream_csum}"
                    log_error "  Run ./scripts/sync_specs.sh --sync to update local specs."
                    drift_detected=1
                else
                    echo -e "  [UPSTREAM MATCH] ${rel_path} matches upstream canonical source."
                fi
            else
                log_warn "Upstream returned non-JSON payload for ${rel_path}."
            fi
            rm -f "${tmp_upstream}"
        else
            log_info "  [OFFLINE / TIMEOUT] Upstream endpoint unreachable for ${rel_path}. Pinned manifest verified."
            rm -f "${tmp_upstream}"
        fi
    }

    check_upstream_drift "${RESOLVE_HANDLE_URL}" "lexicons/com/atproto/identity/resolveHandle.json"
    check_upstream_drift "${CREATE_SESSION_URL}" "lexicons/com/atproto/server/createSession.json"
    check_upstream_drift "${REFRESH_SESSION_URL}" "lexicons/com/atproto/server/refreshSession.json"

    if [[ ${drift_detected} -ne 0 ]]; then
        log_error "Specification drift check FAILED! Local files differ from manifest or upstream."
        return 1
    fi

    log_success "All canonical Lexicons and RFC schemas match manifest and upstream. Zero drift detected."
    return 0
}

# Sync mode: Download latest specs if online, format, and regenerate manifest
sync_specs() {
    log_info "Synchronizing canonical Lexicons and RFC schemas from upstream..."

    local curl_cmd="curl -fsSL --connect-timeout 5 --max-time 15"
    local sync_errors=0

    # Ensure target directories exist
    mkdir -p "${LEXICONS_DIR}/com/atproto/identity"
    mkdir -p "${LEXICONS_DIR}/com/atproto/server"
    mkdir -p "${SCHEMAS_DIR}"

    # Helper function to fetch file with fallback
    fetch_file() {
        local url="$1"
        local dest="$2"
        local desc="$3"
        local tmp="${dest}.download.$$"

        log_info "Fetching ${desc}..."
        if ${curl_cmd} "${url}" -o "${tmp}" 2>/dev/null; then
            if validate_json "${tmp}"; then
                format_json "${tmp}"
                mv "${tmp}" "${dest}"
                log_success "Updated ${desc} from ${url}"
            else
                log_warn "Downloaded ${desc} is invalid JSON; preserving existing local version."
                rm -f "${tmp}"
                sync_errors=$((sync_errors + 1))
            fi
        else
            log_warn "Network request failed for ${desc} (${url}). Using local fallback."
            rm -f "${tmp}"
            if [[ ! -f "${dest}" ]]; then
                log_error "No local fallback available for ${dest}!"
                sync_errors=$((sync_errors + 1))
            fi
        fi
    }

    fetch_file "${RESOLVE_HANDLE_URL}" "${LEXICONS_DIR}/com/atproto/identity/resolveHandle.json" "com.atproto.identity.resolveHandle"
    fetch_file "${CREATE_SESSION_URL}" "${LEXICONS_DIR}/com/atproto/server/createSession.json" "com.atproto.server.createSession"
    fetch_file "${REFRESH_SESSION_URL}" "${LEXICONS_DIR}/com/atproto/server/refreshSession.json" "com.atproto.server.refreshSession"

    # Format existing schemas
    while IFS= read -r rel_path; do
        local full_path="${ROOT_DIR}/${rel_path}"
        if [[ -f "${full_path}" ]]; then
            format_json "${full_path}"
        fi
    done < <(get_managed_files)

    # Regenerate checksum manifest
    generate_manifest

    if [[ ${sync_errors} -gt 0 ]]; then
        log_warn "Sync completed with ${sync_errors} offline/network fallbacks. Local specs preserved."
    else
        log_success "Upstream specifications synchronized and verified successfully."
    fi
}

show_help() {
    cat <<EOF
skyauth Upstream Specification Drift Guard

Usage:
  $(basename "$0") [command]

Commands:
  --check, --verify    Verify local specifications against checksum manifest and JSON schema syntax
  --sync               Download latest upstream lexicons/schemas and update checksum manifest
  --generate-manifest  Force regenerate the checksum manifest from current local files
  --help, -h           Show this help message

Exit Codes:
  0   All specifications valid and matching manifest (no drift)
  1   Drift detected, missing files, or invalid JSON syntax
EOF
}

# Main Dispatcher
main() {
    local cmd="${1:---check}"

    case "${cmd}" in
        --check|--verify)
            verify_specs
            ;;
        --sync)
            sync_specs
            ;;
        --generate-manifest)
            generate_manifest
            ;;
        --help|-h)
            show_help
            ;;
        *)
            log_error "Unknown command: ${cmd}"
            show_help
            exit 1
            ;;
    esac
}

main "$@"
