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

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

LEXICONS_DIR="${ROOT_DIR}/lexicons"
SCHEMAS_DIR="${ROOT_DIR}/schemas"
MANIFEST_FILE="${SCHEMAS_DIR}/.checksums.sha256"

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

# SHA256 calculator usable on any of sha256sum / shasum / openssl.
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

# JSON syntax validator. Fail closed: with no jq/python3/node available there is
# no way to prove a payload is JSON, so validation fails rather than trusting a
# non-empty file (sync would otherwise replace local specs with garbage).
validate_json() {
    local file="$1"
    if command -v jq &>/dev/null; then
        jq empty "${file}" >/dev/null 2>&1
    elif command -v python3 &>/dev/null; then
        python3 -m json.tool "${file}" >/dev/null 2>&1
    elif command -v node &>/dev/null; then
        node -e "JSON.parse(require('fs').readFileSync(process.argv[1]))" "${file}" >/dev/null 2>&1
    else
        log_error "No JSON tool (jq, python3, or node) available; cannot validate ${file}."
        return 1
    fi
}

# Format JSON in-place when a formatting tool is available.
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

# Canonical managed files relative to ROOT_DIR.
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

# Generate the checksums manifest for all managed files.
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

# Verify local files against the manifest and upstream canonical sources.
verify_specs() {
    log_info "Running specification drift verification..."
    local drift_detected=0
    local fetch_failed=0
    local curl_cmd="curl -fsSL --connect-timeout 4 --max-time 10"

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

    if [[ ! -f "${MANIFEST_FILE}" ]]; then
        # Fail closed: verification must not bootstrap its own trust anchor. A
        # missing manifest means checksums cannot be validated, so --verify fails;
        # manifest creation is reserved for the explicit --generate-manifest command.
        log_error "Checksum manifest ${MANIFEST_FILE} does not exist; verification cannot proceed."
        log_error "Run '${0##*/} --generate-manifest' to create it from the current files, then re-verify."
        return 1
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
            # A failed fetch means upstream state is UNKNOWN — never report it as
            # verified. Count the failure so strict verification mode can fail.
            log_error "  [FETCH FAILED] Upstream endpoint unreachable for ${rel_path}; upstream drift status UNVERIFIED."
            fetch_failed=$((fetch_failed + 1))
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

    if [[ ${fetch_failed} -ne 0 ]]; then
        log_error "Specification verification INCOMPLETE: ${fetch_failed} upstream fetch(es) failed; upstream drift could NOT be verified."
        log_error "Set SYNC_SPECS_ALLOW_OFFLINE=1 to accept manifest-only verification for offline development."
        # Status 3 distinguishes "manifest verified, upstream UNVERIFIED" from hard
        # drift (1) so the caller can apply the offline escape hatch to exactly this
        # case. Function-local variables are not visible to main().
        return 3
    fi

    log_success "All canonical Lexicons and RFC schemas match manifest and upstream. Zero drift detected."
    return 0
}

# Sync mode: fetch latest specs when online, format, and regenerate the manifest.
sync_specs() {
    log_info "Synchronizing canonical Lexicons and RFC schemas from upstream..."

    local curl_cmd="curl -fsSL --connect-timeout 5 --max-time 15"
    local sync_errors=0

    mkdir -p "${LEXICONS_DIR}/com/atproto/identity"
    mkdir -p "${LEXICONS_DIR}/com/atproto/server"
    mkdir -p "${SCHEMAS_DIR}"

    # Fetch to a temp file; fall back to the existing local copy on any failure.
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

    while IFS= read -r rel_path; do
        local full_path="${ROOT_DIR}/${rel_path}"
        if [[ -f "${full_path}" ]] && ! format_json "${full_path}"; then
            log_error "Failed to format ${rel_path}; aborting sync before manifest regeneration."
            return 1
        fi
    done < <(get_managed_files)

    # Fail closed on manifest generation: a silent manifest failure would let
    # unverified content look committed. (Errexit is active outside --verify.)
    if ! generate_manifest; then
        log_error "Manifest regeneration failed; aborting sync."
        return 1
    fi

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
  0   All specifications valid and matching manifest AND upstream (no drift)
  1   Drift detected, missing files, or invalid JSON syntax
  3   Local manifest verified but upstream fetch failed (upstream drift
      UNVERIFIED). Set SYNC_SPECS_ALLOW_OFFLINE=1 to accept manifest-only
      verification when upstream is unreachable.
EOF
}

# Command dispatcher. Each subcommand runs with errexit active so any failure
# (formatter errors, manifest generation, a failed fetch without a local copy)
# aborts fail-closed; only the --verify status capture below suppresses errexit.
run_command() {
    case "${1:---check}" in
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
            log_error "Unknown command: ${1}"
            show_help
            exit 1
            ;;
    esac
}

# Offline escape hatch: verify_specs returns 3 when the manifest is verified but
# upstream could not be fetched. With SYNC_SPECS_ALLOW_OFFLINE=1 that specific
# outcome is downgraded to a warning; hard drift (1) always fails. Errexit is
# suppressed ONLY for the status capture so a non-zero return is observable
# rather than fatal.
set +e
run_command "$@"
verify_status=$?
set -e
if [[ ${verify_status} -eq 3 && "${SYNC_SPECS_ALLOW_OFFLINE:-0}" == "1" ]]; then
    log_warn "SYNC_SPECS_ALLOW_OFFLINE=1: accepting manifest-only verification (upstream unverified)."
    exit 0
fi
exit "${verify_status}"
