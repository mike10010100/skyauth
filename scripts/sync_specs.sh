#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
MANIFEST_FILE="${ROOT_DIR}/schemas/.checksums.sha256"
PROVENANCE_FILE="${ROOT_DIR}/schemas/provenance.json"
TEMPORARY_DIRECTORIES=()

cleanup() {
    local directory
    for directory in "${TEMPORARY_DIRECTORIES[@]}"; do
        if [[ -n "${directory}" && -d "${directory}" ]]; then
            rm -r -- "${directory}"
        fi
    done
}
trap cleanup EXIT

managed_files() {
    local provenance="${1:-${PROVENANCE_FILE}}"
    jq -r '.artifacts[].local_path' "${provenance}"
}

sha256_file() {
    sha256sum "$1" | awk '{print $1}'
}

validate_json() {
    jq empty "$1" >/dev/null
}

normalize_json() {
    jq -S . "$1"
}

generate_manifest_to() {
    local provenance="$1"
    local content_root="$2"
    local destination="$3"
    local temporary
    temporary="$(mktemp "${destination}.XXXXXX")"
    local paths
    if ! validate_json "${provenance}" || ! paths="$(managed_files "${provenance}")" || [[ -z "${paths}" ]]; then
        rm -f -- "${temporary}"
        return 1
    fi
    local path digest
    while IFS= read -r path; do
        if ! digest="$(sha256_file "${content_root}/${path}")"; then
            rm -f -- "${temporary}"
            return 1
        fi
        printf '%s  %s\n' "${digest}" "${path}" >>"${temporary}"
    done <<<"${paths}"
    mv "${temporary}" "${destination}"
}

generate_manifest() {
    generate_manifest_to "${PROVENANCE_FILE}" "${ROOT_DIR}" "${MANIFEST_FILE}"
}

verify_tree() {
    local content_root="$1"
    local provenance="$2"
    local manifest="$3"
    validate_json "${provenance}"
    local failed=0
    local path file expected actual
    while IFS= read -r path; do
        file="${content_root}/${path}"
        if [[ ! -f "${file}" ]] || ! validate_json "${file}"; then
            printf 'invalid or missing managed artifact: %s\n' "${path}" >&2
            failed=1
            continue
        fi
        expected="$(jq -r --arg path "${path}" '.artifacts[] | select(.local_path == $path) | .local_sha256' "${provenance}")"
        if ! actual="$(sha256_file "${file}")" || [[ "${actual}" != "${expected}" ]]; then
            printf 'local provenance digest mismatch: %s\n' "${path}" >&2
            failed=1
        fi
    done < <(managed_files "${provenance}")
    if [[ ! -f "${manifest}" ]] || ! (cd "${content_root}" && sha256sum --check --strict "${manifest}"); then
        failed=1
    fi
    if [[ "${failed}" -ne 0 ]]; then
        return 1
    fi
}

verify_local() {
    verify_tree "${ROOT_DIR}" "${PROVENANCE_FILE}" "${MANIFEST_FILE}"
    printf 'local specification integrity verified\n'
}

fetch_upstream() {
    local url="$1"
    local path="$2"
    local kind="$3"
    local destination="$4"
    if [[ -n "${SKYAUTH_UPSTREAM_FIXTURE_DIR:-}" ]]; then
        local fixture="${SKYAUTH_UPSTREAM_FIXTURE_DIR}/${path}"
        if [[ "${kind}" == "live-derived" ]]; then
            fixture="${fixture}.source"
        fi
        cp "${fixture}" "${destination}"
    else
        curl -fsSL --connect-timeout 10 --max-time 30 "${url}" -o "${destination}"
    fi
}

check_upstream() {
    verify_local
    local temporary_directory
    temporary_directory="$(mktemp -d)"
    TEMPORARY_DIRECTORIES+=("${temporary_directory}")
    local failed=0
    local index=0
    local path url kind expected raw normalized committed_normalized actual
    while IFS=$'\t' read -r path url kind expected; do
        raw="${temporary_directory}/raw-${index}"
        index=$((index + 1))
        if ! fetch_upstream "${url}" "${path}" "${kind}" "${raw}"; then
            printf 'failed to fetch authoritative source: %s\n' "${path}" >&2
            failed=1
            continue
        fi
        if [[ "${kind}" == "upstream" ]]; then
            normalized="${raw}.normalized"
            committed_normalized="${raw}.committed.normalized"
            if ! validate_json "${raw}"; then
                printf 'failed to fetch valid upstream JSON: %s\n' "${path}" >&2
                failed=1
                continue
            fi
            normalize_json "${raw}" >"${normalized}"
            normalize_json "${ROOT_DIR}/${path}" >"${committed_normalized}"
            if ! cmp -s "${committed_normalized}" "${normalized}"; then
                printf 'upstream specification drift detected: %s\n' "${path}" >&2
                failed=1
            fi
        else
            if ! actual="$(sha256_file "${raw}")" || [[ "${actual}" != "${expected}" ]]; then
                printf 'live specification source drift detected: %s\n' "${path}" >&2
                failed=1
            fi
        fi
    done < <(jq -r '.artifacts[] | select(.kind == "upstream" or .kind == "live-derived") | [.local_path, .source_url, .kind, .upstream_sha256] | @tsv' "${PROVENANCE_FILE}")
    if [[ "${failed}" -ne 0 ]]; then
        return 1
    fi
    printf 'upstream specification freshness verified\n'
}

install_atomically() {
    local source="$1"
    local destination="$2"
    local temporary
    temporary="$(mktemp "${destination}.XXXXXX")"
    if ! cp -- "${source}" "${temporary}" || ! mv -- "${temporary}" "${destination}"; then
        rm -f -- "${temporary}"
        return 1
    fi
}

rollback_installs() {
    local backup_root="$1"
    shift
    local paths=("$@")
    local index path
    for ((index = ${#paths[@]} - 1; index >= 0; index--)); do
        path="${paths[index]}"
        if ! install_atomically "${backup_root}/${path}" "${ROOT_DIR}/${path}"; then
            printf 'failed to roll back managed path: %s\n' "${path}" >&2
            return 1
        fi
    done
}

sync_upstream() {
    local temporary_directory
    temporary_directory="$(mktemp -d)"
    TEMPORARY_DIRECTORIES+=("${temporary_directory}")
    local staged_root="${temporary_directory}/staged"
    local backup_root="${temporary_directory}/backup"
    mkdir -p "${staged_root}/schemas" "${backup_root}"

    local path
    while IFS= read -r path; do
        mkdir -p "${staged_root}/$(dirname "${path}")"
        cp -- "${ROOT_DIR}/${path}" "${staged_root}/${path}"
    done < <(managed_files)
    cp -- "${PROVENANCE_FILE}" "${staged_root}/schemas/provenance.json"

    local commit upstream_date
    if [[ -n "${SKYAUTH_UPSTREAM_FIXTURE_DIR:-}" ]]; then
        commit="fixture"
        upstream_date="1970-01-01T00:00:00Z"
    else
        commit="$(git ls-remote https://github.com/bluesky-social/atproto.git refs/heads/main | awk '{print $1}')"
        upstream_date="$(curl -fsSL --connect-timeout 10 --max-time 30 "https://api.github.com/repos/bluesky-social/atproto/commits/${commit}" | jq -r '.commit.committer.date')"
    fi
    local retrieved_at
    retrieved_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    local updated="${staged_root}/schemas/provenance.json"
    local index=0
    local url kind raw staged raw_digest local_digest next artifact_commit artifact_date
    while IFS=$'\t' read -r path url kind; do
        raw="${temporary_directory}/raw-${index}"
        index=$((index + 1))
        fetch_upstream "${url}" "${path}" "${kind}" "${raw}"
        raw_digest="$(sha256_file "${raw}")"
        artifact_commit="${commit}"
        artifact_date="${upstream_date}"
        if [[ "${kind}" == "upstream" ]]; then
            validate_json "${raw}"
            staged="${staged_root}/${path}"
            normalize_json "${raw}" >"${staged}"
        else
            staged="${staged_root}/${path}"
            artifact_commit="live-page-sha256"
            artifact_date="${retrieved_at%%T*}"
        fi
        local_digest="$(sha256_file "${staged}")"
        next="${temporary_directory}/provenance-${index}.json"
        jq \
            --arg path "${path}" \
            --arg commit "${artifact_commit}" \
            --arg upstream_date "${artifact_date}" \
            --arg raw_digest "${raw_digest}" \
            --arg local_digest "${local_digest}" \
            '(.artifacts[] | select(.local_path == $path)) |= (.upstream_commit = $commit | .upstream_date = $upstream_date | .upstream_sha256 = $raw_digest | .local_sha256 = $local_digest)' \
            "${updated}" >"${next}"
        mv -- "${next}" "${updated}"
    done < <(jq -r '.artifacts[] | select(.kind == "upstream" or .kind == "live-derived") | [.local_path, .source_url, .kind] | @tsv' "${PROVENANCE_FILE}")

    next="${temporary_directory}/provenance-final.json"
    jq --arg retrieved_at "${retrieved_at}" '.retrieved_at = $retrieved_at' "${updated}" >"${next}"
    mv -- "${next}" "${updated}"
    generate_manifest_to "${updated}" "${staged_root}" "${staged_root}/schemas/.checksums.sha256"
    verify_tree "${staged_root}" "${updated}" "${staged_root}/schemas/.checksums.sha256"

    local commit_paths=()
    while IFS= read -r path; do
        commit_paths+=("${path}")
    done < <(jq -r '.artifacts[] | select(.kind == "upstream") | .local_path' "${PROVENANCE_FILE}")
    commit_paths+=("schemas/.checksums.sha256" "schemas/provenance.json")
    for path in "${commit_paths[@]}"; do
        mkdir -p "${backup_root}/$(dirname "${path}")"
        cp -- "${ROOT_DIR}/${path}" "${backup_root}/${path}"
    done

    local installed=()
    local install_count=0
    local failed=0
    for path in "${commit_paths[@]}"; do
        if ! install_atomically "${staged_root}/${path}" "${ROOT_DIR}/${path}"; then
            failed=1
            break
        fi
        installed+=("${path}")
        install_count=$((install_count + 1))
        if [[ -n "${SKYAUTH_SYNC_FAIL_AFTER_INSTALLS:-}" && "${install_count}" -ge "${SKYAUTH_SYNC_FAIL_AFTER_INSTALLS}" ]]; then
            printf 'injected sync commit failure after %s installs\n' "${install_count}" >&2
            failed=1
            break
        fi
    done
    if [[ "${failed}" -ne 0 ]]; then
        rollback_installs "${backup_root}" "${installed[@]}"
        return 1
    fi
    if ! verify_local; then
        rollback_installs "${backup_root}" "${installed[@]}"
        return 1
    fi
}

case "${1:---verify}" in
    --verify|--check)
        verify_local
        ;;
    --check-upstream)
        check_upstream
        ;;
    --sync|--sync-upstream)
        sync_upstream
        ;;
    --generate-manifest)
        generate_manifest
        ;;
    --help|-h)
        printf '%s\n' 'usage: sync_specs.sh --verify|--check-upstream|--sync|--sync-upstream|--generate-manifest'
        ;;
    *)
        printf 'unknown command: %s\n' "$1" >&2
        exit 2
        ;;
esac
