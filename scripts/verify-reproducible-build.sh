#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${ROOT}/scripts/reproducible-build-env.sh" "${ROOT}"

TMPDIR="$(mktemp -d /tmp/re_repro_build.XXXXXX)"
SIGNING_KEY="${TMPDIR}/worm_signing.key"
STAMP_NAME="ransomeye-repro-stamp.$(printf '%s' "${ROOT}" | sha256sum | awk '{print $1}')"
STAMP_PATH="/tmp/${STAMP_NAME}"

declare -A MANIFEST_PATHS=(
    ["build/ransomeye-core"]="/opt/ransomeye/core/ransomeye-core"
)

ARTIFACTS=(
    "build/ransomeye-core"
    "build/integrity.manifest"
    "build/integrity.sig"
)

cleanup() {
    rm -rf "${TMPDIR}"
}
trap cleanup EXIT

printf '0123456789abcdef0123456789abcdef' > "${SIGNING_KEY}"

clean_build_state() {
    rm -rf "${ROOT}/build"
    go clean -cache -testcache >/dev/null 2>&1 || true
    cargo clean --manifest-path "${ROOT}/scripts/sign-integrity-manifest/Cargo.toml" >/dev/null 2>&1 || true
    make -C "${ROOT}" purge-in-repo-cargo-targets >/dev/null 2>&1 || true
}

assert_manifest_binding() {
    local manifest="${ROOT}/build/integrity.manifest"
    for artifact in "${!MANIFEST_PATHS[@]}"; do
        local actual_hash expected_hash install_path
        install_path="${MANIFEST_PATHS[${artifact}]}"
        actual_hash="$(sha256sum "${ROOT}/${artifact}" | awk '{print $1}')"
        expected_hash="$(awk -v path="${install_path}" '$2 == path { sub(/^sha256:/, "", $1); print $1 }' "${manifest}")"
        if [[ -z "${expected_hash}" ]]; then
            echo "FAIL: missing manifest entry for ${install_path}" >&2
            exit 1
        fi
        if [[ "${actual_hash}" != "${expected_hash}" ]]; then
            echo "FAIL: manifest hash mismatch for ${artifact}" >&2
            echo "expected ${expected_hash}" >&2
            echo "actual   ${actual_hash}" >&2
            exit 1
        fi
    done
}

assert_path_stripped() {
    local artifact binary
    for artifact in "$@"; do
        binary="${ROOT}/${artifact}"
        if grep -aF "${ROOT}" "${binary}" >/dev/null; then
            echo "FAIL: absolute build path leaked into ${binary}" >&2
            exit 1
        fi
    done
}

hash_artifacts() {
    local output="$1"
    : > "${output}"
    local artifact
    for artifact in "${ARTIFACTS[@]}"; do
        if [[ ! -f "${ROOT}/${artifact}" ]]; then
            echo "FAIL: missing artifact ${artifact}" >&2
            exit 1
        fi
        sha256sum "${ROOT}/${artifact}" >> "${output}"
    done
    sort -k2 "${output}" -o "${output}"
}

assert_signature_binding() {
    local recomputed_sig="${TMPDIR}/integrity.${1}.sig"
    cargo run --quiet --release \
        --manifest-path "${ROOT}/scripts/sign-integrity-manifest/Cargo.toml" \
        -- \
        "${ROOT}/build/integrity.manifest" \
        "${recomputed_sig}" \
        "${SIGNING_KEY}" >/dev/null
    if ! cmp -s "${ROOT}/build/integrity.sig" "${recomputed_sig}"; then
        echo "FAIL: integrity.sig does not match the signed manifest bytes" >&2
        exit 1
    fi
}

build_once() {
    local run_name="$1"
    clean_build_state
    make -C "${ROOT}" generate-integrity \
        INTEGRITY_SIGNING_KEY="${SIGNING_KEY}" >/dev/null 2>&1
    assert_manifest_binding
    assert_signature_binding "${run_name}"
    assert_path_stripped \
        "build/ransomeye-core"
    hash_artifacts "${TMPDIR}/${run_name}.sha256"
}

build_once run1
build_once run2

if ! diff -u "${TMPDIR}/run1.sha256" "${TMPDIR}/run2.sha256"; then
    echo "FAIL: reproducible build mismatch" >&2
    exit 1
fi

status_hash() {
    (
        cd "${ROOT}"
        {
            git rev-parse HEAD
            git status --porcelain=v1 --untracked-files=all
        } | sha256sum | awk '{print $1}'
    )
}

printf '%s\n' "$(status_hash)" > "${STAMP_PATH}"
echo "OK: reproducible build verified"
