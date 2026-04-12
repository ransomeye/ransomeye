#!/usr/bin/env bash
# shellcheck shell=bash

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    echo "source scripts/reproducible-build-env.sh <repo-root>" >&2
    exit 2
fi

repo_root_arg="${1:-$(pwd)}"
repo_root="$(cd "${repo_root_arg}" && pwd)"

# Keep all Cargo artifacts outside the repo so `cargo build`/`cargo run` never
# recreate banned in-tree paths like installer/target/ or scripts/.../target/.
_repo_hash="$(printf '%s' "${repo_root}" | sha256sum | awk '{print $1}')"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${XDG_CACHE_HOME:-${HOME}/.cache}/ransomeye-cargo/${_repo_hash}}"

export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1700000000}"
export LC_ALL="${LC_ALL:-C}"
export ZERO_AR_DATE="${ZERO_AR_DATE:-1}"
export CARGO_PROFILE_RELEASE_DEBUG="${CARGO_PROFILE_RELEASE_DEBUG:-false}"
export CARGO_PROFILE_RELEASE_STRIP="${CARGO_PROFILE_RELEASE_STRIP:-true}"
export CARGO_PROFILE_RELEASE_LTO="${CARGO_PROFILE_RELEASE_LTO:-true}"
export CARGO_PROFILE_RELEASE_CODEGEN_UNITS="${CARGO_PROFILE_RELEASE_CODEGEN_UNITS:-1}"

path_map_flags="-ffile-prefix-map=${repo_root}=. -fdebug-prefix-map=${repo_root}=."
if [[ " ${CFLAGS-} " != *" -ffile-prefix-map=${repo_root}=. "* ]]; then
    export CFLAGS="${CFLAGS:+${CFLAGS} }${path_map_flags}"
fi
if [[ " ${CXXFLAGS-} " != *" -ffile-prefix-map=${repo_root}=. "* ]]; then
    export CXXFLAGS="${CXXFLAGS:+${CXXFLAGS} }${path_map_flags}"
fi

rust_remap_flag="--remap-path-prefix=${repo_root}=."
if [[ " ${RUSTFLAGS-} " != *" ${rust_remap_flag} "* ]]; then
    export RUSTFLAGS="${RUSTFLAGS:+${RUSTFLAGS} }${rust_remap_flag}"
fi
