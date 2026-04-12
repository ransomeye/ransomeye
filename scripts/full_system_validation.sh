#!/bin/bash

set -euo pipefail

ports="50052|50053|5432|6379|8443"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

pass() {
  echo "[PASS] $1"
}

fail() {
  echo "[FAIL] $1"
  exit 1
}

run_check() {
  local message="$1"
  shift

  if "$@"; then
    pass "${message}"
  else
    fail "${message}"
  fi
}

check_core_services() {
  command -v ss >/dev/null 2>&1 || return 1

  local listeners4 listeners6 local4 local6 port
  listeners4="$(ss -H -lntp -4 2>/dev/null)" || return 1
  listeners6="$(ss -H -lntp -6 2>/dev/null)" || return 1
  local4="$(printf '%s\n' "${listeners4}" | awk '{print $4}')" || return 1
  local6="$(printf '%s\n' "${listeners6}" | awk '{print $4}')" || return 1

  for port in ${ports//|/ }; do
    printf '%s\n' "${local4}" | grep -Eq "^127\.0\.0\.1:${port}$" || return 1
  done

  if printf '%s\n' "${local4}" | grep -Eq "^0\.0\.0\.0:(${ports})$"; then
    return 1
  fi

  if printf '%s\n' "${local6}" | grep -Eq "^\[::1\]:(${ports})$|^::1:(${ports})$"; then
    return 1
  fi

  return 0
}

check_tls() {
  command -v openssl >/dev/null 2>&1 || return 1

  local cafile out13 out12
  cafile="/opt/ransomeye/core/certs/ca.crt"
  [ -f "${cafile}" ] || return 1

  out13="$(mktemp)" || return 1
  out12="$(mktemp)" || {
    rm -f "${out13}"
    return 1
  }

  if ! openssl s_client \
    -connect 127.0.0.1:8443 \
    -tls1_3 \
    -verify_return_error \
    -CAfile "${cafile}" \
    </dev/null >"${out13}" 2>&1; then
    rm -f "${out13}" "${out12}"
    return 1
  fi

  grep -Eq '^[[:space:]]*Protocol[[:space:]]*:[[:space:]]*TLSv1\.3$' "${out13}" || {
    rm -f "${out13}" "${out12}"
    return 1
  }
  grep -Eq 'Verify return code:[[:space:]]*0[[:space:]]*\(ok\)' "${out13}" || {
    rm -f "${out13}" "${out12}"
    return 1
  }

  openssl s_client \
    -connect 127.0.0.1:8443 \
    -tls1_2 \
    -verify_return_error \
    -CAfile "${cafile}" \
    </dev/null >"${out12}" 2>&1 || true

  if grep -Eq 'Protocol[[:space:]]*:[[:space:]]*TLSv1\.2' "${out12}"; then
    rm -f "${out13}" "${out12}"
    return 1
  fi

  if ! grep -Eqi 'alert protocol version|handshake failure|unsupported protocol|wrong version number|no protocols available' "${out12}"; then
    rm -f "${out13}" "${out12}"
    return 1
  fi

  rm -f "${out13}" "${out12}"
  return 0
}

check_worm_key() {
  local key="/etc/ransomeye/worm_signing.key"
  command -v stat >/dev/null 2>&1 || return 1

  [ -f "${key}" ] || return 1

  local perms size
  perms="$(stat -c '%a' "${key}")" || return 1
  size="$(stat -c '%s' "${key}")" || return 1

  [ "${perms}" = "400" ] || return 1
  [ "${size}" = "32" ] || return 1
  return 0
}

check_merkle_root() {
  command -v psql >/dev/null 2>&1 || return 1
  [ -n "${POSTGRES_DSN:-}" ] || return 1

  local count
  count="$(psql "${POSTGRES_DSN}" -Atv ON_ERROR_STOP=1 -c 'SELECT COUNT(*) FROM merkle_daily_roots;' 2>/dev/null)" || return 1
  count="${count//[[:space:]]/}"

  [[ "${count}" =~ ^[0-9]+$ ]] || return 1
  [ "${count}" -gt 0 ] || return 1
  return 0
}

check_prd_integrity() {
  command -v sha256sum >/dev/null 2>&1 || return 1
  command -v diff >/dev/null 2>&1 || return 1

  (
    cd "${REPO_ROOT}/prd_project_mishka" &&
      sha256sum *.md | LC_ALL=C sort | diff prd.sha256 -
  )
}

check_nginx() {
  command -v nginx >/dev/null 2>&1 || return 1
  nginx -t >/dev/null 2>&1
}

check_ui_access() {
  command -v curl >/dev/null 2>&1 || return 1

  local body
  body="$(curl -ksS --max-time 10 https://127.0.0.1/ 2>/dev/null)" || return 1
  printf '%s' "${body}" | grep -Eiq '<!doctype html|<html[[:space:]>]' || return 1
  return 0
}

check_api_health() {
  command -v curl >/dev/null 2>&1 || return 1

  local body
  body="$(curl -ksS --max-time 10 https://127.0.0.1/api/v1/health 2>/dev/null)" || return 1
  printf '%s' "${body}" | grep -Eq '^\{.*\}$' || return 1
  printf '%s' "${body}" | grep -Eq '"status"[[:space:]]*:[[:space:]]*"ok"' || return 1
  return 0
}

check_core_process() {
  command -v pgrep >/dev/null 2>&1 || return 1
  pgrep -x ransomeye-core >/dev/null 2>&1
}

run_check "ransomeye-core process running" check_core_process
run_check "RansomEye ports present on 127.0.0.1 and not bound to 0.0.0.0 or ::1" check_core_services
run_check "TLS certificate verified and TLSv1.3 enforced on 127.0.0.1:8443" check_tls
run_check "WORM signing key exists with 0400 perms and 32-byte seed size" check_worm_key
run_check "Merkle daily roots present in database" check_merkle_root
run_check "PRD integrity manifest matches markdown contents" check_prd_integrity
run_check "nginx configuration validation" check_nginx
run_check "UI access returns HTML over HTTPS" check_ui_access
run_check "API health endpoint returns JSON status ok" check_api_health

exit 0
