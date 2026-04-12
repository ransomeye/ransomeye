#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

usage() {
  cat <<'EOF'
Usage:
  scripts/authority_db_env.sh --dsn
  scripts/authority_db_env.sh --export
  scripts/authority_db_env.sh --check

Deterministic DB-backed authority test environment for local development.

Overrides:
  POSTGRES_DSN                Use an explicit DSN verbatim.
  MISHKA_TEST_DB_HOST         Default: 127.0.0.1
  MISHKA_TEST_DB_PORT         Default: 5432
  MISHKA_TEST_DB_USER         Default: ransomeye
  MISHKA_TEST_DB_PASSWORD     Default: dev_password
  MISHKA_TEST_DB_NAME         Default: ransomeye_core
  MISHKA_TEST_DB_SSLMODE      Default: verify-full
  MISHKA_TEST_DB_SSLROOTCERT  Default: <repo>/configs/db-certs/ca.crt
  MISHKA_TEST_DB_SSLCERT      Default: <repo>/configs/db-certs/client.crt
  MISHKA_TEST_DB_SSLKEY       Default: <repo>/configs/db-certs/client.key
  MISHKA_TEST_DB_SERVERNAME   Default: host value for openssl probing
EOF
}

require_cmd() {
  local name="$1"
  command -v "${name}" >/dev/null 2>&1 || {
    echo "FATAL: required command not found: ${name}" >&2
    exit 2
  }
}

host_value() {
  printf '%s' "${MISHKA_TEST_DB_HOST:-127.0.0.1}"
}

port_value() {
  printf '%s' "${MISHKA_TEST_DB_PORT:-5432}"
}

user_value() {
  printf '%s' "${MISHKA_TEST_DB_USER:-ransomeye}"
}

password_value() {
  printf '%s' "${MISHKA_TEST_DB_PASSWORD:-dev_password}"
}

dbname_value() {
  printf '%s' "${MISHKA_TEST_DB_NAME:-ransomeye_core}"
}

sslmode_value() {
  printf '%s' "${PGSSLMODE:-${MISHKA_TEST_DB_SSLMODE:-verify-full}}"
}

sslrootcert_value() {
  printf '%s' "${PGSSLROOTCERT:-${MISHKA_TEST_DB_SSLROOTCERT:-${REPO_ROOT}/configs/db-certs/ca.crt}}"
}

sslcert_value() {
  printf '%s' "${PGSSLCERT:-${MISHKA_TEST_DB_SSLCERT:-${REPO_ROOT}/configs/db-certs/client.crt}}"
}

sslkey_value() {
  printf '%s' "${PGSSLKEY:-${MISHKA_TEST_DB_SSLKEY:-${REPO_ROOT}/configs/db-certs/client.key}}"
}

servername_value() {
  printf '%s' "${PGSSLSERVERNAME:-${MISHKA_TEST_DB_SERVERNAME:-$(host_value)}}"
}

dsn_value() {
  if [[ -n "${POSTGRES_DSN:-}" ]]; then
    printf '%s' "${POSTGRES_DSN}"
    return 0
  fi
  printf 'host=%s port=%s user=%s password=%s dbname=%s sslmode=%s sslrootcert=%s sslcert=%s sslkey=%s' \
    "$(host_value)" \
    "$(port_value)" \
    "$(user_value)" \
    "$(password_value)" \
    "$(dbname_value)" \
    "$(sslmode_value)" \
    "$(sslrootcert_value)" \
    "$(sslcert_value)" \
    "$(sslkey_value)"
}

emit_exports() {
  local dsn
  dsn="$(dsn_value)"
  printf 'export POSTGRES_DSN=%q\n' "${dsn}"
  # When POSTGRES_DSN is a self-contained URI (e.g. from /etc/ransomeye/core.env), do not export
  # conflicting libpq single-field vars that would override credentials for psql/goroutines.
  if [[ -n "${POSTGRES_DSN:-}" ]]; then
    printf 'export PGSSLMODE=%q\n' "$(sslmode_value)"
    printf 'export PGSSLROOTCERT=%q\n' "$(sslrootcert_value)"
    printf 'export PGSSLCERT=%q\n' "$(sslcert_value)"
    printf 'export PGSSLKEY=%q\n' "$(sslkey_value)"
    if [[ -n "${PGSSLSERVERNAME:-}" ]]; then
      printf 'export PGSSLSERVERNAME=%q\n' "${PGSSLSERVERNAME}"
    fi
    return 0
  fi
  printf 'export PGHOST=%q\n' "$(host_value)"
  printf 'export PGPORT=%q\n' "$(port_value)"
  printf 'export PGUSER=%q\n' "$(user_value)"
  printf 'export PGPASSWORD=%q\n' "$(password_value)"
  printf 'export PGDATABASE=%q\n' "$(dbname_value)"
  printf 'export PGSSLMODE=%q\n' "$(sslmode_value)"
  printf 'export PGSSLROOTCERT=%q\n' "$(sslrootcert_value)"
  printf 'export PGSSLCERT=%q\n' "$(sslcert_value)"
  printf 'export PGSSLKEY=%q\n' "$(sslkey_value)"
}

check_files() {
  local path
  for path in "$(sslrootcert_value)" "$(sslcert_value)" "$(sslkey_value)"; do
    [[ -r "${path}" ]] || {
      echo "FATAL: required TLS file not readable: ${path}" >&2
      exit 2
    }
  done
}

run_check() {
  require_cmd pg_isready
  require_cmd psql
  require_cmd openssl
  check_files

  local host port dsn servername probe_output
  host="$(host_value)"
  port="$(port_value)"
  dsn="$(dsn_value)"
  servername="$(servername_value)"

  echo "[authority-db] pg_isready ${host}:${port}"
  pg_isready -h "${host}" -p "${port}"

  echo "[authority-db] TLS probe ${host}:${port}"
  probe_output="$(
    openssl s_client \
      -connect "${host}:${port}" \
      -servername "${servername}" \
      -starttls postgres \
      -CAfile "$(sslrootcert_value)" \
      </dev/null 2>&1
  )"
  if ! grep -q 'Verify return code: 0 (ok)' <<<"${probe_output}"; then
    echo "${probe_output}" >&2
    echo "FATAL: PostgreSQL TLS verification failed" >&2
    exit 1
  fi

  echo "[authority-db] SQL probe"
  if ! psql "${dsn}" -Atv ON_ERROR_STOP=1 -c "SELECT current_user, current_database(), current_setting('ssl');"; then
    if [[ -n "${POSTGRES_DSN:-}" ]]; then
      cat >&2 <<'EOF'
FATAL: PostgreSQL auth/connect probe failed.
POSTGRES_DSN is set: psql used that DSN verbatim (check password, db name, sslcert/sslkey in URI or PGSSL*).

If this host is not using the repo's default dev credentials, override one of:
  export POSTGRES_DSN='postgres://... or host=... sslmode=verify-full sslrootcert=... sslcert=... sslkey=...'
  export MISHKA_TEST_DB_USER=...
  export MISHKA_TEST_DB_PASSWORD=...
  export MISHKA_TEST_DB_NAME=...
EOF
    else
      cat >&2 <<EOF
FATAL: PostgreSQL auth/connect probe failed.
Tried host=$(host_value) port=$(port_value) user=$(user_value) dbname=$(dbname_value).

If this host is not using the repo's default dev credentials, override one of:
  export POSTGRES_DSN='host=... port=... user=... password=... dbname=... sslmode=verify-full sslrootcert=... sslcert=... sslkey=...'
  export MISHKA_TEST_DB_USER=...
  export MISHKA_TEST_DB_PASSWORD=...
  export MISHKA_TEST_DB_NAME=...
EOF
    fi
    exit 1
  fi
}

main() {
  if [[ $# -ne 1 ]]; then
    usage >&2
    exit 2
  fi
  case "$1" in
    --dsn)
      dsn_value
      ;;
    --export)
      emit_exports
      ;;
    --check)
      run_check
      ;;
    -h|--help)
      usage
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
}

main "$@"
