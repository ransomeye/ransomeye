#!/usr/bin/env bash
# Slice-1: apply core/migrations numbered SQL in order using psql (no TLS).
# Strips SELECT register_migration(...) lines to match core/internal/db/migrator behavior,
# then inserts schema_migrations rows with the same SHA-256 checksum as the Go migrator (full file bytes).
#
# Usage:
#   export PGHOST=127.0.0.1 PGPORT=5432 PGUSER=ransomeye PGPASSWORD=dev_password PGDATABASE=ransomeye_core
#   ./scripts/slice1_apply_migrations_psql.sh
#
# Live host (Mishka): prefer POSTGRES_DSN (+ PGSSL*) from /etc/ransomeye/core.env (same as authority_db_env.sh).
#
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MIG_DIR="${ROOT}/core/migrations"

if [[ -n "${POSTGRES_DSN:-}" ]]; then
  psql=(psql -v ON_ERROR_STOP=1 "${POSTGRES_DSN}")
  echo "[slice1] using POSTGRES_DSN for psql (PGSSL* / URI params apply from environment)"
else
  : "${PGHOST:=127.0.0.1}"
  : "${PGPORT:=5432}"
  : "${PGUSER:=ransomeye}"
  : "${PGDATABASE:=ransomeye_core}"

  if [[ -z "${PGPASSWORD:-}" ]]; then
    echo "FATAL: PGPASSWORD must be set for non-interactive psql (or set POSTGRES_DSN)" >&2
    exit 1
  fi

  export PGPASSWORD

  psql=(psql -v ON_ERROR_STOP=1 -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$PGDATABASE")
fi

echo "[slice1] applying migrations from ${MIG_DIR}"

shopt -s nullglob
files=("${MIG_DIR}"/[0-9][0-9][0-9]_*.sql)
IFS=$'\n' files=($(sort <<<"${files[*]}"))
shopt -u nullglob

for f in "${files[@]}"; do
  base="$(basename "$f")"
  ver_str="${base:0:3}"
  ver=$((10#${ver_str#0}))
  sum="$(sha256sum "$f" | awk '{print $1}')"
  echo "[slice1] --- ${base} (version ${ver}) ---"
  has_schema_migrations="$("${psql[@]}" -Atqc "SELECT to_regclass('public.schema_migrations') IS NOT NULL")"
  has_schema_migrations="$(echo "$has_schema_migrations" | tr -d '[:space:]')"
  if [[ "$has_schema_migrations" == "t" ]]; then
    existing="$("${psql[@]}" -AtF $'\t' -c "SELECT filename, checksum FROM schema_migrations WHERE version = ${ver} LIMIT 1")"
    if [[ -n "${existing}" ]]; then
      existing_filename="${existing%%$'\t'*}"
      existing_checksum="${existing#*$'\t'}"
      if [[ "${existing_checksum}" == "${sum}" && "${existing_filename}" == "${base}" ]]; then
        echo "[slice1] skip ${base} (already registered with matching filename+checksum)"
        continue
      fi
      if [[ "${existing_checksum}" == "${sum}" && "${existing_filename}" != "${base}" ]]; then
        echo "[slice1] reconcile rename ${existing_filename} -> ${base} (checksum unchanged)"
        "${psql[@]}" -c "UPDATE schema_migrations SET filename = '${base}' WHERE version = ${ver}"
        continue
      fi
      echo "FATAL: schema_migrations version ${ver} already registered with filename=${existing_filename} checksum=${existing_checksum}, expected filename=${base} checksum=${sum}" >&2
      exit 1
    fi
  fi
  # Strip register_migration lines (same as Go migrator stripRegisterMigration)
  body="$(grep -v 'SELECT register_migration(' "$f" || true)"
  if [[ -z "$(echo "$body" | tr -d '[:space:]')" ]]; then
    echo "FATAL: empty migration after strip: $f" >&2
    exit 1
  fi
  printf '%s\n' "$body" | "${psql[@]}" -f -
  "${psql[@]}" -c "INSERT INTO schema_migrations (version, filename, checksum) VALUES (${ver}, '${base}', '${sum}')"
done

echo "[slice1] OK: $(${psql[@]} -tAc 'SELECT COUNT(*) FROM schema_migrations') rows in schema_migrations"
