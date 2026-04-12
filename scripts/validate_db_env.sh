#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CERT_DIR="/opt/ransomeye/core/certs"
CA_CERT="${CERT_DIR}/ca.crt"

DB_USER="ransomeye"
DB_PASSWORD="strong-password"
DB_NAME="ransomeye_core"
EXPECTED_JSON='{"status":"PASS","checks":{"tables":true,"immutability":true,"merkle":true,"rls":true,"timescale":true,"tls":true,"forbidden_tables":true,"indexes":true}}'

fail() {
  echo "$1" >&2
  exit 1
}

listener_output="$(ss -ltn '( sport = :5432 )')"
echo "${listener_output}" | grep -q '127.0.0.1:5432' || fail "loopback listener missing on 127.0.0.1:5432"
if echo "${listener_output}" | grep -Eq '0\.0\.0\.0:5432|:::5432|\[::\]:5432'; then
  fail "non-loopback listener detected for 5432"
fi

openssl_output="$(
  openssl s_client \
    -connect 127.0.0.1:5432 \
    -servername 127.0.0.1 \
    -starttls postgres \
    -tls1_3 \
    -CAfile "${CA_CERT}" \
    </dev/null 2>&1
)"
echo "${openssl_output}" | grep -Eq 'Protocol *: TLSv1\.3|New, TLSv1\.3,' || fail "TLSv1.3 handshake failed"
echo "${openssl_output}" | grep -q 'Verify return code: 0 (ok)' || fail "server certificate verification failed"

psql_output="$(
  PGPASSWORD="${DB_PASSWORD}" \
  psql "host=127.0.0.1 port=5432 user=${DB_USER} dbname=${DB_NAME} sslmode=verify-full sslrootcert=${CA_CERT}" \
    -Atqc "SHOW ssl_min_protocol_version; SHOW ssl_max_protocol_version; SHOW listen_addresses;"
)"
expected_psql_output=$'TLSv1.3\nTLSv1.3\n127.0.0.1'
[[ "${psql_output}" == "${expected_psql_output}" ]] || fail "psql verification failed"

cd "${ROOT_DIR}"
go run ./core/cmd/dbctl migrate

validation_output="$(go run ./core/cmd/dbctl validate)"
echo "${validation_output}"
[[ "${validation_output}" == "${EXPECTED_JSON}" ]] || fail "dbctl validate did not return PASS"
