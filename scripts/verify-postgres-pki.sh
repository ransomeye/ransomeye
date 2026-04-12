#!/usr/bin/env bash
# Validates PostgreSQL TLS leaf certs are RSA (not Ed25519/EC) for libpq compatibility (PRD-14).
set -euo pipefail

CA="${PGVERIFY_CA:-/opt/ransomeye/core/certs/ca.crt}"
SERVER_CERT="${PGVERIFY_SERVER_CERT:-/opt/ransomeye/core/certs/server.crt}"
CLIENT_CERT="${PGVERIFY_CLIENT_CERT:-/opt/ransomeye/core/certs/client.crt}"

pubtext() {
  openssl x509 -in "$1" -noout -pubkey 2>/dev/null | openssl pkey -pubin -text -noout 2>/dev/null
}

if [[ ! -r "$CA" || ! -r "$SERVER_CERT" || ! -r "$CLIENT_CERT" ]]; then
  echo "missing CA or leaf certs (set PGVERIFY_*)" >&2
  exit 2
fi

openssl verify -CAfile "$CA" "$SERVER_CERT" >/dev/null
openssl verify -CAfile "$CA" "$CLIENT_CERT" >/dev/null

for pair in "server:${SERVER_CERT}" "client:${CLIENT_CERT}"; do
  label="${pair%%:*}"
  cert="${pair#*:}"
  info="$(pubtext "$cert")"
  if ! echo "$info" | grep -qE 'Modulus:|RSA Public-Key'; then
    echo "FAIL: ${label} leaf is not RSA (expect RSA-2048 for PostgreSQL TLS)" >&2
    exit 1
  fi
  if echo "$info" | grep -qi 'ED25519'; then
    echo "FAIL: ${label} must not be Ed25519 for this PKI profile" >&2
    exit 1
  fi
done

printf '%s\n' "{\"status\":\"PASS\",\"profile\":\"RSA-2048-postgresql-tls\",\"ca\":\"$CA\",\"server_cert\":\"$SERVER_CERT\",\"client_cert\":\"$CLIENT_CERT\",\"openssl_verify\":\"OK\"}"
