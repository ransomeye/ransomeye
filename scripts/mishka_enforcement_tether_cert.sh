#!/usr/bin/env bash
# Mishka PRD-12: mint a short-lived mTLS client cert for mishka-enforcement-tether with mandatory
# URI SAN urn:ransomeye:agent:<uuid> (core rejects ReceiveActions without it).
#
# Requires: openssl 3.x, read access to intermediate CA + key (default /etc/ransomeye/pki/).
# Does not start any service — writes key/cert paths you pass to mishka-enforcement-tether.
#
# Usage:
#   sudo ./scripts/mishka_enforcement_tether_cert.sh
#   sudo /opt/ransomeye/core/mishka-enforcement-tether -ca /opt/ransomeye/core/certs/ca-chain.crt \
#     -cert /var/lib/ransomeye/state/mishka-tether.crt -key /var/lib/ransomeye/state/mishka-tether.key
set -euo pipefail

INTERMEDIATE_CERT="${INTERMEDIATE_CERT:-/etc/ransomeye/pki/intermediate_ca.crt}"
INTERMEDIATE_KEY="${INTERMEDIATE_KEY:-/etc/ransomeye/pki/intermediate_ca.key}"
OUT_DIR="${OUT_DIR:-/var/lib/ransomeye/state}"
OUT_CERT="${OUT_CERT:-${OUT_DIR}/mishka-tether.crt}"
OUT_KEY="${OUT_KEY:-${OUT_DIR}/mishka-tether.key}"
DAYS="${DAYS:-365}"
AGENT_UUID="${AGENT_UUID:-$(python3 -c 'import uuid; print(uuid.uuid4())')}"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "FATAL: run as root (needs to read ${INTERMEDIATE_KEY} and write ${OUT_DIR})" >&2
  exit 2
fi

[[ -r "${INTERMEDIATE_CERT}" ]] || { echo "FATAL: missing ${INTERMEDIATE_CERT}" >&2; exit 2; }
[[ -r "${INTERMEDIATE_KEY}" ]] || { echo "FATAL: missing ${INTERMEDIATE_KEY}" >&2; exit 2; }

tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

# Ed25519 leaf: SendTelemetry verifies payload signatures against the client cert public key (see gateway.VerifyEd25519Signature).
openssl genpkey -algorithm ED25519 -out "${tmp}/tether.key"

san_line="URI:urn:ransomeye:agent:${AGENT_UUID}"
openssl req -new -key "${tmp}/tether.key" -out "${tmp}/tether.csr" \
  -subj "/CN=${AGENT_UUID}" \
  -addext "subjectAltName=${san_line}"

openssl x509 -req -in "${tmp}/tether.csr" \
  -CA "${INTERMEDIATE_CERT}" -CAkey "${INTERMEDIATE_KEY}" -CAcreateserial \
  -out "${tmp}/tether.crt" -days "${DAYS}" \
  -copy_extensions copyall

install -d -m 0700 "${OUT_DIR}"
install -m 0600 "${tmp}/tether.key" "${OUT_KEY}"
install -m 0644 "${tmp}/tether.crt" "${OUT_CERT}"

echo "[OK] agent_id (URI SAN) = ${AGENT_UUID}"
echo "[OK] cert -> ${OUT_CERT}"
echo "[OK] key  -> ${OUT_KEY} (0600)"
echo "Run tether:"
echo "  mishka-enforcement-tether -ca /opt/ransomeye/core/certs/ca-chain.crt -cert ${OUT_CERT} -key ${OUT_KEY}"
