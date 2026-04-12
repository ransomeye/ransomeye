#!/usr/bin/env bash
# PostgreSQL TLS PKI — RSA-2048 only (libpq / OpenSSL compatibility, PRD-14/PRD-15 air-gap).
# Deterministic paths under /opt/ransomeye/core/certs. TLS 1.3 compatible (RSA-PSS / SHA256 chain).
set -euo pipefail

CERT_DIR="/opt/ransomeye/core/certs"
SERVICE_USER="postgres"
SERVICE_GROUP="postgres"

required_files=(
  "${CERT_DIR}/ca.key"
  "${CERT_DIR}/ca.crt"
  "${CERT_DIR}/server.key"
  "${CERT_DIR}/server.crt"
  "${CERT_DIR}/client.key"
  "${CERT_DIR}/client.crt"
)

existing_count=0
for path in "${required_files[@]}"; do
  if [[ -f "${path}" ]]; then
    existing_count=$((existing_count + 1))
  fi
done

if [[ "${existing_count}" -eq "${#required_files[@]}" ]]; then
  exit 0
fi

if [[ "${existing_count}" -ne 0 ]]; then
  echo "partial PKI state detected in ${CERT_DIR}" >&2
  exit 1
fi

mkdir -p "$CERT_DIR"
cd "$CERT_DIR"

ca_config="$(mktemp)"
server_ext="$(mktemp)"
client_ext="$(mktemp)"
trap 'rm -f "${ca_config}" "${server_ext}" "${client_ext}" server.csr client.csr' EXIT

cat > "${ca_config}" <<'EOF'
[req]
distinguished_name = req

[ca_ext]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
EOF

cat > "${server_ext}" <<'EOF'
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = critical,serverAuth
subjectAltName = IP:127.0.0.1
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
EOF

cat > "${client_ext}" <<'EOF'
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = critical,clientAuth
subjectAltName = DNS:ransomeye
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
EOF

echo "[INFO] Generating RSA PKI (PostgreSQL TLS)"

# =========================
# CA
# =========================
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out ca.key

openssl req -x509 -new \
  -key ca.key \
  -sha256 \
  -out ca.crt \
  -days 3650 \
  -subj "/CN=RansomEye-CA" \
  -config "${ca_config}" \
  -extensions ca_ext

# =========================
# SERVER
# =========================
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out server.key

openssl req -new \
  -key server.key \
  -out server.csr \
  -subj "/CN=127.0.0.1"

openssl x509 -req \
  -in server.csr \
  -CA ca.crt \
  -CAkey ca.key \
  -CAcreateserial \
  -out server.crt \
  -days 3650 \
  -sha256 \
  -extfile "${server_ext}"

# =========================
# CLIENT
# =========================
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out client.key

openssl req -new \
  -key client.key \
  -out client.csr \
  -subj "/CN=ransomeye"

openssl x509 -req \
  -in client.csr \
  -CA ca.crt \
  -CAkey ca.key \
  -CAserial ca.srl \
  -out client.crt \
  -days 3650 \
  -sha256 \
  -extfile "${client_ext}"

# =========================
# PERMISSIONS (STRICT)
# =========================
chown root:root ca.key ca.crt ca.srl
chmod 600 ca.key
chmod 644 ca.crt

chown "${SERVICE_USER}:${SERVICE_GROUP}" server.key server.crt
chmod 600 server.key
chmod 644 server.crt

chown root:root client.key client.crt
chmod 600 client.key
chmod 644 client.crt

echo "[SUCCESS] RSA PKI generated for PostgreSQL TLS"
