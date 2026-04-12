#!/usr/bin/env bash
set -euo pipefail

IS_ROOT=0
if [ "$(id -u)" -eq 0 ]; then
  IS_ROOT=1
fi

echo "[VALIDATION] Starting RansomEye system validation"
if [ "$IS_ROOT" -eq 1 ]; then
  echo "[MODE] SYSTEM (root)"
else
  echo "[MODE] OPERATOR (non-root)"
fi

# 1. Check binary
echo "[CHECK] Core binary"
CORE_BIN="/opt/ransomeye/bin/ransomeye-core"

if [ ! -f "$CORE_BIN" ]; then
  # DEV FALLBACK (non-production)
  if [ -f "./ransomeye-core" ]; then
    CORE_BIN="./ransomeye-core"
  else
    echo "[FAIL] core binary missing in both /opt and local path"
    exit 1
  fi
fi

if [ ! -x "$CORE_BIN" ]; then
  echo "[FAIL] core binary not executable: $CORE_BIN"
  exit 1
fi

echo "[CHECK] using binary: $CORE_BIN"

# 2. Check TLS certs
echo "[CHECK] TLS certificates"
if [ "$IS_ROOT" -eq 1 ]; then
  for f in /etc/ransomeye/certs/ca.crt /etc/ransomeye/certs/server.crt /etc/ransomeye/certs/server.key; do
    if [ ! -f "$f" ]; then
      echo "[FAIL] missing TLS file: $f"
      exit 1
    fi
  done
else
  echo "[WARN] skipping TLS file validation (non-root)"
fi

# 3. Check WORM key
echo "[CHECK] WORM signing key"
if [ "$IS_ROOT" -eq 1 ]; then
  if [ ! -f "/etc/ransomeye/worm_signing.key" ]; then
    echo "[FAIL] missing WORM key"
    exit 1
  fi
else
  echo "[WARN] skipping WORM key validation (non-root)"
fi

# 4. Check DB connectivity (loopback only)
echo "[CHECK] PostgreSQL connectivity"
pg_isready -h 127.0.0.1 -p 5432 > /dev/null || {
  echo "[FAIL] postgres not reachable"
  exit 1
}

# 5. Check telemetry presence
echo "[CHECK] telemetry events"
PSQL_CMD="psql \"sslmode=verify-full sslcert=/etc/ransomeye/certs/client.crt sslkey=/etc/ransomeye/certs/client.key sslrootcert=/etc/ransomeye/certs/ca.crt host=127.0.0.1 port=5432 user=ransomeye_admin dbname=ransomeye_core\" -t -c"

COUNT=$(eval $PSQL_CMD "\"SELECT COUNT(*) FROM telemetry_events;\"")
COUNT="$(echo "$COUNT" | tr -d '[:space:]')"
if [ "$COUNT" -eq 0 ]; then
  echo "[FAIL] no telemetry data"
  exit 1
fi

# 6. Check freshness
echo "[CHECK] telemetry freshness"
STALE=$(eval $PSQL_CMD "\"SELECT EXTRACT(EPOCH FROM (NOW() - MAX(created_at))) > 60 FROM telemetry_events;\"")
STALE="$(echo "$STALE" | tr -d '[:space:]')"
if [[ "$STALE" == "t" ]]; then
  echo "[FAIL] telemetry stale"
  exit 1
fi

echo "[SUCCESS] RansomEye system validation passed"
