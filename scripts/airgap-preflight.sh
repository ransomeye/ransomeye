#!/usr/bin/env bash
# Non-destructive air-gap posture preflight (PRD-19 capability path).
# Does NOT modify routing, resolv.conf, or network. Safe on internet-connected hosts.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RESOLV="${RANSOMEYE_RESOLV_CONF_PATH:-/etc/resolv.conf}"
ROUTE="${RANSOMEYE_ROUTE_TABLE_PATH:-/proc/net/route}"

echo "[airgap-preflight] repo=${ROOT}"
echo "[airgap-preflight] RANSOMEYE_AIR_GAP_MODE=${RANSOMEYE_AIR_GAP_MODE:-<unset>}"
echo "[airgap-preflight] RANSOMEYE_DISABLE_AIR_GAP_CHECKS=${RANSOMEYE_DISABLE_AIR_GAP_CHECKS:-<unset>}"
echo "[airgap-preflight] reading ${RESOLV} (nameserver lines only)"
awk '/^nameserver/ {print}' "${RESOLV}" 2>/dev/null || echo "(unreadable)"
echo "[airgap-preflight] scanning ${ROUTE} for default route (00000000 dest)"
if awk 'NR>1 && $2=="00000000" {found=1} END{exit !found}' "${ROUTE}" 2>/dev/null; then
  echo "[airgap-preflight] RESULT: default_route_present (production air-gap would reject)"
  exit 1
fi
echo "[airgap-preflight] RESULT: no_default_route_row_detected (informational only)"
echo "[airgap-preflight] done (no network dials performed; full evaluation runs in ransomeye-core startup)"
