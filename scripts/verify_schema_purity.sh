#!/usr/bin/env bash
# Gate 1 (PRD-13): superseded proto name must not appear in first-party sources.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
SCAN_PATHS=(prd proto core migrations docs ui/src)
if command -v rg >/dev/null 2>&1; then
  if rg -n 'TelemetryEvent' "${SCAN_PATHS[@]}" \
      --glob '!**/node_modules/**' \
      --glob '!**/target/**' \
      ; then
    echo "FAILED: TelemetryEvent found" >&2
    exit 1
  fi
else
  # Portable fallback: scan source trees only (avoid matching this script’s_literals).
  hits="$(
    grep -RIn --exclude-dir=node_modules --exclude-dir=target --exclude-dir=.git \
      'TelemetryEvent' \
      "${SCAN_PATHS[@]}" 2>/dev/null || true
  )"
  if [[ -n "${hits}" ]]; then
    echo "${hits}" >&2
    echo "FAILED: TelemetryEvent found" >&2
    exit 1
  fi
fi
echo "OK: no TelemetryEvent in first-party tree (node_modules/target excluded)"
