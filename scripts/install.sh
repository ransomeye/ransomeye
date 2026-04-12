#!/usr/bin/env bash
# Mishka Phase-1: installs systemd templates for postgres + core + nginx only
# (see deploy/systemd/) into /etc/systemd/system/ or RANSOMEYE_INSTALL_ROOT.
set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

INSTALL_ROOT="${RANSOMEYE_INSTALL_ROOT:-}"

if [[ -n "${RANSOMEYE_INSTALL_DPI_PROBE:-}" && "${RANSOMEYE_INSTALL_DPI_PROBE}" != "0" ]]; then
  echo "[FATAL] DPI probe install was removed with the dpi-probe tree; Mishka Phase-1 is postgres + core + nginx only." >&2
  exit 2
fi

prefix_path() {
  if [[ -n "${INSTALL_ROOT}" ]]; then
    echo "${INSTALL_ROOT}$1"
  else
    echo "$1"
  fi
}

if [[ -z "${INSTALL_ROOT}" && "${EUID}" -ne 0 ]]; then
  echo "[FATAL] install.sh must run as root (set RANSOMEYE_INSTALL_ROOT to install into a non-root prefix)" >&2
  exit 1
fi

SYSTEMD_DST_DIR="$(prefix_path /etc/systemd/system)"
DEPLOY_SYSTEMD="${REPO_ROOT}/deploy/systemd"

for u in ransomeye-postgres.service ransomeye-core.service ransomeye-nginx.service ransomeye.target; do
  src="${DEPLOY_SYSTEMD}/${u}"
  if [[ ! -f "${src}" ]]; then
    echo "[FATAL] missing Mishka systemd template: ${src}" >&2
    exit 9
  fi
done
install -d -m 0755 "${SYSTEMD_DST_DIR}"
for u in ransomeye-postgres.service ransomeye-core.service ransomeye-nginx.service ransomeye.target; do
  install -m 0644 "${DEPLOY_SYSTEMD}/${u}" "${SYSTEMD_DST_DIR}/${u}"
done

if [[ -z "${INSTALL_ROOT}" && "${SKIP_SYSTEMD:-0}" != "1" ]]; then
  systemctl daemon-reload
  systemctl enable ransomeye.target
else
  echo "[INFO] systemd daemon-reload/enable skipped (RANSOMEYE_INSTALL_ROOT set or SKIP_SYSTEMD=1)" >&2
fi

echo "[OK] Mishka Phase-1 systemd templates installed under ${SYSTEMD_DST_DIR}"
