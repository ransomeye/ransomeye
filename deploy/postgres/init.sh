#!/usr/bin/env bash
# DEPRECATED — PostgreSQL PGDATA initialization and service lifecycle are owned exclusively by the
# RansomEye installer (`installer/src/postgres_setup.rs`: `initialize_postgres_data_dir`,
# `install_postgres_config_files`, `ransomeye-postgres.service`). Do not run manual `initdb`.
set -euo pipefail
echo "This script is deprecated. Use the RansomEye installer to bootstrap PostgreSQL (deterministic initdb + config + systemd)." >&2
exit 1
