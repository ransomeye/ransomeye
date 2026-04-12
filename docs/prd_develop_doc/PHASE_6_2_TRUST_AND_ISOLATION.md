# Phase 6.2 — Trust chain + resource isolation

> **Phase 6.3 update:** Binary integrity is enforced by **signed `integrity.manifest`** + **`integrity.sig` (Ed25519)** — see [`PHASE_6_3_CRYPTO_TRUST.md`](PHASE_6_3_CRYPTO_TRUST.md).

## Paths (Mishka Phase-1)

Canonical Core binary: **`/opt/ransomeye/core/ransomeye-core`**.

systemd resource limits for **`ransomeye-core.service`**, PostgreSQL, and Nginx follow the units under `deploy/systemd/` and what the installer materializes on the host.
