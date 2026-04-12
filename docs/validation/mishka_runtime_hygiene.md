# Mishka runtime hygiene (host acceptance rule)

## Policy

- **Allowed systemd units on host:** `ransomeye-postgres.service`, `ransomeye-core.service`, `ransomeye-nginx.service` only.
- **Do not** rebind Mishka to alternate ports to avoid conflicts. Fix conflicts by **removing legacy listeners/units**, not by moving Mishka.
- Any **extra** `ransomeye*` units, or listeners on Mishka URLs (`/api/`, `/ws`, `/stream`, static SOC) that are **not** served by the nginx → core → postgres stack above, are **legacy or unknown** until proven otherwise.
- **Stale UI at the correct URL** (e.g. old “RansomEye SOC” / Real-Time Stream while nginx still serves `/opt/ransomeye/ui/dist`) is **deployment drift** (outdated `dist/`), not a second port — remediate by **rebuilding and installing** the UI artifact, not by changing Mishka ports.

## Mandatory verification (every slice that touches runtime/deploy)

Run and keep evidence in slice notes:

```bash
ss -tlnp
sudo ss -tlnp   # preferred when permitted — shows process names on listeners
systemctl list-units 'ransomeye*' --all --no-pager
systemctl list-unit-files 'ransomeye*' --no-pager
```

Optional depth:

```bash
systemctl status ransomeye-nginx.service ransomeye-core.service ransomeye-postgres.service --no-pager
readlink -f /opt/ransomeye/core/ransomeye-core
ls -la /opt/ransomeye/ui/dist/index.html
```

### Classify each listener

| Port (example) | Process | Unit / owner | Mishka / legacy / unknown |
|----------------|---------|--------------|---------------------------|
| `0.0.0.0:443` | `nginx` | `ransomeye-nginx.service` | **Current Mishka** (TLS + static UI + proxy) |
| `127.0.0.1:8443` | `ransomeye-core` | `ransomeye-core.service` | **Current Mishka** (API/WS backend) |
| `127.0.0.1:5432` | `postgres` (ransomeye data dir) | `ransomeye-postgres.service` | **Current Mishka** |
| Same ports, **different** binary or extra duplicate listener | — | — | **Legacy or unknown** — stop and remove after proof |

### `https://localhost/.../stream` or old branding

1. Confirm only **one** TLS listener on **443** for SOC (expected: `ransomeye-nginx`).
2. If the page is old but nginx still serves `/opt/ransomeye/ui/dist`, classify as **legacy artifact (stale build)** — update `dist/` from repo `npm run build` + install/sync per your deploy procedure; **do not** open a second port for “new UI.”

## Snapshot — this laptop (2026-04-12, IST)

**`systemctl list-units 'ransomeye*' --all`**

- `ransomeye-postgres.service` — loaded active running  
- `ransomeye-core.service` — loaded active running  
- `ransomeye-nginx.service` — loaded active running  
- **No other** `ransomeye*` units listed.

**`ss -tlnp` (selected, with process names where shown)**

| Local address | Process | Classification |
|---------------|---------|----------------|
| `0.0.0.0:443` | `nginx` (master/worker) | **Current Mishka** (`ransomeye-nginx`) |
| `127.0.0.1:8443` | `ransomeye-core` | **Current Mishka** (`ransomeye-core`) |
| `127.0.0.1:5432` | `postgres` (RansomEye data dir under `/opt/ransomeye/core/postgres/data`) | **Current Mishka** (`ransomeye-postgres`) |
| `127.0.0.1:50051` | `ransomeye-core` | **Current Mishka** (in-process gRPC listener from core binary) |

**Deployed UI artifact**

- `/opt/ransomeye/ui/dist/index.html` present; timestamp **older than** recent Mishka UI slices in git → treat visible “legacy” SOC/stream pages as **stale static files** until `dist/` is refreshed from a current build.

**Deployed core binary**

- Replacing `/opt/ransomeye/core/ransomeye-core` alone can fail **runtime integrity** until `/etc/ransomeye/integrity.manifest` and `integrity.sig` match the new ELF (see `docs/validation/mishka_deployed_ui_alignment_verification.md`).

**Air-gap**

- Continue to **build** air-gap checks in software; **do not** require physical offline testing on this laptop.

## References

- Nginx vhost (repo): `deploy/nginx/ransomeye.conf` — `listen 443`, `root /opt/ransomeye/ui/dist`, `proxy_pass` to `127.0.0.1:8443` for `/api/` and `/ws`.
