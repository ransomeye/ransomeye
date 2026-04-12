# Mishka Phase 1 — acceptance (lab host)

This document is an **operator-facing acceptance snapshot** for the Phase 1 “three-service” slice. It is descriptive, not a product warranty.

## In scope (this phase)

- **Runtime units (intended default slice):** `ransomeye-postgres.service`, `ransomeye-core.service`, `ransomeye-nginx.service`.
- **Core:** PostgreSQL-backed ingest, gateway/SOC HTTP surfaces used for health and validation, storage authority paths exercised by DB tests.
- **Honest lab posture:** non-core planes (AI, SINE, DPI) are **off unless explicitly configured**; HTTP APIs label unconfigured planes as `unconfigured` / `not_applicable` where relevant so they are not mistaken for healthy production telemetry.

## Explicitly excluded / not claimed

- **Strict physical air-gap enforcement** on the host (out of scope for this lab posture).
- **HA** topology, **RBAC** productization, **Windows agent**, **SNMP poller**.
- Retired or non-core planes as **defaults:** Redis, AI sidecar, SINE, DPI — **not** shipped as systemd templates in this repo slice; Core treats them as unconfigured unless you add your own units and env.

## Repo vs live systemd paths

- **Repo:** `deploy/systemd/ransomeye-*.service` and `ransomeye.target` are **templates** aligned with the Phase 1 three-service shape.
- **Installer alignment:** `scripts/install.sh` installs those same `deploy/systemd/` templates (and enables `ransomeye.target` when not skipped).
- **Host:** units are commonly installed under `/etc/systemd/system/` (and may use drop-ins). **Do not assume** byte-identical parity with the repo without diffing; behaviorally, the **enabled unit set** should match the Phase 1 slice above.

## Proof commands (run on the lab host)

Adjust paths only if your install layout differs.

### Core binary (build + install + integrity)

```bash
cd /home/gagan/ransomeye-source/core
go build -trimpath -ldflags="-s -w" -o /opt/ransomeye/core/ransomeye-core ./cmd/ransomeye-core
install -m 0755 /opt/ransomeye/core/ransomeye-core /home/gagan/ransomeye-source/bin/ransomeye-core
sha256sum /opt/ransomeye/core/ransomeye-core /home/gagan/ransomeye-source/bin/ransomeye-core
sudo sha256sum /opt/ransomeye/core/ransomeye-core
sudo grep ransomeye-core /etc/ransomeye/integrity.manifest
```

**Note:** `make build-core` uses different default link flags than `go build … -ldflags="-s -w"`, so the SHA256 of the binary will not match between those two recipes. The signed `integrity.manifest` under `build/` is generated from **`make generate-manifest`** (after `make build-core`) and covers **`ransomeye-core`** only. After rebuilding core, reinstall `/opt/ransomeye/core/ransomeye-core` from `build/`, refresh `integrity.manifest` + `integrity.sig` in `/etc/ransomeye/` using the signing key (and advance **`version.chain`** if you bump `INTEGRITY_MANIFEST_VERSION`), then restart the unit.

### SOC unit tests (no DB required)

```bash
cd /home/gagan/ransomeye-source
env -u POSTGRES_DSN PATH="/usr/local/go/bin:$PATH" go test ./core/internal/soc/... -count=1
```

### Replay DB tests (sudo + DSN + TLS client to Postgres)

```bash
cd /home/gagan/ransomeye-source
sudo env POSTGRES_DSN='postgres://ransomeye:ransomeye%4012345@127.0.0.1:5432/ransomeye?sslmode=verify-full' \
  PGSSLROOTCERT=/opt/ransomeye/core/certs/ca-chain.crt \
  PGSSLCERT=/opt/ransomeye/core/certs/client.crt \
  PGSSLKEY=/opt/ransomeye/core/certs/client.key \
  PGSSLMODE=verify-full \
  PGSSLSERVERNAME=127.0.0.1 \
  PATH="/usr/local/go/bin:$PATH" \
  go test ./core/internal/replay -count=1 -v -timeout 180s
```

### Authority DB lane

```bash
cd /home/gagan/ransomeye-source
sudo env POSTGRES_DSN='postgres://ransomeye:ransomeye%4012345@127.0.0.1:5432/ransomeye?sslmode=verify-full' \
  PGSSLROOTCERT=/opt/ransomeye/core/certs/ca-chain.crt \
  PGSSLCERT=/opt/ransomeye/core/certs/client.crt \
  PGSSLKEY=/opt/ransomeye/core/certs/client.key \
  PGSSLMODE=verify-full \
  PGSSLSERVERNAME=127.0.0.1 \
  PATH="/usr/local/go/bin:$PATH" \
  make authority-db-test
```

### PRD manifest checksum gate

```bash
cd /home/gagan/ransomeye-source
make verify-prd
```

### UI build (static assets)

```bash
cd /home/gagan/ransomeye-source/ui
npm ci
npm run build
```

### Live stack checks

```bash
sudo systemctl restart ransomeye-core.service
systemctl is-active ransomeye-postgres.service ransomeye-core.service ransomeye-nginx.service
systemctl --failed --no-pager
curl -skS https://127.0.0.1/api/v1/health
curl -skS https://127.0.0.1/api/v1/system/health
curl -skS https://127.0.0.1/api/v1/system/ingestion-status
curl -skS https://127.0.0.1/api/v1/shadow/intelligence/status
curl -skS https://127.0.0.1/api/v1/assets/coverage
```

On a host with non-core planes off, **`/api/v1/system/ingestion-status`** should show those planes as `unconfigured` / `not_applicable` (e.g. `sine_state`, `dpi_metrics_scope`) rather than implying they are healthy.

## Lab-only flags (honest posture)

Examples commonly used in lab (names and values depend on your `core.env`):

- `RANSOMEYE_DISABLE_AIR_GAP_CHECKS=true` — **disables strict air-gap checks**; appropriate only where strict isolation is out of scope.
- Absent `RANSOMEYE_AI_ADDR`, `RANSOMEYE_SINE_ADDR`, and incomplete DPI identity env — **non-core planes treated as unconfigured**.

## “Complete enough to use” on this host (working definition)

- The **three** units above are **active**, `systemctl --failed` is clean for this slice, and **core** answers **degraded/ok** consistently with DB + pipeline + compliance bootstrap on `/api/v1/health` and `/api/v1/system/health`.
- **`make verify-prd`** and **`make authority-db-test`** pass with the same **sudo + `POSTGRES_DSN` + `PGSSL*`** discipline as in this doc.
- **Replay** package DB tests pass under that same discipline.
- **Integrity:** the installed `ransomeye-core` binary hash appears in `/etc/ransomeye/integrity.manifest` as expected by your install policy. If you bump `INTEGRITY_MANIFEST_VERSION` in the Makefile, `/var/lib/ransomeye/state/version` and append-only **`/var/lib/ransomeye/state/version.chain`** must advance in lockstep (see `core/internal/integrity/version_chain.go`); otherwise Core fails closed with `version file vs chain mismatch`. Prefer the installer’s anchor/manifest orchestration on production hosts, or append the next `version:N sha256:…` line deterministically after the prior chain tip.

Anything outside this list is **not claimed** for Phase 1 acceptance on this host.
