# RansomEye / Project Mishka (prototype)

Authoritative design: `prd_project_mishka/` (read-only PRDs). Storage authority follows **MISHKA-PRD-13** (PostgreSQL `partition_records`, `batch_commit_records`, `replay_guard`, etc.); Kafka is transport-only.

## Core (Go) — build

```bash
make build-core
```

Artifacts land under `build/` (`ransomeye-core` plus the migration helper built from `core/cmd/`). Signed `build/integrity.manifest` lists **`/opt/ransomeye/core/ransomeye-core`** only (Mishka Phase-1 slice).

## Database migrations

Migrations live in `core/migrations/` (numbered `001_` … `046_`, plus non-numbered helpers). From the repo root:

```bash
make migrate-core
```

(`migrate-core` runs the helper produced under `build/` from `core/cmd/` — not installed under `/opt` in the default slice.)

Requires a compliant PostgreSQL instance and `POSTGRES_DSN` (see `configs/` and your TLS identity). Integration tests that hit the DB are skipped unless `POSTGRES_DSN` (and related env) are set.

**Slice-1 SQL verification (no Go TLS bootstrap):** on a PostgreSQL 16 instance with TimescaleDB preloaded and TLS/listen settings compatible with migration `040_final_sanity.sql`, you can apply the numbered files in order with `scripts/slice1_apply_migrations_psql.sh` (see script header for `PG*` variables). See `docs/migration_checksum_repair.md` if `schema_migrations` checksums drift after pulling migration edits.

Dev database:

```bash
make up-db
```

(`docker-compose.dev.yml` mounts dev TLS certs and sets `listen_addresses` / `ssl` for migration 040 assertions.)

## Mishka PRD manifest

```bash
make verify-prd
```

Checks `prd_project_mishka/prd.sha256` against all `*.md` in `prd_project_mishka/`.

## Environment

See `.env.example` for variables referenced by tooling and tests.

## Mishka 3-service runtime (local/systemd)

Target active units: `ransomeye-postgres.service`, `ransomeye-core.service`, `ransomeye-nginx.service`. Reference unit files live under `deploy/systemd/` for that slice only. `scripts/install.sh` copies those templates into `/etc/systemd/system/` (or under `RANSOMEYE_INSTALL_ROOT`) and enables `ransomeye.target` when systemd hooks are not skipped. Paths and `EnvironmentFile=` locations on a live host may differ from the repo templates. See `docs/validation/mishka_phase1_acceptance.md`.

- **DB auth:** set `POSTGRES_DSN` in `/etc/ransomeye/core.env` with `user`, `password`, and `dbname` in the DSN (keyword or URL). Core merges TLS file paths from `/opt/ransomeye/core/certs` (or `configs/db-certs` in dev). You may omit a separate `PGPASSWORD` when the password is already embedded in `POSTGRES_DSN`.
- **Retired planes:** unset `RANSOMEYE_AI_ADDR`, `RANSOMEYE_SINE_ADDR`, `RANSOMEYE_INTEL_ADDR`, and omit DPI env unless all three DPI identity variables are set. `configs/common.yaml` (dev fallback) may omit `ai.service_addr`.
- **Graceful stop:** core stops the gRPC gateway once via `systemctl stop`; unit `TimeoutStopSec` in `deploy/systemd/ransomeye-core.service` bounds stop duration.
