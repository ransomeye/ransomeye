# Mishka Slice 2 — Storage (PRD-13), WORM (PRD-14), replay (PRD-15), build integrity (PRD-19), observability (PRD-18), air-gap capability

## Implemented (this repo)

| Topic | Where | Notes |
|-------|--------|--------|
| PRD-13 authority commit | `core/internal/storage/authority/*` | Single transactional kernel; `replay_guard`, `batch_commit_records`, bindings |
| PRD-14 WORM triggers + runtime integrity | `core/cmd/ransomeye-core/main.go`, `core/internal/integrity/*`, `validateWORMTriggers` | Fail-closed migration presence; signed manifest gate unless `RANSOMEYE_LAB_SKIP_RUNTIME_INTEGRITY` |
| PRD-15 replay + determinism | `core/internal/replay/*`, `core/cmd/dbctl` | `VerifyStoredReplay`, dbctl multi-run; DB tests require `POSTGRES_DSN` + signed `common.yaml` fingerprint |
| PRD-19 build / manifest | `Makefile`, `scripts/verify-reproducible-build.sh`, `scripts/reproducible-build-env.sh` | `generate-integrity`, out-of-tree `CARGO_TARGET_DIR` for signing |
| PRD-18 health | `core/internal/soc/server.go`, `handlers_db.go`, `handlers_api.go` | `/api/v1/health`, `/system/health`, `/system/ingestion-status`, `/shadow/intelligence/status` |
| Air-gap **capability** | `core/internal/compliance/registry.go` (`AssertNoOutboundConnectivity`), `applyAirGapStartupGates` in `core/cmd/ransomeye-core/main.go` | Resolv.conf + `/proc/net/route` inspection only — **no live dials** |

## Air-gap posture (runtime API)

Startup records posture for SOC JSON (never claims physical isolation on this laptop):

| `air_gap_posture` | Meaning |
|-------------------|---------|
| `disabled` | `RANSOMEYE_AIR_GAP_MODE=off` — enforcement not requested. |
| `validated` | Resolv + default-route checks **passed** at startup (or `preflight` mode pass). |
| `configured_not_validated` | Checks **failed** but process continued (**DEV MODE**), or `preflight` failure. |
| `bypassed_for_lab` | `RANSOMEYE_DISABLE_AIR_GAP_CHECKS=true`. |

Environment:

- `RANSOMEYE_AIR_GAP_MODE` — unset or `enforced` (default): same fail-closed gate as before (fatal if check fails outside DEV).
- `preflight` / `preflight_only`: run checks, record posture, **never fatal**.
- `off`: skip checks; posture `disabled`.

When posture is `bypassed_for_lab` or `configured_not_validated`, **health / ingestion / shadow** top-level `status` is **`degraded`** even if the pipeline is up (PRD-18 truthfulness).

## Verification commands

```bash
make verify-prd
make authority-db-test
export POSTGRES_DSN='postgres://…'   # same verify-full DSN as authority-db-test
export PGSSLROOTCERT=… PGSSLCERT=… PGSSLKEY=… PGSSLMODE=verify-full PGSSLSERVERNAME=127.0.0.1
make replay-db-test
./scripts/airgap-preflight.sh   # read-only; exits 1 if default route row present (informational)
go build -o /tmp/ransomeye-core ./core/cmd/ransomeye-core
```

**Not executed in Slice 2 (by instruction):** physical air-gap validation, default-route removal, outbound internet cut.

## Physical offline validation (future)

On an isolated staging host: set `RANSOMEYE_AIR_GAP_MODE=enforced`, remove default route per site policy, re-run core; confirm `air_gap_posture=validated` and `status=ok` (with full integrity bootstrap).
