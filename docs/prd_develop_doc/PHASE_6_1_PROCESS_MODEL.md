# Phase 6.1 — Process model (Mishka Phase-1)

## Trust model

| Layer | Role |
|--------|------|
| **Core (`ransomeye-core`)** | Loads signed **`/etc/ransomeye/integrity.manifest`** + **`integrity.sig`**, verifies the **`/opt/ransomeye/core/ransomeye-core`** hash on a timer, and (when `RANSOMEYE_AI_ADDR` is set) runs the same vendor checks as `core/internal/ai` before dialing the AI gRPC peer. **No** interpreter `exec` from Core. |
| **systemd** | Supervises **`ransomeye-core.service`**, PostgreSQL, and Nginx only in the default repo slice. |

## Components

- `core/internal/ai/launcher.go` — `VerifyBeforeStart`, `VerifyVendorIntegrity`, `DefaultAIInstallRoot`, `RANSOMEYE_AI_ROOT` when set.
- `core/cmd/ransomeye-core/main.go` — integrity gate then `ai.Dial` when configured.

## Build / integrity

- `make build-core` produces `build/ransomeye-core` (and the migration helper under `build/`, not listed in the manifest).
- `make generate-integrity` produces signed **`build/integrity.manifest`** + **`build/integrity.sig`**; `make install` deploys manifest + sig to `/etc/ransomeye/` and **`ransomeye-core`** to `/opt/ransomeye/core/`.

## Verification gates

1. **Tamper core** — manifest hash mismatch → Core start **fail-closed**.
2. **No Core process control** — Core does not supervise Python or edge collectors in this slice.

Phase 6.0 (Core-spawned interpreter) is **superseded** by this document.
