# Phase 1 Repo Rationalization — Mishka slice (current)

## Active slice (authoritative runtime)

- **Units:** `ransomeye-postgres.service`, `ransomeye-core.service`, `ransomeye-nginx.service` (templates under `deploy/systemd/`).
- **Go core:** `core/` (including `core/cmd/ransomeye-core`, the migration helper under `core/cmd/`, and migrations under `core/migrations/`).
- **Integrity:** `make generate-integrity` produces a signed `build/integrity.manifest` listing **`/opt/ransomeye/core/ransomeye-core`** only; `scripts/sign-integrity-manifest/` signs it; installer and core verify the same contract.
- **Install helpers:** `installer/`, `scripts/install.sh`, `scripts/authority_db_env.sh`, `scripts/run_authority_db_tests.sh`, `scripts/verify-reproducible-build.sh`, `scripts/compute-integrity-anchor.py`.
- **PRDs:** `prd_project_mishka/` (checksum gate: `make verify-prd`).
- **UI:** `ui/` (built assets consumed by nginx as per deploy docs).

## Explicitly out of scope (not shipped in this slice)

- HA, product RBAC, Windows agent, SNMP poller, strict physical air-gap lab enforcement.
- In-repo **Linux agent**, **eBPF**, **Python inference tree**, **DPI crate**, **netflow/syslog/snmp probe crates** — removed; Core may still accept historical `source_type` strings in ingest APIs.

## Removed / retired from repo (summary)

- Top-level **agent**, **probe**, **Python service**, and **DPI** source trees; the former **`ransomeye-ai-verify`** command; Windows-only installer helpers; and the old **`scripts/validation/`** harness that ran `cargo test` across removed crates.

## Manual follow-ups

- Older notes under `docs/prd_develop_doc/` may still read as historical until each file is refreshed; **`prd_project_mishka/*.md`** remain the product authority.
