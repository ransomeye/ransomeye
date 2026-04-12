# Mishka — final in-scope acceptance (matrix + verification log)

**Excluded by explicit user scope:** HA, RBAC, Windows agent, SNMP poller, physical air-gap testing.

## PRD-by-PRD matrix (single classification each)

| PRD | Topic | Classification |
|-----|--------|----------------|
| PRD-01 | System laws / trust boundaries | **partial** — implemented in code + docs; not a single formal proof run this session |
| PRD-02 | Crypto trust root | **complete but source-audited only** (live mTLS paths exercised historically; not re-proven every cert rotation here) |
| PRD-03 | Identity / signing | **complete and verified** (gateway + `mishka-signal-send` path; netcfg allowlist for CLI) |
| PRD-04 | Trust / authority identity | **partial** — authority snapshots + execution context in SIGNAL path; full lifecycle not exhaustively tested live |
| PRD-05 | Edge / transport | **partial** — linux agent path in tree; live agent fleet not in-scope proof |
| PRD-06 | Gateway / replay guard | **complete and verified** (`go test ./core/internal/gateway/...` this session) |
| PRD-07 | Canonical payload | **complete and verified** (prior slice + gateway tests) |
| PRD-08 | Verify-before-admit | **complete but source-audited only** (gateway; live flood not run) |
| PRD-09 | Decision orchestration | **partial** — deterministic in-process path wired; full PRD-09 orchestration scope not fully modeled |
| PRD-10 | SINE / deterministic inference | **partial** — optional SINE; deterministic detector authoritative without SINE |
| PRD-11 | Policy | **complete and verified** (policy tests + runtime gate; slice 3) |
| PRD-12 | Enforcement | **partial** — dispatcher + gates; live agent kill path not exercised end-to-end |
| PRD-13 | Authoritative storage | **partial** — SIGNAL commit + DB; `query_record`/`report_record` contracts not implemented |
| PRD-14 | WORM / forensic | **complete but source-audited only** (sealing in pipeline; not full forensic audit) |
| PRD-15 | Replay / determinism | **partial** — `make replay-db-test` **not run** (no `POSTGRES_DSN` this session); unit tests partial |
| PRD-16 | API / service comms | **complete and verified** (live curls + nginx→core) |
| PRD-17 | Install / deploy | **partial** — host aligned; live nginx differs from `deploy/nginx/ransomeye.conf` (headers/http2) |
| PRD-18 | Health / observability | **complete and verified** (live health + ingestion + SOC fields) |
| PRD-19 | Build / integrity | **complete and verified** (`make build-core`; manifest hash **matched** installed ELF this session) |
| PRD-20 | Safety / execution governance | **partial** — policy + simulation scope honest; isolation HIL not live-tested |
| PRD-21 | SOC UI governance | **complete and verified** (manifest API + UI banner + routes live) |
| PRD-22 | Shadow non-authority | **complete and verified** (API flags + dedicated UI + live 200) |
| PRD-23 | Asset intelligence | **complete and verified** (coverage API + UI + `ui_lineage`; SQL projection basis) |
| PRD-24 | Anti-drift / consistency | **partial** — integrity + PRD verify; full drift automation not claimed |
| PRD-25 | Dashboards / reporting | **partial** — operator + executive surfaces live; **no** committed `query_record`/`report_record` lineage |

## Commands run (this acceptance slice)

See chat log; minimum:

- `make verify-prd` — OK  
- `make build-core` — OK (after netcfg allowlist for `mishka-signal-send`)  
- `go test ./core/internal/netcfg/... ./core/internal/policy/... ./core/internal/soc/... ./core/internal/gateway/...` — OK  
- `go test ./core/internal/pipeline/ -run 'TestHandleOne|TestSeal|TestBounded'` — OK  
- `cd ui && npm run build` — OK  
- `make authority-db-test` — **FAIL** (PostgreSQL password auth for default probe user)  
- `make replay-db-test` — **not run** (exits 2: `POSTGRES_DSN` unset)  
- Live: `ss`, `systemctl list-units 'ransomeye*'`, `systemctl --failed`, curls to listed paths — OK  
- Integrity: `sha256` in `/etc/ransomeye/integrity.manifest` vs `sudo sha256sum /opt/ransomeye/core/ransomeye-core` — **MATCH**

## Final acceptance decision

**B. In-scope Mishka not complete** — at least one in-scope PRD remains **partial** or live verification **blocked** for this run (authority/replay DB lanes without DSN; PRD-13/25 lineage objects absent).

Exact remaining blockers:

1. **`make authority-db-test`** did not pass in this environment (DB auth probe failed; need live `POSTGRES_DSN` / `MISHKA_TEST_*` matching installed Postgres).  
2. **`make replay-db-test`** was not executed (`POSTGRES_DSN` required).  
3. **PRD-13 / PRD-25:** No committed `query_record_v1` / `query_result_record_v1` / `report_record_v1` implementation — dashboards remain presentation-only aggregates.  
4. **PRD-12 / PRD-05:** No live proof of enforcement delivery to a connected agent or full edge fleet in this slice.
