# RansomEye PRD Audit Report (enforced)

Date: 2026-04-01
Scope: All PRDs in `/home/gagan/ransomeye-source/prd/newprd/`.

## 1. Summary
- PRD set reviewed: 22 documents (PRD-01 through PRD-22).
- Key compliance scope: infrastructure, security, identity, database, engine, API, agents, probes, forensics WORM, no-loss pipeline, installer, update, resource fail-safe, testing, UI/UX, key lifecycle.
- Implementation artifacts reviewed: migrations SQL, core schema, trigger code, RLS, indexes.
- Outcome: P0/P1 violations found across multiple PRDs; full remediation required before enterprise assurance.

## 2. Validation methodology
1. Enumerate PRD documents.
2. Map each PRD to relevant folder(s) in source code (`migrations/`, `core/`, `deploy/`, `ui/`, `probes/`, etc.).
3. Extract normative requirements from each PRD.
4. Confirm presence/absence in implementation via direct code inspection (`grep`, `read_file`) and schema analysis.
5. Classify each finding as:
   - `Compliant`
   - `Partial` (exists but incomplete)
   - `Missing` (absent)
   - `Violation` (wrong semantics)
6. Produce detailed report sections for each PRD.

## 3. Global critical violations (ruthless list)
- `event_drop_count` exists in `agent_heartbeats` (PRD-09 forbids).
- `numeric/real` types used for probabilities/metrics (PRD-09  strict integer scaling rule) in `detections`, `agent_heartbeats`.
- `system_identity_hash` missing on key tables (PRD-09.1, PRD-10). Missing in `agent_sessions`, `detections`, `telemetry_events`, etc.
- RLS policies do not enforce `system_identity_hash` predicate (PRD-10 requirement).
- WORM tables missing `signing_context` and bytea signature columns in migrations (PRD-05 and PRD-15).
- Schema migration manifest `migration_manifest.json` is absent; signature+hash precheck requirement unimplemented (PRD-04/PRD-05).
- `schema_migrations` is wrong structure (TEXT/bytea mismatch) relative to PRD-05 §9.6.
- Replay uniqueness rule missing `message_id` + `content_sha256` in telemetry/detections/incidents (PRD-05 §9.4).
- `worm_immutable` trigger function not uniform; existing function names are non-standard (PRD-05 §9.3.1).

## 4. Per-PRD detailed status
### PRD-01_System_Architecture
- Compliant: service/component architecture and trust goals documented.
- Partial: network exposure rules are still soft (need exact port/CIDR and policy enforcement matrix).\
- Missing: migration from architecture to signed deployment artifact checklist.

### PRD-02_Trust_Cryptographic_Root
- Compliant: Ed25519 and SHA-256 policy direction present.
- Partial: exact certificate and key rotation model not emission-level normative.
- Missing: a deterministic canonical JSON canonicalization algorithm nexus; currently described, not artifact-locked.

### PRD-03_Bootstrap_Sequence
- Compliant: initialization sequence and role separation (Core vs installer) clear.
- Violation: installers create roles (yes) but Core DDL appears to require limited role usage; no explicit enforcement in code path I saw (manual check needed in installer code, not schema). 

### PRD-04_Identity_Model
- Compliant: tenant/agent/probe identity definitions exist.
- Partial: `agent_sessions` table uses `INET` type for IP instead of TEXT canonical string; breaks PRD-05 requirement.
- Violation: dual TLS session hashing option still permitted in text, not hard fail-closed.

### PRD-05_Database_Schema (most detailed audit)
- Extensive violations as above, see section 5 below.

### PRD-06_Core_Engine
- Compliant at a high level; ingestion + durability pipeline described.
- Partial: schema wiring of core pipeline to concurrency controls unclear (need specific counters to be atomic + dedup path). 

### PRD-07_Deterministic_AI
- Partial: detection table uses JSONB in signals and bayesian_intermediate; PRD-07 insists deterministic replay via canonical text + signed checks, missing.

### PRD-08_SINE_Engine
- Not fully mapped: `sine-engine/` crate exists but no evidence of PRD alignment checks in this scan.
- TODO: Add deeper code audit for SINE schema and Pub/Sub contract.

### PRD-09_Policy_Enforcement
- Partial: policy invariants are present in DB constraints but not reified for all fields (e.g., policy update audit trail, global denylist). 

### PRD-10_API_Protocol
- Partial: core gRPC endpoint and API names are present, but method-level schema not exported as machine-readable contract.
- Missing: full request/response error codes and exact RLS result semantics.

### PRD-11_Linux_Agent / PRD-12_Windows_Agent / PRD-13_Network_Probes
- Partial: agent table directions exist; real implementation stability not validated in this pass.
- Missing deep protocol status in `probes/`, for eventual WORM/zero-loss telemetry table format.

### PRD-14_Deception_System, PRD-15_Forensics_WORM, PRD-16_Data_Pipeline_ZeroLoss
- Violation: WORM constraints + unified mutability enforcement are only partially implemented in migration scripts; canonical TEXT + digest parity missing.
- Missing: explicit `merkle_leaf_hash` generation/validation code in DB or app layer.

### PRD-17_Installer_Deployment
- Partial: installer code exists, but this audit target only covers DB and schema, not installer binding to policy.

### PRD-18_Airgap_Update_System, PRD-19_Resource_Failsafe, PRD-20_Testing_Validation
- Partial: hardening policies in docs; not linked to direct monitoring or failover test artifacts currently.

### PRD-21_SOC_UI_Security, PRD-22_Key_Lifecycle
- Partial: UI security and key lifecycle policy foundation exists; direct code review needed in UI/backend link state.

## 5. Deep PRD-05 vs implementation mapping (ruthless defects manual)
### State of canonical tables (PRD-05 §9.2/9.2.1)
- `telemetry_events` in code has: `payload JSONB` (non-canonical) replaced later with `payload_bytes BYTEA` + `payload_sha256` generated, but no canonical pure TEXT column and no explicit content signature/digest checks.
- `detections`: uses `JSONB` columns (`signals`, `bayesian_intermediate`) rather than canonical text and fails PRD-05 for WORM signatures.
- `worm_evidence`, `exposure_worm_ledger`, `governance_audit_log`, `bundle_application_log`, `merkle_daily_roots`: none have canonical text columns or required `signing_context` / `ed25519_signature` field definitions.

### WORM immutability trigger (PRD-05 §9.3.1) 
- Existing trigger function names differ; PRD requires single uniform function `worm_immutable_block()`.

### Replay uniqueness (PRD-05 §9.4)
- `telemetry_events`, `detections`, `incidents` lack composite `UNIQUE(tenant_id, agent_id, boot_session_id, message_id, content_sha256)` as required.

### Identity binding (PRD-05 §9.1)
- `agent_sessions` has no `system_identity_hash`; `tenants` has no `system_identity_hash`; related tables miss these required fields.

### Indexes (PRD-05 §12)
- Failed prerequisites: required `INDEX(message_id)` and required `agent_id` indexes are partly present but not full coverage for all tables.

### Migration dove-tail checks (PRD-05 §4/§9.6)
- Missing `migration_manifest.json` and Ed25519 manifest validation routine. `schema_migrations` uses `INTEGER + TEXT` rather than `TEXT + BYTEA`.

### Forbidden columns/types (PRD-05 §13)
- `event_drop_count` present in `agent_heartbeats` (forbidden). 
- `NUMERIC` field usage found in `agent_heartbeats`, `detections` (forbidden). 
- `JSONB = NOT GENERATED` across forensic payloads (forbidden). 

## 6. Suggested path to “ruthless compliance complete”
1. Align `migrations/001_core_schema.sql`+`02` + etc. to the exact PRD-05 schema and add missing fields.
2. Create a migration manifest file with Ed25519-signed hash list (PRD-05 §4); implement preflight file check in installer/core.
3. Adjust RLS policies in `migrations/007_row_level_security.sql` to include both predicates and `fail-closed` behavior.
4. Replace numeric/real columns with PRD-05 scaled integer strategy; remove `event_drop_count` and non-canonical fields.
5. Enforce WORM trigger function: single `worm_immutable_block()` function + all required table trigger creation.
6. Add PRD-09/PRD-10 policy link to tests in `tests/` for all cross-PRD invariants (WORM, replay, RLS, no drop events).
7. Add explicit table-level check constraints for digest parity and canonical non-empty text.
8. Implement agent/probe identity separation, add missing `system_identity_hash` to all tables.

## 7. File created
- `/home/gagan/ransomeye-source/docs/validation/prd_audit_report.md` ✅

## 8. Next step (if you want me to continue)
- Apply migration patch templates to satisfy PRD-05 in code with minimal risk.  
- Generate unit test matrix for each PRD vs implementation (including compilation guard for missing fields).  

