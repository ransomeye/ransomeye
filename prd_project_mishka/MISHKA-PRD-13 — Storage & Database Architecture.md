# MISHKA-PRD-13 — Storage & Database Architecture

**Project:** Project Mishka  
**Classification:** AUTHORITATIVE — DETERMINISTIC STORAGE, DATABASE, AND REPLAY PERSISTENCE LAYER  
**Status:** CRITICAL — APPEND-ONLY, PARTITION-ALIGNED, CRYPTOGRAPHICALLY VERIFIABLE, WORM-COMPLIANT

---
```text id="r8k2sd"
THIS PRD INHERITS GLOBAL RESOURCE BOUND LAW FROM PRD-01.

ALL COLLECTIONS IN THIS PRD ARE REQUIRED TO BE:

- EXPLICITLY BOUNDED
- OVERFLOW → REJECT
```

```text id="u7z4rm"
ALL FAILURES IN THIS PRD MUST BE CLASSIFIED AS:

TYPE 1 / TYPE 2 / TYPE 3

AND MUST FOLLOW PROPAGATION RULES FROM PRD-01
```

# 1. PURPOSE

This document defines the authoritative storage and database architecture for Project Mishka.

It governs how the system MUST durably persist:

* `signal_record`
* `detection_record`
* `decision_record`
* `safety_evaluation_record`
* `action_record`
* `execution_result_record`
* `rollback_record`
* `query_record`
* `query_result_record`
* `report_record`
* `report_delivery_record`
* `ui_action_record`
* `group_record`
* `investigation_record`
* `risk_record`
* `simulation_record`
* replay-support authority snapshots
* append-only audit and commit-boundary metadata

The storage system defined here MUST:

* store all authoritative operational records required for replay
* align exactly with PRD-02 partition execution boundaries
* preserve deterministic replay completeness
* enforce strict append-only and WORM behavior
* expose cryptographically verifiable integrity for every committed record
* support large-scale distributed operation without global ordering requirements

```text
STORAGE IS AUTHORITATIVE ONLY AFTER DURABLE COMMIT.
MUTATION OF AUTHORITATIVE RECORDS IS FORBIDDEN.
MISSING AUTHORITATIVE RECORDS ARE A INTEGRITY_FAILURE.
```

---

# 2. CORE PRINCIPLES

The following principles are mandatory:

* storage MUST be append-only
* authoritative records MUST be immutable
* canonical record content MUST be deterministic
* writes MUST be partition-aligned
* no authoritative cross-partition write ordering is required
* all authoritative writes MUST be atomic and durable
* partial writes MUST NOT be visible
* reads MUST be deterministic and verification-aware
* cryptographic chaining MUST make tampering detectable
* replay completeness MUST be preserved
* retention MUST be deterministic
* indexes MUST be derived only
* storage MUST fail closed on integrity failure

Micro-hardening (PRD-01 alignment):

* canonical object field lock is mandatory (PRD-01 Section 3.1): unknown fields FORBIDDEN; optional fields MUST be omitted (no null/default)
* array determinism law is mandatory (PRD-01 Section 3.2): every array MUST have an explicit deterministic ordering rule; no implicit ordering
* hash function law is mandatory (PRD-01 Section 3.3): all authoritative hashes in this PRD MUST use `SHA256`

The following laws are mandatory:

* records MUST NEVER be updated
* records MUST NEVER be deleted outside deterministic retention execution
```text
canonical_payload_bytes IS MANDATORY

canonical_payload_text IS OPTIONAL
AND MUST BE DERIVED FROM canonical_payload_bytes
```

JSONB MAY exist only as derived projections or indexes
* wall clock MUST NOT define authoritative record order
* authoritative order MUST derive only from partition, epoch, shard, and append sequence metadata

---

# 3. STORAGE MODEL OVERVIEW

## 3.1 Authoritative Storage Ownership

The Storage & Replay Layer defined by PRD-02 owns:

* durable storage of signals
* durable storage of detections
* durable storage of policy decisions
* durable storage of actions
* durable storage of execution results
* durable storage of raw records and audit logs
* replay dataset construction
* tiered retention
* WORM retention for immutable tiers
* cryptographic verifiability of stored artifacts

Upstream components remain authoritative payload producers for their own outputs, but authoritative durable commit MUST occur only through the storage layer commit path.

## 3.2 Tier Model

The storage tier model is mandatory:

```text
HOT  -> WARM -> COLD
```

Tier semantics are:

* HOT: recent operational records required for low-latency partition-local query and replay staging
* WARM: indexed replay indexes, deterministic projections, and analytical materializations derived from authoritative records
* COLD: immutable WORM archives for authoritative historical segments and forensic evidence

All three tiers MUST preserve the same canonical record bytes for the authoritative records they hold.

## 3.3 Database Engine

The authoritative relational database engine for HOT and WARM tier commit metadata, partition logs, and deterministic indexes is:

```text
PostgreSQL 16.x
```

The following database rules are mandatory:

* WAL MUST be enabled
* fsync MUST be enabled
* writes MUST be atomic
* transactions MUST be durable
* partial transaction visibility is FORBIDDEN

## 3.4 Authoritative Database Objects

The authoritative database object model MUST contain at minimum:

* `partition_records`
* `batch_commit_records`
* `authority_snapshots`
* `segment_manifests`
* `retention_proofs`
* `replay_guard`

The only authoritative event log is `partition_records`.

All family-specific query tables, JSONB projections, search indexes, and materialized views are derived only and MUST be rebuildable from authoritative storage.

DATA_MINIMIZATION_LAW (MANDATORY):

Non-authoritative systems MUST receive:

* minimum required fields only
* pre-redacted deterministic projections

OPAIF_DATA_VIEW (CRITICAL):

OPAIF MUST NOT read raw `canonical_payload_text` or `canonical_payload_bytes` directly.

OPAIF MUST consume:

→ derived_redacted_view

derived_redacted_view:

* deterministic projection
* field-level allowlist
* no secrets
* no raw payload bytes

Mandatory:

* redacted_projection tables are derived only
* redacted_projection tables MUST be rebuildable from canonical data
* redacted_projection tables MUST NOT become a source of truth

FAILURE:

If OPAIF accesses raw canonical payload:

```text
FAIL-CLOSED
→ ALERT
```

## 3.5 Authoritative Partition Log Table

The authoritative append-only partition log schema is:

```sql
CREATE TABLE partition_records (
  partition_id BIGINT NOT NULL,
  partition_epoch BIGINT NOT NULL,
  partition_record_seq BIGINT NOT NULL,
  shard_seq BIGINT NOT NULL,
  record_type TEXT NOT NULL,
  record_version TEXT NOT NULL,
  stage_order SMALLINT NOT NULL,
  record_id BYTEA NOT NULL,
  message_id BYTEA,
  agent_id BYTEA,
  boot_session_id BYTEA,
  logical_clock NUMERIC(20,0),
  logical_shard_id BYTEA NOT NULL,
  causal_parent_refs_text TEXT NOT NULL,
  canonical_payload_text TEXT,
  canonical_payload_bytes BYTEA,
  canonical_payload_hash BYTEA NOT NULL,
  payload_hash BYTEA,
  signature BYTEA,
  partition_context BYTEA,
  schema_version TEXT,
  schema_transform_hash BYTEA,
  previous_record_hash BYTEA NOT NULL,
  record_hash BYTEA NOT NULL,
  PRIMARY KEY (partition_id, partition_record_seq),
  UNIQUE (record_type, record_id),
  UNIQUE (message_id),
  UNIQUE (agent_id, boot_session_id, logical_clock),
  CHECK (shard_seq = partition_record_seq),
  CHECK (
    record_type <> 'SIGNAL' OR (
      message_id IS NOT NULL AND
      agent_id IS NOT NULL AND
      boot_session_id IS NOT NULL AND
      logical_clock IS NOT NULL AND
      canonical_payload_bytes IS NOT NULL AND
      payload_hash IS NOT NULL AND
      signature IS NOT NULL AND
      partition_context IS NOT NULL AND
      schema_version IS NOT NULL AND
      schema_transform_hash IS NOT NULL
    )
  )
);
```

`causal_parent_refs_text` MUST be RFC 8785 canonical JSON stored as TEXT.

`canonical_payload_text` MUST be RFC 8785 canonical JSON stored as TEXT.

For `record_type = SIGNAL`, `canonical_payload_bytes` MUST store the exact PRD-03 and PRD-07 `canonical_payload_bytes` used for `payload_hash`, `message_id`, and signature verification.

For `record_type = SIGNAL`, the stored signal-order fields `message_id`, `canonical_payload_bytes`, `payload_hash`, `signature`, `agent_id`, `partition_context`, `boot_session_id`, `logical_clock`, and `schema_version` are mandatory stored columns and MUST NOT be reconstructed implicitly from `canonical_payload_text`, projections, or index state.

If `schema_version` is present for any stored record, the exact committed `schema_transform_hash` used to derive the canonical form MUST also be stored explicitly in `partition_records`.

`record_type` MUST be one of:

```text
SIGNAL
DETECTION
DECISION
SAFETY_EVALUATION
ACTION
EXECUTION_RESULT
ROLLBACK
ROLLBACK_OVERRIDE
REDACTION
QUERY
QUERY_RESULT
REPORT
REPORT_DELIVERY
UI_ACTION
GROUP
CASE
INVESTIGATION
RISK
SIMULATION
```

`stage_order` MUST be one of:

```text
1 = SIGNAL
2 = DETECTION
3 = DECISION
4 = SAFETY_EVALUATION
5 = ACTION
6 = EXECUTION_RESULT
7 = ROLLBACK
18 = ROLLBACK_OVERRIDE
19 = REDACTION
8 = QUERY
9 = QUERY_RESULT
10 = REPORT
11 = REPORT_DELIVERY
12 = UI_ACTION
13 = GROUP
14 = CASE
15 = INVESTIGATION
16 = RISK
17 = SIMULATION
```

### 3.5.1 Asset Intelligence Storage Mapping (PRD-23) (CRITICAL)

PRD-23 Asset Intelligence MUST be implemented using existing PRD-13 record types only.

```text
ASSET INTELLIGENCE IS IMPLEMENTED USING EXISTING RECORD TYPES ONLY:

- SIGNAL -> for all asset observation, coverage, managed binding, and risk signals
- UI_ACTION -> for ENTITY_REGISTRY control-plane writes
- GROUP -> for hierarchical organization
```

Mapping:

| PRD-23 Concept          | PRD-13 Record |
| ----------------------- | ------------- |
| Asset Observation       | SIGNAL        |
| Asset Coverage          | SIGNAL        |
| Managed Binding         | SIGNAL        |
| Unmanaged Risk          | SIGNAL        |
| Expected Asset Registry | UI_ACTION     |
| Grouping                | GROUP         |

NO new PRD-13 `record_type` values are allowed for asset intelligence.

---

## 3.6 Commit Boundary Table

This document adopts the append-only cryptographic chaining commit model defined by PRD-02.

The authoritative commit boundary MUST be one durable `batch_commit_record` per committed partition batch.

The schema is:

```sql
CREATE TABLE batch_commit_records (
  partition_id BIGINT NOT NULL,
  batch_commit_seq BIGINT NOT NULL,
  batch_commit_id BYTEA NOT NULL,
  partition_epoch BIGINT NOT NULL,
  first_partition_record_seq BIGINT NOT NULL,
  last_partition_record_seq BIGINT NOT NULL,
  record_count BIGINT NOT NULL,
  first_record_hash BYTEA NOT NULL,
  last_record_hash BYTEA NOT NULL,
  batch_root_hash BYTEA NOT NULL,
  previous_batch_commit_hash BYTEA NOT NULL,
  signing_context TEXT NOT NULL,
  key_id TEXT NOT NULL,
  key_epoch BIGINT NOT NULL,
  execution_context_hash BYTEA NOT NULL,
  signature BYTEA NOT NULL,
  batch_commit_hash BYTEA NOT NULL,
  PRIMARY KEY (partition_id, batch_commit_seq),
  UNIQUE (batch_commit_id),
  CHECK (signing_context = 'batch_commit_record_v1'),
  CHECK (octet_length(first_record_hash) = 32),
  CHECK (octet_length(last_record_hash) = 32),
  CHECK (octet_length(batch_root_hash) = 32),
  CHECK (octet_length(previous_batch_commit_hash) = 32),
  CHECK (octet_length(execution_context_hash) = 32),
  CHECK (octet_length(batch_commit_hash) = 32)
);
```

No record in the committed range is authoritative until its `batch_commit_record` is durable.

## BATCH_EXECUTION_CONTEXT_UNIFORMITY (MANDATORY)

All records within a single batch_commit_record MUST share:

execution_context_hash

---

RULE:

For batch B:

FOR ALL records r IN B:

ASSERT:

r.execution_context_hash == B.execution_context_hash

---

BATCH COMMIT REQUIREMENT:

batch_commit_record MUST include:

execution_context_hash

---

FAILURE:

If any mismatch detected during batch construction:

→ REJECT BATCH
→ FAIL-CLOSED
→ NO COMMIT

## FIRST_RECORD_CONTEXT_LOCK (MANDATORY)

The first record of every batch MUST define:

execution_context_hash

All subsequent records MUST inherit this value.

---

FORBIDDEN:

- context change within batch
- recomputation mid-batch

---

FAILURE:

→ REJECT BATCH

## EXECUTION_CONTEXT_TRANSITION_RULE (CRITICAL)

Context change is allowed ONLY at:

batch boundaries

---

RULE:

last_record_batch_N.execution_context_hash
MAY differ from
first_record_batch_N+1.execution_context_hash

BUT:

within batch:
MUST be identical

---

FAILURE:

context drift inside batch:
→ FAIL-CLOSED

## 3.7 Authority Snapshot Store

Replay completeness requires immutable signed authority snapshots for all referenced signed control objects.

The schema is:

```sql
CREATE TABLE authority_snapshots (
  authority_type TEXT NOT NULL,
  authority_id TEXT NOT NULL,
  authority_version TEXT NOT NULL,
  canonical_payload_text TEXT NOT NULL,
  payload_hash BYTEA NOT NULL,
  signature BYTEA NOT NULL,
  PRIMARY KEY (authority_type, authority_id, authority_version)
);
```

`authority_type` MUST be one of:

```text
CONFIG
POLICY
MODEL
SHARD_CONFIG
ENTITY_ROUTE_MAP
PARAMETER_PROFILE
ADAPTER_MANIFEST
ACTION_CAPABILITY_DESCRIPTOR
RETENTION_CONFIG
```

Unsigned or partially verified authority snapshots are invalid.

---

## 🔴 CHAOS_MATRIX_STORAGE_RULE (MANDATORY) (CRITICAL)

The chaos matrix MUST be stored as an authoritative signed authority snapshot in PRD-13.

Mandatory identity (MANDATORY):

```text
authority_type = CONFIG
authority_id = "chaos_validation_matrix"
```

Mandatory properties (MANDATORY):

* versioned
* signed
* replay-reconstructable

Storage binding rule (MANDATORY):

```text
authority_type = CONFIG
authority_id = "chaos_validation_matrix"
authority_version = "chaos_validation_matrix_v1"
canonical_payload_text = RFC8785(JCS)(full PRD-01 authoritative chaos scenario matrix object set)
payload_hash = SHA256(canonical_payload_bytes)
signature = Ed25519(signature_input under PRD-04)
```

Replay requirement (MANDATORY):

* replay datasets MUST include the exact committed authority snapshot for `authority_id = chaos_validation_matrix`
* missing or ambiguous chaos matrix snapshot in a validation scope:

```text
INTEGRITY_FAILURE -> FAIL-CLOSED -> ALERT
```

```text
CHAOS_MATRIX_EXECUTION_BINDING (CRITICAL)

Every batch_commit_record MUST implicitly bind to exactly one chaos matrix snapshot via execution_context_hash.

MANDATORY:

- chaos matrix snapshot MUST be immutable per execution_context
- changing chaos matrix REQUIRES new execution_context_hash
- mixed chaos matrix usage within same partition is FORBIDDEN

IF mixed chaos_matrix_snapshot_hash detected within partition:

→ HALT PARTITION
→ FAIL-CLOSED
→ ALERT
```

EXECUTION_CONTEXT_TRANSITION_RULE (CRITICAL)

A partition MUST operate under EXACTLY ONE execution_context_hash at any time.

Transition to a new execution_context_hash is permitted ONLY under the following deterministic condition:

TRANSITION CONDITION (MANDATORY):

- current batch_commit_record is fully committed
- partition has no in-flight records
- next record to be admitted references new execution_context_hash

THEN:

→ START NEW CONTEXT EPOCH AT NEXT partition_record_seq

MANDATORY RULES:

- execution_context_hash MUST NOT change within a batch
- execution_context_hash MUST NOT change mid-record sequence
- execution_context_hash change MUST occur ONLY at commit boundary

FORBIDDEN:

- partial batch context switching
- speculative context switching
- time-based switching
- asynchronous propagation

VIOLATION:

→ HALT PARTITION
→ FAIL-CLOSED
→ ALERT

EXECUTION_CONTEXT_COMMIT_BINDING_RULE (CRITICAL)

All records within a batch and the corresponding batch_commit_record MUST share the EXACT SAME execution_context_hash.

MANDATORY:

- every record admitted into a batch MUST carry execution_context_hash implicitly via partition context
- batch_commit_record.execution_context_hash MUST equal the execution_context_hash of ALL records in that batch

VALIDATION RULE:

FOR batch_commit_record:

    FOR EACH record in [first_partition_record_seq ... last_partition_record_seq]:

        ASSERT record.execution_context_hash == batch_commit_record.execution_context_hash

IF any mismatch detected:

→ REJECT BATCH
→ FAIL-CLOSED
→ ALERT

FIRST RECORD RULE (MANDATORY):

The first record of a new execution context epoch MUST:

- carry the new execution_context_hash
- be included in a batch_commit_record that carries the SAME execution_context_hash

FORBIDDEN:

- batch containing mixed execution_context_hash values
- batch_commit_record execution_context_hash not matching record set
- implicit or inferred execution context

VIOLATION:

→ REJECT BATCH
→ FAIL-CLOSED
→ ALERT

## 3.8 Segment Manifest Table

The schema is:

```sql
CREATE TABLE segment_manifests (
  partition_id BIGINT NOT NULL,
  segment_id BYTEA NOT NULL,
  first_partition_record_seq BIGINT NOT NULL,
  last_partition_record_seq BIGINT NOT NULL,
  first_record_hash BYTEA NOT NULL,
  last_record_hash BYTEA NOT NULL,
  record_count BIGINT NOT NULL,
  segment_root_hash BYTEA NOT NULL,
  manifest_hash BYTEA NOT NULL,
  PRIMARY KEY (partition_id, segment_id)
);
```

`segment_manifests` MUST be append-only and immutable.

## 3.9 Retention Proof Table

The schema is:

```sql
CREATE TABLE retention_proofs (
  partition_id BIGINT NOT NULL,
  segment_id BYTEA NOT NULL,
  retention_proof_id BYTEA NOT NULL,
  first_record_hash BYTEA NOT NULL,
  last_record_hash BYTEA NOT NULL,
  segment_root_hash BYTEA NOT NULL,
  record_count BIGINT NOT NULL,
  retention_rule_id TEXT NOT NULL,
  proof_hash BYTEA NOT NULL,
  PRIMARY KEY (partition_id, retention_proof_id),
  UNIQUE (partition_id, segment_id)
);
```

`retention_proofs` MUST be append-only and immutable.

## 3.10 Replay Guard

The replay guard MUST remain partition-local or logical-shard-local as required by PRD-02.

The schema is:

```sql
CREATE TABLE replay_guard (
  partition_id BIGINT NOT NULL,
  logical_shard_id BYTEA NOT NULL,
  emitter_id BYTEA NOT NULL,
  boot_session_id BYTEA NOT NULL,
  logical_clock NUMERIC(20,0) NOT NULL,
  message_id BYTEA NOT NULL,
  seen_state TEXT NOT NULL,
  pre_auth_nonce BYTEA,
  pre_auth_token BYTEA,
  pre_auth_message_type TEXT,
  pre_auth_validity_window TEXT,
  pre_auth_execution_context_hash BYTEA,
  escrow_handoff_id BYTEA,
  PRIMARY KEY (partition_id, logical_shard_id, message_id),
  UNIQUE (partition_id, logical_shard_id, emitter_id, boot_session_id, logical_clock),
  UNIQUE (partition_id, logical_shard_id, pre_auth_nonce),
  CHECK (seen_state IN ('PENDING_QUEUE_COMMIT', 'ADMITTED')),
  CHECK (pre_auth_message_type IS NULL OR pre_auth_message_type = 'PRE_TLS_AUTH')
);
```

For admitted `signal_record` state, `replay_guard` recovery MUST preserve the PRD-08 session-ordering key `(emitter_id, boot_session_id)` and restore exact `last_seen_logical_clock` and `last_message_id` from committed authoritative storage by replaying committed rows in ascending `logical_clock`.

For pre-TLS admission state, the following are mandatory:

* `pre_auth_token` MUST store the exact committed token bytes
* `pre_auth_nonce` MUST store the ingest-authority-issued nonce
* `pre_auth_nonce` MUST be single-use within `replay_guard`
* `pre_auth_message_type` MUST equal `PRE_TLS_AUTH`
* `pre_auth_execution_context_hash` MUST equal the token-bound `execution_context_hash`

## 🔴 REPLAY GUARD AUTHORITY LAW (CRITICAL)

PRD-13 `replay_guard` IS THE ONLY AUTHORITATIVE SOURCE.

ALL replay decisions MUST derive ONLY from:

* committed `replay_guard`
* committed `partition_records`

FORBIDDEN:

* Kafka `replay_guard_log` as authority
* in-memory replay state as authority
* PRD-08 independent replay structures

PRD-08 is limited to:

* querying PRD-13 `replay_guard`
* maintaining a read-through cache only

PRD-24 `replay_guard_log`:

* MUST be treated as a NON-authoritative cache
* MUST be rebuildable from committed PRD-13 `replay_guard`

VIOLATION:

```text
REJECT → FAIL-CLOSED → ALERT
```

## 3.11 Commit Group Table

The schema is:

```sql
CREATE TABLE commit_groups (
  partition_id BIGINT NOT NULL,
  logical_shard_id BYTEA NOT NULL,
  message_id BYTEA NOT NULL,
  commit_group_id BYTEA NOT NULL,
  commit_group_status TEXT NOT NULL,
  terminal_record_type TEXT NOT NULL,
  terminal_record_id BYTEA NOT NULL,
  batch_commit_seq BIGINT NOT NULL,
  PRIMARY KEY (partition_id, logical_shard_id, message_id),
  UNIQUE (commit_group_id),
  CHECK (commit_group_status IN (
    'ACTION_EXECUTED',
    'POLICY_DENIED',
    'APPROVAL_PENDING',
    'ROLLBACK_TERMINAL',
    'NO_ACTION_DEFERRED_RESOLVED'
  ))
);
```

`commit_groups` MUST be append-only and replay-visible.

## 3.11.1 COMMIT_GROUP_REPLAY_BINDING (MANDATORY)

```text
GLOBAL_INVARIANT

COMMIT_GROUPS_ARE_TERMINAL_SCOPE_METADATA = TRUE
COMMIT_GROUPS_ARE_NOT_BATCH_COMMIT_BOUNDARY_ARTIFACTS = TRUE
COMMIT_GROUPS_DO_NOT_PARTICIPATE_IN_RECORD_HASH = TRUE
COMMIT_GROUPS_DO_NOT_PARTICIPATE_IN_BATCH_ROOT_HASH = TRUE
COMMIT_GROUPS_DO_NOT_PARTICIPATE_IN_BATCH_COMMIT_HASH = TRUE
COMMIT_GROUPS_DO_NOT_PARTICIPATE_IN_BATCH_COMMIT_SIGNATURE = TRUE
```

```text
DETERMINISTIC_PREDICATE

commit_groups.partition_id = batch_commit_records.partition_id
commit_groups.batch_commit_seq REFERENCES EXACTLY ONE batch_commit_records.batch_commit_seq IN THE SAME partition_id
commit_groups.terminal_record_id REFERENCES EXACTLY ONE partition_records.record_id IN THE SAME partition_id
commit_groups.terminal_record_type = REFERENCED partition_records.record_type
REFERENCED partition_records.partition_record_seq MUST SATISFY:
first_partition_record_seq <= partition_record_seq <= last_partition_record_seq
WHERE first_partition_record_seq AND last_partition_record_seq ARE READ FROM THE REFERENCED batch_commit_records ROW
```

```text
DETERMINISTIC_PREDICATE

IF replay_scope INCLUDES terminal-chain completeness:
    replay_dataset MUST include EVERY commit_groups ROW whose terminal_record_id is within the declared scope
IF replay_scope EXCLUDES terminal-chain completeness:
    commit_groups ROWS ARE NOT REQUIRED FOR record_hash RECONSTRUCTION
    commit_groups ROWS ARE NOT REQUIRED FOR batch_root_hash RECONSTRUCTION
    commit_groups ROWS ARE NOT REQUIRED FOR batch_commit_hash RECONSTRUCTION
    commit_groups ROWS ARE NOT REQUIRED FOR batch_commit signature reconstruction
```

```text
STATE_TRANSITION

IF commit_groups REFERENCES A MISSING batch_commit_records ROW:
    FAIL-CLOSED -> ALERT
IF commit_groups REFERENCES A MISSING partition_records ROW:
    FAIL-CLOSED -> ALERT
IF commit_groups REFERENCES A terminal_record_id OUTSIDE THE REFERENCED batch_commit_records RANGE:
    FAIL-CLOSED -> ALERT
```

## 🔴 ESCROW_REPLAY_ALIGNMENT (MANDATORY)

ESCROW_HANDOFF_ID MUST be inserted into:

replay_guard (PRD-13)

KEY:

(partition_id, logical_shard_id, ESCROW_HANDOFF_ID)

---

RULE:

Escrow dedup MUST reuse replay_guard semantics

Mandatory storage binding:

* `replay_guard` MUST additionally persist `escrow_handoff_id` as an explicit committed field for escrow-originated entries
* `escrow_handoff_id` MUST equal `ESCROW_HANDOFF_ID`

---

FORBIDDEN:

separate dedup system outside replay_guard

---

# 4. DATA RECORD TYPES

## 4.1 Common Storage Record Law

Every authoritative storage record MUST be:

* fully deterministic
* self-contained
* cryptographically linked
* partition-aligned
* replay-sufficient

Every authoritative storage record MUST contain the following logical fields:

```json
{
  "record_type": "SIGNAL|DETECTION|DECISION|SAFETY_EVALUATION|ACTION|EXECUTION_RESULT|ROLLBACK|ROLLBACK_OVERRIDE|REDACTION|QUERY|QUERY_RESULT|REPORT|REPORT_DELIVERY|UI_ACTION|GROUP|CASE|INVESTIGATION|RISK|SIMULATION",
  "record_version": "string",
  "partition_id": 0,
  "partition_epoch": 0,
  "partition_record_seq": 0,
  "logical_shard_id": "hex_16_bytes",
  "shard_seq": 0,
  "stage_order": 0,
  "record_id": "hex_32_bytes",
  "causal_parent_refs": ["hex_32_bytes"],
  "canonical_payload_text": "{}",
  "canonical_payload_hash": "hex_32_bytes",
  "previous_record_hash": "hex_32_bytes",
  "record_hash": "hex_32_bytes"
}
```

```text
shard_seq = partition_record_seq

shard_seq MUST EQUAL partition_record_seq FOR EVERY RECORD
```

The following constructions are mandatory:

```text
canonical_payload_hash = SHA256(canonical_payload_bytes)
```

```text
canonical_payload_text IS OPTIONAL

IF PRESENT:
→ MUST BE DERIVED FROM canonical_payload_bytes
→ MUST MATCH EXACTLY
```

```text
PRD-13 HASH CHAIN IS THE ONLY AUTHORITATIVE CHAIN
```

`canonical_payload_text` MUST be RFC 8785 canonical JSON of the full authoritative upstream object for that record family.

For `record_type = SIGNAL`, storage MUST additionally persist the following logical fields explicitly:

```json
{
  "message_id": "hex_32_bytes",
  "canonical_payload_bytes": "bytes",
  "payload_hash": "hex_32_bytes",
  "signature": "hex_ed25519",
  "agent_id": "hex_16_bytes",
  "partition_context": "hex_16_bytes",
  "boot_session_id": "hex_32_bytes",
  "logical_clock": 0,
  "schema_version": "signal_schema_vN"
}
```

For stored `signal_record` rows, the following constructions are mandatory:

```text
logical_clock_bytes = UINT64_BE(logical_clock)
payload_hash = SHA256(canonical_payload_bytes)
message_id = SHA256(RFC8785(full_canonical_object))
```

```text
CANONICAL PAYLOAD SOURCE OF TRUTH (PRD-13):

canonical_payload_bytes IS AUTHORITATIVE

canonical_payload_text IS DERIVED ONLY

IF MISMATCH:
→ FAIL-CLOSED
```

## 4.2 signal_record

`signal_record` MUST store the full authoritative `signal_event` defined by PRD-07.

The following rules are mandatory:

* `record_type = SIGNAL`
* `record_version = signal_record_v1`
* `record_id` MUST equal `signal_event.message_id`
* `message_id` MUST equal `signal_event.message_id`
* `canonical_payload_text` MUST equal RFC 8785 JCS of the full `signal_event`
* `canonical_payload_bytes` MUST equal the exact PRD-03 and PRD-07 canonical payload bytes used to derive `signal_event.payload_hash`, `signal_event.message_id`, and signature verification
* `payload_hash` MUST equal `signal_event.payload_hash`
* `signature` MUST equal `signal_event.signature`
* `agent_id` MUST equal the producer identifier carried in `signal_event.emitter_id`; for `emitter_type = agent` this is `agent_id`, and for `emitter_type = probe` this is `probe_id`
* `partition_context` MUST equal `signal_event.partition_context`
* `boot_session_id` MUST equal `signal_event.boot_session_id`
* `logical_clock` MUST equal `signal_event.logical_clock`
* `schema_version` MUST equal `signal_event.schema_version`
* `causal_parent_refs` MUST be an empty ordered list
* `partition_id`, `partition_epoch`, `logical_shard_id`, and `shard_seq` MUST equal the authoritative routed signal metadata
* `shard_seq` MUST equal `partition_record_seq` for `signal_record`
* `stage_order = 1`
* all listed signal fields are mandatory stored columns
* none of the listed signal fields may be reconstructed implicitly at read time

### 🔴 SESSION_CHAIN_SIGNAL_BINDING (CRITICAL)

For the first `signal_record` of a new `boot_session_id` after a committed `SESSION_CONTINUITY` record:

* `causal_parent_refs` MUST contain exactly one entry: `last_committed_message_id`
* `continuity_hash` MUST be persisted as an explicit committed field on that first `signal_record`
* persisted `continuity_hash` MUST equal `SHA256(previous_boot_session_id || last_committed_message_id || new_boot_session_id)`
* missing `causal_parent_refs` for that first signal is invalid
* this causal link is the PRD-13 storage-visible bridge for the PRD-03 session continuity chain and the PRD-09 causal graph

For all other `signal_record` rows, the empty ordered list rule remains mandatory.

### 4.2.1 Signal Payload Extraction Rule (PRD-23) (CRITICAL)

For asset intelligence support, fields such as:

* `entity_key`
* `coverage_state`
* classification references

MUST be extractable from `signal_record.canonical_payload_text` using deterministic parsing of RFC 8785 canonical JSON.

Extraction MUST NOT require:

* external enrichment
* non-deterministic decoding
* opaque binary-only payload interpretation

Any derived index built from these fields MUST remain rebuildable from `canonical_payload_text` and MUST NOT become a source of truth.

## 4.3 detection_record

`detection_record` MUST store the full authoritative `detection_event` defined by PRD-09.

The following rules are mandatory:

* `record_type = DETECTION`
* `record_version = detection_record_v1`
* `record_id` MUST equal `detection_event.detection_id`
* `canonical_payload_text` MUST equal RFC 8785 JCS of the full `detection_event`
* `causal_parent_refs` MUST equal ordered `signal_refs`
* `partition_id`, `partition_epoch`, and `logical_shard_id` MUST equal the values in `detection_event`
* `shard_seq` MUST equal `partition_record_seq`
* `stage_order = 2`

## 4.4 decision_record

`decision_record` MUST store the full authoritative `action_decision` defined by PRD-11.

The following rules are mandatory:

* `record_type = DECISION`
* `record_version = decision_record_v1`
* `record_id` MUST equal `action_decision.decision_id`
* `canonical_payload_text` MUST equal RFC 8785 JCS of the full `action_decision`
* `causal_parent_refs` MUST contain exactly one entry: `detection_id`
* `partition_id`, `partition_epoch`, `logical_shard_id`, and `shard_seq` MUST be copied from the referenced `detection_record`
* `stage_order = 3`

## 4.5 safety_evaluation_record

`safety_evaluation_record` MUST store the full authoritative `safety_evaluation` defined by PRD-20.

The following rules are mandatory:

* `record_type = SAFETY_EVALUATION`
* `record_version = safety_evaluation_record_v1`
* `record_id` MUST equal `safety_evaluation.safety_evaluation_id`
* `canonical_payload_text` MUST equal RFC 8785 JCS of the full `safety_evaluation`
* `causal_parent_refs` MUST contain exactly one entry: `decision_id`
* `partition_id`, `partition_epoch`, `logical_shard_id`, and `shard_seq` MUST be copied from the referenced `decision_record`
* `stage_order = 4`

## 4.6 action_record

`action_record` MUST store the full authoritative `action_object` defined by PRD-12.

The following rules are mandatory:

* `record_type = ACTION`
* `record_version = action_record_v1`
* `record_id` MUST equal `action_object.action_id`
* `canonical_payload_text` MUST equal RFC 8785 JCS of the full `action_object`
* `causal_parent_refs` MUST contain exactly two entries in deterministic order: `decision_id`, `safety_evaluation_id`
* `partition_id`, `partition_epoch`, `logical_shard_id`, and `shard_seq` MUST be copied from the referenced `safety_evaluation_record`
* `stage_order = 5`

### 🔴 BREAK-GLASS ORDERING & CAUSALITY (CRITICAL)
STAGE ORDER

Break-glass action MUST use:

stage_order = 5
record_type = ACTION
CAUSAL BINDING

Break-glass action MUST include:

causal_parent_refs = [
  last_failed_execution_id,
  last_rollback_id
]
VALIDATION RULE
IF causal chain cannot be reconstructed from committed records:
    REJECT break-glass → FAIL-CLOSED
PURPOSE

Ensures break-glass:

- is replay-safe
- is causally explainable
- cannot bypass execution lineage

## 4.7 execution_result_record

`execution_result_record` MUST store the full authoritative executor receipt containing:

* `execution_result`
* `execution_verification_state`

The following rules are mandatory:

* `record_type = EXECUTION_RESULT`
* `record_version = execution_result_record_v1`
* `record_id` MUST equal `execution_result.execution_id`
* `canonical_payload_text` MUST equal RFC 8785 JCS of the full executor receipt object
* `causal_parent_refs` MUST contain exactly one entry: `action_id`
* `partition_id`, `partition_epoch`, `logical_shard_id`, and `shard_seq` MUST be copied from the referenced `action_record`
* `stage_order = 6`

### 🔴 STATE_HASH_STORAGE_BINDING (MANDATORY)

Every computed `state_hash` MUST be persisted as part of `execution_result_record`.

Mandatory payload fields:

```text
state_scope
state_scope_hash
pre_state_hash
post_state_hash
```

Mandatory:

* `state_scope` MUST equal the exact declared scope used under PRD-20 / PRD-12 `STATE_READ_CONTRACT`
* `state_scope_hash = SHA256(RFC8785(state_scope))`
* `pre_state_hash` and `post_state_hash` MUST be derived only from PRD-20 / PRD-12 scoped-hash construction
* replay MUST use these stored fields only
* if any field is missing, replay validation MUST fail closed

## 4.8 rollback_record

`rollback_record` MUST store the full authoritative rollback verification record defined by PRD-20.

PRD-12 alignment (mandatory):

* the rollback record payload MUST contain `rollback_execution_result`
* the rollback record payload MUST contain `rollback_verification_state`

Missing either field is invalid and MUST fail closed.

The following rules are mandatory:

* `record_type = ROLLBACK`
* `record_version = rollback_record_v1`
* `record_id` MUST equal `rollback_record.rollback_id`
* `canonical_payload_text` MUST equal RFC 8785 JCS of the full authoritative rollback verification record
* `causal_parent_refs` MUST contain exactly one entry: `execution_id`
* `partition_id`, `partition_epoch`, `logical_shard_id`, and `shard_seq` MUST be copied from the referenced `execution_result_record`
* `stage_order = 7`

## 4.8.1 rollback_override_record (ROLLBACK_OVERRIDE) (CRITICAL)

`rollback_override_record` MUST store the full authoritative rollback-override object.

Mandatory:

* `record_type = ROLLBACK_OVERRIDE`
* `record_version = rollback_override_record_v1`
* `record_id` MUST equal `override_hash`
* `canonical_payload_text` MUST equal RFC 8785 JCS of the full rollback override object
* `causal_parent_refs` MUST contain exactly one entry: `linked_execution_id`
* `stage_order = 18`

The canonical payload MUST contain at minimum:

```json
{
  "record_type": "ROLLBACK_OVERRIDE",
  "entity_id": "string",
  "reason": "string",
  "approved_by": "string",
  "linked_execution_id": "hex_32_bytes",
  "authorization_bundle_hash": "hex_32_bytes",
  "control_plane_failure_proof": "hex_32_bytes",
  "breakglass_action_id": "hex_32_bytes",
  "override_hash": "SHA256(...)"
}
```

Replay MUST validate the following required fields for every `rollback_override_record`:

* `authorization_bundle_hash`
* `control_plane_failure_proof`
* `breakglass_action_id`

If any required field is missing or ambiguous:

```text
FAIL-CLOSED -> ALERT
```

## 4.8.2 redaction_record (REDACTION) (CRITICAL)

LOGICAL_ERASURE_LAW:

Legal erasure MUST be implemented as:
- deterministic overlay
- cryptographically provable
- replay-compatible

REDACTION DOES NOT DELETE DATA.

Mandatory:

* original record remains immutable
* new redaction_record overlays access restriction
* redaction records are append-only and MUST NOT break PRD-13 hash chain integrity

REDACTION_IS_READ_LAYER_ONLY (CRITICAL):

Redaction is a read-layer-only overlay.

The following MUST ALWAYS use ORIGINAL canonical data:

* feature_vector_hash
* execution_context_hash
* record_hash
* detection_id
* action_id

Redaction application ONLY applies to:

* UI rendering
* OPAIF views
* query responses

## ZKP_REDACTION_PROOF:

proof = ZKP(original_payload_hash, redacted_payload)

Verifier can validate:

hash(original) == committed_hash

WITHOUT accessing original data

## ZKP_PROFILE_LOCK (MANDATORY)

All ZKP operations MUST use a fully specified deterministic profile.

REQUIRED:

zkp_system = "Groth16"
curve = "BLS12-381"
hash_function = "SHA256"
field_encoding = "big-endian canonical"

---

PROVING KEY:

proving_key_hash = SHA256(proving_key_bytes)

verification_key_hash = SHA256(verification_key_bytes)

Both MUST be stored in PRD-13 authority_snapshots.

---

PROOF STRUCTURE (FIXED):

proof = {
  A: G1,
  B: G2,
  C: G1
}

serialized using deterministic canonical encoding.

---

VERIFIER RULE:

verification MUST:

- use fixed verification_key
- reject any non-canonical encoding
- execute within bounded constraints:

max_constraints = 2^20

---

FORBIDDEN:

- dynamic curve selection
- STARK / SNARK switching
- floating proving systems
- runtime parameter tuning

---

FAILURE:

→ REJECT PROOF
→ FAIL-CLOSED

## ZKP_CONTEXT_BINDING (MANDATORY)

All ZKP proofs MUST bind to execution_context_hash.

---

CONSTRUCTION:

zkp_context_hash = SHA256(
  execution_context_hash ||
  proving_key_hash ||
  verification_key_hash
)

---

PROOF INPUT:

proof MUST be generated over:

(original_payload_hash, redacted_payload, zkp_context_hash)

---

VERIFICATION RULE:

Verifier MUST:

1. recompute zkp_context_hash
2. validate proof against same context

---

REPLAY LAW (PRD-15):

Replay MUST:

- use stored execution_context_hash
- recompute zkp_context_hash
- verify identical proof validity

---

ZKP_INPUT_CANONICALIZATION (MANDATORY)

All ZKP inputs MUST be canonicalized using:

RFC8785 (JCS)

---

INPUT:

(original_payload_hash, redacted_payload, zkp_context_hash)

MUST be serialized deterministically

---

FORBIDDEN:

non-canonical JSON
field reordering

---

FAILURE:

→ REJECT PROOF
→ FAIL-CLOSED

---

FAILURE:

context mismatch:

→ REJECT PROOF
→ FAIL-CLOSED

FORBIDDEN:

* hashing redacted data
* replacing canonical payload bytes during replay

REDACTION_RECORD structure:

```json
{
  "record_type": "REDACTION",
  "target_record_id": "hex_32_bytes",
  "redaction_scope": "FIELD|FULL",
  "redacted_fields": ["field1", "field2"],
  "reason": "GDPR_ERASURE",
  "authority_ref": "legal_request_id",
  "timestamp_logical": "partition_record_seq"
}
```

The following rules are mandatory:

* `record_type = REDACTION`
* `record_version = redaction_record_v1`
* `record_id` MUST equal `SHA256(target_record_id || redaction_scope || RFC8785(redacted_fields) || reason || authority_ref || timestamp_logical)`
* `canonical_payload_text` MUST equal RFC 8785 JCS of the full redaction_record payload
* `causal_parent_refs` MUST contain exactly one entry: `target_record_id`
* `stage_order = 19`

ACCESS RULE (READ-ONLY OVERLAY):

ON READ:

IF a committed redaction_record exists for a target_record_id:
→ apply overlay deterministically:
  - redaction_scope = FULL → hide record AND return REDACTED_REFERENCE_PLACEHOLDER for any reference to the target_record_id
  - redaction_scope = FIELD → mask listed fields
ELSE:
→ normal read

REDACTED_REFERENCE_PLACEHOLDER (CRITICAL):

If a referenced record is redacted:

→ system MUST return placeholder instead of null/missing

Placeholder structure:

```json
{
  "record_id": "hex_32_bytes",
  "state": "REDACTED",
  "redaction_ref": "hex_32_bytes",
  "hash": "hex_32_bytes"
}
```

Mandatory:

* `record_id` MUST equal the referenced `target_record_id`
* `redaction_ref` MUST equal the committed redaction_record `record_id`
* `hash` MUST equal the committed PRD-13 `record_hash` of the redacted record

FORBIDDEN:

* silent removal of references
* null substitution

FAILURE CASE:

If redaction cannot be applied deterministically:

```text
FAIL-CLOSED -> ALERT
```

## 4.9 query_record

`query_record` MUST store the full authoritative `query_object` defined in this PRD.

The following rules are mandatory:

* `record_type = QUERY`
* `record_version = query_record_v1`
* `record_id` MUST equal `query_object.query_hash`
* `canonical_payload_text` MUST equal RFC 8785 JCS of the full `query_object`
* `causal_parent_refs` MUST contain exactly one entry referencing the `UI_ACTION_RECORD` or system trigger that initiated the query
* `stage_order = 8`

## 4.10 query_result_record

`query_result_record` MUST store the result metadata and row hashes of a query execution.

The following rules are mandatory:

* `record_type = QUERY_RESULT`
* `record_version = query_result_record_v1`
* `record_id` MUST equal `query_result_hash` defined in this PRD
* `canonical_payload_text` MUST contain `query_hash`, `result_hash`, and ordered record hashes of the result set
* `causal_parent_refs` MUST contain exactly one entry: `query_hash`
* `stage_order = 9`

## 4.11 report_record

`report_record` MUST store the full authoritative `report` object defined in this PRD.

The following rules are mandatory:

* `record_type = REPORT`
* `record_version = report_record_v1`
* `record_id` MUST equal `report.report_id`
* `canonical_payload_text` MUST equal RFC 8785 JCS of the full `report` object
* `causal_parent_refs` MUST contain exactly one entry: `query_result_hash`
* `stage_order = 10`

If the `report` object is emitted by PRD-22 Shadow Intelligence, it MUST additionally contain:

* `input_record_refs[]`
* `model_id`
* `model_version`
* `output_hash`
* `shadow_metadata`

For Shadow Intelligence reports, `shadow_metadata` MUST contain:

* `source = "OPAIF"`
* `non_authoritative = true`
* `request_hash`
* `execution_context_hash`

Additional Shadow Intelligence inputs MUST be carried in `input_record_refs[]` and MUST NOT change the mandatory `query_result_hash` causal parent binding.

## 4.12 report_delivery_record

`report_delivery_record` MUST store the delivery evidence defined in this PRD.

The following rules are mandatory:

* `record_type = REPORT_DELIVERY`
* `record_version = report_delivery_record_v1`
* `record_id` MUST equal `delivery_hash`
* `canonical_payload_text` MUST contain `report_id`, `delivery_target`, and `delivery_status`
* `causal_parent_refs` MUST contain exactly one entry: `report_id`
* `stage_order = 11`

## 4.13 ui_action_record

`ui_action_record` MUST store the full authoritative `UI_ACTION_RECORD` defined by PRD-20.

The following rules are mandatory:

* `record_type = UI_ACTION`
* `record_version = ui_action_record_v1`
* `record_id` MUST equal `SHA256(RFC8785(UI_ACTION_RECORD))`
* `canonical_payload_text` MUST equal RFC 8785 JCS of the full `UI_ACTION_RECORD`
* `causal_parent_refs` MUST contain the hash of any prerequisite UI action or state reference
* `stage_order = 12`

### 4.13.1 ENTITY_REGISTRY Storage (PRD-23) (CRITICAL)

PRD-23 `ENTITY_REGISTRY` MUST exist ONLY inside:

* `ui_action_record.canonical_payload_text`

Mandatory rules:

* `ENTITY_REGISTRY` MUST NOT be stored as a separate PRD-13 record family
* `ENTITY_REGISTRY` MUST NOT be stored as a separate authoritative table
* mutation is forbidden; registry evolution MUST occur only through new append-only `UI_ACTION_RECORD` entries
* reconstruction MUST occur through deterministic query over committed `UI_ACTION_RECORD` rows

```text
UI_ACTION RECORDS ARE AUTHORITATIVE CONTROL INPUTS

NO OUT-OF-BAND STATE
```

## 4.14 group_record

`group_record` MUST store the full authoritative group definition defined in this PRD.

The following rules are mandatory:

* `record_type = GROUP`
* `record_version = group_record_v1`
* `record_id` MUST equal `group_id`
* `canonical_payload_text` MUST contain `parent_group`, `name`, and `rules`
* `causal_parent_refs` MUST be empty or reference the `parent_group_id`
* `stage_order = 13`

## 4.15 case_record

`case_record` MUST store the full authoritative case state and SLA tracking defined in PRD-21.

The following rules are mandatory:

* `record_type = CASE`
* `record_version = case_record_v1`
* `record_id` MUST equal `case_id`
* `canonical_payload_text` MUST contain `incident_data` and current SLA metadata
* `causal_parent_refs` MUST be empty or reference previous case states or initiating detections
* `stage_order = 14`

## 4.16 investigation_record

`investigation_record` MUST persist the deterministic analyst workflow defined in PRD-21.

The following rules are mandatory:

* `record_type = INVESTIGATION`
* `record_version = investigation_record_v1`
* `record_id` MUST equal `investigation_id`
* `canonical_payload_text` MUST contain `investigation_id`, `entity_set`, `filters`, and `state_hash`
* `causal_parent_refs` MUST reference the `UI_ACTION_RECORD` sequence initiating the state
* `stage_order = 15`

## 4.17 risk_record

`risk_record` MUST store the authoritative risk priority defined in PRD-21.

The following rules are mandatory:

* `record_type = RISK`
* `record_version = risk_record_v1`
* `record_id` MUST equal `SHA256(RFC8785(risk_payload))`
* `canonical_payload_text` MUST contain the hashable risk inputs and resulting `risk_score`
* `causal_parent_refs` MUST reference the configuration snapshot and entity records used
* `stage_order = 16`

## 4.18 simulation_record

`simulation_record` MUST store the dry-run impact evaluation defined in PRD-21.

The following rules are mandatory:

* `record_type = SIMULATION`
* `record_version = simulation_record_v1`
* `record_id` MUST equal `SHA256(RFC8785(simulation_payload))`
* `canonical_payload_text` MUST contain the dry-run inputs and bit-for-bit identical results
* `causal_parent_refs` MUST reference the policy and model snapshots used
* `stage_order = 17`

## 4.19 Record Completeness Rule

## 4.19 Record Completeness Rule

Each authoritative record MUST be sufficient to verify:

* its own partition placement
* its own causal ancestry
* its own payload hash
* its own chain linkage

Reference-only records without canonical payload are FORBIDDEN.

---

# 5. WORM MODEL (CRITICAL)

## 5.1 Append-Only Law

The following are mandatory:

* records MUST NEVER be updated
* records MUST NEVER be deleted outside deterministic retention execution
* mutation is FORBIDDEN
* in-place status changes are FORBIDDEN
* later lifecycle state MUST be represented only by new append-only records
* stored records MUST be immutable after commit
* updates are FORBIDDEN
* deletes are FORBIDDEN until PRD-14 retention execution applies

## 5.2 Visibility Rule

An authoritative record MUST become visible only after durable commit succeeds.

Uncommitted records MUST NOT be visible to authoritative reads.

## 5.3 Tier Immutability Rule

The following are mandatory:

* HOT tier authoritative records are append-only
* WARM tier authoritative records are append-only
* COLD tier authoritative records are immutable WORM segments

Tier transition MUST copy canonical bytes exactly.

Re-serialization during tier movement is FORBIDDEN.

## 5.4 No Mutable Lifecycle Columns

Mutable lifecycle columns such as in-place action status updates are invalid.

Lifecycle progress MUST be represented by:

* `decision_record`
* followed by exactly one causally valid `safety_evaluation_record`
* followed by `action_record` when execution is authorized
* followed by exactly one causally valid `execution_result_record` for the stored `execution_id` when an action is dispatched
* followed by `rollback_record` when rollback executes

## 5.5 WORM Verification Rule

The following MUST remain verifiable at any time:

* record hashes
* partition chains
* batch commit boundaries
* segment manifests
* retention proofs

If any WORM verification fails:

```text
FAIL-CLOSED -> ALERT
```

---

# 6. CRYPTOGRAPHIC CHAINING (CRITICAL)

## 6.1 Record Hash Rule

Each authoritative record MUST include:

* `record_hash`
* `previous_record_hash`

The chain scope is the authoritative append-only log of one `partition_id`.

The exact executable byte grammar is mandatory.

SINGLE SOURCE OF TRUTH = PRD-13 HASH CHAIN

Any implementation that computes `record_hash` differently is INVALID.

## 6.1.1 STORAGE_BYTE_GRAMMAR_PRIMITIVES (MANDATORY)

```text
GLOBAL_INVARIANT

PRD13_STORAGE_BYTE_GRAMMAR_VERSION = "mishka.storage.byte_grammar.v1"
NULL_LITERAL = FORBIDDEN
IMPLICIT_DEFAULT_INSERTION = FORBIDDEN
FIELD_REORDER = FORBIDDEN
EXTRA_FIELD = FORBIDDEN
MISSING_REQUIRED_FIELD = FORBIDDEN
```

```text
PURE_ASSIGNMENT

ASCII_BYTES(x) = ASCII(x)
UTF8_BYTES(x) = UTF8(x)
HEX_LOWER(x) = LOWERCASE_HEX_ASCII_WITHOUT_PREFIX(x)

FIELD_PRESENT = 0x01
FIELD_ABSENT = 0x00

ZERO_HASH_32 = HEX_TO_BYTES("0000000000000000000000000000000000000000000000000000000000000000")

UINT8(x) = 1 BYTE UNSIGNED BIG-ENDIAN
UINT16_BE(x) = 2 BYTE UNSIGNED BIG-ENDIAN
UINT32_BE(x) = 4 BYTE UNSIGNED BIG-ENDIAN
UINT64_BE(x) = 8 BYTE UNSIGNED BIG-ENDIAN

TEXT_FIELD(x) = UINT32_BE(LEN(UTF8_BYTES(x))) || UTF8_BYTES(x)
ENUM_FIELD(x) = TEXT_FIELD(x)
BYTES_FIELD(x) = UINT32_BE(LEN(x)) || x
HASH32_FIELD(x) = x
UINT64_FIELD(x) = UINT64_BE(x)
UINT16_FIELD(x) = UINT16_BE(x)

PRESENT_OR_ABSENT_TEXT_FIELD(x) = FIELD_ABSENT IF x IS OMITTED ELSE FIELD_PRESENT || TEXT_FIELD(x)
PRESENT_OR_ABSENT_BYTES_FIELD(x) = FIELD_ABSENT IF x IS OMITTED ELSE FIELD_PRESENT || BYTES_FIELD(x)
PRESENT_OR_ABSENT_HASH32_FIELD(x) = FIELD_ABSENT IF x IS OMITTED ELSE FIELD_PRESENT || HASH32_FIELD(x)
PRESENT_OR_ABSENT_UINT64_FIELD(x) = FIELD_ABSENT IF x IS OMITTED ELSE FIELD_PRESENT || UINT64_FIELD(x)

ARRAY_FIELD(e_1, e_2, ..., e_n) = UINT32_BE(n) || e_1 || e_2 || ... || e_n
ARRAY_FIELD() = UINT32_BE(0)
```

```text
DETERMINISTIC_PREDICATE

TEXT_FIELD MUST USE UTF-8 ONLY
ENUM_FIELD MUST USE THE EXACT ENUM LITERAL TEXT ONLY
BYTES_FIELD MUST USE RAW STORED BYTES ONLY
HASH32_FIELD MUST USE EXACTLY 32 BYTES
FIELD OMITTED => FIELD_ABSENT ONLY
FIELD PRESENT => FIELD_PRESENT || ENCODED_VALUE ONLY
SQL NULL, JSON null, EMPTY-STRING SUBSTITUTION, ZERO-VALUE SUBSTITUTION, AND DERIVED FILL-IN ARE FORBIDDEN
```

## 6.1.2 CANONICAL_RECORD_BYTES (MANDATORY)

```text
PURE_ASSIGNMENT

canonical_record_bytes =
  ASCII_BYTES("mishka.partition_record.v1") ||
  ENUM_FIELD(record_type) ||
  TEXT_FIELD(record_version) ||
  UINT64_FIELD(partition_id) ||
  UINT64_FIELD(partition_epoch) ||
  UINT64_FIELD(partition_record_seq) ||
  BYTES_FIELD(logical_shard_id) ||
  UINT64_FIELD(shard_seq) ||
  UINT16_FIELD(stage_order) ||
  BYTES_FIELD(record_id) ||
  PRESENT_OR_ABSENT_BYTES_FIELD(message_id) ||
  PRESENT_OR_ABSENT_BYTES_FIELD(agent_id) ||
  PRESENT_OR_ABSENT_BYTES_FIELD(boot_session_id) ||
  PRESENT_OR_ABSENT_UINT64_FIELD(logical_clock) ||
  TEXT_FIELD(causal_parent_refs_text) ||
  BYTES_FIELD(canonical_payload_bytes) ||
  HASH32_FIELD(canonical_payload_hash) ||
  PRESENT_OR_ABSENT_HASH32_FIELD(payload_hash) ||
  PRESENT_OR_ABSENT_BYTES_FIELD(signature) ||
  PRESENT_OR_ABSENT_BYTES_FIELD(partition_context) ||
  PRESENT_OR_ABSENT_TEXT_FIELD(schema_version) ||
  PRESENT_OR_ABSENT_HASH32_FIELD(schema_transform_hash)
```

```text
DETERMINISTIC_PREDICATE

canonical_record_bytes FIELD ORDER IS EXACT
canonical_record_bytes CONCATENATION ORDER IS EXACT
canonical_payload_text DOES NOT PARTICIPATE IN canonical_record_bytes
canonical_payload_text, IF STORED, MUST EQUAL RFC 8785 (JCS) OF canonical_payload_bytes-DERIVED JSON FOR ITS RECORD FAMILY
canonical_payload_bytes IS THE ONLY AUTHORITATIVE PAYLOAD BYTE SOURCE FOR record_hash RECONSTRUCTION
```

```text
STATE_TRANSITION

IF ANY REQUIRED FIELD NEEDED BY canonical_record_bytes IS ABSENT:
    REJECT RECORD BUILD -> FAIL-CLOSED -> ALERT
IF previous_record_hash LENGTH != 32:
    REJECT RECORD BUILD -> FAIL-CLOSED -> ALERT
IF canonical_payload_hash LENGTH != 32:
    REJECT RECORD BUILD -> FAIL-CLOSED -> ALERT
IF payload_hash IS PRESENT AND payload_hash LENGTH != 32:
    REJECT RECORD BUILD -> FAIL-CLOSED -> ALERT
IF schema_transform_hash IS PRESENT AND schema_transform_hash LENGTH != 32:
    REJECT RECORD BUILD -> FAIL-CLOSED -> ALERT
```

## 6.2 First Record Rule

For the first committed record in a partition chain:

```text
PURE_ASSIGNMENT

previous_record_hash = ZERO_HASH_32
```

For every later committed record in the same partition chain:

* `previous_record_hash` MUST equal the immediately preceding committed `record_hash`

## 6.2.1 RECORD_HASH_CONSTRUCTION (MANDATORY)

```text
PURE_ASSIGNMENT

record_hash_input_bytes = previous_record_hash || canonical_record_bytes
record_hash = SHA256(record_hash_input_bytes)
```

```text
DETERMINISTIC_PREDICATE

previous_record_hash INPUT ORDER MUST PRECEDE canonical_record_bytes EXACTLY
ZERO_HASH_32 IS THE ONLY VALID GENESIS previous_record_hash VALUE
FOR partition_record_seq > 1:
    previous_record_hash MUST EQUAL THE IMMEDIATELY PRECEDING COMMITTED record_hash IN THE SAME partition_id
```

```text
STATE_TRANSITION

IF partition_record_seq = 1 AND previous_record_hash != ZERO_HASH_32:
    REJECT RECORD BUILD -> FAIL-CLOSED -> ALERT
IF partition_record_seq > 1 AND previous_record_hash DOES NOT EQUAL THE IMMEDIATELY PRECEDING COMMITTED record_hash:
    REJECT RECORD BUILD -> FAIL-CLOSED -> ALERT
```

## 6.3 Tamper Detection Rule

Any change to:

* `canonical_payload_text`
* `canonical_payload_hash`
* partition metadata
* causal references
* append order
* `previous_record_hash`

MUST change `record_hash`.

Undetectable mutation is FORBIDDEN.

## 6.4 Batch Commit Rule

Every committed partition batch MUST produce one `batch_commit_record`.

The exact executable batch grammar is mandatory.

`batch_commit_record` MUST include:

```json
{
  "signing_context": "batch_commit_record_v1",
  "key_id": "hex_32_bytes",
  "key_epoch": "uint32",
  "execution_context_hash": "hex_32_bytes",
  "signature": "hex_ed25519"
}
```

Failure:

```text
SIGNATURE_INVALID -> REJECT -> FAIL-CLOSED -> ALERT
```

## 6.4.1 BATCH LEAF ORDER AND RANGE VALIDITY (MANDATORY)

```text
GLOBAL_INVARIANT

EMPTY_BATCH = FORBIDDEN
NON_CONTIGUOUS_BATCH_RANGE = FORBIDDEN
MIXED_EXECUTION_CONTEXT_WITHIN_BATCH = FORBIDDEN
```

```text
DETERMINISTIC_PREDICATE

ordered_batch_records = partition_records IN ASCENDING partition_record_seq
WHERE first_partition_record_seq <= partition_record_seq <= last_partition_record_seq

record_count = last_partition_record_seq - first_partition_record_seq + 1
first_record_hash = ordered_batch_records[0].record_hash
last_record_hash = ordered_batch_records[record_count - 1].record_hash
ALL ordered_batch_records.execution_context_hash MUST EQUAL batch_commit_records.execution_context_hash
```

```text
STATE_TRANSITION

IF record_count = 0:
    REJECT BATCH -> FAIL-CLOSED -> ALERT
IF batch RANGE IS NOT CONTIGUOUS IN partition_record_seq:
    REJECT BATCH -> FAIL-CLOSED -> ALERT
IF ANY record_hash LENGTH != 32:
    REJECT BATCH -> FAIL-CLOSED -> ALERT
```

## 6.4.2 BATCH_ROOT_HASH (MANDATORY)

```text
PURE_ASSIGNMENT

leaf_input_bytes_i =
  ASCII_BYTES("mishka.batch_leaf.v1") ||
  UINT64_FIELD(partition_record_seq_i) ||
  HASH32_FIELD(record_hash_i)

leaf_hash_i = SHA256(leaf_input_bytes_i)

inner_node_bytes(left_hash, right_hash) =
  ASCII_BYTES("mishka.batch_node.v1") ||
  HASH32_FIELD(left_hash) ||
  HASH32_FIELD(right_hash)

parent_hash(left_hash, right_hash) = SHA256(inner_node_bytes(left_hash, right_hash))
```

```text
DETERMINISTIC_PREDICATE

LEAF ORDER MUST EQUAL ASCENDING partition_record_seq ONLY
ODD-LEAF HANDLING = DUPLICATE THE LAST HASH AT THAT TREE LEVEL AS THE RIGHT CHILD
SINGLETON BATCH ROOT = leaf_hash_1
batch_root_hash = THE UNIQUE FINAL parent_hash PRODUCED BY RECURSIVE LEVEL REDUCTION
```

```text
STATE_TRANSITION

IF batch_root_hash CANNOT BE RECONSTRUCTED UNIQUELY FROM THE COMMITTED RANGE:
    FAIL-CLOSED -> ALERT
```

## 6.4.3 BATCH_COMMIT_HASH (MANDATORY)

```text
PURE_ASSIGNMENT

previous_batch_commit_hash = ZERO_HASH_32 IF batch_commit_seq = 1 ELSE IMMEDIATELY PRECEDING COMMITTED batch_commit_hash IN THE SAME partition_id

batch_commit_hash_payload_bytes =
  ASCII_BYTES("mishka.batch_commit_hash.v1") ||
  UINT64_FIELD(partition_id) ||
  UINT64_FIELD(partition_epoch) ||
  UINT64_FIELD(batch_commit_seq) ||
  UINT64_FIELD(first_partition_record_seq) ||
  UINT64_FIELD(last_partition_record_seq) ||
  UINT64_FIELD(record_count) ||
  HASH32_FIELD(first_record_hash) ||
  HASH32_FIELD(last_record_hash) ||
  HASH32_FIELD(batch_root_hash) ||
  HASH32_FIELD(previous_batch_commit_hash) ||
  HASH32_FIELD(execution_context_hash)

batch_commit_hash = SHA256(batch_commit_hash_payload_bytes)
```

```text
DETERMINISTIC_PREDICATE

batch_commit_hash FIELD ORDER IS EXACT
batch_commit_hash INPUT FRAMING IS EXACT
execution_context_hash PARTICIPATES IN batch_commit_hash EXACTLY ONCE
```

```text
STATE_TRANSITION

IF previous_batch_commit_hash LENGTH != 32:
    REJECT BATCH -> FAIL-CLOSED -> ALERT
IF execution_context_hash LENGTH != 32:
    REJECT BATCH -> FAIL-CLOSED -> ALERT
IF batch_commit_seq = 1 AND previous_batch_commit_hash != ZERO_HASH_32:
    REJECT BATCH -> FAIL-CLOSED -> ALERT
IF batch_commit_seq > 1 AND previous_batch_commit_hash DOES NOT EQUAL THE IMMEDIATELY PRECEDING COMMITTED batch_commit_hash:
    REJECT BATCH -> FAIL-CLOSED -> ALERT
```

## 6.4.4 BATCH_COMMIT_SIGNATURE_PAYLOAD_BYTES (MANDATORY)

```text
PURE_ASSIGNMENT

batch_commit_signature_payload_json = RFC 8785 (JCS)({
  "batch_commit_seq": batch_commit_seq,
  "batch_root_hash": HEX_LOWER(batch_root_hash),
  "execution_context_hash": HEX_LOWER(execution_context_hash),
  "first_partition_record_seq": first_partition_record_seq,
  "first_record_hash": HEX_LOWER(first_record_hash),
  "last_partition_record_seq": last_partition_record_seq,
  "last_record_hash": HEX_LOWER(last_record_hash),
  "partition_epoch": partition_epoch,
  "partition_id": partition_id,
  "previous_batch_commit_hash": HEX_LOWER(previous_batch_commit_hash),
  "record_count": record_count
})

batch_commit_signature_payload_bytes = UTF8_BYTES(batch_commit_signature_payload_json)
```

```text
DETERMINISTIC_PREDICATE

batch_commit_signature_payload_json KEY SET IS EXACT
batch_commit_signature_payload_json KEY ORDER IS THE RFC 8785 CANONICAL LEXICOGRAPHIC ORDER OF THE EXACT KEYS ABOVE
NO EXTRA KEY IS PERMITTED
NO MISSING KEY IS PERMITTED
ALL BYTE ARRAYS IN batch_commit_signature_payload_json MUST USE LOWERCASE HEX ASCII WITHOUT 0x PREFIX
```

The batch commit record is the authoritative commit boundary.

No record in that batch is authoritative until the batch commit record is durable.

EXECUTION_CONTEXT_LOCK (CRITICAL):

execution_context_hash = SHA256(
  policy_snapshot_hash ||
  model_snapshot_hash ||
  config_snapshot_hash ||
  shard_config_hash ||
  schema_version_set
)

## 🔴 VECTOR_CONTEXT_BINDING (PRD-22 ALIGNMENT) (CRITICAL)

All vector operations MUST bind to the committed `execution_context_hash`.

Additional required inputs:

* `embedding_model_id`
* `tokenizer_version`
* `index_snapshot_id`

Updated construction:

```text
execution_context_hash = SHA256(
  policy_snapshot_hash ||
  model_snapshot_hash ||
  config_snapshot_hash ||
  shard_config_hash ||
  schema_version_set ||
  chaos_matrix_snapshot_hash ||
  embedding_model_id ||
  tokenizer_version ||
  index_snapshot_id
)
```

Mandatory:

* the PRD-22 vector inputs MUST be taken from committed PRD-13 / PRD-15 replay data only
* `embedding_model_id`, `tokenizer_version`, and `index_snapshot_id` MUST exist as committed PRD-13 replay-visible values before any batch may bind them into `execution_context_hash`
* mismatch in any vector context input MUST invalidate the batch execution context
* replay MUST NOT substitute latest or default vector components

Mandatory:

* store `execution_context_hash` in every `batch_commit_record`
* a partition MUST NOT commit a batch containing mixed execution contexts
* mixed-context execution within a partition is FORBIDDEN
* silent config switching is FORBIDDEN

ENFORCEMENT:

If an incoming event references a different `execution_context_hash` than the active partition context:

```text
HALT PARTITION
→ FAIL-CLOSED
→ ALERT
```

## 6.5 Segment Manifest Rule

Every closed immutable segment MUST have one deterministic `segment_manifest` containing:

* `partition_id`
* `segment_id`
* `first_partition_record_seq`
* `last_partition_record_seq`
* `first_record_hash`
* `last_record_hash`
* `record_count`
* `segment_root_hash`
* `manifest_hash`

Segment manifests MUST be append-only and immutable.

---

# 7. PARTITION-ALIGNED STORAGE (CRITICAL)

## 7.1 Exact Partition Alignment Rule

Storage MUST align exactly with execution partitions defined by PRD-02.

The following are mandatory:

* every authoritative record is assigned to exactly one physical partition
* every authoritative record belongs to exactly one logical shard within the active partition epoch
* every partition maintains an independent append-only log
```text
GLOBAL ORDER RECONSTRUCTION LAW:

THERE IS NO SINGLE GLOBAL LINEAR ORDER ACROSS PARTITIONS.

AUTHORITATIVE ORDER IS:

WITHIN PARTITION:
  (partition_epoch, partition_record_seq)

CROSS PARTITION:
  NO ORDERING GUARANTEE

GLOBAL DATASET ORDER:
  SET OF INDEPENDENT PARTITION-ORDERED STREAMS
```
* no authoritative write may require a globally serialized writer

## 7.2 Partition Writer Rule

For each physical partition:

* there MUST be exactly one active append writer authorized to commit authoritative records at a time
* multiple physical partitions MAY commit in parallel
* one partition failure MUST NOT invalidate unrelated partitions

Cross-partition write ambiguity is FORBIDDEN.

## 7.3 Authoritative Order Rule

Within one logical shard, authoritative source order is:

```text
(partition_epoch, logical_shard_id, shard_seq)
```

Within one physical partition log, authoritative append order is:

```text
partition_record_seq
```

The storage layer MUST preserve both.

For each `(agent_id, boot_session_id)` represented by stored `signal_record` rows, the following are mandatory:

* records MUST be stored in `logical_clock` order
* the first stored record for that tuple MUST have `logical_clock = 0`
* each next stored record for that tuple MUST have `logical_clock = previous logical_clock + 1`
* insertion MUST fail if the ordering constraint is violated

Out-of-order `signal_record` insertion is:

```text
REJECT
```

## 7.4 Storage Placement Rule

The following placement rules are mandatory:

* `signal_record` placement MUST derive from the authoritative routed signal partition metadata
* `detection_record` placement MUST equal the partition placement of the referenced signal window
* `decision_record` placement MUST equal the partition placement of the referenced `detection_record`
* `safety_evaluation_record` placement MUST equal the partition placement of the referenced `decision_record`
* `action_record` placement MUST equal the partition placement of the referenced `safety_evaluation_record`
* `execution_result_record` placement MUST equal the partition placement of the referenced `action_record`
* `rollback_record` placement MUST equal the partition placement of the referenced `execution_result_record`

Executor routing MUST NOT change storage partition placement.

## 7.5 Cross-Partition Rule

Cross-partition relationships MAY exist only through explicit causal references stored in canonical payloads.

The following are FORBIDDEN in authoritative storage:

* cross-partition append transactions for unrelated partitions
* synthetic global sequence numbers
* global total-order requirements for correctness

---

# 8. WRITE PATH (STRICT ORDERING)

## 8.1 Strict Write Order Law

For one causal execution chain, authoritative storage order MUST be:

```text
signal -> detection -> decision -> safety_evaluation -> action -> execution_result -> rollback
```

ROLLBACK_OVERRIDE placement rule (CRITICAL):

* `ROLLBACK_OVERRIDE` records are out-of-band control-plane integrity records
* they MUST NOT alter the core causal execution chain ordering above
* they MUST be appended only after `ESCALATED_CRITICAL` conditions exist and MUST be linked explicitly to a specific `execution_id`
* they MUST NOT permit skipping any replay validation, audit requirements, or policy re-evaluation

Out-of-order writes are:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

## 8.2 Conditional Termination Rule

## 🔴 COMMIT GROUP COMPLETION LAW (CRITICAL)

Each `message_id` defines EXACTLY ONE commit group.

A commit group is COMPLETE only when ONE of the following terminal states is reached:

1. `ACTION_EXECUTED`
2. `POLICY_DENIED`
3. `APPROVAL_PENDING`
4. `ROLLBACK_TERMINAL`
5. `NO_ACTION_DEFERRED_RESOLVED`

RULES:

* partial chains are FORBIDDEN
* early termination MUST still produce one explicit terminal record
* `commit_group_status` MUST be stored explicitly in `commit_groups`

FORBIDDEN:

* implicit termination
* missing terminal state
* missing `commit_group_status`

If the authoritative upstream pipeline terminates earlier, no downstream storage record may exist.

The following are mandatory:

* if no `detection_event` exists, no `detection_record` may be written
* if no `action_decision` exists, no `decision_record` may be written
* if no `safety_evaluation` exists, no `safety_evaluation_record`, `action_record`, `execution_result_record`, or `rollback_record` may be written
* if `decision = DENY`, no `action_record`, `execution_result_record`, or `rollback_record` may be written
* if `decision_type = PENDING_APPROVAL`, no `action_record`, `execution_result_record`, or `rollback_record` may be written until a separate authoritative downstream action object exists
* if `safety_result != ALLOW`, no `action_record`, `execution_result_record`, or `rollback_record` may be written
* if `rollback_defined = FALSE`, no `action_record`, `execution_result_record`, or `rollback_record` may be written
* if `action_record` does not exist, no `execution_result_record` or `rollback_record` may be written
* if `execution_result_record` does not exist, no `rollback_record` may be written
* every terminated chain MUST end with one explicit `commit_group_status` in `commit_groups`
* if no terminal record exists, the entire chain MUST be rejected

## 🔴 EDGE CASE HANDLING LAW (CRITICAL)

CASE 2: SAME `message_id` WITH DIFFERENT BYTES

```text
INTEGRITY VIOLATION
→ GLOBAL HALT
```

CASE 4: DUPLICATE MESSAGE WITH DIFFERENT ORDER

```text
REJECT SECOND MESSAGE
→ FAIL-CLOSED
→ ALERT
```

## 8.3 Mandatory Write Sequence

The authoritative write sequence for a committed partition batch is:

```text
1. verify upstream payload integrity and partition placement
2. canonicalize payload text
3. compute canonical_payload_hash
4. allocate next partition_record_seq
5. compute previous_record_hash
6. compute record_hash
7. append record to partition_records
8. repeat in strict stage order for all records in the batch
9. compute `batch_root_hash` and `batch_commit_hash`
10. sign `batch_commit_record`
11. append batch_commit_record
12. fsync
13. mark commit successful
14. commit partition offset only after storage commit success
```

No step may be skipped, reordered, or bypassed.

## 🔴 END-TO-END CHECKSUM CHAIN (CRITICAL)
RULE

Every stage MUST include:

transport_checksum
storage_checksum
processing_checksum
VALIDATION
IF checksum mismatch at ANY stage:

    REJECT → FAIL-CLOSED → ALERT
PURPOSE
detect corruption BEFORE canonical hashing

For `signal_record`, the following write-time validations are mandatory before authoritative append:

* recompute `payload_hash` from stored `canonical_payload_bytes`
* recompute `message_id` using the PRD-03 construction over `canonical_payload_bytes`, `identity_bytes`, `partition_context`, `boot_session_id`, and `logical_clock_bytes`
* verify `schema_version` membership in the active signed `signal_schema_version_set` (PRD-07)
* verify signature using:

```text
signing_input =
  signing_context ||
  payload_hash ||
  identity_bytes ||
  partition_context ||
  boot_session_id ||
  logical_clock_bytes
```

Any mismatch in `payload_hash`, `message_id`, `schema_version` membership, or signature MUST be rejected before record append.

## 8.4 Atomic Write Model

Each write MUST be:

* atomic
* durable
* visible only after commit

Crash MUST NOT produce:

* partial records
* broken chains
* visible uncommitted records

## 8.5 Commit Boundary Rule

The authoritative processing boundary is:

```text
storage_commit_success -> partition_offset_commit
```

Partition offsets MUST NOT advance before storage commit succeeds.

```text
DECOUPLED COMMIT MODEL:

INGEST ACK CONDITION:

ACK AFTER:
- durable queue persistence (PRD-02 Queue layer)

NOT AFTER:
- PRD-13 batch_commit

PRD-13 latency MUST NOT directly terminate ingest connections.
```

## 8.6 Failure Rule

Any failure during validation, hash construction, chain linkage, insert, commit-boundary creation, or fsync is:

```text
ROLLBACK -> REJECT -> FAIL-CLOSED -> ALERT
```

---

# 9. READ PATH (DETERMINISTIC)

## 9.1 Authoritative Read Rule

Authoritative reads MUST consume only:

* committed `partition_records`
* committed `batch_commit_records`
* committed `authority_snapshots`
* committed `segment_manifests`
* committed `retention_proofs`

Uncommitted, partially verified, or projection-only data is not authoritative.

## 9.2 Deterministic Partition Read Order

Within one partition, authoritative read order is:

```text
partition_record_seq ASC
```

For stored `signal_record` replay and forensic reconstruction, authoritative read order MUST be:

```text
ORDER BY (agent_id, boot_session_id, logical_clock ASC)
```

No alternative ordering is allowed for `signal_record` replay.

Time-based ordering is FORBIDDEN.

If a deterministic stage-aware replay view is required within one partition, the comparison order MUST be:

```text
(partition_epoch, logical_shard_id, shard_seq, stage_order, partition_record_seq)
```

## 9.3 Cross-Partition Read Rule

There is no authoritative global read order across unrelated partitions.

Cross-partition reads for audit or replay comparison MUST depend only on:

* explicit causal metadata
* partition identifiers
* logical shard identifiers
* shard sequence metadata

Arrival order, scheduler order, and replica response order MUST NOT affect authoritative reads.

## 9.4 Verification-Before-Read Rule

Before treating any read result as authoritative, the system MUST verify:

* `canonical_payload_hash`
* `record_hash`
* `previous_record_hash` continuity
* enclosing `batch_commit_record`
* `batch_commit_hash`
* batch commit signature
* `manifest_hash` when a closed segment is involved
* `proof_hash` when a retention proof is involved
* required authority snapshot availability

Reads that bypass verification are FORBIDDEN.

## 9.5 Read Isolation Rule

The following are mandatory:

* UI-facing systems MUST NOT read the authoritative database directly without the verification layer
* deterministic query services MAY expose verified projections only
* projections MUST be rebuildable from authoritative storage

---

# 10. INDEXING MODEL

## 10.1 Indexing Law

Indexes MUST:

* NOT be authoritative
* be rebuildable from storage
* NOT affect determinism

Indexes MUST NOT modify canonical data.

The only exception is mandatory signal-record identity and ordering constraints, which MAY be materialized as storage-layer indexes because they enforce PRD-03, PRD-07, and PRD-08 write correctness directly.

## 10.2 Primary Authoritative Keys

The authoritative primary keys are:

* `(partition_id, partition_record_seq)` for `partition_records`
* `(partition_id, batch_commit_seq)` for `batch_commit_records`
* `(authority_type, authority_id, authority_version)` for `authority_snapshots`
* `(partition_id, segment_id)` for `segment_manifests`
* `(partition_id, retention_proof_id)` for `retention_proofs`

For stored `signal_record` rows, the authoritative signal identity primary key is:

```text
(message_id)
```

This signal identity primary key does not replace the physical append-log primary key `(partition_id, partition_record_seq)`.

## 10.3 Allowed Derived Index Families

The following derived index families are allowed:

* `record_type`
* `record_id`
* `message_id`
* `(agent_id, boot_session_id, logical_clock)`
* `logical_shard_id`
* `shard_seq`
* `signal_type`
* `entity_key`
* `detection_id`
* `decision_id`
* `action_id`
* `execution_id`
* `policy_id`
* `policy_version`
* `route_id`
* `executor_id`
* `coverage_state`

All such indexes MUST be derivable only from committed authoritative records.

For stored `signal_record` rows, the following index is mandatory:

```text
(agent_id, boot_session_id, logical_clock)
```

The following constraint is mandatory:

```text
UNIQUE(agent_id, boot_session_id, logical_clock)
```

This constraint enforces storage-layer ordering integrity and insertion determinism for `signal_record`.

### 10.3.1 Asset Intelligence Indexes (PRD-23) (DERIVED ONLY)

The system MUST provide derived (rebuildable) indexes on:

* `entity_key` extracted from:
  * `signal_record.canonical_payload_text`
  * `ui_action_record.canonical_payload_text` (ENTITY_REGISTRY payloads)
* `coverage_state` extracted from `infrastructure.asset_coverage.v1` signal payloads
* `signal_type`

CRITICAL RULE:

```text
Indexes MUST be fully rebuildable from canonical_payload_text.
Indexes MUST NOT become a source of truth.
```

No asset-intelligence index may be required as the sole source of truth for replay or forensic reconstruction.

## 10.4 Projection Rule

JSONB, materialized views, search indexes, incident graphs, and analytical tables MAY exist only as derived projections.

## VECTOR_STORAGE_ALIGNMENT (CRITICAL)

Every index_snapshot_id MUST map to:

vector_segment_manifest

---

vector_segment_manifest MUST include:

- vector_ids
- corresponding record_ids
- storage_tier_location (HOT/WARM/COLD)

---

RULE:

If referenced record is in COLD:

system MUST:

→ prefetch into WARM cache deterministically

---

TIMEOUT RULE:

RAG retrieval MUST NOT depend on real-time fetch

---

FAILURE:

missing underlying record:

→ REJECT VECTOR QUERY
→ FAIL-CLOSED

---

VECTOR_INDEX_ORDERING_RULE (CRITICAL)

All vector_ids within index_snapshot_id MUST be ordered.

---

ORDER:

vector_ids MUST be sorted by:

record_hash ASC

---

MANIFEST RULE:

vector_segment_manifest.vector_ids MUST preserve this order

---

HASHING:

index_snapshot_id MUST include ordered vector_ids

---

FORBIDDEN:

unordered vector insertion
non-deterministic ANN rebuild

---

FAILURE:

ordering mismatch:

→ REJECT INDEX
→ FAIL-CLOSED

## VECTOR_PREFETCH_CONTEXT_LOCK (CRITICAL)

Prefetch of COLD → WARM MUST be:

bound to execution_context_hash

---

RULE:

Prefetch MUST occur BEFORE batch execution

AND

prefetched data MUST be included in:

batch execution context

---

FORBIDDEN:

on-demand fetch during query execution

---

FAILURE:

late fetch:

→ REJECT QUERY
→ FAIL-CLOSED

Derived projections MUST NOT:

* introduce new authoritative fields
* repair missing authoritative records
* override canonical payload text
* change authoritative read outcomes

---

# 11. REPLAY SUPPORT (CRITICAL)

## 11.1 Replay Completeness Law

Storage MUST guarantee full deterministic replay of:

```text
signal -> detection -> decision -> safety_evaluation -> action -> execution_result -> rollback
```

### 11.1.1 Asset Coverage Replay Guarantee (PRD-23) (CRITICAL)

Storage MUST additionally guarantee full deterministic reconstruction for PRD-23 asset intelligence using existing record types only:

* `EXPECTED_SET` MUST be reconstructable from committed `UI_ACTION_RECORD` payloads that contain `ENTITY_REGISTRY`
* `OBSERVED_SET` MUST be reconstructable from committed `signal_record` rows whose `signal_type` proves observation (including `infrastructure.asset_observed.v1` and its proving references)
* `MANAGED_SET` MUST be reconstructable from committed `signal_record` rows with `signal_type = infrastructure.asset_managed_binding.v1`

Coverage state MUST be derivable from stored records alone.

Derived-only truth is forbidden:

* indexes MUST NOT become the source of truth
* projections MUST NOT become the source of truth
* caches MUST NOT become the source of truth

If required PRD-23 asset-intelligence records are missing for the declared replay scope:

```text
FAIL-CLOSED -> ALERT
```

Replay completeness requires all of the following to be durably available:

* every committed `signal_record`
* every committed `detection_record`
* every committed `decision_record`
* every committed `safety_evaluation_record`
* every committed `action_record`
* every committed `execution_result_record`
* every committed `rollback_record`
* every referenced signed authority snapshot required by the replayed records, including configuration, policy, model, shard configuration, route mapping, parameter profiles, adapter manifests, capability descriptors, and retention configuration where applicable
* every required `batch_commit_record`

Missing record = INTEGRITY_FAILURE.

Storage MUST additionally guarantee for every `(agent_id, boot_session_id)` represented by stored `signal_record` rows:

* no gaps in `logical_clock` sequence
* no duplicate `logical_clock`

Any violation is:

```text
INTEGRITY_FAILURE
```

## 11.2 Replay Dataset Rule

The authoritative replay dataset for one partition is:

* committed partition records in ascending `partition_record_seq`
* the corresponding batch commit chain
* the referenced authority snapshots
* the referenced segment manifests and retention proofs, if any historical segments were pruned

## 🔴 MULTI-REGION REPLAY BACKUP (CRITICAL)
RULE

Authoritative dataset MUST be replicated to:

>= 2 independent failure domains
REQUIREMENTS

Each replica MUST preserve:

- canonical bytes
- partition order
- batch_commit_records
- authority_snapshots
VALIDATION
replica_hash = SHA256(all_committed_records)

replicas MUST match
FAILURE RULE
IF primary dataset corrupted:

    replay MUST be executed from replica

IF replica mismatch:

    FAIL-CLOSED → ALERT
HARD LAW
NO SINGLE STORAGE FAILURE MAY MAKE REPLAY IMPOSSIBLE

REDACTION_REPLAY_COMPATIBILITY (MANDATORY):

* the dataset MUST include committed `REDACTION` records
* replay MUST apply redaction overlays deterministically
* redaction overlay application order MUST be:

```text
ORDER BY partition_record_seq ASC
```

For `signal_record` replay, the authoritative dataset MUST be read in:

```text
ORDER BY (agent_id, boot_session_id, logical_clock ASC)
```

## 11.3 Replay Equality Rule

For the same partition input stream, the same partition epochs, and the same referenced authority snapshots, replay MUST produce:

```text
bit-for-bit identical partition-local outputs
```

For the same ingest stream, storage MUST also produce identical:

* record layout
* ordering
* index state

## 11.4 Replay Invalidators

The following invalidate replay correctness:

* missing authoritative record
* missing authority snapshot
* chain discontinuity
* hash mismatch
* out-of-order record
* `logical_clock` gap within one `(agent_id, boot_session_id)` session
* duplicate `logical_clock` within one `(agent_id, boot_session_id)` session
* offset committed before storage commit success
* partition ambiguity

Any replay invalidator is:

```text
FAIL-CLOSED -> ALERT
```

## 11.5 Rebuild Rule

All non-authoritative indexes and projections MUST be rebuildable from authoritative storage alone.

If an index cannot be rebuilt from authoritative storage, that index model is invalid.

---

# 12. RETENTION & COMPACTION

## 12.1 Retention Authority Rule

Retention MUST be deterministic.

Retention execution MUST depend only on:

* signed retention configuration
* immutable segment manifests
* immutable batch commit chain

Ad hoc deletion is FORBIDDEN.

## 12.2 Tier Retention Rule

Tier retention is mandatory:

* HOT retains recent operational records
* WARM retains deterministic indexes and replay-support projections
* COLD retains immutable WORM historical segments

Retention windows MUST be controlled only by signed configuration.

## 12.3 Deterministic Compression Rule

The following are mandatory:

* deterministic compression ONLY
* compression MUST be reversible
* lossy compression is FORBIDDEN

## 12.4 Compaction Rule

Authoritative per-record compaction is FORBIDDEN.

Authoritative retention MUST use closed-segment pruning only.

The following sequence is mandatory:

```text
1. close immutable segment
2. persist segment_manifest
3. persist retention_proof referencing the segment manifest and chain endpoints
4. verify retention eligibility from signed configuration
5. prune the entire closed segment
```

Deletion MUST NOT break chain verifiability.

## 12.5 Retention Proof Rule

Every pruned segment MUST leave one immutable `retention_proof` containing:

* `partition_id`
* `segment_id`
* `first_record_hash`
* `last_record_hash`
* `segment_root_hash`
* `record_count`
* `retention_rule_id`
* `proof_hash`

If preserved integrity proof does not exist, pruning is FORBIDDEN.

---

# 13. FAILURE MODEL

The following fail-closed conditions are mandatory:

* missing required field -> `REJECT`
* index violation -> `REJECT`
* ordering violation -> `REJECT`
* hash mismatch -> `REJECT`
* signature mismatch -> `REJECT`

## 13.1 Disk Full

If authoritative capacity is exhausted:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

Best-effort dropping is FORBIDDEN.

---

## 🔴 OVERFLOW_ESCROW_LAYER (MANDATORY) (CRITICAL)
WHEN:

```text
storage_usage >= HARD_STOP_THRESHOLD
```

SYSTEM MUST:

→ redirect writes to `ESCROW_STORAGE`

ESCROW_STORAGE REQUIREMENTS (MANDATORY):

- append-only
- cryptographically hashed
- NOT part of PRD-13 authoritative state
- MUST preserve canonical bytes

RECOVERY RULE (MANDATORY):

When capacity restored:

→ ESCROW → replay ingest → PRD-13 commit

---

## 🔴 ESCROW_CAPACITY_EXHAUSTION (MANDATORY) (INFRA-05)

HARD LAW (MANDATORY):

```text
NO SIGNAL MAY EXIST WITHOUT:
- durable storage
OR
- durable escrow
```

IF (MANDATORY):

```text
storage_unavailable == TRUE
AND escrow_unavailable == TRUE
```

THEN (MANDATORY):

```text
SYSTEM MUST ENTER: PARTITION_SIGNAL_REJECTION_MODE
```

PARTITION_SIGNAL_REJECTION_MODE RULES (MANDATORY):

* NO NEW `SIGNAL` RECORDS ACCEPTED for the affected partition/scope
* CRITICAL signals MUST NOT be accepted without a persistence guarantee
* the system MUST return:

```json
{
  "status": "REJECTED",
  "reason": "NO_DURABLE_CAPACITY"
}
```

* the system MUST emit a CRITICAL alert

### 🔴 SCOPE LIMITATION LAW (CRITICAL)
This rejection mode MUST be scope-limited.

Mandatory:
* a storage/escrow outage affecting one partition MUST NOT force global rejection for unrelated partitions
* rejection MUST occur only for the partitions/scopes that cannot provide a persistence guarantee

Global halt due to a partition-local storage condition is FORBIDDEN (Section 13.6).

---

## 🔴 NO MEMORY-ONLY BUFFERING FOR CRITICAL SIGNALS (HARD LAW)
CRITICAL signals MUST NOT be buffered only in memory beyond bounded transport framing buffers.

Violation:

```text
FAIL-CLOSED
```

---

## 🔴 ESCROW_INTEGRITY_RULE (MANDATORY) (INFRA-05)

All escrow records MUST include (MANDATORY):

* `canonical_payload_bytes`
* `payload_hash`
* `message_id`

Escrow hashing rule (MANDATORY):

```text
escrow_hash = SHA256(canonical_payload_bytes)
```

Recovery ingestion rule (MANDATORY):

```text
ON RECOVERY:
→ escrow records MUST pass through PRD-08 validation again
→ escrow records MUST NOT bypass ingest pipeline
```

## 🔴 ESCROW RECONCILIATION PROTOCOL (CRITICAL)

ESCROW_HANDOFF_ID = SHA256(
  message_id ||
  escrow_origin_id
)

RULES:

1. Edge escrow MUST include escrow_origin_id
2. Storage MUST maintain:

escrow_dedup_index(ESCROW_HANDOFF_ID)

---

ON INGEST:

IF EXISTS:
→ DROP (duplicate)

ELSE:
→ ACCEPT

---

REPLAY LAW:

Dedup MUST be deterministic and replay-reconstructable

## 🔴 ESCROW_REPLAY_ALIGNMENT (MANDATORY)

ESCROW_HANDOFF_ID MUST be inserted into:

replay_guard (PRD-13)

KEY:

(partition_id, logical_shard_id, ESCROW_HANDOFF_ID)

---

RULE:

Escrow dedup MUST reuse replay_guard semantics

---

FORBIDDEN:

separate dedup system outside replay_guard

## 13.2 Corruption

If corruption is detected by hash mismatch, chain discontinuity, or manifest mismatch:

```text
FAIL-CLOSED -> ISOLATE AFFECTED PARTITION OR SEGMENT -> ALERT
```

Silent repair is FORBIDDEN.

## 13.3 Missing Record

If any required authoritative record is missing:

```text
INTEGRITY_FAILURE -> FAIL-CLOSED -> ALERT
```

Synthetic gap filling is FORBIDDEN.

## 13.4 Partial Write

If a crash occurs before durable commit:

* partial records MUST NOT be visible
* incomplete batches MUST NOT be authoritative
* recovery MUST resume from the last durable batch commit boundary only

## 13.5 Node Failure

Node failure MUST NOT cause authoritative data loss.

Recovered copies MUST be exact byte copies of previously committed authoritative segments or batches.

Replica divergence is invalid.

## 13.6 Failure Containment Rule

One partition failure MUST NOT invalidate unrelated partitions.

Global halt for a partition-local storage failure is FORBIDDEN.

---

# 14. PERFORMANCE MODEL

## 14.1 Scaling Law

The system MUST support:

* millions of devices
* multi-datacenter deployment
* partition-local scaling
* bounded CPU and memory usage

Scaling MUST occur by:

* increasing partition count
* increasing storage bandwidth independently of partition execution
* expanding tier capacity independently

## 14.2 Bounded Resource Rule

Per partition batch:

* storage commit cost MUST be bounded and measurable
* CPU usage MUST be bounded by canonicalization, hashing, and commit work for that batch
* memory usage MUST be bounded by the configured maximum batch size and record size limits

Unbounded batch buffering is FORBIDDEN.

## 14.3 Latency Rule

HOT-tier authoritative writes MUST remain below:

```text
10 ms per insert-equivalent authoritative write under nominal operating conditions
```

Storage commit latency MUST be measured per partition batch.

## 14.4 Multi-Datacenter Rule

Multi-datacenter replication MAY distribute committed authoritative copies, but:

* replicas MUST NOT be authoritative before full durable commit and hash verification
* replica arrival order MUST NOT affect authoritative read results
* replica lag MUST NOT create authoritative write ambiguity

---

# 15. SECURITY MODEL

## 15.1 Verify-Before-Store Rule

Only verified data enters authoritative storage.

The following MUST be verified before authoritative storage:

* payload integrity
* required signatures for signed authority objects
* partition placement
* causal references
* hash construction inputs
* recomputed `payload_hash` for `signal_record`
* recomputed `message_id` for `signal_record`
* `schema_version` membership in the active signed `signal_schema_version_set` for `signal_record`
* signature validity for `signal_record`

Unsigned or partially verified authoritative objects are invalid.

For stored `signal_record` writes:

* `payload_hash` mismatch -> `REJECT`
* `message_id` mismatch -> `REJECT`
* signature mismatch -> `REJECT`

## 15.2 Access Control Rule

The following are mandatory:

* RBAC MUST be enforced
* write isolation MUST be enforced by database roles and service identity
* direct writes bypassing the storage layer are FORBIDDEN
* shared superuser access is FORBIDDEN

## 15.3 Encryption Rule

The following are mandatory:

* encryption at rest
* protected key access
* durable signature and hash preservation

Encryption MUST NOT alter canonical payload bytes.

## 15.4 Identity-Binding Rule

Every authoritative runtime record MUST remain identity-bound through storage.

Identity loss at any stage is an integrity failure.

## 15.5 Read Security Rule

The following are mandatory:

* authoritative reads MUST pass through verification
* direct UI database reads are FORBIDDEN
* projections MUST not bypass integrity verification

---

# 16. FORBIDDEN PATTERNS

```text
FORBIDDEN:

- mutable records
- in-place updates
- deleting authoritative records outside deterministic retention execution
- unordered logs
- unordered ingestion into authoritative storage
- cross-partition write ambiguity
- cross-partition global ordering as a correctness requirement
- best-effort writes
- eventual consistency as an authoritative storage model
- async write ambiguity
- visible partial commits
- broken hash chains
- missing batch commit boundaries
- synthetic gap filling
- JSONB as primary authoritative storage
- projections treated as authoritative
- non-deterministic reads
- direct DB writes bypassing the storage layer
- direct UI reads bypassing verification
- unsigned authoritative snapshots
- lossy compression
- in-memory-only authoritative persistence
```

---

# 17. INGEST BUFFER & BACKPRESSURE MODEL (CRITICAL)

## 17.1 Scope Rule

The storage ingest buffer defined in this section is a storage-layer pre-commit buffer.

It MUST exist only after:

* PRD-08 validation succeeds
* PRD-08 replay admission succeeds
* durable queue admission succeeds
* deterministic partition routing succeeds

This buffer MUST NOT replace the authoritative durable queue defined by PRD-08.

## 18.2 Per-Partition Buffer Rule

Each physical partition MUST have exactly one bounded pre-storage ingest buffer.

The per-partition buffer MUST:

* accept only durably admitted partition-routed records
* preserve the authoritative partition order from the durable queue
* remain lossless
* remain partition-local
* support deterministic in-memory buffering and deterministic disk spill

Cross-partition buffer sharing is FORBIDDEN.

## 18.3 Buffer Sequence Rule

Each buffered item MAY receive one partition-local `ingest_buffer_seq` as an internal scheduling aid only.

The following are mandatory:

* `ingest_buffer_seq` MUST be strictly monotonic within one partition when used
* `ingest_buffer_seq` MUST NOT be used for identity, replay admission, or authoritative ordering correctness
* `partition_record_seq` MUST be allocated only at authoritative append time (after verify-before-admit and after replay validation) and remains the authoritative per-partition order key
* `partition_record_seq` MUST NOT be required to equal `ingest_buffer_seq`
* if one buffered item cannot progress, no later buffered item in that partition may become authoritative ahead of it unless the stalled item is explicitly rejected fail-closed

If any gap, duplicate, reordering, or ambiguous mapping is detected:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

## 18.4 Bounded Memory Buffer Rule

Each partition buffer MUST contain:

* one bounded in-memory ring buffer
* one bounded append-only disk spill buffer

The in-memory buffer exists only to reduce commit latency.

The in-memory buffer MUST NOT be authoritative.

## 18.5 Disk Spill Rule

If the in-memory buffer reaches its configured threshold, the excess buffered items MUST spill to disk in deterministic order. If `ingest_buffer_seq` is used, spill order MUST be ascending `ingest_buffer_seq`.

Disk spill MUST satisfy all of the following:

* append-only writes only
* deterministic segment format
* replayable in the deterministic spill order; authoritative replay correctness remains keyed to committed `partition_record_seq`
* exact canonical payload byte preservation
* exact partition metadata preservation
* crash-safe durable visibility after spill commit only

Spill compaction, reordering, or mutation before authoritative storage commit is FORBIDDEN.

## 18.6 Backpressure Rule

If the partition buffer cannot accept additional durably admitted items without violating capacity limits:

```text
THROTTLE -> BACKPRESSURE -> ALERT
```

The following are mandatory:

* upstream producers MUST be backpressured
* records MUST NOT be dropped
* best-effort overflow handling is FORBIDDEN
* overflow signaling MUST be partition-scoped and deterministic

## 🔴 STORAGE BACKPRESSURE PROPAGATION (CRITICAL)
RULE

If storage capacity reaches threshold:

storage_pressure = TRUE
BEHAVIOR
IF storage_pressure:

    ingest_rate MUST be reduced deterministically
    non-critical signals MAY be rejected (by signed priority rules)
PRIORITY LAW
CRITICAL signals MUST NEVER be dropped
LOW priority MAY be dropped deterministically
HARD LAW
NO UNBOUNDED INGEST WHEN STORAGE IS SATURATED

If both memory buffer capacity and disk spill capacity are exhausted:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

## 18.7 Buffer Recovery Rule

After crash recovery, the buffer MUST be reconstructed deterministically from:

* the last durable `batch_commit_record`
* durable spill segments
* WAL-visible but not yet committed storage artifacts

Uncommitted buffered items MAY be reloaded only if they can be proven identical. Ordering for reload MUST be deterministic; if `ingest_buffer_seq` is present, it MUST be used as the deterministic ordering key for reload scheduling only.

If that proof is absent:

```text
DISCARD UNCOMMITTED BUFFER SUFFIX -> FAIL-CLOSED FOR AMBIGUOUS PARTITION -> ALERT
```

---

# 19. CPU & PARALLEL EXECUTION MODEL (CRITICAL)

## 19.1 Pipeline Stage Rule

The storage execution pipeline MUST use the following bounded worker stages:

1. canonicalization workers
2. hashing workers
3. write workers

The stages MAY execute in parallel across unrelated partitions only.

## 19.2 Partition Isolation Rule

The following are mandatory:

* pipeline execution MUST be partition-isolated
* no cross-partition locking is permitted in the authoritative write path
* no partition may depend on scheduler timing of another partition
* one partition failure MUST NOT stall unrelated partitions

The only shared objects permitted across partitions are:

* read-only signed configuration
* read-only code
* bounded worker-pool admission counters

Shared mutable write-path state across partitions is FORBIDDEN.

## STORAGE_WRITER_SHARDING (MANDATORY)

Storage Writer MUST be horizontally sharded.

---

RULE:

Each partition_id MUST map to:

exactly ONE storage_writer_shard

---

SHARDING FUNCTION:

storage_writer_shard_count MUST be loaded from the committed configuration snapshot referenced by `config_snapshot_hash`

writer_shard_id = UINT32_BE(SHA256(UINT64_BE(partition_id))[0:4]) mod storage_writer_shard_count

---

INDEPENDENCE LAW:

Each shard MUST:

- maintain its own batch_commit_records
- maintain its own WAL
- fail independently

---

FAILURE ISOLATION:

If shard S fails:

→ ONLY partitions mapped to S are affected

SYSTEM MUST NOT globally halt

---

FORBIDDEN:

single global writer instance
cross-shard commit dependency

## GLOBAL_ORDER_RECONSTRUCTION (CRITICAL)

There is NO single global linear order across partitions.

`partition_id` is the sole authoritative partition identifier and MUST be globally unique for the active signed partition map.

AUTHORITATIVE ORDER:

* within one partition: `(partition_epoch, partition_record_seq)`
* across partitions: no implicit ordering guarantee

GLOBAL DATASET ORDER:

* replay and export MUST represent the dataset as a set of independent partition-ordered streams

REPLAY LAW:

* replay MUST execute per-partition independently
* cross-partition interactions MUST depend ONLY on:
  * explicit causal references
  * `message_id` links
* cross-partition interactions MUST NOT depend on implicit ordering

FORBIDDEN:

* sorting by `partition_record_seq` globally
* merging partitions into a synthetic total order
* ambiguous ordering keys
* `global_partition_id`
* overlapping `partition_id` across shards

FAILURE:

ordering conflict or synthetic global order requirement:

→ DETERMINISM_VIOLATION
→ FAIL-CLOSED

## SHARD_IDENTITY_LOCK (MANDATORY)

Each storage_writer_shard MUST have:

shard_id (immutable)

---

RULE:

partition_id → shard_id mapping MUST be:

deterministic and stable

---

REPLAY REQUIREMENT:

Replay MUST use same shard mapping

---

FORBIDDEN:

dynamic shard reassignment without replay mapping record

## 19.3 Single-Writer Preservation Rule

Within one partition:

* exactly one write worker MUST hold commit authority at a time
* authoritative visibility and `partition_record_seq` advancement MUST remain single-lane and ordered
* canonicalization and hashing MAY be offloaded to bounded helper workers only for items already assigned immutable deterministic scheduling identifiers; if `ingest_buffer_seq` is used, it MAY serve this scheduling role
* helper workers MUST NOT reorder items, allocate new sequence values, or commit authoritative writes

If helper-worker parallelism would change authoritative ordering or visibility:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

## 19.4 Worker Pool Bound Rule

All worker pools MUST be bounded.

The following pool types are mandatory:

* canonicalization worker pool
* hashing worker pool
* write worker pool

Unbounded worker creation, unbounded task queues, or unbounded memory growth are FORBIDDEN.

## 19.5 CPU Core Pinning Rule

Partition execution MUST use deterministic CPU placement derived from signed storage configuration.

The following construction is mandatory:

```text
cpu_lane_id = partition_id mod cpu_lane_count
```

The following are mandatory:

* the partition coordinator and its active write worker MUST remain pinned to the same `cpu_lane_id` for the life of the active leader epoch
* helper workers for that partition MUST be selected from the same CPU locality group
* lane reassignment during an active leader epoch is FORBIDDEN unless the partition is stopped and recovered at a durable commit boundary

## 19.6 NUMA-Aware Rule

If the host exposes multiple NUMA nodes, storage execution MUST use deterministic NUMA placement.

The following construction is mandatory:

```text
numa_node_id = cpu_lane_id mod numa_node_count
```

The following are mandatory:

* partition-local buffers MUST be allocated from the partition home NUMA node
* canonicalization, hashing, and write workers for that partition MUST execute on the same home NUMA node
* cross-NUMA migration of live partition buffers during an active leader epoch is FORBIDDEN

If NUMA locality cannot be preserved:

```text
THROTTLE -> BACKPRESSURE -> ALERT
```

## 19.7 Per-Partition Concurrency Limits

The following concurrency limits are mandatory per partition:

* maximum active partition coordinator threads = 1
* maximum active write workers = 1
* maximum in-flight canonicalization tasks = 4
* maximum in-flight hashing tasks = 4

These limits are hard limits.

If any limit would be exceeded:

```text
THROTTLE -> BACKPRESSURE -> ALERT
```

If authoritative ordering cannot still be preserved:

```text
FAIL-CLOSED -> ALERT
```

---

# 20. GPU / SIMD ACCELERATION MODEL

## 20.1 Acceleration Modes

The following hash execution modes are authoritative and exhaustive:

* `CPU_SCALAR_SHA256`
* `CPU_SIMD_SHA256`
* `GPU_BATCH_SHA256`

The default compliant mode is `CPU_SCALAR_SHA256`.

`CPU_SIMD_SHA256` and `GPU_BATCH_SHA256` are permitted only as implementation accelerators.

## 20.2 Deterministic Output Rule

Acceleration MUST NOT change:

* canonical input bytes
* hash input ordering
* `canonical_payload_hash`
* `record_hash`
* `batch_root_hash`
* `batch_commit_hash`

For identical input bytes, all acceleration modes MUST produce identical output bytes.

Any output divergence is:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

## 20.3 GPU Batch Hashing Rule

If `GPU_BATCH_SHA256` is enabled and a compatible GPU is available:

* SHA256 batch hashing MAY execute on the GPU
* leaf order MUST equal the deterministic scheduling order used for hashing; if `ingest_buffer_seq` is used, leaf order MUST equal ascending `ingest_buffer_seq`
* GPU execution MUST consume the exact same canonical bytes as CPU execution
* GPU batching MUST NOT merge, split, or reorder authoritative inputs

GPU-specific salts, padding changes, or transport-dependent byte transformations are FORBIDDEN.

---

## ASYNC_HASH_PIPELINE (MANDATORY)
GPU hashing MUST:

- operate in async ring buffer
- never block commit thread

CPU fallback MUST:

- process partial batches
- not stall pipeline

The async hashing pipeline is a performance mechanism only and MUST NOT:

- reorder authoritative inputs
- change any hash output bytes
- alter commit boundary semantics

---

## REDACTED_MATERIALIZED_VIEW (MANDATORY)

- async generated
- eventually consistent
- derived from canonical data

UI MUST READ FROM THIS VIEW.

## 20.4 SIMD Fallback Rule

If GPU acceleration is unavailable, disabled, or fails:

* hashing MUST fall back to `CPU_SIMD_SHA256` when supported
* otherwise hashing MUST fall back to `CPU_SCALAR_SHA256`
* fallback MUST occur before authoritative commit
* fallback MUST preserve the exact same ordered input bytes

Fallback MUST NOT require sequence reallocation or buffer reordering.

## 20.5 Mixed-Mode Verification Rule

Mixed CPU and GPU execution is permitted only if:

* the same canonical bytes are hashed
* the same ordered leaf set is used
* the resulting hashes are bit-for-bit identical

If a GPU-computed hash, SIMD-computed hash, and scalar CPU recomputation disagree:

```text
REJECT BATCH -> FAIL-CLOSED -> ALERT
```

## 20.6 Failure Rule

GPU driver instability, timeout, partial DMA copy, or incomplete batch result MUST be treated as accelerator failure.

In that case:

* authoritative commit for the affected batch MUST pause
* the batch MUST be recomputed on CPU deterministically
* the GPU result MUST NOT be committed

If CPU recomputation cannot complete successfully:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

---

# 21. CRASH RECOVERY MODEL (CRITICAL)

## 21.1 Recovery Scope Rule

Crash recovery MUST execute independently per partition.

Recovery of one partition MUST NOT require unrelated partitions to stop, except where a shared integrity dependency is proven broken.

## 21.2 Mandatory Recovery Sequence

For each affected partition, recovery MUST execute the following order exactly:

```text
1. load last committed batch_commit_record
2. scan WAL and storage ingest buffer state
3. discard uncommitted records and uncommitted buffer entries
4. verify hash chain continuity
5. restore replay_guard state
6. resume from next partition_record_seq
```

No step may be skipped, reordered, or bypassed.

## 21.3 Commit Boundary Rule

The loaded `batch_commit_record` is the only authoritative recovery anchor for that partition.

The following are mandatory:

* all `partition_records` with `partition_record_seq` greater than `last_partition_record_seq` of the last committed `batch_commit_record` MUST be treated as uncommitted
* all buffer items with `ingest_buffer_seq` (if present) greater than that committed boundary MUST be treated as uncommitted
* all uncommitted suffix data MUST be discarded unless re-proven identical and complete under the same deterministic recovery rules

Partial suffix salvage is FORBIDDEN.

## 21.4 Partial Batch Rule

If a crash occurs after one or more records of a batch were written but before the durable `batch_commit_record` exists:

* the partial batch MUST be discarded fully
* none of its records are authoritative
* none of its sequence values may become visible

Partial batch acceptance is FORBIDDEN.

## 21.5 Chain Verification Rule

Recovery MUST verify:

* `previous_record_hash` continuity
* `record_hash` correctness
* `batch_root_hash` correctness
* `batch_commit_hash` correctness
* batch commit signature validity
* segment manifest and retention proof integrity where historical pruning exists

If continuity or verification fails:

```text
FAIL-CLOSED -> ISOLATE AFFECTED PARTITION -> ALERT
```

## 21.6 Replay Guard Recovery Rule

`replay_guard` state MUST be restored to the exact committed state corresponding to the recovered partition boundary.

The following are mandatory:

* replay guard entries beyond the last durable commit boundary MUST be discarded
* replay guard entries required by committed authoritative records MUST be present after recovery
* replay guard restoration MUST NOT admit duplicates already represented by committed authoritative state

If replay guard state is missing, divergent, or ambiguous:

```text
FAIL-CLOSED -> ALERT
```

## 21.7 Resume Rule

After successful recovery:

* `next_partition_record_seq = last_committed_partition_record_seq + 1`
* if `ingest_buffer_seq` is used, `next_ingest_buffer_seq` MUST be strictly monotonic and MUST NOT be required to equal `next_partition_record_seq`
* resumed writes MUST continue on the same verified chain head

Recovery MUST be deterministic.

For identical durable committed state, recovery MUST produce identical resumed state.

## 21.8 State Reconstruction Alignment

Crash recovery MUST implement exact state reconstruction as defined in PRD-15.

The following are mandatory:
* Recovered state MUST be mathematically verifiable as `state_at_t = authority_snapshots + partition_records[0..t]`.
* Replay MUST NOT occur unless the partition can cryptographically prove its `state_at_t` exactly matches the last durable commit boundary.

---

# 22. PARTITION LEADER ELECTION MODEL

## 22.1 Leadership Rule

Single-writer enforcement for each partition MUST be implemented through deterministic leader election.

The following are mandatory:

* exactly one active writer per partition
* the active writer MUST hold the current leadership lease for that partition
* all authoritative writes for that partition MUST be issued only by the active leader

Any write from a non-leader is:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

## 22.2 Consensus Rule

Leader election MUST be determined by deterministic consensus.

CONSENSUS = RAFT (STRICT IMPLEMENTATION)

The consensus mechanism MUST:

* elect at most one leader for a partition at a time
* advance leadership only through a monotonically increasing term or epoch value
* expose a deterministic committed leader state before authorizing writes

Best-effort leader selection is FORBIDDEN.

## 22.3 Leader Epoch Rule

Each elected partition leader MUST hold one monotonic `leader_epoch`.

`leader_epoch` is distinct from `partition_epoch`.

The following are mandatory:

* `leader_epoch` MUST increase on each successful leadership transfer
* one `leader_epoch` MUST authorize at most one active writer for that partition
* a writer from an older `leader_epoch` MUST be fenced immediately

## 22.4 Fencing Token Rule

Each active partition leader MUST hold one monotonic `fencing_token`.

Mandatory construction:

```text
fencing_token = SHA256(partition_id || leader_epoch || leader_id)
```

The `fencing_token` MUST be attached to:

* buffer admission authority
* sequence allocation authority
* spill append authority
* partition append authority
* batch commit authority

The storage engine MUST reject any write carrying:

* a stale `fencing_token`
* a missing `fencing_token`
* an ambiguous `fencing_token`

Such rejection is:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

## 22.5 Split-Brain Rule

If the system detects or cannot rule out split-brain for a partition:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

The following are mandatory:

* no leader may continue authoritative writes under ambiguous quorum
* no stale leader may retain commit authority after fencing
* recovery or re-election MUST resume only from the last durable commit boundary

## 22.6 Leadership Transfer Rule

Leadership transfer for a partition MUST occur only at a durable commit boundary.

The new leader MUST:

* load the last committed `batch_commit_record`
* verify the chain head
* acquire the next valid `leader_epoch`
* acquire the next valid `fencing_token`
* resume from `next_partition_record_seq`

If any transfer precondition fails:

```text
FAIL-CLOSED -> ALERT
```

---

# 23. STORAGE ENGINE ABSTRACTION

## 23.1 Abstraction Rule

The storage layer MUST expose one deterministic storage engine abstraction.

The abstraction MUST preserve identical authoritative semantics for:

* `partition_records`
* `batch_commit_records`
* `authority_snapshots`
* `segment_manifests`
* `retention_proofs`
* `replay_guard`

## 23.2 Mandatory Engine Contract

Every compliant storage engine implementation MUST support all of the following authoritative operations:

* partition-local sequence reservation
* append-only record insertion
* append-only batch commit insertion
* append-only authority snapshot insertion
* append-only segment manifest insertion
* append-only retention proof insertion
* deterministic replay_guard persistence and restoration
* authoritative range reads in deterministic order
* commit-boundary fsync durable flush
* chain and signature verification reads

If an engine cannot satisfy any required operation exactly:

```text
REJECT ENGINE -> FAIL-CLOSED
```

## 23.3 Supported Engines

The default and mandatory reference backend is:

```text
PostgreSQL 16.x
```

Future pluggable engines are permitted only if they preserve:

* identical canonical payload text
* identical authoritative ordering
* identical hash inputs
* identical hash outputs
* identical commit-boundary semantics
* identical replay results

Backend-specific behavior that changes authoritative bytes or ordering is FORBIDDEN.

## 23.4 Backend Determinism Rule

The selected backend MUST NOT affect:

* `canonical_payload_text`
* `canonical_payload_hash`
* `record_hash`
* `batch_root_hash`
* `batch_commit_hash`
* record layout
* partition ordering
* storage index state
* replay outcome

Collation-dependent ordering, implicit type coercion, non-canonical binary encoding, or backend-specific serialization drift is invalid.

## 23.5 Engine Selection Rule

Backend selection MUST be configuration-driven and deterministic.

For a given deployment revision, exactly one backend implementation is authoritative for one partition leader epoch.

Runtime backend switching within an active leader epoch is FORBIDDEN.

If backend identity is ambiguous or mixed for one partition leader epoch:

```text
FAIL-CLOSED -> ALERT
```

---

# 24. FILE & FOLDER STRUCTURE (MANDATORY)

## 24.1 Authoritative Storage Tree

The authoritative storage implementation root MUST be:

```text
/storage/
  /ingest/
    buffer.go
    backpressure.go
  /partition/
    writer.go
    hash_chain.go
    batch_commit.go
  /commit/
  /replay/
    replay_engine.go
    verification.go
  /retention/
    retention_engine.go
    proof_builder.go
  /verification/
    chain_verifier.go
    signature_verifier.go
  /schema/
```

## 24.2 Module Mapping Rule

Every module MUST map to one or more sections of this PRD.

The following mapping is mandatory:

* `/storage/ingest/buffer.go` -> Sections 18, 19, 21, 25
* `/storage/ingest/backpressure.go` -> Sections 18, 25
* `/storage/partition/writer.go` -> Sections 7, 8, 19, 21, 22, 23, 25
* `/storage/partition/hash_chain.go` -> Sections 6, 19, 20, 21, 23
* `/storage/partition/batch_commit.go` -> Sections 6, 8, 20, 21, 22, 23
* `/storage/replay/replay_engine.go` -> Sections 9, 11, 21, 23
* `/storage/replay/verification.go` -> Sections 9, 11, 15, 21, 23
* `/storage/retention/retention_engine.go` -> Sections 12, 13, 23, 25
* `/storage/retention/proof_builder.go` -> Sections 6, 12, 23
* `/storage/verification/chain_verifier.go` -> Sections 6, 9, 11, 15, 21
* `/storage/verification/signature_verifier.go` -> Sections 6, 9, 15, 21

## 24.3 Reserved Directory Rule

The following directories are reserved:

* `/storage/commit/`
* `/storage/schema/`

Until a future signed PRD revision defines files inside them, they MUST remain empty.

## 24.4 Undefined File Rule

No undefined files are allowed under `/storage/`.

Any file not listed in Section 24.1 or not added by a future signed PRD revision is invalid.

The presence of an undefined file is:

```text
REJECT BUILD -> FAIL-CLOSED -> ALERT
```

---

# 25. PERFORMANCE ENFORCEMENT RULES

## 25.1 Hard Limits

The following hard limits are mandatory per partition:

* `MAX_BATCH_RECORD_COUNT = 1024`
* `MAX_BATCH_CANONICAL_BYTES = 8388608`
* `MAX_IN_MEMORY_BUFFER_RECORDS = 8192`
* `MAX_IN_MEMORY_BUFFER_BYTES = 67108864`
* `MAX_DISK_SPILL_RECORDS = 1048576`
* `MAX_DISK_SPILL_BYTES = 8589934592`
* `MAX_HEAD_OF_LINE_BUFFER_LATENCY_MS = 100`
* `MAX_BATCH_COMMIT_LATENCY_MS = 50`
* `MAX_INSERT_EQUIVALENT_WRITE_LATENCY_MS = 10`

Exceeding any hard limit is invalid.

## 25.2 Enforcement Thresholds

The following deterministic threshold levels are mandatory per partition:

* `THROTTLE_THRESHOLD = 80%` of any buffer hard limit or `batch_commit_latency_ms > 25` for 8 consecutive committed batches
* `BACKPRESSURE_THRESHOLD = 90%` of any buffer hard limit or `batch_commit_latency_ms > 50` for 8 consecutive committed batches
* `HARD_STOP_THRESHOLD = 95%` of any buffer hard limit or `head_of_line_latency_ms > 100`

### 🔴 RESERVED_EMERGENCY_CAPACITY (MANDATORY) (CRITICAL)
To prevent availability deadlocks (including break-glass paradoxes), each partition MUST reserve emergency capacity that is not consumed by normal admission.

Mandatory:
* `EMERGENCY_RESERVE = 5%` of each hard buffer limit (records and bytes)
* admission decisions MUST treat `HARD_STOP_THRESHOLD` as the point at which only emergency-class writes may proceed

Emergency-class writes are strictly limited to:
* `ROLLBACK_OVERRIDE` records (PRD-12 / PRD-20)
* `EXECUTION_RESULT` records needed to close an already-started enforcement chain (PRD-12)
* partition-scoped integrity alerts that are required to preserve replay explainability (as explicit records, not best-effort logs)

Forbidden:
* consuming `EMERGENCY_RESERVE` for `SIGNAL` ingestion under routine backpressure
* reclassifying ordinary workloads as emergency to bypass admission control

Threshold evaluation MUST use only measured partition-local counters and committed batch observations.

## 25.3 Enforcement Order

When thresholds are crossed, enforcement MUST occur in the following order:

```text
THROTTLE -> BACKPRESSURE -> ALERT
```

The following are mandatory:

* `THROTTLE` MUST reduce non-authoritative helper-worker admission for the affected partition
* `BACKPRESSURE` MUST stop accepting new storage-buffer items for the affected partition from upstream until the partition returns below the backpressure threshold
* `ALERT` MUST emit a partition-scoped operational integrity alert

If the hard-stop threshold is reached or exceeded:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

## 25.4 Deterministic Measurement Rule

The following are mandatory:

* latency measurement windows MUST be fixed and partition-local
* counters MUST be monotonic within a process lifetime
* restart recovery MUST not invent synthetic latency or buffer history
* enforcement decisions MUST NOT depend on wall-clock branching outside the measured fixed windows

If performance enforcement inputs are missing or ambiguous:

```text
FAIL-CLOSED -> ALERT
```

## 25.5 PRD Alignment Rule

Sections 18 through 25 MUST NOT contradict:

* PRD-02 partition isolation, single active execution lane, and commit-boundary laws
* PRD-08 verify-before-admit, durable queue admission, and deterministic rejection laws
* PRD-12 deterministic execution_result recording laws

If any implementation of Sections 18 through 25 contradicts those laws:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

---

# 26. TIME & CLOCK ISOLATION MODEL

## 26.1 Authoritative Time Rule

Authoritative storage MUST NOT depend on wall-clock time for:

* ordering
* hashing
* record identity
* replay correctness

The following are mandatory:

* wall-clock time MUST NOT influence `partition_record_seq`
* wall-clock time MUST NOT influence `ingest_buffer_seq`
* wall-clock time MUST NOT influence `record_id`
* wall-clock time MUST NOT influence `record_hash`
* wall-clock time MUST NOT influence `batch_root_hash`
* wall-clock time MUST NOT influence `batch_commit_hash`
* wall-clock time MUST NOT influence checkpoint validity
* wall-clock time MUST NOT influence replay outcome

Any implementation that uses wall-clock time in an authoritative storage decision path is invalid.

## 26.2 Allowed Time Usage

Time MAY be used ONLY for:

* performance measurement
* observability
* alerting thresholds

Time MUST NOT influence:

* `partition_record_seq`
* `record_hash`
* `batch_commit_hash`
* replay outcome
* authority election outcome
* replica verification outcome

If time-derived input affects an authoritative output:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

## 26.3 Time Source Rule

All time measurements used by the storage layer MUST use:

* monotonic clock only
* NOT system wall-clock

The following are mandatory:

* monotonic time MAY be sampled only for latency measurement and threshold evaluation
* monotonic time samples MUST NOT be stored as authoritative ordering inputs
* monotonic time resets across process restart MUST NOT alter authoritative state reconstruction

If monotonic clock is unavailable, inconsistent, non-monotonic, or ambiguous:

```text
FAIL-CLOSED -> ALERT
```

## 26.4 Cross-Node Time Independence

Different nodes MAY have different clocks.

Time MUST NOT be used to reconcile:

* ordering
* replication
* authority

Cross-node storage correctness MUST depend only on:

* durable commit boundaries
* leader epoch and fencing state
* hash verification
* signature verification
* deterministic partition-local ordering

Clock skew, NTP drift, leap seconds, or wall-clock rollback MUST have zero effect on authoritative storage outcomes.

---

# 27. CHECKPOINT & SNAPSHOT MODEL (REPLAY ACCELERATION)

## 27.1 Checkpoint Purpose

Checkpoints exist ONLY to accelerate replay.

They MUST NOT replace authoritative records.

The following are mandatory:

* checkpoints are derived, non-authoritative artifacts
* authoritative replay correctness remains defined only by committed storage records, authority snapshots, manifests, and retention proofs
* absence of a checkpoint MUST NOT block full replay

## 27.2 Checkpoint Definition

A checkpoint is:

* deterministic snapshot of partition replay state
* anchored to a specific `batch_commit_record`

Each checkpoint MUST correspond to exactly one committed partition boundary and exactly one `batch_commit_seq`.

## 27.3 Checkpoint Contents

Each checkpoint MUST include:

* `partition_id`
* `batch_commit_seq`
* `batch_commit_hash`
* `last_record_hash`
* `replay_state_snapshot`
* `checkpoint_hash`

The following constructions are mandatory:

```text
replay_state_snapshot_bytes = replay_state_snapshot

checkpoint_hash = SHA256(
  batch_commit_hash ||
  replay_state_snapshot_bytes
)
```

`replay_state_snapshot` MUST be deterministic canonical bytes representing the exact replay state at the committed boundary.

## 27.4 Checkpoint Validity Rule

A checkpoint is valid ONLY if:

* `batch_commit_hash` matches authoritative storage exactly
* `batch_commit_seq` matches authoritative storage exactly
* `last_record_hash` matches the corresponding authoritative partition chain head exactly
* `checkpoint_hash` recomputes correctly

If any checkpoint field is missing, ambiguous, or mismatched, the checkpoint is invalid.

## 27.5 Replay Optimization Rule

Replay MAY start from a checkpoint ONLY if:

* the checkpoint is valid
* no gap exists after the checkpoint
* the checkpoint batch boundary is present in authoritative storage
* all later authoritative batches are continuous and verified

Otherwise:

```text
FULL REPLAY REQUIRED
```

Checkpoint use MUST NOT skip verification of post-checkpoint authoritative batches.

## 27.6 Checkpoint Storage Rule

Checkpoints MUST be:

* append-only
* immutable
* verifiable

Checkpoint mutation, overwrite, or in-place refresh is FORBIDDEN.

Corrupt checkpoint:

```text
IGNORE -> ALERT
```

If checkpoint ambiguity could affect replay start position selection:

```text
FULL REPLAY REQUIRED -> ALERT
```

## 27.7 Checkpoint Chain Rule

Checkpoint ordering MUST be partition-local and append-only.

The following are mandatory:

* one checkpoint MUST reference only one `partition_id`
* one checkpoint MUST reference only one `batch_commit_seq`
* later checkpoints MUST NOT point to an earlier chain head than the latest earlier valid checkpoint for the same partition

Out-of-order or cross-partition checkpoint linkage is invalid.

## 27.8 Snapshot Redundancy (CRITICAL)

Each checkpoint / snapshot artifact MUST have redundancy to prevent replay acceleration failure from single-copy corruption.

Mandatory:

* PRIMARY copy
* SECONDARY copy (geo-separated)
* HASH VERIFICATION for every read before use

If redundancy is missing, ambiguous, or unreadable:

```text
IGNORE SNAPSHOT -> FULL REPLAY REQUIRED -> ALERT
```

## 27.9 Snapshot Reconstruction Rule (CRITICAL)

If any snapshot is corrupted, missing, or fails hash verification, the system MUST be able to rebuild it deterministically.

Mandatory reconstruction sources:

```text
REBUILD SNAPSHOT FROM:
- partition_records
- batch_commit_records
- authority_snapshots
```

No other reconstruction source is permitted.

If reconstruction inputs are incomplete or ambiguous for the declared scope:

```text
FAIL-CLOSED -> ALERT
```

## 27.10 Snapshot Integrity Record (CRITICAL)

Each snapshot MUST have an integrity record:

```text
snapshot_hash_chain REQUIRED
```

Mandatory:

* the snapshot integrity record MUST bind the snapshot bytes to:
  * `partition_id`
  * `batch_commit_seq`
  * `batch_commit_hash`
  * the previous snapshot integrity record hash for that partition scope
* verification MUST be performed before any snapshot is used for replay acceleration

If the snapshot hash chain is missing, broken, or mismatched:

```text
IGNORE SNAPSHOT -> FULL REPLAY REQUIRED -> ALERT
```

---

# 27. STORAGE REPLICATION MODEL

## 27.1 Replication Purpose

Replication exists for:

* durability
* availability

NOT for:

* authority decision

Replication MUST preserve authoritative data after commit without changing authoritative write semantics.

## 27.2 Authority Rule

Only the partition leader node is authoritative for writes.

Replicas are:

* read-only
* non-authoritative until verified

Replica acknowledgment MUST NOT convert unverified data into authoritative data.

## 27.3 Replication Consistency Rule

Replicas MUST:

* replicate committed `batch_commit_records`
* replicate the exact referenced `partition_records`
* preserve per-partition record order
* verify:
  * `record_hash`
  * `batch_commit_hash`
  * signature

Unverified replica data is invalid.

If any replicated batch fails verification:

```text
REJECT REPLICA BATCH -> FAIL-CLOSED -> ALERT
```

## 27.4 Replica Read Rule

Replica reads are allowed ONLY if:

* the chain is verified
* no batch is missing within the requested verified range
* no hash mismatch exists
* the enclosing `batch_commit_record` chain is continuous

Otherwise:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

Replica reads MUST NOT be used as authoritative if verification is incomplete.

## 27.5 Lag Handling Rule

Replica lag MUST NOT affect:

* authoritative writes
* partition ordering

If lag exceeds the configured threshold:

```text
ALERT
```

Lag alone has no correctness impact unless it creates verification ambiguity or read incompleteness.

If lag causes read-range ambiguity:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

## 🔴 REPLICA FRESHNESS GUARANTEE (CRITICAL)
RULE

Replica MUST satisfy:

replica_lag <= max_replica_lag_records
VALIDATION
leader_last_seq - replica_last_seq <= threshold
FAILOVER RULE
IF replica exceeds lag threshold:

    replica MUST NOT be eligible for failover
HARD LAW
NO STALE REPLICA MAY BECOME AUTHORITATIVE

## 27.6 Split-Brain Protection

If multiple replicas claim authority:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

The following are mandatory:

* replicas MUST NOT self-promote outside deterministic leader election
* stale leaders MUST be fenced before any resumed write authority
* replication state MUST NOT override leader epoch or fencing-token law

## 27.7 Cross-DC Rule

Multi-datacenter replication MUST:

* preserve exact canonical bytes
* preserve ordering per partition
* preserve batch boundaries

Reordering across datacenters is FORBIDDEN.

The following are mandatory:

* transferred bytes for one batch MUST remain byte-identical to the committed source batch
* replicated `partition_records` and `batch_commit_records` MUST remain aligned to the same committed boundary
* datacenter transport timing MUST NOT affect authoritative read or replay results

## 27.8 Replication Alignment Rule

Section 27 MUST NOT contradict:

* PRD-02 partition-local ordering and commit-boundary laws
* PRD-08 durable admit-before-route laws
* PRD-12 deterministic exactly-once execution_result recording laws

If replication behavior would introduce:

* reordered authoritative records
* missing verified batches
* conflicting authority
* canonical-byte drift

the system MUST:

```text
FAIL-CLOSED -> ALERT
```

---

# 28. DETERMINISTIC QUERY MODEL

## 28.1 Query Execution Boundary

PRD-13 defines the authoritative storage format and record schemas for queries only. 

**Query execution logic, retrieval orchestration, and result assembly belong to the API / Query service layer.**

All data retrieval MUST utilize the canonical `query_object`.

## 28.2 Canonical query_object Definition

```json
{
  "query_id": "SHA256(RFC8785(query))",
  "query_hash": "hex_32_bytes",
  "data_sources": [
    "SIGNAL",
    "DETECTION",
    "DECISION",
    "SAFETY_EVALUATION",
    "ACTION",
    "EXECUTION_RESULT",
    "ROLLBACK",
    "ROLLBACK_OVERRIDE",
    "QUERY",
    "QUERY_RESULT",
    "REPORT",
    "REPORT_DELIVERY",
    "UI_ACTION",
    "GROUP",
    "CASE",
    "INVESTIGATION",
    "RISK",
    "SIMULATION"
  ],
  "filters": {},
  "grouping": [],
  "aggregation": [],
  "time_range": {},
  "projection": [],
  "sort": []
}
```

## 28.2 Query Execution Law

The integrity of a query result is bound to the query itself and the ordered data returned.

```text
query_result_hash = SHA256(
  query_hash || 
  ordered_result_rows
)
```

**MANDATORY RULES:**
* **Deterministic Ordering:** Result sets MUST have a total, deterministic order.
* **Pagination Invariance:** Pagination MUST NOT alter the `query_result_hash`.
* **Prohibition of Partial Execution:** Queries MUST execute completely or FAIL-CLOSED.
* **Clock Independence:** Execution MUST NOT depend on wall clock.

## 28.3 Query Execution Authority

Query execution MUST:

* operate ONLY on committed authoritative storage
* use deterministic ordering
* produce canonical serialized output
* be replay-reconstructable

Query execution MUST NOT:

* use caches
* use projections
* use non-authoritative indexes

## 28.4 Asset Intelligence Query Requirements (PRD-23) (CRITICAL)

The system MUST support deterministic queries for PRD-23 asset intelligence using the canonical `query_object`.

The system MUST support deterministic queries for:

* all signals by `entity_key`
* coverage state aggregation derived from `infrastructure.asset_coverage.v1` signals
* expected registry reconstruction from `ui_action_record` payloads that contain `ENTITY_REGISTRY`
* managed binding lookup from `signal_record` rows with `signal_type = infrastructure.asset_managed_binding.v1`

### 28.4.1 Mandatory Query Keys (Derived Indexes Only)

The following fields MUST be queryable via derived (rebuildable) indexes only:

* `entity_key`
* `signal_type`
* `coverage_state`
* `record_type`
* `group_id`

These keys MUST be derivable from committed authoritative records and MUST NOT require any external input.

If a query requires any non-committed input, ambiguous derived key, or non-deterministic ordering:

```text
FAIL-CLOSED -> ALERT
```

---

# 29. REPORT & EXPORT MODEL

A report is a deterministic transformation of a query result.

## 29.1 Report Definition

```json
{
  "report_id": "SHA256(RFC8785(full_canonical_object))",
  "query_hash": "hex",
  "result_hash": "hex",
  "format": "PDF|CSV|JSON",
  "generation_seq": "partition_record_seq",
  "input_record_refs": [],
  "model_id": "string",
  "model_version": "string",
  "output_hash": "hex_32_bytes",
  "shadow_metadata": {
    "source": "OPAIF",
    "non_authoritative": true,
    "request_hash": "hex_32_bytes",
    "execution_context_hash": "hex_32_bytes"
  }
}
```

`input_record_refs`, `model_id`, `model_version`, `output_hash`, and `shadow_metadata` MUST be omitted unless the report is emitted by PRD-22.

## 29.2 Scheduled Reports

* **Deterministic Scheduling:** Schedules MUST be defined using discrete logical intervals.
* **Signed Configuration:** All schedules are stored as signed configuration objects.

## 29.3 Export Requirements

* **Mandatory Metadata:** Every export MUST include `query_hash`, `result_hash`, and `dataset_hash` (PRD-15).
* **Integrity Verification:** The export artifact MUST be verifiable against its `result_hash`.
* **Shadow Report Binding:** If `shadow_metadata.source = "OPAIF"`, the export artifact bytes MUST hash to `output_hash` and remain non-authoritative.

---

# 30. GLOBAL SEARCH ENGINE

* **Canonical Search:** All search queries MUST be converted to a canonical `query_object` and be hash-identifiable.
* **Deterministic Results:** Search results MUST be ordered deterministically and be replayable.

---

# 31. VERSIONING MODEL (HASH-BASED)

All system objects (Policy, Config, Queries, Reports, Groups) are versioned exclusively via cryptographic hashes.

* **ID Generation:** `version_id = SHA256(canonical_object)`
* **No Semantic Versioning:** Versions are identified by state hash only.

---

---

# 32. DATA LINEAGE MODEL (CRITICAL)

The system MUST maintain a verifiable causal chain for every state transition and executed action.

## 32.1 lineage_hash Definition

Every authoritative record MUST compute and store a `lineage_hash`.

```text
lineage_hash = SHA256(
  RFC8785(causal_parent_refs) ||
  canonical_payload_hash
)
```

## 32.2 Mandatory Application

* **Executed Actions**: Every `ACTION_RESULT_RECORD` MUST include the `lineage_hash` of the full decision chain (signal -> detection -> decision -> safety -> action).
* **Lineage Verification**: Replay MUST recompute all lineage hashes and verify bit-for-bit equality with committed state.
* **Lineage Break**: Any gap in causal references or mismatch in `lineage_hash` MUST trigger an `INTEGRITY_FAILURE` and fail-closed halt.

---

---

# 33. STORAGE SCHEMA VERSIONING (AUTHORITATIVE)

The system MUST preserve exact schema compatibility for all committed records.

## 33.1 Version Immutability

* **Immutable Schemas**: Once a record is committed with a `schema_version`, that version identifier MUST NEVER be reused for a different schema structure.
* **Append-Only Growth**: Schema updates MUST be represented by a new, unique `schema_version` identifier.

## 33.2 Replay Compatibility

* **Per-Record Versioning**: Every record stored in `partition_records` MUST explicitly carry its `schema_version`.
* **Historical Logic Preservation**: The system MUST retain the ability to parse and verify all historical `schema_version` types present in the WORM archive.
* **No In-Place Migration**: Updating the schema of already-committed authoritative records is FORBIDDEN. Migration occurs ONLY by emitting new records or during re-serialization into derived projections.

## 33.3 Backward Compatibility

* Verifiers MUST be backward-compatible with all `schema_version` identifiers defined in the signed authority snapshots.

---

# 33.4 SCHEMA EVOLUTION ENGINE (MANDATORY)

```text
SCHEMA EVOLUTION ENGINE (MANDATORY):

PURPOSE:
ENABLE VERSIONED IDENTITY + PAYLOAD PARSING WITHOUT BREAKING REPLAY
```

```text
EVERY RECORD MUST BE PARSED USING:

schema_version FROM RECORD

NOT CURRENT SYSTEM VERSION
```

```text
SYSTEM MUST SUPPORT:

MULTIPLE ACTIVE SCHEMA DECODERS

FOR ALL HISTORICAL VERSIONS
```

```text
NO IN-PLACE MIGRATION ALLOWED

NEW SCHEMA:
→ NEW VERSION
→ OLD DATA REMAINS UNCHANGED
```

```text
ALL schema_version MUST define:

forward_transform
backward_transform
```

```text
RULE:

Each record MUST include:

schema_version
```

```text
TRANSFORMATION:

canonical_form = transform_to_latest(schema_version)
```

```text
REPLAY LAW:

Replay MUST:

1. load original canonical_payload_bytes
2. apply deterministic transform
3. produce identical canonical_form
```

```text
VERSION GRAPH:

Transformations MUST form:

acyclic directed graph
```

```text
FORBIDDEN:

- implicit schema assumptions
- non-deterministic transforms
```

```text
FAILURE:

missing transform:

→ REJECT RECORD
→ FAIL-CLOSED
```

```text
SCHEMA_CONTEXT_BINDING (MANDATORY)

All schema transformations MUST bind to execution_context_hash.

---

CONSTRUCTION:

schema_transform_hash = SHA256(
  schema_version ||
  execution_context_hash
)

---

RULE:

canonical_form MUST be derived as:

canonical_form = transform_to_latest(
  canonical_payload_bytes,
  schema_version,
  schema_transform_hash
)

The exact `schema_transform_hash` used for this derivation MUST be stored in `partition_records.schema_transform_hash`.

---

REPLAY LAW:

Replay MUST:

- recompute schema_transform_hash
- compare recomputed `schema_transform_hash` to the stored PRD-13 value
- apply identical transform
- produce identical canonical_form

---

FORBIDDEN:

context-independent schema transforms

---

FAILURE:

mismatch:

→ DETERMINISM_VIOLATION
→ FAIL-CLOSED
```

---

# 34. SUMMARY

Storage & Database Architecture is the authoritative persistence layer for Project Mishka.

It MUST:
- persist all authoritative operational records
- align exactly to execution partitions
- use append-only partition logs
- enforce WORM semantics
- cryptographically chain every committed record
- expose deterministic reads only
- guarantee replay completeness
- preserve commit durability before partition offset advance
- rebuild all indexes from authoritative storage only

If corruption, missing record, hash mismatch, or chain discontinuity occurs:
FAIL-CLOSED -> ALERT
