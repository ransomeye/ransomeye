# MISHKA-PRD-15 — Replay & Determinism Validation

**Project:** Project Mishka  
**Classification:** AUTHORITATIVE — REPLAY VALIDATION, DRIFT DETECTION, AND OUTPUT EQUIVALENCE  
**Status:** CRITICAL — BIT-FOR-BIT REPLAY VALIDATION, FAIL-CLOSED INTEGRITY ENFORCEMENT

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

This document defines the authoritative replay validation system for Project Mishka.

Its purpose is to provide:

* deterministic replay validation over committed authoritative datasets
* bit-for-bit output reconstruction and comparison
* complete drift detection across records, dependencies, hashes, and ordering
* fail-closed rejection of any replay inconsistency

This PRD exists to guarantee:

```text
IDENTICAL INPUT DATASET -> IDENTICAL OUTPUT (BIT-FOR-BIT)
```

Any deviation is:

```text
FAIL-CLOSED -> ALERT
```

PRD-15 is validation-only. It MUST verify replay correctness without redefining upstream identity, schema, storage, or forensic integrity laws.

---

# 2. CORE PRINCIPLES

```text
EXACT DATASET -> EXACT ORDER -> EXACT REPLAY -> EXACT RECONSTRUCTION -> EXACT COMPARISON
```

The following principles are mandatory:

* replay validation MUST consume only committed authoritative data
* replay validation MUST be deterministic for the same dataset
* replay validation MUST compare canonical bytes, not approximate semantics
* replay validation MUST be partition-local first and dataset-complete second
* replay validation MUST fail closed on the first inconsistency
* replay validation MUST NOT depend on wall clock, scheduler timing, transport timing, or probabilistic logic
* replay validation MUST verify dependency snapshots before accepting replay output
* replay validation MUST preserve upstream authoritative laws exactly

There is no tolerance mode, best-effort mode, or degraded acceptance mode.

---

# 3. REPLAY INPUT DATASET (CRITICAL)

The authoritative replay input dataset for one validation scope MUST contain the complete committed dataset required to reproduce that scope exactly.

The following dataset components are mandatory:

* all committed `signal_record`
* all committed `detection_record`
* all committed `decision_record` as the authoritative `policy_evaluation_record`
* all committed `safety_evaluation_record`
* all committed `action_record`
* all committed `execution_result_record`
* all committed `rollback_record`
* all committed `rollback_override_record`
* all committed `redaction_record`
* all committed `query_record`
* all committed `query_result_record`
* all committed `report_record`
* all committed `report_delivery_record`
* all committed `ui_action_record`
* all committed `group_record`
* all committed `case_record`
* all committed `investigation_record`
* all committed `risk_record`
* all committed `simulation_record`
* all committed `replay_guard` rows covering the same validation scope
* all committed `commit_groups` rows covering the declared validation scope IF validation_scope INCLUDES terminal-chain completeness
* all referenced `authority_snapshots`
* all corresponding `batch_commit_records`
* `segment_manifests`
* `retention_proofs`
* stored `execution_context_hash`

For PRD-13 storage, these records are the exact committed authoritative records in `partition_records` whose `record_type` values are:

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

The following are mandatory:

* the dataset MUST contain the exact committed authoritative record bytes for the validation scope
* the dataset MUST contain the exact committed `batch_commit_records` spanning that scope
* the dataset MUST contain the exact committed `replay_guard` rows required to validate session continuity, pre-TLS admission, and nonce single-use for the same scope
* the dataset MUST contain every referenced signed `authority_snapshot` required by those records
* the dataset MUST store the authoritative `execution_context_hash` bound to `policy_snapshot_hash`, `model_snapshot_hash`, `config_snapshot_hash`, `shard_config_hash`, and `schema_version_set`
* the dataset MUST expose the exact stored `schema_transform_hash` for every record whose `schema_version` is present
* no authoritative field may be reconstructed implicitly from indexes, projections, caches, or heuristics
* no committed record inside the declared validation scope may be omitted
* no extra committed record outside the declared validation scope may be injected into replay input

If any required dataset component is missing or extra:

```text
INTEGRITY_FAILURE
```

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
NO SINGLE STORAGE FAILURE MUST MAKE REPLAY IMPOSSIBLE

---

# 4. REPLAY EXECUTION MODEL

Replay validation MUST execute in the following strict order:

```text
1. load the exact committed replay dataset
2. verify dataset completeness
3. verify batch_commit_records continuity and committed boundary coverage
4. verify all referenced authority_snapshots, signatures, hashes, and versions
5. verify `replay_guard` completeness, pre-TLS nonce single-use, and stored token bindings
6. recompute `execution_context_hash`
7. verify stored `execution_context_hash` equality
8. recompute and verify stored `schema_transform_hash` equality
9. verify PRD-14 forensic integrity for the same committed signal-bearing scope
10. verify authoritative replay ordering inputs
11. replay the authoritative partition-local execution
12. reconstruct canonical output records (original canonical bytes)
13. compute replay hash artifacts
14. compare reconstructed outputs and hashes against committed authoritative state
15. apply redaction overlay (READ-LAYER ONLY)
16. accept only if every check succeeds
```

## BATCH_CONTEXT_VALIDATION (MANDATORY)

Replay MUST:

For each batch_commit_record:

1. read batch.execution_context_hash
2. verify ALL records in batch share same value

---

Mismatch:

→ DETERMINISM_VIOLATION
→ FAIL-CLOSED

## 4.0 BYTE-EXACT STORAGE ARTIFACT RECONSTRUCTION (MANDATORY)

```text
GLOBAL_INVARIANT

PRD15_MUST_RECONSTRUCT_PRD13_STORAGE_BYTES_EXACTLY = TRUE
PRD15_MUST_RECONSTRUCT_PRD04_SIGNATURE_INPUT_EXACTLY = TRUE
SYMBOLIC_HASH_PLACEHOLDER = FORBIDDEN
SYMBOLIC_SIGNATURE_PLACEHOLDER = FORBIDDEN
```

### 4.0.1 RECORD RECONSTRUCTION (MANDATORY)

```text
PURE_ASSIGNMENT

reconstructed_canonical_record_bytes = PRD13.canonical_record_bytes
reconstructed_record_hash_input = committed previous_record_hash || reconstructed_canonical_record_bytes
reconstructed_record_hash = SHA256(reconstructed_record_hash_input)
```

```text
DETERMINISTIC_PREDICATE

replay MUST reconstruct canonical_record_bytes FROM THE EXACT COMMITTED partition_records FIELD VALUES ONLY
replay MUST recompute record_hash FROM THE EXACT committed previous_record_hash BYTES AND reconstructed canonical_record_bytes ONLY
replay MUST verify reconstructed_record_hash = committed record_hash
replay MUST verify committed previous_record_hash continuity AGAINST THE IMMEDIATELY PRECEDING COMMITTED record_hash IN THE SAME partition_id
```

### 4.0.2 BATCH RECONSTRUCTION (MANDATORY)

```text
PURE_ASSIGNMENT

reconstructed_leaf_input_bytes_i = PRD13.leaf_input_bytes_i
reconstructed_leaf_hash_i = SHA256(reconstructed_leaf_input_bytes_i)
reconstructed_batch_root_hash = PRD13.batch_root_hash
reconstructed_batch_commit_hash_payload_bytes = PRD13.batch_commit_hash_payload_bytes
reconstructed_batch_commit_hash = SHA256(reconstructed_batch_commit_hash_payload_bytes)
```

```text
DETERMINISTIC_PREDICATE

replay MUST order committed batch leaves BY ASCENDING partition_record_seq ONLY
replay MUST apply PRD13 odd-leaf duplication EXACTLY
replay MUST verify reconstructed_batch_root_hash = committed batch_root_hash
replay MUST verify reconstructed_batch_commit_hash = committed batch_commit_hash
replay MUST verify batch_commit_records continuity AND complete committed boundary coverage FOR THE DECLARED SCOPE
```

### 4.0.3 SIGNATURE RECONSTRUCTION (MANDATORY)

```text
PURE_ASSIGNMENT

reconstructed_batch_commit_signature_payload_bytes = PRD13.batch_commit_signature_payload_bytes
reconstructed_batch_commit_signature_payload_hash = SHA256(reconstructed_batch_commit_signature_payload_bytes)
reconstructed_batch_commit_signing_input =
  ASCII("batch_commit_record_v1") ||
  reconstructed_batch_commit_signature_payload_hash
```

```text
DETERMINISTIC_PREDICATE

replay MUST verify reconstructed_batch_commit_signature_payload_bytes = committed PRD13 batch commit signature payload bytes
replay MUST verify reconstructed_batch_commit_signing_input = committed PRD04 Ed25519 verification input
replay MUST verify Ed25519(public_key, reconstructed_batch_commit_signing_input, committed signature) = TRUE
```

### 4.0.4 DATASET COMPLETENESS DEPENDENCY CLOSURE (MANDATORY)

```text
DETERMINISTIC_PREDICATE

byte_exact_replay_scope MUST include:
partition_records
batch_commit_records
replay_guard ROWS
authority_snapshots
schema_transform_hash FOR EVERY RECORD WHERE schema_version IS PRESENT

IF validation_scope INCLUDES terminal-chain completeness:
    byte_exact_replay_scope MUST include all committed commit_groups ROWS covering the declared validation scope
IF validation_scope EXCLUDES terminal-chain completeness:
    commit_groups ROWS ARE NOT REQUIRED FOR replay dataset completeness
    commit_groups ROWS ARE NOT REQUIRED FOR replay acceptance
    commit_groups ROWS ARE NOT REQUIRED FOR record_hash RECONSTRUCTION
    commit_groups ROWS ARE NOT REQUIRED FOR batch_root_hash RECONSTRUCTION
    commit_groups ROWS ARE NOT REQUIRED FOR batch_commit_hash RECONSTRUCTION
    commit_groups ROWS ARE NOT REQUIRED FOR batch commit signature reconstruction
```

```text
DETERMINISTIC_PREDICATE

BYTE-RELEVANT INPUT MUST NOT BE RECONSTRUCTED FROM CACHE
BYTE-RELEVANT INPUT MUST NOT BE RECONSTRUCTED FROM INDEX
BYTE-RELEVANT INPUT MUST NOT BE RECONSTRUCTED FROM PROJECTION
BYTE-RELEVANT INPUT MUST NOT BE RECONSTRUCTED FROM HEURISTIC
```

### 4.0.5 FAILURE RULE (MANDATORY)

```text
STATE_TRANSITION

IF reconstructed_canonical_record_bytes IS AMBIGUOUS:
    FAIL-CLOSED -> ALERT
IF reconstructed_record_hash != committed record_hash:
    FAIL-CLOSED -> ALERT
IF reconstructed_batch_root_hash != committed batch_root_hash:
    FAIL-CLOSED -> ALERT
IF reconstructed_batch_commit_hash != committed batch_commit_hash:
    FAIL-CLOSED -> ALERT
IF reconstructed_batch_commit_signature_payload_bytes IS AMBIGUOUS:
    FAIL-CLOSED -> ALERT
IF Ed25519 VERIFICATION FAILS:
    FAIL-CLOSED -> ALERT
IF ANY BYTE-RELEVANT DEPENDENCY IS MISSING:
    FAIL-CLOSED -> ALERT
IF ANY BYTE-RELEVANT DEPENDENCY IS EXTRA FOR THE DECLARED SCOPE:
    FAIL-CLOSED -> ALERT
```

REDACTION_IS_READ_LAYER_ONLY (CRITICAL):

Replay MUST:

* load original canonical data
* compute all hashes on original data
* apply redaction ONLY after computation

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

FORBIDDEN:

* hashing redacted data
* replacing canonical payload during replay

FAILURE:

If replay hashes are computed on redacted data or canonical payload is replaced during replay:

```text
INTEGRITY_FAILURE
```

REDACTED_REFERENCE_PLACEHOLDER (MANDATORY):

If a referenced record is redacted under the replay dataset’s redaction_records:

→ replay MUST generate REDACTED_REFERENCE_PLACEHOLDER deterministically instead of null/missing.

Placeholder generation MUST be deterministic and MUST NOT affect PRD-13 record_hash validation.

Mandatory placeholder fields:

```json
{
  "record_id": "hex_32_bytes",
  "state": "REDACTED",
  "redaction_ref": "hex_32_bytes",
  "hash": "hex_32_bytes"
}
```

FORBIDDEN:

* silent removal of references
* null substitution

---

# 4.2 SCHEMA EVOLUTION ENGINE (MANDATORY)

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
REPLAY MUST LOAD MATCHING DECODER VERSION

MISMATCH:
→ FAIL-CLOSED
```

```text
REPLAY MUST VERIFY:

PRD-13 CHAIN == PRD-14 VERIFICATION RESULT
```

The following are mandatory:

* replay validation MUST operate on committed authoritative data only
* replay validation MUST NOT mutate authoritative state
* replay validation MUST stop immediately on the first inconsistency
* replay validation MUST NOT continue after a failed prerequisite check

## 4.1 Snapshot / Checkpoint Handling (FAIL-CLOSED, VERIFY-BEFORE-USE)

Snapshots / checkpoints are replay accelerators only. They MUST NOT be required for correctness.

Mandatory:

* any snapshot/checkpoint used to accelerate replay MUST be verified before use
* verification MUST include:
  * snapshot hash verification
  * binding to the referenced `batch_commit_hash`
* if any snapshot/checkpoint is missing, ambiguous, corrupted, or fails verification:

```text
IGNORE SNAPSHOT -> FULL REPLAY REQUIRED -> ALERT
```

```text
DETERMINISTIC_PREDICATE

IF checkpoint IS PRESENT:
    IF checkpoint VERIFICATION SUCCEEDS:
        checkpoint IS PERMITTED AS REPLAY ACCELERATOR
    IF checkpoint VERIFICATION FAILS OR checkpoint IS AMBIGUOUS:
        IGNORE CHECKPOINT -> FULL REPLAY REQUIRED -> ALERT

GLOBAL_INVARIANT

CHECKPOINTS MUST NOT BE REQUIRED FOR CORRECTNESS = TRUE
CHECKPOINT VERIFICATION MUST SUCCEED BEFORE USE = TRUE
```

```text
REPLAY MUST NOT SKIP:

- validation
- dependency verification
- ordering checks
```

If full replay cannot be executed due to missing authoritative records, commits, or authority snapshots:

```text
INTEGRITY_FAILURE -> FAIL-CLOSED -> ALERT
```

---

# 5. PARTITION REPLAY MODEL

The authoritative replay unit is one committed partition scope.

Within one partition, replay MUST:

* load committed records in ascending `partition_record_seq`
* load committed `replay_guard` rows for the same partition scope
* validate `signal_record` session continuity by `(agent_id, boot_session_id, logical_clock)`
* validate pre-TLS token admission state, nonce single-use, and replay-guard claim continuity from committed `replay_guard`
* execute the deterministic partition-local logic implied by the committed record stream and referenced authority snapshots
* reconstruct the complete committed output sequence for that partition
* reject any replay scope that begins or ends inside one `(agent_id, boot_session_id)` session

For multi-partition validation:

* each partition MUST be validated independently using the same rules
* dataset validation succeeds only if every partition scope succeeds
* no alternate interleaving of unrelated partitions may be used to alter validation outcome

PRD-15 does not redefine global execution ordering. It validates that the committed partition-local outputs are reproducible exactly from the committed dataset.

---

# 6. ORDERING LAW (CRITICAL)

Replay MUST use ONLY the following authoritative ordering inputs:

* `partition_record_seq`
* `(agent_id, boot_session_id, logical_clock)`

The authoritative partition replay order is:

```text
ORDER BY partition_record_seq ASC
```

The authoritative signal-session replay order is:

```text
FOR EACH (agent_id, boot_session_id):
ORDER BY logical_clock ASC
```

The following are mandatory:

* the first `signal_record` in one `(agent_id, boot_session_id)` scope MUST have `logical_clock = 0`
* each next `signal_record` in that scope MUST increment `logical_clock` by exactly +1
* `logical_clock` regression is invalid
* duplicate `logical_clock` is invalid
* `logical_clock` gap is invalid
* no alternative ordering is allowed

The following are FORBIDDEN as replay ordering inputs:

* wall-clock time
* arrival time
* transport order
* scheduler order
* storage backend incidental scan order

## 🔴 PRE_TLS_REPLAY_GUARD_VALIDATION (MANDATORY) (CRITICAL)

Replay MUST validate every committed pre-TLS admission using committed `replay_guard` state only.

Mandatory:

* `pre_auth_token` MUST equal the exact committed token bytes stored in `replay_guard`
* `pre_auth_message_type` MUST equal `PRE_TLS_AUTH`
* `pre_auth_execution_context_hash` MUST equal the committed `execution_context_hash` for that admission scope
* `pre_auth_nonce` MUST be ingest-authority-issued under PRD-04
* `pre_auth_nonce` MUST be single-use within the committed `replay_guard` scope

Replay MUST recompute and verify:

```text
pre_auth_token = SIGN(
  agent_id ||
  boot_session_id ||
  nonce ||
  message_type = "PRE_TLS_AUTH" ||
  validity_window ||
  execution_context_hash
)
```

Mismatch:

```text
DETERMINISM_VIOLATION
→ FAIL-CLOSED
```

## 🔴 REPLAY ADMISSION CONSISTENCY VALIDATION (CRITICAL)

Replay validation MUST verify:

```text
replay_guard_source == PRD-13 committed state ONLY
```

Mandatory:

* replay admission decision MUST be reconstructed from committed PRD-13 `replay_guard` only
* replay MUST reject any admission path that depends on Kafka topic state, cache state, or probabilistic structures
* replay MUST verify exact `message_id` equality for the admitted `(emitter_id, boot_session_id, logical_clock)` tuple

If replay admission decision differs from committed PRD-13 `replay_guard`:

```text
DETERMINISM_VIOLATION
→ GLOBAL HALT
```

## 🔴 COMMIT GROUP TERMINAL VALIDATION (CRITICAL)

IF validation_scope INCLUDES terminal-chain completeness:

Replay MUST validate for every committed `message_id` within the declared validation scope:

* exactly one committed `commit_groups` row covering the declared validation scope exists
* `commit_group_status` is one of the committed PRD-13 terminal states only covering the declared validation scope
* the stored `terminal_record_type` and `terminal_record_id` match committed authoritative records within the declared validation scope
* short chains are accepted only if the terminal state is present within the declared validation scope

IF validation_scope EXCLUDES terminal-chain completeness:

* `commit_groups` rows are NOT required for replay dataset completeness
* `commit_groups` rows are NOT required for replay acceptance
* `commit_groups` rows are NOT required for record_hash reconstruction
* `commit_groups` rows are NOT required for batch_root_hash reconstruction
* `commit_groups` rows are NOT required for batch_commit_hash reconstruction
* `commit_groups` rows are NOT required for batch commit signature reconstruction

Failure:

```text
DETERMINISM_VIOLATION
→ FAIL-CLOSED
```

If authoritative ordering cannot be established exactly:

```text
FAIL-CLOSED -> ALERT
```

```text
REPLAY MUST VALIDATE:

partition_record_seq → shard_seq → logical_clock CONSISTENCY

ANY MISMATCH:
→ FAIL-CLOSED
```

```text
FOR EACH RECORD:

ASSERT shard_seq == partition_record_seq
```

## 6.1 Logical Clock Spec Version Binding (CRITICAL)

Replay validation MUST enforce the PRD-03 logical clock freeze contract.

Mandatory:

```text
logical_clock_spec_version MUST match REQUIRED
ELSE FAIL-CLOSED
```

For this system revision, the required value is:

```text
logical_clock_spec_version = v1
```

If any replay scope, verifier, or dependency snapshot implies a different logical clock specification version or semantics:

```text
INTEGRITY_FAILURE -> FAIL-CLOSED -> ALERT
```

---

# 7. DETERMINISM LAW (CRITICAL)

For identical replay input datasets, PRD-15 compliant replay validation MUST produce identical:

* reconstructed output bytes
* replay hashes
* reconstructed policy evaluation outputs
* reconstructed safety evaluation outputs
* reconstructed action outputs
* acceptance or rejection decisions
* partition-local ordering
* validation artifacts

The following law is mandatory:

```text
IDENTICAL DATASET -> IDENTICAL RECONSTRUCTED OUTPUT -> IDENTICAL REPLAY HASH -> IDENTICAL VALIDATION RESULT
```

Any difference in reconstructed bytes, replay hashes, or validation outcome is deterministic drift and MUST be treated as invalid.

There is no semantic-equivalence fallback. Equality is exact byte equality.

---

# 8. OUTPUT RECONSTRUCTION MODEL

Replay validation MUST reconstruct the complete authoritative output record set for the validation scope.

The reconstructed output set MUST include:

* every committed `detection_record`
* every committed `decision_record`
* every committed `safety_evaluation_record`
* every committed `action_record`
* every committed `execution_result_record`
* every committed `rollback_record`
* every committed `rollback_override_record`
* every committed `query_record`
* every committed `query_result_record`
* every committed `report_record`
* every committed `report_delivery_record`
* every committed `ui_action_record`
* every committed `group_record`
* every committed `investigation_record`
* every committed `risk_record`
* every committed `simulation_record`

**MANDATORY VALIDATION:**
* **Identical Dataset → Identical Query Output:** Replay MUST produce bit-for-bit identical results for every query in the dataset.
* **Identical Dataset → Identical Report Output:** Replay MUST produce bit-for-bit identical report artifacts.
* **Any Deviation:** FAIL-CLOSED.

For each reconstructed `report_record` with `shadow_metadata.source = "OPAIF"`, replay MUST additionally validate:

* `shadow_metadata.non_authoritative = true`
* `shadow_metadata.request_hash` equals the reconstructed PRD-22 `request_hash`
* `shadow_metadata.execution_context_hash` equals the committed `execution_context_hash`
* reconstructed report artifact bytes hash to the stored `output_hash`

For each reconstructed `rollback_override_record`, replay MUST additionally validate:

* `authorization_bundle_hash`
* `control_plane_failure_proof`
* `breakglass_action_id`

Any mismatch in these bindings is:

```text
DETERMINISM_VIOLATION
→ FAIL-CLOSED
```

For each reconstructed output record, replay validation MUST:

* build the exact PRD-13 canonical record bytes
* compute the exact PRD-13 `record_hash`
* bind the reconstructed record to the committed `partition_record_seq`
* compare the reconstructed canonical record bytes to the committed authoritative record
* compare the reconstructed `record_hash` to the committed authoritative `record_hash`

Replay outputs MUST be serialized using RFC 8785 canonical JSON bytes only.

The following are mandatory:

* replay output serialization MUST preserve the exact authoritative field set used for comparison
* replay output serialization MUST NOT normalize by inserting implicit defaults
* replay output serialization MUST NOT normalize by omitting schema-defined fields during validation output construction

```text
PARTITION DATASET ORDER:

FOR EACH partition_id:
ORDER BY partition_record_seq ASC

NO CROSS-PARTITION TOTAL ORDER
```

The comparison mapping is mandatory:

```text
one reconstructed output record <-> one committed authoritative output record in the same partition_id at the same partition_record_seq
```

If any committed output record is missing, extra, reordered, or byte-different:

```text
FAIL-CLOSED -> ALERT
```

---

# 9. REPLAY HASH MODEL (CRITICAL)

The authoritative replay hash for one partition is `partition_replay_hash`.

Replay hashing MUST include the complete ordered reconstructed output set, including policy evaluation, safety evaluation, action, execution result, and rollback outputs.

The canonical output entry format is:

```text
record_type_tag:
1 = DETECTION
2 = DECISION
3 = SAFETY_EVALUATION
4 = ACTION
5 = EXECUTION_RESULT
6 = ROLLBACK
17 = ROLLBACK_OVERRIDE
7 = QUERY
8 = QUERY_RESULT
9 = REPORT
10 = REPORT_DELIVERY
11 = UI_ACTION
12 = GROUP
13 = CASE
14 = INVESTIGATION
15 = RISK
16 = SIMULATION

output_entry_n =
    UINT64_BE(partition_record_seq) ||
    UINT8(record_type_tag) ||
    UINT64_BE(length(canonical_record_bytes)) ||
    canonical_record_bytes ||
    record_hash
```

The canonical byte stream is:

```text
ordered_output_bytes = output_entry_1 || output_entry_2 || ... || output_entry_n
```

Where:

* entries MUST be ordered by ascending `partition_record_seq`
* `canonical_record_bytes` MUST be the exact reconstructed PRD-13 canonical record bytes
* `record_hash` MUST be the exact reconstructed PRD-13 `record_hash`

Execution context binding is mandatory.

The authoritative `execution_context_hash` is:

```text
execution_context_hash = SHA256(
    policy_snapshot_hash ||
    model_snapshot_hash ||
    config_snapshot_hash ||
    shard_config_hash ||
    schema_version_set
)
```

```text
CHAOS_MATRIX_BINDING_RULE (CRITICAL)

The chaos validation matrix MUST be part of execution context.

Mandatory:

chaos_matrix_snapshot_hash MUST be included in execution_context_hash

Updated construction:

execution_context_hash = SHA256(
    policy_snapshot_hash ||
    model_snapshot_hash ||
    config_snapshot_hash ||
    shard_config_hash ||
    schema_version_set ||
    chaos_matrix_snapshot_hash
)

Where:

chaos_matrix_snapshot_hash = SHA256(canonical_payload_bytes of authority_snapshot where:
    authority_type = CONFIG
    authority_id = "chaos_validation_matrix"
)

MANDATORY RULES:

- replay MUST load the exact chaos matrix snapshot referenced by execution_context_hash
- replay MUST NOT use latest or default chaos matrix
- mismatch between stored and recomputed chaos_matrix_snapshot_hash:

→ INTEGRITY_FAILURE
→ FAIL-CLOSED
→ ALERT
```

The following are mandatory:

* `policy_snapshot_hash` MUST be the SHA256 of the exact committed canonical bytes of the referenced policy snapshot
* `model_snapshot_hash` MUST be the SHA256 of the exact committed canonical bytes of the referenced model snapshot
* `config_snapshot_hash` MUST be the SHA256 of the exact committed canonical bytes of the referenced configuration snapshot
* `shard_config_hash` MUST be the SHA256 of the exact committed canonical bytes of the referenced shard configuration snapshot
* `schema_version_set` MUST be the exact committed schema version set bytes used by the replay dataset
* `execution_context_hash` MUST be stored with the replay dataset
* `execution_context_hash` MUST be recomputed during replay validation
* mismatch between stored and recomputed `execution_context_hash` MUST fail closed

## 🔴 SCHEMA_TRANSFORM_VALIDATION (CRITICAL)

Replay MUST validate the committed storage binding for every record with a stored `schema_version`.

Mandatory:

* recompute `schema_transform_hash = SHA256(schema_version || execution_context_hash)`
* compare the recomputed value to the stored PRD-13 `schema_transform_hash`

Failure:

```text
DETERMINISM_VIOLATION
→ FAIL-CLOSED
```

## 🔴 VECTOR_CONTEXT_BINDING (PRD-22 ALIGNMENT) (CRITICAL)

`execution_context_hash` MUST additionally bind:

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

Replay MUST:

* load the exact committed vector-context inputs from PRD-13 storage
* recompute vector retrieval using the same `execution_context_hash`
* fail closed on any mismatch

## 🔴 STATE_HASH_STORAGE_BINDING (PRD-20 / PRD-12 ALIGNMENT) (CRITICAL)

Replay MUST validate state verification using only committed PRD-13 data.

Mandatory:

* load `state_scope`, `state_scope_hash`, `pre_state_hash`, and `post_state_hash` from committed `execution_result_record`
* recompute `state_scope_hash` and scoped `state_hash` values from the stored scope only
* compare recomputed values against stored `pre_state_hash` / `post_state_hash`

Mismatch:

```text
DETERMINISM_VIOLATION
→ FAIL-CLOSED
```

FORBIDDEN:

* recomputing state from live OS
* using external system reads during replay

EXECUTION_CONTEXT_LOCK (CRITICAL):

Every partition MUST process events under ONE `execution_context_hash`.

FORBIDDEN:

* mixed-context execution within partition
* silent config switching

The authoritative hash is:

```text
partition_replay_hash = SHA256(ordered_output_bytes)
```

When one validation run spans multiple partitions, the validator MUST additionally emit one canonical dataset summary hash:

```text
partition_hash_entry =
    UINT64_BE(partition_id) ||
    partition_replay_hash

dataset_replay_hash =
    SHA256(partition_hash_entry_1 || partition_hash_entry_2 || ... || partition_hash_entry_n)
```

For `dataset_replay_hash`, `partition_hash_entry` values MUST be ordered by ascending `partition_id`.

This dataset summary hash is a validation artifact only. It MUST NOT redefine replay execution order.

---

# 10. DRIFT DETECTION MODEL (CRITICAL)

PRD-15 MUST detect all replay drift.

The following drift classes are mandatory:

* missing record
* extra record
* ordering mismatch
* output mismatch
* query result mismatch
* report artifact mismatch
* policy evaluation mismatch
* safety evaluation mismatch
* hash mismatch
* dependency mismatch
* batch commit mismatch
* forensic chain mismatch
* execution context mismatch
* schema transform mismatch
* replay_guard mismatch
* rollback override binding mismatch
* partial replay incompleteness

The following are mandatory:

* missing committed authoritative record MUST be detected
* unexpected extra authoritative record MUST be detected
* mismatch in `partition_record_seq` ordering MUST be detected
* mismatch in `(agent_id, boot_session_id, logical_clock)` ordering MUST be detected
* mismatch in reconstructed canonical bytes MUST be detected
* mismatch in reconstructed `record_hash` MUST be detected
* mismatch in reconstructed query results MUST be detected
* mismatch in reconstructed report artifacts MUST be detected
* mismatch in reconstructed policy evaluation bytes MUST be detected
* mismatch in reconstructed safety evaluation bytes MUST be detected
* mismatch in `partition_replay_hash` or `dataset_replay_hash` MUST be detected
* mismatch in referenced `authority_snapshots` MUST be detected
* mismatch in stored versus recomputed `execution_context_hash` MUST be detected
* mismatch in stored versus recomputed `schema_transform_hash` MUST be detected
* mismatch in committed `replay_guard` state, pre-TLS token bytes, or nonce single-use MUST be detected
* mismatch in `authorization_bundle_hash`, `control_plane_failure_proof`, or `breakglass_action_id` MUST be detected
* partial replay scope that omits any required session record or `logical_clock` value MUST be detected

No drift tolerance is allowed.

If drift is detected:

```text
FAIL-CLOSED -> ALERT
```

---

# 11. VALIDATION MODES

Only the following validation modes are permitted:

Every validation mode MUST declare its `validation_scope`, including whether terminal-chain completeness validation is INCLUDED or EXCLUDED.

Hard rule:

* IF validation_scope INCLUDES terminal-chain completeness: `commit_groups` rows are REQUIRED and commit group terminal validation applies.
* IF validation_scope EXCLUDES terminal-chain completeness: `commit_groups` rows are NOT required for replay dataset completeness, replay acceptance, or any byte-exact reconstruction step.

## 11.1 FULL_DATASET

`FULL_DATASET` validates the entire declared replay dataset scope.

It MUST include:

* all committed records in scope
* all corresponding `batch_commit_records`
* all referenced `authority_snapshots`
* all required replay hash and drift comparisons

## 11.2 PARTITION_SCOPE

`PARTITION_SCOPE` validates exactly one declared partition scope.

It MUST include:

* all committed records for that partition scope
* all corresponding `batch_commit_records`
* all referenced `authority_snapshots`
* full replay reconstruction and hash comparison for that partition

## 11.3 PARTIAL_REPLAY_SCOPE

`PARTIAL_REPLAY_SCOPE` is permitted only as a restricted form of `PARTITION_SCOPE`.

It is allowed ONLY if:

* the full dependency snapshot set for the declared scope is present
* every included `(agent_id, boot_session_id)` session is complete from `logical_clock = 0` through its last committed `logical_clock`
* the included `logical_clock` sequence is complete

The following are FORBIDDEN:

* partial session replay
* skipping `logical_clock` values
* missing dependencies

The following are mandatory:

* every mode MUST be complete within its declared scope
* no mode may skip dependency verification
* no mode may sample records
* no mode may perform approximate comparison

```text
REPLAY MEMORY BOUNDS:

- max_records_per_scope
- max_output_records
- max_dependency_links

IF EXCEEDED:
→ TYPE 1 FAILURE (REJECT REPLAY SCOPE)
```

---

# 12. FAILURE MODEL

PRD-15 MUST operate fail-closed.

Any mismatch, ambiguity, or incompleteness in replay validation is invalid.

The following fail-closed conditions are mandatory:

* missing required record -> `INTEGRITY_FAILURE`
* extra record in declared scope -> `INTEGRITY_FAILURE`
* missing `batch_commit_record` -> `INTEGRITY_FAILURE`
* missing `authority_snapshot` -> `INTEGRITY_FAILURE`
* missing `safety_evaluation_record` where control-governed action flow exists -> `INTEGRITY_FAILURE`
* ordering violation -> `INTEGRITY_FAILURE`
* output mismatch -> `INTEGRITY_FAILURE`
* `record_hash` mismatch -> `INTEGRITY_FAILURE`
* `partition_replay_hash` mismatch -> `INTEGRITY_FAILURE`
* `dataset_replay_hash` mismatch -> `INTEGRITY_FAILURE`
* `execution_context_hash` mismatch -> `INTEGRITY_FAILURE`
* dependency mismatch -> `INTEGRITY_FAILURE`
* PRD-14 forensic chain mismatch -> `INTEGRITY_FAILURE`
* policy bypass in reconstructed output flow -> `INTEGRITY_FAILURE`
* rollback undefined for reconstructed executable action -> `INTEGRITY_FAILURE`
* partial replay incompleteness -> `INTEGRITY_FAILURE`

Any replay inconsistency MUST result in:

```text
FAIL-CLOSED -> ALERT
STOP_REPLAY_VALIDATION
```

Replay MUST NOT continue after inconsistency.

---

# 13. REPLAY COMPLETENESS RULE

Replay completeness is mandatory.

Replay is complete only if all of the following are true:

* every committed authoritative record in scope is present
* every committed `batch_commit_record` covering that scope is present
* every committed `replay_guard` row required by the scope is present
* every referenced `authority_snapshot` is present
* there is no `partition_record_seq` gap in the committed replay range
* there is no `logical_clock` gap or duplication in any `(agent_id, boot_session_id)` scope
* every reconstructed output record has exactly one committed authoritative counterpart
* every committed `decision_record` has the corresponding committed `safety_evaluation_record` before any committed executable `action_record`
* stored `execution_context_hash` is present and equals the recomputed `execution_context_hash`
* every stored `schema_transform_hash` is present and equals the recomputed value
IF validation_scope INCLUDES terminal-chain completeness:
    all committed `commit_groups` rows covering the declared validation scope MUST be present for replay completeness
IF validation_scope EXCLUDES terminal-chain completeness:
    `commit_groups` rows MUST NOT be required for replay completeness

For `PARTIAL_REPLAY_SCOPE`, completeness additionally requires:

* every included `(agent_id, boot_session_id)` session is present from `logical_clock = 0` through its last committed `logical_clock`
* no session may be truncated at either boundary
* full dependency snapshots for the declared scope are present

The following law is mandatory:

```text
COMPLETE DATASET -> COMPLETE REPLAY
INCOMPLETE DATASET -> INTEGRITY_FAILURE
```

---

# 14. DEPENDENCY SNAPSHOT REQUIREMENTS

Replay validation MUST use exact committed dependency snapshots.

Required `authority_snapshots` include every signed authoritative object referenced by the replayed records, including:

* configuration
* policy
* execution governance configuration
* safety configuration
* asset criticality mapping
* model
* shard configuration
* route mapping
* parameter profiles
* adapter manifests
* capability descriptors
* retention configuration where applicable

The following are mandatory:

* every dependency snapshot MUST be the exact committed authoritative snapshot referenced by replayed records
* every dependency snapshot MUST match its committed identifier, version, hash, and signature
* unsigned, missing, or mismatched dependency snapshots are invalid
* replay validation MUST NOT fetch live dependencies from external systems
* replay validation MUST NOT substitute newer, older, or default dependency snapshots
* the `policy_snapshot_hash`, `model_snapshot_hash`, `config_snapshot_hash`, and `shard_config_hash` inputs to `execution_context_hash` MUST be taken exactly from the committed replay dataset
* dependency snapshot byte variance is FORBIDDEN

Dependency mismatch is:

```text
INTEGRITY_FAILURE
```

---

# 15. BOUNDARY RULE (CRITICAL)

PRD-15 is validation-only.

PRD-15 MUST NOT:

* redefine PRD-03 identity, session, or `message_id` laws
* redefine PRD-07 signal schema or canonicalization
* redefine PRD-13 storage schema, record layout, or `record_hash`
* redefine PRD-14 forensic chain construction
* redefine PRD-20 control, safety, rollback, or UI-governance laws

PRD-15 MUST consume those upstream laws exactly as authoritative inputs.

PRD-15 MUST NOT modify:

* `canonical_payload_bytes`
* `boot_session_id`
* `logical_clock`
* `message_id`
* `record_hash`
* `event_hash_chain`

This PRD validates correctness. It does not create new authoritative runtime state.

---

# 16. FILE & MODULE STRUCTURE

The authoritative implementation root for this PRD MUST be:

```text
/validation/replay/
  dataset_loader.go
  dependency_snapshot_loader.go
  order_validator.go
  partition_replay.go
  output_reconstructor.go
  replay_hasher.go
  drift_detector.go
```

Every module MUST map to one or more sections of this PRD:

* `/validation/replay/dataset_loader.go` -> Sections 3, 11, 13
* `/validation/replay/dependency_snapshot_loader.go` -> Sections 3, 4, 9, 14, 15
* `/validation/replay/order_validator.go` -> Sections 5, 6, 12, 13
* `/validation/replay/partition_replay.go` -> Sections 4, 5, 7, 15
* `/validation/replay/output_reconstructor.go` -> Sections 7, 8, 13
* `/validation/replay/replay_hasher.go` -> Sections 7, 8, 9, 10
* `/validation/replay/drift_detector.go` -> Sections 10, 11, 12, 17, 18

No other authoritative PRD-15 module is permitted.

---

# 17. FORBIDDEN

```text
FORBIDDEN:

- sampling replay
- partial correctness checks
- approximate comparison
- probabilistic validation
- time-based replay
- non-deterministic execution
- ignoring missing dependencies
- partial session replay
- skipping logical_clock values
- live dependency substitution
- replay continuation after inconsistency
- tolerance thresholds for drift
- comparison against derived projections instead of authoritative committed bytes
```

---

---

# 19. STATE RECONSTRUCTION MODEL (CRITICAL)

The system MUST support bit-for-bit reconstruction of any historical state from authoritative records.

## 19.1 Reconstruction Formula

The state of a partition at any logical sequence `t` MUST be derived ONLY from:

```text
state_at_t = authority_snapshots + partition_records[0..t]
```

## 19.2 Reconstruction Requirements

* **Exact Rebuild**: Any node loading the same authoritative dataset MUST arrive at the identical bit-for-bit internal state.
* **Rollback Correctness**: Reverting to a state `state_at_t-n` MUST be deterministic and MUST match the historical state recorded at `t-n`.
* **State Verification**: `state_root_hash` is NOT an authoritative field of `batch_commit_record`.

Normative constraints:

* `state_root_hash` MUST NOT appear in authoritative `batch_commit_records`
* `state_root_hash` MUST NOT participate in:
  * canonical batch commit payload bytes
  * `batch_commit_hash`
  * batch commit signature payload bytes
  * replay dataset completeness
  * replay acceptance
* `state_root_hash` MUST NOT be used as an authoritative substitute for:
  * `record_hash`
  * `batch_root_hash`
  * `batch_commit_hash`

Fail-closed violations:

* If any authoritative `batch_commit_record` contains `state_root_hash`: `INTEGRITY_FAILURE` -> FAIL-CLOSED -> ALERT
* If any replay validator includes `state_root_hash` in canonical batch commit payload bytes, `batch_commit_hash`, or batch commit signature payload bytes: `INTEGRITY_FAILURE` -> FAIL-CLOSED -> ALERT
* If replay dataset completeness or replay acceptance depends on `state_root_hash`: `INTEGRITY_FAILURE` -> FAIL-CLOSED -> ALERT

---

# 20. SUMMARY

```text
PRD-15 is the authoritative replay validation layer for Project Mishka.

It MUST:
- require the complete committed replay dataset
- replay in authoritative committed order only
- reconstruct committed outputs bit-for-bit
- compute deterministic replay hashes
- detect all replay drift
- fail closed on any inconsistency

It MUST NOT:
- redefine PRD-03 identity
- redefine PRD-07 schema
- redefine PRD-13 storage
- redefine PRD-14 chain
- use time, randomness, or approximate validation
```

---

## CHAOS_VALIDATION_RULE (MANDATORY)

For EACH chaos scenario defined by PRD-01 `SECTION: AUTHORITATIVE CHAOS MATRIX (CRITICAL)`, the validator MUST:

```text
1. detect trigger_signal
2. evaluate system behavior
3. compute terminal_state
4. verify equality with expected_terminal_state
5. verify invariants:
   - DETERMINISM
   - FAIL_CLOSED
   - REPLAY_INTEGRITY
   - NO_HIDDEN_STATE
```

If any step cannot be executed deterministically due to missing inputs:

```text
FAIL-CLOSED -> ALERT
```

```text
CHAOS_MATRIX_SOURCE_RULE (MANDATORY)

Validator MUST use chaos matrix ONLY from:

authority_snapshot referenced by execution_context_hash

FORBIDDEN:

- loading chaos matrix from live config
- loading chaos matrix from latest version
- partial matrix usage

Violation:

→ INTEGRITY_FAILURE
→ FAIL-CLOSED
```

## CHAOS_REPLAY_RULE (MANDATORY)

Replay MUST reproduce:

* identical trigger_signal
* identical terminal_state
* identical invariant results

Deviation:

```text
FAIL-CLOSED
```

## PRODUCTION_CERTIFICATION_RULE (MANDATORY)

SYSTEM IS PRODUCTION READY IFF:

ALL 28 scenarios:

* PASS
* have zero ambiguity
