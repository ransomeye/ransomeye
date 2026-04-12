# MISHKA-PRD-24 — Deterministic Execution Architecture (Kafka, Microservices, Replay)

**Project:** Project Mishka  
**Classification:** AUTHORITATIVE — MICROSERVICES + KAFKA TRANSPORT + STORAGE COMMIT + REPLAY ARCHITECTURE  
**Status:** FINAL — BINDS PRD-01/03/05/08/09/11/12/13/15 WITH ZERO AMBIGUITY

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

---

## 0. GLOBAL ARCHITECTURAL LAW (MANDATORY)

```text
AUTHORITATIVE_STATE_LAW:

ONLY PRD-13 committed storage is authoritative.

Kafka is NON-authoritative.

Replay MUST use ONLY PRD-13 committed records.

Violation:
→ REJECT → FAIL-CLOSED → ALERT
```

## DEPLOY DOCUMENTS ARE NOT PRDs

DEPLOY DOCUMENTS ARE NOT PRDs.

FORBIDDEN:

- merging DEPLOY-01 into PRD-24
- treating infrastructure as authority

Binding set (MANDATORY):

* PRD-01 (System Laws & Invariants)
* PRD-03 (Identity & Message Model)
* PRD-05 (Edge Sensors & Probes)
* PRD-08 (Signal Fabric & Ingest Pipeline)
* PRD-09 (Decision Orchestrator)
* PRD-11 (Policy Model)
* PRD-12 (Enforcement Engine)
* PRD-13 (Storage & Database Architecture)
* PRD-15 (Replay & Determinism Validation)

This PRD MUST NOT contradict any of the above.
If contradiction exists:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

---

## SECTION: GLOBAL AUTHORITY MAP (MANDATORY)

Define EXACT bindings.

### A.1 INGEST AUTHORITY (MANDATORY)

```text
PRD-08 governs:

- validation pipeline order
- signature verification
- replay admission
- backpressure signaling

PRD-24 MUST NOT redefine these.
```

### A.2 IDENTITY & MESSAGE AUTHORITY (MANDATORY)

```text
PRD-03 governs:

- message_id construction
- partition_context
- logical_clock rules
- replay identity binding

PRD-24 MUST reference ONLY.
```

### A.3 EDGE AUTHORITY (MANDATORY)

```text
PRD-05 governs:

- signal emission
- logical_clock generation
- buffer + escrow behavior

PRD-24 MUST NOT override.
```

### A.4 DECISION AUTHORITY (MANDATORY)

```text
PRD-09 governs:

- windowing
- feature construction
- correlation rules

PRD-24 MUST NOT redefine logic.
```

### A.5 POLICY AUTHORITY (MANDATORY)

```text
PRD-11 governs:

- decision evaluation
- deferred state behavior

PRD-24 MUST reference only.
```

### A.6 ENFORCEMENT AUTHORITY (MANDATORY)

```text
PRD-12 governs:

- action generation
- execution guarantees
- idempotency

PRD-24 MUST NOT redefine.
```

### A.7 STORAGE AUTHORITY (CRITICAL) (MANDATORY)

```text
PRD-13 governs:

- commit boundary
- WORM storage
- hash-chain integrity

PRD-24 MUST treat PRD-13 as FINAL AUTHORITY.
```

### A.8 REPLAY AUTHORITY (CRITICAL) (MANDATORY)

```text
PRD-15 governs:

- replay dataset definition
- replay correctness validation

PRD-24 MUST enforce storage-only replay.
```

---

## SECTION: PRD PRECEDENCE RULE (MANDATORY)

```text
IF CONFLICT:

PRD-01 (System Laws) → highest authority
PRD-13 (Storage) → state authority
PRD-03 (Identity) → identity authority
PRD-08 (Ingest) → admission authority
PRD-09/11/12 → execution authority
PRD-24 → orchestration only

PRD-24 MUST NEVER override lower-level PRDs
```

Violation:

```text
REJECT → FAIL-CLOSED
```

---

## SECTION: GLOBAL DETERMINISM CHAIN (MANDATORY)

Define exact invariant flow:

```text
EDGE (PRD-05)
→ message_id (PRD-03)
→ validation (PRD-08)
→ Kafka transport (PRD-24 constraint)
→ processing (PRD-09/11/12)
→ storage commit (PRD-13)
→ replay (PRD-15)
```

Mandatory invariant:

```text
same input → same message_id → same commit → same replay output
```

## INTRA_NODE_BYPASS (MANDATORY CONTRACT)

If intra-node bypass is enabled by signed deployment configuration, Kafka MUST be bypassed only for intra-node communication.

---

RULE:

raw body bytes MUST flow via:

lock-free shared memory ring buffer

---

Kafka remains:

replication + durability layer ONLY

---

## SECTION: REPLAY CERTIFICATION (MANDATORY)

Replay is VALID ONLY IF:

1. All inputs read from PRD-13 committed storage
2. Hash-chain verified
3. commit signatures verified
4. no missing records
5. recomputed outputs EXACT match original outputs

Mismatch:

```text
IF partition-scoped:
→ HALT PARTITION

IF dataset-wide:
→ GLOBAL HALT
```

---

## 1. SYSTEM MODEL (MANDATORY)

System definition (MANDATORY):

```text
DETERMINISTIC STATE MACHINE OVER APPEND-ONLY STORAGE
```

End-to-end execution flow (MANDATORY):

```text
EDGE (PRD-05)
→ INGEST (PRD-08)
→ KAFKA (PRD-24 transport log)
→ PROCESSING (PRD-09/11/12)
→ STORAGE COMMIT (PRD-13)
→ REPLAY (PRD-15)
```

Mandatory properties:

* all transitions are append-only
* all outputs are reproducible (PRD-01 determinism law)
* no hidden state is permitted
* no shared mutable state is permitted
* no cross-partition ordering dependency is permitted
* no synchronous request-response coupling between core services is permitted

---

## 2. KAFKA ROLE (STRICTLY DEFINED)

Kafka role (MANDATORY):

```text
NON-AUTHORITATIVE TRANSPORT LOG
```

Kafka is allowed for:

* buffering
* fan-out
* partition-parallel compute
* bounded replay-safe service-local recovery of NON-authoritative derived state

Kafka is forbidden for:

* replay authority
* authoritative state reconstruction
* integrity guarantee
* acting as the source-of-truth for acceptance, ordering, or commit

Any component that treats Kafka offsets as authoritative commit state is invalid:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

## SECTION: KAFKA NON-AUTHORITY ENFORCEMENT (MANDATORY)

```text
Kafka MUST NEVER be used for:

- replay
- audit
- recovery authority

Kafka MUST remain removable WITHOUT breaking correctness
```

---

## 3. STORAGE AUTHORITY MODEL (PRD-13 / PRD-15 BINDING)

AUTHORITATIVE_COMMIT_BOUNDARY (MANDATORY)

A record becomes authoritative ONLY after all of the following are true:

* durable write completed
* `batch_commit_record` exists for the committed range
* hash-chain linkage is continuous and verified
* commit signature is verified under the PRD-04 trust snapshot referenced by the record scope

Authoritative storage requirements (MANDATORY):

* append-only
* immutable (WORM) after commit
* cryptographically verifiable (record hashes + commit signatures)
* reads are verify-before-use (PRD-13 / PRD-15)

Forbidden:

* partial commit visibility
* mutation of authoritative records
* authoritative reads from uncommitted data
* reconstructing authoritative bytes from Kafka

---

## SECTION: STATE VISIBILITY RULE (MANDATORY)

```text
ALL STATE MUST BE DERIVABLE FROM:

PRD-13 storage ONLY

Hidden state:
→ FORBIDDEN
```

---

## 4. MICROSERVICES ARCHITECTURE (EXACT LIST)

Hard law (MANDATORY):

```text
NO DIRECT SERVICE-TO-SERVICE CALLS IN THE CORE EXECUTION PATH.
NO SHARED MEMORY.
NO HIDDEN STATE.
ONLY APPEND-ONLY TOPIC IO + PRD-13 COMMIT.
```

All services MUST:

* be deterministic for identical authoritative inputs
* implement bounded state only
* persist any decision-relevant state as append-only records OR derive it from PRD-13 committed records during replay
* fail closed on ambiguity or integrity breach

### 4.1 Ingest Gateway Service (PRD-16/PRD-08 Boundary)

Responsibilities (MANDATORY):

* transport handling (TCP/API)
* framing validation
* raw-body byte reconstruction (PRD-16)
* raw-body byte handoff to PRD-08
* deterministic batch processing (PRD-08)

Inputs (MANDATORY):

* untrusted network bytes (TCP/UDP/API as permitted by PRD-08/16)

Outputs (Kafka topics) (MANDATORY):

* `signal_ingest_log` (post-PRD-08 admitted records only)

State (MANDATORY):

* ephemeral transport state only
* bounded batch-formation state only
* NO durable authoritative state

Forbidden:

* DB writes
* bypassing PRD-08 verify-before-admit
* bypassing PRD-08 canonical validation, schema validation, signature verification, identity verification, replay admission, or verify-before-admit
* minting or rewriting `boot_session_id`, `logical_clock`, `message_id`

Failure behavior:

* TYPE 1 (invalid bytes / invalid schema / invalid signature): `REJECT -> FAIL-CLOSED -> ALERT`
* TYPE 2 (required dependency missing/ambiguous, e.g. trust snapshot): `REJECT -> FAIL-CLOSED -> ALERT`
* TYPE 3 (resource exhaustion): `RESOURCE_EXHAUSTED` with deterministic pressure signaling (PRD-08)

### 4.2 Replay Guard Service

Responsibilities (MANDATORY):

* enforce session ordering by:

```text
(emitter_id, boot_session_id, logical_clock)
```

* detect and reject:
  * duplicates
  * regression
  * gaps

Inputs (Kafka topics) (MANDATORY):

* `signal_ingest_log`

Outputs (Kafka topics) (MANDATORY):

* no runtime Kafka output

Outputs (direct handoff) (MANDATORY):

* deterministic admission handoff to Partition Router

State (MANDATORY):

Kafka is NON-authoritative (Section 0).

Hard law:
* durable session-ordering (replay guard) state MUST NOT rely on Kafka compaction correctness.
* replay admission MUST be reconstructed from committed PRD-13 `replay_guard` only.

Permitted:
* if `replay_guard_log` exists, it MUST exist only as a NON-authoritative transport log for performance and fan-out.
* if in-memory cache exists, it MUST exist only as a read-through mirror of committed PRD-13 `replay_guard`.

Forbidden:
* treating Kafka compacted topic state as the only durable source-of-truth for replay ordering or duplicate rejection
* emitting `decision_window_log`
* writing directly to storage
* any probabilistic admission structure

If in-memory caches exist, they MUST exist only as bounded performance accelerators and MUST NOT be required for correctness.

Forbidden:

* in-memory-only state
* any acceptance that cannot be proven from durable state machine rules

Failure behavior:

* TYPE 1 (ordering violation): `REJECT -> FAIL-CLOSED -> ALERT`
* TYPE 2 (durable claim ambiguity): `REJECT -> FAIL-CLOSED -> ALERT`
* TYPE 3 (state capacity exhausted): `RESOURCE_EXHAUSTED` (deterministic)

### 4.3 Partition Router Service (PRD-02 Ownership)

Responsibilities (MANDATORY):

* compute `logical_shard_id`
* assign `partition_id` and `partition_epoch` for routed records

Hard law:

* MUST use PRD-02 routing and MUST NOT redefine it here
* MUST be deterministic

Inputs (Kafka topics) (MANDATORY):

* no Kafka input required for runtime admission

Inputs (direct handoff) (MANDATORY):

* deterministic admission handoff from Replay Guard

Outputs (Kafka topics) (MANDATORY):

* `decision_window_log` (window input stream per partition/shard)

State (MANDATORY):

* read-only signed shard configuration snapshots
* no mutable shared state across partitions

Forbidden:

* arrival-order routing
* wall-clock usage
* any non-PRD-02 routing formula
* writing directly to storage
* emitting `worm_storage_log`

Failure behavior:

* TYPE 1 (invalid routing inputs): `REJECT -> FAIL-CLOSED -> ALERT`
* TYPE 2 (missing/ambiguous shard config): `REJECT -> FAIL-CLOSED -> ALERT`
* TYPE 3 (resource exhaustion): `RESOURCE_EXHAUSTED` and backpressure

## 🔴 REPLAY GUARD DERIVATION RULE (MANDATORY)

`replay_guard_log` MUST be:

```text
DERIVED ONLY FROM PRD-13 committed replay_guard
```

It MUST NOT be independently written.

If mismatch exists between `replay_guard_log` and committed storage:

```text
DISCARD LOG
→ REBUILD FROM STORAGE
```

### 4.4 Decision Orchestrator Service (PRD-09)

Responsibilities (MANDATORY):

* window construction (state transitions)
* feature vector construction
* deterministic inference invocation (SINE only, PRD-10 via PRD-09 contract)
* detection emission

Inputs (Kafka topics) (MANDATORY):

* `decision_window_log` (partition-routed ordered inputs)

Outputs (Kafka topics) (MANDATORY):

* `worm_storage_log` (accepted `signal_record` write intents for Storage Writer)
* `feature_vector_log`
* `detection_event_log`

State (MANDATORY):

* partition-local bounded window state
* partition-local bounded feature buffers
* all decision-relevant state MUST be replay-reconstructable from committed inputs (PRD-15)

Forbidden:

* heuristics
* probabilistic logic
* external dependencies for authoritative decisions
* cross-partition state sharing

Failure behavior:

* TYPE 1 (schema/integrity violation): `REJECT -> FAIL-CLOSED -> ALERT`
* TYPE 2 (missing signed model snapshot/feature profile): `HALT PARTITION -> FAIL-CLOSED -> ALERT` (PRD-09)
* TYPE 3 (bounded capacity reached): `REJECT -> FAIL-CLOSED -> ALERT` (no silent drop)

### 4.5 Policy Engine Service (PRD-11)

Responsibilities (MANDATORY):

* evaluate `detection_event`
* produce `action_decision`

Inputs (Kafka topics) (MANDATORY):

* `detection_event_log`

Outputs (Kafka topics) (MANDATORY):

* `policy_decision_log`

State (MANDATORY):

* signed immutable `policy_config` in active scope
* bounded compiled indexes derived only from signed policy

Forbidden:

* external lookups
* side effects
* unbounded memory growth

Failure behavior:

* TYPE 1 (invalid detection signature / invalid policy): `REJECT -> FAIL-CLOSED -> ALERT`
* TYPE 2 (missing policy snapshot): `REJECT -> FAIL-CLOSED -> ALERT`
* TYPE 3 (resource exhaustion): backpressure and `RESOURCE_EXHAUSTED` where applicable

### 4.6 Safety Guardrails Service (PRD-20)

Responsibilities (MANDATORY):

* execute PRD-20 safety evaluation
* generate deterministic `safety_evaluation`
* generate:
  * `safety_result`
  * `rollback_defined`
  * `execution_authorization_token`

Inputs (Kafka topics) (MANDATORY):

* `policy_decision_log`

Outputs (Kafka topics) (MANDATORY):

* `safety_evaluation_log`

State (MANDATORY):

* signed immutable guardrail configuration only
* no hidden mutable state

Forbidden:

* bypassing safety layer
* direct `policy_decision_log` -> enforcement flow
* unsigned safety output

Failure behavior:

* TYPE 1 (guardrail violation): `REJECT -> FAIL-CLOSED -> ALERT`
* TYPE 2 (missing guardrail snapshot): `REJECT -> FAIL-CLOSED -> ALERT`
* TYPE 3 (resource exhaustion): `RESOURCE_EXHAUSTED -> FAIL-CLOSED -> ALERT`

### 4.7 Enforcement Engine Service (PRD-12)

Responsibilities (MANDATORY):

* generate deterministic `action_object`
* dispatch to deterministic adapters
* guarantee exactly-once execution by `execution_id`
* verify execution and emit required enforcement signals

Inputs (Kafka topics) (MANDATORY):

* `safety_evaluation_log`
* `action_execution_log` (if decoupled plan/dispatch is used)

Outputs (Kafka topics) (MANDATORY):

* `action_execution_log` (dispatch intent / execution WAL events)
* `execution_result_log`

State (MANDATORY):

* durable append-only ledgers as required by PRD-12 (action generation / dispatch / receipt / verification)
* any optimization cache MUST be bounded and MUST NOT affect authoritative outcomes

Forbidden:

* unsigned dispatch
* non-idempotent execution
* generating new `action_id` or `execution_id` on retry

Failure behavior:

* TYPE 1 (signature/route/hash mismatch): `REJECT -> FAIL-CLOSED -> ALERT`
* TYPE 2 (missing dependency snapshots): `REJECT -> FAIL-CLOSED -> ALERT`
* TYPE 3 (transport failure): deterministic retry within signed bounds; otherwise `FAIL-CLOSED -> ALERT`

### 4.8 Storage Writer Service (CRITICAL) (PRD-13 Commit Path)

Responsibilities (MANDATORY):

* consume authoritative logs
* perform verify-before-store
* write append-only records to PRD-13 storage
* enforce hash-chain integrity and commit-boundary signatures

Inputs (Kafka topics) (MANDATORY):

* `worm_storage_log` (write intents / canonical bytes + required metadata)
* `detection_event_log`
* `policy_decision_log`
* `safety_evaluation_log`
* `action_execution_log`
* `execution_result_log`

Outputs (Kafka topics) (MANDATORY):

* `storage_commit_log` (NON-authoritative commit notifications only)
* `replay_guard_log` (NON-authoritative post-commit projection from committed PRD-13 `replay_guard`)

State (MANDATORY):

* partition-local writer state only
* one active writer per PRD-13 partition leader epoch
* no shared mutable state across partitions

Failure behavior:

* TYPE 1 (integrity violation): `REJECT -> FAIL-CLOSED -> ALERT`
* TYPE 2 (commit ambiguity): `FAIL-CLOSED -> ALERT`
* TYPE 3 (disk pressure / capacity): deterministic backpressure signaling; fail-closed on authoritative capacity exhaustion (PRD-13)

### 4.9 Replay Engine Service (PRD-15)

Responsibilities (MANDATORY):

* read PRD-13 committed records ONLY
* verify dataset completeness, commit signatures, hash chains, authority snapshots
* replay partition-local deterministic execution
* compare reconstructed outputs bit-for-bit against committed authoritative state

Inputs (MANDATORY):

* PRD-13 committed storage only (NOT Kafka)

Outputs (MANDATORY):

* deterministic validation reports as append-only records in PRD-13 (if persisted) OR deterministic alerts (non-authoritative)

State (MANDATORY):

* no hidden state
* any acceleration snapshot MUST be derived-only and MUST NOT replace full replay ability (PRD-13/15)

Failure behavior:

* any mismatch: `FAIL-CLOSED -> ALERT`

---

## 5. KAFKA TOPOLOGY (AUTHORITATIVE)

Kafka cluster constraints (MANDATORY):

* single logical Kafka cluster (multi-AZ)
* rack-aware replication
* `min.insync.replicas >= 2`
* producer `acks = all`

Hard law (MANDATORY):

```text
NO TOPIC MUST:

- mix message types
- contain mutable updates (except compacted state topics by explicit contract)
- depend on wall-clock ordering
```

### 5.1 `signal_ingest_log` (MANDATORY)

Purpose:

* input: validated signals from PRD-08

Key (MANDATORY):

```text
partition_key = emitter_id
```

Partition strategy (MANDATORY):

* partition count MUST be >= 1024
* assignment MUST be deterministic and stable for the same cluster partition count

Retention (MANDATORY):

* bounded retention window
* MUST be sufficient for transient buffering only
* MUST NOT be relied upon for replay or reconstruction

Compaction:

* FORBIDDEN

Value contract (MANDATORY):

* MUST include immutable post-PRD-08 admitted bytes and required PRD-03/07 envelope fields for downstream verification

### 5.2 `replay_guard_log` (COMPACTED) (MANDATORY)

Purpose:

* NON-authoritative compacted topic containing replay-guard state projections rebuilt from committed PRD-13 `replay_guard` only

Key (MANDATORY):

```text
(emitter_id, boot_session_id)
```

Value (MANDATORY):

```text
last_logical_clock
last_message_id
```

Compaction rules (MANDATORY):

* compaction is permitted ONLY for this topic
* state overwrites are permitted ONLY as last-known-state replacement for the same key
* value MUST remain deterministic and derived only from committed PRD-13 `replay_guard`

Authority rule (CRITICAL):
* loss, truncation, or compaction errors in `replay_guard_log` MUST NOT cause acceptance of duplicates or ordering regressions
* replay guard correctness MUST be enforced by committed PRD-13 `replay_guard` only

Retention (MANDATORY):

* long retention MUST remain bounded by signed configuration

### 5.3 `decision_window_log` (MANDATORY)

Purpose:

* stores window state transitions for PRD-09

Key (MANDATORY):

```text
(partition_id, logical_shard_id)
```

Value (MANDATORY):

* append-only window transition records
* MUST include ordered `signal_refs` or strict references required by PRD-09 window model

Retention:

* bounded transport retention only
* NOT a replay source

Compaction:

* FORBIDDEN

### 5.4 `feature_vector_log` (MANDATORY)

Purpose:

* deterministic feature outputs from PRD-09

Key (MANDATORY):

```text
(partition_id, logical_shard_id)
```

Retention:

* bounded transport retention only

Compaction:

* FORBIDDEN

### 5.5 `detection_event_log` (MANDATORY)

Purpose:

* output of PRD-09

Key (MANDATORY):

```text
(partition_id, logical_shard_id)
```

Retention:

* bounded transport retention only

Compaction:

* FORBIDDEN

### 5.6 `policy_decision_log` (MANDATORY)

Purpose:

* output of PRD-11

Key (MANDATORY):

```text
(partition_id, logical_shard_id)
```

Retention:

* bounded transport retention only

Compaction:

* FORBIDDEN

### 5.7 `safety_evaluation_log` (MANDATORY)

Purpose:

* output of PRD-20 safety guardrails evaluation

Key (MANDATORY):

```text
(partition_id, logical_shard_id)
```

Retention:

* bounded transport retention only

Compaction:

* FORBIDDEN

### 5.8 `action_execution_log` (MANDATORY)

Purpose:

* input to PRD-12 and PRD-12 execution WAL events

Key (MANDATORY):

```text
(partition_id, logical_shard_id)
```

Retention:

* bounded transport retention only

Compaction:

* FORBIDDEN

### 5.9 `execution_result_log` (MANDATORY)

Purpose:

* output of PRD-12

Key (MANDATORY):

```text
(partition_id, logical_shard_id)
```

Retention:

* bounded transport retention only

Compaction:

* FORBIDDEN

### 5.10 `worm_storage_log` (MANDATORY)

Purpose:

* append-only immutable storage feed into Storage Writer
* emitted ONLY by Decision Orchestrator for accepted `signal_record` write intents

Key (MANDATORY):

```text
(partition_id, logical_shard_id)
```

Retention:

* bounded transport retention only
* MUST NOT be used for replay

Compaction:

* FORBIDDEN

### 5.11 `storage_commit_log` (MANDATORY)

Purpose:

* NON-authoritative commit notifications

Key (MANDATORY):

```text
(partition_id, batch_commit_seq)
```

Value (MANDATORY):

* `batch_commit_hash`
* `last_record_hash`
* `record_count`

Retention:

* bounded
* MUST NOT be required for replay

Compaction:

* FORBIDDEN

---

## 6. REPLAY ARCHITECTURE (PRD-15 BINDING)

Definition (MANDATORY):

```text
REPLAY_SOURCE = PRD-13 STORAGE ONLY
```

Replay MUST:

* read committed records only
* verify commit-chain and signatures before use
* rebuild all downstream state deterministically
* produce identical outputs and hashes

Kafka MUST NOT be used for replay.

Violation:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

---

## 7. STORAGE WRITER (CRITICAL) — FULL STATE MACHINE (MANDATORY)

State machine (MANDATORY):

```text
RECEIVE → BATCH → HASH → SIGN → COMMIT → ACK
```

State definitions (MANDATORY):

```text
RECEIVE:
entry = item consumed from authoritative input logs
exit = item validated and staged OR rejected

BATCH:
entry = staged items exist for a partition writer lane
exit = batch boundary fixed deterministically

HASH:
entry = batch boundary fixed
exit = record_hash chain computed deterministically

SIGN:
entry = batch_commit_record materialized
exit = commit signature created deterministically (Ed25519 over required bytes)

COMMIT:
entry = signed commit record ready
exit = durable commit complete and fsync complete

ACK:
entry = commit complete
exit = non-authoritative storage_commit_log emitted
```

Mandatory rules:

* no partial commit
* deterministic batching ONLY (configuration-derived; no time-based batch closing)
* hash-chain continuity MUST be enforced
* commit boundary MUST follow PRD-13 / PRD-02 ordering and visibility rules

Failure:

```text
FAIL-CLOSED -> ALERT
```

---

## 8. PARTITIONING MODEL (MANDATORY)

Partition key (MANDATORY):

```text
partition_key = emitter_id
```

Guarantees (MANDATORY):

* strict ordering per emitter by `(emitter_id, boot_session_id, logical_clock)`
* no cross-partition dependency for correctness
* cross-partition relationships MUST exist ONLY via explicit causal references stored in canonical payloads (PRD-13)

Forbidden:

* global coordinator
* global ordering dependency

---

## 9. BACKPRESSURE MODEL (MANDATORY)

Backpressure chain (MANDATORY):

```text
STORAGE → KAFKA → INGEST → EDGE
```

Mandatory rules:

* CRITICAL signals preserved (no silent drop)
* deterministic throttling only
* explicit `storage_pressure` propagation and deterministic pressure states (PRD-08)

Forbidden:

* silent drop
* randomized delay/jitter
* wall-clock-driven admission decisions

---

## 10. FAILURE MODEL (MANDATORY)

All failures MUST be TYPE 1 / TYPE 2 / TYPE 3 (PRD-01).

### 10.1 Kafka Failure

#### 🔴 KAFKA_OPERATIONAL_STATE (MANDATORY) (INFRA-01)

Kafka availability MUST be evaluated ONLY using:

```text
produce_result ∈ {SUCCESS, RETRIABLE_ERROR, FATAL_ERROR}
```

DETERMINISTIC RULE (MANDATORY):

```text
IF produce_result == SUCCESS:
    CONTINUE

IF produce_result == RETRIABLE_ERROR:
    APPLY BACKPRESSURE
    DO NOT ACK
    DO NOT DROP

IF produce_result == FATAL_ERROR:
    FAIL-CLOSED
    HALT INGEST FOR AFFECTED PARTITIONS
```

FORBIDDEN (MANDATORY):

```text
- broker-count-based decisions (including any fraction-of-brokers-down heuristic)
- ISR inference logic
- probabilistic retry loops
```

Kafka Failure Invariants (MANDATORY):

* Kafka unavailability MUST NOT be treated as authoritative commit loss (PRD-13 remains sole authority)
* partition offsets MUST NOT advance unless the corresponding authoritative commit path remains provably intact (PRD-13/PRD-08/PRD-01)
* no acceptance without later PRD-13 commit path
* no hidden state introduced

Recovery (MANDATORY):

* restart producers/consumers
* resume from last committed Kafka offset for transport continuity only
* MUST NOT treat Kafka offsets as authoritative storage commit state

### 10.2 Storage Failure

Behavior (MANDATORY):

* integrity breach → `FAIL-CLOSED -> ALERT`
* authoritative capacity exhaustion → apply deterministic CRITICAL reservation rules (PRD-13) and fail closed only when CRITICAL capacity is exhausted

Recovery (MANDATORY):

* recover from last durable `batch_commit_record` boundary
* verify chain continuity before resuming

Invariants:

* no partial commit visibility
* no mutation of authoritative records

### 10.3 Replay Failure

Behavior (MANDATORY):

* any mismatch in recomputed bytes/hashes/signatures → `FAIL-CLOSED -> ALERT`

Recovery (MANDATORY):

* rebuild from committed PRD-13 dataset
* if any required dataset component is missing → `FAIL-CLOSED -> ALERT`

### 10.4 Network Partition

Behavior (MANDATORY):

* services MUST NOT request-response chain across partitions
* partition isolation MUST be preserved
* inability to verify required inputs MUST fail closed

Recovery (MANDATORY):

* resume from durable transport and storage boundaries
* no wall-clock reconciliation

---

## 11. DETERMINISM GUARANTEE (MANDATORY)

Authoritative law:

```text
same input → same output
```

Applies to:

* replay (PRD-15)
* crash recovery
* scaling by partitions
* batch processing
* backpressure behavior (deterministic)

If identical inputs can produce different outputs:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

---

## 12. ZERO-COPY / ZERO-REPARSE CONTRACT (MANDATORY)

End-to-end canonical bytes contract (MANDATORY):

* PRD-08 canonical validation output bytes MUST be passed end-to-end as immutable bytes when present in the post-PRD-08 pipeline
* downstream stages MUST NOT re-canonicalize from text when PRD-08 canonical bytes are present
* any hash verification MUST verify equality to the PRD-08 canonical bytes

Forbidden:

* re-parsing and re-serialization drift
* canonicalization “repair”

---

## 13. FORBIDDEN PATTERNS (MANDATORY)

Explicitly forbidden:

* Kafka as source of truth
* Kafka as replay authority
* probabilistic logic
* LLM usage in execution path
* heuristic routing
* time-based ordering
* synchronous service-to-service RPC coupling in core execution path
* shared mutable state across partitions
* hidden state used for correctness

Violation:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

---

## 14. DATAFLOW DIAGRAM (TEXTUAL) (MANDATORY)

```text
EDGE (PRD-05; canonicalize + sign; bounded buffering; backpressure/escrow)
  → Transport Edge (PRD-16; terminate transport; authN/authZ; frame/bound; reconstruct raw body bytes)
  → Ingest Gateway (PRD-08; canonical validate + schema validate + verify-before-admit; signature + identity verify; batch crypto; reject fail-closed)
    → Kafka: signal_ingest_log (NON-authoritative transport)
      → Replay Guard (ordering by emitter/session/logical_clock; durable compacted state)
        → Partition Router (PRD-02 routing only; direct deterministic handoff from Replay Guard; emits decision_window_log only)
          → Decision Orchestrator (PRD-09; windows/features/SINE invoke; emits accepted signal write intents + detection)
            → Kafka: worm_storage_log + detection_event_log
              → Policy Engine (PRD-11; emits action_decision)
                → Kafka: policy_decision_log
                  → Safety Guardrails Service (PRD-20; emits safety_evaluation)
                    → Kafka: safety_evaluation_log
                      → Enforcement Engine (PRD-12; action_object + dispatch; execution_result)
                        → Kafka: action_execution_log + execution_result_log
                          → Storage Writer (PRD-13; verify-before-store; hash-chain; batch_commit; emits replay_guard_log projection)
                            → PRD-13 committed storage (AUTHORITATIVE)
                              → Replay Engine (PRD-15; reads PRD-13 only; bit-for-bit validation)
```

---

## 15. SUMMARY (MANDATORY)

```text
PRD-24 defines the final deterministic execution architecture:

- Kafka is NON-authoritative transport only.
- PRD-13 committed storage is the ONLY authority.
- Replay uses ONLY PRD-13 committed records under PRD-15 validation.
- Core services are partitioned, bounded, fail-closed, and use deterministic handoff contracts only.
- Replay Guard is validation-only, Partition Router is routing-only, and Safety Guardrails is mandatory before Enforcement.
- Policy execution MUST pass through Safety Guardrails before Enforcement.
```

---

```text id="cbxlaw1"
COMMIT_BOUND_EXECUTION_LAW (MANDATORY)

Authoritative system behavior MUST be commit-consistent.

RULE:

NO externally observable effect (including enforcement actions)
MUST be considered NON-FINAL unless the originating signal
and all dependent records are durably committed in PRD-13.

DEFINITION:

execution_visibility_state:

- PRE_COMMIT (non-authoritative, reversible)
- POST_COMMIT (authoritative, irreversible)

MANDATORY:

All execution MUST follow:

PROCESS → STAGE → COMMIT → FINALIZE

---

STAGE PHASE:

- decision + policy + enforcement execute in PRE_COMMIT state only
- results MUST be marked NON-AUTHORITATIVE

---

COMMIT PHASE:

- Storage Writer completes:
  - batch_commit_record
  - hash-chain linkage
  - signature verification

---

FINALIZE PHASE:

- only AFTER commit:
    execution becomes authoritative
    actions become irreversible

---

IF COMMIT FAILS:

- execution MUST be treated as NON-EXISTENT
- any side-effects MUST be:
    - rolled back (if reversible)
    OR
    - compensated deterministically

---

FORBIDDEN:

- irreversible action BEFORE commit
- external side-effect without commit linkage

Violation:

→ DETERMINISM_VIOLATION → FAIL-CLOSED → ALERT
```

```text id="exlink1"
EXECUTION_COMMIT_BINDING (MANDATORY)

Every action_execution MUST include:

- message_id (source signal)
- dependency_set (all upstream message_ids)
- expected_commit_range (batch_commit_seq)

Storage commit MUST include:

- reference to execution_id(s)

Replay MUST verify:

execution_id ↔ committed records bijection

Mismatch:

→ FAIL-CLOSED
```

```text id="replayval1"
REPLAY_ACTION_VALIDATION (MANDATORY)

Replay MUST verify:

- action_execution_log entries correspond ONLY to committed records
- no action exists without corresponding committed signal chain

If action exists without commit:

→ CRITICAL VIOLATION → GLOBAL HALT
```

```text id="swilaw1"
SINGLE_WRITE_INTENT_LAW (MANDATORY)

There MUST exist EXACTLY ONE authoritative write path into:

- decision_window_log
- worm_storage_log
- PRD-13 commit boundary

MANDATORY FLOW:

INGEST_GATEWAY
→ REPLAY_GUARD (validation ONLY)
→ PARTITION_ROUTER (routing ONLY)
→ DECISION_ENGINE

RULES:

- PARTITION_ROUTER MUST be the only service authorized to emit `decision_window_log`
- REPLAY_GUARD MUST NOT emit `decision_window_log`
- REPLAY_GUARD MUST NOT write to storage
- PARTITION_ROUTER MUST NOT write to storage
- DECISION_ORCHESTRATOR MUST be the only service authorized to emit `worm_storage_log`
- STORAGE_WRITER MUST be the only service authorized to write to PRD-13

VIOLATION:

Multiple write paths detected:

→ FAIL-CLOSED
→ ALERT
```

---

## SECTION: FINAL VALIDATION CHECKLIST (MANDATORY)

* No PRD duplication
* No authority conflict
* No hidden state
* Replay fully deterministic
* Kafka not required for correctness
* Storage is sole authority
