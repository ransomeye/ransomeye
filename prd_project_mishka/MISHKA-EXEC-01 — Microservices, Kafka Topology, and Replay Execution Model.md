```text id="doc01"
MISHKA-EXEC-01 — Microservices, Kafka Topology, and Replay Execution Model
```

```text id="doc02"
NON-AUTHORITATIVE — DERIVED FROM PRD-24
```

---

# 1. GLOBAL EXECUTION LAW

```text id="g1"
ALL SERVICES ARE STATELESS.

AUTHORITATIVE RUNTIME / EVENT STATE MUST EXIST ONLY IN:

- PRD-13 COMMITTED STORAGE (authoritative)

Kafka is NON-authoritative transport only.

This derived document MUST NOT claim that all Mishka state exists only in:
PRD-13 storage and Kafka logs.
```

```text id="g2"
NO SERVICE MUST STORE HIDDEN STATE.

Violation:
→ FAIL-CLOSED
```

---

# 2. SERVICE GRAPH (MANDATORY)

```text id="sgraph"
1. INGEST_GATEWAY
2. REPLAY_GUARD
3. PARTITION_ROUTER
4. DECISION_ENGINE
5. POLICY_ENGINE
6. SAFETY_GUARDRAILS_SERVICE
7. ENFORCEMENT_ENGINE
8. STORAGE_WRITER (CRITICAL)
9. REPLAY_ENGINE
```

---

# 3. SERVICE DEFINITIONS (EXACT)

## 3.1 INGEST_GATEWAY

INPUT:

* external signals (PRD-05 output)

OUTPUT:

* Kafka topic: `signal_ingest_log`

FUNCTION:

* transport termination, authN/authZ, framing, and raw-byte handoff (PRD-16)
* canonical validation, schema validation, signature verification, identity verification, replay admission, and durable queue admission (PRD-08)

FAILURE:

* reject → no Kafka write

STATE:

* NONE

---

## 3.2 REPLAY_GUARD

INPUT:

* `signal_ingest_log`

OUTPUT:

* deterministic direct handoff to `PARTITION_ROUTER`

FUNCTION:

* duplicate detection
* logical_clock enforcement
* replay protection

STATE:

* if `replay_guard_log` exists, it MUST be a NON-authoritative post-commit projection of PRD-13 `replay_guard` only
* correctness MUST NOT rely on Kafka compaction state
* replay admission correctness MUST be enforced by committed PRD-13 `replay_guard` only

---

## 3.3 PARTITION_ROUTER

INPUT:

* deterministic direct handoff from `REPLAY_GUARD`

OUTPUT:

* `decision_window_log`

KEY:

```text
partition_key = emitter_id
```

FUNCTION:

* deterministic partition routing
* strict ordering preservation

---

## 3.4 DECISION_ENGINE

INPUT:

* `decision_window_log`

OUTPUT:

* `worm_storage_log`
* `feature_vector_log`
* `detection_event_log`

FUNCTION:

* deterministic feature extraction
* correlation (bounded)

STATE:

* NONE (recomputable only)

---

## 3.5 POLICY_ENGINE

INPUT:

* `detection_event_log`

OUTPUT:

* `policy_decision_log`

FUNCTION:

* rule evaluation (PRD-11)
* deferred decision handling (bounded)

STATE:

* NONE

---

## 3.6 SAFETY_GUARDRAILS_SERVICE

INPUT:

* `policy_decision_log`

OUTPUT:

* `safety_evaluation_log`

FUNCTION:

* PRD-20 safety evaluation
* execution authorization token generation

STATE:

* NONE

---

## 3.7 ENFORCEMENT_ENGINE

INPUT:

* `safety_evaluation_log`

OUTPUT:

* `action_execution_log`
* `execution_result_log`

FUNCTION:

* action execution (PRD-12)
* sandbox invocation (external only)

RULE:

* MUST follow COMMIT_BOUND_EXECUTION_LAW

---

## 3.8 STORAGE_WRITER (CRITICAL)

INPUT:

* ALL FINAL LOGS:
  * `worm_storage_log`
  * `action_execution_log`
  * `execution_result_log`
  * `safety_evaluation_log`
  * `policy_decision_log`
  * `detection_event_log`

OUTPUT:

* PRD-13 storage
* `replay_guard_log`
* `storage_commit_log`

STATE MACHINE:

```text
RECEIVE → VALIDATE → BATCH → HASH → SIGN → COMMIT → ACK
```

MANDATORY:

* deterministic batching
* no partial commit
* hash-chain continuity

## STORAGE_WRITER_CONTEXT_LOCK (MANDATORY)

During batch construction:

1. capture execution_context_hash from first record
2. enforce equality for all subsequent records

---

IF mismatch:

→ ABORT BATCH
→ DO NOT COMMIT

FAILURE:

```text
FAIL-CLOSED → NO COMMIT
```

---

## 3.9 REPLAY_ENGINE

INPUT:

* PRD-13 committed storage ONLY

OUTPUT:

* recomputed logs (all topics)

FUNCTION:

* rebuild full system state
* verify deterministic equivalence

FORBIDDEN:

* reading from Kafka for replay

---

# 4. KAFKA TOPOLOGY (EXACT)

```text
signal_ingest_log
replay_guard_log (compacted)
decision_window_log
worm_storage_log
feature_vector_log
detection_event_log
policy_decision_log
safety_evaluation_log
action_execution_log
execution_result_log
storage_commit_log
```

---

# 5. PARTITIONING RULE

```text
partition_key = emitter_id
```

MANDATORY:

* strict ordering per emitter
* no cross-partition dependency

---

# 6. CONSUMER GROUP MODEL

Each service:

* MUST have its own consumer group
* MUST consume all partitions deterministically
* MUST NOT skip offsets

---

# 7. BACKPRESSURE MODEL

```text
STORAGE → KAFKA → INGEST → EDGE
```

RULES:

* storage pressure propagates upstream
* Kafka lag triggers ingest throttle
* CRITICAL signals preserved

---

# 8. REPLAY EXECUTION MODEL

Replay MUST:

1. read PRD-13 committed records
2. feed into Replay Engine
3. recompute ALL topics
4. compare outputs bit-for-bit

Mismatch:

```text
IF partition-scoped:
→ HALT PARTITION

IF dataset-wide:
→ GLOBAL HALT
```

---

# 9. OFFSET-COMMIT CONSISTENCY LAW (CRITICAL)

## 9.1 OFFSET PROCESSING RULE

```text
A Kafka message at offset_k MUST NOT be considered processed
until its resulting records are durably committed in PRD-13.
```

---

## 9.2 CONSUMER COMMIT RULE

```text
Kafka consumer offsets MUST be committed ONLY AFTER:

- Storage Writer commit succeeds
- batch_commit_record is finalized
- commit signature verified
```

---

## 9.3 PROCESSING MODEL

```text
CONSUME → PROCESS → EMIT → STORAGE COMMIT → OFFSET COMMIT
```

MANDATORY:

* offset commit MUST be downstream of storage commit
* no early offset acknowledgement allowed

---

## 9.4 FAILURE HANDLING

IF crash occurs BEFORE storage commit:

```text
- offset MUST NOT be committed
- message MUST be reprocessed
- system MUST produce identical output
```

---

## 9.5 IDEMPOTENCY REQUIREMENT

All downstream emissions MUST be:

```text
DETERMINISTIC + IDEMPOTENT
```

Such that:

```text
REPROCESSING → SAME OUTPUT → NO DUPLICATION EFFECT
```

---

## 9.6 FORBIDDEN

```text
FORBIDDEN:

- committing offsets before storage commit
- best-effort processing
- at-least-once without idempotency
```

---

# 10. TRANSACTIONAL COMMIT GROUP LAW (CRITICAL)

## 10.1 COMMIT GROUP DEFINITION

```text id="g1a9xk"
All records derived from a single root signal (message_id)
MUST NOT be treated as authoritative unless the required records are durably committed under the PRD-13 durable batch_commit_record commit boundary.
```

Group includes:

* safety_evaluation
* detection_event
* policy_decision
* action_execution
* execution_result

---

## 10.2 ATOMICITY RULE

```text id="b3q8vm"
Authoritative visibility under PRD-13 MUST be:

- fully committed
OR
- fully absent
```

FORBIDDEN:

* partial visibility
* partial commit

---

## 10.3 STORAGE WRITER REQUIREMENT

Storage Writer MUST:

```text id="d2k7op"
- stage records deterministically for PRD-13 append-only commit
- emit PRD-13 durable batch_commit_record commit boundary
- ensure no partial visibility of records beyond a batch_commit_record boundary
```

## 🔴 COMMIT COORDINATOR (MANDATORY)

`STORAGE_WRITER` MUST enforce:

```text
ALL records for one message_id:
→ MUST NOT be visible as authoritative unless covered by a PRD-13 durable batch_commit_record commit boundary
```

SHORT CHAINS:

* allowed ONLY if terminal state is present in committed `commit_group_status`

IF no terminal state exists:

```text
REJECT
→ FAIL-CLOSED
```

---

## 10.4 COMMIT GROUP IDENTIFIER

Each group MUST include:

```text id="f9r6jh"
commit_group_id = DERIVED (NON-AUTHORITATIVE)
```

---

## 10.5 REPLAY VALIDATION

NON-AUTHORITATIVE DERIVED NOTE:

This section MUST NOT redefine commit authority beyond PRD-13 / PRD-15.

Replay validation MUST follow PRD-15:

* authoritative visibility exists only after PRD-13 durable `batch_commit_record` commit
* no partial authoritative visibility within a committed batch boundary
* terminal-chain completeness and `commit_groups` semantics are REQUIRED only when the declared `validation_scope` INCLUDES terminal-chain completeness (PRD-15); there is no unconditional ALL-OR-NONE rule across every possible downstream record type independent of scope

Violation:

```text id="z1t8qa"
INTEGRITY_FAILURE / DETERMINISM_VIOLATION per PRD-15
→ FAIL-CLOSED
→ ALERT
```

---

## 10.6 FAILURE HANDLING

If commit fails:

```text id="c4w2ek"
- entire group MUST be discarded
- no record becomes visible
```

---

## 10.7 FORBIDDEN

```text id="n8y5lp"
FORBIDDEN:

- committing individual records independently
- exposing intermediate states
```

---

# 11. FORBIDDEN PATTERNS

```text
FORBIDDEN:

- service-to-service RPC
- shared memory
- local caches affecting output
- Kafka as source of truth
- time-based logic
```
