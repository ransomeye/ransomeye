# MISHKA-PRD-02 — Unified Architecture & Execution Model

**Project:** Project Mishka  
**Classification:** AUTHORITATIVE — UNIFIED ARCHITECTURE AND EXECUTION MODEL  
**Status:** FOUNDATIONAL — MERGED AND CORRECTED FROM PRIOR PRD-02

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

This document defines the authoritative architecture and runtime execution model of Project Mishka.

It assigns one owner to each system responsibility and removes overlap between architecture definition and execution orchestration.

This document governs:

* system layers
* the exact execution pipeline
* partitioning and horizontal scaling
* backpressure and survivability
* failure containment
* replay scope and correctness

If any component or future PRD contradicts this document, that component or document is invalid within this scope.

---

# 2. CORE PRINCIPLES

```text
Mishka is a deterministic, signal-first, dual-pipeline, partitioned cyber defense system.
```

The following principles are mandatory:

* Operational security decisions MUST flow through signed signals, never raw events.
* The runtime path MUST be ordered, durable, and replay-compatible.
* Scaling MUST occur through independent partitions, never through loss of ordering.
* Survivability MUST preserve integrity before fidelity.
* Local failures MUST be contained; global halt is permitted ONLY on integrity breach.
* The Decision Engine orchestrates processing; deterministic inference math is owned by the dedicated inference engine, not by the orchestrator.

Micro-hardening (PRD-01 alignment):

* canonical object field lock is mandatory (PRD-01 Section 3.1): unknown fields FORBIDDEN; optional fields MUST be omitted (no null/default)
* array determinism law is mandatory (PRD-01 Section 3.2): every array MUST have an explicit deterministic ordering rule; no implicit ordering
* hash function law is mandatory (PRD-01 Section 3.3): all authoritative hashes in this PRD MUST use `SHA256`

```text
System MUST degrade in fidelity, NEVER in integrity.
```

---

# 3. SYSTEM LAYERS (STRICT)

## 3.1 EDGE ACQUISITION AND SIGNALIZATION LAYER

### Owns

* raw telemetry capture
* protocol parsing
* deterministic feature extraction
* deterministic signal generation
* local append-only buffering
* identity binding
* cryptographic signing of emitted records
* parallel raw forensic record creation

### Emits

```text
1. signal_event
2. raw_record
```

### MUST NOT Own

* final threat decisions
* policy evaluation
* enforcement execution
* heuristic filtering

---

## 3.2 INGEST AND VALIDATION LAYER

### Owns

* acceptance of signed bytes at the trusted boundary
* canonical validation
* identity validation
* signing_context validation
* SHA256 hash computation
* Ed25519 signature verification
* batch Ed25519 verification as the default verification mode
* replay protection
* per-identity validation failure rate limiting
* validation quarantine state management
* acceptance or rejection of the event

### Output

```text
validated_event OR deterministic_rejection_code
```

### MUST NOT Own

* enrichment
* correlation
* policy logic
* action generation

---

## 3.3 DURABLE QUEUE AND PARTITION ROUTER

### Owns

* append-only queue admission
* disk-backed durability for accepted events
* logical shard key extraction
* deterministic logical shard mapping
* hot-entity split activation at epoch boundaries
* partition routing
* partition offset tracking
* partition epoch assignment
* single active consumer guarantee per partition

---

### 🔴 SINGLE SOURCE ROUTING LAW (CRITICAL)

PRD-02 OWNS ROUTING FORMULA  
ALL OTHER PRDs MUST REFERENCE ONLY

RULE

PRD-08 MUST NOT DEFINE ROUTING LOGIC

### Partition Key

```text
entity_id = agent_id if present; otherwise probe_id
logical_shard_id = shard_fn(entity_id, signed_shard_config, hot_split_selector)
routing_key = entity_id || logical_shard_id
```

### MUST NOT Own

* decision math
* policy logic
* action execution
* global serialization across unrelated partitions

---

## 3.4 DECISION ORCHESTRATION LAYER

### Owns

* ordered partition and logical-shard consumption
* deterministic grouping by entity and configured window
* complete feature vector construction
* invocation of deterministic inference
* deterministic correlation sequencing
* incident graph assembly
* detection object construction

### Output

```text
detection_event
```

### MUST NOT Own

* raw-event decision making
* probability table ownership
* Bayesian or other inference math implementation
* policy evaluation
* safety evaluation
* action execution
* model mutation at runtime

### Clarification

```text
Decision Orchestration sequences the analysis.
Deterministic inference math is executed only by the signed inference engine.
```

---

## 3.5 POLICY ENGINE

### Owns

* signed policy loading
* deterministic threshold evaluation
* deterministic rule evaluation
* mode enforcement
* single policy outcome selection

### Output

```text
policy_result
```

### MUST NOT Own

* modification of detection outputs
* action dispatch
* external data lookups
* multiple outcome selection

---

## 3.6 SAFETY GUARDRAILS LAYER

### Owns

* deterministic blast-radius evaluation
* protected-asset enforcement
* kill-switch enforcement
* confidence gating
* TTL execution eligibility (partition-seq delta bound only; no wall clock)
* rollback precondition enforcement
* execution authorization token issuance

### Output

```text
safety_result AND execution_authorization_token
```

### MUST NOT Own

* policy authoring
* action dispatch
* storage mutation
* hidden overrides

---

## 3.7 ENFORCEMENT ENGINE

### Owns

* action object creation
* action signing
* action dispatch
* execution_id issuance
* execution_state tracking
* execution acknowledgement tracking
* idempotent redispatch by action_id
* exactly-once enforcement coordination with the agent

### Output

```text
action_result
```

### MUST NOT Own

* policy authoring
* inference
* unsigned execution

---

## 3.8 STORAGE AND REPLAY LAYER

### Owns

* durable storage of signals, detections, policy results, actions, raw records, and audit logs
* append-only writes
* tiered retention
* WORM retention for immutable tiers
* replay dataset construction
* cryptographic verifiability of stored artifacts

### Storage Tiers

* HOT: recent operational signals, detections, policy results, actions
* WARM: indexed aggregates, replay indexes, incident graph materializations
* COLD: immutable WORM archives for raw records and authoritative historical artifacts

### Commit Integrity Requirement

Authoritative storage commit boundary is owned by PRD-13.

Storage commit MUST satisfy PRD-13 durable `batch_commit_record` commit-boundary model only.

```text
authoritative commit boundary = PRD-13 durable batch_commit_record only
```

Mandatory:

* every artifact in the batch MUST be hash-linked into the same PRD-13 durable `batch_commit_record`
* no artifact in that batch is authoritative until the PRD-13 `batch_commit_record` is durable

### MUST NOT Own

* mutation of previously committed authoritative records
* heuristic compaction
* silent data discard

---

## 3.9 CONTROL PLANE

### Owns

* UI write workflows for all control features
* UI read visibility for all control features
* UI trace visibility for all control features
* UI validation workflows for all control features
* SOC access
* query and hunt workflows
* human approval where policy mode requires it
* signed configuration and policy distribution
* audit visibility

```text
ALL CONTROL PLANE WRITES MUST PRODUCE:

SIGNED OBJECT
VERSIONED SNAPSHOT
STORAGE RECORD

NO DIRECT MUTATION ALLOWED
```

### MUST NOT Own

* CLI control of authoritative runtime behavior
* direct mutation of runtime state outside signed control objects
* backend-only toggles
* hidden APIs
* direct DB edits
* bypass of the execution pipeline
* trust overrides

---

# 4. END-TO-END EXECUTION PIPELINE

The operational decision pipeline is fixed.

```text
Ingest -> Validate -> Queue -> Partition -> Decision -> Correlation & Confidence Layer -> Policy Engine -> Safety Guardrails Layer -> Enforcement Engine -> Storage
```

```text
GLOBAL_INVARIANT

NO STAGE MUST BE SKIPPED, REORDERED, OR BYPASSED = TRUE
```

```text
AUTHORITATIVE_EXECUTION_BOUNDARY (MANDATORY):

Authoritative Mishka System includes ONLY:

- Edge
- Ingest
- Queue
- Partition
- Decision
- Policy
- Safety
- Enforcement
- Storage
- Replay

OPAIF is EXPLICITLY OUTSIDE this boundary.

LLMs / RAG / Generative AI:

- MUST NOT exist inside Authoritative Execution Boundary
- MUST exist ONLY in OPAIF (external system)

VALIDATION RULE (CRITICAL):

If any LLM output enters:

- signal_event
- detection_event
- policy_result
- action_object

→ REJECT → FAIL-CLOSED → ALERT
```

```text
AUTHORITATIVE PIPELINE PURITY:

ALL STAGES:
Ingest → Decision → Policy → Enforcement

MUST REMAIN:

- deterministic
- replay-safe
- non-probabilistic

NO EXTERNAL MODEL CALLS PERMITTED.
```

```text
EXECUTION_CONTEXT_LOCK (CRITICAL):

execution_context_hash = SHA256(
  policy_snapshot_hash ||
  model_snapshot_hash ||
  config_snapshot_hash ||
  shard_config_hash ||
  schema_version_set
)

RULE:

Every partition MUST process events under ONE execution_context_hash.

ENFORCEMENT:

If an incoming event references a different execution_context_hash:

→ HALT PARTITION
→ FAIL-CLOSED
→ ALERT

FORBIDDEN:

- mixed-context execution within partition
- silent config switching
```

## 4.1 Stage Definitions

### Ingest

Accept signed event bytes and route them only to validation.

Ingest MUST enforce:

* minimum data rate
* per-identity connection limits

Ingest connection control thresholds MUST derive from signed configuration.

### Validate

Execute the following order exactly:

```text
1. Canonical validation
2. Identity validation
3. signing_context validation
4. SHA256 computation
5. Ed25519 signature verification
6. Replay check
```

Batch Ed25519 verification MUST be the default mode.

Single-event Ed25519 verification is permitted ONLY when:

* batch size is one
* deterministic isolation of a failed batch member is required

FAILURE ATTRIBUTION MODEL:

Validation failures MUST be counted using:

* source_tuple (IP + connection fingerprint)
* bound identity tuple ONLY AFTER a signature verification attempt has executed using the resolved public key for that identity

UNBOUND_IDENTITY_FAILURE:

If identity cannot be cryptographically bound:
→ classify as UNBOUND_FAILURE
→ DO NOT increment identity failure counter

Quarantine MUST trigger ONLY after:

* identity binding verification has executed
* a signature verification attempt has executed against the bound identity candidate

Events that fail before these steps MUST be rejected but MUST NOT contribute to quarantine state for any valid identity.

Unverified identities MUST NOT quarantine valid identities.

VALID_IDENTITY_PROTECTION:

Valid identities MUST NOT be quarantined due to:

* pre-verification failures
* spoofed identity claims

If validation failures for the same identity tuple exceed the signed threshold within the signed window:

```text
identity_state = QUARANTINED
```

While quarantined:

* the identity tuple MUST be rejected with `QUARANTINED_IDENTITY`
* quarantine duration MUST be deterministic
* exit from quarantine MUST occur only by expiry of the signed timeout or signed administrative release

Any failure:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

### Queue

Persist the validated event to the append-only durable queue.

Admission rule:

```text
persist(event) OR return RESOURCE_EXHAUSTED
```

### Partition

Compute deterministic partition assignment and append the event to its partition-ordered stream.

Routing rule:

```text
partition_slot = UINT32_BE(SHA256(routing_key)[0:4]) mod partition_count
partition_id = ENTITY_ROUTE_MAP[partition_epoch, partition_slot].partition_id
```

Logical shard mapping MUST be deterministic within the active partition epoch.

`ENTITY_ROUTE_MAP` MUST be the signed authoritative route map for the same `partition_epoch`.

`partition_id` MUST be globally unique. `global_partition_id` is invalid and forbidden.

Hot-entity splitting is permitted ONLY through signed shard configuration.

### Decision

Consume the ordered partition stream, build deterministic windows, construct complete feature vectors, invoke the deterministic inference engine, build correlation context, and emit `detection_event`.

### Correlation & Confidence Layer

Derive deterministic confidence and correlation governance fields from authoritative detection output.

The Correlation & Confidence Layer MUST:

* preserve the authoritative partition-local ordering established upstream
* derive governance-ready `confidence_score`, `correlation_strength`, and `confidence_vector`
* emit only deterministic fields suitable for downstream policy and safety evaluation

### Policy Engine

Evaluate the detection against the signed policy set in deterministic rule order and emit one `policy_result`.

### Safety Guardrails Layer

Evaluate blast radius, protected assets, kill switches, confidence gating, TTL eligibility, rollback definition, and execution authorization before enforcement.

```text
GLOBAL_INVARIANT

NO STAGE MUST BE SKIPPED = TRUE
```

### Enforcement Engine

Generate one deterministic `action_result`.

`action_result` MUST be one of:

```text
NO_ACTION
PENDING_APPROVAL
DISPATCHED_ACTION
```

If an action is dispatched, it MUST be signed and idempotent by `action_id`.

If an action is dispatched, it MUST also include:

```text
execution_id
execution_state
```

The agent MUST enforce exactly-once execution by `execution_id`.

Exactly-once enforcement is mandatory:

* the agent MUST persist `execution_id` before effecting the action
* a duplicate `execution_id` MUST NOT re-execute the action
* duplicate delivery MUST resolve to the previously persisted `execution_state`
* the agent MUST return `execution_result`
* the agent MUST return `execution_verification_state`

Core MUST validate intended effect versus actual effect using:

* the dispatched action object
* `execution_result`
* `execution_verification_state`

If `execution_verification_state` does not match the expected outcome, the system MUST:

* emit CRITICAL `signal_event`
* trigger policy re-evaluation
* optionally re-dispatch corrective action using idempotent identifiers
* mark the incident as `enforcement_failure`

### Storage

Commit the authoritative artifacts in the following order:

```text
1. signal reference and partition metadata
2. detection_event
3. policy_result
4. action_result
5. stage audit record
```

Offset commit for the processed partition MUST occur only after storage commit succeeds.

Storage commit MUST use:

```text
PRD-13 durable batch_commit_record only
```

The PRD-13 `batch_commit_record` is the authoritative commit boundary.

## 4.2 Parallel Forensic Path

The raw forensic path is mandatory but does not alter the ordered operational pipeline.

```text
raw telemetry -> append-only raw_record -> signed durable storage -> WORM archive
```

The forensic path MUST preserve replay-relevant raw information and MUST NOT bypass the operational path.

---

# 5. DETERMINISTIC PROCESSING LAW

For a given partition, identical:

```text
validated inputs + partition order + signed configuration + model version + policy version
```

MUST produce identical:

```text
detection_event + policy_result + action_result + storage artifacts
```

Per-partition equality is:

```text
BIT-FOR-BIT IDENTICAL
```

Determinism requirements:

* all arithmetic in decision paths MUST use fixed-point or other formally deterministic integer-safe methods
* iteration order MUST be explicit
* missing feature values MUST be explicit zero, never implicit null
* retries MUST be jitter-free and configuration-derived
* if caches exist, they MUST exist only as performance mirrors of authoritative state and MUST NOT change outputs
* side effects MUST be derived from canonical signed inputs only
* aggregation MUST be deterministic
* aggregation for CRITICAL and HIGH signals MUST be reversible OR reconstructable

The following construction is mandatory:

```text
ordered_signals -> feature_vector -> inference_engine -> detection_event -> policy_result -> action_result
```

```text
DETERMINISTIC PARALLELISM LAW:

PARALLEL EXECUTION IS ALLOWED ONLY IF:

- INPUT PARTITIONS ARE ISOLATED WITH:
  - no shared mutable state
  - no implicit cross-partition causal dependency
- NO SHARED MUTABLE STATE EXISTS
- FINAL OUTPUT ORDER IS RECONSTRUCTED USING AUTHORITATIVE ORDERING

PARALLELISM MUST NOT CHANGE:

- output bytes
- ordering
- replay outcome
```

```text
FINAL OUTPUT ORDER:

FOR EACH partition_id:
SORT BY partition_record_seq ASC

NO CROSS-PARTITION TOTAL ORDER
```

```text
PARALLEL EXECUTION PROOF:

FOR ANY EXECUTION:

parallel_output_sorted == serial_output
```

```text
PARALLELISM UNIT = PARTITION

WITHIN PARTITION:
→ STRICTLY SERIAL

ACROSS PARTITIONS:
→ PARALLEL ALLOWED
```

The following is forbidden:

* randomness in production execution
* wall-clock branching in decision paths
* floating-point arithmetic in authoritative decision logic
* any second implementation of inference math inside the Decision Orchestrator

---

# 6. PARTITIONING & SCALING MODEL

## 6.1 Partition Law

The system is NOT a single-writer system.

The system is a:

```text
multi-partition system with deterministic logical shards and one active ordered consumer per physical partition
```

## 6.2 Partition Guarantees

* every event is assigned to exactly one logical shard and one physical partition
* every logical shard has deterministic partition-local ordering only
* each physical partition MUST execute on exactly one thread at a time
* every physical partition has deterministic merge order across its assigned logical shards
* multiple physical partitions MUST be permitted to execute in parallel across CPU cores when partition ownership is disjoint
* unrelated partitions MUST be permitted to execute in parallel
* parallel execution MUST NOT introduce race conditions, shared mutable state, or non-deterministic ordering
* parallel execution MUST NOT change outputs
* one partition failure MUST NOT invalidate unrelated partitions

```text
PARTITIONS ARE ISOLATED EXECUTION UNITS

SHARING STATE:
→ FORBIDDEN
```

## 6.3 Scaling Method

Horizontal scaling MUST occur by:

* increasing partition count
* increasing logical shards for hot entities
* increasing worker count
* rebalancing partitions at deterministic offset boundaries
* scaling storage independently of partition execution

---

## 🔴 HOT PARTITION SPLIT (DETERMINISTIC) (CRITICAL)
RULE

IF hot-partition split conditions are satisfied, logical sharding MUST be increased deterministically:
new_logical_shard_id = SHA256(
  entity_id ||
  shard_split_epoch ||
  shard_index
)
CONDITIONS

Split MUST occur only when:

partition_lag > signed_threshold
AND shard_split_epoch incremented (signed config)
HARD LAW
SPLIT MUST BE CONFIG-DRIVEN
NOT RUNTIME-DECIDED
REPLAY LAW
same shard_split_epoch → same partition mapping

## 6.4 Repartitioning Rule

Repartitioning MUST be configuration-driven and epoch-based.

The following sequence is mandatory:

```text
1. publish signed partition and logical-shard configuration with new partition_epoch
2. drain existing offsets to a commit boundary
3. activate new routing map at the defined boundary
4. resume processing under the new epoch
```

No event may be processed by two active consumers in the same partition epoch.

Hot-entity splitting MUST activate only at the published epoch boundary.

## 6.5 Cross-Partition Behavior

Cross-partition correlation is allowed only through explicit causal references and deterministic correlation inputs.

Cross-partition correlation MUST be causal-only.

Arrival order of unrelated partitions MUST NOT affect correlation outputs.

Cross-partition behavior MUST NOT require a globally serialized writer.

CAUSAL_DEPENDENCY_BOUND (MANDATORY):

Any cross-partition dependency MUST declare:

* max_dependency_depth

NO_WAIT_FOR_FUTURE_DATA (MANDATORY):

System MUST NOT block waiting for:

* future commits
* external partitions

EXECUTION RULE (MANDATORY):

If a cross-partition dependency cannot be resolved within:

* declared max_dependency_depth
* available committed graph

THEN:

* emit PARTIAL_CORRELATION signal
* continue execution

FORBIDDEN:

* waiting for future data
* blocking on unresolved partition

---

# 7. BACKPRESSURE & FLOW CONTROL

## 7.1 Propagation Chain

Backpressure MUST propagate in reverse execution order across the entire system:

```text
Storage -> Actuation -> Enforcement -> Safety -> Policy -> Decision -> Partition -> Queue -> Validate -> Ingest -> Edge Buffer -> Source
```

The following are mandatory:

* backpressure MUST extend beyond storage to ingestion, decision, and execution
* no data loss is permitted during backpressure propagation
* components MUST throttle admission when downstream capacity is reached

```text
BACKPRESSURE ESCALATION LEVELS:

LEVEL 1: Slow ACK (throttle)
LEVEL 2: Queue saturation → reject new ingest
LEVEL 3: Partition pause (localized)
LEVEL 4: Global halt ONLY on integrity failure

NO DIRECT TCP RESET FROM STORAGE LATENCY.
```

```text
STORAGE LATENCY MUST NOT BE A SINGLE POINT OF FAILURE (SPOF)
```

## 7.2 Admission and Rejection Rules

An event may be rejected only for one of the following deterministic reasons:

* validation failure
* replay violation
* integrity failure
* resource exhaustion before durable admission

If durable admission fails:

```text
return RESOURCE_EXHAUSTED
```

The receiver MUST NOT pretend success.

## 7.3 Retry Behavior

Retry scheduling MUST be deterministic and MUST derive from signed configuration.

The retry function is:

```text
retry_delay(n) = min(base_delay_ms * 2^n, max_delay_ms)
```

The following are forbidden:

* random jitter
* unbounded retry loops without durable buffering
* silent retry suppression

## 7.4 Edge Buffer Rules

Edge components MUST maintain a bounded append-only local buffer for undelivered records.

The edge buffer capacity MUST be defined by signed configuration.

If upstream rejects with `RESOURCE_EXHAUSTED`:

* CRITICAL records MUST retain reserved local capacity
* HIGH records MUST remain buffered or MUST be deterministically aggregated according to signed priority policy
* NORMAL records MUST be delayed the longest

Eviction is permitted ONLY for NORMAL priority records.

NORMAL eviction is permitted ONLY if:

* upstream durable commit is confirmed
* OR reconstruction is possible locally using only the retained aggregate record, retained metadata, and deterministic algorithm without upstream dependency

No buffered record may be silently dropped.

## 7.5 Flow-Control Invariant

```text
No signal loss is permitted through flow control.
Flow control MUST only delay or aggregate.
Flow control MUST NOT discard.
```

---

# 8. FAILURE ISOLATION MODEL (NEW — CRITICAL)

Failure containment is mandatory.

## 🔴 FAILURE SCOPE LAW (CRITICAL)

DEFAULT:

```text
FAILURE → PARTITION-LOCAL HALT
```

GLOBAL HALT ONLY IF:

* replay determinism is violated under PRD-15
* storage integrity is broken under PRD-13
* `execution_context_hash` mismatch is detected across partitions for the same committed validation scope

FORBIDDEN:

* escalation from partition failure to global halt without one of the invariant breaches above

```text
System MUST NOT globally halt unless integrity is broken.
```

```text
FAILURE MUST NOT CASCADE UNLESS:

- cryptographic integrity fails
- ordering breaks
```

## 8.1 Level 1 - Local Fail-Closed

Definition:

* the failing component rejects the local unit of work or stops itself
* unrelated components and partitions continue

Examples:

* invalid signature
* malformed canonical payload
* one worker crash
* one probe offline

Required behavior:

```text
reject_or_stop_local_component -> preserve remainder of system
```

```text
PARTITION MUST NOT STALL INDEFINITELY

IF NO PROGRESS:

→ FORCE STATE TRANSITION
OR
→ HALT PARTITION EXPLICITLY
```

## 8.2 Level 2 - Degraded Mode

Definition:

* the affected subsystem continues with reduced fidelity
* integrity, ordering, and auditability remain intact

Examples:

* increased aggregation window
* delayed NORMAL delivery
* reduced control-plane query concurrency

Required behavior:

```text
continue_with_reduced_fidelity -> preserve integrity
```

## 8.3 Level 3 - Continue With Audit Flag

Definition:

* processing continues only when the integrity of authoritative inputs is still intact
* the produced record is marked for replay validation

Mandatory fields on continued output:

```text
audit_flag = true
replay_validation_required = true
```

Allowed use:

* delayed action acknowledgement
* temporary loss of non-authoritative observability path
* partition reassignment recovery after a worker crash

Forbidden use:

* trust failure
* signature failure
* queue durability failure for accepted CRITICAL work

## 8.4 Global Halt Conditions

Global halt is authorized ONLY if one of the following is true:

* the root of trust is invalid
* signed configuration integrity is broken
* authoritative storage integrity is broken
* durable queue integrity is broken
* accepted CRITICAL records can no longer be durably retained anywhere within the trusted system boundary

If a global halt condition is detected, the system MUST first enter:

```text
FAIL_CLOSED_EVENT
```

During `FAIL_CLOSED_EVENT`:

* new non-recovery admissions MUST be rejected
* deterministic retry and revalidation MUST execute for the signed retry window
* the retry window and halt timeout MUST be defined by signed configuration

Global halt becomes mandatory only if the qualifying condition still exists when the halt timeout expires.

Any other failure MUST be contained to event, partition, component, or subsystem scope.

---

# 9. DETERMINISTIC DEGRADATION MODEL (NEW — MUST ADD)

Degradation is a controlled state machine, not an operator preference.

State transitions MUST be triggered only by signed numeric thresholds over:

* queue occupancy
* partition lag
* disk utilization
* worker saturation

## 9.1 Priority Classes

### CRITICAL

Includes:

* execution events
* privilege escalation signals
* lateral movement signals
* trust or integrity violations
* enforcement actions and execution status

Rule:

```text
CRITICAL signals MUST NEVER be dropped.
CRITICAL signals MUST bypass scheduler delay once durable capacity exists.
```

### HIGH

Includes:

* aggregated security signals
* detections
* policy results
* incident graph updates

Rule:

```text
HIGH signals MUST be delayed only within the signed `high_priority_delay_bound`.
HIGH signals MUST use only the signed `high_priority_aggregation_window`.
HIGH signals MUST remain reconstructable.
```

### NORMAL

Includes:

* raw redundancy copies
* non-authoritative operational diagnostics
* replay-reconstructable duplicate materializations

Rule:

```text
NORMAL signals MUST be delayed only within the signed `normal_priority_delay_bound`.
NORMAL signals MUST be compacted only by deterministic, reversible methods.
```

Aggregation rule:

```text
Aggregation MUST be deterministic.
Aggregation for CRITICAL and HIGH signals MUST be reversible OR reconstructable.
Irreversible aggregation is FORBIDDEN.
```

Every aggregated record MUST include:

* aggregation_proof
* reconstruction_metadata

`aggregation_proof` MUST include:

* `hash(input_set)`
* `aggregation_algorithm_id`
* `hash(output_aggregate)`

`aggregation_proof` MUST be:

* signed
* OR cryptographically chained into storage

Reconstruction MUST be possible using ONLY:

* the aggregated record
* reconstruction_metadata
* deterministic algorithm

External dependencies are FORBIDDEN.

## 9.2 Degradation Actions

When resource pressure is active, the system MUST apply the following controls in order:

```text
1. increase NORMAL aggregation window
2. delay NORMAL dispatch
3. increase HIGH aggregation window
4. reduce non-critical control-plane consumption
5. reserve remaining capacity for CRITICAL and HIGH
```

The following are forbidden:

* dropping CRITICAL records
* unsignaled mode changes
* heuristic operator-driven degradation
* irreversible aggregation

## 9.3 Degradation Audit

Every degradation transition MUST emit a signed audit record containing:

* cause
* threshold crossed
* affected scope
* entered state
* exit condition

---

# 10. STATE MANAGEMENT RULES

## 10.1 Allowed State

Only the following mutable runtime state is allowed:

* partition offsets
* partition epochs
* deterministic sliding windows
* deterministic aggregation buffers
* partition-local replay guards
* retry counters
* incident graph state derived from persisted inputs
* validation failure counters
* quarantine timers
* exactly-once execution ledgers

## 10.2 State Constraints

All decision-relevant state MUST be:

```text
explicit + persisted OR reconstructable + deterministic
```

All mutable runtime state MUST be one of:

* partition-scoped
* globally signed configuration state
* globally signed model state
* globally signed policy state

Replay guards MUST be partition-local or logical-shard-local.

Replay guards MUST NOT require global serialization.

Replay guards MUST support:

* deterministic expiration
* partition-local compaction
* bounded storage growth

```text
MANDATORY MEMORY LIMITS:

max_open_windows_per_partition
max_replay_guard_entries
max_inflight_signals

EXCEED:
→ FAIL-CLOSED OR BACKPRESSURE
```

## 10.3 Commit Rule

The authoritative processing boundary is:

```text
storage_commit_success -> partition_offset_commit
```

Partition offsets MUST NOT advance before storage commit succeeds.

All authoritative writes MUST be atomic and durable.

Partial writes MUST NOT be visible.

State MUST be recoverable after crash.

## 10.4 Action Idempotency Rule

Every dispatched action MUST have a deterministic `action_id`.
Every dispatched action MUST have a deterministic `execution_id`.

Redispatch after failure MUST reuse the same `action_id`.
Redispatch after failure MUST reuse the same `execution_id`.

This is mandatory to preserve correctness when:

* action dispatch succeeds
* storage commit fails
* the partition is replayed

The authoritative execution safety rule is:

```text
one execution_id -> one enforcement effect at the agent
```

Crash MUST NOT cause duplicate execution.

Crash MUST NOT cause inconsistent replay state.

## 10.5 Forbidden State

* hidden in-memory-only decision state
* mutable runtime model tables
* unsnapshotted global counters affecting output
* cache state that changes authoritative behavior

On restart, the system MUST:

```text
1. load the last consistent durable state
2. validate integrity
3. replay incomplete operations
4. resume processing without data loss
```

The system MUST auto-start on machine boot.

The system MUST auto-restart on process failure.

The system MUST implement bounded retry with backoff.

System MUST operate under a deterministic process supervision layer.

The supervision layer MUST guarantee:

* automatic process start on system boot
* automatic restart on process failure
* bounded restart retry with backoff
* visibility into process health state

The supervision mechanism MUST NOT:

* bypass application-level recovery logic
* introduce non-deterministic execution behavior

Crash MUST NOT cause signal loss.

---

# 11. ORDERING & CLOCK MODEL (AUTHORITATIVE)

The system MUST use a multi-layered deterministic ordering model.

## 11.1 Authoritative Ordering Inputs

```text id="7mtc2g"
GLOBAL ORDERING PRECEDENCE (MANDATORY):

1. partition_record_seq (PRIMARY)
2. shard_seq (EQUAL TO partition_record_seq)
3. logical_clock (DERIVED / LOCAL ORDER ONLY)

ALL ORDERING RULES MUST FOLLOW THIS EXACT PRECEDENCE
```

The authoritative ordering inputs are:

1. **partition_record_seq**: Strict per-partition monotonic counter allocated at authoritative storage commit.
2. **shard_seq**: Strict per-logical-shard sequence equal to `partition_record_seq`.
3. **logical_clock**: Strict per-session monotonic counter (+1) starting at 0, used only for emitter-local session continuity.
4. **window_id**: Deterministic identifier for a decision window, derived from `partition_record_seq` bounds only.

## 11.2 Wall-Clock Prohibition (CRITICAL)

The system MUST NOT use wall-clock time for:

* authoritative ordering
* hash construction
* message or entity identity
* decision branching

If wall-clock time exists, it MUST exist ONLY for observability and performance measurement.

Any implementation that allows wall-clock time to affect the bit-for-bit output of a decision is invalid.

## 11.3 Causal Ordering

Cross-partition relationships MUST be represented by explicit causal metadata:

* entity identifiers
* message identifiers
* causal references
* logical clocks

Cross-partition correlation MUST depend only on causal metadata and signed correlation inputs.

Cross-partition correlation MUST NOT depend on arrival order, scheduler order, or transport timing.

```text id="1q5p3d"
ANY MERGE / VIEW / AGGREGATION MUST RESOLVE TO:

FOR EACH partition_id:
SORT BY partition_record_seq ASC

NO CROSS-PARTITION TOTAL ORDER
```

## 11.4 Windowing Rule

Decision windows MUST be defined by signed configuration and evaluated against authoritative sequence and logical-clock metadata.

Window evaluation MUST NOT depend on local scheduler timing.

---

# 12. REPLAY COMPATIBILITY CONTRACT (FIXED)

Replay correctness is scope-bound.

## 12.1 Per-Partition Replay

For the same partition input stream, with the same:

* ordered validated events
* partition epochs
* signed configuration
* model version
* policy version

Replay MUST produce:

```text
bit-for-bit identical outputs for that partition
```

Where logical shards are enabled, the same guarantee MUST hold per logical shard within the partition epoch.

## 12.2 Per-Entity Replay

If an entity is fully contained within one logical shard, replay for that entity MUST also be bit-for-bit identical.

## 12.3 Global Replay

Global replay correctness is:

```text
GLOBAL REPLAY MUST PRODUCE BIT-FOR-BIT IDENTICAL OUTPUT
```

Global replay MUST preserve:

* the same per-partition outputs
* the same detections for the same entities
* the same policy outcomes
* the same action results
* the same causal relationships across partitions

Global replay MUST preserve byte-identical global merge ordering.

## 12.4 Replay Invalidators

Replay is invalid if any of the following differ from the original execution scope:

* signed configuration
* model version
* policy version
* partition mapping function
* authoritative input set

---

# 13. PERFORMANCE MODEL

Performance optimization is valid only if correctness is unchanged.

## 13.1 Hot-Path Bounds

The following requirements are mandatory:

* ingest to durable queue admission MUST complete in under 10 ms under non-degraded in-capacity operation
* queue admission and partition routing MUST be constant-time with respect to partition count, excluding cryptographic verification cost
* decision cost per partition MUST be bounded by signed maximum window size and fixed feature vector size
* storage commit cost MUST be bounded and measurable for every processed partition batch

## 13.2 Scaling Behavior

Throughput MUST scale by:

* increasing independent partitions
* increasing workers up to the number of runnable partitions
* expanding storage bandwidth independently of compute

Throughput MUST NOT depend on:

* one global execution lock
* one global writer
* unordered shared mutable state

## 13.3 Resource Reservation

Reserved CPU, memory, queue capacity, and storage bandwidth MUST exist for CRITICAL traffic.

Control-plane activity MUST NOT consume reserved CRITICAL capacity.

System MUST enforce CPU isolation between:

* validation pipeline
* decision pipeline
* action pipeline

CRITICAL processing MUST have reserved compute capacity.

If GPU acceleration is used, it MUST be used only as an acceleration layer for:

* batch cryptographic verification
* batch hashing
* deterministic inference execution (PRD-10 SINE)

GPU execution MUST:

* produce identical results as CPU
* use deterministic kernels
* NOT affect ordering
* NOT affect decision logic

GPU MUST NOT be required for correctness.

CPU MUST remain the authoritative execution layer.

## 13.4 Required Metrics

The system MUST expose at minimum:

* queue depth by partition
* partition lag
* validation rejection count by reason
* decision latency by partition
* storage commit latency
* degradation state
* action dispatch retry count

---

# 14. SECURITY MODEL

## 14.1 Trusted Boundary

The trusted boundary begins only at:

```text
verified, signed, identity-bound event bytes
```

The following are untrusted until verified:

* network transport
* endpoint origin
* probe origin
* external service responses
* operator-provided runtime input

## 14.2 Verify-Before-Use

Nothing may be parsed, processed, executed, or stored as trusted before validation succeeds.

Mandatory rule:

```text
verify -> admit -> process
```

## 14.3 Signed Authority Objects

The following MUST be signed authoritative objects:

* configuration
* models
* policies
* actions

Unsigned or partially verified authority objects are invalid.

## 14.4 Identity Propagation

Every authoritative runtime record MUST remain identity-bound through the pipeline.

Identity loss at any stage is an integrity failure.

## 14.5 Auditability

All stage transitions, degradation transitions, failures, and actions MUST be durably logged in append-only storage.

---

# 15. FORBIDDEN PATTERNS

```text
FORBIDDEN:

- Parsing unverified input
- Decision making from raw events
- Heuristic filtering or heuristic degradation
- Silent drop under load
- Irreversible aggregation
- Global single-writer execution model
- More than one active consumer for the same partition in the same epoch
- Global replay-guard serialization
- Decision Orchestrator reimplementing inference math
- Floating-point or hardware-dependent math in authoritative decision paths
- Wall-clock ordering as the correctness source
- Hidden in-memory-only decision state
- Unsigned configuration, model, policy, or action objects
- Best-effort trust mode
- Global halt for a partition-local or component-local failure
- Immediate global halt without the signed retry window for a qualifying halt condition
- Randomized retry or scheduling behavior
- Control-plane bypass of the runtime pipeline
- Mutation of authoritative committed records
```

---

# 16. SUMMARY

```text
Mishka architecture and execution model is:

- Signal-first
- Dual-pipeline
- Deterministic
- Partitioned
- Horizontally scalable
- Fail-closed on integrity breach
- Survivable under resource pressure
- Replay-correct by scope

Correctness requires:
Ingest -> Validate -> Queue -> Partition -> Decision -> Correlation & Confidence Layer -> Policy Engine -> Safety Guardrails Layer -> Enforcement Engine -> Storage

No deviation is permitted.
```

---
