# MISHKA-PRD-18 — Observability, Resilience & Self-Healing

**Project:** Project Mishka  
**Classification:** AUTHORITATIVE — PASSIVE OBSERVABILITY, FAIL-CLOSED RESILIENCE, AND NON-MUTATING SELF-HEALING  
**Status:** CRITICAL — READ-ONLY MONITORING, COMMIT-BOUNDARY RECOVERY, DETERMINISTIC SUPERVISION

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

This document defines the authoritative observability, resilience, and self-healing layer for Project Mishka.

Its purpose is to:

* observe system behavior without changing system behavior
* derive logs, metrics, traces, and alerts from authoritative committed state
* supervise deterministic restart and failover behavior
* preserve replay correctness, ordering, and committed data integrity during recovery

This layer MUST monitor the system without introducing:

* non-deterministic execution behavior
* authoritative state mutation
* adaptive runtime feedback into routing, ordering, or replay

---

# 2. CORE PRINCIPLES

```text
OBSERVABILITY IS PASSIVE.
RESILIENCE IS COMMIT-BOUNDARY ANCHORED.
SELF-HEALING MUST NOT MUTATE AUTHORITATIVE DATA.
```

The following principles are mandatory:

* observability MUST read from authoritative committed state only
* observability MUST NOT influence execution
* resilience MUST restart from last committed state only
* self-healing MUST use only upstream-authorized restart and failover mechanisms
* any ambiguity MUST result in alert
* silent correction is FORBIDDEN
* observability data MUST remain isolated from authoritative core data

There is no adaptive tuning mode, silent repair mode, or best-effort correction mode.

---

# 3. OBSERVABILITY MODEL (CRITICAL)

Observability is a read-only derivation layer over authoritative committed state.

```text
OBSERVABILITY MUST BE:

- derived from committed records
- NOT real-time dependent

LOGS MUST BE REPLAYABLE
```

The authoritative observability inputs are:

* committed `partition_records`
* committed `batch_commit_records`
* committed `authority_snapshots`
* committed replay-validation artifacts
* committed failover and fencing state
* process health state derived ONLY from:
  * committed authoritative state
  * deterministic counters
  * explicitly defined inputs

The following are mandatory:

* observability MUST read from authoritative committed state only
* observability MUST NOT read from transient, buffered, provisional, or uncommitted state as authoritative input
* observability MUST NOT read from WAL, in-flight queue buffers, or speculative execution state as authoritative input
* observability MUST NOT influence execution, routing, ordering, storage commit, replay, or failover authority
* implicit OS state, runtime heuristics, or hidden metrics are FORBIDDEN
* identical committed state under identical supervisory configuration MUST produce identical canonical observability payloads

If authoritative committed observability input cannot be established exactly:

```text
ALERT -> FAIL-CLOSED OBSERVABILITY DECISION
```

---

# 4. LOGGING MODEL

Logging MUST be derived from deterministic state transitions and deterministic fail-closed outcomes.

The following are mandatory:

* logs MUST be derived from deterministic state
* logs MUST NOT influence system behavior
* log payload fields derived from committed state MUST be emitted in deterministic order
* canonical log payloads MUST be RFC 8785 canonical JSON
* log emission failure MUST NOT modify authoritative execution state

```text
ordering_ref = partition_record_seq
```

The authoritative log payload MUST exclude hidden mutable state.

---

# 5. METRICS MODEL

Metrics are passive derived measurements only.

The following are mandatory:

* metrics MUST be passive
* metrics MUST be derived from committed state, verified process health, or deterministic counters
* metrics MUST NOT drive adaptive system behavior
* metrics MUST NOT affect routing, ordering, replay, leader election, or storage commit
* metrics export failure MUST NOT alter authoritative execution behavior

```text
SEQUENCE-DERIVED METRICS:

rate = delta(events) / delta(partition_record_seq)
```

---

# 6. TRACING MODEL

Tracing is observational only.

The following are mandatory:

* tracing MUST be observational only
* tracing MUST NOT alter execution path
* tracing MUST NOT introduce ordering changes
* trace identifiers MUST be derived from existing authoritative identifiers where applicable
* trace payloads MUST represent already-chosen execution paths only
* trace capture failure MUST NOT block authoritative execution

ordering_ref = partition_record_seq

---

# 7. ALERTING MODEL

Alerting is a deterministic notification layer over fail-closed conditions and verified health failures.

The authoritative supervisory ordering key is:

```text
supervisory_order_key = SHA256(
  partition_id ||
  failure_type ||
  failure_context
)
```

Where:

* `partition_id` is the authoritative affected partition identifier, or the signed supervisory scope identifier for non-partition-scoped failures
* `failure_type` is the deterministic canonical failure classification
* `failure_context` is the canonical RFC 8785 failure context bytes derived from authoritative committed state and deterministic supervisory state only

The following are mandatory:

* alerts MUST trigger on fail-closed conditions
* alerts MUST trigger on verified ambiguity, integrity failure, or recovery failure
* all alerts MUST be ordered by `supervisory_order_key`
* arrival order MUST NOT be used
* alerts MUST NOT trigger corrective mutation directly
* identical alert inputs under identical supervisory configuration MUST produce identical alert classifications
* alert transport failure MUST NOT alter authoritative execution behavior

Alerts MAY request operator action or supervisory restart/failover action, but alerts themselves MUST NOT mutate authoritative data.

---

# 8. RESILIENCE MODEL (CRITICAL)

Resilience is the deterministic restart and recovery supervision layer.

The following are mandatory:

* recovery MUST restart from last committed state
* recovery MUST preserve ordering and replay correctness
* resilience supervision MUST NOT modify stored authoritative records
* resilience supervision MUST invoke upstream recovery laws exactly as defined by PRD-02, PRD-13, PRD-15, and PRD-17
* recovery MUST execute from the last durable commit boundary only
* recovery MUST NOT invent missing state
* all resilience actions MUST be executed in deterministic sorted order
* concurrent execution MUST preserve deterministic ordering

Authoritative data repair is NOT owned by this PRD.

This layer MAY:

* restart services
* trigger deterministic failover as defined by PRD-17

This layer MUST NOT define an alternate recovery sequence.

---

# 9. SELF-HEALING MODEL (CRITICAL)

Self-healing is limited to deterministic supervisory actions that do not mutate authoritative data.

Allowed actions are:

* restart services
* trigger failover as per PRD-17

The following are mandatory:

* self-healing decisions MUST derive only from deterministic fail-closed health conditions and committed supervisory state
* self-healing MUST NOT modify stored records
* self-healing MUST NOT reorder data
* self-healing MUST NOT patch data inconsistencies
* self-healing MUST NOT skip replay validation
* self-healing MUST NOT bypass PRD-13 recovery or PRD-17 failover rules
* supervisory action sequencing MUST follow ascending `supervisory_order_key`

If self-healing authority or action selection is ambiguous:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

---

# 10. FAILURE MODEL

The observability and resilience layer MUST operate fail-closed with respect to its own supervisory decisions.

The following are mandatory:

* any ambiguity MUST result in alert
* no silent correction is allowed
* observability input ambiguity MUST raise alert
* recovery ambiguity MUST raise alert
* self-healing ambiguity MUST raise alert
* data-isolation violation MUST raise alert
* mismatch in supervisory ordering or supervisory action sequence MUST result in `SYSTEM FAILURE`

The following are FORBIDDEN:

* silent observability fallback that mutates behavior
* silent repair of authoritative data
* silent replay bypass

If this layer cannot determine a safe passive or supervisory action:

```text
ALERT -> DO NOT MUTATE CORE STATE
```

---

# 11. DETERMINISM GUARANTEE

For identical:

* authoritative committed state
* replay-validation results
* leader and failover state
* supervisory configuration

This layer MUST produce identical:

* canonical log payloads
* canonical metrics payloads
* canonical trace payloads
* alert classifications
* restart or failover decisions
* ordered supervisory action sequences

The following are mandatory:

* identical failure set MUST result in identical ordered action sequence

The following law is mandatory:

```text
IDENTICAL COMMITTED STATE -> IDENTICAL OBSERVABILITY DERIVATION -> IDENTICAL SUPERVISORY DECISION
```

All outputs MUST be ordered using `ordering_ref` only.

---

# 12. DATA ISOLATION RULE (CRITICAL)

Observability data and authoritative core data MUST remain isolated.

The following are mandatory:

* observability systems MUST NOT write to authoritative data stores
* observability data MUST be separate from core data
* observability credentials MUST be read-only with respect to authoritative stores
* observability exports MUST flow out of the core execution path only
* observability pipelines MUST NOT hold authority to modify canonical records, commit boundaries, replay state, or failover state
* writes to observability stores MUST never be treated as authoritative core input

Any isolation violation is:

```text
ALERT -> FAIL-CLOSED OBSERVABILITY DECISION
```

---

# 13. FILE & MODULE STRUCTURE

The authoritative implementation root for this PRD MUST be:

```text
/observability/
  committed_state_reader.go
  logger.go
  metrics_collector.go
  trace_exporter.go
  alert_manager.go
  resilience_supervisor.go
  isolation_guard.go
```

Every module MUST map to one or more sections of this PRD:

* `/observability/committed_state_reader.go` -> Sections 3, 8, 12
* `/observability/logger.go` -> Sections 3, 4, 11
* `/observability/metrics_collector.go` -> Sections 3, 5, 11
* `/observability/trace_exporter.go` -> Sections 3, 6, 11
* `/observability/alert_manager.go` -> Sections 7, 10, 11
* `/observability/resilience_supervisor.go` -> Sections 8, 9, 10, 11
* `/observability/isolation_guard.go` -> Sections 10, 12

No other authoritative PRD-18 module is permitted.

---

# 14. FORBIDDEN

```text
FORBIDDEN:

- adaptive tuning affecting execution
- auto-correction of data
- modifying canonical records
- replay mutation
- time-based execution changes
- observability reads from uncommitted state as authoritative input
- observability writes to authoritative data stores
- self-healing data patching
- skipping replay validation
- silent correction
```

---

# 15. SUMMARY

```text
PRD-18 defines passive observability and non-mutating resilience for Project Mishka.

It MUST:
- read committed authoritative state only
- derive passive logs, metrics, traces, and alerts
- restart from committed boundaries only
- use only restart and PRD-17 failover as healing actions
- preserve ordering and replay correctness
- keep observability data isolated from core data

It MUST NOT:
- influence execution
- mutate authoritative state
- patch stored data
- bypass replay validation
- change execution based on time or adaptive telemetry
```

---

# 16. RESILIENCE FSM (MANDATORY)

```text
RUNNING → DEGRADED → RECOVERING → RUNNING
ANY → HALTED
```

```text
RUNNING:
entry = normal
exit = anomaly detected

DEGRADED:
entry = partial failure
exit = recovery start

RECOVERING:
entry = recovery initiated
exit = success OR failure

HALTED:
entry = critical failure
exit = manual override
```
