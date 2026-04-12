# MISHKA-PRD-11 — Policy Model

**Project:** Project Mishka  
**Classification:** AUTHORITATIVE — DETERMINISTIC POLICY EVALUATION SYSTEM  
**Status:** FOUNDATIONAL — DETECTION-TO-DECISION MAPPING WITHOUT ENFORCEMENT

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

This document defines the authoritative Policy Model for Project Mishka.

It governs how authoritative `detection_event` input is evaluated against signed policy configuration to produce one deterministic `action_decision`.

This layer exists to:

* convert `detection_event` into `action_decision`
* apply deterministic thresholds and rule matching
* resolve precedence and CRITICAL overrides
* produce auditable and explainable policy output
* remain replay-safe and side-effect-free

```text
(detection_event, policy_config) -> action_decision
```

The Policy Model is the authoritative `policy_result` layer consumed by downstream action generation and dispatch.

---

# 2. CORE PRINCIPLES

```text
Policy evaluation is a pure deterministic function. It decides. It does NOT execute.
```

The following principles are mandatory:

* policy evaluation MUST depend only on `detection_event` and signed `policy_config`
* policy evaluation MUST produce identical output for identical input and identical policy version
* thresholds MUST be deterministic, signed, versioned, and immutable at runtime
* precedence and conflict resolution MUST be explicit and deterministic
* policy output MUST be explainable using structured reason data, not free-text heuristics
* policy MUST NOT execute actions, modify system state, or call external systems
* policy MUST NOT learn, adapt, or branch probabilistically at runtime

PARTIAL_CORRELATION POLICY RULE (CRITICAL):

correlation_completeness = COMPLETE | PARTIAL

If correlation_completeness = PARTIAL:

* Policy MUST NOT evaluate as final DENY
* Policy MUST emit:

```text
decision = DEFERRED_DECISION
decision_type = NO_ACTION
```

Behavior:

PARTIAL → DEFERRED_DECISION → re-evaluate on future signals

FORBIDDEN:

* treating PARTIAL as negative
* final policy decision on incomplete graph

---

# 🔴 DEFERRED DECISION RE-EVALUATION (CRITICAL)
STATE MODEL
DEFERRED_DECISION MUST BE STORED AS:
record_type = DECISION
decision_state = DEFERRED
dependency_refs = [message_id...]
RE-EVALUATION TRIGGER

Re-evaluation MUST occur when:

ANY dependency_ref becomes available in committed storage
EXECUTION MODEL

🔴 INDEX-DRIVEN RE-EVALUATION (CRITICAL)
RULE

Re-evaluation MUST be triggered ONLY by dependency resolution events

MODEL
dependency_index:

key = message_id
value = [deferred_decision_ids]
EXECUTION
ON NEW RECORD COMMIT:

IF record.message_id IN dependency_index:

    FOR each deferred_decision_id:
        RE-EVALUATE deterministically
HARD LAW
NO FULL SCAN OF DEFERRED DECISIONS IS PERMITTED
STORAGE

dependency_index MUST be:

partition-local
replay-reconstructable
derived from committed records
DETERMINISM RULE

Re-evaluation MUST:

use original detection_event
use same policy_version
use same ordering context
TIME-BASED FALLBACK (CONTROLLED)

If dependency NEVER arrives:

AFTER max_logical_span_exceeded:
    EMIT deterministic terminal state:

decision = NO_ACTION
reason = DEPENDENCY_UNRESOLVED
FORBIDDEN
polling loops
wall-clock timers affecting decision
external triggers

---

## 🔴 DEFERRED DECISION HARD LIMIT (CRITICAL)

DEFERRED_BOUND_RULE (MANDATORY)

Each partition MUST define:

max_deferred_decisions

IF exceeded:

→ APPLY deterministic eviction:

ORDER BY (oldest dependency unresolved)

→ emit terminal:

decision = NO_ACTION
reason = DEFERRED_CAP_EXCEEDED

---

DEFERRED_DECISION_PRIORITY_PROTECTION (CRITICAL)

Deferred decisions MUST be prioritized.

---

PRIORITY SCORE:

priority = SHA256(
  detection_confidence ||
  severity ||
  asset_criticality ||
  policy_version ||
  execution_context_hash
)

Priority MUST be:

* deterministic
* comparable using lexicographic byte order
* replay-reconstructable

---

EVICTION RULE:

Eviction MUST use:

ORDER BY (priority ASC, oldest_first)

---

PROTECTED CLASS:

CRITICAL priority decisions MUST NEVER be evicted

---

ATTACK RESISTANCE:

If deferred flood detected:

→ throttle low-priority signals at ingest (PRD-08)

---

FAILURE:

if eviction would remove CRITICAL:

→ REJECT NEW LOW PRIORITY INPUT
→ FAIL-CLOSED FOR LOW PRIORITY ONLY

---

STORAGE_BOUND_ALIGNMENT (CRITICAL)

Deferred decisions MUST be stored as:

DECISION records (PRD-13)

Total count MUST be enforced using:

partition-local count from committed storage

---

FORBIDDEN:

in-memory-only deferred tracking

---

REPLAY LAW:

Deferred eviction MUST be reproducible from PRD-13 dataset

---

## 🔴 PARTITION HALT PROPAGATION (PRD-17)

IF partition_state = HALTED:

dependent partitions MUST:

→ stop accepting new deferred decisions
→ process only resolvable dependencies

---

## 🔴 DEFERRED RULE MODIFICATION (MANDATORY)
IF `dependency_absent_signal` EXISTS:

→ resolve deterministically using:

```text
decision_class = RISK_ESCALATION
decision = REQUIRE_APPROVAL
decision_type = PENDING_APPROVAL
reason = MISSING_DEPENDENCY_UNDER_LOAD
```

---

## DETERMINISTIC_DATAFLOW_COMPILATION (MANDATORY)
Policy + correlation rules MUST be compiled into DAG:

- immutable per version
- loaded at startup
- evaluated as dataflow graph

Benefits:

- O(1) evaluation
- deterministic execution preserved
- no runtime rule scanning

Micro-hardening (PRD-01 alignment):

* canonical object field lock is mandatory (PRD-01 Section 3.1): unknown fields FORBIDDEN; optional fields MUST be omitted (no null/default)
* array determinism law is mandatory (PRD-01 Section 3.2): every array MUST have an explicit deterministic ordering rule; no implicit ordering
* hash function law is mandatory (PRD-01 Section 3.3): all authoritative hashes in this PRD MUST use `SHA256`

```text
NO SIDE EFFECTS.
NO ADAPTIVE THRESHOLDS.
NO HEURISTIC DECISIONS.
```

## DETERMINISTIC_MEMOIZATION (OPTIONAL)

Policy DAG nodes MAY cache outputs using:

cache_key = SHA256(node_input || execution_context_hash)

---

RULE:

cache MUST be:

partition-local
replay-reconstructable

---

MEMOIZATION_STORAGE_BINDING (MANDATORY)

Memoized outputs MUST be:

stored as derived PRD-13 records

---

REQUIREMENT:

cache MUST be reconstructable from:

(committed inputs + execution_context_hash)

---

FORBIDDEN:

in-memory-only memoization

---

REPLAY LAW:

Replay MUST produce identical memoized outputs

---

MEMOIZATION_ORDERING_RULE (MANDATORY)

All memoized records MUST be ordered deterministically.

---

ORDERING KEY:

(primary) partition_id ASC
(secondary) logical_shard_id ASC
(tertiary) dependency_record_seq ASC
(quaternary) node_id ASC

---

STORAGE RULE:

Memoization records MUST be inserted in:

strict ascending ordering of the above key

---

REPLAY LAW:

Replay MUST reconstruct memoization in identical order

---

FAILURE:

unordered insertion:

→ DETERMINISM_VIOLATION
→ FAIL-CLOSED

---

# 3. INPUT CONTRACT (FROM PRD-09/10)

## 3.1 Authoritative Input Tuple

The Policy Model MUST evaluate exactly:

```text
(detection_event, policy_config, asset_criticality)
```

`detection_event` MUST be the authoritative output defined by PRD-09 and MUST contain the inference result fields defined by PRD-10.

`asset_criticality` MUST equal the authoritative integer carried in `detection_event.confidence_vector.asset_criticality`.

## 3.2 Detection Event Requirements

Before policy evaluation, the following MUST be verified:

* `protocol_version = detection_event_v1`
* `detection_id` validity
* `partition_id`, `partition_epoch`, and `logical_shard_id` presence
* `feature_vector_hash` presence
* `confidence_score` presence
* `correlation_strength` presence
* `correlation_completeness` presence
* `confidence_vector` presence
* `confidence_vector.asset_criticality` type and bounds
* `inference.result_id` presence
* `inference.model_id` presence
* `inference.model_version` presence
* `inference.output_schema_id` presence
* `inference.threat_score_fixed` type and bounds
* `inference.confidence_fixed` type and bounds
* `inference.class_code` validity
* `inference.reason_codes` ordering validity
* `inference.raw_output_hash` validity

Any mismatch:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

## 3.3 Policy Configuration Requirements

`policy_config` MUST be:

* canonical JSON conforming to RFC 8785 (JCS)
* signed
* hash-verified
* versioned
* immutable during the active evaluation scope

## 3.4 Allowed Detection Fields

The Policy Model MAY reference only the following authoritative input fields:

* `detection_id`
* `partition_id`
* `partition_epoch`
* `logical_shard_id`
* `window.window_id`
* `signal_refs`
* `affected_entity_keys`
* `inference.model_id`
* `inference.model_version`
* `inference.output_schema_id`
* `inference.threat_score_fixed`
* `inference.confidence_fixed`
* `confidence_score`
* `correlation_strength`
* `correlation_completeness`
* `confidence_vector.asset_criticality`
* `inference.class_code`
* `inference.reason_codes`
* `inference.raw_output_hash`
* `correlation.graph_id`
* `correlation.graph_hash`
* `correlation.node_refs`
* `correlation.edge_refs`

External enrichment fields are FORBIDDEN.

---

# 4. POLICY RULE MODEL

## 4.1 Authoritative Policy Object

Every policy MUST contain:

```json
{
  "policy_id": "string",
  "policy_version": "string",
  "policy_hash": "hex_32_bytes",
  "default_rule_id": "string",
  "thresholds": [],
  "action_templates": [],
  "rules": []
}
```

## 4.2 Rule Schema

Every rule MUST contain:

```json
{
  "rule_id": "string",
  "priority_class": "CRITICAL|HIGH|NORMAL",
  "precedence_index": 0,
  "match_all_threshold_refs": ["string"],
  "match_any_threshold_refs": ["string"],
  "required_class_codes": ["BENIGN|SUSPICIOUS|MALICIOUS"],
  "required_reason_codes_all": ["string"],
  "required_reason_codes_any": ["string"],
  "decision": "ALLOW|DENY|REQUIRE_APPROVAL|DEFERRED_DECISION",
  "execution_mode": "AUTO|HITL|HOTL|SIMULATION",
  "decision_type": "NO_ACTION|PENDING_APPROVAL|AUTHORIZE_ACTIONS",
  "action_template_refs": ["string"],
  "reason_code": "string"
}
```

## 4.3 Rule Constraints

The following are mandatory:

* `rule_id` MUST be unique within the policy
* `precedence_index` MUST be unique within each `priority_class`
* `default_rule_id` MUST reference exactly one existing rule
* `default_rule_id` MUST reference a rule with empty match conditions
* `decision = DENY` MUST imply `decision_type = NO_ACTION`
* `decision = REQUIRE_APPROVAL` MUST imply `decision_type = PENDING_APPROVAL`
* `decision = DEFERRED_DECISION` MUST imply `decision_type = NO_ACTION`
* `decision = ALLOW` with `execution_mode = AUTO` or `execution_mode = HOTL` MUST imply `decision_type = AUTHORIZE_ACTIONS`
* `decision = ALLOW` with `execution_mode = HITL` or `execution_mode = SIMULATION` MUST imply `decision_type = PENDING_APPROVAL`
* `action_template_refs` MUST be empty when `decision = DENY`
* `action_template_refs` MUST be empty when `decision = DEFERRED_DECISION`
* `action_template_refs` MUST be non-empty when `decision = ALLOW` or `decision = REQUIRE_APPROVAL`

Any violation:

```text
INVALID_POLICY -> FAIL-CLOSED
```

## 4.4 Action Template Schema

Every action template MUST contain:

```json
{
  "action_template_id": "string",
  "action_type": "BLOCK_EXEC|KILL_PROCESS|ISOLATE_HOST|BLOCK_IP|BLOCK_DOMAIN",
  "target_selector": "ALL_AFFECTED_ENTITIES|FIRST_AFFECTED_ENTITY",
  "target_scope": "ENTITY_KEY",
  "ttl_ms": 0,
  "parameter_profile_id": "string"
}
```

## 4.5 Action Template Constraints

The following are mandatory:

* `action_template_id` MUST be unique within the policy
* `ttl_ms` MUST be an unsigned integer
* `target_selector` semantics MUST be deterministic
* `parameter_profile_id` MUST reference signed static parameters only

Dynamic template generation is FORBIDDEN.

---

# 5. THRESHOLD MODEL

## 5.1 Threshold Schema

Every threshold MUST contain:

```json
{
  "threshold_id": "string",
  "field_ref": "string",
  "operator": "EQ|NE|GT|GTE|LT|LTE",
  "comparison_value": 0
}
```

## 5.2 Allowed Threshold Field References

The only allowed `field_ref` values are:

* `inference.threat_score_fixed`
* `inference.confidence_fixed`
* `confidence_score`
* `correlation_strength`
* `asset_criticality`
* `inference.class_code`
* `signal_ref_count`
* `affected_entity_count`
* `correlation.node_count`
* `correlation.edge_count`

Derived fields MUST be computed only as:

```text
signal_ref_count = len(signal_refs)
affected_entity_count = len(affected_entity_keys)
correlation.node_count = len(correlation.node_refs)
correlation.edge_count = len(correlation.edge_refs)
```

## 5.3 Threshold Evaluation Rules

The following are mandatory:

* numeric comparisons MUST use integer or fixed-point integer arithmetic only
* every threshold MUST evaluate to `true` or `false`
* missing fields MUST NOT be inferred; they MUST cause evaluation failure

Adaptive runtime thresholds are FORBIDDEN.

## 5.4 Threshold Immutability

Thresholds MUST be defined only by signed policy configuration.

Runtime learning, threshold drift, and operator override of threshold values are FORBIDDEN.

---

# 6. DECISION LOGIC

## 6.1 Evaluation Sequence

The following sequence is mandatory:

```text
1. verify detection_event integrity
2. verify policy signature, hash, and version
3. derive `asset_criticality`, `confidence_score`, `correlation_strength`, and allowed count fields
4. evaluate all thresholds
5. identify matching rules
6. apply priority and override rules
7. select exactly one winning rule
8. materialize ordered action_list
9. emit action_decision
```

```text
NO STEP MAY BE SKIPPED, REORDERED, OR BYPASSED.
```

## 6.2 Rule Matching

A rule matches only if all of the following are true:

* every `match_all_threshold_refs` threshold is `true`
* at least one `match_any_threshold_refs` threshold is `true`, or the list is empty
* `inference.class_code` is in `required_class_codes`, or the list is empty
* every `required_reason_codes_all` entry exists in `inference.reason_codes`
* at least one `required_reason_codes_any` entry exists in `inference.reason_codes`, or the list is empty

## 6.3 Default Rule

If no non-default rule matches, the rule referenced by `default_rule_id` MUST be selected.

There MUST be no implicit default behavior outside the signed default rule.

## 6.4 Action Materialization

`action_list` MUST be generated only from the winning rule’s `action_template_refs`.

Template expansion MUST use only:

* `affected_entity_keys`
* the action template fields
* deterministic `target_selector` rules

Duplicate action objects are FORBIDDEN.

## 6.5 Decision Types

The only authoritative `decision_type` values are:

```text
NO_ACTION
PENDING_APPROVAL
AUTHORIZE_ACTIONS
```

Semantics:

* `NO_ACTION` -> `decision = DENY` and `action_list` MUST be empty
* `NO_ACTION` -> `decision = DEFERRED_DECISION` and `action_list` MUST be empty
* `PENDING_APPROVAL` -> `decision = REQUIRE_APPROVAL` or `execution_mode = HITL` or `execution_mode = SIMULATION`, and `action_list` MUST be present but MUST NOT be treated as dispatch authorization
* `AUTHORIZE_ACTIONS` -> `decision = ALLOW`, `execution_mode` MUST be `AUTO` or `HOTL`, and `action_list` MUST be present and authorized for downstream action generation only

## 6.6 No Side-Effect Rule

Policy evaluation MUST NOT:

* execute actions
* dispatch messages
* mutate queues
* write mutable runtime state required for output correctness
* call external systems

---

# 7. PRIORITY & OVERRIDE RULES

## 7.1 Priority Classes

Every rule MUST declare one priority class:

```text
CRITICAL
HIGH
NORMAL
```

## 7.2 CRITICAL Override Rule

If one or more `CRITICAL` rules match, all matching `HIGH` and `NORMAL` rules MUST be ignored.

If no `CRITICAL` rules match and one or more `HIGH` rules match, all matching `NORMAL` rules MUST be ignored.

## 7.3 Precedence Order

Within the surviving priority class, rules MUST be ordered by:

```text
(precedence_index, rule_id)
```

The first rule in this deterministic order is the winning rule.

## 7.4 Conflict Resolution

The following are mandatory:

* duplicate `(priority_class, precedence_index)` tuples in one policy are invalid
* reference to a missing threshold or action template is invalid
* multiple winning rules after precedence sorting is FORBIDDEN

Any conflict:

```text
INVALID_POLICY -> FAIL-CLOSED
```

## 7.5 Action Ordering

Within `action_list`, action objects MUST be ordered by:

```text
(action_type, target_entity_key, action_template_id)
```

This order is authoritative for replay and hashing.

---

# 8. OUTPUT CONTRACT (action_decision)

## 8.1 Authoritative Output

The only authoritative output of this layer is:

```text
action_decision
```

## 8.2 Action Decision Schema

Every `action_decision` MUST contain:

```json
{
  "protocol_version": "action_decision_v1",
  "schema_version": "policy_schema_v1",
  "signing_context": "action_decision_v1",
  "key_id": "string",
  "key_epoch": "uint32",
  "signature": "hex_ed25519",
  "decision_id": "hex_32_bytes",
  "lineage_hash": "hex_32_bytes",
  "detection_id": "hex_32_bytes",
  "policy_id": "string",
  "policy_version": "string",
  "decision": "ALLOW|DENY|REQUIRE_APPROVAL",
  "execution_mode": "AUTO|HITL|HOTL|SIMULATION",
  "decision_type": "NO_ACTION|PENDING_APPROVAL|AUTHORIZE_ACTIONS",
  "selected_rule_id": "string",
  "action_list": [
    {
      "action_template_id": "string",
      "action_type": "BLOCK_EXEC|KILL_PROCESS|ISOLATE_HOST|BLOCK_IP|BLOCK_DOMAIN",
      "target_entity_key": "hex_32_bytes",
      "target_scope": "ENTITY_KEY",
      "ttl_ms": 0,
      "parameter_profile_id": "string"
    }
  ],
  "reason": {
    "reason_code": "string",
    "matched_rule_ids": ["string"],
    "true_threshold_ids": ["string"]
  },
  "confidence_reference": {
    "class_code": "BENIGN|SUSPICIOUS|MALICIOUS",
    "threat_score_fixed": 0,
    "confidence_fixed": 0,
    "model_id": "string",
    "model_version": "string",
    "raw_output_hash": "hex_32_bytes"
  }
}
```

### 8.2.1 Signing Requirements (CRITICAL)

The following are mandatory:

* `signing_context` MUST equal the exact literal `action_decision_v1` (constant, versioned, immutable)
* `signature` MUST be constructed and verified using the PRD-04 signing model
* signature domain separation by `signing_context` is MANDATORY (PRD-04); any context mismatch MUST be treated as: `REJECT -> FAIL-CLOSED -> ALERT`
* the signature MUST cover the full canonical `action_decision` object **excluding** the `signature` field itself (PRD-04 rule)
* any mismatch, missing signature fields, or unverifiable signature MUST be treated as:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

### 8.2.2 Output Ordering & Omission Rules (CRITICAL)

* `action_list` MUST be strictly ordered, deterministic, and stable across replay
* `action_list` ordering is authoritative and MUST follow Section 7.5:

```text
(action_type, target_entity_key, action_template_id)
```

* null fields are FORBIDDEN
* optional fields MUST be omitted (not null); if omission would make `action_decision_v1` incomplete, emission MUST fail closed before output

## 8.3 Required Output Rules

The following are mandatory:

* `decision` MUST equal the winning rule’s `decision`
* `execution_mode` MUST equal the winning rule’s `execution_mode`
* `reason.reason_code` MUST equal the winning rule’s `reason_code`
* `reason.matched_rule_ids` MUST be ordered by policy precedence order
* `reason.true_threshold_ids` MUST be ordered lexicographically
* `confidence_reference` MUST be copied from authoritative `detection_event.inference`
* `decision = DENY` MUST imply `decision_type = NO_ACTION`
* `decision = REQUIRE_APPROVAL` MUST imply `decision_type = PENDING_APPROVAL`
* `decision = ALLOW` with `execution_mode = AUTO` or `execution_mode = HOTL` MUST imply `decision_type = AUTHORIZE_ACTIONS`
* `decision = ALLOW` with `execution_mode = HITL` or `execution_mode = SIMULATION` MUST imply `decision_type = PENDING_APPROVAL`
* free-text explanation fields are FORBIDDEN

## 8.4 Decision Identifier

`decision_id` MUST be:

```text
action_list_hash = SHA256(RFC 8785 (JCS)(action_list))
reason_hash = SHA256(RFC 8785 (JCS)(reason))
confidence_reference_hash = SHA256(RFC 8785 (JCS)(confidence_reference))

decision_id = SHA256(RFC8785(full_canonical_object))
```

## 8.4.1 Canonical Action Decision Object (CRITICAL)

Canonicalization for all hashing and signing MUST use **RFC 8785 (JCS) ONLY**.

`full_canonical_object` for `action_decision` is the exact object with the following fields and structure (all fields listed are mandatory; optional fields MUST be omitted, not set to null):

```json
{
  "protocol_version": "action_decision_v1",
  "schema_version": "policy_schema_v1",
  "signing_context": "action_decision_v1",
  "key_id": "string",
  "key_epoch": "uint32",
  "decision_id": "hex_32_bytes",
  "lineage_hash": "hex_32_bytes",
  "detection_id": "hex_32_bytes",
  "policy_id": "string",
  "policy_version": "string",
  "decision": "ALLOW|DENY|REQUIRE_APPROVAL",
  "execution_mode": "AUTO|HITL|HOTL|SIMULATION",
  "decision_type": "NO_ACTION|PENDING_APPROVAL|AUTHORIZE_ACTIONS",
  "selected_rule_id": "string",
  "action_list": [
    {
      "action_template_id": "string",
      "action_type": "BLOCK_EXEC|KILL_PROCESS|ISOLATE_HOST|BLOCK_IP|BLOCK_DOMAIN",
      "target_entity_key": "hex_32_bytes",
      "target_scope": "ENTITY_KEY",
      "ttl_ms": 0,
      "parameter_profile_id": "string"
    }
  ],
  "reason": {
    "reason_code": "string",
    "matched_rule_ids": ["string"],
    "true_threshold_ids": ["string"]
  },
  "confidence_reference": {
    "class_code": "BENIGN|SUSPICIOUS|MALICIOUS",
    "threat_score_fixed": 0,
    "confidence_fixed": 0,
    "model_id": "string",
    "model_version": "string",
    "raw_output_hash": "hex_32_bytes"
  }
}
```

Ordering and omission rules (mandatory):

* `action_list` MUST be ordered by `(action_type, target_entity_key, action_template_id)`
* `reason.matched_rule_ids` MUST be ordered by policy precedence order (already required by Section 8.3)
* `reason.true_threshold_ids` MUST be ordered lexicographically (already required by Section 8.3)
* null fields are FORBIDDEN
* optional fields MUST be omitted (not null)

## 8.5 Lineage Hash

`lineage_hash` MUST be:

```text
lineage_hash = SHA256(parent.lineage_hash || canonical_payload)
```

where `parent.lineage_hash` is the `lineage_hash` from the corresponding `detection_event`.

## 8.6 Output Boundary Rule

`action_decision` MUST NOT contain:

* execution status
* dispatch result
* agent acknowledgement
* mutable approval state
* external lookup data

---

# 9. DETERMINISM RULES

## 9.1 Deterministic Equality

For identical:

* `detection_event`
* `policy_config`

the Policy Model MUST produce:

```text
bit-for-bit identical action_decision
```

## 9.2 Hidden Dependency Rule

The following MUST NOT affect policy output:

* wall clock
* process scheduling
* request arrival order
* previous evaluations
* cache contents
* operator session state

## 9.3 Numeric Rule

All policy-owned numeric evaluation MUST use integer or fixed-point integer comparison only.

Floating-point policy evaluation is FORBIDDEN.

## 9.4 Replay Rule

Replay of the same `detection_event` under the same `policy_version` MUST produce the same:

* `decision_type`
* `action_list`
* `reason`
* `confidence_reference`
* `decision_id`

---

# 10. STATE MODEL

## 10.1 Allowed State

The Policy Model MUST have no authoritative mutable evaluation state.

The only allowed runtime state is:

* active signed `policy_config`
* read-only compiled rule indexes derived from `policy_config`
* non-authoritative metrics state

## 10.2 State Constraints

Any state that can affect authoritative output MUST be:

```text
read-only + signed + versioned
```

Mutable counters, caches, or learning state that influence rule selection are FORBIDDEN.

## 10.3 Recovery Rule

On restart, the Policy Model MUST:

```text
1. load the active signed policy
2. verify policy signature and hash
3. rebuild read-only rule indexes deterministically
4. resume evaluation without changing outputs
```

---

# 11. PERFORMANCE MODEL

Policy evaluation MUST remain bounded and deterministic under load.

The following are mandatory:

* threshold evaluation cost MUST be O(threshold_count)
* rule matching cost MUST be O(rule_count)
* action materialization cost MUST be O(action_template_count + affected_entity_count)
* no external I/O is permitted on the hot path
* per-evaluation latency SHOULD remain under 5 ms under non-degraded, in-capacity operation

Signed configuration MUST define at minimum:

* maximum threshold count
* maximum rule count
* maximum action templates per rule
* maximum actions per decision

Performance optimizations MUST NOT change authoritative output.

---

# 12. SECURITY MODEL

## 12.1 Verify-Before-Use Rule

Before evaluation, the system MUST verify:

* `policy_config` signature
* `policy_hash`
* `policy_version`
* `detection_event` integrity
* `detection_event` signature and `signing_context` validity as defined by PRD-09 and verified under the PRD-04 signing model
* `inference.raw_output_hash` presence and type

Unsigned or mismatched policy objects MUST be rejected.

## 12.5 Action Decision Verification Gate (CRITICAL)

Before any downstream use, storage, action generation, or enforcement uses an `action_decision`, the following MUST be verified:

* canonicalize the object using RFC 8785 (JCS) ONLY
* recompute `decision_id` from the canonical object bytes
* verify the signature using the PRD-04 signing model and the resolved trust snapshot
* verify `signing_context` equals the exact literal `action_decision_v1`

If any verification step fails:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

## 12.2 Trust Boundary Rule

The Policy Model MUST trust only:

* authoritative `detection_event`
* signed `policy_config`
* signed static action parameter profiles referenced by `parameter_profile_id`

Everything else is untrusted.

## 12.3 Policy Immutability Rule

The active `policy_version` MUST remain immutable within the active evaluation scope.

Runtime mutation of rules, thresholds, precedence, or action templates is FORBIDDEN.

## 12.4 Auditability Rule

Every `action_decision` MUST be sufficient for audit using only:

* the output object itself
* the referenced `detection_event`
* the referenced `policy_config`

External explanation dependencies are FORBIDDEN.

---

# 13. FORBIDDEN PATTERNS

```text
FORBIDDEN:

- action execution inside policy evaluation
- system-state mutation as part of evaluation
- external API calls during evaluation
- adaptive runtime thresholds
- policy learning
- probabilistic decisions
- heuristic rule matching
- fuzzy matching
- regex-dependent evaluation
- time-dependent behavior
- floating-point threshold evaluation
- multiple winning rules after precedence resolution
- implicit default behavior outside signed policy
- free-text reasons as authoritative explanation
- unsigned policy objects
```

---

# 11. POLICY SCHEMA VERSIONING

## 11.1 Schema Evolution
The Policy Model MUST strictly version all policy outputs and rules using `schema_version`.

## 11.2 Backward Compatibility
The Policy Engine MUST be backward compatible with all historical `schema_version` identifiers defined in the signed policy snapshots. 

## 11.3 Replay Safety
All historical policy schemas MUST remain parsable and replay-safe. Removing support for an old `schema_version` that exists in the WORM archive is FORBIDDEN.

---

# 12. SUMMARY

```text
Policy Model is the deterministic decision layer between detection and action generation.

It MUST:
- evaluate only authoritative detection_event input
- apply signed immutable policy rules
- resolve CRITICAL overrides and precedence deterministically
- emit one replay-safe action_decision
- remain pure, auditable, and side-effect-free

If detection integrity, policy integrity, or rule consistency fails:
REJECT -> FAIL-CLOSED -> ALERT
```

---
