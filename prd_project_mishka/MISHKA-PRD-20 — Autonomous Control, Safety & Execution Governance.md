# MISHKA-PRD-20 — Autonomous Control, Safety & Execution Governance

**Project:** Project Mishka  
**Classification:** SYSTEM CONTROL AUTHORITY — AUTONOMOUS EXECUTION, SAFETY GUARDRAILS, AND UI GOVERNANCE  
**Status:** CRITICAL — FAIL-CLOSED EXECUTION AUTHORITY, UI-ONLY CONTROL, REPLAY-SAFE SAFETY ENFORCEMENT

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

This document defines the authoritative autonomous control, safety, rollback, and execution governance model for Project Mishka.

It governs:

* execution authority
* control-mode semantics
* deterministic safety gating
* rollback preconditions
* execution authorization
* UI-only control-plane authority
* audit and explainability for all control decisions

This PRD is the authoritative control layer between PRD-11 policy output and PRD-12 enforcement dispatch.

---

# 2. CORE PRINCIPLES

```text
POLICY ALLOWANCE -> SAFETY ALLOWANCE -> TOKEN VALIDATION -> EXECUTION
```

The following principles are mandatory:

* no action may execute without explicit policy allowance
* no action may execute without explicit safety allowance
* no action may execute without deterministic rollback definition
* control inputs MUST be explicit, signed where required, and replay-visible
* UI is the only human control surface
* ambiguity in control or safety state MUST fail closed
* every control and execution decision MUST be explainable end to end

Micro-hardening (PRD-01 alignment):

* canonical object field lock is mandatory (PRD-01 Section 3.1): unknown fields FORBIDDEN; optional fields MUST be omitted (no null/default)
* array determinism law is mandatory (PRD-01 Section 3.2): every array MUST have an explicit deterministic ordering rule; no implicit ordering
* hash function law is mandatory (PRD-01 Section 3.3): all authoritative hashes in this PRD MUST use `SHA256`

There is no hidden override path, best-effort execution path, or backend-only control path.

---

# 3. EXECUTION AUTHORITY MODEL

The authoritative execution modes are:

* `AUTONOMOUS`
* `HUMAN_IN_THE_LOOP`
* `HUMAN_ON_THE_LOOP`
* `SIMULATION`

The canonical serialized execution-mode values used by downstream PRDs are:

```text
AUTONOMOUS = AUTO
HUMAN_IN_THE_LOOP = HITL
HUMAN_ON_THE_LOOP = HOTL
SIMULATION = SIMULATION
```

Mode semantics are mandatory:

* `AUTONOMOUS` / `AUTO` -> execution MUST proceed automatically only if all execution-law prerequisites are satisfied
* `HUMAN_IN_THE_LOOP` / `HITL` -> action material MUST be produced and execution MUST wait for explicit UI approval
* `HUMAN_ON_THE_LOOP` / `HOTL` -> execution MUST proceed automatically with full UI visibility and kill-switch authority
* `SIMULATION` -> action material MUST be produced for evaluation and audit, but execution is FORBIDDEN

The authoritative policy-result values are:

```text
ALLOW
DENY
REQUIRE_APPROVAL
```

The authoritative safety-result values are:

```text
ALLOW
DENY
```

---

# 4. DETERMINISTIC CONTROL EVALUATION

The deterministic control evaluation inputs are:

* `confidence_score`
* `correlation_strength`
* `asset_criticality`
* `threat_score`

All four inputs MUST be integers.

The deterministic control evaluation output is exactly one of:

```text
ALLOW
DENY
REQUIRE_APPROVAL
```

The following are mandatory:

* the same ordered control input tuple under the same signed control configuration MUST produce the same control decision
* control evaluation MUST use integer comparison only
* floating-point control evaluation is FORBIDDEN
* missing any control input MUST fail closed
* control thresholds MUST be explicit, signed, and immutable during one evaluation scope

---

# 5. HARD EXECUTION LAW (MANDATORY)

No action may execute unless all of the following are true:

* `policy_result == ALLOW`
* `safety_result == ALLOW`
* `confidence_score >= threshold`
* `rollback_defined == TRUE`

If any execution-law predicate is false:

```text
FAIL-CLOSED -> ALERT
```

The following are mandatory:

* policy bypass is FORBIDDEN
* safety bypass is FORBIDDEN
* missing rollback contract is FORBIDDEN
* degraded execution without the full predicate set is FORBIDDEN

---

# 6. SAFETY GUARDRAILS

The Safety Guardrails Layer MUST evaluate every candidate action before execution eligibility is granted.

Safety evaluation MUST be deterministic and MUST bind to:

* `policy_result`
* `execution_mode`
* `confidence_score`
* `correlation_strength`
* `asset_criticality`
* `threat_score`
* deterministic candidate `action_id`
* signed safety configuration

The Safety Guardrails Layer MUST produce:

* `safety_result`
* `rollback_defined`
* `execution_authorization_token`

No safety rule may be skipped, reordered, or bypassed.

---

# 7. BLAST RADIUS MODEL

Blast-radius controls are mandatory.

The authoritative blast-radius controls are:

* `max_hosts_per_action`
* `max_actions_per_window`
* signed subnet or environment scope limits

The following are mandatory:

* every candidate action MUST be evaluated against `max_hosts_per_action`
* every decision scope MUST be evaluated against `max_actions_per_window`
* target scope MUST remain inside the signed subnet or environment limit
* exceeding any blast-radius limit MUST force `safety_result = DENY`

Unsigned or ambiguous blast-radius configuration is invalid.

---

# 8. PROTECTED ASSET MODEL

Protected assets MUST be enforced through an immutable signed protected-asset list.

The following are mandatory:

* the protected-asset list MUST be explicit and immutable for one evaluation scope
* candidate actions MUST be checked against the protected-asset list before execution eligibility
* actions targeting a protected asset MUST force `safety_result = DENY`
* protected-asset checks MUST use exact identity or exact target-scope matching only

Heuristic protected-asset matching is FORBIDDEN.

---

# 9. KILL SWITCH MODEL

Kill switches are mandatory fail-closed controls.

The authoritative kill-switch scopes are:

* global
* tenant-level
* action-type level

The following are mandatory:

* kill-switch state MUST be explicit and UI-controlled
* active global kill switch MUST deny all execution
* active tenant kill switch MUST deny execution for the affected tenant scope
* active action-type kill switch MUST deny execution for the affected action type
* kill-switch evaluation MUST happen before token issuance

Kill-switch ambiguity is:

```text
DENY -> FAIL-CLOSED
```

---

# 10. CONFIDENCE GATING AND TTL ENFORCEMENT

Confidence gating is mandatory.

The following are mandatory:

* every candidate action MUST be checked against the signed minimum confidence threshold
* `confidence_score < threshold` MUST force `safety_result = DENY`
* `ttl_bound` MUST be explicit for every candidate action
* missing `ttl_bound` is invalid

```text
ttl_bound = max_partition_record_seq_delta

IF current_partition_seq - action_partition_seq > ttl_bound:
→ EXPIRED
```

---

# 11. ROLLBACK FRAMEWORK

Every candidate action MUST define:

* `forward_action`
* `reverse_action`

`forward_action` MUST identify the authoritative candidate action to be executed.

`reverse_action` MUST identify the authoritative deterministic reversal contract for that action.

`rollback_defined = TRUE` only if both `forward_action` and `reverse_action` are present, deterministic, and verifiable.

The authoritative rollback triggers are:

* manual
* automatic failure
* policy-driven

Rollback MUST:

* restore pre-action state
* produce a verification record
* remain deterministic for the same committed rollback dataset

Rollback without verifiable restoration evidence is invalid.

STATE_SNAPSHOT_HASH (CRITICAL):

Whole-machine state hashing is FORBIDDEN for rollback verification because endpoints are dynamic (ambient OS noise).

Rollback verification MUST be action-scoped and SHA256-only (PRD-01 hash law), using the same scoped-hash construction defined in PRD-12 Section 9.7.1.1.

## 🔴 DETERMINISTIC STATE READ CONTRACT (CRITICAL)

STATE_READ_CONTRACT (MANDATORY)

Rollback verification MUST operate ONLY on:

DECLARED_STATE_SCOPE

Each action MUST define:

state_scope = {
  object_type,
  object_identifiers,
  attribute_list
}

Example:

PROCESS:
  pid, binary_hash, parent_pid

FILE:
  path, inode, sha256

REGISTRY:
  key_path, value_name, value_hash

---

RULES:

1. ONLY declared attributes are hashed
2. ambient OS state MUST be ignored
3. ordering MUST be deterministic:

ORDER BY (attribute_name ASC)

---

STATE HASH:

state_hash = SHA256(
  RFC8785(ordered_state_scope)
)

---

STATE_HASH_STORAGE_BINDING (MANDATORY)

Every computed state_hash MUST be persisted as part of:

execution_result_record (PRD-13)

Fields:

{
  pre_state_hash,
  post_state_hash,
  state_scope_hash
}

---

REPLAY REQUIREMENT (PRD-15):

Replay MUST:

1. recompute state_hash using stored state_scope
2. compare against stored pre_state_hash / post_state_hash

Mismatch:

→ DETERMINISM_VIOLATION
→ FAIL-CLOSED

---

FORBIDDEN:

- recomputing state from live OS
- using external system reads during replay

---

HARD LAW:

STATE VERIFICATION MUST DEPEND ONLY ON PRD-13 STORED DATA

## STATE_SCOPE_BOUND (MANDATORY)

Each state_scope MUST define:

max_attribute_count
max_total_bytes

---

RULE:

IF exceeded:

→ split into deterministic chunks:

chunk_i = ordered subset

---

HASHING:

state_hash = SHA256(
  SHA256(chunk_1) ||
  SHA256(chunk_2) ||
  ...
)

---

ORDER:

chunks MUST be ordered deterministically

---

FORBIDDEN:

unbounded attribute expansion

---

FAILURE:

overflow without chunking:

→ REJECT ACTION
→ FAIL-CLOSED

---

ROLLBACK VALIDATION:

pre_state_hash == post_state_hash

---

FORBIDDEN:

- full system snapshot hashing
- unordered reads
- implicit attributes
- environment-dependent fields (timestamps, memory addresses)

---

FAILURE:

Ambiguous state scope:
→ REJECT ACTION
→ FAIL-CLOSED

Before action:
→ capture `pre_action_scope_hash`

After rollback:
→ capture `post_action_scope_hash`

VERIFICATION RULE (MANDATORY):

rollback_success IF:
post_action_scope_hash == pre_action_scope_hash

FORBIDDEN:

* hashing whole-machine state for rollback verification
* boolean-only verification
* executor-declared success without scoped hash equality proof

The authoritative rollback output is `rollback_record`.

Every `rollback_record` MUST contain:

```json
{
  "protocol_version": "rollback_record_v1",
  "rollback_id": "hex_32_bytes",
  "action_id": "hex_32_bytes",
  "execution_id": "hex_32_bytes",
  "forward_action": "hex_32_bytes",
  "reverse_action": "hex_32_bytes",
  "trigger_type": "MANUAL|AUTOMATIC_FAILURE|POLICY_DRIVEN",
  "pre_action_state_hash": "hex_32_bytes",
  "post_rollback_state_hash": "hex_32_bytes",
  "verification_record_hash": "hex_32_bytes",
  "rollback_result": "SUCCESS|FAILED"
}
```

Mandatory:

* `pre_action_state_hash` MUST equal `pre_action_scope_hash` (PRD-12 Section 9.7.1.1)
* `post_rollback_state_hash` MUST equal `post_action_scope_hash` (PRD-12 Section 9.7.1.1)
* `rollback_result = SUCCESS` is valid ONLY IF `post_rollback_state_hash == pre_action_state_hash`
* if `post_rollback_state_hash != pre_action_state_hash`:
  - classify as rollback mismatch
  - escalation to CRITICAL is mandatory under PRD-12 rollback escalation rules

The authoritative identifier is:

```text
rollback_id = SHA256(
  action_id ||
  execution_id ||
  forward_action ||
  reverse_action ||
  trigger_type ||
  pre_action_state_hash ||
  post_rollback_state_hash ||
  verification_record_hash ||
  rollback_result
)
```

## 11.1 Brick-Prevention Override (CLEAR_ROLLBACK_LOCK) (CRITICAL)

If an entity enters an escalated rollback-lock condition (PRD-12 `ESCALATED_CRITICAL`), the system MUST provide an explicit UI-governed override path to prevent permanent deadlock.

The only permitted override action is:

```text
CLEAR_ROLLBACK_LOCK
```

STRICT EXECUTION CONDITIONS (MANDATORY):

```text
REQUIRES:

- MFA approval
- signed UI action
- explicit justification
- scoped entity_id
```

Mandatory:

* override MUST be initiated only through the UI control plane (Section 14)
* override MUST be represented as a committed append-only record (`rollback_override_record` in PRD-13)
* override MUST link to the specific `linked_execution_id` being overridden
* override MUST NOT skip audit
* override MUST NOT skip replay
* override MUST NOT skip policy
* override MUST force deterministic policy re-evaluation before any new action eligibility is granted

If any override prerequisite is missing, ambiguous, unsigned, or cannot be proven:

```text
DENY -> FAIL-CLOSED -> ALERT
```

---

## 🔴 OUT-OF-BAND BREAK-GLASS RECOVERY (CRITICAL)
PURPOSE

Provide deterministic recovery for control-plane critical entities when UI path is unavailable.

BREAK-GLASS CHANNEL DEFINITION
OBGC = OFFLINE SIGNED RECOVERY CHANNEL

Characteristics:

control plane isolated in a separate failure domain from the primary control plane:
* separate network path
* separate credential scope
* separate signer custody
* separate process environment
requires multi-party cryptographic authorization
produces deterministic, replayable artifacts
ALLOWED ACTIONS

Only the following action is permitted:

CLEAR_ROLLBACK_LOCK_BREAKGLASS
AUTHORIZATION MODEL

Break-glass action MUST require:

required_signer_count-of-eligible_signer_count threshold signatures

Minimum quorum parameters:

* `eligible_signer_count >= 3`
* `required_signer_count >= 2`

Signed by:

Root Trust Authority
Security Officer Key
Deployment Owner Key

🔴 BREAK-GLASS KEY GOVERNANCE (CRITICAL)
RULE

Break-glass keys MUST:

be defined in signed authority snapshot
include:
key_id
key_epoch
valid_from
valid_to
revocation_status
ROTATION
new key set MUST NOT invalidate existing replay scope
VALIDATION
break-glass signatures MUST be validated against
the authority snapshot valid at event partition_epoch
FAILURE
invalid / expired / revoked key → REJECT → FAIL-CLOSED

## THRESHOLD_SIGNATURE_AGGREGATION (MANDATORY)

Break-glass signatures MUST use:

FROST (Ed25519)

RESULT:

single aggregated signature

---

RULE:

aggregate signature MUST be deterministic

## BREAKGLASS_QUORUM_RESOLUTION (CRITICAL)

Break-glass MUST support:

ASYNC QUORUM COLLECTION

---

RULE:

Each node produces:

signed_partial_proof

---

AGGREGATION:

proofs MUST be:

collected asynchronously
merged deterministically

---

COUNTER RULE:

failure_observation_counter MUST be:

node-local
included in signature

---

VERIFIER:

Verifier MUST check:

required_signer_count-of-eligible_signer_count valid signatures
independent of ordering

---

FORBIDDEN:

real-time coordination requirement
synchronous quorum dependency

## BREAKGLASS_PROOF_ORDERING (MANDATORY)

Partial proofs MUST be ordered by:

(node_id ASC)

---

AGGREGATION:

proof_set MUST be canonicalized before verification

---

REPLAY LAW:

aggregation MUST produce identical result regardless of arrival order

🔴 EMERGENCY KEY REVOCATION (CRITICAL)
RULE

Revocation MUST be:

deterministic
partition-epoch bound
replay-verifiable
MODEL
revocation_record = {
  key_id,
  key_epoch,
  revocation_epoch,
  revocation_reason
}
ENFORCEMENT
IF record.partition_epoch >= revocation_epoch:

    key MUST be treated as INVALID
HARD LAW
NO RETROACTIVE INVALIDATION
ONLY FORWARD ENFORCEMENT
ACTION CONSTRUCTION
breakglass_action_id = SHA256(
  "breakglass_v1" ||
  target_entity_key ||
  lock_state_hash ||
  authorization_bundle_hash
)
EXECUTION RULES
MUST bypass UI and control plane APIs
MUST be submitted via signed artifact ingestion path
MUST be stored as:
record_type = ACTION
action_type = CLEAR_ROLLBACK_LOCK_BREAKGLASS
MUST follow full PRD-12 validation chain

🔴 BREAK-GLASS IDEMPOTENCY LAW (CRITICAL)
UNIQUENESS KEY
breakglass_uniqueness_key = SHA256(
  target_entity_key ||
  lock_state_hash ||
  control_plane_failure_proof
)
GENERATION RULE
IF breakglass_uniqueness_key already exists in committed storage:

    DO NOT generate new break-glass action
EXECUTION RULE
IF action_id already executed:

    DO NOT re-dispatch
    RETURN existing execution_result_record
STORAGE REQUIREMENT

break-glass uniqueness MUST be:

enforced using PRD-13 committed records
replay-reconstructable
partition-local
HARD LAW
BREAK-GLASS MUST BE EXACTLY-ONCE
UNDER REPLAY AND FAILURE CONDITIONS
SAFETY CONSTRAINTS
ONLY valid when:
entity_state = ESCALATED_CRITICAL

🔴 CONTROL PLANE UNREACHABILITY PROOF (CRITICAL)
REPLACED BY:
* PRD-12 Section 9.7.3.1 (Model A / Model B proof models)
* this PRD Section `LOCAL_FAILURE_PROOF` (offline quorum artifact definition)
REPLAY REQUIREMENT

Break-glass execution MUST be:

FULLY REPLAYABLE
FULLY HASH-VERIFIABLE
FAILURE RULE
invalid break-glass → REJECT → FAIL-CLOSED → ALERT

## 🔴 CONTROL AUTHORITY PRECEDENCE LAW (CRITICAL)

PRECEDENCE ORDER:

1. OFFLINE BREAK-GLASS
2. SIGNED CONTROL-PLANE OBJECTS (UI)
3. DEFAULT SYSTEM STATE

RULES:

* break-glass bypasses UI while active
* break-glass MUST produce:
  * signed control object
  * PRD-13 storage record
  * audit trail
* UI law applies ONLY when break-glass is NOT active

CONFLICT RESOLUTION:

IF break-glass is active:

```text
UI constraints are TEMPORARILY SUSPENDED
system operates under break-glass authority
```

POST-CONDITION:

* system MUST return to UI-governed mode after break-glass closure

FAILURE:

```text
Ambiguous authority
→ FAIL-CLOSED
→ ALERT
```

## 🔴 EDGE CASE HANDLING LAW (CRITICAL)

CASE 3: UI ROLLBACK vs BREAK-GLASS RACE

PRECEDENCE:

```text
break-glass > UI
```

RULE:

* UI rollback action MUST be rejected if break-glass is active for the same entity scope
* the rejection MUST be stored as an append-only audit record

# 12. SAFETY EVALUATION OBJECT

The authoritative safety output is `safety_evaluation`.

Every `safety_evaluation` MUST contain:

```json
{
  "protocol_version": "safety_evaluation_v1",
  "safety_evaluation_id": "hex_32_bytes",
  "decision_id": "hex_32_bytes",
  "policy_result": "ALLOW|DENY|REQUIRE_APPROVAL",
  "execution_mode": "AUTO|HITL|HOTL|SIMULATION",
  "confidence_score": 0,
  "correlation_strength": 0,
  "asset_criticality": 0,
  "threat_score": 0,
  "safety_result": "ALLOW|DENY",
  "max_hosts_per_action": 0,
  "max_actions_per_window": 0,
  "scope_limit_id": "string",
  "ttl_bound": 0,
  "rollback_defined": true,
  "kill_switch_global": false,
  "kill_switch_tenant": false,
  "kill_switch_action_type": false,
  "action_authorizations": [
    {
      "action_id": "hex_32_bytes",
      "forward_action": "hex_32_bytes",
      "reverse_action": "hex_32_bytes",
      "action_type": "string",
      "target_entity_key": "hex_32_bytes",
      "target_scope": "string",
      "protected_asset_match": false,
      "safety_result": "ALLOW|DENY",
      "execution_authorization_token": "hex_32_bytes"
    }
  ]
}
```

The following are mandatory:

* `action_authorizations` MUST preserve the ordered candidate action sequence
* each `action_id` MUST be computed using the same deterministic action identity construction that PRD-12 will later apply before dispatch
* if PRD-12 recomputes a different `action_id` for the same candidate action, the system MUST fail closed
* `safety_result = ALLOW` for one `action_authorizations` entry is required before that exact action may execute

The authoritative identifier is:

```text
action_authorizations_hash = SHA256(RFC 8785 (JCS)(action_authorizations))

safety_evaluation_id = SHA256(
  decision_id ||
  policy_result ||
  execution_mode ||
  confidence_score ||
  correlation_strength ||
  asset_criticality ||
  threat_score ||
  safety_result ||
  max_hosts_per_action ||
  max_actions_per_window ||
  scope_limit_id ||
  ttl_bound ||
  rollback_defined ||
  kill_switch_global ||
  kill_switch_tenant ||
  kill_switch_action_type ||
  action_authorizations_hash
)
```

---

# 13. EXECUTION AUTHORIZATION TOKEN

The authoritative execution authorization token is:

```text
execution_authorization_token = SHA256(
  policy_result ||
  safety_result ||
  confidence_score ||
  action_id
)
```

The following are mandatory:

* the token MUST be computed separately for each candidate `action_id`
* the `safety_result` input to the token MUST be the matching per-action `action_authorizations.safety_result`
* token input bytes MUST be the exact authoritative bytes carried by the committed control records in scope
* the Safety Guardrails Layer MUST issue the token only after all guardrails evaluate deterministically
* the Enforcement Engine MUST require a valid token before execution
* token mismatch MUST reject fail-closed

Unsigned token substitution, token reuse across different `action_id` values, or token reuse across different control tuples is FORBIDDEN.

---

# 14. UI CONTROL PLANE LAW (CRITICAL)

UI is the default control surface when break-glass is NOT active.

The following are prohibited:

* CLI
* direct DB edits
* hidden APIs
* backend-only toggles

Every control feature MUST support:

* UI WRITE
* UI READ
* UI TRACE
* UI VALIDATION

The following hard rule is mandatory:

```text
IF FEATURE NOT IN UI -> FEATURE DOES NOT EXIST
```

The following are mandatory:

* every policy change MUST be initiated through the UI when break-glass is NOT active
* every kill-switch change MUST be initiated through the UI when break-glass is NOT active
* every approval and rollback trigger MUST be initiated through the UI when break-glass is NOT active
* backend services MUST transport only UI-issued canonical requests, and they MUST NOT expose a hidden non-UI control surface

---

# 15. UI ↔ DATABASE CRYPTOGRAPHIC CONTRACT (MANDATORY)

The relationship between the UI and the database is governed by a strict cryptographic contract. No data may enter the authoritative system state without satisfying this contract.

**MANDATORY WRITE FLOW:**
`UI OR ACTIVE OFFLINE BREAK-GLASS OBJECT → Canonicalize (RFC 8785) → Hash (SHA256) → Sign (Ed25519) → DB Write`

**DATABASE ENFORCEMENT:**
The database layer MUST REJECT any write operation that:
* contains unsigned data
* contains non-canonical JSON (violates RFC 8785)
* originates from a backend process or any source other than:
  * a signed UI action
  * a signed active break-glass control object under the CONTROL AUTHORITY PRECEDENCE LAW

---

# 16. UI_ACTION_RECORD

Every interaction with the UI that results in a state change or an authoritative request MUST generate a `UI_ACTION_RECORD`.

```json
{
  "actor_id": "string",
  "action": "string",
  "payload_hash": "hex_32_bytes",
  "signature": "ed25519",
  "ordering_ref": "partition_record_seq"
}
```

**MANDATORY RULES:**
* **Universal Coverage:** Every UI action MUST generate this record.
* **Append-Only:** The record store MUST be append-only and immutable.
* **Replay-Validatable:** The UI action sequence MUST be fully replayable and produce identical system state transitions.

```text
```text
ordering_ref = partition_record_seq
```
```

---

# 17. UI SECURITY MODEL

UI security controls are mandatory.

The following are mandatory:

* RBAC for all control operations
* MFA for policy change
* MFA for kill-switch operations
* MFA for critical actions
```text
ordering_ref = partition_record_seq
```
* re-authentication for sensitive operations

A sensitive control operation without the required UI security posture is invalid.

---

# 18. EXPLAINABILITY CONTRACT

The UI MUST show the full authoritative chain:

```text
signal -> detection -> decision -> policy -> safety -> action -> execution -> result
```

The following are mandatory:

* no black box decision or execution step is allowed
* the UI MUST show the authoritative `policy_result`
* the UI MUST show the authoritative `safety_result`
* the UI MUST show the authoritative `execution_mode`
* the UI MUST show the exact action and rollback linkage
* the UI MUST show kill-switch, blast-radius, protected-asset, TTL, and confidence-gating outcomes

---

# 19. AUDIT & TRACEABILITY

All control and execution outcomes MUST produce:

* append-only logs
* hash-linked records
* exportable audit chain

The following are mandatory:

* every control decision MUST be traceable to its authoritative inputs
* every executed action MUST be traceable to one `execution_authorization_token`
* every rollback MUST be traceable to one forward action and one verification record
* audit export MUST preserve canonical ordering and hash linkage

Silent control or execution state change is FORBIDDEN.

---

# 20. STORAGE AND REPLAY COUPLING

The following outputs from this PRD MUST be stored append-only and replayed exactly:

* `safety_evaluation`
* rollback verification records

The following are mandatory:

* safety records MUST be sufficient to prove why an action was allowed or denied
* rollback records MUST be sufficient to prove restoration and verification outcome
* replay MUST validate identical input -> identical policy, safety, action, execution, and rollback outputs
* control authority MUST remain replay-visible with no hidden state

---

# 21. FAILURE MODEL

The following conditions are mandatory fail-closed events:

* safety layer missing
* policy bypassed
* rollback not defined
* UI control missing
* invalid or missing execution authorization token
* kill-switch ambiguity
* protected-asset ambiguity
* blast-radius ambiguity
* TTL ambiguity
* explainability gap

Any such condition MUST result in:

```text
REJECT OR HALT -> ALERT
```

No corrective mutation may execute automatically to hide or repair the failure.

---

# 21.1 SAFETY FSM (MANDATORY)

```text
EVALUATING → ALLOW
EVALUATING → DENY
EVALUATING → REQUIRE_APPROVAL
ANY → FAILED
```

```text
EVALUATING:
entry = input received
exit = decision computed

ALLOW:
entry = pass
exit = terminal

DENY:
entry = fail
exit = terminal

REQUIRE_APPROVAL:
entry = threshold unmet
exit = approval received OR denied

FAILED:
entry = evaluation error
exit = escalation
```

# 22. DETERMINISM GUARANTEE

For identical:

* `policy_result`
* `execution_mode`
* `confidence_score`
* `correlation_strength`
* `asset_criticality`
* `threat_score`
* candidate `action_id`
* signed safety configuration

the system MUST produce identical:

* `safety_result`
* `execution_authorization_token`
* `safety_evaluation`
* rollback eligibility
* audit chain output

There is no probabilistic safety evaluation mode.

---

# 22.1 RESOURCE BOUNDS (MANDATORY)

```text
ALL LISTS MUST HAVE:

max_size
overflow_behavior = REJECT
```

# 23. BOUNDARY LAW

PRD-20 defines control and safety governance only.

PRD-20 MUST NOT:

* redefine PRD-03 identity or message laws
* redefine PRD-04 cryptographic trust laws
* redefine PRD-07 signal schema
* redefine PRD-12 executor-side effect semantics
* redefine PRD-13 storage hashing
* redefine PRD-15 replay hashing

PRD-20 is authoritative for:

* execution modes
* safety evaluation
* rollback preconditions
* UI-only control governance
* execution authorization token issuance and validation requirements

## PRD-20 OWNERSHIP (MANDATORY)

PRD-20 OWNS:

- enforcement governance
- rollback authority

---

## OFFLINE_RECOVERY_PROTOCOL (MANDATORY)

threshold-recovery tokens MUST:

- be geographically distributed
- have pre-defined activation runbook
- include time-independent validation

IF HSM unavailable:

→ secondary recovery quorum MUST exist

---

## 🔴 LOCAL_FAILURE_PROOF (MANDATORY)
WHEN:

- control plane unreachable
- storage commit unavailable

SYSTEM MUST USE:

```text
local_failure_proof = SHA256(
  last_known_commit_hash ||
  node_id ||
  failure_observation_counter
)
```

SIGNED BY:

- node key (PRD-04)

VALIDATION:

- quorum of nodes required (`quorum_majority_count`, as defined in the signed authority snapshot)

### LOCAL_FAILURE_PROOF semantics (CRITICAL)
`LOCAL_FAILURE_PROOF` exists to prevent availability deadlocks in break-glass paths when commits cannot be produced.

Mandatory rules:
* `last_known_commit_hash` MUST be a previously committed PRD-13 `batch_commit_hash` value (already durable, verifiable)
* `node_id` MUST be the PRD-03/PRD-04 identity of the attesting node, and MUST be bound to the signing key used
* `failure_observation_counter` MUST be a deterministic monotonic counter local to the node process for this outage episode
  * MUST start at 0 when the node enters `CONTROL_PLANE_UNREACHABLE` state
  * MUST increment by +1 per emitted failure proof artifact
  * MUST NOT use wall clock
* this artifact MUST NOT require any new authoritative storage commits to be generated
* the artifact is NOT itself authoritative system state; it is an offline, signed proof input intended only for break-glass eligibility checks

---

# 24. FORBIDDEN

The following are forbidden:

* CLI control
* backend-only control toggles
* hidden APIs
* direct database mutation for control state
* unsigned control overrides
* execution without rollback definition
* execution without safety approval
* execution without token validation
* heuristic safety decisions
* probabilistic safety decisions
* black-box action authorization
* non-exportable audit chains

---

If control is not explicit, replay-visible, and UI-governed, it is invalid.

---

# 26. ASSET GROUPING MODEL

Grouping provides the logical structure for policy and safety evaluations.

## 26.1 Group Identity

```text
group_id = SHA256(parent_group || name || rules)
```

## 26.2 Grouping Rules

* **Max Depth:** 6
* **Deterministic Membership:** Calculated via pure functions.
* **UI Control:** Groups MUST be defined and managed ONLY through the UI.
* **Integration:** Groups influence Policy Evaluation (PRD-11) and Safety Evaluation (PRD-20) input ONLY.

---

# 27. DEPENDENCY GRAPH MODEL

The system maintains a deterministic graph of asset and group dependencies.

## 27.1 Graph Integrity

```text
group_dependency_graph_hash = SHA256(nodes || edges)
```

* **Use Cases:** Blast Radius Evaluation and Impact Simulation.
* **No Dynamic Edges:** Edges MUST be explicitly defined or derived via deterministic rules.

---

# 28. PLAYBOOK MODEL (STRICT)

Playbooks are structured templates for generating system inputs; they are NOT execution engines.

## 28.1 Playbook Constraints

* **Generate Inputs Only**: Playbooks MUST produce only a `synthetic_detection_event` or `policy_input`.
* **No Execution Authority**: Playbooks MUST NOT trigger execution or bypass any control layer.
* **Mandatory Flow**: Execution MUST always follow the sequence: `Decision → Policy → Safety → Enforcement`.

## 28.2 FORBIDDEN

* direct enforcement from a playbook
* bypassing PRD-11 (Policy)
* bypassing PRD-20 (Safety)
* bypassing PRD-12 (Enforcement)

---

# 29. SANDBOX / SIMULATION UI

The UI provides a sandbox for dry-running actions.

* **Full Pipeline Execution:** Simulations MUST execute the complete pipeline: `detection → policy → safety → enforcement (dry-run)`.
* **Hash-Identical Output:** The simulation output MUST be hash-identical to real execution.

---

# 30. SUMMARY

Project Mishka execution authority is:

```text
DECISION -> POLICY -> SAFETY -> TOKEN -> ENFORCEMENT
```

Execution is valid only when policy permits it, safety permits it, rollback exists, the token matches, and the operation is fully visible through the UI.

If control is not explicit, replay-visible, and UI-governed, it is invalid.
