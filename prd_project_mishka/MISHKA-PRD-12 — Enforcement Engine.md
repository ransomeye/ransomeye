# MISHKA-PRD-12 — Enforcement Engine

**Project:** Project Mishka  
**Classification:** AUTHORITATIVE — DETERMINISTIC ENFORCEMENT AND EXECUTION CONTROL  
**Status:** FOUNDATIONAL — ACTION GENERATION, DISPATCH, EXACTLY-ONCE EXECUTION, AND VERIFICATION

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

This document defines the authoritative Enforcement Engine for Project Mishka.

It governs how `action_decision` and `safety_evaluation` are transformed into signed executable actions, dispatched deterministically, executed exactly once at the executor, verified against intended effect, and recorded in a crash-safe replay-compatible result.

This layer exists to:

* execute `action_decision`
* enforce `safety_evaluation`
* guarantee exactly-once execution
* verify execution outcome
* remain replay-safe
* remain crash-safe

The authoritative function of this layer is:

```text
(action_decision, safety_evaluation, enforcement_config) -> action_result
```

---

# 2. CORE PRINCIPLES

```text
Enforcement MUST be deterministic, idempotent, verifiable, and fail-closed.
```

```text
ALL ARRAYS MUST DEFINE:

max_size
overflow_behavior = REJECT
```

The following principles are mandatory:

* action generation MUST depend only on `action_decision`, `safety_evaluation`, and signed enforcement configuration
* `action_id` and `execution_id` MUST be deterministic
* replay MUST NOT cause duplicate execution
* executor execution MUST be exactly-once by `execution_id`
* idempotency MUST be preserved by `action_id`
* every dispatched action MUST produce `execution_result` and `execution_verification_state`
* partial success MUST be detected and MUST trigger corrective logic
* all authoritative state MUST be durable and recoverable after crash
* retry behavior MUST be deterministic and configuration-derived

Micro-hardening (PRD-01 alignment):

* canonical object field lock is mandatory (PRD-01 Section 3.1): unknown fields FORBIDDEN; optional fields MUST be omitted (no null/default)
* array determinism law is mandatory (PRD-01 Section 3.2): every array MUST have an explicit deterministic ordering rule; no implicit ordering
* hash function law is mandatory (PRD-01 Section 3.3): all authoritative hashes in this PRD MUST use `SHA256`

```text
same action_id -> same result -> no re-execution
```

---

# 3. INPUT CONTRACT (FROM PRD-11 / PRD-20)

## 3.1 Authoritative Input

The Enforcement Engine MUST consume only the authoritative `action_decision` defined by PRD-11 and the authoritative `safety_evaluation` defined by PRD-20.

Every input MUST contain:

* `protocol_version = action_decision_v1`
* `safety_evaluation.protocol_version = safety_evaluation_v1`
* `decision_id`
* `detection_id`
* `safety_evaluation_id`
* `policy_id`
* `policy_version`
* `decision`
* `execution_mode`
* `policy_result` resolved from `action_decision.decision`
* `decision_type`
* `selected_rule_id`
* `action_list`
* `reason`
* `confidence_reference`
* `safety_result`
* ordered `execution_authorization_token` values in `safety_evaluation.action_authorizations`
* `rollback_defined`

## 3.2 Input Validation Rule

Before enforcement processing, the following MUST be verified:

* `action_decision` signature validity and `signing_context = action_decision_v1` as defined by PRD-11 and verified using the PRD-04 signing model
* the referenced `detection_event` signature validity and `signing_context = detection_event_v1` as defined by PRD-09 and verified using the PRD-04 signing model
* `decision_id` validity
* `safety_evaluation_id` validity
* `policy_id` presence
* `policy_version` presence
* `decision` validity
* `execution_mode` validity
* `decision_type` validity
* `selected_rule_id` presence
* `action_list` ordering validity
* `reason.reason_code` presence
* `confidence_reference.model_id` presence
* `confidence_reference.model_version` presence
* `confidence_reference.raw_output_hash` presence
* `safety_result` validity
* `safety_evaluation.action_authorizations` ordering validity
* `execution_authorization_token` presence for every ordered `safety_evaluation.action_authorizations` entry
* `rollback_defined` presence

Any mismatch:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

### 3.2.1 CHAIN INTEGRITY VALIDATION (MANDATORY)

The Enforcement Engine MUST cryptographically lock the `detection_event -> action_decision` identity chain before generating or dispatching any action.

Mandatory sequence:

1. Recompute `detection_id` from the referenced `detection_event` canonical object bytes (PRD-09).
2. Verify equality with `action_decision.detection_id`.
3. Recompute `decision_id` from the `action_decision` canonical object bytes (PRD-11).
4. Verify equality with the provided `action_decision.decision_id`.

Failure:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

## 3.3 Decision Type Rule

The only authoritative `decision_type` values are:

```text
NO_ACTION
PENDING_APPROVAL
AUTHORIZE_ACTIONS
```

Semantics:

* `NO_ACTION` -> no executable action may be generated
* `PENDING_APPROVAL` -> action material MAY be generated but MUST NOT be dispatched
* `AUTHORIZE_ACTIONS` -> action material MUST be generated but MUST NOT be dispatched unless `policy_result = ALLOW`, `safety_result = ALLOW`, `execution_authorization_token` is valid, and `rollback_defined = TRUE`

## 3.4 Allowed External Inputs

The Enforcement Engine MAY additionally consume only the following signed control objects:

* `enforcement_config`
* `entity_route_map`
* `action_capability_descriptor`
* adapter manifests referenced by `adapter_type`
* static action parameter profiles referenced by `parameter_profile_id`

External systems, external APIs, and unsigned overrides are FORBIDDEN inputs.

---

# 4. ACTION GENERATION

## 4.1 Action Object Law

For each entry in `action_decision.action_list`, the Enforcement Engine MUST generate one deterministic `action_object`.

One ordered `safety_evaluation.action_authorizations` entry MUST exist for each ordered `action_decision.action_list` entry.

`action_object` MUST contain:

```json
{
  "protocol_version": "action_object_v1",
  "signing_context": "action_object_v1",
  "scope_id": "string",
  "key_id": "string",
  "key_epoch": "uint32",
  "signature": "hex_ed25519",
  "decision_id": "hex_32_bytes",
  "policy_id": "string",
  "policy_version": "string",
  "selected_rule_id": "string",
  "action_template_id": "string",
  "action_type": "BLOCK_EXEC|KILL_PROCESS|ISOLATE_HOST|BLOCK_IP|BLOCK_DOMAIN|ROLLBACK_FILE|ROLLBACK_PROCESS_STATE|ROLLBACK_REGISTRY|ROLLBACK_CONFIG|CLEAR_ROLLBACK_LOCK|QUARANTINE_FILE|SUBMIT_TO_SANDBOX|BLOCK_HASH_GLOBAL|DISABLE_IDENTITY|REVOKE_SESSION|RESET_CREDENTIAL|LOCK_ACCOUNT|DISABLE_SWITCH_PORT|APPLY_FIREWALL_RULE|REMOVE_ROUTE|INJECT_TCP_RESET|BLOCK_DNS|RATE_LIMIT_TRAFFIC|BLACKHOLE_ROUTE|TRAFFIC_REDIRECT_TO_SCRUBBER|GLOBAL_BLOCK_HASH|GLOBAL_BLOCK_IP|GLOBAL_POLICY_UPDATE|INVESTIGATE_ASSET|PROBE_ASSET_PROFILE",
  "source_detection_ref": "hex_32_bytes",
  "detection_snapshot": {
    "detection_type": "string",
    "detection_domain": "string",
    "confidence_score": 0,
    "confidence_vector_hash": "hex_32_bytes"
  },
  "target_entity_key": "hex_32_bytes",
  "target_scope": "ENTITY_KEY|FILE_OBJECT|PROCESS_OBJECT|REGISTRY_OBJECT|CONFIG_OBJECT|HASH_VALUE|IDENTITY_ACCOUNT|IDENTITY_SESSION|SWITCH_PORT|FIREWALL_RULESET|ROUTE_ENTRY|DNS_NAME|NETWORK_FLOW|SCRUBBER_TARGET|FEDERATION_SCOPE",
  "route_id": "string",
  "route_hash": "hex_32_bytes",
  "ttl_bound": 0,
  "parameter_schema_id": "string",
  "parameter_profile_id": "string",
  "parameter_profile_hash": "hex_32_bytes",
  "adapter_type": "ENDPOINT_AGENT_ADAPTER|NETWORK_ADAPTER|IDENTITY_PROVIDER_ADAPTER|FIREWALL_ADAPTER|CLOUD_CONTROL_ADAPTER",
  "adapter_manifest_hash": "hex_32_bytes",
  "required_capability_id": "string",
  "capability_descriptor_hash": "hex_32_bytes",
  "verification_mode": "string",
  "reversibility_mode": "NON_REVERSIBLE|SNAPSHOT_REVERSIBLE|ROLLBACK_ACTION",
  "rollback_snapshot_ref": "hex_32_bytes",
  "expected_effect_hash": "hex_32_bytes",
  "action_id": "hex_32_bytes",
  "execution_id": "hex_32_bytes"
}
```

### 4.1.1 Action Object Signing Rules (CRITICAL)

The following are mandatory:

* `signing_context` MUST equal the exact literal `action_object_v1` (constant, versioned, immutable)
* `action_object` MUST be signed using the PRD-04 signing model
* signature scope MUST cover the full canonical `action_object` **excluding** the `signature` field itself (PRD-04 rule)
* `action_object` MUST be signed **BEFORE dispatch**

#### 4.1.1.1 Signing Order and action_id Binding (CRITICAL)

The signing flow MUST execute in the following order:

1. compute `full_canonical_action_object` (Section 4.3.2)
2. compute:

   ```text
   action_id = SHA256(RFC8785(full_canonical_action_object))
   ```

3. insert `action_id` into `action_object`
4. compute canonical bytes of the signable `action_object` **INCLUDING `action_id`** (and excluding `signature` only)
5. sign using the PRD-04 signing model

MANDATORY:

* the `action_object.signature` MUST bind `action_id` through the signed canonical `action_object` bytes
* if `action_id` is not part of the signed payload, the action is invalid:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

If signature fields are missing, signature verification fails, or signing cannot be performed deterministically:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

## 4.2 Canonical Dependency Hash Binding

Before generating `action_object`, the Enforcement Engine MUST resolve exactly one signed authoritative:

* static action parameter profile referenced by `parameter_profile_id`
* adapter manifest referenced by `adapter_type`
* `action_capability_descriptor` referenced by `action_type`

The following constructions are mandatory:

```text
parameter_profile_hash = SHA256(canonical_parameter_profile_bytes)
adapter_manifest_hash = SHA256(canonical_adapter_manifest_bytes)
capability_descriptor_hash = SHA256(canonical_descriptor_bytes)
```

`canonical_parameter_profile_bytes`, `canonical_adapter_manifest_bytes`, and `canonical_descriptor_bytes` MUST be the exact canonical signed bytes of the resolved authoritative objects.

Missing, ambiguous, unsigned, partially verified, or hash-uncomputable dependency resolution is:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

## 4.3 Deterministic Action Identity

`scope_id` MUST be present in every `action_object` and MUST equal the authoritative enforcement scope identifier for the action (tenant / boundary scope).

Mandatory rules:

* `scope_id` MUST be derived only from signed control-plane configuration and authoritative identity scope laws
* `scope_id` MUST be treated as an immutable input to `action_id` signing and `execution_id` derivation
* if `scope_id` cannot be determined deterministically, enforcement MUST fail closed

`action_id` MUST be:

```text
SHA256(RFC8785(full_canonical_action_object))
```

`execution_id` MUST be:

```text
SHA256(
  action_id ||
  scope_id ||
  executor_id ||
  "execution_v1"
)
```

`execution_id` MUST be unique per:

```text
(action_id, scope_id, executor_id)
```

Cross-domain reuse of `execution_id` is FORBIDDEN.

```text
ttl_bound = max_partition_record_seq_delta

expiry:

IF current_partition_record_seq - action_partition_record_seq > ttl_bound
→ EXPIRED
```

## 4.3.2 Canonical Action Object Definition (MANDATORY)

Canonicalization for action identity and signing MUST use **RFC 8785 (JCS) ONLY**.

`full_canonical_action_object` is the exact object with the following fields (and no others), with the following mandatory exclusions:

* EXCLUDE from `full_canonical_action_object`:
  * `action_id`
  * `execution_id`
  * `signature`

Field set (closed, complete, deterministic):

```text
full_canonical_action_object = {
  protocol_version,
  signing_context,
  scope_id,
  key_id,
  key_epoch,
  decision_id,
  policy_id,
  policy_version,
  selected_rule_id,
  action_template_id,
  action_type,
  source_detection_ref,
  detection_snapshot,
  target_entity_key,
  target_scope,
  route_id,
  route_hash,
  ttl_bound,
  parameter_schema_id,
  parameter_profile_id,
  parameter_profile_hash,
  adapter_type,
  adapter_manifest_hash,
  required_capability_id,
  capability_descriptor_hash,
  verification_mode,
  reversibility_mode,
  rollback_snapshot_ref,
  expected_effect_hash
}
```

Omission rules (mandatory):

* null fields are FORBIDDEN
* optional fields MUST be omitted (not null); if omission would make `action_object_v1` incomplete, the engine MUST fail closed before signing

Immutability lock (mandatory):

* once signed, `action_object` MUST be immutable
* any mutation invalidates the signature and MUST be treated as:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

## 4.3.1 Detection Binding Contract (CRITICAL)

Enforcement MUST be detection-controlled and replay-locked.

MANDATORY RULES:

1. Every `action_object` MUST include:

```json
"source_detection_ref": "hex_32_bytes"
```

2. `source_detection_ref` MUST equal:

```text
detection_event.detection_id
```

3. The Enforcement Engine MUST verify:

```text
action_decision.decision_id -> detection_event.detection_id mapping exists
```

The mapping MUST be verified using committed authoritative records (PRD-13) and MUST NOT depend on transport timing, caches, or external systems.

4. If missing, ambiguous, or unverifiable:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

5. This binding MUST be included in:

* `action_id` hash input (indirectly via the canonical `action_object`)
* `execution_id` derivation (indirectly via `action_id`)

## 4.3.2 Detection Context Snapshot (CRITICAL)

Every `action_object` MUST include `detection_snapshot`.

MANDATORY:

```text
detection_snapshot MUST be derived from detection_event
```

`confidence_vector_hash` MUST be computed as:

```text
confidence_vector_hash = SHA256(RFC8785(confidence_vector))
```

VALIDATION RULE:

```text
detection_snapshot MUST match source_detection_ref
```

Meaning:

* `detection_snapshot.detection_type` MUST equal the `detection_event.detection_type` of `source_detection_ref`
* `detection_snapshot.detection_domain` MUST equal the `detection_event.detection_domain` of `source_detection_ref`
* `detection_snapshot.confidence_score` MUST equal the `detection_event.confidence_score` of `source_detection_ref`
* `detection_snapshot.confidence_vector_hash` MUST equal `SHA256(RFC8785(detection_event.confidence_vector))`

Mismatch is:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

## 4.4 Lineage Hash

`lineage_hash` MUST be:

```text
lineage_hash = SHA256(parent.lineage_hash || canonical_payload)
```
where `parent.lineage_hash` is the `lineage_hash` from the corresponding `action_decision` (or `safety_evaluation`).

## 4.5 Identity Invariants

The following are mandatory:

* the same semantic action MUST always produce the same `action_id`
* the same semantic action MUST always produce the same `route_id`
* the same semantic action MUST always produce the same `route_hash`
* the same semantic action MUST always produce the same `parameter_profile_hash`
* the same semantic action MUST always produce the same `adapter_manifest_hash`
* the same semantic action MUST always produce the same `capability_descriptor_hash`
* the same `action_id` MUST always produce the same `execution_id`
* redispatch after failure MUST reuse the same `action_id`
* redispatch after failure MUST reuse the same `execution_id`
* the same semantic action across environments MUST resolve identical canonical parameter profile bytes, identical canonical adapter manifest bytes, identical canonical capability descriptor bytes, identical `executor_type`, identical `executor_id`, identical `route_id`, and identical canonical transport endpoint tuple before dispatch

## 4.5.1 Action Idempotency Rule (EXTENDED) (CRITICAL)

```text
No duplicate enforcement for identical detection state.
```

Define:

```text
enforcement_uniqueness_key = SHA256(
  source_detection_ref ||
  action_type ||
  target_entity_key ||
  expected_effect_hash
)
```

Mandatory rule:

```text
If enforcement_uniqueness_key already executed:
    DO NOT generate new action_object
```

Violation is:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

`enforcement_uniqueness_key` enforcement MUST be durable and replay-safe. Hidden in-memory-only suppression is FORBIDDEN.

## 4.5 Generation Rules by Decision Type

If `decision_type = NO_ACTION`:

* `action_object` generation is FORBIDDEN

If `decision_type = PENDING_APPROVAL`:

* `action_object` generation is permitted
* dispatch is FORBIDDEN

If `decision_type = AUTHORIZE_ACTIONS`:

* `action_object` generation is mandatory
* dispatch is mandatory unless validation fails
* generated `action_object.action_id` MUST equal the corresponding `safety_evaluation.action_authorizations.action_id`

## 4.6 Ordering Rule

Generated `action_object` records MUST preserve the ordered input `action_list` sequence from PRD-11.

No reordering is permitted during generation.

## 4.7 Authoritative Constants

The following constant is mandatory:

```text
ZERO_HASH_32 = 0000000000000000000000000000000000000000000000000000000000000000
```

`rollback_snapshot_ref` MUST equal `ZERO_HASH_32` when `reversibility_mode = NON_REVERSIBLE`.

## 4.8 Authoritative Action Type Set

The only authoritative `action_type` values are:

```text
BLOCK_EXEC
KILL_PROCESS
ISOLATE_HOST
BLOCK_IP
BLOCK_DOMAIN

ROLLBACK_FILE
ROLLBACK_PROCESS_STATE
ROLLBACK_REGISTRY
ROLLBACK_CONFIG
CLEAR_ROLLBACK_LOCK

QUARANTINE_FILE
SUBMIT_TO_SANDBOX
BLOCK_HASH_GLOBAL

DISABLE_IDENTITY
REVOKE_SESSION
RESET_CREDENTIAL
LOCK_ACCOUNT

DISABLE_SWITCH_PORT
APPLY_FIREWALL_RULE
REMOVE_ROUTE
INJECT_TCP_RESET
BLOCK_DNS

RATE_LIMIT_TRAFFIC
BLACKHOLE_ROUTE
TRAFFIC_REDIRECT_TO_SCRUBBER

GLOBAL_BLOCK_HASH
GLOBAL_BLOCK_IP
GLOBAL_POLICY_UPDATE
```

These values are authoritative and MUST NOT be treated as aliases unless the signed capability registry explicitly declares equivalent semantics.

### 4.8.1 PRD-23 Controlled Asset Investigation Actions (CRITICAL)

This PRD defines additional controlled action types used by PRD-23:

* `INVESTIGATE_ASSET`
* `PROBE_ASSET_PROFILE`

Both action types MUST:

* remain deterministic and replay-safe
* execute only through `adapter_type = NETWORK_ADAPTER`
* produce their results as committed `signal_event` outputs (PRD-07) referenced by the executor receipt
* have no hidden side effects

These action types are investigative and MUST NOT:

* mutate authoritative asset registry state directly
* perform background scanning loops
* call external enrichment APIs

---

## 4.9 Action Capability Model

Each `action_type` MUST resolve through exactly one signed `action_capability_descriptor`.

Every descriptor MUST define:

* deterministic `parameter_schema_id`
* supported `target_scope` set
* required `adapter_type`
* required agent or adapter capability identifier
* deterministic `verification_mode`
* deterministic `expected_effect_hash_rule_id`
* `reversibility_mode`

The following descriptor schema is mandatory:

```json
{
  "action_type": "string",
  "parameter_schema_id": "string",
  "supported_target_scopes": ["string"],
  "adapter_type": "ENDPOINT_AGENT_ADAPTER|NETWORK_ADAPTER|IDENTITY_PROVIDER_ADAPTER|FIREWALL_ADAPTER|CLOUD_CONTROL_ADAPTER",
  "required_capability_id": "string",
  "verification_mode": "string",
  "expected_effect_hash_rule_id": "string",
  "reversibility_mode": "NON_REVERSIBLE|SNAPSHOT_REVERSIBLE|ROLLBACK_ACTION"
}
```

The Enforcement Engine MUST resolve and validate the capability descriptor, referenced parameter profile, and referenced adapter manifest before generating `action_object`.

## 4.9.1 Required Adapter Type (PRD-23)

For `action_type = INVESTIGATE_ASSET` and `action_type = PROBE_ASSET_PROFILE`:

* the resolved `action_capability_descriptor.adapter_type` MUST equal `NETWORK_ADAPTER`
* any other `adapter_type` resolution is invalid and MUST fail closed

## 4.9.2 Asset Intelligence Enforcement Rules (PRD-23) (CRITICAL)

Enforcement MUST be coverage-aware and MUST bind to PRD-23 asset intelligence state.

MANDATORY:

```text
if action_object.detection_snapshot.detection_type = UNMANAGED_ASSET_DETECTED:
    allowed actions:
        INVESTIGATE_ASSET
        PROBE_ASSET_PROFILE
        ISOLATE_HOST (only if policy allows)

if action_object.detection_snapshot.detection_type = NEW_ASSET_DETECTED:
    allowed actions:
        INVESTIGATE_ASSET

if action_object.detection_snapshot.detection_type = MISSING_EXPECTED_ASSET:
    allowed actions:
        INVESTIGATE_ASSET
```

FORBIDDEN:

```text
direct destructive action without coverage_state proof
```

Violation:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

---

## 4.13 Static Parameter Profiles (EXTENDED — PRD-23)

This PRD requires deterministic static parameter profiles for controlled asset investigation actions.

Parameter profiles are authoritative signed control objects referenced by `parameter_profile_id`.

Mandatory rules:

* parameter profiles MUST be immutable for one action execution scope
* profile versioning MUST occur only by publishing a new signed profile with a new `parameter_profile_hash`
* executors MUST lock and hash-match the exact parameter profile bytes as required by Section 7

### 4.13.1 PRD-23 Parameter Schema IDs

The following parameter schema identifiers are mandatory for PRD-23:

* `asset_investigation_params_v1`
* `asset_probe_profile_params_v1`

### 4.13.2 asset_investigation_params_v1 (INVESTIGATE_ASSET)

The canonical parameter profile object for `asset_investigation_params_v1` MUST include:

* `schema_version`
* closed allow-list of permitted probe operations (as signed enum codes)
* deterministic evidence requirements (what signals MUST be emitted)
* explicit limits (max targets per action, max evidence items)

All fields MUST be explicit. Optional omission is forbidden.

### 4.13.3 asset_probe_profile_params_v1 (PROBE_ASSET_PROFILE)

The canonical parameter profile object for `asset_probe_profile_params_v1` MUST include:

* `schema_version`
* closed allow-list of permitted network profile probes that are signal-derived and deterministic
* deterministic output signal schema identifiers that MUST be emitted
* explicit limits on data volume and bounded execution

All fields MUST be explicit. Optional omission is forbidden.

## 4.10 Replay Consistency Rule

The same `action_id` MUST guarantee:

* identical `route_id`
* identical `route_hash`
* identical `parameter_profile_hash`
* identical `adapter_manifest_hash`
* identical `capability_descriptor_hash`
* identical `executor_type`
* identical `executor_id`
* identical canonical transport endpoint tuple
* identical canonical parameter-profile bytes
* identical canonical adapter-manifest bytes
* identical canonical capability-descriptor bytes
* identical executor-side validation, effect application, rollback handling, and verification behavior as a pure function of the canonical `action_object`, the exact hash-matched dependency bytes, and the exact route-hash-matched route bytes

If any dependency or route differs:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

## 4.11 Rollback And Remediation Rule

If `reversibility_mode = SNAPSHOT_REVERSIBLE`:

* the executor MUST store a reversible state snapshot before effecting the action
* snapshot creation MUST succeed before execution
* if snapshot creation fails, the action MUST NOT execute
* executing without snapshot is FORBIDDEN
* fallback to `NON_REVERSIBLE` is FORBIDDEN
* the executor MUST produce deterministic rollback evidence
* the action MUST support replay-safe reversal

If `reversibility_mode = ROLLBACK_ACTION`:

* `rollback_snapshot_ref` MUST NOT equal `ZERO_HASH_32`
* `rollback_snapshot_ref` MUST resolve to one previously stored reversible snapshot

If `reversibility_mode = NON_REVERSIBLE`:

* `rollback_snapshot_ref` MUST equal `ZERO_HASH_32`

## 4.12 Execution Authorization Rule

Before dispatching any generated `action_object`, the Enforcement Engine MUST:

* recompute `policy_result` from `action_decision.decision`
* verify `safety_evaluation.action_authorizations.safety_result = ALLOW` for the matching ordered entry
* verify `rollback_defined = TRUE`
* verify generated `action_object.action_id` equals the matching `safety_evaluation.action_authorizations.action_id`
* recompute `execution_authorization_token = SHA256(policy_result || safety_evaluation.action_authorizations.safety_result || safety_evaluation.confidence_score || action_id)`
* verify the recomputed token equals the matching stored `execution_authorization_token`

Execution MUST NOT occur unless the token is valid.

---

# 5. ACTION DISPATCH MODEL

## 5.1 Route Resolution

Every `action_object` MUST be routed using the signed `entity_route_map`.

The route resolution input is:

```text
(target_entity_key, target_scope, entity_route_map_version)
```

The route resolution output MUST contain exactly one:

* `executor_type`
* `executor_id`
* `route_id`
* canonical transport endpoint tuple

The following construction is mandatory:

```text
route_hash = SHA256(
  executor_type ||
  executor_id ||
  route_id ||
  canonical_transport_endpoint_tuple
)
```

`canonical_transport_endpoint_tuple` MUST be the exact deterministic canonical bytes of the resolved transport endpoint tuple.

Route resolution MUST be deterministic AND cryptographically bound.

The resolved `route_id` and `route_hash` MUST be inserted into `action_object` before `action_id` is computed.

The same `action_id` MUST guarantee identical:

* `executor_type`
* `executor_id`
* `route_id`
* canonical transport endpoint tuple

If generated `action_object.target_scope = ENTITY_KEY`, the Enforcement Engine MUST resolve a concrete `target_scope` allowed by the signed `action_capability_descriptor`.

Missing, ambiguous, non-canonical, or divergent route resolution is:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

## 5.2 Dispatch Envelope

Every dispatched action MUST be wrapped in a signed `action_dispatch_envelope`:

```json
{
  "protocol_version": "action_dispatch_v1",
  "engine_id": "string",
  "executor_type": "ENDPOINT_AGENT_ADAPTER|NETWORK_ADAPTER|IDENTITY_PROVIDER_ADAPTER|FIREWALL_ADAPTER|CLOUD_CONTROL_ADAPTER",
  "executor_id": "string",
  "route_id": "string",
  "payload_hash": "hex_32_bytes",
  "signature": "hex_ed25519",
  "payload": {
    "protocol_version": "action_object_v1",
    "signing_context": "action_object_v1",
    "scope_id": "string",
    "key_id": "string",
    "key_epoch": "uint32",
    "signature": "hex_ed25519",
    "decision_id": "hex_32_bytes",
    "policy_id": "string",
    "policy_version": "string",
    "selected_rule_id": "string",
    "action_template_id": "string",
    "action_type": "BLOCK_EXEC|KILL_PROCESS|ISOLATE_HOST|BLOCK_IP|BLOCK_DOMAIN|ROLLBACK_FILE|ROLLBACK_PROCESS_STATE|ROLLBACK_REGISTRY|ROLLBACK_CONFIG|CLEAR_ROLLBACK_LOCK|QUARANTINE_FILE|SUBMIT_TO_SANDBOX|BLOCK_HASH_GLOBAL|DISABLE_IDENTITY|REVOKE_SESSION|RESET_CREDENTIAL|LOCK_ACCOUNT|DISABLE_SWITCH_PORT|APPLY_FIREWALL_RULE|REMOVE_ROUTE|INJECT_TCP_RESET|BLOCK_DNS|RATE_LIMIT_TRAFFIC|BLACKHOLE_ROUTE|TRAFFIC_REDIRECT_TO_SCRUBBER|GLOBAL_BLOCK_HASH|GLOBAL_BLOCK_IP|GLOBAL_POLICY_UPDATE|INVESTIGATE_ASSET|PROBE_ASSET_PROFILE",
    "source_detection_ref": "hex_32_bytes",
    "detection_snapshot": {
      "detection_type": "string",
      "detection_domain": "string",
      "confidence_score": 0,
      "confidence_vector_hash": "hex_32_bytes"
    },
    "target_entity_key": "hex_32_bytes",
    "target_scope": "ENTITY_KEY|FILE_OBJECT|PROCESS_OBJECT|REGISTRY_OBJECT|CONFIG_OBJECT|HASH_VALUE|IDENTITY_ACCOUNT|IDENTITY_SESSION|SWITCH_PORT|FIREWALL_RULESET|ROUTE_ENTRY|DNS_NAME|NETWORK_FLOW|SCRUBBER_TARGET|FEDERATION_SCOPE",
    "route_id": "string",
    "route_hash": "hex_32_bytes",
    "ttl_bound": 0,
    "parameter_schema_id": "string",
    "parameter_profile_id": "string",
    "parameter_profile_hash": "hex_32_bytes",
    "adapter_type": "ENDPOINT_AGENT_ADAPTER|NETWORK_ADAPTER|IDENTITY_PROVIDER_ADAPTER|FIREWALL_ADAPTER|CLOUD_CONTROL_ADAPTER",
    "adapter_manifest_hash": "hex_32_bytes",
    "required_capability_id": "string",
    "capability_descriptor_hash": "hex_32_bytes",
    "verification_mode": "string",
    "reversibility_mode": "NON_REVERSIBLE|SNAPSHOT_REVERSIBLE|ROLLBACK_ACTION",
    "rollback_snapshot_ref": "hex_32_bytes",
    "expected_effect_hash": "hex_32_bytes",
    "action_id": "hex_32_bytes",
    "execution_id": "hex_32_bytes"
  }
}
```

`payload` MUST be the canonical `action_object`.

## 5.3 Envelope Hash and Signature

The following constructions are mandatory:

```text
payload_hash = SHA256(RFC 8785 (JCS)(payload))

signature = Ed25519(
  "action_dispatch_v1" ||
  engine_id ||
  executor_type ||
  executor_id ||
  route_id ||
  payload_hash
)
```

Unsigned action envelopes MUST NEVER be dispatched.

## 5.3.1 Dispatch Signature Model (MANDATORY)

Enforcement dispatch MUST produce:

1. `action_object.signature` (semantic signature)
   * binds the semantic action (including `action_id`)
   * MUST be generated using the PRD-04 signing model

2. `action_dispatch_envelope.signature` (transport + routing signature)
   * binds `(engine identity, executor identity, route_id, payload_hash)`
   * MUST be generated using the PRD-04 signing model

Hard law:
* unsigned envelopes MUST NEVER be dispatched

### 5.3.1.1 Executor Verification Requirement (OPTIMIZED) (MANDATORY)
To support PRD-05 constrained endpoint agents, executor-side verification is optimized as follows.

Mandatory (all executors):
* the executor MUST verify `action_dispatch_envelope.signature` BEFORE any processing
* the executor MUST recompute and verify `payload_hash = SHA256(RFC8785(payload))`
* the executor MUST reject if any envelope-to-payload binding check fails

Optional (executor-class-dependent):
* verification of `action_object.signature` at the executor is OPTIONAL and MUST be controlled only by signed executor configuration:

```text
executor_signature_mode = ENVELOPE_ONLY | ENVELOPE_PLUS_OBJECT
```

Mandatory defaults:
* `ENDPOINT_AGENT_ADAPTER` executors MUST default to `ENVELOPE_ONLY`
* all other executor classes MUST default to `ENVELOPE_PLUS_OBJECT`
* if `executor_signature_mode` is missing, ambiguous, or unsigned, the executor MUST fail closed

Hard laws:
* `ENVELOPE_ONLY` does NOT permit payload mutation; the envelope signature + verified payload_hash MUST still bind the exact canonical `action_object` bytes.
* `ENVELOPE_ONLY` MUST NOT weaken route binding, dependency locking, or exactly-once semantics.
* If `executor_signature_mode = ENVELOPE_PLUS_OBJECT`, both envelope signature verification and action_object signature verification MUST succeed; otherwise REJECT -> FAIL-CLOSED -> ALERT.

## 5.4 Action Object Immutability Rule

Once `action_object` is signed, it MUST be immutable.

`action_object` MUST NOT be modified by:

* dispatch layer
* transport layer
* executor
* federation

The canonical `action_object` bytes persisted by the Enforcement Engine MUST equal the `payload` bytes in the signed `action_dispatch_envelope` exactly.

If any field or byte differs from the signed payload:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

## 5.5 Dispatch Sequence

The following sequence is mandatory:

```text
1. validate action_decision and safety_evaluation
2. resolve deterministic route and compute `route_hash`
3. generate deterministic immutable `action_object` including `route_id` and `route_hash`
4. verify generated `action_id` matches the ordered safety authorization entry
5. recompute and verify `execution_authorization_token`
6. verify dispatch replay lock
7. persist dispatch ledger state
8. sign action_object (PRD-04 signing model) BEFORE dispatch
9. sign action_dispatch_envelope
10. transmit to executor
11. await execution receipt
12. persist resulting state and receipt
```

```text
EXECUTION WAL (MANDATORY):

BEFORE DISPATCH:

persist(execution_intent)

AFTER EXECUTION:

persist(execution_result)
```

```text
ON RESTART:

IF execution_intent EXISTS AND result MISSING:

→ VERIFY SIDE EFFECT
→ DO NOT RE-EXECUTE BLINDLY
```

```text
ROLLBACK MUST NOT TRIGGER NEW DETECTION LOOPS

IF DETECTED:

→ SUPPRESS SECONDARY ACTION
→ FLAG CRITICAL
```

```text
REVERSIBILITY MODE IS SNAPSHOT AT EXECUTION START

MID-EXECUTION CHANGE:
→ IGNORED
```

```text
NO STEP MAY BE SKIPPED, REORDERED, OR BYPASSED.
```

## 5.6 Dispatch Replay Lock

Before sending, the dispatch layer MUST verify:

* `action_id` uniqueness within the dispatch ledger
* `action_object` byte equality with any stored version for the same `action_id`

For any given `action_id`, the dispatch ledger MUST contain at most one canonical `action_object` byte sequence.

If an `action_id` already exists, the newly prepared `action_object` bytes MUST equal the stored bytes exactly.

The mapping:

```text
one action_id -> one canonical action_object byte sequence
```

is mandatory.

If the stored version is missing, ambiguous, or byte-inequal:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

## 5.7 Dispatch Guarantees

Dispatch MUST be:

* deterministic
* durable
* replay-safe
* idempotent under redispatch
* route-locked
* payload-immutable

Best-effort dispatch is FORBIDDEN.

---

# 🔴 EXECUTION CONFIRMATION RECONCILIATION (CRITICAL)
RULE

Execution truth MUST be derived from:

execution_result_record (committed)
NOT transport acknowledgment
RECONCILIATION FLOW
IF dispatch_ack_missing:

CHECK storage:

IF execution_result_record EXISTS:
    MARK execution = SUCCESS

ELSE:
    RETRY dispatch (idempotent)
HARD LAW
TRANSPORT IS NON-AUTHORITATIVE
STORAGE IS SOURCE OF TRUTH

## 5.8 Adapter Model

External enforcement MUST occur ONLY via deterministic adapters:

* endpoint agent adapter
* network adapter
* identity provider adapter
* firewall adapter
* cloud control adapter

Adapters MUST:

* be stateless
* be deterministic
* be versioned
* be signed
* produce verifiable `execution_result`

For the purposes of Sections 6 through 10, an adapter executor MUST satisfy the same exactly-once, verification, replay, and crash-safety rules as an endpoint agent executor.

## 5.9 Sandbox Integration

Sandbox execution MUST:

* be invoked deterministically
* execute only through a signed cloud control adapter or signed endpoint agent adapter advertising sandbox capability
* produce a signed analysis result
* produce a deterministic `sandbox_analysis_result_hash`

Sandbox analysis MUST NOT influence the current runtime decision path.

Sandbox analysis MAY influence only future signals and future detections.

## SANDBOX_EXECUTION_BOUNDARY (MANDATORY)

SUBMIT_TO_SANDBOX MUST:

- call external system via signed adapter
- treat sandbox as NON-AUTHORITATIVE

sandbox_result MUST be:

- canonicalized
- hashed
- stored as artifact

FORBIDDEN:

- internal sandbox execution
- non-deterministic sandbox output

## 5.10 Global Propagation

The following `action_type` values are global actions:

* `BLOCK_HASH_GLOBAL`
* `GLOBAL_BLOCK_HASH`
* `GLOBAL_BLOCK_IP`
* `GLOBAL_POLICY_UPDATE`

Global actions MUST:

* propagate via federation
* preserve the original `action_id`
* preserve the original `execution_id`
* remain replay-safe across cores

Federation metadata MAY add:

* `origin_core_id`
* `forwarded_by_core_id`
* `received_from_core_id`
* `federation_hop_count`
* `core_id_path`

Federation metadata MUST NOT alter:

* any field of the canonical `action_object`
* canonical `payload` bytes
* `action_id`
* `execution_id`
* `payload_hash`
* `expected_effect_hash`
* `route_id`
* `route_hash`

---

# 6. EXACTLY-ONCE EXECUTION (CRITICAL)

## 6.1 Exact Execution Law

The authoritative exactly-once rule is:

```text
one execution_id -> one enforcement effect at the executor
```

## 6.2 Executor Ledger Rule

The executor MUST maintain a durable execution ledger keyed by:

```text
execution_id
```

Before effecting any action, the executor MUST persist the `execution_id` ledger entry.

## 6.3 Duplicate Handling

If an executor receives a duplicate `execution_id`:

* the action MUST NOT be re-executed
* the previously persisted `execution_state` MUST be returned
* the previously persisted `execution_result` MUST be returned
* the previously persisted `execution_verification_state` MUST be returned

## 6.4 Idempotency Rule

Executors MUST enforce:

```text
same action_id -> same result -> no re-execution
```

If `action_id` matches a previously completed action, the executor MUST resolve to the previously persisted result without causing a second effect.

## 6.5 Replay Safety Rule

Replay of the same `action_decision` under the same signed enforcement configuration MUST produce the same:

* `action_id`
* `execution_id`
* route resolution
* action envelope bytes

Replay MUST NOT cause duplicate enforcement effect.

## 6.6 Replay Lock Extension (CRITICAL)

Replay MUST NOT regenerate:

* new action_object
* new action_object signatures
* new execution_id values
* new signals

Mandatory rule:

```text
(action_id, execution_id, signal_refs) MUST remain identical
```

If replay would cause:

* a different `action_id`
* a different `execution_id`
* a different emitted enforcement-signal set

the system MUST:

```text
FAIL-CLOSED -> ALERT
```

---

# 7. EXECUTOR EXECUTION CONTRACT

## 7.1 Executor Verification Sequence

Upon receipt of `action_dispatch_envelope`, the executor MUST execute the following order:

```text
1. verify envelope signature
2. recompute and verify payload_hash
3. verify engine identity and trust binding
4. verify route binding to local executor identity
5. resolve exactly one local route from signed local configuration
6. recompute `route_hash` from the locally resolved route
7. verify envelope `route_id`, `action_object.route_id`, and recomputed local `route_id` are exactly equal
8. verify recomputed local `route_hash` exactly matches `action_object.route_hash`
9. verify `action_object.signing_context = action_object_v1`
10. verify `action_object.scope_id` is present and matches the executor's active enforcement scope
11. verify action_object signature using PRD-04 signing model UNLESS executor_signature_mode = ENVELOPE_ONLY (Section 5.3.1.1)
12. if any required signature verification fails OR scope validation fails OR route validation fails: REJECT -> FAIL-CLOSED -> ALERT
13. verify action schema and parameter schema
14. resolve exactly one signed static parameter profile referenced by `parameter_profile_id`
15. resolve exactly one signed adapter manifest referenced by `adapter_type`
16. resolve exactly one signed `action_capability_descriptor` referenced by `action_type`
17. recompute `parameter_profile_hash` from canonical resolved parameter-profile bytes
18. recompute `adapter_manifest_hash` from canonical resolved adapter-manifest bytes
19. recompute `capability_descriptor_hash` from canonical resolved descriptor bytes
20. verify all three recomputed dependency hashes exactly match the dispatched `action_object`
21. durably lock route resolution and all dependency inputs as immutable execution inputs
22. if any verification, resolution, hash match, or lock acquisition fails, REJECT -> FAIL-CLOSED -> ALERT
23. persist execution_id if first-seen
24. if duplicate, return stored result without execution
25. if `reversibility_mode = SNAPSHOT_REVERSIBLE`, create and durably persist reversible snapshot before effect
26. if snapshot creation fails, DO NOT EXECUTE ACTION; REJECT -> FAIL-CLOSED -> ALERT
27. execute exactly once
28. collect deterministic evidence
29. commit execution_result and execution_verification_state to PRD-13 storage BEFORE emitting any enforcement signal
30. if execution_result cannot be committed, DO NOT EMIT SIGNAL; FAIL-CLOSED -> ALERT
31. emit PRD-07 enforcement signals only AFTER commit (Section 7.4.2)
32. return receipt
```

## 7.2 Execution Input Lock

Before effect execution, the executor MUST durably lock the following immutable execution inputs:

* `parameter_profile` by canonical bytes and `parameter_profile_hash`
* `adapter_manifest` by canonical bytes and `adapter_manifest_hash`
* `action_capability_descriptor` by canonical bytes and `capability_descriptor_hash`
* route resolution by `route_id`, `executor_type`, `executor_id`, canonical transport endpoint tuple, and `route_hash`

The executor MUST verify:

* `parameter_profile_hash` matches the locally resolved signed parameter profile exactly by canonical bytes and hash
* `adapter_manifest_hash` matches the locally resolved signed adapter manifest exactly by canonical bytes and hash
* `capability_descriptor_hash` matches the locally resolved signed capability descriptor exactly by canonical bytes and hash
* `route_hash` matches the locally resolved route exactly by canonical bytes and hash

The executor MUST NOT:

* dynamically resolve newer parameter profiles
* dynamically resolve newer adapter manifests
* dynamically resolve newer capability descriptors
* re-resolve to an alternative route
* fallback to a secondary executor
* auto-correct a route mismatch
* auto-fetch missing dependencies
* use local defaults
* use unsigned or partially verified copies
* continue execution under dependency version drift

All execution inputs MUST be exact hash-matched locked copies and MUST remain immutable for the entire execution lifecycle.

If any dependency or route changes after validation but before or during execution:

```text
ABORT -> FAIL-CLOSED -> ALERT
```

If any dependency or route is missing, ambiguous, unsigned, partially verified, unresolved, or hash-mismatched:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

## 7.3 Execution State

The only authoritative `execution_state` values are:

```text
NOT_DISPATCHED
DISPATCHED
EXECUTED
REJECTED
FAILED
```

## 7.4 Execution Result Schema

Every action receipt produced by the executor MUST contain:

```json
{
  "action_id": "hex_32_bytes",
  "execution_id": "hex_32_bytes",
  "executor_type": "ENDPOINT_AGENT_ADAPTER|NETWORK_ADAPTER|IDENTITY_PROVIDER_ADAPTER|FIREWALL_ADAPTER|CLOUD_CONTROL_ADAPTER",
  "executor_id": "string",
  "route_id": "string",
  "route_hash": "hex_32_bytes",
  "execution_state": "DISPATCHED|EXECUTED|REJECTED|FAILED",
  "result_code": "NOT_EXECUTED|APPLIED|ALREADY_APPLIED|REJECTED|FAILED|PARTIAL",
  "parameter_profile_hash": "hex_32_bytes",
  "adapter_manifest_hash": "hex_32_bytes",
  "capability_descriptor_hash": "hex_32_bytes",
  "expected_effect_hash": "hex_32_bytes",
  "observed_effect_hash": "hex_32_bytes",
  "evidence_hash": "hex_32_bytes",
  "evidence_signal_refs": ["hex_32_bytes"],
  "rollback_snapshot_id": "hex_32_bytes",
  "rollback_snapshot_hash": "hex_32_bytes",
  "rollback_evidence_hash": "hex_32_bytes",
  "sandbox_analysis_result_hash": "hex_32_bytes"
}
```

`route_id`, `route_hash`, `parameter_profile_hash`, `adapter_manifest_hash`, and `capability_descriptor_hash` in `execution_result` MUST equal the dispatched `action_object` exactly.

Divergence is:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

## 7.4.2 Signal Causal Lock (CRITICAL)

Executor MUST be signal-aware and replay-locked.

MANDATORY:

1. The executor MUST commit `execution_result` (PRD-13) BEFORE emitting any enforcement signal.
2. The executor MUST emit the required PRD-07 compliant enforcement signals ONLY AFTER commit.
3. The executor MUST include the emitted signal references in the receipt:

```json
"evidence_signal_refs": ["hex_32_bytes"]
```

3. `evidence_signal_refs` MUST be:

* non-empty for any `execution_state = EXECUTED|REJECTED|FAILED`
* ordered lexicographically by `message_id` hex text
* comprised only of `message_id` values of signals emitted for this exact `(action_id, execution_id)`

4. `execution_result` MUST be provable from emitted signals:

```text
execution_result MUST be provable from emitted signals
```

If any of the above is missing or ambiguous:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

### 7.4.2.1 Execution Result Commit Gate (CRITICAL)

Enforcement signals MUST include:

* `execution_result_ref`
* `execution_result_hash`

Mandatory rules:

* `execution_result_ref` MUST resolve to a committed PRD-13 execution-result record (`record_id`)
* `execution_result_hash` MUST be derived from PRD-13 storage as:

  ```text
  execution_result_hash = SHA256(execution_result_record.canonical_payload_bytes)
  ```

  where `execution_result_record.canonical_payload_bytes` is the PRD-13 stored RFC 8785 (JCS) canonical payload bytes for the committed execution_result record referenced by `execution_result_ref`.

FORBIDDEN:

* recomputing `execution_result_hash` from any in-memory object representation
* recomputing `execution_result_hash` from any transport payload bytes
* if `execution_result` is not committed, signals MUST NOT be emitted:

```text
DO NOT EMIT SIGNAL -> FAIL-CLOSED -> ALERT
```

## 7.4.3 Bidirectional Signal-Execution Consistency (CRITICAL)

Enforcement MUST guarantee that `execution_result` and emitted signals are mutually provable.

MANDATORY:

`execution_result.evidence_hash` MUST be:

```text
SHA256(
  RFC 8785 (JCS)({
    "signal_refs": sorted_unique(evidence_signal_refs)
  })
)
```

Define:

```text
canonical_signal_set_hash = SHA256(
  RFC 8785 (JCS)({
    "signal_refs": sorted_unique(evidence_signal_refs)
  })
)
```

MANDATORY:

```text
canonical_signal_set_hash MUST equal execution_result.evidence_hash
```

RULES:

* `execution_result` MUST NOT include any evidence not represented in `evidence_signal_refs`
* `evidence_signal_refs` MUST NOT reference signals not emitted for the exact `(action_id, execution_id)`
* divergence between receipt and signal set is FORBIDDEN

VIOLATION:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

## 7.4.1 PRD-23 Verification Requirements (CRITICAL)

For `action_type = INVESTIGATE_ASSET` and `action_type = PROBE_ASSET_PROFILE`, the executor MUST return results only as committed signals.

Mandatory rules:

* the executor MUST emit one or more PRD-07 `signal_event` messages containing the probe results
* the executor receipt MUST include an evidence reference set to those emitted signal `message_id` values
* probe results MUST NOT be returned only in transport responses, logs, or non-authoritative channels
* probe results MUST NOT be stored only in executor-local state
* the emitted result signals MUST be sufficient to support replay-safe forensic reconstruction

No hidden side effects are permitted:

* the executor MUST NOT perform external enrichment lookups
* the executor MUST NOT create unrecorded local state that changes future authoritative behavior
* any side effect intended to persist MUST be represented only by committed authoritative records

Note:

* For PRD-23 investigative actions, the required enforcement feedback signals (Section 8.10) and any probe-result signals MUST be emitted as `signal_event` objects compliant with PRD-07 signal_type rules.
* If the active PRD-07 signal-type registry does not admit the required enforcement signal types, the system MUST fail closed.

## 7.5 Execution Result Causal Lock

`execution_result` MUST be provably derived ONLY from:

* canonical dispatched `action_object`
* hash-matched locked `parameter_profile`
* hash-matched locked `adapter_manifest`
* hash-matched locked `action_capability_descriptor`
* `route_hash`-matched locked route resolution
* deterministic executor logic

The executor MUST NOT:

* include external runtime state
* include non-deterministic data
* include non-deterministic fields affecting output hashes
* allow non-deterministic fields to affect `observed_effect_hash`
* allow non-deterministic fields to affect `evidence_hash`
* allow non-deterministic fields to affect `rollback_evidence_hash`

If any non-deterministic or non-causal field affects `observed_effect_hash`, `evidence_hash`, or `rollback_evidence_hash`:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

## 7.6 Verification State

Every action receipt produced by the executor MUST also contain:

```text
execution_verification_state = MATCH | MISMATCH
```

## 7.7 Receipt Rule

The executor receipt MUST contain:

* `execution_result`
* `execution_verification_state`

Receipts missing either field are invalid.

## 7.8 Rollback Snapshot Contract

If `reversibility_mode = SNAPSHOT_REVERSIBLE`:

* reversible snapshot creation and durable persistence MUST succeed before effect
* if snapshot creation fails, the action MUST NOT execute
* `execution_state` MUST equal `REJECTED` and `result_code` MUST equal `REJECTED` if snapshot creation fails
* executing without snapshot is FORBIDDEN
* fallback to `NON_REVERSIBLE` is FORBIDDEN
* `rollback_snapshot_id` MUST NOT equal `ZERO_HASH_32`
* `rollback_snapshot_hash` MUST NOT equal `ZERO_HASH_32`
* `rollback_evidence_hash` MUST be NON_ZERO only if reversal executed AND succeeded
* `rollback_evidence_hash` MUST equal `ZERO_HASH_32` in all other cases

If `reversibility_mode = ROLLBACK_ACTION`:

* `rollback_snapshot_id` MUST equal `rollback_snapshot_ref` from the dispatched `action_object`
* `rollback_snapshot_hash` MUST equal the hash of the authoritative reversible snapshot being reversed
* `rollback_evidence_hash` MUST be NON_ZERO only if reversal executed AND succeeded
* `rollback_evidence_hash` MUST equal `ZERO_HASH_32` in all other cases

If `reversibility_mode = NON_REVERSIBLE`:

* `rollback_snapshot_id` MUST equal `ZERO_HASH_32`
* `rollback_snapshot_hash` MUST equal `ZERO_HASH_32`
* `rollback_evidence_hash` MUST equal `ZERO_HASH_32`

Mismatch in any rollback field, reversal-evidence state, or snapshot precondition is:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

## 7.9 Sandbox Result Contract

If `action_type = SUBMIT_TO_SANDBOX`:

* `sandbox_analysis_result_hash` MUST NOT equal `ZERO_HASH_32`
* the analysis result referenced by that hash MUST be signed

If `action_type != SUBMIT_TO_SANDBOX`:

* `sandbox_analysis_result_hash` MUST equal `ZERO_HASH_32`

---

# 8. EXECUTION VERIFICATION

## 8.1 Expected Effect Hash Rule

Each `action_type` MUST define:

* deterministic `expected_effect_hash` derivation
* deterministic verification logic

The derivation and verification logic MUST be identified by the signed `action_capability_descriptor`.

The following canonical input construction is mandatory:

```text
action_object_fields_excluding_ids = {
  "protocol_version": action_object.protocol_version,
  "scope_id": action_object.scope_id,
  "decision_id": action_object.decision_id,
  "policy_id": action_object.policy_id,
  "policy_version": action_object.policy_version,
  "selected_rule_id": action_object.selected_rule_id,
  "action_template_id": action_object.action_template_id,
  "action_type": action_object.action_type,
  "source_detection_ref": action_object.source_detection_ref,
  "detection_snapshot": action_object.detection_snapshot,
  "target_entity_key": action_object.target_entity_key,
  "target_scope": action_object.target_scope,
  "route_id": action_object.route_id,
  "ttl_bound": action_object.ttl_bound,
  "parameter_schema_id": action_object.parameter_schema_id,
  "parameter_profile_id": action_object.parameter_profile_id,
  "adapter_type": action_object.adapter_type,
  "required_capability_id": action_object.required_capability_id,
  "verification_mode": action_object.verification_mode,
  "reversibility_mode": action_object.reversibility_mode,
  "rollback_snapshot_ref": action_object.rollback_snapshot_ref
}

expected_effect_input_bytes = SHA256(
  RFC 8785 (JCS)({
    "action_object_fields_excluding_ids": action_object_fields_excluding_ids,
    "parameter_profile_hash": action_object.parameter_profile_hash,
    "adapter_manifest_hash": action_object.adapter_manifest_hash,
    "capability_descriptor_hash": action_object.capability_descriptor_hash,
    "route_hash": action_object.route_hash
  })
)

expected_effect_hash = SHA256(expected_effect_input_bytes)
```

Any implementation that computes `expected_effect_hash` differently is INVALID.

## 8.2 Core Verification Rule

The Enforcement Engine MUST validate intended versus actual effect using:

* the dispatched `action_object`
* `execution_result`
* `execution_verification_state`

The Enforcement Engine MUST compare:

* `action_object.expected_effect_hash`
* `execution_result.expected_effect_hash`
* `execution_result.observed_effect_hash`
* `action_object.route_id`
* `execution_result.route_id`
* `action_object.route_hash`
* `execution_result.route_hash`
* `action_object.parameter_profile_hash`
* `execution_result.parameter_profile_hash`
* `action_object.adapter_manifest_hash`
* `execution_result.adapter_manifest_hash`
* `action_object.capability_descriptor_hash`
* `execution_result.capability_descriptor_hash`

## 🔴 EXTERNAL STATE VERIFICATION LOOP (CRITICAL)
RULE

Every action MUST be followed by:

verification_signal
MODEL
execution_verified ONLY IF:

observed_state == expected_effect_hash
FAILURE
MISMATCH → corrective action OR escalation

## 8.2.1 Signal-Derived Effect Revalidation (CRITICAL)

The Enforcement Engine MUST independently recompute `observed_effect_hash` using emitted signal references.

MANDATORY:

```text
recomputed_observed_effect_hash = SHA256(
  SHA256(
    RFC 8785 (JCS)({
      "signal_refs": sorted_unique(execution_result.evidence_signal_refs)
    })
  )
)
```

Validation rule:

```text
recomputed_observed_effect_hash MUST equal execution_result.observed_effect_hash
```

AND:

```text
execution_result.observed_effect_hash MUST be derived ONLY from evidence_signal_refs
```

STRICT RULES:

* the Enforcement Engine MUST NOT trust executor-provided `observed_effect_hash` without recomputation
* `evidence_signal_refs` MUST be lexicographically sorted (hex string order)
* `evidence_signal_refs` MUST be duplicate-free
* no additional fields are allowed in the hash input
* canonical encoding MUST follow RFC 8785

FORBIDDEN:

* trusting executor-provided `observed_effect_hash` without recomputation
* including local state in effect validation
* including non-deterministic runtime metadata

VIOLATION:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

## 8.3 Verification Success Rule

An action is considered verified only if:

* `result_code = APPLIED` or `ALREADY_APPLIED`
* `execution_state = EXECUTED`
* `execution_verification_state = MATCH`
* `action_object.expected_effect_hash = execution_result.expected_effect_hash`
* `action_object.route_id = execution_result.route_id`
* `action_object.route_hash = execution_result.route_hash`
* `action_object.parameter_profile_hash = execution_result.parameter_profile_hash`
* `action_object.adapter_manifest_hash = execution_result.adapter_manifest_hash`
* `action_object.capability_descriptor_hash = execution_result.capability_descriptor_hash`
* the execution-result causal lock in Section 7.5 is satisfied
* the rollback contract for the declared `reversibility_mode` is satisfied
* the action-type-specific deterministic verification rule accepts `observed_effect_hash`

## 8.4 Replay Consistency Verification Rule

The same `action_id` MUST verify to:

* identical `route_id`
* identical `route_hash`
* identical `parameter_profile_hash`
* identical `adapter_manifest_hash`
* identical `capability_descriptor_hash`
* identical `executor_type`
* identical `executor_id`
* identical executor-side validation, effect application, rollback handling, and verification behavior as a pure function of the canonical `action_object`, exact hash-matched dependency bytes, and exact route-hash-matched route bytes

Any record set that shows the same `action_id` with any route difference, any dependency-hash difference, or different execution behavior is invalid.

Such divergence is:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

## 8.5 Partial Execution Rule

Partial success MUST be detected.

The following MUST be treated as partial or failed execution:

* `result_code = PARTIAL`
* `result_code = REJECTED`
* `result_code = FAILED`
* `execution_state = REJECTED`
* `execution_state = FAILED`
* `execution_verification_state = MISMATCH`
* `execution_result.expected_effect_hash != action_object.expected_effect_hash`
* `execution_result.route_id != action_object.route_id`
* `execution_result.route_hash != action_object.route_hash`
* `execution_result.parameter_profile_hash != action_object.parameter_profile_hash`
* `execution_result.adapter_manifest_hash != action_object.adapter_manifest_hash`
* `execution_result.capability_descriptor_hash != action_object.capability_descriptor_hash`
* missing or invalid evidence hash
* any `rollback_evidence_hash` inconsistent with Section 7.8
* any non-deterministic or non-causal field affecting `observed_effect_hash`
* any non-deterministic or non-causal field affecting `evidence_hash`
* any non-deterministic or non-causal field affecting `rollback_evidence_hash`
* any effect hash inconsistent with the intended action

## 8.6 PRD Alignment Gate

Enforcement Engine execution MUST remain aligned with:

* PRD-02 trusted boundary, verify-before-use, and signed authority-object law
* PRD-08 verify-before-admit and deterministic rejection behavior
* PRD-11 policy immutability and signed static action parameter profiles
* PRD-12 exactly-once execution by `action_id` and `execution_id`

If any execution path, verification rule, or immutable input contract contradicts these laws:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

## 8.7 Corrective Logic

If verification fails or partial execution is detected:

```text
FAIL-CLOSED -> ALERT
```

The following corrective logic is mandatory:

* emit a CRITICAL `signal_event`
* mark the incident as `enforcement_failure`
* trigger deterministic policy re-evaluation

Ordinary retry MUST NOT be used as a substitute for corrective logic after verified mismatch.

## 8.8 Action Result Schema

The authoritative output of this layer is `action_result`.

Every `action_result` MUST contain:

```json
{
  "protocol_version": "action_result_v1",
  "action_result_type": "NO_ACTION|PENDING_APPROVAL|DISPATCHED_ACTION",
  "decision_id": "hex_32_bytes",
  "policy_id": "string",
  "policy_version": "string",
  "action_result_id": "hex_32_bytes",
  "action_records": [
    {
      "action_id": "hex_32_bytes",
      "execution_id": "hex_32_bytes",
      "action_type": "BLOCK_EXEC|KILL_PROCESS|ISOLATE_HOST|BLOCK_IP|BLOCK_DOMAIN|ROLLBACK_FILE|ROLLBACK_PROCESS_STATE|ROLLBACK_REGISTRY|ROLLBACK_CONFIG|CLEAR_ROLLBACK_LOCK|QUARANTINE_FILE|SUBMIT_TO_SANDBOX|BLOCK_HASH_GLOBAL|DISABLE_IDENTITY|REVOKE_SESSION|RESET_CREDENTIAL|LOCK_ACCOUNT|DISABLE_SWITCH_PORT|APPLY_FIREWALL_RULE|REMOVE_ROUTE|INJECT_TCP_RESET|BLOCK_DNS|RATE_LIMIT_TRAFFIC|BLACKHOLE_ROUTE|TRAFFIC_REDIRECT_TO_SCRUBBER|GLOBAL_BLOCK_HASH|GLOBAL_BLOCK_IP|GLOBAL_POLICY_UPDATE",
      "target_entity_key": "hex_32_bytes",
      "target_scope": "ENTITY_KEY|FILE_OBJECT|PROCESS_OBJECT|REGISTRY_OBJECT|CONFIG_OBJECT|HASH_VALUE|IDENTITY_ACCOUNT|IDENTITY_SESSION|SWITCH_PORT|FIREWALL_RULESET|ROUTE_ENTRY|DNS_NAME|NETWORK_FLOW|SCRUBBER_TARGET|FEDERATION_SCOPE",
      "route_id": "string",
      "route_hash": "hex_32_bytes",
      "parameter_schema_id": "string",
      "parameter_profile_hash": "hex_32_bytes",
      "adapter_type": "ENDPOINT_AGENT_ADAPTER|NETWORK_ADAPTER|IDENTITY_PROVIDER_ADAPTER|FIREWALL_ADAPTER|CLOUD_CONTROL_ADAPTER",
      "adapter_manifest_hash": "hex_32_bytes",
      "capability_descriptor_hash": "hex_32_bytes",
      "expected_effect_hash": "hex_32_bytes",
      "executor_type": "ENDPOINT_AGENT_ADAPTER|NETWORK_ADAPTER|IDENTITY_PROVIDER_ADAPTER|FIREWALL_ADAPTER|CLOUD_CONTROL_ADAPTER",
      "executor_id": "string",
      "dispatch_state": "NOT_DISPATCHED|DISPATCHED|ACKNOWLEDGED",
      "execution_state": "NOT_DISPATCHED|DISPATCHED|EXECUTED|REJECTED|FAILED",
      "execution_result": {
        "action_id": "hex_32_bytes",
        "execution_id": "hex_32_bytes",
        "executor_type": "ENDPOINT_AGENT_ADAPTER|NETWORK_ADAPTER|IDENTITY_PROVIDER_ADAPTER|FIREWALL_ADAPTER|CLOUD_CONTROL_ADAPTER",
        "executor_id": "string",
        "route_id": "string",
        "route_hash": "hex_32_bytes",
        "execution_state": "DISPATCHED|EXECUTED|REJECTED|FAILED",
        "result_code": "NOT_EXECUTED|APPLIED|ALREADY_APPLIED|REJECTED|FAILED|PARTIAL",
        "parameter_profile_hash": "hex_32_bytes",
        "adapter_manifest_hash": "hex_32_bytes",
        "capability_descriptor_hash": "hex_32_bytes",
        "expected_effect_hash": "hex_32_bytes",
        "observed_effect_hash": "hex_32_bytes",
        "evidence_hash": "hex_32_bytes",
        "rollback_snapshot_id": "hex_32_bytes",
        "rollback_snapshot_hash": "hex_32_bytes",
        "rollback_evidence_hash": "hex_32_bytes",
        "sandbox_analysis_result_hash": "hex_32_bytes"
      },
      "execution_verification_state": "MATCH|MISMATCH"
    }
  ],
  "result_reason_code": "string"
}
```

## 8.9 Action Result Identifier

`action_result_id` MUST be:

```text
action_records_hash = SHA256(RFC 8785 (JCS)(action_records))

action_result_id = SHA256(
  decision_id ||
  policy_id ||
  policy_version ||
  action_result_type ||
  action_records_hash ||
  result_reason_code
)
```

## 8.10 Enforcement Signal Emission (CRITICAL)

Enforcement Engine MUST be signal-aware and MUST emit PRD-07 compliant signals for all execution outcomes.

MANDATORY SIGNAL TYPES:

* `infrastructure.enforcement_dispatched.v1`
* `infrastructure.enforcement_executed.v1`
* `infrastructure.enforcement_verified.v1`
* `infrastructure.enforcement_failure.v1`

SIGNAL RULES:

* each emitted enforcement signal MUST be a PRD-07 `signal_event`
* each emitted enforcement signal MUST follow PRD-03 canonical schema and signing rules
* each emitted enforcement signal MUST include:

```json
{
  "action_id": "hex_32_bytes",
  "execution_id": "hex_32_bytes",
  "source_detection_ref": "hex_32_bytes",
  "entity_key": "hex_32_bytes",
  "result_code": "enum",
  "verification_state": "MATCH|MISMATCH"
}
```

Correlation rules:

```text
correlation.entity_key MUST equal action_object.target_entity_key
```

PRD-07 alignment rule:

* if the PRD-07 signal-type registry does not admit the above signal_type values for the active scope, enforcement MUST fail closed rather than emitting non-compliant signals.

## 8.10.1 Enforcement Signal Priority Rule (CRITICAL)

All enforcement signals MUST be emitted with CRITICAL priority.

MANDATORY:

```text
payload.priority MUST equal CRITICAL
```

RULES:

* priority MUST NOT be downgraded by any component
* priority MUST match PRD-07 enforcement signal requirements
* missing or incorrect priority is a protocol violation

VIOLATION:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

## 8.11 Signal-Verified Effect Model (CRITICAL)

For PRD-23 investigative actions (`INVESTIGATE_ASSET`, `PROBE_ASSET_PROFILE`):

```text
expected_effect MUST be validated via emitted signals, NOT local execution only
```

MANDATORY:

```text
observed_effect_hash MUST be computed from:
    emitted signal_event.message_id set
```

NOT:

```text
local executor state
```

Violation:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

## 8.11.1 Canonical Signal Set Hashing (CRITICAL)

Define deterministic construction of observed effect from signals.

MANDATORY:

`observed_effect_input_bytes` MUST be:

```text
SHA256(
  RFC 8785 (JCS)({
    "signal_refs": sorted_unique(evidence_signal_refs)
  })
)
```

`observed_effect_hash` MUST be:

```text
SHA256(observed_effect_input_bytes)
```

RULES:

* `evidence_signal_refs` MUST be lexicographically sorted (hex string order)
* `evidence_signal_refs` MUST be duplicate-free
* no additional fields are permitted in the hash input
* canonical encoding MUST follow RFC 8785

VIOLATION:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

---

# 9. RETRY & FAILURE MODEL

## 9.1 Deterministic Retry Rule

Retry scheduling MUST derive only from signed configuration.

The retry function is:

```text
retry_delay(n) = min(base_delay_ms * 2^n, max_delay_ms)
```

Signed configuration MUST define:

* `base_delay_ms`
* `max_delay_ms`
* `max_dispatch_retries`

## 9.2 Allowed Retry Cases

Retry is permitted ONLY for:

* transport delivery failure
* executor unreachability
* missing receipt beyond signed `receipt_lag_bound` measured as:
  * `current_partition_record_seq - action_partition_record_seq`

Retry is FORBIDDEN for:

* signature failure
* route ambiguity
* verification mismatch
* partial execution detection

## 9.3 Retry Identity Rule

Every retry MUST reuse the same:

* `action_id`
* `execution_id`
* action payload

Generating a new identity on retry is FORBIDDEN.

## 🔴 RETRY TERMINATION LAW (CRITICAL)
RULE

Retry MUST terminate deterministically based on:

max_logical_span
OR
max_retry_count (from signed config)
TERMINATION OUTCOME
IF retries exhausted AND no execution_result_record:

    execution_state = FAILED_UNVERIFIED
HARD LAW
NO INFINITE RETRY LOOPS PERMITTED

## 9.4 Failure Outcomes

If dispatch cannot be completed within signed retry bounds:

```text
FAIL-CLOSED -> ALERT
```

If the executor returns `REJECTED` or `FAILED`:

```text
FAIL-CLOSED -> ALERT
```

## 9.5 No Partial Execution Rule

Partial success MUST NOT be treated as success.

Partial success MUST NOT be hidden by retry.

## 9.6 Failure Signal Enforcement (CRITICAL)

No silent enforcement failure is allowed.

MANDATORY:

```text
All enforcement failures MUST emit:
infrastructure.asset_intelligence_failure.v1
OR
infrastructure.enforcement_failure.v1
```

If a failure is related to PRD-23 asset intelligence scope, the system MUST emit:

* `infrastructure.asset_intelligence_failure.v1`

Otherwise, the system MUST emit:

* `infrastructure.enforcement_failure.v1`

If failure signaling cannot be completed deterministically:

```text
FAIL-CLOSED -> ALERT
```

## 9.7 Rollback State Machine (CRITICAL)

Rollback MUST NOT create undefined system state.

For any action where rollback is required by policy or reversibility mode, rollback handling MUST be represented by an explicit deterministic state machine.

Mandatory states:

```text
ROLLBACK_STATE:

PENDING
EXECUTING
VERIFIED_SUCCESS
FAILED_RETRYABLE
FAILED_NON_RECOVERABLE
ESCALATED_CRITICAL
OVERRIDE_APPLIED
ACTIVE
```

### 9.7.1 Dual Verification Outputs (MANDATORY)

Every rollback attempt MUST produce both:

* `rollback_execution_result`
* `rollback_verification_state`

`rollback_verification_state` MUST be:

```text
MATCH | MISMATCH
```

Missing either output is invalid:

```text
FAIL-CLOSED -> ALERT
```

### 9.7.1.1 STATE_SNAPSHOT_HASH VERIFICATION (CRITICAL)

Whole-machine state hashing is FORBIDDEN for rollback verification because endpoints are dynamic (ambient OS noise).

Rollback verification MUST be **action-scoped** and MUST remain SHA256-only (PRD-01 hash law).

#### 🔴 DETERMINISTIC STATE READ CONTRACT (CRITICAL)

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

Before action:
→ capture `pre_action_scope_hash`

After rollback:
→ capture `post_action_scope_hash`

Mandatory:
* the signed `action_capability_descriptor` MUST define `state_scope`
* the signed `parameter_profile` MAY further restrict `attribute_list` (never expand)
* `pre_action_scope_hash` MUST equal `state_hash` for the declared pre-action read
* `post_action_scope_hash` MUST equal `state_hash` for the declared post-rollback read

---

ROLLBACK VALIDATION:

pre_state_hash == post_state_hash

Verification rule (mandatory):

```text
rollback_success IF:
post_action_scope_hash == pre_action_scope_hash
```

If mismatch:
* `rollback_verification_state = MISMATCH`
* emit `ROLLBACK_MISMATCH`
* escalate CRITICAL

---

FORBIDDEN:
* full system snapshot hashing
* unordered reads
* implicit attributes
* environment-dependent fields (timestamps, memory addresses)
* boolean-only rollback verification
* executor-declared rollback success without scoped hash equality proof

---

FAILURE:

Ambiguous state scope:
→ REJECT ACTION
→ FAIL-CLOSED

### 9.7.2 Deterministic Rollback Retry Policy (MANDATORY)

Rollback retry MUST be deterministic and MUST NOT use jitter.

Mandatory:

* fixed retry count
* fixed retry interval
* no exponential backoff
* no randomization

Signed configuration MUST define:

* `rollback_max_retries` (fixed count)
* `rollback_retry_interval_ms` (fixed interval)

If rollback retry configuration is missing or ambiguous:

```text
FAIL-CLOSED -> ALERT
```

### 9.7.3 Escalation Rule (CRITICAL)

If rollback fails (including exhausted retries or a non-retryable failure):

```text
ACTION_STATE = UNVERIFIED
```

SYSTEM MUST:

* EMIT CRITICAL SIGNAL
* TRIGGER POLICY RE-EVALUATION
* LOCK ENTITY (if configured)
* HALT FURTHER ACTIONS ON ENTITY

This escalation MUST be deterministic and MUST be recorded as append-only authoritative records (PRD-13).

Override escape hatch (CRITICAL):

* the only permitted mechanism to clear a rollback lock after `ESCALATED_CRITICAL` is the controlled override action `CLEAR_ROLLBACK_LOCK`
* `CLEAR_ROLLBACK_LOCK` MUST require the PRD-20 UI governance and MFA approval requirements
* any override MUST be represented as a committed `rollback_override_record` (PRD-13)
* override MUST NOT bypass audit, replay, or policy re-evaluation
* override MUST NOT permit automatic resumption without explicit committed override evidence

### 🔴 OUT-OF-BAND BREAK-GLASS RECOVERY (CRITICAL)

#### PURPOSE

Provide deterministic recovery for control-plane critical entities when UI path is unavailable.

#### BREAK-GLASS CHANNEL DEFINITION

OBGC = OFFLINE SIGNED RECOVERY CHANNEL

Characteristics:

* physically independent from primary control plane
* requires multi-party cryptographic authorization
* produces deterministic, replayable artifacts

#### ALLOWED ACTIONS

Only the following action is permitted:

```text
CLEAR_ROLLBACK_LOCK_BREAKGLASS
```

#### AUTHORIZATION MODEL

Break-glass action MUST require:

* required_signer_count-of-eligible_signer_count threshold signatures
* `eligible_signer_count >= 3`
* `required_signer_count >= 2`

Signed by:

* Root Trust Authority
* Security Officer Key
* Deployment Owner Key

#### ACTION CONSTRUCTION

```text
breakglass_action_id = SHA256(
  "breakglass_v1" ||
  target_entity_key ||
  lock_state_hash ||
  authorization_bundle_hash
)
```

#### EXECUTION RULES

* MUST bypass UI and control plane APIs
* MUST be submitted via signed artifact ingestion path
* MUST be stored as:
  * `record_type = ACTION`
  * `action_type = CLEAR_ROLLBACK_LOCK_BREAKGLASS`
* MUST follow full PRD-12 validation chain

#### 🔴 BREAK-GLASS ORDERING & CAUSALITY (CRITICAL)

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

#### 🔴 BREAK-GLASS IDEMPOTENCY LAW (CRITICAL)

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

#### SAFETY CONSTRAINTS

ONLY valid when:

```text
entity_state = ESCALATED_CRITICAL
```

🔴 CONTROL PLANE UNREACHABILITY PROOF (CRITICAL)
REPLACED BY Section 9.7.3.1.

#### 9.7.3.1 Break-Glass Proof When Commit Is Unavailable (REPLACEMENT, CRITICAL)
The system MUST NOT create a logical deadlock where break-glass requires new commits to prove commits are impossible.

Hard law:

```text
Break-glass eligibility proof MUST be derivable from:
EITHER committed authoritative records
OR signed offline failure artifacts that are themselves replay-verifiable once storage resumes.
```

Define:
* `last_known_commit_hash`: the last committed PRD-13 `batch_commit_record.batch_commit_hash` that the break-glass operator can present (already committed, verifiable)
* `local_failure_proof` artifacts as defined by PRD-20 `LOCAL_FAILURE_PROOF` (signed by node keys)

Allowed proof sources (exactly one of the following models MUST be selected per break-glass attempt and declared in the break-glass payload):

**MODEL A — COMMITTED_SIGNAL_PROOF (unchanged)**
* `control_plane_failure_proof` is derived from committed signals as previously defined.

**MODEL B — OFFLINE_QUORUM_FAILURE_PROOF (NEW)**
* `control_plane_failure_proof` MUST be derived from a quorum set of signed `local_failure_proof` artifacts plus an already-committed anchor:

```text
control_plane_failure_proof = SHA256(
  "offline_failure_proof_v1" ||
  last_known_commit_hash ||
  ordered_local_failure_proofs_hash
)
```

Where:

```text
ordered_local_failure_proofs_hash = SHA256(
  sort_lex_hex(SHA256(local_failure_proof_bytes_1)) ||
  ... ||
  sort_lex_hex(SHA256(local_failure_proof_bytes_n))
)
```

Mandatory rules:
* each `local_failure_proof` MUST be signed and verifiable under PRD-04
* the quorum threshold MUST use the signed `required_signer_count` and `eligible_signer_count` values already required for break-glass authorization
* `last_known_commit_hash` MUST resolve to an existing committed PRD-13 record; if it cannot be verified, the break-glass attempt MUST be rejected
* proof verification MUST be time-independent (no wall-clock)
* if neither MODEL A nor MODEL B can be satisfied deterministically, break-glass MUST be rejected fail-closed

#### REPLAY REQUIREMENT

Break-glass execution MUST be:

* FULLY REPLAYABLE
* FULLY HASH-VERIFIABLE

#### FAILURE RULE

```text
invalid break-glass → REJECT → FAIL-CLOSED → ALERT
```

If escalation cannot be completed deterministically:

```text
FAIL-CLOSED -> ALERT
```

### 9.7.4 State Transition Rules (MANDATORY)

* `PENDING` -> `EXECUTING` only after all rollback prerequisites are verified and locked
* `EXECUTING` -> `VERIFIED_SUCCESS` only if `rollback_verification_state = MATCH`
* `EXECUTING` -> `FAILED_RETRYABLE` only if failure is classified retryable by signed configuration AND retries remain
* `EXECUTING` -> `FAILED_NON_RECOVERABLE` only if failure is classified non-recoverable by signed configuration OR retries are exhausted
* `FAILED_NON_RECOVERABLE` -> `ESCALATED_CRITICAL` is mandatory
* `ESCALATED_CRITICAL` -> `OVERRIDE_APPLIED` is permitted ONLY if a committed `rollback_override_record` exists for the same `entity_id` and links to the relevant `execution_id` (PRD-13) and the override was authorized under PRD-20
* `OVERRIDE_APPLIED` -> `ACTIVE` is mandatory after the override is committed and verified

No other transitions are allowed.

If an implementation encounters an unknown rollback state or cannot classify a failure deterministically:

```text
FAIL-CLOSED -> ALERT
```

---

# 10. STATE MODEL

## 10.1 Allowed State

The only authoritative mutable state of the Enforcement Engine is:

* action generation ledger
* dispatch ledger
* route resolution ledger
* execution receipt ledger
* verification ledger
* exactly-once recovery ledger

## 10.2 Durability Rule

All authoritative action state MUST be:

* atomic
* durable
* append-only or cryptographically chained
* recoverable after crash

Partial writes MUST NOT be visible.

## 10.3 Crash Safety Rule

Crash MUST NOT cause:

* duplicate execution
* loss of durable action state
* inconsistent verification state

## 10.4 Restart Recovery Rule

On restart, the Enforcement Engine MUST:

```text
1. load the last consistent durable state
2. validate integrity of action, dispatch, and verification ledgers
3. identify incomplete dispatches and incomplete verifications
4. resume processing using the same action_id and execution_id
5. reissue deterministic retries only where permitted
6. resume without duplicate execution
```

## 10.5 Forbidden State

The following are FORBIDDEN:

* hidden in-memory-only action state
* mutable counters that change action identity
* cache state that changes authoritative behavior
* unsnapshotted dispatch or verification status

---

# 11. PERFORMANCE MODEL

Enforcement performance is valid only if correctness is unchanged.

The following are mandatory:

* action generation cost MUST be O(action_count)
* route resolution cost MUST be O(action_count)
* dispatch bookkeeping cost MUST be O(action_count)
* verification cost MUST be O(action_count)
* decision-to-dispatch latency SHOULD remain under 100 ms under non-degraded, in-capacity operation

Signed configuration MUST define at minimum:

* maximum actions per decision
* maximum concurrent dispatches
* maximum outstanding receipts

Performance optimization MUST NOT change:

* `action_id`
* `execution_id`
* verification outcome
* `action_result`

---

# 12. SECURITY MODEL

## 12.1 Verify-Before-Use Rule

Before any enforcement step, the system MUST verify:

* `action_decision` integrity
* `enforcement_config` signature
* `entity_route_map` signature
* `action_capability_descriptor` signature
* adapter manifest signature
* static parameter profile signature
* action envelope signature before executor execution

## 12.2 Trust Boundary Rule

The Enforcement Engine MUST trust only:

* signed `action_decision`
* signed enforcement configuration
* signed route maps
* signed action capability descriptors
* signed adapter manifests
* signed parameter profiles
* verified executor identities

Everything else is untrusted.

## 12.3 Executor Trust Rule

The executor MUST trust only:

* signed action envelopes
* verified enforcement engine identity
* signed local configuration

Unsigned commands MUST NEVER execute.

## 12.4 Auditability Rule

Every `action_result` MUST be traceable to:

* `decision_id`
* `policy_id`
* `policy_version`
* `action_id`
* `execution_id`

---

# 13. FORBIDDEN PATTERNS

```text
FORBIDDEN:

- retry heuristics
- adaptive execution
- best-effort dispatch
- unsigned action envelopes
- manual command injection
- new action_id on retry
- new execution_id on retry
- duplicate execution on replay
- partial execution treated as success
- verification mismatch ignored
- stateful adapters
- unsigned adapters
- runtime sandbox results affecting the current decision path
- rollback-capable action without reversible snapshot
- federation propagation that rewrites action_id or execution_id
- mutable runtime logic that changes dispatch outcome
- external API calls as authoritative execution dependency
```

---

# 14. CANONICAL EXECUTION LIFECYCLE

```text id="x2b6mr"
EXECUTION STATE MACHINE:

PLANNED:
entry = action created
exit = approval decision computed

APPROVED:
entry = policy allows execution
exit = execution started

EXECUTING:
entry = dispatch initiated
exit = execution completed OR failure detected

EXECUTED:
entry = execution result received
exit = verification started

VERIFIED:
entry = effect verified
exit = terminal

FAILED:
entry = execution error detected
exit = rollback initiated

ROLLBACK_PENDING:
entry = rollback required
exit = rollback executed

ROLLED_BACK:
entry = rollback success
exit = verification started

ALL TRANSITIONS MUST DEPEND ONLY ON:
- committed records
- signed configuration
- deterministic input

NO IMPLICIT TRANSITIONS ALLOWED
```

# 15. ACTUATION LAYER

The Actuation Layer is the low-level interface between the Enforcement Engine and the physical environment.

## 15.1 Actuation Functions

```text
execute(action_object) -> execution_result
rollback(action_object) -> rollback_result
```

## 15.2 Actuation Rules

* **No Policy/Safety Logic**: The Actuation Layer MUST NOT perform policy evaluation or safety checks. It executes authorized commands only.
* **Idempotency**: All actuation calls MUST be idempotent. Repeating a call with the same `execution_id` MUST return the same result without side effects.
* **Determinism**: For identical inputs and environment state, actuation MUST produce identical effects and output hashes.
* **Short-Lived Credentials**: Actuation MUST use scoped, short-lived credentials derived from the `execution_authorization_token`.
* **Encrypted Communication**: All actuation traffic MUST be encrypted using TLS 1.3 with mandatory mTLS.

## 15.3 GLOBAL VALIDATION RULE (CRITICAL)

Reject enforcement if ANY of the following is true:

* missing `source_detection_ref`
* missing `detection_snapshot`
* `detection_snapshot` mismatch with `source_detection_ref`
* missing enforcement-signal emission for execution outcomes
* mismatch between `expected_effect_hash` and signal-derived `observed_effect_hash` where required
* duplicate `enforcement_uniqueness_key`
* missing `evidence_signal_refs` where required
* non-PRD-07 compliant signal emission
* enforcement signal_type not admitted by PRD-07 signal-type registry

If any validation predicate fails:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

---

# 16. SUMMARY

```text
Enforcement Engine is the deterministic execution layer.

It MUST:
- consume authoritative action_decision input
- generate deterministic action identities
- dispatch signed actions
- guarantee exactly-once execution at the executor
- verify intended versus actual effect
- remain replay-safe and crash-safe

For any given action_id:
- execution MUST be deterministic
- execution MUST be replay-identical
- execution MUST be dependency-locked
- execution MUST be route-locked
- execution MUST be effect-verifiable

Violation of this invariant is:
INTEGRITY_FAILURE -> FAIL-CLOSED -> ALERT

If execution integrity, verification integrity, or state integrity fails:
FAIL-CLOSED -> ALERT
```

---
