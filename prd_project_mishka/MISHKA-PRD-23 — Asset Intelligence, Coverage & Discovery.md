# MISHKA-PRD-23 — Asset Intelligence, Coverage & Discovery

**Project:** Project Mishka  
**Classification:** AUTHORITATIVE — SIGNAL-DRIVEN ASSET DISCOVERY, COVERAGE RECONCILIATION, AND CONTROLLED ONBOARDING  
**Status:** CRITICAL — DETERMINISTIC, REPLAY-SAFE, FAIL-CLOSED ASSET INTELLIGENCE

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

This document defines the authoritative Asset Intelligence subsystem for Project Mishka.

Asset Intelligence is the deterministic reconciliation layer that compares:

* **EXPECTED assets** (control plane authority, signed and UI-governed)
* **OBSERVED assets** (provable existence derived only from admitted signals)
* **MANAGED assets** (provable management bindings derived only from admitted signals)

Asset Intelligence MUST emit deterministic, replay-safe signals for:

* unknown assets
* unmanaged assets
* missing expected assets

Asset Intelligence MUST enable controlled enforcement actions for investigation and onboarding through PRD-12.

This PRD MUST NOT violate:

* PRD-01 (system laws)
* PRD-02 (execution model)
* PRD-03 (identity & message model)
* PRD-07 (signal model)
* PRD-08 (ingest)
* PRD-13 (storage)
* PRD-15 (replay)

---

# 2. CORE PRINCIPLES

```text
EXPECTED vs OBSERVED vs MANAGED reconciliation MUST be:
signal-derived only, deterministic, replayable, and fail-closed.
```

The following laws are mandatory:

* Discovery MUST be signal-derived only.
* Asset existence MUST be provable from admitted signals.
* Coverage evaluation MUST be deterministic for the same committed input dataset.
* No implicit asset state is permitted outside committed storage records.
* Replay MUST reconstruct an identical asset view (bit-for-bit for all emitted asset-intelligence signals).

Micro-hardening (PRD-01 alignment):

* canonical object field lock is mandatory (PRD-01 Section 3.1): unknown fields FORBIDDEN; optional fields MUST be omitted (no null/default)
* array determinism law is mandatory (PRD-01 Section 3.2): every array MUST have an explicit deterministic ordering rule; no implicit ordering
* hash function law is mandatory (PRD-01 Section 3.3): all authoritative hashes in this PRD MUST use `SHA256`

The following are forbidden:

* wall-clock dependency in authoritative logic
* time-based heuristics (including "first seen within a configured recentness window" decisions)
* hidden state (in-memory-only truth, mutable caches that change results)
* external enrichment (DNS reputation, asset inventories, cloud APIs, vendor lookups)
* background scanning loops (periodic network scans, scheduled discovery sweeps)

```text
If a required input signal, identity mapping, or classification input is missing or ambiguous:
FAIL-CLOSED -> emit deterministic failure signal -> do not invent coverage state.
```

---

# 3. ASSET IDENTITY MODEL

## 3.1 Scope Boundary (CRITICAL)

This PRD introduces an **asset identity** for infrastructure assets.

This asset identity:

* is used ONLY inside PRD-23 scope for asset reconciliation
* MUST NOT override, replace, or redefine PRD-03 identities (`agent_id`, `probe_id`, `system_id`)
* MUST NOT be used as an emitter identity
* MUST NOT appear in PRD-03 identity derivation or message_id derivation

PRD-03 forbids IP-based identities for emitters. This PRD permits IP-based identity ONLY as a non-emitter **asset key** used for reconciliation.

## 3.2 Canonicalization Rules

All canonicalization MUST be exact, explicit, and repeatable.

### 3.2.1 Canonical IP

Canonical IP representation MUST satisfy:

* IPv4 MUST be represented as dotted-decimal with no leading zeros in octets (e.g., `10.0.0.1`)
* IPv6 MUST be represented in RFC 5952 canonical form (lowercase hex, shortest form, `::` compression rules)
* IP version MUST be explicit in canonical input
* ambiguous or non-parseable IP MUST fail closed

The canonical IP bytes MUST be UTF-8 encoding of the canonical text form.

### 3.2.2 Canonical MAC (Optional)

If MAC is available deterministically from admitted signals:

* MUST be lowercase hex pairs separated by `:` (e.g., `aa:bb:cc:dd:ee:ff`)
* MUST be exactly 6 octets (EUI-48) unless an explicitly supported and signed schema version permits others
* invalid length or invalid hex MUST fail closed for the MAC field (MAC becomes absent, not repaired)

If MAC is absent, it MUST be represented as explicit absence in the canonical identity input (not implied).

### 3.2.3 Namespace Binding (Optional)

Namespace binding MAY be included only if:

* it is explicit in admitted signals or explicit in signed control-plane inputs
* it is a canonical namespace path satisfying PRD-03 segment rules

Namespace binding MUST NOT be derived heuristically from DNS suffixes, reverse lookup, or external sources.

## 3.3 asset_entity_key Construction (CRITICAL)

Asset Intelligence MUST use a deterministic, content-addressed entity key:

```text
asset_entity_key = SHA256(RFC8785(canonical_identity_input))
```

Where `canonical_identity_input` is the RFC 8785 canonical JSON object:

```json
{
  "schema_version": "asset_identity_v1",
  "ip": {
    "version": 4,
    "canonical": "10.0.0.1"
  },
  "mac": "aa:bb:cc:dd:ee:ff",
  "namespace": "federation/system/core/infrastructure/segment-a"
}
```

Mandatory rules:

* `schema_version` MUST be present and MUST equal `asset_identity_v1`
* `ip.version` MUST be either `4` or `6`
* `ip.canonical` MUST be the canonical IP text form
* `mac` MUST be either a canonical MAC string or MUST be omitted entirely (not empty string)
* `namespace` MUST be either a canonical namespace path string or MUST be omitted entirely
* key ordering and serialization MUST use RFC 8785 canonical JSON

If multiple candidate identity inputs exist for the same observation and they are not byte-identical after canonicalization:

```text
AMBIGUOUS_IDENTITY_MAPPING -> FAIL-CLOSED
```

---

# 4. SIGNAL TYPES (CRITICAL)

All signals defined by this PRD are standard PRD-07 `signal_event` messages with:

* `schema_version` MUST be a member of the active signed `signal_schema_version_set` (PRD-07)
* `signing_context = signal_v1`
* RFC 8785 canonical JSON `canonical_payload_bytes`

This PRD defines new `signal_type` values.

## 4.1 infrastructure.asset_observed.v1

### 4.1.1 Purpose

`infrastructure.asset_observed.v1` is emitted when an asset is observed for the first time within one declared replay scope.

“First time” is defined only by deterministic dataset ordering, not by wall clock.

### 4.1.2 Allowed Source Signals

This signal MAY be derived only from admitted signals, including:

* `network.flow.v1`
* `network.dns.v1`
* `user.auth.v1`
* `process.exec.v1`
* other PRD-07 compliant signals explicitly listed in signed configuration for this PRD revision

No raw telemetry may be used.

### 4.1.3 Deterministic Emission Rule

For one partition-local processing scope, `infrastructure.asset_observed.v1` MUST be emitted exactly once per `asset_entity_key` when the first qualifying observation is encountered in authoritative order.

The “first qualifying observation” MUST be selected using only committed order:

* primary: ascending `partition_record_seq` of the source `signal_record`
* tie-break: ascending `message_id` byte order if multiple sources share the same `partition_record_seq` in derived projections

If the system cannot establish a unique first observation reference:

```text
FAIL-CLOSED -> emit deterministic failure signal (Section 13)
```

### 4.1.4 Payload Requirements

The signal payload MUST include:

* `entity_key` (the `asset_entity_key`)
* `observed_ip` (canonical IP string)
* optional `observed_mac` (canonical MAC string, only if deterministically present)
* optional `namespace` (canonical namespace path, only if deterministically present)
* `fingerprint` feature set summarizing observation features
* `first_observed_ref` (the `message_id` of the first source signal proving observation)

`first_observed_ref` MUST be the exact 32-byte `message_id` of an admitted source `signal_event`.

The payload MUST be RFC 8785 canonical JSON under the PRD-07 `signal_event.payload` object.

### 4.1.5 Fingerprint Feature Set (Deterministic)

Fingerprint features MUST be derived only from source signal features.

At minimum the fingerprint MUST include deterministic, schema-defined fields for:

* observed L4 ports (as sorted unique integer set)
* observed protocols (as sorted unique canonical enum code set)
* observed DNS names (as sorted unique canonical lower-case FQDN strings if and only if deterministically present in `network.dns.v1`)

All sets MUST be stored in deterministic sorted order:

* integers: ascending numeric order
* byte strings / hex: lexicographic order
* domain strings: ASCII lower-case lexicographic order

Any normalization beyond explicit schema rules is forbidden.

## 4.2 infrastructure.asset_coverage.v1

### 4.2.1 Purpose

`infrastructure.asset_coverage.v1` represents the deterministic coverage state for one asset entity as derived from reconciliation inputs.

### 4.2.2 Coverage Enum (Closed Set)

`coverage_state` MUST be exactly one of:

* `EXPECTED_NOT_OBSERVED`
* `OBSERVED_UNMANAGED`
* `MANAGED`
* `UNKNOWN`

Any other value is invalid and MUST be rejected by ingest if encountered.

### 4.2.3 Payload Requirements

The payload MUST include:

* `entity_key`
* `coverage_state`
* `expected_ref` (optional) — the deterministic reference to the expected registry entry proving expectation for this asset
* `observed_ref` (optional) — the deterministic reference to the observation proof (`first_observed_ref`)
* `managed_ref` (optional) — the deterministic reference proving management binding
* `classification` (optional) — the deterministic classification output reference (Section 8)

If a reference is absent, it MUST be omitted, not set to null.

## 4.3 risk.unmanaged_asset.v1

### 4.3.1 Purpose

`risk.unmanaged_asset.v1` is emitted when an asset is provably observed but provably not managed under the management-binding rules of this PRD.

### 4.3.2 Emission Rule

This signal MUST be emitted if and only if:

```text
coverage_state == OBSERVED_UNMANAGED
```

The emitted signal MUST include:

* `entity_key`
* `observed_ref`
* `coverage_ref` (the `message_id` of the corresponding `infrastructure.asset_coverage.v1` signal)
* deterministic risk inputs sufficient to justify severity ranking in downstream UI (no external enrichment)

## 4.4 infrastructure.asset_managed_binding.v1 (REQUIRED FOR MANAGED_SET)

### 4.4.1 Purpose

`infrastructure.asset_managed_binding.v1` provides deterministic proof that a specific observed asset is managed by a specific PRD-03 emitter identity.

This signal exists to ensure `MANAGED_SET` is reconstructable from committed signals without heuristic IP-to-agent inference.

### 4.4.2 Emission Rule

An agent MUST emit this signal only when it has an explicit, deterministic local fact for:

* its own canonical primary IP
* optional MAC
* optional namespace binding if explicitly configured

This emission MUST be signal-driven by the agent’s own boot / identity initialization sequence and MUST NOT be a background scan.

### 4.4.3 Payload Requirements

The payload MUST include:

* `entity_key` (computed `asset_entity_key` from the agent’s canonical primary IP and optional MAC/namespace)
* `managed_by`:
  * `emitter_type`
  * `emitter_id`
  * `boot_session_id`
* `managed_binding_proof`:
  * `proof_type = "agent_self_assertion_v1"`
  * `proof_ref` — `message_id` of the signal that established the agent’s canonical network identity within its process (implementation-specific but MUST be a committed signal reference)

If `managed_binding_proof` cannot be constructed deterministically, the binding MUST NOT be emitted.

---

# 5. EXPECTED ASSET REGISTRY (CONTROL PLANE)

## 5.1 Authority & UI Governance (CRITICAL)

The expected asset registry is a control-plane authority artifact.

The following are mandatory:

* expected assets MUST be defined ONLY through signed UI actions governed by PRD-20 and PRD-21
* every expected-asset write MUST produce a committed `ui_action_record` (PRD-13)
* there is no backend-only registry mutation path
* direct DB edits are forbidden

## 5.2 Registry Structure: GROUP + ENTITY_REGISTRY

Expected assets MUST be organized via the existing `GROUP` hierarchy (PRD-13 `group_record`) and an `ENTITY_REGISTRY` canonical object carried inside `UI_ACTION_RECORD` payloads.

This PRD defines the canonical `ENTITY_REGISTRY` payload schema:

```text
ENTITY_REGISTRY.schema_version = entity_registry_v1
```

`ENTITY_REGISTRY` MUST be persisted only as part of committed `ui_action_record` canonical payloads.

Derived projections MAY materialize it for query, but projections are non-authoritative.

## 5.3 Fields (Mandatory)

Each registry entry MUST include:

* `expected_entity_key` (the `asset_entity_key`)
* `expected_type` (closed enum defined in signed configuration; e.g., `SERVER`, `ENDPOINT`, `PRINTER`, `NETWORK_DEVICE`, `DIRECTORY_SERVICE`, `UNKNOWN`)
* group hierarchy placement (up to 6 levels, via `group_id` references)
* policy bindings (references to signed policy identifiers; no inline policy duplication)

## 5.4 Deterministic Identity Rule

The registry MUST NOT store alternate identity keys for the same asset.

If a UI action attempts to register an expected asset whose canonical identity input is ambiguous or invalid:

```text
REJECT UI ACTION -> FAIL-CLOSED
```

## 5.5 Duplicate Rule

If two registry entries attempt to claim the same `expected_entity_key` with non-identical registry payload:

```text
REGISTRY_CONFLICT -> FAIL-CLOSED -> require operator resolution via UI
```

---

# 6. OBSERVED ASSET MODEL

Observed assets are derived ONLY from committed signals.

The observed asset model is the set:

```text
OBSERVED_SET = { asset_entity_key | there exists at least one admitted source signal that deterministically maps to asset_entity_key }
```

Mandatory rules:

* Observed assets MUST NOT be created by background scans.
* Observed assets MUST NOT be created from external enrichment.
* Observed asset existence MUST be provable by one or more committed `signal_record` entries.
* Observed asset state MUST NOT exist outside committed storage records.

The authoritative observation proof is the `first_observed_ref` stored in `infrastructure.asset_observed.v1`.

---

# 7. COVERAGE EVALUATION ENGINE (CRITICAL)

## 7.1 Deterministic Coverage Function

Coverage state is defined as a deterministic function:

```text
COVERAGE_STATE = f(EXPECTED_SET, OBSERVED_SET, MANAGED_SET)
```

Where:

* `EXPECTED_SET` is derived only from committed `ui_action_record` payloads defining `ENTITY_REGISTRY` entries
* `OBSERVED_SET` is derived only from committed observation-derivable source signals
* `MANAGED_SET` is derived only from committed `infrastructure.asset_managed_binding.v1` signals

## 7.2 Coverage Rules (Exact)

For one `asset_entity_key = k`, define:

* `k ∈ EXPECTED_SET` if and only if an expected registry entry exists for k
* `k ∈ OBSERVED_SET` if and only if an observation proof exists for k
* `k ∈ MANAGED_SET` if and only if a management binding exists for k

The coverage state MUST be computed by the following rules in this exact order:

1. IF `k ∈ EXPECTED_SET` AND `k ∉ OBSERVED_SET` → `EXPECTED_NOT_OBSERVED`
2. IF `k ∈ OBSERVED_SET` AND `k ∉ MANAGED_SET` → `OBSERVED_UNMANAGED`
3. IF `k ∈ OBSERVED_SET` AND `k ∈ MANAGED_SET` → `MANAGED`
4. IF `k ∈ OBSERVED_SET` AND `k ∉ EXPECTED_SET` → `UNKNOWN`

No time-based logic is permitted.

## 7.3 Emission Requirements

For each `k` in the union set:

```text
U = EXPECTED_SET ∪ OBSERVED_SET
```

the system MUST emit exactly one `infrastructure.asset_coverage.v1` per deterministic evaluation boundary.

The evaluation boundary MUST be defined only by:

* partition execution windows defined by signed configuration (PRD-02 windowing)
* committed ordering inputs (`partition_record_seq`, `logical_clock`)

Evaluation boundaries MUST NOT depend on wall clock.

## 7.4 Fail-Closed Preconditions

Coverage evaluation MUST fail closed if any of the following is true for a candidate `k`:

* `asset_entity_key` cannot be computed deterministically from the proving signal set
* the “first observation” proof is ambiguous
* `MANAGED_SET` is required by configuration but no compliant managed-binding signals exist to compute it
* `EXPECTED_SET` contains conflicting registry entries for the same key

On fail-closed, the system MUST:

* NOT emit a coverage state for `k`
* emit a deterministic failure signal as defined in Section 13

---

# 8. DEVICE CLASSIFICATION

## 8.1 Deterministic Classification Law

Classification MUST be deterministic and MUST depend only on:

* admitted signals proving observation behavior
* deterministic feature extraction rules under PRD-07
* signed model snapshots when ML inference is used (PRD-10)

Classification MUST NOT depend on:

* scanning
* external enrichment
* wall-clock behavior
* probabilistic, nondeterministic ML execution

## 8.2 Classification Integration With PRD-09 and PRD-10

Classification is an inference output and MUST be produced through:

* PRD-09 Decision Orchestrator: feature vector construction for classification
* PRD-10 SINE Inference Engine: deterministic inference execution using signed model snapshots

The orchestrator MUST NOT implement inference math.

## 8.3 Deterministic Rule Examples (Non-Exhaustive)

If rule-based classification is enabled by signed configuration, it MUST use exact feature predicates only.

Examples of permissible deterministic feature-to-class rules:

* presence of observed TCP port `9100` → `PRINTER`
* observed LDAP protocol behavior (as defined by signal features) → `DIRECTORY_SERVICE`
* observed SMB + user authentication signals → `ENDPOINT`

If multiple classes match and the tie-break rule is not explicitly defined in signed configuration:

```text
AMBIGUOUS_CLASSIFICATION -> FAIL-CLOSED
```

## 8.4 Classification Traceability

Any classification output MUST be traceable to:

* the exact contributing signal set (ordered deterministic `message_id` list)
* the exact model snapshot or rule-set snapshot used
* the exact feature vector bytes used

Classification outputs MUST be represented as committed signals or committed downstream records whose canonical payload contains these references.

---

# 9. CONTROLLED INVESTIGATION ACTIONS

This PRD defines controlled action intents for asset onboarding and investigation.

## 9.1 Action Types

The following action types are defined:

* `INVESTIGATE_ASSET`
* `PROBE_ASSET_PROFILE`

## 9.2 Governance Requirements (PRD-12 / PRD-20)

All actions MUST:

* be created only through PRD-12 Enforcement Engine
* be signed
* be idempotent by deterministic `action_id`
* be exactly-once executed by deterministic `execution_id`
* be replay-safe under PRD-15
* be UI-governed under PRD-20 and PRD-21 where human approval is required by policy mode

## 9.3 Idempotency Inputs

Each asset investigation action MUST include the target `asset_entity_key` and MUST bind it into:

* `action_id = SHA256(RFC8785(action_object))` as required by PRD-01 and PRD-12

Actions MUST NOT use random IDs or wall-clock-dependent IDs.

## 9.4 Output Signals (Mandatory)

Each action execution MUST produce output signals that are stored as `signal_record` entries.

At minimum:

* `INVESTIGATE_ASSET` MUST produce a deterministic investigation signal referencing:
  * `action_id`
  * `execution_id`
  * `asset_entity_key`
  * ordered evidence references (source `message_id` list)
* `PROBE_ASSET_PROFILE` MUST produce a deterministic profiling signal referencing the same identifiers and the deterministic output feature set

If an action execution cannot produce required output signals:

```text
EXECUTION_FAILURE -> FAIL-CLOSED -> ALERT
```

---

# 10. STORAGE MODEL EXTENSIONS

## 10.1 Storage Boundary (CRITICAL)

This PRD MUST NOT redefine PRD-13 storage schemas or record families.

This PRD defines **new canonical payload schemas** that are stored using existing PRD-13 record families:

* `ASSET_OBSERVATION` → stored as `signal_record` with `signal_type = infrastructure.asset_observed.v1`
* `ASSET_COVERAGE` → stored as `signal_record` with `signal_type = infrastructure.asset_coverage.v1`
* `ENTITY_REGISTRY` (control plane) → stored as `ui_action_record` payload object defining registry writes, and optionally organized by `group_record`

No new PRD-13 `record_type` values are introduced.

## 10.2 Append-Only & Immutability

All asset-intelligence artifacts MUST follow:

* append-only storage
* no mutation of committed authoritative records
* later changes represented only by new records

## 10.3 Replay Completeness

Replay MUST be able to reconstruct:

* the observed asset set (`infrastructure.asset_observed.v1` signals)
* the managed binding set (`infrastructure.asset_managed_binding.v1` signals)
* the expected registry state (from committed `ui_action_record` payloads)
* the computed coverage state (from committed `infrastructure.asset_coverage.v1` signals)
* unmanaged risk outputs (`risk.unmanaged_asset.v1` signals)

Missing any of the above required records for a declared replay scope is:

```text
INTEGRITY_FAILURE -> FAIL-CLOSED -> ALERT
```

---

# 11. UI MODEL (HIGH LEVEL)

All UI behavior MUST be governed by PRD-21 and backed by deterministic query objects (PRD-13 query model).

The UI MUST expose:

* coverage dashboard:
  * totals by `coverage_state`
  * drill-down by group hierarchy (up to 6 levels)
* unknown asset alerts:
  * `coverage_state = UNKNOWN`
  * must link to the proving `infrastructure.asset_observed.v1` and `first_observed_ref`
* unmanaged asset alerts:
  * `coverage_state = OBSERVED_UNMANAGED`
  * must link to `risk.unmanaged_asset.v1` and its `coverage_ref`
* missing expected assets:
  * `coverage_state = EXPECTED_NOT_OBSERVED`
  * must link to the expected registry entry reference

All UI interactions that create or modify expected assets MUST produce `UI_ACTION_RECORD` entries.

No UI-only hidden state is permitted.

---

# 12. REPLAY & FORENSICS

Asset Intelligence MUST support replay-safe forensic reconstruction.

## 12.1 First-Seen Reconstruction

“First seen” for an asset MUST be reconstructed deterministically as:

* the `first_observed_ref` in `infrastructure.asset_observed.v1`
* which references the exact source `message_id` proving the observation

No wall-clock timestamps may be used as authoritative first-seen identity.

## 12.2 Behavior Evolution

Behavior evolution MUST be represented only as:

* additional committed observation-derived features over deterministic evaluation boundaries
* additional committed coverage signals
* additional committed classification outputs with explicit evidence references

## 12.3 Classification Traceability

Classification MUST remain traceable to:

* exact ordered evidence references
* exact model snapshot / ruleset snapshot
* exact feature vector construction inputs

If any traceability input is missing:

```text
FAIL-CLOSED -> do not emit classification output
```

---

# 13. FAILURE MODES

Asset Intelligence MUST fail closed.

## 13.1 Fail-Closed Conditions (Mandatory)

The following conditions MUST fail closed:

* inconsistent identity mapping for an observation
* non-canonical or invalid IP canonicalization
* registry conflicts for the same `expected_entity_key`
* missing required proof references (`first_observed_ref`, managed binding proof)
* ambiguous classification (multiple classes without deterministic tie-break)
* missing required contributing signals for a configured evaluation
* inability to reconstruct `EXPECTED_SET`, `OBSERVED_SET`, or `MANAGED_SET` from committed records

## 13.2 Failure Signaling

On any fail-closed condition, the system MUST emit a deterministic failure signal:

* `infrastructure.asset_intelligence_failure.v1`

This failure signal MUST include:

* `failure_code` (closed enum in signed configuration)
* `entity_key` if determinable
* ordered evidence references (`message_id` list) if available
* deterministic context references (e.g., registry entry ref, coverage evaluation boundary id)

Failure signals MUST NOT attempt recovery by heuristics.

## 13.3 Forbidden Recovery Patterns

The following are forbidden:

* guessing identity fields
* substituting missing MAC or namespace values
* “nearest match” registry mapping
* time-window tolerance logic
* background re-scan to “confirm” an asset

```text
AMBIGUITY OR MISSING INPUT -> FAIL-CLOSED -> ALERT
```

---

# 14. SUMMARY

```text
PRD-23 defines deterministic Asset Intelligence:

- EXPECTED assets are UI-governed, signed, and stored as committed UI action records.
- OBSERVED assets are provable only from admitted signals.
- MANAGED assets are provable only from admitted managed-binding signals.
- Coverage is computed by an explicit deterministic function with no time heuristics.
- The system emits deterministic signals for unknown, unmanaged, and missing expected assets.
- All behavior is replay-safe and fail-closed on ambiguity.
```
