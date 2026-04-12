# MISHKA-PRD-07 — Signal Model

**Project:** Project Mishka  
**Classification:** AUTHORITATIVE — DETERMINISTIC SIGNAL LAYER  
**Status:** FOUNDATIONAL — ONLY CORE INPUT FOR DETECTION, CORRELATION, AND RESPONSE

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

This document defines the authoritative `signal_event` model for Project Mishka.

It establishes how raw telemetry is transformed into deterministic, minimal, lossless, replay-safe signals that:

* normalize all telemetry into one canonical core input
* remove vendor and transport ambiguity
* support deterministic aggregation without loss of security-relevant information
* feed deterministic inference and correlation
* preserve replay correctness

```text
ALL CORE INPUTS MUST BE signal_event.
RAW EVENTS MUST NOT ENTER THE CORE DECISION PATH.
```

---

# 2. CORE PRINCIPLES

```text
A signal is the minimal, self-contained, deterministic representation of security-relevant behavior.
```

Every `signal_event` MUST be:

* deterministic
* minimal
* self-contained
* replayable
* identity-bound
* cryptographically verifiable

The following laws are mandatory:

* all telemetry MUST be normalized before core admission
* signal construction MUST be byte-identical for identical normalized input
* decision-relevant information MUST exist in the signal itself
* raw vendor fields MUST remain outside the core path
* signal aggregation MUST preserve reconstructability

Micro-hardening (PRD-01 alignment):

* canonical object field lock is mandatory (PRD-01 Section 3.1): unknown fields FORBIDDEN; optional fields MUST be omitted (no null/default)
* array determinism law is mandatory (PRD-01 Section 3.2): every array MUST have an explicit deterministic ordering rule; no implicit ordering
* hash function law is mandatory (PRD-01 Section 3.3): all authoritative hashes in this PRD MUST use `SHA256`

---

# 3. SIGNAL TYPES

## 3.1 Authoritative Type Rule

`signal_type` MUST match:

```text
<domain>.<subtype>.v<major>
```

`domain` MUST be one of:

```text
process
network
user
deception
infrastructure
risk
```

Unknown `signal_type` values MUST be rejected.

## 3.2 process

Use for:

* execution activity
* process lineage
* privilege change
* persistence-related execution

Examples:

```text
process.exec.v1
process.privilege.v1
process.persistence.v1
```

## 3.3 network

Use for:

* connection behavior
* flow behavior
* DNS behavior
* lateral movement behavior

Examples:

```text
network.flow.v1
network.dns.v1
network.lateral.v1
```

## 3.4 user

Use for:

* authentication
* session behavior
* account privilege behavior

Examples:

```text
user.auth.v1
user.session.v1
user.privilege.v1
```

## 3.5 deception

Use for:

* decoy interaction
* fake credential use
* deception-triggered access

Examples:

```text
deception.interaction.v1
deception.credential.v1
```

## 3.6 infrastructure

Use for:

* infrastructure state change
* protocol health behavior
* telemetry source status relevant to security posture

Examples:

```text
infrastructure.state.v1
infrastructure.protocol.v1
infrastructure.asset_observed.v1
infrastructure.asset_coverage.v1
infrastructure.asset_managed_binding.v1
infrastructure.asset_intelligence_failure.v1
```

## 3.6.1 Enforcement Signal Types (CRITICAL)

This section defines authoritative enforcement feedback signals emitted by the Enforcement Engine (PRD-12).

The following signal types are mandatory and MUST be accepted as first-class `signal_type` entries:

* `infrastructure.enforcement_dispatched.v1`
* `infrastructure.enforcement_executed.v1`
* `infrastructure.enforcement_verified.v1`
* `infrastructure.enforcement_failure.v1`

MANDATORY PAYLOAD RULES:

Each enforcement signal payload MUST include:

```json
{
  "signal_type": "...",
  "entity_key": "hex_32_bytes",
  "action_id": "hex_32_bytes",
  "execution_id": "hex_32_bytes",
  "execution_result_ref": "hex_32_bytes",
  "execution_result_hash": "hex_32_bytes",
  "source_detection_ref": "hex_32_bytes",
  "result_code": "enum",
  "verification_state": "MATCH|MISMATCH"
}
```

Mandatory rules:

* `payload.signal_type` MUST equal the declared enforcement signal_type
* `payload.entity_key` MUST equal the enforcement target entity key
* `payload.source_detection_ref` MUST be a `detection_event.detection_id` reference
* `payload.execution_result_ref` MUST equal `execution_result_record.record_id` (PRD-13)
* `payload.execution_result_hash` MUST equal `SHA256(RFC 8785 (JCS)(execution_result))` where `execution_result` is the committed execution-result object bytes referenced by `execution_result_ref` (PRD-13)
* `correlation.entity_key` MUST equal `payload.entity_key`
* `feature_set.schema_id` MUST equal `payload.signal_type`
* feature schema MUST be closed and signed
* `priority` MUST be `CRITICAL`

## 3.7 risk

Use for:

* deterministic risk assertions derived from admitted signals and signed authority objects
* risk notifications that MUST remain replay-safe and evidence-bound

Examples:

```text
risk.unmanaged_asset.v1
```

## 3.8 PRD-23 Asset Intelligence Signal Types (CRITICAL)

This section defines required signal-type payload schema rules for PRD-23.

All PRD-23 signal types MUST satisfy:

* deterministic construction for identical normalized inputs
* minimal payload: only the fields required to prove the claim and enable deterministic reconciliation
* self-contained: all required evidence references MUST be carried in the signal payload
* replay-safe: identical committed datasets MUST produce identical emitted bytes
* **no implicit defaults**: every required field MUST be present explicitly
* **no ambiguity**: optional fields are permitted ONLY when this PRD explicitly allows them AND only when deterministically provable (Section 5.8)

Integration constraints (MANDATORY):

* this section MUST NOT change PRD-03 message_id construction
* this section MUST NOT change PRD-03 signing input or signature rules
* this section MUST NOT change PRD-03 identity binding
* this section MUST NOT change PRD-03/PRD-08 partition routing semantics

### 3.8.1 infrastructure.asset_observed.v1

Purpose:

* record a provable asset observation derived from admitted signals

Mandatory payload schema rules:

* `payload.signal_type` MUST equal `infrastructure.asset_observed.v1`
* `payload.entity_key` MUST be present and MUST be the PRD-23 `asset_entity_key` (`hex_32_bytes`)
* `payload.observed_ip` MUST be present and MUST be the canonical IP string form (Section 5.6)
* `payload.first_observed_ref` MUST be present and MUST be a `message_id` reference to the proving source signal
* `payload.fingerprint` MUST be present
* `payload.fingerprint.ports` MUST be present and MUST be a sorted integer array (Section 5.7)
* `payload.fingerprint.protocols` MUST be present and MUST be a sorted canonical enum array (Section 5.7)
* `payload.fingerprint.dns` MAY be present ONLY if deterministically present in admitted inputs; if present it MUST be a sorted lower-case FQDN array (Section 5.7)

Correlation rules:

* `correlation.entity_key` MUST equal `payload.entity_key`

Feature schema rules:

* `feature_set.schema_id` MUST equal `infrastructure.asset_observed.v1`
* the signed feature schema MUST define a fixed, closed feature key set sufficient to verify fingerprint stability (e.g. digests over the canonical arrays)

### 3.8.2 infrastructure.asset_coverage.v1

Purpose:

* record a deterministic reconciliation result for one asset entity

Mandatory payload schema rules:

* `payload.signal_type` MUST equal `infrastructure.asset_coverage.v1`
* `payload.entity_key` MUST be present and MUST be the PRD-23 `asset_entity_key`
* `payload.coverage_state` MUST be present and MUST be one of:
  * `EXPECTED_NOT_OBSERVED`
  * `OBSERVED_UNMANAGED`
  * `MANAGED`
  * `UNKNOWN`
* optional refs MAY be present ONLY if deterministically provable and non-empty:
  * `payload.expected_ref`
  * `payload.observed_ref`
  * `payload.managed_ref`
  * `payload.classification_ref`

If any optional ref is present it MUST be a valid `message_id` reference and MUST NOT be null or an empty placeholder.

Correlation rules:

* `correlation.entity_key` MUST equal `payload.entity_key`

Feature schema rules:

* `feature_set.schema_id` MUST equal `infrastructure.asset_coverage.v1`
* the signed feature schema MUST define a fixed, closed feature key set that encodes the closed coverage_state enum deterministically

### 3.8.3 risk.unmanaged_asset.v1

Purpose:

* record that an asset is provably observed and provably not managed under the declared management-binding rules

Mandatory payload schema rules:

* `payload.signal_type` MUST equal `risk.unmanaged_asset.v1`
* `payload.entity_key` MUST be present and MUST be the PRD-23 `asset_entity_key`
* `payload.coverage_ref` MUST be present and MUST reference the corresponding `infrastructure.asset_coverage.v1` `message_id`
* `payload.observed_ref` MUST be present and MUST reference the proving observation `message_id`
* deterministic risk inputs MAY be present ONLY if:
  * they are derived only from admitted signals and signed authority objects
  * they include no external enrichment
  * their schema is closed, versioned, and machine-verifiable

Correlation rules:

* `correlation.entity_key` MUST equal `payload.entity_key`

Feature schema rules:

* `feature_set.schema_id` MUST equal `risk.unmanaged_asset.v1`
* the signed feature schema MUST define a fixed, closed feature key set that encodes:
  * unmanaged assertion type code
  * any deterministic risk-input codes used by this signal type

### 3.8.4 infrastructure.asset_managed_binding.v1

Purpose:

* provide deterministic proof that an asset entity_key is managed by a specific PRD-03 emitter identity

Mandatory payload schema rules:

* `payload.signal_type` MUST equal `infrastructure.asset_managed_binding.v1`
* `payload.entity_key` MUST be present and MUST be the PRD-23 `asset_entity_key`
* `payload.managed_by` MUST be present and MUST include:
  * `emitter_type`
  * `emitter_id`
  * `boot_session_id`
* `payload.managed_binding_proof` MUST be present and MUST include:
  * `proof_type` MUST equal the exact literal `agent_self_assertion_v1`
  * `proof_ref` MUST be present and MUST be a `message_id` reference

Rules:

* inferred mapping from IP is FORBIDDEN
* management binding MUST require explicit deterministic proof (`managed_binding_proof`)

Correlation rules:

* `correlation.entity_key` MUST equal `payload.entity_key`

Feature schema rules:

* `feature_set.schema_id` MUST equal `infrastructure.asset_managed_binding.v1`
* the signed feature schema MUST define a fixed, closed feature key set sufficient to verify the binding claim deterministically

### 3.8.5 infrastructure.asset_intelligence_failure.v1

Purpose:

* emit deterministic, machine-verifiable fail-closed signals for asset intelligence failures

Mandatory payload schema rules:

* `payload.signal_type` MUST equal `infrastructure.asset_intelligence_failure.v1`
* `payload.failure_code` MUST be present and MUST be a closed enum code from a signed registry
* `payload.evidence_refs` MUST be present and MUST be an ordered list of `message_id` references
* `payload.entity_key` MAY be present ONLY if deterministically computable; if present it MUST be a valid `hex_32_bytes` value
* `payload.context_refs` MAY be present ONLY if deterministically provable and machine-verifiable

Rules:

* free-form error text is FORBIDDEN
* failure payload MUST remain machine-verifiable and schema-closed
* `evidence_refs` MUST be ordered lexicographically by `message_id` hex text

Correlation rules:

* if `payload.entity_key` is present, `correlation.entity_key` MUST equal it
* if `payload.entity_key` is absent, `correlation.entity_key` MUST be the deterministic correlation entity key for the emitting system scope (per signed schema); ambiguity MUST be rejected before emission

---

# 4. SIGNAL STRUCTURE (STRICT SCHEMA)

## 4.1 Authoritative Envelope

Every signal MUST be a PRD-03 compliant message with:

```json
{
  "protocol_version": "signal_event_v1",
  "schema_version": "signal_schema_vN",
  "signing_context": "signal_v1",
  "system_id": "hex_32_bytes",
  "identity_version": 1,
  "emitter_type": "agent|probe",
  "emitter_id": "hex_16_bytes",
  "boot_session_id": "hex_32_bytes",
  "logical_clock": 0,
  "partition_context": "hex_16_bytes",
  "payload_hash": "hex_32_bytes",
  "message_id": "hex_32_bytes",
  "lineage_hash": "hex_32_bytes",
  "signature": "hex_ed25519",
  "payload": {
    "signal_type": "process.exec.v1",
    "priority": "CRITICAL|HIGH|NORMAL",
    "ordering_ref": 0,
    "window": {
      "logical_start": 0,
      "logical_end": 0
    },
    "feature_set": {
      "schema_id": "process.exec.v1",
      "feature_version": 1,
      "features": {
        "feature_name": 0
      }
    },
    "correlation": {
      "entity_key": "hex_32_bytes",
      "correlation_key": "hex_32_bytes",
      "causal_hash": "hex_32_bytes"
    },
    "aggregation": {
      "mode": "NONE|IDENTICAL_COLLAPSE",
      "input_signal_count": 1,
      "aggregation_group_key": "hex_32_bytes",
      "aggregation_proof": {
        "hash_input_set": "hex_32_bytes",
        "aggregation_algorithm_id": "none_v1|identical_collapse_v1",
        "hash_output_aggregate": "hex_32_bytes"
      },
      "reconstruction_metadata": {
        "reconstruction_algorithm_id": "none_v1|expand_identical_collapse_v1",
        "window_logical_width": 0,
        "occurrence_offsets_rle": [[0, 1]]
      }
    }
  }
}
```

## 4.2 Mandatory Field Rules

The following fields are mandatory for every signal:

* identity fields in the message envelope
* `schema_version`
* `boot_session_id`
* `logical_clock`
* `lineage_hash`
* `signal_type`
* `priority`
* `ordering_ref`
* `window`
* `feature_set`
* `correlation`
* `aggregation`

No critical field may be omitted.

## 4.3 Field Semantics

* `schema_version` is the authoritative signal payload schema identifier and MUST equal the system-wide supported signal schema version
* `lineage_hash` is `SHA256(canonical_payload)` for root signals.
* `ordering_ref = partition_record_seq`
* `window.logical_start` and `window.logical_end` define the source logical observation span
* `feature_set` contains all decision-relevant normalized features
* `correlation` contains the canonical correlation inputs
* `aggregation` is mandatory even when no aggregation occurred
* `boot_session_id` identifies one immutable emitter process session and MUST follow PRD-03 session binding for the declared emitter type
* `logical_clock` defines strict per-session signal ordering and MUST follow PRD-03 exactly

## 4.4 Fixed-Point Rule

All fractional values MUST be encoded as fixed-point integers with:

```text
S = 1_000_000_000_000
```

Floating-point values are forbidden.

## 4.5 Envelope Integrity Rule

The signal envelope MUST bind exactly the PRD-03 message-construction inputs required for deterministic replay and verification.

The following fields are part of authoritative message binding and MUST participate in:

* `message_id` construction
* signature input
* replay validation

Binding set:

* `canonical_payload_bytes`
* `identity_bytes`
* `partition_context`
* `boot_session_id`
* `logical_clock`
* `schema_version`

`schema_version` participates through `canonical_payload_bytes`.

`boot_session_id` and `logical_clock` MUST NOT be omitted, synthesized, inferred, or rewritten after signal construction.

## 4.6 Session And Clock Rules

The following are mandatory:

* `boot_session_id` MUST be present in all signals
* `boot_session_id` MUST be exactly 32 bytes
* for `emitter_type = agent`, `boot_session_id` MUST follow `SHA256(agent_id || boot_nonce)` as defined by PRD-03
* for `emitter_type = probe`, `boot_session_id` MUST follow `SHA256(probe_id || boot_nonce)` as defined by PRD-03
* `logical_clock` MUST be `UINT64`
* `logical_clock` MUST be strictly monotonic per `(emitter_id, boot_session_id)`
* `logical_clock` MUST start at `0` for a new `boot_session_id`
* `logical_clock` MUST increment by exactly `+1` for each next emitted signal in the same `(emitter_id, boot_session_id)`
* logical-clock regression MUST be rejected
* logical-clock duplication MUST be rejected
* logical-clock gap MUST be rejected

## 4.7 Schema Version Rule

### 🔴 SCHEMA EVOLUTION & HISTORICAL SUPPORT (CRITICAL)
Signal schemas MUST support evolution without bricking ingest or replay.

Authoritative rule:
* producers MUST emit exactly one `schema_version` identifier per signal
* verifiers (edge self-check, ingest, storage, replay) MUST accept any `schema_version` that is present in the active signed schema registry AND MUST maintain support for all historical schema versions present in the replay dataset

#### SIGNED SCHEMA REGISTRY (MANDATORY)
The system MUST maintain a signed schema registry control object:

```json
{
  "protocol_version": "schema_registry_v1",
  "signing_context": "schema_registry_v1",
  "registry_id": "hex_32_bytes",
  "active_schema_versions": ["signal_schema_v1"],
  "allowed_historical_schema_versions": ["signal_schema_v1"],
  "schema_hash_map": [
    { "schema_version": "signal_schema_v1", "schema_hash": "hex_32_bytes" }
  ]
}
```

Derived sets (authoritative):
* `signal_schema_version_set = union(active_schema_versions, allowed_historical_schema_versions)`

Mandatory:
* `schema_version` MUST be present in all signals
* `schema_version` MUST be part of `canonical_payload_bytes`
* `schema_version` MUST be a member of the active signed `signal_schema_version_set`
* `schema_version` not in set MUST be rejected (`REJECT_SCHEMA_MISMATCH`)
* schema registry objects MUST be verified under PRD-04 before use
* schema registry MUST be replay-verifiable and versioned; removal of a historical version that exists in WORM is FORBIDDEN

---

# 5. SIGNAL NORMALIZATION RULES

## 5.1 Normalization Boundary

All vendor-specific, transport-specific, and raw event formats MUST be transformed into canonical signal fields before emission.

The following are mandatory:

* field names MUST be canonical
* units MUST be canonical
* enum values MUST be canonical integer or canonical string codes from a signed registry
* missing numeric values MUST be explicit zero
* missing categorical values MUST be explicit `"unknown"` only if the schema defines `"unknown"`; otherwise reject

## 5.1.1 Signal-Type Schema Validation Rule (CRITICAL)

Each emitted `signal_event` MUST additionally satisfy the strict payload schema rules for its declared `signal_type`.

The following are mandatory:

* missing required fields for the declared `signal_type` MUST be rejected
* invalid enum values MUST be rejected
* invalid canonical formats (including IP canonicalization requirements where applicable) MUST be rejected
* unsorted set arrays where sorting is required MUST be rejected
* duplicate entries in any set array are forbidden and MUST be rejected

Signals that do not satisfy their declared `signal_type` schema are invalid and MUST NOT be emitted.

## 5.2 Canonical Encoding

Signal payload canonicalization MUST follow:

```text
RFC 8785 (JCS) ONLY
```

All implementations MUST produce byte-identical `canonical_payload_bytes`.

## 5.3 Canonical Payload Construction

For `signal_event`, `canonical_payload_bytes` MUST be the RFC 8785 canonical UTF-8 JSON bytes of:

```json
{
  "schema_version": "signal_schema_vN",
  "payload": { ... }
}
```

The following are mandatory:

* `canonical_payload_bytes` MUST include `schema_version`
* `canonical_payload_bytes` MUST include all required payload fields already defined by this PRD
* `canonical_payload_bytes` MUST NOT exclude any required signal payload field
* `canonical_payload_bytes` MUST exclude `signature`
* `canonical_payload_bytes` MUST exclude transport metadata

`message_id`, `payload_hash`, `partition_context`, and signature verification MUST use this exact canonical payload construction.

## 5.4 Unit Rules

The following unit rules are mandatory:

* duration -> nanoseconds
* size -> bytes
* counts -> unsigned integers
* booleans -> `0` or `1`
* ratios and probabilities -> fixed-point integers using scale `S`

## 5.5 Raw Field Exclusion

The following MUST NOT appear in the authoritative signal payload:

* raw log lines
* raw packet bytes
* vendor field names
* transport headers not required for security meaning
* ambiguous free-text fields

## 5.6 Canonical IP Normalization (CRITICAL)

Signals that carry IP addresses as part of their payload schema (including PRD-23 asset intelligence signals) MUST canonicalize IP deterministically.

Mandatory rules:

* IPv4 MUST be represented as dotted-decimal with no leading zeros in octets.
* IPv6 MUST be represented in RFC 5952 canonical form (lowercase hex, shortest form, `::` compression rules).
* IP version MUST be explicit as `4` or `6` where an IP appears in a payload schema.
* ambiguous, non-parseable, or non-canonical IP MUST be rejected at the producer before emission.

No heuristic normalization is permitted.

## 5.7 Stable Fingerprint Construction (PRD-23)

PRD-23 fingerprint objects MUST be stable and replay-safe.

Mandatory rules:

* any set encoded in the payload MUST be represented as an explicit array
* arrays representing sets MUST be sorted deterministically:
  * ports: ascending numeric order
  * protocol codes: ascending numeric order (or lexicographic order for canonical strings if the schema defines strings)
  * DNS names: ASCII lower-case lexicographic order
* duplicates in any set array are forbidden
* missing set elements MUST be represented by an explicit empty array, not omission

Fingerprint digests:

* any feature digest that claims to summarize one of these sets MUST be computed over the RFC 8785 canonical JSON bytes of the corresponding sorted array
* producers and verifiers MUST compute identical digests for identical sets

Implicit defaults are forbidden:

* a missing fingerprint object MUST be rejected
* a missing fingerprint field MUST be rejected

## 5.8 Optional Field & Ambiguity Rule (CRITICAL)

Optional fields MUST only exist if deterministically provable from admitted signals and/or signed authority objects.

Mandatory rules:

* optional fields MUST NOT be present with `null`
* optional fields MUST NOT be present with empty placeholder values
* optional set arrays MUST NOT be present as empty arrays unless the schema explicitly allows empty as meaningful

If an optional field cannot be proven deterministically:

```text
OMIT FIELD (do not invent placeholders)
```

If omission would make the schema incomplete for the declared `signal_type`:

```text
REJECT BEFORE EMISSION -> FAIL-CLOSED
```

## 5.9 PRD-23 entity_key Handling (CRITICAL)

For PRD-23 asset intelligence signals, `entity_key` MUST be treated as an opaque SHA256 hex string.

```text
entity_key MUST be treated as opaque SHA256 hex string
MUST NOT be recomputed inside PRD-07
MUST be passed as provided by upstream deterministic computation (PRD-23)
```

Any attempt by a signal producer or verifier to recompute or “repair” `entity_key` inside the signal layer is FORBIDDEN.

---

# 6. FEATURE EXTRACTION RULES

## 6.1 Feature Schema Authority

Every `signal_type` MUST have exactly one signed feature schema.

The feature schema MUST define:

* allowed feature names
* feature order
* feature type
* feature unit
* zero value

`feature_set.schema_id` MUST equal `signal_type`.

## 6.2 Feature Set Rules

`feature_set.features` MUST satisfy:

* only schema-defined keys are allowed
* all schema-defined keys MUST be present
* keys MUST be canonically ordered by the encoding standard
* values MUST be integer, fixed-point integer, or signed enum code
* duplicate keys are forbidden

## 6.3 Deterministic Extraction

The same normalized raw input set MUST produce the same feature values bit-for-bit.

The following are forbidden:

* floating-point extraction
* heuristic feature omission
* dynamic feature names
* environment-dependent feature derivation

## 6.4 Correlation Field Derivation

`correlation.entity_key` MUST be:

```text
SHA256(RFC 8785 (JCS)(sorted_canonical_entity_tuple_set))
```

`correlation.correlation_key` MUST be:

```text
SHA256(
  signal_type ||
  entity_key ||
  window.logical_start ||
  window.logical_end
)
```

`correlation.causal_hash` MUST be:

```text
SHA256(ordered_contributing_source_reference_set)
```

`ordered_contributing_source_reference_set` MUST be sorted lexicographically by canonical byte form before hashing.

---

# 7. AGGREGATION MODEL (CRITICAL)

## 7.1 Aggregation Law

Signal aggregation MUST be:

* deterministic
* reversible OR reconstructable
* cryptographically provable

Irreversible aggregation is forbidden.

## 7.2 Allowed Aggregation Modes

The only authoritative aggregation modes are:

```text
NONE
IDENTICAL_COLLAPSE
```

`IDENTICAL_COLLAPSE` is permitted ONLY when all component signals are identical in:

* `signal_type`
* `priority`
* `feature_set`
* `correlation.entity_key`
* `correlation.correlation_key`
* envelope identity fields

## 7.3 Aggregation Group Key

`aggregation_group_key` MUST be:

```text
SHA256(
  signal_type ||
  priority ||
  RFC 8785 (JCS)(feature_set) ||
  correlation.entity_key ||
  correlation.correlation_key ||
  emitter_type ||
  emitter_id
)
```

## 7.4 Aggregation Proof

`aggregation_proof` is mandatory for every signal.

It MUST include:

* `hash_input_set`
* `aggregation_algorithm_id`
* `hash_output_aggregate`

`aggregation_proof` MUST be:

* signed as part of the signal payload
* OR cryptographically chained into authoritative storage

## 7.5 Reconstruction Metadata

`reconstruction_metadata` is mandatory for every signal.

For `mode = NONE`:

```text
reconstruction_algorithm_id = none_v1
window_logical_width = window.logical_end - window.logical_start
occurrence_offsets_rle = [[0, 1]]
```

For `mode = IDENTICAL_COLLAPSE`:

* `reconstruction_algorithm_id` MUST be `expand_identical_collapse_v1`
* `occurrence_offsets_rle` MUST be sorted by ascending offset
* `occurrence_offsets_rle` MUST exactly encode the multiplicity of component occurrences within the aggregate window

## 7.6 Reconstruction Rule

Reconstruction MUST be possible using ONLY:

* the aggregated signal record
* `reconstruction_metadata`
* the statically implemented deterministic reconstruction algorithm identified by `reconstruction_algorithm_id`

No network lookup, database lookup, vendor dictionary, or external runtime dependency is permitted.

## 7.7 Input Set Hash

`hash_input_set` MUST be computed over the lexicographically ordered set of component `message_id` values.

`hash_output_aggregate` MUST be computed over the canonical aggregate payload bytes.

---

# 8. PRIORITY CLASSIFICATION (CRITICAL/HIGH/NORMAL)

## 8.1 Mandatory Classes

Every signal MUST declare exactly one priority:

```text
CRITICAL
HIGH
NORMAL
```

## 8.2 CRITICAL

Use ONLY for:

* execution-control behavior
* privilege escalation behavior
* lateral movement behavior
* trust or integrity violations
* deception credential use
* enforcement failure signals

CRITICAL signals MUST NEVER be silently dropped.

## 8.3 HIGH

Use for:

* suspicious process behavior
* suspicious network behavior
* suspicious user behavior
* deterministic aggregated security signals
* high-confidence correlation inputs

HIGH signals MAY use larger deterministic aggregation windows only under the rules in Section 7.

## 8.4 NORMAL

Use for:

* redundant periodic summaries
* low-risk telemetry summaries
* operationally useful but non-urgent security context

NORMAL signals MAY be delayed longest under PRD-02 degradation rules.

## 8.5 Priority Authority

The minimum allowed priority for each `signal_type` MUST be defined in a signed signal registry.

Runtime logic MAY escalate priority.

Runtime logic MUST NOT downgrade below the registry minimum.

---

# 9. SIGNAL DEDUPLICATION

## 9.1 Authoritative Key

Exact signal deduplication MUST use:

```text
message_id
```

## 9.2 Exact Duplicate Rule

If two signals have the same:

* canonical payload bytes
* identity bytes
* partition context
* boot_session_id
* logical_clock

they MUST produce the same `message_id` and MUST be treated as duplicates or replays.

## 9.3 Deduplication Scope

Deduplication MUST be exact only.

The following are forbidden:

* fuzzy matching
* similarity thresholds
* time-near dedupe without byte identity

## 9.4 Deduplication vs Aggregation

Deduplication removes retransmission of the same signal.

Aggregation combines multiple valid component occurrences under Section 7.

These are different operations and MUST NOT be conflated.

---

# 10. SIGNAL ORDERING

## 10.1 Source Ordering

Signal generation MUST use deterministic source ordering inside each closed logical window.

Contributing source references MUST be sorted before:

* feature extraction that depends on set order
* `causal_hash` computation
* `hash_input_set` computation

## 10.1.1 Signal Reference Ordering Rule (CRITICAL)

Any ordered list of references to admitted signals (including any `signal_refs` field defined by any downstream PRD) MUST be ordered by:

```text
PRIMARY: partition_record_seq ASC
TIE BREAK: message_id ASC (lexicographic)
```

If a reference list does not carry `partition_record_seq`, it is incomplete and MUST be rejected before emission.

## 10.2 Core Ordering

Authoritative core ordering is defined by PRD-02 after signal admission.

```text
ordering_ref = partition_record_seq
```

Signal admission and signal construction MUST follow partition-based parallelism:

* each partition executes on a single thread
* multiple partitions MAY execute in parallel across CPU cores

Parallel execution MUST NOT introduce race conditions, shared mutable state, or non-deterministic ordering.

Parallelism MUST NOT change canonical signal bytes, `payload_hash`, or `message_id`.

## 10.3 Window Rule

`window.logical_start` MUST be less than or equal to `window.logical_end`.

Signals with inverted windows MUST be rejected.

## 10.4 Logical Clock Ordering Rule

Signal schema ordering MUST be enforced by the carried `logical_clock`.

The following are mandatory:

* `logical_clock` MUST be validated before signal acceptance
* `logical_clock` MUST be strictly monotonic per `(emitter_id, boot_session_id)`
* `logical_clock` regression MUST be rejected
* `logical_clock` duplication MUST be rejected
* non-sequential increment MUST be rejected
* downstream systems MUST NOT derive `logical_clock`

---

# 11. SIGNAL STORAGE FORMAT

## 11.1 Authoritative Format

Signals MUST be stored as:

```text
canonical JSON bytes of the full signal_event
```

The full stored record MUST preserve:

* the message envelope
* the signal payload
* the signature

## 11.2 Projection Rule

Optional indexed or columnar projections MAY exist.

These projections:

* MUST be derived only from the authoritative canonical record
* MUST NOT be treated as authoritative
* MUST NOT omit mandatory authoritative fields from the primary record

## 11.3 Storage Key Rule

`message_id` is the authoritative signal identifier for storage and replay.

Separate `signal_id` fields are forbidden because they duplicate identity.

All authoritative signal writes MUST be atomic and durable.

Partial signal writes MUST NOT be visible.

Signal state MUST be recoverable after crash.

---

# 12. REPLAY COMPATIBILITY

## 12.1 Replay Law

For identical:

* normalized telemetry input
* identity
* `boot_session_id`
* `logical_clock`
* `schema_version`
* feature schema
* signal registry
* aggregation configuration

the resulting `signal_event` MUST be bit-for-bit identical.

## 12.2 Aggregated Replay

Aggregated signals MUST replay identically if:

* component input set is identical
* logical window is identical
* `occurrence_offsets_rle` is identical
* aggregation algorithm version is identical

## 12.3 No Hidden Dependencies

Replay MUST NOT depend on:

* vendor parser state outside signed code and canonical rules
* wall-clock order
* arrival-time order
* runtime randomness
* hidden caches

On restart, the signal subsystem MUST:

```text
1. load the last consistent durable signal state
2. validate integrity
3. replay incomplete signal operations
4. resume processing without signal loss
```

Signal-processing services MUST auto-start on machine boot.

Signal-processing services MUST auto-restart on process failure.

Signal-processing services MUST implement bounded retry with backoff.

Crash MUST NOT cause signal loss.

Crash MUST NOT cause duplicate authoritative signal admission.

Crash MUST NOT cause inconsistent replay state.

## 12.4 Replay Compatibility Contract

The signal schema MUST guarantee:

* deterministic reconstruction of `message_id`
* deterministic signature verification
* strict ordering via `logical_clock`
* session isolation via `boot_session_id`

The following are mandatory:

* identical `canonical_payload_bytes`, `identity_bytes`, `partition_context`, `boot_session_id`, and `logical_clock` MUST produce identical `message_id`
* identical `canonical_payload_bytes`, `identity_bytes`, `partition_context`, `boot_session_id`, and `logical_clock` MUST produce identical signature verification outcome
* replay validation MUST treat `boot_session_id` and `logical_clock` as authoritative binding inputs
* no downstream system may inject `schema_version`, derive `logical_clock`, or rewrite `boot_session_id`

---

# 13. PERFORMANCE MODEL

The signal model MUST remain bounded and scalable.

The following are mandatory:

* each `signal_event` serialized size MUST be less than or equal to 4096 bytes
* each `signal_type` MUST define a fixed maximum feature count less than or equal to 64
* feature extraction MUST be O(feature_count)
* exact deduplication MUST be O(1) by `message_id`
* aggregation MUST be O(input_count) within a closed window with bounded memory

GPU MAY be used only as an acceleration layer for:

* batch cryptographic verification
* batch hashing
* deterministic inference execution (PRD-10 SINE)

GPU execution MUST:

* produce identical results as CPU
* use deterministic kernels
* NOT affect ordering
* NOT affect signal meaning

GPU MUST NOT be required for correctness.

CPU MUST remain the authoritative execution layer.

Signals SHOULD reduce core ingestion volume by removing duplicate semantics, but correctness MUST NOT depend on any target compression ratio.

---

# 14. SECURITY MODEL

## 14.1 Verify-Before-Use

No signal may be parsed as trusted input before:

* envelope identity verification
* `boot_session_id` validation
* `logical_clock` validation
* `schema_version` validation
* `message_id` recomputation
* signature verification

## 14.2 Signal Trust

A signal is valid ONLY if:

* message envelope is valid
* `boot_session_id` is present and valid
* `logical_clock` is present and valid
* `schema_version` is present and exact
* `signal_type` is registry-valid
* feature schema is valid
* aggregation proof is valid
* reconstruction metadata is valid

## 14.3 Corruption Rule

If any of the following differ from recomputed values:

* `payload_hash`
* `message_id`
* `correlation.causal_hash`
* `aggregation_proof.hash_output_aggregate`

the signal MUST be rejected.

## 14.4 Mandatory Envelope Validation Failures

The following conditions MUST be rejected:

* missing `boot_session_id`
* missing `logical_clock`
* missing `schema_version`
* `boot_session_id` wrong length
* `logical_clock` regression
* `logical_clock` duplication
* `logical_clock` non-sequential increment
* `schema_version` mismatch
* non-canonical JSON

Any of the above is:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

---

# 15. FORBIDDEN PATTERNS

```text
FORBIDDEN:

- raw logs in authoritative signal payload
- vendor-specific field names in authoritative signal payload
- optional omission of mandatory correlation or aggregation fields
- optional presence of required envelope fields
- ambiguous free-text decision fields
- floating-point values
- heuristic scores without signed schema definition
- variable meaning for the same feature key
- dynamic feature names at runtime
- separate signal_id distinct from message_id
- lossy aggregation
- aggregation without aggregation_proof
- aggregation without reconstruction_metadata
- raw-event dependence in the core decision path
- deriving `logical_clock` downstream
- injecting `schema_version` downstream
- omitting `boot_session_id` from authoritative signal construction
- unsigned signal_event records
```

---

# 16. SUMMARY

```text
signal_event is the only authoritative core input.

Signals are:
- deterministic
- minimal
- self-contained
- replay-safe
- identity-bound
- session-isolated
- strictly ordered
- aggregation-safe

Aggregation is allowed only when:
- deterministic
- provable
- reversible or reconstructable

If a signal is ambiguous, lossy, unsigned, or non-deterministic:
REJECT -> FAIL-CLOSED -> ALERT
```

---
