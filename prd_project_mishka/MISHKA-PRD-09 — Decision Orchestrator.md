# MISHKA-PRD-09 — Decision Orchestrator

**Project:** Project Mishka  
**Classification:** AUTHORITATIVE — DETERMINISTIC DECISION ORCHESTRATION LAYER  
**Status:** FOUNDATIONAL — WINDOWING, FEATURE CONSTRUCTION, INFERENCE INVOCATION, AND CORRELATION EMISSION

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

This document defines the authoritative Decision Orchestrator for Project Mishka.

It governs how validated and durably admitted `signal_event` inputs are:

* sequenced by authoritative partition order
* assembled into deterministic windows
* transformed into complete feature vectors
* submitted to the deterministic inference engine
* correlated using explicit causal rules
* emitted as `detection_event`

This layer exists to sequence and assemble analysis.

```text
signals -> window -> features -> inference -> correlation -> detection_event
```

The Decision Orchestrator MUST NOT implement inference mathematics, policy evaluation, or action execution.

---

# 2. CORE PRINCIPLES

```text
Decision Orchestrator sequences deterministic analysis. It does NOT implement inference mathematics.
```

## 2.1 FORBIDDEN_EXECUTION_LOGIC (CRITICAL)

```text
FORBIDDEN_EXECUTION_LOGIC:

- prompt chaining
- LLM inference
- heuristic scoring
- probabilistic branching

IF DETECTED:
→ REJECT INPUT
→ EMIT CRITICAL SIGNAL
→ HALT PARTITION
```

The following principles are mandatory:

* the orchestrator MUST consume only validated, replay-safe, queue-admitted signals from PRD-08
* authoritative execution order MUST be the partition-local order defined by PRD-02
* windowing MUST be partition-scoped, configuration-driven, and replay-safe
* feature vectors MUST be complete, ordered, deterministic, and free of missing ambiguity
* inference MUST be invoked through the signed deterministic inference engine only
* correlation MUST be causal-only and MUST NOT depend on arrival order
* `detection_event` MUST be deterministic, replay-compatible, and sufficient for downstream policy evaluation
* heuristics, dynamic runtime logic, and probabilistic branching are FORBIDDEN

Micro-hardening (PRD-01 alignment):

* canonical object field lock is mandatory (PRD-01 Section 3.1): unknown fields FORBIDDEN; optional fields MUST be omitted (no null/default)
* array determinism law is mandatory (PRD-01 Section 3.2): every array MUST have an explicit deterministic ordering rule; no implicit ordering
* hash function law is mandatory (PRD-01 Section 3.3): all authoritative hashes in this PRD MUST use `SHA256`

```text
NO RAW EVENTS MAY ENTER THIS LAYER.
NO BAYESIAN LOGIC, SCORING LOGIC, OR MODEL MUTATION MAY EXIST IN THIS LAYER.
```

---

# 3. INPUT CONTRACT (FROM PRD-08)

## 3.1 Authoritative Source

The Decision Orchestrator MUST consume input only from the PRD-08 durable queue and partition-routing handoff.

The input unit is:

```text
decision_input
```

`decision_input` MUST represent a signal that has already passed:

* canonical validation
* identity validation
* `signing_context` validation
* SHA256 recomputation
* Ed25519 signature verification
* replay acceptance
* durable queue admission

## 3.2 Authoritative Input Structure

Every `decision_input` MUST contain:

```json
{
  "queue_ref": "opaque_durable_reference",
  "partition_id": 0,
  "partition_epoch": 0,
  "logical_shard_id": "hex_16_bytes",
  "shard_seq": 0,
  "signal_event": {}
}
```

`signal_event` MUST be PRD-07 compliant.

## 3.3 Input Validity Rules

The following are mandatory before orchestration:

* `partition_id` MUST match the active signed routing configuration
* `partition_epoch` MUST match the active partition epoch for `shard_seq`
* `logical_shard_id` MUST be the deterministic shard for the routed entity
* `shard_seq` MUST be contiguous within the active logical shard
* `signal_event.message_id` MUST be unique in the ordered stream unless replay has already been rejected upstream

Any mismatch:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

## 3.4 Authoritative Ordering

Within one logical shard, authoritative input order is:

```text
(partition_epoch, logical_shard_id, shard_seq)
```

```text
shard_seq IS A DERIVED REPRESENTATION OF partition_record_seq

MAPPING MUST BE LOSSLESS AND DETERMINISTIC
```

```text
shard_seq MUST BE DIRECTLY DERIVED FROM partition_record_seq
NO INDEPENDENT ALLOCATION
```

```text
FOR EACH RECORD:

ASSERT shard_seq == partition_record_seq
```

The orchestrator MUST NOT reorder inputs inside a logical shard.

Cross-partition merge order is NOT authoritative for orchestration correctness.

## 3.5 Forbidden Inputs

The Decision Orchestrator MUST NOT consume:

* raw telemetry
* rejected or quarantined signals
* unsigned signals
* policy objects as decision inputs
* action results as decision inputs
* external enrichment feeds
* runtime operator annotations

---

# 4. WINDOWING MODEL (CRITICAL)

## 4.1 Window Law

Windowing MUST be:

* deterministic
* partition-scoped
* logical-shard-scoped
* defined only by signed configuration
* replay-compatible

Wall-clock timers MUST NOT define authoritative window boundaries.

```text
WINDOW_STATE:

OPEN
CLOSING
CLOSED
EMITTED
REJECTED

TRANSITIONS:

OPEN → CLOSING (predicate met)
CLOSING → CLOSED (finalization)
CLOSED → EMITTED (output committed)
ANY → REJECTED (failure)
```

```text
OPEN:
entry = new window created
exit = predicate met OR max bound reached

CLOSING:
entry = predicate met
exit = final aggregation complete

CLOSED:
entry = finalized
exit = emission success

EMITTED:
entry = record committed
exit = terminal

REJECTED:
entry = validation failure
exit = terminal
```

## 4.2 Signed Window Rule

Every window MUST be governed by one signed `window_rule`.

`window_rule` MUST define at minimum:

* `window_rule_id`
* `feature_profile_id`
* allowed `signal_type` set
* open predicate
* close predicate
* `max_signal_count`
* `max_logical_span`
* `max_open_windows_per_shard`
* overlap mode

Open and close predicates MUST be explicit boolean expressions over:

* `signal_type`
* `priority`
* `message_id`
* `correlation.entity_key`
* `correlation.correlation_key`
* `correlation.causal_hash`
* `window.logical_start`
* `window.logical_end`
* `shard_seq`

External data dependencies are FORBIDDEN.

```text
IF max_open_windows_per_shard EXCEEDED:

→ STOP OPENING NEW WINDOWS
→ DO NOT EVICT EXISTING
```

## 4.3 Allowed Window Modes

The only authoritative window modes are:

```text
FIXED_COUNT
LOGICAL_SPAN
TRIGGERED
```

`FIXED_COUNT`:

* opens on the first matching signal
* closes after exactly `max_signal_count` matching signals

`LOGICAL_SPAN`:

* opens on the first matching signal
* closes when:

```text
max(window.logical_end) - min(window.logical_start) >= max_logical_span
```

`TRIGGERED`:

* opens only when the signed open predicate evaluates true
* closes only when the signed close predicate evaluates true
* MUST still honor `max_signal_count` and `max_logical_span` as hard bounds

```text
WINDOW STALL PROTECTION:

IF NO NEW SIGNALS AND WINDOW OPEN:

→ FORCE CLOSE USING max_logical_span
```

## 4.4 Window Membership Rule

Signal membership in a window MUST be evaluated in ascending `(agent_id, boot_session_id, logical_clock)` order.

A signal MAY belong to more than one window ONLY when the signed overlap mode explicitly permits it.

If overlap mode forbids overlap, a signal MUST belong to at most one open window for the same `window_rule_id`.

`max_open_windows_per_shard` MUST be defined in signed configuration.

The following enforcement is mandatory:

```text
if open_windows > max_open_windows_per_shard:
    REJECT -> FAIL-CLOSED -> ALERT
```

No eviction, LRU, or heuristic cleanup is permitted.

## 4.5 Window Identifier

Every closed window MUST have a deterministic `window_id`:

```text
ordered_signal_ref_hash = SHA256(message_id_1 || message_id_2 || ... || message_id_n)

window_id = SHA256(
  partition_epoch ||
  logical_shard_id ||
  window_rule_id ||
  first_shard_seq ||
  last_shard_seq ||
  ordered_signal_ref_hash
)
```

`message_id_n` order MUST be ascending `(agent_id, boot_session_id, logical_clock)`.

## 4.6 Cross-Partition Windowing Rule

Authoritative window membership MUST NOT span multiple physical partitions.

Cross-partition relationships MAY be correlated later using explicit causal metadata only.

## 4.7 PRD-23 Asset Observation Window Rules (CRITICAL)

Asset discovery and coverage processing MUST be signal-driven and MUST follow the same windowing law.

For PRD-23 asset observation, the following window rules are mandatory:

* window membership MUST group by `correlation.entity_key` (the PRD-23 `asset_entity_key`)
* asset observation windows MUST be shard-local and partition-scoped
* asset observation windows MUST NOT require wall-clock or external registry lookups

### 4.7.1 First Occurrence Detection (Deterministic)

The orchestrator MUST support deterministic first-occurrence detection for assets.

Definition:

* “first occurrence” means: the first admitted signal in ascending `(agent_id, boot_session_id, logical_clock)` order whose `correlation.entity_key = k` for a given asset key `k`

Mandatory rule:

* first-occurrence determination MUST depend only on the ordered `decision_input` stream and the signed PRD-23 window rule configuration

The orchestrator MAY maintain shard-local mutable state during execution:

* `seen_asset_entity_keys` keyed by `correlation.entity_key`

This state is permitted only if it is:

* deterministic for the same committed input stream
* reconstructable from committed inputs during replay
* partition-scoped and shard-scoped

Hidden or non-replayable “seen” state is FORBIDDEN.

### 4.7.1.1 Ordering Key Alignment (CRITICAL)

PRD-23 requires first-observation selection to use:

* `partition_record_seq ASC`
* tie-break: `message_id ASC`

In the Decision Orchestrator input stream, the authoritative ordering key is:

```text
(partition_epoch, logical_shard_id, shard_seq)
```

For PRD-23 asset intelligence inside the orchestrator, the following equivalence rule is mandatory:

* `partition_record_seq` in PRD-23 selection rules MUST be treated as the deterministic per-partition admission sequence for the windowed signal stream, represented here by `shard_seq` within the active `(partition_epoch, logical_shard_id)` scope.

Tie-break rule:

* if two candidate first-observation signals are equal under the primary ordering key due to derived views, the tie-break MUST be ascending `signal_event.message_id` byte order.

No wall-clock or arrival-time ordering is permitted.

### 4.7.2 Required PRD-23 Window Configuration Shape

Signed `window_rule` definitions for PRD-23 asset observation MUST satisfy:

* allowed `signal_type` set MUST include the PRD-23 observation inputs (e.g., `infrastructure.asset_observed.v1`) and any additional admitted proof signals explicitly listed in signed configuration
* open predicate MUST require `signal_type` membership and equality on `correlation.entity_key`
* close predicate MUST be deterministic and MUST NOT depend on timers
* `max_signal_count` and `max_logical_span` MUST be hard bounds

If a PRD-23 asset observation window cannot be closed deterministically under the signed predicates and hard bounds:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

---

# 5. FEATURE VECTOR CONSTRUCTION

## 5.1 Feature Profile Authority

Every window MUST map to exactly one signed `feature_profile`.

```text
ASYNC PRE-COMPUTE RULE:

FEATURE PRE-COMPUTATION IS ALLOWED ONLY IF:

- FINAL FEATURE VECTOR IS BUILT FROM AUTHORITATIVE ORDERED SIGNALS
- PRE-COMPUTED DATA IS DISCARDED IF WINDOW CHANGES

FINALIZATION MUST BE:

STRICTLY DETERMINISTIC
```

```text
IF WINDOW MUTATES:

→ INVALIDATE ALL PRE-COMPUTED STATE
```

`feature_profile` MUST define:

* `feature_profile_id`
* `feature_profile_version`
* ordered feature index list
* feature type per index
* zero value per index
* extraction operator per index
* allowed source `signal_type` set per index

## 5.2 Authoritative Feature Vector

The authoritative feature vector object is:

```json
{
  "feature_profile_id": "string",
  "feature_profile_version": 1,
  "window_id": "hex_32_bytes",
  "vector_length": 0,
  "values": [0],
  "feature_vector_hash": "hex_32_bytes"
}
```

`vector_length` MUST equal the number of ordered feature indices in the signed profile.

## 5.3 Completeness Rule

Every feature slot MUST be present for every emitted vector.

Missing source evidence MUST resolve to the signed zero value for that slot.

Implicit null, omitted positions, and sparse vectors are FORBIDDEN.

## 5.4 Allowed Extraction Operators

The only authoritative extraction operators are:

```text
COUNT
SUM_INT
MIN_INT
MAX_INT
BOOL_OR
LAST_VALUE_BY_ORDER
```

All operators MUST execute over signals in ascending `(agent_id, boot_session_id, logical_clock)` order.

Any operator not in the signed profile is FORBIDDEN.

## 🔴 RATE LIMIT AGGREGATION FALLBACK (CRITICAL)
RULE

When rate exceeded:

signals MUST NOT be silently dropped
BEHAVIOR
overflow_signals → aggregated_signal
AGGREGATION MODEL
aggregated_signal = {
  signal_type,
  entity_key,
  count,
  time_span,
  aggregation_hash
}
FEATURE COMPATIBILITY

Feature extraction MUST treat:

aggregated_signal.count AS COUNT operator input
HARD LAW
NO EVIDENCE LOSS IS PERMITTED
ONLY EVIDENCE COMPRESSION
REPLAY LAW
same overflow → same aggregated_signal

## 5.5 Numeric Rules

Feature values MUST be one of:

* integer
* fixed-point integer
* signed enum code

Floating-point feature values are FORBIDDEN.

## 5.6 Feature Vector Hash

`feature_vector_hash` MUST be:

```text
SHA256(
  feature_profile_id ||
  feature_profile_version ||
  window_id ||
  vector_length ||
  ordered_feature_values
)
```

`ordered_feature_values` MUST be serialized in feature-index order.

```text
FEATURE VECTOR IMMUTABILITY LAW:

ONCE window_id IS COMPUTED:

- feature vector MUST NOT change
- late signals MUST NOT mutate vector

LATE SIGNAL:
→ NEW WINDOW
```

```text
feature_vector_hash MUST BE COMPUTED BEFORE INFERENCE

AND VERIFIED AFTER STORAGE
```

```text
MULTIPLE WINDOWS MAY BE BATCHED

BUT:

EACH WINDOW MUST PRODUCE IDENTICAL OUTPUT
AS IF EXECUTED INDIVIDUALLY
```

## 5.7 PRD-23 Asset Intelligence Feature Vector Extension (CRITICAL)

PRD-23 requires deterministic asset feature vectors built only from admitted signals.

For PRD-23 asset discovery and coverage detections, the signed `feature_profile` MUST include explicit slots for at minimum:

* **port profile**: deterministic port presence and/or counts derived from admitted network signals
* **protocol distribution**: deterministic protocol code counts derived from admitted network signals
* **dns associations**: deterministic DNS name association set digest and counts derived from admitted DNS signals

Mandatory rules:

* all asset-intelligence features MUST be derived only from `signal_refs` in the window
* no external inputs are permitted
* no heuristic selection (e.g., “top ports”) is permitted unless the selection basis is a signed, fixed registry defining a total order
* set-like inputs MUST be canonicalized into deterministic sorted arrays before hashing or counting
* missing evidence MUST resolve to explicit signed zero values

DNS association stability rule:

* any DNS-name set MUST be canonicalized to ASCII lower-case FQDN strings
* ordering MUST be lexicographic
* duplicates are forbidden

The resulting feature vector MUST remain:

```text
complete + ordered + deterministic + replay-safe
```

---

# 5.8 PRD-23 ASSET INTELLIGENCE COMPUTATION (CRITICAL)

This section integrates PRD-23 Asset Intelligence into deterministic orchestration.

Asset intelligence MUST:

* use ONLY admitted signals and committed control-plane records
* use NO time-based heuristics
* use NO external enrichment
* preserve replay exactness
* fail closed on ambiguity

## 5.8.1 Detection Domain Extension (CRITICAL)

The orchestrator MUST recognize the following detection domains as a signed closed set.

This PRD extends that set to include:

```text
ASSET_INTELLIGENCE
```

## 5.8.2 Required PRD-23 Detection Types (CRITICAL)

This PRD defines required PRD-23 detection types. They MUST exist in the signed closed detection-type registry:

```text
NEW_ASSET_DETECTED
UNMANAGED_ASSET_DETECTED
MISSING_EXPECTED_ASSET
ASSET_COVERAGE_COMPUTED
```

Each detection type MUST map to PRD-23 signal outputs (Section 5.8.6) and MUST be deterministic and replay-safe.

## 5.8.3 Asset Observation Logic (NEW_ASSET_DETECTED)

Trigger:

* when first observation of `entity_key` occurs

Implementation:

* group by `correlation.entity_key` (PRD-23 `asset_entity_key`)
* select first occurrence using the ordering rule in Section 4.7.1.1

Outputs:

* emit `detection_event` with:
  * `detection_domain = ASSET_INTELLIGENCE`
  * `detection_type = NEW_ASSET_DETECTED`
  * `affected_entity_keys = [entity_key]`
  * ordered `signal_refs` proving the first observation
* emit PRD-23 signal:
  * `infrastructure.asset_observed.v1`

## 5.8.4 Coverage Computation Engine (CRITICAL)

Inputs:

* `EXPECTED_SET` (from committed UI control-plane writes recorded as `UI_ACTION_RECORD` payloads, deterministically reconstructed for the declared execution scope)
* `OBSERVED_SET` (from admitted signals proving observation for one `entity_key`)
* `MANAGED_SET` (from admitted `infrastructure.asset_managed_binding.v1` signals)

Deterministic function:

```text
coverage_state = f(EXPECTED, OBSERVED, MANAGED)
```

Rules MUST EXACTLY MATCH PRD-23:

1. EXPECTED & NOT OBSERVED → EXPECTED_NOT_OBSERVED
2. OBSERVED & NOT MANAGED → OBSERVED_UNMANAGED
3. OBSERVED & MANAGED → MANAGED
4. OBSERVED & NOT EXPECTED → UNKNOWN

Output:

* emit `detection_event` with:
  * `detection_domain = ASSET_INTELLIGENCE`
  * `detection_type = ASSET_COVERAGE_COMPUTED`
  * `affected_entity_keys = [entity_key]`
  * ordered evidence refs sufficient to justify the computed state deterministically
* emit PRD-23 signal:
  * `infrastructure.asset_coverage.v1`

## 5.8.5 Unmanaged Asset Detection (UNMANAGED_ASSET_DETECTED)

Rule:

```text
if coverage_state == OBSERVED_UNMANAGED:
    emit UNMANAGED_ASSET_DETECTED
    emit risk.unmanaged_asset.v1
```

Outputs:

* emit `detection_event` with:
  * `detection_domain = ASSET_INTELLIGENCE`
  * `detection_type = UNMANAGED_ASSET_DETECTED`
* emit PRD-23 signal:
  * `risk.unmanaged_asset.v1`

## 5.8.6 Missing Expected Asset Detection (MISSING_EXPECTED_ASSET)

Rule:

```text
if entity_key ∈ EXPECTED_SET AND entity_key ∉ OBSERVED_SET:
    emit MISSING_EXPECTED_ASSET
```

Output:

* emit `detection_event` with:
  * `detection_domain = ASSET_INTELLIGENCE`
  * `detection_type = MISSING_EXPECTED_ASSET`

## 5.8.7 Classification Trigger (PRD-10 Integration)

Classification MUST be invoked ONLY through PRD-10 SINE.

Trigger:

* classification MAY be triggered only when the signed feature profile indicates sufficient features are available for the target model

Mandatory request contents:

* deterministic feature vector
* ordered evidence refs (`signal_refs` in authoritative order)
* signed model snapshot identifiers

Inline ML, heuristic classification, or external enrichment is FORBIDDEN.

## 5.8.8 PRD-23 Signal Emission Contract (CRITICAL)

When this orchestrator emits PRD-23 asset intelligence signals, it MUST do so as standard PRD-07 `signal_event` messages.

Mandatory rules:

* emitted signals MUST be signed under a PRD-03 compliant `probe` identity dedicated to asset intelligence emission
* emitted signals MUST preserve PRD-03 `boot_session_id` and `logical_clock` laws
* emitted signals MUST use the PRD-07 schema rules for the corresponding PRD-23 `signal_type`
* emitted signals MUST be stored as `signal_record` (PRD-13)

If the orchestrator cannot emit compliant signals deterministically:

```text
FAIL-CLOSED -> ALERT
```

## 5.8.9 Failure Handling Alignment (PRD-23) (CRITICAL)

If any of the following occurs:

* ambiguous first observation selection
* missing required signal inputs
* inconsistent `entity_key` mapping
* missing managed binding when required by signed configuration

then the system MUST fail closed and MUST emit:

* `infrastructure.asset_intelligence_failure.v1`

This failure signal MUST be emitted as a PRD-07 `signal_event` and MUST be stored as `signal_record` (PRD-13).

---

# 6. INFERENCE INVOCATION (STRICT)

## 6.1 Invocation Law

The Decision Orchestrator MUST invoke the deterministic inference engine as an external authoritative component.

The Decision Orchestrator MUST NOT:

* implement Bayesian logic
* implement scoring
* implement model thresholding
* modify model outputs
* mutate model tables

## 6.2 Signed Model Selection

The orchestrator MUST select the inference engine and model ONLY from signed configuration.

The following are mandatory:

* `engine_id`
* `model_id`
* `model_version`
* `model_hash`
* compatible `feature_profile_id`
* output schema identifier

Unsigned or incompatible models MUST be rejected.

## 6.3 Authoritative Inference Request

The orchestrator MUST construct:

```json
{
  "request_id": "hex_32_bytes",
  "engine_id": "string",
  "model_id": "string",
  "model_version": "string",
  "feature_profile_id": "string",
  "feature_profile_version": 1,
  "window_id": "hex_32_bytes",
  "feature_vector_hash": "hex_32_bytes",
  "values": [0]
}
```

`request_id` MUST be:

```text
SHA256(
  engine_id ||
  model_id ||
  model_version ||
  feature_profile_id ||
  feature_profile_version ||
  window_id ||
  feature_vector_hash
)
```

## 6.4 Invocation Sequence

The following sequence is mandatory:

```text
1. verify signed engine and model metadata
2. verify feature_profile compatibility
3. construct inference_request
4. invoke deterministic inference engine
5. validate returned request_id, model_id, model_version, and output schema
6. continue only if all values match
```

## 6.5 Authoritative Inference Result

The inference engine MUST return:

```json
{
  "result_id": "hex_32_bytes",
  "request_id": "hex_32_bytes",
  "model_id": "string",
  "model_version": "string",
  "output_schema_id": "string",
  "threat_score_fixed": 0,
  "confidence_fixed": 0,
  "class_code": "BENIGN|SUSPICIOUS|MALICIOUS",
  "reason_codes": ["string"],
  "raw_output_hash": "hex_32_bytes"
}
```

`reason_codes` MUST be ordered by the signed output schema.

## 6.6 Output Validation Rule

The orchestrator MUST validate:

* `request_id` equality
* `model_id` equality
* `model_version` equality
* `output_schema_id` equality
* `raw_output_hash` validity
* type and bounds of all returned values

Any mismatch:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

---

# 7. CORRELATION ENGINE

## 7.1 Correlation Law

Correlation MUST be:

* causal-only
* deterministic
* rule-driven
* replay-compatible

Arrival order, network timing, and transport timing MUST NOT influence correlation results.

## 7.2 Correlation Identity

Every unique correlation instance MUST have a deterministic `correlation_id`.

```text
correlation_id = SHA256(RFC8785(full_canonical_object))
```

## 7.3 Correlation Outputs

The Correlation Engine MUST produce the following authoritative outputs:

* **correlation_strength**: An integer value representing the cumulative weight of causal edges.
* **attack_graph_hash**: The deterministic hash of the constructed correlation graph.

## 7.4 Correlation Rules

* **Deterministic Graph Construction**: Graphs MUST be built using pure functions of authoritative inputs and signed rules.
* **No Probabilistic Inference**: Correlation MUST NOT use Bayesian or probabilistic guessing. An edge exists only if explicitly proven by a rule.

## 7.5 Signed Correlation Rules (Extended)

Every correlation edge MUST be produced by a signed `correlation_rule`.

`correlation_rule` MUST define:

* `rule_id`
* allowed source `signal_type` set
* allowed target `signal_type` set
* required equality predicates over canonical correlation fields
* maximum relative shard distance if same-partition correlation is required
* whether cross-partition causal references are allowed
* max_dependency_depth

The only canonical correlation fields allowed in rule predicates are:

* `correlation.entity_key`
* `correlation.correlation_key`
* `correlation.causal_hash`
* `message_id`
* `partition_epoch`
* `logical_shard_id`
* `shard_seq`

```text
correlation.entity_key MUST INCLUDE scope_id

CROSS-TENANT MATCH:
→ REJECT → FAIL-CLOSED
```

## 7.3 Allowed Edge Preconditions

An edge MAY exist ONLY when a signed `correlation_rule` evaluates true over authoritative inputs.

Order alone MUST NOT create an edge.

Same entity alone MUST NOT create an edge unless a signed `correlation_rule` explicitly allows it.

## 7.4 Correlation Graph Structure

The authoritative correlation graph MUST contain:

* ordered node reference set
* ordered edge reference set
* deterministic `graph_id`
* deterministic `graph_hash`

`max_nodes_per_graph` MUST be enforced.

`max_edges_per_graph` MUST be enforced.

Nodes MAY reference only:

* `signal_event.message_id`
* `correlation.entity_key`

Edges MUST contain:

```json
{
  "src_ref": "hex_32_bytes",
  "dst_ref": "hex_32_bytes",
  "rule_id": "string"
}
```

## 7.5 Ordering Rule

Node references MUST be ordered lexicographically by canonical byte form.

Edge references MUST be ordered by:

```text
(src_ref, dst_ref, rule_id)
```

## 7.6 Correlation Graph Identity

`graph_id` MUST be:

```text
SHA256(window_id || ordered_node_ref_hash || ordered_edge_ref_hash)
```

`graph_hash` MUST be the SHA256 hash of the canonical graph object bytes.

The following enforcement is mandatory:

```text
if node_count > max_nodes_per_graph:
    REJECT -> FAIL-CLOSED -> ALERT

if edge_count > max_edges_per_graph:
    REJECT -> FAIL-CLOSED -> ALERT
```

Graph truncation is FORBIDDEN.

## 7.7 Cross-Partition Correlation Rule

Cross-partition correlation is permitted ONLY through explicit causal references already present in authoritative inputs and allowed by signed `correlation_rule`.

Cross-partition arrival order dependency is FORBIDDEN.

CAUSAL_DEPENDENCY_BOUND (CRITICAL):

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

Mandatory:

* emitted `detection_event.correlation_completeness` MUST be `PARTIAL` when PARTIAL_CORRELATION is emitted
* emitted `detection_event.correlation_completeness` MUST be `COMPLETE` otherwise

FORBIDDEN:

* waiting for future data
* blocking on unresolved partition

---

## 🔴 NEGATIVE_EVIDENCE_SIGNAL (MANDATORY)
IF dependency missing AND:

```text
edge_drop_detected = TRUE
```

SYSTEM MUST EMIT:

```text
DEPENDENCY_ABSENT_SIGNAL
```

This signal becomes valid input for correlation.

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

---

# 8. DETECTION EVENT MODEL

## 8.1 Authoritative Output

The only authoritative output of this layer is:

```text
detection_event
```

## 8.2 Detection Event Schema

Every `detection_event` MUST contain:

```json
{
  "protocol_version": "detection_event_v1",
  "signing_context": "detection_event_v1",
  "key_id": "string",
  "key_epoch": "uint32",
  "signature": "hex_ed25519",
  "detection_domain": "string",
  "detection_type": "string",
  "detection_id": "hex_32_bytes",
  "lineage_hash": "hex_32_bytes",
  "partition_id": 0,
  "partition_epoch": 0,
  "logical_shard_id": "hex_16_bytes",
  "window": {
    "window_id": "hex_32_bytes",
    "window_rule_id": "string",
    "first_shard_seq": 0,
    "last_shard_seq": 0
  },
  "signal_refs": ["hex_32_bytes"],
  "affected_entity_keys": ["hex_32_bytes"],
  "feature_profile_id": "string",
  "feature_profile_version": 1,
  "feature_vector_hash": "hex_32_bytes",
  "confidence_score": 0,
  "correlation_strength": 0,
  "correlation_completeness": "COMPLETE|PARTIAL",
  "confidence_vector": {
    "threat_score": 0,
    "confidence_score": 0,
    "correlation_strength": 0,
    "asset_criticality": 0
  },
  "inference": {
    "request_id": "hex_32_bytes",
    "result_id": "hex_32_bytes",
    "model_id": "string",
    "model_version": "string",
    "output_schema_id": "string",
    "threat_score_fixed": 0,
    "confidence_fixed": 0,
    "class_code": "BENIGN|SUSPICIOUS|MALICIOUS",
    "reason_codes": ["string"],
    "raw_output_hash": "hex_32_bytes"
  },
  "correlation": {
    "graph_id": "hex_32_bytes",
    "graph_hash": "hex_32_bytes",
    "node_refs": ["hex_32_bytes"],
    "edge_refs": [
      {
        "src_ref": "hex_32_bytes",
        "dst_ref": "hex_32_bytes",
        "rule_id": "string"
      }
    ]
  }
}
```

```text
IF REQUIRED MAPPING (e.g. asset_criticality) MISSING:

→ PARTITION DEGRADED MODE
→ DO NOT BLOCK ALL DETECTIONS
```

### 8.2.1 Signing Requirements (CRITICAL)

The following are mandatory:

* `signing_context` MUST equal the exact literal `detection_event_v1` (constant, versioned, immutable)
* `signature` MUST be constructed and verified using the PRD-04 signing model
* signature domain separation by `signing_context` is MANDATORY (PRD-04); any context mismatch MUST be treated as: `REJECT -> FAIL-CLOSED -> ALERT`
* the signature MUST cover the full canonical `detection_event` object **excluding** the `signature` field itself (PRD-04 rule)
* any mismatch, missing signature fields, or unverifiable signature MUST be treated as:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

`detection_domain` MUST be present and MUST be drawn from a signed, closed detection-domain registry.

This PRD extends that registry to include:

```text
ASSET_INTELLIGENCE
```

`detection_type` MUST be present and MUST be drawn from a signed, closed detection-type registry.

For PRD-23 asset intelligence integration, the following detection types MUST exist in that registry:

* `NEW_ASSET_DETECTED`
* `UNMANAGED_ASSET_DETECTED`
* `MISSING_EXPECTED_ASSET`
* `ASSET_COVERAGE_COMPUTED`

`detection_type` selection MUST be deterministic and MUST depend only on:

* the ordered `signal_refs`
* the signed window rules
* the signed feature profile
* the signed inference model outputs (if inference is used)
* the signed expected-asset registry records admitted through the control plane (when required for `MISSING_EXPECTED_ASSET`)

External enrichment and heuristic branching are FORBIDDEN.

The following governance output rules are mandatory:

* `confidence_score` MUST be an integer
* `correlation_strength` MUST be an integer
* `confidence_vector` MUST be a deterministic structure
* `confidence_vector.threat_score` MUST equal `inference.threat_score_fixed`
* `confidence_vector.confidence_score` MUST equal top-level `confidence_score`
* `confidence_vector.correlation_strength` MUST equal top-level `correlation_strength`
* `confidence_vector.asset_criticality` MUST be a deterministic integer derived only from authoritative ordered orchestration inputs and signed asset criticality mapping objects

## 8.3 Detection Identifier

`detection_id` MUST be:

```text
detection_id = SHA256(RFC8785(full_canonical_object))
```

## 8.3.1 Canonical Detection Event Object (CRITICAL)

Canonicalization for all hashing and signing MUST use **RFC 8785 (JCS) ONLY**.

`full_canonical_object` for `detection_event` is the exact object with the following fields and structure (all fields listed are mandatory; optional fields MUST be omitted, not set to null):

```json
{
  "protocol_version": "detection_event_v1",
  "signing_context": "detection_event_v1",
  "key_id": "string",
  "key_epoch": "uint32",
  "detection_domain": "string",
  "detection_type": "string",
  "detection_id": "hex_32_bytes",
  "lineage_hash": "hex_32_bytes",
  "partition_id": 0,
  "partition_epoch": 0,
  "logical_shard_id": "hex_16_bytes",
  "window": {
    "window_id": "hex_32_bytes",
    "window_rule_id": "string",
    "first_shard_seq": 0,
    "last_shard_seq": 0
  },
  "signal_refs": ["hex_32_bytes"],
  "affected_entity_keys": ["hex_32_bytes"],
  "feature_profile_id": "string",
  "feature_profile_version": 1,
  "feature_vector_hash": "hex_32_bytes",
  "confidence_score": 0,
  "correlation_strength": 0,
  "confidence_vector": {
    "threat_score": 0,
    "confidence_score": 0,
    "correlation_strength": 0,
    "asset_criticality": 0
  },
  "inference": {
    "request_id": "hex_32_bytes",
    "result_id": "hex_32_bytes",
    "model_id": "string",
    "model_version": "string",
    "output_schema_id": "string",
    "threat_score_fixed": 0,
    "confidence_fixed": 0,
    "class_code": "BENIGN|SUSPICIOUS|MALICIOUS",
    "reason_codes": ["string"],
    "raw_output_hash": "hex_32_bytes"
  },
  "correlation": {
    "graph_id": "hex_32_bytes",
    "graph_hash": "hex_32_bytes",
    "node_refs": ["hex_32_bytes"],
    "edge_refs": [
      {
        "src_ref": "hex_32_bytes",
        "dst_ref": "hex_32_bytes",
        "rule_id": "string"
      }
    ]
  }
}
```

Ordering and omission rules (mandatory):

* `signal_refs` MUST contain `message_id` references only (no storage metadata).
* `signal_refs` MUST be ordered deterministically as:
  * PRIMARY: `partition_record_seq` ASC
  * TIE BREAK: `message_id` ASC (lexicographic)
* `partition_record_seq` MUST be resolved by looking up each referenced `message_id` in committed PRD-13 `signal_record` storage within the same verification scope.
* if any referenced `message_id` cannot be resolved to exactly one committed `signal_record`, ordering cannot be established and the `detection_event` MUST be rejected:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

Purity rule (mandatory):

* `detection_id` MUST depend ONLY on the canonical `detection_event` fields and `signal_refs` (`message_id` only).
* `detection_id` MUST NOT depend on:
  * `partition_record_seq`
  * storage-layer metadata
  * derived ordering artifacts
* `affected_entity_keys` MUST be ordered lexicographically by canonical byte form
* `inference.reason_codes` MUST be ordered exactly as defined by the signed `output_schema_id`
* `correlation.node_refs` MUST be ordered lexicographically by canonical byte form
* `correlation.edge_refs` MUST be ordered by `(src_ref, dst_ref, rule_id)` (as already required by Section 7)
* null fields are FORBIDDEN
* optional fields MUST be omitted (not null); if omission would make the schema incomplete for `detection_event_v1`, emission MUST fail closed before output

## 8.4 Lineage Hash

`lineage_hash` MUST be:

```text
lineage_hash = SHA256(parent.lineage_hash || canonical_payload)
```
where `parent.lineage_hash` is the hash of the initiating root signal's `lineage_hash`.

## 8.4 Ordering Rules

`signal_refs` MUST be ordered by:

```text
PRIMARY: partition_record_seq ASC
TIE BREAK: message_id ASC (lexicographic)
```

Resolution rule (mandatory):

* `partition_record_seq` MUST be resolved via PRD-13 committed `signal_record` lookup using `message_id`
* if ordering cannot be deterministically resolved for all `signal_refs`:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

`affected_entity_keys` MUST be ordered lexicographically.

`correlation.node_refs` and `correlation.edge_refs` MUST follow Section 7 ordering rules.

## 8.6 Verification Gate (CRITICAL)

Before any downstream processing, storage, policy evaluation, or action generation uses a `detection_event`, the following MUST be verified:

* canonicalize the object using RFC 8785 (JCS) ONLY
* recompute all hash-derived fields governed by this PRD (including `detection_id`) from the canonical object bytes
* verify the signature using the PRD-04 signing model and the resolved trust snapshot
* verify `signing_context` equals the exact literal `detection_event_v1`

If any verification step fails:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

## 8.5 Output Boundary Rules

`detection_event` MUST NOT contain:

* `policy_result`
* `safety_result`
* `action_result`
* operator annotations
* mutable runtime hints
* external enrichment payloads

---

# 9. DETERMINISM RULES

## 9.1 Deterministic Equality

For identical:

* ordered `decision_input` stream
* signed `window_rule` set
* signed `feature_profile`
* signed engine and model metadata
* signed `correlation_rule` set

the Decision Orchestrator MUST produce:

```text
bit-for-bit identical detection_event
```

## 9.2 Execution Rule

Each partition MUST execute on a single thread at a time.

Multiple partitions MAY execute in parallel across CPU cores.

Parallel execution MUST NOT change:

* window membership
* feature vector values
* inference request bytes
* correlation graph
* `detection_event`

## 9.3 Numeric Rule

All orchestrator-owned numeric computation MUST use integer or fixed-point arithmetic only.

Floating-point computation in authoritative orchestration logic is FORBIDDEN.

## 9.4 Missing Data Rule

Missing feature evidence MUST resolve to explicit zero values.

Absent correlation edges MUST resolve to an empty ordered list.

Implicit null in authoritative output is FORBIDDEN.

## 9.5 Hidden Dependency Rule

The following MUST NOT affect authoritative output:

* wall clock
* process scheduling
* transport arrival timing
* cache contents
* random seeds
* retry count

```text
FEATURE CACHE ALLOWED ONLY IF:

- keyed by feature_vector_hash
- validated before use
```

## 9.6 PRD-23 Ordering Guarantee (CRITICAL)

All PRD-23 asset intelligence detections and emitted PRD-23 asset intelligence signals MUST execute in deterministic order by the authoritative per-partition sequence:

```text
partition_record_seq ASC
```

Within this orchestrator scope, `partition_record_seq` ordering is represented by the authoritative shard-order stream consumed by the partition worker (Section 4.7.1.1) and MUST NOT depend on wall clock, transport arrival, or scheduler timing.

---

# 10. INFERENCE FAILURE HANDLING

```text id="s2g1fm"
INFERENCE ELIGIBILITY RULE:

Inference execution MUST depend ONLY on:

- availability of required model_snapshot (committed)
- availability of feature_vector (constructed deterministically)
- signed configuration

IF ANY DEPENDENCY MISSING:

→ CLASSIFY AS TYPE 2 FAILURE (STATE INCONSISTENCY)
→ HALT PARTITION

NO TIME / IO / AVAILABILITY BASED CONDITIONS ALLOWED
```

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

🔴 DEPENDENCY INDEX RECOVERY (CRITICAL)
RULE

dependency_index MUST be:

RECONSTRUCTABLE FROM COMMITTED RECORDS
RECOVERY

On startup or corruption:

REBUILD index FROM:

decision_records WHERE state = DEFERRED
VALIDATION
index_hash = SHA256(all_dependency_mappings)

MUST match recomputed value
FAILURE
mismatch → REBUILD → ALERT
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

Priority MUST equal the deterministic priority hash defined by PRD-11 and MUST be compared using lexicographic byte order.

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

## 🔴 PARTITION HALT PROPAGATION (PRD-17)

IF partition_state = HALTED:

dependent partitions MUST:

→ stop accepting new deferred decisions
→ process only resolvable dependencies

---

# 11. STATE MANAGEMENT

## 11.1 Allowed State

The only allowed mutable orchestrator state is:

* partition-local open window state
* partition-local feature construction buffers
* partition-local correlation graph state derived from authoritative inputs
* inference request ledger
* inference result ledger

## 11.2 State Constraints

All decision-relevant state MUST be:

```text
explicit + persisted OR reconstructable + deterministic
```

All mutable runtime state MUST be:

* partition-scoped
* logical-shard-scoped
* derived only from authoritative queue inputs and signed configuration

Shared mutable global graph state is FORBIDDEN.

```text
NO CROSS-PARTITION STATE SHARING

ALL STATE MUST BE:

partition-local
shard-local
replay-reconstructable
```

## 11.3 Recovery Rule

On restart, the Decision Orchestrator MUST:

```text
1. load the last consistent durable state
2. validate integrity of open windows and inference ledgers
3. reconstruct incomplete windows and graph state from authoritative queue inputs
4. reissue incomplete inference requests using the same request_id
5. resume processing without changing deterministic outputs
```

## 🔴 SESSION CONTINUITY BRIDGE (PRD-03) (CRITICAL)

ORCHESTRATOR RULE (PRD-09):

Continuity graph MUST treat:

(previous_session → new_session)

as a continuous causal chain.

## 11.4 State Eviction Rule

Open-window and graph state MAY be evicted from memory ONLY if:

* the state is durably persisted
* OR the state is fully reconstructable from authoritative queue inputs and signed configuration

## 11.5 Forbidden State

The following are FORBIDDEN:

* hidden in-memory decision state
* unsnapshotted counters affecting output
* mutable runtime model tables
* heuristic caches that alter correlation or feature values

---

# 12. PERFORMANCE MODEL

The Decision Orchestrator MUST scale through partition parallelism without weakening determinism.

The following are mandatory:

* throughput MUST scale by increasing independent partitions
* each partition worker MUST remain single-threaded with respect to authoritative partition order
* window construction cost MUST be bounded by signed `max_signal_count`
* feature vector construction cost MUST be O(vector_length + matched_signal_count)
* correlation cost MUST be bounded by signed caps on node count and edge count
* inference invocation overhead inside the orchestrator MUST be O(1) excluding inference-engine execution cost

Signed configuration MUST define at minimum:

* maximum open windows per logical shard
* maximum vector length
* maximum correlation nodes per detection
* maximum correlation edges per detection

Performance optimization MUST NOT change authoritative output.

---

# 13. SECURITY MODEL

## 13.1 Trusted Inputs Only

The Decision Orchestrator MUST trust only:

* PRD-08 validated and durably admitted `signal_event` inputs
* signed `window_rule` configuration
* signed `feature_profile` objects
* signed engine and model metadata
* signed `correlation_rule` objects
* signed asset criticality mapping objects

## 13.2 Verify-Before-Use Rule

Before any orchestration step executes, the system MUST verify:

* configuration signatures
* model metadata integrity
* feature profile compatibility
* correlation rule integrity

Unsigned or mismatched control objects MUST be rejected.

## 13.3 Output Integrity Rule

`detection_event` is valid ONLY if:

* every referenced signal input is authoritative
* `window_id` is valid
* `feature_vector_hash` is valid
* inference output validation succeeds
* `graph_hash` is valid
* `detection_id` is valid

## 13.4 Isolation Rule

The Decision Orchestrator MUST NOT accept:

* direct network input
* external feature values
* unsigned model output
* unsigned correlation rules
* runtime operator overrides of authoritative output

---

# 14. FORBIDDEN PATTERNS

```text
FORBIDDEN:

- Bayesian math implementation inside the orchestrator
- scoring implementation inside the orchestrator
- threshold evaluation inside the orchestrator
- policy selection inside the orchestrator
- policy evaluation inside the orchestrator
- safety evaluation inside the orchestrator
- action generation inside the orchestrator
- execute actions inside the orchestrator
- apply safety inside the orchestrator
- raw-event decision making
- heuristic feature generation
- dynamic feature names at runtime
- probabilistic branching
- floating-point decision logic
- arrival-order-dependent correlation
- global mutable shared decision state
- model mutation at runtime
- modification of inference-engine outputs
- inference fallback logic
- default inference outputs
- partial detection emission
- window eviction heuristics
- graph truncation
- external enrichment as an authoritative input
- wall-clock-dependent window boundaries
```

---

# 15. SUMMARY

```text
Decision Orchestrator is the deterministic sequencing layer.

It MUST:
- consume only validated signals
- build deterministic windows
- construct complete ordered feature vectors
- invoke the signed inference engine without implementing its math
- build causal-only correlation graphs
- emit deterministic detection_event records

If any input, model, rule, or output integrity check fails:
REJECT -> FAIL-CLOSED -> ALERT
```

---
