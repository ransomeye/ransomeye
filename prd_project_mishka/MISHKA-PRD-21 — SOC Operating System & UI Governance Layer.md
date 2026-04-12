# MISHKA-PRD-21 — SOC Operating System & UI Governance Layer

**Project:** Project Mishka  
**Classification:** AUTHORITATIVE — SOC OPERATING SYSTEM & UI GOVERNANCE  
**Status:** CRITICAL — DETERMINISTIC INVESTIGATION, UI CONTROL, AND SOC WORKFLOW ENFORCEMENT

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

This document defines the authoritative SOC Operating System and UI Governance Layer for Project Mishka.

It governs:
* Investigation and Case Management
* Dashboards and Reporting interfaces
* Behavioral Baseline and Anomaly Scoring integration
* Action Chains
* Risk Engine logic
* Global Search
* Policy Simulation
* Compute Optimization for UI
* UI Governance Law

If any feature, UI capability, or operational workflow contradicts this document, it is invalid.

## PRD-21 OWNERSHIP (MANDATORY)

PRD-21 OWNS:

- UI interaction layer only
- intent capture

PRD-21 MUST NOT define execution rules.

If any statement in this PRD is interpreted as defining execution behavior, enforcement behavior, or rollback authority:
→ it is invalid
→ authority resides in PRD-20 and PRD-12
→ FAIL-CLOSED

Micro-hardening (PRD-01 alignment):

* canonical object field lock is mandatory (PRD-01 Section 3.1): unknown fields FORBIDDEN; optional fields MUST be omitted (no null/default)
* array determinism law is mandatory (PRD-01 Section 3.2): every array MUST have an explicit deterministic ordering rule; no implicit ordering
* hash function law is mandatory (PRD-01 Section 3.3): all authoritative hashes in this PRD MUST use `SHA256`

---

## 1.1 OFF_PLATFORM_AI_INTERFACE (OPAIF) — AI Assistant Panel (NON-AUTHORITATIVE)

ADD:
“AI Assistant Panel” backed by OPAIF

RULES:
- clearly labeled NON-AUTHORITATIVE
- cannot trigger actions
- cannot auto-fill policy
- cannot influence enforcement

OPAIF_ACCESS:
INPUT:
  - derived_redacted_view (copy only)

OUTPUT:
  - human-readable advisory ONLY

FORBIDDEN:
  - pipeline write-back
  - signal emission
  - decision influence
  - policy mutation

VIOLATION:
→ IGNORE OUTPUT
→ ALERT

OPAIF_DATA_VIEW (CRITICAL):

OPAIF MUST NOT read raw `canonical_payload_text` or `canonical_payload_bytes` directly.

DATA_MINIMIZATION_LAW (MANDATORY):

Non-authoritative systems MUST receive:

* minimum required fields only
* pre-redacted deterministic projections

FAILURE:

If OPAIF accesses raw canonical payload:

```text
FAIL-CLOSED
→ ALERT
```

SIDE_CHANNEL_RESISTANCE_LAW (CRITICAL):

Non-authoritative interfaces MUST NOT leak:

* timing
* frequency
* volume

OPAIF_TIMING_NORMALIZATION (CRITICAL):

OPAIF responses MUST be:

* batched
* delayed to fixed intervals
* size-normalized

FIXED_RESPONSE_WINDOW (MANDATORY):

```text
FIXED_RESPONSE_WINDOW = 5 seconds
```

Rule:

* all OPAIF outputs MUST be released only at the fixed window boundary

SIZE NORMALIZATION (MANDATORY):

* responses MUST pad to deterministic size buckets
* variable-length leakage is FORBIDDEN

QUERY RATE LIMIT (MANDATORY):

* OPAIF queries MUST be rate-limited
* OPAIF query limits MUST be tenant-scoped

FAILURE:

If timing variance is detected:

```text
DISABLE OPAIF
→ ALERT
```

---

## OPAIF_UI_ASYNC_MODEL (MANDATORY)
NO synchronous dependency on OPAIF is allowed.

UI MUST:

- render immediate placeholder: `AI processing...`
- poll OPAIF at deterministic lease-controlled `FIXED_RESPONSE_WINDOW` intervals
- display last known cached output if exists

FORBIDDEN:

- blocking UI rendering on LLM response
- retry loops in user path

---

## 🔴 OPAIF FAILURE STATE MODEL (CRITICAL)

OPAIF_STATUS:

AVAILABLE
UNAVAILABLE
DEGRADED

---

RULE:

If `opaif_unavailable_failure_threshold` consecutive failures:

→ status = UNAVAILABLE

`opaif_unavailable_failure_threshold` MUST be loaded from the signed configuration snapshot referenced by `config_snapshot_hash`

UI MUST:

- STOP polling
- display deterministic fallback:
  "AI UNAVAILABLE"

---

RECOVERY:

Only on explicit success:

UNAVAILABLE → AVAILABLE

## 🔴 OPAIF RECOVERY OBSERVABILITY LAW (CRITICAL)

UI MUST observe recovery deterministically.

MANDATORY MECHANISM:

* deterministic lease-based polling only

LEASE MODEL:

```text
ui_session_lease_id
lease_expiry_seq
```

RULES:

* `ui_session_lease_id` MUST be issued by the UI backend from committed session state
* `lease_expiry_seq` MUST equal `current_ui_seq + opaif_ui_lease_windows`
* `opaif_ui_lease_windows` MUST come from the signed configuration snapshot referenced by `config_snapshot_hash`
* UI stops polling ONLY after `lease_expiry_seq`
* recovery MUST emit an explicit `RESUME` signal before UI returns to `AVAILABLE`

FORBIDDEN:

* silent background recovery
* hidden retries without observable state

## OPAIF_PREDICTIVE_CACHE (MANDATORY CONTRACT)

If the UI cache exists, it MUST cache responses using:

request_hash

---

RULE:

cache MUST NOT influence authoritative decisions

---

FORBIDDEN:

- infinite retry loop
- blocking UI thread

# 2. INVESTIGATION SYSTEM

The investigation system MUST capture and replay analyst workflows deterministically.

## 2.1 Investigation Identity
Every investigation state MUST be cryptographically bound.
```text
investigation_id = SHA256(RFC8785(investigation_state))
```

## 2.2 Investigation Record
The system MUST persist an `INVESTIGATION_RECORD` (PRD-13) for every saved or shared state.
The record MUST persist:
* **investigation_id**: The deterministic identifier.
* **entity_set**: The list of entities currently being analyzed.
* **filters**: All active UI filters and window bounds.
* **state_hash**: The hash of the complete UI state.

## 2.2.1 REDACTED_REFERENCE_PLACEHOLDER RENDERING (CRITICAL)

If a referenced record is redacted:

→ UI MUST render placeholder node
→ UI MUST NOT hide graph edge
→ UI MUST indicate redaction explicitly

FORBIDDEN:

* silent removal of references
* null substitution

---

## 🔴 REDACTION-AWARE HASH RESOLUTION (CRITICAL)
RULE

UI MUST NEVER USE REDACTED DATA FOR HASH OPERATIONS

MODEL
UI VIEW:
  redacted_payload

HASH OPERATIONS:
  MUST use canonical_payload_text (unredacted, backend-only)
API CONTRACT

Backend MUST expose:

hash_reference_token

Which maps to:

canonical_payload_hash (unredacted)
RESULT
UI usability preserved
Replay integrity preserved

## 2.3 UI Action Recording
* **ALL UI interactions** (filters applied, nodes expanded, queries executed, notes added) MUST generate a `UI_ACTION_RECORD` as defined in PRD-20 and PRD-13.
* **No Hidden Analyst State**: The UI MUST NOT maintain local state that is unrecorded or not bound to an investigation.

### 2.3.1 UI_ACTION_INTENT (LOCAL PRE-COMMIT BUFFER) (CRITICAL)

To prevent UI control-action loss on browser crash or offline interruption, the UI MUST create a local pre-commit record:

```text
UI_ACTION_INTENT (LOCAL BUFFER)
```

Mandatory:

* the intent MUST contain the full canonical UI action payload fields required to produce the final `UI_ACTION_RECORD`
* the intent MUST be stored in a crash-recoverable local buffer before the UI considers the action “submitted”
* the buffer MUST be deterministic and MUST NOT rewrite payload fields

### 2.3.1.1 UI Idempotency Key (MANDATORY)

The idempotency key for UI control actions is:

```text
idempotency_key = SHA256(UI_ACTION_INTENT)
```

The following law is mandatory:

```text
SAME INTENT HASH → SAME RESULT → NO SIDE EFFECTS
```

### 2.3.2 Two-Phase Commit (MANDATORY)

The UI governance commit MUST be two-phase:

1. UI creates and persists `UI_ACTION_INTENT` locally (pre-commit)
2. Backend finalizes the authoritative record by computing the final hash and signature and persisting the committed `UI_ACTION_RECORD` (PRD-20 / PRD-13)

Mandatory:

* backend finalization MUST compute hashes and signatures deterministically from RFC 8785 canonical bytes
* the finalized committed record MUST be the single authoritative `UI_ACTION_RECORD`
* the UI MUST treat backend finalization failure as a failed control action (fail-closed)

BACKEND COMMIT IS AUTHORITATIVE (CRITICAL):

Backend commit of the authoritative `UI_ACTION_RECORD` is authoritative.

UI MUST NOT guess commit state.

### 2.3.3 Recovery Rule (MANDATORY)

If the UI crashes or restarts:

* `UI_ACTION_INTENT` entries MUST be recoverable from the local buffer
* re-hash of the intent payload MUST produce an identical result (bit-for-bit) as the original attempted submission
* UI MUST enter:

```text
state = UNKNOWN_COMMIT_STATE
```

until backend confirms authoritative commit state

On reconnect:

→ query by idempotency_key
→ fetch authoritative state

The UI MUST either:

* deterministically resubmit the same intent for backend finalization, OR
* fetch the committed authoritative `UI_ACTION_RECORD` by idempotency_key and render it as committed

If intent recovery is ambiguous:

```text
FAIL-CLOSED -> ALERT
```

### 2.3.4 UI Retry Idempotency Law (CRITICAL)

```text
CLIENT MUST RETRY USING THE SAME IDEMPOTENCY_KEY UNTIL TERMINAL AUTHORITATIVE RESPONSE OR EXPLICIT FAIL-CLOSED RESPONSE

SYSTEM MUST:
- remain idempotent
- never duplicate execution
```

## 2.4 Replayability
* The investigation state MUST be completely replayable from authoritative storage.
* Reloading the investigation from the stored `UI_ACTION_RECORD` sequence MUST produce the exact same bit-for-bit investigation view.

---

# 3. CASE MANAGEMENT

Case management governs the lifecycle of structured incidents.

## 3.1 Case Identity
```text
case_id = SHA256(RFC8785(full_canonical_object))
```

## 3.2 Lifecycle Rules
* **Append-Only**: Case lifecycle MUST be a series of append-only records. In-place status updates are FORBIDDEN.
```text
ordering_ref = partition_record_seq
```

---

# 4. DASHBOARDS & CACHING

Dashboards are visual projections of deterministic data retrieval.

## 4.1 Dashboard Backing
* ALL dashboards MUST be backed strictly by the canonical `query_object`.
* Dashboards MUST NOT execute custom retrieval logic bypassing the query engine.

## 4.2 Query Cache Model
* **No Execution Influence**: Caching MUST NOT affect the execution logic or the bit-for-bit accuracy of query results.
* **Storage Restriction**: If the cache stores records, it MUST store `query_result_record` objects ONLY. Caching of unverified, intermediate, or non-record data is FORBIDDEN.

## 4.3 No Cached Authority
* NO cached authority is permitted. All dashboard caches MUST be verifiable projections of committed storage.

## 4.4 Result Mapping
* ALL dashboard results MUST map explicitly to a `query_result_record` (PRD-13).

## 4.5 Shadow Intelligence UI Separation (PRD-22) (CRITICAL)

The UI MUST clearly separate:

* **Authoritative System Output**
* **AI Insight (Non-Authoritative)**

Mandatory:

* Authoritative views MUST be backed only by committed authoritative records and verified query results (PRD-13 / PRD-15).
* AI Insight views (PRD-22) MUST be explicitly labeled non-authoritative and MUST NOT be presented as evidence, proof, or system decision.
* AI Insight MUST NOT be allowed to trigger any control action, policy change, or enforcement workflow directly.

If the UI cannot maintain this separation unambiguously:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

---

# 5. BEHAVIORAL BASELINE ENGINE

The Behavioral Baseline Engine establishes normal entity activity bounds.

## 5.1 Baseline Storage
* The behavioral baseline MUST be stored as a **MODEL snapshot** (PRD-04, PRD-13).

## 5.2 Versioning
* The baseline MUST be explicitly versioned via cryptographic hash.

## 5.3 Execution Context Binding
* The active baseline MUST be included in the `execution_context_hash` (PRD-15). Replay validation MUST use the exact historical baseline snapshot present during the original execution.

---

# 6. ANOMALY SCORING

Anomaly scores quantify deviation from the Behavioral Baseline.

## 6.1 Deterministic Output
* `anomaly_score` MUST be deterministic. Given the same signal sequence and the same baseline model snapshot, the engine MUST produce the identical `anomaly_score`.

## 6.2 No Runtime Randomness
* The anomaly calculation MUST NOT depend on runtime randomness, heuristic drift, or unversioned ML algorithms.

---

# 7. ACTION CHAINS

Action chains represent multi-step SOC remediation or response workflows.

## 7.1 Record Mapping
* Each step in an action chain MUST map to a separate, distinct `ACTION_RECORD`.

## 7.2 Rollback Support
* The action chain MUST support rollback. Each step MUST define a `reverse_action` as required by PRD-20.

## 7.3 Lineage Linkage
* Every step in the action chain MUST be lineage-linked via `lineage_hash` (PRD-13), ensuring causal provenance back to the initiating detection or prior action step.

## 7.4 CLEAR_ROLLBACK_LOCK (BRICKED ENTITY ESCAPE HATCH) (CRITICAL)

If an entity is locked due to rollback failure escalation (PRD-12 `ESCALATED_CRITICAL`), the UI MUST expose an explicit controlled override workflow.

The only permitted override action is:

```text
CLEAR_ROLLBACK_LOCK
```

Mandatory UI requirements:

* MFA approval is REQUIRED
* the UI action MUST be signed
* explicit justification text is REQUIRED
* the UI MUST require the operator to select exactly one scoped `entity_id`
* the UI MUST require the operator to select the specific `linked_execution_id` being overridden
* the UI MUST show the full authoritative chain and the exact escalation evidence references

Mandatory storage requirements:

* the override MUST produce a committed `rollback_override_record` (PRD-13)
* the UI MUST NOT present the override as automatic recovery
* the UI MUST force deterministic policy re-evaluation before any new actions may proceed

Override safety rule (mandatory):

```text
OVERRIDE MUST NOT:
- skip audit
- skip replay
- skip policy
```

---

# 8. RISK ENGINE

The Risk Engine calculates risk priority for assets and entities.

## 8.1 Snapshot Binding
* `risk_score` MUST be snapshot-bound. It is derived from a signed configuration snapshot of risk weights and rules.

## 8.2 Hashable Inputs
* All inputs to the risk calculation MUST be explicit, hashable, and recorded.

## 8.3 Replay Verifiability
* `risk_score` evaluation MUST be replay-verifiable.

---

# 9. GLOBAL SEARCH

Search across the SOC OS MUST follow strict retrieval laws.

## 9.1 Query Object Usage
* Global search MUST use the canonical `query_object`.

## 9.2 Search-Result Mapping
* Every `search_result` MUST map explicitly to a `query_result_record`.
* **No UI-Only Search**: Providing search output that is not backed by a stored `query_result_record` is FORBIDDEN.

## 9.3 Deterministic Ordering
* Search results MUST produce a deterministic ordering. Ties MUST be broken by deterministic identifiers (e.g., `partition_record_seq`).

## 9.4 No Ranking Randomness
* Global search MUST NOT use non-deterministic ranking algorithms or probabilistic relevance scoring.

---

# 10. POLICY SIMULATION

The Policy Simulation engine allows dry-run impact evaluation.

## 10.1 Snapshot Inputs Only
* Simulation MUST use explicit snapshot inputs only (committed event datasets, specific policy snapshots, and model snapshots).

## 10.2 Replay Verifiability
* Simulation execution MUST be fully replay-verifiable and bit-for-bit identical to the results a real execution would produce under the same snapshots.

---

# 11. UI vs API GOVERNANCE (CRITICAL)

The UI and API MUST share identical control logic.

## 11.1 Control Plane Authority
* The UI is the primary human control plane for the system.

## 11.2 Identical Record Law
* The API MUST generate records (UI_ACTION_RECORD, ACTION_RECORD, etc.) that are identical in structure and verifiability to those generated by the UI.

## 11.3 No Governance Bypass
* The API MUST NOT bypass the UI governance law. All API-driven state changes MUST satisfy the same audit, control, and replay requirements as UI-driven actions.

---

# 12. COMPUTE OPTIMIZATION

UI and query performance optimizations MUST NOT break deterministic laws.

## 12.1 Caching
* All result caching MUST be keyed by `query_hash`.
* Cache invalidation MUST be deterministic.

## 12.2 Batching
* Batching of UI requests or queries MUST NOT alter the final outputs or `query_result_record` hashes.

## 12.3 Pre-Aggregation
* UI pre-aggregation MUST exist as derived projections only. Projections MUST be rebuildable from authoritative storage.

---

# 13. UI GOVERNANCE LAW (CRITICAL)

The UI is the sole human control plane for the system.

NO feature, workflow, or capability may exist without:
1. **UI Control**: Explicit governance exposed via the user interface.
2. **Audit Record**: Every state transition generating a verifiable append-only record.
3. **Replay Capability**: Complete bit-for-bit reproducible state from stored records.

If any feature bypasses these rules, it is a critical vulnerability.
```text
REJECT -> FAIL-CLOSED -> ALERT
```

---

# 14. SUMMARY

Project Mishka's SOC Operating System is deterministic, fully verifiable, and exclusively UI-governed.

If any UI state is unrecorded, any output is not stored as a record, any cache influences a result, any simulation is not replayable, any investigation is not reconstructable, or any action chain is not lineage-bound:
```text
FAIL-CLOSED -> ALERT
```

---

# 15. ASSET INVENTORY, COVERAGE & DISCOVERY UI (PRD-23)

This section defines the SOC UI and control-plane governance required to support PRD-23 Asset Intelligence.

The UI MUST enable:

* expected asset inventory creation (control-plane authority)
* grouping and hierarchy (up to 6 levels)
* coverage visualization (EXPECTED vs OBSERVED vs MANAGED vs UNKNOWN)
* controlled action workflows (investigation, profiling, onboarding)

No feature in this section may bypass:

* PRD-20 UI-only control authority
* PRD-13 append-only record law
* PRD-15 replay correctness

## 15.1 Entity Registry UI (EXPECTED ASSETS)

The UI MUST provide an **Entity Registry** workflow that allows operators to create and manage expected assets.

Mandatory capabilities:

* create expected assets (PRD-23 `asset_entity_key`)
* assign the expected asset to a group hierarchy
* define and browse the group hierarchy up to 6 levels

Authority rules:

* every registry mutation MUST be represented as an append-only authoritative record
* in-place edits are FORBIDDEN
* registry versioning MUST occur only by new committed records

## 15.2 Grouping & Hierarchy (Up to 6 Levels)

Grouping MUST use committed `GROUP` records (PRD-13).

Mandatory rules:

* the UI MUST allow assets to be assigned to a group path of depth \(0..6\)
* group membership changes MUST be represented as append-only UI actions and resulting authoritative records
* the UI MUST NOT maintain hidden group membership state

If a group reference is missing, ambiguous, or not committed:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

## 15.3 Coverage Dashboard

The UI MUST provide a Coverage Dashboard backed strictly by canonical `query_object` execution (PRD-13).

The dashboard MUST show counts and drill-down views for:

* expected
* observed
* managed
* unknown

Mapping rule:

* every dashboard view MUST map to a stored `query_result_record`

The dashboard MUST compute coverage views using authoritative committed records only, including:

* PRD-23 `ASSET_COVERAGE` records (PRD-13)
* PRD-23 `ASSET_OBSERVATION` records (PRD-13)
* PRD-23 `ENTITY_REGISTRY` records (PRD-13)

Derived-only dashboards are forbidden.

## 15.4 Alert Panel (Asset Intelligence)

The UI MUST provide an alert panel containing deterministic alerts backed by canonical queries.

The alert panel MUST include:

* **new device detected**: derived from PRD-09 `detection_type = NEW_ASSET_DETECTED`
* **unmanaged asset**: derived from PRD-09 `detection_type = UNMANAGED_ASSET` and/or `risk.unmanaged_asset.v1` signals
* **missing expected asset**: derived from PRD-09 `detection_type = MISSING_EXPECTED_ASSET`

Alert ordering MUST be deterministic and MUST use only deterministic identifiers (e.g., `partition_record_seq` tie-breaks) as required by PRD-13/PRD-21.

No probabilistic ranking is permitted.

## 15.5 Actions (UI Workflows)

The UI MUST support the following operator actions for asset intelligence:

* **ignore**
* **assign group**
* **trigger investigation**
* **deploy agent**

All actions MUST be governed by PRD-20 control semantics and MUST be fully replayable.

### 15.5.1 Ignore

Ignore is a UI-governed suppression intent only.

Mandatory rules:

* ignore MUST NOT delete or mutate authoritative evidence
* ignore MUST be represented only as new append-only records
* ignore MUST NOT change upstream PRD-23 coverage computation; it MUST change UI presentation only

### 15.5.2 Assign Group

Assigning a group MUST:

* reference the target `asset_entity_key`
* reference the target `group_id`
* produce an append-only authoritative record chain that is replayable

### 15.5.3 Trigger Investigation

Triggering investigation MUST produce an enforcement action request that results in a PRD-12 action execution:

* `INVESTIGATE_ASSET`
* optionally `PROBE_ASSET_PROFILE`

The UI MUST:

* show the exact target `asset_entity_key`
* show the exact evidence references that justify the request (ordered `message_id` set)
* require human approval when policy mode requires it

### 15.5.4 Deploy Agent

Deploy Agent MUST be a controlled onboarding workflow.

Mandatory rules:

* the UI MUST emit a UI-governed signed request record for onboarding
* onboarding MUST NOT be performed by hidden backend toggles
* any resulting deployment/enrollment steps MUST be represented by committed authoritative records and/or committed action execution records

Implementation details of endpoint enrollment and agent deployment are owned by the authoritative Edge/Deployment PRDs. This section defines the UI governance and record requirements only.

## 15.6 UI Action Record Requirements (CRITICAL)

ALL UI actions in Sections 15.1 through 15.5 MUST:

* generate a `UI_ACTION_RECORD` (PRD-20 / PRD-13)
* be signed
* be stored append-only
* be replayable to reconstruct the identical UI state and asset inventory view

If any UI action would mutate state without generating a `UI_ACTION_RECORD`:

```text
REJECT -> FAIL-CLOSED -> ALERT
```
