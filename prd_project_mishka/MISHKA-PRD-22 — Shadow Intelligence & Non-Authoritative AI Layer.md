# MISHKA-PRD-22 — Shadow Intelligence & Non-Authoritative AI Layer

**Project:** Project Mishka  
**Classification:** NON-AUTHORITATIVE — READ-ONLY INSIGHT GENERATION ISOLATION LAYER  
**Status:** CRITICAL — STRICT ISOLATION, NO AUTHORITY, NO SIDE EFFECTS, FAIL-CLOSED ON ANY BREACH

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

This document defines the **Shadow Intelligence Layer**: a strictly isolated, non-authoritative subsystem that produces **human-readable insight only** from already-committed records.

This PRD exists to eliminate any ambiguity about “AI usage” in a system whose authoritative pipeline is strictly deterministic (PRD-01).

OPAIF NOTE:
`OFF_PLATFORM_AI_INTERFACE (OPAIF)` is a separate concept from Shadow Intelligence:

- NOT part of Mishka authoritative system
- NOT part of Shadow Intelligence
- NOT replay-relevant
- NOT cryptographically bound
- NOT trusted for any decision

Shadow Intelligence MUST NOT participate in any authoritative system behavior.

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
- IF they exist, they MUST exist ONLY in OPAIF (external system)

VALIDATION RULE (CRITICAL):

If any LLM output enters:

- signal_event
- detection_event
- policy_result
- action_object

→ REJECT → FAIL-CLOSED → ALERT
```

---

# 2. HARD BOUNDARY RULE (GLOBAL, NON-NEGOTIABLE)

The following boundary is mandatory and MUST be enforced by architecture, configuration, and runtime access control:

```text
SHADOW_AI_LAYER:
INPUT: WARM/COLD STORAGE ONLY
OUTPUT: HUMAN-READABLE INSIGHT ONLY
NO PIPELINE WRITE ACCESS
NO AUTHORITY
NO SIDE EFFECTS
```

Violation of any boundary rule is:

```text
FAIL-CLOSED -> HALT SHADOW LAYER -> ALERT
```

---

# 3. AUTHORITY & NON-AUTHORITY

## 3.1 Non-Authoritative Definition

Shadow Intelligence is non-authoritative by definition.

The following are mandatory:

* Shadow Intelligence output MUST NOT be treated as evidence, proof, or input to any authoritative decision path.
* Shadow Intelligence output MUST NOT be referenced by any authoritative record as justification for detection, policy, or enforcement.
* Shadow Intelligence output MUST NOT be used to mutate any authoritative state.
* Shadow Intelligence MUST NOT directly write to PRD-13; any persisted output MUST be emitted through the PRD-13 `report_record_v1` contract only.

```text
SHADOW INTELLIGENCE IS NON-AUTHORITATIVE:

- MUST FAIL WITHOUT SYSTEM IMPACT
- MUST NOT EMIT SIGNALS
- MUST NOT BYPASS PRD-13 STORAGE CONTRACTS
- MUST NOT INFLUENCE PIPELINE

OUTPUT = HUMAN ONLY
```

## 3.1.1 AUTHORITATIVE REFERENCE LAW (MANDATORY)

Shadow Intelligence MUST consume authoritative definitions only from:

* PRD-03 for identity and request/message bindings
* PRD-04 for signature, key, and nonce issuance validation
* PRD-13 for storage schema and record contracts
* PRD-15 for replay, drift detection, and validation outcome

PRD-22 MUST reference these authorities and MUST NOT redefine them.

## 3.2 Shadow Intelligence Determinism Rule (MANDATORY)

### 🔴 DETERMINISTIC AI OUTPUT MODEL (CRITICAL)

#### HARD LAW

LLM OUTPUT IS NOT AUTHORITATIVE AT READ TIME  
ANY PERSISTED SHADOW OUTPUT MUST RESOLVE TO ONE COMMITTED `REPORT` OBJECT UNDER PRD-13

#### EXECUTION MODEL

STEP 1: REQUEST HASHING  
request_hash = SHA256(
  canonical_input_records ||
  embedding_model_id ||
  tokenizer_version
)

STEP 2: CACHE LOOKUP  
IF committed `report_record` exists with
`shadow_metadata.request_hash = request_hash`:  
    RETURN stored report artifact bytes

STEP 3: CONTROLLED GENERATION (ONE-TIME ONLY)

- temperature MUST equal 0
- seed MUST be fixed
- model version MUST be pinned

STEP 4: OUTPUT NORMALIZATION

- whitespace canonicalization
- deterministic formatting rules
- max token truncation rule

STEP 5: COMMIT ARTIFACT  
emit deterministic `report` object via PRD-13 `report_record_v1` containing:  
  request_hash  
  model_id  
  model_version  
  output_hash  
  required `shadow_metadata`

direct writes outside PRD-13 report contract are forbidden

STEP 6: ALL FUTURE REQUESTS:  
RETURN STORED OUTPUT ONLY FROM THE COMMITTED `REPORT` PATH

#### FAILURE RULES

If generation produces:

API error  
timeout  
non-reproducible output  
REJECT → DO NOT STORE → RETURN NON-AUTHORITATIVE UNAVAILABLE

Mandatory returned shape:

```json
{
  "status": "UNAVAILABLE",
  "reason_code": "OPAIF_TEMPORARY_FAILURE"
}
```

Hard law:
* timeouts and upstream failures MUST NOT halt the UI or investigation workflows (PRD-21)
* fail-closed halts are reserved for boundary breaches (e.g., any attempted authoritative write-back), not for non-authoritative availability loss

#### FORBIDDEN

real-time LLM calls in user path  
non-cached responses  
temperature > 0  
model auto-updates

#### REPLAY LAW

IDENTICAL INPUT RECORDS → IDENTICAL OUTPUT BYTES (FROM CACHE)

---

### 🔴 VECTOR DETERMINISM LOCK (CRITICAL)

VECTOR_DETERMINISM_LOCK (MANDATORY)

All vectorization MUST be fully deterministic.

The following are REQUIRED:

1. EMBEDDING MODEL PINNING

embedding_model_id MUST include:
- model_name
- exact_version
- checksum

Example:
embedding_model_id = "e5-large-v2@sha256:<hash>"

FORBIDDEN:
- floating model versions
- provider auto-updates

---

2. TOKENIZATION LOCK

tokenizer_version MUST be fixed and included in:

request_hash = SHA256(
  canonical_input_records ||
  embedding_model_id ||
  tokenizer_version
)

---

3. VECTOR INDEX BUILD DETERMINISM

Index MUST be constructed using:

- deterministic insertion order:
  ORDER BY (record_hash ASC)

- deterministic index algorithm parameters:
  (e.g., HNSW M, efConstruction MUST be fixed)

- no background rebalancing
- no async compaction

---

4. TOP-K RETRIEVAL DETERMINISM

Retrieval MUST enforce:

ORDER BY:
  (similarity_score DESC, record_hash ASC)

Tie-breaking MUST use record_hash ONLY.

---

5. INDEX VERSIONING

index_snapshot_id = SHA256(
  ordered_vector_ids ||
  embedding_model_id ||
  index_parameters
)

Shadow queries MUST bind to:

(index_snapshot_id, embedding_model_id)

---

VECTOR_CONTEXT_BINDING (CRITICAL)

All vector operations MUST bind to:

execution_context_hash

---

execution_context_hash MUST include:

- embedding_model_id
- tokenizer_version
- index_snapshot_id

---

CONSTRUCTION:

execution_context_hash = SHA256(
  policy_snapshot_hash ||
  model_snapshot_hash ||
  config_snapshot_hash ||
  embedding_model_id ||
  tokenizer_version ||
  index_snapshot_id
)

---

PRD-13 / PRD-15 PRECEDENCE LAW:

This construction defines the minimum vector-context binding set only.

Any additional `execution_context_hash` inputs already required by PRD-13 or PRD-15 remain mandatory and superseding.

---

REPLAY LAW (PRD-15):

Replay MUST recompute vector retrieval using:

same execution_context_hash

Mismatch:

→ DETERMINISM_VIOLATION
→ FAIL-CLOSED

---

FAILURE:

If any component differs:
→ DO NOT GENERATE
→ FAIL-CLOSED

---

# 3.3 OFF_PLATFORM_AI_INTERFACE (OPAIF) (NON-AUTHORITATIVE, OUTSIDE BOUNDARY)

ALLOW:
Non-deterministic systems ONLY IF:
- They are outside Mishka execution boundary
- They consume exported, already committed data
- They cannot write back into any Mishka pipeline

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

## 🔴 OPAIF_AVAILABILITY_MODEL (MANDATORY) (NON-AUTHORITATIVE AVAILABILITY MODEL) (CRITICAL)
OPAIF MUST NOT propagate failure into:

- UI availability
- investigation workflows
- authoritative pipeline

LLM FAILURE CONDITIONS:

- API error
- timeout
- malformed output
- non-reproducible output

ON FAILURE (MANDATORY):

→ DO NOT STORE  
→ DO NOT RETRY SYNCHRONOUSLY  
→ RETURN:

```json
{
  "status": "UNAVAILABLE",
  "reason_code": "OPAIF_TEMPORARY_FAILURE"
}
```

UI MUST CONTINUE OPERATION.

FORBIDDEN:

- blocking UI on LLM response
- retry loops in user path

---

## OPAIF_BACKGROUND_QUEUE (NON-AUTHORITATIVE)
FAILED requests MUST be retried asynchronously through the deterministic non-authoritative retry state machine:

- outside user request path
- without blocking UI
- without affecting determinism

QUEUE MUST NOT:

- influence authoritative system
- guarantee delivery

Failure and loss of the background queue is permitted and MUST NOT affect:

- authoritative behavior
- replay validation

## 🔴 OPAIF RESPONSE CONTRACT (MANDATORY)

Each async retry MUST produce:

```text
status = PENDING | FAILED | COMPLETED
```

UI MUST receive deterministic state transitions for every async retry.

NO silent success is allowed.

---

## RAG_PIPELINE (NON-AUTHORITATIVE)
RAG exists ONLY as a non-authoritative retrieval and context assembly mechanism over already-committed PRD-13 records.

INPUT:

- input_record_refs

PROCESS (MANDATORY):

1. FETCH records from PRD-13 (verified committed records only)
2. APPLY redaction (PRD-13 read-overlay rules)
3. CHUNK deterministically:

```text
chunk_id = SHA256(record_id || chunk_index)
```

4. VECTORIZE (NON-AUTHORITATIVE)
5. RETRIEVE top-K chunks (deterministic K)
6. CONTEXT LIMIT RULE:

IF tokens > MAX_CONTEXT:

→ apply canonical RAG compaction:

#### 🔴 RAG_CANONICAL_COMPACTION (MANDATORY)

RAG context compaction MUST operate on:

STRUCTURAL JSON UNITS, NOT BYTES

---

RULE:

Input MUST be parsed as RFC8785 canonical JSON

Compaction MUST:

1. truncate at object / field boundary ONLY
2. preserve valid JSON structure
3. never cut inside:
   - string
   - array
   - object

---

METHOD:

Use deterministic field pruning:

ORDER fields by configured priority ASC

Mandatory deterministic inputs:
* `context_budget_bytes` MUST come from the committed configuration snapshot referenced by `config_snapshot_hash`
* field-priority ordering MUST come from the same committed configuration snapshot
* duplicate structural units are forbidden; if duplicates exist, fail closed

REMOVE lowest priority fields UNTIL:

byte_budget satisfied

Compaction result MUST include:

* `included_chunk_refs[]`
* `included_bytes_total`
* `excluded_chunk_count`
* `excluded_chunk_digest`

```text
excluded_chunk_digest = SHA256(
  SHA256(excluded_structural_unit_1) ||
  ... ||
  SHA256(excluded_structural_unit_k)
)
```

```text
compaction_key = SHA256(
  "rag_canonical_compaction_v1" ||
  request_hash ||
  context_budget_bytes
)
```

---

OUTPUT:

Result MUST be valid RFC8785 JSON

---

FORBIDDEN:

- byte-level truncation
- UTF-8 slicing without JSON parsing

---

FAILURE:

invalid JSON:

→ REJECT RAG REQUEST
→ FAIL-CLOSED

---

## 🔴 RAG_FAILURE_HANDLING (MANDATORY) (AI-03)

IF (MANDATORY):

```text
context_incomplete == TRUE
```

RETURN (MANDATORY):

```json
{
  "status": "PARTIAL_CONTEXT",
  "reason_code": "RAG_INCOMPLETE_CONTEXT"
}
```

RULES (MANDATORY):

* MUST NOT trigger LLM generation
* MUST NOT fallback silently
* MUST NOT affect authoritative system

## 🔴 RETRIEVAL INSTRUCTION QUARANTINE (CRITICAL)

ALL retrieved text MUST be treated as DATA ONLY.

MANDATORY:

* retrieved text MUST be rendered as inert tokens
* retrieved text MUST NOT receive execution interpretation
* prompt injection propagation MUST be blocked

MODEL:

```text
retrieved_text → DATA_BLOCK
```

FORBIDDEN:

* merging retrieved text into the system prompt
* executing instructions inside retrieved content

LLM INPUT STRUCTURE:

```text
SYSTEM: fixed
USER: query
DATA: retrieved_text (isolated DATA_BLOCK)
```

VIOLATION:

```text
DISCARD RESPONSE
→ ALERT
```

### 🔴 OPAIF FIXED-WINDOW AVAILABILITY RULE (MANDATORY)
OPAIF MUST preserve fixed-window timing without turning storage/RAG slowness into a UI failure storm.

Mandatory:
* if RAG retrieval/compaction cannot complete within the signed non-authoritative retrieval bound, OPAIF MUST:
  * return at the fixed-window boundary
  * return `PARTIAL_CONTEXT` with a deterministic `reason_code`
  * include `compaction_key` if computable
  * include `request_hash` always
* OPAIF MUST enqueue a background retry outside the user path when retry criteria are met and MUST NOT block the UI

Additional reason codes (closed set extension):
* `RAG_INCOMPLETE_CONTEXT`
* `RAG_TIMEOUT`

---

## 🔴 PROMPT_TEMPLATE_MODEL (MANDATORY)
Every prompt MUST be:

- versioned
- signed (PRD-04)
- stored in PRD-13

Prompt identity (mandatory):

```text
prompt_id = SHA256(template_bytes)
```

FORBIDDEN:

- runtime prompt mutation
- user-controlled system prompts

---

# 4. INPUT CONTRACT (READ-ONLY, STORAGE-ONLY)

Shadow Intelligence MUST be READ-ONLY and MUST consume ONLY the following committed record families:

* `investigation_record` (PRD-13)
* `query_result_record` (PRD-13)
* `report_record` (PRD-13)

The following are mandatory:

* inputs MUST be read only from **WARM/COLD** storage tiers (PRD-13 tier model)
* inputs MUST be verified (hash/chain/commit-boundary verification) before use (PRD-13 / PRD-15)
* inputs MUST be treated as immutable committed bytes
* missing required input records MUST fail closed

Shadow Intelligence MUST NOT consume:

* raw ingest bytes
* durable queue state
* uncommitted records
* derived caches as a source of truth

## 🔴 SHADOW INPUT BOUNDARY LAW (CRITICAL)
RULE

Shadow Intelligence input MUST be:

EXPLICITLY BOUNDED AND HASH-DEFINED
INPUT CONTRACT
shadow_request = {
  request_hash,
  input_record_refs[],
  input_scope_hash
}
INPUT SCOPE HASH
input_scope_hash = SHA256(
  ordered(input_record_refs)
)
HARD LIMITS
max_input_records MUST be defined in signed config
max_total_bytes MUST be defined
ordering MUST be deterministic
FORBIDDEN
implicit DB queries
unbounded joins
“latest state” queries
external enrichment
REPLAY LAW
IDENTICAL input_record_refs → IDENTICAL input_scope_hash → IDENTICAL output

## 4.1 HARD ISOLATION (CRITICAL)

```text
HARD ISOLATION:

INPUT:
- investigation_record
- query_result_record
- report_record

SOURCE:
- WARM / COLD STORAGE ONLY

OUTPUT:
- HUMAN READABLE ONLY

FORBIDDEN:
- API write access
- pipeline hooks
- action triggers
- feedback loops

ANY BREACH:
→ FAIL-CLOSED
```

---

# 5. OUTPUT CONTRACT (HUMAN-READABLE ONLY)

Shadow Intelligence output MUST be:

* human-readable
* explicitly labeled non-authoritative
* derived only from verified committed inputs
* side-effect free

Shadow Intelligence MUST NOT emit:

* `signal_event`
* `detection_event`
* `action_decision`
* `safety_evaluation`
* `action_object`
* any authoritative pipeline record type

Shadow Intelligence MUST NOT directly write to:

* ingest pipeline
* detection pipeline
* policy pipeline
* enforcement pipeline
* authoritative storage record families outside the PRD-13 `REPORT` contract

---

# 6. STRICT ISOLATION REQUIREMENTS

The following isolation requirements are mandatory:

* **Network isolation**: Shadow Intelligence MUST NOT have network egress to external services as part of insight generation.
* **Data-plane isolation**: Shadow Intelligence MUST NOT have credentials capable of writing to authoritative stores, queues, or control planes.
* **API isolation**: Shadow Intelligence MUST expose no API endpoints that can mutate authoritative state.
* **Capability isolation**: Any attempt to request an authoritative action from Shadow Intelligence MUST be rejected.

If any isolation boundary is ambiguous or cannot be proven at runtime:

```text
FAIL-CLOSED -> DISABLE SHADOW LAYER -> ALERT
```

---

# 7. DETERMINISM & REPLAY COMPATIBILITY

Shadow Intelligence MUST be replay-compatible as a pure read-only transformation over committed inputs.

Mandatory rule:

```text
IDENTICAL VERIFIED INPUT RECORD SET -> IDENTICAL INSIGHT OUTPUT BYTES
```

If Shadow Intelligence output is persisted, it MUST be persisted only as a PRD-13 `REPORT` record and replayed only through PRD-15 report reconstruction rules.

Cache entries, transient artifacts, and derived indexes MUST remain disposable and MUST NOT become a second storage authority.

---

## 🔴 SHADOW_STORAGE_CONTRACT (CRITICAL)

Shadow Intelligence outputs MUST be emitted as:

```text
record_type = REPORT
record_version = report_record_v1
```

Mandatory storage contract:

* the emitted object MUST conform to PRD-13 `report_record_v1`
* the emitted object MUST retain the mandatory PRD-13 `query_result_hash` causal parent; any additional shadow inputs MUST be carried in `input_record_refs[]`
* the canonical report payload MUST include:
  * `input_record_refs[]`
  * `model_id`
  * `model_version`
  * `output_hash`
  * `shadow_metadata`
* `shadow_metadata` MUST equal:

```json
{
  "source": "OPAIF",
  "non_authoritative": true,
  "request_hash": "hex_32_bytes",
  "execution_context_hash": "hex_32_bytes"
}
```

* report artifact bytes MUST hash to `output_hash`
* PRD-22 MUST NOT directly write to PRD-13 tables; persistence MUST occur only through the authoritative PRD-13 report contract

Replay law:

* shadow report output MUST be reconstructable from the committed PRD-13 dataset
* PRD-15 MUST validate `shadow_metadata.request_hash`, `shadow_metadata.execution_context_hash`, and `output_hash`

FORBIDDEN:

* new storage schemas (for example `shadow_insight_v1`)
* direct writes bypassing PRD-13 contracts
* cache-only sources of truth
* any storage path that makes PRD-13 `REPORT` records optional

# 8. FAILURE MODEL (FAIL-CLOSED)

Shadow Intelligence MUST fail closed on:

* missing committed input record
* failed storage verification
* ambiguous input scope selection
* nondeterministic output
* any attempt to write to authoritative systems
* any attempt to influence detection, policy, or enforcement

Failure result is:

```text
FAIL-CLOSED -> ALERT
```

---

# 9. FORBIDDEN PATTERNS

```text
FORBIDDEN:

- reading HOT tier as a source of truth
- reading uncommitted records
- consuming raw ingest bytes
- producing or writing signal_event/detection/policy/enforcement outputs
- writing to authoritative storage
- triggering enforcement actions
- hidden state caches that change outputs
- nondeterministic or probabilistic insight generation
- any side effects
```

---

# 10. SUMMARY

```text
PRD-22 defines the Shadow Intelligence Layer:

- READ-ONLY
- WARM/COLD STORAGE INPUTS ONLY
- HUMAN-READABLE OUTPUT ONLY
- NO PIPELINE WRITE ACCESS
- NO AUTHORITY
- NO SIDE EFFECTS
- DETERMINISTIC AND REPLAY-SAFE
```
