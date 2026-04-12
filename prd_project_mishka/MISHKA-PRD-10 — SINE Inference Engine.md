# MISHKA-PRD-10 — SINE Inference Engine

**Project:** Project Mishka  
**Classification:** AUTHORITATIVE — FULLY DETERMINISTIC INFERENCE ENGINE  
**Status:** FOUNDATIONAL — FIXED-POINT MODEL EXECUTION, VERIFIABLE OUTPUT, AND REPLAY-IDENTICAL INFERENCE

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

This document defines the authoritative SINE Inference Engine for Project Mishka.

It governs how feature vectors from the Decision Orchestrator are transformed into deterministic inference outputs that are:

* model-bound
* hash-verifiable
* signature-verifiable at the engine boundary
* replay-identical across CPU and GPU execution
* free of nondeterministic behavior

```text
(feature_vector, model) -> deterministic output
```

SINE is the only component authorized to execute inference mathematics for Mishka detection.

---

# 2. CORE PRINCIPLES

```text
SINE is a pure, deterministic, fixed-point inference engine.
```

## 2.1 INFERENCE PURITY LAW (CRITICAL)

```text
INFERENCE PURITY LAW:

ONLY:
- fixed-point math
- deterministic Bayesian tables

FORBIDDEN:
- neural networks
- LLMs
- adaptive learning

MODEL OUTPUT MUST BE:
PURE FUNCTION (input_vector, model_snapshot)
```

The following principles are mandatory:

* inference MUST depend only on the feature vector, the signed model, and signed engine configuration
* the same valid request and the same valid model MUST always produce the same output bit-for-bit
* model bytes MUST be signed, hash-verified, immutable, and versioned
* CPU execution MUST remain authoritative
* GPU execution MAY accelerate but MUST produce identical results
* outputs MUST match the PRD-09 payload schema exactly
* outputs MUST be verifiable by deterministic hashing and engine-bound signature
* no fallback, heuristic, adaptive, or probabilistic runtime behavior is permitted

Micro-hardening (PRD-01 alignment):

* canonical object field lock is mandatory (PRD-01 Section 3.1): unknown fields FORBIDDEN; optional fields MUST be omitted (no null/default)
* array determinism law is mandatory (PRD-01 Section 3.2): every array MUST have an explicit deterministic ordering rule; no implicit ordering
* hash function law is mandatory (PRD-01 Section 3.3): all authoritative hashes in this PRD MUST use `SHA256`

```text
NO FLOATING-POINT NON-DETERMINISM.
NO RUNTIME MODEL MUTATION.
NO FALLBACK INFERENCE.
```

---

# 3. INPUT CONTRACT (FROM PRD-09)

## 3.1 Authoritative Input

SINE MUST accept only the PRD-09 `inference_request` payload:

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

## 3.2 Request Validity Rule

The following MUST be verified before execution:

* `engine_id` matches the active engine identity
* `model_id` matches the active signed model
* `model_version` matches the active signed model version
* `feature_profile_id` matches the model manifest
* `feature_profile_version` matches the model manifest
* `values` length matches the model manifest vector length
* `feature_vector_hash` matches the recomputed hash over the canonical feature vector fields defined by PRD-09

Any mismatch:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

## 3.3 Compatibility Rule

SINE MUST execute a request only if the model manifest explicitly declares compatibility with:

* `engine_id`
* `feature_profile_id`
* `feature_profile_version`
* `output_schema_id`

Incompatible requests are FORBIDDEN.

## 3.4 Input Ordering Rule

`values` MUST be interpreted strictly by ascending feature index order from the signed feature profile.

Sparse, reordered, or partially populated vectors are FORBIDDEN.

---

# 4. MODEL REPRESENTATION (STRICT)

## 4.1 Authoritative Model Type

The only authoritative model type is:

```text
BAYES_FIXED_V1
```

This model type is a deterministic, table-driven, fixed-point Bayesian inference model.

## 4.2 Model Manifest

Every model MUST include a signed manifest containing at minimum:

* `engine_id`
* `model_id`
* `model_version`
* `model_type`
* `model_hash`
* `feature_profile_id`
* `feature_profile_version`
* `vector_length`
* `numeric_system_id`
* `output_schema_id`
* `class_code_set`
* `reason_code_registry_id`
* `normalization_rule_id`

`model_version` MUST be bound to `partition_epoch`.

Inference within one `partition_epoch` MUST use exactly one `model_version`.

Mixed-model execution within one `partition_epoch` is FORBIDDEN.

## 4.3 Canonical Model Bytes

`canonical_model_bytes` MUST be a deterministic binary serialization with:

* fixed section order
* fixed-width integer fields
* unsigned big-endian encoding for non-negative integers
* signed two's-complement big-endian encoding for signed integers
* lexicographically ordered table identifiers
* ascending feature index order inside every feature-indexed table
* ascending class index order inside every class-indexed table

Runtime reserialization differences are FORBIDDEN.

## 4.4 Model Hash and Signature

The following constructions are mandatory:

```text
model_hash = SHA256(canonical_model_bytes)

model_signature = Ed25519(
  "sine_model_v1" ||
  model_hash ||
  engine_id ||
  model_id ||
  model_version
)
```

The model MUST NOT execute unless:

* `model_hash` matches the manifest
* `model_signature` verifies against the signed model-publisher key

## 4.5 Immutable Model Sections

The authoritative model MUST contain only immutable sections:

* class prior table
* feature likelihood tables
* normalization constant table
* score mapping table
* confidence mapping table
* reason-code mapping table

Runtime mutation of any section is FORBIDDEN.

---

# 5. INFERENCE EXECUTION MODEL

## 5.1 Pure Function Law

SINE inference MUST be a pure function:

```text
inference_result = F(feature_vector, canonical_model_bytes)
```

The function MUST NOT depend on:

* wall clock
* request arrival timing
* thread scheduling
* network state
* previous inference outputs
* mutable caches

## 5.2 Mandatory Execution Sequence

The following execution order is mandatory:

```text
1. verify request structure and feature_vector_hash
2. verify model signature and model_hash
3. verify request-to-model compatibility
4. load immutable tables
5. execute fixed-point inference in ascending feature index order
6. apply deterministic normalization
7. map normalized outputs to threat_score_fixed, confidence_fixed, class_code, and reason_codes
8. construct authoritative output payload
9. compute output hashes and identifiers
10. sign the output envelope
```

```text
NO STEP MAY BE SKIPPED, REORDERED, OR BYPASSED.
```

## 5.3 Table Lookup Rule

All table lookup keys MUST be fully specified by:

* feature index
* feature value
* class index
* signed model section identifier

Missing table entries are FORBIDDEN.

## 5.4 Output Mapping Rule

The mapping from internal normalized accumulator state to:

* `threat_score_fixed`
* `confidence_fixed`
* `class_code`
* `reason_codes`

MUST be defined only by signed model sections.

Heuristic mapping is FORBIDDEN.

---

# 6. NUMERIC SYSTEM (CRITICAL)

## 6.1 Authoritative Scale

The authoritative fixed-point scale is:

```text
S = 1_000_000_000_000
```

All probabilities, scores, and confidences MUST use integer values relative to `S`.

## 6.2 Allowed Numeric Domain

The following are the only allowed authoritative numeric forms:

* unsigned fixed-point integers in `[0, S]`
* signed fixed-point integers when explicitly declared by the signed model section
* unsigned counters
* signed intermediate accumulators

Floating-point values are FORBIDDEN everywhere in authoritative inference.

Signed configuration MUST define:

* `max_accumulator_value`
* `max_feature_count`
* `minimum_probability_floor`

## 6.3 Authoritative Arithmetic

The following operations are mandatory:

```text
add_int(a, b) = a + b
sub_int(a, b) = a - b
mul_fp(a, b) = floor((a * b) / S)
div_fp(a, b) = floor((a * S) / b) where b != 0
```

The rounding rule is:

```text
FLOOR ONLY
```

Alternative rounding rules are FORBIDDEN.

## 6.4 Intermediate Precision

All intermediate multiplication and accumulation MUST use signed 128-bit integer precision or a mathematically equivalent deterministic integer framework.

Hardware-specific approximate arithmetic is FORBIDDEN.

The active request feature vector length MUST NOT exceed `max_feature_count`.

If accumulator magnitude exceeds `max_accumulator_value`, the result MUST be:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

Zero-probability collapse is FORBIDDEN.

If linear-domain probability computation is used, the following rule is mandatory:

```text
if probability < minimum_probability_floor:
    probability = minimum_probability_floor
```

Deterministic log-domain computation is permitted as an alternative compliant implementation.

## 6.5 Overflow and Zero-Division Rule

If any of the following occur:

* integer overflow
* integer underflow outside the signed model bounds
* division by zero
* normalization outside declared bounds

the result MUST be:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

Saturation arithmetic is FORBIDDEN.

---

# 7. OUTPUT CONTRACT

## 7.1 Authoritative Output Payload

The authoritative inference result payload MUST match PRD-09 exactly:

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

## 7.2 Output Hash Rule

Define `output_core` as the canonical JSON object containing exactly:

* `request_id`
* `model_id`
* `model_version`
* `output_schema_id`
* `threat_score_fixed`
* `confidence_fixed`
* `class_code`
* `reason_codes`

The following constructions are mandatory:

```text
output_core_bytes = RFC 8785 (JCS)(output_core)
raw_output_hash = SHA256(output_core_bytes)

result_id = SHA256(
  request_id ||
  model_id ||
  model_version ||
  raw_output_hash
)
```

## 7.3 Ordering Rule

`reason_codes` MUST be emitted in the exact order defined by the signed reason-code mapping table.

Runtime score-based reordering is FORBIDDEN.

## 7.4 Signed Output Envelope

Every inference result payload MUST be emitted inside a signed engine envelope:

```json
{
  "protocol_version": "sine_result_envelope_v1",
  "engine_id": "string",
  "model_id": "string",
  "model_version": "string",
  "payload_hash": "hex_32_bytes",
  "signature": "hex_ed25519",
  "payload": {}
}
```

The following constructions are mandatory:

```text
payload_hash = SHA256(RFC 8785 (JCS)(payload))

signature = Ed25519(
  "sine_result_v1" ||
  engine_id ||
  model_id ||
  model_version ||
  payload_hash
)
```

`payload` MUST be byte-identical to the authoritative PRD-09 output payload.

---

# 8. DETERMINISM GUARANTEES

## 8.1 Request Equality Rule

For identical:

* `inference_request`
* `canonical_model_bytes`
* signed engine configuration

SINE MUST produce:

```text
bit-for-bit identical output payload
bit-for-bit identical output envelope
```

## 8.2 Replay Rule

Replay of the same request under the same model version MUST produce identical:

* `threat_score_fixed`
* `confidence_fixed`
* `class_code`
* `reason_codes`
* `raw_output_hash`
* `result_id`
* `signature`

## 8.3 Hidden Dependency Rule

The following MUST NOT affect output:

* thread interleaving
* batch size
* cache state
* hardware identity
* NUMA placement
* process restart count

## 8.4 Purity Rule

Inference execution MUST NOT mutate:

* model tables
* feature vector contents
* output mapping tables

---

# 9. CPU vs GPU EXECUTION MODEL

## 9.1 CPU Authority Rule

CPU execution is the authoritative reference implementation.

CPU MUST remain the source of truth for correctness.

CPU_AUTHORITY_LAW (CRITICAL):

All inference outputs MUST originate from CPU deterministic execution.

GPU is an optional speculative accelerator only. GPU outputs MUST NEVER be treated as authoritative.

## 9.2 Execution Mode Rule

```text
CPU IS AUTHORITATIVE EXECUTION ENGINE
GPU IS OPTIONAL ACCELERATION
```

```text
GPU-ONLY INFERENCE IS FORBIDDEN
```

```text
FOR CRITICAL PATHS:

CPU AND GPU MAY EXECUTE IN PARALLEL

GPU computes candidate_result.

CPU recomputes authoritative_result.

MUST verify:

candidate_result == authoritative_result
```

```text
IF GPU_RESULT != CPU_RESULT:

→ DISCARD GPU
→ USE CPU
→ EMIT DRIFT ALERT
```

FORBIDDEN:

* GPU-only inference
* GPU-trusted output

GPU MAY be used only as an acceleration layer for deterministic inference.

GPU MUST NOT be required for correctness.

```text
GPU_STATE:

START
→ RUNNING
→ COMPLETED
→ VERIFIED
→ ACCEPTED

GPU_RESULT_ACCEPTANCE:

IF GPU_COMPLETED AND CPU_COMPLETED:

→ REQUIRE GPU_RESULT == CPU_RESULT
→ ACCEPT RESULT

IF GPU_NOT_COMPLETED:

→ USE CPU_RESULT

NO TIME-BASED CONDITIONS ALLOWED
```

## 9.2.1 GPU Optional Execution Engine Guarantee (CRITICAL)

GPU is an optional execution engine only.

Mandatory:

```text
CPU_RESULT == GPU_RESULT (BIT-FOR-BIT)
```

If a GPU-enabled deployment cannot prove bit-for-bit equality for the active model/version under the active engine configuration:

```text
GPU EXECUTION FORBIDDEN -> CPU_ONLY REQUIRED
```

## 9.3 GPU Determinism Rule

GPU execution MUST:

* use deterministic kernels only
* use only the authoritative integer numeric framework
* preserve feature index order semantics
* produce bit-for-bit identical output payloads as CPU execution

Floating-point GPU kernels are FORBIDDEN for authoritative inference.

## 🔴 CPU-GPU PARITY VALIDATION (CRITICAL)
RULE

For every model version:

sample_inputs MUST be executed on:

CPU AND GPU
VALIDATION
IF output_cpu != output_gpu:

    GPU execution MUST be DISABLED
HARD LAW
CPU IS AUTHORITATIVE
GPU IS OPTIONAL

## 9.4 Periodic Cross-Validation Rule

System MUST perform periodic deterministic cross-validation between CPU and GPU results.

If mismatch occurs:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

## 9.5 CPU vs GPU Mismatch Rule

Any CPU versus GPU mismatch in:

* `threat_score_fixed`
* `confidence_fixed`
* `class_code`
* `reason_codes`
* `raw_output_hash`
* `result_id`

MUST be treated as a critical integrity failure.

## 9.6 Preload Optimization (DETERMINISTIC) (MANDATORY)

As a performance optimization, the engine MAY preload models asynchronously.

Mandatory:

* preload MUST NOT alter any authoritative output bytes
* preload MUST use deterministic allocation order and deterministic memory layout
* the same model bytes MUST map to the same in-memory table layout across runs for the same engine build
* any preload failure MUST NOT cause fallback inference or altered outputs

If preload state is ambiguous or would change execution behavior:

```text
FAIL-CLOSED -> ALERT
```

---

# 10. FAILURE MODEL

## 10.1 Invalid Request

If the request is:

* structurally invalid
* feature-profile incompatible
* hash mismatched
* vector-length mismatched

the result MUST be:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

## 10.2 Invalid Model

If the model is:

* unsigned
* signature-invalid
* hash-invalid
* incompatible with the request
* runtime-mutated

the result MUST be:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

## 10.3 Engine Unavailability

If the inference engine is unreachable or unavailable:

```text
FAIL-CLOSED -> ALERT
```

Fallback inference is FORBIDDEN.

## 10.4 Timeout

Inference execution MUST complete within:

```text
inference_timeout = signed_config.inference_timeout_ms
```

If timeout occurs:

```text
FAIL-CLOSED -> REJECT -> ALERT
```

## 10.5 Numeric Failure

If overflow, zero-division, invalid normalization, or out-of-range output occurs:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

## 10.6 Partial or Corrupt Output

If the result payload or envelope is:

* missing fields
* schema mismatched
* hash mismatched
* signature invalid

the result MUST be:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

## 10.7 CPU vs GPU Mismatch

CPU versus GPU mismatch MUST be:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

Default outputs, partial outputs, and heuristic substitutes are FORBIDDEN.

---

# 11. PERFORMANCE MODEL

Performance optimization is valid only if output correctness is unchanged.

The following are mandatory:

* model verification MUST be O(model_size) at load time
* per-request compatibility verification MUST be O(vector_length)
* per-request inference execution MUST be O(vector_length)
* table lookups MUST be O(1) per feature index
* output construction and hashing MUST be O(result_size)
* batch execution MAY be used only if every request result remains identical to independent execution

Signed engine configuration MUST define at minimum:

* `inference_timeout_ms`
* maximum concurrent requests
* maximum batch size
* maximum vector length

Performance gains MUST NOT depend on:

* heuristic pruning
* approximate math
* skipped verification
* nondeterministic batching

---

# 12. SECURITY MODEL

## 12.1 Verify-Before-Use Rule

SINE MUST verify before use:

* request integrity
* model signature
* model hash
* engine configuration signature
* output envelope signature before external acceptance

## 12.2 Trust Boundary Rule

The following are untrusted until verified:

* inference requests from the orchestrator
* model bytes from storage
* GPU-produced intermediates
* output envelopes received over IPC or network transport

## 12.3 Key Binding Rule

Every `engine_id` MUST map to exactly one active engine signing key in the active verification scope.

Key rotation is permitted ONLY through signed configuration.

Shared active signing keys across different `engine_id` values are FORBIDDEN.

## 12.4 Model Immutability Rule

The active model MUST be:

* versioned
* signed
* hash-verified
* immutable for the lifetime of the active execution scope

Hot mutation of active model tables is FORBIDDEN.

---

# 13. FORBIDDEN PATTERNS

```text
FORBIDDEN:

- floating-point inference math
- hardware-dependent rounding
- adaptive runtime logic
- probabilistic branching
- model mutation at runtime
- fallback inference
- default inference outputs
- partial output emission
- skipped model verification
- skipped request verification
- unsigned models
- unsigned output envelopes
- heuristic score mapping
- heuristic reason-code ordering
- graph-aware inference side effects
- runtime learning
- CPU/GPU divergent kernels
```

---

# 14. NORMALIZED CONFIDENCE MODEL

The SINE engine MUST output a normalized confidence score for every inference result.

## 14.1 Confidence Score Definition

```text
confidence_score ∈ [0, 100]
```

The score MUST be an integer representing the system's certainty in the detection.

## 14.2 Derivation Rules

The `confidence_score` MUST be derived deterministically from:

1. **Signal Reliability**: Fixed-point weight of the underlying signal quality.
2. **Source Trust**: Cryptographic trust level of the emitting sensor/probe.
3. **Correlation Strength**: Quantitative weight from the Correlation Engine (PRD-09).
4. **History**: Deterministic aggregate of previous similar detections.

## 14.3 Confidence Constraints

* **Integer Only**: All confidence calculations MUST use integer arithmetic. No floating point.
* **Deterministic**: For the same input set and model, the `confidence_score` MUST be bit-for-bit identical.
* **Replay-Bound**: The confidence derivation MUST be fully reproducible during system replay.

---

# 15. SUMMARY

```text
SINE is the only authoritative inference engine.

It MUST:
- consume only PRD-09 feature-vector requests
- execute signed immutable models
- use deterministic fixed-point math only
- emit PRD-09 compliant outputs
- sign and hash outputs for verification
- remain replay-identical across CPU and GPU

If request integrity, model integrity, numeric integrity, or CPU/GPU equality fails:
REJECT -> FAIL-CLOSED -> ALERT
```

---
