# RansomEye Master Skill (Unified System Intelligence)

## 1. System Invariants (Non-Negotiable)

* **Fail-closed everywhere** — any violation → terminate component
* **Zero event loss** — persist or backpressure, never drop 
* **Deterministic execution** — identical input → identical output across system
* **TLS 1.3 only**, strict mTLS identity binding 
* **No unsigned execution** — verify-before-parse mandatory 
* **No floating point in AI inference** — fixed-point only (S = 10¹²) 

---

## 2. Cryptographic Trust Model

### Root of Trust

* **ONLY**: Ed25519 signed configuration 
* No environment, DNS, or external CA trust allowed

### Signing Law (Global)

```
signing_input = signing_context || SHA256(canonical_payload_bytes)
signature     = Ed25519(signing_input)
```

* Raw payload signing → forbidden
* Hash-only trust → forbidden
* Multiple signing paths → forbidden

### Canonical JSON

* Lexicographically sorted keys
* No whitespace
* UTF-8 strict
* Deterministic serialization only

Violation → reject before ingestion

---

## 3. Identity Model (Strict Binding)

### Mandatory Identity Fields

Every event MUST include:

* `agent_id` or `probe_id`
* `boot_session_id`
* `system_identity_hash`
* `message_id`

Missing → **reject at ingest boundary** 

---

### mTLS Binding (Non-bypassable)

Agent identity MUST be bound via:

1. **SAN URI**

```
urn:ransomeye:agent:<uuid-v4>
```

OR

2. **Certificate fingerprint (SHA-256 DER)**

Mismatch → **fail-closed connection** 

---

### Session Integrity

* `boot_session_id` = per-process UUID
* Bound to TLS session (anti-replay)
* Session change → new ID

---

## 4. Core Engine (Authoritative Control Plane)

### Absolute Responsibilities

* Only component allowed to:

  * Write PostgreSQL
  * Maintain WORM ledger
  * Enforce ordering and no-loss



---

### Ingest Pipeline (Mandatory Order)

1. Canonical JSON validation
2. Identity validation
3. `signing_context` validation
4. Signature verification
5. Replay check
6. Queue admission

Any failure → reject

---

### Queue Semantics

* Logically **unbounded queue**
* Disk-backed spill mandatory
* No enqueue failure after admission

Allowed outcomes:

* Durable persistence
* Backpressure

Forbidden:

* Drop
* Overwrite
* Silent discard

---

### Backpressure Model

Full propagation required:

```
Core → Agent → Kernel → Source
```

Mechanisms:

* gRPC RESOURCE_EXHAUSTED
* Blocking ingestion
* Kernel throttling

---

## 5. Zero-Loss Pipeline

### Core Guarantees

* Core defines durability boundary
* Agents are NOT trusted for no-loss



---

### Endpoint Buffer

* Append-only
* Hash-chained
* Tamper-evident

---

### Replay Rules

* Ordered by `logical_clock`
* Deduped by `message_id`
* Signature verified before accept

---

### Forbidden Concepts

* `event_drop_count`
* Any metric implying allowed loss

---

## 6. WORM & Forensics (Legal-Grade)

### Seal Pipeline (Exact Order)

1. Canonical JSON
2. SHA-256 hash
3. AES-256-GCM encryption
4. Ed25519 signature



---

### Storage Rules

* Append-only
* Immutable (no UPDATE/DELETE)
* Merkle tree (RFC 6962)

---

### Atomicity

* DB row + Merkle append = single transaction

---

### Identity Binding (Mandatory in payload)

* `system_identity_hash`
* `agent_id` / `probe_id`
* `boot_session_id`
* `message_id`

---

### Daily Root

* Signed with Ed25519
* Includes `previous_root_hash`
* Immutable once finalized

---

## 7. Deterministic AI Engine

### Core Constraints

* Fixed-point arithmetic ONLY
* Scale: **S = 10¹²**
* No floats anywhere



---

### Signal Model

| Signal    | Type    |
| --------- | ------- |
| Process   | integer |
| File      | integer |
| Network   | integer |
| User      | integer |
| Deception | binary  |

---

### Inference Rules

* Bayesian fusion (integer math)
* Sigmoid via precomputed lookup table
* LOO explainability only

---

### Model Integrity

* Ed25519 signed `model_config`
* Sigmoid hash included in identity
* Mismatch → fail-closed

---

## 8. Policy Enforcement (Deterministic)

### AEC-3 (Critical)

Mandatory containment set:

* `BLOCK_EXEC`
* `KILL_PROCESS`
* `ISOLATE_HOST`



---

### Modes

| Mode   | Behavior                   |
| ------ | -------------------------- |
| HUMAN  | Default, approval required |
| HYBRID | Auto + notify              |
| AUTO   | Full automation            |

---

### Pre-Execution Enforcement

* Must occur **before syscall success**
* No DB dependency in decision path
* Kernel-level enforcement required

Latency constraint:

```
< 50 ms (signal → block)
```

---

## 9. Linux Agent (Kernel Enforcement)

### Capabilities

* eBPF hooks:

  * execve
  * openat
  * rename
  * unlink



---

### Enforcement Rules

* Pre-execution deny (5.8+ with BPF_LSM)
* No post-facto-only kill model

---

### Modes

| Kernel  | Mode        |
| ------- | ----------- |
| ≥ 5.8   | Full        |
| 5.4–5.7 | Limited     |
| < 5.4   | Unsupported |

---

### Autonomous Blocking

* No Core round-trip
* Deterministic from:

  * signed policy
  * signals
  * identity

---

## 10. SINE Engine (Non-Trust AI)

### Role

* Narrative generation ONLY
* Never affects detection or enforcement



---

### Constraints

* Deterministic outputs
* Fixed generation parameters
* No randomness

---

### Input Boundary

Allowed:

* Final detection outputs

Forbidden:

* Raw telemetry
* Intermediate signals
* Feature vectors

---

### Output

* Canonical JSON
* Includes:

  * `model_hash`
  * `prompt_hash`
  * `system_identity_hash`

---

## 11. Resource Failsafe System

### States

```
NORMAL → PRESSURE → FAILSAFE → RECOVERY
```



---

### Disk Exhaustion Behavior

1. Apply backpressure
2. Attempt recovery
3. Fail-closed if unresolved

---

### Forbidden

* Dropping events under pressure
* Continuing without durable path

---

## 12. Air-Gapped Update System

### Trust Model

* Ed25519 only
* Manifest-signed bundles



---

### Verification

* Verify-before-activate
* Hash + signature check
* No partial load

---

### Identity Binding

* Must match `system_identity_hash`

---

## 13. Database Guarantees

### Canonical Storage

* JSON stored as TEXT only
* JSONB = projection only



---

### Digest Enforcement

```
sha256(canonical_json) == stored_hash
```

Mismatch → reject

---

### WORM Tables

* INSERT only
* Immutable triggers mandatory

---

## 14. System Identity

### `system_identity_hash`

Derived from:

* Config
* PKI
* Model config
* Trust anchors

Any change → new identity

Mismatch anywhere → fail-closed

---

## 15. Absolute Prohibitions

* Event dropping (any form)
* Float math in AI
* Unsigned config/model/bundles
* Multiple trust roots
* Runtime schema mutation
* CN-based identity
* Prompt injection into SINE
* Partial ingestion success

---

## 16. Execution Philosophy

* Deterministic > probabilistic
* Cryptographic truth > inferred truth
* Backpressure > data loss
* Fail-closed > degraded operation
* Identity-bound > implicit trust

---

## Result

This single document now:

* Encodes **all system invariants**
* Eliminates cross-PRD ambiguity
* Is **Cursor-ingestable** for architectural alignment
* Prevents drift across AI, Core, Agent, and WORM layers

---

