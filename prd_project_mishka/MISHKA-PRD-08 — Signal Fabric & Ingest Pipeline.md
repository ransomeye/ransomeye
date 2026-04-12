# MISHKA-PRD-08 — Signal Fabric & Ingest Pipeline

**Project:** Project Mishka  
**Classification:** AUTHORITATIVE — HIGH-THROUGHPUT, VERIFY-FIRST INGEST SYSTEM  
**Status:** FOUNDATIONAL — TRUST GATEWAY, VALIDATION FIREWALL, AND PARTITION HANDOFF

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

This document defines the authoritative Signal Fabric and ingest pipeline for Project Mishka.

It governs how `signal_event` bytes are received, validated, protected against adversarial input, durably admitted, and handed off to partitioned execution.

This document exists to ensure the ingest system:

* accepts only valid signals
* rejects malformed or adversarial input before admission
* scales horizontally without shared ingest-node state
* preserves deterministic replay and partition-routing guarantees
* applies backpressure instead of silent loss

```text
NO SIGNAL MAY ENTER THE SYSTEM BEFORE VALIDATION.
NO BYTES MAY BECOME TRUSTED BY TRANSPORT OR ORIGIN ALONE.
```

---

# 2. CORE PRINCIPLES

```text
Signal Fabric is a deterministic, verify-before-admit, fail-closed ingress firewall.
```

The following principles are mandatory:

* all pre-validation input MUST be treated as untrusted bytes
* ingest MUST accept only PRD-03 and PRD-07 compliant `signal_event` messages
* validation order MUST exactly match PRD-02
* batch signature verification MUST be the default verification mode
* batch hashing MUST be supported
* overload MUST result in explicit backpressure, never silent drop
* ingest nodes MUST be stateless with respect to authoritative replay and queue state
* partition routing MUST occur only after validation and durable queue admission
* ingest MUST NOT perform inference, enrichment, correlation, or policy evaluation

```text
INGEST_BUFFER_LAYER (MANDATORY):

A bounded, disk-backed pre-commit buffer MUST exist BEFORE PRD-13 commit.

PROPERTIES:

- append-only
- not authoritative
- bounded by size + time
- spill-to-disk enabled

PURPOSE:
ABSORB STORAGE LATENCY SPIKES WITHOUT TCP RESET CASCADE
```

Micro-hardening (PRD-01 alignment):

* canonical object field lock is mandatory (PRD-01 Section 3.1): unknown fields FORBIDDEN; optional fields MUST be omitted (no null/default)
* array determinism law is mandatory (PRD-01 Section 3.2): every array MUST have an explicit deterministic ordering rule; no implicit ordering
* hash function law is mandatory (PRD-01 Section 3.3): all authoritative hashes in this PRD MUST use `SHA256`

```text
UNTRUSTED BYTES -> VALIDATE -> REPLAY GATE -> DURABLE QUEUE -> PARTITION HANDOFF
```

---

# 3. TRUST BOUNDARY

## 3.1 Zero-Trust Input Rule

Everything received from TCP, UDP, API, relay, or federation transport is:

```text
UNTRUSTED BYTES
```

The following inputs are untrusted and MUST NOT grant admission authority:

* source IP
* source port
* hostname
* API client identity
* mTLS identity
* transport path
* listener identity
* arrival order

## 3.2 Trusted Admission Boundary

A signal becomes trusted for core admission ONLY after all of the following succeed:

* canonical validation
* identity validation
* `signing_context` validation
* SHA256 recomputation of authoritative hash-derived fields
* Ed25519 signature verification
* replay-guard acceptance
* durable queue admission

Before these conditions are satisfied, the bytes MUST NOT be treated as:

* a valid signal
* a valid identity
* a valid replay claim
* a valid partition-routable event

## 3.3 Transport Authentication Rule

Transport authentication MAY restrict listener access.

Transport authentication MUST NOT replace:

* canonical validation
* identity validation
* signature verification
* replay protection

---

## TRUSTED_HANDOFF_FLAG (MANDATORY)
IF PRD-16 signed handoff present:

→ skip duplicate transport validation

BUT MUST STILL VERIFY:

- canonicalization
- signature
- identity

---

# 4. INGEST INTERFACES (TCP/UDP/API)

## 4.1 Common Interface Rules

Every ingest interface MUST satisfy all of the following:

* exactly one transport unit MUST contain exactly one complete `signal_event`
* authoritative input bytes MUST remain unchanged across the interface boundary
* interface framing MUST be deterministic and fully specified
* oversize units MUST be rejected before admission
* partial units MUST NOT be admitted
* multi-message units MUST be rejected

The authoritative maximum serialized `signal_event` size is the PRD-07 limit.

## 4.2 TCP Interface

TCP ingest MUST use deterministic length-delimited framing:

```text
frame = uint32_be(length) || signal_event_bytes
```

The following are mandatory:

* `length` MUST be greater than zero
* `length` MUST NOT exceed the signed maximum frame size
CONNECTION TERMINATION RULES:

- MAX_BYTES_PER_CONNECTION
- MAX_FRAMES_PER_CONNECTION
- MAX_INVALID_FRAMES

IF LIMIT EXCEEDED:
→ TYPE 1 FAILURE (REJECT)
* one frame MUST map to one validation attempt
* success acknowledgment MUST occur only after durable queue admission

If any connection termination limit is exceeded:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

The connection MUST be closed deterministically after rejection.

## 4.3 UDP Interface

UDP ingest MUST use exactly one datagram per `signal_event`.

The following are mandatory:

* one datagram MUST contain exactly one complete message
* truncated or malformed datagrams MUST be rejected
* datagrams exceeding the signed maximum datagram size MUST be rejected
* UDP ingest MUST be enabled ONLY when a deterministic rejection-response channel exists
* overload and validation failures MUST be returned over the registered response channel using exact rejection codes

If deterministic response signaling cannot be guaranteed, UDP ingest is FORBIDDEN.

If the deterministic response channel becomes unavailable at runtime:

```text
UDP ingest MUST be disabled
OR
the listener MUST fail-closed
```

```text
IF RESPONSE CHANNEL FAILS:

→ FORCE SWITCH TO TCP MODE
→ UDP INGEST DISABLED
```

## 4.4 API Interface

API ingest MUST accept exactly one `signal_event` per request body.

The following are mandatory:

* request body bytes MUST be the authoritative message bytes
* `Content-Length` MUST be present and exact
* request bodies exceeding the signed maximum body size MUST be rejected
* success response MUST occur only after durable queue admission
* failure response MUST contain the deterministic rejection code

## 4.5 Interface Equivalence Rule

For identical authoritative input bytes, TCP, UDP, and API ingestion MUST produce identical validation, replay, and routing outcomes.

Transport type MUST NOT alter:

* canonical bytes
* `payload_hash`
* `message_id`
* replay outcome
* partition routing outcome

---

# 5. CONNECTION MANAGEMENT

## 5.1 Deterministic Listener Configuration

All listener behavior MUST derive from signed configuration.

Signed listener configuration MUST define at minimum:

* listener identifier
* transport type
* maximum frame or body size
* MAX_BYTES_PER_CONNECTION
* minimum data rate
* maximum concurrent connections
* maximum concurrent connections per verified identity
* maximum provisional connections per source tuple

## 5.2 Provisional vs Verified Scope

Before identity validation succeeds, connection control MUST apply only to the provisional source tuple:

```text
(listener_id, transport, remote_address, remote_port)
```

After identity validation succeeds, identity-scoped connection limits MUST apply to:

```text
(system_id, identity_version, emitter_type, emitter_id)
```

Unverified identities MUST NOT consume verified-identity connection quotas.

## 5.3 Slow-Client Protection

Ingest MUST enforce only:

* MAX_BYTES_PER_CONNECTION
* MAX_FRAMES_PER_CONNECTION
* MAX_INVALID_FRAMES

Slow clients MUST be disconnected before admission.

## 5.4 Stateless Ingest Node Rule

Ingest nodes MUST maintain only:

* ephemeral transport state
* ephemeral batch formation state
* ephemeral metrics state

Ingest nodes MUST NOT maintain authoritative shared mutable state for:

* replay decisions
* queue admission state
* partition ownership
* ordering state

No shared in-memory state is permitted between ingest nodes.

## 5.5 TLS HANDSHAKE EXHAUSTION PROTECTION (CRITICAL)

For any ingest interface that uses TLS termination, the system MUST implement a deterministic pre-TLS admission gate to prevent handshake exhaustion.

### 5.5.1 Pre-TLS Gate (MANDATORY)

Before performing any expensive cryptographic work for a new TLS connection, the listener MUST apply at least one of the following deterministic admission controls:

```text
PROOF_OF_WORK_CHALLENGE (DETERMINISTIC)
OR
TOKEN BUCKET ADMISSION
```

Mandatory:

* the control MUST execute before expensive cryptographic operations
* the control MUST be deterministic for the same source tuple and the same signed configuration
* if admission control inputs are missing or ambiguous: FAIL-CLOSED (drop/deny)

### 5.5.2 Handshake Budget (MANDATORY)

The listener MUST enforce:

```text
MAX_TLS_HANDSHAKES_PER_SECOND GLOBAL
GLOBAL HARD CAP
```

Definitions:

* **GLOBAL** MUST be enforced per `listener_id` under signed configuration.
* the budget window MUST be fixed and configuration-derived
* the token bucket / counter state MUST be bounded

All thresholds MUST derive from signed configuration.

### 🔴 PRE-TLS IDENTITY PROTECTION (CRITICAL)
RULE

Pre-TLS attribution MUST be treated as attacker-controlled.

Hard laws:
* pre-TLS admission MUST NOT enforce blocking decisions keyed by `source_ip` intended to protect a specific legitimate identity (spoofable)
* pre-TLS admission MUST NOT enforce per-source quotas that can be weaponized via source spoofing

Allowed additional protection (pre-TLS):
* SYN-cookie / SYNPROXY style stateless validation
* bounded global accept queue limits
* bounded global token bucket admission for handshake work per listener

HARD LAW
UNVERIFIED CONNECTIONS MUST NOT EXHAUST VERIFIED IDENTITY BUDGET

---

## 🔴 PRE_TLS_ADMISSION_RULE (REPLACEMENT)
FORBIDDEN:

- parsing payload bytes before TLS termination
- deriving entropy from raw packet payload

## PRE_TLS_ADMISSION_PARTITIONING (MANDATORY)

Global token bucket as sole admission control is FORBIDDEN.

System MUST implement:

HIERARCHICAL TOKEN BUCKETS:

1. global_bucket (coarse upper bound)
2. per-partition_bucket (keyed by partition_key = emitter_id hash prefix)
3. per-connection_bucket

---

RULE:

Admission MUST require ALL:

global_bucket > 0
AND partition_bucket > 0
AND connection_bucket > 0

---

FAIRNESS LAW:

No single partition may consume more than the committed `per_partition_global_capacity_ratio` of global capacity.

`per_partition_global_capacity_ratio` MUST be loaded from the signed configuration snapshot referenced by `config_snapshot_hash`.

---

ATTACK RESISTANCE:

Unknown sources MUST be mapped to:

"unverified_partition"

WITH strict rate cap.

---

FAILURE MODE:

If global exhaustion occurs:

→ reserve capacity for:

SIGNED KNOWN AGENTS ONLY

---

TOKEN_BUCKET_STATE_MODEL (MANDATORY)

Token bucket state MUST be fully deterministic and replay-reconstructable.

---

STATE DEFINITION:

bucket_state = {
  partition_id,
  tokens_available,
  last_refill_seq
}

---

SOURCE OF TRUTH:

Token consumption MUST be derived ONLY from:

PRD-13 committed signal_records

---

REFILL MODEL:

tokens_available MUST be computed as:

function(
  last_refill_seq,
  current_partition_record_seq,
  fixed_refill_rate
)

---

FORBIDDEN:

- wall-clock time
- real-time timers
- in-memory-only counters

---

REPLAY LAW:

Replay MUST recompute bucket_state from:

partition_record_seq progression

---

TOKEN_BUCKET_ORDERING_RULE (MANDATORY)

Token consumption MUST follow deterministic ordering.

---

ORDER:

signals MUST be processed in:

(partition_id, logical_shard_id, partition_record_seq)

---

CROSS-PARTITION RULE:

Global bucket updates MUST be applied in:

partition_id ASC order

---

FORBIDDEN:

parallel unordered token consumption

---

REPLAY LAW:

Replay MUST apply token consumption in identical sequence

---

FAILURE:

If bucket state cannot be reconstructed:

→ FAIL-CLOSED

---

PRE_TLS_AUTHENTICATION_ESCAPE (CRITICAL)

System MUST allow:

PRIORITY AUTHENTICATION CHANNEL

---

METHOD:

Agents MUST include:

cryptographic pre-auth token

---

TOKEN:

pre_auth_token = SIGN(
  agent_id ||
  boot_session_id ||
  nonce ||
  message_type = "PRE_TLS_AUTH" ||
  validity_window ||
  execution_context_hash
)

---

ADMISSION:

If pre_auth_token valid:

→ bypass global token bucket
→ allocate reserved capacity

---

RESERVATION:

`authenticated_agent_reserved_capacity_ratio` of capacity MUST be reserved for authenticated agents

`authenticated_agent_reserved_capacity_ratio` MUST be loaded from the signed configuration snapshot referenced by `config_snapshot_hash`

---

FORBIDDEN:

blocking signed agents due to unverified traffic

---

PRE_AUTH_TOKEN_CANONICALIZATION (MANDATORY)

pre_auth_token input MUST be canonicalized:

RFC8785

---

INPUT:

(agent_id, boot_session_id, nonce, message_type, validity_window, execution_context_hash)

---

SIGNATURE:

MUST be deterministic

PRE_TLS_TOKEN_HARDENING (MANDATORY)

* `nonce` MUST be issued by ingest authority under PRD-04
* `nonce` MUST be single-use
* `message_type` MUST equal `PRE_TLS_AUTH`
* `pre_auth_token`, `pre_auth_nonce`, `pre_auth_message_type`, `pre_auth_validity_window`, and `pre_auth_execution_context_hash` MUST be stored in PRD-13 `replay_guard`
* replay MUST validate the exact stored token binding under PRD-15

---

FAILURE:

non-canonical token:

→ REJECT
→ FAIL-CLOSED

---

FORBIDDEN:

single shared global pool without partitioning

ALLOWED PRE-TLS SIGNALS:

- source IP
- SYN rate
- connection rate
- TCP metadata only

### 🔴 PRE-TLS ANTI-SPOOFING RULE (CRITICAL)
The above "allowed pre-TLS signals" are permitted ONLY for coarse-grained global protection and observability.

Mandatory:
* pre-TLS logic MUST NOT convert spoofable attributes (including `source IP`) into per-identity denial decisions
* any per-identity or per-agent rate limiting MUST occur only AFTER:
  * TLS handshake success AND
  * PRD-03 identity verification AND
  * the PRD-08 validation pipeline begins on framed messages

POST-TLS ONLY (MANDATORY):

```text
tls_fingerprint = SHA256(peer_cert || negotiated_params)
```

`connection_entropy_hash` MUST be derived ONLY AFTER:

- TLS handshake success
- identity verification

### 5.5.3 Early Drop Rule (MANDATORY)

Connections MUST be dropped BEFORE expensive cryptographic work if any of the following are true under signed thresholds:

* no payload intent can be established (no valid framing progress toward a complete unit)
* connection termination limit exceeded
* repeated opens from the same provisional source tuple exceed the signed window

Early drop MUST be deterministic:

* no randomized delay
* no probabilistic scoring
* no best-effort exceptions

---

## 🔴 KERNEL_OFFLOAD_INGEST_ACCELERATION (OPTIONAL) (PRD-24 ALIGNED)
To reduce user-space CPU exhaustion under SYN floods and high handshake rates, the ingest gateway MAY implement kernel-level acceleration using eBPF/XDP and AF_XDP.

Hard laws:
* this optimization MUST NOT create new admission authority
* this optimization MUST NOT change validation order (Section 6.1)
* this optimization MUST NOT parse `signal_event` payload bytes before TLS termination (Section 5.5 / PRE_TLS_ADMISSION_RULE)
* acceptance MUST still depend on PRD-08 validation + durable queue admission

Allowed kernel-level functions (pre-TLS):
* deterministic SYN-cookie / SYNPROXY enforcement
* bounded global accept-queue shaping per `listener_id` under signed configuration
* coarse-grained drop of clearly invalid TCP handshake patterns as defined by signed thresholds

Allowed kernel-level functions (post-TLS, post-framing):
* zero-copy delivery of framed message bytes into user-space via AF_XDP/zero-copy buffers
* optional zero-copy staging of verified canonical bytes into a batch-verification pipeline (CPU SIMD or GPU), provided:
  - the same canonical bytes are verified
  - per-message pass/fail outcomes are identical to the non-offloaded pipeline
  - fallback to user-space processing is deterministic and preserves outcomes

## INGEST_FAST_PATH:

AF_XDP → zero-copy → batch hash pipeline

MUST preserve:

- byte order
- packet boundaries
- deterministic batching

## GPU_DMA_INGEST_PIPELINE (OPTIONAL)

AF_XDP buffers MAY be DMA-mapped directly to GPU memory.

REQUIREMENTS:

- byte order preservation
- deterministic batching size
- no reordering

## GPU_BUFFER_REUSE (OPTIONAL)

Same DMA buffer MAY be reused for:

- inference
- hashing

---

RULE:

payload MUST remain immutable

# 6. VALIDATION PIPELINE (STRICT ORDER)

## 6.1 Exact Validation Order

Validation order MUST match PRD-02 exactly:

```text
1. Canonical validation
2. Identity validation
3. signing_context validation
4. SHA256 computation
5. Ed25519 signature verification
6. Replay check
```

```text
NO STEP MAY BE SKIPPED, REORDERED, OR BYPASSED.
```

Transport framing checks MAY occur before Step 1, but they MUST NOT create trusted state.

## 🔴 END-TO-END CHECKSUM CHAIN (CRITICAL)
RULE

Every stage MUST include:

transport_checksum
storage_checksum
processing_checksum
VALIDATION
IF checksum mismatch at ANY stage:

    REJECT → FAIL-CLOSED → ALERT
PURPOSE
detect corruption BEFORE canonical hashing

## 6.2 Step 1 - Canonical Validation

Canonical validation MUST verify:

* RFC 8785 (JCS) compliance as defined by PRD-03
* Canonicalization MUST use RFC 8785 (JCS) canonical JSON ONLY.
* No alternative, equivalent, or custom canonicalization is permitted.
* complete envelope presence
* complete payload presence
* schema-valid required fields
* `boot_session_id` presence
* `logical_clock` presence
* `schema_version` presence
* `boot_session_id` structural validity
* `logical_clock` type validity as `UINT64`
* `schema_version` membership in the active signed `signal_schema_version_set` (PRD-07 / PRD-13)
* canonical JSON compliance
* field-type validity
* size-bound validity

```text
MAX_JSON_DEPTH = CONFIGURED_LIMIT

IF EXCEEDED:
→ REJECT → FAIL-CLOSED
```

Malformed bytes MUST be rejected with:

```text
INVALID_CANONICAL
```

Missing `boot_session_id`, missing `logical_clock`, or missing `schema_version` MUST be rejected fail-closed before any later validation step.

`schema_version` not present in the active signed `signal_schema_version_set` MUST set decision state `REJECT_SCHEMA_MISMATCH` and MUST be rejected fail-closed.

## 6.3 Step 2 - Identity Validation

Identity validation MUST verify:

* `system_id`
* `identity_version`
* `emitter_type`
* `emitter_id`
* identity-to-key binding
* namespace-record validity

Identity validation failure MUST be rejected with:

```text
INVALID_IDENTITY
```

## 6.4 Step 3 - signing_context Validation

`signing_context` MUST be drawn from the signed allowed set for the declared message class.

Context mismatch MUST be rejected with:

```text
INVALID_SIGNING_CONTEXT
```

## 6.5 Step 4 - SHA256 Computation

The system MUST recompute all required SHA256-derived fields from canonical bytes and validated identity inputs.

The following recomputations are mandatory:

* `payload_hash`
* `partition_context`
* `message_id`

Mandatory construction:

```text
payload_hash = SHA256(canonical_payload_bytes)

logical_clock_bytes = UINT64_BE(logical_clock)

partition_context = TRUNC128(
  SHA256(
    canonical_payload_bytes ||
    identity_bytes
  )
)

message_id = SHA256(RFC8785(full_canonical_object))
```

Mandatory rule:

```text
partition_context MUST NEVER depend on payload_hash or any derived hash (including SHA256(canonical_payload_bytes)).
partition_context MUST be computed directly from canonical_payload_bytes || identity_bytes.
```

Any mismatch against transmitted values MUST be rejected with:

```text
HASH_MISMATCH
```

`message_id` mismatch after recomputation MUST be rejected fail-closed.

## 6.6 Step 5 - Ed25519 Signature Verification

Signature verification MUST use the authoritative construction defined in PRD-03 and carried by PRD-07.

Mandatory construction:

```text
logical_clock_bytes = UINT64_BE(logical_clock)

signing_input =
  signing_context ||
  payload_hash ||
  identity_bytes ||
  partition_context ||
  boot_session_id ||
  logical_clock_bytes
```

The ingest system MUST also verify `expiry_logical_clock` from the trust snapshot.
If `logical_clock > expiry_logical_clock`, the signature is EXPIRED.

Invalid or expired signature MUST be rejected with:

```text
AUTH_FAILURE
```

Invalid or expired signature MUST set decision state `REJECT_SIGNATURE_INVALID`.

## 6.7 Step 6 - Replay Check

Replay check MUST execute only after successful signature verification.

Replay / ingest decision state MUST be one of:

* `ACCEPTED_FIRST`
* `REJECT_DUPLICATE`
* `REJECT_REGRESSION`
* `REJECT_GAP`
* `REJECT_SIGNATURE_INVALID`
* `REJECT_SCHEMA_MISMATCH`

Any other replay or ingest decision state is invalid.

`REJECT_DUPLICATE`, `REJECT_REGRESSION`, `REJECT_GAP`, `REJECT_SIGNATURE_INVALID`, and `REJECT_SCHEMA_MISMATCH` MUST be rejected fail-closed.

## 6.8 Validation Failure Rule

At any validation failure:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

No failed validation result may enter:

* replay-accepted state
* durable queue state
* partition routing state

---

# 7. BATCH PROCESSING MODEL

## 7.1 Batch-First Rule

Batch signature verification MUST be the default mode.

Batch hashing MUST be supported.

Single-message verification is permitted ONLY when:

* the batch size is one
* deterministic failed-member isolation requires fallback

## 7.2 Deterministic Batch Formation

Each listener worker MUST assign an ephemeral `receive_seq` in framing-completion order.

Batch formation MUST depend only on:

* listener identifier
* `receive_seq`
* signed `batch_max_items`
* signed `batch_max_bytes`

Random batch formation is FORBIDDEN.

```text
BATCH FORMATION MUST BE:

- size-bounded
- time-independent
- deterministic based on input sequence
```

## 7.3 Batch Hashing

Batch hashing MUST process candidate messages in ascending `receive_seq`.

Batch hashing MUST NOT change:

* canonical bytes
* computed `payload_hash`
* computed `partition_context`
* computed `message_id`

## 7.4 Batch Signature Verification

Batch Ed25519 verification MUST produce identical per-message pass or fail outcomes as single-message verification.

If a batch verification fails, failed-member isolation MUST be deterministic.

The required isolation order is:

```text
lower receive_seq subset first -> higher receive_seq subset second
```

Batch failure isolation MUST enforce:

* a maximum recursion depth
* fallback to single-message verification beyond the signed recursion threshold
* a per-batch CPU cost cap

## 7.5 Batch Equivalence Law

Batch processing MUST NOT change:

* acceptance versus rejection outcome
* rejection code
* replay decision
* queue admission decision
* partition routing result

Batching is a performance optimization only.

Correctness MUST NOT depend on batch size.

For an identical ordered input stream, the ingest system MUST produce identical:

* acceptance and rejection decisions
* stored outputs
* replay outcomes

---

# 8. REPLAY PROTECTION

## 8.1 Replay Guard Routing

Replay guards MUST be partition-local and MUST NOT require global serialization.

Authoritative routing rule:

```text
replay_guard_partition =
  UINT32_BE(SHA256(message_id)[0:4]) mod replay_guard_partition_count
```

Hotspot mitigation MUST support deterministic multi-bucket or deterministic secondary-shard distribution within the authoritative replay-guard partition.

The PRD-03 deterministic secondary shard key MAY be used as one compliant implementation.

## 8.2 Replay Decision Rule

Replay guard state MUST be keyed by:

```text
ReplayGuardKey = (emitter_id, boot_session_id)
```

## 🔴 EXACT REPLAY ADMISSION LAW (CRITICAL)

Replay admission MUST be EXACT and AUTHORITATIVE.

MANDATORY:

* replay admission MUST depend ONLY on:
  * committed PRD-13 `replay_guard`
  * exact `message_id` match
  * exact `(emitter_id, boot_session_id, logical_clock)` ordering
* in-memory cache MAY exist ONLY as a read-through mirror of committed PRD-13 `replay_guard`
* cache MUST NOT be authoritative
* cache miss MUST query authoritative storage before admission
* replay guard state for each `ReplayGuardKey` MUST be reconstructed from committed PRD-13 `replay_guard` only

FORBIDDEN:

* probabilistic structures
* Count-Min sketch
* Bloom filters
* bounded LRU caches for admission decisions
* Kafka topic state as authoritative replay truth
* unbounded maps

FAILURE:

```text
INTEGRITY VIOLATION
→ FAIL-CLOSED
→ ALERT
```

For `emitter_type = agent`, `emitter_id = agent_id`.

For `emitter_type = probe`, `emitter_id = probe_id`.

Replay guard state for each `ReplayGuardKey` MUST contain:

* `last_seen_logical_clock`
* `last_message_id`

The following outcomes are mandatory:

* first message for `ReplayGuardKey` with `logical_clock = 0` -> `ACCEPTED_FIRST`
* first message for `ReplayGuardKey` with `logical_clock != 0` -> `REJECT_GAP`
* next message for the same `ReplayGuardKey` with `logical_clock = last_seen_logical_clock + 1` -> `ACCEPTED_FIRST`
* `logical_clock < last_seen_logical_clock` -> `REJECT_REGRESSION`
* `logical_clock = last_seen_logical_clock` -> `REJECT_DUPLICATE`
* `logical_clock > last_seen_logical_clock + 1` -> `REJECT_GAP`

No global coordinator is permitted.

## 8.3 Queue-Coupled Replay Claim

Replay protection MUST be coupled to durable queue admission so that queue failure cannot create false duplicates.

Replay claim state MUST be durably coupled to committed PRD-13 `replay_guard` for `ReplayGuardKey`, `logical_clock`, and `message_id`.

The authoritative model is the durable replay-claim state machine with deterministic recovery backed by committed PRD-13 `replay_guard`.

## 8.4 Replay Claim State Machine

The state-machine model is mandatory. `seen_state` MUST be one of:

```text
PENDING_QUEUE_COMMIT
ADMITTED
```

The following sequence is mandatory:

```text
1. create durable replay claim with seen_state = PENDING_QUEUE_COMMIT for the candidate ReplayGuardKey, `logical_clock`, and `message_id`
2. append to durable queue
3. durably update ReplayGuardKey state: last_seen_logical_clock = logical_clock and last_message_id = message_id, then transition claim to ADMITTED
4. return success only after Step 3 succeeds
```

On restart, unresolved `PENDING_QUEUE_COMMIT` claims MUST be reconciled deterministically:

* if the queue append exists -> transition to `ADMITTED` and restore `last_seen_logical_clock` and `last_message_id` consistently
* if the queue append does not exist -> delete or release the pending claim without advancing ordering state and allow retransmission

## 8.5 Replay Availability Rule

If replay guard capacity is exhausted but integrity remains intact:

```text
return RESOURCE_EXHAUSTED
```

If replay guard integrity is broken:

```text
FAIL-CLOSED -> ALERT
```

---

# 9. BACKPRESSURE HANDLING

## 9.1 Ingest Backpressure Rule

Signal Fabric MUST integrate with the PRD-02 backpressure chain.

Within this layer, backpressure MUST propagate as:

```text
Queue -> Replay Guard -> Validate -> Ingest Interface -> Source
```

## 9.2 Capacity Rejection Rule

If durable admission cannot be completed, the authoritative result MUST be:

```text
RESOURCE_EXHAUSTED
```

The ingest layer MUST NOT:

* pretend success
* silently drop
* overwrite buffered authoritative data

System MUST implement global admission control.

Global admission control MUST:

* prioritize CRITICAL signals
* degrade NORMAL admission first
* enforce signed system-wide caps

## 🔴 STORAGE BACKPRESSURE PROPAGATION (CRITICAL)
RULE

If storage capacity reaches threshold:

storage_pressure = TRUE
BEHAVIOR
IF storage_pressure:

    ingest_rate MUST be reduced deterministically
    non-critical signals MAY be rejected (by signed priority rules)
PRIORITY LAW
CRITICAL signals MUST NEVER be dropped
LOW priority MAY be dropped deterministically
HARD LAW
NO UNBOUNDED INGEST WHEN STORAGE IS SATURATED

## STORAGE_PRESSURE_SIGNAL (MANDATORY)

STORAGE_PRESSURE_SIGNAL (MANDATORY)

Ingest MUST emit deterministic pressure states:

* NORMAL
* THROTTLED
* BLOCKED

Edge MUST react deterministically based on state.

## 9.3 Response Semantics

TCP and API interfaces MUST return exact rejection codes synchronously.

UDP interfaces MUST return exact rejection codes over the deterministic response channel.

Success MUST be reported only after:

* replay acceptance is durable
* durable queue admission succeeds

## 9.4 Backpressure Integrity Rule

Backpressure MAY:

* delay transmission
* reject with `RESOURCE_EXHAUSTED`

Backpressure MUST NOT:

* mutate signal bytes
* invent acceptance
* discard accepted signals

---

# 10. RATE LIMITING & DOS PROTECTION

## 10.1 Mandatory Controls

The ingest system MUST enforce:

* per-identity rate limits
* per-identity connection limits
* provisional per-source-tuple rate limits
* provisional per-source-tuple connection limits
* slow-client protection
* invalid signature throttling
* malformed-input throttling

All thresholds MUST derive from signed configuration.

## 🔴 PER-IDENTITY RATE GOVERNANCE (CRITICAL)
RULE

Each identity MUST have:

max_signal_rate_per_logical_span
ENFORCEMENT
IF rate exceeded:

    signals MUST be:
        - throttled
        OR
        - rejected deterministically
HARD LAW
VALID SIGNATURE DOES NOT IMPLY UNLIMITED TRUST
REPLAY LAW
same signal stream → same throttling decisions

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

## ANTI_AGGREGATION_EVASION (MANDATORY)

Aggregated signals MUST include:

- entropy summary
- signal distribution hash
- anomaly flags

RULE:

aggregation MUST NOT hide rare events

IF entropy anomaly detected:
→ escalate as CRITICAL

## 10.2 Identity Failure Rate Limiting

FAILURE ATTRIBUTION MODEL:

Validation failure counters MUST be maintained using:

* source_tuple (IP + connection fingerprint)
* bound identity tuple ONLY AFTER a signature verification attempt has executed using the resolved public key for that identity

UNBOUND_IDENTITY_FAILURE:

If identity cannot be cryptographically bound:
→ classify as UNBOUND_FAILURE
→ DO NOT increment identity failure counter

## 10.2.1 Bounded Tracking Structure (CRITICAL)

The ingest system MUST NOT allocate unbounded memory for attacker-controlled inputs.

Tracking for provisional source tuples (Section 5.2) MUST use a bounded structure:

```text
BOUNDED STRUCTURE:

- fixed-size exact table keyed by canonical provisional source tuple
```

Mandatory:

* unbounded maps are FORBIDDEN
* the chosen structure MUST have a fixed configured maximum memory footprint
* overflow MUST NOT allocate new state
* overflow MUST fail closed with deterministic backpressure signaling

FORBIDDEN:

* LRU eviction
* Count-Min Sketch
* Bloom filters
* probabilistic tracking

### 10.2.1.1 Hard Limit (MANDATORY)

```text
MAX_TRACKED_SOURCE_TUPLES = CONFIGURED_LIMIT
```

The limit MUST derive from signed configuration.

### 10.2.1.2 Overflow Rule (MANDATORY)

If capacity is reached:

```text
→ DROP NEW UNVERIFIED CONNECTIONS
→ DO NOT ALLOCATE NEW STATE
```

Drop MUST occur before any expensive cryptographic work.

### 10.2.1.3 Memory Safety Law (CRITICAL)

```text
INGEST MUST NEVER:
- grow unbounded memory
- allocate per attacker-controlled input infinitely
```

Quarantine MUST trigger ONLY after:

* identity binding verification has executed
* a signature verification attempt has executed against the bound identity candidate

Events that fail before these steps MUST NOT contribute to quarantine state for any valid identity.

Unverified identities MUST NOT quarantine valid identities.

If the same identity tuple exceeds the signed failure threshold within the signed window:

```text
identity_state = QUARANTINED
```

While quarantined:

* the identity tuple MUST be rejected with `QUARANTINED_IDENTITY`
* quarantine duration MUST be deterministic
* exit from quarantine MUST occur only by signed administrative release

## 10.3 Invalid Signature Throttling

Invalid signature events MUST increment:

* the source_tuple failure counter

Invalid signature events MUST increment the identity failure counter ONLY IF:

* signature verification attempt has executed using the resolved public key for that identity, AND
* the key matched identity, AND
* the failure occurred post-binding

Throttle action MUST be deterministic and MUST NOT modify valid identities.

VALID_IDENTITY_PROTECTION:

Valid identities MUST NOT be quarantined due to:

* pre-verification failures
* spoofed identity claims

## 10.4 Slow-Client and Flood Protection

Ingest MUST reject or disconnect clients that violate:

* MAX_BYTES_PER_CONNECTION
* MAX_FRAMES_PER_CONNECTION
* MAX_INVALID_FRAMES
* maximum requests per signed window
* maximum datagrams per signed window

Flood protection MUST apply before authoritative admission and MUST NOT create trusted state.

---

# 11. PARTITION ROUTING HANDOFF

## 🔴 SINGLE SOURCE ROUTING LAW (CRITICAL)
PRD-02 OWNS ROUTING FORMULA
ALL OTHER PRDs MUST REFERENCE ONLY
RULE

PRD-08 MUST NOT DEFINE ROUTING LOGIC

## 11.1 Handoff Boundary

Partition routing MUST occur only after:

* validation succeeds
* replay acceptance succeeds
* durable queue admission succeeds

No rejected signal may be routed.

## 11.2 Routing Inputs

The authoritative routing inputs are:

* `emitter_type`
* `emitter_id`
* signed shard configuration

The routing entity is:

```text
entity_id = emitter_id
```

`emitter_type` MUST remain attached to the event metadata.

## 11.3 Routing Rule

Logical shard mapping MUST be deterministic within the active partition epoch.

Authoritative routing formula is owned by PRD-02.

PRD-08 MUST reference PRD-02 and MUST NOT restate, re-derive, or implement the routing formula here.

Routing MUST NOT depend on:

* ingress node identity
* transport type
* arrival wall-clock time
* CPU scheduling
* batch size

## 11.4 Handoff Record

The handoff to the partition router MUST include at minimum:

* canonical message bytes
* `message_id`
* queue reference
* `logical_shard_id`
* `partition_id`

This handoff record MUST be sufficient for deterministic downstream routing and replay.

---

# 11.5 FEDERATION LOOP PROTECTION (CRITICAL)

```text
DUPLICATE SIGNED MESSAGE DETECTED:

→ DROP
→ ALERT

NO REPLAY STATE EXPANSION
```

---

# 12. FAILURE HANDLING

## 12.1 Malformed Input

Malformed input MUST be rejected.

Missing required fields or unsupported `schema_version` MUST also be rejected fail-closed.

Decision state for schema-version mismatch:

```text
REJECT_SCHEMA_MISMATCH
```

Required result:

```text
INVALID_CANONICAL -> REJECT
```

## 12.2 Invalid Signature

Invalid signature MUST be rejected and throttled.

Decision state:

```text
REJECT_SIGNATURE_INVALID
```

Required result:

```text
INVALID_SIGNATURE -> REJECT + RATE_LIMIT_EVALUATION
```

## 12.3 Replay Duplicate

Replay duplicate MUST be rejected idempotently.

Decision state:

```text
REJECT_DUPLICATE
```

Required result:

```text
REJECT_DUPLICATE -> REJECT
```

## 12.4 Overload

Overload MUST trigger backpressure, not drop.

Required result:

```text
RESOURCE_EXHAUSTED -> REJECT_WITH_RETRY_SIGNAL
```

## 12.5 Durable Integrity Failure

If any of the following integrity conditions are broken:

* replay-guard integrity
* durable queue integrity
* signed configuration integrity

the affected ingest scope MUST fail closed.

The following fail-closed conditions are mandatory:

```text
ordering violation -> REJECT
replay inconsistency -> DETERMINISM_DRIFT
state corruption -> HALT INGEST PIPELINE
```

If system-wide integrity is broken, PRD-02 global halt rules apply.

## 12.6 Node Failure

Ingest node failure MUST NOT invalidate unrelated ingest nodes.

Because ingest nodes are stateless with respect to authoritative replay and queue state:

* node replacement MUST be automatic
* admitted signals MUST remain recoverable
* retransmission of non-admitted signals MUST remain safe by `message_id`

No node failure may cause silent admission loss.

---

# 13. PERFORMANCE MODEL

The ingest system MUST remain high-throughput and horizontally scalable without relaxing validation correctness.

The following are mandatory:

* ingest-to-durable-queue admission MUST complete in under 10 ms under non-degraded, in-capacity operation
* canonical validation cost MUST be O(message_size)
* identity validation cost MUST be O(1) relative to fleet size given signed local identity records
* replay-guard routing MUST be O(1)
* partition-routing computation MUST be O(1)
* batch hashing MUST be supported on the hot path
* batch Ed25519 verification MUST be the default mode on the hot path

Horizontal scaling MUST occur by:

* adding stateless ingest nodes
* increasing replay-guard partitions
* increasing durable-queue capacity
* increasing partition count downstream

Horizontal scaling MUST NOT require:

* shared mutable in-memory state between ingest nodes
* a global ingest lock
* a global replay lock

---

# 14. SECURITY MODEL

## 14.1 Verify-Before-Admit Law

No signal may be admitted before:

* canonical validation
* identity validation
* `schema_version` validation
* `boot_session_id` validation
* `logical_clock` validation
* `signing_context` validation
* SHA256 recomputation
* `message_id` recomputation
* Ed25519 signature verification
* replay acceptance
* durable queue admission

## 14.2 Input Non-Trust Rule

The following MUST NOT create trust:

* network location
* host reputation
* API caller reputation
* TLS session success
* previous successful traffic from the same source

## 14.3 Attack Resistance Rule

The ingest system MUST resist:

* malformed message floods
* invalid signature floods
* replay floods
* slow-client exhaustion
* hot-identity overload

Resistance MUST preserve:

* correctness
* deterministic rejection behavior
* admission integrity

## 14.4 Audit Rule

Every rejection outcome MUST be auditable with:

* rejection code
* listener identifier
* source tuple
* presented identity tuple if available
* `message_id` if derivable

Auditability MUST NOT require admission of the rejected signal.

---

# 15. FORBIDDEN PATTERNS

```text
FORBIDDEN:

- accepting raw telemetry directly into the core
- trusting source IP, TLS success, or API authentication as signal validity
- skipping canonical validation
- skipping identity validation
- skipping signature verification
- replay check before signature verification
- queue admission before validation succeeds
- partition routing before durable queue admission
- best-effort ingestion
- silent drop on overload
- global mutable shared ingest state
- inference inside ingest
- enrichment inside ingest
- correlation inside ingest
- random batching behavior
- random retry behavior
- unsigned admission decisions
- UDP ingest without deterministic rejection signaling
- invalid identities consuming valid identity quarantine state

# RECOVERY_SESSION_ACCEPTANCE (MANDATORY)

RECOVERY_SESSION_ACCEPTANCE

Ingest MUST accept:

```text
NEW (agent_id, boot_session_id)
```

EVEN IF:

* previous session terminated mid-sequence

Replay safety preserved via:

```text
(agent_id, boot_session_id, logical_clock)
```
```

---

# 16. SUMMARY

```text
Signal Fabric is the only authoritative ingest firewall.

It MUST:
- treat all incoming bytes as untrusted
- validate in strict order
- verify before admit
- batch cryptographic work by default
- reject malformed and adversarial input deterministically
- backpressure instead of dropping
- hand off only durably admitted signals to partitioned execution

If validation, replay integrity, or durable admission integrity is broken:
REJECT -> FAIL-CLOSED -> ALERT
```

---
