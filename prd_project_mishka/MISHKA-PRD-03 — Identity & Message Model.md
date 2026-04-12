# MISHKA-PRD-03 — Identity & Message Model

**Project:** Project Mishka  
**Classification:** AUTHORITATIVE — GLOBAL IDENTITY, MESSAGE ADDRESSING, AND REPLAY-SAFE BINDING  
**Status:** FOUNDATIONAL — CORRECTED IDENTITY AND MESSAGE MODEL

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

This document defines the authoritative identity, namespace, and message model for Project Mishka.

It establishes how:

* deployments are identified
* agents and probes are named and derived
* messages are deterministically addressed
* duplicates and replays are detected without global coordination
* federation preserves identity and replay correctness

This document replaces non-scalable namespace-only message addressing with a deterministic, content-addressed, identity-bound model suitable for millions of emitters and federated cores.

---

# 2. CORE PRINCIPLES

```text
Identity and message addressing MUST be deterministic, collision-safe, cryptographically bound, and locally derivable.
```

The following laws are mandatory:

* Identity derivation MUST depend only on canonical namespace bytes and signed trust configuration.
* `message_id` MUST be content-addressed, identity-bound, session-bound, order-bound, and partition-safe.
* Replay protection MUST operate with partition-local replay guards and MUST NOT require global DB lookup.
* Federation MUST preserve original emitter identity and original `message_id`.
* Physical routing and wall clock MUST NOT affect identity or `message_id`.
* The only runtime counter permitted in `message_id` generation is the explicit `logical_clock` defined by this PRD.

Micro-hardening (PRD-01 alignment):

* canonical object field lock is mandatory (PRD-01 Section 3.1): unknown fields FORBIDDEN; optional fields MUST be omitted (no null/default)
* array determinism law is mandatory (PRD-01 Section 3.2): any authoritative array MUST define deterministic ordering rules
* hash function law is mandatory (PRD-01 Section 3.3): all authoritative hashes in this PRD MUST use `SHA256`

Canonicalization MUST use RFC 8785 (JCS) canonical JSON ONLY.
No alternative, equivalent, or custom canonicalization is permitted.

Failure:

```text
CANONICALIZATION_VIOLATION -> REJECT -> FAIL-CLOSED -> ALERT
```

```text
No randomness, timestamps, floating logic, or global counters are permitted in identity generation.
For message construction, `boot_nonce` MUST be deterministic and used exactly once to derive `boot_session_id`.
The only local counter permitted in message construction is the explicit `logical_clock`.
```

---

# 3. IDENTITY MODEL (agent_id, probe_id, system_id)

`TRUNC128(x)` is defined as:

```text
the leftmost 16 bytes of x
```

## 3.1 system_id

`system_id` is the authoritative deployment trust-domain identifier.

`system_id` is version-independent.

Emitter identity derivation MUST include explicit `identity_version`.

Mandatory construction:

```text
system_id = SHA256(root_public_key_bytes)
```

Properties:

* length MUST be exactly 32 bytes
* text form MUST be 64 lower-case hexadecimal characters
* same root public key MUST produce the same `system_id`
* different root public keys MUST produce different `system_id`

Compatibility rule:

```text
system_identity_hash is the legacy field name for system_id and MUST equal system_id byte-for-byte.
```

## 3.2 agent_id

`agent_id` identifies one endpoint sensor namespace leaf.

`identity_version` MUST be explicit.

Current emitter identity version:

```text
identity_version = 0x01
```

Mandatory construction:

```text
agent_id = TRUNC128(
  SHA256(
    "agent_id" ||
    identity_version ||
    system_id ||
    canonical_namespace_path_bytes
  )
)
```

Properties:

* length MUST be exactly 16 bytes
* text form MUST be 32 lower-case hexadecimal characters
* same `system_id` and same canonical namespace path MUST produce the same `agent_id`
* any change to canonical namespace path MUST produce a new `agent_id`

## 3.3 probe_id

`probe_id` identifies one non-endpoint telemetry collector.

Mandatory construction:

```text
probe_id = TRUNC128(
  SHA256(
    "probe_id" ||
    identity_version ||
    system_id ||
    canonical_namespace_path_bytes
  )
)
```

Properties:

* length MUST be exactly 16 bytes
* text form MUST be 32 lower-case hexadecimal characters
* same `system_id` and same canonical namespace path MUST produce the same `probe_id`
* any change to canonical namespace path MUST produce a new `probe_id`

## 3.4 Identity Invariants

The following rules are mandatory:

* one canonical namespace path MUST map to exactly one identity of the declared component type
* one identity MUST map to exactly one canonical namespace path within the same `system_id`
* identities are immutable after issuance
* component type MUST be part of the derivation boundary
* multiple `identity_version` values MUST be supported concurrently during controlled migration

The following are forbidden:

* random UUIDs
* mutable emitter identities
* IP-based identities
* hostname-based trust

## 3.5 Session Binding

Every emitting process MUST derive exactly one immutable `boot_session_id` for the life of that process.

`boot_nonce` MUST be:

```text
boot_nonce = SHA256(
  emitter_id ||
  boot_counter ||
  last_committed_partition_hash
)
```

`boot_counter` MUST be:

* monotonic
* stored in PRD-13
* replay-visible

For `emitter_type = agent`:

```text
boot_session_id = SHA256(agent_id || boot_nonce)
```

For `emitter_type = probe`:

```text
boot_session_id = SHA256(probe_id || boot_nonce)
```

The following are mandatory:

* `boot_nonce` MUST be exactly 32 bytes
* `boot_nonce` MUST be generated exactly once per emitter process start
* `boot_nonce` MUST remain immutable for the life of the emitting process
* `boot_session_id` MUST be exactly 32 bytes
* text form of `boot_session_id` MUST be 64 lower-case hexadecimal characters
* all messages emitted by the same live process MUST carry the same `boot_session_id`
* a new emitter process start MUST create a new `boot_session_id`
* `boot_session_id` MUST be included in all message constructions

## BOOT_COUNTER_DURABILITY (MANDATORY)

boot_counter MUST be persisted using:

write-ahead log (WAL) style durability

---

BOOT SEQUENCE:

1. read last_committed_boot_counter
2. increment
3. fsync BEFORE emitting any SIGNAL

---

ATOMICITY:

boot_counter update MUST be:

atomic write + checksum protected

---

RECOVERY:

IF corruption detected:

→ increment last valid counter
→ emit BOOT_RECOVERY_RECORD

---

FORBIDDEN:

- in-memory-only counters
- delayed persistence

---

FAILURE:

counter regression:

→ REJECT SESSION
→ FAIL-CLOSED

## SESSION_INVALIDATION_RULE (CRITICAL)

SESSION_INVALIDATION_RULE (CRITICAL)

A `boot_session_id` becomes INVALID IF:

* emitter detects unclean shutdown
* logical_clock continuity cannot be proven

INVALID SESSION:

```text
→ MUST NOT emit further messages
→ MUST rotate session
```

Violation:

```text
→ REJECT → FAIL-CLOSED
```

---

## 🔴 SESSION CONTINUITY BRIDGE (CRITICAL)

SESSION_CONTINUITY_RECORD (MANDATORY)

On unclean shutdown:

Agent MUST emit:

record_type = SESSION_CONTINUITY

payload:

```text
{
  previous_boot_session_id,
  new_boot_session_id,
  last_committed_message_id,
  last_logical_clock
}
```

---

RULES:

1. MUST be first record in new session
2. MUST be signed
3. MUST be committed before any SIGNAL

---

SESSION_CHAIN_BINDING (CRITICAL)

SESSION_CONTINUITY record MUST include:

continuity_hash = SHA256(
  previous_boot_session_id ||
  last_committed_message_id ||
  new_boot_session_id
)

---

MESSAGE_ID INTEGRATION:

First SIGNAL of new session MUST include:

causal_parent_refs = [last_committed_message_id]

---

CHAIN LAW:

Session continuity MUST become part of:

PRD-13 hash chain

AND

causal graph used by PRD-09

---

FAILURE:

If continuity_hash mismatch OR missing causal_parent_refs:

→ REJECT SIGNAL
→ FAIL-CLOSED

---

ORCHESTRATOR RULE (PRD-09):

Continuity graph MUST treat:

(previous_session → new_session)

as a continuous causal chain.

---

FORBIDDEN:

- silent session reset
- correlation break

---

FAILURE:

Missing continuity record:
→ mark session as ISOLATED
→ no cross-session correlation

---

# 4. NAMESPACE & HIERARCHY

## 4.1 Canonical Namespace Path

Every emitter MUST have one canonical namespace path.

Mandatory structure:

```text
<federation_scope>/<system_scope>/<core_scope>/<component_type>/<component_name>
```

## 4.2 Segment Rules

Every segment MUST satisfy:

```text
regex = [a-z0-9][a-z0-9._-]{0,63}
```

The following are mandatory:

* lower-case ASCII only
* slash `/` as the only separator
* no empty segments
* no whitespace
* no Unicode normalization step at runtime because non-ASCII is forbidden

`canonical_namespace_path_bytes` MUST be:

```text
ASCII(canonical_namespace_path)
```

`canonical_core_namespace_path_bytes` MUST be:

```text
ASCII(canonical_core_namespace_path)
```

## 4.3 Component Types

`component_type` MUST be one of:

```text
agent
dpi
netflow
syslog
snmp
core
```

## 4.4 Governance

The namespace root and all delegation boundaries MUST originate only from signed configuration.

The following rules are mandatory:

* `federation_scope` MUST be stable within the federation
* `system_scope` MUST be unique within `federation_scope`
* `core_scope` MUST be unique within `system_scope`
* `component_name` MUST be unique within `(system_scope, core_scope, component_type)`

Namespace reassignment MUST create a new canonical namespace path and therefore a new derived identity.

---

# 5. MESSAGE MODEL

## 5.1 Authoritative Message Envelope

Every authoritative message MUST contain:

```text
protocol_version
signing_context
system_id
identity_version
emitter_type
emitter_id
boot_session_id
logical_clock
partition_context
payload_hash
message_id
signature
```

`emitter_id` MUST be:

```text
agent_id OR probe_id
```

## 5.2 Canonical Payload Bytes

`canonical_payload_bytes` is the deterministic byte serialization of the message body.

It MUST:

* use canonical JSON conforming to RFC 8785 (JCS) ONLY
* use UTF-8 text encoding
* use lexicographically sorted object keys
* use no insignificant whitespace
* exclude transport framing
* exclude compression wrappers
* exclude encryption wrappers
* exclude `message_id`
* exclude `signature`

`payload_hash` is:

```text
payload_hash = SHA256(canonical_payload_bytes)
```

All implementations MUST produce byte-identical `canonical_payload_bytes`.

## 5.3 identity_bytes

`identity_bytes` MUST be encoded in the following order:

```text
identity_bytes =
  system_id ||
  identity_version ||
  emitter_type ||
  emitter_id
```

`emitter_type` MUST be one byte:

```text
0x01 = agent
0x02 = probe
```

## 5.4 Runtime Metadata

Transport-only runtime metadata MAY exist.

If present, runtime metadata:

* MUST NOT participate in `agent_id`, `probe_id`, or `system_id` generation
* MUST NOT participate in `message_id` generation
* MUST NOT be required for replay correctness

## 5.5 Schema Versioning Model (Authoritative)

Every canonical payload MUST contain one explicit `schema_version` field.

### 5.5.1 Version Immutability

* once a `schema_version` is assigned to a payload, it MUST NOT be changed
* different versions of the same schema MUST use different `schema_version` identifiers
* mutation of a versioned schema without changing the `schema_version` is FORBIDDEN

### 5.5.2 Replay & Backward Compatibility

* all verifiers MUST maintain support for all historical `schema_version` identifiers present in authoritative storage
* replay validation MUST use the exact schema logic corresponding to the stored `schema_version`
* backward compatibility MUST be preserved for all message classes required for replay completeness

### 5.5.3 Enforcement

* `schema_version` MUST be present before canonicalization
* `schema_version` MUST be part of `canonical_payload_bytes`
* `schema_version` MUST therefore participate in `payload_hash`, `partition_context`, `message_id`, and `signature` derivation
* schema-version mismatch between producer and verifier MUST be rejected
* missing `schema_version` MUST be rejected

---

# 5.5.4 SCHEMA EVOLUTION ENGINE (MANDATORY)

```text
SCHEMA EVOLUTION ENGINE (MANDATORY):

PURPOSE:
ENABLE VERSIONED IDENTITY + PAYLOAD PARSING WITHOUT BREAKING REPLAY
```

```text
EVERY RECORD MUST BE PARSED USING:

schema_version FROM RECORD

NOT CURRENT SYSTEM VERSION
```

```text
SYSTEM MUST SUPPORT:

MULTIPLE ACTIVE SCHEMA DECODERS

FOR ALL HISTORICAL VERSIONS
```

```text
NO IN-PLACE MIGRATION ALLOWED

NEW SCHEMA:
→ NEW VERSION
→ OLD DATA REMAINS UNCHANGED
```

```text
ALL schema_version MUST define:

forward_transform
backward_transform
```

```text
RULE:

Each record MUST include:

schema_version
```

```text
TRANSFORMATION:

canonical_form = transform_to_latest(schema_version)
```

```text
REPLAY LAW:

Replay MUST:

1. load original canonical_payload_bytes
2. apply deterministic transform
3. produce identical canonical_form
```

```text
VERSION GRAPH:

Transformations MUST form:

acyclic directed graph
```

```text
FORBIDDEN:

- implicit schema assumptions
- non-deterministic transforms
```

```text
FAILURE:

missing transform:

→ REJECT RECORD
→ FAIL-CLOSED
```

```text
SCHEMA_CONTEXT_BINDING (MANDATORY)

All schema transformations MUST bind to execution_context_hash.

---

CONSTRUCTION:

schema_transform_hash = SHA256(
  schema_version ||
  execution_context_hash
)

---

RULE:

canonical_form MUST be derived as:

canonical_form = transform_to_latest(
  canonical_payload_bytes,
  schema_version,
  schema_transform_hash
)

---

REPLAY LAW:

Replay MUST:

- recompute schema_transform_hash
- apply identical transform
- produce identical canonical_form

---

FORBIDDEN:

context-independent schema transforms

---

FAILURE:

mismatch:

→ DETERMINISM_VIOLATION
→ FAIL-CLOSED
```

## 5.6 Logical Clock Model

`logical_clock` is the authoritative per-session emission ordering field.

Freeze contract (mandatory):

```text
logical_clock_spec_version = v1 (IMMUTABLE)
```

The following are mandatory:

* every implementation MUST implement `logical_clock` exactly as defined in this PRD under `logical_clock_spec_version = v1`
* the `logical_clock_spec_version` value MUST NOT be negotiated, configured at runtime, inferred, or substituted
* any divergence in `logical_clock` rules under the same spec version is invalid

Mandatory construction rules:

* `logical_clock` MUST be an unsigned 64-bit integer
* `logical_clock` MUST be strictly monotonic per `(emitter_id, boot_session_id)`
* `logical_clock` MUST start at `0` for a new `boot_session_id`
* `logical_clock` MUST increment by exactly `+1` per emitted message within the same `boot_session_id`
* regression of `logical_clock` MUST be rejected
* duplication of `logical_clock` within the same `(emitter_id, boot_session_id)` MUST be rejected

Encoding rule:

```text
logical_clock_bytes = UINT64_BE(logical_clock)
```

---

# 6. MESSAGE_ID GENERATION (CRITICAL)

## 6.1 Mandatory Construction

`partition_context` MUST be deterministic and stable for the same canonical payload and identity scope.

`partition_context` MUST be derived ONLY from:

* `canonical_payload_bytes`
* and optionally `identity_bytes`

`partition_context` MUST NOT depend on `signing_context`, `boot_session_id`, or `logical_clock`.

Mandatory construction:

```text
partition_context = TRUNC128(
  SHA256(
    canonical_payload_bytes ||
    identity_bytes
  )
)
```

* `partition_context` MUST NOT depend on `payload_hash` or any derived hash layer
* `partition_context` MUST be computed directly from `canonical_payload_bytes` to avoid double-hash coupling

`message_id` MUST be:

```text
message_id = SHA256(RFC8785(full_canonical_object))
```

## 6.2 Properties

The following are mandatory:

* `message_id` MUST be exactly 32 bytes
* `message_id` MUST be cryptographically strong
* `message_id` MUST be locally derivable
* `message_id` MUST NOT require global DB lookup
* `message_id` MUST NOT rely only on `agent_id` or `probe_id` namespace
* `message_id` MUST be identical for identical canonical inputs
* `message_id` MUST include `boot_session_id`
* `message_id` MUST include `logical_clock`
* UUID-based `message_id` generation is FORBIDDEN

Optional indexing optimization:

```text
message_id_index = TRUNC128(message_id)
```

The system MAY use `message_id_index` for indexing only.

The full 32-byte `message_id` remains authoritative for:

* replay guard decisions
* signature-bound verification
* collision handling
* federation preservation

## 6.3 Stability Rules

For identical `canonical_payload_bytes`, identical `identity_bytes`, identical `partition_context`, identical `boot_session_id`, and identical `logical_clock_bytes`:

* identical payload MUST produce identical `message_id`
* replay reuse MUST produce the same `message_id`
* retry transmission MUST reuse the same `message_id`

The following are forbidden in `message_id` generation:

* timestamps
* wall-clock time
* random seeds other than the single `boot_nonce` used to derive `boot_session_id`
* global counters
* local counters other than the explicit `logical_clock`
* physical partition id
* partition epoch
* floating-point logic

## 6.4 Replay Invariant

For one fixed `signing_context`, given an identical sequence of:

* `canonical_payload_bytes`
* `identity_bytes`
* `boot_session_id`
* `logical_clock_bytes`

the system MUST produce:

* identical `message_id`
* identical `payload_hash`
* identical `signature`

Any deviation is:

```text
PROTOCOL_VIOLATION -> FAIL-CLOSED -> ALERT
```

## 6.5 Rationale Boundary

`partition_context` exists to separate deterministic message classes and distribute replay-guard work without using a global namespace allocator.

`partition_context` MUST NOT be derived from transport path or physical routing state.

---

# 7. IDENTITY BINDING & SIGNING

## 7.1 Mandatory Binding

Each message MUST cryptographically bind:

* identity
* payload hash
* signing context
* `boot_session_id`
* `logical_clock`

Mandatory construction:

```text
canonical_signable_message_bytes = RFC8785(message_envelope_without_signature)
signature = Ed25519(
  UTF8(signing_context) ||
  SHA256(canonical_signable_message_bytes)
)
```

## 7.2 Message Verification

The following order is mandatory:

```text
1. canonicalize payload
2. verify `schema_version` is present and exact
3. recompute payload_hash
4. validate system_id against trusted root key
5. validate identity_version and emitter_id against signed namespace record
6. validate `boot_session_id` structure and emitter binding
7. validate `logical_clock` type and session ordering state
8. recompute partition_context
9. recompute message_id
10. verify signature
11. accept ONLY if all values match
```

Any mismatch:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

## 7.3 Key Binding

Each emitter identity MUST map to exactly one active public key at any verification point.

Key rotation is permitted ONLY through signed identity records.

The following are mandatory:

* key epoch MUST be explicit
* old and new keys MUST NOT both be active for the same identity in the same verification scope
* key reuse across different emitter identities is FORBIDDEN

## 7.4 Signing Context

`signing_context` MUST be drawn only from a finite, signed, versioned set.

The following are mandatory:

* context mismatch MUST invalidate the signature
* context reuse across incompatible message classes is FORBIDDEN
* federation forwarding MUST preserve original `signing_context`

---

# 8. REPLAY GUARD COMPATIBILITY

## 8.1 Local Routing

Replay guards MUST be partition-local.

Mandatory routing rule:

```text
replay_guard_partition =
  UINT32_BE(SHA256(message_id)[0:4]) mod replay_guard_partition_count
```

`UINT32_BE(x)` is defined as:

```text
the unsigned 32-bit big-endian integer represented by the 4-byte sequence x
```

The same `message_id` MUST always route to the same replay-guard partition within the same replay-guard configuration epoch.

Replay guard MUST support:

* load-aware scaling
* deterministic secondary shard key for hotspot mitigation
* bounded hotspot mitigation

Deterministic secondary shard key:

```text
secondary_shard_key =
  UINT32_BE(SHA256(message_id)[4:8]) mod hotspot_shard_count
```

`secondary_shard_key` MAY be used only inside the authoritative replay-guard partition for:

* lock striping
* subpartitioning
* bounded hotspot mitigation

Authoritative duplicate and collision decisions MUST remain keyed by the full `message_id`.

## 8.2 Guard Record

Replay guards MUST store at minimum:

```text
message_id
binding_hash
emitter_id
boot_session_id
logical_clock
seen_state
```

Replay guards MUST additionally maintain one deterministic session-ordering state keyed by:

```text
(emitter_id, boot_session_id)
```

That session-ordering state MUST contain:

```text
last_accepted_logical_clock
```

Where:

```text
binding_hash = SHA256(
  payload_hash ||
  identity_bytes ||
  partition_context ||
  signing_context ||
  boot_session_id ||
  logical_clock_bytes
)
```

## 8.3 Acceptance Rule

If replay guard lookup returns:

* first observation for `(emitter_id, boot_session_id)` with `logical_clock = 0` and no existing `message_id` -> ACCEPTABLE FOR FIRST PROCESSING
* unseen `message_id` and `logical_clock = last_accepted_logical_clock + 1` for the same `(emitter_id, boot_session_id)` -> ACCEPTABLE FOR FIRST PROCESSING
* same `message_id`, same `binding_hash`, and same `logical_clock` -> DUPLICATE / REPLAY
* same `message_id` and different `binding_hash` -> COLLISION / PROTOCOL VIOLATION
* `logical_clock <= last_accepted_logical_clock` for the same `(emitter_id, boot_session_id)` and different `message_id` -> REJECT / LOGICAL CLOCK REGRESSION OR DUPLICATION
* `logical_clock > last_accepted_logical_clock + 1` for the same `(emitter_id, boot_session_id)` -> REJECT / OUT-OF-ORDER GAP

The duplicate case MUST be handled idempotently.

The collision, regression, duplication, and out-of-order gap cases MUST:

```text
REJECT -> ALERT -> FAIL-CLOSED
```

## 8.4 Coordination Rule

Replay protection MUST NOT require:

* global coordinator
* global lock
* global database read before accept/reject

Cross-partition duplicates are safe because identical `message_id` values deterministically route to the same replay-guard partition.

---

# 9. FEDERATION IDENTITY RULES

## 9.1 Core Identity

Federated cores MUST derive their own routing identities deterministically.

Mandatory construction:

```text
core_id = TRUNC128(
  SHA256(
    "core_id" ||
    identity_version ||
    system_id ||
    canonical_core_namespace_path_bytes
  )
)
```

`canonical_core_namespace_path` MUST use the same canonical structure defined in Section 4 with:

```text
component_type = core
```

`core_id` is federation routing metadata.

`core_id` MUST NOT replace origin emitter identity.

## 9.2 Origin Preservation

When a message crosses cores, the following fields MUST remain unchanged:

* `system_id`
* `emitter_type`
* `emitter_id`
* `boot_session_id`
* `logical_clock`
* `partition_context`
* `payload_hash`
* `message_id`
* `signing_context`
* original `signature`

Federation transport metadata MAY add:

* `forwarded_by_core_id`
* `received_from_core_id`
* `federation_hop_count`
* `core_id_path`

These fields MUST NOT alter `message_id` or origin signature validation.

System MUST detect and prevent federation loops using:

* hop count limits
* `core_id` path tracking

Federation forwarding MUST append the local `core_id` to `core_id_path`.

A federated receiver MUST reject the message if:

* `federation_hop_count` exceeds the signed maximum hop count
* local `core_id` already exists in `core_id_path`

## 9.3 Namespace Isolation

The following are mandatory:

* no two federated trust domains may share a conflicting `system_id`
* no core may issue identities outside its signed namespace delegation
* a federated receiver MUST reject overlapping namespace claims within the same `system_id`

## 9.4 Conflict Avoidance

If two federated sources present the same emitter identity with different signed namespace records or different active public keys:

```text
REJECT BOTH CLAIMS -> ALERT -> REQUIRE OPERATOR RESOLUTION
```

---

# 10. COLLISION & DUPLICATE HANDLING

## 10.1 Duplicate Rules

For the same `identity_bytes`, the same `partition_context`, the same `boot_session_id`, and the same `logical_clock_bytes`:

* identical payload MUST produce identical `message_id`
* replay reuse MUST produce the same `message_id`
* retransmission MUST preserve the same `message_id`

## 10.2 Cross-Partition Duplicates

If the same message is observed through multiple ingestion paths or physical partitions:

* the original `message_id` MUST be preserved
* duplicate processing MUST remain safe
* no new `message_id` may be minted for the same canonical message

## 10.3 Collision Handling

If two different canonical message tuples produce the same `message_id`, the system MUST treat this as a critical integrity event.

Critical handling rule:

```text
collision_suspected -> reject incoming message -> emit critical audit event -> quarantine source scope
```

The system MUST compare `binding_hash` before classifying an event as ordinary duplicate.

## 10.4 Identity Collision Handling

If two different canonical namespace paths derive the same `agent_id`, `probe_id`, or `core_id` within the same `system_id`:

```text
NAMESPACE COLLISION -> INVALID CONFIGURATION -> FAIL-CLOSED
```

---

# 11. PERFORMANCE & SCALING

The model MUST scale to millions of agents and probes without central contention.

The following are mandatory:

* identity derivation MUST be O(1) with respect to fleet size
* `message_id` generation MUST be O(1) per message
* replay-guard routing MUST be O(1) per message
* no hot-path global allocator is permitted
* no hot-path namespace registry lookup is permitted for `message_id` generation

Scalability rules:

* identity derivation occurs from local canonical bytes and signed config only
* replay-guard distribution MUST use cryptographic hash partitioning
* uniform hashing MUST prevent namespace-only hotspots
* federation forwarding MUST preserve `message_id` and therefore MUST NOT add duplicate allocation cost

---

# 12. SECURITY MODEL

## 12.1 Trust Boundary

Identity is NOT trusted until all of the following succeed:

* namespace record verification
* emitter key binding verification
* `system_id` validation
* `message_id` recomputation
* signature verification

## 12.2 Message Safety

The following are mandatory:

* `message_id` MUST bind payload and emitter identity
* `message_id` MUST bind payload, emitter identity, boot session, and strict order
* `signing_context` MUST prevent cross-class replay
* replay guards MUST reject duplicate `message_id` reuse after first acceptance
* collision suspicion MUST be treated as security-critical

## 12.3 Transport Non-Trust

The following are untrusted:

* source IP
* source hostname
* transport path
* federation hop path
* arrival order

These values MUST NOT determine identity or `message_id`.

---

# 13. FORBIDDEN PATTERNS

```text
FORBIDDEN:

- UUIDv4 or any random identity generation
- timestamps in identity generation
- timestamps in message_id generation
- global counters in identity generation
- global counters in message_id generation
- local counters in message_id generation other than the explicit `logical_clock`
- floating-point or heuristic logic in identity or message_id derivation
- message_id = hash(payload) without identity binding
- message_id derived only from agent_id or probe_id namespace
- global DB lookup before message_id generation
- global DB lookup as a precondition for replay detection
- mutable namespace paths without new identity issuance
- regenerating message_id during federation forwarding
- rewriting origin emitter identity at an intermediate core
- physical partition id in message_id derivation
- partition_epoch in message_id derivation
- omitting `boot_session_id` from message construction
- non-monotonic `logical_clock`
- changing `boot_session_id` within a live emitter process
- unsigned namespace records
- shared public keys across different active emitter identities
```

---

# 14. SUMMARY

```text
Mishka identity and message model is:

- deterministic
- content-addressed
- identity-bound
- replay-safe
- collision-aware
- federation-safe
- locally derivable
- free of global contention

Authoritative law:
message_id = SHA256(RFC8785(full_canonical_object))

If identity, binding, or message_id verification fails:
REJECT -> FAIL-CLOSED -> ALERT
```

---
