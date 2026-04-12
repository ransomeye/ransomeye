# MISHKA-PRD-05 — Edge Sensors & Probes

**Project:** Project Mishka  
**Classification:** AUTHORITATIVE — EDGE SIGNAL ACQUISITION AND NORMALIZATION LAYER  
**Status:** FOUNDATIONAL — DEFINES ALL SIGNAL ORIGINS ENTERING THE SYSTEM

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

This document defines the authoritative edge layer responsible for:

* collecting raw telemetry from sources
* performing deterministic normalization
* enforcing identity-bound signal emission
* producing only valid `signal_event` objects compliant with PRD-07

This document is the only authoritative upstream producer specification for `signal_event`.

The edge layer defined here MUST:

* integrate with PRD-03 identity and message binding
* use PRD-04 trust, key usage, and signing rules
* emit only PRD-07 compliant `signal_event`
* hand off emitted signals to PRD-08 without re-defining ingest admission logic
* remain deterministic, replay-safe, and fail-closed

The edge layer MUST NOT:

* perform detection
* perform scoring
* perform inference
* perform policy evaluation
* bypass PRD-08 verify-before-admit

---

# 2. CORE PRINCIPLES

The following principles are mandatory:

* all raw telemetry is untrusted until locally validated
* only deterministic normalized telemetry may become `signal_event`
* identical valid raw input MUST produce identical canonical signal output
* signal emission MUST be identity-bound and cryptographically signed
* edge buffering MUST preserve integrity before availability
* edge delivery MUST backpressure instead of silently dropping
* the edge layer MUST fail closed on invalid identity, invalid schema, invalid signing state, or invalid canonicalization

Micro-hardening (PRD-01 alignment):

* canonical object field lock is mandatory (PRD-01 Section 3.1): unknown fields FORBIDDEN; optional fields MUST be omitted (no null/default)
* array determinism law is mandatory (PRD-01 Section 3.2): every array MUST have an explicit deterministic ordering rule; no implicit ordering
* hash function law is mandatory (PRD-01 Section 3.3): all authoritative hashes in this PRD MUST use `SHA256`

The following laws are mandatory:

```text
raw telemetry MUST NOT enter the core decision path
only signed PRD-07 compliant signal_event may leave the edge layer
no signal loss is permitted through edge flow control for CRITICAL signals
```

```text
ordering_ref = partition_record_seq
```

* canonical payload bytes
* `payload_hash`
* `partition_context`
* `message_id`
* signature validity
* replay outcome

---

# 3. EDGE ENTITY MODEL

## 3.1 Authoritative Edge Entity Set

The only authoritative edge entity classes are:

* `AGENT`
* `PROBE`

No other producer type may emit `signal_event`.

## 3.2 AGENT

`AGENT` is an endpoint-resident producer.

`AGENT` MAY collect only:

* process execution events
* file system events
* authentication events
* local DNS telemetry when the endpoint has direct authoritative visibility

`AGENT` MUST derive its emitter identity using PRD-03 `agent_id` rules.

`AGENT` MUST sign emitted signals only with an `AGENT` key valid under PRD-04.

## 3.3 PROBE

`PROBE` is a non-endpoint telemetry collector.

`PROBE` MAY collect only:

* syslog telemetry
* NetFlow telemetry
* DNS telemetry
* infrastructure-side authentication telemetry when the telemetry origin is external to the endpoint

`PROBE` MUST derive its emitter identity using PRD-03 `probe_id` rules.

`PROBE` MUST sign emitted signals only with a `PROBE` key valid under PRD-04.

## 3.4 Identity Binding Rule

Every emitted `signal_event` MUST bind to exactly one edge producer identity.

The following are mandatory:

* `emitter_type` MUST equal `agent` for `AGENT` and `probe` for `PROBE`
* `emitter_id` MUST equal the PRD-03 derived identity for that producer
* `system_id` MUST equal the PRD-03 trust-domain identifier derived from the pinned root trust key
* one edge instance MUST map to exactly one active producer key in one verification scope

Implicit producer identity is FORBIDDEN.

## 3.5 Key Usage Constraint

The edge layer MUST emit signals only when the producer key:

* is active in the resolved trust snapshot
* is not revoked
* is not compromised
* is authorized for `signing_context = "signal_v1"`
* matches the producer identity type

If any key-use condition fails:

```text
DROP + ALERT -> FAIL-CLOSED
```

## 3.6 Scope Constraint

`AGENT` and `PROBE` identities MUST remain within their delegated namespace scope from PRD-03 and PRD-04.

No edge entity may:

* emit under another producer identity
* emit outside its signed namespace delegation
* emit using a `NODE`, `CLUSTER`, `ROOT`, or `ADAPTER` key

---

# 4. TELEMETRY SOURCE MODEL

## 4.1 Source Authority Rule

The authoritative supported edge telemetry sources are:

* `SYSLOG`
* `NETFLOW`
* `DNS`
* `PROCESS_EXEC`
* `FILE_SYSTEM`
* `AUTHENTICATION`

Each source MUST define:

* deterministic parse boundary
* canonical extraction rules
* normalization constraints
* allowed emitted `signal_type` set

If raw input cannot be mapped to one allowed source model deterministically:

```text
DROP + ALERT -> FAIL-CLOSED
```

## 4.2 SYSLOG

Supported syslog input formats are:

* RFC3164
* RFC5424

The following extraction rules are mandatory:

* framing MUST be parsed according to the selected RFC grammar exactly
* facility and severity MUST be parsed from PRI deterministically
* host, app-name, procid, msgid, and structured-data MUST be extracted exactly where present
* free-text body parsing MUST use only signed deterministic parser profiles local to the producer
* if no signed deterministic parser profile matches, the syslog record MUST NOT emit a core signal

The following normalization constraints are mandatory:

* transport framing metadata MUST NOT enter the authoritative signal payload
* RFC3164 missing fields MUST become explicit schema-defined zero or `"unknown"` values only where the target schema permits them
* RFC5424 structured-data parameter keys MUST be canonically sorted before any schema mapping
```text
ordering_ref = partition_record_seq
```

Allowed emitted `signal_type` values are:

* `user.auth.v1`
* `network.dns.v1`
* `infrastructure.protocol.v1`
* `infrastructure.state.v1`

Any syslog-derived signal type outside this set is invalid.

## 4.3 NETFLOW

Supported flow input formats are:

* NetFlow v5
* NetFlow v9
* IPFIX

The following extraction rules are mandatory:

* template resolution for NetFlow v9 and IPFIX MUST use only locally retained deterministic template state
* template identity MUST be bound to exporter identity and template ID
* unrecognized, missing, or expired required templates MUST invalidate dependent records
* 5-tuple and byte/packet counters MUST be extracted exactly as integers
* exporter-provided start and end times MUST remain observational only

The following normalization constraints are mandatory:

* all addresses MUST be normalized to canonical textual form before schema mapping
* byte and packet counts MUST remain unsigned integers
* protocol values MUST remain canonical integer codes
* direction inference is FORBIDDEN unless explicitly provided by deterministic local interface metadata

Allowed emitted `signal_type` values are:

* `network.flow.v1`
* `network.lateral.v1`

Any flow record not mappable to one of these signal types deterministically MUST be dropped locally with alert.

## 4.4 DNS Telemetry

Supported DNS telemetry sources are:

* resolver query logs
* passive DNS packet-derived metadata from probes
* endpoint DNS API or kernel event feeds from agents

The following extraction rules are mandatory:

* qname MUST be normalized to lowercase ASCII where IDNA processing has already produced a canonical ASCII form
* qtype and rcode MUST remain canonical integer or signed registry values
* answer-count, authority-count, and additional-count MUST remain unsigned integers
* packet bytes MUST NOT enter the authoritative signal payload
* truncated, malformed, or undecodable names MUST be rejected

The following normalization constraints are mandatory:

* answer sets used for correlation MUST be deterministically sorted by canonical byte form before hashing
```text
ordering_ref = partition_record_seq
```
* transport path and capture interface MUST NOT affect emitted canonical bytes

Allowed emitted `signal_type` values are:

* `network.dns.v1`

## 4.5 PROCESS Execution

Supported process execution inputs are:

* kernel process-create notifications
* endpoint audit execution events
* endpoint EDR execution telemetry

The following extraction rules are mandatory:

* executable path, argv, parent process reference, effective user, integrity level, and execution result fields MUST be extracted exactly where present
* absent fields MUST map only to schema-defined zero or `"unknown"` values
* environment-dependent path expansion is FORBIDDEN
* command-line tokenization MUST use a fully specified local deterministic tokenizer for the operating system family

The following normalization constraints are mandatory:

* path strings MUST be normalized using signed local platform rules only
* process lineage references MUST be deterministic and locally derivable
* PID values alone MUST NOT serve as durable identity

Allowed emitted `signal_type` values are:

* `process.exec.v1`
* `process.privilege.v1`
* `process.persistence.v1`

## 4.6 FILE SYSTEM Events

Supported file system inputs are:

* create
* modify
* delete
* rename
* attribute-change

The following extraction rules are mandatory:

* file path, operation type, subject identity, actor process reference, and target classification fields MUST be extracted exactly where present
* file content bytes MUST NOT enter the authoritative signal payload
* file hash computation MAY occur only if it is locally available without external dependency and uses deterministic hashing rules defined by the owning file schema

The following normalization constraints are mandatory:

* path normalization MUST use signed local platform rules only
* equivalent path renderings MUST collapse to one canonical representation before signal construction
* ambiguous rename pairs MUST be rejected

Allowed emitted `signal_type` values are:

* `process.persistence.v1`
* `infrastructure.state.v1`

If a file system event cannot be mapped to one of these signal types deterministically, it MUST NOT emit a core signal.

## 4.7 AUTHENTICATION Events

Supported authentication inputs are:

* local login audit events
* remote login audit events
* Kerberos authentication events where deterministic local decoding exists
* PAM (Linux) and Windows OS authentication feeds with deterministic parser profiles

The following extraction rules are mandatory:

* subject account, auth method, target service, source address if present, outcome, and privilege context MUST be extracted exactly where present
* free-text reason fields MUST NOT enter the authoritative signal payload
* session identifiers MAY be used only as observational fields unless the schema makes them decision-relevant

The following normalization constraints are mandatory:

* account names MUST be normalized using signed local account canonicalization rules
* auth outcome MUST map to canonical enum values
* privilege level MUST map to canonical signed registry values

Allowed emitted `signal_type` values are:

* `user.auth.v1`
* `user.session.v1`
* `user.privilege.v1`

---

# 5. NORMALIZATION PIPELINE

## 5.1 Mandatory Pipeline Order

The edge normalization pipeline MUST execute in the following exact order:

```text
raw_input -> validation -> canonical mapping -> normalization -> enrichment -> pre_signal_aggregation -> signal_event
```

No step may be skipped, reordered, or bypassed.

## 5.2 Raw Input Stage

The raw input stage MUST:

* accept source-native bytes or structured local OS event records
* assign source class deterministically
* attach local producer identity context
* reject unsupported framing or unsupported event class before canonical mapping

Raw input MUST remain outside the core path.

## 5.3 Validation Stage

Validation MUST perform all of the following:

* source grammar validation
* schema profile selection
* required field presence checks
* field-type validation
* length and bounds validation
* canonical encoding validation

Validation MUST occur before normalization and before deduplication.

## 5.4 Canonical Mapping Stage

Canonical mapping MUST:

* map source-native fields to canonical field names
* discard transport-only and vendor-only artifacts not permitted by PRD-07
* map source enums to canonical signed registry values
* ensure all mandatory schema-defined keys are present

Canonical mapping MUST use only signed local mappings.

## 5.5 Normalization Stage

Normalization MUST:

* convert units to canonical units
* convert booleans to `0` or `1`
* convert ratios to fixed-point integers where the target schema requires them
* materialize explicit zero or schema-defined `"unknown"` values where permitted
* reject any value with no canonical form

Floating-point normalization is FORBIDDEN.

## NORMALIZATION_ENGINE = WASM (SIGNED)

RULES:

- module_hash MUST be signed
- deterministic execution ONLY
- no syscalls
- no floating point nondeterminism

## 5.6 Enrichment Stage

Enrichment is permitted ONLY when all enrichment inputs are:

* deterministic
* local
* static or signed
* replay-safe

Allowed enrichment inputs are limited to:

* signed local feature schemas
* signed local signal registry
* signed local namespace and scope configuration
* signed local account and asset normalization tables

The following are FORBIDDEN:

* external API calls
* DNS lookups for enrichment
* remote reputation lookups
* probabilistic enrichment
* time-dependent logic

## 5.7 Construction Boundary

Only after enrichment succeeds AND pre-signal aggregation (Section 6) succeeds MAY the edge layer construct `signal_event`.

If any prior stage fails:

```text
DROP + ALERT -> FAIL-CLOSED
```

---

---

# 6. PRE-SIGNAL AGGREGATION, FILTERING & STATE MODEL (CRITICAL)

## 6.1 POSITION IN PIPELINE (MANDATORY)

```text
RAW TELEMETRY
→ PARSE
→ NORMALIZE
→ PRE-SIGNAL AGGREGATION (THIS SECTION)
→ SIGNAL_EVENT CONSTRUCTION (PRD-07)
```

MANDATORY:

* This layer operates BEFORE PRD-07 canonical_payload_bytes construction
* This layer MUST NOT emit signal_event directly
* This layer MUST produce deterministic intermediate structures ONLY

---

## 6.2 AGGREGATION MODEL (MANDATORY)

Aggregation MUST be:

* deterministic
* lossless
* replay-reconstructable

MANDATORY RULES:

* grouping_key MUST be explicitly defined per signal_type
* grouping_key MUST be derived ONLY from normalized deterministic fields
* grouping MUST use byte-equality on canonical field representations
* component ordering MUST equal input sequence order
* aggregation MUST NOT reorder inputs

---

## 6.3 WINDOW CLOSURE RULES (MANDATORY)

Aggregation windows MUST close ONLY by:

* fixed_component_count reached
* deterministic grouping_key change
* explicit end-of-sequence marker
* deterministic saturation rule

FORBIDDEN:

* wall-clock timers
* arrival-time delays
* batching based on latency
* scheduler-dependent closing

Violation:

```text
NON_DETERMINISTIC_WINDOW → REJECT → FAIL-CLOSED
```

---

## 6.4 FILTERING MODEL (MANDATORY)

Allowed filtering:

1. EXACT DUPLICATE SUPPRESSION
2. EXACT MATCH SUPPRESSION

MANDATORY:

* suppression MUST preserve occurrence_count
* suppression MUST be reconstructable during replay
* suppression MUST NOT remove information irreversibly

FORBIDDEN:

* heuristic filtering
* fuzzy matching
* probabilistic suppression

---

## 6.5 STATE MODEL (MANDATORY)

Allowed state:

* bounded aggregation buffers
* grouping state
* suppression tracking

MANDATORY:

* all state MUST be bounded
* eviction MUST be deterministic
* state MUST be reconstructable from input stream
* restart MUST restore identical state from replay

FORBIDDEN:

* unbounded buffers
* time-based eviction
* hidden caches

---

## 6.6 LOSSLESS RECONSTRUCTION LAW (CRITICAL)

The system MUST guarantee:

```text
AGGREGATED OUTPUT → EXACT ORIGINAL INPUT RECOVERY
```

MANDATORY:

* all components MUST be recoverable
* ordering MUST be preserved
* counts MUST match exactly

Violation:

```text
LOSSY_TRANSFORMATION → FAIL-CLOSED → ALERT
```

---

## 6.7 CANONICALIZATION BOUNDARY (CRITICAL)

This layer defines the FINAL transformation BEFORE:

* canonical_payload_bytes
* payload_hash
* message_id

MANDATORY:

* no transformation is allowed AFTER this stage that changes semantic content
* PRD-07 MUST consume output of this layer EXACTLY

---

## 6.8 MODULE OWNERSHIP (MANDATORY)

This layer is implemented by:

```text
/edge/intelligence/
```

Responsibilities:

* aggregation
* filtering
* deterministic state
* reconstruction guarantees

PRD-05 is the SOLE authority for this layer.

---

# 7. DEDUPLICATION MODEL

## 7.1 Authoritative Dedup Key

Local exact deduplication MUST use `message_id` only.

The dedup key is therefore payload-bound, identity-bound, session-bound, and order-bound.

## 7.2 Dedup Sequence Rule

The following order is mandatory:

```text
validate -> canonicalize -> construct prospective payload -> derive identity bytes -> derive partition_context -> bind boot_session_id -> assign logical_clock -> derive message_id -> deduplicate
```

Deduplicating pre-canonical raw input is FORBIDDEN.

## 7.3 Exact Duplicate Rule

If two candidate signals produce the same:

* canonical payload bytes
* identity bytes
* partition context
* boot_session_id
* logical_clock

they MUST produce the same `message_id` and MUST be treated as duplicates or replays.

Duplicates MUST NOT emit multiple signals.

## 7.4 Scope Rule

Local deduplication MUST be exact only.

The following are FORBIDDEN:

* fuzzy deduplication
* similarity thresholds
* time-near deduplication without byte identity
* heuristic suppression

## 7.5 Suppression Rule

If a duplicate is detected:

* the duplicate MUST NOT emit a second authoritative `signal_event`
* duplicate suppression MUST be auditable locally
* duplicate suppression MUST preserve the original canonical `message_id`

---

# 8. LOCAL BUFFER MODEL

## 8.1 Buffer Boundary Rule

The local edge buffer exists only for undelivered signed `signal_event` awaiting handoff to PRD-08.

The local edge buffer MUST NOT be treated as ingest admission state.

## 8.2 Buffer Structure Rule

Each edge producer instance MUST maintain:

* one bounded in-memory append queue
* one append-only disk spill buffer

The following are mandatory:

* emission order MUST be preserved across memory and disk
* disk spill MUST be append-only
* disk spill records MUST store the canonical full `signal_event`
* buffer capacity MUST derive from signed configuration

## 8.3 Ordering Rule

Within one producer instance, emitted signals MUST preserve deterministic local emission order.

The following are mandatory:

* `logical_clock` MUST be maintained per `(emitter_id, boot_session_id)`
* `logical_clock` MUST be strictly monotonic per `(emitter_id, boot_session_id)`
* `logical_clock` MUST start at `0` for a new `boot_session_id`
* `logical_clock` MUST increment by exactly `+1` per emitted signal
* buffer enqueue order MUST equal emission order
* spill order MUST equal enqueue order
* recovery replay order MUST equal spill order

Cross-producer global ordering is NOT authoritative.

If the edge layer cannot increment `logical_clock` for the next emitted signal:

```text
HALT EMISSION
```

If `(emitter_id, boot_session_id)` ordering state becomes non-sequential:

```text
HALT AGENT
```

## 8.4 Priority Retention Rule

If upstream rejects with `RESOURCE_EXHAUSTED`:

* CRITICAL signals MUST retain reserved local capacity
* HIGH signals MAY remain buffered or be deterministically aggregated only if the aggregation rule is already authorized by PRD-07
* NORMAL signals MAY be delayed the longest

No CRITICAL signal may be silently dropped.

NORMAL eviction is forbidden unless deterministic reconstruction remains possible locally under PRD-02 rules.

## 8.5 Overflow Rule

If the buffer cannot safely accept another signal without violating reserved CRITICAL capacity:

```text
BACKPRESSURE -> ALERT
```

Best-effort overflow handling is FORBIDDEN.

---

## 🔴 EDGE_TERMINAL_CAPACITY_STATE (MANDATORY) (EDGE-01, EDGE-04)

IF (MANDATORY):

```text
memory_full == TRUE
AND disk_spill_full == TRUE
AND escrow_unreachable == TRUE
```

THEN (MANDATORY):

```text
EDGE MUST ENTER: EDGE_HALT_STATE
```

EDGE_HALT_STATE RULES (MANDATORY):

* STOP signal generation
* DO NOT DROP CRITICAL silently
* DO NOT mutate signals
* EMIT local alert

RECOVERY (MANDATORY):

```text
RECOVERY IS PERMITTED ONLY WHEN: durable path restored
```

## 8.5.1 STORAGE_PRESSURE_MODE (CRITICAL)

STORAGE_PRESSURE_MODE:

LEVEL 0: NORMAL
LEVEL 1: DROP_NON_CRITICAL
LEVEL 2: COMPRESS_NON_CRITICAL
LEVEL 3: SIGNAL_SUMMARY_MODE

Mandatory:

* CRITICAL signals MUST NEVER be dropped
* NON-CRITICAL signals MAY be deterministically reduced only under this section
* any transition into a higher pressure level MUST be deterministic and based only on local storage state and signed configuration thresholds

LEVEL 1 (DROP_NON_CRITICAL):

* drop NON-CRITICAL only
* drop MUST be deterministic
* drop MUST emit local alert
* drop MUST also emit a CRITICAL, escrow-eligible dependency absence notice when any drop occurs:

```text
DEPENDENCY_ABSENT_SIGNAL (PRD-09) MUST be emitted as:
signal_type = infrastructure.dependency_absent.v1
priority = CRITICAL
```

Mandatory payload (bounded):
* `emitter_id`
* `boot_session_id`
* `drop_mode = DROP_NON_CRITICAL`
* `dropped_signal_count`
* `dropped_group_digest = SHA256(ordered_group_keys)` where `ordered_group_keys` are the deterministic grouping keys of dropped items (bounded list; overflow -> hash-only)

Hard law:
* the dependency absence notice MUST be routed through CRITICAL escrow rules and MUST NOT be subject to NON-CRITICAL drop.

LEVEL 2 (COMPRESS_NON_CRITICAL):

* compress NON-CRITICAL only
* compression MUST NOT change canonical signal bytes for any emitted `signal_event`
* compression MUST be a storage-layer wrapper only and MUST be replay-transparent
* entering LEVEL 2 MUST emit `infrastructure.dependency_absent.v1` with `drop_mode = COMPRESS_NON_CRITICAL` (CRITICAL, escrow-eligible) so downstream deferred decisions can deterministically interpret missing evidence under load

LEVEL 3 (SIGNAL_SUMMARY_MODE):

Aggregate repetitive NON-CRITICAL signals into a deterministic summary artifact:

```json
{
  "type": "SUMMARY",
  "count": 0,
  "pattern_hash": "hex_32_bytes",
  "deterministic_expansion_metadata": {
    "canonical_pattern_template": "string",
    "ordered_field_definitions": ["string"],
    "reconstruction_rules": "string"
  }
}
```

Mandatory:

* summary MUST be deterministic for identical buffered inputs
* `count` MUST be derived only from the ordered buffered signal stream
* `pattern_hash` MUST be:

```text
pattern_hash = SHA256(RFC 8785 (JCS)(pattern))
```

* summary artifacts MUST NOT replace or mutate any CRITICAL signals
* summary artifacts MUST NOT introduce ambiguity in subsequent deterministic processing

SUMMARY_REVERSIBILITY_LAW (CRITICAL):

Every summary MUST be fully expandable into:
→ exact original event sequence

FAILURE:

If reconstruction not possible:
→ SUMMARY INVALID
→ FAIL-CLOSED

FINAL FAIL-SAFE (CRITICAL):

If CRITICAL cannot be persisted:

```text
STOP signal ingestion
→ FREEZE sensor pipeline
→ EMIT local CRITICAL alert
→ DO NOT crash host OS
→ DO NOT drop signal
```

ESCROW_FORWARDING_MODE (REPLACEMENT)

CRITICAL signals MUST:

→ be forwarded to escrow endpoint  
→ NOT remain in memory indefinitely

Mandatory state:

```text
state = ESCROW_FORWARDING_MODE
```

ESCROW_FORWARDING_MODE rules (MANDATORY):

* forward CRITICAL canonical bytes to escrow endpoint
* escrow forwarding MUST be append-only and preserve canonical bytes
* escrow forwarding MUST NOT block UI or authoritative ingest

FORBIDDEN:

* memory-only indefinite buffering for CRITICAL signals
* killing host OS
* dropping CRITICAL signal silently

---

## 🔴 EDGE_ISOLATION_RULE (MANDATORY) (EDGE-01, EDGE-04)

Edge MUST NOT use wall-clock time for retry, delay, or escalation decisions.

Instead, edge MUST use:

```text
retry_attempt_counter
```

Deterministic rule (MANDATORY):

```text
IF retry_attempt_counter > MAX_RETRY_BOUND:
    SWITCH TO ESCROW_FORWARDING_MODE

IF escrow forwarding fails:
    EDGE MUST ENTER EDGE_HALT_STATE
```

## 8.5.2 CRITICAL_SIGNAL_ESCROW_MODE (MANDATORY)

CRITICAL_SIGNAL_ESCROW_MODE (MANDATORY)

STATE MACHINE:

```text
NORMAL
→ DEGRADED (storage_pressure = TRUE)
→ ESCROW_ACTIVE (local disk threshold reached)
→ HALT (only if escrow exhausted)
```

RULES:

IF `storage_pressure = TRUE`:

```text
NON_CRITICAL:
    DROP (deterministic, priority-based)

CRITICAL:
    MUST enter ESCROW QUEUE
```

ESCROW QUEUE:

* disk-backed
* bounded
* append-only
* priority = CRITICAL only

ESCROW DRAIN RULE:

IF `storage_pressure = FALSE`:

```text
replay escrow in strict logical_clock order
```

FORBIDDEN:

* dropping CRITICAL signals
* reordering escrow replay

## ESCROW_DEADLOCK_RESOLUTION (CRITICAL)

IF:

disk_full == TRUE
AND escrow_endpoint_unreachable == TRUE

THEN:

ACTIVATE:

CRITICAL_SIGNAL_COMPRESSION_MODE

---

RULES:

1. signals MUST be losslessly compressed:

compression = zstd (level fixed)

2. multiple signals MAY be packed into:

ESCROW_BATCH_RECORD

3. memory buffer MUST be:

bounded_ring_buffer

max_size MUST be defined

---

PRIORITY RULE:

Only CRITICAL signals allowed in buffer

---

BACKPRESSURE:

Agent MUST:

→ stop accepting non-critical signals
→ emit BACKPRESSURE_SIGNAL upstream

---

FAILURE:

If buffer full:

→ deterministic eviction:

DROP lowest priority NON-CRITICAL ONLY

CRITICAL MUST NEVER be dropped

IF no NON-CRITICAL entry exists for eviction:

→ ENTER EDGE_HALT_STATE
→ FAIL-CLOSED

## ESCROW_COMPRESSION_DETERMINISM (MANDATORY)

Compression MUST be deterministic.

---

REQUIRED:

compression = zstd
compression_level = fixed
dictionary = fixed (if used)

---

INPUT ORDER:

Signals MUST be ordered by:

(message_id ASC)

---

ESCROW_BATCH_ORDERING (MANDATORY)

Signals inside ESCROW_BATCH_RECORD MUST be ordered by:

(agent_id ASC, boot_session_id ASC, logical_clock ASC)

---

RULE:

message_id ordering alone is insufficient

---

REPLAY LAW:

batch reconstruction MUST produce identical ordering

---

OUTPUT:

compressed_payload MUST be identical for identical input set

---

FAILURE:

non-deterministic compression output:

→ REJECT ESCROW_BATCH_RECORD
→ FAIL-CLOSED

## 8.6 Crash Recovery Rule

On restart, the edge layer MUST:

```text
1. load the last consistent durable edge buffer state
2. validate buffer integrity
3. replay incomplete local delivery operations
4. resume local delivery without signal loss
```

CRASH RECOVERY LAW (MANDATORY):

UNCLEAN_SHUTDOWN_DETECTION (MANDATORY)

IF `last_shutdown != CLEAN`:

MUST:

* increment `boot_counter`
* derive NEW `boot_session_id`

MUST NOT reuse previous session.

Crash MUST NOT cause:

* signal loss
* duplicate authoritative emission
* ordering drift

---

# 9. SIGNAL CONSTRUCTION

## 9.1 PRD-07 Compliance Rule

Every emitted signal MUST be exactly one PRD-07 compliant `signal_event`.

This document MUST NOT redefine the PRD-07 authoritative schema.

The following fields MUST be present in every emitted `signal_event`, MUST NOT be optional, and MUST match the PRD-07 schema exactly:

* `boot_session_id`
* `logical_clock`
* `schema_version`

These fields are authoritative and MUST NOT be synthesized, inferred, or rewritten downstream.

## 9.2 Canonical Payload Rule

The edge layer MUST construct `canonical_payload_bytes` using:

```text
RFC 8785 (JCS) UTF-8 canonical JSON
```

For `signal_event`, `canonical_payload_bytes` MUST include `schema_version` exactly as required by PRD-07.

The following are mandatory:

* `schema_version` MUST be present before canonicalization
* `schema_version` MUST be selected from the active signed `signal_schema_version_set` (PRD-07)
* `schema_version` selection MUST be deterministic under signed configuration (no runtime negotiation)
* missing `schema_version` MUST be rejected before emission

The canonical payload MUST exclude:

* `message_id`
* `signature`
* transport framing
* compression wrappers
* encryption wrappers

## 9.3 Payload Hash Rule

The following construction is mandatory:

```text
payload_hash = SHA256(canonical_payload_bytes)
```

`payload_hash` MUST equal the PRD-03 and PRD-07 payload hash exactly.

## 9.4 Message ID Rule

The following PRD-03 constructions are mandatory:

The following session-binding rules are mandatory before `message_id` construction:

* `boot_session_id` MUST follow PRD-03 session binding for the declared emitter type
* `boot_session_id` MUST be generated exactly once per emitter process start
* all signals emitted by the same live process MUST carry the same `boot_session_id`
* a new emitter process start MUST create a new `boot_session_id`
* `boot_session_id` MUST NOT be reused across restarts

```text
identity_bytes =
  system_id ||
  identity_version ||
  emitter_type ||
  emitter_id

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

The following are forbidden in edge `message_id` generation:

* wall-clock time
* random seeds other than the single `boot_nonce` used to derive `boot_session_id`
* global counters
* local counters other than the explicit `logical_clock`
* physical partition identifiers
* partition epoch

## 9.5 Source-To-Signal Mapping Rule

The source-to-signal mapping set is:

* `SYSLOG` -> `user.auth.v1` or `network.dns.v1` or `infrastructure.protocol.v1` or `infrastructure.state.v1`
* `NETFLOW` -> `network.flow.v1` or `network.lateral.v1`
* `DNS` -> `network.dns.v1`
* `PROCESS_EXEC` -> `process.exec.v1` or `process.privilege.v1` or `process.persistence.v1`
* `FILE_SYSTEM` -> `process.persistence.v1` or `infrastructure.state.v1`
* `AUTHENTICATION` -> `user.auth.v1` or `user.session.v1` or `user.privilege.v1`

Any other mapping is invalid unless a future signed PRD extends the authoritative set.

## 9.6 Observational Ordering Rule

```text
ordering_ref = partition_record_seq
```

* canonical identity
* `payload_hash`
* `message_id`
* signature validity

---

# 10. SIGNING MODEL

## 10.1 Signing Context Rule

The only allowed edge emission signing context is:

```text
signal_v1
```

## 10.2 Signature Construction Rule

The edge layer MUST follow the message-class-specific signing profile already made authoritative by PRD-03 for `signal_v1`.

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

signature = Ed25519(signing_input)
```

## 10.3 Key Usage Enforcement Rule

Before signing, the edge layer MUST verify under PRD-04:

* key type matches producer type
* `signing_context = signal_v1` is allowed for the key
* key is active in the resolved trust snapshot
* key is not revoked
* `expiry_logical_clock` constraint is NOT exceeded
* expired signatures MUST be rejected
* key is not compromised

Unsigned signal emission is FORBIDDEN.

## 10.4 Signing Failure Rule

If signing state is invalid or signature generation fails:

```text
DROP + ALERT -> FAIL-CLOSED
```

---

# 11. FAILURE MODEL

The edge layer MUST operate fail-closed.

The following behaviors are mandatory:

* invalid input -> `DROP + ALERT`
* invalid identity -> `DROP + ALERT`
* signing failure -> `DROP + ALERT`
* buffer overflow -> `BACKPRESSURE`

The following are also mandatory:

* invalid canonicalization -> `DROP + ALERT`
* invalid schema mapping -> `DROP + ALERT`
* invalid source template state -> `DROP + ALERT`
* trust-state ambiguity -> `DROP + ALERT`

The following fail-closed hard-stop conditions are mandatory:

* missing `boot_session_id` -> `HALT`
* missing `logical_clock` -> `HALT`
* `logical_clock` regression -> `HALT`
* `logical_clock` duplication -> `HALT`
* missing `schema_version` -> `HALT`
* `message_id` mismatch after construction -> `HALT`

There is no best-effort mode.

Any attempt to continue with partial validation, partial normalization, partial trust, or unsigned emission is invalid.

---

# 12. DETERMINISM GUARANTEES

For the same:

* valid raw input bytes or valid structured local event input
* producer identity
* local signed normalization tables
* local signed feature schema
* local signed signal registry
* local signed trust state

the edge layer MUST produce:

* identical canonical payload bytes
* identical `payload_hash`
* identical `partition_context`
* identical `message_id`
* identical signature-validity inputs
* identical `signal_event`

Replay of the same valid raw input MUST produce an identical `signal_event`.

Parallel execution, crash recovery, retry, and local buffering MUST NOT alter the resulting canonical signal bytes.

For identical:

* `canonical_payload_bytes`
* `identity_bytes`
* `partition_context`
* `boot_session_id`
* `logical_clock`

the edge layer MUST produce:

* identical `message_id`
* identical signature

---

# 13. FILE & MODULE STRUCTURE

The authoritative edge implementation root MUST be:

```text
/edge/
  /agent/
    collector.go
    process_source.go
    file_source.go
    auth_source.go
    dns_source.go
  /probe/
    collector.go
    syslog_source.go
    netflow_source.go
    dns_source.go
    auth_source.go
  /normalizer/
    pipeline.go
    source_mapper.go
    canonicalizer.go
    deduplicator.go
  /intelligence/
    ingestion.go
    aggregation_engine.go
    filtering_engine.go
    state_store.go
    pipeline.go
  /buffer/
    memory_queue.go
    disk_spool.go
    recovery.go
  /signing/
    signal_signer.go
    key_usage_gate.go
```

Every module MUST map to one or more sections of this PRD:

* `/edge/agent/collector.go` -> Sections 3, 4, 5, 6, 8, 11, 12
* `/edge/agent/process_source.go` -> Section 4
* `/edge/agent/file_source.go` -> Section 4
* `/edge/agent/auth_source.go` -> Section 4
* `/edge/agent/dns_source.go` -> Section 4
* `/edge/probe/collector.go` -> Sections 3, 4, 5, 6, 8, 11, 12
* `/edge/probe/syslog_source.go` -> Section 4
* `/edge/probe/netflow_source.go` -> Section 4
* `/edge/probe/dns_source.go` -> Section 4
* `/edge/probe/auth_source.go` -> Section 4
* `/edge/normalizer/pipeline.go` -> Sections 4, 5, 6, 7, 9, 12
* `/edge/normalizer/source_mapper.go` -> Sections 4, 5, 9
* `/edge/normalizer/canonicalizer.go` -> Sections 5, 9, 12
* `/edge/normalizer/deduplicator.go` -> Section 7
* `/edge/buffer/memory_queue.go` -> Section 8
* `/edge/buffer/disk_spool.go` -> Section 8
* `/edge/buffer/recovery.go` -> Sections 8, 11, 12
* `/edge/signing/signal_signer.go` -> Sections 9, 10
* `/edge/signing/key_usage_gate.go` -> Section 10

* `/edge/intelligence/ingestion.go` -> Sections 6, 5, 12
* `/edge/intelligence/aggregation_engine.go` -> Sections 6, 8, 12
* `/edge/intelligence/filtering_engine.go` -> Sections 6, 7, 8, 12
* `/edge/intelligence/state_store.go` -> Sections 6, 7, 8, 12
* `/edge/intelligence/pipeline.go` -> Sections 6, 5, 9, 12

No undefined files are allowed under `/edge/`.

The presence of an undefined file is:

```text
REJECT BUILD -> FAIL-CLOSED -> ALERT
```

---

# 14. FORBIDDEN OPERATIONS

```text
FORBIDDEN:

- LLMs, RAG, prompt-chaining, probabilistic logic, AI, or ML logic in the edge layer
- heuristic filtering
- adaptive filtering
- probabilistic enrichment
- external API calls
- external reputation lookups
- time-dependent logic in canonicalization, hashing, message_id, or signing
- random deduplication
- fuzzy duplicate suppression
- unsigned signal emission
- raw telemetry entering the core path
- mutable state that changes output for identical valid input
- parser profiles that are not signed and local
- bypass of PRD-08 verify-before-admit
- transport metadata as an identity or message_id input
- wall-clock time as a canonical signal input
```

---

# 15. SUMMARY

```text
Edge Sensors & Probes is the authoritative edge production layer for signal_event.

It MUST:
- collect raw telemetry only from authorized edge sources
- normalize telemetry deterministically
- bind every emitted signal to explicit producer identity
- derive message_id exactly as required by PRD-03
- sign only with authorized AGENT or PROBE keys under PRD-04
- emit only PRD-07 compliant signal_event
- buffer and backpressure without silent loss
- remain replay-safe and fail-closed

The edge layer MUST NOT:
- perform ingest admission logic
- perform AI/ML scoring, inference, or policy evaluation
- emit unsigned or schema-invalid signals
```
