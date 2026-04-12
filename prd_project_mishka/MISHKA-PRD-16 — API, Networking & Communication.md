# MISHKA-PRD-16 — API, Networking & Communication

**Project:** Project Mishka  
**Classification:** AUTHORITATIVE — DETERMINISTIC, SECURE, REPLAY-SAFE API AND NETWORK EDGE  
**Status:** CRITICAL — TRANSPORT TERMINATION, AUTHN/AUTHZ, AND RAW-BYTE HANDOFF ONLY

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

This document defines the authoritative API, networking, and communication layer for Project Mishka.

Its purpose is to:

* expose system capabilities through a deterministic network boundary
* accept only transport-framed and bounded input at the edge
* prevent non-deterministic or replay-unsafe communication behavior
* hand all accepted write-capable input into PRD-08 without bypass
* ensure responses are deterministic and derived from authoritative state

This layer MUST NOT introduce:

* non-determinism
* ordering ambiguity
* replay inconsistency
* direct authoritative state mutation

```text
UNTRUSTED NETWORK INPUT -> TERMINATE TRANSPORT -> ENFORCE AUTHN/AUTHZ -> FRAME/BOUND -> PASS RAW BYTES TO PRD-08
```

---

# 2. CORE PRINCIPLES

```text
PRD-16 IS A ZERO-TRUST TRANSPORT EDGE.
IT TERMINATES TRANSPORT AND ENFORCES AUTHN/AUTHZ ONLY.
IT MUST NOT PERFORM SCHEMA/CANONICAL/SIGNATURE/IDENTITY VERIFICATION.
```

The following principles are mandatory:

* all inbound data MUST be treated as untrusted
* inbound bytes MUST be framed and bounded deterministically before forwarding
* PRD-16 MUST NOT canonicalize, schema-validate, or cryptographically verify payload contents
* direct authoritative state mutation from the API layer is FORBIDDEN
* PRD-08 is the only authoritative ingest admission path
* network timing, worker scheduling, and transport behavior MUST NOT change authoritative outcomes
* parallel execution is permitted only when emitted handoff and response ordering remain identical
* transport authentication MUST restrict access but MUST NOT replace PRD-08 validation

There is no best-effort mode or partial-acceptance mode.

---

## 🔴 WALL CLOCK IS NON-AUTHORITATIVE (ENFORCEMENT)
RULE

System MUST NOT depend on wall clock for:

- ordering
- validation
- execution
EXCEPTION
TLS / infra validation MUST use bounded skew window
HARD LIMIT
max_clock_skew_ms MUST be defined in signed config

---

# 3. NETWORK TRUST MODEL

Everything received from the network is:

```text
UNTRUSTED INPUT
```

The following are untrusted and MUST NOT grant authoritative admission by themselves:

* source IP
* source port
* network path
* TLS success
* API token presence
* mTLS identity
* hostname
* arrival timing
* worker-local receive order

Trusted admission for write-capable input occurs only in PRD-08 after verify-before-admit.

Before these conditions succeed, input MUST NOT be treated as:

* valid signal content
* valid identity
* valid replay-safe request
* valid authoritative state change

---

# 4. API INPUT MODEL

The API input model is one deterministic request per transport unit.

The following are mandatory:

* every request body MUST contain exactly one complete opaque byte sequence (body bytes)
* every write-capable request MUST contain exactly one candidate `signal_event` byte payload for downstream PRD-08 admission
* request body bytes MUST remain unchanged across the PRD-16 → PRD-08 handoff
* oversize request bodies MUST be rejected before parsing
* multi-message request bodies are FORBIDDEN
* if a write-capable endpoint supports client retry correlation, the external request reference MUST be one explicit canonical field in the request schema

All incoming data MUST:

* be treated as untrusted
* be validated for framing, size, and authN/authZ eligibility before forwarding

If input cannot be parsed as one complete request object:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

---

# 5. API OUTPUT MODEL

All API responses MUST be deterministic JSON.

The authoritative response envelope is:

```json
{
  "status": "ACCEPTED_FOR_INGEST|REJECTED",
  "decision_code": "string",
  "authoritative_handoff_ref": "string|null"
}
```

The following are mandatory:

* `status` MUST be determined only by validation outcome and PRD-08 handoff outcome
* `decision_code` MUST be stable for the same request and same authoritative outcome
* `authoritative_handoff_ref` MUST be `null` unless PRD-08 authoritative handoff has succeeded
* response fields MUST appear in the exact order shown above
* responses MUST NOT include wall-clock timestamps, latency samples, worker identifiers, or non-authoritative debug data
* identical authoritative state MUST produce identical response bytes

---

# 6. TRANSPORT FRAMING & HANDOFF PIPELINE (CRITICAL)

The mandatory high-level request flow is:

```text
receive -> terminate transport -> enforce authN/authZ -> validate framing/size -> forward raw bytes to PRD-08 ingest
```

Within that flow, the authoritative order is:

```text
1. receive complete transport unit bytes
2. enforce framing, method, size, and endpoint eligibility
3. enforce transport authentication and authorization policy (authN/authZ only)
4. fully reconstruct request body bytes in exact streaming order (no parsing)
5. forward raw body bytes to PRD-08 for canonicalization + schema validation + signature + identity + replay admission
6. return deterministic response derived from PRD-08 handoff result (or deterministic local framing/auth rejection)
```

The following are mandatory:

* PRD-16 MUST NOT parse or interpret request body semantics beyond framing/size limits
* PRD-16 MUST NOT perform canonicalization, schema validation, signature verification, or identity verification
* PRD-08 MUST perform canonicalization, schema validation, signature verification, identity verification, replay gate, and durable admission

Version mismatch is:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

Any validation failure is:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

---

# 7. ROLE REDUCTION (MANDATORY)
PRD-16 MUST ONLY:

- terminate transport
- enforce authN/authZ
- pass raw bytes forward

FORBIDDEN in PRD-16:

- schema validation
- canonical validation
- signature verification

---

# 8. INGEST HANDOFF RULE (CRITICAL)

All accepted write-capable inputs MUST enter the PRD-08 ingest pipeline.

The following are mandatory:

* accepted raw body bytes MUST be handed off exactly once to PRD-08
* the PRD-08 handoff bytes MUST equal the raw body bytes reconstructed under Section 6
* no accepted write-capable request may bypass PRD-08
* direct database writes from the API layer are FORBIDDEN
* direct storage mutation from the API layer is FORBIDDEN
* direct partition mutation from the API layer is FORBIDDEN
* success response MUST NOT be emitted before PRD-08 handoff succeeds

PRD-16 MUST NOT derive idempotency keys from request-body semantics.
Authoritative idempotency, canonicalization, signature, identity binding, and replay semantics are owned by PRD-08 / PRD-03.

## NETWORK_EDGE_PROTECTION (MANDATORY)
All deep parsing MUST occur ONLY after:

- TLS termination
- request framing validation

Pre-TLS layer MUST operate as:

- rate limiter
- connection gate

NOT parser.

## 8.1 UI IDEMPOTENCY KEY (CRITICAL)

For UI-governed control actions that originate from `UI_ACTION_INTENT` (PRD-21), the authoritative idempotency key MUST be:

```text
idempotency_key = SHA256(UI_ACTION_INTENT)
```

This is mandatory for UI control endpoints and MUST override any other idempotency-key derivation for those endpoints.

Duplicate prevention law:

```text
SAME INTENT HASH → SAME RESULT → NO SIDE EFFECTS
```

UI retry rule:

```text
CLIENT RETRY IS PERMITTED
SYSTEM MUST remain idempotent and MUST NOT duplicate execution
```

BACKEND COMMIT IS AUTHORITATIVE (CRITICAL):

Backend commit of the authoritative record is authoritative.

For UI-governed control actions:

* backend-committed `UI_ACTION_RECORD` is authoritative (PRD-21 / PRD-20 / PRD-13)
* UI MUST NOT guess commit state

UI RECOVERY FLOW (MANDATORY):

On reconnect:

→ query by idempotency_key
→ fetch authoritative state

UI MUST enter:

```text
state = UNKNOWN_COMMIT_STATE
```

until backend confirms authoritative commit state.

API ingest rule (MANDATORY):

```text
IF idempotency_key EXISTS IN WORM:

→ DO NOT RE-EXECUTE
→ RETURN SUCCESS RESPONSE
→ RETURN EXISTING RESULT
```

The following are mandatory:

* idempotency semantics for write-capable ingest are owned by PRD-08 / PRD-03 and MUST be enforced only after PRD-08 verify-before-admit succeeds
* PRD-16 MUST treat the request body as opaque raw bytes and MUST NOT compare, normalize, or reason about `canonical_payload_bytes`

If PRD-08 handoff cannot be completed deterministically:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

---

# 9. RESPONSE MODEL

Responses MUST be deterministic and MUST reflect authoritative state.

The following are mandatory:

* success responses MUST derive from authoritative PRD-08 handoff state
* rejection responses MUST derive from deterministic local validation outcome or deterministic PRD-08 rejection outcome
* identical request bytes under identical signed configuration MUST produce identical response bytes
* identical authoritative state MUST produce identical response bytes
* response generation MUST NOT depend on timing, thread scheduling, or backend selection

For accepted requests:

```text
RESPONSE STATE = ACCEPTED_FOR_INGEST ONLY AFTER AUTHORITATIVE HANDOFF
```

---

# 10. ERROR MODEL

Errors MUST be deterministic, explicit, and fail-closed.

The authoritative rejection codes are:

```text
FRAMING_INVALID
METHOD_INVALID
CONTENT_LENGTH_INVALID
AUTHENTICATION_FAILED
AUTHORIZATION_FAILED
PRD08_REJECTED
INGEST_HANDOFF_FAILED
CONCURRENCY_VIOLATION
TRANSPORT_UNSUPPORTED
PARTIAL_PAYLOAD
API_SCHEMA_VERSION_MISMATCH
REQUEST_ORDERING_INVALID
IDEMPOTENCY_CONFLICT
TRANSPORT_ENCODING_AMBIGUOUS
```

The following are mandatory:

* the same invalid request under the same signed configuration MUST produce the same rejection code
* error responses MUST use the response envelope defined in Section 5
* `authoritative_handoff_ref` MUST be `null` for all rejection responses
* free-form stack traces, runtime-dependent text, and mutable debug payloads are FORBIDDEN

---

# 11. TRANSPORT LAYER RULES

Only deterministic transport behavior is permitted.

The following are mandatory:

* remote API transport MUST use authenticated TLS
* each transport unit MUST contain exactly one complete request
* `Content-Length` MUST be present and exact where applicable
* streaming request bodies are FORBIDDEN
* chunked or indeterminate-length request bodies are FORBIDDEN
* transport-level compression or transformation that changes authoritative request bytes is FORBIDDEN
* persistent connections are permitted only if request boundaries remain deterministic
* retries MUST resend the exact same request bytes or be rejected
* payload bytes MUST be fully reconstructed before forwarding to PRD-08
* partial payload MUST be rejected
* if transport fragmentation occurs below the API layer, byte reconstruction MUST preserve streaming order exactly
* multiple transport encoding representations for the same request semantics MUST be rejected
* content encoding MUST be identity only

Transport framing MUST NOT introduce:

* ordering ambiguity
* partial validation
* partial request acceptance

---

# 12. CONCURRENCY MODEL (CRITICAL)

The API layer MUST ensure deterministic processing order without introducing race conditions.

The following are mandatory:

* request extraction order within one connection or stream MUST match deterministic transport framing order
* no worker may mutate shared authoritative API state during validation or handoff
* unordered ingestion is FORBIDDEN
* write-capable request handoff MUST preserve deterministic per-stream order after `request_order_key` ordering has been applied
* if parallel validation could change emitted handoff or response order for the same input stream, serialization is required
* parallel execution is allowed only if output order is identical

The authoritative pre-ingest ordering key is:

```text
request_order_key = TRANSPORT_FRAMING_ORDER
```

The following are mandatory:

* request extraction order within one connection or stream MUST match deterministic transport framing order
* PRD-16 MUST forward write-capable requests to PRD-08 in deterministic transport framing order only
* PRD-16 MUST NOT derive ordering keys from payload semantics, canonicalization outputs, signature results, schema results, or identity fields inside the request body
* if transport framing order is ambiguous: REJECT -> FAIL-CLOSED -> ALERT

Ordering Constraint:

* PRD-08 MUST own all payload semantic ordering validation, including PRD-03 session and `logical_clock` rules

PRD-16 MUST NOT assign a new authoritative global order. Authoritative downstream ordering remains owned by PRD-08 and later storage layers.

---

# 13. IDENTITY PROPAGATION

Identity propagation MUST preserve authoritative identity binding exactly.

The following are mandatory:

* transport-authenticated caller identity MUST be propagated only as validated access-control metadata
* signed payload identity MUST remain authoritative for signal identity
* the API layer MUST NOT synthesize, rewrite, or substitute `agent_id`
* the API layer MUST NOT synthesize, rewrite, or substitute `boot_session_id`
* the API layer MUST NOT synthesize, rewrite, or substitute `logical_clock`
* the API layer MUST NOT synthesize, rewrite, or substitute `message_id`
* mismatch between authenticated caller identity and signed payload identity binding MUST be rejected
* propagated identity metadata to PRD-08 MUST be deterministic and read-only

---

# 14. SECURITY MODEL

The API and networking layer MUST enforce:

* authentication
* authorization

The following are mandatory:

* authentication MUST be verified before a request can reach accepted handoff state
* authorization policy MUST derive from signed configuration
* transport authentication MUST NOT replace PRD-08 canonicalization, schema validation, signature verification, identity verification, replay gate, or durable admission
* zero-trust handling MUST apply to every inbound request

Any security violation is:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

---

# 15. FAILURE MODEL

The API and networking layer MUST operate fail-closed.

Any of the following is invalid:

* validation failure
* transport ambiguity
* partial payload
* concurrency ambiguity
* request ordering ambiguity
* idempotency conflict
* PRD-08 handoff failure

The following are mandatory:

* any violation MUST result in `REJECT -> FAIL-CLOSED -> ALERT`
* no partial request acceptance is permitted
* no best-effort handoff is permitted
* no write-capable request may remain in ambiguous state after response emission

---

# 16. DETERMINISM GUARANTEE

For identical:

* request bytes
* signed configuration
* authentication inputs
* PRD-08 availability and deterministic outcome

The API layer MUST produce identical:

* transport framing decision
* authN/authZ decision
* `request_order_key`
* handoff bytes (raw body bytes)
* response bytes
* rejection code or authoritative handoff reference state

The following law is mandatory:

```text
IDENTICAL INPUT -> IDENTICAL VALIDATION -> IDENTICAL HANDOFF -> IDENTICAL RESPONSE
```

---

# 17. FILE & MODULE STRUCTURE

The authoritative implementation root for this PRD MUST be:

```text
/api/network/
  listener.go
  request_validator.go
  ingest_handoff.go
  response_encoder.go
  security_gateway.go
  concurrency_controller.go
```

Every module MUST map to one or more sections of this PRD:

* `/api/network/listener.go` -> Sections 3, 4, 11
* `/api/network/request_validator.go` -> Sections 4, 6, 10, 15
* `/api/network/request_validator.go` -> Sections 4, 6, 10, 15
* `/api/network/ingest_handoff.go` -> Sections 6, 8, 12, 15
* `/api/network/response_encoder.go` -> Sections 5, 9, 10, 16
* `/api/network/security_gateway.go` -> Sections 3, 6, 13, 14, 15
* `/api/network/concurrency_controller.go` -> Sections 8, 11, 12, 16

No other authoritative PRD-16 module is permitted.

---

# 18. FORBIDDEN

```text
FORBIDDEN:

- direct DB writes from API
- bypassing ingest pipeline
- time-based ordering
- arrival-order correctness
- async race conditions
- partial validation
- partial request acceptance
- multi-message request bodies
- transport framing ambiguity
- multiple encoding representations for the same request semantics
- worker-local ordering as an authoritative correctness source
- transport authentication as a replacement for signature validation
```

---

# 13. API SCHEMA VERSIONING & COMPATIBILITY

## 13.1 Schema Evolution
The API MUST strictly version all request and response payloads using `schema_version`.

## 13.2 Backward Compatibility
The API MUST be backward compatible with all historical `schema_version` identifiers defined in the signed authority snapshots. 

## 13.3 Replay Safety
All historical API schema structures MUST remain parsable and replay-safe. Removing support for an old `schema_version` that exists in the WORM archive is FORBIDDEN, as it would break exact state reconstruction.

---

# 14. SUMMARY

```text
PRD-16 is the deterministic and secure API boundary for Project Mishka.

It MUST:
- treat all incoming data as untrusted
- terminate transport and enforce authN/authZ only
- frame/bound request bodies and reconstruct raw body bytes
- hand all accepted write-capable input to PRD-08
- produce deterministic responses
- fail closed on any violation

It MUST NOT:
- mutate authoritative state directly
- bypass ingest
- canonicalize, schema-validate, signature-verify, or identity-verify payload semantics
- introduce ordering ambiguity
- permit race-driven or timing-driven outcomes
```

---
