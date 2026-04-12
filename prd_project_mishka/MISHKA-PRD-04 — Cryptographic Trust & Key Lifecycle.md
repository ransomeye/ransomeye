# MISHKA-PRD-04 — Cryptographic Trust & Key Lifecycle

**Project:** Project Mishka  
**Classification:** AUTHORITATIVE — CRYPTOGRAPHIC TRUST, IDENTITY SIGNING, VERIFICATION, AND KEY LIFECYCLE  
**Status:** CRITICAL — DETERMINISTIC, REPLAY-SAFE, FAIL-CLOSED TRUST MODEL

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

This document defines the authoritative cryptographic trust and key lifecycle model for Project Mishka.

It governs:

* identity signing
* message signing
* signature verification
* trust-chain resolution
* key generation
* key storage
* key distribution
* key rotation
* key revocation
* federation trust propagation

This document is authoritative for cryptographic trust state.

If any component, workflow, or future PRD contradicts this document within this scope, that component, workflow, or PRD is invalid.

---

# 2. CORE PRINCIPLES

The following principles are mandatory:

* all trust MUST be explicit
* all authoritative cryptographic objects MUST be signed
* verification MUST be deterministic
* verification MUST be local and replay-safe
* trust resolution MUST be fail-closed
* key status MUST be explicit
* key rotation MUST preserve historical verifiability
* key revocation MUST stop future trust without breaking historical verification
* no hidden trust is permitted
* no wall-clock dependency is permitted in authoritative trust decisions
* no network lookups are permitted in authoritative verification paths

Canonicalization MUST use RFC 8785 (JCS) canonical JSON ONLY.
No alternative, equivalent, or custom canonicalization is permitted.

Failure:

```text
CANONICALIZATION_VIOLATION -> REJECT -> FAIL-CLOSED -> ALERT
```

Mandatory trust law:

```text
verify -> admit -> use
```

The following are untrusted until verified:

* transport success
* TLS success
* source IP
* host location
* API caller reputation
* previous valid traffic from the same source
* operator-provided runtime input

---

# 3. CRYPTOGRAPHIC ALGORITHMS (MANDATORY)

## 3.1 Fixed Algorithm Profile

The current authoritative cryptographic profile is:

```text
crypto_profile_id = ed25519_sha256
```

This profile MUST use:

* `Ed25519` for digital signatures
* `SHA256` for hashing (PRD-01 §3.3)

No alternatives are permitted. The hash function MUST be `SHA256` exactly as defined in PRD-01 §3.3 (no version suffix, no configuration, no negotiation).

Any deviation:

```text
INTEGRITY_FAILURE -> FAIL-CLOSED -> ALERT
```

## 3.2 Signature Algorithm Law

All signatures governed by this document MUST use Ed25519.

Any non-Ed25519 signature presented as authoritative is invalid.

## 3.3 Hash Algorithm Law

All hashes governed by this document MUST use SHA256 exactly as defined in PRD-01 §3.3.

Any non-SHA256 hash presented as authoritative is invalid.

Any deviation:

```text
INTEGRITY_FAILURE -> FAIL-CLOSED -> ALERT
```

## 3.4 Batch Verification Rule

Batch Ed25519 verification MAY be used only as a performance optimization.

The following are mandatory:

* batch verification output MUST equal single-signature verification output exactly
* batch verification MUST NOT weaken correctness
* if deterministic failed-member isolation is required, fallback to single verification is permitted

If batch verification result is ambiguous:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

---

# 4. KEY TYPES & ROLES

## 4.1 Common Key Record Law

Every authoritative key record MUST contain at minimum:

```json
{
  "key_id": "hex_32_bytes",
  "key_type": "ROOT|CLUSTER|NODE|AGENT|PROBE|ADAPTER",
  "scope_id": "string",
  "authority_scope": "string",
  "key_epoch": 0,
  "public_key": "hex_ed25519_public_key",
  "allowed_signing_contexts": ["string"],
  "issuer_key_id": "hex_32_bytes",
  "status": "ACTIVE|RETIRED|REVOKED",
  "signature": "hex_ed25519"
}
```

The following construction is mandatory:

```text
key_id = SHA256(
  UTF8(key_type) ||
  UTF8(scope_id) ||
  UINT64_BE(key_epoch) ||
  public_key
)
```

`key_id` MUST be deterministic and immutable.

## 4.2 Root Keys

`ROOT` keys are the top-level trust anchors.

For `ROOT` self-signed trust records:

```text
issuer_key_id = key_id
```

`ROOT` keys MUST:

* define the top authoritative trust boundary
* sign cluster delegation records
* sign root rotation records
* sign federation trust records
* sign bootstrap trust bundles

`ROOT` keys MUST NOT sign runtime signal messages or executor receipts.

## 4.3 Cluster Keys

`CLUSTER` keys are system-local trust authorities below the root.

`CLUSTER` keys MUST:

* sign node identity records
* sign cluster-scoped adapter identity records
* sign configuration, model, and policy authority records where the owning PRD requires signature
* sign rotation records for descendant keys within delegated scope
* sign revocation records for descendant keys within delegated scope

`CLUSTER` keys MUST NOT exceed the authority delegated by the root.

## 4.4 Node Keys

`NODE` keys identify one trusted core node or one delegated control-plane node.

`NODE` keys MUST:

* sign node-local trust attestations
* sign node-scoped emitter identity records when delegated
* sign node-scoped adapter identity records when delegated
* sign node-authored cryptographic lifecycle records when the owning PRD authorizes it

`NODE` keys MUST NOT sign cluster authority records, policies, or models unless explicitly delegated by a signed cluster authority object.

## 4.5 Agent And Probe Keys

`AGENT` and `PROBE` keys identify signal emitters.

`AGENT` and `PROBE` keys MUST:

* sign only the message classes authorized by their signed identity records
* remain bound to exactly one emitter identity in one verification scope
* remain identity-bound through the entire runtime pipeline

Emitter keys MUST NOT sign cluster, node, rotation, revocation, or federation authority objects.

## 4.6 Adapter Keys

`ADAPTER` keys identify enforcement or control adapters.

`ADAPTER` keys MUST:

* sign only the message classes authorized by their signed adapter identity records
* sign executor receipts or adapter attestations only within delegated scope
* remain bound to exactly one adapter identity in one verification scope

Adapter keys MUST NOT sign root, cluster, or unrelated emitter authority objects.

---

# SYMMETRIC_STORAGE_KEY_LAW (MANDATORY)

All PRD-13 encryption-at-rest MUST use:

- deterministic key hierarchy
- root bound to PRD-04 trust anchor

KEY DERIVATION:

```text
data_key = HKDF(master_key, partition_id || epoch)
```

RULES:

- key rotation MUST be deterministic
- replay MUST derive identical keys
- key version MUST be embedded in storage record

FORBIDDEN:

- random key generation
- external KMS dependency for replay

---

# 5. KEY GENERATION MODEL

## 5.1 Generation Scope Rule

Key generation is the only cryptographic operation in this document that MAY use approved entropy.

Key generation MUST NOT participate in authoritative runtime replay decision paths.

Once a key exists, all lifecycle handling of that key MUST be deterministic.

## 5.2 Entropy Rule

Key generation MUST use only:

* hardware-backed HSM entropy
* TPM-backed entropy
* operating-system cryptographically secure random generation

The following are FORBIDDEN for key generation:

* timestamps
* counters
* namespace strings alone
* deterministic derivation from hostnames
* user-provided weak entropy

## 5.3 Generation Requirements By Key Type

The following are mandatory:

* `ROOT` keys MUST be generated in an offline HSM
* `CLUSTER` keys MUST be generated in an HSM or KMS-backed HSM boundary
* `NODE` keys MUST be generated in a TPM or HSM boundary when available
* `AGENT`, `PROBE`, and `ADAPTER` keys MUST be generated in sealed local storage, TPM, or HSM boundary

If required protected generation is unavailable for a key type:

```text
FAIL-CLOSED -> ALERT
```

## 5.4 Generation Output Rule

Every generated key MUST immediately produce:

* `public_key`
* `key_id`
* `key_epoch`
* signed key record or signed enrollment request

Unsigned generated keys MUST NOT enter active trust state.

---

# 6. KEY STORAGE MODEL

## 6.1 Private Key Storage Rule

Private keys MUST NEVER be stored in authoritative runtime storage.

Private keys MUST be stored only in:

* offline HSM for `ROOT`
* HSM or sealed KMS boundary for `CLUSTER`
* TPM, HSM, or sealed node-local key store for `NODE`
* TPM, HSM, or sealed emitter-local key store for `AGENT` and `PROBE`
* TPM, HSM, or sealed adapter-local key store for `ADAPTER`

Plaintext private-key storage is FORBIDDEN.

## 6.2 Public Trust State Storage Rule

Public keys and trust metadata MUST be stored as append-only signed authority objects.

The following MUST be durably retained:

* root trust records
* cluster delegation records
* node identity records
* emitter identity records
* adapter identity records
* rotation records
* revocation records
* trust bundles

Historical trust records MUST NOT be deleted if they are needed for replay or historical verification.

## 6.3 Storage Protection Rule

The following are mandatory:

* private key export MUST be disabled where the hardware boundary supports it
* key access MUST be role-scoped
* private-key use MUST be auditable
* private-key material MUST be zeroized from process memory after use where technically possible

If private-key protection is broken:

```text
FAIL-CLOSED -> ALERT
```

---

# 7. KEY DISTRIBUTION MODEL

## 7.1 Trust Bundle Rule

All active trust state MUST be distributed through signed immutable trust bundles or signed trust records.

The minimum authoritative distribution set is:

* pinned root trust record
* cluster delegation records
* node identity records
* emitter identity records
* adapter identity records
* rotation records
* revocation records
* allowed signing-context set

## 7.2 Local Verification Rule

Authoritative verification MUST use only local signed trust state already admitted into the trusted boundary.

The following are FORBIDDEN in authoritative verification paths:

* live CA fetch
* online OCSP
* unsigned key discovery
* best-effort remote trust lookup
* auto-fetch of newer trust state

If required trust state is missing:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

## 7.3 Distribution Integrity Rule

Every distributed trust object MUST be:

* canonicalized
* hashed
* signed by an authorized issuer
* versioned
* immutable after distribution

Partially propagated trust state is invalid.

## 7.4 Activation Scope Rule

Trust state activation MUST be determined only by explicit signed scope identifiers such as:

* trust bundle version
* configuration version
* key epoch
* storage commit boundary reference

Wall-clock activation is FORBIDDEN.

---

# 8. SIGNING MODEL

## 8.1 Base Signing Rule

Every signed authoritative object governed by this system-wide cryptographic profile MUST include the following signature envelope fields:

```json
{
  "signing_context": "string",
  "key_id": "string",
  "key_epoch": "uint32",
  "signature": "hex_ed25519"
}
```

For signable objects governed directly by this document, the following construction is mandatory:

```text
canonical_payload_bytes = RFC8785(signable_object_without_signature)
canonical_payload_hash = SHA256(canonical_payload_bytes)
signing_context_bytes = UTF8(signing_context)

signing_input =
  signing_context_bytes ||
  canonical_payload_hash

signature = Ed25519(signing_input)
```

Every such signed object MUST contain:

* `signing_context`
* `key_id`
* `key_epoch`
* `signature`

## 8.1.1 SIGNATURE DOMAIN SEPARATION (MANDATORY)

All authoritative Ed25519 signatures in Mishka MUST be domain-separated by the exact `signing_context`.

Mandatory construction:

```text
signature = Ed25519(
  signing_context ||
  SHA256(canonical_payload_bytes)
)
```

Verification MUST enforce:

* `signing_context` EXACT match (byte-for-byte)
* the verifier MUST recompute `SHA256(canonical_payload_bytes)` from RFC 8785 canonical bytes
* the verifier MUST verify the Ed25519 signature over the domain-separated input above

If `signing_context` mismatches, is missing, or cannot be deterministically validated:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

### 8.1.1.1 Mandatory signing_context constants (Mishka core objects)

The following `signing_context` literal constants are mandatory and MUST be enforced exactly (no aliases, no normalization, no fallback):

```text
detection_event_v1
action_decision_v1
action_object_v1
batch_commit_record_v1
```

### 8.1.1.2 BATCH_COMMIT_SIGNATURE_PAYLOAD_GRAMMAR (MANDATORY)

```text
GLOBAL_INVARIANT

PRD04_OWNS_SIGNATURE_ALGORITHM = TRUE
PRD13_OWNS_BATCH_COMMIT_SIGNATURE_PAYLOAD_BYTES = TRUE
PRD04_MUST_NOT_REDEFINE_PRD13_BATCH_COMMIT_SIGNATURE_PAYLOAD_FIELDS = TRUE
```

```text
PURE_ASSIGNMENT

batch_commit_signing_context_literal = "batch_commit_record_v1"
batch_commit_signing_context_bytes = ASCII(batch_commit_signing_context_literal)

batch_commit_signature_payload_bytes = PRD13.batch_commit_signature_payload_bytes
batch_commit_signature_payload_hash = SHA256(batch_commit_signature_payload_bytes)

batch_commit_signature_signing_input =
  batch_commit_signing_context_bytes ||
  batch_commit_signature_payload_hash

batch_commit_signature = Ed25519(batch_commit_signature_signing_input)
```

```text
DETERMINISTIC_PREDICATE

batch_commit_signature_payload_bytes MUST BIND EXACTLY:
partition_id
partition_epoch
batch_commit_seq
first_partition_record_seq
last_partition_record_seq
record_count
first_record_hash
last_record_hash
batch_root_hash
previous_batch_commit_hash
execution_context_hash

batch_commit_signature_payload_bytes MUST BE RECONSTRUCTED FROM THE EXACT PRD-13 STORED VALUES ONLY
batch_commit_signature_payload_hash MUST EQUAL SHA256(batch_commit_signature_payload_bytes)
Ed25519 VERIFICATION INPUT MUST EQUAL batch_commit_signature_signing_input EXACTLY
```

```text
DETERMINISTIC_PREDICATE

DOMAIN_SEPARATION_CONTEXT = ASCII("batch_commit_record_v1")
DOMAIN_SEPARATION_CONTEXT MUST MATCH BYTE-FOR-BYTE
NO PREFIX TRUNCATION = TRUE
NO SUFFIX TRUNCATION = TRUE
NO NORMALIZATION = TRUE
```

```text
STATE_TRANSITION

IF signing_context != "batch_commit_record_v1":
    REJECT -> FAIL-CLOSED -> ALERT
IF recomputed batch_commit_signature_payload_bytes != committed batch_commit_signature_payload_bytes:
    REJECT -> FAIL-CLOSED -> ALERT
IF recomputed batch_commit_signature_payload_hash != committed SHA256(batch_commit_signature_payload_bytes):
    REJECT -> FAIL-CLOSED -> ALERT
IF Ed25519Verify(public_key, batch_commit_signature_signing_input, signature) != TRUE:
    REJECT -> FAIL-CLOSED -> ALERT
```

## 8.2 Versioned Signing Profile Rule

`signing_context` MUST be drawn only from a finite, signed, versioned set.

The following are mandatory:

* context mismatch MUST invalidate the signature
* context reuse across incompatible message classes is FORBIDDEN
* context interpretation MUST be deterministic

## 8.3 Message-Class Compatibility Rule

If an already-authoritative PRD defines a stricter versioned signing profile for a specific `signing_context`, that profile remains authoritative for that `signing_context`.

PRD-03 `signal_v1` is one such authoritative versioned signing profile.

Such profiles remain compliant only if all of the following hold:

* Ed25519 is used for the signature
* SHA256 is used for all required hash construction
* the signing profile is explicit and versioned
* the verification result is deterministic

Any unsigned or implicitly versioned signing profile is invalid.

## 8.4 Signing Capability Rule

A key MUST sign only objects authorized by:

* its `key_type`
* its delegated authority scope
* its allowed `signing_context` set

Out-of-scope signing is invalid.

---

# 9. VERIFICATION MODEL

## 9.1 Verification Determinism Rule

For the same:

* canonical input bytes
* signing context
* trust bundle
* key record set
* rotation state
* revocation state

verification MUST return the same result.

No network lookup, wall-clock check, or operator override may affect the result.

## 9.2 Mandatory Verification Sequence

The following order is mandatory:

```text
1. canonicalize payload or signable object bytes
2. recompute SHA256-derived hash inputs
3. validate signing_context against signed allowed context set
4. resolve candidate key record from local signed trust state
5. verify key status and key epoch in the active verification scope
6. verify full issuer chain to the pinned root
7. verify revocation state
8. verify Ed25519 signature
9. accept ONLY if all checks succeed
```

Any mismatch:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

## 9.3 Active-Key Rule

At any verification point:

* one identity MUST map to exactly one active public key in the same verification scope
* two active keys for the same identity in the same verification scope are FORBIDDEN
* key reuse across different identities is FORBIDDEN

If active-key resolution is ambiguous:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

## 9.4 Historical Verification Rule

Historical verification MUST resolve against the authoritative trust snapshot retained for the original acceptance scope.

Historical verification MUST NOT depend on:

* current wall-clock time
* current active key alone
* current revocation state alone

If the historical trust snapshot is missing:

```text
FAIL-CLOSED -> ALERT
```

---

# 10. KEY ROTATION MODEL (CRITICAL)

## 10.1 Rotation Record Rule

Every key rotation MUST be represented by one signed immutable `key_rotation_record`.

The record MUST contain at minimum:

```json
{
  "subject_identity": "string",
  "key_type": "ROOT|CLUSTER|NODE|AGENT|PROBE|ADAPTER",
  "old_key_id": "hex_32_bytes",
  "new_key_id": "hex_32_bytes",
  "old_key_epoch": 0,
  "new_key_epoch": 0,
  "activation_scope_id": "string",
  "issuer_key_id": "hex_32_bytes",
  "signature": "hex_ed25519"
}
```

## 10.2 Rotation Determinism Rule

Rotation MUST be deterministic.

The following are mandatory:

* `new_key_epoch` MUST be explicit
* activation MUST occur only at an explicit signed activation scope
* old and new keys MUST NOT both be active for the same identity in the same verification scope
* rotation MUST NOT depend on wall-clock time

## 10.3 Expiry Rule (NEW)

Key records MAY include an explicit `expiry_logical_clock` or `expiry_epoch`.

The following are mandatory:

* revocation by wall-clock time alone is FORBIDDEN
* a key MUST be treated as `RETIRED` once its declared logical boundary is reached
* retired keys remain valid for historical verification but MUST NOT sign new records

## 10.4 Tenant Isolation Rule (NEW)

The system MUST enforce strict tenant isolation using `scope_id`.

The following are mandatory:

* a key MUST ONLY be valid for the `scope_id` defined in its signed key record
* cross-tenant key usage is FORBIDDEN and MUST trigger a `FAIL_CLOSED_EVENT`
* trust chains MUST NOT cross `scope_id` boundaries unless explicitly authorized by a signed federation record

## 10.5 Replay Preservation Rule

Rotation MUST preserve replay validity.

The following are mandatory:

* historical signatures under the old key MUST remain verifiable
* historical key records MUST remain durably retained
* historical trust snapshots MUST remain durably retained

Deleting superseded public-key records is FORBIDDEN.

## 10.6 Rotation Propagation Rule

Rotation state MUST propagate as signed trust state before the new key may become active.

Partial propagation is invalid.

If rotation state is partially propagated or ambiguous:

```text
FAIL-CLOSED -> ALERT
```

## 10.7 Root Rotation Rule

`ROOT` key rotation MUST occur only through a signed root rotation bundle containing:

* old root key record
* new root key record
* explicit delegation continuity
* signed root rotation record

If root continuity cannot be proven:

```text
GLOBAL FAIL-CLOSED -> ALERT
```

---

# 11. KEY REVOCATION MODEL (CRITICAL)

## 11.1 Revocation Record Rule

Every revocation MUST be represented by one signed immutable `key_revocation_record`.

The record MUST contain at minimum:

```json
{
  "key_id": "hex_32_bytes",
  "subject_identity": "string",
  "key_type": "ROOT|CLUSTER|NODE|AGENT|PROBE|ADAPTER",
  "revocation_epoch": 0,
  "activation_scope_id": "string",
  "reason_code": "COMPROMISED|SUPERSEDED|DECOMMISSIONED|SCOPE_VIOLATION|TRUST_CONFLICT",
  "issuer_key_id": "hex_32_bytes",
  "replacement_key_id": "hex_32_bytes",
  "signature": "hex_ed25519"
}
```

## 11.2 Explicit Revocation Rule

Revocation MUST be explicit.

The following are mandatory:

* unsigned revocation is invalid
* implicit revocation is FORBIDDEN
* revocation by silence is FORBIDDEN
* revocation by time expiry alone is FORBIDDEN

## 11.3 Propagation Rule

Revocation MUST propagate through signed trust state.

New trust decisions after revocation activation MUST reject the revoked key.

If revocation state is missing, partially propagated, or ambiguous:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

## 11.4 Historical Verification Preservation Rule

Revocation MUST NOT break historical verification of records that were valid in their original acceptance scope.

The following are mandatory:

* revoked key records MUST remain retained for historical verification
* revocation records MUST remain retained
* historical verification MUST use the retained trust snapshot for that historical scope

## 11.5 Root And Cluster Revocation Rule

If a `ROOT` key or `CLUSTER` key is revoked:

* all descendant trust paths under that key become invalid for new trust decisions after activation
* historical records remain verifiable only through retained historical trust snapshots

If descendant containment cannot be determined:

```text
FAIL-CLOSED -> ALERT
```

## 🔴 EMERGENCY KEY REVOCATION (CRITICAL)
RULE

Revocation MUST be:

deterministic
partition-epoch bound
replay-verifiable
MODEL
revocation_record = {
  key_id,
  key_epoch,
  revocation_epoch,
  revocation_reason
}
ENFORCEMENT
IF record.partition_epoch >= revocation_epoch:

    key MUST be treated as INVALID
HARD LAW
NO RETROACTIVE INVALIDATION
ONLY FORWARD ENFORCEMENT

---

# 12. TRUST CHAIN MODEL

## 12.1 Root Trust Anchor

The root trust anchor is the pinned `ROOT` public key.

The following construction is mandatory:

```text
system_id = SHA256(root_public_key_bytes)
```

`system_id` MUST equal the identity law defined by PRD-03.

## 12.2 Authoritative Trust Chains

The following trust chains are authoritative:

```text
ROOT -> CLUSTER
ROOT -> CLUSTER -> NODE
ROOT -> CLUSTER -> NODE -> AGENT
ROOT -> CLUSTER -> NODE -> PROBE
ROOT -> CLUSTER -> ADAPTER
ROOT -> CLUSTER -> NODE -> ADAPTER
```

No other authority path is valid unless a future signed PRD explicitly adds it.

## 12.3 Full-Chain Verification Rule

Verification MUST follow the full chain from subject key to pinned root.

The following are mandatory:

* every delegation step MUST be signed
* every delegation scope MUST be explicit
* every delegation record MUST be locally available
* every delegation record MUST be immutable after admission

Any missing, unsigned, revoked, ambiguous, or out-of-scope chain element is invalid.

## 12.4 Authority Boundary Rule

A parent key MUST NOT delegate authority beyond its own authorized scope.

Scope escalation is FORBIDDEN.

If scope escalation is detected:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

---

# 13. BOOTSTRAP TRUST (CRITICAL)

## 13.1 Root Bootstrap Rule

Initial root trust establishment MUST occur only through an out-of-band pinned root trust bundle.

Trust-on-first-use is FORBIDDEN.

The bootstrap bundle MUST contain:

* root public key
* root key record
* crypto profile identifier
* bootstrap signature continuity data

## 13.2 Cluster Bootstrap Rule

Cluster trust MUST be established only through a root-signed cluster delegation record.

Unsigned cluster establishment is invalid.

## 13.3 Node Enrollment Rule

Secure enrollment of nodes MUST require all of the following:

* node-generated public key
* signed enrollment request
* explicit delegated cluster scope
* signed node identity record issued by the authorized cluster key

No node becomes trusted before the signed node identity record is admitted.

## 13.4 Agent And Probe Provisioning Rule

Secure provisioning of `AGENT` and `PROBE` identities MUST require all of the following:

* canonical namespace path
* derived emitter identity as defined by PRD-03
* generated emitter public key
* explicit allowed signing contexts
* signed emitter identity record issued by an authorized node or cluster authority

Unsigned emitter provisioning is invalid.

## 13.5 Adapter Provisioning Rule

Secure provisioning of `ADAPTER` identities MUST require:

* adapter public key
* explicit adapter scope
* explicit allowed signing contexts
* signed adapter identity record issued by an authorized cluster or node authority

Unsigned adapter provisioning is invalid.

## 13.6 TRUST_BOOTSTRAP_MODE (TIERED TRUST BOOTSTRAP) (CRITICAL)

To prevent an HSM availability single point of failure while preserving fail-closed trust rules, the system MUST support an explicit tiered bootstrap mode.

The following mode selector is mandatory:

```text
TRUST_BOOTSTRAP_MODE:

LEVEL 0 → ROOT (Offline HSM only)
LEVEL 1 → CLUSTER (HSM or quorum-approved KMS)
LEVEL 2 → RECOVERY MODE (STRICTLY LIMITED)
```

### 13.6.1 LEVEL 0 — ROOT (Offline HSM only)

Mandatory:

* `ROOT` key generation MUST occur only in an offline HSM (Section 5.3)
* `ROOT` key generation MUST NOT occur in LEVEL 1 or LEVEL 2

### 13.6.2 LEVEL 1 — CLUSTER (HSM or quorum-approved KMS)

CLUSTER bootstrap MAY use:

* HSM-backed generation, OR
* a quorum-approved KMS-backed HSM boundary

Mandatory:

* the approved KMS boundary MUST be explicitly identified by signed configuration
* KMS approval MUST be represented as a signed trust object admitted into local trust state
* if the KMS boundary identity is missing or ambiguous: FAIL-CLOSED

### 13.6.3 LEVEL 2 — RECOVERY MODE (STRICTLY LIMITED)

Recovery Mode is allowed ONLY if ALL of the following are true:

* quorum approval exists (**required_approval_count-of-eligible_node_count signed nodes**)
* an audit record exists and is durably retained
* the recovery activation is **time-bound** by a deterministic activation window (defined below)
* capabilities are strictly limited

Allowed capabilities in Recovery Mode:

* NO root key generation
* ONLY temporary cluster key issuance

Forbidden in Recovery Mode:

* any `ROOT` key operation other than verification of already-pinned root public key
* indefinite key issuance
* any unsigned approval
* any wall-clock-dependent approval decision

#### 13.6.3.1 Quorum Approval Object (MANDATORY)

Recovery Mode MUST be authorized only by a signed `recovery_activation_record` that contains at minimum:

* `activation_scope_id` (explicit signed scope identifier; MUST NOT be wall-clock)
* `expiry_scope_id` (explicit signed expiry boundary; MUST NOT be wall-clock)
* `activation_reason` (closed enum or exact string, canonicalized)
* ordered `quorum_signatures` (deterministically ordered by signer `key_id` ASC)
* `quorum_rule_id` identifying the signed quorum policy (`eligible_node_count`, `required_approval_count`)

If the quorum set, quorum rule, or signatures are missing or ambiguous:

```text
FAIL-CLOSED -> ALERT
```

#### 13.6.3.2 Deterministic Activation Identifier (MANDATORY)

Recovery activation MUST be deterministic:

```text
recovery_mode_id = SHA256(quorum_signatures || activation_reason || timestamp_fixed_window)
```

`timestamp_fixed_window` is NOT wall clock.

Mandatory definition:

* `timestamp_fixed_window` MUST be the RFC 8785 canonical bytes of a deterministic activation window descriptor derived ONLY from signed scope identifiers:
  * `activation_scope_id`
  * `expiry_scope_id`
* the window descriptor MUST be immutable once admitted
* any attempt to derive the window from wall-clock timestamps is FORBIDDEN

If `timestamp_fixed_window` cannot be derived deterministically from signed scope identifiers:

```text
FAIL-CLOSED -> ALERT
```

#### 13.6.3.3 Mandatory Expiry & Reversion (CRITICAL)

Recovery Mode MUST have mandatory expiry.

Mandatory:

* once `expiry_scope_id` is reached for the active verification scope, Recovery Mode MUST be treated as inactive
* post-expiry: the system MUST revert to HSM-backed operation (LEVEL 0 / LEVEL 1 as applicable)
* if the system cannot prove Recovery Mode is within its active window for the current verification scope: FAIL-CLOSED

---

# 14. FEDERATION TRUST MODEL

## 14.1 Federation Admission Rule

Federation trust MUST be explicit.

A federated trust domain becomes trusted only through a signed federation trust record issued by the local `ROOT` key.

## 14.2 Federation Preservation Rule

Federation forwarding MUST preserve:

* original emitter identity
* original `signing_context`
* original `message_id`
* original signature

Intermediate federation metadata MUST NOT replace origin signature validation.

## 14.3 Namespace Isolation Rule

The following are mandatory:

* no two federated trust domains may present conflicting `system_id`
* no federated source may issue identities outside its signed namespace delegation
* overlapping namespace claims within the same `system_id` are invalid

## 14.4 Federation Conflict Rule

If two federated sources present:

* the same emitter identity with different signed namespace records
* the same emitter identity with different active public keys
* conflicting cluster or node delegation records

the system MUST:

```text
REJECT BOTH CLAIMS -> ALERT -> REQUIRE OPERATOR RESOLUTION
```

## 14.5 No Trust Re-Signing Rule

An intermediate federated core MAY sign a transport envelope or forwarding record.

It MUST NOT:

* replace the origin signature
* rewrite origin identity
* rewrite origin `message_id`
* create a new trusted origin claim

---

# 15. FAILURE MODEL

## 15.1 Signature Failure

If signature verification fails:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

## 15.2 Trust-Chain Failure

If any chain element is missing, revoked, invalid, unsigned, or ambiguous:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

## 15.3 Rotation Failure

If rotation continuity or activation scope is ambiguous:

```text
REJECT ROTATION -> FAIL-CLOSED -> ALERT
```

## 15.4 Revocation Failure

If revocation state for a required key cannot be determined:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

## 15.5 Root Trust Failure

If the pinned root trust anchor is invalid, missing, or contradicted:

```text
GLOBAL FAIL-CLOSED -> ALERT
```

## 15.6 Historical Trust Failure

If a historical record cannot be validated because the corresponding historical trust snapshot is missing:

```text
FAIL-CLOSED -> ALERT
```

---

# 16. SECURITY MODEL

## 16.1 Verify-Before-Use Rule

Nothing may be parsed, processed, executed, or stored as trusted before cryptographic validation succeeds.

## 16.2 Least-Privilege Key Access Rule

Key usage MUST be limited by:

* key type
* scope delegation
* signing context
* runtime role

Shared unrestricted signing capability is FORBIDDEN.

## 16.3 Offline Root Rule

`ROOT` private keys MUST remain offline except during tightly controlled trust-maintenance operations.

Continuous online root-key availability is FORBIDDEN.

## 16.4 Auditability Rule

The following cryptographic events MUST be durably auditable:

* key generation
* enrollment
* trust bundle admission
* signing operation class
* rotation
* revocation
* verification failure
* trust conflict

## 16.5 No Hidden Trust Rule

The following MUST NOT create trust:

* transport success
* API authentication alone
* TLS success alone
* hostname match
* operator memory
* undocumented local overrides

---

# 17. FORBIDDEN PATTERNS

```text
FORBIDDEN:

- implicit trust
- trust-on-first-use
- unsigned config
- unsigned authority objects
- unsigned key records
- unverifiable keys
- unverifiable rotation
- unverifiable revocation
- multiple active keys for one identity in one verification scope
- key reuse across different identities
- wall-clock validity windows as authoritative trust criteria
- live network trust fetch in authoritative verification
- online CA dependency in authoritative verification
- online OCSP dependency in authoritative verification
- plaintext private-key storage
- exporting protected private keys without explicit signed authorization
- accepting messages before signature verification
- trusting TLS, IP, or location as message validity
- rewriting origin signature during federation forwarding
- deleting historical trust records needed for replay
- mutable trust records
- unsigned namespace records
- unsigned adapter manifests
- hidden trust overrides
```

---

# 18. FILE & FOLDER STRUCTURE (MANDATORY)

## 18.1 Authoritative Crypto Tree

The authoritative cryptographic implementation root MUST be:

```text
/crypto/
  /keys/
    key_manager.go
    key_store.go
  /signing/
    signer.go
  /verification/
    verifier.go
  /rotation/
    rotation_engine.go
  /revocation/
    revocation_engine.go
  /trust/
    trust_chain.go
    bootstrap.go
```

## 18.2 Module Mapping Rule

Every module MUST map to one or more sections of this PRD.

The following mapping is mandatory:

* `/crypto/keys/key_manager.go` -> Sections 4, 5, 6, 7, 10, 11
* `/crypto/keys/key_store.go` -> Sections 6, 7, 10, 11, 15, 16
* `/crypto/signing/signer.go` -> Sections 3, 8, 16
* `/crypto/verification/verifier.go` -> Sections 3, 8, 9, 12, 14, 15, 16
* `/crypto/rotation/rotation_engine.go` -> Sections 7, 10, 15
* `/crypto/revocation/revocation_engine.go` -> Sections 7, 11, 14, 15
* `/crypto/trust/trust_chain.go` -> Sections 7, 9, 12, 14, 15
* `/crypto/trust/bootstrap.go` -> Sections 12, 13, 16

## 18.3 Undefined File Rule

No undefined files are allowed under `/crypto/`.

Any file not listed in Section 18.1 or not added by a future signed PRD revision is invalid.

The presence of an undefined file is:

```text
REJECT BUILD -> FAIL-CLOSED -> ALERT
```

---

# 19. SUMMARY

```text
Cryptographic Trust & Key Lifecycle is the authoritative trust model for Project Mishka.

It MUST:
- use Ed25519 for signatures
- use SHA256 for hashing
- resolve trust only through signed local trust state
- preserve full root-to-subject verification chains
- rotate keys without breaking historical verification
- revoke keys explicitly without deleting history
- preserve origin trust across federation
- fail closed on every trust ambiguity

If trust, signature, rotation, revocation, or chain verification fails:
REJECT -> FAIL-CLOSED -> ALERT
```

---

# 20. KEY USAGE ENFORCEMENT MODEL

## 20.1 Binding Rule

Every key MUST be cryptographically bound to:

* `key_type`
* `authority_scope`
* `allowed_signing_contexts`

The following construction is mandatory:

```text
key_usage_binding_bytes = RFC8785({
  "key_id": key_id,
  "key_type": key_type,
  "authority_scope": authority_scope,
  "allowed_signing_contexts": allowed_signing_contexts,
  "key_epoch": key_epoch
})

key_usage_binding_hash = SHA256(key_usage_binding_bytes)
```

`key_usage_binding_hash` MUST be covered by the signed key record through the key record signature inputs.

## 20.2 Enforcement Rule

At signing time:

* signer MUST verify `signing_context` is allowed for the key
* signer MUST verify `key_type` permits this message class
* signer MUST verify the active delegated `authority_scope` permits this message instance

At verification time:

* verifier MUST verify `signing_context` is allowed for the key
* verifier MUST verify `key_type` permits this message class
* verifier MUST verify the delegated `authority_scope` permits this message instance
* verifier MUST recompute `key_usage_binding_hash` from the resolved signed key record

The message-class permission decision MUST derive only from:

* signed allowed signing-context set
* signed key record
* signed delegation scope
* explicit message-class rules from the owning PRD

Implicit key-use permission is FORBIDDEN.

## 20.3 Violation Rule

If a key is used outside its allowed context, allowed scope, or allowed message class:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

If the signer cannot determine whether the use is allowed:

```text
FAIL-CLOSED -> ALERT
```

---

# 21. KEY COMPROMISE CONTAINMENT MODEL

## 21.1 Detection Trigger

Key compromise containment MAY be triggered only by one or more of the following explicit inputs:

* deterministic anomaly detection result
* signed manual operator action
* cryptographic inconsistency

Unsigned operator action is invalid.

## 21.2 Immediate Containment

Upon compromise declaration:

* the key MUST be marked `COMPROMISED` in effective enforcement state
* the key MUST be added to the revocation set immediately
* all future messages or objects signed by that key MUST be rejected

The effective `COMPROMISED` state MUST be represented by one signed immutable `key_compromise_record`.

`key_compromise_record` MUST contain at minimum:

```json
{
  "key_id": "hex_32_bytes",
  "key_type": "ROOT|CLUSTER|NODE|AGENT|PROBE|ADAPTER",
  "compromise_epoch": 0,
  "activation_scope_id": "string",
  "trigger_type": "ANOMALY_DETECTION|SIGNED_OPERATOR_ACTION|CRYPTOGRAPHIC_INCONSISTENCY",
  "issuer_key_id": "hex_32_bytes",
  "signature": "hex_ed25519"
}
```

`key_compromise_record` MUST be treated as stronger than `ACTIVE` or `RETIRED` status in all trust decisions.

## 21.3 Blast Radius Rule

The system MUST:

* identify all identities signed directly by the compromised key
* identify all descendant trust paths delegated by the compromised key
* mark dependent trust paths as suspicious
* trigger deterministic re-validation of affected trust state

The blast-radius computation MUST depend only on signed local trust state and retained historical trust records.

If blast radius cannot be determined completely:

```text
FAIL-CLOSED -> ALERT
```

## 21.4 Containment Priority

Containment MUST take precedence over availability.

The following are mandatory:

* new trust admission under a compromised path MUST stop immediately
* ambiguous descendants of the compromised key MUST be rejected
* service continuity MUST NOT override containment

If containment and availability conflict:

```text
CONTAINMENT WINS -> FAIL-CLOSED -> ALERT
```

## 21.5 Historical Preservation Rule

Containment MUST NOT delete historical trust evidence.

The following MUST remain retained:

* compromised key record
* revocation record
* compromise record
* historical trust snapshots

Historical verification MUST still resolve through the retained historical trust snapshot for its original verification scope.

---

# 22. SIGNATURE REPLAY PROTECTION MODEL

## 22.1 Replay Constraint Rule

A valid signature MUST NOT be reusable outside its:

* `signing_context`
* `canonical_payload_bytes`
* identity scope

For message classes with stricter binding rules defined by other authoritative PRDs, those stricter rules remain mandatory.

## 22.2 Binding Rule

Signature validity MUST bind to:

* `canonical_payload_hash`
* `signing_context`
* `key_id`
* `key_epoch`

The authoritative signature-validity tuple is:

```text
signature_validity_scope =
  canonical_payload_hash ||
  UTF8(signing_context) ||
  key_id ||
  UINT64_BE(key_epoch) ||
  verification_scope_id
```

For identity-bound message classes, `verification_scope_id` MUST include the message-class identity scope defined by the owning PRD.

A signature is valid only for exactly one `signature_validity_scope`.

## 22.3 Replay Violation

If a signature is reused across:

* different payload
* different context
* different identity

```text
REJECT -> FAIL-CLOSED -> ALERT
```

If the verifier cannot prove that the signature is being evaluated in the original validity scope:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

## 22.4 Cross-Class Replay Rule

Context reuse across incompatible message classes is FORBIDDEN.

The following are mandatory:

* a signature valid for one `signing_context` MUST NOT validate another `signing_context`
* a signature valid for one identity scope MUST NOT validate another identity scope
* a signature valid for one key epoch MUST NOT validate another key epoch

## 22.5 Replay Detection Rule

Replay detection MUST depend only on:

* signature-validity scope
* retained verification metadata
* retained trust snapshot hash
* message-class replay identifiers where the owning PRD defines them

Wall-clock time, transport path, and source location MUST NOT determine replay validity.

---

# 23. TRUST SNAPSHOT BINDING MODEL

## 23.1 Snapshot Definition

Trust snapshot = deterministic set of:

* key records
* rotation records
* revocation records
* trust chain state

The snapshot MUST be resolved for one explicit verification scope.

## 23.2 Snapshot Hash

The following constructions are mandatory:

```text
canonical_trust_state_bytes = RFC8785({
  "verification_scope_id": verification_scope_id,
  "key_records": ordered_key_records,
  "rotation_records": ordered_rotation_records,
  "revocation_records": ordered_revocation_records,
  "trust_chain_state": canonical_trust_chain_state
})

trust_snapshot_hash = SHA256(
  canonical_trust_state_bytes
)
```

The ordered sets inside `canonical_trust_state_bytes` MUST be deterministically ordered by:

```text
key_id ASC, key_epoch ASC
```

for record families that contain those fields, and by canonical byte order otherwise.

## 23.3 Storage Binding Rule

Every verified record MUST bind to:

* `trust_snapshot_hash`
* verification scope

This binding MUST be durably retained in authoritative verification metadata, admission metadata, or storage metadata for that record.

If a verified record lacks this binding:

```text
FAIL-CLOSED -> ALERT
```

## 23.4 Replay Rule

Replay MUST use the same `trust_snapshot_hash`.

If snapshot differs:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

If the retained `trust_snapshot_hash` cannot be resolved to retained trust state:

```text
FAIL-CLOSED -> ALERT
```

## 23.5 Historical Verification Rule

Historical verification MUST resolve against the retained `trust_snapshot_hash` bound to the original verification event.

Current active trust state MUST NOT replace the retained historical trust snapshot for historical verification.

## 23.6 Snapshot Completeness Rule

If any required key record, rotation record, revocation record, or trust-chain element is missing from the resolved snapshot:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

---

# 24. HARDWARE ATTESTATION MODEL

## 24.1 Attestation Requirement

Keys generated in:

* TPM
* HSM

MUST provide attestation proof.

If a key is declared as hardware-generated, hardware attestation is mandatory.

## 24.2 Attestation Binding

The authoritative key record or its signed companion attestation record MUST include:

* `attestation_type`
* `attestation_proof_hash`

The following constructions are mandatory:

```text
attestation_proof_hash = SHA256(attestation_proof_bytes)
```

`attestation_type` MUST be explicit and versioned.

## 24.3 Verification Rule

Verifier MUST validate:

* attestation proof
* hardware trust root

The following are mandatory:

* hardware root trust anchors MUST be locally provisioned signed trust state
* attestation verification MUST be deterministic
* attestation verification MUST NOT depend on live network lookup in authoritative trust paths
* attested key public bytes MUST match the public key in the signed key record exactly

## 24.4 Failure Rule

If attestation fails or is missing:

```text
REJECT KEY -> FAIL-CLOSED -> ALERT
```

If attestation proof is present but cannot be verified against the local hardware trust root:

```text
REJECT KEY -> FAIL-CLOSED -> ALERT
```

## 24.5 Attestation Scope Rule

Hardware attestation proves key-protection origin only within the declared attestation scope.

Attestation MUST NOT be interpreted as:

* message validity by itself
* identity validity by itself
* delegation validity by itself

Trust admission still requires full key-record, delegation-chain, revocation, and signing-context verification.

---

# 25. CRYPTOGRAPHIC PERFORMANCE MODEL

## 25.1 Acceleration Rule

Cryptographic operations MAY use:

* batch Ed25519 verification
* SIMD acceleration
* GPU acceleration if available

Acceleration is permitted only as a performance optimization.

Acceleration MUST NOT introduce:

* alternate trust semantics
* alternate acceptance criteria
* alternate ordering
* alternate signature-validity logic

## 25.2 Determinism Rule

Acceleration MUST NOT change:

* verification result
* ordering
* signature validity outcome

The same inputs MUST produce identical outputs across:

* CPU scalar
* CPU SIMD
* GPU execution

The following are mandatory:

* canonical input bytes MUST remain identical across all modes
* candidate-key resolution MUST remain identical across all modes
* trust-chain resolution MUST remain identical across all modes
* revocation evaluation MUST remain identical across all modes
* final accept or reject result MUST remain identical across all modes

## 25.3 Fallback Rule

If accelerated verification fails or is ambiguous:

* fallback to single verification MUST occur

The following are mandatory:

* fallback MUST use the exact same canonical input bytes
* fallback MUST use the exact same local trust state
* fallback MUST preserve the same verification ordering constraints

If deterministic single verification cannot complete:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

## 25.4 Failure Rule

If verification result differs between modes:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

If acceleration produces:

* inconsistent member isolation
* inconsistent signature-validity result
* inconsistent key-resolution result
* inconsistent trust-chain result

the accelerated result is invalid.

---

# 26. KEY ID CANONICALIZATION & INVARIANT RULE

The `key_id` derivation defined in Section 4.1 is authoritative and MUST NOT be altered.

The following invariants are mandatory:

1. `public_key` MUST be canonical byte representation

   * no encoding variation allowed
   * no DER versus raw ambiguity allowed
   * no whitespace or formatting variance allowed
   * exact byte equality is required
   * for Ed25519, `public_key` MUST be the canonical raw 32-byte public key bytes
   * where `public_key` is rendered as text, it MUST be lowercase hexadecimal of those exact raw bytes

2. `key_type` MUST be exact canonical string

   * it is case-sensitive
   * no aliasing is permitted
   * it MUST equal one of the exact Section 4.1 enumerated values byte-for-byte

3. `scope_id` MUST be canonical and globally unique within its trust domain

   * normalization rules MUST be defined and enforced before Section 4.1 derivation
   * `scope_id_bytes` for Section 4.1 derivation MUST equal `UTF8(scope_id)`
   * leading or trailing whitespace is FORBIDDEN
   * embedded carriage return, line feed, or tab normalization is FORBIDDEN
   * equivalent scope representations MUST NOT produce different `key_id` values

4. `key_epoch` MUST be strictly monotonic per key lineage

   * for this rule, `key_lineage` MUST mean the exact logical subject identified by `(key_type, scope_id, authority_scope)`
   * reuse of `key_epoch` with different `public_key` in the same `key_lineage` is FORBIDDEN
   * reuse of `key_epoch` with different `scope_id` in the same `key_lineage` is FORBIDDEN

5. identical Section 4.1 inputs MUST always produce identical `key_id` across:

   * nodes
   * languages
   * architectures

6. different Section 4.1 inputs MUST NEVER be treated as the same `key_id`

   * collision resistance relies on SHA256 and MUST be preserved
   * any observed collision MUST be treated as a critical integrity event

If any canonicalization ambiguity exists:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

---

# 27. KEY ID STABILITY RULE

Once a `key_id` is assigned:

* it MUST be immutable
* it MUST NOT be recomputed using altered Section 4.1 inputs
* it MUST remain stable across:
  * federation
  * replay
  * storage
  * verification

The following are mandatory:

* the same canonical Section 4.1 input tuple MUST always resolve to the same `key_id`
* federation forwarding MUST preserve the original `key_id`
* replay verification MUST preserve the original `key_id`
* storage and retrieval MUST preserve the original `key_id` byte-for-byte
* verification logic MUST reject any attempt to reinterpret `key_id` under a different canonical input tuple

Any recomputation that produces a different `key_id` for the same canonical Section 4.1 input tuple is:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

---

# 30. TRUST STATE RESOLUTION LOCK (CRITICAL)

All verification operations MUST execute against exactly one resolved `trust_snapshot`.

The following are mandatory:

1. single snapshot binding

   * verification MUST resolve exactly one `trust_snapshot_hash`
   * all key records, rotation records, revocation records, and trust-chain inputs MUST derive from that snapshot only
   * mixing records from multiple snapshots is FORBIDDEN

2. immutable verification scope

   * `verification_scope_id` MUST be fixed before verification begins
   * verification MUST NOT switch scope mid-execution
   * verification MUST NOT fall back to alternative trust state

3. dependency lock

   the following inputs MUST be locked before signature verification:

   * key record
   * issuer chain
   * rotation state
   * revocation state
   * allowed signing contexts

   all inputs MUST be derived from the same `trust_snapshot_hash`

4. no dynamic trust resolution

   verification MUST NOT:

   * fetch missing trust records
   * resolve newer trust state
   * fall back to alternative issuer chains
   * attempt partial verification

5. failure rule

   if trust resolution is:

   * missing
   * ambiguous
   * partially available
   * cross-snapshot inconsistent

```text
REJECT -> FAIL-CLOSED -> ALERT
```

---

# 31. FEDERATION TRUST CONSISTENCY LOCK

Federated verification MUST preserve original trust binding.

The following are mandatory:

1. original trust snapshot preservation

   * forwarded records MUST retain original `trust_snapshot_hash`
   * receiving system MUST verify using that same snapshot

2. no re-binding

   federation MUST NOT:

   * rebind records to a different trust snapshot
   * re-evaluate using local active trust state
   * replace issuer chain

3. consistency rule

   the following MUST remain identical across federation:

   * `key_id`
   * `key_epoch`
   * `trust_snapshot_hash`
   * `verification_scope_id`

4. divergence rule

   if receiving system cannot resolve the original `trust_snapshot_hash`:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

---

# 32. KEY DERIVATION VALIDATION GATE (CRITICAL)

Before computing `key_id` using Section 4.1, the system MUST execute a deterministic validation gate.

The following sequence is mandatory:

1. validate `public_key`

   * it MUST be exact canonical byte representation as defined in Section 26
   * it MUST be exactly 32 bytes for Ed25519
   * it MUST NOT be decoded from ambiguous encodings

2. validate `key_type`

   * it MUST match the exact allowed enumeration
   * it MUST be case-sensitive
   * it MUST NOT allow alias values

3. validate `scope_id`

   * it MUST be normalized before use
   * it MUST be UTF-8 encoded
   * it MUST NOT contain leading or trailing whitespace
   * it MUST NOT contain alternate canonical forms

4. validate `key_epoch`

   * it MUST be explicitly present
   * it MUST be `UINT64`
   * it MUST satisfy monotonic lineage constraints

5. validate `authority_scope`

   * it MUST match signed delegation scope
   * it MUST NOT be inferred or defaulted

6. canonicalization verification

   * all Section 26 canonicalization rules MUST be satisfied
   * any ambiguity MUST be treated as invalid input

Only after all validations succeed:

```text
PROCEED -> key_id derivation (Section 4.1)
```

If any validation fails:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

---

# 33. KEY DERIVATION TRACEABILITY (FORENSIC INTEGRITY)

Every derived `key_id` MUST be traceable to its exact canonical derivation inputs.

The following MUST be retained in authoritative or auditable metadata:

* canonical `public_key` bytes
* canonical `key_type`
* canonical `scope_id` bytes
* `key_epoch`
* `authority_scope`

The following are mandatory:

1. traceability binding

   * stored derivation inputs MUST exactly match the inputs used in Section 4.1
   * no transformation is permitted after derivation

2. verification recomputation

   * any system MUST be able to recompute `key_id` from stored inputs
   * recomputed `key_id` MUST equal stored `key_id` exactly

3. cross-system validation

   * independent systems MUST be able to verify identity equivalence using only canonical inputs

4. forensic requirement

   * absence of derivation traceability for any `key_id` is invalid

If derivation traceability is missing, ambiguous, or mismatched:

```text
REJECT -> FAIL-CLOSED -> ALERT
```

---

# 34. KEY DERIVATION TRACEABILITY STORAGE BINDING

Derivation traceability defined in Section 33 MUST be durably bound to authoritative storage.

The following are mandatory:

1. storage binding location

   derivation traceability MUST be stored in one or more of:

   * key record extended metadata
   * authoritative trust storage
   * append-only audit log

2. immutability

   stored derivation inputs MUST be:

   * append-only
   * immutable after write
   * cryptographically bound to the key record or audit entry

3. binding construction

```text
traceability_binding_hash = SHA256(
  canonical_public_key_bytes ||
  UTF8(key_type) ||
  UTF8(scope_id) ||
  UINT64_BE(key_epoch) ||
  UTF8(authority_scope)
)
```

   `traceability_binding_hash` MUST be included in:

   * key record signature input OR
   * associated signed metadata object

4. retrieval requirement

   any verification system MUST be able to retrieve derivation inputs deterministically

5. failure rule

   if traceability storage is:

   * missing
   * mutable
   * not cryptographically bound
   * inconsistent with key record

```text
REJECT -> FAIL-CLOSED -> ALERT
```
