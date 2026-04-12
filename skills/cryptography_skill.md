## 1. Purpose

This document is the **sole authority** for cryptographic trust roots, TLS rules, configuration signing, canonical configuration bytes, system identity hashing, secret-file integrity expectations, and trust boundaries for transport. Identity semantics for runtime actors are defined in **PRD-04**.

**PRD-02 permits no optional signature algorithms, no YAML configuration wire format, and no alternate config-signing keys.**

**Alignment:** **PRD-01 §3.1** (*Mandatory trust bindings* / system identity) is defined **exactly** as in this document. **PRD-01** states system-level laws; **PRD-02** is the **normative definition** of bindings, canonical bytes, and **system_identity_hash**. No other document may redefine them.

---

## 2. Root of Trust

### 2.1 Configuration Signature Is the Only Root of Trust

1. No operational parameter may be trusted unless it appears inside a **cryptographically signed configuration** whose **Ed25519** signature has been verified **before** any use of the parsed content (**PRD-03**).
2. **Environment variables, process environment, shell exports, systemd `Environment=`, and interactive prompts** must not override signed configuration for discovery, trust, or identity. On conflict, the process **must exit unsuccessfully**.
3. Secrets (database passwords, Redis AUTH, master key material) are **authorization inputs**, not roots of trust. They **must** be referenced by **path** from signed configuration only, with **integrity validation** before use (**§8**).
4. **No external trust source** is permitted: trust **must** be derivable solely from verified signed configuration and the bindings in **§3**, **§6**, and **§8**. Trust **must not** depend on public CAs, DNS, DHCP, NTP, vendor phone-home, or operator memory.

---

## 3. Single Signing Authority (Configuration)

1. Each deployment has **exactly one** **configuration signing key** (Ed25519 private key used **only** for configuration signatures computed per **§4.3**).
2. There is **no** alternate config signer and **no** second valid key for the same deployment generation.
3. After initialization, the configuration signing key is **immutable** for that deployment epoch: it **must not** be rotated in place by runtime services. A new key implies a new deployment identity epoch and **must** be handled only through controlled procedures (**PRD-17**, **PRD-18**).

**Distinction:** TLS PKI (Root CA / Intermediate CA / leaf certificates) exists for **transport authentication**. It does **not** replace the **configuration signing key**. TLS keys **must not** sign operational JSON configuration.

### 3.1 Configuration signing key binding to PKI root

1. The **Ed25519 fingerprint** (or the single defined **SHA-256** fingerprint of the **Ed25519 public key**) of the configuration signing key **must** be present in signed configuration.
2. That fingerprint **must** be **bound** to the deployment **PKI root fingerprint** by an explicit field in signed configuration (e.g. `config_signing_key_bound_to_pki_root_fingerprint`) such that the binding **must** match the deployment’s PKI root and **must** be verified **before** any configuration payload is trusted.
3. Verification **must** succeed using **only** signed configuration bytes and locally present public material (PKI root cert, config signing public key); **no external trust source** (**§2.1**).
4. A configuration whose signing key fingerprint **cannot** be verified against the bound PKI root **must** be rejected; **fail-closed**.

---

## 5. Canonical Configuration Bytes (Normative)

The signed payload **must** be **JSON** only. **YAML is prohibited** as a wire format for signed configuration.

**Canonicalization rules** (exact; violations **must** fail verification):

| Rule | Requirement |
|------|-------------|
| Encoding | UTF-8 |
| Structure | JSON object at root |
| Key order | All object keys at every depth **lexicographically sorted** |
| Whitespace | **No** ASCII space, tab, or carriage return inside the JSON document; **no** whitespace between tokens. **Single** `\n` (U+000A) **only** as the final end-of-file newline after the closing `}` of the root object. |
| Numbers | **Integer only.** Floating-point JSON numbers are **prohibited** anywhere in signed configuration. |
| Strings | UTF-8; escaping per JSON standard |

The field **`integrity.signature`** (or the single field holding the detached signature) **must be omitted** from the **canonical_payload_bytes** that are input to the signing pipeline (**§4**).

**Ed25519** signatures MUST be computed per **§4.3** using:
- `signing_context` = `ransomeye:v1:config:signed_config`
- `canonical_payload_bytes` = the **full** canonical JSON (**§5**) of every field **except** **`integrity.signature`**, including **`config_version`**, **`schema_version`**, and **`system_identity_hash_expected`** (**§10**).

The **`system_identity_hash`** (**§6**) is **not** the same byte string: it uses **`canonical_config_bytes_for_identity`**, which **omits** **`integrity.signature`** **and** **`system_identity_hash_expected`**, then concatenates with anchor fingerprints per **§6.1**—preventing circular dependence while binding the rest of config and anchors to the expected hash.

---

## 6. System Identity Hash

### 6.1 Definition

```
system_identity_hash = SHA-256(
    canonical_config_bytes_for_identity ||
    pki_root_fingerprint ||
    db_fingerprint ||
    worm_public_key
)
```

Where:

- **`canonical_config_bytes_for_identity`** — UTF-8 octets of the canonical JSON per **§5** containing **all** signed fields **except** `integrity.signature` **and** **`system_identity_hash_expected`**, with lexicographic key order and the single trailing newline. (**Exclusion** of `system_identity_hash_expected` avoids circular dependence; the hash commits to the rest of config plus anchors.)
- **`pki_root_fingerprint`** — SHA-256 over the deployment-defined encoding of the PKI **root** trust anchor (**PRD-17**).
- **`db_fingerprint`** — the bound **database TLS** server fingerprint.
- **`worm_public_key`** — the **32-byte** Ed25519 WORM **public** key.

### 6.2 Required field in signed configuration

Signed configuration **must** include **`system_identity_hash_expected`**: a JSON string whose value is **64** lowercase hexadecimal characters (SHA-256 output).

### 6.3 Validation (fail-closed)

1. After signature verification, the runtime **must** compute **`system_identity_hash`** using **§6.1** from the **same** canonical bytes and anchor material loaded for the session.
2. The runtime **must** compare **octet-for-octet** (or case-normalized hex) **`system_identity_hash`** to **`system_identity_hash_expected`**.
3. **Mismatch → fail-closed:** immediate process termination with non-success status. **No** continuation, **no** partial trust.

### 6.4 Session and telemetry

1. **Must** be computed at **bootstrap** immediately after signature verification and **§6.3** equality.
2. **Must** be attached to **telemetry** on every telemetry-bearing message (**PRD-10**).
3. **Must** be **immutable for the lifetime of the process session** (one value from successful bootstrap until process exit).

---

## 7. PKI Hierarchy (Transport Only)

| Layer | Role |
|-------|------|
| Root CA | Trust anchor for issued chains |
| Intermediate CA | Issues server and client leaf certificates |
| Leaf certificates | Core server, agents, probes |

- **mTLS** (TLS **1.3** only) for agent/probe → Core (**PRD-04**, **PRD-10**).
- **PostgreSQL** server identity: TLS **1.3**; fingerprint pinned via signed configuration (**PRD-03**, **PRD-05**).
- **Subject CN** is **not** an authorization identifier (**PRD-04**).

TLS PKI material **must not** be conflated with the **configuration signing key** (**§3**).

---

## 8. Secret Integrity

1. Signed configuration **must** include, for every referenced secret file path, an **integrity reference**: **SHA-256** hex digest of the file contents expected at runtime.
2. Before opening a secret file for use, the runtime **must** read the file, compute SHA-256, and **must** compare to the digest in signed configuration.
3. **Hash mismatch → immediate termination** of the process with non-success status. **No retry, no fallback,** and **no** alternate code path that uses the secret.
4. Secret files **must not** be trusted on path alone.

---

## 9. Transport Security Rules

| Channel | Requirement |
|---------|-------------|
| Browser ↔ nginx | TLS **1.3** only |
| Agent/Probe ↔ Core | TLS **1.3** only; mTLS mandatory |
| Core ↔ PostgreSQL | TLS **1.3** only; fingerprint binding per signed config |

### 9.1 Redis (non–trust-bearing only)

**Redis is non–trust-bearing only.** There is **no** optional trust mode for Redis.

| Law | Requirement |
|-----|-------------|
| **Non–trust-bearing** | Redis **must not** store or relay roots of trust, signed configuration, signature verification results, WORM private material, or **`system_identity_hash`**. Redis **must not** be used for **identity**, **policy**, or **trust decisions**. |
| **Loopback only** | Redis **must** listen on **`127.0.0.1`** only in production; clients **must** connect to **`127.0.0.1`** only. |
| **No TLS requirement** | Because Redis is **strictly** non–trust-bearing, **TLS to Redis is not required**. This **does not** weaken the global **TLS 1.3** invariant for **trust-bearing** channels (**PRD-01**). |

### 9.2 Loopback plaintext (Core ↔ AI ↔ SINE)

- gRPC between Core, AI, and SINE on **`127.0.0.1`** may be **plaintext**.
- These channels are **non-trust channels**: they **must not** carry **trust decisions** (no signatures, no roots of trust, no “trust this peer” outcomes). Trust is already established **before** operational traffic uses these hops (**PRD-01**, **PRD-03**).

---

## 10. Configuration Versioning

Every signed configuration document **must** include:

| Field | Type | Law |
|-------|------|-----|
| `schema_version` | JSON integer | Monotonic schema epoch; verifier **must** reject unknown schema versions. |
| `config_version` | JSON integer | Monotonic configuration revision within a schema epoch. |
| `system_identity_hash_expected` | JSON string (64 hex) | **§6** |

**Floating-point values are prohibited** in signed JSON (**§5**).

---

## 11. WORM & Evidence Keys

| Asset | Algorithm | Notes |
|-------|-----------|--------|
| WORM signing | Ed25519 | Private key path referenced from signed config; public key participates in **§6** |
| Tenant DEKs | AES-256-GCM | Master key file integrity **§8** |
| Bundles / models | Per **PRD-18** | **PRD-18** must not introduce non-Ed25519 configuration signatures |

WORM private key **must not** appear in logs or database rows.

---

## 12. Prohibited

- TLS 1.2 or lower; trust decisions on plaintext WAN paths.
- YAML as signed configuration wire format.
- Unsorted JSON keys; insignificant whitespace inside JSON; floating-point numbers in signed JSON.
- ECDSA for configuration signatures.
- ECDSA (all variants) anywhere as a trust primitive.
- RSA anywhere as a trust primitive.
- HMAC as a trust primitive or primary signature.
- More than one active configuration signing key per deployment epoch.
- Runtime rotation of the configuration signing key without a defined deployment epoch change.
- Trust-on-first-use for Core certificate.
- Using certificate **Subject CN** as database principal or agent identity.
- Carrying trust decisions on loopback plaintext channels (**§9.2**).
- Trust-bearing use of Redis; Redis TLS as a substitute for trust-bearing semantics.
- Retry or fallback after secret integrity hash mismatch (**§8**).
- Python-based SINE execution.
- Event dropping under any condition.
- Environment variable overrides for secrets, ports, or cryptographic configuration.

Hard assertion:
Any implementation using **ECDSA**, **RSA**, **HMAC as a primary signature or trust primitive**, **Python SINE runtime**, or **drop-based queue logic** MUST be rejected as non-compliant.

---

## 13. Relationship to Other Documents

- **PRD-01:** System laws; **§3.1** bindings and **system identity hash** are **exactly** as defined in **§6** and **§3.1** of this document.
- **PRD-03:** Verify-before-parse ordering.
- **PRD-04:** SCRAM vs mTLS; CN unused.
- **PRD-17:** Installer generates exactly one configuration signing key per deployment epoch, binds it to the PKI root in signed configuration, emits canonical JSON, computes signatures per **§4.3** (with **`canonical_payload_bytes`** per **§5**), and installs secret files with digests.

---

*End of PRD-02*
