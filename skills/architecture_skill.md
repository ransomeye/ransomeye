## 1. Purpose & Authority

This document defines **system-wide laws** for RansomEye: global invariants, root of trust, fail-closed rule, forbidden constructs, and **exclusive ownership** of each major concept by exactly one PRD.

**PRD-01 does not specify:** algorithms, schemas, file paths, repository layout, protobuf fields, service implementation language, CI commands, or operational runbooks. The single exception is the **normative port registry** in **§3.2**, which fixes system-wide service bindings to prevent contradictory deployment interpretations. Those concepts otherwise belong **only** to the owning PRD in the **Concept ownership** table. **No dual authority:** if a normative rule appears elsewhere, it must be a strict specialization of this document, never a contradiction.

---

## 2. Global Invariants

The following are **mandatory** for every production configuration and release:

| Invariant | Law |
|-----------|-----|
| **TLS 1.3 only** | Every encrypted channel (HTTPS, WSS, gRPC mTLS, PostgreSQL TLS) **must** negotiate TLS **1.3** only. No older TLS version may be offered or accepted. |
| **IPv4 loopback only** | Internal control-plane and data-plane services that are defined as loopback-bound **must** use **`127.0.0.1`** only. Binding those services to `0.0.0.0`, `[::1]`, `[::]`, or any non-loopback address for those roles is forbidden. |
| **No event loss (strict)** | No event may be dropped under any condition. Each event **must** either: **(a)** be durably persisted, **or** **(b)** be backpressured upstream until persistence succeeds. **Logging or counting dropped events is NOT acceptable.** Operational detail for persistence and back-pressure is owned solely by **PRD-16**; this law is not satisfied by recording a “drop.” |
| **No float math in AI** | AI inference paths **must not** use hardware floating-point types for Bayesian fusion, posteriors, or signal likelihoods. Fixed-point / integer-only semantics **must** apply per **PRD-07**. |
| **No unsigned execution** | No configuration, migration bundle, model artifact, or update payload may be **parsed or applied** without prior successful cryptographic verification per **PRD-02**, **PRD-03**, **PRD-05**, and **PRD-18**. Execution of operational logic on unverified bytes is forbidden. |

---

## 3. Root of Trust

| Rule | Law |
|------|-----|
| **Config signature is the ONLY root of trust** | The **sole** authoritative source for what to trust at runtime (whom to connect to, which keys and fingerprints to accept, and which role a component plays) is a **cryptographically signed configuration payload** verified **before** use. No other artifact (environment, CLI, registry alone, DNS alone, implicit default) may establish trust. Detail: **PRD-02**, **PRD-03**. |
| **No environment override** | Process environment variables **must not** override, bypass, or replace signed configuration for trust, discovery, identity, or security parameters. If a process detects an attempt to override signed configuration via the environment, it **must** exit unsuccessfully. |
| **No fallback** | There is **no** alternate trust path: no trust-on-first-use, no “disable TLS,” no “allow insecure,” no downgrade to unsigned config, no optional skip of signature verification. Failure to verify **must** result in refusal to operate. |

### 3.1 Mandatory trust bindings

The signed configuration **must** bind, at minimum:

- **PKI root fingerprint** (trust anchor for internal TLS and mTLS),
- **Database TLS fingerprint** (server identity for the primary relational store),
- **WORM public key** (forensic verification root for sealed evidence),
- **System identity hash** — a **single** digest derived **deterministically** from **all** bindings above (and any other trust anchors declared mandatory in **PRD-02**), such that any change to any binding changes the system identity hash.

**No runtime component** may establish trust **outside** these bindings. Trust decisions **must** reduce to: signature valid + bindings match live material + system identity hash consistent. Anything else is **unsigned execution** or **fallback** and is forbidden.

### 3.2 Port Registry (Normative)

The following service ports and bindings are **fixed system-wide**:

| Port | Service | Binding | Protocol | mTLS | Owner |
|------|---------|---------|----------|------|-------|
| `443` | SOC UI (nginx) | `0.0.0.0` | HTTPS / WSS | TLS 1.3 | **PRD-17** |
| `8443` | Core REST API | `127.0.0.1` | HTTPS / WSS | TLS 1.3 | **PRD-06** |
| `50051` | Core gRPC | LAN | gRPC | TLS 1.3 | **PRD-06** |
| `50052` | AI Engine | `127.0.0.1` | gRPC | none | **PRD-07** |
| `50053` | SINE Engine | `127.0.0.1` | gRPC | none | **PRD-08** |
| `5432` | PostgreSQL | `127.0.0.1` | TCP | TLS 1.3 | **PRD-05** |
| `6379` | Redis | `127.0.0.1` | TCP | AUTH | **PRD-06** |

Rules:

- Ports **MUST NOT** be configurable via environment variables.
- Ports **MUST** originate only from signed configuration (**PRD-02**).
- Any implementation that exposes these services on conflicting ports or bindings without a signed configuration change is non-compliant.

---

## 4. Fail-Closed System Rule

Any violation of a global invariant (**§2**), root-of-trust rule (**§3**), or forbidden construct (**§6**) **must**:

1. **Terminate the violating component** immediately with a non-success exit status; and  
2. **Cause all other components to reject its communication** (no continued session, ingress, or data acceptance from that component until trust and invariants are restored by a controlled, verified procedure).

**No partial-trust operation is permitted.** A component that has violated these laws **must not** be treated as partially trustworthy.

---

## 5. Architectural Boundaries (Laws Only)

- **Core exclusivity:** Only the Core Engine may open connections to the primary relational store and the cache store used for session and coordination; other components **must** use Core’s APIs. (Owner: **PRD-06**.)
- **Boundary hardening (mandatory):** **Direct** database or cache access **outside** Core is a **P0** violation. The platform **must** enforce this by **credentials** (no credentials issued to non-Core components for those stores) **and** **network isolation** (those stores reachable only where Core runs). Stated operational rules live in **PRD-06**, **PRD-17**, and **PRD-05** without duplicating this law.
- **AI exclusivity:** Probabilistic threat scoring is performed only in the AI Detection Service; Core **must not** reimplement fusion. (Owner: **PRD-07**.)
- **Deception exclusivity:** The deception signal dimension **must** be produced only by the deception subsystem. (Owner: **PRD-14**.)
- **Provisioning exclusivity:** Creation of database **roles** is **only** permitted in installer-driven provisioning, never in long-running application startup. (Sole owner: **PRD-17**.)

---

## 6. Forbidden Constructs

The following are **forbidden** in any shipping artifact (code, schema, config, metric name, migration, log category):

| Construct | Law |
|-----------|-----|
| **`graph_nodes`, `graph_edges`** | These relations **must not** exist. Persisted graph summaries **must** use the approved path-summary mechanism only (**PRD-05**). |
| **TLS 1.2** (or lower) | Offered or accepted TLS versions below **1.3** are forbidden. |
| **IPv6 loopback** | Service binds of the form `[::1]` or dual-stack wildcard that exposes loopback-only services on IPv6 are forbidden for those services. |
| **`event_drop_count`** | This identifier **must not** appear as a column, field, or metric name. |
| **Drop accounting as substitute for retention** | Any log line, metric, or UI field whose purpose is to **count or acknowledge dropped events** is forbidden; it does not satisfy **§2** and is **not** an acceptable substitute for persistence or upstream back-pressure. |
| **Runtime `CREATE ROLE`** | Application processes (including Core) **must not** execute role-creation DDL at runtime. (**PRD-17**.) |

---

## 7. Concept Ownership Table

Each **concept** has **exactly one** owning PRD. Other PRDs may **reference** the owner; they **must not** redefine the concept.

### 7.1 Enforcement

- If a PRD **defines** (normatively specifies behavior of) a concept **it does not own** per the table below → **P0 defect**; the document **must** be corrected so only the owner defines that concept.
- **Cross-references must not redefine behavior.** A reference may point to the owner; it **must not** restate or alter the owner’s normative rules.

| Concept | Sole owner |
|---------|------------|
| Normative service port registry and fixed bindings | **PRD-01** |
| Cryptographic primitives, PKI roles, config signature format, WORM key material rules | **PRD-02** |
| Bootstrap ordering, verify-before-parse sequencing | **PRD-03** |
| Identity: SCRAM vs mTLS, CN non-authoritative, `agent_id`, `boot_session_id`, Lamport | **PRD-04** |
| Database schema, RLS, migrations, signed migration manifest, forbidden column names | **PRD-05** |
| Core Engine behavior, queues, ingress, exclusivity of DB access | **PRD-06** |
| Deterministic / fixed-point AI, signals, fusion, LOO, drift | **PRD-07** |
| SINE optional narrative inference | **PRD-08** |
| Policy, AEC, enforcement governance | **PRD-09** |
| Protobuf and non-SOC REST / WebSocket transport contracts | **PRD-10** |
| SOC UI authentication, RBAC, UI response envelope, pagination, CSRF / CSP / XSS controls, and endpoint rate limiting | **PRD-21** |
| Key generation, distribution, activation, expiry, rotation, revocation, and decommission lifecycle | **PRD-22** |
| Linux agent | **PRD-11** |
| Windows agent | **PRD-12** |
| Network probes (DPI and infrastructure collectors) | **PRD-13** |
| Deception and `signal_deception` | **PRD-14** |
| Forensics, WORM storage semantics, Merkle, legal readiness | **PRD-15** |
| Zero-loss pipeline, back-pressure, replay | **PRD-16** |
| Installer, deployment, **sole** DB role creation authority | **PRD-17** |
| Air-gap updates, signed bundles | **PRD-18** |
| Resource limits, degradation ordering | **PRD-19** |
| Testing, validation, release gates | **PRD-20** |

---

## 8. Consistency Rule

If any other PRD appears to conflict with **§2–§7**, the conflict **must** be resolved by changing the other PRD; **PRD-01** prevails as the **system law** layer.

---

