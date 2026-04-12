## 1. Purpose

**Sole authority** for release certification: required tests, CI gates, and validation of global invariants (signed config, no env override, fixed-point AI, migrations signed, forbidden schema names, **PRD-16** no-loss). **Must not** weaken **determinism** guarantees (**PRD-07**, **PRD-09**) or **forensic** guarantees (**PRD-15**, **PRD-16**).

---

## 2. Mandatory Test Classes (Summary)

| Area | Requirement |
|------|-------------|
| Config trust | Load tampered config → must exit ≠0 before parse (**PRD-02**, **PRD-03**) |
| Cross-impl Bayes | Go ↔ Rust ↔ Python parity: **exact** integer equality and byte-equivalent canonical outputs on shared deterministic fixtures (**PRD-07**, **PRD-10**) |
| Merkle | RFC 6962 vectors + odd-leaf promotion (**PRD-15**) |
| mTLS | Handshake fails on wrong CA / expired cert (**PRD-04**, **PRD-10**) |
| PostgreSQL | Rejects TLS 1.2 client (**PRD-01**) |
| Loopback bind | No `[::1]` on roles defined loopback-only (**PRD-01**, **PRD-17** §10) |
| Migrations | Tampered SQL hash or bad manifest **Ed25519** → abort (**PRD-05** §4) |
| WORM triggers | UPDATE/DELETE rejected where immutable (**PRD-05**, **PRD-15**) |
| Intel | No physical DELETE route (**PRD-05**) |
| Buffer under stress | Core overload → **append-only hash-chained** endpoint buffer growth (**PRD-11** §8, **PRD-12** §8, **PRD-16** §4), **no** silent drop |
| **Forbidden symbol** | Source must not contain `event_drop_count` identifier |

**Additional** mandatory categories: **§3–§13**.

---

## 3. End-to-End Determinism Test

| Law | Requirement |
|-----|-------------|
| **Scope** | Golden vectors traverse **agent/probe → Core → AI → DB** (or offline parity path) with **identical** scaled integers, hashes, and canonical JSON bytes for forensic fields (**PRD-07** §15, **PRD-05** §6, **PRD-10** §8). |
| **Pass** | **Zero** tolerance on integer outputs; signature and Merkle bindings unchanged across runs with same signed config revision. |

### 3.1 Cross-Language Determinism

| Law | Requirement |
|-----|-------------|
| **Parity set** | Test suites **MUST** verify **Go ↔ Rust ↔ Python** parity on shared deterministic fixtures covering canonical serialization, fixed-point math, protocol hashing/signing input construction, replay verification, and bundle/manifest validation logic. |
| **Identical input, identical output** | The same test vector **MUST** produce identical outputs across languages with no tolerance band. |
| **Byte-level equivalence** | Canonical payload bytes, manifest bytes, hashes, signatures, Merkle proofs, and fixed-point outputs **MUST** match at byte level. |

### 3.2 Golden Cryptographic Test Vectors

Golden test vectors **MUST** exist for all of the following:

1. **`canonical_payload_bytes`**
2. **`SHA-256(canonical_payload_bytes)`**
3. **`signing_input = signing_context || SHA-256(canonical_payload_bytes)`**
4. **Ed25519 signature verification outcome**

| Law | Requirement |
|-----|-------------|
| **Cross-language parity** | Golden vectors **MUST** be executed in **Go**, **Rust**, and **Python**. |
| **Exact equivalence** | All vector outputs **MUST** be identical across the three implementations at byte level. |
| **Build gate** | Any mismatch **MUST** fail the build. |

### 3.3 Cryptographic Validation Tests

| Law | Requirement |
|-----|-------------|
| **Ed25519 correctness** | Tests **MUST** verify valid Ed25519 signature generation/verification against authoritative vectors and product signing inputs. |
| **Canonical parity** | Tests **MUST** verify **`canonical_payload_bytes`** parity for identical logical payloads across implementations. |
| **Signing context correctness** | Tests **MUST** verify the exact **`signing_context`** used for each message class and reject any mismatched or unregistered value. |
| **Invalid signature rejection** | Tests **MUST** verify rejection of invalid signatures, altered payloads, altered hashes, and altered signing contexts. |

### 3.4 Serialization Snapshot Tests

| Law | Requirement |
|-----|-------------|
| **Canonical JSON snapshots** | Tests **MUST** enforce canonical JSON byte snapshots for release-critical payload classes. |
| **Protobuf snapshots** | Tests **MUST** enforce deterministic protobuf encoding snapshots for release-critical protocol messages. |
| **No byte drift** | Any byte deviation from approved snapshots **MUST** fail. |

### 3.5 Global Determinism Assertion

| Law | Requirement |
|-----|-------------|
| **Database determinism** | Identical input **MUST** produce identical database state for deterministic subsystems under the same signed configuration and schema revision. |
| **Detection determinism** | Identical input **MUST** produce identical detection outputs. |
| **Forensic determinism** | Identical input **MUST** produce identical forensic artifacts, including canonical payload bytes, hashes, signatures, Merkle proofs, and root linkage where applicable. |
| **Failure rule** | Any deviation **MUST** fail validation. |

### 3.6 SINE Determinism Test

| Law | Requirement |
|-----|-------------|
| **Input fixture** | The SINE determinism fixture **MUST** include the exact **`detection_id`**, canonical **`features`** payload, **`model_hash`**, and exact **`prompt_template`** bytes used for narrative construction (**PRD-08** §4.1, **PRD-08** §5). |
| **Fixed runtime** | The test **MUST** run against the exact approved SINE runtime and dependency baseline recorded in **§15.1**, with fixed generation parameters as required by **PRD-08** §5. |
| **Repeated execution** | The same fixture **MUST** be executed at least **3** consecutive times in the same release-validation run with no mutation of inputs, model artifact, prompt template, or generation parameters. |
| **Assertion** | The full SINE output artifact bytes **MUST** be byte-identical across runs, including canonical JSON serialization and narrative body (**PRD-08** §5). |
| **Failure rule** | Any byte drift across runs **MUST** fail the build. Ignore-and-continue behavior is forbidden. |

---

## 4. TLS Exporter Binding Tests

| Law | Requirement |
|-----|-------------|
| **Golden vectors** | TLS 1.3 exporter binding **MUST** have golden test vectors. |
| **Cross-implementation parity** | Test suites **MUST** verify **Go `crypto/tls`** ↔ **Rust `rustls`** parity for exporter-derived bytes and any downstream binding fields defined by **PRD-04**. |
| **Fail rule** | Any mismatch **MUST** fail validation. |

---

## 5. Pre-Execution Containment Test

| Law | Requirement |
|-----|-------------|
| **Linux** | Assert **< 50 ms** signal→block and **veto** on **execve**/file paths per **PRD-11**; **eBPF/LSM** path exercised. |
| **Windows** | Assert process/create veto, **minifilter** enforcement, **ObRegisterCallbacks**, and **no user-mode execution before decision** for deny cases. **`PsSetLoadImageNotifyRoutine`** must be tested as **notify-only**, not as an enforcement point (**PRD-12**). |
| **Policy** | **BLOCK_EXEC** autonomous path deterministic from signed policy + streaming inputs (**PRD-09**). |

### 5.1 OS Compatibility & SAFE MODE Tests

| Law | Requirement |
|-----|-------------|
| **Linux kernel matrix** | Tests **MUST** verify startup behavior on **5.8+** full-enforcement kernels, **5.4–5.7** limited-mode kernels, and unsupported kernels, including correct **fail-closed** or **PRD-01 SAFE MODE** transitions (**PRD-11**). |
| **Windows OS / driver matrix** | Tests **MUST** verify supported Windows version paths, signed driver load behavior, unsupported-version rejection, and correct **fail-closed** or **PRD-01 SAFE MODE** transitions (**PRD-12**). |
| **Enforcement correctness** | OS-agent tests **MUST** verify that the effective allow/deny outcome matches signed policy semantics across both operating systems. |

---

## 6. No-Loss Under Stress Test

| Law | Requirement |
|-----|-------------|
| **Core** | Saturate ingest; verify **spill-to-disk**, **durable ACK** only after commit, **RESOURCE_EXHAUSTED** propagation (**PRD-06**, **PRD-16**, **PRD-19**). |
| **Endpoint** | Grow **append-only hash-chained** buffer; verify **retry until ACK**; **no** gap in `logical_clock` / `message_id` sequence for accepted work. |
| **Pass** | **PRD-16** assertion: **no** accepted-event loss; overflow beyond bounds → **failure** condition surfaced (**PRD-16** §2), not hidden drop. |

---

## 7. Forensic Replay Validation

| Law | Requirement |
|-----|-------------|
| **Read path** | Export/replay **must** verify **Ed25519**, **content_sha256**, Merkle inclusion, root signature, and identity fields (**PRD-15** §7, **PRD-10**). |
| **Merkle proof** | Tests **MUST** verify full Merkle proof validation and rejection of altered proof paths. |
| **Root chain** | Tests **MUST** verify **previous_root_hash** chain integrity and reject forks, regressions, or broken links. |
| **Replay correctness** | Replay tests **MUST** reconstruct canonical payload bytes and prove replay verification correctness end-to-end. |
| **Tamper** | Intentionally corrupt ciphertext/chain → consumer **rejects** as evidence (**PRD-15** §8). |
| **Seal failure** | Rows with failed seal **must not** pass “valid WORM” checks in tooling. |

### 7.1 WORM Export Round-Trip

| Law | Requirement |
|-----|-------------|
| **Round-trip flow** | Tests **MUST** verify **export -> import -> verify -> reconstruct canonical_payload_bytes**. |
| **Exact reconstruction** | Reconstructed **`canonical_payload_bytes`** **MUST** match the original bytes exactly. |
| **Failure rule** | Any round-trip deviation **MUST** fail validation. |

---

## 8. Update System Adversarial Tests

| Law | Requirement |
|-----|-------------|
| **Bundle** | Tampered manifest hash, bad **Ed25519**, broken **previous_bundle_hash** chain, **`system_identity_hash`** mismatch, unknown **`signing_context`**, or invalid manifest structure → **no activate** (**PRD-18**). |
| **Version chain** | Tests **MUST** verify strict **`version_n -> version_n+1`** continuity, rollback rejection, and rejection of skipped versions. |
| **Partial rejection** | Tests **MUST** verify rejection of partial bundle application, partial manifest trust, and runtime patching outside the update path. |
| **Atomic** | Mid-switch failure → prior **verified** artifact set only; **no** mixed-binaries runtime. |

---

## 9. Resource Exhaustion Fail-Closed Test

| Law | Requirement |
|-----|-------------|
| **Governor** | Under extreme load, ordering **enforcement > ingestion > AI > SINE** observable in metrics/traces (**PRD-19** §5). |
| **Exhaustion** | Breach ceilings → **halt** / **SAFE MODE** per signed config; **no** undocumented loss path (**PRD-19** §9, **PRD-16**). Disk spill below threshold → **PRD-19** §4 (fail-closed / backpressure; **no** drop or overwrite). |
| **Pressure simulation** | Tests **MUST** simulate disk exhaustion, memory pressure, and recovery transitions. |
| **Recovery** | System **MUST NOT** drop events, **MUST** maintain ordering, and **MUST** respect hysteresis and stability-window rules during recovery. |

### 9.1 Sustained Chaos & Stress

| Law | Requirement |
|-----|-------------|
| **Disk exhaustion duration** | System **MUST** survive sustained disk exhaustion for **> 5 minutes**. |
| **Memory pressure duration** | System **MUST** survive sustained memory pressure for **> 5 minutes**. |
| **Combined exhaustion** | System **MUST** survive combined resource exhaustion scenarios. |
| **Pass conditions** | During these tests the system **MUST NOT** drop events, **MUST NOT** oscillate, and **MUST** recover deterministically. |

---

## 10. Identity / Replay Attack Tests

| Law | Requirement |
|-----|-------------|
| **Replay** | Duplicate **`message_id`** with altered payload → **reject**; duplicate with same payload → **idempotent ACK** (**PRD-10** §4). |
| **Spoof** | Wrong **`system_identity_hash`**, **`boot_session_id`**, or **signature** → **reject** on gRPC and WebSocket (**PRD-10**, **PRD-05** §10). |

---

## 11. Kernel Race Condition Tests

| Law | Requirement |
|-----|-------------|
| **TOCTOU** | Fuzz rapid create/exec races; deny path **must** win before user thread schedules (**PRD-12** §4). |
| **Linux** | Concurrent exec + file replace; enforcement remains **deterministic** per policy (**PRD-11**). |

---

## 12. Chaos / Fault Injection Tests

| Law | Requirement |
|-----|-------------|
| **Core** | Kill worker, pause disk, flap Redis: **no** silent telemetry loss from accepted work; backpressure or **fail-closed** behavior only (**PRD-06** §9, **PRD-16**). |
| **Agent** | Driver reload, eBPF detach simulation: **fail-closed** or **SAFE MODE** per **PRD-11** §10 / **PRD-12** §17. |
| **DB** | Transaction abort mid-batch: **no** partial Merkle/WORM state treated as valid (**PRD-15** §5). |

---

## 13. CI Static Checks

- Grep ban: `event_drop_count`, `graph_nodes`, `graph_edges`, `asyncpg` in AI service.
- Verify **no** `CREATE ROLE` in Core SQL packages (**PRD-05**, **PRD-06**).
- Flag **SQLite WAL** as **sole** authoritative endpoint buffer pattern (forbidden **PRD-16** §4) in agent/probe code paths where applicable.

### 13.1 Signing Context Registry CI Gate

CI **MUST**:

1. extract all **`signing_context`** values from code, manifests, protocol definitions, and test fixtures
2. verify uniqueness
3. verify presence in the **PRD-02** signing-context registry

Unknown, duplicated, or missing registry mappings **MUST** fail the build.

### 13.2 Signing Context Collision Gate

CI **MUST** detect duplicate **`signing_context`** usage and enforce a **1:1 mapping** between **`signing_context`** and message type. Any collision **MUST** fail the build.

### 13.3 Cryptographic Gate

Any failed cryptographic check in CI — signature verification, canonical-byte parity, signing-context validation, Merkle verification, manifest verification, or replay verification — **MUST** fail the pipeline. Ignore-and-continue behavior is forbidden.

---

## 14. Performance

### 14.1 Mandatory Performance SLAs

| SLA | Requirement |
|-----|-------------|
| **Ingest throughput** | **`>= 10,000 events/sec`** at **500 agents** |
| **Detection latency P99** | **`< 100 ms`** |
| **Pre-execution containment P99** | **`< 50 ms`** |
| **WORM seal latency P99** | **`< 200 ms`** |
| **Core bootstrap time** | **`<= 30 sec`** |

These SLAs are release-blocking unless a signed exception process exists outside this PRD. CI/load-test reporting **MUST** measure and retain results against these exact thresholds.

---

## 15. Supply Chain

- `cargo deny`, `go-licenses`, `pip-licenses` — block GPL/AGPL as policy dictates.

### 15.1 Security-Critical Dependency Registry

Release certification evidence **MUST** contain a machine-readable security-critical dependency registry. Every listed entry **MUST** record the exact version or exact upstream commit used by the release artifact, the component that consumes it, and the governing license. Floating ranges, wildcard versions, implicit system-package drift, and unpinned `latest` tags are forbidden.

| Library name | Exact version / commit | Component | License |
|--------------|------------------------|-----------|---------|
| `ed25519-dalek` | `2.2.0` | Rust signing / verification paths (`agents/linux`, `dpi-probe`, `installer`, `signed-config`, signing tools) | `BSD-3-Clause` |
| `ring` | `0.17.14` | Rust TLS / cryptographic support paths (`agents/linux`, probes, `signed-config`) | `Apache-2.0 AND ISC` |
| Go stdlib | `go1.24.0` | Core Engine and Go-based tooling / verifiers | `BSD-3-Clause` |
| `PyNaCl` | `ABSENT` in the current approved baseline; any future introduction **MUST** record an exact version in this registry before merge | Python cryptographic helper path | `Apache-2.0` |
| `cryptography` | `41.0.7` | Python model-signing / offline verification helper path (`ml/model/sign.py`) | `Apache-2.0 OR BSD-3-Clause` |
| `llama.cpp` | Exact upstream vendored commit hash **MUST** be recorded in release evidence; wrapper crate baseline is `llama-cpp-2 0.1.139` / `llama-cpp-sys-2 0.1.139`, but crate version alone is insufficient | SINE Engine local LLM runtime | `MIT` |
| `tonic` | `0.12.3` | Rust gRPC transport in SINE, Linux Agent, DPI, and Rust probes | `MIT` |
| TimescaleDB | Exact extension version **MUST** be recorded in release evidence; unpinned tags such as `latest-pg16` are non-compliant for release certification | Core database platform | `Timescale License (TSL)` |

CI **MUST** compare lockfiles, dependency metadata, vendored artifacts, and container/image references against this registry. Any missing entry, missing exact version / commit, license omission, undeclared introduction, or registry mismatch **MUST** fail the build.

---

## 16. Air-Gap

- Install and update without internet; **PRD-18** bundle verification tests.
- Tests **MUST** verify Genesis Bundle bootstrap, manifest signature validation, version-chain enforcement, rollback rejection, and partial bundle rejection.

---

## 17. Release Gate

- All mandatory tests green (**§2–§13**), performance/supply-chain/airgap checks (**§14–§16**) per release scope, + manual SOC sign-off per organizational policy.
- Release certification evidence **MUST** be retained as immutable CI artifacts with commit identity, test-vector hashes, and result metadata sufficient for audit.
- Missing execution or missing pass/fail evidence for any mandatory category in this PRD **MUST** block release.

### 17.1 Prohibited Test Outcomes

- Ignoring failed cryptographic checks.
- Partial mandatory test coverage for release-blocking categories in this PRD.
- Nondeterministic test outcomes for deterministic subsystems.

---

