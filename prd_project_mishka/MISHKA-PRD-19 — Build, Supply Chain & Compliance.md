# MISHKA-PRD-19 — Build, Supply Chain & Compliance

**Project:** Project Mishka  
**Classification:** AUTHORITATIVE — DETERMINISTIC BUILD, SUPPLY CHAIN VERIFICATION, AND DEPLOYMENT COMPLIANCE  
**Status:** CRITICAL — REPRODUCIBLE BUILDS, SIGNED ARTIFACTS, VERIFIED DEPLOYMENT, FAIL-CLOSED RUNTIME ATTESTATION

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

This document defines the authoritative build, supply chain, and compliance model for Project Mishka.

Its purpose is to guarantee that:

* verified source code produces deterministic artifacts
* deployed binaries exactly match verified source code
* every deployment artifact is cryptographically verifiable
* runtime binaries are checked against verified deployment state before execution

This PRD is authoritative for build determinism, artifact signing, dependency locking, deployment verification, and runtime binary verification.

---

# 2. CORE PRINCIPLES

```text
VERIFY SOURCE -> REPRODUCE BUILD -> HASH -> SIGN -> VERIFY BEFORE DEPLOY -> VERIFY AT RUNTIME
```

The following principles are mandatory:

* identical source MUST produce identical binary
* nondeterministic builds are FORBIDDEN
* all authoritative build inputs MUST be explicit and pinned
* all authoritative artifacts MUST be hashed
* all authoritative artifacts MUST be signed
* only verified artifacts MAY be deployed
* runtime MUST verify deployed binary identity before serving traffic
* supply chain drift MUST fail closed

There is no best-effort build admission, unsigned deployment path, or runtime trust-on-first-use.

---

# 3. BUILD MODEL (CRITICAL)

The authoritative build is one deterministic transformation from verified source and locked inputs to artifact bytes.

The authoritative build inputs are:

* verified source files
* pinned dependency set
* canonical build configuration
* exact compiler version
* canonical build steps
* authoritative build script bytes
* deterministic toolchain invocation sequence
* fixed environment lock

The following are mandatory:

* source inputs MUST be enumerated deterministically by relative path
* source file bytes MUST be consumed exactly as versioned
* build configuration MUST be RFC 8785 canonical JSON
* compiler version MUST be exact and immutable for one build scope
* build steps MUST be explicitly defined and canonicalized
* build script MUST be treated as authoritative input
* toolchain invocation order MUST be deterministic
* environment lock MUST be resolved before build start
* build output bytes MUST be determined only by the authoritative build inputs

Builds that depend on mutable network state, wall-clock time, host-specific ambient state, or unpinned tool resolution are invalid.

---

# 4. REPRODUCIBLE BUILD LAW (CRITICAL)

For identical:

* source file set and source file bytes
* dependency set and dependency hashes
* canonical build configuration
* compiler version
* canonical build steps
* build script bytes
* toolchain invocation sequence
* environment lock

The build system MUST produce identical:

* artifact bytes
* artifact hash
* build hash
* signature input
* deployment verification result

The following law is mandatory:

```text
IDENTICAL BUILD INPUTS -> IDENTICAL ARTIFACT BYTES
```

Any build process that can produce different bytes from identical build inputs is invalid.

---

# 5. BUILD HASH MODEL (CRITICAL)

The authoritative build graph hash is:

```text
build_graph_hash = SHA256(
  canonical_build_steps ||
  build_script_bytes ||
  toolchain_invocation_sequence
)
```

The authoritative build hash is:

```text
build_hash = SHA256(
  source_files ||
  dependency_hashes ||
  build_config ||
  compiler_version ||
  build_graph_hash
)
```

The following canonical construction rules are mandatory:

* `source_files` MUST be the concatenation of:
  * UTF8(relative_path) ||
  * UINT64_BE(length(file_bytes)) ||
  * file_bytes
* source file entries MUST be ordered lexicographically by relative path
* `dependency_hashes` MUST be the concatenation of canonical dependency entries ordered lexicographically by canonical package identifier
* each dependency entry MUST contain package identifier, pinned version, and exact dependency content hash
* `build_config` MUST be RFC 8785 canonical JSON bytes
* `compiler_version` MUST be exact canonical UTF-8 bytes
* `canonical_build_steps` MUST be RFC 8785 canonical JSON bytes describing the explicit ordered build graph
* `build_script_bytes` MUST be the exact byte content of the authoritative build script entrypoint and any authoritative included build-script sources in deterministic path order
* `toolchain_invocation_sequence` MUST be the canonical byte sequence of the ordered toolchain invocations used by the build
* build graph variation MUST change `build_hash`

The build system MUST also compute:

```text
artifact_hash = SHA256(artifact_bytes)
```

`build_hash` identifies the deterministic build input set. `artifact_hash` identifies the produced artifact bytes.

---

# 6. SIGNING MODEL (CRITICAL)

All authoritative artifacts MUST be signed using the cryptographic trust model from PRD-04.

The following are mandatory:

* all artifacts MUST be signed with `Ed25519`
* unsigned artifacts MUST be rejected
* non-Ed25519 artifact signatures are invalid
* artifact verification MUST use only local signed trust state admitted under PRD-04

The authoritative signing inputs are:

```text
artifact_hash = SHA256(artifact_bytes)

signing_input =
  UTF8(signing_context) ||
  build_hash ||
  artifact_hash

artifact_signature = Ed25519(signing_input)
```

The following are mandatory:

* `signing_context` MUST be explicit, versioned, and authorized under PRD-04
* identical `build_hash`, `artifact_hash`, and `signing_context` MUST produce identical signature verification outcome
* missing signature, invalid signature, or unauthorized signing context MUST fail closed

---

# 7. DEPENDENCY MANAGEMENT (CRITICAL)

Dependencies MUST be pinned, hashed, and immutable within one build scope.

The following are mandatory:

* all dependencies MUST be pinned
* all dependencies MUST be hashed
* external drift MUST NOT be allowed
* dependency resolution MUST use only the pinned manifest
* floating versions, implicit latest selection, and mutable tags are FORBIDDEN
* transitive dependencies MUST also be pinned and hashed
* dependency manifest changes MUST change the build verification outcome

If any dependency cannot be resolved exactly to its pinned version and pinned hash:

```text
REJECT BUILD -> FAIL-CLOSED -> ALERT
```

---

# 8. ENVIRONMENT LOCK (CRITICAL)

The build environment MUST be fixed and reproducible.

The authoritative environment lock MUST contain at minimum:

* build container image digest (immutable OS image identifier)
* target architecture
* target operating system
* exact compiler toolchain identity
* exact linker identity where applicable
* exact build script entrypoint

The following are mandatory:

* the build environment MUST be fixed
* container or OS MUST be reproducible
* environment lock resolution MUST complete before build start
* environment drift between verified build and executed build is invalid
* local host-only ambient state MUST NOT change artifact bytes

If the environment lock cannot be resolved exactly:

```text
REJECT BUILD -> FAIL-CLOSED -> ALERT
```

---

# 9. ARTIFACT REGISTRY MODEL

The artifact registry is the authoritative distribution point for verified build outputs.

Each authoritative registry entry MUST contain at minimum:

* artifact identifier
* `build_hash`
* `artifact_hash`
* artifact signature
* dependency manifest hash
* environment lock identifier
* compiler version
* build configuration hash

The following are mandatory:

* registry entries MUST be append-only
* artifact bytes stored in the registry MUST be byte-identical to signed artifact bytes
* registry retrieval MUST NOT transform artifact bytes
* registry metadata MUST be sufficient to verify deployability without external guesswork
* unverified or partially verified artifacts are non-authoritative

---

# 10. DEPLOYMENT VERIFICATION (CRITICAL)

Only verified artifacts MAY be deployed.

The following are mandatory before deploy:

* verify `build_hash`
* verify `artifact_hash`
* verify artifact signature
* verify dependency manifest identity
* verify environment lock identity
* verify compiler version identity
* verify artifact bytes exactly match the verified registry entry

The deployment admission rule is:

```text
verify(build_hash, artifact_hash, signature, dependency_lock, environment_lock) -> deploy
```

If any verification step fails:

```text
REJECT DEPLOY -> FAIL-CLOSED -> ALERT
```

---

# 11. RUNTIME VERIFICATION (CRITICAL)

Runtime MUST verify its own binary identity at startup.

The following are mandatory:

* system MUST verify its own binary hash at startup
* runtime verification MUST compare the loaded binary bytes against the deployed authoritative `artifact_hash`
* runtime verification MUST validate that the deployed artifact signature remains valid under the retained trust state
* mismatch MUST fail closed
* startup MUST NOT proceed before runtime verification succeeds

If runtime binary verification fails:

```text
FAIL-CLOSED -> ALERT -> DO NOT START
```

Runtime patching, replacement, or mutation after verification is FORBIDDEN.

---

# 12. COMPLIANCE MODEL

Compliance is the retained evidence model proving build-to-runtime integrity.

The following evidence MUST be retained:

* verified source manifest
* dependency lock manifest
* environment lock manifest
* `build_hash`
* `artifact_hash`
* artifact signature
* deployment verification record
* runtime verification record

The following are mandatory:

* compliance evidence MUST be append-only
* compliance evidence MUST be sufficient to re-verify the full build chain later
* missing compliance evidence invalidates provenance claims
* historical verification MUST use retained trust state and retained artifact metadata

If compliance evidence required for verification is missing:

```text
FAIL-CLOSED -> ALERT
```

---

# 13. FAILURE MODEL

The build and supply-chain system MUST operate fail-closed.

The following failures are mandatory rejection conditions:

* nondeterministic build result
* dependency hash mismatch
* dependency version drift
* environment lock mismatch
* missing artifact signature
* invalid artifact signature
* unverified deployment artifact
* runtime binary hash mismatch
* missing compliance evidence

The following are mandatory:

* any verification ambiguity MUST reject build or deploy
* no unsigned artifact may enter deployment
* no unverified dependency may enter build
* no runtime mismatch may continue execution

---

# 14. DETERMINISM GUARANTEE

For identical:

* verified source files
* dependency hashes
* canonical build configuration
* compiler version
* environment lock
* retained trust state

The system MUST produce identical:

* `build_hash`
* `artifact_hash`
* signature verification result
* deployment verification result
* runtime verification result

The following law is mandatory:

```text
IDENTICAL SOURCE AND LOCKED INPUTS -> IDENTICAL VERIFIED ARTIFACT
```

---

# 15. FILE & MODULE STRUCTURE

The authoritative implementation root for this PRD MUST be:

```text
/build/trust/
  source_manifest.go
  reproducible_builder.go
  dependency_lock.go
  environment_lock.go
  artifact_signer.go
  deployment_verifier.go
  runtime_verifier.go
  compliance_ledger.go
```

Every module MUST map to one or more sections of this PRD:

* `/build/trust/source_manifest.go` -> Sections 3, 5, 12, 14
* `/build/trust/reproducible_builder.go` -> Sections 3, 4, 5, 8, 13, 14
* `/build/trust/dependency_lock.go` -> Sections 5, 7, 12, 13
* `/build/trust/environment_lock.go` -> Sections 4, 8, 10, 13
* `/build/trust/artifact_signer.go` -> Sections 5, 6, 9, 14
* `/build/trust/deployment_verifier.go` -> Sections 9, 10, 13, 14
* `/build/trust/runtime_verifier.go` -> Sections 10, 11, 13, 14
* `/build/trust/compliance_ledger.go` -> Sections 9, 12, 13

No other authoritative PRD-19 module is permitted.

---

# 16. FORBIDDEN

```text
FORBIDDEN:

- dynamic code loading
- unsigned binaries
- runtime patching
- unverified dependencies
- non-reproducible builds
- floating dependency versions
- mutable dependency tags
- network-dependent build resolution in authoritative builds
- artifact transformation after signing
- deploy-before-verify
```

---

# 17. SUMMARY

```text
PRD-19 defines deterministic build and supply-chain verification for Project Mishka.

It MUST:
- reproduce identical artifacts from identical verified source and locked inputs
- hash build inputs and produced artifacts
- sign all authoritative artifacts
- deploy only verified artifacts
- verify binary identity at runtime startup
- retain compliance evidence for later verification

It MUST NOT:
- allow unsigned artifacts
- allow dependency drift
- allow non-reproducible builds
- allow runtime patching
- allow unverified deployment
```

---
