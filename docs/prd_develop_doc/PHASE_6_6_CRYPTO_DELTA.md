# Phase 6.6 — Cryptographic delta verification (final)

## Policy

**Metadata-based optimization removed due to bypass risk.**  
**Integrity verification now relies solely on cryptographic hashing.**

`Stat` / size / mtime MUST NOT be used as a trust signal to skip verification. Each pass performs a **full read** of every manifest-listed binary and every `vendor.sha256`-listed file, then **SHA256**.

## Hash cache (performance only)

- **Type:** `map[string][32]byte` — last verified raw digest per absolute path.
- **Skip rule:** after `sum := sha256.Sum256(content)`, if `hashCache[path] == sum`, the implementation **skips re-comparing** the hex digest to the manifest line (content is unchanged since last successful check; collision resistance of SHA-256).
- **Correctness:** changing file bytes changes `sum` → full compare runs → tamper detected (including mtime spoof).

## Memory bound

Each `runIntegrityCheck` pass records **`seen[path]=true`** for every path processed. After manifest + vendor verification, entries **`delete(hashCache, k)`** for `k` not in `seen`, so the map cannot grow without bound when manifests shrink or paths rotate.

## Code

- `core/internal/integrity/manifest.go` — `verifySignedManifestWithHashCache`
- `core/internal/ai/launcher.go` — `verifyVendorIntegrityWithHashCache` / `VerifyBeforeStartWithHashCache`
- `core/internal/integrity/runtime.go` — unified `runtimeHashCache` + prune

Phase 6.5 “O(Δ) via metadata” is **superseded** by this model (still O(files) reads; reduced CPU on unchanged digests).
