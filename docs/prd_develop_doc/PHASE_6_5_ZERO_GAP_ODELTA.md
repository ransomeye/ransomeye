# Phase 6.5 — Zero-gap + periodic checks (historical)

> **Phase 6.6 update:** Metadata-based skipping (`Stat`, size, mtime) is **removed** — bypass risk. See [`PHASE_6_6_CRYPTO_DELTA.md`](PHASE_6_6_CRYPTO_DELTA.md) for **hash-only** caching and full reads per file.

## Still current

- **`RunRuntimeIntegrityCheck()`** synchronously before **AI dial** (no trust window before client setup).
- **`StartRuntimeIntegrityLoop`**: immediate goroutine pass + **30s** ticker, **`log.Fatalf`** on failure.

The incremental optimization is now **SHA256 digest equality** in memory, not filesystem metadata.
