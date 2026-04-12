# Phase 7.2 — Tamper-evident anchor history

## Principles

**Anchor history is cryptographically chained. Any modification is detectable.**

Each line binds the approved anchor digest to the previous line’s cumulative hash, so truncation, reordering, or rewriting breaks verification.

## On-disk format

```text
anchor:<64 hex> hash:<64 hex>
```

- **H(0)** = 32 zero bytes (implicit genesis).
- **H(n)** = `SHA256(anchor_n || H(n-1))` with **anchor_n** as the raw 32-byte digest on that line.

Appends use **`O_APPEND`** on the history file; mode **0600** `root:root`.

## Verification

The implementation **replays** the full file and recomputes each stored `hash:`; mismatch → **FAIL**.

Live-host **membership** (Phase 7.1) still applies: the current multi-source anchor must appear as some line’s `anchor:`.

**Chain genesis for `version.chain`** remains the **first line’s `anchor:`**.

## Migration (one-time)

Legacy lines with only `anchor:<hex>` (no `hash:`) are detected, parsed in order, chained hashes recomputed, and the file replaced atomically via **`anchor.history.tmp`** → rename, with an **`[AUDIT]`** log.

**Phase 7.2.1:** tmp writes are **fsync**’d, **pre- and post-rename** chain replay is enforced, the **parent directory is fsync**’d, and a stale tmp is **removed on next startup** — see `PHASE_7_2_1_CRASH_SAFE_ANCHOR_HISTORY_MIGRATION.md`.

## Implementation

| Artifact | Location |
|----------|----------|
| Chaining + verify + migrate | `core/internal/integrity/anchor_history.go` |
| Tests | `core/internal/integrity/anchor_history_chained_test.go` |
| Installer | `installer/src/main.rs` |
| Seed | `scripts/compute-integrity-anchor.py` (second path argument), `Makefile` |

## References

- Phase 7.1: `PHASE_7_1_CONTROLLED_ANCHOR_ROTATION.md`
- Phase 7.0: `PHASE_7_0_MULTI_SOURCE_ROOT_OF_TRUST.md`
