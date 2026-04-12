# Phase 7.2.1 — Crash-safe anchor history migration

## Principles

**Anchor history migration is atomic and crash-safe. Incomplete migrations are discarded on next startup.**

- **`anchor.history.tmp`** is never trusted as source of truth: it is removed on verifier/installer entry if present (incomplete migration or crash mid-write).
- **Final `anchor.history`** is published only via **`rename(tmp → anchor.history)`** after the tmp payload has been **fsync**’d and **replay-verified** (chained format).

## Write discipline (Go + installer)

1. Remove any stale tmp (startup recovery).
2. Write full migrated/bootstrap content to **`anchor.history.tmp`** at mode **0600**.
3. **`fsync`** the tmp file.
4. **`verifyChainedHistoryBytes`** on the tmp bytes (**pre-rename**); on failure → remove tmp, abort.
5. **`rename(tmp → anchor.history)`** (atomic replace).
6. **`fsync`** the **parent directory** (`/var/lib/ransomeye/state`) so the directory entry is durable.
7. Read **`anchor.history`** and **verify** again (**post-rename**); on failure → **`migration corruption`** (fail-closed).

## Idempotency

- If the file is **already** Phase 7.2 chained, prior-format detection is false → **no migration**, content unchanged.
- Re-running migration on the **same** prior-format bytes yields the **same** chained file (deterministic).

## Validation

Crash safety verified via deterministic fault injection testing.

## Parity

Installer (`installer/src/main.rs`) uses the same **tmp → sync → verify → rename → parent sync → verify** path via **`atomic_write_verified_anchor_history`**.

## References

- Phase 7.2 format & chaining: `PHASE_7_2_TAMPER_EVIDENT_ANCHOR_HISTORY.md`
- Implementation: `core/internal/integrity/anchor_history.go` (`atomicWriteVerifiedAnchorHistory`, `discardStaleAnchorHistoryTmp`, `syncParentDirOf`)
