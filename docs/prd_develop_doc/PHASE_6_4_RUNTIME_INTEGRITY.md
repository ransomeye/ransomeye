# Phase 6.4 — Runtime integrity enforcement (final P0)

## Behavior

**`integrity.RunRuntimeIntegrityCheck()`** runs **synchronously** in `main` before **`ai.Dial`** (manifest + vendor, cache-populating). Then **`integrity.StartRuntimeIntegrityLoop()`** runs in a **background goroutine** (`core/internal/integrity/runtime.go`):

1. **Immediate** **`runIntegrityCheck()`** in the goroutine (hash cache may skip redundant hex compares after identical digest).
2. Then every **30s** — full read + SHA256 per file; **cryptographic hash cache** only (`PHASE_6_6_CRYPTO_DELTA.md`).

On any error: **`log.Fatalf("[FATAL] Runtime integrity violation: %v", err)`** → immediate process exit (fail-closed); **systemd** may restart Core.

## Constraints

- Interval **≥ 30s** between subsequent passes; first pass is immediate inside the goroutine.
- Stronger responses (stop auxiliary peers, forensic snapshot) deferred — exit is sufficient for P0.

## Verification gates

1. **Tamper listed binary** (e.g. append to `ransomeye-core`) → next tick → SHA mismatch → **`[FATAL] Runtime integrity violation:`** …  
2. **Tamper AI vendor file** → **`VerifyBeforeStart`** fails → same fatal log.  
3. **Tamper manifest / sig** → signature or hash verification fails → fatal.  
4. **Stable tree** → deterministic passes, no false positives from the checks themselves.

See also: `PHASE_6_3_CRYPTO_TRUST.md`, `PHASE_6_1_PROCESS_MODEL.md`.
