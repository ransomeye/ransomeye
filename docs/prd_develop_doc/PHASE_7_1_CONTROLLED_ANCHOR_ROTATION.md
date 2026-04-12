# Phase 7.1 — Controlled anchor rotation

## Principles

**Anchor rotation is explicit, append-only, and auditable. No implicit trust reset is allowed.**

- Live **multi-source anchor** (Phase 7.0) must appear in **`anchor.history`**. Plain mismatch against a single cached file is no longer the gate.
- **Forensic continuity:** `version.chain` is **not** reset on rotation. Replay still uses the **original** chain genesis: the **first** `anchor:` line in `anchor.history`.
- **Implicit transplant** (new host material without an approved history entry) → **FAIL**.

## `anchor.history`

| Property | Value |
|---------|--------|
| Path | `/var/lib/ransomeye/state/anchor.history` |
| Mode | **0600** `root:root` |
| Format | **Phase 7.2:** `anchor:<hex> hash:<hex>` (chained); prior-format `anchor:`-only is migrated once |
| Semantics | Line 1 = original install anchor; later lines = **approved** rotations; hashes detect tamper |

See `PHASE_7_2_TAMPER_EVIDENT_ANCHOR_HISTORY.md`.

Verification:

1. Compute **current** anchor from live machine (Phase 7.0).
2. Require **current ∈ parsed history** (order-preserving set).
3. Return **chain genesis** = decoded **first** history line for `version.chain` replay/bootstrap.

## Controlled rotation API (Go)

- **`ApproveNewAnchor(newAnchor [32]byte) error`** — **root only** (`geteuid() == 0`). Appends `anchor:<hex>` if not already present. Logs `[AUDIT]` via `log`.
- **`ReprovisionAnchorAppend()` error** — convenience: compute live anchor and call `ApproveNewAnchor` (root only).

## Installer

- **`--reprovision-anchor`** (after integrity state dir exists): recompute live anchor; if already in history, audit no-op; else **append** to `anchor.history` and sync flat `anchor` file. Does **not** truncate history.
- Normal install still seeds **`anchor` + `anchor.history`** with one line when neither exists.

## Upgrade / migration

If **`anchor.history`** is missing but the flat **`anchor`** file exists and matches the **current** compute, a **single-line** history is created once (bootstrap). Otherwise fail closed (forces explicit provisioning or rotation).

## Attack / tamper notes

| Scenario | Behavior |
|----------|----------|
| Unexpected material change | Current ∉ history → **FAIL** until `--reprovision-anchor` / `ApproveNewAnchor` |
| Approved rotation | Current ∈ history; chain genesis unchanged → **PASS** if chain intact |
| History tamper (prepend/truncate) | Often breaks history parse or chain replay vs first-line genesis → **FAIL** |

## Implementation

| Artifact | Location |
|----------|----------|
| History + verify + API | `core/internal/integrity/anchor_history.go` |
| Legacy anchor file | `core/internal/integrity/anchor.go` |
| Installer + flag | `installer/src/main.rs` |
| Dev install seed | `Makefile` (`anchor.history` next to `anchor`) |

## References

- Phase 7.0 preimage: `PHASE_7_0_MULTI_SOURCE_ROOT_OF_TRUST.md`
- Phase 6.9 / 6.8 chain: `PHASE_6_9_ROOT_OF_TRUST_ANCHOR.md`, `PHASE_6_8_DUAL_ANCHOR_ANTI_ROLLBACK.md`
