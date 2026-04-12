# Phase 6.9 — Root-of-trust anchor (final)

**Phase 7.0** replaces the single-factor preimage with **multi-source** binding (machine-id + CPU identity + root filesystem UUID). The anchor **file format** and hash-chain use as genesis are unchanged; see `PHASE_7_0_MULTI_SOURCE_ROOT_OF_TRUST.md`.

**Phase 7.1:** Trust is **membership** in append-only `anchor.history`; chain genesis remains the **first** history entry. See `PHASE_7_1_CONTROLLED_ANCHOR_ROTATION.md`.

## Principles

**Root-of-trust anchored to machine identity. State cannot be transplanted or reset without detection.**

- **No fallback:** missing or invalid anchor → fail closed.
- **Air-gap:** anchor derives only from local host invariants and fixed zero-bytes suffix inside `SHA256` (no network, no timestamps).

## Anchor file

| Property | Value |
|---------|--------|
| Path | `/var/lib/ransomeye/state/anchor` |
| Content | Raw **32 bytes** — `SHA256( preimage_utf8 \|\| 0³² )` (Phase 7.0 preimage, normalized; see Phase 7.0 doc) |
| Mode | **0400** `root:root` |
| Source | Multi-source material (Phase 7.0); was machine-id-only before 7.0 |

On every integrity gate, the runtime recomputes the expected anchor and compares it to the file. **Mismatch → `root-of-trust violation`** (VM/disk transplant, tamper, or wrong anchor file).

## Hash chain genesis (Phase 6.8 extension)

The first chain step uses the **anchor** as the implicit previous hash (not 32 zero bytes):

- `H(1) = SHA256( UTF-8("1") || anchor )`
- `H(k) = SHA256( UTF-8(decimal k) || H(k-1) )` for subsequent lines (strictly increasing `k`; jumps allowed in one line).

The file on disk `version:1 sha256:…` is therefore **SHA256("1" || anchor)**, matching the spec “chain genesis tied to anchor.”

## Verification order (Go)

1. `VerifyAndLoadAnchor` / `VerifyRootAnchor` — machine-id vs `/var/lib/.../anchor`.
2. Read monotonic **version** file (Phase 6.7).
3. Bootstrap **version.chain** if missing, starting from **anchor** as genesis.
4. Replay **version.chain** with initial previous hash = **anchor**.
5. Cross-check version file vs chain tip; manifest rollback rules unchanged.

## Installer / provisioning

- **First install:** read `/etc/machine-id`, compute anchor, write `anchor` at **0400** (atomic tmp → rename where applicable).
- Initialize or extend **version.chain** using the **same** anchor genesis as Go.

`Makefile` `install` target materializes `anchor` the same way for dev/prod parity.

## Attack outcomes

| Attack | Result |
|--------|--------|
| Delete `version` / `version.chain` | Fail closed (missing state / chain vs anchor-only recovery path) |
| Copy `/var/lib/ransomeye/state` from another host | Anchor mismatch vs local `machine-id` → **fail** |
| Rebuild chain without correct anchor | Line 1+ hash mismatch on replay → **fail** |
| Rollback signed manifest | Unchanged — fails vs chain / version monotonicity |

## Upgrade note (pre-6.9 chains)

Chains built with the **old** zero-byte genesis will **not** replay once anchor enforcement is enabled. After the anchor file is in place, remove the stale `version.chain` and allow a verifier/core pass to **re-bootstrap** the chain from the current **version** file and **anchor** (or re-run installer finalize). Do not delete the anchor once established unless performing a controlled reprovision.

## Implementation

| Artifact | Location |
|----------|----------|
| Anchor + verify | `core/internal/integrity/anchor.go` |
| Chain genesis threading | `core/internal/integrity/version_chain.go` |
| Installer | `installer/src/main.rs` (`ensure_integrity_anchor_file`, chain replay/bootstrap args) |
| Dev install seed | `Makefile` (`install` → `.integrity-anchor`) |

## References

- Phase 6.8: `PHASE_6_8_DUAL_ANCHOR_ANTI_ROLLBACK.md`
- Phase 6.7: `PHASE_6_7_ANTI_ROLLBACK.md`
