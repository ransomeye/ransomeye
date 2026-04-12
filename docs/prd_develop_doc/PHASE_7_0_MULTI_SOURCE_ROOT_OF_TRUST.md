# Phase 7.0 — Multi-source root of trust (final hardening)

## Principles

**Root-of-trust derived from multiple independent system invariants. Single-source spoofing is insufficient to bypass trust.**

- **Offline / deterministic:** inputs are read only from local OS and hardware descriptors; no network.
- **Fail-closed:** if any required source is missing or unusable, verification fails (no fallback values).
- **Normalization:** each component is **trimmed**, **lowercased**, then concatenated in **stable order** with **`\n`** separators.

## Anchor preimage (UTF-8)

```text
<preimage> = machine_id + "\n" + cpu_id + "\n" + rootfs_uuid   // each line normalized
<anchor>   = SHA256( <preimage_bytes> || 0³² )
```

Stored as **raw 32 bytes** in `/var/lib/ransomeye/state/anchor` (0400 `root:root`). The hash chain (Phase 6.8–6.9) still uses this **anchor** as genesis for `version:1`.

### Sources (all mandatory)

| # | Source | Origin |
|---|--------|--------|
| 1 | **machine-id** | `/etc/machine-id` |
| 2 | **cpu-id** | `/proc/cpuinfo` first logical CPU: `Serial` if present, else `model name`, else ordered tuple `vendor_id`, `cpu family`, `model`, `model name` joined by `|` |
| 3 | **rootfs UUID** | `findmnt -n -o UUID /`, else `findmnt -n -o SOURCE /` + `blkid`/`UUID=`, else `/proc/mounts` root device + `blkid` |

## Verification

On every gate, the runtime recomputes `<anchor>` from **live** inputs and compares to the file. Mismatch → **`root-of-trust violation`**.

## Installer / build

- **Installer:** `ensure_integrity_anchor_file` matches Go semantics; on **first anchor creation**, prints an audit line: `SHA256` digest **first 8 bytes** as hex.
- **Makefile `install`:** `scripts/compute-integrity-anchor.py` writes the same anchor for dev/prod parity (requires `findmnt`/`blkid` on the install host when UUID cannot be read directly).

## Attack outcomes (intent)

| Attack | Typical result |
|--------|----------------|
| Alter only `machine-id` | Anchor mismatch (CPU + disk still bind) |
| Clone disk to new metal | Often CPU and/or mounting context mismatch → fail |
| VM copy | Root UUID / device graph mismatch → fail |
| Partial spoof | preimage change → `SHA256` mismatch → fail |

## Implementation

| Location | Role |
|----------|------|
| `core/internal/integrity/anchor.go` | `ComputeMachineAnchor`, file I/O |
| `core/internal/integrity/anchor_sources.go` | Multi-source collection |
| `installer/src/main.rs` | Parity + audit log on first write |
| `scripts/compute-integrity-anchor.py` | `make install` anchor seed |

## References

- Phase 7.1 (append-only **anchor.history**, membership verify, rotations): `PHASE_7_1_CONTROLLED_ANCHOR_ROTATION.md`
- Phase 7.2 (chained **hash:** …): `PHASE_7_2_TAMPER_EVIDENT_ANCHOR_HISTORY.md`
- Phase 7.2.1 (crash-safe tmp/rename/fsync migration): `PHASE_7_2_1_CRASH_SAFE_ANCHOR_HISTORY_MIGRATION.md`
- Phase 6.9 (single-identity doc superseded by preimage details here): `PHASE_6_9_ROOT_OF_TRUST_ANCHOR.md`
- Phase 6.8 chain: `PHASE_6_8_DUAL_ANCHOR_ANTI_ROLLBACK.md`
