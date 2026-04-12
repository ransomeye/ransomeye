# Phase 6.7 — Anti-rollback protection (P0)

## Goal

Replay of an **older but still validly signed** `integrity.manifest` must be rejected. Evolution is **monotonic** in manifest **version** (uint64), independent of file hash changes.

## Manifest format

The **first line** of the signed blob (entire file is signed, including this line):

```text
version: <uint64>
```

Followed by existing `sha256:` lines (sorted by path in generated manifests). The version line is **not** a file path; verifiers skip it when building the path→hash map.

Example:

```text
version: 42
sha256:abc...  /opt/ransomeye/core/ransomeye-core
```

## Persistent state

**Phase 6.8:** Append-only **`/var/lib/ransomeye/state/version.chain`** cross-checks the version file; see `PHASE_6_8_DUAL_ANCHOR_ANTI_ROLLBACK.md`.

**Phase 6.9+:** **`/var/lib/ransomeye/state/anchor`** (0400) and append-only **`anchor.history`** (0600); live anchor verified by **history membership** (Phase 7.1); chain genesis = **first** history line. See `PHASE_6_9_ROOT_OF_TRUST_ANCHOR.md`, `PHASE_7_1_CONTROLLED_ANCHOR_ROTATION.md`.

- **Path:** `/var/lib/ransomeye/state/version`
- **Content:** decimal uint64 and newline (atomic write via `version.tmp` → rename)
- **Permissions:** `root:root`, mode **0600**
- **Directory:** `/var/lib/ransomeye/state`, mode **0700** `root:root`

Missing version file when enforcing rollback is **fail-closed** (Core / verify exit with error).

## Enforcement order

1. Read manifest + signature + WORM public key.
2. **Ed25519** verify over **raw manifest bytes** (version line included → tampering breaks signature).
3. Parse **first line** as `version: N`.
4. Read stored version from disk; if `N < stored` → **rollback detected**, exit.
5. Verify every `sha256:` line (skip `version:` line).
6. On full success → **atomic write** stored version = `N`.

## systemd

- **ransomeye-core:** runs as **root** with `ReadWritePaths=/var/lib/ransomeye/state` so it can update the version file under `ProtectSystem=strict`.

## Build / bump version

- Makefile: `INTEGRITY_MANIFEST_VERSION`; bump on each deploy that must refuse older signed manifests.
- `make generate-manifest` emits `version:` first, then sorted `sha256:` lines.

## Verification gates

| Gate | Expectation |
|------|-------------|
| Rollback | Deploy manifest `version: 10`, then `version: 9` with valid sig → **fail** |
| Forward | `10` → `11` → **success** |
| Tamper version file | Attacker bumps only disk file; without a matching **signed** manifest version and hashes, verification still **fails**; monotonic check still binds to signed `N` vs stored |
| Determinism | Same `N` + same artifact hashes → same pass/fail |

## References

- Go: `core/internal/integrity/manifest.go`, `core/internal/integrity/version.go`
- Installer: `installer/src/main.rs` (`verify_signed_integrity_manifest_and_harden`, atomic version write)
- Non-slice binaries are not listed in the Mishka manifest; only paths under `/opt/ransomeye/core/ransomeye-core` are verified for this slice.
