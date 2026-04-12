# Phase 6.8 — Dual-anchor anti-rollback (hardening)

**Phase 6.9:** Chain genesis is the machine-bound **anchor** (`SHA256(machine-id || 0³²)`), not 32 zero bytes — see `PHASE_6_9_ROOT_OF_TRUST_ANCHOR.md`.

## Goal

**Dual-anchor monotonic enforcement:**

- **Version file** (`/var/lib/ransomeye/state/version`) — fast path (single `uint64`, atomic replace).
- **Hash chain** (`/var/lib/ransomeye/state/version.chain`) — tamper-evident append-only log.

Together they bound rollback and offline replay even if an attacker can rewrite the fast-path file with root: continuity breaks unless the chain is extended with valid hashes (append-only, `O_APPEND`, mode **0600**).

## Hash chain

- **Path:** `/var/lib/ransomeye/state/version.chain`
- **Lines (append-only):** `version:N sha256:<64 hex>` (no timestamps; strictly monotonic integer `N`).
- **Rule (6.9):** Implicit previous hash before `version:1` is the **root-of-trust anchor** (see Phase 6.9), not zero-bytes. For each entry `N`:

  `H(N) = SHA256( UTF-8(decimal N) || H(previous) )`

  where `H(previous)` is the anchor (for `N=1`) or the prior line’s hash (versions strictly increase; non-consecutive jumps are allowed with one line, e.g. 42 → 44).

- **Genesis:** First line `version:1` stores `H(1) = SHA256("1" || anchor)`.

## Startup / verification order (Go)

1. Ed25519-verify the manifest (unchanged).
2. **Phase 6.9:** Verify **anchor** vs `/etc/machine-id` (fail closed).
3. Require fast-path **version** file (Phase 6.7 fail-closed).
4. **Bootstrap** chain if missing: from **anchor** genesis, write lines `1..V` once (upgrade path).
5. **Replay** entire chain with anchor genesis; reject truncate, bad hex, non-increasing `N`, or hash mismatch.
6. **Cross-check:** `version` file must equal chain tip; else tamper or truncate.
7. **Rollback vs chain:** if `manifest_version < chain_tip` → fail.
8. **Anti-rollback vs file:** `manifest_version < stored` → fail (redundant if anchors match).
9. SHA256-verify manifest paths; on success **commit:** if `manifest_version > chain_tip`, **append** one chain line then atomic-write version.

## Implementation

| Component | Location |
|-----------|----------|
| Root anchor (6.9) | `core/internal/integrity/anchor.go` |
| Chain logic | `core/internal/integrity/version_chain.go` |
| Manifest integration | `core/internal/integrity/manifest.go` |
| Monotonic file (6.7) | `core/internal/integrity/version.go` |
| Installer parity | `installer/src/main.rs` (`installer_prepare_dual_anchor`, `installer_finalize_dual_anchor`) |

Exported API: `integrity.VerifyVersionChain() error` — full replay; used implicitly inside `VerifySignedManifest` / runtime integrity.

## Verification gates

| Gate | Expectation |
|------|-------------|
| Normal update | 42 → 43: append chain + version file → **success** |
| Rollback attempt | 43 → 42 (valid sig): **fail** (manifest &lt; chain tip and/or file) |
| Tamper version file | File ≠ chain tip: **fail** cross-check |
| Tamper chain | Any line hash break: **fail** replay |
| No clock | No timestamps in chain; integer monotonicity only |

## References

- Phase 6.7: `PHASE_6_7_ANTI_ROLLBACK.md`
- systemd state: `ReadWritePaths=/var/lib/ransomeye/state` (core + installer expectations unchanged; chain is additional state in same directory).
