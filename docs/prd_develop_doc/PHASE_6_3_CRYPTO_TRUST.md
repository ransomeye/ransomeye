# Phase 6.3 — Cryptographic trust unification (P0)

**Mishka Phase-1 slice:** `make generate-manifest` lists only **`/opt/ransomeye/core/ransomeye-core`**. Historical AI tarball signing is not part of this manifest.

## Artifacts (under `/etc/ransomeye/`)

| File | Role |
|------|------|
| **`integrity.manifest`** | UTF-8 text, one line per deployed binary: `sha256:<64-hex>␠␠<absolute-path>` (paths sorted for deterministic signing). |
| **`integrity.sig`** | **Raw 64-byte Ed25519 signature** over the **exact manifest bytes** (no separate plain hash list). |
| **`worm_signing.pub`** | 32-byte Ed25519 public key used to verify `integrity.sig`. |

**Trust rule:** SHA256 lines are **not** trusted until **`ed25519.Verify(pub, manifest, sig)`** succeeds (installer and `ransomeye-core` runtime loop).

## Build / sign (offline air-gap host with `/etc/ransomeye/worm_signing.key`)

```bash
make generate-manifest   # writes build/integrity.manifest
make sign-manifest       # signs with WORM key → build/integrity.sig
# or
make generate-integrity  # both
make install             # copies manifest + sig (0444) and binaries under /opt/ransomeye/...
```

Signer: `scripts/sign-integrity-manifest` (`cargo run --release -- <manifest> <sig>`).

## Runtime verification

- **`installer`:** reads manifest + sig → **signature first** → parse lines → `sha256` each file → lock `integrity.*` (0444).
- **`ransomeye-core`:** [`core/internal/integrity/manifest.go`](../../core/internal/integrity/manifest.go) via [`core/internal/integrity/runtime.go`](../../core/internal/integrity/runtime.go) on a timer; AI vendor checks run only when `RANSOMEYE_AI_ADDR` is set.

## Core binary path

Single canonical Core ELF:

```text
/opt/ransomeye/core/ransomeye-core
```

References under `deploy/systemd/ransomeye-core.service` and the installer **must** match this path (no `/opt/ransomeye/core/bin/...`).

## Verification gates

1. **Tamper manifest** → signature fails → install / ExecStartPre fails.  
2. **Tamper binary** → line hash fails after good signature.  
3. **Tamper both** → signature fails if manifest bytes change; re-signing without key fails verify.  
4. **PATH:** production does not require `which ransomeye-core` — services use absolute `ExecStart`. Operators should not rely on a global `ransomeye-core` in `PATH`.

Phase 6.2’s *plain* `integrity.sig` hash-list model is **superseded** by this manifest + Ed25519 scheme.
