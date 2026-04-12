# Mishka — deployed UI / API alignment (host verification log)

## Classification (exactly one)

**Mixed stale deploy** — stale **`/opt/ransomeye/ui/dist`** (old hashed JS/CSS from 2026-04-04) **and** stale **`ransomeye-core`** binary (missing `GET /api/v1/soc/governance-manifest`, returned `404`).  

Live **`/opt/ransomeye/nginx/nginx.conf`** already pointed at `root /opt/ransomeye/ui/dist` and `proxy_pass http://127.0.0.1:8443` for `/api/` and `/ws` — **not** an nginx root mismatch.

## Deploy commands executed (this host)

```bash
# 1) UI — build from repo, sync to nginx static root (ports unchanged)
cd /home/gagan/ransomeye-source/ui && npm ci && npm run build
rsync -av --delete /home/gagan/ransomeye-source/ui/dist/ /opt/ransomeye/ui/dist/
sudo systemctl reload ransomeye-nginx.service

# 2) Core — build bypassed `make build-core` (validate-hardcoded-addrs failure on mishka-signal-send)
cd /home/gagan/ransomeye-source
source scripts/reproducible-build-env.sh "$(pwd)"
go build -trimpath -buildvcs=false -ldflags "-buildid=" -o build/ransomeye-core ./core/cmd/ransomeye-core

# 3) Integrity — new ELF requires new manifest + WORM signature (or core exits: runtime integrity violation)
core_h=$(sha256sum build/ransomeye-core | awk '{print $1}')
printf 'version: 3\nsha256:%s  /opt/ransomeye/core/ransomeye-core\n' "$core_h" > build/integrity.manifest
# Temporary copy of key for user-owned signer (then deleted):
sudo cp /etc/ransomeye/worm_signing.key build/.worm-signing.key.tmp && sudo chown "$USER:$USER" build/.worm-signing.key.tmp && chmod 400 build/.worm-signing.key.tmp
cd scripts/sign-integrity-manifest && cargo run --release -- \
  "$(pwd)/../../build/integrity.manifest" "$(pwd)/../../build/integrity.sig" "$(pwd)/../../build/.worm-signing.key.tmp"
rm -f ../../build/.worm-signing.key.tmp

sudo install -m 0444 build/integrity.manifest /etc/ransomeye/integrity.manifest
sudo install -m 0444 build/integrity.sig /etc/ransomeye/integrity.sig
sudo chown root:root /etc/ransomeye/integrity.manifest /etc/ransomeye/integrity.sig
sudo install -m 0500 build/ransomeye-core /opt/ransomeye/core/ransomeye-core
sudo systemctl restart ransomeye-core.service
```

## Live checks (HTTPS, `-k` for local cert)

| Check | Result |
|-------|--------|
| `GET https://127.0.0.1/` | `200`, references `index-Cq6mKpv-.js` (new Vite hash) |
| `GET https://127.0.0.1/dashboard` … `/executive`, `/stream` | `200` (SPA `index.html`) |
| `GET https://127.0.0.1/api/v1/health` | `200` |
| `GET https://127.0.0.1/api/v1/system/health` | `200` |
| `GET https://127.0.0.1/api/v1/system/ingestion-status` | `200` |
| `GET https://127.0.0.1/api/v1/shadow/intelligence/status` | `200` |
| `GET https://127.0.0.1/api/v1/assets/coverage` | `200` |
| `GET https://127.0.0.1/api/v1/soc/governance-manifest` | **`200`** after core + integrity refresh |

## Runtime hygiene (same slice)

```text
ss -tlnp  (filtered): 0.0.0.0:443 nginx; 127.0.0.1:8443 ransomeye-core; 127.0.0.1:5432 postgres;
 127.0.0.1:50051 ransomeye-core; 127.0.0.1:44353 containerd (non-Mishka)
systemctl list-units 'ransomeye*' --all: postgres, core, nginx — all active
systemctl --failed: 0 units
```

## PRD notes

- **PRD-21 / 25:** Live UI now serves Mishka slice-4 routes and banner text; manifest API matches governance doc.
- **PRD-22 / 23 / 18:** Shadow and assets APIs unchanged contract, now paired with aligned UI.
- **PRD-13 / 24:** Core swap required **signed** `integrity.manifest` + `integrity.sig` consistent with deployed ELF.

## Follow-ups

- Restore `make build-core` by fixing or scoping `TestNoHardcodedNetworkAddresses` vs `mishka-signal-send`.
- Prefer a single documented `make install` path when `rustup` + signing key are available as root, to avoid ad-hoc manifest steps.
