# Mishka Slice 1 — Authoritative signal path (PRD-05, 07, 08, 16, 03, 04 touchpoints)

## What is implemented (reuse)

| Area | Location | Notes |
|------|----------|--------|
| PRD-03 envelope + hashes + Ed25519 | `core/internal/gateway/signal_ingest.go` (`SendSignal`) | `ComputeSignalMessageID`, `ComputeSignalSigningInput`, `CanonicalizeStrictJSONRFC8785Like` exported for clients |
| PRD-04 emitter key | `core/internal/storage/authority/key_resolution.go` | `ResolveEmitterPublicKeyByIdentity` reads **committed** `authority_snapshots` trust material |
| PRD-08 verify-before-admit | Same + `checkSignalReplayGuard` | Canonical JSON, identity, payload/partition hashes, signature, replay cursor, then `CommitPartitionBatch` only |
| PRD-16 transport (edge → core) | mTLS gRPC `RansomEyeService.SendSignal` | `proto/ransomeye.proto`, `core/internal/gateway/server.go` binds loopback |
| PRD-05 / 07 payload | Caller-supplied canonical JSON bytes | Schema evolution is explicit via `protocol_version` / record typing in authority commit |

## What is partial / operator-dependent

- **Trust snapshot**: Core must have a committed trust_snapshot whose key index includes the **emitter_id** (first 16 bytes of Ed25519 pubkey, 32 hex chars) with **ACTIVE** status and an **allowed signing_context** (e.g. `ransomeye:v1:telemetry:event`).
- **PRD-13 execution context**: Live `ransomeye-core` requires `RANSOMEYE_PRD13_*` env (bindings, snapshots, commit signer) consistent with the running partition — same as authority DB tests.
- **Nginx (443)**: Terminates TLS for SOC **REST/WebSocket** only; **authoritative signal ingress is gRPC to core**, not `POST /api/...` (avoids duplicating verify logic outside the gateway).

## Smoke client (runtime proof)

Build:

```bash
go build -o /tmp/mishka-signal-send ./core/cmd/mishka-signal-send
```

Run against live core (requires trust material for the emitter seed you pass):

```bash
/tmp/mishka-signal-send \
  -addr 127.0.0.1:50051 \
  -ca /opt/ransomeye/core/certs/ca-chain.crt \
  -cert /etc/ransomeye/client.crt \
  -key /etc/ransomeye/client.key \
  -emitter-key-hex <64-hex-ed25519-seed-listed-in-trust-snapshot>
```

## Automated proof (CI / laptop)

```bash
sudo env POSTGRES_DSN='postgres://…' PGSSLROOTCERT=… PGSSLCERT=… PGSSLKEY=… PGSSLMODE=verify-full PGSSLSERVERNAME=127.0.0.1 \
  go test ./core/internal/gateway -run TestSendSignal_DB_E2E_AcceptedCommitCoupling -count=1 -v
```

Legacy **binary telemetry** path remains `SendTelemetry` (`tools/test_ingest`); Mishka **authoritative** path for new work is **`SendSignal`**.
