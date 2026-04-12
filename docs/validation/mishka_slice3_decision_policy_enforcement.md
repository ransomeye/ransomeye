# Mishka Slice 3 — Decision, policy, safety, enforcement

## Authoritative path (implemented)

1. Ingest worker: `DeterministicDetector.Evaluate` → `policy.Engine.Evaluate` → `DetectionEvent.PolicyDecision`.
2. Optional SINE: `SINEFilter.Filter` before persistence when SINE client is non-nil.
3. Persistence of detections is not gated on AI sidecar (see `worker.go` comment).
4. **Runtime enforcement pre-check**: `PolicyEvaluator.EvaluateEnforcementDispatch()` (pipeline healthy; configured SINE ready). Advisory AI and DPI **do not** gate automated dispatch.
5. `enforcement.ActionDispatcher.Dispatch` returns early when `!req.Decision.Allowed` (policy fail-closed).

## Safety / simulation (honest scope)

- `actions.SimulationGate` applies to **ISOLATE_HOST** actions via DB / HIL workflows — **not** wired on the hot path for agent kill/block-write from telemetry. SOC exposes `isolation_simulation_gate_scope` with that wording.

## Observability

- `/api/v1/health`, `/api/v1/system/health`, `/api/v1/system/ingestion-status`, `/api/v1/shadow/intelligence/status` include:
  - `enforcement_dispatch_gate_blocked`, `enforcement_dispatch_gate_reason`
  - `authoritative_decision_path`
  - `isolation_simulation_gate_scope`

## Verification commands

```bash
go test ./core/internal/policy/... -count=1
go test ./core/internal/pipeline/ -run 'TestHandleOne|TestSeal|TestBounded' -count=1 -timeout 60s
go test ./core/internal/soc/... -count=1 -timeout 90s
go build -o /tmp/ransomeye-core ./core/cmd/ransomeye-core/
```

Full `./core/internal/pipeline/...` includes long-running zero-loss tests; use a higher timeout locally if needed.
