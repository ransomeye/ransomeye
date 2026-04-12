## PRD-20 Core Queue + Hub Validation Execution Report

### Scope

- Target: Core queue and hub fan-out validation (`PRD-06`, `PRD-16`, `PRD-19`, `PRD-20`)
- Authority loaded:
  - `prd/newprd/PRD-06_Core_Engine.md`
  - `prd/newprd/PRD-16_Data_Pipeline_ZeroLoss.md`
  - `prd/newprd/PRD-19_Resource_Failsafe.md`
  - `prd/newprd/PRD-20_Testing_Validation.md`
  - `docs/EXECUTION_HARNESS.md`

### Executed Validation Commands

- Queue suite (FIFO/concurrency, memory->disk ordering, crash+replay, disk state transitions, determinism):
```text
go test ./internal/pipeline -run 'TestQueue_' -count=1 -timeout=120s -v
```

```text
=== RUN   TestQueue_CrashReplay_OrderIntegrity
--- PASS: TestQueue_CrashReplay_OrderIntegrity (0.00s)
=== RUN   TestQueue_DiskExhaustion_StateTransitions
--- PASS: TestQueue_DiskExhaustion_StateTransitions (0.40s)
=== RUN   TestQueue_StrictFIFO_ConcurrentProducers
    ringbuffer_test.go:110: StrictFIFO concurrent: producers=12 perProducer=50 total=600 first=1 last=600
--- PASS: TestQueue_StrictFIFO_ConcurrentProducers (0.00s)
=== RUN   TestQueue_FIFO_AcrossMemoryDiskBoundary
    ringbuffer_test.go:144: FIFO across boundary: memCap=2 total=24 first=1 last=24
--- PASS: TestQueue_FIFO_AcrossMemoryDiskBoundary (0.06s)
=== RUN   TestQueue_DeterministicExecution
    ringbuffer_test.go:193: Determinism hash run=0 hash=259171690a58d74dce8050db11e4b6e1b9ab4f235946d53af32c9dc7a7d72d15 total=1000
--- PASS: TestQueue_DeterministicExecution (17.46s)
PASS
ok  	ransomeye/core/internal/pipeline	17.930s
```

- Hub suite (slow subscriber deterministic blocking + no-drop/no-starvation/no-reordering):
```text
go test ./internal/pipeline -run 'TestHub_SlowSubscriberEnforcesDeterministicBlocking' -count=1 -timeout=120s -v
```

```text
=== RUN   TestHub_SlowSubscriberEnforcesDeterministicBlocking
    hub_test.go:110: TryPublish completed while slow subscriber was stalled; expected deterministic blocking or lossless persistence
--- FAIL: TestHub_SlowSubscriberEnforcesDeterministicBlocking (0.05s)
FAIL
FAIL	ransomeye/core/internal/pipeline	0.053s
FAIL
```

### Test Outcomes (PRD-20)

- `TestQueue_StrictFIFO_ConcurrentProducers` (PRD-06 FIFO under concurrency; PRD-16 strict FIFO across boundary): PASS (ordering preserved: received `1..600`, log `first=1 last=600`)
- `TestQueue_FIFO_AcrossMemoryDiskBoundary` (PRD-06 memory->disk spill ordering; PRD-16 no reordering across spill): PASS (ordering preserved: received `1..24`, log `memCap=2 total=24 first=1 last=24`; spill evidence: durable queue log non-empty)
- `TestQueue_CrashReplay_OrderIntegrity` (PRD-06 crash safety + replay correctness; PRD-19 fail-closed on corruption): PASS (truncated tail: fail-closed + tail truncated; checksum corruption: fail-closed + tail truncated; reopen preserves valid prefix ordering)
- `TestQueue_DiskExhaustion_StateTransitions` (PRD-19 `NORMAL -> BACKPRESSURE -> DISK_EXHAUSTED -> FAIL_CLOSED`; deterministic blocking/no deadlock): PASS (enqueue blocks under forced `StateBackpressure` and `StateDiskExhausted`, then panics under `StateFailClosed`)
- `TestQueue_DeterministicExecution` (PRD-20 determinism / repeated identical output): PASS (determinism hash run=0: `259171690a58d74dce8050db11e4b6e1b9ab4f235946d53af32c9dc7a7d72d15`)
- `TestHub_SlowSubscriberEnforcesDeterministicBlocking` (PRD-16 no-drop + deterministic blocking/no-starvation/no-reordering): FAIL
- Failure evidence: `hub_test.go:110` (publisher completed early while slow subscriber was stalled)

### P0 Defects (Release-Blocking)

- `P0-1: Hub deterministic blocking/no-loss invariant not proven` (evidence: `TestHub_SlowSubscriberEnforcesDeterministicBlocking` fails; `hub_test.go:110` publisher completes while slow subscriber stalled)
- PRD-20 impact: breaks the required deterministic blocking-or-lossless behavior for hub fan-out under slow subscriber pressure (violates the validation’s no-drop/no-starvation/no-reordering contract)

### Final Verdict

- **FAIL**
- Reason: Core queue PRD-20 scenarios passed, but the hub fan-out validation fails to demonstrate deterministic blocking/no-drop under slow subscriber stall conditions.

