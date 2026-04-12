# Performance Harness

This directory contains the PRD-21 / PRD-18 / PRD-02 performance validation surface for RansomEye.

## What It Covers

- load profiles at `1000`, `10000`, `50000`, and `100000` EPS
- in-memory pipeline exercise through scheduler enqueue, deterministic detector evaluation, and enforcement dispatch
- latency capture for ingestion, detection, enforcement, and end-to-end processing
- heap, allocation-rate, and GC-pause tracking
- deterministic backpressure validation for scheduler overflow, enforcement dispatch overflow, and hub subscriber drops
- vectorized-math correctness checks against the scalar prediction path

## Run

Generate JSON metrics and a Markdown report:

```bash
go run ./core/cmd/perf-harness \
  -profiles 1000,10000,50000,100000 \
  -duration 1s \
  -repetitions 3 \
  -json tests/performance/sample_output.json \
  -report tests/performance/performance_report.md
```

For a fast local smoke pass:

```bash
go test ./tests/performance
```

## Fail Conditions

- unstable P99 latency across repeated runs
- peak heap over the configured memory budget
- nondeterministic backpressure drops
- blocking enqueue/dispatch behavior
- pipeline stall / deadlock
- scalar vs vectorized math mismatch
