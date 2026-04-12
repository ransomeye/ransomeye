# Performance Report

- Generated: `2026-03-23T09:43:21Z`
- Passed: `true`
- Repetitions: `3`
- Workers: `8`

| EPS | Throughput EPS | P50 ms | P95 ms | P99 ms | Memory MB | Drops | Stable |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| 1000 | 999 | 0 | 0 | 0 | 2 | 0 | true |
| 10000 | 9982 | 0 | 0 | 0 | 2 | 1329 | true |
| 50000 | 48044 | 0 | 0 | 1 | 10 | 17800 | true |
| 100000 | 49655 | 0 | 0 | 1 | 53 | 43365 | true |

## Backpressure

- Scheduler deterministic drops: `true` (128/128)
- Dispatcher deterministic drops: `true` (64/64)
- Hub deterministic drops: `true` (128/128)
- No deadlocks: `true`

## SIMD Validation

- Identical vs scalar path: `true`
- Max absolute delta: `0.000000000000`
