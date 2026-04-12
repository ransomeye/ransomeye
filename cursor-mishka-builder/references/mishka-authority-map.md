# mishka prototype authority map

## hard constraints
- treat PRD-01 as root law: deterministic, fail-closed, no hidden state, explicit bounds, exact replay.
- keep authoritative runtime inside edge → ingest → queue/partition → decision → policy → safety → enforcement → storage → replay.
- keep all LLM or generative features outside the authoritative boundary. Shadow Intelligence and OPAIF are read-only and non-authoritative.
- treat PostgreSQL storage commit plus `batch_commit_record` as the only authoritative state. Kafka transport is non-authoritative.

## phase 1 exclusions
Do not build:
- high availability
- role-based access control
- windows agent
- snmp poller

Build everything else as a working prototype.

## prototype defaults for this laptop
Use these defaults unless the repo already contains a stronger, PRD-compliant implementation:
- monorepo with separately runnable services
- backend services: go
- ui: react + typescript
- database: postgresql 16
- transport: single-node redpanda or kafka in dev mode
- observability: prometheus + grafana + otel in local/dev form
- deployment: docker compose for prototype orchestration

## mandatory service set
- ingest gateway
- replay guard
- partition router
- decision engine
- policy engine
- safety guardrails service
- enforcement engine
- storage writer
- replay engine
- ui backend + soc ui
- shadow intelligence as isolated read-only component only

## build order
1. audit repo and identify drift, duplicates, dead code, and port collisions.
2. lock target architecture and service boundaries.
3. implement storage authority and execution context handling first.
4. implement ingest, replay guard, and partition routing.
5. implement decision, inference, policy, safety, and enforcement chain.
6. implement ui and asset intelligence.
7. implement replay validation and observability.
8. run end-to-end deterministic checks before expanding scope.

## required recurring checks
- no direct mutation outside PRD-13 commit path
- no runtime AI in authoritative path
- no wall-clock dependency for authoritative ordering or decisions
- no hidden in-memory-only decision state
- no skipped stage in pipeline
- no new record types beyond PRD-13 allowances
