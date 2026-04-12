# Failure Harness

This directory contains the PRD-18 / PRD-02 / PRD-10 fail-closed validation surface for RansomEye.

## What It Covers

- PostgreSQL failure injected between telemetry and WORM inserts
- storage `ENOSPC` during sealed evidence write
- AI gRPC service crash with no fallback heuristic
- TLS validation failure on the live PostgreSQL path
- deterministic queue overflow without deadlock
- replay verification and orphan-record checks after each scenario

## Run

Generate JSON results and a Markdown report:

```bash
go run ./core/cmd/failure-harness \
  -json tests/failure/sample_output.json \
  -report tests/failure/validation_report.md
```

For a smoke pass:

```bash
go test ./tests/failure
```

## Fail Conditions

- partial persistence after a storage or DB failure
- inconsistent DB state or orphan records
- replay verification mismatch after failure
- AI output emitted after service crash
- nondeterministic overflow or deadlock
