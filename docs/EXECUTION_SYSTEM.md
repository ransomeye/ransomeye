RansomEye Execution System — Unified Specification

Path: ~/ransomeye-source/docs/EXECUTION_SYSTEM.md
Classification: AUTHORITATIVE — EXECUTION LAYER
Scope: Cursor / LLM-driven implementation, validation, and enforcement

1. Purpose

This document defines the only valid execution model for building RansomEye.

It enforces:

Deterministic implementation behavior
Strict PRD compliance
Zero deviation from system laws
Machine-verifiable correctness before merge

This document binds together:

Prompting system (what Cursor is allowed to do)
Execution harness (how correctness is verified)
2. Execution Philosophy (Non-Negotiable)
2.1 No Interpretation Layer

Cursor is not allowed to interpret PRDs.

It must:

Translate → NOT reinterpret
Implement → NOT approximate
Enforce → NOT relax

Any ambiguity = STOP + escalate

2.2 Fail-Closed Execution

Every execution step must follow:

IF (uncertain OR unverifiable OR conflicting)
→ STOP
→ DO NOT PROCEED

No fallback logic. No assumptions.

Aligned with global system law

2.3 Deterministic Output Requirement

For identical:

Inputs
PRDs
Config
Environment

Output MUST be:

BYTE-FOR-BYTE IDENTICAL

Applies to:

Code generation
JSON
Signatures
AI outputs
WORM artifacts
3. Execution Pipeline (Mandatory)
3.1 Pipeline Stages
1. PRD Extraction
2. Constraint Mapping
3. Implementation Generation
4. Static Validation
5. Dynamic Validation
6. Cryptographic Validation
7. Determinism Check
8. Final Acceptance

No step may be skipped.

3.2 Stage Definitions
Stage 1 — PRD Extraction
Parse ONLY authoritative PRDs
Identify:
MUST rules
FORBIDDEN rules
INVARIANTS
Build constraint graph

Violation → STOP

Stage 2 — Constraint Mapping

Convert PRD rules into:

Code constraints
Schema constraints
Runtime invariants

Example:

PRD: "No float math"
→ Constraint: forbid float/double types at compile-time

Ref:

Stage 3 — Implementation Generation

Rules:

No placeholder logic
No pseudo-code
No TODOs
No inferred behavior

All code must be:

Production-grade
Deterministic
Fully typed
Fail-closed
Stage 4 — Static Validation

Must validate:

Type safety
Forbidden constructs
Schema correctness
API compliance

Examples:

Reject float usage (AI)
Reject JSONB as canonical store
Stage 5 — Dynamic Validation

Test runtime behavior:

Backpressure enforcement
No-loss guarantees
Ordering guarantees

Ref:

Core queue laws
Zero-loss pipeline
Stage 6 — Cryptographic Validation

Mandatory checks:

canonical_payload_bytes
→ SHA-256
→ signing_context + hash
→ Ed25519 verify

No alternate path allowed.

Ref:

Stage 7 — Determinism Check

Run:

Same input → multiple executions → compare output

Mismatch = FAIL

Stage 8 — Final Acceptance

Only if ALL pass:

Accept artifact
Mark as production-valid

Else:

REJECT
4. Prompt System (Cursor Control Layer)
4.1 Allowed Prompt Structure

Every execution prompt MUST include:

- Objective
- PRD references
- Constraints
- Expected output type
- Validation requirements
4.2 Forbidden Prompt Patterns

Cursor MUST reject prompts that:

Ask for approximation
Ask for shortcuts
Ignore PRDs
Introduce heuristics
4.3 Prompt → Execution Binding

Every prompt MUST map to:

PRD → Constraint → Code → Validation

If mapping is incomplete → STOP

5. Execution Rules (Hard Constraints)
5.1 Cryptography
Ed25519 ONLY for trust
SHA-256 ONLY for hashing
No alternate algorithms

Ref:

5.2 Canonical Data
Canonical JSON → TEXT only
JSONB → projection only

Ref:

5.3 No Data Loss

System MUST guarantee:

persist OR backpressure

Never drop

Ref:

Core ingest
Zero-loss
5.4 Identity Enforcement

Every event MUST include:

agent_id / probe_id
boot_session_id
system_identity_hash
message_id

Missing → reject

Ref:

5.5 Deterministic AI
Fixed-point only
No float
No runtime randomness

Ref:

5.6 Verify-Before-Use

Nothing executes before:

signature verification

Ref:

6. Execution Harness (Validation System)
6.1 Purpose

The harness enforces:

PRD compliance
Determinism
Security invariants

It is the final authority before merge

6.2 Harness Layers
Layer 1 — Structural Tests

Validate:

Schema
Types
API contracts
Layer 2 — Constraint Tests

Validate:

PRD rules enforcement
Forbidden constructs
Layer 3 — Cryptographic Tests

Validate:

Signature correctness
Canonical bytes
Hash integrity
Layer 4 — Replay Tests

Validate:

Deterministic replay
Ordering guarantees
Layer 5 — Failure Injection

Simulate:

Disk exhaustion
WAL latency
Crash windows

Ref:

Layer 6 — Backpressure Tests

Ensure:

No event loss
Proper propagation
Layer 7 — Identity Tests

Validate:

mTLS binding
session binding
identity propagation

Ref:

6.3 Pass Criteria

A build is valid ONLY if:

ALL tests PASS
AND determinism holds
AND no PRD violation detected
6.4 Fail Criteria

Immediate rejection if:

Any PRD violated
Any nondeterminism detected
Any cryptographic mismatch
Any data loss path exists
7. Enforcement Model
7.1 Absolute Rules

Cursor MUST:

Refuse invalid tasks
Reject incomplete implementations
Block unsafe code
7.2 No Partial Completion

This is forbidden:

"Partially correct"
"Mostly compliant"
"Temporary workaround"

Only:

FULLY COMPLIANT OR REJECTED
7.3 No Silent Degradation

System MUST NOT:

Switch modes silently
Reduce guarantees
Skip validation

Ref:

8. Output Contract

Every execution must produce:

8.1 Code
Production-ready
Deterministic
Fully validated
8.2 Validation Report

Must include:

- PRDs referenced
- Constraints enforced
- Tests executed
- Determinism proof
8.3 Reproducibility Guarantee

Given same inputs:

Output MUST be identical
9. System Integration

This execution system governs:

Core Engine (PRD-06)
AI Engine (PRD-07)
SINE (PRD-08)
Agents (PRD-11 / PRD-12)
WORM (PRD-15)
Pipeline (PRD-16)

It is mandatory.

10. Final Law
IF implementation != PRD
→ implementation is INVALID
→ MUST NOT SHIP

No exceptions.

Deliverable Summary
Merged both documents into single execution authority
Removed duplication
Enforced strict PRD alignment
Embedded validation + prompt system into one pipeline
