RansomEye Implementation Prompt System (Cursor Control Layer)
GLOBAL LAW (NON-NEGOTIABLE)
Cursor MUST generate code ONLY from cited PRD clauses.
If any required behavior is not explicitly defined → return UNSPECIFIED_BY_PRD and STOP.
No inference, no approximation, no gap-filling.
Every symbol MUST map to PRD authority.
Any deviation = PROJECTION_DRIFT.
Validation outcomes MUST match **PRD-01 §9** exactly:
- missing → `UNSPECIFIED_BY_PRD`
- extra → `PROJECTION_DRIFT`
- structural collision → `BUILD_FAIL`
No alternate terminal constants.
No reinterpretation of failure classes.

PRD_AUTHORITY MUST be:
- COMPLETE for task domain
- MINIMAL (no unrelated clauses)
- SUFFICIENT to derive all REQUIRED_SYMBOL_MAP entries
- exactly match the clause set defined in **PRD-01 §9** (PRD CLAUSE COVERAGE REGISTRY) for the requested domain

Missing required clause from **PRD-01 §9** → `UNSPECIFIED_BY_PRD`
Extra clause beyond **PRD-01 §9** → `PROJECTION_DRIFT`
Parent-child collision in **PRD_AUTHORITY** → `BUILD_FAIL`

SINGLE PATH ENFORCEMENT (MANDATORY)

If a PRD defines a canonical execution path, Cursor MUST generate exactly one implementation path.

The following are strictly forbidden:
- Parallel verification pipelines
- Alternate signing_input construction
- Multiple serialization strategies for the same message class
- Mixed-version handlers for identical route shapes
- Redundant validation branches producing the same outcome

Any attempt to introduce alternate or “equivalent” logic paths MUST result in:
PROJECTION_DRIFT

(PRD-02; PRD-06 §4.1; PRD-10 §3; PRD-15 §7; PRD-20 §18)

SIGNING_CONTEXT REGISTRY (MANDATORY)

Allowed values (closed set):

- ransomeye:v1:config:signed_config
- ransomeye:v1:telemetry:event
- ransomeye:v1:telemetry:heartbeat
- ransomeye:v1:worm:evidence_record
- ransomeye:v1:worm:daily_root
- ransomeye:v1:rpc:action_dispatch
- ransomeye:v1:rpc:request_detection
- ransomeye:v1:rpc:request_narrative
- ransomeye:v1:governance:policy_change
- ransomeye:v1:update:bundle_manifest
- ransomeye:v1:migration:manifest
- ransomeye:v1:deception:event
- ransomeye:v1:probe:flow_batch

Rules:
- Closed set
- No dynamic generation
- Unknown value → REJECT_BEFORE_QUEUE
(PRD-02; PRD-20 §18.4.1)

SIGNATURE LAW (MANDATORY)

- signing_input = signing_context || SHA-256(canonical_payload_bytes)
- Any deviation → PROJECTION_DRIFT
(PRD-02 §4.3; PRD-06 §4.1; PRD-10 §3; PRD-15 §7)

DETERMINISTIC FAILURE ACTIONS (MANDATORY)

- Canonical failure → REJECT_BEFORE_QUEUE
- Signing_context invalid → REJECT_BEFORE_QUEUE
- Signature invalid → REJECT_BEFORE_QUEUE
- Identity failure → REJECT
- Replay duplicate → IDEMPOTENT_ACK
- Replay mismatch → REJECT
- Queue overflow → BACKPRESSURE → FAIL_CLOSED
- SINE timeout → terminate request only
- WORM seal failure → Record invalid for forensic purposes; MUST NOT be treated as admissible evidence
(PRD-06; PRD-10; PRD-15; PRD-19; PRD-20 §18)
PROMPT TEMPLATE (MANDATORY STRUCTURE)

Every prompt MUST follow this exact structure:

SYSTEM LAW
Generate only from cited PRD clauses. No assumptions. No extensions.

TASK
[Concrete implementation task]

PRD_AUTHORITY
[List exact PRD sections]

REQUIRED_SYMBOL_MAP
[Symbol → PRD mapping]

INPUT_CONTRACT
[Exact input schema definition]

OUTPUT_CONTRACT
[Exact output schema definition]

INVARIANTS
[Deterministic invariants derived from PRDs]

FORBIDDEN
[Explicit forbidden constructs from PRDs]

ACCEPTANCE_LAWS
[Binary acceptance rules]

REJECTION_LAWS
[Binary rejection rules]

SINGLE_PATH_ASSERTION
Implementation MUST follow exactly one canonical path derived from PRD_AUTHORITY.
Multiple or branching-equivalent paths are forbidden.

If any symbol or behavior is not mapped to PRD_AUTHORITY → UNSPECIFIED_BY_PRD and STOP.
TEMPLATE 1 — CORE INGEST VERIFICATION
SYSTEM LAW
Generate only from cited PRD clauses. If undefined → UNSPECIFIED_BY_PRD.

TASK
Implement Core pre-queue ingest verification pipeline.

PRD_AUTHORITY
- PRD-02 §4.3
- PRD-02 §4.2
- PRD-04 §§4,6,7
- PRD-06 §4.1, §5
- PRD-10 §3, §3.1, §4
- PRD-16 §7

REQUIRED_SYMBOL_MAP
- CanonicalizePayload → PRD-02
- VerifySigningContext → PRD-02
- VerifySignature → PRD-02, PRD-10
- VerifyIdentity → PRD-04
- ReplayCheck → PRD-10, PRD-16
- RejectBeforeQueue → PRD-06

INPUT_CONTRACT
- canonical_payload_bytes: []byte
- signing_context: string
- signature: []byte
- message_id: UUID
- system_identity_hash: []byte

OUTPUT_CONTRACT
- ACCEPT | REJECT_BEFORE_QUEUE | REJECT | IDEMPOTENT_ACK

INVARIANTS
- signing_input = signing_context || SHA-256(canonical_payload_bytes)
- verification order fixed
- no partial execution

FORBIDDEN
- alternate signing_input
- unordered verification
- queue-before-verify
- best effort / fallback

ACCEPTANCE_LAWS
- all checks pass → ACCEPT

REJECTION_LAWS
- canonical failure → REJECT_BEFORE_QUEUE
- signing_context failure → REJECT_BEFORE_QUEUE
- signature failure → REJECT_BEFORE_QUEUE
- identity/session failure → REJECT
- replay same hash → IDEMPOTENT_ACK
- replay different hash → REJECT
TEMPLATE 2 — AI INFERENCE (DETERMINISTIC)
SYSTEM LAW
No float operations. Deterministic only.

TASK
Implement deterministic AEC inference.

PRD_AUTHORITY
- PRD-07 §1–§4, §10, §12
- PRD-20 §3.5

REQUIRED_SYMBOL_MAP
- ComputePosterior → PRD-07
- ApplyThresholds → PRD-07
- EnforceFeatureOrder → PRD-07

INPUT_CONTRACT
- feature_vector: []int64 (ordered)
- model_config: signed struct

OUTPUT_CONTRACT
- aec_score: int64
- classification: enum

INVARIANTS
- S = 10^12 scaling
- thresholds strictly ordered
- no float math

FORBIDDEN
- float/double
- unordered features
- runtime threshold override

ACCEPTANCE_LAWS
- identical input → identical output

REJECTION_LAWS
- invalid config → FAIL_CLOSED
TEMPLATE 3 — SINE NARRATIVE GENERATION
SYSTEM LAW
SINE is deterministic and bounded.

TASK
Generate narrative from detection.

PRD_AUTHORITY
- PRD-08 §3, §4.1, §5, §6, §9

REQUIRED_SYMBOL_MAP
- BuildPrompt → PRD-08
- ExecuteModel → PRD-08

INPUT_CONTRACT
- detection_id
- structured_features
- prompt_template (fixed)

OUTPUT_CONTRACT
- {
  "detection_id": "...",
  "model_hash": "...",
  "prompt_hash": "...",
  "system_identity_hash": "...",
  "timestamp": "...",
  "narrative_text": "..."
}

INVARIANTS
- canonical JSON artifact only
- no randomness
- fixed template
- bounded tokens

FORBIDDEN
- streaming output
- prompt mutation
- external calls

ACCEPTANCE_LAWS
- deterministic output
- exact canonical artifact schema match

REJECTION_LAWS
- timeout → kill request only
TEMPLATE 4 — WORM SEAL
SYSTEM LAW
Forensic integrity is absolute.

TASK
Seal forensic record.

PRD_AUTHORITY
- PRD-15 §3, §5, §7, §8

REQUIRED_SYMBOL_MAP
- ComputeHash → PRD-15
- SignRecord → PRD-15
- BuildMerkle → PRD-15

INPUT_CONTRACT
- canonical_payload
- signing_context

OUTPUT_CONTRACT
- sealed_record

INVARIANTS
- SHA-256 hash
- Ed25519 signature
- Merkle inclusion

FORBIDDEN
- mutation after seal
- re-signing

ACCEPTANCE_LAWS
- valid seal → admissible

REJECTION_LAWS
- seal failure → Record invalid for forensic purposes; MUST NOT be treated as admissible evidence
TEMPLATE 5 — REST API HANDLER
SYSTEM LAW
Strict contract. No deviation.

TASK
Implement SOC API endpoint.

PRD_AUTHORITY
- PRD-10 §10
- PRD-10 §13
- PRD-21 §5

REQUIRED_SYMBOL_MAP
- BuildResponseEnvelope → PRD-21
- ApplyPagination → PRD-21

INPUT_CONTRACT
- cursor
- limit

OUTPUT_CONTRACT
- { data, meta, errors }

INVARIANTS
- cursor-based pagination only
- deterministic errors

FORBIDDEN
- offset pagination
- raw exceptions
- alternate response shape

ACCEPTANCE_LAWS
- exact schema match

REJECTION_LAWS
- contract violation → PROJECTION_DRIFT
ENFORCEMENT
Any Cursor output missing PRD references → UNSPECIFIED_BY_PRD
Any symbol without mapping → UNSPECIFIED_BY_PRD
Any duplicate symbol or structural collision → BUILD_FAIL
Any non-determinism → PROJECTION_DRIFT
Any fallback logic → PROJECTION_DRIFT
TERMINATION CONDITIONS

Cursor MUST STOP with:

UNSPECIFIED_BY_PRD
PROJECTION_DRIFT
BUILD_FAIL

CI ENFORCEMENT (MANDATORY)

- Missing signing-context registry entry → UNSPECIFIED_BY_PRD
- Extra or mismatched signing-context → PROJECTION_DRIFT
- Duplicate signing-context → BUILD_FAIL
- Canonical mismatch → PROJECTION_DRIFT
- Snapshot drift → PROJECTION_DRIFT
- Cross-language mismatch → PROJECTION_DRIFT
- Determinism failure → PROJECTION_DRIFT
(PRD-20 §3, §13)

END OF FILE
