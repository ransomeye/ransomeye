GLOBAL LAW (PRD-20 §18; PRD-02 §4.3; PRD-02 §4.2; PRD-06 §4.1; PRD-15 §7)
- RULE: binary gate only; fail-closed only; uncited behavior forbidden; alternate equivalent path forbidden. FAIL: `UNSPECIFIED_BY_PRD` or `PROJECTION_DRIFT`. (PRD-20 §18 CG-03; PRD-20 §18 CG-04; PRD-20 §18 CG-06)
- RULE: clause-bound input only; exact clause mapping for every generated symbol only; exact acceptance invariants only; exact rejection conditions only. FAIL: `UNSPECIFIED_BY_PRD`. (PRD-20 §18 CG-01; PRD-20 §18 CG-02; PRD-20 §18 CG-03; PRD-20 §18 CG-07)
- RULE: PRD-01 §9 is the sole authority for control-layer validation outcomes. (PRD-01 §9)
- RULE: missing violation class MUST terminate as `UNSPECIFIED_BY_PRD`. (PRD-01 §9)
- RULE: extra violation class MUST terminate as `PROJECTION_DRIFT`. (PRD-01 §9)
- RULE: structural collision violation class MUST terminate as `BUILD_FAIL`. (PRD-01 §9)
- RULE: any alternate terminal constant or layer-specific reinterpretation → `PROJECTION_DRIFT`. (PRD-01 §9)
0. SKILL VALIDATOR (PRD-20 §18 CG-06; PRD-01 §7.1; PRD-01 §8)
- VALIDATE: non-numeric clause reference. FAIL: `PROJECTION_DRIFT`. (PRD-01 §9)
- VALIDATE: every line in skill files maps to explicit PRD clause ID. FAIL: `PROJECTION_DRIFT`.
- VALIDATE: invariant text in skill matches PRD clause text exactly (no paraphrasing). FAIL: `PROJECTION_DRIFT`.
- VALIDATE: no omission of any clause required for that domain. FAIL: `UNSPECIFIED_BY_PRD`.
- VALIDATE: no additional behavior beyond PRD clauses. FAIL: `PROJECTION_DRIFT`.
- VALIDATE: all three skill files are structurally identical for shared sections. FAIL: `PROJECTION_DRIFT`.
0.1 PRD COVERAGE REGISTRY VALIDATOR (PRD-01 §7.1; PRD-20 §18)
- DEFINE: required PRD clause set MUST be loaded from **PRD-01 §9** (PRD CLAUSE COVERAGE REGISTRY).
- VALIDATE: full clause-set coverage for domain. FAIL: `UNSPECIFIED_BY_PRD`.
- VALIDATE: every clause required by **PRD-01 §9** for the domain is present in the skill file clause coverage set. FAIL: `UNSPECIFIED_BY_PRD`.
- VALIDATE: no extra clause beyond the domain clause set defined by **PRD-01 §9** appears in the skill file clause coverage set. FAIL: `PROJECTION_DRIFT`.
- VALIDATE: no registry domain lists a numeric parent clause together with any of its child clauses in the same domain clause set, per PRD-01 §9 granularity law. FAIL: `BUILD_FAIL`.
- VALIDATE: clause enumeration source MUST be static and versioned. Dynamic inference forbidden. FAIL: `PROJECTION_DRIFT`.
1. PROMPT VALIDATOR (PRD-20 §18)
- VALIDATE: PRD_AUTHORITY must exactly match the **PRD-01 §9** registry clause set for the requested domain; no subset and no superset. Missing clause → `UNSPECIFIED_BY_PRD`; extra clause → `PROJECTION_DRIFT`.
- VALIDATE: cited governing clauses present for every requested domain in scope. FAIL: `UNSPECIFIED_BY_PRD`. (PRD-20 §18 CG-01; PRD-20 §18 CG-03)
- VALIDATE: PRD_AUTHORITY set is COMPLETE for the requested domain. FAIL: `UNSPECIFIED_BY_PRD`.
- VALIDATE: PRD_AUTHORITY contains no superfluous clauses unrelated to task. FAIL: `PROJECTION_DRIFT`.
- VALIDATE: PRD_AUTHORITY minimal set produces full REQUIRED_SYMBOL_MAP coverage. FAIL: `UNSPECIFIED_BY_PRD`.
- VALIDATE: every generated function, method, migration, route, proto message, test, and config field maps to one or more exact PRD clauses. FAIL: `UNSPECIFIED_BY_PRD`. (PRD-20 §18 CG-02; PRD-20 §18 CG-03)
- VALIDATE: one canonical path only where cited clauses define one canonical path. FAIL: `PROJECTION_DRIFT`. (PRD-20 §18 CG-04; PRD-20 §18 CG-06; PRD-02 §4.1; PRD-06 §4.1; PRD-10 §3; PRD-15 §7)
- VALIDATE: exact acceptance invariants present and exact rejection conditions present. FAIL: `UNSPECIFIED_BY_PRD`. (PRD-20 §18 CG-07; PRD-20 §18 CG-03)
1.1 PROMPT-TO-OUTPUT TRACE VALIDATOR (PRD-20 §18; PRD-01 §7.1; PRD-01 §8)
- VALIDATE: every REQUIRED_SYMBOL_MAP entry is implemented in output at least once. Missing REQUIRED_SYMBOL_MAP entry → `UNSPECIFIED_BY_PRD`. (PRD-20 §2; PRD-01 §9)
- VALIDATE: every generated symbol in output exists in REQUIRED_SYMBOL_MAP from prompt. Extra symbol → `PROJECTION_DRIFT`. (PRD-20 §2; PRD-01 §9)
- VALIDATE: no REQUIRED_SYMBOL_MAP entry or generated symbol is duplicated in output. Duplicate symbol → `BUILD_FAIL`. (PRD-20 §2; PRD-01 §9)
- VALIDATE: no additional symbols exist in output beyond REQUIRED_SYMBOL_MAP and explicitly cited PRD-derived structures (no surplus symbols). FAIL: `PROJECTION_DRIFT`. (PRD-20 §18 CG-02)
- VALIDATE: symbol-to-PRD mapping preserved without alteration; symbol behavior matches cited PRD clauses exactly. FAIL: `PROJECTION_DRIFT`.
- VALIDATE: execution flow in output matches ACCEPTANCE_LAWS and REJECTION_LAWS from prompt exactly; no additional branches. FAIL: `PROJECTION_DRIFT`.
1.2 PRD-TO-PROMPT EQUIVALENCE VALIDATOR (PRD-20 §18 CG-07)
- VALIDATE: every ACCEPTANCE_LAW in prompt is directly derivable from cited PRD clauses. FAIL: `PROJECTION_DRIFT`.
- VALIDATE: every REJECTION_LAW in prompt matches exact PRD-defined failure behavior. FAIL: `PROJECTION_DRIFT`.
- VALIDATE: no acceptance or rejection rule exists in prompt without explicit PRD clause backing. FAIL: `UNSPECIFIED_BY_PRD`.
- VALIDATE: no PRD-defined branch is omitted in prompt. FAIL: `UNSPECIFIED_BY_PRD`.
1.3 SYMBOL-CLAUSE BIJECTION VALIDATOR (PRD-20 §18 CG-02)
- VALIDATE: every symbol maps to ≥1 PRD clause. Missing clause mapping → `UNSPECIFIED_BY_PRD`.
- VALIDATE: every PRD clause in PRD_AUTHORITY maps to ≥1 symbol. Missing clause mapping → `UNSPECIFIED_BY_PRD`.
- VALIDATE: no symbol maps to any clause outside PRD_AUTHORITY. Extra clause mapping → `PROJECTION_DRIFT`.
- VALIDATE: no symbol-to-clause collision, duplicate clause ownership, or duplicated mapping edge exists. Collision or duplication → `BUILD_FAIL`. (PRD-20 §2; PRD-01 §9)
2. OUTPUT VALIDATOR (PRD-20 §2; PRD-20 §18)
- VALIDATE: trust-bearing output uses `Ed25519` and `SHA-256` only; raw-payload verification absent; ciphertext signing absent; alternate digest absent; dual verification path absent. FAIL: `BUILD_FAIL`. (PRD-20 §2 CT-01; PRD-02 §4.3; PRD-02 §4.4; PRD-10 §3; PRD-15 §3)
- VALIDATE: exactly one signing-input constructor equals `signing_context || SHA-256(canonical_payload_bytes)`. FAIL: `BUILD_FAIL`. (PRD-20 §2 CT-02; PRD-02 §4.3; PRD-06 §4.1; PRD-10 §3; PRD-15 §7)
- VALIDATE: SOC response output equals `{ data, meta, errors }`; paginated output accepts `cursor` and `limit` only; `offset`, `page`, and `page_number` absent. FAIL: `BUILD_FAIL`. (PRD-20 §2 CT-06; PRD-10 §2; PRD-10 §13; PRD-21 §5)
- VALIDATE: canonical/signed/hashed JSON stored only as non-empty TEXT; JSONB exists only as generated projection; JSONB not used as authoritative source; JSONB not used for hashing or signature input. FAIL: `BUILD_FAIL`. (PRD-20 §2 CT-04; PRD-05 §6; PRD-05 §9.2; PRD-05 §9.2.1)
- VALIDATE: no environment-variable sourcing for secrets, ports, cryptographic configuration, or trust primitives; all values originate from signed configuration only. FAIL: `BUILD_FAIL`. (PRD-02 §2.1; PRD-20 §2 CT-01)
- VALIDATE: no alternate REST contract behavior; no in-place breaking changes under `/api/v1/`; no mixed-version behavior for identical route shape; no alternate top-level response body beyond `{ data, meta, errors }`; no offset pagination; no silent page-size clamping; no raw exception leakage; no fail-open rate limiting. FAIL: `BUILD_FAIL`. (PRD-10 §10; PRD-10 §13; PRD-21 §5; PRD-21 §6.4)
- VALIDATE: single execution path enforced for each deterministic flow; no parallel or redundant validation pipelines producing equivalent outcomes; no alternate serialization or verification paths. FAIL: `PROJECTION_DRIFT`. (PRD-20 §18 CG-04; PRD-02; PRD-06 §4.1; PRD-10 §3; PRD-15 §7)
3. SIGNING CONTEXT ENFORCER (PRD-02 §4.2; PRD-20 §13.1; PRD-20 §13.2; PRD-20 §13.3)
- VALIDATE: every extracted `signing_context` has a registry entry. Missing registry entry → `UNSPECIFIED_BY_PRD`. (PRD-20 §13.1; PRD-02 §4.2; PRD-01 §9)
- VALIDATE: no extra or unknown `signing_context` appears beyond the allowed registry set. Extra symbol → `PROJECTION_DRIFT`. (PRD-20 §13.1; PRD-20 §13.2; PRD-02 §4.2; PRD-01 §9)
- VALIDATE: `signing_context` values are unique and preserve a 1:1 mapping with message type. Duplicate symbol → `BUILD_FAIL`. (PRD-20 §13.1; PRD-20 §13.2; PRD-20 §13.3; PRD-02 §4.2; PRD-01 §9)
- VALIDATE: pre-queue `signing_context` present and valid. FAIL: `REJECT_BEFORE_QUEUE`. (PRD-06 §4.1; PRD-10 §3.1)
4. DETERMINISM CHECKER (PRD-20 §2; PRD-20 §3.1; PRD-20 §3.4; PRD-20 §3.5; PRD-20 §3.6; PRD-07 §1-§4; PRD-07 §10.1-§10.3; PRD-07 §12.1; PRD-07 §14; PRD-08 §4.1; PRD-08 §5; PRD-08 §9)
- VALIDATE: no `float`, `double`, `numpy.float64`, hardware float math, `REAL`, `DOUBLE PRECISION`, or non-integer `NUMERIC/DECIMAL` in inference or persisted probability paths; `S = 10^12`; `Q = 2^48`. FAIL: `BUILD_FAIL`. (PRD-20 §2 CT-07; PRD-07 §1-§4; PRD-07 §14; PRD-05 §9.0)
- VALIDATE: `aec_1_threshold`, `aec_2_threshold`, and `aec_3_threshold` exist in signed `model_config`, are scaled `BIGINT`, are strictly ordered, and are the only thresholds used; `feature_schema_version` maps to one indexed order only. FAIL: `BUILD_FAIL`. (PRD-20 §2 CT-08; PRD-07 §10.1-§10.3; PRD-07 §12.1)
- VALIDATE: SINE prompt template, field order, generation parameters, and bounded narrative scope are fixed release artifacts; randomness absent; prompt mutation absent; runtime overrides absent; streaming partials absent. FAIL: `BUILD_FAIL`. (PRD-20 §2 CT-09; PRD-08 §4.1; PRD-08 §5; PRD-08 §9)
- VALIDATE: repeated runs with identical signed input produce byte-identical canonical serialization, fixed-point math outputs, replay verification results, manifest validation results, database outputs, forensic outputs, and SINE outputs. FAIL: `PROJECTION_DRIFT`. (PRD-20 §3.1; PRD-20 §3.4; PRD-20 §3.5; PRD-20 §3.6; PRD-01 §9)
5. FAILURE MODE VALIDATOR (PRD-20 §3; PRD-06 §4.1; PRD-06 §5; PRD-06 §5.2; PRD-10 §3; PRD-10 §3.1; PRD-10 §4; PRD-15 §7; PRD-15 §7.1; PRD-15 §10.1; PRD-15 §12; PRD-16 §2; PRD-16 §7; PRD-19 §4; PRD-19 §11)
- VALIDATE: canonical payload valid before hash, signature verification, queue admission, or ACK. FAIL: `REJECT_BEFORE_QUEUE`. (PRD-20 §3; PRD-06 §4.1; PRD-10 §3)
- VALIDATE: `signing_context` valid before signature verification or queue admission. FAIL: `REJECT_BEFORE_QUEUE`. (PRD-20 §3; PRD-06 §4.1; PRD-10 §3.1)
- VALIDATE: signature valid on the canonical signing input. FAIL: `REJECT_BEFORE_QUEUE`. (PRD-20 §3; PRD-10 §3.1)
- VALIDATE: identity, fingerprint, `boot_session_id`, session, and `system_identity_hash` valid. FAIL: `REJECT`. (PRD-20 §3; PRD-04 §3-§7; PRD-10 §3.1)
- VALIDATE: duplicate replay with same `message_id` and same hash. OUTPUT: `IDEMPOTENT_ACK`. (PRD-20 §3; PRD-10 §4)
- VALIDATE: duplicate replay with same `message_id` and different hash. FAIL: `REJECT`. (PRD-20 §3; PRD-10 §4; PRD-16 §7)
- VALIDATE: durable spill path available within policy threshold. FAIL: `BACKPRESSURE` then `FAIL_CLOSED`. (PRD-20 §3; PRD-06 §5; PRD-19 §4)
- VALIDATE: drop path absent; overwrite path absent; overflow-discard path absent. FAIL: `FAIL_CLOSED`. (PRD-20 §3; PRD-06 §5.2; PRD-16 §2; PRD-16 §11; PRD-19 §11)
- VALIDATE: WORM read signature, Merkle path, and root verification valid. FAIL: `REJECT_READ`. (PRD-20 §3; PRD-15 §7)
- VALIDATE: replay verification valid. FAIL: `REJECT_REPLAY`. (PRD-20 §3; PRD-15 §7.1; PRD-15 §12)
- VALIDATE: export verification valid. FAIL: `REJECT_EXPORT`. (PRD-20 §3; PRD-15 §10.1; PRD-15 §12)
6. CI GATE BINDING (PRD-20 §13; PRD-20 §3.1; PRD-20 §3.2; PRD-20 §3.3; PRD-20 §3.4; PRD-20 §3.5; PRD-20 §3.6; PRD-20 §6; PRD-20 §7; PRD-20 §9; PRD-20 §14; PRD-20 §15; PRD-20 §16; PRD-20 §17)
- VALIDATE: Stage 1 static contract gate enforces signing-context registry, forbidden symbols, schema completeness, API contract, AI numeric rules, and SINE generation rules. FAIL: `BUILD_FAIL`. (PRD-20 §13)
- VALIDATE: Stage 2 golden crypto vector gate enforces `canonical_payload_bytes`, `SHA-256`, `signing_input`, and `Ed25519` verification parity in Go, Rust, and Python. FAIL: `PROJECTION_DRIFT`. (PRD-20 §3.2; PRD-20 §3.3; PRD-01 §9)
- VALIDATE: Stage 3 snapshot gate enforces byte-match on canonical JSON and deterministic protobuf snapshots. FAIL: `PROJECTION_DRIFT`. (PRD-20 §3.4; PRD-01 §9)
- VALIDATE: Stage 4 cross-language parity gate enforces exact parity on canonical serialization, fixed-point math, replay verification, and manifest validation. FAIL: `PROJECTION_DRIFT`. (PRD-20 §3.1; PRD-01 §9)
- VALIDATE: Stage 5 determinism gate enforces byte-identical end-to-end, database, forensic, and SINE outputs across repeated runs with identical signed inputs. FAIL: `PROJECTION_DRIFT`. (PRD-20 §3.5; PRD-20 §3.6; PRD-01 §9)
- VALIDATE: Stage 6 no-loss, WORM, and replay gate enforces stress, replay, export round-trip, tamper, seal-failure, and fail-closed pass conditions. FAIL: `PROJECTION_DRIFT`. (PRD-20 §6; PRD-20 §7; PRD-20 §12; PRD-01 §9)
- VALIDATE: Stage 7 resource and SLA gate enforces deterministic backpressure, deterministic fail-closed behavior, and release-blocking SLA compliance. FAIL: `PROJECTION_DRIFT`. (PRD-20 §9; PRD-20 §14; PRD-19 §4; PRD-19 §11; PRD-01 §9)
- VALIDATE: Stage 8 supply-chain and air-gap gate enforces exact dependency registry, bundle verification, and rollback rejection. FAIL: `PROJECTION_DRIFT`. (PRD-20 §15; PRD-20 §16; PRD-01 §9)
- VALIDATE: Stage 9 release certification gate has explicit immutable CI evidence for commit identity, vector hashes, pass or fail metadata, and required sign-off. Missing evidence or sign-off → `UNSPECIFIED_BY_PRD`; altered or unrelated evidence → `PROJECTION_DRIFT`. (PRD-20 §17; PRD-01 §9)
- VALIDATE: signing-context mismatch absent; canonical mismatch absent; snapshot drift absent; cross-language parity mismatch absent; determinism failure absent. Missing registry entry → `UNSPECIFIED_BY_PRD`; duplicate signing_context → `BUILD_FAIL`; canonical mismatch, snapshot drift, cross-language parity mismatch, and determinism failure → `PROJECTION_DRIFT`. (PRD-20 §13.1; PRD-20 §13.2; PRD-20 §13.3; PRD-20 §3.2; PRD-20 §3.3; PRD-20 §3.4; PRD-20 §3.5; PRD-20 §3.6; PRD-01 §9)
7. TERMINATION ENGINE (PRD-20 §18; PRD-20 §2; PRD-20 §3.1; PRD-20 §3.2; PRD-20 §3.3; PRD-20 §3.4; PRD-20 §3.5; PRD-20 §3.6)

TERMINATION MODEL (STRICT)

There are **two** layers of outcomes:

1. **CONTROL-LAYER TERMINATION (global)**  
   - `UNSPECIFIED_BY_PRD`  
   - `PROJECTION_DRIFT`  
   - `BUILD_FAIL`

2. **DOMAIN RUNTIME OUTCOMES (non-terminal)**  
   - `REJECT_BEFORE_QUEUE`  
   - `REJECT`  
   - `REJECT_READ`  
   - `REJECT_REPLAY`  
   - `REJECT_EXPORT`  
   - `IDEMPOTENT_ACK`  
   - `BACKPRESSURE`  
   - `FAIL_CLOSED`

RULE:

- Domain runtime outcomes **MUST NOT** be treated as control-layer termination; they **MUST** represent successful enforcement of cited PRD rules at the ingress/forensics/API boundary.
- Only control-layer constants **terminate** the Cursor / strict validation pipeline per **§8 TERMINATION PRECEDENCE**.
- Same violation at any layer MUST resolve to the identical control-layer terminal constant. Any layer-dependent remapping or reinterpretation → `PROJECTION_DRIFT`. (PRD-01 §9)

- VALIDATE: if any validator cannot prove `PRD == SKILL == PROMPT == OUTPUT`, FAIL: `UNSPECIFIED_BY_PRD`. (PRD-20 §18 CG-03; PRD-20 §18 CG-06; PRD-20 §18 CG-07)
- VALIDATE: required behavior explicit in cited clauses. FAIL: `UNSPECIFIED_BY_PRD`. (PRD-20 §18 CG-03)
- VALIDATE: projection matches cited clauses and preserves the single canonical path. FAIL: `PROJECTION_DRIFT`. (PRD-20 §18 CG-04; PRD-20 §18 CG-06)
- VALIDATE: compile-time invariants satisfied. FAIL: `BUILD_FAIL`. (PRD-20 §2 CT-01; PRD-20 §2 CT-02; PRD-20 §2 CT-03; PRD-20 §2 CT-06; PRD-20 §2 CT-07; PRD-20 §2 CT-08; PRD-20 §2 CT-09)
- VALIDATE: release gates satisfied without omitted evidence or drifted outcomes. Missing required release evidence → `UNSPECIFIED_BY_PRD`; drifted release outcome → `PROJECTION_DRIFT`. (PRD-20 §3.1; PRD-20 §3.2; PRD-20 §3.3; PRD-20 §3.4; PRD-20 §3.5; PRD-20 §3.6; PRD-01 §9)
8. TERMINATION PRECEDENCE (MANDATORY)

If multiple violations occur, resolution order is:

1. UNSPECIFIED_BY_PRD
2. PROJECTION_DRIFT
3. BUILD_FAIL

RULE:
- Highest-precedence violation MUST terminate execution immediately.
- No multi-error aggregation allowed.
- No ambiguity permitted.
