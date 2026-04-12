---
name: cursor-mishka-builder
description: build and audit the project mishka prototype inside cursor ide using the uploaded prds and repo contents. use when chatgpt needs to guide or perform deterministic implementation planning, repo auditing, port/conflict detection, phased coding, or cleanup for a mishka codebase in cursor. optimized for cursor-style iterative editing, codebase search, multi-file refactors, and acceptance-driven delivery while preserving mishka laws and prototype scope exclusions.
---

# cursor mishka builder

Use this skill to drive Project Mishka implementation from inside Cursor-oriented workflows.

## workflow
1. Run `scripts/audit_repo.py <repo-root>` before proposing major edits when the repo state is unknown.
2. Read `references/mishka-authority-map.md` and treat it as the control plane for decisions.
3. Produce the report structure in `references/acceptance-pattern.md`.
4. Work one vertical slice at a time and keep diffs reviewable.
5. Prefer editing existing files over creating parallel alternates unless the existing file violates the PRDs.
6. When two implementations overlap, keep exactly one and mark the other `remove` or `refactor` explicitly.

## cursor-specific behavior
- Prefer small, precise, reviewable edits over giant rewrites.
- Start with codebase search and architecture mapping before editing.
- Keep an explicit task list for the current slice.
- When touching more than 3 files, explain why the change remains one coherent slice.
- Preserve developer ergonomics: `.env.example`, `docker-compose.yml`, Makefile targets, seed scripts, and local run docs are part of a good prototype.

## architectural defaults
Follow `references/mishka-authority-map.md` exactly.

Additional defaults for Cursor work:
- Keep a monorepo layout with service folders under `services/`, shared contracts under `packages/` or `libs/`, infra under `deploy/`, and docs under `docs/`.
- Keep prototype networking explicit and stable. Default ports:
  - ui: 3000
  - ui api/backend: 8080
  - ingest gateway: 8081
  - decision engine: 8082
  - policy engine: 8083
  - safety guardrails: 8084
  - enforcement engine: 8085
  - replay api/engine: 8086
  - postgres: 5432
  - kafka/redpanda: 9092
  - prometheus: 9090
  - grafana: 3001
- If the repo already uses a port, either keep it consistently or reassign once globally. Do not leave conflicting mappings.

## audit rules
During audit, identify:
- duplicate services with overlapping responsibility
- direct service-to-service calls in core execution path
- state stored outside PRD-13 authority where it affects correctness
- hidden caches or wall-clock logic in authoritative flows
- AI or heuristic logic inside authoritative services
- dead files, obsolete experiments, and duplicate ports

## build rules
- Storage authority and execution context lock come first.
- Kafka or Redpanda must remain transport only, never source of truth.
- Replay guard correctness must anchor to committed storage semantics.
- UI and Shadow Intelligence must stay non-authoritative.
- Asset Intelligence must be implemented using existing PRD-13 record types only.

## required resources
- Use `references/mishka-authority-map.md` for design constraints.
- Use `references/acceptance-pattern.md` for every major response.
- Use `scripts/audit_repo.py` to produce an initial repo map and candidate conflicts.
