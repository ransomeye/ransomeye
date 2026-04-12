# PRD development notes (derivations only)

**Governance (Project Mishka):** Authoritative PRDs live under `prd_project_mishka/` and are cryptographically locked via `prd_project_mishka/prd.sha256`. **No modification** to those files except manifest refresh is allowed unless explicitly ordered by the Chief Architect.

Use **this directory** (`/docs/prd_develop_doc/`) for drafts, elaborations, implementation notes, and UI mock descriptions derived from PRDs—not for changing the locked PRD sources.

## PRD DIRECTORY POLICY

- Entire `prd_project_mishka/` is immutable for Markdown sources.
- Only `prd_project_mishka/prd.sha256` may change (checksum manifest line updates).
- Any other file change under `prd_project_mishka/` is rejected at server level (`git-hooks/pre-receive` on the authoritative bare remote).
- Client-only hooks can be skipped with `git commit --no-verify`; **they do not defeat** a remote configured with this hook.

## PRD enforcement model

- **Server-side enforcement is non-bypassable** for `git push` to a repo that installs `git-hooks/pre-receive`.
- **`prd_project_mishka/prd.sha256` updates** are allowed only when the push does not modify any other path under `prd_project_mishka/`.
- Install the hook on the **bare repo** you push to: copy `git-hooks/pre-receive` to that repository’s `hooks/pre-receive` and `chmod +x`. (A local target `make install-prd-pre-receive-hook` installs into the current clone for convenience; the trust boundary is the remote.)
- Runtime check: `make verify-prd` (runs `sha256sum -c prd_project_mishka/prd.sha256`).
