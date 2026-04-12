# required output format

For every substantial run, produce these sections in order:

# 1. repo audit summary
- what exists
- what conflicts with the PRDs
- what can be reused unchanged
- what must be removed
- what must be rewritten

# 2. current slice
- exact subsystem being worked on now
- why this slice comes next
- PRDs that govern it

# 3. implementation plan
- files to create
- files to edit
- files to delete
- ports and service names affected

# 4. changes applied
- concise list of actual code or config changes

# 5. verification
- commands run
- expected outputs
- deterministic or replay checks performed

# 6. remaining gaps
- still missing for phase 1
- blockers
- deferred items explicitly excluded from scope

## keep/remove decision rule
Always classify pre-existing code into exactly one bucket:
- keep
- refactor
- remove

Never leave conflicting code in place without explicitly marking the reason.
