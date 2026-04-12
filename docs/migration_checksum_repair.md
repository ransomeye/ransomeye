# Migration checksum repair (core/internal/db/migrator)

The migrator stores a **SHA-256 checksum of the entire migration file** (including `SELECT register_migration(...)` lines) in `schema_migrations.checksum` and **refuses to start** if an already-applied version’s file content no longer matches.

## Migration 039 (`039_validation_guards.sql`)

`assert_all_schema_versions` was updated so `assert_all_schema_versions(p_min, p_max)` only verifies versions `p_min..LEAST(p_max, MAX(schema_migrations.version))`. This preserves historical callers such as migration **040**’s `assert_all_schema_versions(1, 42)` during a linear bootstrap (versions 40–42 are not recorded until those migrations complete).

If a database was created when migration **039** had the **previous** file bytes, the stored checksum for version **39** will not match the current file after a `git pull`. Repair options:

1. **Preferred (empty / disposable dev DB):** drop and recreate the database, then re-run migrations.
2. **Controlled repair:** compute the new checksum and update the row (only when you intentionally accept the new SQL):

```bash
sha256sum core/migrations/039_validation_guards.sql
```

```sql
UPDATE schema_migrations
SET checksum = '<paste sha256 hex>'
WHERE version = 39 AND filename = '039_validation_guards.sql';
```

Re-run the migration helper from `core/cmd/` (via `make migrate-core`); it must skip re-execution and pass checksum verification.

## Migration 040 (`040_final_sanity.sql`)

040 is **not** edited for the assert-range fix; behavior is corrected via the **039** function definition so migration **040** content (and checksum) can stay aligned with historical trees.

## Renamed migration files (same SQL bytes)

If a migration file is **renamed on disk** but the file **content is unchanged** (SHA-256 matches the stored checksum), `core/internal/db/migrator` updates `schema_migrations.filename` automatically. If both **filename and checksum** drift, the migrator fails closed (manual repair required).
