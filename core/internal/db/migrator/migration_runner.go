package migrator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"

	dbbase "ransomeye/core/internal/db"
)

const requiredMigrationCount = 48

var migrationFilePattern = regexp.MustCompile(`^(\d{3})_.+\.sql$`)

type Config struct {
	DB            dbbase.Config
	MigrationsDir string
}

type Result struct {
	Applied int
	Skipped int
	Total   int
}

type migrationFile struct {
	Version  int
	Filename string
	Path     string
	Body     []byte
	Checksum string
}

type appliedMigration struct {
	Filename string
	Checksum string
}

func reconcileMigrationFilename(ctx context.Context, conn *dbbase.TrustedConn, version int, newFilename, expectedChecksum string) error {
	tag, err := conn.Exec(ctx, `
UPDATE schema_migrations
SET filename = $1
WHERE version = $2 AND checksum = $3`,
		newFilename, version, expectedChecksum)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("schema_migrations update affected 0 rows (version=%d)", version)
	}
	return nil
}

func Run(ctx context.Context, cfg Config) (Result, error) {
	migrationsDir, err := resolveMigrationsDir(cfg.MigrationsDir)
	if err != nil {
		return Result{}, err
	}

	files, err := loadMigrationFiles(migrationsDir)
	if err != nil {
		return Result{}, err
	}

	conn, err := dbbase.Connect(ctx, cfg.DB)
	if err != nil {
		return Result{}, err
	}
	defer conn.Close(ctx)

	if err := dbbase.VerifyProvisioningSession(ctx, conn, cfg.DB, cfg.DB.User); err != nil {
		return Result{}, fmt.Errorf("migrator session trust: %w", err)
	}

	if err := ensureSchemaMigrationsTable(ctx, conn); err != nil {
		return Result{}, err
	}

	applied, err := loadAppliedMigrations(ctx, conn)
	if err != nil {
		return Result{}, err
	}

	for version := range applied {
		if !containsVersion(files, version) {
			return Result{}, fmt.Errorf("unexpected applied migration version %d present in schema_migrations", version)
		}
	}

	var result Result
	result.Total = len(files)

	for _, migration := range files {
		existing, ok := applied[migration.Version]
		if ok {
			if existing.Filename != migration.Filename {
				// Allow renames of migration files when the canonical migration *content* is unchanged
				// (checksum of full file bytes matches). Updates schema_migrations.filename in-place.
				if existing.Checksum != migration.Checksum {
					return Result{}, fmt.Errorf(
						"migration filename mismatch for version %d: db=%q file=%q (checksum also differs; refusing unsafe rename)",
						migration.Version,
						existing.Filename,
						migration.Filename,
					)
				}
				if err := reconcileMigrationFilename(ctx, conn, migration.Version, migration.Filename, existing.Checksum); err != nil {
					return Result{}, fmt.Errorf("reconcile migration filename v%d: %w", migration.Version, err)
				}
			} else if existing.Checksum != migration.Checksum {
				return Result{}, fmt.Errorf(
					"migration checksum mismatch for version %d file %q",
					migration.Version,
					migration.Filename,
				)
			}
			result.Skipped++
			continue
		}

		if err := executeMigration(ctx, conn, migration); err != nil {
			return Result{}, err
		}
		result.Applied++
	}

	if err := verifyAppliedSequence(ctx, conn, files); err != nil {
		return Result{}, err
	}

	return result, nil
}

func executeMigration(ctx context.Context, conn *dbbase.TrustedConn, migration migrationFile) error {
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin migration %03d: %w", migration.Version, err)
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	sqlText := stripRegisterMigration(string(migration.Body))
	if strings.TrimSpace(sqlText) == "" {
		return fmt.Errorf("migration %03d %q is empty after sanitation", migration.Version, migration.Filename)
	}

	if _, err := tx.Exec(ctx, sqlText); err != nil {
		return fmt.Errorf("execute migration %03d %q: %w", migration.Version, migration.Filename, err)
	}

	if _, err := tx.Exec(
		ctx,
		`INSERT INTO schema_migrations (version, filename, checksum) VALUES ($1, $2, $3)`,
		migration.Version,
		migration.Filename,
		migration.Checksum,
	); err != nil {
		return fmt.Errorf("record migration %03d %q: %w", migration.Version, migration.Filename, err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit migration %03d %q: %w", migration.Version, migration.Filename, err)
	}

	return nil
}

func ensureSchemaMigrationsTable(ctx context.Context, conn *dbbase.TrustedConn) error {
	const createTableSQL = `
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INT PRIMARY KEY,
    filename TEXT NOT NULL,
    checksum TEXT NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`

	if _, err := conn.Exec(ctx, createTableSQL); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	type column struct {
		Name string
		Type string
	}

	rows, err := conn.Query(ctx, `
SELECT column_name, data_type
FROM information_schema.columns
WHERE table_schema = 'public'
  AND table_name = 'schema_migrations'
ORDER BY ordinal_position`)
	if err != nil {
		return fmt.Errorf("inspect schema_migrations columns: %w", err)
	}
	defer rows.Close()

	var actual []column
	for rows.Next() {
		var col column
		if err := rows.Scan(&col.Name, &col.Type); err != nil {
			return fmt.Errorf("scan schema_migrations columns: %w", err)
		}
		actual = append(actual, col)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate schema_migrations columns: %w", err)
	}

	expected := []column{
		{Name: "version", Type: "integer"},
		{Name: "filename", Type: "text"},
		{Name: "checksum", Type: "text"},
		{Name: "applied_at", Type: "timestamp with time zone"},
	}
	if !slices.Equal(actual, expected) {
		return fmt.Errorf("schema_migrations has unexpected structure: got=%v want=%v", actual, expected)
	}

	var primaryKeyDef string
	if err := conn.QueryRow(ctx, `
SELECT pg_get_constraintdef(oid)
FROM pg_constraint
WHERE conrelid = 'public.schema_migrations'::regclass
  AND contype = 'p'`).Scan(&primaryKeyDef); err != nil {
		return fmt.Errorf("inspect schema_migrations primary key: %w", err)
	}
	if primaryKeyDef != "PRIMARY KEY (version)" {
		return fmt.Errorf("schema_migrations primary key must be version, got %q", primaryKeyDef)
	}

	return nil
}

func loadAppliedMigrations(ctx context.Context, conn *dbbase.TrustedConn) (map[int]appliedMigration, error) {
	rows, err := conn.Query(ctx, `
SELECT version, filename, checksum
FROM schema_migrations
ORDER BY version`)
	if err != nil {
		return nil, fmt.Errorf("load applied migrations: %w", err)
	}
	defer rows.Close()

	applied := make(map[int]appliedMigration)
	for rows.Next() {
		var version int
		var item appliedMigration
		if err := rows.Scan(&version, &item.Filename, &item.Checksum); err != nil {
			return nil, fmt.Errorf("scan applied migration: %w", err)
		}
		applied[version] = item
	}

	return applied, rows.Err()
}

func verifyAppliedSequence(ctx context.Context, conn *dbbase.TrustedConn, files []migrationFile) error {
	rows, err := conn.Query(ctx, `
SELECT version, filename, checksum
FROM schema_migrations
ORDER BY version`)
	if err != nil {
		return fmt.Errorf("verify schema_migrations: %w", err)
	}
	defer rows.Close()

	index := 0
	for rows.Next() {
		if index >= len(files) {
			return errors.New("schema_migrations contains more rows than expected")
		}

		var version int
		var filename, checksum string
		if err := rows.Scan(&version, &filename, &checksum); err != nil {
			return fmt.Errorf("scan schema_migrations: %w", err)
		}

		expected := files[index]
		if version != expected.Version || filename != expected.Filename || checksum != expected.Checksum {
			return fmt.Errorf(
				"schema_migrations row mismatch at position %d: got=(%d,%q,%q) want=(%d,%q,%q)",
				index,
				version,
				filename,
				checksum,
				expected.Version,
				expected.Filename,
				expected.Checksum,
			)
		}
		index++
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate schema_migrations: %w", err)
	}
	if index != len(files) {
		return fmt.Errorf("schema_migrations row count mismatch: got=%d want=%d", index, len(files))
	}

	return nil
}

func loadMigrationFiles(dir string) ([]migrationFile, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read migrations dir %q: %w", dir, err)
	}

	migrations := make([]migrationFile, 0, requiredMigrationCount)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		match := migrationFilePattern.FindStringSubmatch(name)
		if match == nil {
			continue
		}

		version := 0
		if _, err := fmt.Sscanf(match[1], "%d", &version); err != nil {
			return nil, fmt.Errorf("parse migration version from %q: %w", name, err)
		}

		path := filepath.Join(dir, name)
		body, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read migration %q: %w", path, err)
		}

		checksum := sha256.Sum256(body)
		migrations = append(migrations, migrationFile{
			Version:  version,
			Filename: name,
			Path:     path,
			Body:     body,
			Checksum: hex.EncodeToString(checksum[:]),
		})
	}

	slices.SortFunc(migrations, func(a, b migrationFile) int {
		return a.Version - b.Version
	})

	if len(migrations) != requiredMigrationCount {
		return nil, fmt.Errorf(
			"missing migration: expected %d numbered files in %q, found %d",
			requiredMigrationCount,
			dir,
			len(migrations),
		)
	}

	for i, migration := range migrations {
		expectedVersion := i + 1
		if migration.Version != expectedVersion {
			return nil, fmt.Errorf("missing migration version %03d", expectedVersion)
		}
	}

	return migrations, nil
}

func resolveMigrationsDir(explicit string) (string, error) {
	if explicit != "" {
		return filepath.Abs(explicit)
	}

	workingDir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("resolve working directory: %w", err)
	}

	for current := workingDir; ; current = filepath.Dir(current) {
		candidate := filepath.Join(current, "core", "migrations")
		info, err := os.Stat(candidate)
		if err == nil && info.IsDir() {
			return candidate, nil
		}

		parent := filepath.Dir(current)
		if parent == current {
			break
		}
	}

	return "", errors.New("unable to locate core/migrations")
}

func stripRegisterMigration(sqlText string) string {
	lines := strings.Split(sqlText, "\n")
	filtered := lines[:0]
	for _, line := range lines {
		if strings.Contains(line, "SELECT register_migration(") {
			continue
		}
		filtered = append(filtered, line)
	}
	return strings.Join(filtered, "\n")
}

func containsVersion(files []migrationFile, version int) bool {
	for _, file := range files {
		if file.Version == version {
			return true
		}
	}
	return false
}
