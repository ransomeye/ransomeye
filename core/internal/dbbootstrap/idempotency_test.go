//go:build dbbootstrap_integration

package dbbootstrap

import (
	"context"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	dbbase "ransomeye/core/internal/db"
)

// TestBootstrapIdempotency runs RunMigrationsAndValidate twice; migrations, login role set, and table grants must be bitwise identical across runs.
func TestBootstrapIdempotency(t *testing.T) {
	if os.Getenv("RANSOMEYE_DB_BOOTSTRAP_INTEGRATION") != "1" {
		t.Skip("set RANSOMEYE_DB_BOOTSTRAP_INTEGRATION=1, POSTGRES_DSN (verify-full @127.0.0.1), PG* certs, ransomeye_admin TLS identity, compliant pg_hba")
	}
	mig := strings.TrimSpace(os.Getenv("RANSOMEYE_MIGRATIONS_DIR"))
	if mig == "" {
		mig = "/opt/ransomeye/core/migrations/"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	if err := RunMigrationsAndValidate(ctx, Options{MigrationsDir: mig}); err != nil {
		t.Fatalf("first RunMigrationsAndValidate: %v", err)
	}
	s1 := snapshotDBState(t, ctx)

	if err := RunMigrationsAndValidate(ctx, Options{MigrationsDir: mig}); err != nil {
		t.Fatalf("second RunMigrationsAndValidate: %v", err)
	}
	s2 := snapshotDBState(t, ctx)

	if s1.migrations != s2.migrations {
		t.Fatalf("Idempotency violation: schema_migrations count %d != %d", s1.migrations, s2.migrations)
	}
	if !reflect.DeepEqual(s1.roles, s2.roles) {
		t.Fatalf("Idempotency violation: login roles changed\nbefore: %#v\nafter:  %#v", s1.roles, s2.roles)
	}
	if !reflect.DeepEqual(s1.grants, s2.grants) {
		t.Fatalf("Idempotency violation: table grants changed\nbefore: %d rows\nafter:  %d rows", len(s1.grants), len(s2.grants))
	}
	t.Log("[DB] Idempotency verified: migrations, roles, grants unchanged across second RunMigrationsAndValidate")
}

type dbSnapshot struct {
	migrations int
	roles      []string
	grants     []string
}

func snapshotDBState(t *testing.T, ctx context.Context) dbSnapshot {
	t.Helper()
	cfg, err := EffectiveAppConfig()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := dbbase.Connect(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)

	var s dbSnapshot
	if err := conn.QueryRow(ctx, `SELECT COUNT(*) FROM schema_migrations`).Scan(&s.migrations); err != nil {
		t.Fatal(err)
	}
	s.roles = listLoginRoles(t, ctx, conn)
	s.grants = listTableGrants(t, ctx, conn, cfg.User)
	return s
}

func listLoginRoles(t *testing.T, ctx context.Context, conn *dbbase.TrustedConn) []string {
	t.Helper()
	rows, err := conn.Query(ctx, `SELECT rolname FROM pg_catalog.pg_roles WHERE rolcanlogin ORDER BY rolname`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		out = append(out, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func listTableGrants(t *testing.T, ctx context.Context, conn *dbbase.TrustedConn, grantee string) []string {
	t.Helper()
	rows, err := conn.Query(ctx, `
		SELECT table_catalog, table_schema, table_name, privilege_type
		FROM information_schema.role_table_grants
		WHERE grantee = $1
		ORDER BY table_catalog, table_schema, table_name, privilege_type
	`, grantee)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var cat, schema, table, priv string
		if err := rows.Scan(&cat, &schema, &table, &priv); err != nil {
			t.Fatal(err)
		}
		out = append(out, cat+"|"+schema+"|"+table+"|"+priv)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}
