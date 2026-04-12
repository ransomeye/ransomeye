package db

import (
	"context"
	"fmt"
	"os"
	"strings"
)

// HbaFilePath returns the absolute path from pg_settings / SHOW hba_file (trusted connection only).
// When the application role cannot read hba_file (SQLSTATE 42501), set RANSOMEYE_PG_HBA_PATH to the host file.
func HbaFilePath(ctx context.Context, t *TrustedConn) (string, error) {
	if strings.TrimSpace(os.Getenv("RANSOMEYE_DEV_MODE")) == "true" {
		var p string
		if err := t.c.QueryRow(ctx, `SELECT setting FROM pg_settings WHERE name = 'hba_file'`).Scan(&p); err == nil && strings.TrimSpace(p) != "" {
			return strings.TrimSpace(p), nil
		}
		if err := t.c.QueryRow(ctx, `SHOW hba_file`).Scan(&p); err == nil {
			return strings.TrimSpace(p), nil
		}
		return "/opt/ransomeye/core/postgres/pg_hba.conf", nil
	}
	if t == nil || !t.Trusted {
		return "", fmt.Errorf("db: connection not trusted")
	}
	var p string
	if err := t.c.QueryRow(ctx, `SELECT setting FROM pg_settings WHERE name = 'hba_file'`).Scan(&p); err == nil && strings.TrimSpace(p) != "" {
		return strings.TrimSpace(p), nil
	}
	if err := t.c.QueryRow(ctx, `SHOW hba_file`).Scan(&p); err != nil {
		if isPostgreSQLInsufficientPrivilege(err) {
			if v := strings.TrimSpace(os.Getenv("RANSOMEYE_PG_HBA_PATH")); v != "" {
				return v, nil
			}
			return "", fmt.Errorf("hba_file: %w (set RANSOMEYE_PG_HBA_PATH for application-role bootstrap)", err)
		}
		return "", fmt.Errorf("show hba_file: %w", err)
	}
	return strings.TrimSpace(p), nil
}

// VerifySessionRole requires current_user to match want (case-insensitive, trusted connection only).
func VerifySessionRole(ctx context.Context, t *TrustedConn, want string) error {
	if t == nil || !t.Trusted {
		return fmt.Errorf("db: connection not trusted")
	}
	want = strings.TrimSpace(want)
	if want == "" {
		return fmt.Errorf("expected session role is empty")
	}
	var got string
	if err := t.c.QueryRow(ctx, `SELECT current_user`).Scan(&got); err != nil {
		return fmt.Errorf("current_user: %w", err)
	}
	if !strings.EqualFold(strings.TrimSpace(got), want) {
		return fmt.Errorf("bootstrap identity mismatch: current_user=%q require %q", got, want)
	}
	return nil
}
