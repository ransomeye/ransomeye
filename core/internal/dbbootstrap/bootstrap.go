// Package dbbootstrap applies migrations and validation using the application PostgreSQL identity only.
// Role/database provisioning is installer-owned (PRD-01 DB-BOOTSTRAP-01).
package dbbootstrap

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/jackc/pgx/v5"

	coreconfig "ransomeye/core/internal/config"
	dbbase "ransomeye/core/internal/db"
	"ransomeye/core/internal/db/migrator"
	"ransomeye/core/internal/db/validator"
)

//go:embed schema.sql
var schemaFS embed.FS

// ExpectedSchemaHash is SHA-256 (hex) of the exact embedded schema.sql bytes (PRD-03 immutability).
const ExpectedSchemaHash = "17ee3f90d53d6c5f9cdbb1a710974ce135fa5112b04ac4efa7c69e8d6a1be1ac"

const (
	rolePostgres          = "postgres"
	roleRansomeye         = "ransomeye"
	roleRansomeyeReadonly = "ransomeye_readonly"
	roleRansomeyeAdmin    = "ransomeye_admin"
)

// EffectiveAppConfig merges POSTGRES_DSN (keyword or URL) with PGSSL* paths from the environment.
// User, database, and password come from the DSN when present; if the DSN omits password, PGPASSWORD
// may be used. The pool never substitutes db.DefaultPassword when POSTGRES_DSN is set.
func EffectiveAppConfig() (dbbase.Config, error) {
	dsn := strings.TrimSpace(os.Getenv("POSTGRES_DSN"))
	if dsn == "" {
		return dbbase.Config{}, errors.New("POSTGRES_DSN is required")
	}
	if err := dbbase.ValidateInboundPostgresDSN(dsn); err != nil {
		return dbbase.Config{}, err
	}
	cfg := dbbase.LoadConfigFromEnv()
	identityDSN := dbbase.StripLibpqSSLFileParamsFromDSN(dsn)
	pc, err := pgx.ParseConfig(identityDSN)
	if err != nil {
		return dbbase.Config{}, fmt.Errorf("parse POSTGRES_DSN: %w", err)
	}
	if u := strings.TrimSpace(pc.User); u != "" {
		cfg.User = u
	}
	if d := strings.TrimSpace(pc.Database); d != "" {
		cfg.Database = d
	}
	if pc.Password != "" {
		cfg.Password = pc.Password
	} else if envPW := strings.TrimSpace(os.Getenv("PGPASSWORD")); envPW != "" {
		cfg.Password = envPW
	} else {
		cfg.Password = ""
	}
	return cfg, nil
}

// Options drives RunMigrationsAndValidate.
type Options struct {
	MigrationsDir                     string
	ExpectedPostgresServerFingerprint string
}

func resolvePostgresServerFingerprint(explicit string) (string, error) {
	if fp := strings.TrimSpace(explicit); fp != "" {
		return fp, nil
	}
	cc, err := coreconfig.LoadVerifiedCommonConfig(coreconfig.InstalledCommonConfigPath, coreconfig.IntermediateCACertPath)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(cc.Database.ExpectedServerFingerprint), nil
}

// RunMigrationsAndValidate applies SQL migrations and runs schema validation using only the application DSN
// (ransomeye → database ransomeye). Database and roles must already exist (installer phase).
func RunMigrationsAndValidate(ctx context.Context, opts Options) error {
	if strings.TrimSpace(opts.MigrationsDir) == "" {
		return errors.New("migrations dir is required")
	}

	appCfg, err := EffectiveAppConfig()
	if err != nil {
		return err
	}
	if appCfg.User != dbbase.DefaultUser || appCfg.Database != dbbase.DefaultDatabase {
		return fmt.Errorf("runtime DSN must use user %q and dbname %q", dbbase.DefaultUser, dbbase.DefaultDatabase)
	}
	fp, err := resolvePostgresServerFingerprint(opts.ExpectedPostgresServerFingerprint)
	if err != nil {
		return err
	}
	appCfg.ExpectedPostgresServerFingerprint = fp

	precheck, err := dbbase.Connect(ctx, appCfg)
	if err != nil {
		return fmt.Errorf("application db connect: %w", err)
	}
	if err := dbbase.RunTCPTrustGateWithLogs(ctx, precheck, appCfg, appCfg.User, "pre-migration"); err != nil {
		_ = precheck.Close(ctx)
		return err
	}
	hbaPath, err := dbbase.HbaFilePath(ctx, precheck)
	if err != nil {
		_ = precheck.Close(ctx)
		return fmt.Errorf("hba_file: %w", err)
	}
	if err := ValidatePgHbaStrict(hbaPath); err != nil {
		_ = precheck.Close(ctx)
		return err
	}
	log.Printf("[DB] pg_hba.conf validated: %s", hbaPath)
	_ = precheck.Close(ctx)

	if _, err := migrator.Run(ctx, migrator.Config{
		DB:            appCfg,
		MigrationsDir: opts.MigrationsDir,
	}); err != nil {
		return fmt.Errorf("migrations: %w", err)
	}

	if err := validator.VerifyLayoutDrift(ctx, validator.Config{DB: appCfg}); err != nil {
		return fmt.Errorf("schema drift: %w", err)
	}

	appDriftConn, err := dbbase.Connect(ctx, appCfg)
	if err != nil {
		return fmt.Errorf("post-migration connect for role audit: %w", err)
	}
	if err := dbbase.RunTCPTrustGateWithLogs(ctx, appDriftConn, appCfg, appCfg.User, "post-migration audit"); err != nil {
		_ = appDriftConn.Close(ctx)
		return err
	}
	if err := verifyRoleLockdown(ctx, appDriftConn); err != nil {
		_ = appDriftConn.Close(ctx)
		return fmt.Errorf("role lockdown: %w", err)
	}
	_ = appDriftConn.Close(ctx)

	vr := validator.Run(ctx, validator.Config{DB: appCfg})
	if vr.Status != "PASS" {
		if vr.Detail != "" {
			log.Printf("[DB] post-migration validation failed (%s): %s", vr.FailedCheck, vr.Detail)
		}
		return fmt.Errorf("post-migration validation failed: %s", vr.FailedCheck)
	}
	log.Printf("[DB] migrations and validation complete (application role only)")
	return nil
}

var allowedLoginRoles = map[string]struct{}{
	rolePostgres:          {},
	roleRansomeye:         {},
	roleRansomeyeReadonly: {},
	roleRansomeyeAdmin:    {},
}

func verifyRoleLockdown(ctx context.Context, conn *dbbase.TrustedConn) error {
	rows, err := conn.Query(ctx, `SELECT rolname, rolsuper FROM pg_roles WHERE rolcanlogin ORDER BY rolname`)
	if err != nil {
		return fmt.Errorf("list login roles: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var name string
		var super bool
		if err := rows.Scan(&name, &super); err != nil {
			return err
		}
		if _, ok := allowedLoginRoles[name]; !ok {
			return fmt.Errorf("unexpected login role %q (allowed: postgres, ransomeye, ransomeye_readonly, ransomeye_admin)", name)
		}
		if name == rolePostgres {
			if !super {
				return errors.New("postgres role must be superuser when it can login")
			}
			continue
		}
		if name == roleRansomeyeAdmin {
			if !super {
				return errors.New("ransomeye_admin must be PostgreSQL superuser for TLS bootstrap policy")
			}
			continue
		}
		if super {
			return fmt.Errorf("superuser drift: role %q must not be superuser", name)
		}
	}
	return rows.Err()
}

// StatusReport is the db-bootstrap validate JSON shape (stable field order for deterministic output).
type StatusReport struct {
	Overall string `json:"overall"`
	DB      string `json:"db"`
	Schema  string `json:"schema"`
	Roles   string `json:"roles"`
	TLS     string `json:"tls"`
}

// ValidateReport checks connectivity, TLS policy, role lockdown, layout drift, and full validator.
func ValidateReport(ctx context.Context) (StatusReport, bool, error) {
	out := StatusReport{Overall: "FAIL", DB: "FAIL", Schema: "FAIL", Roles: "FAIL", TLS: "FAIL"}
	appCfg, err := EffectiveAppConfig()
	if err != nil {
		return out, false, err
	}
	fp, err := resolvePostgresServerFingerprint("")
	if err != nil {
		return out, false, err
	}
	appCfg.ExpectedPostgresServerFingerprint = fp

	conn, err := dbbase.Connect(ctx, appCfg)
	if err != nil {
		return out, false, fmt.Errorf("connect: %w", err)
	}
	defer conn.Close(ctx)

	if err := dbbase.RunTCPTrustGateWithLogs(ctx, conn, appCfg, appCfg.User, "validate"); err != nil {
		return out, false, err
	}
	hbaPath, err := dbbase.HbaFilePath(ctx, conn)
	if err != nil {
		return out, false, fmt.Errorf("hba_file: %w", err)
	}
	if err := ValidatePgHbaStrict(hbaPath); err != nil {
		return out, false, err
	}
	log.Printf("[BOOTSTRAP] pg_hba.conf validated: %s (validate)", hbaPath)
	out.TLS = "OK"

	if err := conn.Ping(ctx); err != nil {
		return out, false, fmt.Errorf("ping: %w", err)
	}
	out.DB = "OK"

	var curUser, curDB string
	if err := conn.QueryRow(ctx, `SELECT current_user, current_database()`).Scan(&curUser, &curDB); err != nil {
		return out, false, fmt.Errorf("session identity: %w", err)
	}
	if !strings.EqualFold(curUser, appCfg.User) || curDB != appCfg.Database {
		out.Roles = "FAIL"
		return out, false, fmt.Errorf("session user/db mismatch: got %s@%s want %s@%s", curUser, curDB, appCfg.User, appCfg.Database)
	}

	if err := verifyRoleLockdown(ctx, conn); err != nil {
		out.Roles = "FAIL"
		return out, false, fmt.Errorf("role lockdown: %w", err)
	}
	out.Roles = "OK"

	if err := validator.VerifyLayoutDrift(ctx, validator.Config{DB: appCfg}); err != nil {
		out.Schema = "FAIL"
		return out, false, fmt.Errorf("layout drift: %w", err)
	}

	vr := validator.Run(ctx, validator.Config{DB: appCfg})
	if vr.Status != "PASS" {
		out.Schema = "FAIL"
		return out, false, fmt.Errorf("validator: %s", vr.FailedCheck)
	}
	out.Schema = "OK"
	out.Overall = "PASS"
	return out, true, nil
}
