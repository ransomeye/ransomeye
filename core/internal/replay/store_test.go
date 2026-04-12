package replay

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	coreconfig "ransomeye/core/internal/config"
	dbbase "ransomeye/core/internal/db"
	"ransomeye/core/internal/db/migrator"
	"ransomeye/core/internal/dbbootstrap"
	"ransomeye/core/internal/storage"
)

func TestVerifyStoredReplayAgainstDatabase(t *testing.T) {
	ctx := context.Background()
	envelope, _ := deterministicReplayEnvelope(t)
	setMatchingReplayEnv(t, envelope)

	cfg, pool := mustReplayDatabase(t, ctx)
	defer pool.Close()

	store, err := NewBaselineStore(pool.Pool, Metadata{
		ConfigHash:     envelope.ConfigHash,
		ModelHash:      envelope.ModelHash,
		FeatureVersion: envelope.FeatureVersion,
		PRDHash:        envelope.PRDHash,
	})
	if err != nil {
		t.Fatalf("NewBaselineStore: %v", err)
	}

	replayID, err := store.CaptureEnvelope(ctx, envelope)
	if err != nil {
		t.Fatalf("CaptureEnvelope: %v", err)
	}

	conn, err := dbbase.Connect(ctx, cfg)
	if err != nil {
		t.Fatalf("dbbase.Connect: %v", err)
	}
	defer conn.Close(ctx)

	result, err := VerifyStoredReplay(ctx, conn, replayID)
	if err != nil {
		t.Fatalf("VerifyStoredReplay: %v", err)
	}
	if result.Status != "PASS" {
		t.Fatalf("VerifyStoredReplay status = %s", result.Status)
	}
}

func TestDBCTLReplayTenRuns(t *testing.T) {
	ctx := context.Background()
	envelope, _ := deterministicReplayEnvelope(t)
	setMatchingReplayEnv(t, envelope)

	cfg, pool := mustReplayDatabase(t, ctx)
	defer pool.Close()

	store, err := NewBaselineStore(pool.Pool, Metadata{
		ConfigHash:     envelope.ConfigHash,
		ModelHash:      envelope.ModelHash,
		FeatureVersion: envelope.FeatureVersion,
		PRDHash:        envelope.PRDHash,
	})
	if err != nil {
		t.Fatalf("NewBaselineStore: %v", err)
	}
	replayID, err := store.CaptureEnvelope(ctx, envelope)
	if err != nil {
		t.Fatalf("CaptureEnvelope: %v", err)
	}

	root, err := findRepoRoot()
	if err != nil {
		t.Fatalf("findRepoRoot: %v", err)
	}
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("exec.LookPath(go): %v", err)
	}

	cmd := exec.CommandContext(goContextWithTimeout(t, ctx), goBin, "run", "./core/cmd/dbctl", "replay", "--id", replayID.String(), "--runs", "10")
	cmd.Dir = root
	cmd.Env = replayDBTestChildEnv(t, envelope, cfg, root)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("dbctl replay failed: %v output=%s", err, string(out))
	}

	var summary struct {
		Status    string `json:"status"`
		Runs      int    `json:"runs"`
		Deviation int    `json:"deviation"`
	}
	if err := json.Unmarshal(out, &summary); err != nil {
		t.Fatalf("json.Unmarshal: %v output=%s", err, string(out))
	}
	if summary.Status != "PASS" || summary.Runs != 10 || summary.Deviation != 0 {
		t.Fatalf("unexpected replay summary: %+v", summary)
	}
}

func mustReplayDatabase(t *testing.T, ctx context.Context) (dbbase.Config, *storage.DB) {
	t.Helper()

	dsn := strings.TrimSpace(os.Getenv("POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("POSTGRES_DSN not set — replay DB integration requires the same DSN + PGSSL* env as authority-db tests")
	}
	cfg, err := dbbootstrap.EffectiveAppConfig()
	if err != nil {
		t.Fatalf("EffectiveAppConfig: %v", err)
	}
	cc, err := coreconfig.LoadVerifiedCommonConfig(
		coreconfig.InstalledCommonConfigPath,
		coreconfig.IntermediateCACertPath,
	)
	if err != nil {
		t.Skipf("signed common.yaml not available: %v", err)
	}
	cfg.ExpectedPostgresServerFingerprint = strings.TrimSpace(cc.Database.ExpectedServerFingerprint)
	if cfg.ExpectedPostgresServerFingerprint == "" {
		t.Skip("database.expected_server_fingerprint missing in signed common.yaml")
	}
	if _, err := migrator.Run(ctx, migrator.Config{DB: cfg}); err != nil {
		t.Fatalf("database migrate: %v", err)
	}

	db, err := storage.Open(ctx, storage.DBOptions{
		BaseDSN:       fmt.Sprintf("user=%s password=%s dbname=%s", cfg.User, quoteReplayPass(cfg.Password), cfg.Database),
		Host:          dbbase.LoopbackHost,
		Port:          dbbase.LoopbackPort,
		TLSRootCAPath: cfg.SSLRootCert,
		TLSServerName: cfg.TLSServerName,
		MaxConns:      2,
	})
	if err != nil {
		t.Fatalf("database open: %v", err)
	}
	return cfg, db
}

func quoteReplayPass(pw string) string {
	// libpq single-quote escaping for passwords with @ or spaces
	if !strings.ContainsAny(pw, " '@\\") {
		return pw
	}
	return "'" + strings.ReplaceAll(pw, "'", "''") + "'"
}

// replayDBTestChildEnv builds dbctl subprocess env: POSTGRES_DSN + PGSSL* match the authority lane; last duplicate keys win in Go.
func replayDBTestChildEnv(t *testing.T, envelope Envelope, cfg dbbase.Config, root string) []string {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("POSTGRES_DSN"))
	if dsn == "" {
		t.Fatal("POSTGRES_DSN required for dbctl replay child")
	}
	sslMode := strings.TrimSpace(os.Getenv("PGSSLMODE"))
	if sslMode == "" {
		sslMode = "verify-full"
	}
	srvName := strings.TrimSpace(os.Getenv("PGSSLSERVERNAME"))
	if srvName == "" {
		srvName = cfg.TLSServerName
	}
	env := append([]string{}, os.Environ()...)
	env = append(env,
		"POSTGRES_DSN="+dsn,
		"PGSSLROOTCERT="+cfg.SSLRootCert,
		"PGSSLCERT="+cfg.SSLClientCert,
		"PGSSLKEY="+cfg.SSLClientKey,
		"PGSSLMODE="+sslMode,
		"PGSSLSERVERNAME="+srvName,
		DefaultConfigHashEnv+"="+envelope.ConfigHash,
		DefaultModelHashEnv+"="+envelope.ModelHash,
		DefaultFeatureVersionEnv+"="+envelope.FeatureVersion,
		DefaultPRDHashEnv+"="+envelope.PRDHash,
		"RANSOMEYE_AI_ROOT="+filepath.Join(root, "ml"),
	)
	if p := strings.TrimSpace(os.Getenv(DefaultReplaySigningKeyEnv)); p != "" {
		env = append(env, DefaultReplaySigningKeyEnv+"="+p)
	}
	return env
}

func goContextWithTimeout(t *testing.T, parent context.Context) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}
