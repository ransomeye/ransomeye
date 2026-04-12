package db

import (
	"testing"
)

// TestRejectEnvFingerprint ensures no environment variable can inject the server cert fingerprint (installer-sealed path only).
func TestRejectEnvFingerprint(t *testing.T) {
	t.Setenv("POSTGRES_SERVER_FP_BYPASS_LAB_ONLY", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	cfg := LoadConfigFromEnv()
	if cfg.ExpectedPostgresServerFingerprint != "" {
		t.Fatal("LoadConfigFromEnv must not populate ExpectedPostgresServerFingerprint from any env var")
	}
}
