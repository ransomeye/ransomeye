package health

import (
	"testing"
)

func TestDPIPlaneEnvConfigured(t *testing.T) {
	t.Setenv("RANSOMEYE_DPI_PUBLIC_KEY_PATH", "")
	t.Setenv("RANSOMEYE_DPI_AGENT_ID", "")
	t.Setenv("RANSOMEYE_DPI_TENANT_ID", "")
	if DPIPlaneEnvConfigured() {
		t.Fatal("expected DPI plane not configured when env empty")
	}
	t.Setenv("RANSOMEYE_DPI_PUBLIC_KEY_PATH", "/x.pub")
	t.Setenv("RANSOMEYE_DPI_AGENT_ID", "550e8400-e29b-41d4-a716-446655440000")
	t.Setenv("RANSOMEYE_DPI_TENANT_ID", "6ba7b810-9dad-11d1-80b4-00c04fd430c8")
	if !DPIPlaneEnvConfigured() {
		t.Fatal("expected DPI plane configured when all env set")
	}
}
