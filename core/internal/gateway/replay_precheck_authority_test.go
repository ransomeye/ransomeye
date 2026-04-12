package gateway

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestReplayPrecheck_DBPoolRequiresPositivePartition(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("POSTGRES_DSN not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool: %v", err)
	}
	t.Cleanup(pool.Close)

	t.Setenv("RANSOMEYE_PRD13_PARTITION_ID", "0")
	h := NewHandlers(nil, nil, nil)
	h.SetDBPool(pool)

	tenant := strings.Repeat("a", 64)
	agent := uuid.New().String()
	boot := uuid.New().String()
	msg := uuid.New().String()
	var ph [32]byte
	ph[0] = 1

	_, err = h.ReplayPrecheck(ctx, tenant, agent, boot, msg, ph)
	if err == nil {
		t.Fatal("expected error when db pool is set but partition id is not positive")
	}
	if !strings.Contains(err.Error(), "partition_id") {
		t.Fatalf("unexpected error: %v", err)
	}
}
