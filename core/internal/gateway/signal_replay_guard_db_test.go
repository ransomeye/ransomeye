package gateway

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"ransomeye/core/internal/storage/authority"
)

// Replay admission for live SendSignal is covered by TestSendSignal_DB_E2E_* in signal_ingest_db_e2e_test.go
// (requires POSTGRES_DSN). Those tests exercise checkSignalReplayGuard via the full commit path because
// admission must read only replay_guard rows that are ADMITTED and covered by batch_commit_records.

func TestLastCommittedReplayCursor_EmptyDB_NoRows(t *testing.T) {
	pool := requireReplayDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	partitionID := int64(99199)
	logicalShardID := randomBytes(t, 32)
	emitterID := randomBytes(t, 16)
	bootSessionID := randomBytes(t, 32)
	if _, err := pool.Exec(ctx, `DELETE FROM replay_guard WHERE partition_id = $1 AND logical_shard_id = $2`, partitionID, logicalShardID); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	lc, mid, found, err := authority.LastCommittedReplayCursor(ctx, pool, partitionID, logicalShardID, emitterID, bootSessionID)
	if err != nil {
		t.Fatalf("LastCommittedReplayCursor: %v", err)
	}
	if found {
		t.Fatalf("expected no committed cursor, got clock=%d msg=%x", lc, mid)
	}
}

func requireReplayDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("POSTGRES_DSN not set - skipping DB-backed replay admission test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}
