package health

import (
	"context"
	"net"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"ransomeye/core/internal/contracts"
	"ransomeye/core/internal/identity"
)

// Dead-Peer Threshold (P0) — PRD-18 §15.2 Agent AWOL critical at ≥90s.
const AWOL_THRESHOLD = 90 * time.Second

// RunSweeper runs the agent health sweeper loop.
// Ticks every 30 seconds, reaps AWOL sessions, unregisters any zombie action streams,
// and marks agents OFFLINE in PostgreSQL.
// unregister implements contracts.StreamUnregister (e.g. enforcement.ActionDispatcher).
//
// Lock optimization (P0):
// - Step A: snapshot sessions (read lock held only for copy)
// - Step B: delete per-token (write lock held only for delete)
// Database I/O occurs with NO SessionManager lock held.
func RunSweeper(ctx context.Context, sm *identity.SessionManager, unregister contracts.StreamUnregister, pool *pgxpool.Pool) {
	if sm == nil || unregister == nil || pool == nil {
		return
	}

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			runOnce(ctx, sm, unregister, pool)
		}
	}
}

// DPIPlaneEnvConfigured reports the same optional DPI plane as core startup (main.dpiPlaneEnvComplete).
// When unset, Mishka does not require dpi_probe telemetry for readiness gates.
func DPIPlaneEnvConfigured() bool {
	return strings.TrimSpace(os.Getenv("RANSOMEYE_DPI_PUBLIC_KEY_PATH")) != "" &&
		strings.TrimSpace(os.Getenv("RANSOMEYE_DPI_AGENT_ID")) != "" &&
		strings.TrimSpace(os.Getenv("RANSOMEYE_DPI_TENANT_ID")) != ""
}

// AIPlaneEnvConfigured is true when the AI sidecar address is set (deployment intent).
func AIPlaneEnvConfigured() bool {
	return strings.TrimSpace(os.Getenv("RANSOMEYE_AI_ADDR")) != ""
}

// SINEPlaneEnvConfigured is true when the SINE sidecar address is set (deployment intent).
func SINEPlaneEnvConfigured() bool {
	return strings.TrimSpace(os.Getenv("RANSOMEYE_SINE_ADDR")) != ""
}

func runOnce(ctx context.Context, sm *identity.SessionManager, unregister contracts.StreamUnregister, pool *pgxpool.Pool) {
	now := time.Now().UTC()

	// DPI: ready only when configured and recently producing telemetry.
	dpiConfigured := DPIPlaneEnvConfigured()
	dpiOK := dpiConfigured && dpiInitialized(ctx, pool, now)

	aiAddr := strings.TrimSpace(os.Getenv("RANSOMEYE_AI_ADDR"))
	sineAddr := strings.TrimSpace(os.Getenv("RANSOMEYE_SINE_ADDR"))
	aiConfigured := aiAddr != ""
	sineConfigured := sineAddr != ""
	sineOK := sineConfigured && loopbackServiceReachable(sineAddr)
	aiOK := aiConfigured && loopbackServiceReachable(aiAddr)

	s := GetSystemState()
	pipelineOK := s.PipelineHealthy

	// Publish global system state snapshot (deterministic).
	UpdateSystemState(func(s *SystemState) {
		s.DPIReady = dpiOK
		s.SINEReady = sineOK
		s.AIReady = aiOK
		s.PipelineHealthy = pipelineOK
	})

	// Step A: snapshot under read lock (copy only).
	snap := sm.SnapshotSessions()

	expiredTokens := make([]string, 0, 16)
	for tok, sess := range snap {
		if now.Sub(sess.LastSeen) >= AWOL_THRESHOLD {
			expiredTokens = append(expiredTokens, tok)
		}
	}
	if len(expiredTokens) == 0 {
		return
	}

	// Step B: delete each under write lock (no DB work while locked).
	offlineAgentIDs := make([]string, 0, len(expiredTokens))
	for _, tok := range expiredTokens {
		sess, ok := sm.DeleteSession(tok)
		if !ok {
			continue
		}
		if sess.AgentID != "" {
			offlineAgentIDs = append(offlineAgentIDs, sess.AgentID)
			unregister.UnregisterStream(sess.AgentID)
		}
	}
	if len(offlineAgentIDs) == 0 {
		return
	}

	// Step C: batch DB update without holding SessionManager locks.
	// Schema authority in this repo uses agent_sessions.status and agent_sessions.last_heartbeat (PRD-03).
	// Negative constraint (P0): graph_ tracking tables DO NOT EXIST.
	const q = `
UPDATE agent_sessions
SET status = 'OFFLINE', last_heartbeat = $1
WHERE agent_id = $2::uuid
`
	batch := &pgx.Batch{}
	for _, agentID := range offlineAgentIDs {
		batch.Queue(q, now, agentID)
	}
	br := pool.SendBatch(ctx, batch)
	defer br.Close()

	for range offlineAgentIDs {
		_, _ = br.Exec()
	}
}

// PrimePlaneReadinessGates sets AI/SINE/DPI readiness bits before the first sweeper tick so Mishka
// (no retired sidecars) does not start with false gates for 30s.
func PrimePlaneReadinessGates(ctx context.Context, pool *pgxpool.Pool) {
	if pool == nil {
		return
	}
	now := time.Now().UTC()
	dpiConfigured := DPIPlaneEnvConfigured()
	dpiOK := dpiConfigured && dpiInitialized(ctx, pool, now)
	aiAddr := strings.TrimSpace(os.Getenv("RANSOMEYE_AI_ADDR"))
	sineAddr := strings.TrimSpace(os.Getenv("RANSOMEYE_SINE_ADDR"))
	aiConfigured := aiAddr != ""
	sineConfigured := sineAddr != ""
	sineOK := sineConfigured && loopbackServiceReachable(sineAddr)
	aiOK := aiConfigured && loopbackServiceReachable(aiAddr)
	UpdateSystemState(func(s *SystemState) {
		s.DPIReady = dpiOK
		s.SINEReady = sineOK
		s.AIReady = aiOK
	})
}

func dpiInitialized(ctx context.Context, pool *pgxpool.Pool, now time.Time) bool {
	if pool == nil {
		return false
	}
	// Consider DPI alive if it has produced telemetry within the last 60 seconds.
	const window = 60 * time.Second
	const q = `
SELECT 1
FROM telemetry_events
WHERE source = 'dpi_probe'
  AND timestamp >= $1
LIMIT 1
`
	var one int
	err := pool.QueryRow(ctx, q, now.Add(-window)).Scan(&one)
	return err == nil
}

func loopbackServiceReachable(addr string) bool {
	if addr == "" {
		return false
	}
	conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
