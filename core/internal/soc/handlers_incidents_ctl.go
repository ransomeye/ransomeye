package soc

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"ransomeye/core/internal/forensics"
)

type createIncidentRequest struct {
	TenantID    string `json:"tenant_id"`
	DetectionID string `json:"detection_id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
}

type patchIncidentRequest struct {
	Status string `json:"status"`
}

func allowedIncidentTransition(from, to string) bool {
	from = strings.ToUpper(strings.TrimSpace(from))
	to = strings.ToUpper(strings.TrimSpace(to))
	switch to {
	case "INVESTIGATING", "CONTAINED", "RESOLVED":
	default:
		return false
	}
	switch from {
	case "OPEN":
		return true
	case "INVESTIGATING":
		return to == "CONTAINED" || to == "RESOLVED"
	case "CONTAINED":
		return to == "RESOLVED"
	default:
		return false
	}
}

// handleCreateIncident inserts a row into incidents and optionally links detection_id.
func (s *Server) handleCreateIncident(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.pool == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "database pool not available"})
		return
	}
	if err := s.mustWorm(); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "read body"})
		return
	}
	var req createIncidentRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	tenantID, err := uuid.Parse(strings.TrimSpace(req.TenantID))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid tenant_id"})
		return
	}
	sev := strings.ToUpper(strings.TrimSpace(req.Severity))
	if sev == "" {
		sev = "HIGH"
	}
	switch sev {
	case "LOW", "MEDIUM", "HIGH", "CRITICAL":
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid severity"})
		return
	}
	title := strings.TrimSpace(req.Title)
	if title == "" {
		title = "SOC incident"
		if strings.TrimSpace(req.DetectionID) != "" {
			title = "Incident — detection " + strings.TrimSpace(req.DetectionID)
		}
	}
	desc := strings.TrimSpace(req.Description)
	if desc == "" && strings.TrimSpace(req.DetectionID) != "" {
		desc = "Opened from detection_id " + strings.TrimSpace(req.DetectionID)
	}

	ctx, cancel := context.WithTimeout(r.Context(), dbQueryTimeout*3)
	defer cancel()

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "tx begin"})
		return
	}
	defer tx.Rollback(ctx)

	var incidentID uuid.UUID
	err = tx.QueryRow(ctx, `
		INSERT INTO incidents (
			tenant_id, title, description, severity, status,
			assigned_to, created_by, first_seen_at, last_updated_at, resolved_at, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, 'OPEN',
			'', 'soc-ui', NOW(), NOW(), '1970-01-01 00:00:00+00', NOW(), NOW()
		) RETURNING incident_id
	`, tenantID, title, desc, sev).Scan(&incidentID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "insert failed"})
		return
	}

	var detPtr *uuid.UUID
	if detStr := strings.TrimSpace(req.DetectionID); detStr != "" {
		if detID, err := uuid.Parse(detStr); err == nil {
			detPtr = &detID
		}
	}

	actorID := strings.TrimSpace(r.Header.Get("X-Actor-ID"))
	if actorID == "" {
		actorID = "anonymous"
	}
	host, _, _ := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	sourceIP := strings.TrimSpace(host)
	ts := time.Now().UTC().Format(time.RFC3339Nano)

	forensicPayload, err := forensics.MarshalCanonical(map[string]any{
		"action":      "POST /api/v1/incidents",
		"actor_id":    actorID,
		"source_ip":   sourceIP,
		"incident_id": incidentID.String(),
		"raw_request": string(body),
		"timestamp":   ts,
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "forensic marshal failed"})
		return
	}

	wormPath, err := s.persistControlWORM(ctx, tx, tenantID, detPtr, "SOC_INCIDENT_CREATE", actorID, forensicPayload)
	committed := false
	defer func() {
		if !committed {
			removeWORMFile(wormPath)
		}
	}()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "forensic persistence failed"})
		return
	}

	if detPtr != nil {
		if _, err := tx.Exec(ctx, `
				UPDATE detections SET incident_id = $1, updated_at = NOW()
				WHERE detection_id = $2 AND tenant_id = $3`,
			incidentID, *detPtr, tenantID); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "detection link failed"})
			return
		}
	}

	if err := tx.Commit(ctx); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "commit failed"})
		return
	}
	committed = true

	writeJSON(w, http.StatusCreated, map[string]any{
		"incident_id": incidentID.String(),
	})
}

// handlePatchIncident updates incident status (FSM-enforced).
func (s *Server) handlePatchIncident(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPatch {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.pool == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "database pool not available"})
		return
	}
	if err := s.mustWorm(); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
		return
	}
	idStr := strings.TrimSpace(r.PathValue("id"))
	incidentID, err := uuid.Parse(idStr)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid incident id"})
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "read body"})
		return
	}
	var req patchIncidentRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	newStatus := strings.ToUpper(strings.TrimSpace(req.Status))
	if newStatus == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing status"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), dbQueryTimeout*3)
	defer cancel()

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "tx begin"})
		return
	}
	defer tx.Rollback(ctx)

	var cur string
	var tenantID uuid.UUID
	err = tx.QueryRow(ctx, `SELECT status, tenant_id FROM incidents WHERE incident_id = $1`, incidentID).Scan(&cur, &tenantID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "incident not found"})
		return
	}
	if !allowedIncidentTransition(cur, newStatus) {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "invalid status transition"})
		return
	}

	now := time.Now().UTC()
	if newStatus == "RESOLVED" {
		_, err = tx.Exec(ctx, `
			UPDATE incidents SET status = $1, last_updated_at = $2, resolved_at = $2, updated_at = $2
			WHERE incident_id = $3`,
			newStatus, now, incidentID)
	} else {
		_, err = tx.Exec(ctx, `
			UPDATE incidents SET status = $1, last_updated_at = $2, updated_at = $2
			WHERE incident_id = $3`,
			newStatus, now, incidentID)
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "update failed"})
		return
	}

	actorID := strings.TrimSpace(r.Header.Get("X-Actor-ID"))
	if actorID == "" {
		actorID = "anonymous"
	}
	host, _, _ := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	sourceIP := strings.TrimSpace(host)
	ts := time.Now().UTC().Format(time.RFC3339Nano)
	forensicPayload, err := forensics.MarshalCanonical(map[string]any{
		"action":       "PATCH /api/v1/incidents/{id}",
		"actor_id":     actorID,
		"source_ip":    sourceIP,
		"incident_id":  incidentID.String(),
		"new_status":   newStatus,
		"prior_status": cur,
		"raw_request":  string(body),
		"timestamp":    ts,
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "forensic marshal failed"})
		return
	}

	wormPath, err := s.persistControlWORM(ctx, tx, tenantID, nil, "SOC_INCIDENT_PATCH", actorID, forensicPayload)
	committed := false
	defer func() {
		if !committed {
			removeWORMFile(wormPath)
		}
	}()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "forensic persistence failed"})
		return
	}

	if err := tx.Commit(ctx); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "commit failed"})
		return
	}
	committed = true

	writeJSON(w, http.StatusOK, map[string]any{
		"incident_id": incidentID.String(),
		"status":      newStatus,
	})
}

// replayDetectionsSince pushes historical detection rows to one subscriber after reconnect.
func (s *Server) replayDetectionsSince(ctx context.Context, client *wsClient, since int64) {
	if s == nil || s.pool == nil || client == nil {
		return
	}

	for {
		cur := atomic.LoadInt32(&client.replayReqs)
		if cur >= maxReplayRequestsPerWS {
			return
		}
		if atomic.CompareAndSwapInt32(&client.replayReqs, cur, cur+1) {
			break
		}
	}

	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	var maxLC int64
	if err := s.pool.QueryRow(ctx, `SELECT COALESCE(MAX(logical_clock), 0) FROM detections`).Scan(&maxLC); err != nil {
		atomic.AddInt32(&client.replayReqs, -1)
		return
	}
	// Logical rejects consume a replay slot (no decrement) to prevent unbounded abuse.
	if maxLC > replayLogicalClockWindow && since < maxLC-replayLogicalClockWindow {
		return
	}
	if since > maxLC {
		return
	}

	rows, err := s.pool.Query(ctx, `
		SELECT COALESCE(event_id::text, detection_id::text), agent_id::text, posterior_prob, logical_clock,
		       EXTRACT(EPOCH FROM timestamp)::bigint, COALESCE(signals, '{}'::jsonb)
		FROM detections
		WHERE logical_clock > $1
		ORDER BY logical_clock ASC
		LIMIT 500
	`, since)
	if err != nil {
		atomic.AddInt32(&client.replayReqs, -1)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var eventID, agentID string
		var signalsRaw []byte
		var post float64
		var lc, tsUnix int64
		if err := rows.Scan(&eventID, &agentID, &post, &lc, &tsUnix, &signalsRaw); err != nil {
			continue
		}
		decision := "detected"
		var sig map[string]any
		if json.Unmarshal(signalsRaw, &sig) == nil {
			if d, ok := sig["decision"].(string); ok && d != "" {
				decision = d
			}
		}
		payload := map[string]any{
			"seq":              lc,
			"type":             "detection",
			"event_id":         eventID,
			"agent_id":         agentID,
			"timestamp":        tsUnix,
			"logical_clock":    lc,
			"score":            post,
			"decision":         decision,
			"model_prediction": 0.0,
			"entropy_score":    0.0,
			"burst_score":      0.0,
			"process_anomaly":  0.0,
			"explanation":      []any{},
		}
		b, err := json.Marshal(payload)
		if err != nil {
			continue
		}
		select {
		case client.queue <- b:
		default:
			log.Printf("WS_REPLAY_DROP client=%d queue_depth=%d queue_full since_logical_clock=%d", client.id, len(client.queue), since)
			return
		}
	}
}

func (s *Server) enqueueReplayPayload(client *wsClient, payload []byte, since int64) bool {
	if client == nil || len(payload) == 0 {
		return false
	}
	select {
	case client.queue <- payload:
		return true
	default:
		log.Printf("WS_REPLAY_DROP client=%d queue_depth=%d queue_full since_logical_clock=%d", client.id, len(client.queue), since)
		return false
	}
}

func (s *Server) replayTelemetrySince(ctx context.Context, client *wsClient, since int64) {
	_ = ctx
	_ = client
	_ = since
}

func (s *Server) replaySystemMetricsSince(ctx context.Context, client *wsClient, since int64) {
	if s == nil || s.pool == nil || client == nil {
		return
	}

	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	rows, err := s.pool.Query(ctx, `
		SELECT metric_name, component, metric_value, metric_time
		FROM system_metrics
		WHERE metric_time > GREATEST(
			NOW() - INTERVAL '1 minute',
			to_timestamp($1::double precision / 1000.0)
		)
		ORDER BY metric_time ASC, metric_name ASC
		LIMIT 240
	`, since)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var sample metricSample
		if err := rows.Scan(&sample.Name, &sample.Component, &sample.Value, &sample.RecordedAt); err != nil {
			continue
		}
		sample.LogicalClock = sample.RecordedAt.UTC().UnixMilli()
		env := s.buildSystemMetricEnvelope(sample)
		payload := append([]byte(nil), env.Payload...)
		env.Release()
		if ok := s.enqueueReplayPayload(client, payload, since); !ok {
			return
		}
	}
}

func (s *Server) replayGovernanceSince(ctx context.Context, client *wsClient, since int64) {
	if s == nil || s.pool == nil || client == nil {
		return
	}

	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	rows, err := s.pool.Query(ctx, `
		SELECT audit_id::text,
		       tenant_id::text,
		       event_type,
		       actor,
		       COALESCE(details_json, '{}'::jsonb),
		       COALESCE(signature_hex, ''),
		       created_at
		FROM governance_audit_log
		WHERE created_at > GREATEST(
			NOW() - INTERVAL '1 minute',
			to_timestamp($1::double precision / 1000.0)
		)
		ORDER BY created_at ASC, audit_id ASC
		LIMIT 240
	`, since)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var auditID, tenantID, eventType, actorID, sigHex string
		var detailsRaw []byte
		var createdAt time.Time
		if err := rows.Scan(&auditID, &tenantID, &eventType, &actorID, &detailsRaw, &sigHex, &createdAt); err != nil {
			continue
		}
		valid := verifyGovernanceSignature(tenantID, eventType, actorID, createdAt, detailsRaw, sigHex)
		env := s.buildGovernanceEnvelope(auditID, tenantID, eventType, actorID, valid, createdAt)
		payload := append([]byte(nil), env.Payload...)
		env.Release()
		if ok := s.enqueueReplayPayload(client, payload, since); !ok {
			return
		}
	}
}

func (s *Server) replayHeartbeatsSince(ctx context.Context, client *wsClient, since int64) {
	if s == nil || s.pool == nil || client == nil {
		return
	}

	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	rows, err := s.pool.Query(ctx, `
		SELECT agent_id::text,
		       hostname,
		       status,
		       lamport_clock,
		       last_heartbeat
		FROM agent_sessions
		WHERE lamport_clock > $1
		   OR last_heartbeat > NOW() - INTERVAL '1 minute'
		ORDER BY last_heartbeat ASC, agent_id ASC
		LIMIT 240
	`, since)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var agentID, hostname, status string
		var logicalClock int64
		var heartbeatAt time.Time
		if err := rows.Scan(&agentID, &hostname, &status, &logicalClock, &heartbeatAt); err != nil {
			continue
		}
		env := s.buildHeartbeatEnvelope(agentID, hostname, status, logicalClock, heartbeatAt)
		payload := append([]byte(nil), env.Payload...)
		env.Release()
		if ok := s.enqueueReplayPayload(client, payload, since); !ok {
			return
		}
	}
}
