package soc

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	corecrypto "ransomeye/core/internal/crypto"
	"ransomeye/core/internal/forensics"
	"ransomeye/core/internal/health"
)

// ---------------------------------------------------------------------------
// PRD-03 response structs — field names match DB schema exactly.
// ---------------------------------------------------------------------------

// AlertRow represents a detection that crossed the AEC threshold (aec_class >= 2).
type AlertRow struct {
	DetectionID   string  `json:"detection_id"`
	TenantID      string  `json:"tenant_id"`
	AgentID       string  `json:"agent_id"`
	EventID       string  `json:"event_id,omitempty"`
	Timestamp     string  `json:"timestamp"`
	PosteriorProb float64 `json:"posterior_prob"`
	AECClass      int     `json:"aec_class"`
	ThreatType    string  `json:"threat_type,omitempty"`
	Decision      string  `json:"analyst_disposition"`
	LogicalClock  int64   `json:"logical_clock"`
	DriftAlert    bool    `json:"drift_alert"`
	CreatedAt     string  `json:"created_at"`
}

// TelemetryRow represents a single telemetry event from the telemetry_events table.
type TelemetryRow struct {
	EventID              string `json:"event_id"`
	TenantID             string `json:"tenant_id"`
	AgentID              string `json:"agent_id,omitempty"`
	ProbeID              string `json:"probe_id,omitempty"`
	EventType            string `json:"event_type"`
	Timestamp            string `json:"timestamp"`
	LogicalClock         int64  `json:"logical_clock"`
	Source               string `json:"source"`
	SourceType           string `json:"source_type"`
	CanonicalPayloadHash string `json:"canonical_payload_hash"`
	CreatedAt            string `json:"created_at"`
}

// IncidentRow represents a row from the incidents table.
type IncidentRow struct {
	IncidentID    string `json:"incident_id"`
	TenantID      string `json:"tenant_id"`
	Title         string `json:"title"`
	Description   string `json:"description,omitempty"`
	Severity      string `json:"severity"`
	Status        string `json:"status"`
	AssignedTo    string `json:"assigned_to,omitempty"`
	FirstSeenAt   string `json:"first_seen_at,omitempty"`
	LastUpdatedAt string `json:"last_updated_at,omitempty"`
	CreatedAt     string `json:"created_at"`
}

// DetectionListRow is the DB-backed detection model used by the SOC dashboard.
// `id` stays aligned with the WebSocket detection event identifier for stable merging.
type DetectionListRow struct {
	ID            string         `json:"id"`
	DetectionID   string         `json:"detection_id"`
	EventID       string         `json:"event_id,omitempty"`
	AgentID       string         `json:"agent_id"`
	Timestamp     string         `json:"timestamp"`
	Posterior     float64        `json:"posterior"`
	Confidence    float64        `json:"confidence"`
	AECClass      string         `json:"aec_class"`
	AECClassIndex int            `json:"aec_class_index"`
	Signals       map[string]any `json:"signals"`
	LOOImportance map[string]any `json:"loo_importance"`
	Decision      string         `json:"decision,omitempty"`
	LogicalClock  int64          `json:"logical_clock"`
	CreatedAt     string         `json:"created_at"`
}

type systemMetricAggregateRow struct {
	MetricName     string  `json:"metric_name"`
	LatestValue    float64 `json:"latest_value"`
	AvgValue       float64 `json:"avg_value"`
	MinValue       float64 `json:"min_value"`
	MaxValue       float64 `json:"max_value"`
	SampleCount    int64   `json:"sample_count"`
	LastRecordedAt string  `json:"last_recorded_at"`
}

type governanceAuditRow struct {
	AuditID        string `json:"audit_id"`
	EventType      string `json:"event_type"`
	ActorID        string `json:"actor_id"`
	SignatureValid bool   `json:"signature_valid"`
	CreatedAt      string `json:"created_at"`
}

// ---------------------------------------------------------------------------
// DB-backed handlers (real queries, never cache-only).
// ---------------------------------------------------------------------------

const (
	// MAX_QUERY_LIMIT is the absolute ceiling for all DB query result sets (PRD-18 §3 resource budget).
	MAX_QUERY_LIMIT         = 1000
	defaultResultLimit      = 100
	maxCursorTelemetryLimit = 200
	dbQueryTimeout          = 5 * time.Second
)

type telemetryPageCursor struct {
	Timestamp string `json:"timestamp"`
	EventID   string `json:"event_id"`
}

func clampLimit(raw string, defaultVal, maxVal int) int {
	n, _ := strconv.Atoi(raw)
	if n <= 0 {
		return defaultVal
	}
	if n > MAX_QUERY_LIMIT {
		return MAX_QUERY_LIMIT
	}
	if n > maxVal {
		return maxVal
	}
	return n
}

func aecClassLabel(n int16) string {
	return "AEC-" + strconv.Itoa(int(n))
}

func decodeJSONMap(raw []byte) map[string]any {
	if len(raw) == 0 {
		return map[string]any{}
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil || out == nil {
		return map[string]any{}
	}
	return out
}

func isAllowedTelemetrySource(source string) bool {
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "agent", "syslog", "netflow", "dpi":
		return true
	default:
		return false
	}
}

func encodeTelemetryCursor(ts time.Time, eventID string) string {
	payload, err := json.Marshal(telemetryPageCursor{
		Timestamp: ts.UTC().Format(time.RFC3339Nano),
		EventID:   eventID,
	})
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(payload)
}

func decodeTelemetryCursor(raw string) (time.Time, string, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(raw))
	if err != nil {
		return time.Time{}, "", fmt.Errorf("decode cursor: %w", err)
	}
	var cursor telemetryPageCursor
	if err := json.Unmarshal(decoded, &cursor); err != nil {
		return time.Time{}, "", fmt.Errorf("unmarshal cursor: %w", err)
	}
	if strings.TrimSpace(cursor.EventID) == "" {
		return time.Time{}, "", errors.New("cursor event_id missing")
	}
	ts, err := time.Parse(time.RFC3339Nano, cursor.Timestamp)
	if err != nil {
		return time.Time{}, "", fmt.Errorf("parse cursor timestamp: %w", err)
	}
	return ts.UTC(), strings.TrimSpace(cursor.EventID), nil
}

func validateTelemetryRow(row TelemetryRow) error {
	if strings.TrimSpace(row.EventID) == "" {
		return errors.New("event_id missing")
	}
	if !isAllowedTelemetrySource(row.SourceType) {
		return errors.New("source_type invalid")
	}
	if strings.TrimSpace(row.Timestamp) == "" {
		return errors.New("timestamp missing")
	}
	if strings.TrimSpace(row.CanonicalPayloadHash) == "" {
		return errors.New("canonical_payload_hash missing")
	}
	if strings.TrimSpace(row.AgentID) == "" && strings.TrimSpace(row.ProbeID) == "" {
		return errors.New("agent_id or probe_id required")
	}
	return nil
}

func telemetryIdentityFields(sourceType, identity string) (string, string) {
	identity = strings.TrimSpace(identity)
	if identity == "" {
		return "", ""
	}
	if strings.EqualFold(strings.TrimSpace(sourceType), "agent") {
		return identity, ""
	}
	return "", identity
}

func detectionDecision(signals map[string]any) string {
	if v, ok := signals["decision"].(string); ok {
		return v
	}
	return ""
}

func scanDetectionListRows(rows pgx.Rows) []DetectionListRow {
	out := make([]DetectionListRow, 0)
	for rows.Next() {
		var item DetectionListRow
		var eventID *string
		var ts, createdAt time.Time
		var aecClass int16
		var signalsRaw, looRaw []byte
		if err := rows.Scan(
			&item.DetectionID,
			&eventID,
			&item.AgentID,
			&ts,
			&item.Posterior,
			&aecClass,
			&signalsRaw,
			&looRaw,
			&item.LogicalClock,
			&createdAt,
		); err != nil {
			continue
		}
		item.Timestamp = ts.UTC().Format(time.RFC3339)
		item.CreatedAt = createdAt.UTC().Format(time.RFC3339)
		item.Confidence = item.Posterior
		item.AECClassIndex = int(aecClass)
		item.AECClass = aecClassLabel(aecClass)
		item.Signals = decodeJSONMap(signalsRaw)
		item.LOOImportance = decodeJSONMap(looRaw)
		item.Decision = detectionDecision(item.Signals)
		if eventID != nil && *eventID != "" {
			item.EventID = *eventID
			item.ID = *eventID
		} else {
			item.ID = item.DetectionID
		}
		out = append(out, item)
	}
	return out
}

func (s *Server) queryDetectionsList(ctx context.Context, page, pageSize int, minScore float64, agentFilter string) ([]DetectionListRow, int, error) {
	if s.pool == nil {
		return nil, 0, errors.New("database pool not available")
	}
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 20
	}
	if pageSize > MAX_QUERY_LIMIT {
		pageSize = MAX_QUERY_LIMIT
	}
	var total int
	if err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM detections
		WHERE posterior_prob >= $1
		  AND ($2 = '' OR agent_id::text = $2)
	`, minScore, agentFilter).Scan(&total); err != nil {
		return nil, 0, err
	}

	cursorTS := time.Time{}
	cursorID := ""
	for current := 1; current <= page; current++ {
		args := []any{minScore, agentFilter, pageSize}
		query := `
			SELECT detection_id::text,
			       event_id::text,
			       agent_id::text,
			       timestamp,
			       posterior_prob::double precision,
			       aec_class,
			       COALESCE(signals, '{}'::jsonb),
			       COALESCE(loo_importance, '{}'::jsonb),
			       logical_clock,
			       created_at
			FROM detections
			WHERE posterior_prob >= $1
			  AND ($2 = '' OR agent_id::text = $2)
		`
		if !cursorTS.IsZero() && cursorID != "" {
			query += `
			  AND (timestamp < $4 OR (timestamp = $4 AND detection_id::text < $5))
			`
			args = append(args, cursorTS, cursorID)
		}
		query += `
			ORDER BY timestamp DESC, detection_id DESC
			LIMIT $3
		`
		rows, err := s.pool.Query(ctx, query, args...)
		if err != nil {
			return nil, 0, err
		}
		batch := scanDetectionListRows(rows)
		rows.Close()
		if current == page {
			return batch, total, nil
		}
		if len(batch) == 0 {
			return []DetectionListRow{}, total, nil
		}
		last := batch[len(batch)-1]
		ts, err := time.Parse(time.RFC3339, last.Timestamp)
		if err != nil {
			return nil, 0, err
		}
		cursorTS = ts.UTC()
		cursorID = last.DetectionID
	}
	return []DetectionListRow{}, total, nil
}

func (s *Server) queryRecentDetections(ctx context.Context, limit int) ([]DetectionListRow, error) {
	if s.pool == nil {
		return nil, errors.New("database pool not available")
	}
	limit = clampLimit(strconv.Itoa(limit), defaultResultLimit, MAX_QUERY_LIMIT)
	rows, err := s.pool.Query(ctx, `
		SELECT detection_id::text,
		       event_id::text,
		       agent_id::text,
		       timestamp,
		       posterior_prob::double precision,
		       aec_class,
		       COALESCE(signals, '{}'::jsonb),
		       COALESCE(loo_importance, '{}'::jsonb),
		       logical_clock,
		       created_at
		FROM detections
		ORDER BY timestamp DESC, detection_id DESC
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanDetectionListRows(rows), nil
}

// handleAlertsDB queries the detections table for alerts (aec_class >= 2), ordered newest first.
func (s *Server) handleAlertsDB(w http.ResponseWriter, r *http.Request) {
	if s.pool == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "database pool not available",
		})
		return
	}

	limit := clampLimit(r.URL.Query().Get("limit"), defaultResultLimit, MAX_QUERY_LIMIT)

	ctx, cancel := context.WithTimeout(r.Context(), dbQueryTimeout)
	defer cancel()

	rows, err := s.pool.Query(ctx, `
		SELECT detection_id, tenant_id, agent_id, event_id,
		       timestamp, posterior_prob, aec_class, threat_type,
		       analyst_disposition, logical_clock, drift_alert, created_at
		FROM detections
		WHERE aec_class >= 2
		ORDER BY timestamp DESC
		LIMIT $1
	`, limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "query failed",
		})
		return
	}
	defer rows.Close()

	alerts := make([]AlertRow, 0, limit)
	for rows.Next() {
		var a AlertRow
		var ts, createdAt time.Time
		var eventID *string
		var threatType *string
		var disposition *string
		if err := rows.Scan(
			&a.DetectionID, &a.TenantID, &a.AgentID, &eventID,
			&ts, &a.PosteriorProb, &a.AECClass, &threatType,
			&disposition, &a.LogicalClock, &a.DriftAlert, &createdAt,
		); err != nil {
			continue
		}
		a.Timestamp = ts.UTC().Format(time.RFC3339)
		a.CreatedAt = createdAt.UTC().Format(time.RFC3339)
		if eventID != nil {
			a.EventID = *eventID
		}
		if threatType != nil {
			a.ThreatType = *threatType
		}
		if disposition != nil {
			a.Decision = *disposition
		}
		alerts = append(alerts, a)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"total":  len(alerts),
		"alerts": alerts,
	})
}

func (s *Server) handleSystemHealth(w http.ResponseWriter, r *http.Request) {
	st := health.GetSystemState()
	pipelineOK := st != nil && st.PipelineHealthy
	dbOK := poolHealthy(r.Context(), s.pool)

	if s.pool == nil {
		status := "degraded"
		if pipelineOK {
			status = "degraded"
		}
		if health.AirGapDegradesHealth() {
			status = "degraded"
		}
		gateBlocked, gateReason := EnforcementDispatchGateView()
		writeJSON(w, http.StatusOK, map[string]any{
			"status":                    status,
			"db":                        false,
			"pipeline_healthy":          pipelineOK,
			"ai_configured":             health.AIPlaneEnvConfigured(),
			"ai_ready":                  st != nil && st.AIReady,
			"sine_configured":           health.SINEPlaneEnvConfigured(),
			"sine_ready":                st != nil && st.SINEReady,
			"dpi_configured":            health.DPIPlaneEnvConfigured(),
			"dpi_ready":                 st != nil && st.DPIReady,
			"compliance_bootstrap_ok":   health.ComplianceBootstrapOK(),
			"air_gap_posture":           health.AirGapPosture(),
			"air_gap_detail":            health.AirGapDetail(),
			"enforcement_dispatch_gate_blocked": gateBlocked,
			"enforcement_dispatch_gate_reason":  gateReason,
			"authoritative_decision_path":       AuthoritativeDecisionPath,
			"isolation_simulation_gate_scope":   IsolationSimulationGateScope,
			"system_metrics_available":          false,
			"transport":                         "http_plaintext",
			"loopback":                          true,
		})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), dbQueryTimeout)
	defer cancel()

	_, _ = s.captureRuntimeMetrics(ctx)

	rows, err := s.pool.Query(ctx, `
		SELECT DISTINCT ON (metric_name)
		       metric_name,
		       metric_value,
		       metric_time AS recorded_at
		FROM system_metrics
		WHERE metric_time > NOW() - INTERVAL '1 minute'
		  AND metric_name = ANY($1)
		ORDER BY metric_name, metric_time DESC
	`, []string{"wal_fsync_latency", "event_queue_depth", "batch_size", "circuit_breaker_tripped"})
	metricsAvailable := err == nil
	var values map[string]float64
	var recordedAt time.Time
	if err != nil {
		metricsAvailable = false
	} else {
		defer rows.Close()
		values = make(map[string]float64, 4)
		for rows.Next() {
			var name string
			var value float64
			var ts time.Time
			if err := rows.Scan(&name, &value, &ts); err != nil {
				continue
			}
			values[name] = value
			if ts.After(recordedAt) {
				recordedAt = ts
			}
		}
	}

	circuitBreaker := false
	if len(values) > 0 {
		circuitBreaker = values["circuit_breaker_tripped"] >= 0.5
	}

	status := "ok"
	if !health.SliceTelemetryOK(dbOK, pipelineOK) || circuitBreaker || health.AirGapDegradesHealth() {
		status = "degraded"
	}

	gateBlocked, gateReason := EnforcementDispatchGateView()
	out := map[string]any{
		"status":                    status,
		"db":                        dbOK,
		"pipeline_healthy":          pipelineOK,
		"ai_configured":             health.AIPlaneEnvConfigured(),
		"ai_ready":                  st != nil && st.AIReady,
		"sine_configured":           health.SINEPlaneEnvConfigured(),
		"sine_ready":                st != nil && st.SINEReady,
		"dpi_configured":            health.DPIPlaneEnvConfigured(),
		"dpi_ready":                 st != nil && st.DPIReady,
		"compliance_bootstrap_ok":   health.ComplianceBootstrapOK(),
		"air_gap_posture":           health.AirGapPosture(),
		"air_gap_detail":            health.AirGapDetail(),
		"enforcement_dispatch_gate_blocked": gateBlocked,
		"enforcement_dispatch_gate_reason":  gateReason,
		"authoritative_decision_path":       AuthoritativeDecisionPath,
		"isolation_simulation_gate_scope":   IsolationSimulationGateScope,
		"system_metrics_available":          metricsAvailable && len(values) > 0,
		"transport":                         "http_plaintext",
		"loopback":                          true,
		"circuit_breaker":                   circuitBreaker,
		"circuit_breaker_tripped":           circuitBreaker,
	}
	if err != nil {
		out["metrics_error"] = "query failed"
	}
	if len(values) > 0 {
		out["wal_fsync_latency_ms"] = values["wal_fsync_latency"]
		out["event_queue_depth"] = int64(values["event_queue_depth"])
		out["batch_size"] = int64(values["batch_size"])
		if !recordedAt.IsZero() {
			out["recorded_at"] = recordedAt.UTC().Format(time.RFC3339)
		}
	}

	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleSystemMetrics(w http.ResponseWriter, r *http.Request) {
	if s.pool == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "database pool not available",
		})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), dbQueryTimeout)
	defer cancel()

	_, _ = s.captureRuntimeMetrics(ctx)

	rows, err := s.pool.Query(ctx, `
		WITH recent AS (
			SELECT metric_name, metric_value, metric_time
			FROM system_metrics
			WHERE metric_time > NOW() - INTERVAL '1 minute'
		),
		latest AS (
			SELECT DISTINCT ON (metric_name)
			       metric_name,
			       metric_value AS latest_value,
			       metric_time AS last_recorded_at
			FROM recent
			ORDER BY metric_name, metric_time DESC
		)
		SELECT r.metric_name,
		       l.latest_value::double precision,
		       AVG(r.metric_value)::double precision,
		       MIN(r.metric_value)::double precision,
		       MAX(r.metric_value)::double precision,
		       COUNT(*)::bigint,
		       l.last_recorded_at
		FROM recent r
		JOIN latest l USING (metric_name)
		GROUP BY r.metric_name, l.latest_value, l.last_recorded_at
		ORDER BY r.metric_name
	`)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "query failed",
		})
		return
	}
	defer rows.Close()

	aggregates := make([]systemMetricAggregateRow, 0, 8)
	latest := make(map[string]float64)
	for rows.Next() {
		var item systemMetricAggregateRow
		var ts time.Time
		if err := rows.Scan(
			&item.MetricName,
			&item.LatestValue,
			&item.AvgValue,
			&item.MinValue,
			&item.MaxValue,
			&item.SampleCount,
			&ts,
		); err != nil {
			continue
		}
		item.LastRecordedAt = ts.UTC().Format(time.RFC3339)
		aggregates = append(aggregates, item)
		latest[item.MetricName] = item.LatestValue
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"window_seconds": 60,
		"metrics":        aggregates,
		"latest":         latest,
	})
}

func (s *Server) handleGovernanceAudit(w http.ResponseWriter, r *http.Request) {
	if s.pool == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "database pool not available",
		})
		return
	}

	limit := clampLimit(r.URL.Query().Get("limit"), defaultResultLimit, 500)

	ctx, cancel := context.WithTimeout(r.Context(), dbQueryTimeout*2)
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
		ORDER BY created_at DESC, audit_id DESC
		LIMIT $1
	`, limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "query failed",
		})
		return
	}
	defer rows.Close()

	events := make([]governanceAuditRow, 0, limit)
	for rows.Next() {
		var item governanceAuditRow
		var tenantID, sigHex string
		var detailsRaw []byte
		var createdAt time.Time
		if err := rows.Scan(
			&item.AuditID,
			&tenantID,
			&item.EventType,
			&item.ActorID,
			&detailsRaw,
			&sigHex,
			&createdAt,
		); err != nil {
			continue
		}
		item.CreatedAt = createdAt.UTC().Format(time.RFC3339)
		item.SignatureValid = verifyGovernanceSignature(tenantID, item.EventType, item.ActorID, createdAt, detailsRaw, sigHex)
		events = append(events, item)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"total":  len(events),
		"events": events,
	})
}

// handleTelemetryDB queries the telemetry_events table for recent events, ordered newest first.
func (s *Server) handleTelemetryDB(w http.ResponseWriter, r *http.Request) {
	if s.pool == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "database pool not available",
		})
		return
	}

	sourceFilter := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("source")))
	if sourceFilter != "" && !isAllowedTelemetrySource(sourceFilter) {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid source filter",
		})
		return
	}
	limit := clampLimit(r.URL.Query().Get("limit"), defaultResultLimit, maxCursorTelemetryLimit)
	cursorRaw := strings.TrimSpace(r.URL.Query().Get("cursor"))
	cursorTS := time.Time{}
	cursorEventID := ""
	if cursorRaw != "" {
		var err error
		cursorTS, cursorEventID, err = decodeTelemetryCursor(cursorRaw)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "invalid cursor",
			})
			return
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), dbQueryTimeout)
	defer cancel()

	args := []any{sourceFilter}
	query := `
		SELECT event_id::text,
		       tenant_id::text,
		       COALESCE(agent_id::text, ''),
		       event_type,
		       timestamp,
		       logical_clock,
		       source,
		       source_type,
		       created_at,
		       COALESCE(encode(payload_sha256, 'hex'), '')
		FROM telemetry_events
		WHERE ($1 = '' OR source_type = $1)
	`
	if !cursorTS.IsZero() && cursorEventID != "" {
		query += `
		  AND (timestamp < $2 OR (timestamp = $2 AND event_id::text < $3))
		`
		args = append(args, cursorTS, cursorEventID)
	}
	query += fmt.Sprintf(`
		ORDER BY timestamp DESC, event_id::text DESC
		LIMIT $%d
	`, len(args)+1)
	args = append(args, limit+1)

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "query failed",
		})
		return
	}
	defer rows.Close()

	type telemetryScanResult struct {
		row      TelemetryRow
		cursorTS time.Time
	}
	scanned := make([]telemetryScanResult, 0, limit+1)
	for rows.Next() {
		var t TelemetryRow
		var identity string
		var hashHex string
		var ts, createdAt time.Time
		if err := rows.Scan(
			&t.EventID, &t.TenantID, &identity, &t.EventType,
			&ts, &t.LogicalClock, &t.Source, &t.SourceType, &createdAt, &hashHex,
		); err != nil {
			continue
		}
		t.AgentID, t.ProbeID = telemetryIdentityFields(t.SourceType, identity)
		t.Timestamp = ts.UTC().Format(time.RFC3339Nano)
		t.CreatedAt = createdAt.UTC().Format(time.RFC3339Nano)
		t.CanonicalPayloadHash = hashHex
		if err := validateTelemetryRow(t); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{
				"error": "telemetry row validation failed",
			})
			return
		}
		scanned = append(scanned, telemetryScanResult{row: t, cursorTS: ts.UTC()})
	}

	events := make([]TelemetryRow, 0, limit)
	for idx, item := range scanned {
		if idx >= limit {
			break
		}
		events = append(events, item.row)
	}
	hasMore := len(scanned) > limit
	nextCursor := ""
	if hasMore && len(events) > 0 {
		last := scanned[len(events)-1]
		nextCursor = encodeTelemetryCursor(last.cursorTS, last.row.EventID)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"data":     events,
		"cursor":   nextCursor,
		"has_more": hasMore,
	})
}

// handleIncidentsDB queries the incidents table for real incident data, ordered newest first.
func (s *Server) handleIncidentsDB(w http.ResponseWriter, r *http.Request) {
	if s.pool == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "database pool not available",
		})
		return
	}

	limit := clampLimit(r.URL.Query().Get("limit"), defaultResultLimit, MAX_QUERY_LIMIT)

	ctx, cancel := context.WithTimeout(r.Context(), dbQueryTimeout)
	defer cancel()

	rows, err := s.pool.Query(ctx, `
		SELECT incident_id, tenant_id, title, description,
		       severity, status, assigned_to,
		       first_seen_at, last_updated_at, created_at
		FROM incidents
		ORDER BY created_at DESC
		LIMIT $1
	`, limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "query failed",
		})
		return
	}
	defer rows.Close()

	incidents := make([]IncidentRow, 0, limit)
	for rows.Next() {
		var inc IncidentRow
		var createdAt time.Time
		var description, assignedTo *string
		var firstSeen, lastUpdated *time.Time
		if err := rows.Scan(
			&inc.IncidentID, &inc.TenantID, &inc.Title, &description,
			&inc.Severity, &inc.Status, &assignedTo,
			&firstSeen, &lastUpdated, &createdAt,
		); err != nil {
			continue
		}
		inc.CreatedAt = createdAt.UTC().Format(time.RFC3339)
		if description != nil {
			inc.Description = *description
		}
		if assignedTo != nil {
			inc.AssignedTo = *assignedTo
		}
		if firstSeen != nil {
			inc.FirstSeenAt = firstSeen.UTC().Format(time.RFC3339)
		}
		if lastUpdated != nil {
			inc.LastUpdatedAt = lastUpdated.UTC().Format(time.RFC3339)
		}
		incidents = append(incidents, inc)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"total":     len(incidents),
		"incidents": incidents,
	})
}

// poolHealthy returns true if the DB pool is reachable.
func poolHealthy(ctx context.Context, pool *pgxpool.Pool) bool {
	if pool == nil {
		return false
	}
	pctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return pool.Ping(pctx) == nil
}

func loadGovernancePublicKey() (ed25519.PublicKey, error) {
	raw, err := corecrypto.ReadValidatedWormSeed(corecrypto.WormSigningKeyPath, true)
	if err != nil {
		return nil, err
	}
	priv := ed25519.NewKeyFromSeed(raw)
	return append(ed25519.PublicKey(nil), priv.Public().(ed25519.PublicKey)...), nil
}

func verifyGovernanceSignature(tenantID, eventType, actorID string, createdAt time.Time, detailsRaw []byte, sigHex string) bool {
	if sigHex == "" {
		return false
	}
	pub, err := loadGovernancePublicKey()
	if err != nil {
		return false
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	details := decodeJSONMap(detailsRaw)
	payload, err := forensics.MarshalCanonical(map[string]any{
		"actor":      actorID,
		"created_at": createdAt.UTC().Format(time.RFC3339Nano),
		"details":    details,
		"event_type": eventType,
		"tenant_id":  tenantID,
	})
	if err != nil {
		return false
	}
	return ed25519.Verify(pub, payload, sig)
}
