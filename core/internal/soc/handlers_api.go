package soc

import (
	"context"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"ransomeye/core/internal/compliance"
	"ransomeye/core/internal/health"
	"ransomeye/core/internal/metrics"
)

func clamp01(x float64) float64 {
	if x < 0 {
		return 0
	}
	if x > 1 {
		return 1
	}
	return x
}

func (s *Server) handleDetectionsList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	if page < 1 {
		page = 1
	}
	pageSize, _ := strconv.Atoi(q.Get("page_size"))
	if pageSize < 1 {
		pageSize = 20
	}
	if pageSize > 100 {
		pageSize = 100
	}
	minScore, _ := strconv.ParseFloat(q.Get("min_score"), 64)
	agentFilter := strings.TrimSpace(q.Get("agent_id"))

	ctx, cancel := context.WithTimeout(r.Context(), dbQueryTimeout)
	defer cancel()

	pageRows, total, err := s.queryDetectionsList(ctx, page, pageSize, minScore, agentFilter)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "query failed",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"page":       page,
		"page_size":  pageSize,
		"total":      total,
		"detections": pageRows,
		"ui_lineage": map[string]any{
			"presentation_only":     true,
			"not_query_record_v1":   true,
			"not_report_record_v1":  true,
			"drill_down_basis":      "detections_table_rows",
		},
	})
}

func (s *Server) handleIncidents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	if page < 1 {
		page = 1
	}
	pageSize, _ := strconv.Atoi(q.Get("page_size"))
	if pageSize < 1 {
		pageSize = 20
	}
	if pageSize > 100 {
		pageSize = 100
	}
	statusFilter := strings.TrimSpace(strings.ToLower(q.Get("status")))

	s.mu.RLock()
	raw := s.cache.snapshotNewestFirst()
	s.mu.RUnlock()

	type incidentRow struct {
		IncidentID  string  `json:"incident_id"`
		DetectionID string  `json:"detection_id"`
		AgentID     string  `json:"agent_id"`
		Status      string  `json:"status"`
		Severity    string  `json:"severity"`
		OpenedAt    string  `json:"opened_at"`
		Confidence  float64 `json:"confidence"`
		Decision    string  `json:"decision"`
	}

	incidents := make([]incidentRow, 0, len(raw))
	for _, d := range raw {
		if d.ID == "" {
			continue
		}
		sev := "low"
		if d.Confidence >= 0.8 {
			sev = "critical"
		} else if d.Confidence >= 0.5 {
			sev = "medium"
		}
		st := "open"
		row := incidentRow{
			IncidentID:  "inc-" + d.ID,
			DetectionID: d.ID,
			AgentID:     d.AgentID,
			Status:      st,
			Severity:    sev,
			OpenedAt:    d.Timestamp.UTC().Format("2006-01-02T15:04:05Z"),
			Confidence:  d.Confidence,
			Decision:    d.Decision,
		}
		if statusFilter != "" && row.Status != statusFilter {
			continue
		}
		incidents = append(incidents, row)
	}
	sort.SliceStable(incidents, func(i, j int) bool {
		if incidents[i].OpenedAt == incidents[j].OpenedAt {
			return incidents[i].IncidentID < incidents[j].IncidentID
		}
		return incidents[i].OpenedAt > incidents[j].OpenedAt
	})
	total := len(incidents)
	start := (page - 1) * pageSize
	if start > total {
		start = total
	}
	end := start + pageSize
	if end > total {
		end = total
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"page":      page,
		"page_size": pageSize,
		"total":     total,
		"incidents": incidents[start:end],
	})
}

func (s *Server) handleFleetStatus(w http.ResponseWriter, r *http.Request) {
	agents := make([]map[string]any, 0, 32)
	if s.pool != nil {
		ctx, cancel := context.WithTimeout(r.Context(), dbQueryTimeout)
		rows, err := s.pool.Query(ctx, `
			SELECT agent_id::text, hostname, status, last_heartbeat
			FROM agent_sessions
			ORDER BY last_heartbeat DESC, agent_id DESC
			LIMIT 100
		`)
		if err == nil {
			for rows.Next() {
				var agentID, hostname, status string
				var lastHeartbeat time.Time
				if scanErr := rows.Scan(&agentID, &hostname, &status, &lastHeartbeat); scanErr != nil {
					continue
				}
				agents = append(agents, map[string]any{
					"agent_id":       agentID,
					"hostname":       hostname,
					"status":         status,
					"last_heartbeat": lastHeartbeat.UTC().Format(time.RFC3339),
				})
			}
			rows.Close()
		}
		cancel()
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"agents":     agents,
		"dpi_probe":  dpiProbeFleetPayload(),
		"sine_plane": optionalPlaneLabel(health.SINEPlaneEnvConfigured()),
		"core": map[string]any{
			"events_ingested": metrics.EventsIngested(),
			"events_dropped":  metrics.EventsDropped(),
			"queue_drops":     metrics.CoreQueueDrops(),
		},
		"sine_state": ingestionSINEStateLine(),
		"ui_lineage": map[string]any{
			"presentation_only":    true,
			"authority_basis":      "agent_sessions_table_plus_in_process_metrics",
			"not_query_record_v1":  true,
			"not_report_record_v1": true,
		},
	})
}

func (s *Server) handleGovernancePolicies(w http.ResponseWriter, r *http.Request) {
	if s.pool == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "database pool not available",
		})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), dbQueryTimeout)
	defer cancel()

	rows, err := s.pool.Query(ctx, `
		SELECT audit_id::text, event_type, actor, created_at
		FROM governance_audit_log
		WHERE event_type LIKE 'POLICY_%'
		ORDER BY created_at DESC, audit_id DESC
		LIMIT 100
	`)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "query failed",
		})
		return
	}
	defer rows.Close()

	policies := make([]map[string]any, 0, 32)
	for rows.Next() {
		var auditID, eventType, actor string
		var createdAt time.Time
		if err := rows.Scan(&auditID, &eventType, &actor, &createdAt); err != nil {
			continue
		}
		policies = append(policies, map[string]any{
			"id":         auditID,
			"event_type": eventType,
			"actor_id":   actor,
			"created_at": createdAt.UTC().Format(time.RFC3339),
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"policies": policies,
	})
}

func (s *Server) handleComplianceReport(w http.ResponseWriter, r *http.Request) {
	outcomes := compliance.RunRegisteredChecks()
	passed := 0
	for _, o := range outcomes {
		if o.OK {
			passed++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"requirements": compliance.ListRequirementInfo(),
		"outcomes":     outcomes,
		"summary": map[string]any{
			"total":   len(outcomes),
			"passed":  passed,
			"failed":  len(outcomes) - passed,
			"healthy": passed == len(outcomes),
		},
		"ui_lineage": map[string]any{
			"presentation_only":           true,
			"prd25_dashboard_projection":  true,
			"not_committed_report_record_v1": true,
			"rebuild_note":                "in_process_compliance_checks_not_replay_certificate",
		},
	})
}

func (s *Server) findDetection(eventID string) (recentDetection, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	raw := s.cache.snapshotNewestFirst()
	for _, d := range raw {
		if d.ID == eventID {
			return d, true
		}
	}
	return recentDetection{}, false
}

func (s *Server) handleExplainabilityLOO(w http.ResponseWriter, r *http.Request) {
	eventID := strings.TrimSpace(r.URL.Query().Get("event_id"))
	if eventID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "event_id required"})
		return
	}
	d, ok := s.findDetection(eventID)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "detection not in working set"})
		return
	}

	feats := append([]explanationFeat(nil), d.Explanation...)
	sort.SliceStable(feats, func(i, j int) bool {
		return feats[i].Feature < feats[j].Feature
	})

	pFull := clamp01(d.Confidence)
	rows := make([]map[string]any, 0, len(feats))
	for _, f := range feats {
		// PRD-07 LOO: treat pipeline impact as marginal contribution; P_{-i} ≈ P_full - impact (clamped).
		pMinus := clamp01(pFull - f.Impact)
		loo := pFull - pMinus
		rows = append(rows, map[string]any{
			"feature":                f.Feature,
			"value":                  f.Value,
			"impact":                 f.Impact,
			"posterior_full":         pFull,
			"posterior_without_feat": pMinus,
			"loo_delta":              loo,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"event_id":       eventID,
		"agent_id":       d.AgentID,
		"decision":       d.Decision,
		"posterior_full": pFull,
		"method":         "LOO_from_pipeline_impacts",
		"features":       rows,
		"ui_lineage": map[string]any{
			"presentation_only":       true,
			"data_scope":                "in_memory_working_set_not_db_replay",
			"not_query_record_v1":     true,
			"deterministic_sort":        "lexicographic_by_feature",
			"authoritative_drill_down": "use_detections_list_and_committed_paths_outside_this_api",
		},
	})
}

// handleShadowIntelStatus is non-authoritative: advisory plane visibility only (no writes, no authority joins).
func (s *Server) handleShadowIntelStatus(w http.ResponseWriter, r *http.Request) {
	st := health.GetSystemState()
	pipelineOK := st != nil && st.PipelineHealthy
	dbOK := poolHealthy(r.Context(), s.pool)
	top := "ok"
	if !health.SliceTelemetryOK(dbOK, pipelineOK) || health.AirGapDegradesHealth() {
		top = "degraded"
	}
	gateBlocked, gateReason := EnforcementDispatchGateView()
	writeJSON(w, http.StatusOK, map[string]any{
		"authoritative":           false,
		"prd_22_non_authoritative": true,
		"opaif_safe_surface":      true,
		"cannot_trigger_enforcement": true,
		"cannot_influence_priority":  true,
		"status":                  top,
		"mode":                    "read_only_advisory",
		"db":                      dbOK,
		"pipeline_healthy":        pipelineOK,
		"compliance_bootstrap_ok": health.ComplianceBootstrapOK(),
		"air_gap_posture":         health.AirGapPosture(),
		"air_gap_detail":          health.AirGapDetail(),
		"enforcement_dispatch_gate_blocked": gateBlocked,
		"enforcement_dispatch_gate_reason":  gateReason,
		"authoritative_decision_path":       AuthoritativeDecisionPath,
		"isolation_simulation_gate_scope":   IsolationSimulationGateScope,
		"planes": map[string]any{
			"ai_sidecar_configured":   health.AIPlaneEnvConfigured(),
			"sine_sidecar_configured": health.SINEPlaneEnvConfigured(),
			"dpi_plane_configured":    health.DPIPlaneEnvConfigured(),
		},
		"health_snapshot": map[string]any{
			"pipeline_healthy": pipelineOK,
			"ai_configured":    health.AIPlaneEnvConfigured(),
			"ai_ready":         st != nil && st.AIReady,
			"sine_configured":  health.SINEPlaneEnvConfigured(),
			"sine_ready":       st != nil && st.SINEReady,
			"dpi_configured":   health.DPIPlaneEnvConfigured(),
			"dpi_ready":        st != nil && st.DPIReady,
		},
	})
}

// handleAssetsCoverage returns read-only discovery/coverage aggregates (telemetry + sessions).
func (s *Server) handleAssetsCoverage(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{
		"agents_registered":     int64(0),
		"agents_active_24h":     int64(0),
		"telemetry_sources_24h": []map[string]any{},
		"distinct_emitters_24h": int64(0),
		"authoritative":         false,
		"source":                "read_only_aggregate",
		"ui_lineage": map[string]any{
			"presentation_only": true,
			"prd_23_basis": []string{
				"agent_sessions",
				"telemetry_events_last_24h",
			},
			"no_parallel_cmdb":              true,
			"not_committed_signal_join":     "coverage_api_does_not_read_partition_records_directly",
			"not_query_record_v1":             true,
			"not_report_record_v1":            true,
			"window":                          "24h_rolling_sql",
		},
	}
	if s.pool == nil {
		writeJSON(w, http.StatusOK, out)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), dbQueryTimeout)
	defer cancel()

	var registered int64
	if err := s.pool.QueryRow(ctx, `SELECT COUNT(*)::bigint FROM agent_sessions`).Scan(&registered); err == nil {
		out["agents_registered"] = registered
	}

	var active int64
	if err := s.pool.QueryRow(ctx, `
SELECT COUNT(*)::bigint FROM agent_sessions
WHERE last_heartbeat >= NOW() - INTERVAL '24 hours'`).Scan(&active); err == nil {
		out["agents_active_24h"] = active
	}

	var distinct int64
	if err := s.pool.QueryRow(ctx, `
SELECT COUNT(DISTINCT agent_id)::bigint FROM telemetry_events
WHERE timestamp >= NOW() - INTERVAL '24 hours'`).Scan(&distinct); err == nil {
		out["distinct_emitters_24h"] = distinct
	}

	rows, err := s.pool.Query(ctx, `
SELECT source, COUNT(*)::bigint AS n
FROM telemetry_events
WHERE timestamp >= NOW() - INTERVAL '24 hours'
GROUP BY source
ORDER BY n DESC`)
	if err == nil {
		defer rows.Close()
		srcs := make([]map[string]any, 0)
		for rows.Next() {
			var src string
			var n int64
			if scanErr := rows.Scan(&src, &n); scanErr != nil {
				continue
			}
			srcs = append(srcs, map[string]any{"source": src, "events": n})
		}
		out["telemetry_sources_24h"] = srcs
	}

	writeJSON(w, http.StatusOK, out)
}
