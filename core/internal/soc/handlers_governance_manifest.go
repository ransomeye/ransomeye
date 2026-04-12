package soc

import "net/http"

// handleSocGovernanceManifest exposes static PRD-21/22/23/25 interaction boundaries for the SOC UI.
// This endpoint is read-only metadata: it does not define execution rules and carries no authority.
func (s *Server) handleSocGovernanceManifest(w http.ResponseWriter, r *http.Request) {
	_ = s
	_ = r
	writeJSON(w, http.StatusOK, map[string]any{
		"manifest_version": "mishka_slice4_v1",
		"prd_21_ui_governance": map[string]any{
			"role":              "intent_capture_and_presentation_only",
			"does_not_define":   []string{"enforcement_rules", "policy_engine", "safety_gates", "prd13_commit_authority"},
			"write_surfaces":    []string{"POST /api/v1/incidents", "PATCH /api/v1/incidents/{id}"},
			"write_semantics":   "case_workflow_intents_only_no_execution_bypass",
			"non_write_surfaces": "all_other_listed_routes_are_get_read_only",
		},
		"prd_22_shadow_intelligence": map[string]any{
			"authoritative":                false,
			"segregation":                  "dedicated_route_and_ui_panel_advisory_styling",
			"cannot_trigger_enforcement": true,
			"cannot_mutate_prd13":          true,
			"route":                        "GET /api/v1/shadow/intelligence/status",
		},
		"prd_23_asset_intelligence": map[string]any{
			"no_parallel_cmdb":          true,
			"coverage_basis":            "sql_aggregates_over_telemetry_events_and_agent_sessions",
			"not_sole_signal_authority": "committed_SIGNAL_lives_in_partition_records_not_joined_in_coverage_api",
			"route":                     "GET /api/v1/assets/coverage",
		},
		"prd_25_dashboard_reporting": map[string]any{
			"presentation_law_only":    true,
			"executive_subordinate_to": "same_read_aggregates_as_operator_views",
			"query_report_lineage": map[string]any{
				"soc_db_projection_table":    "mishka_soc_report_lineage",
				"read_route":                 "GET /api/v1/reporting/lineage",
				"initial_write_surface":      "successful GET /api/v1/forensics/export/{evidence_id} inserts one row (scope=forensics_export)",
				"partition_records_types":    "QUERY QUERY_RESULT REPORT REPORT_DELIVERY exist in schema; SOC does not commit those rows",
				"authority_boundary":         "partition_records+batch_commit_records remain PRD-13 execution truth; lineage table is audit-friendly projection",
			},
			"cache_rebuild": "dashboard_metrics_are_ephemeral_client_views",
		},
		"prd_15_replay": map[string]any{
			"ui_state_non_authoritative": true,
			"deterministic_api_contracts": []string{
				"sorted_loo_features",
				"stable_json_keys_on_manifest",
			},
		},
		"prd_12_enforcement": map[string]any{
			"grpc_stream":              "RansomEyeService/ReceiveActions (mTLS; agent_id from client cert URI SAN urn:ransomeye:agent:<uuid>)",
			"registered_streams_route": "GET /api/v1/enforcement/registered-agents",
			"operator_loopback_tether": "go run ./core/cmd/mishka-enforcement-tether (holds stream open for dispatch smoke; not a production agent)",
		},
	})
}
