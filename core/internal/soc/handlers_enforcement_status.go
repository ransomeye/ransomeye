package soc

import "net/http"

// handleEnforcementRegisteredAgents exposes which agent IDs have an active loopback
// ReceiveActions gRPC stream (runtime only; not EXECUTION_RESULT authority).
func (s *Server) handleEnforcementRegisteredAgents(w http.ResponseWriter, r *http.Request) {
	_ = r
	var ids []string
	if s.enforcement != nil {
		ids = s.enforcement.RegisteredEnforcementAgents()
	}
	if ids == nil {
		ids = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"registered_agent_ids": ids,
		"count":                len(ids),
		"ui_lineage": "PRD-12: enforcement dispatch requires a registered loopback agent stream. " +
			"Empty list means no connected executor on this core instance — Dispatch queues or drops per dispatcher rules. " +
			"Authoritative outcome rows remain EXECUTION_RESULT in partition_records when the pipeline commits them.",
	})
}
