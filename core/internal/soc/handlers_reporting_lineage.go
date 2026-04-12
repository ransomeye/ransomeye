package soc

import (
	"context"
	"net/http"
	"time"
)

// handleReportingLineage lists recent rows from mishka_soc_report_lineage (PRD-25 projection).
func (s *Server) handleReportingLineage(w http.ResponseWriter, r *http.Request) {
	if s.pool == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "db pool not available"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), dbQueryTimeout)
	defer cancel()

	rows, err := s.pool.Query(ctx, `
SELECT id::text, scope, query_spec::text, result_ref, authority_note, created_at
FROM mishka_soc_report_lineage
ORDER BY created_at DESC
LIMIT 100
`)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"error": err.Error(),
			"ui_lineage": "If relation missing, apply migration 048_mishka_soc_report_lineage.sql " +
				"(make migrate-core or scripts/slice1_apply_migrations_psql.sh after authority-db prepare).",
		})
		return
	}
	defer rows.Close()

	type row struct {
		ID            string    `json:"id"`
		Scope         string    `json:"scope"`
		QuerySpecJSON string    `json:"query_spec_json"`
		ResultRef     string    `json:"result_ref"`
		AuthorityNote string    `json:"authority_note"`
		CreatedAt     time.Time `json:"created_at"`
	}
	out := make([]row, 0, 32)
	for rows.Next() {
		var rec row
		if scanErr := rows.Scan(&rec.ID, &rec.Scope, &rec.QuerySpecJSON, &rec.ResultRef, &rec.AuthorityNote, &rec.CreatedAt); scanErr != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": scanErr.Error()})
			return
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"records": out,
		"ui_lineage": "Rows are SOC DB projections from export/report paths (e.g. forensics bundle). " +
			"Committed partition authority for QUERY/REPORT record types uses partition_records + batch_commit_records; " +
			"that writer is not the same code path as dashboard SQL aggregates.",
	})
}
