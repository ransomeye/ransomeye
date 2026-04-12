package soc

import (
	"testing"
)

// TestClampLimit_MaxQueryLimit verifies that clampLimit enforces MAX_QUERY_LIMIT
// as the absolute ceiling, regardless of per-endpoint maxVal (PRD-18 §3).
func TestClampLimit_MaxQueryLimit(t *testing.T) {
	tests := []struct {
		name       string
		raw        string
		defaultVal int
		maxVal     int
		want       int
	}{
		{"default when empty", "", 100, 500, 100},
		{"default when zero", "0", 100, 500, 100},
		{"default when negative", "-5", 100, 500, 100},
		{"normal value", "50", 100, 500, 50},
		{"at per-endpoint max", "500", 100, 500, 500},
		{"above per-endpoint max", "600", 100, 500, 500},
		{"at global MAX_QUERY_LIMIT", "1000", 100, 2000, 1000},
		{"above MAX_QUERY_LIMIT", "5000", 100, 2000, MAX_QUERY_LIMIT},
		{"way above MAX_QUERY_LIMIT", "999999", 100, 2000, MAX_QUERY_LIMIT},
		{"SQL injection attempt", "1; DROP TABLE--", 100, 500, 100},
		{"float ignored", "50.5", 100, 500, 100},
		{"whitespace only", "  ", 100, 500, 100},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := clampLimit(tt.raw, tt.defaultVal, tt.maxVal)
			if got != tt.want {
				t.Errorf("clampLimit(%q, %d, %d) = %d, want %d",
					tt.raw, tt.defaultVal, tt.maxVal, got, tt.want)
			}
		})
	}
}

// TestClampLimit_SQLInjection verifies that SQL injection payloads in the limit
// parameter are safely rejected (parsed as 0 by strconv.Atoi → default).
func TestClampLimit_SQLInjection(t *testing.T) {
	payloads := []string{
		"1; DROP TABLE telemetry_events;--",
		"1 OR 1=1",
		"0 UNION SELECT * FROM pg_shadow",
		"'; DELETE FROM incidents; --",
		"1/**/UNION/**/SELECT/**/1,2,3",
	}

	for _, p := range payloads {
		got := clampLimit(p, 100, 500)
		if got != 100 {
			t.Errorf("clampLimit(%q, 100, 500) = %d, want 100 (should fall to default)", p, got)
		}
	}
}

// TestMAX_QUERY_LIMIT_Value confirms the constant value matches the PRD-18 specification.
func TestMAX_QUERY_LIMIT_Value(t *testing.T) {
	if MAX_QUERY_LIMIT != 1000 {
		t.Fatalf("MAX_QUERY_LIMIT = %d, want 1000 (PRD-18 §3)", MAX_QUERY_LIMIT)
	}
}

// TestWSClientQueueSize validates that perClientQueueSize is bounded and > 0.
func TestWSClientQueueSize(t *testing.T) {
	if perClientQueueSize <= 0 {
		t.Fatal("perClientQueueSize must be > 0")
	}
	if perClientQueueSize > 4096 {
		t.Fatalf("perClientQueueSize = %d, exceeds resource ceiling", perClientQueueSize)
	}
}
