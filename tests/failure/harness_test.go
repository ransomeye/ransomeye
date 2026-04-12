package failure_test

import (
	"context"
	"strings"
	"testing"

	corefail "ransomeye/core/failure"
)

func TestFailureHarnessSmoke(t *testing.T) {
	report, err := corefail.RunFailureValidation(context.Background(), corefail.DefaultConfig())
	if err != nil && strings.Contains(err.Error(), "database") {
		t.Skipf("failure harness requires local postgres/tls fixtures: %v", err)
	}
	if err != nil {
		t.Fatalf("RunFailureValidation: %v", err)
	}
	if !report.Passed {
		t.Fatalf("expected passing report, got failures=%v", report.Failures)
	}
	if len(report.Results) != 5 {
		t.Fatalf("scenario count = %d, want 5", len(report.Results))
	}
	for _, result := range report.Results {
		if !result.Passed {
			t.Fatalf("scenario %s failed: %+v", result.Scenario, result)
		}
	}
}
