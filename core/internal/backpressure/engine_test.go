package backpressure

import (
	"testing"
	"time"
)

func TestEvaluateWithThresholdsRejectsPressureDeterministically(t *testing.T) {
	assessment := evaluateWithThresholds(Metrics{
		QueueDepth:    10,
		QueueCapacity: 64,
	}, Thresholds{
		MemoryThreshold:    10,
		DiskThresholdBytes: 1024,
		WALLatency:         500 * time.Millisecond,
	})
	if assessment.State != StatePressure {
		t.Fatalf("state=%v want=%v", assessment.State, StatePressure)
	}

	assessment = evaluateWithThresholds(Metrics{
		QueueDepth:    1,
		QueueCapacity: 64,
		PendingBytes:  2048,
	}, Thresholds{
		MemoryThreshold:    10,
		DiskThresholdBytes: 2048,
		WALLatency:         500 * time.Millisecond,
	})
	if assessment.State != StatePressure {
		t.Fatalf("state=%v want=%v", assessment.State, StatePressure)
	}

	assessment = evaluateWithThresholds(Metrics{
		QueueDepth:    1,
		QueueCapacity: 64,
		WALLatency:    750 * time.Millisecond,
	}, Thresholds{
		MemoryThreshold:    10,
		DiskThresholdBytes: 2048,
		WALLatency:         750 * time.Millisecond,
	})
	if assessment.State != StatePressure {
		t.Fatalf("state=%v want=%v", assessment.State, StatePressure)
	}
}

func TestEvaluateWithThresholdsRejectsFailsafeDeterministically(t *testing.T) {
	assessment := evaluateWithThresholds(Metrics{
		QueueUnavailable: true,
	}, Thresholds{
		MemoryThreshold:    1,
		DiskThresholdBytes: 1,
		WALLatency:         time.Millisecond,
	})
	if assessment.State != StateFailsafe {
		t.Fatalf("state=%v want=%v", assessment.State, StateFailsafe)
	}

	assessment = evaluateWithThresholds(Metrics{
		DiskExhausted: true,
	}, Thresholds{
		MemoryThreshold:    1,
		DiskThresholdBytes: 1,
		WALLatency:         time.Millisecond,
	})
	if assessment.State != StateFailsafe {
		t.Fatalf("state=%v want=%v", assessment.State, StateFailsafe)
	}
}

func TestUpdatePreservesMetricsUnderPressure(t *testing.T) {
	SetTestThresholds(Thresholds{
		MemoryThreshold:    128,
		DiskThresholdBytes: 1024 * 1024,
		WALLatency:         100 * time.Millisecond,
	})
	defer ClearTestThresholds()

	engine := NewEngine()

	engine.IncrementPressure("test")

	metrics := Metrics{
		QueueDepth:    10,
		QueueCapacity: 100,
		PendingBytes:  1234,
	}

	a := engine.Update(metrics)

	if a.Metrics.QueueDepth != metrics.QueueDepth {
		t.Fatalf("metrics lost under pressure")
	}

	if a.State != StatePressure {
		t.Fatalf("expected PRESSURE")
	}
}

func TestFailsafeNotOverriddenByPressure(t *testing.T) {
	SetTestThresholds(Thresholds{
		MemoryThreshold:    128,
		DiskThresholdBytes: 1024 * 1024,
		WALLatency:         100 * time.Millisecond,
	})
	defer ClearTestThresholds()

	engine := NewEngine()

	engine.IncrementPressure("test")

	metrics := Metrics{
		QueueUnavailable: true, // forces FAILSAFE
	}

	a := engine.Update(metrics)

	if a.State != StateFailsafe {
		t.Fatalf("FAILSAFE must not be overridden, got %v", a.State)
	}
}

func TestFailsafePreservesSignalReason(t *testing.T) {
	SetTestThresholds(Thresholds{
		MemoryThreshold:    128,
		DiskThresholdBytes: 1024 * 1024,
		WALLatency:         100 * time.Millisecond,
	})
	defer ClearTestThresholds()

	engine := NewEngine()

	engine.IncrementPressure("hub backpressure")

	metrics := Metrics{
		QueueUnavailable: true,
	}

	a := engine.Update(metrics)

	if a.State != StateFailsafe {
		t.Fatalf("expected FAILSAFE")
	}

	expected := "hub backpressure | queue unavailable"
	if a.Reason != expected {
		t.Fatalf("unexpected reason: %s, expected: %s", a.Reason, expected)
	}
}

func TestReasonDeduplication(t *testing.T) {
	SetTestThresholds(Thresholds{
		MemoryThreshold:    128,
		DiskThresholdBytes: 1024 * 1024,
		WALLatency:         100 * time.Millisecond,
	})
	defer ClearTestThresholds()

	engine := NewEngine()

	// use reason that Evaluate(metrics) will return for QueueUnavailable
	reason := "queue unavailable"
	engine.IncrementPressure(reason)

	metrics := Metrics{
		QueueUnavailable: true,
	}

	// result calls Evaluate(metrics) which returns "queue unavailable"
	// and merges it with engine.signal.Reason ("queue unavailable")
	result := engine.Update(metrics)

	if result.State != StateFailsafe {
		t.Fatalf("expected FAILSAFE")
	}

	if result.Reason != reason {
		t.Fatalf("expected single deduplicated reason, got: %s", result.Reason)
	}
}

func TestReasonCanonicalOrdering(t *testing.T) {
	SetTestThresholds(Thresholds{
		MemoryThreshold:    128,
		DiskThresholdBytes: 1024 * 1024,
		WALLatency:         100 * time.Millisecond,
	})
	defer ClearTestThresholds()

	engine := NewEngine()

	engine.IncrementPressure("z_reason")

	metrics := Metrics{
		QueueUnavailable: true, // "queue unavailable"
	}

	result := engine.Update(metrics)

	expected := "queue unavailable | z_reason"

	if result.Reason != expected {
		t.Fatalf("expected ordered reasons, got: %s", result.Reason)
	}
}

func TestReasonNormalization(t *testing.T) {
	SetTestThresholds(Thresholds{
		MemoryThreshold:    128,
		DiskThresholdBytes: 1024 * 1024,
		WALLatency:         100 * time.Millisecond,
	})
	defer ClearTestThresholds()

	engine := NewEngine()

	engine.IncrementPressure("  reason  ")

	metrics := Metrics{
		QueueUnavailable: true,
	}

	result := engine.Update(metrics)

	expected := "queue unavailable | reason"

	if result.Reason != expected {
		t.Fatalf("unexpected normalized reason: %q, expected: %q", result.Reason, expected)
	}
}
