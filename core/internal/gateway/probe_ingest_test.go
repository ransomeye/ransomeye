package gateway

import (
	"testing"

	"ransomeye/core/internal/ingest"
)

func TestAdvanceProbeClockAllowsIdempotentRetry(t *testing.T) {
	h := NewHandlers(nil, nil, nil)
	var requestHash [32]byte
	requestHash[0] = 0x42

	if err := h.advanceProbeClock("5dc099d6-56d4-4e4e-9f59-d0ebf5741d8a", 12, requestHash); err != nil {
		t.Fatalf("first advanceProbeClock: %v", err)
	}
	if err := h.advanceProbeClock("5dc099d6-56d4-4e4e-9f59-d0ebf5741d8a", 12, requestHash); err != nil {
		t.Fatalf("retry advanceProbeClock: %v", err)
	}
}

func TestAdvanceProbeClockRejectsChangedPayloadOnSameClock(t *testing.T) {
	h := NewHandlers(nil, nil, nil)
	var requestHashA [32]byte
	var requestHashB [32]byte
	requestHashA[0] = 0x11
	requestHashB[0] = 0x22

	if err := h.advanceProbeClock("5dc099d6-56d4-4e4e-9f59-d0ebf5741d8a", 12, requestHashA); err != nil {
		t.Fatalf("first advanceProbeClock: %v", err)
	}
	if err := h.advanceProbeClock("5dc099d6-56d4-4e4e-9f59-d0ebf5741d8a", 12, requestHashB); err == nil {
		t.Fatal("advanceProbeClock accepted changed payload on same logical clock")
	}
}

func TestProbeMessageIDDeterministic(t *testing.T) {
	event := &ingest.VerifiedTelemetry{
		Payload:       []byte("probe-payload"),
		LogicalClock:  33,
		SourceType:    "syslog",
		AgentIDStr:    "5dc099d6-56d4-4e4e-9f59-d0ebf5741d8a",
		TimestampUnix: 1_700_000_000,
	}

	idA, hashA, err := probeMessageID("5dc099d6-56d4-4e4e-9f59-d0ebf5741d8a", "syslog", event)
	if err != nil {
		t.Fatalf("probeMessageID first: %v", err)
	}
	idB, hashB, err := probeMessageID("5dc099d6-56d4-4e4e-9f59-d0ebf5741d8a", "syslog", event)
	if err != nil {
		t.Fatalf("probeMessageID second: %v", err)
	}
	if idA != idB {
		t.Fatalf("message id mismatch: %s vs %s", idA, idB)
	}
	if hashA != hashB {
		t.Fatal("payload hash mismatch across deterministic calls")
	}
}
