package gateway

import (
	"bytes"
	"testing"

	pb "ransomeye/proto/ransomeyepb"
)

func TestNetflowDeterminism(t *testing.T) {
	probeID := "5dc099d6-56d4-4e4e-9f59-d0ebf5741d8a"
	batchA := &pb.FlowBatch{
		ProbeId:        probeID,
		LogicalClock:   12,
		WallClockEpoch: 1_700_000_000,
		Flows: []*pb.Flow{
			{
				SrcIp:            "10.0.0.2",
				DstIp:            "10.0.0.1",
				SrcPort:          53,
				DstPort:          4444,
				Protocol:         "udp",
				BytesSent:        512,
				BytesRecv:        0,
				AppProto:         "dns",
				ExfilConfidence:  0.0,
				BeaconConfidence: 0.4,
				ThreatMetadata:   "netflow:v5",
			},
			{
				SrcIp:            "10.0.0.1",
				DstIp:            "10.0.0.2",
				SrcPort:          4444,
				DstPort:          53,
				Protocol:         "udp",
				BytesSent:        4096,
				BytesRecv:        0,
				AppProto:         "dns",
				ExfilConfidence:  0.0,
				BeaconConfidence: 0.4,
				ThreatMetadata:   "netflow:v5",
			},
		},
	}
	batchB := &pb.FlowBatch{
		ProbeId:        probeID,
		LogicalClock:   12,
		WallClockEpoch: 1_700_000_000,
		Flows: []*pb.Flow{
			batchA.Flows[1],
			batchA.Flows[0],
		},
	}

	eventsA, err := verifiedTelemetryFromFlowBatch(probeID, batchA)
	if err != nil {
		t.Fatalf("verifiedTelemetryFromFlowBatch batchA: %v", err)
	}
	eventsB, err := verifiedTelemetryFromFlowBatch(probeID, batchB)
	if err != nil {
		t.Fatalf("verifiedTelemetryFromFlowBatch batchB: %v", err)
	}
	if len(eventsA) != len(eventsB) {
		t.Fatalf("event count mismatch: %d vs %d", len(eventsA), len(eventsB))
	}

	for idx := range eventsA {
		if !bytes.Equal(eventsA[idx].Payload, eventsB[idx].Payload) {
			t.Fatalf("payload %d mismatch across deterministic batches", idx)
		}
		if !bytes.Equal(eventsA[idx].AgentSignature, eventsB[idx].AgentSignature) {
			t.Fatalf("signature %d mismatch across deterministic batches", idx)
		}
		if eventsA[idx].LogicalClock != eventsB[idx].LogicalClock {
			t.Fatalf("logical clock %d mismatch: %d vs %d", idx, eventsA[idx].LogicalClock, eventsB[idx].LogicalClock)
		}
	}
}
