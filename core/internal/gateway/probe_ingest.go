package gateway

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"sort"
	"strings"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"ransomeye/core/internal/ack"
	"ransomeye/core/internal/identity"
	"ransomeye/core/internal/ingest"
	pb "ransomeye/proto/ransomeyepb"
)

const (
	maxProbeFlowBatchSize   = 100
	probeLogicalClockStride = uint64(1024)
	probeReplayBootSession  = "probe-ingest-v1"
)

var (
	probeFlowNamespace    = uuid.MustParse("ab3740d4-59eb-4510-95ff-2de15428d498")
	probeFindingNamespace = uuid.MustParse("ebdd4f55-4f46-4dd6-9e7f-c1331866d2ad")
	probeMessageNamespace = uuid.MustParse("b332f9e0-6ce3-494e-a8d7-ee2e315de398")
)

type normalizedFlow struct {
	SrcIP            string
	DstIP            string
	SrcPort          int32
	DstPort          int32
	Protocol         string
	BytesSent        int64
	BytesRecv        int64
	AppProto         string
	JA3Hash          string
	ExfilConfidence  uint32
	BeaconConfidence uint32
	ThreatMetadata   string
	Timestamp        int64
}

type findingTimestampEnvelope struct {
	Timestamp int64 `json:"timestamp"`
}

func (h *Handlers) SendFlowStream(ctx context.Context, req *pb.FlowBatch) (*pb.FlowAck, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "nil request")
	}
	if h.scheduler == nil && h.ingestQueue == nil && h.schedulerEnqueuer == nil {
		return nil, status.Error(codes.FailedPrecondition, "scheduler not initialized")
	}

	probeID, err := identity.ExtractAgentID(ctx)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.GetProbeId()) == "" || req.GetProbeId() != probeID {
		return nil, status.Error(codes.PermissionDenied, "probe_id mismatch")
	}
	if req.GetLogicalClock() < 0 || req.GetWallClockEpoch() < 0 {
		return nil, status.Error(codes.InvalidArgument, "logical_clock and wall_clock_epoch must be non-negative")
	}

	events, err := verifiedTelemetryFromFlowBatch(probeID, req)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	requestHash := hashProbeEvents(events)
	if err := h.advanceProbeClock(probeID, uint64(req.GetLogicalClock()), requestHash); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	for _, event := range events {
		if err := h.submitProbeEvent(ctx, probeID, "netflow", event); err != nil {
			return nil, err
		}
	}
	return &pb.FlowAck{}, nil
}

func (h *Handlers) RegisterProbe(ctx context.Context, req *pb.ProbeRegistration) (*pb.ProbeRegistrationAck, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "nil request")
	}
	probeID, err := identity.ExtractAgentID(ctx)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.GetProbeId()) == "" || req.GetProbeId() != probeID {
		return nil, status.Error(codes.PermissionDenied, "probe_id mismatch")
	}
	return &pb.ProbeRegistrationAck{}, nil
}

func (h *Handlers) ProbeHeartbeat(ctx context.Context, _ *pb.ProbeHeartbeatRequest) (*pb.ProbeHeartbeatAck, error) {
	if _, err := identity.ExtractAgentID(ctx); err != nil {
		return nil, err
	}
	return &pb.ProbeHeartbeatAck{}, nil
}

func (h *Handlers) PullConfig(ctx context.Context, _ *pb.PullConfigRequest) (*pb.ProbeConfig, error) {
	if _, err := identity.ExtractAgentID(ctx); err != nil {
		return nil, err
	}
	return &pb.ProbeConfig{}, nil
}

func (h *Handlers) ReportFinding(ctx context.Context, req *pb.NetworkInfraFinding) (*pb.FindingAck, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "nil request")
	}
	if h.scheduler == nil && h.ingestQueue == nil && h.schedulerEnqueuer == nil {
		return nil, status.Error(codes.FailedPrecondition, "scheduler not initialized")
	}

	probeID, err := identity.ExtractAgentID(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetLogicalClock() < 0 {
		return nil, status.Error(codes.InvalidArgument, "logical_clock must be non-negative")
	}

	event, err := verifiedTelemetryFromFinding(probeID, req)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	requestHash := hashProbeEvents([]*ingest.VerifiedTelemetry{event})
	if err := h.advanceProbeClock(probeID, uint64(req.GetLogicalClock()), requestHash); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if err := h.submitProbeEvent(ctx, probeID, "syslog", event); err != nil {
		return nil, err
	}
	return &pb.FindingAck{}, nil
}

func (h *Handlers) advanceProbeClock(agentID string, logicalClock uint64, requestHash [32]byte) error {
	h.telemetryClockMu.Lock()
	defer h.telemetryClockMu.Unlock()

	key := "probe:" + agentID
	prev, seen := h.telemetryLast[key]
	if seen {
		switch {
		case logicalClock < prev:
			return errors.New("REPLAY_DETECTED")
		case logicalClock == prev:
			if priorHash, ok := h.probeLastHash[key]; ok && priorHash == requestHash {
				return nil
			}
			return errors.New("logical_clock reused with different payload")
		}
	}
	h.telemetryLast[key] = logicalClock
	h.probeLastHash[key] = requestHash
	return nil
}

func hashProbeEvents(events []*ingest.VerifiedTelemetry) [32]byte {
	hasher := sha256.New()
	for _, event := range events {
		if event == nil {
			continue
		}
		payloadHash := sha256.Sum256(event.Payload)
		hasher.Write(payloadHash[:])
	}
	var out [32]byte
	copy(out[:], hasher.Sum(nil))
	return out
}

func probeMessageID(probeID, streamKind string, event *ingest.VerifiedTelemetry) (string, [32]byte, error) {
	if event == nil {
		return "", [32]byte{}, errors.New("nil probe event")
	}
	if strings.TrimSpace(probeID) == "" {
		return "", [32]byte{}, errors.New("probe_id missing")
	}
	payloadHash := sha256.Sum256(event.Payload)
	material := make([]byte, 0, len(probeID)+len(streamKind)+len(payloadHash)+32)
	material = append(material, strings.TrimSpace(streamKind)...)
	material = append(material, 0)
	material = append(material, strings.TrimSpace(probeID)...)
	material = append(material, 0)
	material = append(material, payloadHash[:]...)
	material = append(material, 0)
	material = append(material, fmt.Sprintf("%d", event.LogicalClock)...)
	return uuid.NewSHA1(probeMessageNamespace, material).String(), payloadHash, nil
}

func (h *Handlers) submitProbeEvent(ctx context.Context, probeID, streamKind string, event *ingest.VerifiedTelemetry) error {
	if h == nil {
		return status.Error(codes.FailedPrecondition, "handler not initialized")
	}

	messageID, payloadHash, err := probeMessageID(probeID, streamKind, event)
	if err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	replayKey, err := h.replayKey(h.systemIdentityHash, probeID, probeReplayBootSession, messageID)
	if err != nil {
		return status.Error(codes.FailedPrecondition, err.Error())
	}
	// ReplayPrecheck: Mishka-authoritative when h.dbPool != nil and PRD-13 partition id > 0; otherwise non-authoritative replaySeen only.
	if replayAck, err := h.ReplayPrecheck(ctx, h.systemIdentityHash, probeID, probeReplayBootSession, messageID, payloadHash); err != nil {
		return status.Error(codes.PermissionDenied, "REJECT: "+err.Error())
	} else if replayAck != nil {
		return nil
	}

	meta := ack.Metadata{
		ReplayKey:     replayKey,
		MessageID:     messageID,
		ContentSHA256: payloadHash,
	}
	waitOnly, err := h.beginReplay(meta)
	if err != nil {
		return status.Error(codes.PermissionDenied, "REJECT: "+err.Error())
	}
	if waitOnly {
		if waitErr := h.waitForCommit(meta); waitErr != nil {
			return status.Error(codes.Aborted, "REJECT: "+waitErr.Error())
		}
		return nil
	}
	if assessment := h.queueAdmissionAssessment(0); !assessment.AdmissionAllowed() {
		return h.rejectAdmission(meta, assessment.AdmissionError())
	}
	if _, err := h.ForwardToQueue(event, meta); err != nil {
		return h.rejectAdmission(meta, err)
	}
	if waitErr := h.waitForCommit(meta); waitErr != nil {
		return status.Error(codes.Aborted, "REJECT: "+waitErr.Error())
	}
	return nil
}

func verifiedTelemetryFromFlowBatch(probeID string, batch *pb.FlowBatch) ([]*ingest.VerifiedTelemetry, error) {
	if strings.TrimSpace(probeID) == "" {
		return nil, errors.New("probe_id missing")
	}
	if batch == nil {
		return nil, errors.New("nil flow batch")
	}
	if len(batch.GetFlows()) == 0 {
		return nil, nil
	}
	if len(batch.GetFlows()) > maxProbeFlowBatchSize {
		return nil, fmt.Errorf("flow batch exceeds max size %d", maxProbeFlowBatchSize)
	}

	agentUUID, err := uuid.Parse(probeID)
	if err != nil {
		return nil, fmt.Errorf("parse probe_id uuid: %w", err)
	}
	if uint64(batch.GetLogicalClock()) > math.MaxUint64/probeLogicalClockStride {
		return nil, errors.New("logical_clock overflow")
	}

	normalized, err := normalizeFlowBatch(batch)
	if err != nil {
		return nil, err
	}

	events := make([]*ingest.VerifiedTelemetry, 0, len(normalized))
	for idx, flow := range normalized {
		logicalClock := uint64(batch.GetLogicalClock())*probeLogicalClockStride + uint64(idx+1)
		timestampNano := uint64(flow.Timestamp) * uint64(1_000_000_000)
		eventID := uuid.NewSHA1(probeFlowNamespace, []byte(flow.canonicalString(logicalClock)))
		processHash := sha256.Sum256([]byte("probe-flow|" + flow.canonicalString(logicalClock)))
		fileHash := sha256.Sum256([]byte("probe-id|" + probeID))
		networkTuple := probeTupleHash(flow.networkKey())
		payload, err := ingest.BuildCanonicalV1(
			logicalClock,
			agentUUID,
			eventID,
			ingest.EventTypeCodeNetwork,
			0,
			processHash,
			fileHash,
			networkTuple,
			timestampNano,
			[16]byte{},
		)
		if err != nil {
			return nil, err
		}
		signature := sha512.Sum512([]byte("probe-flow-signature|" + flow.canonicalString(logicalClock)))
		events = append(events, &ingest.VerifiedTelemetry{
			Payload:        append([]byte(nil), payload[:]...),
			AgentSignature: append([]byte(nil), signature[:]...),
			AgentIDStr:     probeID,
			EventType:      "NETWORK_EVENT",
			SourceType:     "netflow",
			TimestampUnix:  float64(flow.Timestamp),
			LogicalClock:   int64(logicalClock),
			DroppedCount:   0,
		})
	}
	return events, nil
}

func verifiedTelemetryFromFinding(probeID string, finding *pb.NetworkInfraFinding) (*ingest.VerifiedTelemetry, error) {
	if strings.TrimSpace(probeID) == "" {
		return nil, errors.New("probe_id missing")
	}
	if finding == nil {
		return nil, errors.New("nil finding")
	}

	agentUUID, err := uuid.Parse(probeID)
	if err != nil {
		return nil, fmt.Errorf("parse probe_id uuid: %w", err)
	}
	sourceIP, err := canonicalIP(finding.GetSourceIp())
	if err != nil {
		return nil, err
	}
	score := confidencePPM(finding.GetScore())
	timestamp := extractFindingTimestamp(finding.GetDetailJson(), finding.GetLogicalClock())
	if timestamp < 0 {
		return nil, errors.New("finding timestamp must be non-negative")
	}
	logicalClock := uint64(finding.GetLogicalClock())*probeLogicalClockStride + 1
	canonical := fmt.Sprintf(
		"%s|%d|%s|%d|%s",
		strings.TrimSpace(finding.GetFindingType()),
		score,
		sourceIP,
		timestamp,
		strings.TrimSpace(finding.GetDetailJson()),
	)
	eventID := uuid.NewSHA1(probeFindingNamespace, []byte(canonical))
	processHash := sha256.Sum256([]byte("probe-finding|" + canonical))
	fileHash := sha256.Sum256([]byte("probe-id|" + probeID))
	networkTuple := probeTupleHash(fmt.Sprintf("%s|%d|%s", sourceIP, score, strings.TrimSpace(finding.GetFindingType())))
	payload, err := ingest.BuildCanonicalV1(
		logicalClock,
		agentUUID,
		eventID,
		ingest.EventTypeCodeNetwork,
		0,
		processHash,
		fileHash,
		networkTuple,
		uint64(timestamp)*uint64(1_000_000_000),
		[16]byte{},
	)
	if err != nil {
		return nil, err
	}
	signature := sha512.Sum512([]byte("probe-finding-signature|" + canonical))
	return &ingest.VerifiedTelemetry{
		Payload:        append([]byte(nil), payload[:]...),
		AgentSignature: append([]byte(nil), signature[:]...),
		AgentIDStr:     probeID,
		EventType:      "NETWORK_EVENT",
		SourceType:     "syslog",
		TimestampUnix:  float64(timestamp),
		LogicalClock:   int64(logicalClock),
		DroppedCount:   0,
	}, nil
}

func normalizeFlowBatch(batch *pb.FlowBatch) ([]normalizedFlow, error) {
	if batch == nil {
		return nil, errors.New("nil flow batch")
	}
	if batch.GetWallClockEpoch() < 0 {
		return nil, errors.New("wall_clock_epoch must be non-negative")
	}
	out := make([]normalizedFlow, 0, len(batch.GetFlows()))
	for _, flow := range batch.GetFlows() {
		if flow == nil {
			return nil, errors.New("nil flow record")
		}
		srcIP, err := canonicalIP(flow.GetSrcIp())
		if err != nil {
			return nil, err
		}
		dstIP, err := canonicalIP(flow.GetDstIp())
		if err != nil {
			return nil, err
		}
		if err := validatePort(flow.GetSrcPort()); err != nil {
			return nil, err
		}
		if err := validatePort(flow.GetDstPort()); err != nil {
			return nil, err
		}
		out = append(out, normalizedFlow{
			SrcIP:            srcIP,
			DstIP:            dstIP,
			SrcPort:          flow.GetSrcPort(),
			DstPort:          flow.GetDstPort(),
			Protocol:         strings.TrimSpace(flow.GetProtocol()),
			BytesSent:        flow.GetBytesSent(),
			BytesRecv:        flow.GetBytesRecv(),
			AppProto:         strings.TrimSpace(flow.GetAppProto()),
			JA3Hash:          strings.TrimSpace(flow.GetJa3Hash()),
			ExfilConfidence:  confidencePPM(flow.GetExfilConfidence()),
			BeaconConfidence: confidencePPM(flow.GetBeaconConfidence()),
			ThreatMetadata:   strings.TrimSpace(flow.GetThreatMetadata()),
			Timestamp:        batch.GetWallClockEpoch(),
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].SrcIP != out[j].SrcIP {
			return out[i].SrcIP < out[j].SrcIP
		}
		if out[i].DstIP != out[j].DstIP {
			return out[i].DstIP < out[j].DstIP
		}
		if out[i].SrcPort != out[j].SrcPort {
			return out[i].SrcPort < out[j].SrcPort
		}
		if out[i].DstPort != out[j].DstPort {
			return out[i].DstPort < out[j].DstPort
		}
		if out[i].Protocol != out[j].Protocol {
			return out[i].Protocol < out[j].Protocol
		}
		if out[i].BytesSent != out[j].BytesSent {
			return out[i].BytesSent < out[j].BytesSent
		}
		if out[i].BytesRecv != out[j].BytesRecv {
			return out[i].BytesRecv < out[j].BytesRecv
		}
		if out[i].AppProto != out[j].AppProto {
			return out[i].AppProto < out[j].AppProto
		}
		if out[i].JA3Hash != out[j].JA3Hash {
			return out[i].JA3Hash < out[j].JA3Hash
		}
		if out[i].ExfilConfidence != out[j].ExfilConfidence {
			return out[i].ExfilConfidence < out[j].ExfilConfidence
		}
		if out[i].BeaconConfidence != out[j].BeaconConfidence {
			return out[i].BeaconConfidence < out[j].BeaconConfidence
		}
		return out[i].ThreatMetadata < out[j].ThreatMetadata
	})
	return out, nil
}

func (f normalizedFlow) networkKey() string {
	return fmt.Sprintf("%s|%s|%d|%d|%s", f.SrcIP, f.DstIP, f.SrcPort, f.DstPort, f.Protocol)
}

func (f normalizedFlow) canonicalString(logicalClock uint64) string {
	return fmt.Sprintf(
		"%s|%s|%d|%d|%s|%d|%d|%s|%s|%d|%d|%s|%d|%d",
		f.SrcIP,
		f.DstIP,
		f.SrcPort,
		f.DstPort,
		f.Protocol,
		f.BytesSent,
		f.BytesRecv,
		f.AppProto,
		f.JA3Hash,
		f.ExfilConfidence,
		f.BeaconConfidence,
		f.ThreatMetadata,
		f.Timestamp,
		logicalClock,
	)
}

func probeTupleHash(value string) [16]byte {
	sum := sha256.Sum256([]byte(value))
	var out [16]byte
	copy(out[:], sum[:16])
	return out
}

func canonicalIP(raw string) (string, error) {
	ip := net.ParseIP(strings.TrimSpace(raw))
	if ip == nil {
		return "", fmt.Errorf("invalid IP %q", raw)
	}
	return ip.String(), nil
}

func validatePort(port int32) error {
	if port < 0 || port > 65535 {
		return fmt.Errorf("invalid port %d", port)
	}
	return nil
}

func confidencePPM(value float32) uint32 {
	if value <= 0 {
		return 0
	}
	if value >= 1 {
		return 1_000_000
	}
	return uint32(math.Round(float64(value) * 1_000_000))
}

func extractFindingTimestamp(detailJSON string, fallback int64) int64 {
	if strings.TrimSpace(detailJSON) == "" {
		return fallback
	}
	var envelope findingTimestampEnvelope
	if err := json.Unmarshal([]byte(detailJSON), &envelope); err != nil {
		return fallback
	}
	if envelope.Timestamp == 0 {
		return fallback
	}
	return envelope.Timestamp
}
