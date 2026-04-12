package gateway

import (
	"fmt"
	"strings"
	"sync"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"ransomeye/core/internal/ack"
	"ransomeye/core/internal/backpressure"
	pb "ransomeye/proto/ransomeyepb"
)

func (h *Handlers) queueAdmissionAssessment(additionalDepth int) backpressure.Assessment {
	if h == nil {
		return backpressure.Evaluate(backpressure.Metrics{QueueUnavailable: true})
	}

	var metrics backpressure.Metrics
	switch {
	case h.ingestQueue != nil:
		metrics = h.ingestQueue.BackpressureMetrics()
	case h.scheduler != nil:
		metrics = h.scheduler.BackpressureMetrics()
	case h.schedulerEnqueuer != nil:
		return backpressure.Assessment{State: backpressure.StateNormal}
	default:
		metrics = backpressure.Metrics{QueueUnavailable: true}
	}

	metrics = metrics.WithAdditionalDepth(additionalDepth)
	if h.backpressure == nil {
		assessment := backpressure.Evaluate(metrics)
		h.publishBackpressureState(assessment)
		return assessment
	}
	assessment := h.backpressure.Update(metrics)
	h.publishBackpressureState(assessment)
	return assessment
}

func queueAdmissionError(err error) error {
	if err == nil {
		return nil
	}
	if backpressure.IsResourceExhausted(err) {
		return err
	}
	return backpressure.NewAdmissionError(backpressure.StateFailsafe, "queue admission unavailable")
}

func queueAdmissionStatus(err error) error {
	return status.Error(codes.ResourceExhausted, backpressure.MessageFromError(queueAdmissionError(err)))
}

func (h *Handlers) rejectAdmission(meta ack.Metadata, err error) error {
	admissionErr := queueAdmissionError(err)
	if h != nil && h.ackController != nil && meta.ReplayKey != "" {
		h.ackController.Fail(meta, admissionErr)
	}
	return queueAdmissionStatus(admissionErr)
}

type actionStreamWrapper struct {
	pb.RansomEyeService_ReceiveActionsServer
	sendMu sync.Mutex
}

func (s *actionStreamWrapper) Send(cmd *pb.ActionCommand) error {
	if s == nil || s.RansomEyeService_ReceiveActionsServer == nil {
		return status.Error(codes.FailedPrecondition, "action stream unavailable")
	}
	if cmd == nil {
		return status.Error(codes.InvalidArgument, "nil action command")
	}
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	return s.RansomEyeService_ReceiveActionsServer.Send(cmd)
}

func (h *Handlers) registerActionStream(agentID string, stream *actionStreamWrapper) {
	if h == nil || strings.TrimSpace(agentID) == "" || stream == nil {
		return
	}
	h.actionStreamMu.Lock()
	h.actionStreams[agentID] = stream
	h.actionStreamMu.Unlock()
}

func (h *Handlers) unregisterActionStream(agentID string) {
	if h == nil || strings.TrimSpace(agentID) == "" {
		return
	}
	h.actionStreamMu.Lock()
	delete(h.actionStreams, agentID)
	h.actionStreamMu.Unlock()
}

func (h *Handlers) publishBackpressureState(assessment backpressure.Assessment) {
	if h == nil {
		return
	}

	h.actionStreamMu.Lock()
	if h.lastBackpressureSet && h.lastBackpressure.State == assessment.State {
		h.lastBackpressure = assessment
		h.actionStreamMu.Unlock()
		return
	}
	h.lastBackpressure = assessment
	h.lastBackpressureSet = true

	streams := make(map[string]*actionStreamWrapper, len(h.actionStreams))
	for agentID, stream := range h.actionStreams {
		streams[agentID] = stream
	}
	h.actionStreamMu.Unlock()

	for agentID, stream := range streams {
		cmd := h.backpressureActionCommand(agentID, assessment)
		_ = stream.Send(cmd)
	}
}

func (h *Handlers) publishCurrentBackpressureState(agentID string) {
	if h == nil || strings.TrimSpace(agentID) == "" {
		return
	}

	h.actionStreamMu.Lock()
	stream := h.actionStreams[agentID]
	assessment := h.lastBackpressure
	known := h.lastBackpressureSet
	h.actionStreamMu.Unlock()
	if stream == nil {
		return
	}
	if !known {
		assessment = backpressure.Assessment{State: backpressure.StateNormal}
	}
	_ = stream.Send(h.backpressureActionCommand(agentID, assessment))
}

func (h *Handlers) backpressureActionCommand(agentID string, assessment backpressure.Assessment) *pb.ActionCommand {
	logicalClock := int64(0)
	if h != nil {
		logicalClock = h.bumpLamport(0)
	}
	return &pb.ActionCommand{
		ActionId:       fmt.Sprintf("backpressure:%s:%s:%d", agentID, assessment.State, logicalClock),
		DetectionId:    "backpressure",
		ActionType:     pb.ActionType_ALERT_ONLY,
		ParametersJson: backpressureControlJSON(assessment),
		LogicalClock:   logicalClock,
	}
}

func backpressureControlJSON(assessment backpressure.Assessment) string {
	reason := assessment.Reason
	reason = strings.ReplaceAll(reason, `\`, `\\`)
	reason = strings.ReplaceAll(reason, `"`, `\"`)
	signal := "NORMAL"
	if assessment.State != backpressure.StateNormal {
		signal = backpressure.SignalResourceExhausted
	}
	if reason == "" {
		return fmt.Sprintf(
			`{"control":"backpressure","signal":"%s","state":"%s","admission_allowed":%t}`,
			signal,
			assessment.State,
			assessment.AdmissionAllowed(),
		)
	}
	return fmt.Sprintf(
		`{"control":"backpressure","signal":"%s","state":"%s","reason":"%s","admission_allowed":%t}`,
		signal,
		assessment.State,
		reason,
		assessment.AdmissionAllowed(),
	)
}

func newActionStreamWrapper(stream pb.RansomEyeService_ReceiveActionsServer) *actionStreamWrapper {
	if stream == nil {
		return nil
	}
	return &actionStreamWrapper{RansomEyeService_ReceiveActionsServer: stream}
}
