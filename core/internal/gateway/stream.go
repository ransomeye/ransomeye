package gateway

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"ransomeye/core/internal/identity"
	pb "ransomeye/proto/ransomeyepb"
)

// ReceiveActions is the strict gRPC server-streaming handler for action dispatch.
// Memory leak prevention (P0): UnregisterStream MUST fire on disconnect.
//
// agent_id extraction from mTLS is stubbed here and will be replaced with strict X.509 parsing.
func (h *Handlers) ReceiveActions(_ *pb.ActionStreamRequest, stream pb.RansomEyeService_ReceiveActionsServer) error {
	if h == nil || h.dispatcher == nil {
		return status.Error(codes.FailedPrecondition, "action dispatcher not initialized")
	}

	agentID, err := identity.ExtractAgentID(stream.Context())
	if err != nil {
		// P0: unauthenticated -> drop immediately.
		return err
	}

	wrapped := newActionStreamWrapper(stream)
	h.dispatcher.RegisterStream(agentID, wrapped)
	h.registerActionStream(agentID, wrapped)
	defer h.dispatcher.UnregisterStream(agentID)
	defer h.unregisterActionStream(agentID)

	h.queueAdmissionAssessment(0)
	h.publishCurrentBackpressureState(agentID)

	<-stream.Context().Done()
	return stream.Context().Err()
}
