package ai

import (
	"context"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"ransomeye/core/internal/enforcement"
	"ransomeye/core/internal/policy"
	internalaipb "ransomeye/proto/internalai"
)

const (
	defaultQueueDepth = 1024
	maxPayloadBytes   = 64 * 1024
)

type Router struct {
	client     *Client
	dispatcher *enforcement.ActionDispatcher
	evaluator  *policy.PolicyEvaluator

	ch        chan *queuedEval
	closeOnce sync.Once

	dropped atomic.Uint64

	payloadPool sync.Pool // *[]byte up to 64KB

	tenantConfigAEC bool
}

type queuedEval struct {
	agentID      string
	eventID      string
	payload      []byte
	logicalClock int64
}

func NewRouter(client *Client, dispatcher *enforcement.ActionDispatcher, queueDepth int, evaluator *policy.PolicyEvaluator) *Router {
	if queueDepth <= 0 {
		queueDepth = defaultQueueDepth
	}
	r := &Router{
		client:     client,
		dispatcher: dispatcher,
		evaluator:  evaluator,
		ch:         make(chan *queuedEval, queueDepth),
	}
	r.payloadPool.New = func() any {
		b := make([]byte, 0, maxPayloadBytes)
		return &b
	}
	return r
}

func (r *Router) SetTenantConfigAEC(enabled bool) {
	r.tenantConfigAEC = enabled
}

func (r *Router) DroppedCount() uint64 {
	return r.dropped.Load()
}

// Close stops accepting new items and lets Run drain the queue.
func (r *Router) Close() {
	if r == nil {
		return
	}
	r.closeOnce.Do(func() {
		if r.ch != nil {
			close(r.ch)
		}
	})
}

// TryEnqueue backpressures when the queue is saturated instead of discarding accepted work.
// Payload is copied into a pool-owned buffer so the caller may safely release its own buffers
// (e.g., the gateway payload pool) right after committing.
func (r *Router) TryEnqueue(eventID string, agentID string, payload []byte, logicalClock int64) {
	if r == nil || r.ch == nil {
		return
	}
	// No sidecar: advisory AI evaluation is disabled — never queue (avoids blocking workers on a full channel with no consumer).
	if r.client == nil {
		return
	}
	if len(payload) == 0 || len(payload) > maxPayloadBytes {
		return
	}
	if agentID == "" || eventID == "" {
		return
	}

	p := r.payloadPool.Get().(*[]byte)
	buf := (*p)[:0]
	buf = append(buf, payload...)

	item := &queuedEval{
		agentID:      agentID,
		eventID:      eventID,
		payload:      buf,
		logicalClock: logicalClock,
	}

	select {
	case r.ch <- item:
		return
	default:
		r.ch <- item
		return
	}
}

func (r *Router) Run(ctx context.Context) error {
	if r == nil || r.client == nil {
		return nil
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case item, ok := <-r.ch:
			if !ok {
				return nil
			}
			if item == nil {
				continue
			}
			r.handleOne(ctx, item)
		}
	}
}

func (r *Router) handleOne(ctx context.Context, item *queuedEval) {
	// AI is advisory only. Enforcement is driven by the deterministic detector policy path.
	callCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	req := &internalaipb.EvaluationRequest{
		EventId:      item.eventID,
		Payload:      item.payload,
		LogicalClock: item.logicalClock,
	}
	resp, err := r.client.EvaluateTelemetry(callCtx, req)
	if err != nil {
		log.Printf("[WARN] AI_EVALUATE_FAILED event_id=%s err=%v", item.eventID, err)
		r.releaseItem(item)
		return
	}

	decision := enforcement.EvaluateEnforcementDecision(resp.AecClass, r.tenantConfigAEC)
	auto := enforcement.IsAutoEnforceEnabled(r.tenantConfigAEC)

	log.Printf("[INFO] AI_EVALUATED event_id=%s agent_id=%s posterior=%.8f aec=%s auto_enforce=%t decision=%s",
		item.eventID, item.agentID, resp.PosteriorProbability, resp.AecClass,
		auto, decision,
	)

	r.releaseItem(item)
}

func (r *Router) releaseItem(item *queuedEval) {
	if item == nil || item.payload == nil {
		return
	}
	if cap(item.payload) < maxPayloadBytes/4 {
		item.payload = nil
		return
	}
	b := item.payload[:0]
	item.payload = nil
	r.payloadPool.Put(&b)
}
