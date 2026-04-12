package enforcement

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"google.golang.org/grpc/peer"

	"ransomeye/core/internal/contracts"
	"ransomeye/core/internal/events"
	"ransomeye/core/internal/forensics"
	"ransomeye/core/internal/health"
	"ransomeye/core/internal/ingest"
	"ransomeye/core/internal/policy"
	pb "ransomeye/proto/ransomeyepb"
)

var (
	ErrAgentOffline         = errors.New("agent offline")
	ErrDispatchBackpressure = errors.New("enforcement dispatch backpressure")
)

const (
	dispatchQueueDepth      = 64
	defaultRateLimitWindow  = int64(64)
	defaultRateLimitMaximum = 8
)

type EventRecorder interface {
	Record(agentID string, logicalClock int64, event forensics.EnforcementEvent) (forensics.StoredEnforcementEvent, error)
}

type DispatchRequest struct {
	AgentID      string
	DetectionID  string
	LogicalClock int64
	Timestamp    int64
	Score        float64
	Target       string
	Process      ProcessBinding
	Decision     policy.EnforcementDecision
	Command      *pb.ActionCommand
}

type ProcessBinding struct {
	ProcessHash    string
	ExecutablePath string
	KernelTag      string
}

type ProcessBindingResolver func(ingest.TelemetryV1View) (ProcessBinding, error)

type dispatchEnvelope struct {
	command *pb.ActionCommand
	event   *contracts.EnforcementEvent
}

type agentRoute struct {
	stream pb.RansomEyeService_ReceiveActionsServer
	queue  chan dispatchEnvelope
	stop   chan struct{}
}

type ActionDispatcher struct {
	mu       sync.RWMutex
	routes   map[string]*agentRoute
	bus      events.EventBus
	recorder EventRecorder
	limiter  *RateLimiter
	seq      atomic.Int64
}

func NewActionDispatcher(bus events.EventBus, recorder EventRecorder) *ActionDispatcher {
	return NewActionDispatcherWithRateLimiter(
		bus,
		recorder,
		NewRateLimiter(defaultRateLimitWindow, defaultRateLimitMaximum),
	)
}

func NewActionDispatcherWithRateLimiter(bus events.EventBus, recorder EventRecorder, limiter *RateLimiter) *ActionDispatcher {
	return &ActionDispatcher{
		routes:   make(map[string]*agentRoute),
		bus:      bus,
		recorder: recorder,
		limiter:  limiter,
	}
}

func (d *ActionDispatcher) RegisterStream(agentID string, stream pb.RansomEyeService_ReceiveActionsServer) {
	if d == nil || agentID == "" || stream == nil {
		return
	}
	if !isLoopbackStream(stream) {
		slog.Warn("enforcement.reject_non_loopback_stream", "agent_id", agentID)
		return
	}

	route := &agentRoute{
		stream: stream,
		queue:  make(chan dispatchEnvelope, dispatchQueueDepth),
		stop:   make(chan struct{}),
	}

	d.mu.Lock()
	if prev, ok := d.routes[agentID]; ok {
		close(prev.stop)
	}
	d.routes[agentID] = route
	d.mu.Unlock()

	go d.runRoute(agentID, route)
}

func (d *ActionDispatcher) UnregisterStream(agentID string) {
	if d == nil || agentID == "" {
		return
	}
	d.mu.Lock()
	route, ok := d.routes[agentID]
	if ok {
		delete(d.routes, agentID)
		close(route.stop)
	}
	d.mu.Unlock()
}

// RegisteredEnforcementAgents returns agent IDs with an active loopback ReceiveActions stream.
// Read-only observability for SOC (PRD-12); not a substitute for EXECUTION_RESULT authority rows.
func (d *ActionDispatcher) RegisteredEnforcementAgents() []string {
	if d == nil {
		return nil
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]string, 0, len(d.routes))
	for id := range d.routes {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func (d *ActionDispatcher) unregisterRoute(agentID string, route *agentRoute) {
	if d == nil || agentID == "" || route == nil {
		return
	}
	d.mu.Lock()
	current, ok := d.routes[agentID]
	if ok && current == route {
		delete(d.routes, agentID)
		close(route.stop)
	}
	d.mu.Unlock()
}

func (d *ActionDispatcher) Dispatch(req DispatchRequest) error {
	if d == nil {
		return errors.New("nil dispatcher")
	}
	if !req.Decision.Allowed {
		return nil
	}
	if req.AgentID == "" {
		return errors.New("agent_id missing")
	}
	if req.Command == nil {
		return errors.New("nil action command")
	}
	if req.Target == "" {
		return errors.New("target missing")
	}
	if req.Process.ProcessHash == "" || req.Process.ExecutablePath == "" || req.Process.KernelTag == "" {
		return errors.New("process identity binding missing")
	}
	if d.recorder == nil {
		return errors.New("enforcement recorder not initialized")
	}
	if d.limiter != nil && !d.limiter.Allow(req.LogicalClock) {
		slog.Warn("enforcement.rate_limited",
			"agent_id", req.AgentID,
			"detection_id", req.DetectionID,
			"logical_clock", req.LogicalClock,
		)
		return nil
	}

	d.mu.RLock()
	route, ok := d.routes[req.AgentID]
	d.mu.RUnlock()
	if !ok {
		return fmt.Errorf("%w: agent_id=%s", ErrAgentOffline, req.AgentID)
	}

	stored, err := d.recorder.Record(req.AgentID, req.LogicalClock, forensics.EnforcementEvent{
		EventID:       req.Command.GetActionId(),
		Action:        req.Decision.Action,
		Target:        req.Target,
		DecisionScore: req.Score,
		Timestamp:     req.Timestamp,
	})
	if err != nil {
		return err
	}

	event := &contracts.EnforcementEvent{
		Seq:       d.seq.Add(1),
		EventID:   req.Command.GetActionId(),
		AgentID:   req.AgentID,
		Action:    req.Decision.Action,
		Target:    req.Target,
		Status:    "DISPATCHED",
		Timestamp: req.Timestamp,
		Signature: stored.Signature,
	}

	select {
	case route.queue <- dispatchEnvelope{command: req.Command, event: event}:
		return nil
	default:
		return ErrDispatchBackpressure
	}
}

func (d *ActionDispatcher) DispatchAction(agentID string, action *pb.ActionCommand) error {
	if action == nil {
		return errors.New("nil action")
	}
	return d.Dispatch(DispatchRequest{
		AgentID:      agentID,
		DetectionID:  action.GetDetectionId(),
		LogicalClock: action.GetLogicalClock(),
		Timestamp:    action.GetLogicalClock(),
		Score:        0,
		Target:       agentID,
		Decision: policy.EnforcementDecision{
			Action:  legacyActionName(action.GetActionType()),
			Allowed: true,
		},
		Command: action,
	})
}

func (d *ActionDispatcher) runRoute(agentID string, route *agentRoute) {
	for {
		select {
		case <-route.stop:
			return
		case item := <-route.queue:
			if item.command == nil {
				continue
			}
			if err := route.stream.Send(item.command); err != nil {
				slog.Error("enforcement.dispatch_send_failed",
					"agent_id", agentID,
					"action_id", item.command.GetActionId(),
					"error", err.Error(),
				)
				d.unregisterRoute(agentID, route)
				return
			}
			if d.bus != nil && item.event != nil {
				if err := d.bus.Publish(item.event); err != nil {
					slog.Warn("enforcement.bus_backpressure",
						"agent_id", agentID,
						"action_id", item.command.GetActionId(),
						"error", err.Error(),
					)
				}
			}
		}
	}
}

func BuildDispatchRequest(agentID string, detectionID string, logicalClock int64, timestamp int64, payload []byte, score float64, decision policy.EnforcementDecision) (DispatchRequest, error) {
	return BuildDispatchRequestWithResolver(agentID, detectionID, logicalClock, timestamp, payload, score, decision, resolveLiveProcessBinding)
}

func BuildDispatchRequestWithResolver(agentID string, detectionID string, logicalClock int64, timestamp int64, payload []byte, score float64, decision policy.EnforcementDecision, resolver ProcessBindingResolver) (DispatchRequest, error) {
	req := DispatchRequest{
		AgentID:      agentID,
		DetectionID:  detectionID,
		LogicalClock: logicalClock,
		Timestamp:    timestamp,
		Score:        score,
		Decision:     decision,
	}
	if decision.Action == policy.ActionNone {
		return req, nil
	}

	view, err := ingest.ParseTelemetryV1(payload)
	if err != nil {
		return DispatchRequest{}, err
	}
	if view.AuxPID == 0 {
		return DispatchRequest{}, errors.New("enforcement target pid missing")
	}
	if resolver == nil {
		return DispatchRequest{}, errors.New("process binding resolver not configured")
	}

	processBinding, err := resolver(view)
	if err != nil {
		return DispatchRequest{}, err
	}

	target := fmt.Sprintf("pid:%d", view.AuxPID)
	actionID := deterministicActionID(agentID, detectionID, decision.Action, logicalClock, target)
	command, err := buildActionCommand(actionID, detectionID, decision.Action, int(view.AuxPID), logicalClock, processBinding)
	if err != nil {
		return DispatchRequest{}, err
	}

	req.Target = target
	req.Process = processBinding
	req.Command = command
	return req, nil
}

func buildActionCommand(actionID string, detectionID string, action string, pid int, logicalClock int64, binding ProcessBinding) (*pb.ActionCommand, error) {
	type actionParameters struct {
		Action         string `json:"action"`
		PID            int    `json:"pid"`
		ProcessHash    string `json:"process_hash"`
		ExecutablePath string `json:"executable_path"`
		KernelTag      string `json:"kernel_tag"`
	}

	raw, err := json.Marshal(actionParameters{
		Action:         action,
		PID:            pid,
		ProcessHash:    binding.ProcessHash,
		ExecutablePath: binding.ExecutablePath,
		KernelTag:      binding.KernelTag,
	})
	if err != nil {
		return nil, err
	}

	switch action {
	case policy.ActionKillProcess:
		return &pb.ActionCommand{
			ActionId:       actionID,
			DetectionId:    detectionID,
			ActionType:     pb.ActionType_KILL_PROCESS,
			ParametersJson: string(raw),
			LogicalClock:   logicalClock,
		}, nil
	case policy.ActionBlockWrite:
		return &pb.ActionCommand{
			ActionId:       actionID,
			DetectionId:    detectionID,
			ActionType:     pb.ActionType_ALERT_ONLY,
			ParametersJson: string(raw),
			LogicalClock:   logicalClock,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported enforcement action %q", action)
	}
}

func resolveLiveProcessBinding(view ingest.TelemetryV1View) (ProcessBinding, error) {
	if isZeroProcessHash(view.ProcessHash) {
		return ProcessBinding{}, errors.New("process identity binding missing process_hash")
	}

	executablePath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", view.AuxPID))
	if err != nil {
		return ProcessBinding{}, fmt.Errorf("resolve executable path for pid %d: %w", view.AuxPID, err)
	}
	executablePath = strings.TrimSpace(executablePath)
	if executablePath == "" {
		return ProcessBinding{}, errors.New("executable path missing")
	}
	if !strings.Contains(executablePath, " (deleted)") {
		executablePath = filepath.Clean(executablePath)
	}

	kernelTag, err := currentKernelTag()
	if err != nil {
		return ProcessBinding{}, err
	}

	return ProcessBinding{
		ProcessHash:    hex.EncodeToString(view.ProcessHash[:]),
		ExecutablePath: executablePath,
		KernelTag:      kernelTag,
	}, nil
}

func currentKernelTag() (string, error) {
	raw, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return "", fmt.Errorf("read kernel tag: %w", err)
	}
	release := strings.TrimSpace(string(raw))
	if release == "" {
		return "", errors.New("kernel tag missing")
	}
	return fmt.Sprintf("linux|%s|%s", release, runtime.GOARCH), nil
}

func isZeroProcessHash(hash [32]byte) bool {
	for _, b := range hash {
		if b != 0 {
			return false
		}
	}
	return true
}

func deterministicActionID(agentID string, detectionID string, action string, logicalClock int64, target string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s|%d|%s", agentID, detectionID, action, logicalClock, target)))
	return hex.EncodeToString(sum[:])
}

func isLoopbackStream(stream pb.RansomEyeService_ReceiveActionsServer) bool {
	p, ok := peer.FromContext(stream.Context())
	if !ok || p.Addr == nil {
		return true
	}
	switch addr := p.Addr.(type) {
	case *net.TCPAddr:
		return addr.IP.IsLoopback()
	case *net.UnixAddr:
		return true
	default:
		host, _, err := net.SplitHostPort(addr.String())
		if err != nil {
			return false
		}
		ip := net.ParseIP(host)
		return ip != nil && ip.IsLoopback()
	}
}

func legacyActionName(actionType pb.ActionType) string {
	switch actionType {
	case pb.ActionType_KILL_PROCESS:
		return policy.ActionKillProcess
	default:
		return policy.ActionNone
	}
}

type BlockReason int

const (
	BlockNone BlockReason = iota
	BlockNoDPI
	BlockNoSINE
	BlockNoAI
	BlockPipelineDegraded
)

type BlockedError struct {
	Reason BlockReason
}

func (e BlockedError) Error() string {
	return fmt.Sprintf("enforcement blocked (reason=%d)", e.Reason)
}

func EvaluateBlockFromState(s *contracts.BlockEvalState) BlockReason {
	if s == nil {
		return BlockPipelineDegraded
	}
	if health.DPIPlaneEnvConfigured() && !s.DPIReady {
		return BlockNoDPI
	}
	if health.SINEPlaneEnvConfigured() && !s.SINEReady {
		return BlockNoSINE
	}
	if health.AIPlaneEnvConfigured() && !s.AIReady {
		return BlockNoAI
	}
	if !s.PipelineHealthy {
		return BlockPipelineDegraded
	}
	return BlockNone
}
