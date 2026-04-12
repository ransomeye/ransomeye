package adversarial

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"ransomeye/core/internal/ai"
	"ransomeye/core/internal/enforcement"
	"ransomeye/core/internal/ingest"
	"ransomeye/core/internal/pipeline"
	"ransomeye/core/internal/policy"
	"ransomeye/core/internal/replay"
)

const (
	DetectionLatencyThresholdMS   = 100
	EnforcementLatencyThresholdMS = 200
)

var replayEnvMu sync.Mutex

var scenarioNamespace = uuid.MustParse("83ec6177-d060-4b90-922e-dcc29ced6876")

type Result struct {
	Attack                 string `json:"attack"`
	Detected               bool   `json:"detected"`
	LatencyMS              int64  `json:"latency_ms"`
	EnforcementLatencyMS   int64  `json:"enforcement_latency_ms"`
	FalseNegatives         int    `json:"false_negatives"`
	FalsePositives         int    `json:"false_positives"`
	Enforced               bool   `json:"enforced"`
	ReplayConsistent       bool   `json:"replay_consistent"`
	ExpectedAction         string `json:"expected_action"`
	ObservedAction         string `json:"observed_action"`
	DetectionThresholdMS   int64  `json:"detection_threshold_ms"`
	EnforcementThresholdMS int64  `json:"enforcement_threshold_ms"`
}

type entropyProfile string

const (
	entropyLow    entropyProfile = "low"
	entropyMedium entropyProfile = "medium"
	entropyHigh   entropyProfile = "high"
)

type eventPlan struct {
	Name            string
	EventTypeCode   uint32
	Delay           time.Duration
	AuxPID          uint32
	DroppedCount    uint64
	ProcessLabel    string
	FileLabel       string
	NetworkLabel    string
	MemoryOnly      bool
	CandidateCount  int
	Profiles        []entropyProfile
	ExpectMalicious bool
	RequireBurst    *bool
	EntropyFloor    float64
	ExpectedAction  string
}

type scenarioSpec struct {
	Name           string
	ExpectedAction string
	Plans          []eventPlan
}

type harness struct {
	repoRoot   string
	model      ai.RuntimeModel
	keyPath    string
	configHash string
	prdHash    string
}

type candidateOutcome struct {
	event    *ingest.VerifiedTelemetry
	finding  pipeline.DetectionEvent
	trace    pipeline.DetectionTrace
	priority float64
}

type liveOutcome struct {
	detected   bool
	enforced   bool
	action     string
	target     string
	sequenceID uint64
	latencyMS  int64
	enforceMS  int64
	falseNeg   int
	falsePos   int
}

type replayDecisionArtifact struct {
	SequenceID uint64 `json:"sequence_id"`
	Decision   string `json:"decision"`
	Action     string `json:"action"`
}

type replayEnforcementArtifact struct {
	SequenceID uint64 `json:"sequence_id"`
	Action     string `json:"action"`
	Target     string `json:"target"`
	Skipped    bool   `json:"skipped"`
}

func ScenarioNames() []string {
	names := make([]string, 0, len(scenarioSpecs))
	for _, spec := range scenarioSpecs {
		names = append(names, spec.Name)
	}
	return names
}

func RunAll(ctx context.Context) ([]Result, error) {
	return run(ctx, ScenarioNames())
}

func RunScenario(ctx context.Context, attack string) (Result, error) {
	results, err := run(ctx, []string{attack})
	if err != nil {
		return Result{}, err
	}
	return results[0], nil
}

func (r Result) Pass() bool {
	if !r.Detected || !r.Enforced || !r.ReplayConsistent {
		return false
	}
	if r.FalseNegatives != 0 || r.FalsePositives != 0 {
		return false
	}
	if r.ObservedAction != r.ExpectedAction {
		return false
	}
	if r.LatencyMS >= DetectionLatencyThresholdMS {
		return false
	}
	if r.EnforcementLatencyMS >= EnforcementLatencyThresholdMS {
		return false
	}
	return true
}

func run(ctx context.Context, names []string) ([]Result, error) {
	h, cleanup, err := newHarness()
	if err != nil {
		return nil, err
	}
	defer cleanup()

	results := make([]Result, 0, len(names))
	for _, name := range names {
		spec, ok := lookupScenario(name)
		if !ok {
			return nil, fmt.Errorf("unknown attack scenario %q", name)
		}
		result, err := h.runScenario(ctx, spec)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		results = append(results, result)
	}
	return results, nil
}

func newHarness() (*harness, func(), error) {
	root, err := findRepoRoot()
	if err != nil {
		return nil, nil, err
	}

	tempDir, err := os.MkdirTemp("", "ransomeye-adversarial-*")
	if err != nil {
		return nil, nil, err
	}
	cleanup := func() { _ = os.RemoveAll(tempDir) }

	keyPath := filepath.Join(tempDir, "worm_signing.key")
	seed := make([]byte, ed25519.SeedSize)
	for idx := range seed {
		seed[idx] = byte((idx*5 + 11) & 0xff)
	}
	if err := os.WriteFile(keyPath, seed, 0o600); err != nil {
		cleanup()
		return nil, nil, err
	}

	model, err := ai.LoadRuntimeModelFromRootWithSigningKeyPath(filepath.Join(root, "ml"), keyPath)
	if err != nil {
		cleanup()
		return nil, nil, err
	}

	return &harness{
		repoRoot:   root,
		model:      model,
		keyPath:    keyPath,
		configHash: strings.Repeat("1", 64),
		prdHash:    strings.Repeat("3", 64),
	}, cleanup, nil
}

func (h *harness) runScenario(ctx context.Context, spec scenarioSpec) (Result, error) {
	events, err := h.synthesizeScenario(spec)
	if err != nil {
		return Result{}, err
	}
	live, err := h.executeScenario(events, spec.ExpectedAction, spec.Plans)
	if err != nil {
		return Result{}, err
	}
	replayConsistent, err := h.verifyReplay(ctx, spec, events, live)
	if err != nil {
		return Result{}, err
	}

	return Result{
		Attack:                 spec.Name,
		Detected:               live.detected,
		LatencyMS:              live.latencyMS,
		EnforcementLatencyMS:   live.enforceMS,
		FalseNegatives:         live.falseNeg,
		FalsePositives:         live.falsePos,
		Enforced:               live.enforced,
		ReplayConsistent:       replayConsistent,
		ExpectedAction:         spec.ExpectedAction,
		ObservedAction:         live.action,
		DetectionThresholdMS:   DetectionLatencyThresholdMS,
		EnforcementThresholdMS: EnforcementLatencyThresholdMS,
	}, nil
}

func (h *harness) synthesizeScenario(spec scenarioSpec) ([]*ingest.VerifiedTelemetry, error) {
	baseTS := uint64(1_710_000_000_000_000_000)
	events := make([]*ingest.VerifiedTelemetry, 0, len(spec.Plans))
	nowTS := baseTS
	logicalClock := uint64(1000)

	for _, plan := range spec.Plans {
		nowTS += uint64(plan.Delay)
		event, err := h.selectEvent(spec, events, logicalClock, nowTS, plan)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
		logicalClock++
	}
	return events, nil
}

func (h *harness) selectEvent(spec scenarioSpec, prefix []*ingest.VerifiedTelemetry, logicalClock uint64, timestamp uint64, plan eventPlan) (*ingest.VerifiedTelemetry, error) {
	budget := plan.CandidateCount
	if budget <= 0 {
		budget = 256
	}
	profiles := plan.Profiles
	if len(profiles) == 0 {
		profiles = []entropyProfile{entropyMedium}
	}

	var best *candidateOutcome
	var closest *candidateOutcome
	for attempt := 0; attempt < budget; attempt++ {
		profile := profiles[attempt%len(profiles)]
		event, err := buildEvent(spec.Name, logicalClock, timestamp, plan, profile, attempt)
		if err != nil {
			return nil, err
		}
		finding, trace, err := h.evaluateCandidate(prefix, event)
		if err != nil {
			return nil, err
		}
		if closest == nil || finding.Confidence > closest.finding.Confidence {
			closest = &candidateOutcome{
				event:    event,
				finding:  finding,
				trace:    trace,
				priority: finding.Confidence,
			}
		}
		if outcome, ok := scoreCandidate(plan, event, finding, trace); ok {
			if best == nil || outcome.priority > best.priority {
				best = outcome
			}
		}
	}
	if best == nil {
		if closest == nil {
			return nil, fmt.Errorf("unable to synthesize event %q", plan.Name)
		}
		return nil, fmt.Errorf(
			"unable to synthesize event %q: best_score=%.6f decision=%s action=%s entropy=%.6f burst=%.6f",
			plan.Name,
			closest.finding.Confidence,
			closest.finding.Decision,
			closest.finding.PolicyDecision.Action,
			closest.trace.Features.EntropyScore,
			closest.trace.Features.BurstScore,
		)
	}
	return best.event, nil
}

func (h *harness) evaluateCandidate(prefix []*ingest.VerifiedTelemetry, candidate *ingest.VerifiedTelemetry) (pipeline.DetectionEvent, pipeline.DetectionTrace, error) {
	detector, err := h.newDetector()
	if err != nil {
		return pipeline.DetectionEvent{}, pipeline.DetectionTrace{}, err
	}
	for _, event := range prefix {
		if _, _, err := detector.EvaluateWithTrace(event); err != nil {
			return pipeline.DetectionEvent{}, pipeline.DetectionTrace{}, err
		}
	}
	return detector.EvaluateWithTrace(candidate)
}

func (h *harness) executeScenario(events []*ingest.VerifiedTelemetry, expectedAction string, plans []eventPlan) (liveOutcome, error) {
	detector, err := h.newDetector()
	if err != nil {
		return liveOutcome{}, err
	}

	start := time.Now()
	outcome := liveOutcome{}
	for idx, event := range events {
		finding, _, err := detector.EvaluateWithTrace(event)
		if err != nil {
			return liveOutcome{}, err
		}
		expectMalicious := plans[idx].ExpectMalicious
		if !expectMalicious && finding.Decision == "malicious" {
			outcome.falsePos++
		}
		if !expectMalicious {
			continue
		}
		if finding.Decision != "malicious" || finding.PolicyDecision.Action != expectedAction || !finding.PolicyDecision.Allowed {
			outcome.falseNeg++
			continue
		}

		view, err := ingest.ParseTelemetryV1(event.Payload)
		if err != nil {
			return liveOutcome{}, err
		}
		enforcementStart := time.Now()
		dispatch, err := enforcement.BuildDispatchRequestWithResolver(
			view.AgentID.String(),
			view.EventID.String(),
			int64(view.LogicalClock),
			ingest.TimestampUTC(view.TimestampUnixNano).Unix(),
			event.Payload,
			finding.Confidence,
			finding.PolicyDecision,
			simulatedProcessBindingResolver,
		)
		if err != nil {
			return liveOutcome{}, err
		}
		outcome.detected = true
		outcome.enforced = dispatch.Command != nil
		outcome.action = finding.PolicyDecision.Action
		outcome.target = dispatch.Target
		outcome.sequenceID = view.LogicalClock
		outcome.latencyMS = durationMS(time.Since(start))
		outcome.enforceMS = durationMS(time.Since(enforcementStart))
		break
	}
	return outcome, nil
}

func (h *harness) verifyReplay(ctx context.Context, spec scenarioSpec, events []*ingest.VerifiedTelemetry, live liveOutcome) (bool, error) {
	envelope, err := h.buildEnvelope(events)
	if err != nil {
		return false, err
	}

	replayEnvMu.Lock()
	defer replayEnvMu.Unlock()
	restore := setEnvs(map[string]string{
		replay.DefaultReplaySigningKeyEnv: h.keyPath,
		replay.DefaultConfigHashEnv:       envelope.ConfigHash,
		replay.DefaultModelHashEnv:        envelope.ModelHash,
		replay.DefaultFeatureVersionEnv:   envelope.FeatureVersion,
		replay.DefaultPRDHashEnv:          envelope.PRDHash,
		"RANSOMEYE_AI_ROOT":               filepath.Join(h.repoRoot, "ml"),
	})
	defer restore()

	run1, run2, err := replay.VerifyEnvelope(ctx, envelope)
	if err != nil {
		return false, err
	}

	var decisions []replayDecisionArtifact
	if err := json.Unmarshal(run1.StageArtifacts.Decision, &decisions); err != nil {
		return false, err
	}
	var enforcements []replayEnforcementArtifact
	if err := json.Unmarshal(run1.StageArtifacts.Enforcement, &enforcements); err != nil {
		return false, err
	}
	decision, ok := findReplayDecision(decisions, live.sequenceID)
	if !ok {
		return false, fmt.Errorf("replay decision missing sequence_id=%d", live.sequenceID)
	}
	enforcementArtifact, ok := findReplayEnforcement(enforcements, live.sequenceID)
	if !ok {
		return false, fmt.Errorf("replay enforcement missing sequence_id=%d", live.sequenceID)
	}
	if decision.Decision != "malicious" {
		return false, fmt.Errorf("replay decision=%s want malicious", decision.Decision)
	}
	if decision.Action != spec.ExpectedAction {
		return false, fmt.Errorf("replay action=%s want %s", decision.Action, spec.ExpectedAction)
	}
	if enforcementArtifact.Action != live.action || enforcementArtifact.Target != live.target || enforcementArtifact.Skipped {
		return false, fmt.Errorf(
			"replay enforcement mismatch: action=%s target=%s skipped=%t want_action=%s want_target=%s",
			enforcementArtifact.Action,
			enforcementArtifact.Target,
			enforcementArtifact.Skipped,
			live.action,
			live.target,
		)
	}
	return run1.StageHashes == run2.StageHashes, nil
}

func (h *harness) buildEnvelope(events []*ingest.VerifiedTelemetry) (replay.Envelope, error) {
	out := replay.Envelope{
		Events:         make([]replay.CapturedEvent, 0, len(events)),
		ConfigHash:     h.configHash,
		ModelHash:      h.model.Identity.ModelHash,
		FeatureVersion: h.model.Identity.FeatureVersion,
		PRDHash:        h.prdHash,
	}
	for _, event := range events {
		view, err := ingest.ParseTelemetryV1(event.Payload)
		if err != nil {
			return replay.Envelope{}, err
		}
		eventType, err := ingest.DBEventType(view.EventTypeCode)
		if err != nil {
			return replay.Envelope{}, err
		}
		out.Events = append(out.Events, replay.CapturedEvent{
			SequenceID:           view.LogicalClock,
			TimestampUnixNano:    view.TimestampUnixNano,
			DroppedPacketsBefore: event.DroppedCount,
			AgentID:              view.AgentID.String(),
			EventType:            eventType,
			PayloadBase64:        base64.StdEncoding.EncodeToString(event.Payload),
			AgentSignatureBase64: base64.StdEncoding.EncodeToString(event.AgentSignature),
		})
	}
	return out, nil
}

func (h *harness) newDetector() (*pipeline.DeterministicDetector, error) {
	detector, err := pipeline.NewDeterministicDetector(h.model)
	if err != nil {
		return nil, err
	}
	detector.SetPolicyEngine(policy.NewEngine(policy.EnforcementPolicy{
		Mode:           policy.ModeAuto,
		Threshold:      h.model.ScoreThreshold,
		AllowedActions: []string{policy.ActionKillProcess, policy.ActionBlockWrite},
	}, true))
	return detector, nil
}

func scoreCandidate(plan eventPlan, event *ingest.VerifiedTelemetry, finding pipeline.DetectionEvent, trace pipeline.DetectionTrace) (*candidateOutcome, bool) {
	if plan.ExpectMalicious {
		if finding.Decision != "malicious" || !finding.PolicyDecision.Allowed || finding.PolicyDecision.Action != plan.ExpectedAction {
			return nil, false
		}
		if plan.EntropyFloor > 0 && trace.Features.EntropyScore < plan.EntropyFloor {
			return nil, false
		}
		if plan.RequireBurst != nil && (trace.Features.BurstScore == 1) != *plan.RequireBurst {
			return nil, false
		}
		return &candidateOutcome{
			event:    event,
			finding:  finding,
			trace:    trace,
			priority: finding.Confidence + trace.Features.EntropyScore,
		}, true
	}
	if finding.Decision == "malicious" {
		return nil, false
	}
	return &candidateOutcome{
		event:    event,
		finding:  finding,
		trace:    trace,
		priority: 1 - finding.Confidence,
	}, true
}

func buildEvent(attack string, logicalClock uint64, timestamp uint64, plan eventPlan, profile entropyProfile, attempt int) (*ingest.VerifiedTelemetry, error) {
	agentID := uuid.NewSHA1(scenarioNamespace, []byte("agent|"+attack))
	eventID := uuid.NewSHA1(
		scenarioNamespace,
		[]byte(fmt.Sprintf("%s|%s|%d|%d|%s", attack, plan.Name, logicalClock, attempt, profile)),
	)
	processHash := buildDigestBytes(32, profile, fmt.Sprintf("proc|%s|%s", attack, plan.ProcessLabel), attempt)
	fileHash := buildDigestBytes(32, profile, fmt.Sprintf("file|%s|%s", attack, plan.FileLabel), attempt)
	if plan.MemoryOnly {
		fileHash = make([]byte, 32)
	}
	networkTuple := buildDigestBytes(16, profile, fmt.Sprintf("net|%s|%s", attack, plan.NetworkLabel), attempt)
	bootSession := buildDigestBytes(16, entropyLow, "boot|"+attack, 0)

	var processHash32 [32]byte
	var fileHash32 [32]byte
	var networkTuple16 [16]byte
	var bootSession16 [16]byte
	copy(processHash32[:], processHash)
	copy(fileHash32[:], fileHash)
	copy(networkTuple16[:], networkTuple)
	copy(bootSession16[:], bootSession)

	payload, err := ingest.BuildCanonicalV1(
		logicalClock,
		agentID,
		eventID,
		plan.EventTypeCode,
		plan.AuxPID,
		processHash32,
		fileHash32,
		networkTuple16,
		timestamp,
		bootSession16,
	)
	if err != nil {
		return nil, err
	}
	eventType, err := ingest.DBEventType(plan.EventTypeCode)
	if err != nil {
		return nil, err
	}
	signature := sha256.Sum256([]byte(fmt.Sprintf("signature|%s|%s|%d|%d", attack, plan.Name, logicalClock, attempt)))
	return &ingest.VerifiedTelemetry{
		Payload:        payload[:],
		AgentSignature: signature[:],
		AgentIDStr:     agentID.String(),
		EventType:      eventType,
		TimestampUnix:  float64(timestamp) / 1e9,
		LogicalClock:   int64(logicalClock),
		DroppedCount:   plan.DroppedCount,
	}, nil
}

func buildDigestBytes(length int, profile entropyProfile, label string, attempt int) []byte {
	seed1 := sha256.Sum256([]byte(fmt.Sprintf("%s|%d|a", label, attempt)))
	seed2 := sha256.Sum256([]byte(fmt.Sprintf("%s|%d|b", label, attempt)))
	out := make([]byte, length)

	switch profile {
	case entropyLow:
		fill := seed1[0]
		for idx := range out {
			out[idx] = fill
		}
		if len(out) > 0 {
			out[0] = byte(attempt)
		}
		if len(out) > 1 {
			out[1] = seed1[1]
		}
		if len(out) > 2 {
			out[len(out)-1] = seed1[2]
		}
	case entropyMedium:
		pattern := []byte{seed1[0], seed1[1], seed1[2], seed1[3]}
		for idx := range out {
			out[idx] = pattern[idx%len(pattern)]
		}
		if len(out) > 4 {
			copy(out[len(out)-4:], []byte{seed2[0], seed2[1], seed2[2], seed2[3]})
		}
	default:
		full := append(seed1[:], seed2[:]...)
		copy(out, full[:length])
	}

	return out
}

func simulatedProcessBindingResolver(view ingest.TelemetryV1View) (enforcement.ProcessBinding, error) {
	return enforcement.ProcessBinding{
		ProcessHash:    hex.EncodeToString(view.ProcessHash[:]),
		ExecutablePath: fmt.Sprintf("/simulated/pid/%d/%s", view.AuxPID, hex.EncodeToString(view.ProcessHash[:4])),
		KernelTag:      fmt.Sprintf("adversarial|%d|%d", view.EventTypeCode, view.LogicalClock),
	}, nil
}

func findReplayDecision(items []replayDecisionArtifact, sequenceID uint64) (replayDecisionArtifact, bool) {
	for _, item := range items {
		if item.SequenceID == sequenceID {
			return item, true
		}
	}
	return replayDecisionArtifact{}, false
}

func findReplayEnforcement(items []replayEnforcementArtifact, sequenceID uint64) (replayEnforcementArtifact, bool) {
	for _, item := range items {
		if item.SequenceID == sequenceID {
			return item, true
		}
	}
	return replayEnforcementArtifact{}, false
}

func durationMS(value time.Duration) int64 {
	ms := value.Milliseconds()
	if ms == 0 && value > 0 {
		return 1
	}
	return ms
}

func lookupScenario(name string) (scenarioSpec, bool) {
	for _, spec := range scenarioSpecs {
		if spec.Name == name {
			return spec, true
		}
	}
	return scenarioSpec{}, false
}

func setEnvs(values map[string]string) func() {
	previous := make(map[string]*string, len(values))
	for key, value := range values {
		if current, ok := os.LookupEnv(key); ok {
			copyValue := current
			previous[key] = &copyValue
		} else {
			previous[key] = nil
		}
		_ = os.Setenv(key, value)
	}
	return func() {
		for key, value := range previous {
			if value == nil {
				_ = os.Unsetenv(key)
				continue
			}
			_ = os.Setenv(key, *value)
		}
	}
}

func findRepoRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(wd, "go.mod")); err == nil {
			return wd, nil
		}
		parent := filepath.Dir(wd)
		if parent == wd {
			return "", fmt.Errorf("unable to locate repository root")
		}
		wd = parent
	}
}

var (
	burstRequired   = true
	noBurstRequired = false
	scenarioSpecs   = []scenarioSpec{
		{
			Name:           "high_entropy_encryption",
			ExpectedAction: policy.ActionBlockWrite,
			Plans: []eventPlan{
				{
					Name:           "warmup_write_1",
					EventTypeCode:  ingest.EventTypeCodeFile,
					AuxPID:         4100,
					ProcessLabel:   "encryptor",
					FileLabel:      "invoice.docx",
					NetworkLabel:   "none",
					Delay:          0,
					CandidateCount: 256,
					Profiles:       []entropyProfile{entropyLow, entropyMedium},
				},
				{
					Name:           "warmup_write_2",
					EventTypeCode:  ingest.EventTypeCodeFile,
					AuxPID:         4100,
					ProcessLabel:   "encryptor",
					FileLabel:      "finance.xlsx",
					NetworkLabel:   "none",
					Delay:          200 * time.Millisecond,
					CandidateCount: 256,
					Profiles:       []entropyProfile{entropyLow, entropyMedium},
				},
				{
					Name:            "burst_encrypt",
					EventTypeCode:   ingest.EventTypeCodeFile,
					AuxPID:          4100,
					DroppedCount:    4,
					ProcessLabel:    "encryptor",
					FileLabel:       "archive.enc",
					NetworkLabel:    "none",
					Delay:           400 * time.Millisecond,
					CandidateCount:  2048,
					Profiles:        []entropyProfile{entropyHigh},
					ExpectMalicious: true,
					RequireBurst:    &burstRequired,
					EntropyFloor:    0.74,
					ExpectedAction:  policy.ActionBlockWrite,
				},
			},
		},
		{
			Name:           "low_slow_encryption",
			ExpectedAction: policy.ActionBlockWrite,
			Plans: []eventPlan{
				{
					Name:           "low_write_1",
					EventTypeCode:  ingest.EventTypeCodeFile,
					AuxPID:         4200,
					ProcessLabel:   "slow-encryptor",
					FileLabel:      "seed.txt",
					NetworkLabel:   "none",
					Delay:          0,
					CandidateCount: 256,
					Profiles:       []entropyProfile{entropyLow},
				},
				{
					Name:           "low_write_2",
					EventTypeCode:  ingest.EventTypeCodeFile,
					AuxPID:         4200,
					ProcessLabel:   "slow-encryptor",
					FileLabel:      "seed-2.txt",
					NetworkLabel:   "none",
					Delay:          3 * time.Second,
					CandidateCount: 256,
					Profiles:       []entropyProfile{entropyLow, entropyMedium},
				},
				{
					Name:           "entropy_ramp",
					EventTypeCode:  ingest.EventTypeCodeFile,
					AuxPID:         4200,
					ProcessLabel:   "slow-encryptor",
					FileLabel:      "staged.enc",
					NetworkLabel:   "none",
					Delay:          4 * time.Second,
					CandidateCount: 256,
					Profiles:       []entropyProfile{entropyMedium},
				},
				{
					Name:            "slow_encrypt",
					EventTypeCode:   ingest.EventTypeCodeFile,
					AuxPID:          4200,
					DroppedCount:    8,
					ProcessLabel:    "slow-encryptor",
					FileLabel:       "final.enc",
					NetworkLabel:    "none",
					Delay:           5 * time.Second,
					CandidateCount:  4096,
					Profiles:        []entropyProfile{entropyHigh},
					ExpectMalicious: true,
					RequireBurst:    &noBurstRequired,
					EntropyFloor:    0.74,
					ExpectedAction:  policy.ActionBlockWrite,
				},
			},
		},
		{
			Name:           "fileless_execution",
			ExpectedAction: policy.ActionKillProcess,
			Plans: []eventPlan{
				{
					Name:           "script_host_start",
					EventTypeCode:  ingest.EventTypeCodeProcess,
					AuxPID:         5100,
					ProcessLabel:   "powershell-loader",
					FileLabel:      "none",
					NetworkLabel:   "loopback",
					MemoryOnly:     true,
					Delay:          0,
					CandidateCount: 256,
					Profiles:       []entropyProfile{entropyLow, entropyMedium},
				},
				{
					Name:            "reflective_loader",
					EventTypeCode:   ingest.EventTypeCodeProcess,
					AuxPID:          5100,
					DroppedCount:    8,
					ProcessLabel:    "reflective-loader",
					FileLabel:       "none",
					NetworkLabel:    "c2-pivot",
					MemoryOnly:      true,
					Delay:           250 * time.Millisecond,
					CandidateCount:  2048,
					Profiles:        []entropyProfile{entropyMedium, entropyHigh},
					ExpectMalicious: true,
					EntropyFloor:    0.45,
					ExpectedAction:  policy.ActionKillProcess,
				},
			},
		},
		{
			Name:           "lolbins_abuse",
			ExpectedAction: policy.ActionKillProcess,
			Plans: []eventPlan{
				{
					Name:           "powershell_bootstrap",
					EventTypeCode:  ingest.EventTypeCodeProcess,
					AuxPID:         6100,
					ProcessLabel:   "powershell.exe",
					FileLabel:      "script.ps1",
					NetworkLabel:   "none",
					Delay:          0,
					CandidateCount: 256,
					Profiles:       []entropyProfile{entropyLow, entropyMedium},
				},
				{
					Name:           "certutil_stage",
					EventTypeCode:  ingest.EventTypeCodeProcess,
					AuxPID:         6101,
					ProcessLabel:   "certutil.exe",
					FileLabel:      "payload.b64",
					NetworkLabel:   "download",
					Delay:          500 * time.Millisecond,
					CandidateCount: 256,
					Profiles:       []entropyProfile{entropyLow, entropyMedium},
				},
				{
					Name:            "bash_execute",
					EventTypeCode:   ingest.EventTypeCodeProcess,
					AuxPID:          6102,
					DroppedCount:    8,
					ProcessLabel:    "bash",
					FileLabel:       "decoded-payload",
					NetworkLabel:    "egress",
					Delay:           3 * time.Second,
					CandidateCount:  4096,
					Profiles:        []entropyProfile{entropyMedium},
					ExpectMalicious: true,
					EntropyFloor:    0.45,
					ExpectedAction:  policy.ActionKillProcess,
				},
			},
		},
		{
			Name:           "process_kill_evasion",
			ExpectedAction: policy.ActionKillProcess,
			Plans: []eventPlan{
				{
					Name:           "fork_1",
					EventTypeCode:  ingest.EventTypeCodeProcess,
					AuxPID:         7100,
					ProcessLabel:   "fork-parent",
					FileLabel:      "none",
					NetworkLabel:   "none",
					Delay:          0,
					CandidateCount: 256,
					Profiles:       []entropyProfile{entropyLow, entropyMedium},
				},
				{
					Name:           "fork_2",
					EventTypeCode:  ingest.EventTypeCodeProcess,
					AuxPID:         7101,
					ProcessLabel:   "fork-child-1",
					FileLabel:      "none",
					NetworkLabel:   "none",
					Delay:          150 * time.Millisecond,
					CandidateCount: 256,
					Profiles:       []entropyProfile{entropyLow, entropyMedium},
				},
				{
					Name:           "fork_3",
					EventTypeCode:  ingest.EventTypeCodeProcess,
					AuxPID:         7102,
					ProcessLabel:   "fork-child-2",
					FileLabel:      "none",
					NetworkLabel:   "none",
					Delay:          150 * time.Millisecond,
					CandidateCount: 256,
					Profiles:       []entropyProfile{entropyLow, entropyMedium},
				},
				{
					Name:            "pid_churn_trigger",
					EventTypeCode:   ingest.EventTypeCodeProcess,
					AuxPID:          7103,
					DroppedCount:    8,
					ProcessLabel:    "fork-storm",
					FileLabel:       "none",
					NetworkLabel:    "none",
					Delay:           2 * time.Second,
					CandidateCount:  4096,
					Profiles:        []entropyProfile{entropyMedium},
					ExpectMalicious: true,
					EntropyFloor:    0.45,
					ExpectedAction:  policy.ActionKillProcess,
				},
			},
		},
	}
)
