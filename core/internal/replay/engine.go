package replay

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"ransomeye/core/internal/ai"
	"ransomeye/core/internal/enforcement"
	"ransomeye/core/internal/ingest"
	"ransomeye/core/internal/pipeline"
)

const (
	stageCapture               = "capture"
	stageIngest                = "ingest"
	stageFeature               = "feature"
	stageModel                 = "model"
	stageSINE                  = "sine"
	stageDecision              = "decision"
	stageEnforcement           = "enforcement"
	stageFinal                 = "final"
	DefaultReplaySigningKeyEnv = "RANSOMEYE_REPLAY_WORM_SIGNING_KEY_PATH"
)

type StageHashes struct {
	Ingest      string `json:"ingest"`
	Feature     string `json:"feature"`
	Model       string `json:"model"`
	SINE        string `json:"sine"`
	Decision    string `json:"decision"`
	Enforcement string `json:"enforcement"`
	Final       string `json:"final"`
}

type StageArtifacts struct {
	Capture     json.RawMessage
	Ingest      json.RawMessage
	Feature     json.RawMessage
	Model       json.RawMessage
	SINE        json.RawMessage
	Decision    json.RawMessage
	Enforcement json.RawMessage
	Final       json.RawMessage
}

type Result struct {
	InputHash      string         `json:"input_hash"`
	OutputHash     string         `json:"output_hash"`
	StageHashes    StageHashes    `json:"stage_hashes"`
	StageArtifacts StageArtifacts `json:"-"`
}

type ingestStageRecord struct {
	SequenceID           uint64 `json:"sequence_id"`
	TimestampUnixNano    uint64 `json:"timestamp_unix_nano"`
	DroppedPacketsBefore uint64 `json:"dropped_packets_before"`
	AgentID              string `json:"agent_id"`
	EventID              string `json:"event_id"`
	EventType            string `json:"event_type"`
	PayloadBase64        string `json:"payload_base64"`
	PayloadSHA256        string `json:"payload_sha256"`
	SignatureBase64      string `json:"signature_base64"`
	SignatureSHA256      string `json:"signature_sha256"`
}

type featureStageRecord struct {
	SequenceID               uint64   `json:"sequence_id"`
	AgentID                  string   `json:"agent_id"`
	EventID                  string   `json:"event_id"`
	EventTypeNorm            string   `json:"event_type_norm"`
	TimeDeltaNorm            string   `json:"time_delta_norm"`
	ProcessIDNorm            string   `json:"process_id_norm"`
	EntropyScore             string   `json:"entropy_score"`
	BurstScore               string   `json:"burst_score"`
	ChainDepthNorm           string   `json:"chain_depth_norm"`
	ExecutionFrequencyNorm   string   `json:"execution_frequency_norm"`
	PrivilegeLevelNorm       string   `json:"privilege_level_norm"`
	DroppedPacketsNorm       string   `json:"dropped_packets_norm"`
	WindowEntropyMean        string   `json:"window_entropy_mean"`
	WindowBurstMean          string   `json:"window_burst_mean"`
	WindowProcessAnomalyMean string   `json:"window_process_anomaly_mean"`
	WindowExecutionFreqMean  string   `json:"window_execution_frequency_mean"`
	WindowTimeDeltaMean      string   `json:"window_time_delta_mean"`
	WindowPrivilegeLevelMean string   `json:"window_privilege_level_mean"`
	ProcessAnomaly           string   `json:"process_anomaly"`
	Vector                   []string `json:"vector"`
}

type modelStageRecord struct {
	SequenceID       uint64 `json:"sequence_id"`
	AgentID          string `json:"agent_id"`
	EventID          string `json:"event_id"`
	ModelPrediction  string `json:"model_prediction"`
	DecisionScore    string `json:"decision_score"`
	ScoreThreshold   string `json:"score_threshold"`
	SINEMinThreshold string `json:"sine_min_threshold"`
}

type sineStageRecord struct {
	SequenceID    uint64 `json:"sequence_id"`
	AgentID       string `json:"agent_id"`
	EventID       string `json:"event_id"`
	PayloadSHA256 string `json:"payload_sha256"`
	Allowed       bool   `json:"allowed"`
	Skipped       bool   `json:"skipped"`
	Reason        string `json:"reason"`
}

type decisionStageContribution struct {
	Feature string `json:"feature"`
	Impact  string `json:"impact"`
	Value   string `json:"value"`
}

type decisionStageRecord struct {
	SequenceID      uint64                      `json:"sequence_id"`
	AgentID         string                      `json:"agent_id"`
	EventID         string                      `json:"event_id"`
	Timestamp       int64                       `json:"timestamp"`
	Decision        string                      `json:"decision"`
	SinePass        bool                        `json:"sine_pass"`
	Allowed         bool                        `json:"allowed"`
	Action          string                      `json:"action"`
	ModelPrediction string                      `json:"model_prediction"`
	DecisionScore   string                      `json:"decision_score"`
	Explanation     []decisionStageContribution `json:"explanation"`
}

type enforcementStageRecord struct {
	SequenceID    uint64 `json:"sequence_id"`
	AgentID       string `json:"agent_id"`
	EventID       string `json:"event_id"`
	ActionID      string `json:"action_id"`
	Target        string `json:"target"`
	Action        string `json:"action"`
	Allowed       bool   `json:"allowed"`
	DecisionScore string `json:"decision_score"`
	Timestamp     int64  `json:"timestamp"`
	Skipped       bool   `json:"skipped"`
	Reason        string `json:"reason"`
}

type finalStageRecord struct {
	InputHash       string `json:"input_hash"`
	IngestHash      string `json:"ingest_hash"`
	FeatureHash     string `json:"feature_hash"`
	ModelHash       string `json:"model_hash"`
	SINEHash        string `json:"sine_hash"`
	DecisionHash    string `json:"decision_hash"`
	EnforcementHash string `json:"enforcement_hash"`
}

var loadReplayRuntimeModel = ai.LoadRuntimeModelFromRoot

func loadReplayRuntimeModelForRoot(root string) (ai.RuntimeModel, error) {
	if override := strings.TrimSpace(os.Getenv(DefaultReplaySigningKeyEnv)); override != "" {
		return ai.LoadRuntimeModelFromRootWithSigningKeyPath(root, override)
	}
	return loadReplayRuntimeModel(root)
}

func RunFile(ctx context.Context, path string) (Result, error) {
	envelope, err := LoadEnvelope(path)
	if err != nil {
		return Result{}, err
	}
	return RunEnvelope(ctx, envelope)
}

func RunEnvelope(ctx context.Context, envelope Envelope) (Result, error) {
	if err := validateReplayEnvironment(envelope); err != nil {
		return Result{}, err
	}

	aiRoot, err := resolveReplayAIArtifactRoot()
	if err != nil {
		return Result{}, err
	}
	runtimeModel, err := loadReplayRuntimeModelForRoot(aiRoot)
	if err != nil {
		return Result{}, fmt.Errorf("load replay runtime model: %w", err)
	}
	detector, err := pipeline.NewDeterministicDetector(runtimeModel)
	if err != nil {
		return Result{}, fmt.Errorf("create replay detector: %w", err)
	}

	captureRaw, inputHash, err := marshalAndHash(envelope)
	if err != nil {
		return Result{}, fmt.Errorf("capture stage hash: %w", err)
	}

	ingestRecords := make([]ingestStageRecord, 0, len(envelope.Events))
	featureRecords := make([]featureStageRecord, 0, len(envelope.Events))
	modelRecords := make([]modelStageRecord, 0, len(envelope.Events))
	sineRecords := make([]sineStageRecord, 0, len(envelope.Events))
	decisionRecords := make([]decisionStageRecord, 0, len(envelope.Events))
	enforcementRecords := make([]enforcementStageRecord, 0, len(envelope.Events))

	for idx := range envelope.Events {
		ev, err := envelope.Events[idx].VerifiedTelemetry()
		if err != nil {
			return Result{}, fmt.Errorf("event %d: %w", idx, err)
		}
		ingestRecord, err := buildIngestStageRecord(ev)
		if err != nil {
			return Result{}, fmt.Errorf("event %d ingest stage: %w", idx, err)
		}
		ingestRecords = append(ingestRecords, ingestRecord)

		finding, trace, err := detector.EvaluateWithTrace(ev)
		if err != nil {
			return Result{}, fmt.Errorf("event %d evaluate: %w", idx, err)
		}

		featureRecords = append(featureRecords, buildFeatureStageRecord(ingestRecord, trace.Features))
		modelRecords = append(modelRecords, buildModelStageRecord(ingestRecord, trace, runtimeModel))
		sineRecords = append(sineRecords, buildSINEStageRecord(ingestRecord, trace))
		decisionRecord, err := buildDecisionStageRecord(ingestRecord, ev, trace)
		if err != nil {
			return Result{}, fmt.Errorf("event %d decision stage: %w", idx, err)
		}
		decisionRecords = append(decisionRecords, decisionRecord)

		enforcementRecord, err := buildEnforcementStageRecord(ingestRecord, ev, finding)
		if err != nil {
			return Result{}, fmt.Errorf("event %d enforcement stage: %w", idx, err)
		}
		enforcementRecords = append(enforcementRecords, enforcementRecord)
	}

	ingestRaw, ingestHash, err := marshalAndHash(ingestRecords)
	if err != nil {
		return Result{}, fmt.Errorf("ingest stage hash: %w", err)
	}
	featureRaw, featureHash, err := marshalAndHash(featureRecords)
	if err != nil {
		return Result{}, fmt.Errorf("feature stage hash: %w", err)
	}
	modelRaw, modelHash, err := marshalAndHash(modelRecords)
	if err != nil {
		return Result{}, fmt.Errorf("model stage hash: %w", err)
	}
	sineRaw, sineHash, err := marshalAndHash(sineRecords)
	if err != nil {
		return Result{}, fmt.Errorf("sine stage hash: %w", err)
	}
	decisionRaw, decisionHash, err := marshalAndHash(decisionRecords)
	if err != nil {
		return Result{}, fmt.Errorf("decision stage hash: %w", err)
	}
	enforcementRaw, enforcementHash, err := marshalAndHash(enforcementRecords)
	if err != nil {
		return Result{}, fmt.Errorf("enforcement stage hash: %w", err)
	}

	finalRecord := finalStageRecord{
		InputHash:       inputHash,
		IngestHash:      ingestHash,
		FeatureHash:     featureHash,
		ModelHash:       modelHash,
		SINEHash:        sineHash,
		DecisionHash:    decisionHash,
		EnforcementHash: enforcementHash,
	}
	finalRaw, finalHash, err := marshalAndHash(finalRecord)
	if err != nil {
		return Result{}, fmt.Errorf("final stage hash: %w", err)
	}

	stageHashes := StageHashes{
		Ingest:      ingestHash,
		Feature:     featureHash,
		Model:       modelHash,
		SINE:        sineHash,
		Decision:    decisionHash,
		Enforcement: enforcementHash,
		Final:       finalHash,
	}
	return Result{
		InputHash:   inputHash,
		OutputHash:  finalHash,
		StageHashes: stageHashes,
		StageArtifacts: StageArtifacts{
			Capture:     captureRaw,
			Ingest:      ingestRaw,
			Feature:     featureRaw,
			Model:       modelRaw,
			SINE:        sineRaw,
			Decision:    decisionRaw,
			Enforcement: enforcementRaw,
			Final:       finalRaw,
		},
	}, nil
}

func VerifyEnvelope(ctx context.Context, envelope Envelope) (Result, Result, error) {
	run1, err := RunEnvelope(ctx, envelope)
	if err != nil {
		return Result{}, Result{}, err
	}
	run2, err := RunEnvelope(ctx, envelope)
	if err != nil {
		return Result{}, Result{}, err
	}
	if stage, expectedHash, actualHash, ok := FirstStageMismatch(run1.StageHashes, run2.StageHashes); ok {
		return run1, run2, fmt.Errorf(
			"deterministic replay mismatch\nstage=%s\nexpected_hash=%s\nactual_hash=%s",
			stage,
			expectedHash,
			actualHash,
		)
	}
	if run1.OutputHash != run2.OutputHash {
		return run1, run2, fmt.Errorf(
			"deterministic replay mismatch\nstage=%s\nexpected_hash=%s\nactual_hash=%s",
			stageFinal,
			run1.OutputHash,
			run2.OutputHash,
		)
	}
	return run1, run2, nil
}

func FirstStageMismatch(expected, actual StageHashes) (string, string, string, bool) {
	for _, pair := range []struct {
		stage    string
		expected string
		actual   string
	}{
		{stage: stageIngest, expected: expected.Ingest, actual: actual.Ingest},
		{stage: stageFeature, expected: expected.Feature, actual: actual.Feature},
		{stage: stageModel, expected: expected.Model, actual: actual.Model},
		{stage: stageSINE, expected: expected.SINE, actual: actual.SINE},
		{stage: stageDecision, expected: expected.Decision, actual: actual.Decision},
		{stage: stageEnforcement, expected: expected.Enforcement, actual: actual.Enforcement},
		{stage: stageFinal, expected: expected.Final, actual: actual.Final},
	} {
		if pair.expected != pair.actual {
			return pair.stage, pair.expected, pair.actual, true
		}
	}
	return "", "", "", false
}

func DiffStageHashes(run1, run2 StageHashes) string {
	stage, expectedHash, actualHash, ok := FirstStageMismatch(run1, run2)
	if !ok {
		return ""
	}
	return fmt.Sprintf("stage=%s expected_hash=%s actual_hash=%s", stage, expectedHash, actualHash)
}

func buildIngestStageRecord(ev *ingest.VerifiedTelemetry) (ingestStageRecord, error) {
	view, err := ingest.ParseTelemetryV1(ev.Payload)
	if err != nil {
		return ingestStageRecord{}, err
	}
	eventType, err := ingest.DBEventType(view.EventTypeCode)
	if err != nil {
		return ingestStageRecord{}, err
	}
	return ingestStageRecord{
		SequenceID:           view.LogicalClock,
		TimestampUnixNano:    view.TimestampUnixNano,
		DroppedPacketsBefore: ev.DroppedCount,
		AgentID:              view.AgentID.String(),
		EventID:              view.EventID.String(),
		EventType:            eventType,
		PayloadBase64:        base64.StdEncoding.EncodeToString(ev.Payload),
		PayloadSHA256:        sha256Hex(ev.Payload),
		SignatureBase64:      base64.StdEncoding.EncodeToString(ev.AgentSignature),
		SignatureSHA256:      sha256Hex(ev.AgentSignature),
	}, nil
}

func buildFeatureStageRecord(ingestRecord ingestStageRecord, features pipeline.DetectionFeatureVector) featureStageRecord {
	vector := make([]string, 0, len(features.Vector))
	for _, value := range features.Vector {
		vector = append(vector, formatProbability(value))
	}
	return featureStageRecord{
		SequenceID:               ingestRecord.SequenceID,
		AgentID:                  ingestRecord.AgentID,
		EventID:                  ingestRecord.EventID,
		EventTypeNorm:            formatProbability(features.EventTypeNorm),
		TimeDeltaNorm:            formatProbability(features.TimeDeltaNorm),
		ProcessIDNorm:            formatProbability(features.ProcessIDNorm),
		EntropyScore:             formatEntropy(features.EntropyScore),
		BurstScore:               formatProbability(features.BurstScore),
		ChainDepthNorm:           formatProbability(features.ChainDepthNorm),
		ExecutionFrequencyNorm:   formatProbability(features.ExecutionFrequencyNorm),
		PrivilegeLevelNorm:       formatProbability(features.PrivilegeLevelNorm),
		DroppedPacketsNorm:       formatProbability(features.DroppedPacketsNorm),
		WindowEntropyMean:        formatEntropy(features.WindowEntropyMean),
		WindowBurstMean:          formatProbability(features.WindowBurstMean),
		WindowProcessAnomalyMean: formatProbability(features.WindowProcessAnomalyMean),
		WindowExecutionFreqMean:  formatProbability(features.WindowExecutionFrequencyMean),
		WindowTimeDeltaMean:      formatProbability(features.WindowTimeDeltaMean),
		WindowPrivilegeLevelMean: formatProbability(features.WindowPrivilegeLevelMean),
		ProcessAnomaly:           formatProbability(features.ProcessAnomaly),
		Vector:                   vector,
	}
}

func buildModelStageRecord(ingestRecord ingestStageRecord, trace pipeline.DetectionTrace, model ai.RuntimeModel) modelStageRecord {
	return modelStageRecord{
		SequenceID:       ingestRecord.SequenceID,
		AgentID:          ingestRecord.AgentID,
		EventID:          ingestRecord.EventID,
		ModelPrediction:  formatProbability(trace.ModelPrediction),
		DecisionScore:    formatProbability(trace.Score),
		ScoreThreshold:   formatProbability(model.ScoreThreshold),
		SINEMinThreshold: formatProbability(model.SineMinThreshold),
	}
}

func buildSINEStageRecord(ingestRecord ingestStageRecord, trace pipeline.DetectionTrace) sineStageRecord {
	record := sineStageRecord{
		SequenceID:    ingestRecord.SequenceID,
		AgentID:       ingestRecord.AgentID,
		EventID:       ingestRecord.EventID,
		PayloadSHA256: ingestRecord.PayloadSHA256,
	}
	if !trace.SinePass {
		record.Skipped = true
		record.Reason = "below_sine_threshold"
		return record
	}
	record.Allowed = true
	record.Reason = "deterministic_replay_allow"
	return record
}

func buildDecisionStageRecord(ingestRecord ingestStageRecord, ev *ingest.VerifiedTelemetry, trace pipeline.DetectionTrace) (decisionStageRecord, error) {
	view, err := ingest.ParseTelemetryV1(ev.Payload)
	if err != nil {
		return decisionStageRecord{}, err
	}
	explanation := make([]decisionStageContribution, 0, len(trace.Explanation))
	for _, item := range trace.Explanation {
		explanation = append(explanation, decisionStageContribution{
			Feature: item.Feature,
			Impact:  formatProbability(item.Impact),
			Value:   formatProbability(item.Value),
		})
	}
	return decisionStageRecord{
		SequenceID:      ingestRecord.SequenceID,
		AgentID:         ingestRecord.AgentID,
		EventID:         ingestRecord.EventID,
		Timestamp:       ingest.TimestampUTC(view.TimestampUnixNano).Unix(),
		Decision:        trace.Decision,
		SinePass:        trace.SinePass,
		Allowed:         trace.PolicyDecision.Allowed,
		Action:          trace.PolicyDecision.Action,
		ModelPrediction: formatProbability(trace.ModelPrediction),
		DecisionScore:   formatProbability(trace.Score),
		Explanation:     explanation,
	}, nil
}

func buildEnforcementStageRecord(ingestRecord ingestStageRecord, ev *ingest.VerifiedTelemetry, finding pipeline.DetectionEvent) (enforcementStageRecord, error) {
	view, err := ingest.ParseTelemetryV1(ev.Payload)
	if err != nil {
		return enforcementStageRecord{}, err
	}
	dispatchReq, err := enforcement.BuildDispatchRequestWithResolver(
		view.AgentID.String(),
		view.EventID.String(),
		int64(view.LogicalClock),
		ingest.TimestampUTC(view.TimestampUnixNano).Unix(),
		ev.Payload,
		finding.Confidence,
		finding.PolicyDecision,
		replayProcessBindingResolver,
	)
	if err != nil {
		return enforcementStageRecord{}, err
	}
	record := enforcementStageRecord{
		SequenceID:    ingestRecord.SequenceID,
		AgentID:       ingestRecord.AgentID,
		EventID:       ingestRecord.EventID,
		Target:        dispatchReq.Target,
		Action:        finding.PolicyDecision.Action,
		Allowed:       finding.PolicyDecision.Allowed,
		DecisionScore: formatProbability(finding.Confidence),
		Timestamp:     ingest.TimestampUTC(view.TimestampUnixNano).Unix(),
	}
	if dispatchReq.Command == nil {
		record.Skipped = true
		record.Reason = "no_enforcement_action"
		return record, nil
	}
	record.ActionID = dispatchReq.Command.GetActionId()
	record.Reason = "dispatch_built"
	return record, nil
}

func replayProcessBindingResolver(view ingest.TelemetryV1View) (enforcement.ProcessBinding, error) {
	return enforcement.ProcessBinding{
		ProcessHash:    sha256Hex(view.ProcessHash[:]),
		ExecutablePath: fmt.Sprintf("/replay/pid/%d/%x", view.AuxPID, view.ProcessHash[:4]),
		KernelTag:      fmt.Sprintf("replay|%d|%d", view.EventTypeCode, view.LogicalClock),
	}, nil
}

func resolveReplayAIArtifactRoot() (string, error) {
	if raw := strings.TrimSpace(os.Getenv("RANSOMEYE_AI_ROOT")); raw != "" {
		return filepath.Clean(raw), nil
	}
	root, err := findRepoRoot()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "ml"), nil
}

func validateReplayEnvironment(envelope Envelope) error {
	current, err := ResolveRuntimeMetadata()
	if err != nil {
		return fmt.Errorf("resolve replay environment: %w", err)
	}
	if current.ConfigHash != envelope.ConfigHash {
		return fmt.Errorf("config mismatch: current=%s replay=%s", current.ConfigHash, envelope.ConfigHash)
	}
	if current.ModelHash != envelope.ModelHash {
		return fmt.Errorf("model mismatch: current=%s replay=%s", current.ModelHash, envelope.ModelHash)
	}
	if current.FeatureVersion != envelope.FeatureVersion {
		return fmt.Errorf(
			"feature version mismatch: current=%s replay=%s",
			current.FeatureVersion,
			envelope.FeatureVersion,
		)
	}
	if current.PRDHash != envelope.PRDHash {
		return fmt.Errorf("PRD mismatch: current=%s replay=%s", current.PRDHash, envelope.PRDHash)
	}
	return nil
}

func marshalAndHash(value any) (json.RawMessage, string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(raw)
	return append(json.RawMessage(nil), raw...), hex.EncodeToString(sum[:]), nil
}

func sha256Hex(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func formatEntropy(value float64) string {
	return formatFixed(value, 6)
}

func formatProbability(value float64) string {
	return formatFixed(value, 12)
}

func formatFixed(value float64, decimals int) string {
	return strconv.FormatFloat(round(value, decimals), 'f', decimals, 64)
}

func round(value float64, decimals int) float64 {
	if decimals < 0 {
		return value
	}
	scale := math.Pow(10, float64(decimals))
	return math.Round(value*scale) / scale
}
