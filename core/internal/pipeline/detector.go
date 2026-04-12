package pipeline

import (
	"crypto/sha256"
	"fmt"
	"math"
	"sort"
	"sync"

	"ransomeye/core/internal/ai"
	"ransomeye/core/internal/ingest"
	"ransomeye/core/internal/policy"
)

const (
	maxProcessID      = 4095
	maxChainDepth     = 6
	maxPrivilegeLevel = 3
	maxDroppedPackets = 8
)

var privilegeLevelEnum = map[string]int{
	"USER_EVENT":      0,
	"FILE_EVENT":      1,
	"PROCESS_EVENT":   2,
	"NETWORK_EVENT":   2,
	"DECEPTION_EVENT": 3,
}

type Detector interface {
	Evaluate(ev *ingest.VerifiedTelemetry) (DetectionEvent, error)
}

type DetailedDetector interface {
	EvaluateWithTrace(ev *ingest.VerifiedTelemetry) (DetectionEvent, DetectionTrace, error)
}

type DeterministicDetector struct {
	model        ai.RuntimeModel
	policyEngine policy.DecisionEvaluator
	mu           sync.Mutex
	window       []sequenceMetrics
	prevTS       uint64
	hasPrevTS    bool
}

type DetectionFeatureVector struct {
	EventTypeNorm                float64
	TimeDeltaNorm                float64
	ProcessIDNorm                float64
	EntropyScore                 float64
	BurstScore                   float64
	ChainDepthNorm               float64
	ExecutionFrequencyNorm       float64
	PrivilegeLevelNorm           float64
	DroppedPacketsNorm           float64
	WindowEntropyMean            float64
	WindowBurstMean              float64
	WindowProcessAnomalyMean     float64
	WindowExecutionFrequencyMean float64
	WindowTimeDeltaMean          float64
	WindowPrivilegeLevelMean     float64
	ProcessAnomaly               float64
	Vector                       []float64
}

type DetectionTrace struct {
	Features        DetectionFeatureVector
	ModelPrediction float64
	Score           float64
	Decision        string
	SinePass        bool
	Explanation     []DetectionContribution
	PolicyDecision  policy.EnforcementDecision
}

type sequenceMetrics struct {
	ProcessID              int
	EntropyScore           float64
	BurstScore             float64
	ChainDepthNorm         float64
	ExecutionFrequencyNorm float64
	PrivilegeLevelNorm     float64
	DroppedPacketsNorm     float64
	TimeDeltaNorm          float64
	ProcessAnomaly         float64
}

func NewDeterministicDetector(model ai.RuntimeModel) (*DeterministicDetector, error) {
	if model.VectorLength <= 0 {
		return nil, fmt.Errorf("detector vector_length must be positive")
	}
	if model.SequenceWindowSize <= 0 {
		return nil, fmt.Errorf("detector sequence_window_size must be positive")
	}
	if len(model.Weights) != model.VectorLength {
		return nil, fmt.Errorf("detector weights length mismatch: got %d want %d", len(model.Weights), model.VectorLength)
	}
	policyConfig := policy.DefaultEnforcementPolicy()
	policyConfig.Threshold = model.ScoreThreshold
	return &DeterministicDetector{
		model:        model,
		policyEngine: policy.NewEngine(policyConfig, false),
	}, nil
}

func (d *DeterministicDetector) SetPolicyEngine(engine policy.DecisionEvaluator) {
	if d == nil || engine == nil {
		return
	}
	d.mu.Lock()
	d.policyEngine = engine
	d.mu.Unlock()
}

func (d *DeterministicDetector) Evaluate(ev *ingest.VerifiedTelemetry) (DetectionEvent, error) {
	finding, _, err := d.evaluate(ev)
	return finding, err
}

func (d *DeterministicDetector) EvaluateWithTrace(ev *ingest.VerifiedTelemetry) (DetectionEvent, DetectionTrace, error) {
	return d.evaluate(ev)
}

func (d *DeterministicDetector) evaluate(ev *ingest.VerifiedTelemetry) (DetectionEvent, DetectionTrace, error) {
	if d == nil {
		return DetectionEvent{}, DetectionTrace{}, fmt.Errorf("nil detector")
	}
	if ev == nil {
		return DetectionEvent{}, DetectionTrace{}, fmt.Errorf("nil telemetry")
	}
	view, err := ingest.ParseTelemetryV1(ev.Payload)
	if err != nil {
		return DetectionEvent{}, DetectionTrace{}, err
	}
	eventType, err := ingest.DBEventType(view.EventTypeCode)
	if err != nil {
		return DetectionEvent{}, DetectionTrace{}, err
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	processID := processIDFromPayload(ev.Payload)
	timeDelta := uint64(0)
	if d.hasPrevTS && view.TimestampUnixNano >= d.prevTS {
		timeDelta = view.TimestampUnixNano - d.prevTS
	}
	entropyScore := round64(normalizeEntropy(shannonEntropy(ev.Payload)))
	burstScore := round64(boolScore(d.hasPrevTS && timeDelta < uint64(d.model.TemporalBurstThresholdNS)))
	chainDepthNorm := round64(safeRatio(float64(chainDepthFromPayload(ev.Payload)), float64(maxChainDepth)))
	execFrequencyNorm := round64(safeRatio(float64(executionFrequency(d.window, processID, d.model.SequenceWindowSize)), float64(d.model.SequenceWindowSize)))
	privilegeLevelNorm := round64(safeRatio(float64(privilegeLevelEnum[eventType]), float64(maxPrivilegeLevel)))
	droppedPacketsNorm := round64(safeRatio(float64(minUint64ByInt(ev.DroppedCount, maxDroppedPackets)), float64(maxDroppedPackets)))
	timeDeltaNorm := round64(safeRatio(float64(minUint64ByUint64(timeDelta, uint64(d.model.MaxTimeDeltaNS))), float64(d.model.MaxTimeDeltaNS)))
	processAnomaly := round64((chainDepthNorm + execFrequencyNorm + privilegeLevelNorm + droppedPacketsNorm) / 4.0)

	metrics := sequenceMetrics{
		ProcessID:              processID,
		EntropyScore:           entropyScore,
		BurstScore:             burstScore,
		ChainDepthNorm:         chainDepthNorm,
		ExecutionFrequencyNorm: execFrequencyNorm,
		PrivilegeLevelNorm:     privilegeLevelNorm,
		DroppedPacketsNorm:     droppedPacketsNorm,
		TimeDeltaNorm:          timeDeltaNorm,
		ProcessAnomaly:         processAnomaly,
	}
	currentWindow := append(append([]sequenceMetrics(nil), d.window...), metrics)
	vector := []float64{
		round64(safeRatio(float64(view.EventTypeCode), 5.0)),
		timeDeltaNorm,
		round64(safeRatio(float64(processID), float64(maxProcessID))),
		entropyScore,
		burstScore,
		chainDepthNorm,
		execFrequencyNorm,
		privilegeLevelNorm,
		droppedPacketsNorm,
		windowMean(currentWindow, func(item sequenceMetrics) float64 { return item.EntropyScore }),
		windowMean(currentWindow, func(item sequenceMetrics) float64 { return item.BurstScore }),
		windowMean(currentWindow, func(item sequenceMetrics) float64 { return item.ProcessAnomaly }),
		windowMean(currentWindow, func(item sequenceMetrics) float64 { return item.ExecutionFrequencyNorm }),
		windowMean(currentWindow, func(item sequenceMetrics) float64 { return item.TimeDeltaNorm }),
		windowMean(currentWindow, func(item sequenceMetrics) float64 { return item.PrivilegeLevelNorm }),
	}
	if len(vector) != d.model.VectorLength {
		return DetectionEvent{}, DetectionTrace{}, fmt.Errorf("detector vector length mismatch: got %d want %d", len(vector), d.model.VectorLength)
	}

	modelPrediction := logisticPrediction(vector, d.model.Weights, d.model.Bias)
	score := fuseSignals(d.model, modelPrediction, entropyScore, burstScore, processAnomaly)
	classification := decisionForScore(score, d.model.ScoreThreshold)
	explanation := explanationForScore(d.model, modelPrediction, entropyScore, burstScore, processAnomaly, score)
	policyDecision := policy.EnforcementDecision{Action: policy.ActionNone, Allowed: false}
	if d.policyEngine != nil {
		policyDecision = d.policyEngine.Evaluate(policy.DetectionInput{
			Score:          score,
			Classification: classification,
			Explanation:    toPolicyExplanation(explanation),
		})
	}
	finding := DetectionEvent{
		Timestamp:       ingest.TimestampUTC(view.TimestampUnixNano),
		Confidence:      score,
		Decision:        classification,
		ModelPrediction: modelPrediction,
		EntropyScore:    entropyScore,
		BurstScore:      burstScore,
		ProcessAnomaly:  processAnomaly,
		SinePass:        score > d.model.SineMinThreshold,
		Explanation:     explanation,
		PolicyDecision:  policyDecision,
	}
	trace := DetectionTrace{
		Features: DetectionFeatureVector{
			EventTypeNorm:                vector[0],
			TimeDeltaNorm:                vector[1],
			ProcessIDNorm:                vector[2],
			EntropyScore:                 vector[3],
			BurstScore:                   vector[4],
			ChainDepthNorm:               vector[5],
			ExecutionFrequencyNorm:       vector[6],
			PrivilegeLevelNorm:           vector[7],
			DroppedPacketsNorm:           vector[8],
			WindowEntropyMean:            vector[9],
			WindowBurstMean:              vector[10],
			WindowProcessAnomalyMean:     vector[11],
			WindowExecutionFrequencyMean: vector[12],
			WindowTimeDeltaMean:          vector[13],
			WindowPrivilegeLevelMean:     vector[14],
			ProcessAnomaly:               processAnomaly,
			Vector:                       append([]float64(nil), vector...),
		},
		ModelPrediction: modelPrediction,
		Score:           score,
		Decision:        classification,
		SinePass:        finding.SinePass,
		Explanation:     cloneDetectionContributions(explanation),
		PolicyDecision:  policyDecision,
	}

	d.window = append(d.window, metrics)
	if len(d.window) > d.model.SequenceWindowSize-1 {
		d.window = d.window[1:]
	}
	d.prevTS = view.TimestampUnixNano
	d.hasPrevTS = true
	return finding, trace, nil
}

func cloneDetectionContributions(items []DetectionContribution) []DetectionContribution {
	if len(items) == 0 {
		return nil
	}
	out := make([]DetectionContribution, 0, len(items))
	for _, item := range items {
		out = append(out, DetectionContribution{
			Feature: item.Feature,
			Impact:  item.Impact,
			Value:   item.Value,
		})
	}
	return out
}

func shannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var counts [256]int
	for _, value := range data {
		counts[value]++
	}
	total := float64(len(data))
	entropy := 0.0
	for _, count := range counts {
		if count == 0 {
			continue
		}
		probability := float64(count) / total
		entropy -= probability * math.Log2(probability)
	}
	return roundN(entropy, 6)
}

func normalizeEntropy(entropy float64) float64 {
	return safeRatio(entropy, 8.0)
}

func logisticPrediction(vector []float64, weights []float64, bias float64) float64 {
	total := round64(bias)
	for idx, value := range vector {
		total = round64(total + round64(weights[idx]*value))
	}
	return sigmoid(total)
}

func sigmoid(value float64) float64 {
	if value >= 0 {
		exponent := math.Exp(-value)
		return round64(1.0 / (1.0 + exponent))
	}
	exponent := math.Exp(value)
	return round64(exponent / (1.0 + exponent))
}

func fuseSignals(model ai.RuntimeModel, modelPrediction float64, entropyScore float64, burstScore float64, processAnomaly float64) float64 {
	return round64(
		model.FusionWeights.ModelPrediction*modelPrediction +
			model.FusionWeights.EntropyScore*entropyScore +
			model.FusionWeights.BurstScore*burstScore +
			model.FusionWeights.ProcessAnomaly*processAnomaly,
	)
}

func explanationForScore(model ai.RuntimeModel, modelPrediction float64, entropyScore float64, burstScore float64, processAnomaly float64, score float64) []DetectionContribution {
	items := []DetectionContribution{
		{Feature: "model_prediction", Impact: round64(score - fuseSignals(model, 0, entropyScore, burstScore, processAnomaly)), Value: round64(modelPrediction)},
		{Feature: "entropy_score", Impact: round64(score - fuseSignals(model, modelPrediction, 0, burstScore, processAnomaly)), Value: round64(entropyScore)},
		{Feature: "burst_score", Impact: round64(score - fuseSignals(model, modelPrediction, entropyScore, 0, processAnomaly)), Value: round64(burstScore)},
		{Feature: "process_anomaly", Impact: round64(score - fuseSignals(model, modelPrediction, entropyScore, burstScore, 0)), Value: round64(processAnomaly)},
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Impact == items[j].Impact {
			return items[i].Feature < items[j].Feature
		}
		return items[i].Impact > items[j].Impact
	})
	return items
}

func toPolicyExplanation(items []DetectionContribution) []policy.ExplanationSignal {
	out := make([]policy.ExplanationSignal, 0, len(items))
	for _, item := range items {
		out = append(out, policy.ExplanationSignal{
			Feature: item.Feature,
			Impact:  item.Impact,
			Value:   item.Value,
		})
	}
	return out
}

func decisionForScore(score float64, threshold float64) string {
	if score > threshold {
		return "malicious"
	}
	return "benign"
}

func processIDFromPayload(payload []byte) int {
	sum := sha256.Sum256(payload)
	value := int(sum[0])<<8 | int(sum[1])
	return 1 + (value % maxProcessID)
}

func chainDepthFromPayload(payload []byte) int {
	sum := sha256.Sum256(payload)
	return 1 + (int(sum[2]) % maxChainDepth)
}

func executionFrequency(window []sequenceMetrics, processID int, maxWindow int) int {
	count := 1
	for _, item := range window {
		if item.ProcessID == processID {
			count++
		}
	}
	if count > maxWindow {
		return maxWindow
	}
	return count
}

func windowMean(window []sequenceMetrics, fn func(sequenceMetrics) float64) float64 {
	total := 0.0
	for _, item := range window {
		total = round64(total + fn(item))
	}
	return round64(total / float64(len(window)))
}

func safeRatio(numerator float64, denominator float64) float64 {
	if denominator == 0 {
		return 0
	}
	return numerator / denominator
}

func round64(value float64) float64 {
	return roundN(value, 8)
}

func roundN(value float64, decimals int) float64 {
	scale := math.Pow(10, float64(decimals))
	return math.Round(value*scale) / scale
}

func boolScore(value bool) float64 {
	if value {
		return 1
	}
	return 0
}

func minUint64ByInt(value uint64, maxValue int) uint64 {
	if value > uint64(maxValue) {
		return uint64(maxValue)
	}
	return value
}

func minUint64ByUint64(value uint64, maxValue uint64) uint64 {
	if value > maxValue {
		return maxValue
	}
	return value
}
