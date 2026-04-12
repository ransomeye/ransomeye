package ai

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	corecrypto "ransomeye/core/internal/crypto"
)

type FusionWeights struct {
	ModelPrediction float64 `json:"model_prediction"`
	EntropyScore    float64 `json:"entropy_score"`
	BurstScore      float64 `json:"burst_score"`
	ProcessAnomaly  float64 `json:"process_anomaly"`
}

type RuntimeModel struct {
	Identity                 ModelIdentity
	Algorithm                string
	Bias                     float64
	VectorLength             int
	Weights                  []float64
	FeatureNames             []string
	Explainability           string
	FusionVersion            string
	FusionWeights            FusionWeights
	MaxTimeDeltaNS           int64
	SequenceWindowSize       int
	ScoreThreshold           float64
	SineMinThreshold         float64
	TemporalBurstThresholdNS int64
}

type runtimeModelMetadata struct {
	Algorithm                string        `json:"algorithm"`
	ModelID                  string        `json:"model_id"`
	ModelHash                string        `json:"model_hash"`
	DatasetHash              string        `json:"dataset_hash"`
	DatasetSchemaVersion     string        `json:"dataset_schema_version"`
	FeatureVersion           string        `json:"feature_version"`
	CreatedAt                string        `json:"created_at"`
	VectorLength             int           `json:"vector_length"`
	FeatureNames             []string      `json:"feature_names"`
	Explainability           string        `json:"explainability"`
	FusionVersion            string        `json:"fusion_version"`
	FusionWeights            FusionWeights `json:"fusion_weights"`
	MaxTimeDeltaNS           int64         `json:"max_time_delta_ns"`
	SequenceWindowSize       int           `json:"sequence_window_size"`
	ScoreThreshold           float64       `json:"score_threshold"`
	SineMinThreshold         float64       `json:"sine_min_threshold"`
	TemporalBurstThresholdNS int64         `json:"temporal_burst_threshold_ns"`
}

func LoadRuntimeModel() (RuntimeModel, error) {
	return LoadRuntimeModelFromRoot(resolveAIInstallRoot())
}

func LoadRuntimeModelFromRoot(root string) (RuntimeModel, error) {
	return LoadRuntimeModelFromRootWithSigningKeyPath(root, corecrypto.WormSigningKeyPath)
}

func LoadRuntimeModelFromRootWithSigningKeyPath(root string, signingKeyPath string) (RuntimeModel, error) {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return RuntimeModel{}, fmt.Errorf("ai root: %w", err)
	}
	rootAbs = filepath.Clean(rootAbs)

	identity, err := loadVerifiedModelIdentityWithSigningKeyPath(rootAbs, signingKeyPath)
	if err != nil {
		return RuntimeModel{}, err
	}
	paths := resolveModelArtifactPaths(rootAbs)
	metadata, err := loadRuntimeModelMetadata(paths.metadataPath)
	if err != nil {
		return RuntimeModel{}, err
	}
	algorithm, bias, vectorLength, weights, err := parseRuntimeModelBin(paths.modelBinPath)
	if err != nil {
		return RuntimeModel{}, err
	}

	if metadata.ModelID != identity.ModelID {
		return RuntimeModel{}, fmt.Errorf("runtime metadata model_id mismatch: metadata=%s identity=%s", metadata.ModelID, identity.ModelID)
	}
	if metadata.ModelHash != identity.ModelHash {
		return RuntimeModel{}, fmt.Errorf("runtime metadata model_hash mismatch: metadata=%s identity=%s", metadata.ModelHash, identity.ModelHash)
	}
	if metadata.DatasetHash != identity.DatasetHash {
		return RuntimeModel{}, fmt.Errorf("runtime metadata dataset_hash mismatch: metadata=%s identity=%s", metadata.DatasetHash, identity.DatasetHash)
	}
	if metadata.DatasetSchemaVersion != identity.DatasetSchemaVersion {
		return RuntimeModel{}, fmt.Errorf(
			"runtime metadata dataset_schema_version mismatch: metadata=%s identity=%s",
			metadata.DatasetSchemaVersion,
			identity.DatasetSchemaVersion,
		)
	}
	if metadata.FeatureVersion != identity.FeatureVersion {
		return RuntimeModel{}, fmt.Errorf(
			"runtime metadata feature_version mismatch: metadata=%s identity=%s",
			metadata.FeatureVersion,
			identity.FeatureVersion,
		)
	}
	if metadata.CreatedAt != identity.CreatedAt {
		return RuntimeModel{}, fmt.Errorf("runtime metadata created_at mismatch: metadata=%s identity=%s", metadata.CreatedAt, identity.CreatedAt)
	}
	if metadata.VectorLength != vectorLength {
		return RuntimeModel{}, fmt.Errorf("runtime vector_length mismatch: metadata=%d model.bin=%d", metadata.VectorLength, vectorLength)
	}
	if len(weights) != vectorLength {
		return RuntimeModel{}, fmt.Errorf("runtime weights length mismatch: weights=%d vector_length=%d", len(weights), vectorLength)
	}
	if len(metadata.FeatureNames) != vectorLength {
		return RuntimeModel{}, fmt.Errorf("runtime feature_names length mismatch: feature_names=%d vector_length=%d", len(metadata.FeatureNames), vectorLength)
	}

	return RuntimeModel{
		Identity:                 identity,
		Algorithm:                algorithm,
		Bias:                     bias,
		VectorLength:             vectorLength,
		Weights:                  weights,
		FeatureNames:             metadata.FeatureNames,
		Explainability:           metadata.Explainability,
		FusionVersion:            metadata.FusionVersion,
		FusionWeights:            metadata.FusionWeights,
		MaxTimeDeltaNS:           metadata.MaxTimeDeltaNS,
		SequenceWindowSize:       metadata.SequenceWindowSize,
		ScoreThreshold:           metadata.ScoreThreshold,
		SineMinThreshold:         metadata.SineMinThreshold,
		TemporalBurstThresholdNS: metadata.TemporalBurstThresholdNS,
	}, nil
}

func loadRuntimeModelMetadata(path string) (runtimeModelMetadata, error) {
	var metadata runtimeModelMetadata
	if err := loadJSONObject(path, &metadata); err != nil {
		return runtimeModelMetadata{}, fmt.Errorf("runtime model metadata: %w", err)
	}
	if _, err := normalizeRequiredText(metadata.Algorithm, "algorithm"); err != nil {
		return runtimeModelMetadata{}, err
	}
	if _, err := normalizeRequiredText(metadata.ModelID, "model_id"); err != nil {
		return runtimeModelMetadata{}, err
	}
	if _, err := normalizeHexHash(metadata.ModelHash, "model_hash"); err != nil {
		return runtimeModelMetadata{}, err
	}
	if _, err := normalizeHexHash(metadata.DatasetHash, "dataset_hash"); err != nil {
		return runtimeModelMetadata{}, err
	}
	if _, err := normalizeRequiredText(metadata.DatasetSchemaVersion, "dataset_schema_version"); err != nil {
		return runtimeModelMetadata{}, err
	}
	if _, err := normalizeRequiredText(metadata.FeatureVersion, "feature_version"); err != nil {
		return runtimeModelMetadata{}, err
	}
	if _, err := normalizeRequiredText(metadata.CreatedAt, "created_at"); err != nil {
		return runtimeModelMetadata{}, err
	}
	if metadata.VectorLength <= 0 {
		return runtimeModelMetadata{}, fmt.Errorf("vector_length must be positive")
	}
	if len(metadata.FeatureNames) == 0 {
		return runtimeModelMetadata{}, fmt.Errorf("feature_names must be non-empty")
	}
	for idx, name := range metadata.FeatureNames {
		if _, err := normalizeRequiredText(name, fmt.Sprintf("feature_names[%d]", idx)); err != nil {
			return runtimeModelMetadata{}, err
		}
	}
	if _, err := normalizeRequiredText(metadata.Explainability, "explainability"); err != nil {
		return runtimeModelMetadata{}, err
	}
	if _, err := normalizeRequiredText(metadata.FusionVersion, "fusion_version"); err != nil {
		return runtimeModelMetadata{}, err
	}
	if metadata.MaxTimeDeltaNS <= 0 {
		return runtimeModelMetadata{}, fmt.Errorf("max_time_delta_ns must be positive")
	}
	if metadata.SequenceWindowSize <= 0 {
		return runtimeModelMetadata{}, fmt.Errorf("sequence_window_size must be positive")
	}
	if metadata.TemporalBurstThresholdNS <= 0 {
		return runtimeModelMetadata{}, fmt.Errorf("temporal_burst_threshold_ns must be positive")
	}
	if err := validateThreshold(metadata.ScoreThreshold, "score_threshold"); err != nil {
		return runtimeModelMetadata{}, err
	}
	if err := validateThreshold(metadata.SineMinThreshold, "sine_min_threshold"); err != nil {
		return runtimeModelMetadata{}, err
	}
	if err := validateThreshold(metadata.FusionWeights.ModelPrediction, "fusion_weights.model_prediction"); err != nil {
		return runtimeModelMetadata{}, err
	}
	if err := validateThreshold(metadata.FusionWeights.EntropyScore, "fusion_weights.entropy_score"); err != nil {
		return runtimeModelMetadata{}, err
	}
	if err := validateThreshold(metadata.FusionWeights.BurstScore, "fusion_weights.burst_score"); err != nil {
		return runtimeModelMetadata{}, err
	}
	if err := validateThreshold(metadata.FusionWeights.ProcessAnomaly, "fusion_weights.process_anomaly"); err != nil {
		return runtimeModelMetadata{}, err
	}
	return metadata, nil
}

func parseRuntimeModelBin(path string) (string, float64, int, []float64, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", 0, 0, nil, fmt.Errorf("runtime model.bin: %w", err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	fields := make(map[string]string, len(lines))
	for _, line := range lines {
		parts := strings.SplitN(strings.TrimSpace(line), "=", 2)
		if len(parts) != 2 {
			return "", 0, 0, nil, fmt.Errorf("runtime model.bin: malformed line %q", line)
		}
		fields[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
	}
	if len(fields) != 4 {
		return "", 0, 0, nil, fmt.Errorf("runtime model.bin: expected 4 fields, got %d", len(fields))
	}

	algorithm, err := normalizeRequiredText(fields["algorithm"], "algorithm")
	if err != nil {
		return "", 0, 0, nil, err
	}
	vectorLength, err := strconv.Atoi(fields["vector_length"])
	if err != nil || vectorLength <= 0 {
		return "", 0, 0, nil, fmt.Errorf("vector_length: %w", err)
	}
	bias, err := strconv.ParseFloat(fields["bias"], 64)
	if err != nil {
		return "", 0, 0, nil, fmt.Errorf("bias: %w", err)
	}
	weightParts := strings.Split(fields["weights"], ",")
	if len(weightParts) != vectorLength {
		return "", 0, 0, nil, fmt.Errorf("weights length mismatch: got %d want %d", len(weightParts), vectorLength)
	}
	weights := make([]float64, 0, len(weightParts))
	for idx, part := range weightParts {
		value, parseErr := strconv.ParseFloat(strings.TrimSpace(part), 64)
		if parseErr != nil {
			return "", 0, 0, nil, fmt.Errorf("weights[%d]: %w", idx, parseErr)
		}
		weights = append(weights, value)
	}
	return algorithm, bias, vectorLength, weights, nil
}

func validateThreshold(value float64, fieldName string) error {
	if value < 0 || value > 1 {
		return fmt.Errorf("%s must be within [0,1]", fieldName)
	}
	return nil
}
