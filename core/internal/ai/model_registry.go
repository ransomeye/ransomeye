package ai

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	corecrypto "ransomeye/core/internal/crypto"
)

const (
	DefaultAIModelBinPathEnv         = "RANSOMEYE_AI_MODEL_BIN_PATH"
	DefaultAIModelMetadataPathEnv    = "RANSOMEYE_AI_MODEL_METADATA_PATH"
	DefaultAIModelSignaturePathEnv   = "RANSOMEYE_AI_MODEL_SIGNATURE_PATH"
	DefaultAIModelRegistryPathEnv    = "RANSOMEYE_AI_MODEL_REGISTRY_PATH"
	DefaultAICanonicalDatasetPathEnv = "RANSOMEYE_AI_CANONICAL_DATASET_PATH"

	defaultModelBinRelativePath         = "model/model.bin"
	defaultModelMetadataRelativePath    = "model/model.json"
	defaultModelSignatureRelativePath   = "model/model.sig"
	defaultModelRegistryRelativePath    = "registry/registry.json"
	defaultCanonicalDatasetRelativePath = "dataset/canonical_dataset.json"
)

type ModelIdentity struct {
	ModelID              string
	ModelHash            string
	DatasetHash          string
	DatasetSchemaVersion string
	FeatureVersion       string
	CreatedAt            string
}

type modelArtifactPaths struct {
	modelBinPath         string
	metadataPath         string
	signaturePath        string
	registryPath         string
	canonicalDatasetPath string
	signingKeyPath       string
}

type modelMetadata struct {
	ModelID              string `json:"model_id"`
	ModelHash            string `json:"model_hash"`
	DatasetHash          string `json:"dataset_hash"`
	DatasetSchemaVersion string `json:"dataset_schema_version"`
	FeatureVersion       string `json:"feature_version"`
	CreatedAt            string `json:"created_at"`
}

type modelRegistryRecord struct {
	ModelID        string `json:"model_id"`
	Hash           string `json:"hash"`
	Signature      string `json:"signature"`
	DatasetHash    string `json:"dataset_hash"`
	FeatureVersion string `json:"feature_version"`
	CreatedAt      string `json:"created_at"`
}

type canonicalDatasetIdentity struct {
	DatasetHash    string
	SchemaVersion  string
	FeatureVersion string
}

func VerifyModelArtifacts(root string) error {
	_, err := loadVerifiedModelIdentity(root)
	return err
}

func ResolveModelIdentity() (ModelIdentity, error) {
	return loadVerifiedModelIdentity(resolveAIInstallRoot())
}

func resolveAIInstallRoot() string {
	root := DefaultAIInstallRoot
	if v := strings.TrimSpace(os.Getenv("RANSOMEYE_AI_ROOT")); v != "" {
		root = filepath.Clean(v)
	}
	return root
}

func loadVerifiedModelIdentity(root string) (ModelIdentity, error) {
	return loadVerifiedModelIdentityWithSigningKeyPath(root, corecrypto.WormSigningKeyPath)
}

func loadVerifiedModelIdentityWithSigningKeyPath(root string, signingKeyPath string) (ModelIdentity, error) {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return ModelIdentity{}, fmt.Errorf("ai root: %w", err)
	}
	rootAbs = filepath.Clean(rootAbs)

	paths := resolveModelArtifactPathsWithSigningKey(rootAbs, signingKeyPath)
	modelBytes, err := os.ReadFile(paths.modelBinPath)
	if err != nil {
		return ModelIdentity{}, fmt.Errorf("model.bin: %w", err)
	}
	modelSum := sha256.Sum256(modelBytes)
	modelHash := hex.EncodeToString(modelSum[:])

	metadata, err := loadModelMetadata(paths.metadataPath)
	if err != nil {
		return ModelIdentity{}, err
	}
	if metadata.ModelHash != modelHash {
		return ModelIdentity{}, fmt.Errorf(
			"model metadata hash mismatch: metadata=%s actual=%s",
			metadata.ModelHash,
			modelHash,
		)
	}

	registry, err := loadModelRegistry(paths.registryPath)
	if err != nil {
		return ModelIdentity{}, err
	}
	if registry.Hash != modelHash {
		return ModelIdentity{}, fmt.Errorf(
			"registry model hash mismatch: registry=%s actual=%s",
			registry.Hash,
			modelHash,
		)
	}
	if metadata.ModelID != registry.ModelID {
		return ModelIdentity{}, fmt.Errorf(
			"model_id mismatch: metadata=%s registry=%s",
			metadata.ModelID,
			registry.ModelID,
		)
	}
	if metadata.DatasetHash != registry.DatasetHash {
		return ModelIdentity{}, fmt.Errorf(
			"dataset_hash mismatch: metadata=%s registry=%s",
			metadata.DatasetHash,
			registry.DatasetHash,
		)
	}
	if metadata.FeatureVersion != registry.FeatureVersion {
		return ModelIdentity{}, fmt.Errorf(
			"feature_version mismatch: metadata=%s registry=%s",
			metadata.FeatureVersion,
			registry.FeatureVersion,
		)
	}
	if metadata.CreatedAt != registry.CreatedAt {
		return ModelIdentity{}, fmt.Errorf(
			"created_at mismatch: metadata=%s registry=%s",
			metadata.CreatedAt,
			registry.CreatedAt,
		)
	}

	signatureBytes, err := os.ReadFile(paths.signaturePath)
	if err != nil {
		return ModelIdentity{}, fmt.Errorf("model.sig: %w", err)
	}
	registrySignature, err := hex.DecodeString(registry.Signature)
	if err != nil {
		return ModelIdentity{}, fmt.Errorf("registry signature: %w", err)
	}
	if !bytes.Equal(signatureBytes, registrySignature) {
		return ModelIdentity{}, fmt.Errorf("model signature mismatch: model.sig differs from registry.json")
	}
	if len(signatureBytes) != ed25519.SignatureSize {
		return ModelIdentity{}, fmt.Errorf(
			"invalid model signature length: got %d want %d",
			len(signatureBytes),
			ed25519.SignatureSize,
		)
	}

	publicKey, err := loadWormVerificationKey(paths.signingKeyPath)
	if err != nil {
		return ModelIdentity{}, err
	}
	if !ed25519.Verify(publicKey, []byte(modelHash), signatureBytes) {
		return ModelIdentity{}, fmt.Errorf("model signature verification failed")
	}

	datasetIdentity, err := loadCanonicalDatasetIdentity(paths.canonicalDatasetPath)
	if err != nil {
		return ModelIdentity{}, err
	}
	if datasetIdentity.DatasetHash != metadata.DatasetHash {
		return ModelIdentity{}, fmt.Errorf(
			"dataset compatibility mismatch: metadata=%s actual=%s",
			metadata.DatasetHash,
			datasetIdentity.DatasetHash,
		)
	}
	if datasetIdentity.FeatureVersion != metadata.FeatureVersion {
		return ModelIdentity{}, fmt.Errorf(
			"dataset feature version mismatch: metadata=%s actual=%s",
			metadata.FeatureVersion,
			datasetIdentity.FeatureVersion,
		)
	}
	if datasetIdentity.SchemaVersion != metadata.DatasetSchemaVersion {
		return ModelIdentity{}, fmt.Errorf(
			"dataset schema version mismatch: metadata=%s actual=%s",
			metadata.DatasetSchemaVersion,
			datasetIdentity.SchemaVersion,
		)
	}

	return ModelIdentity{
		ModelID:              metadata.ModelID,
		ModelHash:            modelHash,
		DatasetHash:          metadata.DatasetHash,
		DatasetSchemaVersion: metadata.DatasetSchemaVersion,
		FeatureVersion:       metadata.FeatureVersion,
		CreatedAt:            metadata.CreatedAt,
	}, nil
}

func resolveModelArtifactPaths(root string) modelArtifactPaths {
	return resolveModelArtifactPathsWithSigningKey(root, corecrypto.WormSigningKeyPath)
}

func resolveModelArtifactPathsWithSigningKey(root string, signingKeyPath string) modelArtifactPaths {
	return modelArtifactPaths{
		modelBinPath:         resolveAIArtifactPath(root, DefaultAIModelBinPathEnv, defaultModelBinRelativePath),
		metadataPath:         resolveAIArtifactPath(root, DefaultAIModelMetadataPathEnv, defaultModelMetadataRelativePath),
		signaturePath:        resolveAIArtifactPath(root, DefaultAIModelSignaturePathEnv, defaultModelSignatureRelativePath),
		registryPath:         resolveAIArtifactPath(root, DefaultAIModelRegistryPathEnv, defaultModelRegistryRelativePath),
		canonicalDatasetPath: resolveAIArtifactPath(root, DefaultAICanonicalDatasetPathEnv, defaultCanonicalDatasetRelativePath),
		signingKeyPath:       filepath.Clean(signingKeyPath),
	}
}

func resolveAIArtifactPath(root string, envName string, relativePath string) string {
	if raw := strings.TrimSpace(os.Getenv(envName)); raw != "" {
		if filepath.IsAbs(raw) {
			return filepath.Clean(raw)
		}
		return filepath.Clean(filepath.Join(root, raw))
	}
	return filepath.Clean(filepath.Join(root, relativePath))
}

func loadModelMetadata(path string) (modelMetadata, error) {
	var metadata modelMetadata
	if err := loadJSONObject(path, &metadata); err != nil {
		return modelMetadata{}, fmt.Errorf("model metadata: %w", err)
	}
	modelID, err := normalizeRequiredText(metadata.ModelID, "model_id")
	if err != nil {
		return modelMetadata{}, err
	}
	modelHash, err := normalizeHexHash(metadata.ModelHash, "model_hash")
	if err != nil {
		return modelMetadata{}, err
	}
	datasetHash, err := normalizeHexHash(metadata.DatasetHash, "dataset_hash")
	if err != nil {
		return modelMetadata{}, err
	}
	datasetSchemaVersion, err := normalizeRequiredText(metadata.DatasetSchemaVersion, "dataset_schema_version")
	if err != nil {
		return modelMetadata{}, err
	}
	featureVersion, err := normalizeRequiredText(metadata.FeatureVersion, "feature_version")
	if err != nil {
		return modelMetadata{}, err
	}
	createdAt, err := normalizeRequiredText(metadata.CreatedAt, "created_at")
	if err != nil {
		return modelMetadata{}, err
	}
	return modelMetadata{
		ModelID:              modelID,
		ModelHash:            modelHash,
		DatasetHash:          datasetHash,
		DatasetSchemaVersion: datasetSchemaVersion,
		FeatureVersion:       featureVersion,
		CreatedAt:            createdAt,
	}, nil
}

func loadModelRegistry(path string) (modelRegistryRecord, error) {
	var registry modelRegistryRecord
	if err := loadJSONObject(path, &registry); err != nil {
		return modelRegistryRecord{}, fmt.Errorf("model registry: %w", err)
	}
	modelID, err := normalizeRequiredText(registry.ModelID, "model_id")
	if err != nil {
		return modelRegistryRecord{}, err
	}
	modelHash, err := normalizeHexHash(registry.Hash, "hash")
	if err != nil {
		return modelRegistryRecord{}, err
	}
	signature, err := normalizeHexBytes(registry.Signature, "signature", ed25519.SignatureSize)
	if err != nil {
		return modelRegistryRecord{}, err
	}
	datasetHash, err := normalizeHexHash(registry.DatasetHash, "dataset_hash")
	if err != nil {
		return modelRegistryRecord{}, err
	}
	featureVersion, err := normalizeRequiredText(registry.FeatureVersion, "feature_version")
	if err != nil {
		return modelRegistryRecord{}, err
	}
	createdAt, err := normalizeRequiredText(registry.CreatedAt, "created_at")
	if err != nil {
		return modelRegistryRecord{}, err
	}
	return modelRegistryRecord{
		ModelID:        modelID,
		Hash:           modelHash,
		Signature:      signature,
		DatasetHash:    datasetHash,
		FeatureVersion: featureVersion,
		CreatedAt:      createdAt,
	}, nil
}

func loadJSONObject(path string, dst any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

func loadCanonicalDatasetIdentity(path string) (canonicalDatasetIdentity, error) {
	value, err := decodeJSONValue(path)
	if err != nil {
		return canonicalDatasetIdentity{}, fmt.Errorf("canonical dataset: %w", err)
	}
	root, ok := value.(map[string]any)
	if !ok {
		return canonicalDatasetIdentity{}, fmt.Errorf("canonical dataset must be an object")
	}
	if err := requireExactJSONKeys(root, []string{
		"feature_version",
		"records",
		"schema_version",
	}, "canonical dataset"); err != nil {
		return canonicalDatasetIdentity{}, err
	}

	schemaVersion, err := normalizeRequiredJSONText(root["schema_version"], "schema_version")
	if err != nil {
		return canonicalDatasetIdentity{}, err
	}
	featureVersion, err := normalizeRequiredJSONText(root["feature_version"], "feature_version")
	if err != nil {
		return canonicalDatasetIdentity{}, err
	}

	records, ok := root["records"].([]any)
	if !ok {
		return canonicalDatasetIdentity{}, fmt.Errorf("records must be an array")
	}
	for idx, rawRecord := range records {
		record, ok := rawRecord.(map[string]any)
		if !ok {
			return canonicalDatasetIdentity{}, fmt.Errorf("records[%d] must be an object", idx)
		}
		if err := requireExactJSONKeys(record, []string{
			"agent_id",
			"dropped_packets_before",
			"event_type",
			"event_type_id",
			"label",
			"label_id",
			"payload_base64",
			"payload_sha256",
			"payload_size",
			"sequence_id",
			"timestamp",
		}, fmt.Sprintf("records[%d]", idx)); err != nil {
			return canonicalDatasetIdentity{}, err
		}
		if _, err := normalizeJSONInt(record["sequence_id"], fmt.Sprintf("records[%d].sequence_id", idx)); err != nil {
			return canonicalDatasetIdentity{}, err
		}
		if _, err := normalizeJSONInt(record["timestamp"], fmt.Sprintf("records[%d].timestamp", idx)); err != nil {
			return canonicalDatasetIdentity{}, err
		}
		if _, err := normalizeRequiredJSONText(record["agent_id"], fmt.Sprintf("records[%d].agent_id", idx)); err != nil {
			return canonicalDatasetIdentity{}, err
		}
		if _, err := normalizeRequiredJSONText(record["event_type"], fmt.Sprintf("records[%d].event_type", idx)); err != nil {
			return canonicalDatasetIdentity{}, err
		}
		if _, err := normalizeJSONInt(record["event_type_id"], fmt.Sprintf("records[%d].event_type_id", idx)); err != nil {
			return canonicalDatasetIdentity{}, err
		}
		if _, err := normalizeRequiredJSONText(record["payload_base64"], fmt.Sprintf("records[%d].payload_base64", idx)); err != nil {
			return canonicalDatasetIdentity{}, err
		}
		if _, err := normalizeHexJSONText(record["payload_sha256"], fmt.Sprintf("records[%d].payload_sha256", idx), sha256.Size); err != nil {
			return canonicalDatasetIdentity{}, err
		}
		if _, err := normalizeJSONInt(record["payload_size"], fmt.Sprintf("records[%d].payload_size", idx)); err != nil {
			return canonicalDatasetIdentity{}, err
		}
		if _, err := normalizeJSONInt(record["dropped_packets_before"], fmt.Sprintf("records[%d].dropped_packets_before", idx)); err != nil {
			return canonicalDatasetIdentity{}, err
		}
		if _, err := normalizeRequiredJSONText(record["label"], fmt.Sprintf("records[%d].label", idx)); err != nil {
			return canonicalDatasetIdentity{}, err
		}
		if _, err := normalizeJSONInt(record["label_id"], fmt.Sprintf("records[%d].label_id", idx)); err != nil {
			return canonicalDatasetIdentity{}, err
		}
	}

	canonicalBytes, err := json.Marshal(value)
	if err != nil {
		return canonicalDatasetIdentity{}, fmt.Errorf("canonical dataset: %w", err)
	}
	sum := sha256.Sum256(canonicalBytes)
	return canonicalDatasetIdentity{
		DatasetHash:    hex.EncodeToString(sum[:]),
		SchemaVersion:  schemaVersion,
		FeatureVersion: featureVersion,
	}, nil
}

func decodeJSONValue(path string) (any, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("%s: trailing data after JSON value", path)
		}
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return value, nil
}

func requireExactJSONKeys(value map[string]any, expected []string, fieldName string) error {
	actual := make([]string, 0, len(value))
	for key := range value {
		actual = append(actual, key)
	}
	sort.Strings(actual)
	want := append([]string(nil), expected...)
	sort.Strings(want)

	missing := make([]string, 0)
	extra := make([]string, 0)
	actualSet := make(map[string]struct{}, len(actual))
	for _, key := range actual {
		actualSet[key] = struct{}{}
	}
	wantSet := make(map[string]struct{}, len(want))
	for _, key := range want {
		wantSet[key] = struct{}{}
		if _, ok := actualSet[key]; !ok {
			missing = append(missing, key)
		}
	}
	for _, key := range actual {
		if _, ok := wantSet[key]; !ok {
			extra = append(extra, key)
		}
	}
	if len(missing) == 0 && len(extra) == 0 {
		return nil
	}
	parts := make([]string, 0, 2)
	if len(missing) > 0 {
		parts = append(parts, fmt.Sprintf("missing=%v", missing))
	}
	if len(extra) > 0 {
		parts = append(parts, fmt.Sprintf("extra=%v", extra))
	}
	return fmt.Errorf("%s must contain the strict schema (%s)", fieldName, strings.Join(parts, ", "))
}

func normalizeRequiredJSONText(value any, fieldName string) (string, error) {
	text, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("%s must be a string", fieldName)
	}
	return normalizeRequiredText(text, fieldName)
}

func normalizeHexJSONText(value any, fieldName string, expectedLen int) (string, error) {
	text, err := normalizeRequiredJSONText(value, fieldName)
	if err != nil {
		return "", err
	}
	return normalizeHexBytes(text, fieldName, expectedLen)
}

func normalizeJSONInt(value any, fieldName string) (int64, error) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, fmt.Errorf("%s must be an integer", fieldName)
	}
	text := strings.TrimSpace(number.String())
	if text == "" || strings.ContainsAny(text, ".eE") {
		return 0, fmt.Errorf("%s must be an integer", fieldName)
	}
	parsed, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer: %w", fieldName, err)
	}
	if parsed < 0 {
		return 0, fmt.Errorf("%s must be non-negative", fieldName)
	}
	return parsed, nil
}

func loadWormVerificationKey(path string) (ed25519.PublicKey, error) {
	raw, err := corecrypto.ReadValidatedWormSeed(path, false)
	if err != nil {
		return nil, fmt.Errorf("worm signing key: %w", err)
	}
	privateKey := ed25519.NewKeyFromSeed(raw)
	publicKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("worm signing key public key conversion failed")
	}
	return publicKey, nil
}

func normalizeHexHash(raw string, fieldName string) (string, error) {
	return normalizeHexBytes(raw, fieldName, sha256.Size)
}

func normalizeHexBytes(raw string, fieldName string, expectedLen int) (string, error) {
	text := strings.ToLower(strings.TrimSpace(raw))
	if text == "" {
		return "", fmt.Errorf("%s is required", fieldName)
	}
	decoded, err := hex.DecodeString(text)
	if err != nil {
		return "", fmt.Errorf("%s must be hex encoded: %w", fieldName, err)
	}
	if len(decoded) != expectedLen {
		return "", fmt.Errorf("%s must decode to %d bytes, got %d", fieldName, expectedLen, len(decoded))
	}
	return text, nil
}

func normalizeRequiredText(raw string, fieldName string) (string, error) {
	text := strings.TrimSpace(raw)
	if text == "" {
		return "", fmt.Errorf("%s is required", fieldName)
	}
	return text, nil
}
