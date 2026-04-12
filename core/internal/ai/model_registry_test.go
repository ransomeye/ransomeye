package ai

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyModelArtifactsRejectsTamperedModel(t *testing.T) {
	root, _ := writeModelFixture(t)
	keyPath := filepath.Join(root, "worm_signing.key")
	if err := verifyModelArtifactsWithSigningKeyPath(root, keyPath); err != nil {
		t.Fatalf("VerifyModelArtifacts initial: %v", err)
	}

	modelPath := filepath.Join(root, defaultModelBinRelativePath)
	if err := os.WriteFile(modelPath, []byte("tampered-model\n"), 0o644); err != nil {
		t.Fatalf("WriteFile tampered model: %v", err)
	}

	err := verifyModelArtifactsWithSigningKeyPath(root, keyPath)
	if err == nil || !strings.Contains(err.Error(), "model metadata hash mismatch") {
		t.Fatalf("VerifyModelArtifacts error = %v, want model metadata hash mismatch", err)
	}
}

func TestResolveModelIdentityFromRegistry(t *testing.T) {
	root, datasetHash := writeModelFixture(t)
	keyPath := filepath.Join(root, "worm_signing.key")

	identity, err := resolveModelIdentityWithSigningKeyPath(root, keyPath)
	if err != nil {
		t.Fatalf("ResolveModelIdentity: %v", err)
	}
	if identity.ModelID == "" {
		t.Fatal("ResolveModelIdentity returned empty ModelID")
	}
	if identity.ModelHash == "" {
		t.Fatal("ResolveModelIdentity returned empty ModelHash")
	}
	if identity.DatasetHash != datasetHash {
		t.Fatalf("DatasetHash = %s, want %s", identity.DatasetHash, datasetHash)
	}
	if identity.DatasetSchemaVersion != "canonical-dataset-v1" {
		t.Fatalf("DatasetSchemaVersion = %s, want canonical-dataset-v1", identity.DatasetSchemaVersion)
	}
	if identity.FeatureVersion != "ml.features.v1" {
		t.Fatalf("FeatureVersion = %s, want ml.features.v1", identity.FeatureVersion)
	}
}

func TestVerifyModelArtifactsRejectsDatasetMismatch(t *testing.T) {
	root, _ := writeModelFixture(t)
	keyPath := filepath.Join(root, "worm_signing.key")
	if err := verifyModelArtifactsWithSigningKeyPath(root, keyPath); err != nil {
		t.Fatalf("VerifyModelArtifacts initial: %v", err)
	}

	datasetPath := filepath.Join(root, defaultCanonicalDatasetRelativePath)
	if err := os.WriteFile(datasetPath, []byte(`{"feature_version":"ml.features.v1","records":[],"schema_version":"canonical-dataset-v1"}`+"\n"), 0o644); err != nil {
		t.Fatalf("WriteFile tampered dataset: %v", err)
	}

	err := verifyModelArtifactsWithSigningKeyPath(root, keyPath)
	if err == nil || !strings.Contains(err.Error(), "dataset compatibility mismatch") {
		t.Fatalf("VerifyModelArtifacts error = %v, want dataset compatibility mismatch", err)
	}
}

func verifyModelArtifactsWithSigningKeyPath(root string, keyPath string) error {
	_, err := loadVerifiedModelIdentityWithSigningKeyPath(root, keyPath)
	return err
}

func resolveModelIdentityWithSigningKeyPath(root string, keyPath string) (ModelIdentity, error) {
	return loadVerifiedModelIdentityWithSigningKeyPath(root, keyPath)
}

func writeModelFixture(t *testing.T) (string, string) {
	t.Helper()

	root := t.TempDir()
	modelDir := filepath.Join(root, "model")
	registryDir := filepath.Join(root, "registry")
	datasetDir := filepath.Join(root, "dataset")
	if err := os.MkdirAll(modelDir, 0o755); err != nil {
		t.Fatalf("MkdirAll modelDir: %v", err)
	}
	if err := os.MkdirAll(registryDir, 0o755); err != nil {
		t.Fatalf("MkdirAll registryDir: %v", err)
	}
	if err := os.MkdirAll(datasetDir, 0o755); err != nil {
		t.Fatalf("MkdirAll datasetDir: %v", err)
	}

	modelBytes := []byte("algorithm=deterministic_logistic_regression_v1\nvector_length=8\nbias=0.10000000\nweights=0.01000000\n")
	modelSum := sha256.Sum256(modelBytes)
	modelHash := hex.EncodeToString(modelSum[:])

	datasetValue := map[string]any{
		"feature_version": "ml.features.v1",
		"records": []map[string]any{
			{
				"agent_id":               "agent-alpha",
				"dropped_packets_before": 0,
				"event_type":             "PROCESS_EVENT",
				"event_type_id":          1,
				"label":                  "benign",
				"label_id":               0,
				"payload_base64":         "cHJvY2Vzcy1ub3JtYWwtMDE=",
				"payload_sha256":         "c09405fe34c62e3c8b7011a1427ceed3ed05cea341c6b89b096e37438d301945",
				"payload_size":           17,
				"sequence_id":            3,
				"timestamp":              1700000003,
			},
		},
		"schema_version": "canonical-dataset-v1",
	}
	datasetBytes, err := json.Marshal(datasetValue)
	if err != nil {
		t.Fatalf("json.Marshal dataset: %v", err)
	}
	datasetSum := sha256.Sum256(datasetBytes)
	datasetHash := hex.EncodeToString(datasetSum[:])

	seed := make([]byte, ed25519.SeedSize)
	for idx := range seed {
		seed[idx] = byte((idx*11 + 37) & 0xff)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	signature := ed25519.Sign(privateKey, []byte(modelHash))

	modelID := "model-" + modelHash[:16]
	metadata := map[string]any{
		"algorithm":              "deterministic_logistic_regression_v1",
		"created_at":             "2023-11-14T22:13:20Z",
		"dataset_hash":           datasetHash,
		"dataset_schema_version": "canonical-dataset-v1",
		"feature_version":        "ml.features.v1",
		"model_hash":             modelHash,
		"model_id":               modelID,
		"vector_length":          8,
	}
	registry := map[string]any{
		"created_at":      metadata["created_at"],
		"dataset_hash":    metadata["dataset_hash"],
		"feature_version": metadata["feature_version"],
		"hash":            modelHash,
		"model_id":        modelID,
		"signature":       hex.EncodeToString(signature),
	}

	writeBytes(t, filepath.Join(modelDir, "model.bin"), modelBytes, 0o644)
	writeJSONFile(t, filepath.Join(modelDir, "model.json"), metadata)
	writeBytes(t, filepath.Join(modelDir, "model.sig"), signature, 0o644)
	writeBytes(t, filepath.Join(datasetDir, "canonical_dataset.json"), append(datasetBytes, '\n'), 0o644)
	writeJSONFile(t, filepath.Join(registryDir, "registry.json"), registry)
	writeBytes(t, filepath.Join(root, "worm_signing.key"), seed, 0o400)

	return root, datasetHash
}

func writeJSONFile(t *testing.T, path string, value any) {
	t.Helper()
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatalf("json.MarshalIndent %s: %v", path, err)
	}
	writeBytes(t, path, append(raw, '\n'), 0o644)
}

func writeBytes(t *testing.T, path string, raw []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, raw, mode); err != nil {
		t.Fatalf("WriteFile %s: %v", path, err)
	}
}
