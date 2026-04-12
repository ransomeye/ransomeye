package replay

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"ransomeye/core/internal/ai"
	coreconfig "ransomeye/core/internal/config"
	"ransomeye/core/internal/ingest"
)

const (
	DefaultReplayCaptureEnv  = "RANSOMEYE_REPLAY_CAPTURE_PATH"
	DefaultConfigHashEnv     = "RANSOMEYE_CONFIG_HASH"
	DefaultModelHashEnv      = "RANSOMEYE_MODEL_HASH"
	DefaultFeatureVersionEnv = "RANSOMEYE_FEATURE_VERSION"
	DefaultPRDHashEnv        = "RANSOMEYE_PRD_HASH"
	prdManifestRelativePath  = "prd_project_mishka/prd.sha256"
)

type Envelope struct {
	Events         []CapturedEvent `json:"events"`
	ConfigHash     string          `json:"config_hash"`
	ModelHash      string          `json:"model_hash"`
	FeatureVersion string          `json:"feature_version"`
	PRDHash        string          `json:"prd_hash"`
}

type CapturedEvent struct {
	SequenceID           uint64 `json:"sequence_id"`
	TimestampUnixNano    uint64 `json:"timestamp_unix_nano"`
	DroppedPacketsBefore uint64 `json:"dropped_packets_before"`
	AgentID              string `json:"agent_id"`
	EventType            string `json:"event_type"`
	PayloadBase64        string `json:"payload_base64"`
	AgentSignatureBase64 string `json:"agent_signature_base64"`
}

type Metadata struct {
	ConfigHash     string
	ModelHash      string
	FeatureVersion string
	PRDHash        string
}

type InputCapture struct {
	path     string
	mu       sync.Mutex
	envelope Envelope
}

type capturingEnqueuer struct {
	next     ingest.VerifiedTelemetryEnqueuer
	capture  *InputCapture
	baseline *BaselineStore
}

func NewInputCapture(path string, metadata Metadata) (*InputCapture, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("replay capture path is required")
	}

	envelope, err := NewEnvelope(metadata)
	if err != nil {
		return nil, err
	}

	capture := &InputCapture{
		path:     path,
		envelope: envelope,
	}
	if err := capture.persist(); err != nil {
		return nil, err
	}
	return capture, nil
}

func NewInputCaptureFromEnv() (*InputCapture, error) {
	path := strings.TrimSpace(os.Getenv(DefaultReplayCaptureEnv))
	if path == "" {
		return nil, nil
	}

	metadata, err := ResolveRuntimeMetadata()
	if err != nil {
		return nil, err
	}
	return NewInputCapture(path, metadata)
}

func NewCapturingEnqueuer(next ingest.VerifiedTelemetryEnqueuer, capture *InputCapture) ingest.VerifiedTelemetryEnqueuer {
	return NewCapturingEnqueuerWithBaseline(next, capture, nil)
}

func NewCapturingEnqueuerWithBaseline(next ingest.VerifiedTelemetryEnqueuer, capture *InputCapture, baseline *BaselineStore) ingest.VerifiedTelemetryEnqueuer {
	if capture == nil {
		if baseline == nil {
			return next
		}
	}
	return &capturingEnqueuer{
		next:     next,
		capture:  capture,
		baseline: baseline,
	}
}

func (e *capturingEnqueuer) Enqueue(payload *ingest.VerifiedTelemetry) error {
	if err := ingest.EnqueueVerifiedTelemetry(e.next, payload); err != nil {
		log.Printf("[QUEUE] enqueue failed agent_id=%s logical_clock=%d err=%v", payload.AgentIDStr, payload.LogicalClock, err)
		return err
	}
	if e.capture == nil {
		if e.baseline == nil {
			return nil
		}
	} else if err := e.capture.CaptureVerifiedDPIEvent(payload); err != nil {
		// Queue ownership transfers once enqueue succeeds. Replay capture is best-effort and
		// must not surface as a scheduler backpressure error after the payload is already live.
		log.Printf("[QUEUE] replay capture failed agent_id=%s logical_clock=%d err=%v", payload.AgentIDStr, payload.LogicalClock, err)
	}
	if e.baseline != nil {
		if _, err := e.baseline.CaptureVerifiedTelemetry(context.Background(), payload); err != nil {
			log.Printf("[QUEUE] replay baseline failed agent_id=%s logical_clock=%d err=%v", payload.AgentIDStr, payload.LogicalClock, err)
		}
	}
	return nil
}

func NewEnvelope(metadata Metadata) (Envelope, error) {
	configHash, err := normalizeHash(metadata.ConfigHash)
	if err != nil {
		return Envelope{}, fmt.Errorf("config_hash: %w", err)
	}
	modelHash, err := normalizeHash(metadata.ModelHash)
	if err != nil {
		return Envelope{}, fmt.Errorf("model_hash: %w", err)
	}
	featureVersion, err := normalizeRequiredText(metadata.FeatureVersion, "feature_version")
	if err != nil {
		return Envelope{}, err
	}
	prdHash, err := normalizeHash(metadata.PRDHash)
	if err != nil {
		return Envelope{}, fmt.Errorf("prd_hash: %w", err)
	}

	return Envelope{
		Events:         make([]CapturedEvent, 0),
		ConfigHash:     configHash,
		ModelHash:      modelHash,
		FeatureVersion: featureVersion,
		PRDHash:        prdHash,
	}, nil
}

func LoadEnvelope(path string) (Envelope, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Envelope{}, err
	}

	var envelope Envelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return Envelope{}, fmt.Errorf("decode replay envelope: %w", err)
	}
	if _, err := NewEnvelope(Metadata{
		ConfigHash:     envelope.ConfigHash,
		ModelHash:      envelope.ModelHash,
		FeatureVersion: envelope.FeatureVersion,
		PRDHash:        envelope.PRDHash,
	}); err != nil {
		return Envelope{}, err
	}
	for idx := range envelope.Events {
		if _, err := envelope.Events[idx].VerifiedTelemetry(); err != nil {
			return Envelope{}, fmt.Errorf("event %d: %w", idx, err)
		}
	}
	return envelope, nil
}

func (c *InputCapture) CaptureVerifiedDPIEvent(ev *ingest.VerifiedTelemetry) error {
	if c == nil {
		return errors.New("nil replay input capture")
	}
	captured, err := capturedEventFromVerifiedTelemetry(ev)
	if err != nil {
		return err
	}

	c.mu.Lock()
	c.envelope.Events = append(c.envelope.Events, captured)
	err = c.persist()
	c.mu.Unlock()
	return err
}

func (c *InputCapture) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.persist()
}

func (e Envelope) Save(path string) error {
	capture, err := NewInputCapture(path, Metadata{
		ConfigHash:     e.ConfigHash,
		ModelHash:      e.ModelHash,
		FeatureVersion: e.FeatureVersion,
		PRDHash:        e.PRDHash,
	})
	if err != nil {
		return err
	}
	capture.mu.Lock()
	capture.envelope.Events = append(capture.envelope.Events, e.Events...)
	err = capture.persist()
	capture.mu.Unlock()
	return err
}

func (e CapturedEvent) VerifiedTelemetry() (*ingest.VerifiedTelemetry, error) {
	payload, err := base64.StdEncoding.DecodeString(e.PayloadBase64)
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}
	signature, err := base64.StdEncoding.DecodeString(e.AgentSignatureBase64)
	if err != nil {
		return nil, fmt.Errorf("decode agent signature: %w", err)
	}
	view, err := ingest.ParseTelemetryV1(payload)
	if err != nil {
		return nil, err
	}
	if view.LogicalClock != e.SequenceID {
		return nil, fmt.Errorf("sequence_id mismatch: payload=%d captured=%d", view.LogicalClock, e.SequenceID)
	}
	if view.TimestampUnixNano != e.TimestampUnixNano {
		return nil, fmt.Errorf("timestamp_unix_nano mismatch: payload=%d captured=%d", view.TimestampUnixNano, e.TimestampUnixNano)
	}
	if view.AgentID.String() != e.AgentID {
		return nil, fmt.Errorf("agent_id mismatch: payload=%s captured=%s", view.AgentID, e.AgentID)
	}
	eventType, err := ingest.DBEventType(view.EventTypeCode)
	if err != nil {
		return nil, err
	}
	if eventType != e.EventType {
		return nil, fmt.Errorf("event_type mismatch: payload=%s captured=%s", eventType, e.EventType)
	}

	payloadCopy := append([]byte(nil), payload...)
	signatureCopy := append([]byte(nil), signature...)

	return &ingest.VerifiedTelemetry{
		Payload:        payloadCopy,
		AgentSignature: signatureCopy,
		AgentIDStr:     e.AgentID,
		EventType:      e.EventType,
		TimestampUnix:  float64(e.TimestampUnixNano) / 1e9,
		LogicalClock:   int64(e.SequenceID),
		DroppedCount:   e.DroppedPacketsBefore,
	}, nil
}

func ResolveRuntimeMetadata() (Metadata, error) {
	configHash, err := resolveConfigHash()
	if err != nil {
		return Metadata{}, err
	}
	modelIdentity, err := resolveReplayModelIdentity()
	if err != nil {
		return Metadata{}, err
	}
	prdHash, err := resolvePRDHash()
	if err != nil {
		return Metadata{}, err
	}
	return Metadata{
		ConfigHash:     configHash,
		ModelHash:      modelIdentity.ModelHash,
		FeatureVersion: modelIdentity.FeatureVersion,
		PRDHash:        prdHash,
	}, nil
}

func capturedEventFromVerifiedTelemetry(ev *ingest.VerifiedTelemetry) (CapturedEvent, error) {
	if ev == nil {
		return CapturedEvent{}, errors.New("nil verified telemetry")
	}
	view, err := ingest.ParseTelemetryV1(ev.Payload)
	if err != nil {
		return CapturedEvent{}, err
	}
	eventType, err := ingest.DBEventType(view.EventTypeCode)
	if err != nil {
		return CapturedEvent{}, err
	}

	return CapturedEvent{
		SequenceID:           view.LogicalClock,
		TimestampUnixNano:    view.TimestampUnixNano,
		DroppedPacketsBefore: ev.DroppedCount,
		AgentID:              view.AgentID.String(),
		EventType:            eventType,
		PayloadBase64:        base64.StdEncoding.EncodeToString(ev.Payload),
		AgentSignatureBase64: base64.StdEncoding.EncodeToString(ev.AgentSignature),
	}, nil
}

func (c *InputCapture) persist() error {
	if c == nil {
		return errors.New("nil replay input capture")
	}
	if err := os.MkdirAll(filepath.Dir(c.path), 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(c.envelope, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(c.path), "*.rre.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, c.path); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}

func resolveConfigHash() (string, error) {
	if raw := strings.TrimSpace(os.Getenv(DefaultConfigHashEnv)); raw != "" {
		return normalizeHash(raw)
	}

	cfg, err := coreconfig.LoadVerifiedCommonConfig(
		coreconfig.InstalledCommonConfigPath,
		coreconfig.IntermediateCACertPath,
	)
	if err != nil {
		return "", fmt.Errorf("load common config: %w", err)
	}
	canonical, err := coreconfig.CanonicalJSONBytes(cfg)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

func resolveReplayModelIdentity() (ai.ModelIdentity, error) {
	modelHashRaw := strings.TrimSpace(os.Getenv(DefaultModelHashEnv))
	featureVersionRaw := strings.TrimSpace(os.Getenv(DefaultFeatureVersionEnv))
	if modelHashRaw != "" || featureVersionRaw != "" {
		if modelHashRaw == "" || featureVersionRaw == "" {
			return ai.ModelIdentity{}, errors.New("RANSOMEYE_MODEL_HASH and RANSOMEYE_FEATURE_VERSION must both be set")
		}
		modelHash, err := normalizeHash(modelHashRaw)
		if err != nil {
			return ai.ModelIdentity{}, fmt.Errorf("RANSOMEYE_MODEL_HASH: %w", err)
		}
		featureVersion, err := normalizeRequiredText(featureVersionRaw, "feature_version")
		if err != nil {
			return ai.ModelIdentity{}, fmt.Errorf("RANSOMEYE_FEATURE_VERSION: %w", err)
		}
		return ai.ModelIdentity{
			ModelHash:      modelHash,
			FeatureVersion: featureVersion,
		}, nil
	}
	return ai.ResolveModelIdentity()
}

func resolvePRDHash() (string, error) {
	if raw := strings.TrimSpace(os.Getenv(DefaultPRDHashEnv)); raw != "" {
		return normalizeHash(raw)
	}
	root, err := findRepoRoot()
	if err != nil {
		return "", err
	}
	return sha256File(filepath.Join(root, prdManifestRelativePath))
}

func normalizeHash(raw string) (string, error) {
	text := strings.ToLower(strings.TrimSpace(raw))
	if text == "" {
		return "", errors.New("hash is required")
	}
	if strings.HasPrefix(text, "sha256:") {
		text = strings.TrimSpace(strings.TrimPrefix(text, "sha256:"))
	}
	if len(text) != 64 {
		return "", fmt.Errorf("expected 64 hex chars, got %d", len(text))
	}
	if _, err := hex.DecodeString(text); err != nil {
		return "", err
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

func sha256File(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func findRepoRoot() (string, error) {
	if root := strings.TrimSpace(os.Getenv("RANSOMEYE_REPO_ROOT")); root != "" {
		if _, err := os.Stat(filepath.Join(root, prdManifestRelativePath)); err == nil {
			return root, nil
		}
	}

	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(wd, prdManifestRelativePath)); err == nil {
			return wd, nil
		}
		parent := filepath.Dir(wd)
		if parent == wd {
			break
		}
		wd = parent
	}
	return "", errors.New("unable to locate repository root")
}
