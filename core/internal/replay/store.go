package replay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"ransomeye/core/internal/db"
	"ransomeye/core/internal/ingest"
)

const DefaultReplayCaptureDBEnv = "RANSOMEYE_REPLAY_CAPTURE_DB"

type BaselineStore struct {
	pool     *pgxpool.Pool
	metadata Metadata
}

type StoredReplay struct {
	ReplayID     uuid.UUID
	InputHash    string
	ExpectedHash string
	ActualHash   string
	Status       string
	Envelope     Envelope
	StageHashes  StageHashes
}

type ReplayCheckResult struct {
	Status       string `json:"status"`
	Stage        string `json:"stage,omitempty"`
	ExpectedHash string `json:"expected_hash,omitempty"`
	ActualHash   string `json:"actual_hash,omitempty"`
	InputHash    string `json:"input_hash,omitempty"`
	OutputHash   string `json:"output_hash,omitempty"`
}

func NewBaselineStore(pool *pgxpool.Pool, metadata Metadata) (*BaselineStore, error) {
	if pool == nil {
		return nil, errors.New("nil replay baseline pool")
	}
	envelope, err := NewEnvelope(metadata)
	if err != nil {
		return nil, err
	}
	return &BaselineStore{
		pool: pool,
		metadata: Metadata{
			ConfigHash:     envelope.ConfigHash,
			ModelHash:      envelope.ModelHash,
			FeatureVersion: envelope.FeatureVersion,
			PRDHash:        envelope.PRDHash,
		},
	}, nil
}

func NewBaselineStoreFromEnv(pool *pgxpool.Pool) (*BaselineStore, error) {
	if !envEnabled(DefaultReplayCaptureDBEnv) {
		return nil, nil
	}
	metadata, err := ResolveRuntimeMetadata()
	if err != nil {
		return nil, err
	}
	return NewBaselineStore(pool, metadata)
}

func (s *BaselineStore) CaptureVerifiedTelemetry(ctx context.Context, ev *ingest.VerifiedTelemetry) (uuid.UUID, error) {
	if s == nil {
		return uuid.Nil, errors.New("nil replay baseline store")
	}
	captured, err := capturedEventFromVerifiedTelemetry(ev)
	if err != nil {
		return uuid.Nil, err
	}
	envelope := Envelope{
		Events:         []CapturedEvent{captured},
		ConfigHash:     s.metadata.ConfigHash,
		ModelHash:      s.metadata.ModelHash,
		FeatureVersion: s.metadata.FeatureVersion,
		PRDHash:        s.metadata.PRDHash,
	}
	return s.CaptureEnvelope(ctx, envelope)
}

func (s *BaselineStore) CaptureEnvelope(ctx context.Context, envelope Envelope) (uuid.UUID, error) {
	if s == nil || s.pool == nil {
		return uuid.Nil, errors.New("nil replay baseline store")
	}
	result, err := RunEnvelope(ctx, envelope)
	if err != nil {
		return uuid.Nil, err
	}

	replayID := uuid.New()
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return uuid.Nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(
		ctx,
		`INSERT INTO replay_sessions (replay_id, created_at, input_hash, expected_hash, actual_hash, status)
		 VALUES ($1, NOW(), $2, $3, $4, $5)`,
		replayID,
		result.InputHash,
		result.OutputHash,
		result.OutputHash,
		"CAPTURED",
	); err != nil {
		return uuid.Nil, fmt.Errorf("insert replay_sessions: %w", err)
	}

	artifacts := []struct {
		stage string
		hash  string
		raw   json.RawMessage
	}{
		{stage: stageCapture, hash: result.InputHash, raw: result.StageArtifacts.Capture},
		{stage: stageIngest, hash: result.StageHashes.Ingest, raw: result.StageArtifacts.Ingest},
		{stage: stageFeature, hash: result.StageHashes.Feature, raw: result.StageArtifacts.Feature},
		{stage: stageModel, hash: result.StageHashes.Model, raw: result.StageArtifacts.Model},
		{stage: stageSINE, hash: result.StageHashes.SINE, raw: result.StageArtifacts.SINE},
		{stage: stageDecision, hash: result.StageHashes.Decision, raw: result.StageArtifacts.Decision},
		{stage: stageEnforcement, hash: result.StageHashes.Enforcement, raw: result.StageArtifacts.Enforcement},
		{stage: stageFinal, hash: result.StageHashes.Final, raw: result.StageArtifacts.Final},
	}
	for _, artifact := range artifacts {
		if _, err := tx.Exec(
			ctx,
			`INSERT INTO replay_stage_artifacts (artifact_id, replay_id, created_at, stage_name, stage_hash, canonical_json)
			 VALUES (gen_random_uuid(), $1, NOW(), $2, $3, $4)`,
			replayID,
			artifact.stage,
			artifact.hash,
			string(artifact.raw),
		); err != nil {
			return uuid.Nil, fmt.Errorf("insert replay_stage_artifacts %s: %w", artifact.stage, err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return uuid.Nil, err
	}
	return replayID, nil
}

func LoadStoredReplay(ctx context.Context, conn *db.TrustedConn, replayID uuid.UUID) (StoredReplay, error) {
	if conn == nil {
		return StoredReplay{}, errors.New("nil replay connection")
	}

	var stored StoredReplay
	stored.ReplayID = replayID
	if err := conn.QueryRow(
		ctx,
		`SELECT input_hash, expected_hash, actual_hash, status
		 FROM replay_sessions
		 WHERE replay_id = $1`,
		replayID,
	).Scan(&stored.InputHash, &stored.ExpectedHash, &stored.ActualHash, &stored.Status); err != nil {
		return StoredReplay{}, fmt.Errorf("load replay session: %w", err)
	}

	rows, err := conn.Query(
		ctx,
		`SELECT stage_name, stage_hash, canonical_json
		 FROM replay_stage_artifacts
		 WHERE replay_id = $1
		 ORDER BY stage_name`,
		replayID,
	)
	if err != nil {
		return StoredReplay{}, fmt.Errorf("load replay artifacts: %w", err)
	}
	defer rows.Close()

	var captureJSON string
	required := map[string]bool{
		stageCapture:     false,
		stageIngest:      false,
		stageFeature:     false,
		stageModel:       false,
		stageSINE:        false,
		stageDecision:    false,
		stageEnforcement: false,
		stageFinal:       false,
	}
	for rows.Next() {
		var stageName string
		var stageHash string
		var canonicalJSON string
		if err := rows.Scan(&stageName, &stageHash, &canonicalJSON); err != nil {
			return StoredReplay{}, fmt.Errorf("scan replay artifact: %w", err)
		}
		switch stageName {
		case stageCapture:
			captureJSON = canonicalJSON
		case stageIngest:
			stored.StageHashes.Ingest = stageHash
		case stageFeature:
			stored.StageHashes.Feature = stageHash
		case stageModel:
			stored.StageHashes.Model = stageHash
		case stageSINE:
			stored.StageHashes.SINE = stageHash
		case stageDecision:
			stored.StageHashes.Decision = stageHash
		case stageEnforcement:
			stored.StageHashes.Enforcement = stageHash
		case stageFinal:
			stored.StageHashes.Final = stageHash
		default:
			return StoredReplay{}, fmt.Errorf("unexpected replay artifact stage %q", stageName)
		}
		required[stageName] = true
	}
	if err := rows.Err(); err != nil {
		return StoredReplay{}, fmt.Errorf("iterate replay artifacts: %w", err)
	}
	for stageName, present := range required {
		if !present {
			return StoredReplay{}, fmt.Errorf("missing replay artifact stage %q", stageName)
		}
	}
	if strings.TrimSpace(captureJSON) == "" {
		return StoredReplay{}, errors.New("missing capture artifact payload")
	}
	if err := json.Unmarshal([]byte(captureJSON), &stored.Envelope); err != nil {
		return StoredReplay{}, fmt.Errorf("decode capture artifact envelope: %w", err)
	}
	return stored, nil
}

func VerifyStoredReplay(ctx context.Context, conn *db.TrustedConn, replayID uuid.UUID) (ReplayCheckResult, error) {
	stored, err := LoadStoredReplay(ctx, conn, replayID)
	if err != nil {
		return ReplayCheckResult{}, err
	}
	result, err := RunEnvelope(ctx, stored.Envelope)
	if err != nil {
		return ReplayCheckResult{}, err
	}

	if stored.InputHash != result.InputHash {
		return ReplayCheckResult{
			Status:       "FAIL",
			Stage:        stageCapture,
			ExpectedHash: stored.InputHash,
			ActualHash:   result.InputHash,
		}, nil
	}
	if stage, expectedHash, actualHash, ok := FirstStageMismatch(stored.StageHashes, result.StageHashes); ok {
		return ReplayCheckResult{
			Status:       "FAIL",
			Stage:        stage,
			ExpectedHash: expectedHash,
			ActualHash:   actualHash,
		}, nil
	}
	if stored.ExpectedHash != result.OutputHash {
		return ReplayCheckResult{
			Status:       "FAIL",
			Stage:        stageFinal,
			ExpectedHash: stored.ExpectedHash,
			ActualHash:   result.OutputHash,
		}, nil
	}
	if stored.ActualHash != stored.ExpectedHash {
		return ReplayCheckResult{
			Status:       "FAIL",
			Stage:        stageFinal,
			ExpectedHash: stored.ExpectedHash,
			ActualHash:   stored.ActualHash,
		}, nil
	}

	return ReplayCheckResult{
		Status:     "PASS",
		InputHash:  result.InputHash,
		OutputHash: result.OutputHash,
	}, nil
}

func envEnabled(name string) bool {
	value := strings.TrimSpace(strings.ToLower(os.Getenv(name)))
	return value == "1" || value == "true" || value == "yes" || value == "on"
}
