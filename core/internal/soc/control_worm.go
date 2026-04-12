package soc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	corecrypto "ransomeye/core/internal/crypto"
	"ransomeye/core/internal/forensics"
)

const maxReplayRequestsPerWS = 5

// replayLogicalClockWindow rejects replay windows older than this span vs current DB max.
const replayLogicalClockWindow = int64(10000)

// ControlAction is the canonical forensic envelope for SOC control-plane mutations (signed + WORM).
type ControlAction struct {
	ActionID  uuid.UUID `json:"action_id"`
	Type      string    `json:"type"`
	Actor     string    `json:"actor"`
	Payload   []byte    `json:"payload"`
	Timestamp time.Time `json:"timestamp"`
}

// controlActionCanonicalJSON builds deterministic JSON (sorted keys) for the control envelope.
func controlActionCanonicalJSON(ca ControlAction) ([]byte, error) {
	m := map[string]any{
		"action_id": ca.ActionID.String(),
		"actor":     ca.Actor,
		"payload":   base64.StdEncoding.EncodeToString(ca.Payload),
		"timestamp": ca.Timestamp.UTC().Format(time.RFC3339Nano),
		"type":      ca.Type,
	}
	return forensics.MarshalCanonical(m)
}

// persistControlWORM seals plaintext JSON (AES-256-GCM), signs Ed25519, writes sealed blob,
// inserts worm_evidence in the same transaction, RFC 6962 ledger leaf + merkle_daily_roots rollup.
// Returns absolute file path for rollback on commit failure.
func (s *Server) persistControlWORM(
	ctx context.Context,
	tx pgx.Tx,
	tenantID uuid.UUID,
	detectionID *uuid.UUID,
	actionType, actor string,
	payload []byte,
) (sealedPath string, err error) {
	if s == nil || s.worm == nil {
		return "", errors.New("worm crypto not configured")
	}
	if s.wormStorageRoot == "" {
		return "", errors.New("WORM storage path not configured")
	}

	actionID := uuid.New()
	now := time.Now().UTC()
	ca := ControlAction{
		ActionID:  actionID,
		Type:      actionType,
		Actor:     actor,
		Payload:   append([]byte(nil), payload...),
		Timestamp: now,
	}
	plaintext, err := controlActionCanonicalJSON(ca)
	if err != nil {
		return "", err
	}

	ciphertext, nonce, err := s.worm.EncryptEvidence(plaintext)
	if err != nil {
		return "", err
	}

	logicalClock := ca.Timestamp.UnixNano()
	sig, err := s.worm.SignEvidence(ciphertext, logicalClock, actor, actionID.String(), actionType)
	if err != nil {
		return "", err
	}
	if !s.worm.VerifyEvidence(ciphertext, logicalClock, actor, actionID.String(), actionType, sig) {
		return "", errors.New("worm self-verify failed (fail closed)")
	}

	blob := make([]byte, 0, len(nonce)+len(ciphertext))
	blob = append(blob, nonce...)
	blob = append(blob, ciphertext...)

	canonicalSum := sha256.Sum256(plaintext)
	canonicalHex := hex.EncodeToString(canonicalSum[:])
	wormHash := sha256.Sum256(blob)
	wormHex := hex.EncodeToString(wormHash[:])
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	if err := forensics.MustBeSealed(&forensics.Event{WormSignature: sig, Hash: wormHex}); err != nil {
		return "", err
	}

	evidenceID := uuid.New()
	sealedPath = filepath.Join(s.wormStorageRoot, "soc_control", tenantID.String(), evidenceID.String()+".sealed")
	if err := os.MkdirAll(filepath.Dir(sealedPath), 0o755); err != nil {
		return "", err
	}
	tmp := sealedPath + ".tmp"
	if err := os.WriteFile(tmp, blob, 0o644); err != nil {
		return "", err
	}
	if err := os.Chmod(tmp, 0o444); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	if err := os.Rename(tmp, sealedPath); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	if st, err := os.Stat(sealedPath); err != nil {
		_ = os.Remove(sealedPath)
		return "", err
	} else if st.Mode().Perm() != 0o444 {
		_ = os.Remove(sealedPath)
		return "", fmt.Errorf("sealed file mode want 0444 got %#o", st.Mode().Perm())
	}

	const qWorm = `
INSERT INTO worm_evidence (
    evidence_id, tenant_id, detection_id, event_id, evidence_type, file_path,
    canonical_json_hash, worm_file_hash, ed25519_sig, retention_tier, file_size_bytes, dropped_packets_before,
    soc_merkle_leaf
) VALUES (
    $1::uuid, $2::uuid, $3::uuid, $4::uuid, 'CUSTOM', $5::text,
    $6::text, $7::text, $8::text, 'hot', $9::bigint, 0,
    $10::bytea
)`
	var det any
	if detectionID != nil {
		det = *detectionID
	}
	_, err = tx.Exec(ctx, qWorm,
		evidenceID,
		tenantID,
		det,
		actionID,
		sealedPath,
		canonicalHex,
		wormHex,
		sigB64,
		int64(len(blob)),
		append([]byte(nil), plaintext...),
	)
	if err != nil {
		_ = os.Remove(sealedPath)
		return "", err
	}

	leafHex := hex.EncodeToString(forensics.LeafHash(plaintext))
	tag, err := tx.Exec(ctx, `
UPDATE exposure_worm_ledger SET leaf_hash = $1
WHERE evidence_id = $2 AND tenant_id = $3`,
		leafHex, evidenceID, tenantID)
	if err != nil {
		_ = os.Remove(sealedPath)
		return "", fmt.Errorf("worm ledger leaf_hash RFC6962: %w", err)
	}
	if tag.RowsAffected() == 0 {
		_ = os.Remove(sealedPath)
		return "", errors.New("exposure_worm_ledger: leaf_hash update matched no rows (fail closed)")
	}

	if err := s.persistSocMerkleDailyRFC6962(ctx, tx, tenantID); err != nil {
		_ = os.Remove(sealedPath)
		return "", err
	}

	return sealedPath, nil
}

func (s *Server) persistSocMerkleDailyRFC6962(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID) error {
	now := time.Now().UTC()
	dailyDate := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)

	rows, err := tx.Query(ctx, `
SELECT w.soc_merkle_leaf
FROM worm_evidence w
INNER JOIN exposure_worm_ledger ewl ON ewl.evidence_id = w.evidence_id
WHERE w.tenant_id = $1
  AND ewl.daily_date = $2::date
  AND w.soc_merkle_leaf IS NOT NULL
ORDER BY ewl.merkle_position ASC`,
		tenantID, dailyDate)
	if err != nil {
		return fmt.Errorf("merkle leaf load: %w", err)
	}
	defer rows.Close()

	var leaves [][]byte
	for rows.Next() {
		var leaf []byte
		if err := rows.Scan(&leaf); err != nil {
			return fmt.Errorf("merkle leaf scan: %w", err)
		}
		leaves = append(leaves, append([]byte(nil), leaf...))
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(leaves) == 0 {
		return errors.New("merkle: no leaves after WORM insert (fail closed)")
	}

	rfcRoot, err := forensics.MerkleTreeHash(leaves)
	if err != nil {
		return err
	}

	var priorRootHex string
	err = tx.QueryRow(ctx, `
SELECT merkle_root FROM merkle_daily_roots
WHERE tenant_id = $1 AND daily_date = $2::date
FOR UPDATE`,
		tenantID, dailyDate).Scan(&priorRootHex)
	hasPriorRow := true
	if errors.Is(err, pgx.ErrNoRows) {
		hasPriorRow = false
		err = nil
		priorRootHex = ""
	}
	if err != nil {
		return fmt.Errorf("merkle_daily_roots lock: %w", err)
	}

	var prevInner []byte
	if priorRootHex != "" {
		prevInner, err = hex.DecodeString(priorRootHex)
		if err != nil || len(prevInner) != sha256.Size {
			return errors.New("merkle: corrupt prior daily root")
		}
	}

	chained := corecrypto.ComputeChainedRoot(prevInner, rfcRoot)
	sig, err := s.worm.SignChainedMerkleDigest(chained)
	if err != nil {
		return err
	}
	if !s.worm.VerifyChainedMerkleDigest(chained, sig) {
		return errors.New("merkle rollup signature self-verify failed")
	}
	sigB64 := base64.StdEncoding.EncodeToString(sig)
	prevHex := ""
	if len(prevInner) > 0 {
		prevHex = hex.EncodeToString(prevInner)
	}
	rfcHex := hex.EncodeToString(rfcRoot)
	computedAt := time.Now().UTC()
	leafCount := len(leaves)

	if !hasPriorRow {
		_, err = tx.Exec(ctx, `
INSERT INTO merkle_daily_roots (tenant_id, daily_date, merkle_root, prev_root_hash, leaf_count, computed_at, ed25519_sig)
VALUES ($1, $2::date, $3, $4, $5, $6, $7)`,
			tenantID, dailyDate, rfcHex, prevHex, leafCount, computedAt, sigB64)
	} else {
		_, err = tx.Exec(ctx, `
UPDATE merkle_daily_roots SET
    merkle_root = $3,
    prev_root_hash = $4,
    leaf_count = $5,
    computed_at = $6,
    ed25519_sig = $7
WHERE tenant_id = $1 AND daily_date = $2::date`,
			tenantID, dailyDate, rfcHex, prevHex, leafCount, computedAt, sigB64)
	}
	if err != nil {
		return fmt.Errorf("merkle_daily_roots persist: %w", err)
	}
	return nil
}

func removeWORMFile(path string) {
	if path != "" {
		_ = os.Remove(path)
	}
}

// mustWorm returns an error if control actions cannot be persisted.
func (s *Server) mustWorm() error {
	if s == nil || s.worm == nil {
		return errors.New("worm not configured")
	}
	if s.wormStorageRoot == "" {
		return errors.New("worm storage not configured")
	}
	return nil
}
