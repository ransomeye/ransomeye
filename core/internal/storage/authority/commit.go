package authority

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AuthorityRef references a row in authority_snapshots that must exist before commit.
type AuthorityRef struct {
	Type    string
	ID      string
	Version string
}

// SnapshotUpsert is a deterministic, caller-supplied authority snapshot (no inference).
type SnapshotUpsert struct {
	Type                 string
	ID                   string
	Version              string
	CanonicalPayloadText string
	PayloadHash          [32]byte
	Signature            []byte
}

// RecordDraft is one row to append in a batch (execution context is batch-level).
type RecordDraft struct {
	RecordType            string
	RecordVersion         string
	StageOrder            uint16
	RecordID              []byte
	MessageID             []byte
	AgentID               []byte
	BootSessionID         []byte
	LogicalClock          *uint64
	LogicalShardID        []byte
	CausalParentRefsText  string
	CanonicalPayloadText  *string
	CanonicalPayloadBytes []byte
	CanonicalPayloadHash  [32]byte
	PayloadHash           *[32]byte
	Signature             []byte
	PartitionContext      []byte
	SchemaVersion         *string
	SchemaTransformHash   *[32]byte
}

// ReplayGuardAdmittedRow is written in the same transaction as the commit boundary (PRD-13 + PRD-08 coupling).
type ReplayGuardAdmittedRow struct {
	LogicalShardID []byte
	EmitterID      []byte
	BootSessionID  []byte
	LogicalClock   uint64
	MessageID      []byte
}

// CommitOptions configures a single authoritative batch (PRD-13 §8.3).
type CommitOptions struct {
	PartitionID    int64
	PartitionEpoch int64
	// ExecutionContextHash must be identical for every record in the batch (PRD-13 BATCH_EXECUTION_CONTEXT_UNIFORMITY).
	ExecutionContextHash [32]byte

	Records []RecordDraft

	// AuthorityRefs must already exist in authority_snapshots unless AuthoritySnapshots supplies them in the same commit.
	AuthorityRefs []AuthorityRef
	// AuthoritySnapshots optional insert-before-verify (deterministic bytes only; no AI/SINE).
	AuthoritySnapshots []SnapshotUpsert

	ReplayGuard []ReplayGuardAdmittedRow

	PrivateKey ed25519.PrivateKey
	// KeyID is stored verbatim (PRD-13); typically lowercase hex of the verifying key (32 bytes).
	KeyID    string
	KeyEpoch int64
}

// CommitPartitionBatch runs advisory lock + atomic append of partition_records, batch_commit_records,
// batch_commit_authority_bindings, and optional replay_guard rows in one transaction.
func CommitPartitionBatch(ctx context.Context, pool *pgxpool.Pool, opts CommitOptions) error {
	if pool == nil {
		return errors.New("nil pool")
	}
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := CommitPartitionBatchTx(ctx, tx, opts); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// CommitPartitionBatchTx is the transactional core (single database transaction).
func CommitPartitionBatchTx(ctx context.Context, tx pgx.Tx, opts CommitOptions) error {
	if len(opts.Records) == 0 {
		return errors.New("empty batch forbidden")
	}
	if opts.PrivateKey == nil || len(opts.PrivateKey) != ed25519.PrivateKeySize {
		return errors.New("invalid ed25519 private key")
	}
	if opts.KeyID == "" {
		return errors.New("key_id required")
	}
	if len(opts.ExecutionContextHash) != 32 {
		return errors.New("execution_context_hash must be 32 bytes")
	}
	if err := validateSignalRecordsInBatch(opts); err != nil {
		return err
	}

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, opts.PartitionID); err != nil {
		return fmt.Errorf("advisory lock: %w", err)
	}

	// PRD-01 / PRD-04 / PRD-13 / PRD-15:
	// Every authority snapshot upsert MUST be verified against RFC 8785 canonical bytes before commit.
	// Signature verification MUST use committed trust material only (bound trust_snapshot).
	trustDoc, trustIndex, err := resolveCommitTrustSnapshotIndex(ctx, tx, opts)
	if err != nil {
		return err
	}
	_ = trustDoc

	// PRD-01 / PRD-04 / PRD-13 / PRD-15:
	// Validate every referenced committed authority snapshot before we bind it into this batch.
	for _, ref := range opts.AuthorityRefs {
		if err := validateCommittedAuthorityRef(ctx, tx, ref, trustIndex); err != nil {
			return err
		}
	}

	for _, snap := range opts.AuthoritySnapshots {
		// PRD-01 / PRD-04 / PRD-13 / PRD-15:
		// Fail closed before commit if any upsert is non-canonical or cryptographically invalid.
		if err := verifyAuthoritySnapshotUpsert(snap, trustIndex); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `
INSERT INTO authority_snapshots (authority_type, authority_id, authority_version, canonical_payload_text, payload_hash, signature)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (authority_type, authority_id, authority_version) DO NOTHING`,
			snap.Type, snap.ID, snap.Version, snap.CanonicalPayloadText, snap.PayloadHash[:], snap.Signature)
		if err != nil {
			return fmt.Errorf("authority_snapshots upsert: %w", err)
		}
	}

	// PRD-01 / PRD-04 / PRD-13 / PRD-15:
	// Build the final bound authority set deterministically and fail closed on ambiguity.
	// Rules:
	// - non-empty authority set required
	// - exactly one CONFIG/trust_snapshot required
	// - duplicate logical bindings after normalization are forbidden
	bindRefs, err := buildNormalizedBindSet(opts.AuthorityRefs, opts.AuthoritySnapshots)
	if err != nil {
		return err
	}

	bindingPayloadHashes := make([][32]byte, 0, len(bindRefs))
	for _, ref := range bindRefs {
		var ph []byte
		err := tx.QueryRow(ctx, `
SELECT payload_hash FROM authority_snapshots
WHERE authority_type = $1 AND authority_id = $2 AND authority_version = $3`,
			ref.Type, ref.ID, ref.Version).Scan(&ph)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("authority snapshot missing: %s/%s/%s", ref.Type, ref.ID, ref.Version)
			}
			return fmt.Errorf("authority snapshot lookup: %w", err)
		}
		if len(ph) != 32 {
			return fmt.Errorf("authority snapshot payload_hash length %d for %s/%s/%s", len(ph), ref.Type, ref.ID, ref.Version)
		}
		var h32 [32]byte
		copy(h32[:], ph)
		bindingPayloadHashes = append(bindingPayloadHashes, h32)
	}

	if err := validateSignalCommitAuthorityClosure(opts, bindRefs, bindingPayloadHashes); err != nil {
		return err
	}

	var lastSeq int64
	var lastRecordHash []byte
	err = tx.QueryRow(ctx, `
SELECT partition_record_seq, record_hash
FROM partition_records
WHERE partition_id = $1
ORDER BY partition_record_seq DESC
LIMIT 1`, opts.PartitionID).Scan(&lastSeq, &lastRecordHash)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("load partition head: %w", err)
	}

	var chainPrev [32]byte
	if errors.Is(err, pgx.ErrNoRows) || lastSeq == 0 {
		chainPrev = ZeroHash32
		lastSeq = 0
	} else {
		if len(lastRecordHash) != 32 {
			return fmt.Errorf("stored record_hash length %d", len(lastRecordHash))
		}
		copy(chainPrev[:], lastRecordHash)
	}

	var lastBatchSeq int64
	var prevBatchCommitHash []byte
	err = tx.QueryRow(ctx, `
SELECT batch_commit_seq, batch_commit_hash
FROM batch_commit_records
WHERE partition_id = $1
ORDER BY batch_commit_seq DESC
LIMIT 1`, opts.PartitionID).Scan(&lastBatchSeq, &prevBatchCommitHash)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("load batch head: %w", err)
	}
	var prevBatch [32]byte
	nextBatchSeq := int64(1)
	if err == nil && lastBatchSeq > 0 {
		nextBatchSeq = lastBatchSeq + 1
		if len(prevBatchCommitHash) != 32 {
			return fmt.Errorf("stored batch_commit_hash length %d", len(prevBatchCommitHash))
		}
		copy(prevBatch[:], prevBatchCommitHash)
	} else {
		prevBatch = ZeroHash32
	}

	if nextBatchSeq == 1 && prevBatch != ZeroHash32 {
		return errors.New("genesis batch must use zero previous_batch_commit_hash")
	}
	if nextBatchSeq > 1 && prevBatch == ZeroHash32 {
		return errors.New("non-genesis batch requires non-zero previous_batch_commit_hash")
	}

	firstSeq := lastSeq + 1
	if firstSeq == 1 && chainPrev != ZeroHash32 {
		return errors.New("genesis partition_record requires zero previous_record_hash")
	}

	seqs := make([]uint64, len(opts.Records))
	hashes := make([][32]byte, len(opts.Records))
	pid := uint64(opts.PartitionID)
	pe := uint64(opts.PartitionEpoch)

	nilBytes := func(b []byte) []byte {
		if len(b) == 0 {
			return nil
		}
		return b
	}

	for i := range opts.Records {
		rec := opts.Records[i]
		if err := ValidatePRD13RecordType(rec.RecordType); err != nil {
			return fmt.Errorf("record %d: %w", i, err)
		}
		if err := ValidatePRD13StageOrder(rec.RecordType, rec.StageOrder); err != nil {
			return fmt.Errorf("record %d: %w", i, err)
		}
		if rec.CanonicalPayloadBytes == nil {
			rec.CanonicalPayloadBytes = []byte{}
		}
		curSeq := uint64(firstSeq + int64(i))
		seqs[i] = curSeq

		wire := PartitionRecordWire{
			RecordType:            rec.RecordType,
			RecordVersion:         rec.RecordVersion,
			PartitionID:           pid,
			PartitionEpoch:        pe,
			PartitionRecordSeq:    curSeq,
			LogicalShardID:        rec.LogicalShardID,
			ShardSeq:              curSeq,
			StageOrder:            rec.StageOrder,
			RecordID:              rec.RecordID,
			MessageID:             nilBytes(rec.MessageID),
			AgentID:               nilBytes(rec.AgentID),
			BootSessionID:         nilBytes(rec.BootSessionID),
			LogicalClock:          rec.LogicalClock,
			CausalParentRefsText:  rec.CausalParentRefsText,
			CanonicalPayloadBytes: rec.CanonicalPayloadBytes,
			CanonicalPayloadHash:  rec.CanonicalPayloadHash,
			PayloadHash:           rec.PayloadHash,
			Signature:             nilBytes(rec.Signature),
			PartitionContext:      nilBytes(rec.PartitionContext),
			SchemaVersion:         rec.SchemaVersion,
			SchemaTransformHash:   rec.SchemaTransformHash,
		}
		canonical, err := CanonicalRecordBytes(wire)
		if err != nil {
			return fmt.Errorf("record %d canonical: %w", i, err)
		}
		previousForRow := chainPrev
		rh := RecordHash(chainPrev, canonical)
		hashes[i] = rh
		chainPrev = rh

		if err := insertPartitionRecord(ctx, tx, opts.PartitionID, opts.PartitionEpoch, int64(curSeq), rec, opts.ExecutionContextHash, previousForRow, rh); err != nil {
			return fmt.Errorf("insert partition_records %d: %w", i, err)
		}
	}

	firstU := uint64(firstSeq)
	lastU := uint64(firstSeq + int64(len(opts.Records)) - 1)
	rcount := uint64(len(opts.Records))
	root, err := BatchRootHash(seqs, hashes)
	if err != nil {
		return err
	}
	bCommitHash, err := BatchCommitHash(
		pid, pe, uint64(nextBatchSeq),
		firstU, lastU, rcount,
		hashes[0], hashes[len(hashes)-1], root, prevBatch, opts.ExecutionContextHash,
	)
	if err != nil {
		return err
	}
	if err := ValidateBatchCommitRecordShape(BatchCommitRecordShape{
		SigningContext:          BatchCommitSigningContext,
		FirstRecordHash:         hashes[0],
		LastRecordHash:          hashes[len(hashes)-1],
		BatchRootHash:           root,
		PreviousBatchCommitHash: prevBatch,
		ExecutionContextHash:    opts.ExecutionContextHash,
		BatchCommitHash:         bCommitHash,
	}); err != nil {
		return err
	}

	sigPayload := BatchCommitSignaturePayloadJSON(
		pid, pe, uint64(nextBatchSeq),
		firstU, lastU, rcount,
		hashes[0], hashes[len(hashes)-1], root, prevBatch, opts.ExecutionContextHash,
	)
	ph := sha256.Sum256(sigPayload)
	sigInput := append([]byte(BatchCommitSigningContext), ph[:]...)
	signature := ed25519.Sign(opts.PrivateKey, sigInput)

	batchCommitID := DeterministicBatchCommitID(opts.PartitionID, opts.PartitionEpoch, nextBatchSeq, opts.ExecutionContextHash, bCommitHash)

	_, err = tx.Exec(ctx, `
INSERT INTO batch_commit_records (
  partition_id, batch_commit_seq, batch_commit_id, partition_epoch,
  first_partition_record_seq, last_partition_record_seq, record_count,
  first_record_hash, last_record_hash, batch_root_hash, previous_batch_commit_hash,
  signing_context, key_id, key_epoch, execution_context_hash, signature, batch_commit_hash
) VALUES (
  $1, $2, $3, $4,
  $5, $6, $7,
  $8, $9, $10, $11,
  $12, $13, $14, $15, $16, $17
)`,
		opts.PartitionID, nextBatchSeq, batchCommitID[:], opts.PartitionEpoch,
		firstSeq, firstSeq+int64(len(opts.Records))-1, int64(rcount),
		hashes[0][:], hashes[len(hashes)-1][:], root[:], prevBatch[:],
		BatchCommitSigningContext, opts.KeyID, opts.KeyEpoch, opts.ExecutionContextHash[:], signature, bCommitHash[:],
	)
	if err != nil {
		return fmt.Errorf("insert batch_commit_records: %w", err)
	}

	// Deterministic explicit binding at commit time (PRD-13): stable lexicographic order.
	sort.Slice(bindRefs, func(i, j int) bool {
		if bindRefs[i].Type != bindRefs[j].Type {
			return bindRefs[i].Type < bindRefs[j].Type
		}
		if bindRefs[i].ID != bindRefs[j].ID {
			return bindRefs[i].ID < bindRefs[j].ID
		}
		return bindRefs[i].Version < bindRefs[j].Version
	})
	for _, ref := range bindRefs {
		_, err := tx.Exec(ctx, `
INSERT INTO batch_commit_authority_bindings (partition_id, batch_commit_seq, authority_type, authority_id, authority_version)
VALUES ($1, $2, $3, $4, $5)`,
			opts.PartitionID, nextBatchSeq, ref.Type, ref.ID, ref.Version)
		if err != nil {
			return fmt.Errorf("insert batch_commit_authority_bindings: %w", err)
		}
	}

	for _, rg := range opts.ReplayGuard {
		// pre_auth_nonce must be non-NULL for normal admits when the table has
		// UNIQUE NULLS NOT DISTINCT (partition_id, logical_shard_id, pre_auth_nonce): otherwise
		// every NULL collides and only one row per shard is possible. Use message_id bytes as the
		// row distinguisher (distinct per PK); migration 047 replaces this with a partial unique index.
		nonce := append([]byte(nil), rg.MessageID...)
		_, err := tx.Exec(ctx, `
INSERT INTO replay_guard (
  partition_id, logical_shard_id, emitter_id, boot_session_id, logical_clock, message_id, seen_state, pre_auth_nonce
) VALUES ($1, $2, $3, $4, $5::numeric, $6, 'ADMITTED', $7)`,
			opts.PartitionID, rg.LogicalShardID, rg.EmitterID, rg.BootSessionID, strconv.FormatUint(rg.LogicalClock, 10), rg.MessageID, nonce)
		if err != nil {
			return fmt.Errorf("insert replay_guard: %w", err)
		}
	}

	return nil
}

func buildNormalizedBindSet(refs []AuthorityRef, snaps []SnapshotUpsert) ([]AuthorityRef, error) {
	out := make([]AuthorityRef, 0, len(refs)+len(snaps))
	for _, r := range refs {
		if strings.TrimSpace(r.Type) == "" || strings.TrimSpace(r.ID) == "" || strings.TrimSpace(r.Version) == "" {
			return nil, FailType1("INPUT_ERROR", errors.New("authority_ref fields required"))
		}
		if r.Type != strings.TrimSpace(r.Type) || r.ID != strings.TrimSpace(r.ID) || r.Version != strings.TrimSpace(r.Version) {
			return nil, FailType1("INPUT_ERROR", errors.New("authority_ref must not have surrounding whitespace"))
		}
		out = append(out, r)
	}
	for _, s := range snaps {
		r := AuthorityRef{Type: s.Type, ID: s.ID, Version: s.Version}
		if strings.TrimSpace(r.Type) == "" || strings.TrimSpace(r.ID) == "" || strings.TrimSpace(r.Version) == "" {
			return nil, FailType1("INPUT_ERROR", errors.New("authority_snapshot ref fields required"))
		}
		if r.Type != strings.TrimSpace(r.Type) || r.ID != strings.TrimSpace(r.ID) || r.Version != strings.TrimSpace(r.Version) {
			return nil, FailType1("INPUT_ERROR", errors.New("authority_snapshot ref must not have surrounding whitespace"))
		}
		out = append(out, r)
	}
	if len(out) == 0 {
		return nil, FailType1("MISSING_AUTHORITY_SET", errors.New("missing batch_commit_authority_bindings (empty authority set forbidden)"))
	}

	// Sort then enforce uniqueness + trust_snapshot cardinality deterministically.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		if out[i].ID != out[j].ID {
			return out[i].ID < out[j].ID
		}
		return out[i].Version < out[j].Version
	})

	uniq := make([]AuthorityRef, 0, len(out))
	var trustCount int
	var prev *AuthorityRef
	for i := range out {
		r := out[i]
		if prev != nil && prev.Type == r.Type && prev.ID == r.ID && prev.Version == r.Version {
			// Identical logical binding can appear once in refs and once in snapshots;
			// collapse deterministically rather than failing.
			continue
		}
		uniq = append(uniq, r)
		if r.Type == trustAuthorityType && r.ID == trustAuthorityID {
			trustCount++
		}
		prev = &out[i]
	}
	if trustCount == 0 {
		return nil, FailType1("MISSING_TRUST_SNAPSHOT", errors.New("missing bound trust_snapshot"))
	}
	if trustCount != 1 {
		return nil, FailType1("AMBIGUOUS_TRUST_SNAPSHOT", errors.New("ambiguous bound trust_snapshot"))
	}
	return uniq, nil
}

func resolveCommitTrustSnapshotIndex(ctx context.Context, tx pgx.Tx, opts CommitOptions) (trustSnapshotDoc, map[string]keyRecord, error) {
	// Prefer trust_snapshot provided in the same commit (strongest, deterministic).
	var upserts []SnapshotUpsert
	for _, s := range opts.AuthoritySnapshots {
		if s.Type == trustAuthorityType && s.ID == trustAuthorityID {
			upserts = append(upserts, s)
		}
	}
	if len(upserts) == 1 {
		doc, idx, err := parseTrustSnapshotUpsertCanonical(upserts[0])
		if err != nil {
			return trustSnapshotDoc{}, nil, err
		}
		// Verify signature using trust material inside snapshot only.
		canonical := []byte(upserts[0].CanonicalPayloadText)
		if err := verifyTrustSnapshotSignature(idx, canonical, upserts[0].Signature); err != nil {
			return trustSnapshotDoc{}, nil, err
		}
		return doc, idx, nil
	}
	if len(upserts) > 1 {
		return trustSnapshotDoc{}, nil, FailType1("AMBIGUOUS_TRUST_SNAPSHOT", errors.New("ambiguous trust_snapshot upsert"))
	}

	// Otherwise, resolve from pre-existing committed authority_snapshots via AuthorityRefs.
	var refs []AuthorityRef
	for _, r := range opts.AuthorityRefs {
		if r.Type == trustAuthorityType && r.ID == trustAuthorityID {
			refs = append(refs, r)
		}
	}
	if len(refs) == 0 {
		return trustSnapshotDoc{}, nil, FailType1("MISSING_TRUST_SNAPSHOT", errors.New("missing bound trust_snapshot (required for authority snapshot signature verification)"))
	}
	if len(refs) != 1 {
		return trustSnapshotDoc{}, nil, FailType1("AMBIGUOUS_TRUST_SNAPSHOT", errors.New("ambiguous bound trust_snapshot (required for authority snapshot signature verification)"))
	}

	var payloadText string
	var payloadHash []byte
	var sig []byte
	if err := tx.QueryRow(ctx, `
SELECT canonical_payload_text, payload_hash, signature
FROM authority_snapshots
WHERE authority_type = $1 AND authority_id = $2 AND authority_version = $3`,
		refs[0].Type, refs[0].ID, refs[0].Version,
	).Scan(&payloadText, &payloadHash, &sig); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return trustSnapshotDoc{}, nil, FailType2("STATE_INCONSISTENCY", errors.New("trust_snapshot missing"))
		}
		return trustSnapshotDoc{}, nil, FailType2("STATE_INCONSISTENCY", err)
	}
	if strings.TrimSpace(payloadText) == "" {
		return trustSnapshotDoc{}, nil, FailType3("INTEGRITY_FAILURE", errors.New("trust_snapshot empty payload"))
	}
	if len(payloadHash) != 32 {
		return trustSnapshotDoc{}, nil, FailType3("INTEGRITY_FAILURE", errors.New("trust_snapshot payload_hash length invalid"))
	}
	if len(sig) != ed25519.SignatureSize {
		return trustSnapshotDoc{}, nil, FailType3("INTEGRITY_FAILURE", errors.New("trust_snapshot signature length invalid"))
	}

	raw := []byte(payloadText)
	canonical, err := canonicalizeStrictJSONRFC8785(raw)
	if err != nil {
		return trustSnapshotDoc{}, nil, FailType3("CANONICALIZATION_VIOLATION", errors.New("trust_snapshot malformed JSON"))
	}
	if !bytes.Equal(raw, canonical) {
		return trustSnapshotDoc{}, nil, FailType3("CANONICALIZATION_VIOLATION", errors.New("trust_snapshot non-canonical JSON"))
	}
	wantPH := sha256.Sum256(canonical)
	if bytesTo32(payloadHash) != wantPH {
		return trustSnapshotDoc{}, nil, FailType3("INTEGRITY_FAILURE", errors.New("trust_snapshot payload_hash mismatch"))
	}
	doc, idx, err := parseTrustSnapshotCanonicalPayload(canonical)
	if err != nil {
		return trustSnapshotDoc{}, nil, err
	}
	if err := verifyTrustSnapshotSignature(idx, canonical, sig); err != nil {
		return trustSnapshotDoc{}, nil, FailType3("SIGNATURE_MISMATCH", err)
	}
	return doc, idx, nil
}

func validateCommittedAuthorityRef(ctx context.Context, tx pgx.Tx, ref AuthorityRef, trustIndex map[string]keyRecord) error {
	// trust_snapshot itself is already validated as the trust basis above (and also validated if upserted).
	if ref.Type == trustAuthorityType && ref.ID == trustAuthorityID {
		return nil
	}

	var payloadText string
	var payloadHash []byte
	var sig []byte
	if err := tx.QueryRow(ctx, `
SELECT canonical_payload_text, payload_hash, signature
FROM authority_snapshots
WHERE authority_type = $1 AND authority_id = $2 AND authority_version = $3`,
		ref.Type, ref.ID, ref.Version,
	).Scan(&payloadText, &payloadHash, &sig); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return FailType1("INPUT_ERROR", fmt.Errorf("authority snapshot missing: %s/%s/%s", ref.Type, ref.ID, ref.Version))
		}
		return FailType2("STATE_INCONSISTENCY", fmt.Errorf("authority snapshot lookup: %w", err))
	}
	if len(payloadHash) != 32 {
		return fmt.Errorf("authority snapshot payload_hash length %d: %s/%s/%s", len(payloadHash), ref.Type, ref.ID, ref.Version)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("authority snapshot signature length %d: %s/%s/%s", len(sig), ref.Type, ref.ID, ref.Version)
	}

	snap := SnapshotUpsert{
		Type:                 ref.Type,
		ID:                   ref.ID,
		Version:              ref.Version,
		CanonicalPayloadText: payloadText,
		PayloadHash:          bytesTo32(payloadHash),
		Signature:            sig,
	}
	if err := verifyAuthoritySnapshotUpsert(snap, trustIndex); err != nil {
		return FailType3("INTEGRITY_FAILURE", fmt.Errorf("authority snapshot invalid: %s/%s/%s: %w", ref.Type, ref.ID, ref.Version, err))
	}
	return nil
}

func parseTrustSnapshotUpsertCanonical(snap SnapshotUpsert) (trustSnapshotDoc, map[string]keyRecord, error) {
	if strings.TrimSpace(snap.CanonicalPayloadText) == "" {
		return trustSnapshotDoc{}, nil, FailType1("INPUT_ERROR", errors.New("trust snapshot empty payload"))
	}
	if len(snap.Signature) != ed25519.SignatureSize {
		return trustSnapshotDoc{}, nil, FailType1("INPUT_ERROR", errors.New("trust snapshot signature length invalid"))
	}
	raw := []byte(snap.CanonicalPayloadText)
	canonical, err := canonicalizeStrictJSONRFC8785(raw)
	if err != nil {
		return trustSnapshotDoc{}, nil, FailType1("CANONICALIZATION_VIOLATION", errors.New("trust snapshot malformed JSON"))
	}
	if !bytes.Equal(raw, canonical) {
		return trustSnapshotDoc{}, nil, FailType1("CANONICALIZATION_VIOLATION", errors.New("trust snapshot non-canonical JSON"))
	}
	wantPH := sha256.Sum256(canonical)
	if snap.PayloadHash != wantPH {
		return trustSnapshotDoc{}, nil, FailType1("PAYLOAD_HASH_MISMATCH", errors.New("trust snapshot payload_hash mismatch"))
	}
	return parseTrustSnapshotCanonicalPayload(canonical)
}

func verifyAuthoritySnapshotUpsert(snap SnapshotUpsert, trustIndex map[string]keyRecord) error {
	// Trust snapshot requires additional checks (key_records validation + self-contained signature).
	if snap.Type == trustAuthorityType && snap.ID == trustAuthorityID {
		doc, idx, err := parseTrustSnapshotUpsertCanonical(snap)
		if err != nil {
			return err
		}
		_ = doc
		if err := verifyTrustSnapshotSignature(idx, []byte(snap.CanonicalPayloadText), snap.Signature); err != nil {
			return FailType1("SIGNATURE_MISMATCH", err)
		}
		return nil
	}

	if strings.TrimSpace(snap.CanonicalPayloadText) == "" {
		return FailType1("INPUT_ERROR", errors.New("authority snapshot empty payload"))
	}
	if len(snap.Signature) != ed25519.SignatureSize {
		return FailType1("INPUT_ERROR", errors.New("authority snapshot signature length invalid"))
	}

	raw := []byte(snap.CanonicalPayloadText)
	canonical, err := canonicalizeStrictJSONRFC8785(raw)
	if err != nil {
		return FailType1("CANONICALIZATION_VIOLATION", errors.New("authority snapshot malformed JSON"))
	}
	if !bytes.Equal(raw, canonical) {
		return FailType1("CANONICALIZATION_VIOLATION", errors.New("authority snapshot non-canonical JSON"))
	}
	wantPH := sha256.Sum256(canonical)
	if snap.PayloadHash != wantPH {
		return FailType1("PAYLOAD_HASH_MISMATCH", errors.New("authority snapshot payload_hash mismatch"))
	}

	env, err := parseAuthoritySnapshotEnvelope(string(canonical))
	if err != nil {
		return FailType1("INPUT_ERROR", errors.New("authority snapshot envelope invalid"))
	}
	pub, err := resolveTrustSnapshotPublicKeyFromIndex(trustIndex, env.keyID, env.keyEpoch, env.signingContext)
	if err != nil {
		return FailType1("MISSING_ISSUER", err)
	}
	sum := sha256.Sum256(canonical)
	signingInput := append([]byte(env.signingContext), sum[:]...)
	if !ed25519.Verify(pub, signingInput, snap.Signature) {
		return FailType1("SIGNATURE_MISMATCH", errors.New("authority snapshot signature verify failed"))
	}
	return nil
}

func resolveTrustSnapshotPublicKeyFromIndex(index map[string]keyRecord, keyID string, keyEpoch int64, requiredSigningContext string) (ed25519.PublicKey, error) {
	if strings.TrimSpace(keyID) == "" || keyEpoch <= 0 {
		return nil, errors.New("invalid key_id or key_epoch")
	}
	if strings.TrimSpace(requiredSigningContext) == "" {
		return nil, errors.New("required signing_context missing")
	}
	target, ok := index[keyID]
	if !ok {
		return nil, errors.New("missing key material for key_id")
	}
	if target.KeyEpoch != keyEpoch {
		return nil, errors.New("key_epoch mismatch for key_id")
	}
	if target.Status != "ACTIVE" {
		return nil, errors.New("key material revoked/retired/inapplicable")
	}
	if !containsString(target.AllowedSigningContexts, requiredSigningContext) {
		return nil, errors.New("signing_context not allowed for key")
	}

	visited := make(map[string]struct{}, 8)
	if err := verifyKeyRecordRecursive(index, target.KeyID, visited); err != nil {
		return nil, err
	}
	pubBytes, err := hex.DecodeString(target.PublicKey)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return nil, errors.New("public_key invalid")
	}
	return ed25519.PublicKey(pubBytes), nil
}

func verifyTrustSnapshotUpsert(snap SnapshotUpsert) error {
	if strings.TrimSpace(snap.CanonicalPayloadText) == "" {
		return errors.New("trust snapshot empty payload")
	}
	if len(snap.Signature) != ed25519.SignatureSize {
		return errors.New("trust snapshot signature length invalid")
	}

	// Enforce: provided bytes MUST already be RFC 8785 canonical JSON.
	raw := []byte(snap.CanonicalPayloadText)
	canonical, err := canonicalizeStrictJSONRFC8785(raw)
	if err != nil {
		return errors.New("trust snapshot malformed JSON")
	}
	if !bytes.Equal(raw, canonical) {
		return errors.New("trust snapshot non-canonical JSON")
	}

	// Enforce: payload_hash is SHA256(canonical_bytes).
	wantPH := sha256.Sum256(canonical)
	if snap.PayloadHash != wantPH {
		return errors.New("trust snapshot payload_hash mismatch")
	}

	// Parse + validate key_records shape, key_id derivation, uniqueness, and signer chain.
	doc, keyIndex, err := parseTrustSnapshotCanonicalPayload(canonical)
	if err != nil {
		return err
	}
	_ = doc

	// Enforce: signature verifies over canonical bytes using committed trust material INSIDE the snapshot only.
	if err := verifyTrustSnapshotSignature(keyIndex, canonical, snap.Signature); err != nil {
		return err
	}
	return nil
}

func parseTrustSnapshotCanonicalPayload(canonical []byte) (trustSnapshotDoc, map[string]keyRecord, error) {
	var doc trustSnapshotDoc
	dec := json.NewDecoder(bytes.NewReader(canonical))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return trustSnapshotDoc{}, nil, fmt.Errorf("trust snapshot decode: %w", err)
	}
	// Ensure there are no additional JSON values.
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return trustSnapshotDoc{}, nil, errors.New("trust snapshot payload has trailing data")
	}
	if strings.TrimSpace(doc.VerificationScopeID) == "" {
		return trustSnapshotDoc{}, nil, errors.New("trust snapshot missing verification_scope_id")
	}
	if len(doc.KeyRecords) == 0 {
		return trustSnapshotDoc{}, nil, errors.New("trust snapshot empty key_records")
	}
	keyIndex := make(map[string]keyRecord, len(doc.KeyRecords))
	for _, kr := range doc.KeyRecords {
		if err := validateKeyRecordShape(kr); err != nil {
			return trustSnapshotDoc{}, nil, err
		}
		if err := validateKeyIDDerivation(kr); err != nil {
			return trustSnapshotDoc{}, nil, err
		}
		if _, ok := keyIndex[kr.KeyID]; ok {
			return trustSnapshotDoc{}, nil, errors.New("duplicate key_id in trust snapshot")
		}
		keyIndex[kr.KeyID] = kr
	}
	return doc, keyIndex, nil
}

func insertPartitionRecord(
	ctx context.Context, tx pgx.Tx,
	partitionID, partitionEpoch, seq int64,
	d RecordDraft,
	executionContextHash [32]byte,
	previousRecordHash, recordHash [32]byte,
) error {
	cpb := d.CanonicalPayloadBytes
	if cpb == nil {
		cpb = []byte{}
	}

	var messageID interface{}
	if len(d.MessageID) > 0 {
		messageID = d.MessageID
	}
	var agentID interface{}
	if len(d.AgentID) > 0 {
		agentID = d.AgentID
	}
	var bootID interface{}
	if len(d.BootSessionID) > 0 {
		bootID = d.BootSessionID
	}
	var logicalClock interface{}
	if d.LogicalClock != nil {
		logicalClock = strconv.FormatUint(*d.LogicalClock, 10)
	}
	var ctext interface{}
	if d.CanonicalPayloadText != nil {
		ctext = *d.CanonicalPayloadText
	}
	var payloadHash interface{}
	if d.PayloadHash != nil {
		payloadHash = d.PayloadHash[:]
	}
	var sig interface{}
	if len(d.Signature) > 0 {
		sig = d.Signature
	}
	var pctx interface{}
	if len(d.PartitionContext) > 0 {
		pctx = d.PartitionContext
	}
	var schemaVer interface{}
	if d.SchemaVersion != nil {
		schemaVer = *d.SchemaVersion
	}
	var schemaTransform interface{}
	if d.SchemaTransformHash != nil {
		schemaTransform = d.SchemaTransformHash[:]
	}

	_, err := tx.Exec(ctx, `
INSERT INTO partition_records (
  partition_id, partition_epoch, partition_record_seq, shard_seq,
  record_type, record_version, stage_order, record_id,
  message_id, agent_id, boot_session_id, logical_clock,
  logical_shard_id, causal_parent_refs_text,
  canonical_payload_text, canonical_payload_bytes,
  canonical_payload_hash, payload_hash, signature, partition_context,
  schema_version, schema_transform_hash,
  previous_record_hash, record_hash, execution_context_hash
) VALUES (
  $1, $2, $3, $3,
  $4, $5, $6, $7,
  $8, $9, $10, $11,
  $12, $13,
  $14, $15,
  $16, $17, $18, $19,
  $20, $21,
  $22, $23, $24
)`,
		partitionID, partitionEpoch, seq,
		d.RecordType, d.RecordVersion, d.StageOrder, d.RecordID,
		messageID, agentID, bootID, logicalClock,
		d.LogicalShardID, d.CausalParentRefsText,
		ctext, cpb,
		d.CanonicalPayloadHash[:], payloadHash, sig, pctx,
		schemaVer, schemaTransform,
		previousRecordHash[:], recordHash[:], executionContextHash[:],
	)
	return err
}

// RecomputeExecutionContextHashFromBindings matches gateway/worker binding resolution: sort keys
// Type+"\x00"+ID+"\x00"+Version lexicographically, then SHA256(concat(payload_hash[i] in that order)).
func RecomputeExecutionContextHashFromBindings(bindRefs []AuthorityRef, payloadHashAt func(i int) [32]byte) ([32]byte, error) {
	if len(bindRefs) == 0 {
		return [32]byte{}, errors.New("empty bind refs")
	}
	type row struct {
		k string
		h [32]byte
	}
	rows := make([]row, 0, len(bindRefs))
	for i := range bindRefs {
		r := bindRefs[i]
		k := r.Type + "\x00" + r.ID + "\x00" + r.Version
		rows = append(rows, row{k: k, h: payloadHashAt(i)})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].k < rows[j].k })
	sum := sha256.New()
	for i := range rows {
		_, _ = sum.Write(rows[i].h[:])
	}
	var out [32]byte
	copy(out[:], sum.Sum(nil))
	return out, nil
}

func batchContainsSignal(records []RecordDraft) bool {
	for i := range records {
		if records[i].RecordType == "SIGNAL" {
			return true
		}
	}
	return false
}

func validateSignalCommitAuthorityClosure(opts CommitOptions, bindRefs []AuthorityRef, bindingPayloadHashes [][32]byte) error {
	if !batchContainsSignal(opts.Records) {
		return nil
	}
	if len(bindingPayloadHashes) != len(bindRefs) {
		return errors.New("internal: binding payload hash count mismatch")
	}
	if err := RequireSingleTrustSnapshotBindingForSignal(bindRefs); err != nil {
		return err
	}
	recomputed, err := RecomputeExecutionContextHashFromBindings(bindRefs, func(i int) [32]byte {
		return bindingPayloadHashes[i]
	})
	if err != nil {
		return err
	}
	if recomputed != opts.ExecutionContextHash {
		return FailType1("INPUT_ERROR", errors.New("execution_context_hash mismatch vs bound authority_snapshots"))
	}
	return nil
}

// validateSignalRecordsInBatch enforces SIGNAL-specific authority fields at the authoritative commit kernel.
// Gateway and worker must not bypass these rules via ad hoc INSERTs into partition_records.
func validateSignalRecordsInBatch(opts CommitOptions) error {
	var sawSignal bool
	var firstSchema string
	var firstTransform [32]byte
	var haveFirst bool
	for i := range opts.Records {
		rec := opts.Records[i]
		if rec.RecordType != "SIGNAL" {
			continue
		}
		sawSignal = true
		if rec.SchemaVersion == nil || strings.TrimSpace(*rec.SchemaVersion) == "" {
			return FailType1("INPUT_ERROR", fmt.Errorf("record %d: SIGNAL requires schema_version", i))
		}
		if rec.SchemaTransformHash == nil {
			return FailType1("INPUT_ERROR", fmt.Errorf("record %d: SIGNAL requires schema_transform_hash", i))
		}
		if *rec.SchemaTransformHash == ZeroHash32 {
			return FailType1("INPUT_ERROR", fmt.Errorf("record %d: SIGNAL schema_transform_hash must not be zero", i))
		}
		sv := strings.TrimSpace(*rec.SchemaVersion)
		st := *rec.SchemaTransformHash
		if !haveFirst {
			firstSchema = sv
			firstTransform = st
			haveFirst = true
			continue
		}
		if sv != firstSchema || st != firstTransform {
			return FailType1("INPUT_ERROR", fmt.Errorf("record %d: mixed SIGNAL schema_version / schema_transform_hash in one batch forbidden", i))
		}
	}
	if sawSignal && opts.ExecutionContextHash == ZeroHash32 {
		return FailType1("INPUT_ERROR", errors.New("SIGNAL batch forbids zero execution_context_hash"))
	}
	return nil
}
