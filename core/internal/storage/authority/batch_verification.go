package authority

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type VerifiedBatch struct {
	PartitionID    int64
	BatchCommitSeq int64

	FirstPartitionRecordSeq int64
	LastPartitionRecordSeq  int64
	RecordCount             int64

	CommittedBatchCommitHash [32]byte
	RecomputedBatchCommitHash [32]byte

	SignaturePayloadBytes []byte
	SignatureInputBytes   []byte
}

// VerifyCommittedBatch reconstructs and verifies PRD-13 batch invariants using committed rows only.
//
// Checks:
// - batch_commit_hash matches deterministic reconstruction
// - signature input bytes are reconstructable from committed values only (PRD-04/13)
// - execution_context_hash uniformity across the committed partition_records range
// - previous_batch_commit_hash matches committed predecessor (or zero for genesis)
// - authority bindings exist and execution_context_hash matches bound authority inputs
func VerifyCommittedBatch(ctx context.Context, pool *pgxpool.Pool, partitionID int64, batchCommitSeq int64) (VerifiedBatch, error) {
	if pool == nil {
		return VerifiedBatch{}, FailType1("INPUT_ERROR", errors.New("nil pool"))
	}
	if partitionID <= 0 || batchCommitSeq <= 0 {
		return VerifiedBatch{}, FailType1("INPUT_ERROR", errors.New("invalid partition_id or batch_commit_seq"))
	}

	type batchRow struct {
		partitionEpoch int64
		firstSeq       int64
		lastSeq        int64
		recordCount    int64
		firstRecordHash []byte
		lastRecordHash  []byte
		batchRootHash   []byte
		prevBatchHash   []byte
		execHash        []byte
		keyID          string
		keyEpoch       int64
		signature      []byte
		commitHash      []byte
	}

	var br batchRow
	err := pool.QueryRow(ctx, `
SELECT partition_epoch,
       first_partition_record_seq,
       last_partition_record_seq,
       record_count,
       first_record_hash,
       last_record_hash,
       batch_root_hash,
       previous_batch_commit_hash,
       execution_context_hash,
       key_id,
       key_epoch,
       signature,
       batch_commit_hash
FROM batch_commit_records
WHERE partition_id = $1 AND batch_commit_seq = $2`,
		partitionID, batchCommitSeq,
	).Scan(
		&br.partitionEpoch,
		&br.firstSeq,
		&br.lastSeq,
		&br.recordCount,
		&br.firstRecordHash,
		&br.lastRecordHash,
		&br.batchRootHash,
		&br.prevBatchHash,
		&br.execHash,
		&br.keyID,
		&br.keyEpoch,
		&br.signature,
		&br.commitHash,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return VerifiedBatch{}, FailType3("INTEGRITY_FAILURE", errors.New("batch_commit_record missing"))
		}
		return VerifiedBatch{}, FailType2("STATE_INCONSISTENCY", err)
	}
	if br.recordCount <= 0 {
		return VerifiedBatch{}, FailType3("INTEGRITY_FAILURE", errors.New("record_count=0"))
	}
	if br.lastSeq < br.firstSeq {
		return VerifiedBatch{}, FailType3("INTEGRITY_FAILURE", errors.New("invalid batch range"))
	}
	if want := br.lastSeq - br.firstSeq + 1; want != br.recordCount {
		return VerifiedBatch{}, FailType3("INTEGRITY_FAILURE", fmt.Errorf("record_count=%d want=%d", br.recordCount, want))
	}
	for _, f := range []struct {
		name string
		b    []byte
	}{
		{"first_record_hash", br.firstRecordHash},
		{"last_record_hash", br.lastRecordHash},
		{"batch_root_hash", br.batchRootHash},
		{"previous_batch_commit_hash", br.prevBatchHash},
		{"execution_context_hash", br.execHash},
		{"signature", br.signature},
		{"batch_commit_hash", br.commitHash},
	} {
		want := 32
		if f.name == "signature" {
			want = ed25519.SignatureSize
		}
		if len(f.b) != want {
			return VerifiedBatch{}, FailType3("INTEGRITY_FAILURE", fmt.Errorf("%s length %d", f.name, len(f.b)))
		}
	}
	if br.keyID == "" {
		return VerifiedBatch{}, FailType3("INTEGRITY_FAILURE", errors.New("key_id missing"))
	}
	if br.keyEpoch <= 0 {
		return VerifiedBatch{}, FailType3("INTEGRITY_FAILURE", errors.New("key_epoch invalid"))
	}

	// Load committed range leaves from partition_records.
	rows, err := pool.Query(ctx, `
SELECT partition_record_seq, record_hash, execution_context_hash
FROM partition_records
WHERE partition_id = $1
  AND partition_record_seq BETWEEN $2 AND $3
ORDER BY partition_record_seq ASC`,
		partitionID, br.firstSeq, br.lastSeq,
	)
	if err != nil {
		return VerifiedBatch{}, FailType2("STATE_INCONSISTENCY", err)
	}
	defer rows.Close()

	seqs := make([]uint64, 0, br.recordCount)
	hashes := make([][32]byte, 0, br.recordCount)
	var execCommitted32 [32]byte
	copy(execCommitted32[:], br.execHash)

	var gotRows int64
	var prevSeq int64
	for rows.Next() {
		var seq int64
		var rh, eh []byte
		if err := rows.Scan(&seq, &rh, &eh); err != nil {
			return VerifiedBatch{}, FailType2("STATE_INCONSISTENCY", err)
		}
		gotRows++
		if gotRows == 1 {
			prevSeq = seq
		} else {
			if seq != prevSeq+1 {
				return VerifiedBatch{}, FailType3("INTEGRITY_FAILURE", errors.New("non-contiguous partition_record_seq in committed range"))
			}
			prevSeq = seq
		}
		if len(rh) != 32 {
			return VerifiedBatch{}, FailType3("INTEGRITY_FAILURE", fmt.Errorf("record_hash length %d", len(rh)))
		}
		if len(eh) != 32 {
			return VerifiedBatch{}, FailType3("INTEGRITY_FAILURE", fmt.Errorf("partition execution_context_hash length %d", len(eh)))
		}
		var eh32 [32]byte
		copy(eh32[:], eh)
		if eh32 != execCommitted32 {
			return VerifiedBatch{}, FailType3("DETERMINISM_VIOLATION", errors.New("execution_context_hash mismatch inside committed range"))
		}
		var rh32 [32]byte
		copy(rh32[:], rh)
		seqs = append(seqs, uint64(seq))
		hashes = append(hashes, rh32)
	}
	if err := rows.Err(); err != nil {
		return VerifiedBatch{}, FailType2("STATE_INCONSISTENCY", err)
	}
	if gotRows != br.recordCount {
		return VerifiedBatch{}, FailType3("INTEGRITY_FAILURE", fmt.Errorf("partition_records count=%d want=%d", gotRows, br.recordCount))
	}
	if hashes[0] != bytesTo32(br.firstRecordHash) {
		return VerifiedBatch{}, FailType3("INTEGRITY_FAILURE", errors.New("first_record_hash mismatch vs committed leaves"))
	}
	if hashes[len(hashes)-1] != bytesTo32(br.lastRecordHash) {
		return VerifiedBatch{}, FailType3("INTEGRITY_FAILURE", errors.New("last_record_hash mismatch vs committed leaves"))
	}

	root, err := BatchRootHash(seqs, hashes)
	if err != nil {
		return VerifiedBatch{}, FailType3("INTEGRITY_FAILURE", err)
	}
	if root != bytesTo32(br.batchRootHash) {
		return VerifiedBatch{}, FailType3("INTEGRITY_FAILURE", errors.New("batch_root_hash mismatch"))
	}

	var prevExpected [32]byte
	if batchCommitSeq == 1 {
		prevExpected = ZeroHash32
	} else {
		var prev []byte
		if err := pool.QueryRow(ctx, `
SELECT batch_commit_hash
FROM batch_commit_records
WHERE partition_id = $1 AND batch_commit_seq = $2`,
			partitionID, batchCommitSeq-1,
		).Scan(&prev); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return VerifiedBatch{}, FailType3("INTEGRITY_FAILURE", errors.New("previous batch_commit_record missing"))
			}
			return VerifiedBatch{}, FailType2("STATE_INCONSISTENCY", err)
		}
		if len(prev) != 32 {
			return VerifiedBatch{}, FailType3("INTEGRITY_FAILURE", fmt.Errorf("previous batch_commit_hash length %d", len(prev)))
		}
		copy(prevExpected[:], prev)
	}
	if prevExpected != bytesTo32(br.prevBatchHash) {
		return VerifiedBatch{}, FailType3("INTEGRITY_FAILURE", errors.New("previous_batch_commit_hash mismatch"))
	}

	recomputed, err := BatchCommitHash(
		uint64(partitionID),
		uint64(br.partitionEpoch),
		uint64(batchCommitSeq),
		uint64(br.firstSeq),
		uint64(br.lastSeq),
		uint64(br.recordCount),
		bytesTo32(br.firstRecordHash),
		bytesTo32(br.lastRecordHash),
		bytesTo32(br.batchRootHash),
		prevExpected,
		bytesTo32(br.execHash),
	)
	if err != nil {
		return VerifiedBatch{}, FailType3("INTEGRITY_FAILURE", err)
	}
	committedHash := bytesTo32(br.commitHash)
	if committedHash != recomputed {
		return VerifiedBatch{}, FailType3("INTEGRITY_FAILURE", errors.New("batch_commit_hash mismatch vs reconstruction"))
	}

	// Signature payload bytes must be reconstructable from committed values only.
	payload := BatchCommitSignaturePayloadJSON(
		uint64(partitionID),
		uint64(br.partitionEpoch),
		uint64(batchCommitSeq),
		uint64(br.firstSeq),
		uint64(br.lastSeq),
		uint64(br.recordCount),
		bytesTo32(br.firstRecordHash),
		bytesTo32(br.lastRecordHash),
		bytesTo32(br.batchRootHash),
		prevExpected,
		bytesTo32(br.execHash),
	)
	ph := sha256.Sum256(payload)
	sigInput := append([]byte(BatchCommitSigningContext), ph[:]...)

	// Ensure authority set exists + execution_context_hash matches bound inputs.
	if err := VerifyBatchExecutionContextHash(ctx, pool, partitionID, batchCommitSeq); err != nil {
		return VerifiedBatch{}, err
	}

	// Verify signatures over committed authority_snapshots using committed trust only.
	if err := VerifyBoundAuthoritySnapshots(ctx, pool, partitionID, batchCommitSeq); err != nil {
		return VerifiedBatch{}, err
	}

	// Verify Ed25519 signature using committed trust material only.
	pub, err := ResolveBatchCommitPublicKey(ctx, pool, partitionID, batchCommitSeq, br.keyID, br.keyEpoch)
	if err != nil {
		return VerifiedBatch{}, err
	}
	if !ed25519.Verify(pub, sigInput, br.signature) {
		return VerifiedBatch{}, FailType3("SIGNATURE_MISMATCH", errors.New("batch_commit signature invalid"))
	}

	return VerifiedBatch{
		PartitionID:              partitionID,
		BatchCommitSeq:           batchCommitSeq,
		FirstPartitionRecordSeq:  br.firstSeq,
		LastPartitionRecordSeq:   br.lastSeq,
		RecordCount:              br.recordCount,
		CommittedBatchCommitHash: committedHash,
		RecomputedBatchCommitHash: recomputed,
		SignaturePayloadBytes:    payload,
		SignatureInputBytes:      sigInput,
	}, nil
}

func bytesTo32(b []byte) [32]byte {
	var out [32]byte
	copy(out[:], b)
	return out
}

