package authority

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type AuthorityInput struct {
	Ref        AuthorityRef
	PayloadHash [32]byte
}

// LoadBatchAuthorityInputs loads the authority inputs bound to a specific committed batch.
//
// Determinism:
// - ordering is explicit and stable by (authority_type, authority_id, authority_version)
// - duplicates are rejected (fail-closed)
// - missing snapshots are rejected (fail-closed)
func LoadBatchAuthorityInputs(ctx context.Context, pool *pgxpool.Pool, partitionID int64, batchCommitSeq int64) ([]AuthorityInput, error) {
	if pool == nil {
		return nil, FailType1("INPUT_ERROR", errors.New("nil pool"))
	}
	if partitionID <= 0 || batchCommitSeq <= 0 {
		return nil, FailType1("INPUT_ERROR", errors.New("invalid partition_id or batch_commit_seq"))
	}

	const q = `
SELECT b.authority_type, b.authority_id, b.authority_version, s.payload_hash
FROM batch_commit_authority_bindings b
INNER JOIN authority_snapshots s
  ON s.authority_type = b.authority_type
 AND s.authority_id = b.authority_id
 AND s.authority_version = b.authority_version
WHERE b.partition_id = $1
  AND b.batch_commit_seq = $2
ORDER BY b.authority_type ASC, b.authority_id ASC, b.authority_version ASC
`
	rows, err := pool.Query(ctx, q, partitionID, batchCommitSeq)
	if err != nil {
		return nil, FailType2("STATE_INCONSISTENCY", err)
	}
	defer rows.Close()

	out := make([]AuthorityInput, 0, 8)
	seen := make(map[string]struct{}, 8)
	for rows.Next() {
		var typ, id, ver string
		var ph []byte
		if err := rows.Scan(&typ, &id, &ver, &ph); err != nil {
			return nil, FailType2("STATE_INCONSISTENCY", err)
		}
		if len(ph) != 32 {
			return nil, FailType3("INTEGRITY_FAILURE", fmt.Errorf("authority payload_hash length %d", len(ph)))
		}
		k := typ + "\x00" + id + "\x00" + ver
		if _, ok := seen[k]; ok {
			return nil, FailType3("INTEGRITY_FAILURE", fmt.Errorf("duplicate authority binding %s/%s/%s", typ, id, ver))
		}
		seen[k] = struct{}{}
		var ph32 [32]byte
		copy(ph32[:], ph)
		out = append(out, AuthorityInput{
			Ref: AuthorityRef{
				Type:    typ,
				ID:      id,
				Version: ver,
			},
			PayloadHash: ph32,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, FailType2("STATE_INCONSISTENCY", err)
	}
	if len(out) == 0 {
		return nil, FailType3("INTEGRITY_FAILURE", errors.New("missing batch_commit_authority_bindings (empty authority set forbidden)"))
	}
	return out, nil
}

// ComputeExecutionContextHashFromAuthorityInputs deterministically computes execution_context_hash
// as SHA256(concat(payload_hash_1 || payload_hash_2 || ...)) in the input order.
func ComputeExecutionContextHashFromAuthorityInputs(inputs []AuthorityInput) ([32]byte, error) {
	if len(inputs) == 0 {
		return [32]byte{}, FailType3("INTEGRITY_FAILURE", errors.New("empty authority input set"))
	}
	h := sha256.New()
	for _, in := range inputs {
		_, _ = h.Write(in.PayloadHash[:])
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}

// VerifyBatchExecutionContextHash loads the committed batch's execution_context_hash and
// verifies it matches the deterministic recomputation from bound authority snapshots.
func VerifyBatchExecutionContextHash(ctx context.Context, pool *pgxpool.Pool, partitionID int64, batchCommitSeq int64) error {
	if pool == nil {
		return FailType1("INPUT_ERROR", errors.New("nil pool"))
	}
	var committed []byte
	err := pool.QueryRow(ctx, `
SELECT execution_context_hash
FROM batch_commit_records
WHERE partition_id = $1 AND batch_commit_seq = $2`, partitionID, batchCommitSeq).Scan(&committed)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return FailType3("INTEGRITY_FAILURE", errors.New("batch_commit_record missing"))
		}
		return FailType2("STATE_INCONSISTENCY", err)
	}
	if len(committed) != 32 {
		return FailType3("INTEGRITY_FAILURE", fmt.Errorf("committed execution_context_hash length %d", len(committed)))
	}
	var committed32 [32]byte
	copy(committed32[:], committed)

	inputs, err := LoadBatchAuthorityInputs(ctx, pool, partitionID, batchCommitSeq)
	if err != nil {
		return err
	}
	recomputed, err := ComputeExecutionContextHashFromAuthorityInputs(inputs)
	if err != nil {
		return err
	}
	if committed32 != recomputed {
		return FailType3("DETERMINISM_VIOLATION", errors.New("execution_context_hash mismatch vs bound authority inputs"))
	}
	return nil
}

