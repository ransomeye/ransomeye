package authority

import (
	"crypto/sha256"
	"encoding/binary"
)

const batchCommitIDDomain = "mishka.batch_commit_id.v1"

// DeterministicBatchCommitID derives a 16-byte batch_commit_id from the batch identity (PRD-13 UNIQUE(batch_commit_id)).
// Replaces non-deterministic random IDs so authoritative commits are replay-reconstructable without entropy.
func DeterministicBatchCommitID(partitionID, partitionEpoch, batchCommitSeq int64, executionContextHash, batchCommitHash [32]byte) [16]byte {
	var b []byte
	b = append(b, batchCommitIDDomain...)
	b = binary.BigEndian.AppendUint64(b, uint64(partitionID))
	b = binary.BigEndian.AppendUint64(b, uint64(partitionEpoch))
	b = binary.BigEndian.AppendUint64(b, uint64(batchCommitSeq))
	b = append(b, executionContextHash[:]...)
	b = append(b, batchCommitHash[:]...)
	sum := sha256.Sum256(b)
	var out [16]byte
	copy(out[:], sum[:16])
	return out
}
