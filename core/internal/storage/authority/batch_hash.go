package authority

import (
	"crypto/sha256"
	"fmt"
	"strconv"
)

// BatchLeafHash implements PRD-13 §6.4.2 leaf_input_bytes / leaf_hash.
func BatchLeafHash(partitionRecordSeq uint64, recordHash [32]byte) [32]byte {
	h := sha256.New()
	_, _ = h.Write([]byte(batchLeafVersion))
	var seqBE [8]byte
	for i := 0; i < 8; i++ {
		seqBE[7-i] = byte(partitionRecordSeq >> (8 * i))
	}
	_, _ = h.Write(seqBE[:])
	_, _ = h.Write(recordHash[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func innerNodeBytes(left, right [32]byte) []byte {
	b := appendASCIIBytes(nil, batchNodeVersion)
	b = appendHash32Field(b, left)
	b = appendHash32Field(b, right)
	return b
}

// BatchRootHash implements PRD-13 §6.4.2 (odd-leaf duplication).
func BatchRootHash(partitionRecordSeqs []uint64, recordHashes [][32]byte) ([32]byte, error) {
	if len(partitionRecordSeqs) != len(recordHashes) {
		return [32]byte{}, fmt.Errorf("seq/hash count mismatch")
	}
	if len(partitionRecordSeqs) == 0 {
		return [32]byte{}, fmt.Errorf("empty batch")
	}
	for i := 1; i < len(partitionRecordSeqs); i++ {
		if partitionRecordSeqs[i] != partitionRecordSeqs[i-1]+1 {
			return [32]byte{}, fmt.Errorf("non-contiguous partition_record_seq")
		}
	}
	level := make([][32]byte, len(recordHashes))
	for i := range recordHashes {
		level[i] = BatchLeafHash(partitionRecordSeqs[i], recordHashes[i])
	}
	for len(level) > 1 {
		next := make([][32]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			left := level[i]
			right := left
			if i+1 < len(level) {
				right = level[i+1]
			}
			sum := sha256.Sum256(innerNodeBytes(left, right))
			next = append(next, sum)
		}
		level = next
	}
	return level[0], nil
}

// BatchCommitHash implements PRD-13 §6.4.3.
func BatchCommitHash(
	partitionID, partitionEpoch, batchCommitSeq uint64,
	firstPartitionRecordSeq, lastPartitionRecordSeq, recordCount uint64,
	firstRecordHash, lastRecordHash, batchRootHash, previousBatchCommitHash, executionContextHash [32]byte,
) ([32]byte, error) {
	if recordCount == 0 {
		return [32]byte{}, fmt.Errorf("record_count=0")
	}
	h := sha256.New()
	_, _ = h.Write([]byte(batchCommitHashVersion))
	var buf [8]byte
	putU64 := func(v uint64) {
		for i := 0; i < 8; i++ {
			buf[7-i] = byte(v >> (8 * i))
		}
		_, _ = h.Write(buf[:])
	}
	putU64(partitionID)
	putU64(partitionEpoch)
	putU64(batchCommitSeq)
	putU64(firstPartitionRecordSeq)
	putU64(lastPartitionRecordSeq)
	putU64(recordCount)
	_, _ = h.Write(firstRecordHash[:])
	_, _ = h.Write(lastRecordHash[:])
	_, _ = h.Write(batchRootHash[:])
	_, _ = h.Write(previousBatchCommitHash[:])
	_, _ = h.Write(executionContextHash[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}

// BatchCommitSignaturePayloadJSON is PRD-13 §6.4.4 (RFC 8785 key order).
func BatchCommitSignaturePayloadJSON(
	partitionID, partitionEpoch, batchCommitSeq uint64,
	firstPartitionRecordSeq, lastPartitionRecordSeq, recordCount uint64,
	firstRecordHash, lastRecordHash, batchRootHash, previousBatchCommitHash, executionContextHash [32]byte,
) []byte {
	// Lexicographic key order of the exact mandatory key set.
	s := `{"batch_commit_seq":` + strconv.FormatUint(batchCommitSeq, 10) +
		`,"batch_root_hash":"` + fmt.Sprintf("%x", batchRootHash[:]) + `"` +
		`,"execution_context_hash":"` + fmt.Sprintf("%x", executionContextHash[:]) + `"` +
		`,"first_partition_record_seq":` + strconv.FormatUint(firstPartitionRecordSeq, 10) +
		`,"first_record_hash":"` + fmt.Sprintf("%x", firstRecordHash[:]) + `"` +
		`,"last_partition_record_seq":` + strconv.FormatUint(lastPartitionRecordSeq, 10) +
		`,"last_record_hash":"` + fmt.Sprintf("%x", lastRecordHash[:]) + `"` +
		`,"partition_epoch":` + strconv.FormatUint(partitionEpoch, 10) +
		`,"partition_id":` + strconv.FormatUint(partitionID, 10) +
		`,"previous_batch_commit_hash":"` + fmt.Sprintf("%x", previousBatchCommitHash[:]) + `"` +
		`,"record_count":` + strconv.FormatUint(recordCount, 10) + `}`
	return []byte(s)
}
