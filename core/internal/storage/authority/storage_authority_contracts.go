package authority

import (
	"bytes"
	"fmt"
)

// Authoritative cryptographic and serialization laws (PRD-01, PRD-04, PRD-13):
//   - Canonical JSON: RFC 8785 (JCS profile) for persisted authority and causal_parent payloads
//   - Hash: SHA-256 only (32-byte digests)
//   - Signatures: Ed25519 only
//   - Kafka / Redpanda: non-authoritative transport; never source of truth
//   - Replay: committed PRD-13 rows only (partition_records, batch_commit_records, replay_guard, …)

const (
	ExecutionContextHashBytes = 32
	HashSizeBytes             = 32
)

// PRD-13 §3.5 allowed record_type values (closed enum; PRD-23 must not add types).
var AllowedRecordTypes = map[string]struct{}{
	"SIGNAL":            {},
	"DETECTION":         {},
	"DECISION":          {},
	"SAFETY_EVALUATION": {},
	"ACTION":            {},
	"EXECUTION_RESULT":  {},
	"ROLLBACK":          {},
	"ROLLBACK_OVERRIDE": {},
	"REDACTION":         {},
	"QUERY":             {},
	"QUERY_RESULT":      {},
	"REPORT":            {},
	"REPORT_DELIVERY":   {},
	"UI_ACTION":         {},
	"GROUP":             {},
	"CASE":              {},
	"INVESTIGATION":     {},
	"RISK":              {},
	"SIMULATION":        {},
}

// ExpectedStageOrder maps PRD-13 record_type to the single allowed stage_order for that type.
var ExpectedStageOrder = map[string]uint16{
	"SIGNAL":            1,
	"DETECTION":         2,
	"DECISION":          3,
	"SAFETY_EVALUATION": 4,
	"ACTION":            5,
	"EXECUTION_RESULT":  6,
	"ROLLBACK":          7,
	"QUERY":             8,
	"QUERY_RESULT":      9,
	"REPORT":            10,
	"REPORT_DELIVERY":   11,
	"UI_ACTION":         12,
	"GROUP":             13,
	"CASE":              14,
	"INVESTIGATION":     15,
	"RISK":              16,
	"SIMULATION":        17,
	"ROLLBACK_OVERRIDE": 18,
	"REDACTION":         19,
}

// ValidatePRD13RecordType returns an error if t is not a PRD-13 allowed record_type.
func ValidatePRD13RecordType(t string) error {
	if t == "" {
		return fmt.Errorf("record_type empty")
	}
	if _, ok := AllowedRecordTypes[t]; !ok {
		return fmt.Errorf("record_type not allowed by PRD-13: %q", t)
	}
	return nil
}

// ValidatePRD13StageOrder checks record_type vs stage_order per PRD-13 §3.5.
func ValidatePRD13StageOrder(recordType string, stageOrder uint16) error {
	if err := ValidatePRD13RecordType(recordType); err != nil {
		return err
	}
	want, ok := ExpectedStageOrder[recordType]
	if !ok {
		return fmt.Errorf("internal: missing stage mapping for %q", recordType)
	}
	if stageOrder != want {
		return fmt.Errorf("stage_order %d invalid for record_type %q (want %d)", stageOrder, recordType, want)
	}
	return nil
}

// ValidateShardSeqEqualsPartitionRecordSeq enforces PRD-13 shard_seq == partition_record_seq.
func ValidateShardSeqEqualsPartitionRecordSeq(shardSeq, partitionRecordSeq uint64) error {
	if shardSeq != partitionRecordSeq {
		return fmt.Errorf("shard_seq must equal partition_record_seq (got %d vs %d)", shardSeq, partitionRecordSeq)
	}
	return nil
}

// ValidateExecutionContextUniformBatch checks every row shares the same 32-byte execution context (PRD-13 BATCH_EXECUTION_CONTEXT_UNIFORMITY).
func ValidateExecutionContextUniformBatch(batchExecutionContext [32]byte, perRecord [][32]byte) error {
	for i := range perRecord {
		if !bytes.Equal(perRecord[i][:], batchExecutionContext[:]) {
			return fmt.Errorf("execution_context_hash mismatch at record index %d", i)
		}
	}
	return nil
}

// BatchCommitRecordShape documents the PRD-13 batch_commit_records column set (signing_context, hashes, execution_context_hash).
// Used for static validation and tests; durable shape is enforced by SQL CHECK constraints.
type BatchCommitRecordShape struct {
	SigningContext          string
	FirstRecordHash         [32]byte
	LastRecordHash          [32]byte
	BatchRootHash           [32]byte
	PreviousBatchCommitHash [32]byte
	ExecutionContextHash    [32]byte
	BatchCommitHash         [32]byte
}

// ValidateBatchCommitRecordShape checks lengths and signing_context (PRD-13 / PRD-04).
func ValidateBatchCommitRecordShape(s BatchCommitRecordShape) error {
	if s.SigningContext != BatchCommitSigningContext {
		return fmt.Errorf("signing_context must be %q", BatchCommitSigningContext)
	}
	return nil
}
