package authority

import (
	"fmt"
)

// PartitionRecordWire captures PRD-13 §6.1.2 canonical_record_bytes inputs.
// Optional pointer fields mean FIELD_ABSENT in the grammar (SQL NULL).
type PartitionRecordWire struct {
	RecordType            string
	RecordVersion         string
	PartitionID           uint64
	PartitionEpoch        uint64
	PartitionRecordSeq    uint64
	LogicalShardID        []byte
	ShardSeq              uint64
	StageOrder            uint16
	RecordID              []byte
	MessageID             []byte
	AgentID               []byte
	BootSessionID         []byte
	LogicalClock          *uint64
	CausalParentRefsText  string
	CanonicalPayloadBytes []byte
	CanonicalPayloadHash  [32]byte
	PayloadHash           *[32]byte
	Signature             []byte
	PartitionContext      []byte
	SchemaVersion         *string
	SchemaTransformHash   *[32]byte
}

// CanonicalRecordBytes returns PRD-13 canonical_record_bytes (§6.1.2).
func CanonicalRecordBytes(r PartitionRecordWire) ([]byte, error) {
	if err := requireLen("canonical_payload_hash", r.CanonicalPayloadHash[:], 32); err != nil {
		return nil, err
	}
	if r.RecordType == "" || r.RecordVersion == "" {
		return nil, fmt.Errorf("record_type/record_version required")
	}
	if len(r.RecordID) == 0 {
		return nil, fmt.Errorf("record_id required")
	}
	if len(r.LogicalShardID) == 0 {
		return nil, fmt.Errorf("logical_shard_id required")
	}
	if r.ShardSeq != r.PartitionRecordSeq {
		return nil, fmt.Errorf("shard_seq must equal partition_record_seq")
	}

	out := appendASCIIBytes(nil, recordGrammarVersion)
	out = appendEnumField(out, r.RecordType)
	out = appendTextField(out, r.RecordVersion)
	out = appendUint64Field(out, r.PartitionID)
	out = appendUint64Field(out, r.PartitionEpoch)
	out = appendUint64Field(out, r.PartitionRecordSeq)
	out = appendBytesField(out, r.LogicalShardID)
	out = appendUint64Field(out, r.ShardSeq)
	out = appendU16BE(out, r.StageOrder)
	out = appendBytesField(out, r.RecordID)
	out = appendPresentOrAbsentBytes(out, r.MessageID)
	out = appendPresentOrAbsentBytes(out, r.AgentID)
	out = appendPresentOrAbsentBytes(out, r.BootSessionID)
	out = appendPresentOrAbsentUint64(out, r.LogicalClock)
	out = appendTextField(out, r.CausalParentRefsText)
	out = appendBytesField(out, r.CanonicalPayloadBytes)
	out = appendHash32Field(out, r.CanonicalPayloadHash)
	out = appendPresentOrAbsentHash32(out, r.PayloadHash)
	out = appendPresentOrAbsentBytes(out, r.Signature)
	out = appendPresentOrAbsentBytes(out, r.PartitionContext)
	out = appendPresentOrAbsentText(out, r.SchemaVersion)
	out = appendPresentOrAbsentHash32(out, r.SchemaTransformHash)
	return out, nil
}
