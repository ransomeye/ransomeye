package authority

import (
	"testing"
)

func TestValidateSignalRecordsInBatch_RejectsNilSchemaTransform(t *testing.T) {
	sv := "telemetry_v1"
	err := validateSignalRecordsInBatch(CommitOptions{
		ExecutionContextHash: nonZeroTestExecHash(),
		Records: []RecordDraft{{
			RecordType:          "SIGNAL",
			RecordVersion:       "v1",
			SchemaVersion:       &sv,
			SchemaTransformHash: nil,
		}},
	})
	if err == nil {
		t.Fatal("expected error for nil schema_transform_hash")
	}
}

func TestValidateSignalRecordsInBatch_RejectsExplicitZeroSchemaTransform(t *testing.T) {
	sv := "telemetry_v1"
	z := ZeroHash32
	err := validateSignalRecordsInBatch(CommitOptions{
		ExecutionContextHash: nonZeroTestExecHash(),
		Records: []RecordDraft{{
			RecordType:          "SIGNAL",
			RecordVersion:       "v1",
			SchemaVersion:       &sv,
			SchemaTransformHash: &z,
		}},
	})
	if err == nil {
		t.Fatal("expected error for zero schema_transform_hash")
	}
}

func TestValidateSignalRecordsInBatch_RejectsZeroExecutionContextWithSignal(t *testing.T) {
	sv := "telemetry_v1"
	st := SchemaTransformHash(sv, nonZeroTestExecHash())
	err := validateSignalRecordsInBatch(CommitOptions{
		ExecutionContextHash: ZeroHash32,
		Records: []RecordDraft{{
			RecordType:          "SIGNAL",
			RecordVersion:       "v1",
			SchemaVersion:       &sv,
			SchemaTransformHash: &st,
		}},
	})
	if err == nil {
		t.Fatal("expected error for zero execution_context_hash with SIGNAL")
	}
}

func TestValidateSignalRecordsInBatch_RejectsMixedSchemaInBatch(t *testing.T) {
	sv1 := "telemetry_v1"
	sv2 := "telemetry_v2"
	ex := nonZeroTestExecHash()
	st1 := SchemaTransformHash(sv1, ex)
	st2 := SchemaTransformHash(sv2, ex)
	err := validateSignalRecordsInBatch(CommitOptions{
		ExecutionContextHash: ex,
		Records: []RecordDraft{
			{
				RecordType:          "SIGNAL",
				RecordVersion:       "v1",
				SchemaVersion:       &sv1,
				SchemaTransformHash: &st1,
			},
			{
				RecordType:          "SIGNAL",
				RecordVersion:       "v1",
				SchemaVersion:       &sv2,
				SchemaTransformHash: &st2,
			},
		},
	})
	if err == nil {
		t.Fatal("expected error for mixed SIGNAL schema in batch")
	}
}

func nonZeroTestExecHash() [32]byte {
	var h [32]byte
	h[0] = 0x01
	h[31] = 0x02
	return h
}

func TestRequireSingleTrustSnapshotBindingForSignal_RejectsWrongID(t *testing.T) {
	err := RequireSingleTrustSnapshotBindingForSignal([]AuthorityRef{
		{Type: "CONFIG", ID: "other_snapshot", Version: "v1"},
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestValidateSignalCommitAuthorityClosure_RejectsMultiBinding(t *testing.T) {
	ex := nonZeroTestExecHash()
	refs := []AuthorityRef{
		{Type: "CONFIG", ID: "trust_snapshot", Version: "v1"},
		{Type: "CONFIG", ID: "chaos_validation_matrix", Version: "v1"},
	}
	hashes := [][32]byte{ex, ex}
	err := validateSignalCommitAuthorityClosure(CommitOptions{
		ExecutionContextHash: ex,
		Records: []RecordDraft{{
			RecordType:          "SIGNAL",
			RecordVersion:       "v1",
			SchemaVersion:       strPtr("telemetry_v1"),
			SchemaTransformHash: ptrSchemaTransform("telemetry_v1", ex),
		}},
	}, refs, hashes)
	if err == nil {
		t.Fatal("expected multi-binding rejection for SIGNAL")
	}
}

func strPtr(s string) *string { return &s }

func ptrSchemaTransform(sv string, ex [32]byte) *[32]byte {
	h := SchemaTransformHash(sv, ex)
	return &h
}

func TestRecomputeExecutionContextHashFromBindings_Ordered(t *testing.T) {
	a := [32]byte{1}
	b := [32]byte{2}
	refs := []AuthorityRef{
		{Type: "CONFIG", ID: "z", Version: "v1"},
		{Type: "CONFIG", ID: "a", Version: "v1"},
	}
	h1, err := RecomputeExecutionContextHashFromBindings(refs, func(i int) [32]byte {
		if i == 0 {
			return a
		}
		return b
	})
	if err != nil {
		t.Fatal(err)
	}
	// Swap ref order — recomputed hash must match (sort is by binding key, not slice order).
	refs2 := []AuthorityRef{
		{Type: "CONFIG", ID: "a", Version: "v1"},
		{Type: "CONFIG", ID: "z", Version: "v1"},
	}
	h2, err := RecomputeExecutionContextHashFromBindings(refs2, func(i int) [32]byte {
		if i == 0 {
			return b
		}
		return a
	})
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Fatalf("order-independent hash: %x vs %x", h1, h2)
	}
}
