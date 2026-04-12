package authority

import (
	"testing"
)

func TestValidatePRD13RecordType(t *testing.T) {
	if err := ValidatePRD13RecordType("SIGNAL"); err != nil {
		t.Fatal(err)
	}
	if err := ValidatePRD13RecordType("NOT_A_TYPE"); err == nil {
		t.Fatal("expected error")
	}
}

func TestValidatePRD13StageOrder(t *testing.T) {
	if err := ValidatePRD13StageOrder("SIGNAL", 1); err != nil {
		t.Fatal(err)
	}
	if err := ValidatePRD13StageOrder("SIGNAL", 2); err == nil {
		t.Fatal("expected error")
	}
	if err := ValidatePRD13StageOrder("ROLLBACK_OVERRIDE", 18); err != nil {
		t.Fatal(err)
	}
}

func TestValidateExecutionContextUniformBatch(t *testing.T) {
	var h [32]byte
	h[0] = 1
	h2 := h
	h2[1] = 2
	if err := ValidateExecutionContextUniformBatch(h, [][32]byte{h, h}); err != nil {
		t.Fatal(err)
	}
	if err := ValidateExecutionContextUniformBatch(h, [][32]byte{h, h2}); err == nil {
		t.Fatal("expected error")
	}
}

func TestExpectedStageOrderCoversAllRecordTypes(t *testing.T) {
	for rt := range AllowedRecordTypes {
		if _, ok := ExpectedStageOrder[rt]; !ok {
			t.Fatalf("missing stage for %q", rt)
		}
	}
}
