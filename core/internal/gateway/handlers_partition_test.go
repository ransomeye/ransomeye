package gateway

import "testing"

func TestPRD13PartitionID_MissingEnvDefaultsToOne(t *testing.T) {
	t.Setenv("RANSOMEYE_PRD13_PARTITION_ID", "")
	if got := prd13PartitionID(); got != 1 {
		t.Fatalf("prd13PartitionID() = %d, want 1", got)
	}
}

func TestPRD13PartitionID_MalformedEnvFailsClosed(t *testing.T) {
	t.Setenv("RANSOMEYE_PRD13_PARTITION_ID", "not-an-int")
	if got := prd13PartitionID(); got != 0 {
		t.Fatalf("prd13PartitionID() = %d, want 0", got)
	}
}

func TestPRD13PartitionID_NonPositiveEnvFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name string
		val  string
	}{
		{name: "zero", val: "0"},
		{name: "negative", val: "-17"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("RANSOMEYE_PRD13_PARTITION_ID", tc.val)
			if got := prd13PartitionID(); got != 0 {
				t.Fatalf("prd13PartitionID() = %d, want 0", got)
			}
		})
	}
}

func TestPRD13PartitionID_ValidEnv(t *testing.T) {
	t.Setenv("RANSOMEYE_PRD13_PARTITION_ID", "7")
	if got := prd13PartitionID(); got != 7 {
		t.Fatalf("prd13PartitionID() = %d, want 7", got)
	}
}
