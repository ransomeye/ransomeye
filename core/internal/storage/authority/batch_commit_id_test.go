package authority

import (
	"testing"
)

func TestDeterministicBatchCommitID_Stable(t *testing.T) {
	var ex, bh [32]byte
	ex[0] = 1
	bh[0] = 2
	a := DeterministicBatchCommitID(7, 0, 3, ex, bh)
	b := DeterministicBatchCommitID(7, 0, 3, ex, bh)
	if a != b {
		t.Fatal("batch_commit_id not stable")
	}
	c := DeterministicBatchCommitID(8, 0, 3, ex, bh)
	if a == c {
		t.Fatal("partition_id must affect id")
	}
}
