package forensics

import (
	"bytes"
	"testing"
)

func TestBuildMerkleRootUsesInternalPrefix(t *testing.T) {
	leaves := [][]byte{
		[]byte("a"),
		[]byte("b"),
		[]byte("c"),
	}

	got := BuildMerkleRoot(leaves)
	want := HashInternal(
		HashInternal(HashLeaf(leaves[0]), HashLeaf(leaves[1])),
		HashLeaf(leaves[2]),
	)

	if !bytes.Equal(got, want) {
		t.Fatalf("BuildMerkleRoot() mismatch\n got: %x\nwant: %x", got, want)
	}
}

func TestBuildMerkleRootDoesNotDuplicateOddLeaf(t *testing.T) {
	leaves := [][]byte{
		[]byte("a"),
		[]byte("b"),
		[]byte("c"),
	}

	got := BuildMerkleRoot(leaves)
	duplicatePadded := HashInternal(
		HashInternal(HashLeaf(leaves[0]), HashLeaf(leaves[1])),
		HashInternal(HashLeaf(leaves[2]), HashLeaf(leaves[2])),
	)

	if bytes.Equal(got, duplicatePadded) {
		t.Fatalf("BuildMerkleRoot() used duplicate-leaf padding")
	}
}
