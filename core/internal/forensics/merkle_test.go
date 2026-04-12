package forensics

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestLeafHashNodeHashSizes(t *testing.T) {
	l := LeafHash([]byte("hello"))
	if len(l) != 32 {
		t.Fatalf("leaf hash len %d", len(l))
	}
	n := NodeHash(l, l)
	if len(n) != 32 {
		t.Fatalf("node hash len %d", len(n))
	}
}

func TestMerkleTreeHashOneLeaf(t *testing.T) {
	want := LeafHash([]byte("a"))
	got, err := MerkleTreeHash([][]byte{[]byte("a")})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("single leaf: got %s want %s", hex.EncodeToString(got), hex.EncodeToString(want))
	}
}

func TestMerkleTreeHashTwoLeaves(t *testing.T) {
	L0 := LeafHash([]byte("a"))
	L1 := LeafHash([]byte("b"))
	want := NodeHash(L0, L1)
	got, err := MerkleTreeHash([][]byte{[]byte("a"), []byte("b")})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("two leaves: got %s want %s", hex.EncodeToString(got), hex.EncodeToString(want))
	}
}

func TestInclusionProofVerifiesForAllIndices(t *testing.T) {
	leaves := [][]byte{
		[]byte("leaf-0"),
		[]byte("leaf-1"),
		[]byte("leaf-2"),
		[]byte("leaf-3"),
		[]byte("leaf-4"),
		[]byte("leaf-5"),
		[]byte("leaf-6"),
	}
	root, err := MerkleTreeHash(leaves)
	if err != nil {
		t.Fatal(err)
	}
	for i := range leaves {
		proof := GenerateInclusionProof(leaves, i)
		if proof == nil {
			t.Fatalf("proof nil for index %d", i)
		}
		if ok := VerifyInclusionProof(leaves[i], proof, root, i); !ok {
			t.Fatalf("inclusion proof failed for index %d", i)
		}
	}
}

func TestInclusionProofTamperFails(t *testing.T) {
	leaves := [][]byte{[]byte("a"), []byte("b"), []byte("c")}
	root, err := MerkleTreeHash(leaves)
	if err != nil {
		t.Fatal(err)
	}
	proof := GenerateInclusionProof(leaves, 1)
	if proof == nil || len(proof) == 0 {
		t.Fatal("expected non-empty proof")
	}

	// Tamper: flip one bit in the first sibling hash.
	proof[0][len(proof[0])-1] ^= 0x01
	if ok := VerifyInclusionProof(leaves[1], proof, root, 1); ok {
		t.Fatal("tampered inclusion proof unexpectedly verified")
	}
}
