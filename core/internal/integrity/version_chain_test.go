package integrity

import (
	"encoding/hex"
	"testing"
)

func TestChainStepHash_Genesis(t *testing.T) {
	var anchor [32]byte
	anchor[0] = 0xab
	h1 := chainStepHash(1, &anchor)
	// Deterministic smoke: second step links to first
	h2 := chainStepHash(2, &h1)
	if h1 == h2 {
		t.Fatal("H(1) must differ from H(2)")
	}
	if chainStepHash(1, &anchor) != h1 {
		t.Fatal("chain step must be deterministic")
	}
}

func TestParseChainLine_roundTrip(t *testing.T) {
	var prev [32]byte
	prev[31] = 0x01
	n := uint64(7)
	want := chainStepHash(n, &prev)
	line := "version:7 sha256:" + hex.EncodeToString(want[:])
	gotN, gotD, err := parseChainLine(line)
	if err != nil {
		t.Fatal(err)
	}
	if gotN != n || gotD != want {
		t.Fatalf("parse mismatch n=%d d=%x vs want n=%d d=%x", gotN, gotD, n, want)
	}
}
