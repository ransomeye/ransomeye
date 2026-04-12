package integrity

import (
	"encoding/hex"
	"testing"
)

func TestVerifyChainedHistoryBytes_twoSteps(t *testing.T) {
	var a1, a2 [32]byte
	a1[0] = 1
	a2[0] = 2
	h1 := anchorHistoryLineHash(anchorHistoryGenesis, a1)
	h2 := anchorHistoryLineHash(h1, a2)
	s := "anchor:" + hex.EncodeToString(a1[:]) + " hash:" + hex.EncodeToString(h1[:]) + "\n" +
		"anchor:" + hex.EncodeToString(a2[:]) + " hash:" + hex.EncodeToString(h2[:]) + "\n"
	anchors, tip, err := verifyChainedHistoryBytes([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	if len(anchors) != 2 || anchors[0] != a1 || anchors[1] != a2 {
		t.Fatalf("anchors %v", anchors)
	}
	if tip != h2 {
		t.Fatal("bad tip")
	}
}

func TestVerifyChainedHistoryBytes_tamperFails(t *testing.T) {
	var a1 [32]byte
	a1[0] = 1
	h1 := anchorHistoryLineHash(anchorHistoryGenesis, a1)
	h1[31] ^= 0xff
	s := "anchor:" + hex.EncodeToString(a1[:]) + " hash:" + hex.EncodeToString(h1[:]) + "\n"
	if _, _, err := verifyChainedHistoryBytes([]byte(s)); err == nil {
		t.Fatal("expected mismatch")
	}
}

func TestLegacyMigrationRewrite(t *testing.T) {
	var a1, a2 [32]byte
	a1[0] = 0x11
	a2[0] = 0x22
	leg := "anchor:" + hex.EncodeToString(a1[:]) + "\nanchor:" + hex.EncodeToString(a2[:]) + "\n"
	got, err := parseLegacyAnchorHistoryAnchors([]byte(leg))
	if err != nil || len(got) != 2 {
		t.Fatal(got, err)
	}
	// rewrite would produce chained lines; verify that chained verify passes on rewritten content
	var sb string
	prev := anchorHistoryGenesis
	for _, a := range got {
		h := anchorHistoryLineHash(prev, a)
		sb += "anchor:" + hex.EncodeToString(a[:]) + " hash:" + hex.EncodeToString(h[:]) + "\n"
		prev = h
	}
	if _, _, err := verifyChainedHistoryBytes([]byte(sb)); err != nil {
		t.Fatal(err)
	}
}
