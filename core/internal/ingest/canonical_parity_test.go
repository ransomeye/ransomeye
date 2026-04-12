package ingest

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/google/uuid"
)

// Golden vector: fixed inputs; Linux (`build_canonical_v1`) and Windows (`build_canonical_v1`)
// MUST produce identical raw bytes (PRD-02 / FIX 6).
func TestCanonicalV1CrossPlatformGolden(t *testing.T) {
	t.Parallel()
	agentID := uuid.MustParse("11111111-2222-3333-4444-555555555555")
	eventID := uuid.MustParse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
	var procHash, fileHash [32]byte
	for i := range procHash {
		procHash[i] = byte(i + 1)
		fileHash[i] = byte(0xff - i)
	}
	var netTuple [16]byte
	copy(netTuple[:], []byte("tuple16bytes!!!"))
	var boot [16]byte
	copy(boot[:], []byte("bootsess16bytes!"))

	got, err := BuildCanonicalV1(
		0x0102030405060708,
		agentID,
		eventID,
		EventTypeCodeProcess,
		0xdeadbeef,
		procHash,
		fileHash,
		netTuple,
		0x1122334455667788,
		boot,
	)
	if err != nil {
		t.Fatal(err)
	}

	// Hex snapshot — update only when layout version intentionally changes.
	const wantHex = "01080706050403020111111111222233334444555555555555aaaaaaaabbbbccccddddeeeeeeeeeeee01000000efbeadde0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e07475706c6531366279746573212121008877665544332211626f6f74736573733136627974657321"
	want, err := hex.DecodeString(wantHex)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[:], want) {
		t.Fatalf("canonical mismatch\n got %x\nwant %x", got[:], want)
	}
	if _, err := ParseTelemetryV1(got[:]); err != nil {
		t.Fatalf("parse golden: %v", err)
	}
}
