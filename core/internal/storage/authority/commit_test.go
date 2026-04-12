package authority

import (
	"crypto/ed25519"
	"crypto/sha256"
	"testing"
)

func TestBatchRootHashSingleton(t *testing.T) {
	seqs := []uint64{1}
	h1 := sha256.Sum256([]byte("a"))
	var rh [][32]byte
	rh = append(rh, h1)
	root, err := BatchRootHash(seqs, rh)
	if err != nil {
		t.Fatal(err)
	}
	want := BatchLeafHash(1, h1)
	if root != want {
		t.Fatalf("singleton root mismatch")
	}
}

func TestBatchRootHashRejectsGap(t *testing.T) {
	seqs := []uint64{1, 3}
	rh := [][32]byte{sha256.Sum256([]byte("a")), sha256.Sum256([]byte("b"))}
	_, err := BatchRootHash(seqs, rh)
	if err == nil {
		t.Fatal("expected non-contiguous error")
	}
}

func TestBatchCommitSignatureRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	var a, b, c, d, e [32]byte
	copy(a[:], []byte{1})
	copy(b[:], []byte{2})
	copy(c[:], []byte{3})
	copy(d[:], []byte{4})
	copy(e[:], []byte{5})
	payload := BatchCommitSignaturePayloadJSON(7, 8, 9, 10, 11, 3, a, b, c, d, e)
	ph := sha256.Sum256(payload)
	sigIn := append([]byte(BatchCommitSigningContext), ph[:]...)
	sig := ed25519.Sign(priv, sigIn)
	if !ed25519.Verify(pub, sigIn, sig) {
		t.Fatal("signature verify failed")
	}
}

func TestRecordHashChain(t *testing.T) {
	w := PartitionRecordWire{
		RecordType:            "DECISION",
		RecordVersion:         "v1",
		PartitionID:           1,
		PartitionEpoch:        0,
		PartitionRecordSeq:    1,
		LogicalShardID:        make([]byte, 32),
		ShardSeq:              1,
		StageOrder:            3,
		RecordID:              []byte{9, 9},
		CausalParentRefsText:  "{}",
		CanonicalPayloadBytes: []byte("x"),
		CanonicalPayloadHash:  sha256.Sum256([]byte("x")),
	}
	cb, err := CanonicalRecordBytes(w)
	if err != nil {
		t.Fatal(err)
	}
	h1 := RecordHash(ZeroHash32, cb)
	w2 := w
	w2.PartitionRecordSeq = 2
	w2.ShardSeq = 2
	w2.RecordID = []byte{8, 8}
	cb2, err := CanonicalRecordBytes(w2)
	if err != nil {
		t.Fatal(err)
	}
	h2 := RecordHash(h1, cb2)
	if h1 == h2 {
		t.Fatal("chain hash collision")
	}
}
