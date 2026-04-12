package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestValidateWormSeed_AcceptsRandom(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	seed := priv.Seed()
	if err := ValidateWormSeed(seed); err != nil {
		t.Fatalf("valid seed rejected: %v", err)
	}
}

func TestValidateWormSeed_RejectsWeak(t *testing.T) {
	zero := make([]byte, 32)
	if ValidateWormSeed(zero) == nil {
		t.Fatal("expected reject all-zero")
	}
	same := make([]byte, 32)
	for i := range same {
		same[i] = 0xab
	}
	if ValidateWormSeed(same) == nil {
		t.Fatal("expected reject all-same")
	}
	seq0 := make([]byte, 32)
	for i := range seq0 {
		seq0[i] = byte(i)
	}
	if ValidateWormSeed(seq0) == nil {
		t.Fatal("expected reject sequential 0..31")
	}
	seq1 := make([]byte, 32)
	for i := range seq1 {
		seq1[i] = byte(i + 1)
	}
	if ValidateWormSeed(seq1) == nil {
		t.Fatal("expected reject sequential 1..32")
	}
}

func TestValidateWormSeed_RejectsPEMPrefix(t *testing.T) {
	pemLike := []byte("-----BEGIN XXXXXXXXXXXXXXXXXXXXX") // 10 + 22 = 32
	if len(pemLike) != 32 {
		t.Fatalf("test vector len %d", len(pemLike))
	}
	if ValidateWormSeed(pemLike) == nil {
		t.Fatal("expected reject PEM prefix")
	}
}

func TestWORM_VerifyEvidence_RoundTrip(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		t.Fatalf("rand: %v", err)
	}
	w, err := NewWORM(priv, aesKey)
	if err != nil {
		t.Fatalf("NewWORM: %v", err)
	}

	ciphertext := []byte("sealed evidence payload")
	logicalClock := int64(42)
	agentID := "agent-uuid-1234"
	eventID := "event-uuid-5678"
	eventType := "PROCESS_EVENT"

	sig, err := w.SignEvidence(ciphertext, logicalClock, agentID, eventID, eventType)
	if err != nil {
		t.Fatalf("SignEvidence: %v", err)
	}
	if len(sig) != ed25519.SignatureSize {
		t.Errorf("signature length want %d, got %d", ed25519.SignatureSize, len(sig))
	}

	if !w.VerifyEvidence(ciphertext, logicalClock, agentID, eventID, eventType, sig) {
		t.Error("VerifyEvidence must accept signature produced by SignEvidence (round-trip)")
	}
}

func TestWORM_VerifyEvidence_RejectInvalid(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	aesKey := make([]byte, 32)
	rand.Read(aesKey)
	w, _ := NewWORM(priv, aesKey)

	ciphertext := []byte("payload")
	sig, _ := w.SignEvidence(ciphertext, 1, "agent1", "event1", "FILE_EVENT")

	// Tampered ciphertext must fail.
	if w.VerifyEvidence([]byte("tampered"), 1, "agent1", "event1", "FILE_EVENT", sig) {
		t.Error("VerifyEvidence must reject when ciphertext is tampered")
	}
	// Wrong logical clock must fail.
	if w.VerifyEvidence(ciphertext, 2, "agent1", "event1", "FILE_EVENT", sig) {
		t.Error("VerifyEvidence must reject when logicalClock differs")
	}
	// Wrong agentID must fail.
	if w.VerifyEvidence(ciphertext, 1, "other", "event1", "FILE_EVENT", sig) {
		t.Error("VerifyEvidence must reject when agentID differs")
	}
	// Wrong eventID must fail.
	if w.VerifyEvidence(ciphertext, 1, "agent1", "other-event", "FILE_EVENT", sig) {
		t.Error("VerifyEvidence must reject when eventID differs")
	}
	// Wrong signature size must fail.
	if w.VerifyEvidence(ciphertext, 1, "agent1", "event1", "FILE_EVENT", sig[:10]) {
		t.Error("VerifyEvidence must reject short signature")
	}
}
