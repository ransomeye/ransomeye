package gateway

import (
	"testing"
)

func TestIdentityBindingChangesSignature(t *testing.T) {
	id1 := Identity{"a", "s", "f1"}
	id2 := Identity{"a", "s", "f2"}

	msg1 := buildMessage([]byte("payload"), id1)
	msg2 := buildMessage([]byte("payload"), id2)

	if string(msg1) == string(msg2) {
		t.Fatal("identity not bound to message")
	}
}

func TestNonceEvictionBound(t *testing.T) {
	v := NewValidator()

	for i := 0; i < maxNonceEntries+10; i++ {
		n := "n" + string(rune(i))
		_ = v.checkNonce(n, int64(i))
	}

	if len(v.nonceMap) > maxNonceEntries {
		t.Fatal("nonce map exceeded bound")
	}
}

func TestBuildMessageCanonicalEncoding(t *testing.T) {
	id := Identity{"agent", "session", "fp"}

	msg := buildMessage([]byte("abc"), id)

	if len(msg) < 20 {
		t.Fatal("invalid encoded message")
	}

	prefixLen := int(msg[0])<<24 | int(msg[1])<<16 | int(msg[2])<<8 | int(msg[3])

	if prefixLen != len("RANSOMEYE_EVENT_V1") {
		t.Fatal("invalid prefix length encoding")
	}
}

func TestPayloadTamperBreaksSignature(t *testing.T) {
	id := baseIdentity()

	msg1 := buildMessage([]byte("payload"), id)
	msg2 := buildMessage([]byte("payloadX"), id)

	if string(msg1) == string(msg2) {
		t.Fatal("payload tampering not reflected in message")
	}
}

func TestIdentityTamperBreaksSignature(t *testing.T) {
	id1 := Identity{"agent", "session", "fp1"}
	id2 := Identity{"agent", "session", "fp2"}

	msg1 := buildMessage([]byte("payload"), id1)
	msg2 := buildMessage([]byte("payload"), id2)

	if string(msg1) == string(msg2) {
		t.Fatal("identity tampering not reflected in message")
	}
}

func baseIdentity() Identity {
	return Identity{
		AgentID:        "agent-1",
		SessionID:      "session-1",
		FingerprintHex: "abc123",
	}
}
