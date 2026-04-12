package authority

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/google/uuid"
)

func TestTelemetryMessageIDBytes_UUIDRoundTrip(t *testing.T) {
	u := uuid.New()
	b, err := TelemetryMessageIDBytes(u.String())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, u[:]) {
		t.Fatalf("bytes mismatch")
	}
}

func TestTelemetryMessageIDBytes_32ByteHex(t *testing.T) {
	raw := bytes.Repeat([]byte{0x3a}, 32)
	hexStr := hex.EncodeToString(raw)
	b, err := TelemetryMessageIDBytes(hexStr)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, raw) {
		t.Fatalf("decode mismatch")
	}
}
