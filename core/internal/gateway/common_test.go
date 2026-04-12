package gateway

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"testing"

	"ransomeye/core/internal/storage/authority"
)

type mockPublicKeyResolver struct {
	keys map[string]ed25519.PublicKey // keyID|keyEpoch|context -> pubKey
}

func (m *mockPublicKeyResolver) ResolveEmitterPublicKey(ctx context.Context, keyID string, keyEpoch int64, requiredSigningContext string) (ed25519.PublicKey, error) {
	if m.keys == nil {
		return nil, authority.FailType3("INTEGRITY_FAILURE", errors.New("missing key material"))
	}
	k := strings.Join([]string{keyID, strconv.FormatInt(keyEpoch, 10), requiredSigningContext}, "|")
	pub, ok := m.keys[k]
	if !ok {
		return nil, authority.FailType3("INTEGRITY_FAILURE", errors.New("missing key material"))
	}
	return pub, nil
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex.DecodeString: %v", err)
	}
	return b
}

func bytesFilled(n int, v byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = v
	}
	return out
}
