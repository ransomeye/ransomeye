package dbbootstrap

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestExpectedSchemaHashMatchesEmbedded(t *testing.T) {
	t.Helper()
	body, err := schemaFS.ReadFile("schema.sql")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	got := hex.EncodeToString(sum[:])
	if got != ExpectedSchemaHash {
		t.Fatalf("update ExpectedSchemaHash to %q after editing schema.sql", got)
	}
}
