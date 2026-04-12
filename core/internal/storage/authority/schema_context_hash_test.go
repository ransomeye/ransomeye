package authority

import (
	"bytes"
	"testing"
)

func TestSchemaTransformHash_Deterministic(t *testing.T) {
	var ex [32]byte
	ex[0] = 0xab
	h1 := SchemaTransformHash("signal_schema_v1", ex)
	h2 := SchemaTransformHash("signal_schema_v1", ex)
	if h1 != h2 {
		t.Fatal("schema_transform_hash not deterministic")
	}
	h3 := SchemaTransformHash("signal_schema_v2", ex)
	if bytes.Equal(h1[:], h3[:]) {
		t.Fatal("schema version must affect hash")
	}
}
