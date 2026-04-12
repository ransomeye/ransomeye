package authority

import (
	"crypto/sha256"
)

// SchemaTransformHash binds schema_version to execution_context_hash (PRD-03 / PRD-13 SCHEMA_CONTEXT_BINDING;
// PRD-15 replay verification). It MUST equal SHA256(UTF-8(schema_version) || execution_context_hash bytes).
func SchemaTransformHash(schemaVersion string, executionContextHash [32]byte) [32]byte {
	// schema_version is stored as TEXT in partition_records; UTF-8 is the normative encoding for the string field.
	return sha256.Sum256(append([]byte(schemaVersion), executionContextHash[:]...))
}
