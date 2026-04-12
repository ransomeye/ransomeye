package authority

const (
	recordGrammarVersion   = "mishka.partition_record.v1"
	batchLeafVersion       = "mishka.batch_leaf.v1"
	batchNodeVersion       = "mishka.batch_node.v1"
	batchCommitHashVersion = "mishka.batch_commit_hash.v1"

	// BatchCommitSigningContext is PRD-04 / PRD-13 batch commit Ed25519 domain separation + DB signing_context column.
	BatchCommitSigningContext = "batch_commit_record_v1"
)

var ZeroHash32 [32]byte
