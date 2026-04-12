package forensics

import (
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log"
	"time"

	crypto "ransomeye/core/internal/crypto"
)

const (
	sha256Size    = 32
	ed25519SigLen = 64
)

var (
	ErrInvalidRoot      = errors.New("invalid merkle root")
	ErrInvalidChain     = errors.New("invalid merkle chain")
	ErrInvalidSignature = errors.New("invalid signature")
)

// ValidateMerkleSchema ensures merkle_daily_roots has prev_root_hash for chain persistence.
// Call at startup; fails process if column is missing.
func ValidateMerkleSchema(db *sql.DB) {
	if db == nil {
		log.Fatalf("[FATAL] nil db in ValidateMerkleSchema")
	}
	row := db.QueryRow(`
		SELECT column_name
		FROM information_schema.columns
		WHERE table_schema = 'public'
		AND table_name = 'merkle_daily_roots'
		AND column_name = 'prev_root_hash'
	`)
	var col string
	if err := row.Scan(&col); err != nil {
		log.Fatalf("[FATAL] Missing prev_root_hash column in merkle_daily_roots")
	}
}

// PersistMerkleRoot verifies then inserts a Merkle root into merkle_daily_roots (WORM at DB level).
// Verify BEFORE insert; no trust in caller. Insert only; no UPDATE/DELETE.
// computedAt is the deterministic timestamp for this root (caller-controlled).
func PersistMerkleRoot(
	db *sql.DB,
	tenantID string,
	root []byte,
	prevRoot []byte,
	sig []byte,
	pub ed25519.PublicKey,
	computedAt time.Time,
) error {
	if db == nil {
		return errors.New("nil db")
	}

	// Strict validation: root 32 bytes
	if len(root) != sha256Size {
		return ErrInvalidRoot
	}
	// prevRoot 32 bytes or empty (genesis only)
	if len(prevRoot) != 0 && len(prevRoot) != sha256Size {
		return ErrInvalidChain
	}
	// sig 64 bytes (Ed25519)
	if len(sig) != ed25519SigLen {
		return ErrInvalidSignature
	}

	// Compute and verify chain
	finalRoot := crypto.ComputeChainedRoot(prevRoot, root)
	if !crypto.VerifyChainedRoot(prevRoot, root, finalRoot) {
		return ErrInvalidChain
	}

	// Verify signature over finalRoot (chained value)
	if !crypto.VerifyRoot(finalRoot, sig, pub) {
		return ErrInvalidSignature
	}

	deterministicTime := computedAt.UTC()
	rootHex := hex.EncodeToString(root)
	prevRootHex := ""
	if len(prevRoot) > 0 {
		prevRootHex = hex.EncodeToString(prevRoot)
	}
	sigB64 := base64.StdEncoding.EncodeToString(sig)
	dailyDate := time.Date(deterministicTime.Year(), deterministicTime.Month(), deterministicTime.Day(), 0, 0, 0, 0, time.UTC)

	_, err := db.Exec(`
		INSERT INTO merkle_daily_roots
		(tenant_id, daily_date, merkle_root, prev_root_hash, leaf_count, computed_at, ed25519_sig)
		VALUES ($1::uuid, $2::date, $3::text, $4::text, $5, $6, $7)
	`,
		tenantID,
		dailyDate,
		rootHex,
		prevRootHex,
		0,
		deterministicTime,
		sigB64,
	)
	return err
}
