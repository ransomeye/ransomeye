package forensics

import (
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/hex"

	crypto "ransomeye/core/internal/crypto"
)

// VerifyFullChain verifies the entire Merkle chain for a tenant: sequential order, link continuity, and signatures.
// ORDER BY computed_at ASC ensures deterministic verification. Fails on any mismatch.
func VerifyFullChain(
	db *sql.DB,
	tenantID string,
	pub ed25519.PublicKey,
) error {
	if db == nil {
		return ErrInvalidChain
	}

	rows, err := db.Query(`
		SELECT merkle_root, prev_root_hash, ed25519_sig
		FROM merkle_daily_roots
		WHERE tenant_id = $1::uuid
		ORDER BY computed_at ASC
	`, tenantID)
	if err != nil {
		return err
	}
	defer rows.Close()

	var prevRoot []byte

	for rows.Next() {
		var rootHex, prevHex, sigB64 string
		if err := rows.Scan(&rootHex, &prevHex, &sigB64); err != nil {
			return err
		}

		root, err := hex.DecodeString(rootHex)
		if err != nil {
			return ErrInvalidChain
		}
		var storedPrev []byte
		if prevHex != "" {
			storedPrev, err = hex.DecodeString(prevHex)
			if err != nil {
				return ErrInvalidChain
			}
		}
		sig, err := base64.StdEncoding.DecodeString(sigB64)
		if err != nil {
			return ErrInvalidSignature
		}

		// Genesis: first row must have empty prev_root_hash
		if len(prevRoot) == 0 {
			if len(storedPrev) != 0 {
				return ErrInvalidChain
			}
		} else {
			if !crypto.ConstantTimeEqual(prevRoot, storedPrev) {
				return ErrInvalidChain
			}
		}

		// Recompute chained root
		finalRoot := crypto.ComputeChainedRoot(storedPrev, root)

		// Verify signature over finalRoot
		if !crypto.VerifyRoot(finalRoot, sig, pub) {
			return ErrInvalidSignature
		}

		prevRoot = root
	}

	if err := rows.Err(); err != nil {
		return err
	}
	return nil
}
