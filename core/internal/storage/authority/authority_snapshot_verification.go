package authority

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// VerifyBoundAuthoritySnapshots verifies signatures for every authority_snapshot bound to the batch.
// This is committed-storage-only and fails closed on any malformed, missing, or invalid snapshot.
func VerifyBoundAuthoritySnapshots(ctx context.Context, pool *pgxpool.Pool, partitionID int64, batchCommitSeq int64) error {
	if pool == nil {
		return FailType1("INPUT_ERROR", errors.New("nil pool"))
	}
	if partitionID <= 0 || batchCommitSeq <= 0 {
		return FailType1("INPUT_ERROR", errors.New("invalid partition_id or batch_commit_seq"))
	}

	rows, err := pool.Query(ctx, `
SELECT b.authority_type,
       b.authority_id,
       b.authority_version,
       s.canonical_payload_text,
       s.payload_hash,
       s.signature
FROM batch_commit_authority_bindings b
INNER JOIN authority_snapshots s
  ON s.authority_type = b.authority_type
 AND s.authority_id = b.authority_id
 AND s.authority_version = b.authority_version
WHERE b.partition_id = $1
  AND b.batch_commit_seq = $2
ORDER BY b.authority_type ASC, b.authority_id ASC, b.authority_version ASC`,
		partitionID, batchCommitSeq,
	)
	if err != nil {
		return FailType2("STATE_INCONSISTENCY", err)
	}
	defer rows.Close()

	var count int
	for rows.Next() {
		var typ, id, ver string
		var payloadText string
		var payloadHash []byte
		var sig []byte
		if err := rows.Scan(&typ, &id, &ver, &payloadText, &payloadHash, &sig); err != nil {
			return FailType2("STATE_INCONSISTENCY", err)
		}
		count++
		if strings.TrimSpace(payloadText) == "" {
			return FailType3("INTEGRITY_FAILURE", fmt.Errorf("authority snapshot empty canonical_payload_text: %s/%s/%s", typ, id, ver))
		}
		if len(payloadHash) != 32 {
			return FailType3("INTEGRITY_FAILURE", fmt.Errorf("authority snapshot payload_hash length %d: %s/%s/%s", len(payloadHash), typ, id, ver))
		}
		if len(sig) != ed25519.SignatureSize {
			return FailType3("INTEGRITY_FAILURE", fmt.Errorf("authority snapshot signature length %d: %s/%s/%s", len(sig), typ, id, ver))
		}

		trimmed := bytes.TrimSpace([]byte(payloadText))
		canonical, err := canonicalizeStrictJSONRFC8785(trimmed)
		if err != nil {
			return FailType3("CANONICALIZATION_VIOLATION", fmt.Errorf("authority snapshot malformed JSON: %s/%s/%s", typ, id, ver))
		}
		if !bytes.Equal(trimmed, canonical) {
			return FailType3("CANONICALIZATION_VIOLATION", fmt.Errorf("authority snapshot non-canonical JSON: %s/%s/%s", typ, id, ver))
		}

		wantPH := sha256.Sum256(canonical)
		if bytesTo32(payloadHash) != wantPH {
			return FailType3("INTEGRITY_FAILURE", fmt.Errorf("authority snapshot payload_hash mismatch: %s/%s/%s", typ, id, ver))
		}

		env, err := parseAuthoritySnapshotEnvelope(string(canonical))
		if err != nil {
			return FailType3("INTEGRITY_FAILURE", fmt.Errorf("authority snapshot envelope invalid: %s/%s/%s: %w", typ, id, ver, err))
		}
		pub, err := resolveBoundTrustSnapshotPublicKey(ctx, pool, partitionID, batchCommitSeq, env.keyID, env.keyEpoch, env.signingContext)
		if err != nil {
			return FailType3("INTEGRITY_FAILURE", fmt.Errorf("authority snapshot issuer/key resolution failed: %s/%s/%s: %w", typ, id, ver, err))
		}

		sum := sha256.Sum256(canonical)
		signingInput := append([]byte(env.signingContext), sum[:]...)
		if !ed25519.Verify(pub, signingInput, sig) {
			return FailType3("SIGNATURE_MISMATCH", fmt.Errorf("authority snapshot signature verify failed: %s/%s/%s", typ, id, ver))
		}
	}
	if err := rows.Err(); err != nil {
		return FailType2("STATE_INCONSISTENCY", err)
	}
	if count == 0 {
		return FailType3("INTEGRITY_FAILURE", errors.New("missing batch_commit_authority_bindings (empty authority set forbidden)"))
	}
	return nil
}

type authoritySnapshotEnvelope struct {
	signingContext string
	keyID          string
	keyEpoch       int64
}

func parseAuthoritySnapshotEnvelope(canonicalPayloadText string) (authoritySnapshotEnvelope, error) {
	var m map[string]any
	if err := json.Unmarshal([]byte(canonicalPayloadText), &m); err != nil {
		return authoritySnapshotEnvelope{}, err
	}
	sc, ok := m["signing_context"].(string)
	if !ok || strings.TrimSpace(sc) == "" {
		return authoritySnapshotEnvelope{}, errors.New("missing signing_context")
	}
	kid, ok := m["key_id"].(string)
	if !ok || strings.TrimSpace(kid) == "" {
		return authoritySnapshotEnvelope{}, errors.New("missing key_id")
	}
	ke, err := jsonNumberToInt64(m["key_epoch"])
	if err != nil || ke <= 0 {
		return authoritySnapshotEnvelope{}, errors.New("invalid key_epoch")
	}

	// Require key_id to be lowercase hex (PRD-04 key_id is SHA256 -> 32 bytes).
	raw, err := hex.DecodeString(strings.TrimSpace(kid))
	if err != nil || len(raw) != 32 {
		return authoritySnapshotEnvelope{}, errors.New("key_id invalid")
	}
	return authoritySnapshotEnvelope{signingContext: sc, keyID: strings.ToLower(strings.TrimSpace(kid)), keyEpoch: ke}, nil
}

func jsonNumberToInt64(v any) (int64, error) {
	switch t := v.(type) {
	case float64:
		if t != float64(int64(t)) {
			return 0, errors.New("non-integer")
		}
		return int64(t), nil
	case int64:
		return t, nil
	case json.Number:
		return t.Int64()
	default:
		return 0, errors.New("not a number")
	}
}

var _ = pgx.ErrNoRows

