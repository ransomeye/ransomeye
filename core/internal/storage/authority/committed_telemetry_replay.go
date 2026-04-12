package authority

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// CommittedTelemetryReplayPayloadHash returns whether a SIGNAL replay tuple exists in committed
// authoritative storage (replay_guard ADMITTED ∩ partition_records ∩ batch_commit_records) and
// the stored payload_hash for that row.
//
// Live telemetry/probe replay admission must use this (or equivalent SQL), not replay_guard-only
// scans and not process-local maps or JSON replay files.
func CommittedTelemetryReplayPayloadHash(
	ctx context.Context,
	pool *pgxpool.Pool,
	partitionID int64,
	logicalShardID, emitterID, bootSessionID, messageID []byte,
) (found bool, payloadHash [32]byte, err error) {
	if pool == nil {
		return false, [32]byte{}, errors.New("nil pool")
	}
	if partitionID <= 0 {
		return false, [32]byte{}, fmt.Errorf("invalid partition_id")
	}
	if len(logicalShardID) != 32 || len(emitterID) != 16 || len(bootSessionID) != 16 || len(messageID) == 0 {
		return false, [32]byte{}, fmt.Errorf("invalid replay identity lengths")
	}
	var ph []byte
	err = pool.QueryRow(ctx, `
SELECT pr.payload_hash
FROM replay_guard rg
INNER JOIN partition_records pr
  ON pr.partition_id = rg.partition_id
 AND pr.logical_shard_id = rg.logical_shard_id
 AND pr.message_id = rg.message_id
 AND pr.record_type = 'SIGNAL'
 AND pr.agent_id = rg.emitter_id
 AND pr.boot_session_id = rg.boot_session_id
INNER JOIN batch_commit_records b
  ON b.partition_id = pr.partition_id
 AND pr.partition_record_seq BETWEEN b.first_partition_record_seq AND b.last_partition_record_seq
WHERE rg.partition_id = $1
  AND rg.logical_shard_id = $2
  AND rg.emitter_id = $3
  AND rg.boot_session_id = $4
  AND rg.message_id = $5
  AND rg.seen_state = 'ADMITTED'
LIMIT 1
`, partitionID, logicalShardID, emitterID, bootSessionID, messageID).Scan(&ph)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, [32]byte{}, nil
		}
		return false, [32]byte{}, err
	}
	if len(ph) != 32 {
		return false, [32]byte{}, fmt.Errorf("payload_hash length %d", len(ph))
	}
	copy(payloadHash[:], ph)
	return true, payloadHash, nil
}

// TelemetryMessageIDBytes parses telemetry/probe message_id: canonical UUID string or strict lowercase hex (16 or 32 bytes).
func TelemetryMessageIDBytes(messageID string) ([]byte, error) {
	s := trimLowerHexOrUUID(messageID)
	if s == "" {
		return nil, errors.New("empty message_id")
	}
	// Try UUID (16-byte wire form) first — standard ingest path.
	if b, err := parseUUIDBytes(s); err == nil {
		return b, nil
	}
	return DecodeMessageIDHexStrict(s)
}

func trimLowerHexOrUUID(s string) string {
	// Accept UUID with dashes; normalize to lowercase for UUID parse.
	return trimSpaceLower(s)
}

func trimSpaceLower(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	out := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'F' {
			out[i] = c + ('a' - 'A')
		} else {
			out[i] = c
		}
	}
	return string(out)
}

func parseUUIDBytes(s string) ([]byte, error) {
	// Minimal UUID parser: 8-4-4-4-12 lowercase hex with dashes.
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return nil, errors.New("not uuid")
	}
	hexStr := s[0:8] + s[9:13] + s[14:18] + s[19:23] + s[24:36]
	if len(hexStr) != 32 {
		return nil, errors.New("not uuid")
	}
	for _, b := range []byte(hexStr) {
		if !isLowerHex(b) {
			return nil, errors.New("not uuid")
		}
	}
	b, err := hex.DecodeString(hexStr)
	if err != nil || len(b) != 16 {
		return nil, errors.New("not uuid")
	}
	return b, nil
}

func isLowerHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
}
