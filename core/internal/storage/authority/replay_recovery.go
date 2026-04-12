package authority

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// LoadCommittedReplaySeen rebuilds gateway replay deduplication state strictly from rows that are
// (1) present in replay_guard as ADMITTED and (2) covered by a durable batch_commit_records range.
// This implements PRD-13 / PRD-24: replay guard authority is committed storage only (not Kafka or disk cache).
func LoadCommittedReplaySeen(
	ctx context.Context,
	pool *pgxpool.Pool,
	partitionID int64,
	logicalShardID []byte,
	systemIdentityHash string,
) (map[string][32]byte, error) {
	if pool == nil {
		return nil, errors.New("nil pool")
	}
	if len(logicalShardID) != 32 {
		return nil, fmt.Errorf("logical_shard_id must be 32 bytes, got %d", len(logicalShardID))
	}
	if systemIdentityHash == "" {
		return nil, errors.New("systemIdentityHash required for replay key reconstruction")
	}

	const q = `
SELECT pr.agent_id, pr.boot_session_id, pr.message_id, pr.payload_hash
FROM replay_guard rg
INNER JOIN partition_records pr
  ON pr.partition_id = rg.partition_id
 AND pr.message_id = rg.message_id
 AND pr.logical_shard_id = rg.logical_shard_id
 AND pr.record_type = 'SIGNAL'
INNER JOIN batch_commit_records b
  ON b.partition_id = pr.partition_id
 AND pr.partition_record_seq BETWEEN b.first_partition_record_seq AND b.last_partition_record_seq
WHERE rg.partition_id = $1
  AND rg.logical_shard_id = $2
  AND rg.seen_state = 'ADMITTED'
`
	rows, err := pool.Query(ctx, q, partitionID, logicalShardID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make(map[string][32]byte)
	for rows.Next() {
		var agentID, bootID, msgID, payloadHash []byte
		if err := rows.Scan(&agentID, &bootID, &msgID, &payloadHash); err != nil {
			return nil, err
		}
		if len(payloadHash) != 32 {
			return nil, fmt.Errorf("payload_hash length %d", len(payloadHash))
		}
		agentStr, err := uuidBytesToString(agentID)
		if err != nil {
			return nil, fmt.Errorf("agent_id: %w", err)
		}
		bootStr, err := uuidBytesToString(bootID)
		if err != nil {
			return nil, fmt.Errorf("boot_session_id: %w", err)
		}
		msgStr, err := replayMessageIDKeyString(msgID)
		if err != nil {
			return nil, fmt.Errorf("message_id: %w", err)
		}
		key := systemIdentityHash + "|" + agentStr + "|" + bootStr + "|" + msgStr
		var h [32]byte
		copy(h[:], payloadHash)
		out[key] = h
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func uuidBytesToString(b []byte) (string, error) {
	if len(b) != 16 {
		return "", fmt.Errorf("expected 16-byte uuid, got %d", len(b))
	}
	u, err := uuid.FromBytes(b)
	if err != nil {
		return "", err
	}
	return u.String(), nil
}

// replayMessageIDKeyString formats message_id bytes for replay map keys: UUID text for 16-byte wire IDs,
// lowercase hex for 32-byte digests (Mishka SIGNAL shape).
func replayMessageIDKeyString(msgID []byte) (string, error) {
	switch len(msgID) {
	case 16:
		return uuidBytesToString(msgID)
	case 32:
		return hex.EncodeToString(msgID), nil
	default:
		return "", fmt.Errorf("message_id length %d", len(msgID))
	}
}
