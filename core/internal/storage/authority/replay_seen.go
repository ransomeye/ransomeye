package authority

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// LoadCommittedReplaySeenHexEmitter is a hex-emitter variant retained for transitional callers.
// The returned map key format matches gateway replayKey: tenant|identity|boot_session|message_id.
func LoadCommittedReplaySeenHexEmitter(ctx context.Context, pool *pgxpool.Pool, partitionID int64, logicalShardID []byte, tenantID string) (map[string][32]byte, error) {
	if pool == nil {
		return nil, fmt.Errorf("nil replay_seen pool")
	}
	if partitionID <= 0 {
		return nil, fmt.Errorf("partition_id must be positive")
	}
	if len(logicalShardID) == 0 {
		return nil, fmt.Errorf("logical_shard_id required")
	}
	tenant := strings.TrimSpace(tenantID)
	if tenant == "" {
		return nil, fmt.Errorf("tenant_id required")
	}

	rows, err := pool.Query(ctx, `
SELECT
  rg.emitter_id,
  rg.boot_session_id,
  rg.message_id,
  pr.payload_hash
FROM replay_guard rg
JOIN partition_records pr
  ON pr.partition_id = rg.partition_id
 AND pr.logical_shard_id = rg.logical_shard_id
 AND pr.message_id = rg.message_id
WHERE rg.partition_id = $1
  AND rg.logical_shard_id = $2
  AND rg.seen_state = 'ADMITTED'
  AND pr.record_type = 'SIGNAL'
  AND pr.partition_record_seq <= COALESCE((
      SELECT MAX(last_partition_record_seq)
      FROM batch_commit_records
      WHERE partition_id = $1
  ), 0)`,
		partitionID,
		logicalShardID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make(map[string][32]byte)
	for rows.Next() {
		var emitterID []byte
		var bootSessionID []byte
		var messageID []byte
		var payloadHash []byte
		if err := rows.Scan(&emitterID, &bootSessionID, &messageID, &payloadHash); err != nil {
			return nil, err
		}
		if len(payloadHash) != 32 {
			return nil, fmt.Errorf("payload_hash length %d", len(payloadHash))
		}
		var sum [32]byte
		copy(sum[:], payloadHash)
		replayKey := strings.Join([]string{
			tenant,
			hex.EncodeToString(emitterID),
			hex.EncodeToString(bootSessionID),
			hex.EncodeToString(messageID),
		}, "|")
		out[replayKey] = sum
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
