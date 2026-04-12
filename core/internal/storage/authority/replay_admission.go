package authority

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// LastCommittedReplayCursor returns the highest logical_clock and message_id for (partition, shard, emitter, boot)
// that is both ADMITTED in replay_guard and covered by a durable batch_commit_records range (PRD-13 / PRD-24).
// Live admission MUST use this (or equivalent) — not unscoped replay_guard scans.
func LastCommittedReplayCursor(
	ctx context.Context,
	pool *pgxpool.Pool,
	partitionID int64,
	logicalShardID, emitterID, bootSessionID []byte,
) (lastLogicalClock uint64, lastMessageID []byte, found bool, err error) {
	if pool == nil {
		return 0, nil, false, errors.New("nil pool")
	}
	var clockText string
	var msgID []byte
	err = pool.QueryRow(ctx, `
SELECT rg.logical_clock::text, rg.message_id
FROM replay_guard rg
INNER JOIN partition_records pr
  ON pr.partition_id = rg.partition_id
 AND pr.logical_shard_id = rg.logical_shard_id
 AND pr.message_id = rg.message_id
 AND pr.record_type = 'SIGNAL'
INNER JOIN batch_commit_records b
  ON b.partition_id = pr.partition_id
 AND pr.partition_record_seq BETWEEN b.first_partition_record_seq AND b.last_partition_record_seq
WHERE rg.partition_id = $1
  AND rg.logical_shard_id = $2
  AND rg.emitter_id = $3
  AND rg.boot_session_id = $4
  AND rg.seen_state = 'ADMITTED'
ORDER BY rg.logical_clock DESC
LIMIT 1
`, partitionID, logicalShardID, emitterID, bootSessionID).Scan(&clockText, &msgID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, nil, false, nil
		}
		return 0, nil, false, err
	}
	lc, perr := strconv.ParseUint(clockText, 10, 64)
	if perr != nil {
		return 0, nil, false, fmt.Errorf("replay_guard logical_clock: %w", perr)
	}
	return lc, msgID, true, nil
}
