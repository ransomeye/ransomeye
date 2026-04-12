package authority

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SignalMessageIDCommitted reports whether a committed SIGNAL row exists for message_id (inside a durable batch).
// Used for ingest dedup: authoritative state is partition_records + batch_commit_records, not legacy telemetry_events.
func SignalMessageIDCommitted(ctx context.Context, pool *pgxpool.Pool, partitionID int64, messageID []byte) (bool, error) {
	if pool == nil {
		return false, errors.New("nil pool")
	}
	if partitionID <= 0 {
		return false, fmt.Errorf("partition_id invalid")
	}
	if len(messageID) == 0 || len(messageID) > 64 {
		return false, fmt.Errorf("message_id length invalid")
	}
	var ok bool
	err := pool.QueryRow(ctx, `
SELECT true
FROM partition_records pr
INNER JOIN batch_commit_records b
  ON b.partition_id = pr.partition_id
 AND pr.partition_record_seq BETWEEN b.first_partition_record_seq AND b.last_partition_record_seq
WHERE pr.partition_id = $1
  AND pr.record_type = 'SIGNAL'
  AND pr.message_id = $2
LIMIT 1
`, partitionID, messageID).Scan(&ok)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// DecodeMessageIDHexStrict decodes lowercase hex for a SIGNAL message_id (16-byte UUID or 32-byte digest).
func DecodeMessageIDHexStrict(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("empty message_id")
	}
	if strings.ToLower(s) != s {
		return nil, errors.New("message_id must be lowercase hex")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != 16 && len(b) != 32 {
		return nil, fmt.Errorf("message_id decoded length %d", len(b))
	}
	return b, nil
}
