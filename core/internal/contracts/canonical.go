package contracts

import "strconv"

// CanonicalString builds the deterministic canonical payload.
// Format: seq|type|event_id|agent_id|action|target|status|timestamp
// Fields must not contain '|' to ensure reproducibility across versions.
func CanonicalString(evType string, seq int64, eventID, agentID, action, target, status string, timestamp int64) string {
	// Preallocate: rough upper bound to avoid multiple allocs
	b := make([]byte, 0, 64+len(evType)+len(eventID)+len(agentID)+len(action)+len(target)+len(status))
	b = appendInt(b, seq)
	b = append(b, '|')
	b = append(b, evType...)
	b = append(b, '|')
	b = append(b, eventID...)
	b = append(b, '|')
	b = append(b, agentID...)
	b = append(b, '|')
	b = append(b, action...)
	b = append(b, '|')
	b = append(b, target...)
	b = append(b, '|')
	b = append(b, status...)
	b = append(b, '|')
	b = appendInt(b, timestamp)
	return string(b)
}

func appendInt(b []byte, n int64) []byte {
	return append(b, strconv.FormatInt(n, 10)...)
}
