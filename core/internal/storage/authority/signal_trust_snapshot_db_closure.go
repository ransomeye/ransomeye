package authority

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Gateway signal DB e2e tests use these version prefixes so production trust_snapshot rows
// (e.g. Mishka v1) can coexist on the same database without tripping closure checks.
const (
	GatewaySignalE2ETrustVersionPrefix        = "signal_e2e."
	GatewaySignalE2ECorruptTrustVersionPrefix = "corrupt_signal_e2e."
)

func isGatewaySignalE2EScopedTrustVersion(version string) bool {
	v := strings.TrimSpace(version)
	return strings.HasPrefix(v, GatewaySignalE2ETrustVersionPrefix) || strings.HasPrefix(v, GatewaySignalE2ECorruptTrustVersionPrefix)
}

// AssertCommittedTrustSnapshotsMatchSignalBoundClosure fails closed (TYPE 3) if authority_snapshots
// contains any CONFIG/trust_snapshot row outside the bound closure supplied with the SIGNAL (env snapshots).
// Extra versions (e.g. poisoned rows) or byte drift vs the bound upsert are rejected before commit.
func AssertCommittedTrustSnapshotsMatchSignalBoundClosure(ctx context.Context, pool *pgxpool.Pool, snaps []SnapshotUpsert) error {
	if pool == nil {
		return nil
	}
	allowed := make(map[string]SnapshotUpsert)
	for _, s := range snaps {
		if s.Type == trustAuthorityType && s.ID == trustAuthorityID {
			allowed[s.Version] = s
		}
	}
	if len(allowed) == 0 {
		return nil
	}
	rows, err := pool.Query(ctx, `
SELECT authority_version, canonical_payload_text, payload_hash, signature
FROM authority_snapshots
WHERE authority_type = $1 AND authority_id = $2`,
		trustAuthorityType, trustAuthorityID)
	if err != nil {
		return FailType2("STATE_INCONSISTENCY", fmt.Errorf("read authority_snapshots trust rows: %w", err))
	}
	defer rows.Close()
	for rows.Next() {
		var ver, text string
		var h, sig []byte
		if err := rows.Scan(&ver, &text, &h, &sig); err != nil {
			return FailType2("STATE_INCONSISTENCY", fmt.Errorf("scan authority_snapshots: %w", err))
		}
		exp, ok := allowed[ver]
		if !ok {
			if isGatewaySignalE2EScopedTrustVersion(ver) {
				return FailType3("TRUST_SNAPSHOT_CLOSURE_VIOLATION", fmt.Errorf("unexpected trust_snapshot version %q in authority_snapshots (not in bound closure)", ver))
			}
			// Other versions (e.g. production v1) may remain in the table but are outside this SIGNAL's bound closure.
			continue
		}
		if text != exp.CanonicalPayloadText {
			return FailType3("TRUST_SNAPSHOT_CLOSURE_VIOLATION", errors.New("trust_snapshot canonical_payload_text mismatch vs bound closure"))
		}
		if len(h) != 32 || !bytes.Equal(h, exp.PayloadHash[:]) {
			return FailType3("TRUST_SNAPSHOT_CLOSURE_VIOLATION", errors.New("trust_snapshot payload_hash mismatch vs bound closure"))
		}
		if len(sig) == 0 || !bytes.Equal(sig, exp.Signature) {
			return FailType3("TRUST_SNAPSHOT_CLOSURE_VIOLATION", errors.New("trust_snapshot signature mismatch vs bound closure"))
		}
	}
	if err := rows.Err(); err != nil {
		return FailType2("STATE_INCONSISTENCY", err)
	}
	return nil
}
