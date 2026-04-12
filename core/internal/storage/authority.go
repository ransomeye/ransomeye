package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	ReplayGuardStatePendingQueueCommit = "PENDING_QUEUE_COMMIT"
	ReplayGuardStateAdmitted           = "ADMITTED"
	preAuthMessageTypePreTLSAuth       = "PRE_TLS_AUTH"
)

var allowedAuthorityTypes = map[string]struct{}{
	"CONFIG":                       {},
	"POLICY":                       {},
	"MODEL":                        {},
	"SHARD_CONFIG":                 {},
	"ENTITY_ROUTE_MAP":             {},
	"PARAMETER_PROFILE":            {},
	"ADAPTER_MANIFEST":             {},
	"ACTION_CAPABILITY_DESCRIPTOR": {},
	"RETENTION_CONFIG":             {},
}

type AuthoritySnapshot struct {
	AuthorityType        string
	AuthorityID          string
	AuthorityVersion     string
	CanonicalPayloadText string
	PayloadHash          []byte
	Signature            []byte
}

type ReplayGuardEntry struct {
	PartitionID                 int64
	LogicalShardID              []byte
	EmitterID                   []byte
	BootSessionID               []byte
	LogicalClock                string
	MessageID                   []byte
	SeenState                   string
	PreAuthNonce                []byte
	PreAuthToken                []byte
	PreAuthMessageType          string
	PreAuthValidityWindow       string
	PreAuthExecutionContextHash []byte
	EscrowHandoffID             []byte
}

func (s AuthoritySnapshot) Validate() error {
	if _, ok := allowedAuthorityTypes[strings.TrimSpace(s.AuthorityType)]; !ok {
		return fmt.Errorf("authority snapshot type %q not allowed", s.AuthorityType)
	}
	if err := validateTightText("authority_id", s.AuthorityID); err != nil {
		return err
	}
	if err := validateTightText("authority_version", s.AuthorityVersion); err != nil {
		return err
	}
	if err := validateTightText("canonical_payload_text", s.CanonicalPayloadText); err != nil {
		return err
	}
	if len(s.PayloadHash) != 32 {
		return errors.New("authority snapshot payload_hash must be 32 bytes")
	}
	if len(s.Signature) == 0 {
		return errors.New("authority snapshot signature required")
	}
	return nil
}

func (e ReplayGuardEntry) Validate() error {
	if e.PartitionID <= 0 {
		return errors.New("replay guard partition_id must be positive")
	}
	if len(e.LogicalShardID) == 0 {
		return errors.New("replay guard logical_shard_id required")
	}
	if len(e.EmitterID) == 0 {
		return errors.New("replay guard emitter_id required")
	}
	if len(e.BootSessionID) == 0 {
		return errors.New("replay guard boot_session_id required")
	}
	if len(e.MessageID) == 0 {
		return errors.New("replay guard message_id required")
	}
	if err := validateUint20("logical_clock", e.LogicalClock); err != nil {
		return err
	}
	switch e.SeenState {
	case ReplayGuardStatePendingQueueCommit, ReplayGuardStateAdmitted:
	default:
		return fmt.Errorf("replay guard seen_state %q not allowed", e.SeenState)
	}
	if e.PreAuthMessageType != "" && e.PreAuthMessageType != preAuthMessageTypePreTLSAuth {
		return fmt.Errorf("replay guard pre_auth_message_type %q not allowed", e.PreAuthMessageType)
	}
	if len(e.PreAuthExecutionContextHash) != 0 && len(e.PreAuthExecutionContextHash) != 32 {
		return errors.New("replay guard pre_auth_execution_context_hash must be 32 bytes")
	}
	return nil
}

func UpsertAuthoritySnapshot(ctx context.Context, pool *pgxpool.Pool, snapshot AuthoritySnapshot) error {
	if pool == nil {
		return errors.New("nil authority snapshot pool")
	}
	if err := snapshot.Validate(); err != nil {
		return err
	}

	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	tag, err := tx.Exec(
		ctx,
		`INSERT INTO authority_snapshots (
			authority_type,
			authority_id,
			authority_version,
			canonical_payload_text,
			payload_hash,
			signature
		) VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT DO NOTHING`,
		strings.TrimSpace(snapshot.AuthorityType),
		snapshot.AuthorityID,
		snapshot.AuthorityVersion,
		snapshot.CanonicalPayloadText,
		snapshot.PayloadHash,
		snapshot.Signature,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		if err := verifyStoredAuthoritySnapshot(ctx, tx, snapshot); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func PutReplayGuardEntry(ctx context.Context, pool *pgxpool.Pool, entry ReplayGuardEntry) error {
	if pool == nil {
		return errors.New("nil replay guard pool")
	}
	if err := entry.Validate(); err != nil {
		return err
	}

	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	tag, err := tx.Exec(
		ctx,
		`INSERT INTO replay_guard (
			partition_id,
			logical_shard_id,
			emitter_id,
			boot_session_id,
			logical_clock,
			message_id,
			seen_state,
			pre_auth_nonce,
			pre_auth_token,
			pre_auth_message_type,
			pre_auth_validity_window,
			pre_auth_execution_context_hash,
			escrow_handoff_id
		) VALUES (
			$1, $2, $3, $4, $5::numeric(20,0), $6, $7, $8, $9, $10, $11, $12, $13
		)
		ON CONFLICT DO NOTHING`,
		entry.PartitionID,
		entry.LogicalShardID,
		entry.EmitterID,
		entry.BootSessionID,
		entry.LogicalClock,
		entry.MessageID,
		entry.SeenState,
		nilIfEmpty(entry.PreAuthNonce),
		nilIfEmpty(entry.PreAuthToken),
		nilIfBlank(entry.PreAuthMessageType),
		nilIfBlank(entry.PreAuthValidityWindow),
		nilIfEmpty(entry.PreAuthExecutionContextHash),
		nilIfEmpty(entry.EscrowHandoffID),
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		if err := verifyStoredReplayGuardEntry(ctx, tx, entry); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func RestoreAdmittedReplayGuard(ctx context.Context, pool *pgxpool.Pool, partitionID int64) error {
	if pool == nil {
		return errors.New("nil replay guard pool")
	}
	if partitionID <= 0 {
		return errors.New("partition_id must be positive")
	}

	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `DELETE FROM replay_guard WHERE partition_id = $1`, partitionID); err != nil {
		return fmt.Errorf("delete replay_guard partition %d: %w", partitionID, err)
	}

	if _, err := tx.Exec(ctx, `
INSERT INTO replay_guard (
	partition_id,
	logical_shard_id,
	emitter_id,
	boot_session_id,
	logical_clock,
	message_id,
	seen_state,
	pre_auth_nonce
)
SELECT
	pr.partition_id,
	pr.logical_shard_id,
	pr.agent_id,
	pr.boot_session_id,
	pr.logical_clock,
	pr.message_id,
	$2,
	pr.message_id
FROM partition_records pr
WHERE pr.partition_id = $1
  AND pr.record_type = 'SIGNAL'
  AND pr.partition_record_seq <= COALESCE((
      SELECT MAX(last_partition_record_seq)
      FROM batch_commit_records
      WHERE partition_id = $1
  ), 0)
ORDER BY pr.partition_record_seq ASC
`, partitionID, ReplayGuardStateAdmitted); err != nil {
		return fmt.Errorf("restore replay_guard partition %d: %w", partitionID, err)
	}

	return tx.Commit(ctx)
}

func verifyStoredAuthoritySnapshot(ctx context.Context, tx pgx.Tx, snapshot AuthoritySnapshot) error {
	var existing AuthoritySnapshot
	if err := tx.QueryRow(
		ctx,
		`SELECT authority_type, authority_id, authority_version, canonical_payload_text, payload_hash, signature
		 FROM authority_snapshots
		 WHERE authority_type = $1 AND authority_id = $2 AND authority_version = $3`,
		strings.TrimSpace(snapshot.AuthorityType),
		snapshot.AuthorityID,
		snapshot.AuthorityVersion,
	).Scan(
		&existing.AuthorityType,
		&existing.AuthorityID,
		&existing.AuthorityVersion,
		&existing.CanonicalPayloadText,
		&existing.PayloadHash,
		&existing.Signature,
	); err != nil {
		return err
	}
	if existing.CanonicalPayloadText != snapshot.CanonicalPayloadText ||
		!bytes.Equal(existing.PayloadHash, snapshot.PayloadHash) ||
		!bytes.Equal(existing.Signature, snapshot.Signature) {
		return errors.New("authority snapshot conflict with committed row")
	}
	return nil
}

func verifyStoredReplayGuardEntry(ctx context.Context, tx pgx.Tx, entry ReplayGuardEntry) error {
	var existing ReplayGuardEntry
	if err := tx.QueryRow(
		ctx,
		`SELECT
			partition_id,
			logical_shard_id,
			emitter_id,
			boot_session_id,
			logical_clock::text,
			message_id,
			seen_state,
			pre_auth_nonce,
			pre_auth_token,
			COALESCE(pre_auth_message_type, ''),
			COALESCE(pre_auth_validity_window, ''),
			COALESCE(pre_auth_execution_context_hash, '\x'::bytea),
			COALESCE(escrow_handoff_id, '\x'::bytea)
		 FROM replay_guard
		 WHERE partition_id = $1 AND logical_shard_id = $2 AND message_id = $3`,
		entry.PartitionID,
		entry.LogicalShardID,
		entry.MessageID,
	).Scan(
		&existing.PartitionID,
		&existing.LogicalShardID,
		&existing.EmitterID,
		&existing.BootSessionID,
		&existing.LogicalClock,
		&existing.MessageID,
		&existing.SeenState,
		&existing.PreAuthNonce,
		&existing.PreAuthToken,
		&existing.PreAuthMessageType,
		&existing.PreAuthValidityWindow,
		&existing.PreAuthExecutionContextHash,
		&existing.EscrowHandoffID,
	); err != nil {
		return err
	}

	if existing.LogicalClock != entry.LogicalClock ||
		existing.SeenState != entry.SeenState ||
		!bytes.Equal(existing.LogicalShardID, entry.LogicalShardID) ||
		!bytes.Equal(existing.EmitterID, entry.EmitterID) ||
		!bytes.Equal(existing.BootSessionID, entry.BootSessionID) ||
		!bytes.Equal(existing.MessageID, entry.MessageID) ||
		!bytes.Equal(existing.PreAuthNonce, entry.PreAuthNonce) ||
		!bytes.Equal(existing.PreAuthToken, entry.PreAuthToken) ||
		existing.PreAuthMessageType != entry.PreAuthMessageType ||
		existing.PreAuthValidityWindow != entry.PreAuthValidityWindow ||
		!bytes.Equal(existing.PreAuthExecutionContextHash, entry.PreAuthExecutionContextHash) ||
		!bytes.Equal(existing.EscrowHandoffID, entry.EscrowHandoffID) {
		return errors.New("replay guard conflict with committed row")
	}
	return nil
}

func validateTightText(field string, value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s required", field)
	}
	if value != strings.TrimSpace(value) {
		return fmt.Errorf("%s must not have surrounding whitespace", field)
	}
	if !utf8.ValidString(value) {
		return fmt.Errorf("%s must be valid UTF-8", field)
	}
	return nil
}

func validateUint20(field string, value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s required", field)
	}
	if value != strings.TrimSpace(value) {
		return fmt.Errorf("%s must not have surrounding whitespace", field)
	}
	if len(value) > 20 {
		return fmt.Errorf("%s exceeds numeric(20,0)", field)
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return fmt.Errorf("%s must contain only decimal digits", field)
		}
	}
	return nil
}

func nilIfEmpty(raw []byte) []byte {
	if len(raw) == 0 {
		return nil
	}
	return raw
}

func nilIfBlank(s string) any {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return s
}
