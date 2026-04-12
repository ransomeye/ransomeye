package authority

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestVerifyCommittedBatch_ReconstructsAndVerifies(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("POSTGRES_DSN not set — skipping DB integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool: %v", err)
	}
	defer pool.Close()

	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 root: %v", err)
	}
clusterPub, clusterPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 cluster: %v", err)
	}

	partitionID := int64(9001)
	logicalShardID := make([]byte, 32)

	// Bind both chaos snapshot and trust snapshot; exec context = SHA256(chaos_payload_hash || trust_payload_hash).
	scopeID := "scope-1"
	rootEpoch := int64(1)
	rootType := "ROOT"
	rootKeyID := prd04KeyID(rootType, scopeID, rootEpoch, rootPub)
	clusterEpoch := int64(1)
	clusterType := "CLUSTER"
	clusterKeyID := prd04KeyID(clusterType, scopeID, clusterEpoch, clusterPub)

	// Key record signing: issuer signs key_record payload under signing_context "key_record_v1".
	rootRec, err := signedKeyRecord(rootPriv, keyRecordInput{
		KeyID:                  rootKeyID,
		KeyType:                rootType,
		ScopeID:                scopeID,
		AuthorityScope:         "cluster",
		KeyEpoch:               rootEpoch,
		PublicKeyHex:           hex.EncodeToString(rootPub),
		AllowedSigningContexts: []string{"key_record_v1", "config_snapshot_v1", "trust_snapshot_v1"},
		IssuerKeyID:            rootKeyID,
		Status:                 "ACTIVE",
		SigningContext:         "key_record_v1",
	})
	if err != nil {
		t.Fatalf("root key record: %v", err)
	}
	clusterRec, err := signedKeyRecord(rootPriv, keyRecordInput{
		KeyID:                  clusterKeyID,
		KeyType:                clusterType,
		ScopeID:                scopeID,
		AuthorityScope:         "cluster",
		KeyEpoch:               clusterEpoch,
		PublicKeyHex:           hex.EncodeToString(clusterPub),
		AllowedSigningContexts: []string{BatchCommitSigningContext},
		IssuerKeyID:            rootKeyID,
		Status:                 "ACTIVE",
		SigningContext:         "key_record_v1",
	})
	if err != nil {
		t.Fatalf("cluster key record: %v", err)
	}
	trustText, trustPH, trustSig, err := signedTrustSnapshot(rootPriv, rootKeyID, rootEpoch, scopeID, []string{rootRec, clusterRec})
	if err != nil {
		t.Fatalf("trust snapshot sign: %v", err)
	}

	chaosText, chaosPH, chaosSig, err := signedChaosValidationMatrixSnapshot(rootPriv, rootKeyID, rootEpoch, "batch_verify_test")
	if err != nil {
		t.Fatalf("chaos snapshot sign: %v", err)
	}
	chaosVersion := fmt.Sprintf("chaos_validation_matrix_v1_%d", time.Now().UnixNano())
	trustVersion := fmt.Sprintf("trust_snapshot_v1_%d", time.Now().UnixNano())
	exec := sha256.Sum256(append(chaosPH[:], trustPH[:]...))

	recPayload := []byte("x")
	recPH := sha256.Sum256(recPayload)
	recordID := sha256.Sum256([]byte(fmt.Sprintf("record-1-%d", time.Now().UnixNano())))

	opts := CommitOptions{
		PartitionID:          partitionID,
		PartitionEpoch:       0,
		ExecutionContextHash: exec,
		AuthoritySnapshots: []SnapshotUpsert{
			{
				Type:                 "CONFIG",
				ID:                   "chaos_validation_matrix",
				Version:              chaosVersion,
				CanonicalPayloadText: chaosText,
				PayloadHash:          chaosPH,
				Signature:            chaosSig,
			},
			{
				Type:                 "CONFIG",
				ID:                   "trust_snapshot",
				Version:              trustVersion,
				CanonicalPayloadText: trustText,
				PayloadHash:          trustPH,
				Signature:            trustSig,
			},
		},
		Records: []RecordDraft{{
			RecordType:            "DECISION",
			RecordVersion:         "v1",
			StageOrder:            3,
			RecordID:              recordID[:],
			LogicalShardID:        logicalShardID,
			CausalParentRefsText:  "{}",
			CanonicalPayloadBytes: recPayload,
			CanonicalPayloadHash:  recPH,
		}},
		PrivateKey: clusterPriv,
		KeyID:      clusterKeyID,
		KeyEpoch:   1,
	}

	if err := CommitPartitionBatch(ctx, pool, opts); err != nil {
		t.Fatalf("commit: %v", err)
	}

	var batchSeq int64
	if err := pool.QueryRow(ctx, `SELECT MAX(batch_commit_seq) FROM batch_commit_records WHERE partition_id = $1`, partitionID).Scan(&batchSeq); err != nil {
		t.Fatalf("batch seq: %v", err)
	}
	if batchSeq == 0 {
		t.Fatalf("missing batch_commit_seq")
	}

	if _, err := VerifyCommittedBatch(ctx, pool, partitionID, batchSeq); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestVerifyBoundAuthoritySnapshots_Valid(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("POSTGRES_DSN not set — skipping DB integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool: %v", err)
	}
	defer pool.Close()

	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 root: %v", err)
	}
	signerPub, signerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 signer: %v", err)
	}

	partitionID := int64(9101)
	logicalShardID := make([]byte, 32)
	scopeID := "scope-snap-ok"
	rootEpoch := int64(1)
	rootType := "ROOT"
	rootKeyID := prd04KeyID(rootType, scopeID, rootEpoch, rootPub)
	signerEpoch := int64(1)
	signerType := "CLUSTER"
	signerKeyID := prd04KeyID(signerType, scopeID, signerEpoch, signerPub)

	rootRec, err := signedKeyRecord(rootPriv, keyRecordInput{
		KeyID:                  rootKeyID,
		KeyType:                rootType,
		ScopeID:                scopeID,
		AuthorityScope:         "cluster",
		KeyEpoch:               rootEpoch,
		PublicKeyHex:           hex.EncodeToString(rootPub),
		AllowedSigningContexts: []string{"key_record_v1", "trust_snapshot_v1", "config_snapshot_v1"},
		IssuerKeyID:            rootKeyID,
		Status:                 "ACTIVE",
		SigningContext:         "key_record_v1",
	})
	if err != nil {
		t.Fatalf("root key record: %v", err)
	}
	signerRec, err := signedKeyRecord(rootPriv, keyRecordInput{
		KeyID:                  signerKeyID,
		KeyType:                signerType,
		ScopeID:                scopeID,
		AuthorityScope:         "cluster",
		KeyEpoch:               signerEpoch,
		PublicKeyHex:           hex.EncodeToString(signerPub),
		AllowedSigningContexts: []string{BatchCommitSigningContext, "config_snapshot_v1"},
		IssuerKeyID:            rootKeyID,
		Status:                 "ACTIVE",
		SigningContext:         "key_record_v1",
	})
	if err != nil {
		t.Fatalf("signer key record: %v", err)
	}

	trustText, trustPH, trustSig, err := signedTrustSnapshot(rootPriv, rootKeyID, rootEpoch, scopeID, []string{rootRec, signerRec})
	if err != nil {
		t.Fatalf("trust snapshot sign: %v", err)
	}
	chaosText, chaosPH, chaosSig, err := signedChaosValidationMatrixSnapshot(signerPriv, signerKeyID, signerEpoch, "snap-ok")
	if err != nil {
		t.Fatalf("chaos snapshot sign: %v", err)
	}
	exec := sha256.Sum256(append(chaosPH[:], trustPH[:]...))

	recPayload := []byte("x")
	recPH := sha256.Sum256(recPayload)
	recordID := sha256.Sum256([]byte("record-snap-ok"))

	opts := CommitOptions{
		PartitionID:          partitionID,
		PartitionEpoch:       0,
		ExecutionContextHash: exec,
		AuthoritySnapshots: []SnapshotUpsert{
			{
				Type:                 "CONFIG",
				ID:                   "chaos_validation_matrix",
				Version:              "chaos_validation_matrix_v1",
				CanonicalPayloadText: chaosText,
				PayloadHash:          chaosPH,
				Signature:            chaosSig,
			},
			{
				Type:                 "CONFIG",
				ID:                   "trust_snapshot",
				Version:              "v1",
				CanonicalPayloadText: trustText,
				PayloadHash:          trustPH,
				Signature:            trustSig,
			},
		},
		Records: []RecordDraft{{
			RecordType:            "DECISION",
			RecordVersion:         "v1",
			StageOrder:            3,
			RecordID:              recordID[:],
			LogicalShardID:        logicalShardID,
			CausalParentRefsText:  "{}",
			CanonicalPayloadBytes: recPayload,
			CanonicalPayloadHash:  recPH,
		}},
		PrivateKey: signerPriv,
		KeyID:      signerKeyID,
		KeyEpoch:   1,
	}
	if err := CommitPartitionBatch(ctx, pool, opts); err != nil {
		t.Fatalf("commit: %v", err)
	}
	var batchSeq int64
	if err := pool.QueryRow(ctx, `SELECT MAX(batch_commit_seq) FROM batch_commit_records WHERE partition_id = $1`, partitionID).Scan(&batchSeq); err != nil {
		t.Fatalf("batch seq: %v", err)
	}
	if err := VerifyBoundAuthoritySnapshots(ctx, pool, partitionID, batchSeq); err != nil {
		t.Fatalf("VerifyBoundAuthoritySnapshots: %v", err)
	}
}

func TestVerifyBoundAuthoritySnapshots_FailsOnMissingIssuerKey(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("POSTGRES_DSN not set — skipping DB integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool: %v", err)
	}
	defer pool.Close()

	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 root: %v", err)
	}
	partitionID := int64(9102)
	logicalShardID := make([]byte, 32)
	scopeID := "scope-snap-missing-issuer"
	rootEpoch := int64(1)
	rootType := "ROOT"
	rootKeyID := prd04KeyID(rootType, scopeID, rootEpoch, rootPub)

	rootRec, err := signedKeyRecord(rootPriv, keyRecordInput{
		KeyID:                  rootKeyID,
		KeyType:                rootType,
		ScopeID:                scopeID,
		AuthorityScope:         "cluster",
		KeyEpoch:               rootEpoch,
		PublicKeyHex:           hex.EncodeToString(rootPub),
		AllowedSigningContexts: []string{"key_record_v1", "trust_snapshot_v1"},
		IssuerKeyID:            rootKeyID,
		Status:                 "ACTIVE",
		SigningContext:         "key_record_v1",
	})
	if err != nil {
		t.Fatalf("root key record: %v", err)
	}
	trustText, trustPH, trustSig, err := signedTrustSnapshot(rootPriv, rootKeyID, rootEpoch, scopeID, []string{rootRec})
	if err != nil {
		t.Fatalf("trust snapshot sign: %v", err)
	}

	// Snapshot claims signer key that is NOT present in trust snapshot.
	missingKeyID := strings.Repeat("11", 32)
	chaosText, chaosPH, chaosSig, err := signedChaosValidationMatrixSnapshot(rootPriv, missingKeyID, rootEpoch, "snap-missing-issuer")
	if err != nil {
		t.Fatalf("chaos snapshot sign: %v", err)
	}
	exec := sha256.Sum256(append(chaosPH[:], trustPH[:]...))

	recPayload := []byte("x")
	recPH := sha256.Sum256(recPayload)
	recordID := sha256.Sum256([]byte("record-snap-missing-issuer"))

	opts := CommitOptions{
		PartitionID:          partitionID,
		PartitionEpoch:       0,
		ExecutionContextHash: exec,
		AuthoritySnapshots: []SnapshotUpsert{
			{
				Type:                 "CONFIG",
				ID:                   "chaos_validation_matrix",
				Version:              "chaos_validation_matrix_v1",
				CanonicalPayloadText: chaosText,
				PayloadHash:          chaosPH,
				Signature:            chaosSig,
			},
			{
				Type:                 "CONFIG",
				ID:                   "trust_snapshot",
				Version:              "v1",
				CanonicalPayloadText: trustText,
				PayloadHash:          trustPH,
				Signature:            trustSig,
			},
		},
		Records: []RecordDraft{{
			RecordType:            "DECISION",
			RecordVersion:         "v1",
			StageOrder:            3,
			RecordID:              recordID[:],
			LogicalShardID:        logicalShardID,
			CausalParentRefsText:  "{}",
			CanonicalPayloadBytes: recPayload,
			CanonicalPayloadHash:  recPH,
		}},
		PrivateKey: rootPriv,
		KeyID:      rootKeyID,
		KeyEpoch:   1,
	}
	if err := CommitPartitionBatch(ctx, pool, opts); err != nil {
		t.Fatalf("commit: %v", err)
	}
	var batchSeq int64
	if err := pool.QueryRow(ctx, `SELECT MAX(batch_commit_seq) FROM batch_commit_records WHERE partition_id = $1`, partitionID).Scan(&batchSeq); err != nil {
		t.Fatalf("batch seq: %v", err)
	}
	if err := VerifyBoundAuthoritySnapshots(ctx, pool, partitionID, batchSeq); err == nil {
		t.Fatalf("expected failure")
	}
}

func TestVerifyBoundAuthoritySnapshots_FailsOnBadSignature(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("POSTGRES_DSN not set — skipping DB integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool: %v", err)
	}
	defer pool.Close()

	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 root: %v", err)
	}
	signerPub, signerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 signer: %v", err)
	}

	partitionID := int64(9103)
	logicalShardID := make([]byte, 32)
	scopeID := "scope-snap-bad-sig"
	rootEpoch := int64(1)
	rootType := "ROOT"
	rootKeyID := prd04KeyID(rootType, scopeID, rootEpoch, rootPub)
	signerEpoch := int64(1)
	signerType := "CLUSTER"
	signerKeyID := prd04KeyID(signerType, scopeID, signerEpoch, signerPub)

	rootRec, err := signedKeyRecord(rootPriv, keyRecordInput{
		KeyID:                  rootKeyID,
		KeyType:                rootType,
		ScopeID:                scopeID,
		AuthorityScope:         "cluster",
		KeyEpoch:               rootEpoch,
		PublicKeyHex:           hex.EncodeToString(rootPub),
		AllowedSigningContexts: []string{"key_record_v1", "trust_snapshot_v1"},
		IssuerKeyID:            rootKeyID,
		Status:                 "ACTIVE",
		SigningContext:         "key_record_v1",
	})
	if err != nil {
		t.Fatalf("root key record: %v", err)
	}
	signerRec, err := signedKeyRecord(rootPriv, keyRecordInput{
		KeyID:                  signerKeyID,
		KeyType:                signerType,
		ScopeID:                scopeID,
		AuthorityScope:         "cluster",
		KeyEpoch:               signerEpoch,
		PublicKeyHex:           hex.EncodeToString(signerPub),
		AllowedSigningContexts: []string{BatchCommitSigningContext, "config_snapshot_v1"},
		IssuerKeyID:            rootKeyID,
		Status:                 "ACTIVE",
		SigningContext:         "key_record_v1",
	})
	if err != nil {
		t.Fatalf("signer key record: %v", err)
	}

	trustText, trustPH, trustSig, err := signedTrustSnapshot(rootPriv, rootKeyID, rootEpoch, scopeID, []string{rootRec, signerRec})
	if err != nil {
		t.Fatalf("trust snapshot sign: %v", err)
	}
	chaosText, chaosPH, chaosSig, err := signedChaosValidationMatrixSnapshot(signerPriv, signerKeyID, signerEpoch, "snap-bad-sig")
	if err != nil {
		t.Fatalf("chaos snapshot sign: %v", err)
	}
	chaosSig[0] ^= 0xFF

	exec := sha256.Sum256(append(chaosPH[:], trustPH[:]...))
	recPayload := []byte("x")
	recPH := sha256.Sum256(recPayload)
	recordID := sha256.Sum256([]byte("record-snap-bad-sig"))

	opts := CommitOptions{
		PartitionID:          partitionID,
		PartitionEpoch:       0,
		ExecutionContextHash: exec,
		AuthoritySnapshots: []SnapshotUpsert{
			{
				Type:                 "CONFIG",
				ID:                   "chaos_validation_matrix",
				Version:              "chaos_validation_matrix_v1",
				CanonicalPayloadText: chaosText,
				PayloadHash:          chaosPH,
				Signature:            chaosSig,
			},
			{
				Type:                 "CONFIG",
				ID:                   "trust_snapshot",
				Version:              "v1",
				CanonicalPayloadText: trustText,
				PayloadHash:          trustPH,
				Signature:            trustSig,
			},
		},
		Records: []RecordDraft{{
			RecordType:            "DECISION",
			RecordVersion:         "v1",
			StageOrder:            3,
			RecordID:              recordID[:],
			LogicalShardID:        logicalShardID,
			CausalParentRefsText:  "{}",
			CanonicalPayloadBytes: recPayload,
			CanonicalPayloadHash:  recPH,
		}},
		PrivateKey: signerPriv,
		KeyID:      signerKeyID,
		KeyEpoch:   1,
	}
	if err := CommitPartitionBatch(ctx, pool, opts); err != nil {
		t.Fatalf("commit: %v", err)
	}
	var batchSeq int64
	if err := pool.QueryRow(ctx, `SELECT MAX(batch_commit_seq) FROM batch_commit_records WHERE partition_id = $1`, partitionID).Scan(&batchSeq); err != nil {
		t.Fatalf("batch seq: %v", err)
	}
	if err := VerifyBoundAuthoritySnapshots(ctx, pool, partitionID, batchSeq); err == nil {
		t.Fatalf("expected failure")
	}
}

func TestVerifyBoundAuthoritySnapshots_FailsOnRevokedIssuerKey(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("POSTGRES_DSN not set — skipping DB integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool: %v", err)
	}
	defer pool.Close()

	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 root: %v", err)
	}
	signerPub, signerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 signer: %v", err)
	}

	partitionID := int64(9104)
	logicalShardID := make([]byte, 32)
	scopeID := "scope-snap-revoked-issuer"
	rootEpoch := int64(1)
	rootType := "ROOT"
	rootKeyID := prd04KeyID(rootType, scopeID, rootEpoch, rootPub)
	signerEpoch := int64(1)
	signerType := "CLUSTER"
	signerKeyID := prd04KeyID(signerType, scopeID, signerEpoch, signerPub)

	rootRec, err := signedKeyRecord(rootPriv, keyRecordInput{
		KeyID:                  rootKeyID,
		KeyType:                rootType,
		ScopeID:                scopeID,
		AuthorityScope:         "cluster",
		KeyEpoch:               rootEpoch,
		PublicKeyHex:           hex.EncodeToString(rootPub),
		AllowedSigningContexts: []string{"key_record_v1", "trust_snapshot_v1"},
		IssuerKeyID:            rootKeyID,
		Status:                 "REVOKED",
		SigningContext:         "key_record_v1",
	})
	if err != nil {
		t.Fatalf("root key record: %v", err)
	}
	signerRec, err := signedKeyRecord(rootPriv, keyRecordInput{
		KeyID:                  signerKeyID,
		KeyType:                signerType,
		ScopeID:                scopeID,
		AuthorityScope:         "cluster",
		KeyEpoch:               signerEpoch,
		PublicKeyHex:           hex.EncodeToString(signerPub),
		AllowedSigningContexts: []string{BatchCommitSigningContext, "config_snapshot_v1"},
		IssuerKeyID:            rootKeyID,
		Status:                 "ACTIVE",
		SigningContext:         "key_record_v1",
	})
	if err != nil {
		t.Fatalf("signer key record: %v", err)
	}

	trustText, trustPH, trustSig, err := signedTrustSnapshot(rootPriv, rootKeyID, rootEpoch, scopeID, []string{rootRec, signerRec})
	if err != nil {
		t.Fatalf("trust snapshot sign: %v", err)
	}
	chaosText, chaosPH, chaosSig, err := signedChaosValidationMatrixSnapshot(signerPriv, signerKeyID, signerEpoch, "snap-revoked-issuer")
	if err != nil {
		t.Fatalf("chaos snapshot sign: %v", err)
	}

	exec := sha256.Sum256(append(chaosPH[:], trustPH[:]...))
	recPayload := []byte("x")
	recPH := sha256.Sum256(recPayload)
	recordID := sha256.Sum256([]byte("record-snap-revoked-issuer"))

	opts := CommitOptions{
		PartitionID:          partitionID,
		PartitionEpoch:       0,
		ExecutionContextHash: exec,
		AuthoritySnapshots: []SnapshotUpsert{
			{
				Type:                 "CONFIG",
				ID:                   "chaos_validation_matrix",
				Version:              "chaos_validation_matrix_v1",
				CanonicalPayloadText: chaosText,
				PayloadHash:          chaosPH,
				Signature:            chaosSig,
			},
			{
				Type:                 "CONFIG",
				ID:                   "trust_snapshot",
				Version:              "v1",
				CanonicalPayloadText: trustText,
				PayloadHash:          trustPH,
				Signature:            trustSig,
			},
		},
		Records: []RecordDraft{{
			RecordType:            "DECISION",
			RecordVersion:         "v1",
			StageOrder:            3,
			RecordID:              recordID[:],
			LogicalShardID:        logicalShardID,
			CausalParentRefsText:  "{}",
			CanonicalPayloadBytes: recPayload,
			CanonicalPayloadHash:  recPH,
		}},
		PrivateKey: signerPriv,
		KeyID:      signerKeyID,
		KeyEpoch:   1,
	}
	if err := CommitPartitionBatch(ctx, pool, opts); err != nil {
		t.Fatalf("commit: %v", err)
	}
	var batchSeq int64
	if err := pool.QueryRow(ctx, `SELECT MAX(batch_commit_seq) FROM batch_commit_records WHERE partition_id = $1`, partitionID).Scan(&batchSeq); err != nil {
		t.Fatalf("batch seq: %v", err)
	}
	if err := VerifyBoundAuthoritySnapshots(ctx, pool, partitionID, batchSeq); err == nil {
		t.Fatalf("expected failure")
	}
}

func TestVerifyBoundAuthoritySnapshots_FailsOnMalformedAuthoritySnapshotPayload(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("POSTGRES_DSN not set — skipping DB integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool: %v", err)
	}
	defer pool.Close()

	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 root: %v", err)
	}

	partitionID := int64(9105)
	logicalShardID := make([]byte, 32)
	scopeID := "scope-snap-malformed"
	rootEpoch := int64(1)
	rootType := "ROOT"
	rootKeyID := prd04KeyID(rootType, scopeID, rootEpoch, rootPub)

	rootRec, err := signedKeyRecord(rootPriv, keyRecordInput{
		KeyID:                  rootKeyID,
		KeyType:                rootType,
		ScopeID:                scopeID,
		AuthorityScope:         "cluster",
		KeyEpoch:               rootEpoch,
		PublicKeyHex:           hex.EncodeToString(rootPub),
		AllowedSigningContexts: []string{"key_record_v1", "trust_snapshot_v1", "config_snapshot_v1"},
		IssuerKeyID:            rootKeyID,
		Status:                 "ACTIVE",
		SigningContext:         "key_record_v1",
	})
	if err != nil {
		t.Fatalf("root key record: %v", err)
	}
	trustText, trustPH, trustSig, err := signedTrustSnapshot(rootPriv, rootKeyID, rootEpoch, scopeID, []string{rootRec})
	if err != nil {
		t.Fatalf("trust snapshot sign: %v", err)
	}

	badPayload := "{"
	badPH := sha256.Sum256([]byte(badPayload))
	badSig := make([]byte, ed25519.SignatureSize)
	exec := sha256.Sum256(append(badPH[:], trustPH[:]...))

	recPayload := []byte("x")
	recPH := sha256.Sum256(recPayload)
	recordID := sha256.Sum256([]byte("record-snap-malformed"))

	opts := CommitOptions{
		PartitionID:          partitionID,
		PartitionEpoch:       0,
		ExecutionContextHash: exec,
		AuthoritySnapshots: []SnapshotUpsert{
			{
				Type:                 "CONFIG",
				ID:                   "chaos_validation_matrix",
				Version:              "chaos_validation_matrix_v1",
				CanonicalPayloadText: badPayload,
				PayloadHash:          badPH,
				Signature:            badSig,
			},
			{
				Type:                 "CONFIG",
				ID:                   "trust_snapshot",
				Version:              "v1",
				CanonicalPayloadText: trustText,
				PayloadHash:          trustPH,
				Signature:            trustSig,
			},
		},
		Records: []RecordDraft{{
			RecordType:            "DECISION",
			RecordVersion:         "v1",
			StageOrder:            3,
			RecordID:              recordID[:],
			LogicalShardID:        logicalShardID,
			CausalParentRefsText:  "{}",
			CanonicalPayloadBytes: recPayload,
			CanonicalPayloadHash:  recPH,
		}},
		PrivateKey: rootPriv,
		KeyID:      rootKeyID,
		KeyEpoch:   1,
	}
	if err := CommitPartitionBatch(ctx, pool, opts); err != nil {
		t.Fatalf("commit: %v", err)
	}
	var batchSeq int64
	if err := pool.QueryRow(ctx, `SELECT MAX(batch_commit_seq) FROM batch_commit_records WHERE partition_id = $1`, partitionID).Scan(&batchSeq); err != nil {
		t.Fatalf("batch seq: %v", err)
	}
	if err := VerifyBoundAuthoritySnapshots(ctx, pool, partitionID, batchSeq); err == nil {
		t.Fatalf("expected failure")
	}
}

func TestVerifyBoundAuthoritySnapshots_FailsOnNonCanonicalJSON(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("POSTGRES_DSN not set — skipping DB integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool: %v", err)
	}
	defer pool.Close()

	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 root: %v", err)
	}

	partitionID := int64(9110)
	logicalShardID := make([]byte, 32)
	scopeID := "scope-noncanonical"
	rootEpoch := int64(1)
	rootType := "ROOT"
	rootKeyID := prd04KeyID(rootType, scopeID, rootEpoch, rootPub)

	rootRec, err := signedKeyRecord(rootPriv, keyRecordInput{
		KeyID:                  rootKeyID,
		KeyType:                rootType,
		ScopeID:                scopeID,
		AuthorityScope:         "cluster",
		KeyEpoch:               rootEpoch,
		PublicKeyHex:           hex.EncodeToString(rootPub),
		AllowedSigningContexts: []string{"key_record_v1", "trust_snapshot_v1", "config_snapshot_v1"},
		IssuerKeyID:            rootKeyID,
		Status:                 "ACTIVE",
		SigningContext:         "key_record_v1",
	})
	if err != nil {
		t.Fatalf("root key record: %v", err)
	}
	trustText, trustPH, trustSig, err := signedTrustSnapshot(rootPriv, rootKeyID, rootEpoch, scopeID, []string{rootRec})
	if err != nil {
		t.Fatalf("trust snapshot sign: %v", err)
	}

	// Canonical bytes (from helper) and an intentionally non-canonical textual form (key order).
	chaosCanonicalText, chaosPH, chaosSig, err := signedChaosValidationMatrixSnapshot(rootPriv, rootKeyID, rootEpoch, "noncanonical")
	if err != nil {
		t.Fatalf("chaos snapshot sign: %v", err)
	}
	// Non-canonical equivalent JSON (reordered keys + whitespace).
	chaosNonCanonicalText := `{"authority":"noncanonical", "key_epoch":1, "key_id":"` + rootKeyID + `", "signing_context":"config_snapshot_v1"}`
	_ = chaosCanonicalText

	exec := sha256.Sum256(append(chaosPH[:], trustPH[:]...))
	recPayload := []byte("x")
	recPH := sha256.Sum256(recPayload)
	recordID := sha256.Sum256([]byte("record-noncanonical"))

	opts := CommitOptions{
		PartitionID:          partitionID,
		PartitionEpoch:       0,
		ExecutionContextHash: exec,
		AuthoritySnapshots: []SnapshotUpsert{
			{
				Type:                 "CONFIG",
				ID:                   "chaos_validation_matrix",
				Version:              "chaos_validation_matrix_v1",
				CanonicalPayloadText: chaosNonCanonicalText,
				PayloadHash:          chaosPH,  // matches canonical bytes, but stored text is non-canonical -> must fail
				Signature:            chaosSig, // matches canonical bytes, but stored text is non-canonical -> must fail
			},
			{
				Type:                 "CONFIG",
				ID:                   "trust_snapshot",
				Version:              "v1",
				CanonicalPayloadText: trustText,
				PayloadHash:          trustPH,
				Signature:            trustSig,
			},
		},
		Records: []RecordDraft{{
			RecordType:            "DECISION",
			RecordVersion:         "v1",
			StageOrder:            3,
			RecordID:              recordID[:],
			LogicalShardID:        logicalShardID,
			CausalParentRefsText:  "{}",
			CanonicalPayloadBytes: recPayload,
			CanonicalPayloadHash:  recPH,
		}},
		PrivateKey: rootPriv,
		KeyID:      rootKeyID,
		KeyEpoch:   1,
	}
	if err := CommitPartitionBatch(ctx, pool, opts); err != nil {
		t.Fatalf("commit: %v", err)
	}
	var batchSeq int64
	if err := pool.QueryRow(ctx, `SELECT MAX(batch_commit_seq) FROM batch_commit_records WHERE partition_id = $1`, partitionID).Scan(&batchSeq); err != nil {
		t.Fatalf("batch seq: %v", err)
	}
	if err := VerifyBoundAuthoritySnapshots(ctx, pool, partitionID, batchSeq); err == nil {
		t.Fatalf("expected failure")
	}
}

func TestVerifyBoundAuthoritySnapshots_FailsOnCanonicalizationInducedPayloadHashMismatch(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("POSTGRES_DSN not set — skipping DB integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool: %v", err)
	}
	defer pool.Close()

	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 root: %v", err)
	}

	partitionID := int64(9111)
	logicalShardID := make([]byte, 32)
	scopeID := "scope-canon-hash-mismatch"
	rootEpoch := int64(1)
	rootType := "ROOT"
	rootKeyID := prd04KeyID(rootType, scopeID, rootEpoch, rootPub)

	rootRec, err := signedKeyRecord(rootPriv, keyRecordInput{
		KeyID:                  rootKeyID,
		KeyType:                rootType,
		ScopeID:                scopeID,
		AuthorityScope:         "cluster",
		KeyEpoch:               rootEpoch,
		PublicKeyHex:           hex.EncodeToString(rootPub),
		AllowedSigningContexts: []string{"key_record_v1", "trust_snapshot_v1", "config_snapshot_v1"},
		IssuerKeyID:            rootKeyID,
		Status:                 "ACTIVE",
		SigningContext:         "key_record_v1",
	})
	if err != nil {
		t.Fatalf("root key record: %v", err)
	}
	trustText, trustPH, trustSig, err := signedTrustSnapshot(rootPriv, rootKeyID, rootEpoch, scopeID, []string{rootRec})
	if err != nil {
		t.Fatalf("trust snapshot sign: %v", err)
	}

	// Store non-canonical text and compute payload_hash/signature over the NON-canonical bytes.
	nonCanonical := `{"authority":"canon-hash-mismatch", "key_epoch":1, "key_id":"` + rootKeyID + `", "signing_context":"config_snapshot_v1"}`
	ph := sha256.Sum256([]byte(nonCanonical))
	sig := ed25519.Sign(rootPriv, append([]byte("config_snapshot_v1"), ph[:]...))

	// execution_context_hash uses the (incorrect) committed payload_hash bytes to remain internally consistent for commit.
	exec := sha256.Sum256(append(ph[:], trustPH[:]...))

	recPayload := []byte("x")
	recPH := sha256.Sum256(recPayload)
	recordID := sha256.Sum256([]byte("record-canon-hash-mismatch"))

	opts := CommitOptions{
		PartitionID:          partitionID,
		PartitionEpoch:       0,
		ExecutionContextHash: exec,
		AuthoritySnapshots: []SnapshotUpsert{
			{
				Type:                 "CONFIG",
				ID:                   "chaos_validation_matrix",
				Version:              "chaos_validation_matrix_v1",
				CanonicalPayloadText: nonCanonical,
				PayloadHash:          ph,
				Signature:            sig,
			},
			{
				Type:                 "CONFIG",
				ID:                   "trust_snapshot",
				Version:              "v1",
				CanonicalPayloadText: trustText,
				PayloadHash:          trustPH,
				Signature:            trustSig,
			},
		},
		Records: []RecordDraft{{
			RecordType:            "DECISION",
			RecordVersion:         "v1",
			StageOrder:            3,
			RecordID:              recordID[:],
			LogicalShardID:        logicalShardID,
			CausalParentRefsText:  "{}",
			CanonicalPayloadBytes: recPayload,
			CanonicalPayloadHash:  recPH,
		}},
		PrivateKey: rootPriv,
		KeyID:      rootKeyID,
		KeyEpoch:   1,
	}
	if err := CommitPartitionBatch(ctx, pool, opts); err != nil {
		t.Fatalf("commit: %v", err)
	}
	var batchSeq int64
	if err := pool.QueryRow(ctx, `SELECT MAX(batch_commit_seq) FROM batch_commit_records WHERE partition_id = $1`, partitionID).Scan(&batchSeq); err != nil {
		t.Fatalf("batch seq: %v", err)
	}
	if err := VerifyBoundAuthoritySnapshots(ctx, pool, partitionID, batchSeq); err == nil {
		t.Fatalf("expected failure")
	}
}

func TestVerifyBoundAuthoritySnapshots_FailsOnInvalidSigningContextNotAllowed(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("POSTGRES_DSN not set — skipping DB integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool: %v", err)
	}
	defer pool.Close()

	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 root: %v", err)
	}
	signerPub, signerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 signer: %v", err)
	}

	partitionID := int64(9106)
	logicalShardID := make([]byte, 32)
	scopeID := "scope-snap-bad-context"
	rootEpoch := int64(1)
	rootType := "ROOT"
	rootKeyID := prd04KeyID(rootType, scopeID, rootEpoch, rootPub)
	signerEpoch := int64(1)
	signerType := "CLUSTER"
	signerKeyID := prd04KeyID(signerType, scopeID, signerEpoch, signerPub)

	rootRec, err := signedKeyRecord(rootPriv, keyRecordInput{
		KeyID:                  rootKeyID,
		KeyType:                rootType,
		ScopeID:                scopeID,
		AuthorityScope:         "cluster",
		KeyEpoch:               rootEpoch,
		PublicKeyHex:           hex.EncodeToString(rootPub),
		AllowedSigningContexts: []string{"key_record_v1", "trust_snapshot_v1"},
		IssuerKeyID:            rootKeyID,
		Status:                 "ACTIVE",
		SigningContext:         "key_record_v1",
	})
	if err != nil {
		t.Fatalf("root key record: %v", err)
	}
	signerRec, err := signedKeyRecord(rootPriv, keyRecordInput{
		KeyID:                  signerKeyID,
		KeyType:                signerType,
		ScopeID:                scopeID,
		AuthorityScope:         "cluster",
		KeyEpoch:               signerEpoch,
		PublicKeyHex:           hex.EncodeToString(signerPub),
		AllowedSigningContexts: []string{BatchCommitSigningContext}, // does NOT include "config_snapshot_v1"
		IssuerKeyID:            rootKeyID,
		Status:                 "ACTIVE",
		SigningContext:         "key_record_v1",
	})
	if err != nil {
		t.Fatalf("signer key record: %v", err)
	}

	trustText, trustPH, trustSig, err := signedTrustSnapshot(rootPriv, rootKeyID, rootEpoch, scopeID, []string{rootRec, signerRec})
	if err != nil {
		t.Fatalf("trust snapshot sign: %v", err)
	}

	// Authority snapshot uses signing_context "config_snapshot_v1" but signer key does not allow it.
	chaosText, chaosPH, chaosSig, err := signedChaosValidationMatrixSnapshot(signerPriv, signerKeyID, signerEpoch, "snap-bad-context")
	if err != nil {
		t.Fatalf("chaos snapshot sign: %v", err)
	}

	exec := sha256.Sum256(append(chaosPH[:], trustPH[:]...))
	recPayload := []byte("x")
	recPH := sha256.Sum256(recPayload)
	recordID := sha256.Sum256([]byte("record-snap-bad-context"))

	opts := CommitOptions{
		PartitionID:          partitionID,
		PartitionEpoch:       0,
		ExecutionContextHash: exec,
		AuthoritySnapshots: []SnapshotUpsert{
			{
				Type:                 "CONFIG",
				ID:                   "chaos_validation_matrix",
				Version:              "chaos_validation_matrix_v1",
				CanonicalPayloadText: chaosText,
				PayloadHash:          chaosPH,
				Signature:            chaosSig,
			},
			{
				Type:                 "CONFIG",
				ID:                   "trust_snapshot",
				Version:              "v1",
				CanonicalPayloadText: trustText,
				PayloadHash:          trustPH,
				Signature:            trustSig,
			},
		},
		Records: []RecordDraft{{
			RecordType:            "DECISION",
			RecordVersion:         "v1",
			StageOrder:            3,
			RecordID:              recordID[:],
			LogicalShardID:        logicalShardID,
			CausalParentRefsText:  "{}",
			CanonicalPayloadBytes: recPayload,
			CanonicalPayloadHash:  recPH,
		}},
		PrivateKey: signerPriv,
		KeyID:      signerKeyID,
		KeyEpoch:   1,
	}
	if err := CommitPartitionBatch(ctx, pool, opts); err != nil {
		t.Fatalf("commit: %v", err)
	}
	var batchSeq int64
	if err := pool.QueryRow(ctx, `SELECT MAX(batch_commit_seq) FROM batch_commit_records WHERE partition_id = $1`, partitionID).Scan(&batchSeq); err != nil {
		t.Fatalf("batch seq: %v", err)
	}
	if err := VerifyBoundAuthoritySnapshots(ctx, pool, partitionID, batchSeq); err == nil {
		t.Fatalf("expected failure")
	}
}

func TestVerifyBoundAuthoritySnapshots_FailsOnAmbiguousTrustSnapshotDuplicateKeyID(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("POSTGRES_DSN not set — skipping DB integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool: %v", err)
	}
	defer pool.Close()

	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 root: %v", err)
	}

	partitionID := int64(9107)
	logicalShardID := make([]byte, 32)
	scopeID := "scope-trust-dup-key"
	rootEpoch := int64(1)
	rootType := "ROOT"
	rootKeyID := prd04KeyID(rootType, scopeID, rootEpoch, rootPub)

	// Create a valid root key record, then duplicate it (same key_id) to force ambiguity.
	rootRec, err := signedKeyRecord(rootPriv, keyRecordInput{
		KeyID:                  rootKeyID,
		KeyType:                rootType,
		ScopeID:                scopeID,
		AuthorityScope:         "cluster",
		KeyEpoch:               rootEpoch,
		PublicKeyHex:           hex.EncodeToString(rootPub),
		AllowedSigningContexts: []string{"key_record_v1", "trust_snapshot_v1", "config_snapshot_v1"},
		IssuerKeyID:            rootKeyID,
		Status:                 "ACTIVE",
		SigningContext:         "key_record_v1",
	})
	if err != nil {
		t.Fatalf("root key record: %v", err)
	}

	trustText, trustPH, trustSig, err := signedTrustSnapshot(rootPriv, rootKeyID, rootEpoch, scopeID, []string{rootRec, rootRec})
	if err != nil {
		t.Fatalf("trust snapshot sign: %v", err)
	}

	chaosText, chaosPH, chaosSig, err := signedChaosValidationMatrixSnapshot(rootPriv, rootKeyID, rootEpoch, "snap-trust-dup-key")
	if err != nil {
		t.Fatalf("chaos snapshot sign: %v", err)
	}

	exec := sha256.Sum256(append(chaosPH[:], trustPH[:]...))
	recPayload := []byte("x")
	recPH := sha256.Sum256(recPayload)
	recordID := sha256.Sum256([]byte("record-trust-dup-key"))

	opts := CommitOptions{
		PartitionID:          partitionID,
		PartitionEpoch:       0,
		ExecutionContextHash: exec,
		AuthoritySnapshots: []SnapshotUpsert{
			{
				Type:                 "CONFIG",
				ID:                   "chaos_validation_matrix",
				Version:              "chaos_validation_matrix_v1",
				CanonicalPayloadText: chaosText,
				PayloadHash:          chaosPH,
				Signature:            chaosSig,
			},
			{
				Type:                 "CONFIG",
				ID:                   "trust_snapshot",
				Version:              "v1",
				CanonicalPayloadText: trustText,
				PayloadHash:          trustPH,
				Signature:            trustSig,
			},
		},
		Records: []RecordDraft{{
			RecordType:            "DECISION",
			RecordVersion:         "v1",
			StageOrder:            3,
			RecordID:              recordID[:],
			LogicalShardID:        logicalShardID,
			CausalParentRefsText:  "{}",
			CanonicalPayloadBytes: recPayload,
			CanonicalPayloadHash:  recPH,
		}},
		PrivateKey: rootPriv,
		KeyID:      rootKeyID,
		KeyEpoch:   1,
	}
	if err := CommitPartitionBatch(ctx, pool, opts); err != nil {
		t.Fatalf("commit: %v", err)
	}
	var batchSeq int64
	if err := pool.QueryRow(ctx, `SELECT MAX(batch_commit_seq) FROM batch_commit_records WHERE partition_id = $1`, partitionID).Scan(&batchSeq); err != nil {
		t.Fatalf("batch seq: %v", err)
	}
	if err := VerifyBoundAuthoritySnapshots(ctx, pool, partitionID, batchSeq); err == nil {
		t.Fatalf("expected failure")
	}
}

func prd04KeyID(keyType, scopeID string, keyEpoch int64, pub ed25519.PublicKey) string {
	h := sha256.New()
	h.Write([]byte(keyType))
	h.Write([]byte(scopeID))
	var be [8]byte
	binary.BigEndian.PutUint64(be[:], uint64(keyEpoch))
	h.Write(be[:])
	h.Write(pub)
	return hex.EncodeToString(h.Sum(nil))
}

type keyRecordInput struct {
	KeyID                  string
	KeyType                string
	ScopeID                string
	AuthorityScope         string
	KeyEpoch               int64
	PublicKeyHex           string
	AllowedSigningContexts []string
	IssuerKeyID            string
	Status                 string
	SigningContext         string
}

func signedKeyRecord(issuerPriv ed25519.PrivateKey, in keyRecordInput) (string, error) {
	rec := keyRecord{
		KeyID:                 in.KeyID,
		KeyType:               in.KeyType,
		ScopeID:               in.ScopeID,
		AuthorityScope:        in.AuthorityScope,
		KeyEpoch:              in.KeyEpoch,
		PublicKey:             in.PublicKeyHex,
		AllowedSigningContexts: append([]string(nil), in.AllowedSigningContexts...),
		IssuerKeyID:           in.IssuerKeyID,
		Status:                in.Status,
		SigningContext:        in.SigningContext,
		SignatureHex:          "00", // placeholder
	}
	payload, err := keyRecordCanonicalPayloadBytes(rec)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(payload)
	signingInput := append([]byte(rec.SigningContext), sum[:]...)
	sig := ed25519.Sign(issuerPriv, signingInput)
	rec.SignatureHex = hex.EncodeToString(sig)
	b, err := JCSCanonicalJSONBytes(map[string]any{
		"allowed_signing_contexts": func() []any { a := make([]any, 0, len(rec.AllowedSigningContexts)); for _, s := range rec.AllowedSigningContexts { a = append(a, s) }; return a }(),
		"authority_scope":          rec.AuthorityScope,
		"issuer_key_id":            rec.IssuerKeyID,
		"key_epoch":                rec.KeyEpoch,
		"key_id":                   rec.KeyID,
		"key_type":                 rec.KeyType,
		"public_key":               rec.PublicKey,
		"scope_id":                 rec.ScopeID,
		"signing_context":          rec.SigningContext,
		"signature":                rec.SignatureHex,
		"status":                   rec.Status,
	})
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func trustSnapshotPayload(scopeID string, keyRecordJSONObjects []string) (string, error) {
	recs := make([]any, 0, len(keyRecordJSONObjects))
	for _, raw := range keyRecordJSONObjects {
		m, err := parseCanonicalJSONObject(raw)
		if err != nil {
			return "", err
		}
		recs = append(recs, m)
	}
	b, err := JCSCanonicalJSONBytes(map[string]any{
		"key_records":          recs,
		"verification_scope_id": scopeID,
	})
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func signedAuthoritySnapshot(priv ed25519.PrivateKey, canonicalObj map[string]any) (string, [32]byte, []byte, error) {
	b, err := JCSCanonicalJSONBytes(canonicalObj)
	if err != nil {
		return "", [32]byte{}, nil, err
	}
	text := string(b)
	ph := sha256.Sum256([]byte(text))
	sc, _ := canonicalObj["signing_context"].(string)
	if strings.TrimSpace(sc) == "" {
		return "", [32]byte{}, nil, errors.New("missing signing_context")
	}
	signingInput := append([]byte(sc), ph[:]...)
	sig := ed25519.Sign(priv, signingInput)
	return text, ph, sig, nil
}

func signedChaosValidationMatrixSnapshot(priv ed25519.PrivateKey, signerKeyID string, signerEpoch int64, authority string) (string, [32]byte, []byte, error) {
	return signedAuthoritySnapshot(priv, map[string]any{
		"signing_context": "config_snapshot_v1",
		"key_id":          signerKeyID,
		"key_epoch":       signerEpoch,
		"authority":       authority,
	})
}

func signedTrustSnapshot(priv ed25519.PrivateKey, signerKeyID string, signerEpoch int64, scopeID string, keyRecordJSONObjects []string) (string, [32]byte, []byte, error) {
	return signedAuthoritySnapshot(priv, map[string]any{
		"signing_context":       "trust_snapshot_v1",
		"key_id":                signerKeyID,
		"key_epoch":             signerEpoch,
		"verification_scope_id": scopeID,
		"key_records":           mustJSONArray(keyRecordJSONObjects),
	})
}

func mustJSONArray(rawObjs []string) []any {
	out := make([]any, 0, len(rawObjs))
	for _, r := range rawObjs {
		m, err := parseCanonicalJSONObject(r)
		if err != nil {
			panic(err)
		}
		out = append(out, m)
	}
	return out
}

func parseCanonicalJSONObject(raw string) (map[string]any, error) {
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	normalized, err := normalizeJSONNumbers(m)
	if err != nil {
		return nil, err
	}
	out, ok := normalized.(map[string]any)
	if !ok {
		return nil, errors.New("object decode failed")
	}
	return out, nil
}

func normalizeJSONNumbers(v any) (any, error) {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			nv, err := normalizeJSONNumbers(val)
			if err != nil {
				return nil, err
			}
			out[k] = nv
		}
		return out, nil
	case []any:
		out := make([]any, 0, len(t))
		for _, val := range t {
			nv, err := normalizeJSONNumbers(val)
			if err != nil {
				return nil, err
			}
			out = append(out, nv)
		}
		return out, nil
	case json.Number:
		if i, err := strconv.ParseInt(t.String(), 10, 64); err == nil {
			return i, nil
		}
		// Keep non-integer numeric values as strings so JCS can still canonicalize deterministically.
		return t.String(), nil
	default:
		return v, nil
	}
}

func TestVerifyCommittedBatch_FailsOnExecutionContextMismatchInRange(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("POSTGRES_DSN not set — skipping DB integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool: %v", err)
	}
	defer pool.Close()

	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}

	partitionID := int64(9002)
	logicalShardID := make([]byte, 32)

	rootEpoch := int64(1)
	rootType := "ROOT"
	scopeID := "scope-2"
	keyID := prd04KeyID(rootType, scopeID, rootEpoch, rootPub)
	rootRec, err := signedKeyRecord(rootPriv, keyRecordInput{
		KeyID:                  keyID,
		KeyType:                rootType,
		ScopeID:                scopeID,
		AuthorityScope:         "cluster",
		KeyEpoch:               rootEpoch,
		PublicKeyHex:           hex.EncodeToString(rootPub),
		AllowedSigningContexts: []string{BatchCommitSigningContext, "config_snapshot_v1", "trust_snapshot_v1", "key_record_v1"},
		IssuerKeyID:            keyID,
		Status:                 "ACTIVE",
		SigningContext:         "key_record_v1",
	})
	if err != nil {
		t.Fatalf("root key record: %v", err)
	}
	trustText, trustPH, trustSig, err := signedTrustSnapshot(rootPriv, keyID, rootEpoch, scopeID, []string{rootRec})
	if err != nil {
		t.Fatalf("trust snapshot sign: %v", err)
	}
	chaosText, chaosPH, chaosSig, err := signedChaosValidationMatrixSnapshot(rootPriv, keyID, rootEpoch, "batch_verify_mismatch")
	if err != nil {
		t.Fatalf("chaos snapshot sign: %v", err)
	}
	chaosVersion := fmt.Sprintf("chaos_validation_matrix_v1_%d", time.Now().UnixNano())
	trustVersion := fmt.Sprintf("trust_snapshot_v1_%d", time.Now().UnixNano())
	exec := sha256.Sum256(append(chaosPH[:], trustPH[:]...))

	recPayload := []byte("x")
	recPH := sha256.Sum256(recPayload)
	recordID := sha256.Sum256([]byte(fmt.Sprintf("record-1-%d", time.Now().UnixNano())))

	opts := CommitOptions{
		PartitionID:          partitionID,
		PartitionEpoch:       0,
		ExecutionContextHash: exec,
		AuthoritySnapshots: []SnapshotUpsert{
			{
				Type:                 "CONFIG",
				ID:                   "chaos_validation_matrix",
				Version:              chaosVersion,
				CanonicalPayloadText: chaosText,
				PayloadHash:          chaosPH,
				Signature:            chaosSig,
			},
			{
				Type:                 "CONFIG",
				ID:                   "trust_snapshot",
				Version:              trustVersion,
				CanonicalPayloadText: trustText,
				PayloadHash:          trustPH,
				Signature:            trustSig,
			},
		},
		Records: []RecordDraft{{
			RecordType:            "DECISION",
			RecordVersion:         "v1",
			StageOrder:            3,
			RecordID:              recordID[:],
			LogicalShardID:        logicalShardID,
			CausalParentRefsText:  "{}",
			CanonicalPayloadBytes: recPayload,
			CanonicalPayloadHash:  recPH,
		}},
		PrivateKey: rootPriv,
		KeyID:      keyID,
		KeyEpoch:   1,
	}

	if err := CommitPartitionBatch(ctx, pool, opts); err != nil {
		t.Fatalf("commit: %v", err)
	}

	var batchSeq int64
	var firstSeq int64
	if err := pool.QueryRow(ctx, `
SELECT batch_commit_seq, first_partition_record_seq
FROM batch_commit_records
WHERE partition_id = $1
ORDER BY batch_commit_seq DESC
LIMIT 1`, partitionID).Scan(&batchSeq, &firstSeq); err != nil {
		t.Fatalf("load batch: %v", err)
	}

	// Corrupt execution_context_hash in-range to ensure uniformity check fails (fail-closed).
	corrupt := make([]byte, 32)
	for i := range corrupt {
		corrupt[i] = 0xFF
	}
	if _, err := pool.Exec(ctx, `
UPDATE partition_records
SET execution_context_hash = $1
WHERE partition_id = $2 AND partition_record_seq = $3`, corrupt, partitionID, firstSeq); err != nil {
		t.Fatalf("corrupt update failed: %v", err)
	}

	if _, err := VerifyCommittedBatch(ctx, pool, partitionID, batchSeq); err == nil {
		t.Fatalf("expected verify failure")
	}
}

func TestVerifyCommittedBatch_SucceedsWithCanonicalTrustSnapshot(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("POSTGRES_DSN not set — skipping DB integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool: %v", err)
	}
	defer pool.Close()

	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}

	partitionID := int64(9301)
	logicalShardID := make([]byte, 32)

	rootEpoch := int64(1)
	rootType := "ROOT"
	scopeID := "scope-trust-ok"
	keyID := prd04KeyID(rootType, scopeID, rootEpoch, rootPub)
	rootRec, err := signedKeyRecord(rootPriv, keyRecordInput{
		KeyID:                  keyID,
		KeyType:                rootType,
		ScopeID:                scopeID,
		AuthorityScope:         "cluster",
		KeyEpoch:               rootEpoch,
		PublicKeyHex:           hex.EncodeToString(rootPub),
		AllowedSigningContexts: []string{BatchCommitSigningContext, "config_snapshot_v1", "trust_snapshot_v1", "key_record_v1"},
		IssuerKeyID:            keyID,
		Status:                 "ACTIVE",
		SigningContext:         "key_record_v1",
	})
	if err != nil {
		t.Fatalf("root key record: %v", err)
	}

	trustText, trustPH, trustSig, err := signedTrustSnapshot(rootPriv, keyID, rootEpoch, scopeID, []string{rootRec})
	if err != nil {
		t.Fatalf("trust snapshot sign: %v", err)
	}
	chaosText, chaosPH, chaosSig, err := signedChaosValidationMatrixSnapshot(rootPriv, keyID, rootEpoch, "batch_verify_ok")
	if err != nil {
		t.Fatalf("chaos snapshot sign: %v", err)
	}
	exec := sha256.Sum256(append(chaosPH[:], trustPH[:]...))

	recPayload := []byte("ok")
	recPH := sha256.Sum256(recPayload)
	recordID := sha256.Sum256([]byte("record-ok"))

	opts := CommitOptions{
		PartitionID:          partitionID,
		PartitionEpoch:       0,
		ExecutionContextHash: exec,
		AuthoritySnapshots: []SnapshotUpsert{
			{
				Type:                 "CONFIG",
				ID:                   "chaos_validation_matrix",
				Version:              "chaos_validation_matrix_v1",
				CanonicalPayloadText: chaosText,
				PayloadHash:          chaosPH,
				Signature:            chaosSig,
			},
			{
				Type:                 "CONFIG",
				ID:                   "trust_snapshot",
				Version:              "v1",
				CanonicalPayloadText: trustText,
				PayloadHash:          trustPH,
				Signature:            trustSig,
			},
		},
		Records: []RecordDraft{{
			RecordType:            "DECISION",
			RecordVersion:         "v1",
			StageOrder:            3,
			RecordID:              recordID[:],
			LogicalShardID:        logicalShardID,
			CausalParentRefsText:  "{}",
			CanonicalPayloadBytes: recPayload,
			CanonicalPayloadHash:  recPH,
		}},
		PrivateKey: rootPriv,
		KeyID:      keyID,
		KeyEpoch:   1,
	}
	if err := CommitPartitionBatch(ctx, pool, opts); err != nil {
		t.Fatalf("commit: %v", err)
	}

	var batchSeq int64
	if err := pool.QueryRow(ctx, `
SELECT batch_commit_seq
FROM batch_commit_records
WHERE partition_id = $1
ORDER BY batch_commit_seq DESC
LIMIT 1`, partitionID).Scan(&batchSeq); err != nil {
		t.Fatalf("load batch: %v", err)
	}

	if _, err := VerifyCommittedBatch(ctx, pool, partitionID, batchSeq); err != nil {
		t.Fatalf("expected verify success, got %v", err)
	}
}

func TestVerifyCommittedBatch_FailsOnNonCanonicalTrustSnapshotEvenIfHashAndSigMatchStoredBytes(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("POSTGRES_DSN not set — skipping DB integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool: %v", err)
	}
	defer pool.Close()

	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}

	partitionID := int64(9302)
	logicalShardID := make([]byte, 32)

	rootEpoch := int64(1)
	rootType := "ROOT"
	scopeID := "scope-trust-noncanonical"
	keyID := prd04KeyID(rootType, scopeID, rootEpoch, rootPub)
	rootRec, err := signedKeyRecord(rootPriv, keyRecordInput{
		KeyID:                  keyID,
		KeyType:                rootType,
		ScopeID:                scopeID,
		AuthorityScope:         "cluster",
		KeyEpoch:               rootEpoch,
		PublicKeyHex:           hex.EncodeToString(rootPub),
		AllowedSigningContexts: []string{BatchCommitSigningContext, "config_snapshot_v1", "trust_snapshot_v1", "key_record_v1"},
		IssuerKeyID:            keyID,
		Status:                 "ACTIVE",
		SigningContext:         "key_record_v1",
	})
	if err != nil {
		t.Fatalf("root key record: %v", err)
	}

	trustText, trustPH, trustSig, err := signedTrustSnapshot(rootPriv, keyID, rootEpoch, scopeID, []string{rootRec})
	if err != nil {
		t.Fatalf("trust snapshot sign: %v", err)
	}
	chaosText, chaosPH, chaosSig, err := signedChaosValidationMatrixSnapshot(rootPriv, keyID, rootEpoch, "batch_verify_noncanonical")
	if err != nil {
		t.Fatalf("chaos snapshot sign: %v", err)
	}
	exec := sha256.Sum256(append(chaosPH[:], trustPH[:]...))

	recPayload := []byte("x")
	recPH := sha256.Sum256(recPayload)
	recordID := sha256.Sum256([]byte("record-noncanonical"))

	opts := CommitOptions{
		PartitionID:          partitionID,
		PartitionEpoch:       0,
		ExecutionContextHash: exec,
		AuthoritySnapshots: []SnapshotUpsert{
			{
				Type:                 "CONFIG",
				ID:                   "chaos_validation_matrix",
				Version:              "chaos_validation_matrix_v1",
				CanonicalPayloadText: chaosText,
				PayloadHash:          chaosPH,
				Signature:            chaosSig,
			},
			{
				Type:                 "CONFIG",
				ID:                   "trust_snapshot",
				Version:              "v1",
				CanonicalPayloadText: trustText,
				PayloadHash:          trustPH,
				Signature:            trustSig,
			},
		},
		Records: []RecordDraft{{
			RecordType:            "DECISION",
			RecordVersion:         "v1",
			StageOrder:            3,
			RecordID:              recordID[:],
			LogicalShardID:        logicalShardID,
			CausalParentRefsText:  "{}",
			CanonicalPayloadBytes: recPayload,
			CanonicalPayloadHash:  recPH,
		}},
		PrivateKey: rootPriv,
		KeyID:      keyID,
		KeyEpoch:   1,
	}
	if err := CommitPartitionBatch(ctx, pool, opts); err != nil {
		t.Fatalf("commit: %v", err)
	}

	// Mutate the committed trust_snapshot payload to a non-canonical form, but keep payload_hash and signature
	// consistent with the stored (non-canonical) bytes. Verification must still fail closed.
	nonCanonical := " \n" + trustText + "\n"
	phStored := sha256.Sum256([]byte(nonCanonical))
	signingInput := append([]byte("trust_snapshot_v1"), phStored[:]...)
	sigStored := ed25519.Sign(rootPriv, signingInput)

	if _, err := pool.Exec(ctx, `
UPDATE authority_snapshots
SET canonical_payload_text = $1, payload_hash = $2, signature = $3
WHERE authority_type = 'CONFIG' AND authority_id = 'trust_snapshot' AND authority_version = 'v1'`,
		nonCanonical, phStored[:], sigStored,
	); err != nil {
		t.Fatalf("update trust_snapshot: %v", err)
	}

	var batchSeq int64
	if err := pool.QueryRow(ctx, `
SELECT batch_commit_seq
FROM batch_commit_records
WHERE partition_id = $1
ORDER BY batch_commit_seq DESC
LIMIT 1`, partitionID).Scan(&batchSeq); err != nil {
		t.Fatalf("load batch: %v", err)
	}

	if _, err := VerifyCommittedBatch(ctx, pool, partitionID, batchSeq); err == nil {
		t.Fatalf("expected verify failure")
	} else {
		// Verify-time committed-row canonicalization violation must be Type 3 (PRD-01) and fail closed.
		if f, ok := FailureAs(err); !ok {
			t.Fatalf("expected typed Failure, got %T: %v", err, err)
		} else {
			if f.Type != FailureType3IntegrityFailure || f.Code != "CANONICALIZATION_VIOLATION" {
				t.Fatalf("unexpected failure classification: %+v", f)
			}
		}
	}
}

func TestVerifyCommittedBatch_FailsOnTrustSnapshotPayloadHashMismatchOnCanonicalBytes(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("POSTGRES_DSN not set — skipping DB integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool: %v", err)
	}
	defer pool.Close()

	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}

	partitionID := int64(9303)
	logicalShardID := make([]byte, 32)

	rootEpoch := int64(1)
	rootType := "ROOT"
	scopeID := "scope-trust-ph-mismatch"
	keyID := prd04KeyID(rootType, scopeID, rootEpoch, rootPub)
	rootRec, err := signedKeyRecord(rootPriv, keyRecordInput{
		KeyID:                  keyID,
		KeyType:                rootType,
		ScopeID:                scopeID,
		AuthorityScope:         "cluster",
		KeyEpoch:               rootEpoch,
		PublicKeyHex:           hex.EncodeToString(rootPub),
		AllowedSigningContexts: []string{BatchCommitSigningContext, "config_snapshot_v1", "trust_snapshot_v1", "key_record_v1"},
		IssuerKeyID:            keyID,
		Status:                 "ACTIVE",
		SigningContext:         "key_record_v1",
	})
	if err != nil {
		t.Fatalf("root key record: %v", err)
	}

	trustText, trustPH, trustSig, err := signedTrustSnapshot(rootPriv, keyID, rootEpoch, scopeID, []string{rootRec})
	if err != nil {
		t.Fatalf("trust snapshot sign: %v", err)
	}
	chaosText, chaosPH, chaosSig, err := signedChaosValidationMatrixSnapshot(rootPriv, keyID, rootEpoch, "batch_verify_ph_mismatch")
	if err != nil {
		t.Fatalf("chaos snapshot sign: %v", err)
	}
	exec := sha256.Sum256(append(chaosPH[:], trustPH[:]...))

	recPayload := []byte("x")
	recPH := sha256.Sum256(recPayload)
	recordID := sha256.Sum256([]byte("record-ph-mismatch"))

	opts := CommitOptions{
		PartitionID:          partitionID,
		PartitionEpoch:       0,
		ExecutionContextHash: exec,
		AuthoritySnapshots: []SnapshotUpsert{
			{
				Type:                 "CONFIG",
				ID:                   "chaos_validation_matrix",
				Version:              "chaos_validation_matrix_v1",
				CanonicalPayloadText: chaosText,
				PayloadHash:          chaosPH,
				Signature:            chaosSig,
			},
			{
				Type:                 "CONFIG",
				ID:                   "trust_snapshot",
				Version:              "v1",
				CanonicalPayloadText: trustText,
				PayloadHash:          trustPH,
				Signature:            trustSig,
			},
		},
		Records: []RecordDraft{{
			RecordType:            "DECISION",
			RecordVersion:         "v1",
			StageOrder:            3,
			RecordID:              recordID[:],
			LogicalShardID:        logicalShardID,
			CausalParentRefsText:  "{}",
			CanonicalPayloadBytes: recPayload,
			CanonicalPayloadHash:  recPH,
		}},
		PrivateKey: rootPriv,
		KeyID:      keyID,
		KeyEpoch:   1,
	}
	if err := CommitPartitionBatch(ctx, pool, opts); err != nil {
		t.Fatalf("commit: %v", err)
	}

	// Corrupt stored payload_hash while leaving canonical_payload_text unchanged.
	bad := make([]byte, 32)
	for i := range bad {
		bad[i] = 0xAA
	}
	if _, err := pool.Exec(ctx, `
UPDATE authority_snapshots
SET payload_hash = $1
WHERE authority_type = 'CONFIG' AND authority_id = 'trust_snapshot' AND authority_version = 'v1'`,
		bad,
	); err != nil {
		t.Fatalf("update trust_snapshot payload_hash: %v", err)
	}

	var batchSeq int64
	if err := pool.QueryRow(ctx, `
SELECT batch_commit_seq
FROM batch_commit_records
WHERE partition_id = $1
ORDER BY batch_commit_seq DESC
LIMIT 1`, partitionID).Scan(&batchSeq); err != nil {
		t.Fatalf("load batch: %v", err)
	}

	if _, err := VerifyCommittedBatch(ctx, pool, partitionID, batchSeq); err == nil {
		t.Fatalf("expected verify failure")
	}
}

func TestVerifyCommittedBatch_FailsOnTrustSnapshotSignatureMismatchDueToCanonicalizationDrift(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("POSTGRES_DSN not set — skipping DB integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool: %v", err)
	}
	defer pool.Close()

	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}

	partitionID := int64(9304)
	logicalShardID := make([]byte, 32)

	rootEpoch := int64(1)
	rootType := "ROOT"
	scopeID := "scope-trust-sig-drift"
	keyID := prd04KeyID(rootType, scopeID, rootEpoch, rootPub)
	rootRec, err := signedKeyRecord(rootPriv, keyRecordInput{
		KeyID:                  keyID,
		KeyType:                rootType,
		ScopeID:                scopeID,
		AuthorityScope:         "cluster",
		KeyEpoch:               rootEpoch,
		PublicKeyHex:           hex.EncodeToString(rootPub),
		AllowedSigningContexts: []string{BatchCommitSigningContext, "config_snapshot_v1", "trust_snapshot_v1", "key_record_v1"},
		IssuerKeyID:            keyID,
		Status:                 "ACTIVE",
		SigningContext:         "key_record_v1",
	})
	if err != nil {
		t.Fatalf("root key record: %v", err)
	}

	trustText, trustPH, trustSig, err := signedTrustSnapshot(rootPriv, keyID, rootEpoch, scopeID, []string{rootRec})
	if err != nil {
		t.Fatalf("trust snapshot sign: %v", err)
	}
	chaosText, chaosPH, chaosSig, err := signedChaosValidationMatrixSnapshot(rootPriv, keyID, rootEpoch, "batch_verify_sig_drift")
	if err != nil {
		t.Fatalf("chaos snapshot sign: %v", err)
	}
	exec := sha256.Sum256(append(chaosPH[:], trustPH[:]...))

	recPayload := []byte("x")
	recPH := sha256.Sum256(recPayload)
	recordID := sha256.Sum256([]byte("record-sig-drift"))

	opts := CommitOptions{
		PartitionID:          partitionID,
		PartitionEpoch:       0,
		ExecutionContextHash: exec,
		AuthoritySnapshots: []SnapshotUpsert{
			{
				Type:                 "CONFIG",
				ID:                   "chaos_validation_matrix",
				Version:              "chaos_validation_matrix_v1",
				CanonicalPayloadText: chaosText,
				PayloadHash:          chaosPH,
				Signature:            chaosSig,
			},
			{
				Type:                 "CONFIG",
				ID:                   "trust_snapshot",
				Version:              "v1",
				CanonicalPayloadText: trustText,
				PayloadHash:          trustPH,
				Signature:            trustSig,
			},
		},
		Records: []RecordDraft{{
			RecordType:            "DECISION",
			RecordVersion:         "v1",
			StageOrder:            3,
			RecordID:              recordID[:],
			LogicalShardID:        logicalShardID,
			CausalParentRefsText:  "{}",
			CanonicalPayloadBytes: recPayload,
			CanonicalPayloadHash:  recPH,
		}},
		PrivateKey: rootPriv,
		KeyID:      keyID,
		KeyEpoch:   1,
	}
	if err := CommitPartitionBatch(ctx, pool, opts); err != nil {
		t.Fatalf("commit: %v", err)
	}

	// Replace signature with one computed over a non-canonical byte representation (canonicalization drift).
	nonCanonical := " \n" + trustText + "\n"
	phNonCanonical := sha256.Sum256([]byte(nonCanonical))
	signingInput := append([]byte("trust_snapshot_v1"), phNonCanonical[:]...)
	sigDrift := ed25519.Sign(rootPriv, signingInput)

	if _, err := pool.Exec(ctx, `
UPDATE authority_snapshots
SET signature = $1
WHERE authority_type = 'CONFIG' AND authority_id = 'trust_snapshot' AND authority_version = 'v1'`,
		sigDrift,
	); err != nil {
		t.Fatalf("update trust_snapshot signature: %v", err)
	}

	var batchSeq int64
	if err := pool.QueryRow(ctx, `
SELECT batch_commit_seq
FROM batch_commit_records
WHERE partition_id = $1
ORDER BY batch_commit_seq DESC
LIMIT 1`, partitionID).Scan(&batchSeq); err != nil {
		t.Fatalf("load batch: %v", err)
	}

	if _, err := VerifyCommittedBatch(ctx, pool, partitionID, batchSeq); err == nil {
		t.Fatalf("expected verify failure")
	}
}

func TestCommitPartitionBatch_AcceptsCanonicalTrustSnapshotUpsert(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("POSTGRES_DSN not set — skipping DB integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool: %v", err)
	}
	defer pool.Close()

	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}

	partitionID := int64(9401)
	logicalShardID := make([]byte, 32)

	rootEpoch := int64(1)
	rootType := "ROOT"
	scopeID := "scope-upsert-ok"
	keyID := prd04KeyID(rootType, scopeID, rootEpoch, rootPub)
	rootRec, err := signedKeyRecord(rootPriv, keyRecordInput{
		KeyID:                  keyID,
		KeyType:                rootType,
		ScopeID:                scopeID,
		AuthorityScope:         "cluster",
		KeyEpoch:               rootEpoch,
		PublicKeyHex:           hex.EncodeToString(rootPub),
		AllowedSigningContexts: []string{BatchCommitSigningContext, "config_snapshot_v1", "trust_snapshot_v1", "key_record_v1"},
		IssuerKeyID:            keyID,
		Status:                 "ACTIVE",
		SigningContext:         "key_record_v1",
	})
	if err != nil {
		t.Fatalf("root key record: %v", err)
	}

	trustText, trustPH, trustSig, err := signedTrustSnapshot(rootPriv, keyID, rootEpoch, scopeID, []string{rootRec})
	if err != nil {
		t.Fatalf("trust snapshot sign: %v", err)
	}
	chaosText, chaosPH, chaosSig, err := signedChaosValidationMatrixSnapshot(rootPriv, keyID, rootEpoch, "commit_upsert_ok")
	if err != nil {
		t.Fatalf("chaos snapshot sign: %v", err)
	}
	exec := sha256.Sum256(append(chaosPH[:], trustPH[:]...))

	recPayload := []byte("ok")
	recPH := sha256.Sum256(recPayload)
	recordID := sha256.Sum256([]byte("record-upsert-ok"))

	opts := CommitOptions{
		PartitionID:          partitionID,
		PartitionEpoch:       0,
		ExecutionContextHash: exec,
		AuthoritySnapshots: []SnapshotUpsert{
			{
				Type:                 "CONFIG",
				ID:                   "chaos_validation_matrix",
				Version:              "chaos_validation_matrix_v1",
				CanonicalPayloadText: chaosText,
				PayloadHash:          chaosPH,
				Signature:            chaosSig,
			},
			{
				Type:                 "CONFIG",
				ID:                   "trust_snapshot",
				Version:              "v1",
				CanonicalPayloadText: trustText,
				PayloadHash:          trustPH,
				Signature:            trustSig,
			},
		},
		Records: []RecordDraft{{
			RecordType:            "DECISION",
			RecordVersion:         "v1",
			StageOrder:            3,
			RecordID:              recordID[:],
			LogicalShardID:        logicalShardID,
			CausalParentRefsText:  "{}",
			CanonicalPayloadBytes: recPayload,
			CanonicalPayloadHash:  recPH,
		}},
		PrivateKey: rootPriv,
		KeyID:      keyID,
		KeyEpoch:   1,
	}

	if err := CommitPartitionBatch(ctx, pool, opts); err != nil {
		t.Fatalf("expected commit success, got %v", err)
	}
}

func TestCommitPartitionBatch_RejectsNonCanonicalTrustSnapshotBeforeCommit(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("POSTGRES_DSN not set — skipping DB integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool: %v", err)
	}
	defer pool.Close()

	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}

	partitionID := int64(9402)
	logicalShardID := make([]byte, 32)

	rootEpoch := int64(1)
	rootType := "ROOT"
	scopeID := "scope-upsert-noncanonical"
	keyID := prd04KeyID(rootType, scopeID, rootEpoch, rootPub)
	rootRec, err := signedKeyRecord(rootPriv, keyRecordInput{
		KeyID:                  keyID,
		KeyType:                rootType,
		ScopeID:                scopeID,
		AuthorityScope:         "cluster",
		KeyEpoch:               rootEpoch,
		PublicKeyHex:           hex.EncodeToString(rootPub),
		AllowedSigningContexts: []string{BatchCommitSigningContext, "config_snapshot_v1", "trust_snapshot_v1", "key_record_v1"},
		IssuerKeyID:            keyID,
		Status:                 "ACTIVE",
		SigningContext:         "key_record_v1",
	})
	if err != nil {
		t.Fatalf("root key record: %v", err)
	}

	trustText, trustPH, _, err := signedTrustSnapshot(rootPriv, keyID, rootEpoch, scopeID, []string{rootRec})
	if err != nil {
		t.Fatalf("trust snapshot sign: %v", err)
	}
	chaosText, chaosPH, chaosSig, err := signedChaosValidationMatrixSnapshot(rootPriv, keyID, rootEpoch, "commit_upsert_noncanonical")
	if err != nil {
		t.Fatalf("chaos snapshot sign: %v", err)
	}

	// Provide non-canonical bytes (leading/trailing whitespace).
	nonCanonical := " \n" + trustText + "\n"
	phNonCanonical := sha256.Sum256([]byte(nonCanonical))
	signingInput := append([]byte("trust_snapshot_v1"), phNonCanonical[:]...)
	sigNonCanonical := ed25519.Sign(rootPriv, signingInput)
	exec := sha256.Sum256(append(chaosPH[:], trustPH[:]...))

	recPayload := []byte("x")
	recPH := sha256.Sum256(recPayload)
	recordID := sha256.Sum256([]byte("record-upsert-noncanonical"))

	opts := CommitOptions{
		PartitionID:          partitionID,
		PartitionEpoch:       0,
		ExecutionContextHash: exec,
		AuthoritySnapshots: []SnapshotUpsert{
			{
				Type:                 "CONFIG",
				ID:                   "chaos_validation_matrix",
				Version:              "chaos_validation_matrix_v1",
				CanonicalPayloadText: chaosText,
				PayloadHash:          chaosPH,
				Signature:            chaosSig,
			},
			{
				Type:                 "CONFIG",
				ID:                   "trust_snapshot",
				Version:              "v1",
				CanonicalPayloadText: nonCanonical,
				PayloadHash:          phNonCanonical,
				Signature:            sigNonCanonical,
			},
		},
		Records: []RecordDraft{{
			RecordType:            "DECISION",
			RecordVersion:         "v1",
			StageOrder:            3,
			RecordID:              recordID[:],
			LogicalShardID:        logicalShardID,
			CausalParentRefsText:  "{}",
			CanonicalPayloadBytes: recPayload,
			CanonicalPayloadHash:  recPH,
		}},
		PrivateKey: rootPriv,
		KeyID:      keyID,
		KeyEpoch:   1,
	}

	if err := CommitPartitionBatch(ctx, pool, opts); err == nil {
		t.Fatalf("expected commit failure")
	}
	assertNoBatchCommitted(t, ctx, pool, partitionID)
}

func TestCommitPartitionBatch_RejectsTrustSnapshotPayloadHashMismatchBeforeCommit(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("POSTGRES_DSN not set — skipping DB integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool: %v", err)
	}
	defer pool.Close()

	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}

	partitionID := int64(9403)
	logicalShardID := make([]byte, 32)

	rootEpoch := int64(1)
	rootType := "ROOT"
	scopeID := "scope-upsert-ph-mismatch"
	keyID := prd04KeyID(rootType, scopeID, rootEpoch, rootPub)
	rootRec, err := signedKeyRecord(rootPriv, keyRecordInput{
		KeyID:                  keyID,
		KeyType:                rootType,
		ScopeID:                scopeID,
		AuthorityScope:         "cluster",
		KeyEpoch:               rootEpoch,
		PublicKeyHex:           hex.EncodeToString(rootPub),
		AllowedSigningContexts: []string{BatchCommitSigningContext, "config_snapshot_v1", "trust_snapshot_v1", "key_record_v1"},
		IssuerKeyID:            keyID,
		Status:                 "ACTIVE",
		SigningContext:         "key_record_v1",
	})
	if err != nil {
		t.Fatalf("root key record: %v", err)
	}

	trustText, trustPH, trustSig, err := signedTrustSnapshot(rootPriv, keyID, rootEpoch, scopeID, []string{rootRec})
	if err != nil {
		t.Fatalf("trust snapshot sign: %v", err)
	}
	chaosText, chaosPH, chaosSig, err := signedChaosValidationMatrixSnapshot(rootPriv, keyID, rootEpoch, "commit_upsert_ph_mismatch")
	if err != nil {
		t.Fatalf("chaos snapshot sign: %v", err)
	}
	exec := sha256.Sum256(append(chaosPH[:], trustPH[:]...))

	recPayload := []byte("x")
	recPH := sha256.Sum256(recPayload)
	recordID := sha256.Sum256([]byte("record-upsert-ph-mismatch"))

	bad := trustPH
	bad[0] ^= 0xFF

	opts := CommitOptions{
		PartitionID:          partitionID,
		PartitionEpoch:       0,
		ExecutionContextHash: exec,
		AuthoritySnapshots: []SnapshotUpsert{
			{
				Type:                 "CONFIG",
				ID:                   "chaos_validation_matrix",
				Version:              "chaos_validation_matrix_v1",
				CanonicalPayloadText: chaosText,
				PayloadHash:          chaosPH,
				Signature:            chaosSig,
			},
			{
				Type:                 "CONFIG",
				ID:                   "trust_snapshot",
				Version:              "v1",
				CanonicalPayloadText: trustText,
				PayloadHash:          bad,
				Signature:            trustSig,
			},
		},
		Records: []RecordDraft{{
			RecordType:            "DECISION",
			RecordVersion:         "v1",
			StageOrder:            3,
			RecordID:              recordID[:],
			LogicalShardID:        logicalShardID,
			CausalParentRefsText:  "{}",
			CanonicalPayloadBytes: recPayload,
			CanonicalPayloadHash:  recPH,
		}},
		PrivateKey: rootPriv,
		KeyID:      keyID,
		KeyEpoch:   1,
	}

	if err := CommitPartitionBatch(ctx, pool, opts); err == nil {
		t.Fatalf("expected commit failure")
	}
	assertNoBatchCommitted(t, ctx, pool, partitionID)
}

func TestCommitPartitionBatch_RejectsTrustSnapshotSignatureCanonicalizationDriftBeforeCommit(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("POSTGRES_DSN not set — skipping DB integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool: %v", err)
	}
	defer pool.Close()

	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}

	partitionID := int64(9404)
	logicalShardID := make([]byte, 32)

	rootEpoch := int64(1)
	rootType := "ROOT"
	scopeID := "scope-upsert-sig-drift"
	keyID := prd04KeyID(rootType, scopeID, rootEpoch, rootPub)
	rootRec, err := signedKeyRecord(rootPriv, keyRecordInput{
		KeyID:                  keyID,
		KeyType:                rootType,
		ScopeID:                scopeID,
		AuthorityScope:         "cluster",
		KeyEpoch:               rootEpoch,
		PublicKeyHex:           hex.EncodeToString(rootPub),
		AllowedSigningContexts: []string{BatchCommitSigningContext, "config_snapshot_v1", "trust_snapshot_v1", "key_record_v1"},
		IssuerKeyID:            keyID,
		Status:                 "ACTIVE",
		SigningContext:         "key_record_v1",
	})
	if err != nil {
		t.Fatalf("root key record: %v", err)
	}

	trustText, trustPH, _, err := signedTrustSnapshot(rootPriv, keyID, rootEpoch, scopeID, []string{rootRec})
	if err != nil {
		t.Fatalf("trust snapshot sign: %v", err)
	}
	chaosText, chaosPH, chaosSig, err := signedChaosValidationMatrixSnapshot(rootPriv, keyID, rootEpoch, "commit_upsert_sig_drift")
	if err != nil {
		t.Fatalf("chaos snapshot sign: %v", err)
	}
	exec := sha256.Sum256(append(chaosPH[:], trustPH[:]...))

	// Signature computed over non-canonical bytes (drift), but payload text is canonical.
	nonCanonical := " \n" + trustText + "\n"
	phNonCanonical := sha256.Sum256([]byte(nonCanonical))
	signingInput := append([]byte("trust_snapshot_v1"), phNonCanonical[:]...)
	sigDrift := ed25519.Sign(rootPriv, signingInput)

	recPayload := []byte("x")
	recPH := sha256.Sum256(recPayload)
	recordID := sha256.Sum256([]byte("record-upsert-sig-drift"))

	opts := CommitOptions{
		PartitionID:          partitionID,
		PartitionEpoch:       0,
		ExecutionContextHash: exec,
		AuthoritySnapshots: []SnapshotUpsert{
			{
				Type:                 "CONFIG",
				ID:                   "chaos_validation_matrix",
				Version:              "chaos_validation_matrix_v1",
				CanonicalPayloadText: chaosText,
				PayloadHash:          chaosPH,
				Signature:            chaosSig,
			},
			{
				Type:                 "CONFIG",
				ID:                   "trust_snapshot",
				Version:              "v1",
				CanonicalPayloadText: trustText,
				PayloadHash:          trustPH,
				Signature:            sigDrift,
			},
		},
		Records: []RecordDraft{{
			RecordType:            "DECISION",
			RecordVersion:         "v1",
			StageOrder:            3,
			RecordID:              recordID[:],
			LogicalShardID:        logicalShardID,
			CausalParentRefsText:  "{}",
			CanonicalPayloadBytes: recPayload,
			CanonicalPayloadHash:  recPH,
		}},
		PrivateKey: rootPriv,
		KeyID:      keyID,
		KeyEpoch:   1,
	}

	if err := CommitPartitionBatch(ctx, pool, opts); err == nil {
		t.Fatalf("expected commit failure")
	}
	assertNoBatchCommitted(t, ctx, pool, partitionID)
}

func TestCommitPartitionBatch_AcceptsCanonicalNonTrustAuthoritySnapshotUpsert(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("POSTGRES_DSN not set — skipping DB integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool: %v", err)
	}
	defer pool.Close()

	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}

	partitionID := int64(9451)
	logicalShardID := make([]byte, 32)

	rootEpoch := int64(1)
	rootType := "ROOT"
	scopeID := "scope-upsert-nontrust-ok"
	keyID := prd04KeyID(rootType, scopeID, rootEpoch, rootPub)
	rootRec, err := signedKeyRecord(rootPriv, keyRecordInput{
		KeyID:                  keyID,
		KeyType:                rootType,
		ScopeID:                scopeID,
		AuthorityScope:         "cluster",
		KeyEpoch:               rootEpoch,
		PublicKeyHex:           hex.EncodeToString(rootPub),
		AllowedSigningContexts: []string{BatchCommitSigningContext, "config_snapshot_v1", "trust_snapshot_v1", "key_record_v1"},
		IssuerKeyID:            keyID,
		Status:                 "ACTIVE",
		SigningContext:         "key_record_v1",
	})
	if err != nil {
		t.Fatalf("root key record: %v", err)
	}

	trustText, trustPH, trustSig, err := signedTrustSnapshot(rootPriv, keyID, rootEpoch, scopeID, []string{rootRec})
	if err != nil {
		t.Fatalf("trust snapshot sign: %v", err)
	}
	chaosText, chaosPH, chaosSig, err := signedChaosValidationMatrixSnapshot(rootPriv, keyID, rootEpoch, "commit_upsert_nontrust_ok")
	if err != nil {
		t.Fatalf("chaos snapshot sign: %v", err)
	}
	exec := sha256.Sum256(append(chaosPH[:], trustPH[:]...))

	recPayload := []byte("ok")
	recPH := sha256.Sum256(recPayload)
	recordID := sha256.Sum256([]byte("record-upsert-nontrust-ok"))

	opts := CommitOptions{
		PartitionID:          partitionID,
		PartitionEpoch:       0,
		ExecutionContextHash: exec,
		AuthoritySnapshots: []SnapshotUpsert{
			{
				Type:                 "CONFIG",
				ID:                   "chaos_validation_matrix",
				Version:              "chaos_validation_matrix_v1",
				CanonicalPayloadText: chaosText,
				PayloadHash:          chaosPH,
				Signature:            chaosSig,
			},
			{
				Type:                 "CONFIG",
				ID:                   "trust_snapshot",
				Version:              "v1",
				CanonicalPayloadText: trustText,
				PayloadHash:          trustPH,
				Signature:            trustSig,
			},
		},
		Records: []RecordDraft{{
			RecordType:            "DECISION",
			RecordVersion:         "v1",
			StageOrder:            3,
			RecordID:              recordID[:],
			LogicalShardID:        logicalShardID,
			CausalParentRefsText:  "{}",
			CanonicalPayloadBytes: recPayload,
			CanonicalPayloadHash:  recPH,
		}},
		PrivateKey: rootPriv,
		KeyID:      keyID,
		KeyEpoch:   1,
	}

	if err := CommitPartitionBatch(ctx, pool, opts); err != nil {
		t.Fatalf("expected commit success, got %v", err)
	}
}

func TestCommitPartitionBatch_RejectsNonCanonicalNonTrustAuthoritySnapshotBeforeCommit(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("POSTGRES_DSN not set — skipping DB integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool: %v", err)
	}
	defer pool.Close()

	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}

	partitionID := int64(9452)
	logicalShardID := make([]byte, 32)

	rootEpoch := int64(1)
	rootType := "ROOT"
	scopeID := "scope-upsert-nontrust-noncanonical"
	keyID := prd04KeyID(rootType, scopeID, rootEpoch, rootPub)
	rootRec, err := signedKeyRecord(rootPriv, keyRecordInput{
		KeyID:                  keyID,
		KeyType:                rootType,
		ScopeID:                scopeID,
		AuthorityScope:         "cluster",
		KeyEpoch:               rootEpoch,
		PublicKeyHex:           hex.EncodeToString(rootPub),
		AllowedSigningContexts: []string{BatchCommitSigningContext, "config_snapshot_v1", "trust_snapshot_v1", "key_record_v1"},
		IssuerKeyID:            keyID,
		Status:                 "ACTIVE",
		SigningContext:         "key_record_v1",
	})
	if err != nil {
		t.Fatalf("root key record: %v", err)
	}

	trustText, trustPH, trustSig, err := signedTrustSnapshot(rootPriv, keyID, rootEpoch, scopeID, []string{rootRec})
	if err != nil {
		t.Fatalf("trust snapshot sign: %v", err)
	}
	chaosText, chaosPH, _, err := signedChaosValidationMatrixSnapshot(rootPriv, keyID, rootEpoch, "commit_upsert_nontrust_noncanonical")
	if err != nil {
		t.Fatalf("chaos snapshot sign: %v", err)
	}

	nonCanonicalChaos := " \n" + chaosText + "\n"
	phNonCanonical := sha256.Sum256([]byte(nonCanonicalChaos))
	signingInput := append([]byte("config_snapshot_v1"), phNonCanonical[:]...)
	sigNonCanonical := ed25519.Sign(rootPriv, signingInput)

	exec := sha256.Sum256(append(chaosPH[:], trustPH[:]...))

	recPayload := []byte("x")
	recPH := sha256.Sum256(recPayload)
	recordID := sha256.Sum256([]byte("record-upsert-nontrust-noncanonical"))

	opts := CommitOptions{
		PartitionID:          partitionID,
		PartitionEpoch:       0,
		ExecutionContextHash: exec,
		AuthoritySnapshots: []SnapshotUpsert{
			{
				Type:                 "CONFIG",
				ID:                   "chaos_validation_matrix",
				Version:              "chaos_validation_matrix_v1",
				CanonicalPayloadText: nonCanonicalChaos,
				PayloadHash:          phNonCanonical,
				Signature:            sigNonCanonical,
			},
			{
				Type:                 "CONFIG",
				ID:                   "trust_snapshot",
				Version:              "v1",
				CanonicalPayloadText: trustText,
				PayloadHash:          trustPH,
				Signature:            trustSig,
			},
		},
		Records: []RecordDraft{{
			RecordType:            "DECISION",
			RecordVersion:         "v1",
			StageOrder:            3,
			RecordID:              recordID[:],
			LogicalShardID:        logicalShardID,
			CausalParentRefsText:  "{}",
			CanonicalPayloadBytes: recPayload,
			CanonicalPayloadHash:  recPH,
		}},
		PrivateKey: rootPriv,
		KeyID:      keyID,
		KeyEpoch:   1,
	}

	if err := CommitPartitionBatch(ctx, pool, opts); err == nil {
		t.Fatalf("expected commit failure")
	} else {
		if f, ok := FailureAs(err); !ok {
			t.Fatalf("expected typed Failure, got %T: %v", err, err)
		} else {
			if f.Type != FailureType1InputError || f.Code != "CANONICALIZATION_VIOLATION" {
				t.Fatalf("unexpected failure classification: %+v", f)
			}
		}
	}
	assertNoBatchCommitted(t, ctx, pool, partitionID)
}

func TestCommitPartitionBatch_RejectsNonTrustAuthoritySnapshotPayloadHashMismatchBeforeCommit(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("POSTGRES_DSN not set — skipping DB integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool: %v", err)
	}
	defer pool.Close()

	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}

	partitionID := int64(9453)
	logicalShardID := make([]byte, 32)

	rootEpoch := int64(1)
	rootType := "ROOT"
	scopeID := "scope-upsert-nontrust-ph-mismatch"
	keyID := prd04KeyID(rootType, scopeID, rootEpoch, rootPub)
	rootRec, err := signedKeyRecord(rootPriv, keyRecordInput{
		KeyID:                  keyID,
		KeyType:                rootType,
		ScopeID:                scopeID,
		AuthorityScope:         "cluster",
		KeyEpoch:               rootEpoch,
		PublicKeyHex:           hex.EncodeToString(rootPub),
		AllowedSigningContexts: []string{BatchCommitSigningContext, "config_snapshot_v1", "trust_snapshot_v1", "key_record_v1"},
		IssuerKeyID:            keyID,
		Status:                 "ACTIVE",
		SigningContext:         "key_record_v1",
	})
	if err != nil {
		t.Fatalf("root key record: %v", err)
	}

	trustText, trustPH, trustSig, err := signedTrustSnapshot(rootPriv, keyID, rootEpoch, scopeID, []string{rootRec})
	if err != nil {
		t.Fatalf("trust snapshot sign: %v", err)
	}
	chaosText, chaosPH, chaosSig, err := signedChaosValidationMatrixSnapshot(rootPriv, keyID, rootEpoch, "commit_upsert_nontrust_ph_mismatch")
	if err != nil {
		t.Fatalf("chaos snapshot sign: %v", err)
	}

	badChaosPH := chaosPH
	badChaosPH[0] ^= 0xFF

	exec := sha256.Sum256(append(chaosPH[:], trustPH[:]...))

	recPayload := []byte("x")
	recPH := sha256.Sum256(recPayload)
	recordID := sha256.Sum256([]byte("record-upsert-nontrust-ph-mismatch"))

	opts := CommitOptions{
		PartitionID:          partitionID,
		PartitionEpoch:       0,
		ExecutionContextHash: exec,
		AuthoritySnapshots: []SnapshotUpsert{
			{
				Type:                 "CONFIG",
				ID:                   "chaos_validation_matrix",
				Version:              "chaos_validation_matrix_v1",
				CanonicalPayloadText: chaosText,
				PayloadHash:          badChaosPH,
				Signature:            chaosSig,
			},
			{
				Type:                 "CONFIG",
				ID:                   "trust_snapshot",
				Version:              "v1",
				CanonicalPayloadText: trustText,
				PayloadHash:          trustPH,
				Signature:            trustSig,
			},
		},
		Records: []RecordDraft{{
			RecordType:            "DECISION",
			RecordVersion:         "v1",
			StageOrder:            3,
			RecordID:              recordID[:],
			LogicalShardID:        logicalShardID,
			CausalParentRefsText:  "{}",
			CanonicalPayloadBytes: recPayload,
			CanonicalPayloadHash:  recPH,
		}},
		PrivateKey: rootPriv,
		KeyID:      keyID,
		KeyEpoch:   1,
	}

	if err := CommitPartitionBatch(ctx, pool, opts); err == nil {
		t.Fatalf("expected commit failure")
	}
	assertNoBatchCommitted(t, ctx, pool, partitionID)
}

func TestCommitPartitionBatch_RejectsNonTrustAuthoritySnapshotSignatureCanonicalizationDriftBeforeCommit(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("POSTGRES_DSN not set — skipping DB integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool: %v", err)
	}
	defer pool.Close()

	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}

	partitionID := int64(9454)
	logicalShardID := make([]byte, 32)

	rootEpoch := int64(1)
	rootType := "ROOT"
	scopeID := "scope-upsert-nontrust-sig-drift"
	keyID := prd04KeyID(rootType, scopeID, rootEpoch, rootPub)
	rootRec, err := signedKeyRecord(rootPriv, keyRecordInput{
		KeyID:                  keyID,
		KeyType:                rootType,
		ScopeID:                scopeID,
		AuthorityScope:         "cluster",
		KeyEpoch:               rootEpoch,
		PublicKeyHex:           hex.EncodeToString(rootPub),
		AllowedSigningContexts: []string{BatchCommitSigningContext, "config_snapshot_v1", "trust_snapshot_v1", "key_record_v1"},
		IssuerKeyID:            keyID,
		Status:                 "ACTIVE",
		SigningContext:         "key_record_v1",
	})
	if err != nil {
		t.Fatalf("root key record: %v", err)
	}

	trustText, trustPH, trustSig, err := signedTrustSnapshot(rootPriv, keyID, rootEpoch, scopeID, []string{rootRec})
	if err != nil {
		t.Fatalf("trust snapshot sign: %v", err)
	}
	chaosText, chaosPH, _, err := signedChaosValidationMatrixSnapshot(rootPriv, keyID, rootEpoch, "commit_upsert_nontrust_sig_drift")
	if err != nil {
		t.Fatalf("chaos snapshot sign: %v", err)
	}

	// Signature computed over non-canonical bytes while payload text stays canonical.
	nonCanonicalChaos := " \n" + chaosText + "\n"
	phNonCanonical := sha256.Sum256([]byte(nonCanonicalChaos))
	signingInput := append([]byte("config_snapshot_v1"), phNonCanonical[:]...)
	sigDrift := ed25519.Sign(rootPriv, signingInput)

	exec := sha256.Sum256(append(chaosPH[:], trustPH[:]...))

	recPayload := []byte("x")
	recPH := sha256.Sum256(recPayload)
	recordID := sha256.Sum256([]byte("record-upsert-nontrust-sig-drift"))

	opts := CommitOptions{
		PartitionID:          partitionID,
		PartitionEpoch:       0,
		ExecutionContextHash: exec,
		AuthoritySnapshots: []SnapshotUpsert{
			{
				Type:                 "CONFIG",
				ID:                   "chaos_validation_matrix",
				Version:              "chaos_validation_matrix_v1",
				CanonicalPayloadText: chaosText,
				PayloadHash:          chaosPH,
				Signature:            sigDrift,
			},
			{
				Type:                 "CONFIG",
				ID:                   "trust_snapshot",
				Version:              "v1",
				CanonicalPayloadText: trustText,
				PayloadHash:          trustPH,
				Signature:            trustSig,
			},
		},
		Records: []RecordDraft{{
			RecordType:            "DECISION",
			RecordVersion:         "v1",
			StageOrder:            3,
			RecordID:              recordID[:],
			LogicalShardID:        logicalShardID,
			CausalParentRefsText:  "{}",
			CanonicalPayloadBytes: recPayload,
			CanonicalPayloadHash:  recPH,
		}},
		PrivateKey: rootPriv,
		KeyID:      keyID,
		KeyEpoch:   1,
	}

	if err := CommitPartitionBatch(ctx, pool, opts); err == nil {
		t.Fatalf("expected commit failure")
	}
	assertNoBatchCommitted(t, ctx, pool, partitionID)
}

func TestCommitPartitionBatch_AcceptsReferencedCommittedAuthoritySnapshotsForBinding(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("POSTGRES_DSN not set — skipping DB integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool: %v", err)
	}
	defer pool.Close()

	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}

	// Seed committed snapshots via an initial commit.
	seedPartitionID := int64(9460)
	logicalShardID := make([]byte, 32)
	rootEpoch := int64(1)
	rootType := "ROOT"
	scopeID := "scope-ref-ok"
	keyID := prd04KeyID(rootType, scopeID, rootEpoch, rootPub)
	rootRec, err := signedKeyRecord(rootPriv, keyRecordInput{
		KeyID:                  keyID,
		KeyType:                rootType,
		ScopeID:                scopeID,
		AuthorityScope:         "cluster",
		KeyEpoch:               rootEpoch,
		PublicKeyHex:           hex.EncodeToString(rootPub),
		AllowedSigningContexts: []string{BatchCommitSigningContext, "config_snapshot_v1", "trust_snapshot_v1", "key_record_v1"},
		IssuerKeyID:            keyID,
		Status:                 "ACTIVE",
		SigningContext:         "key_record_v1",
	})
	if err != nil {
		t.Fatalf("root key record: %v", err)
	}

	trustText, trustPH, trustSig, err := signedTrustSnapshot(rootPriv, keyID, rootEpoch, scopeID, []string{rootRec})
	if err != nil {
		t.Fatalf("trust snapshot sign: %v", err)
	}
	chaosText, chaosPH, chaosSig, err := signedChaosValidationMatrixSnapshot(rootPriv, keyID, rootEpoch, "commit_ref_ok_seed")
	if err != nil {
		t.Fatalf("chaos snapshot sign: %v", err)
	}
	exec := sha256.Sum256(append(chaosPH[:], trustPH[:]...))

	seedRecPayload := []byte("seed")
	seedRecPH := sha256.Sum256(seedRecPayload)
	seedRecordID := sha256.Sum256([]byte("record-ref-ok-seed"))

	seedOpts := CommitOptions{
		PartitionID:          seedPartitionID,
		PartitionEpoch:       0,
		ExecutionContextHash: exec,
		AuthoritySnapshots: []SnapshotUpsert{
			{
				Type:                 "CONFIG",
				ID:                   "chaos_validation_matrix",
				Version:              "chaos_validation_matrix_v1",
				CanonicalPayloadText: chaosText,
				PayloadHash:          chaosPH,
				Signature:            chaosSig,
			},
			{
				Type:                 "CONFIG",
				ID:                   "trust_snapshot",
				Version:              "v1",
				CanonicalPayloadText: trustText,
				PayloadHash:          trustPH,
				Signature:            trustSig,
			},
		},
		Records: []RecordDraft{{
			RecordType:            "DECISION",
			RecordVersion:         "v1",
			StageOrder:            3,
			RecordID:              seedRecordID[:],
			LogicalShardID:        logicalShardID,
			CausalParentRefsText:  "{}",
			CanonicalPayloadBytes: seedRecPayload,
			CanonicalPayloadHash:  seedRecPH,
		}},
		PrivateKey: rootPriv,
		KeyID:      keyID,
		KeyEpoch:   1,
	}
	if err := CommitPartitionBatch(ctx, pool, seedOpts); err != nil {
		t.Fatalf("seed commit: %v", err)
	}

	// Now commit a new partition using AuthorityRefs only, validated before binding.
	partitionID := int64(9461)
	recPayload := []byte("x")
	recPH := sha256.Sum256(recPayload)
	recordID := sha256.Sum256([]byte("record-ref-ok"))

	opts := CommitOptions{
		PartitionID:          partitionID,
		PartitionEpoch:       0,
		ExecutionContextHash: exec,
		AuthorityRefs: []AuthorityRef{
			{Type: "CONFIG", ID: "trust_snapshot", Version: "v1"},
			{Type: "CONFIG", ID: "chaos_validation_matrix", Version: "chaos_validation_matrix_v1"},
		},
		Records: []RecordDraft{{
			RecordType:            "DECISION",
			RecordVersion:         "v1",
			StageOrder:            3,
			RecordID:              recordID[:],
			LogicalShardID:        logicalShardID,
			CausalParentRefsText:  "{}",
			CanonicalPayloadBytes: recPayload,
			CanonicalPayloadHash:  recPH,
		}},
		PrivateKey: rootPriv,
		KeyID:      keyID,
		KeyEpoch:   1,
	}

	if err := CommitPartitionBatch(ctx, pool, opts); err != nil {
		t.Fatalf("expected commit success, got %v", err)
	}
}

func TestCommitPartitionBatch_RejectsNonCanonicalReferencedSnapshotBeforeBinding(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("POSTGRES_DSN not set — skipping DB integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool: %v", err)
	}
	defer pool.Close()

	// Create committed snapshots we will reference.
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	seedPartitionID := int64(9462)
	logicalShardID := make([]byte, 32)
	rootEpoch := int64(1)
	rootType := "ROOT"
	scopeID := "scope-ref-noncanonical"
	keyID := prd04KeyID(rootType, scopeID, rootEpoch, rootPub)
	rootRec, err := signedKeyRecord(rootPriv, keyRecordInput{
		KeyID:                  keyID,
		KeyType:                rootType,
		ScopeID:                scopeID,
		AuthorityScope:         "cluster",
		KeyEpoch:               rootEpoch,
		PublicKeyHex:           hex.EncodeToString(rootPub),
		AllowedSigningContexts: []string{BatchCommitSigningContext, "config_snapshot_v1", "trust_snapshot_v1", "key_record_v1"},
		IssuerKeyID:            keyID,
		Status:                 "ACTIVE",
		SigningContext:         "key_record_v1",
	})
	if err != nil {
		t.Fatalf("root key record: %v", err)
	}
	trustText, trustPH, trustSig, err := signedTrustSnapshot(rootPriv, keyID, rootEpoch, scopeID, []string{rootRec})
	if err != nil {
		t.Fatalf("trust snapshot sign: %v", err)
	}
	chaosText, chaosPH, chaosSig, err := signedChaosValidationMatrixSnapshot(rootPriv, keyID, rootEpoch, "commit_ref_noncanonical_seed")
	if err != nil {
		t.Fatalf("chaos snapshot sign: %v", err)
	}
	exec := sha256.Sum256(append(chaosPH[:], trustPH[:]...))
	seedRecPayload := []byte("seed")
	seedRecPH := sha256.Sum256(seedRecPayload)
	seedRecordID := sha256.Sum256([]byte("record-ref-noncanonical-seed"))
	seedOpts := CommitOptions{
		PartitionID:          seedPartitionID,
		PartitionEpoch:       0,
		ExecutionContextHash: exec,
		AuthoritySnapshots: []SnapshotUpsert{
			{Type: "CONFIG", ID: "chaos_validation_matrix", Version: "chaos_validation_matrix_v1", CanonicalPayloadText: chaosText, PayloadHash: chaosPH, Signature: chaosSig},
			{Type: "CONFIG", ID: "trust_snapshot", Version: "v1", CanonicalPayloadText: trustText, PayloadHash: trustPH, Signature: trustSig},
		},
		Records:     []RecordDraft{{RecordType: "DECISION", RecordVersion: "v1", StageOrder: 3, RecordID: seedRecordID[:], LogicalShardID: logicalShardID, CausalParentRefsText: "{}", CanonicalPayloadBytes: seedRecPayload, CanonicalPayloadHash: seedRecPH}},
		PrivateKey:  rootPriv,
		KeyID:       keyID,
		KeyEpoch:    1,
	}
	if err := CommitPartitionBatch(ctx, pool, seedOpts); err != nil {
		t.Fatalf("seed commit: %v", err)
	}

	// Corrupt the committed chaos snapshot into a non-canonical form while keeping hash+sig consistent with stored bytes.
	nonCanonical := " \n" + chaosText + "\n"
	phStored := sha256.Sum256([]byte(nonCanonical))
	signingInput := append([]byte("config_snapshot_v1"), phStored[:]...)
	sigStored := ed25519.Sign(rootPriv, signingInput)
	if _, err := pool.Exec(ctx, `
UPDATE authority_snapshots
SET canonical_payload_text = $1, payload_hash = $2, signature = $3
WHERE authority_type = 'CONFIG' AND authority_id = 'chaos_validation_matrix' AND authority_version = 'chaos_validation_matrix_v1'`,
		nonCanonical, phStored[:], sigStored,
	); err != nil {
		t.Fatalf("corrupt chaos snapshot: %v", err)
	}

	// Now attempt a commit that references the corrupted snapshot: must fail before binding.
	partitionID := int64(9463)
	recPayload := []byte("x")
	recPH := sha256.Sum256(recPayload)
	recordID := sha256.Sum256([]byte("record-ref-noncanonical"))
	opts := CommitOptions{
		PartitionID:          partitionID,
		PartitionEpoch:       0,
		ExecutionContextHash: exec,
		AuthorityRefs: []AuthorityRef{
			{Type: "CONFIG", ID: "trust_snapshot", Version: "v1"},
			{Type: "CONFIG", ID: "chaos_validation_matrix", Version: "chaos_validation_matrix_v1"},
		},
		Records:    []RecordDraft{{RecordType: "DECISION", RecordVersion: "v1", StageOrder: 3, RecordID: recordID[:], LogicalShardID: logicalShardID, CausalParentRefsText: "{}", CanonicalPayloadBytes: recPayload, CanonicalPayloadHash: recPH}},
		PrivateKey: rootPriv,
		KeyID:      keyID,
		KeyEpoch:   1,
	}
	if err := CommitPartitionBatch(ctx, pool, opts); err == nil {
		t.Fatalf("expected commit failure")
	}
	assertNoBatchCommitted(t, ctx, pool, partitionID)
}

func TestCommitPartitionBatch_RejectsReferencedSnapshotPayloadHashMismatchBeforeBinding(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("POSTGRES_DSN not set — skipping DB integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool: %v", err)
	}
	defer pool.Close()

	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	seedPartitionID := int64(9464)
	logicalShardID := make([]byte, 32)
	rootEpoch := int64(1)
	rootType := "ROOT"
	scopeID := "scope-ref-ph-mismatch"
	keyID := prd04KeyID(rootType, scopeID, rootEpoch, rootPub)
	rootRec, err := signedKeyRecord(rootPriv, keyRecordInput{
		KeyID:                  keyID,
		KeyType:                rootType,
		ScopeID:                scopeID,
		AuthorityScope:         "cluster",
		KeyEpoch:               rootEpoch,
		PublicKeyHex:           hex.EncodeToString(rootPub),
		AllowedSigningContexts: []string{BatchCommitSigningContext, "config_snapshot_v1", "trust_snapshot_v1", "key_record_v1"},
		IssuerKeyID:            keyID,
		Status:                 "ACTIVE",
		SigningContext:         "key_record_v1",
	})
	if err != nil {
		t.Fatalf("root key record: %v", err)
	}
	trustText, trustPH, trustSig, err := signedTrustSnapshot(rootPriv, keyID, rootEpoch, scopeID, []string{rootRec})
	if err != nil {
		t.Fatalf("trust snapshot sign: %v", err)
	}
	chaosText, chaosPH, chaosSig, err := signedChaosValidationMatrixSnapshot(rootPriv, keyID, rootEpoch, "commit_ref_ph_mismatch_seed")
	if err != nil {
		t.Fatalf("chaos snapshot sign: %v", err)
	}
	exec := sha256.Sum256(append(chaosPH[:], trustPH[:]...))
	seedRecPayload := []byte("seed")
	seedRecPH := sha256.Sum256(seedRecPayload)
	seedRecordID := sha256.Sum256([]byte("record-ref-ph-mismatch-seed"))
	seedOpts := CommitOptions{
		PartitionID:          seedPartitionID,
		PartitionEpoch:       0,
		ExecutionContextHash: exec,
		AuthoritySnapshots: []SnapshotUpsert{
			{Type: "CONFIG", ID: "chaos_validation_matrix", Version: "chaos_validation_matrix_v1", CanonicalPayloadText: chaosText, PayloadHash: chaosPH, Signature: chaosSig},
			{Type: "CONFIG", ID: "trust_snapshot", Version: "v1", CanonicalPayloadText: trustText, PayloadHash: trustPH, Signature: trustSig},
		},
		Records:     []RecordDraft{{RecordType: "DECISION", RecordVersion: "v1", StageOrder: 3, RecordID: seedRecordID[:], LogicalShardID: logicalShardID, CausalParentRefsText: "{}", CanonicalPayloadBytes: seedRecPayload, CanonicalPayloadHash: seedRecPH}},
		PrivateKey:  rootPriv,
		KeyID:       keyID,
		KeyEpoch:    1,
	}
	if err := CommitPartitionBatch(ctx, pool, seedOpts); err != nil {
		t.Fatalf("seed commit: %v", err)
	}

	// Corrupt payload_hash only (leave canonical payload untouched).
	bad := make([]byte, 32)
	for i := range bad {
		bad[i] = 0xAA
	}
	if _, err := pool.Exec(ctx, `
UPDATE authority_snapshots
SET payload_hash = $1
WHERE authority_type = 'CONFIG' AND authority_id = 'chaos_validation_matrix' AND authority_version = 'chaos_validation_matrix_v1'`,
		bad,
	); err != nil {
		t.Fatalf("corrupt payload_hash: %v", err)
	}

	partitionID := int64(9465)
	recPayload := []byte("x")
	recPH := sha256.Sum256(recPayload)
	recordID := sha256.Sum256([]byte("record-ref-ph-mismatch"))
	opts := CommitOptions{
		PartitionID:          partitionID,
		PartitionEpoch:       0,
		ExecutionContextHash: exec,
		AuthorityRefs: []AuthorityRef{
			{Type: "CONFIG", ID: "trust_snapshot", Version: "v1"},
			{Type: "CONFIG", ID: "chaos_validation_matrix", Version: "chaos_validation_matrix_v1"},
		},
		Records:    []RecordDraft{{RecordType: "DECISION", RecordVersion: "v1", StageOrder: 3, RecordID: recordID[:], LogicalShardID: logicalShardID, CausalParentRefsText: "{}", CanonicalPayloadBytes: recPayload, CanonicalPayloadHash: recPH}},
		PrivateKey: rootPriv,
		KeyID:      keyID,
		KeyEpoch:   1,
	}
	if err := CommitPartitionBatch(ctx, pool, opts); err == nil {
		t.Fatalf("expected commit failure")
	}
	assertNoBatchCommitted(t, ctx, pool, partitionID)
}

func TestCommitPartitionBatch_RejectsReferencedSnapshotSignatureCanonicalizationDriftBeforeBinding(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("POSTGRES_DSN not set — skipping DB integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool: %v", err)
	}
	defer pool.Close()

	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	seedPartitionID := int64(9466)
	logicalShardID := make([]byte, 32)
	rootEpoch := int64(1)
	rootType := "ROOT"
	scopeID := "scope-ref-sig-drift"
	keyID := prd04KeyID(rootType, scopeID, rootEpoch, rootPub)
	rootRec, err := signedKeyRecord(rootPriv, keyRecordInput{
		KeyID:                  keyID,
		KeyType:                rootType,
		ScopeID:                scopeID,
		AuthorityScope:         "cluster",
		KeyEpoch:               rootEpoch,
		PublicKeyHex:           hex.EncodeToString(rootPub),
		AllowedSigningContexts: []string{BatchCommitSigningContext, "config_snapshot_v1", "trust_snapshot_v1", "key_record_v1"},
		IssuerKeyID:            keyID,
		Status:                 "ACTIVE",
		SigningContext:         "key_record_v1",
	})
	if err != nil {
		t.Fatalf("root key record: %v", err)
	}
	trustText, trustPH, trustSig, err := signedTrustSnapshot(rootPriv, keyID, rootEpoch, scopeID, []string{rootRec})
	if err != nil {
		t.Fatalf("trust snapshot sign: %v", err)
	}
	chaosText, chaosPH, chaosSig, err := signedChaosValidationMatrixSnapshot(rootPriv, keyID, rootEpoch, "commit_ref_sig_drift_seed")
	if err != nil {
		t.Fatalf("chaos snapshot sign: %v", err)
	}
	exec := sha256.Sum256(append(chaosPH[:], trustPH[:]...))
	seedRecPayload := []byte("seed")
	seedRecPH := sha256.Sum256(seedRecPayload)
	seedRecordID := sha256.Sum256([]byte("record-ref-sig-drift-seed"))
	seedOpts := CommitOptions{
		PartitionID:          seedPartitionID,
		PartitionEpoch:       0,
		ExecutionContextHash: exec,
		AuthoritySnapshots: []SnapshotUpsert{
			{Type: "CONFIG", ID: "chaos_validation_matrix", Version: "chaos_validation_matrix_v1", CanonicalPayloadText: chaosText, PayloadHash: chaosPH, Signature: chaosSig},
			{Type: "CONFIG", ID: "trust_snapshot", Version: "v1", CanonicalPayloadText: trustText, PayloadHash: trustPH, Signature: trustSig},
		},
		Records:     []RecordDraft{{RecordType: "DECISION", RecordVersion: "v1", StageOrder: 3, RecordID: seedRecordID[:], LogicalShardID: logicalShardID, CausalParentRefsText: "{}", CanonicalPayloadBytes: seedRecPayload, CanonicalPayloadHash: seedRecPH}},
		PrivateKey:  rootPriv,
		KeyID:       keyID,
		KeyEpoch:    1,
	}
	if err := CommitPartitionBatch(ctx, pool, seedOpts); err != nil {
		t.Fatalf("seed commit: %v", err)
	}

	// Replace committed signature with one computed over non-canonical bytes while payload remains canonical.
	nonCanonical := " \n" + chaosText + "\n"
	phNonCanonical := sha256.Sum256([]byte(nonCanonical))
	signingInput := append([]byte("config_snapshot_v1"), phNonCanonical[:]...)
	sigDrift := ed25519.Sign(rootPriv, signingInput)
	if _, err := pool.Exec(ctx, `
UPDATE authority_snapshots
SET signature = $1
WHERE authority_type = 'CONFIG' AND authority_id = 'chaos_validation_matrix' AND authority_version = 'chaos_validation_matrix_v1'`,
		sigDrift,
	); err != nil {
		t.Fatalf("corrupt signature: %v", err)
	}

	partitionID := int64(9467)
	recPayload := []byte("x")
	recPH := sha256.Sum256(recPayload)
	recordID := sha256.Sum256([]byte("record-ref-sig-drift"))
	opts := CommitOptions{
		PartitionID:          partitionID,
		PartitionEpoch:       0,
		ExecutionContextHash: exec,
		AuthorityRefs: []AuthorityRef{
			{Type: "CONFIG", ID: "trust_snapshot", Version: "v1"},
			{Type: "CONFIG", ID: "chaos_validation_matrix", Version: "chaos_validation_matrix_v1"},
		},
		Records:    []RecordDraft{{RecordType: "DECISION", RecordVersion: "v1", StageOrder: 3, RecordID: recordID[:], LogicalShardID: logicalShardID, CausalParentRefsText: "{}", CanonicalPayloadBytes: recPayload, CanonicalPayloadHash: recPH}},
		PrivateKey: rootPriv,
		KeyID:      keyID,
		KeyEpoch:   1,
	}
	if err := CommitPartitionBatch(ctx, pool, opts); err == nil {
		t.Fatalf("expected commit failure")
	}
	assertNoBatchCommitted(t, ctx, pool, partitionID)
}

func TestCommitPartitionBatch_FailsClosedOnMissingTrustSnapshotBinding(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("POSTGRES_DSN not set — skipping DB integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool: %v", err)
	}
	defer pool.Close()

	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}

	partitionID := int64(9471)
	logicalShardID := make([]byte, 32)

	rootEpoch := int64(1)
	rootType := "ROOT"
	scopeID := "scope-missing-trust"
	keyID := prd04KeyID(rootType, scopeID, rootEpoch, rootPub)

	chaosText, chaosPH, chaosSig, err := signedChaosValidationMatrixSnapshot(rootPriv, keyID, rootEpoch, "commit_missing_trust")
	if err != nil {
		t.Fatalf("chaos snapshot sign: %v", err)
	}

	exec := sha256.Sum256(append(chaosPH[:], chaosPH[:]...)) // arbitrary deterministic
	recPayload := []byte("x")
	recPH := sha256.Sum256(recPayload)
	recordID := sha256.Sum256([]byte("record-missing-trust"))

	opts := CommitOptions{
		PartitionID:          partitionID,
		PartitionEpoch:       0,
		ExecutionContextHash: exec,
		AuthoritySnapshots: []SnapshotUpsert{
			{
				Type:                 "CONFIG",
				ID:                   "chaos_validation_matrix",
				Version:              "chaos_validation_matrix_v1",
				CanonicalPayloadText: chaosText,
				PayloadHash:          chaosPH,
				Signature:            chaosSig,
			},
		},
		Records: []RecordDraft{{
			RecordType:            "DECISION",
			RecordVersion:         "v1",
			StageOrder:            3,
			RecordID:              recordID[:],
			LogicalShardID:        logicalShardID,
			CausalParentRefsText:  "{}",
			CanonicalPayloadBytes: recPayload,
			CanonicalPayloadHash:  recPH,
		}},
		PrivateKey: rootPriv,
		KeyID:      keyID,
		KeyEpoch:   1,
	}

	if err := CommitPartitionBatch(ctx, pool, opts); err == nil {
		t.Fatalf("expected commit failure")
	}
	assertNoBatchCommitted(t, ctx, pool, partitionID)
}

func TestCommitPartitionBatch_FailsClosedOnAmbiguousTrustSnapshotBindings(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("POSTGRES_DSN not set — skipping DB integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool: %v", err)
	}
	defer pool.Close()

	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}

	// Seed committed trust_snapshot v1 so AuthorityRefs can reference it.
	seedPartitionID := int64(9472)
	logicalShardID := make([]byte, 32)
	rootEpoch := int64(1)
	rootType := "ROOT"
	scopeID := "scope-ambiguous-trust"
	keyID := prd04KeyID(rootType, scopeID, rootEpoch, rootPub)
	rootRec, err := signedKeyRecord(rootPriv, keyRecordInput{
		KeyID:                  keyID,
		KeyType:                rootType,
		ScopeID:                scopeID,
		AuthorityScope:         "cluster",
		KeyEpoch:               rootEpoch,
		PublicKeyHex:           hex.EncodeToString(rootPub),
		AllowedSigningContexts: []string{BatchCommitSigningContext, "config_snapshot_v1", "trust_snapshot_v1", "key_record_v1"},
		IssuerKeyID:            keyID,
		Status:                 "ACTIVE",
		SigningContext:         "key_record_v1",
	})
	if err != nil {
		t.Fatalf("root key record: %v", err)
	}
	trustText, trustPH, trustSig, err := signedTrustSnapshot(rootPriv, keyID, rootEpoch, scopeID, []string{rootRec})
	if err != nil {
		t.Fatalf("trust snapshot sign: %v", err)
	}
	chaosText, chaosPH, chaosSig, err := signedChaosValidationMatrixSnapshot(rootPriv, keyID, rootEpoch, "commit_ambiguous_trust_seed")
	if err != nil {
		t.Fatalf("chaos snapshot sign: %v", err)
	}
	exec := sha256.Sum256(append(chaosPH[:], trustPH[:]...))
	seedRecPayload := []byte("seed")
	seedRecPH := sha256.Sum256(seedRecPayload)
	var runNonce [16]byte
	if _, err := rand.Read(runNonce[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	seedRecordID := sha256.Sum256([]byte(fmt.Sprintf("record-ambiguous-trust-seed|%s|%x", t.Name(), runNonce)))
	seedOpts := CommitOptions{
		PartitionID:          seedPartitionID,
		PartitionEpoch:       0,
		ExecutionContextHash: exec,
		AuthoritySnapshots: []SnapshotUpsert{
			{Type: "CONFIG", ID: "chaos_validation_matrix", Version: "chaos_validation_matrix_v1", CanonicalPayloadText: chaosText, PayloadHash: chaosPH, Signature: chaosSig},
			{Type: "CONFIG", ID: "trust_snapshot", Version: "v1", CanonicalPayloadText: trustText, PayloadHash: trustPH, Signature: trustSig},
		},
		Records:    []RecordDraft{{RecordType: "DECISION", RecordVersion: "v1", StageOrder: 3, RecordID: seedRecordID[:], LogicalShardID: logicalShardID, CausalParentRefsText: "{}", CanonicalPayloadBytes: seedRecPayload, CanonicalPayloadHash: seedRecPH}},
		PrivateKey: rootPriv,
		KeyID:      keyID,
		KeyEpoch:   1,
	}
	if err := CommitPartitionBatch(ctx, pool, seedOpts); err != nil {
		t.Fatalf("seed commit: %v", err)
	}

	// Now attempt a commit with two logically distinct trust_snapshot bindings -> must fail closed.
	partitionID := int64(9473)
	recPayload := []byte("x")
	recPH := sha256.Sum256(recPayload)
	recordID := sha256.Sum256([]byte(fmt.Sprintf("record-ambiguous-trust|%s|%x", t.Name(), runNonce)))
	opts := CommitOptions{
		PartitionID:          partitionID,
		PartitionEpoch:       0,
		ExecutionContextHash: exec,
		AuthorityRefs: []AuthorityRef{
			{Type: "CONFIG", ID: "trust_snapshot", Version: "v1"},
			{Type: "CONFIG", ID: "trust_snapshot", Version: "v2"},
			{Type: "CONFIG", ID: "chaos_validation_matrix", Version: "chaos_validation_matrix_v1"},
		},
		Records:    []RecordDraft{{RecordType: "DECISION", RecordVersion: "v1", StageOrder: 3, RecordID: recordID[:], LogicalShardID: logicalShardID, CausalParentRefsText: "{}", CanonicalPayloadBytes: recPayload, CanonicalPayloadHash: recPH}},
		PrivateKey: rootPriv,
		KeyID:      keyID,
		KeyEpoch:   1,
	}
	if err := CommitPartitionBatch(ctx, pool, opts); err == nil {
		t.Fatalf("expected commit failure")
	}
	assertNoBatchCommitted(t, ctx, pool, partitionID)
}

func TestCommitPartitionBatch_FailsClosedOnDuplicateLogicalBindings(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("POSTGRES_DSN not set — skipping DB integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool: %v", err)
	}
	defer pool.Close()

	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}

	// Seed committed snapshots.
	seedPartitionID := int64(9474)
	logicalShardID := make([]byte, 32)
	rootEpoch := int64(1)
	rootType := "ROOT"
	scopeID := "scope-dup-bindings"
	keyID := prd04KeyID(rootType, scopeID, rootEpoch, rootPub)
	rootRec, err := signedKeyRecord(rootPriv, keyRecordInput{
		KeyID:                  keyID,
		KeyType:                rootType,
		ScopeID:                scopeID,
		AuthorityScope:         "cluster",
		KeyEpoch:               rootEpoch,
		PublicKeyHex:           hex.EncodeToString(rootPub),
		AllowedSigningContexts: []string{BatchCommitSigningContext, "config_snapshot_v1", "trust_snapshot_v1", "key_record_v1"},
		IssuerKeyID:            keyID,
		Status:                 "ACTIVE",
		SigningContext:         "key_record_v1",
	})
	if err != nil {
		t.Fatalf("root key record: %v", err)
	}
	trustText, trustPH, trustSig, err := signedTrustSnapshot(rootPriv, keyID, rootEpoch, scopeID, []string{rootRec})
	if err != nil {
		t.Fatalf("trust snapshot sign: %v", err)
	}
	chaosText, chaosPH, chaosSig, err := signedChaosValidationMatrixSnapshot(rootPriv, keyID, rootEpoch, "commit_dup_bindings_seed")
	if err != nil {
		t.Fatalf("chaos snapshot sign: %v", err)
	}
	exec := sha256.Sum256(append(chaosPH[:], trustPH[:]...))
	seedRecPayload := []byte("seed")
	seedRecPH := sha256.Sum256(seedRecPayload)
	var runNonce [16]byte
	if _, err := rand.Read(runNonce[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	seedRecordID := sha256.Sum256([]byte(fmt.Sprintf("record-dup-bindings-seed|%s|%x", t.Name(), runNonce)))
	seedOpts := CommitOptions{
		PartitionID:          seedPartitionID,
		PartitionEpoch:       0,
		ExecutionContextHash: exec,
		AuthoritySnapshots: []SnapshotUpsert{
			{Type: "CONFIG", ID: "chaos_validation_matrix", Version: "chaos_validation_matrix_v1", CanonicalPayloadText: chaosText, PayloadHash: chaosPH, Signature: chaosSig},
			{Type: "CONFIG", ID: "trust_snapshot", Version: "v1", CanonicalPayloadText: trustText, PayloadHash: trustPH, Signature: trustSig},
		},
		Records:    []RecordDraft{{RecordType: "DECISION", RecordVersion: "v1", StageOrder: 3, RecordID: seedRecordID[:], LogicalShardID: logicalShardID, CausalParentRefsText: "{}", CanonicalPayloadBytes: seedRecPayload, CanonicalPayloadHash: seedRecPH}},
		PrivateKey: rootPriv,
		KeyID:      keyID,
		KeyEpoch:   1,
	}
	if err := CommitPartitionBatch(ctx, pool, seedOpts); err != nil {
		t.Fatalf("seed commit: %v", err)
	}

	partitionID := int64(9475)
	recPayload := []byte("x")
	recPH := sha256.Sum256(recPayload)
	recordID := sha256.Sum256([]byte(fmt.Sprintf("record-dup-bindings|%s|%x", t.Name(), runNonce)))
	opts := CommitOptions{
		PartitionID:          partitionID,
		PartitionEpoch:       0,
		ExecutionContextHash: exec,
		AuthorityRefs: []AuthorityRef{
			{Type: "CONFIG", ID: "trust_snapshot", Version: "v1"},
			{Type: "CONFIG", ID: "trust_snapshot", Version: "v1"}, // duplicate logical binding
			{Type: "CONFIG", ID: "chaos_validation_matrix", Version: "chaos_validation_matrix_v1"},
		},
		Records:    []RecordDraft{{RecordType: "DECISION", RecordVersion: "v1", StageOrder: 3, RecordID: recordID[:], LogicalShardID: logicalShardID, CausalParentRefsText: "{}", CanonicalPayloadBytes: recPayload, CanonicalPayloadHash: recPH}},
		PrivateKey: rootPriv,
		KeyID:      keyID,
		KeyEpoch:   1,
	}
	if err := CommitPartitionBatch(ctx, pool, opts); err == nil {
		t.Fatalf("expected commit failure")
	}
	assertNoBatchCommitted(t, ctx, pool, partitionID)
}

func assertNoBatchCommitted(t *testing.T, ctx context.Context, pool *pgxpool.Pool, partitionID int64) {
	t.Helper()
	var n int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM batch_commit_records WHERE partition_id = $1`, partitionID).Scan(&n); err != nil {
		t.Fatalf("count batch_commit_records: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected no committed batches, found %d", n)
	}
}

func TestVerifyCommittedBatch_FailsOnAuthoritySnapshotSignatureDrift_ReturnsType3SignatureMismatch(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("POSTGRES_DSN not set — skipping DB integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool: %v", err)
	}
	defer pool.Close()

	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}

	partitionID := int64(9310)
	logicalShardID := make([]byte, 32)

	rootEpoch := int64(1)
	rootType := "ROOT"
	scopeID := "scope-authority-sig-drift"
	keyID := prd04KeyID(rootType, scopeID, rootEpoch, rootPub)
	rootRec, err := signedKeyRecord(rootPriv, keyRecordInput{
		KeyID:                  keyID,
		KeyType:                rootType,
		ScopeID:                scopeID,
		AuthorityScope:         "cluster",
		KeyEpoch:               rootEpoch,
		PublicKeyHex:           hex.EncodeToString(rootPub),
		AllowedSigningContexts: []string{BatchCommitSigningContext, "config_snapshot_v1", "trust_snapshot_v1", "key_record_v1"},
		IssuerKeyID:            keyID,
		Status:                 "ACTIVE",
		SigningContext:         "key_record_v1",
	})
	if err != nil {
		t.Fatalf("root key record: %v", err)
	}

	trustText, trustPH, trustSig, err := signedTrustSnapshot(rootPriv, keyID, rootEpoch, scopeID, []string{rootRec})
	if err != nil {
		t.Fatalf("trust snapshot sign: %v", err)
	}
	chaosText, chaosPH, chaosSig, err := signedChaosValidationMatrixSnapshot(rootPriv, keyID, rootEpoch, "verify_authority_sig_drift")
	if err != nil {
		t.Fatalf("chaos snapshot sign: %v", err)
	}
	exec := sha256.Sum256(append(chaosPH[:], trustPH[:]...))

	recPayload := []byte("x")
	recPH := sha256.Sum256(recPayload)
	recordID := sha256.Sum256([]byte("record-authority-sig-drift"))

	opts := CommitOptions{
		PartitionID:          partitionID,
		PartitionEpoch:       0,
		ExecutionContextHash: exec,
		AuthoritySnapshots: []SnapshotUpsert{
			{
				Type:                 "CONFIG",
				ID:                   "chaos_validation_matrix",
				Version:              "chaos_validation_matrix_v1",
				CanonicalPayloadText: chaosText,
				PayloadHash:          chaosPH,
				Signature:            chaosSig,
			},
			{
				Type:                 "CONFIG",
				ID:                   "trust_snapshot",
				Version:              "v1",
				CanonicalPayloadText: trustText,
				PayloadHash:          trustPH,
				Signature:            trustSig,
			},
		},
		Records: []RecordDraft{{
			RecordType:            "DECISION",
			RecordVersion:         "v1",
			StageOrder:            3,
			RecordID:              recordID[:],
			LogicalShardID:        logicalShardID,
			CausalParentRefsText:  "{}",
			CanonicalPayloadBytes: recPayload,
			CanonicalPayloadHash:  recPH,
		}},
		PrivateKey: rootPriv,
		KeyID:      keyID,
		KeyEpoch:   1,
	}
	if err := CommitPartitionBatch(ctx, pool, opts); err != nil {
		t.Fatalf("commit: %v", err)
	}

	var batchSeq int64
	if err := pool.QueryRow(ctx, `
SELECT batch_commit_seq
FROM batch_commit_records
WHERE partition_id = $1
ORDER BY batch_commit_seq DESC
LIMIT 1`, partitionID).Scan(&batchSeq); err != nil {
		t.Fatalf("load batch: %v", err)
	}

	// Replace committed signature with one computed over non-canonical bytes while payload stays canonical.
	nonCanonical := " \n" + chaosText + "\n"
	phNonCanonical := sha256.Sum256([]byte(nonCanonical))
	signingInput := append([]byte("config_snapshot_v1"), phNonCanonical[:]...)
	sigDrift := ed25519.Sign(rootPriv, signingInput)

	if _, err := pool.Exec(ctx, `
UPDATE authority_snapshots
SET signature = $1
WHERE authority_type = 'CONFIG' AND authority_id = 'chaos_validation_matrix' AND authority_version = 'chaos_validation_matrix_v1'`,
		sigDrift,
	); err != nil {
		t.Fatalf("update chaos snapshot signature: %v", err)
	}

	if _, err := VerifyCommittedBatch(ctx, pool, partitionID, batchSeq); err == nil {
		t.Fatalf("expected verify failure")
	} else {
		if f, ok := FailureAs(err); !ok {
			t.Fatalf("expected typed Failure, got %T: %v", err, err)
		} else {
			if f.Type != FailureType3IntegrityFailure || f.Code != "SIGNATURE_MISMATCH" {
				t.Fatalf("unexpected failure classification: %+v", f)
			}
		}
	}
}

func TestVerifyCommittedBatch_FailsOnMissingAuthorityBindings(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("POSTGRES_DSN not set — skipping DB integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool: %v", err)
	}
	defer pool.Close()

	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}

	partitionID := int64(9003)
	logicalShardID := make([]byte, 32)

	rootEpoch := int64(1)
	rootType := "ROOT"
	scopeID := "scope-3"
	keyID := prd04KeyID(rootType, scopeID, rootEpoch, rootPub)
	rootRec, err := signedKeyRecord(rootPriv, keyRecordInput{
		KeyID:                  keyID,
		KeyType:                rootType,
		ScopeID:                scopeID,
		AuthorityScope:         "cluster",
		KeyEpoch:               rootEpoch,
		PublicKeyHex:           hex.EncodeToString(rootPub),
		AllowedSigningContexts: []string{BatchCommitSigningContext, "config_snapshot_v1", "trust_snapshot_v1", "key_record_v1"},
		IssuerKeyID:            keyID,
		Status:                 "ACTIVE",
		SigningContext:         "key_record_v1",
	})
	if err != nil {
		t.Fatalf("root key record: %v", err)
	}
	trustText, trustPH, trustSig, err := signedTrustSnapshot(rootPriv, keyID, rootEpoch, scopeID, []string{rootRec})
	if err != nil {
		t.Fatalf("trust snapshot sign: %v", err)
	}
	chaosText, chaosPH, chaosSig, err := signedChaosValidationMatrixSnapshot(rootPriv, keyID, rootEpoch, "batch_verify_missing_auth")
	if err != nil {
		t.Fatalf("chaos snapshot sign: %v", err)
	}
	exec := sha256.Sum256(append(chaosPH[:], trustPH[:]...))

	recPayload := []byte("x")
	recPH := sha256.Sum256(recPayload)
	recordID := sha256.Sum256([]byte("record-1"))

	opts := CommitOptions{
		PartitionID:          partitionID,
		PartitionEpoch:       0,
		ExecutionContextHash: exec,
		AuthoritySnapshots: []SnapshotUpsert{
			{
				Type:                 "CONFIG",
				ID:                   "chaos_validation_matrix",
				Version:              "chaos_validation_matrix_v1",
				CanonicalPayloadText: chaosText,
				PayloadHash:          chaosPH,
				Signature:            chaosSig,
			},
			{
				Type:                 "CONFIG",
				ID:                   "trust_snapshot",
				Version:              "v1",
				CanonicalPayloadText: trustText,
				PayloadHash:          trustPH,
				Signature:            trustSig,
			},
		},
		Records: []RecordDraft{{
			RecordType:            "DECISION",
			RecordVersion:         "v1",
			StageOrder:            3,
			RecordID:              recordID[:],
			LogicalShardID:        logicalShardID,
			CausalParentRefsText:  "{}",
			CanonicalPayloadBytes: recPayload,
			CanonicalPayloadHash:  recPH,
		}},
		PrivateKey: rootPriv,
		KeyID:      keyID,
		KeyEpoch:   1,
	}

	if err := CommitPartitionBatch(ctx, pool, opts); err != nil {
		t.Fatalf("commit: %v", err)
	}

	var batchSeq int64
	if err := pool.QueryRow(ctx, `SELECT MAX(batch_commit_seq) FROM batch_commit_records WHERE partition_id = $1`, partitionID).Scan(&batchSeq); err != nil {
		t.Fatalf("batch seq: %v", err)
	}

	// Remove authority bindings; verification must fail closed.
	if _, err := pool.Exec(ctx, `DELETE FROM batch_commit_authority_bindings WHERE partition_id = $1 AND batch_commit_seq = $2`, partitionID, batchSeq); err != nil {
		t.Fatalf("delete bindings: %v", err)
	}
	if _, err := VerifyCommittedBatch(ctx, pool, partitionID, batchSeq); err == nil {
		t.Fatalf("expected verify failure")
	}
}

func TestVerifyCommittedBatch_FailsOnMissingKeyMaterial(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("POSTGRES_DSN not set — skipping DB integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool: %v", err)
	}
	defer pool.Close()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}

	partitionID := int64(9004)
	logicalShardID := make([]byte, 32)

	chaosText := `{"authority":"batch_verify_missing_key"}`
	chaosPH := sha256.Sum256([]byte(chaosText))
	exec := sha256.Sum256(chaosPH[:])

	recPayload := []byte("x")
	recPH := sha256.Sum256(recPayload)
	recordID := sha256.Sum256([]byte("record-1"))

	// Intentionally omit trust_snapshot binding/key records.
	opts := CommitOptions{
		PartitionID:          partitionID,
		PartitionEpoch:       0,
		ExecutionContextHash: exec,
		AuthoritySnapshots: []SnapshotUpsert{{
			Type:                 "CONFIG",
			ID:                   "chaos_validation_matrix",
			Version:              "chaos_validation_matrix_v1",
			CanonicalPayloadText: chaosText,
			PayloadHash:          chaosPH,
			Signature:            []byte{0xAA},
		}},
		Records: []RecordDraft{{
			RecordType:            "DECISION",
			RecordVersion:         "v1",
			StageOrder:            3,
			RecordID:              recordID[:],
			LogicalShardID:        logicalShardID,
			CausalParentRefsText:  "{}",
			CanonicalPayloadBytes: recPayload,
			CanonicalPayloadHash:  recPH,
		}},
		PrivateKey: priv,
		KeyID:      strings.Repeat("00", 32),
		KeyEpoch:   1,
	}
	if err := CommitPartitionBatch(ctx, pool, opts); err != nil {
		t.Fatalf("commit: %v", err)
	}
	var batchSeq int64
	if err := pool.QueryRow(ctx, `SELECT MAX(batch_commit_seq) FROM batch_commit_records WHERE partition_id = $1`, partitionID).Scan(&batchSeq); err != nil {
		t.Fatalf("batch seq: %v", err)
	}
	if _, err := VerifyCommittedBatch(ctx, pool, partitionID, batchSeq); err == nil {
		t.Fatalf("expected verify failure")
	}
}

func TestVerifyCommittedBatch_FailsOnWrongKeySignatureMismatch(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("POSTGRES_DSN not set — skipping DB integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool: %v", err)
	}
	defer pool.Close()

	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	clusterPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 cluster: %v", err)
	}
	_, otherPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 other: %v", err)
	}

	partitionID := int64(9005)
	logicalShardID := make([]byte, 32)

	chaosText := `{"authority":"batch_verify_wrong_key"}`
	chaosPH := sha256.Sum256([]byte(chaosText))
	scopeID := "scope-5"
	rootEpoch := int64(1)
	rootType := "ROOT"
	rootKeyID := prd04KeyID(rootType, scopeID, rootEpoch, rootPub)
	clusterEpoch := int64(1)
	clusterType := "CLUSTER"
	clusterKeyID := prd04KeyID(clusterType, scopeID, clusterEpoch, clusterPub)

	rootRec, err := signedKeyRecord(rootPriv, keyRecordInput{
		KeyID:                  rootKeyID,
		KeyType:                rootType,
		ScopeID:                scopeID,
		AuthorityScope:         "cluster",
		KeyEpoch:               rootEpoch,
		PublicKeyHex:           hex.EncodeToString(rootPub),
		AllowedSigningContexts: []string{"key_record_v1"},
		IssuerKeyID:            rootKeyID,
		Status:                 "ACTIVE",
		SigningContext:         "key_record_v1",
	})
	if err != nil {
		t.Fatalf("root key record: %v", err)
	}
	clusterRec, err := signedKeyRecord(rootPriv, keyRecordInput{
		KeyID:                  clusterKeyID,
		KeyType:                clusterType,
		ScopeID:                scopeID,
		AuthorityScope:         "cluster",
		KeyEpoch:               clusterEpoch,
		PublicKeyHex:           hex.EncodeToString(clusterPub),
		AllowedSigningContexts: []string{BatchCommitSigningContext},
		IssuerKeyID:            rootKeyID,
		Status:                 "ACTIVE",
		SigningContext:         "key_record_v1",
	})
	if err != nil {
		t.Fatalf("cluster key record: %v", err)
	}
	trustText, err := trustSnapshotPayload(scopeID, []string{rootRec, clusterRec})
	if err != nil {
		t.Fatalf("trust payload: %v", err)
	}
	trustPH := sha256.Sum256([]byte(trustText))
	exec := sha256.Sum256(append(chaosPH[:], trustPH[:]...))

	recPayload := []byte("x")
	recPH := sha256.Sum256(recPayload)
	recordID := sha256.Sum256([]byte("record-1"))

	opts := CommitOptions{
		PartitionID:          partitionID,
		PartitionEpoch:       0,
		ExecutionContextHash: exec,
		AuthoritySnapshots: []SnapshotUpsert{
			{
				Type:                 "CONFIG",
				ID:                   "chaos_validation_matrix",
				Version:              "chaos_validation_matrix_v1",
				CanonicalPayloadText: chaosText,
				PayloadHash:          chaosPH,
				Signature:            []byte{0xAA},
			},
			{
				Type:                 "CONFIG",
				ID:                   "trust_snapshot",
				Version:              "v1",
				CanonicalPayloadText: trustText,
				PayloadHash:          trustPH,
				Signature:            []byte{0xAA},
			},
		},
		Records: []RecordDraft{{
			RecordType:            "DECISION",
			RecordVersion:         "v1",
			StageOrder:            3,
			RecordID:              recordID[:],
			LogicalShardID:        logicalShardID,
			CausalParentRefsText:  "{}",
			CanonicalPayloadBytes: recPayload,
			CanonicalPayloadHash:  recPH,
		}},
		PrivateKey: otherPriv,
		KeyID:      clusterKeyID,
		KeyEpoch:   1,
	}
	if err := CommitPartitionBatch(ctx, pool, opts); err != nil {
		t.Fatalf("commit: %v", err)
	}
	var batchSeq int64
	if err := pool.QueryRow(ctx, `SELECT MAX(batch_commit_seq) FROM batch_commit_records WHERE partition_id = $1`, partitionID).Scan(&batchSeq); err != nil {
		t.Fatalf("batch seq: %v", err)
	}
	if _, err := VerifyCommittedBatch(ctx, pool, partitionID, batchSeq); err == nil {
		t.Fatalf("expected verify failure")
	}
}

func TestVerifyCommittedBatch_FailsOnBadKeyRecordSignature(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("POSTGRES_DSN not set — skipping DB integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool: %v", err)
	}
	defer pool.Close()

	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 root: %v", err)
	}
	clusterPub, clusterPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 cluster: %v", err)
	}

	partitionID := int64(9008)
	logicalShardID := make([]byte, 32)

	chaosText := `{"authority":"batch_verify_bad_keyrec_sig"}`
	chaosPH := sha256.Sum256([]byte(chaosText))
	scopeID := "scope-8"
	rootEpoch := int64(1)
	rootType := "ROOT"
	rootKeyID := prd04KeyID(rootType, scopeID, rootEpoch, rootPub)
	clusterEpoch := int64(1)
	clusterType := "CLUSTER"
	clusterKeyID := prd04KeyID(clusterType, scopeID, clusterEpoch, clusterPub)

	rootRec, err := signedKeyRecord(rootPriv, keyRecordInput{
		KeyID:                  rootKeyID,
		KeyType:                rootType,
		ScopeID:                scopeID,
		AuthorityScope:         "cluster",
		KeyEpoch:               rootEpoch,
		PublicKeyHex:           hex.EncodeToString(rootPub),
		AllowedSigningContexts: []string{"key_record_v1"},
		IssuerKeyID:            rootKeyID,
		Status:                 "ACTIVE",
		SigningContext:         "key_record_v1",
	})
	if err != nil {
		t.Fatalf("root key record: %v", err)
	}
	clusterRec, err := signedKeyRecord(rootPriv, keyRecordInput{
		KeyID:                  clusterKeyID,
		KeyType:                clusterType,
		ScopeID:                scopeID,
		AuthorityScope:         "cluster",
		KeyEpoch:               clusterEpoch,
		PublicKeyHex:           hex.EncodeToString(clusterPub),
		AllowedSigningContexts: []string{BatchCommitSigningContext},
		IssuerKeyID:            rootKeyID,
		Status:                 "ACTIVE",
		SigningContext:         "key_record_v1",
	})
	if err != nil {
		t.Fatalf("cluster key record: %v", err)
	}
	clusterRec, err = tamperKeyRecordSignature(clusterRec)
	if err != nil {
		t.Fatalf("tamper cluster key record: %v", err)
	}
	trustText, err := trustSnapshotPayload(scopeID, []string{rootRec, clusterRec})
	if err != nil {
		t.Fatalf("trust payload: %v", err)
	}
	trustPH := sha256.Sum256([]byte(trustText))
	exec := sha256.Sum256(append(chaosPH[:], trustPH[:]...))

	recPayload := []byte("x")
	recPH := sha256.Sum256(recPayload)
	recordID := sha256.Sum256([]byte("record-1"))

	opts := CommitOptions{
		PartitionID:          partitionID,
		PartitionEpoch:       0,
		ExecutionContextHash: exec,
		AuthoritySnapshots: []SnapshotUpsert{
			{
				Type:                 "CONFIG",
				ID:                   "chaos_validation_matrix",
				Version:              "chaos_validation_matrix_v1",
				CanonicalPayloadText: chaosText,
				PayloadHash:          chaosPH,
				Signature:            []byte{0xAA},
			},
			{
				Type:                 "CONFIG",
				ID:                   "trust_snapshot",
				Version:              "v1",
				CanonicalPayloadText: trustText,
				PayloadHash:          trustPH,
				Signature:            []byte{0xAA},
			},
		},
		Records: []RecordDraft{{
			RecordType:            "DECISION",
			RecordVersion:         "v1",
			StageOrder:            3,
			RecordID:              recordID[:],
			LogicalShardID:        logicalShardID,
			CausalParentRefsText:  "{}",
			CanonicalPayloadBytes: recPayload,
			CanonicalPayloadHash:  recPH,
		}},
		PrivateKey: clusterPriv,
		KeyID:      clusterKeyID,
		KeyEpoch:   1,
	}
	if err := CommitPartitionBatch(ctx, pool, opts); err != nil {
		t.Fatalf("commit: %v", err)
	}
	var batchSeq int64
	if err := pool.QueryRow(ctx, `SELECT MAX(batch_commit_seq) FROM batch_commit_records WHERE partition_id = $1`, partitionID).Scan(&batchSeq); err != nil {
		t.Fatalf("batch seq: %v", err)
	}
	if _, err := VerifyCommittedBatch(ctx, pool, partitionID, batchSeq); err == nil {
		t.Fatalf("expected verify failure")
	}
}

func TestVerifyCommittedBatch_FailsOnRevokedKey(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("POSTGRES_DSN not set — skipping DB integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool: %v", err)
	}
	defer pool.Close()

	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	clusterPub, clusterPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 cluster: %v", err)
	}

	partitionID := int64(9006)
	logicalShardID := make([]byte, 32)

	chaosText := `{"authority":"batch_verify_revoked_key"}`
	chaosPH := sha256.Sum256([]byte(chaosText))
	rootEpoch := int64(1)
	rootType := "ROOT"
	scopeID := "scope-6"
	rootKeyID := prd04KeyID(rootType, scopeID, rootEpoch, rootPub)
	clusterEpoch := int64(1)
	clusterType := "CLUSTER"
	clusterKeyID := prd04KeyID(clusterType, scopeID, clusterEpoch, clusterPub)

	rootRec, err := signedKeyRecord(rootPriv, keyRecordInput{
		KeyID:                  rootKeyID,
		KeyType:                rootType,
		ScopeID:                scopeID,
		AuthorityScope:         "cluster",
		KeyEpoch:               rootEpoch,
		PublicKeyHex:           hex.EncodeToString(rootPub),
		AllowedSigningContexts: []string{"key_record_v1"},
		IssuerKeyID:            rootKeyID,
		Status:                 "ACTIVE",
		SigningContext:         "key_record_v1",
	})
	if err != nil {
		t.Fatalf("root key record: %v", err)
	}
	clusterRec, err := signedKeyRecord(rootPriv, keyRecordInput{
		KeyID:                  clusterKeyID,
		KeyType:                clusterType,
		ScopeID:                scopeID,
		AuthorityScope:         "cluster",
		KeyEpoch:               clusterEpoch,
		PublicKeyHex:           hex.EncodeToString(clusterPub),
		AllowedSigningContexts: []string{BatchCommitSigningContext},
		IssuerKeyID:            rootKeyID,
		Status:                 "REVOKED",
		SigningContext:         "key_record_v1",
	})
	if err != nil {
		t.Fatalf("cluster key record: %v", err)
	}
	trustText, err := trustSnapshotPayload(scopeID, []string{rootRec, clusterRec})
	if err != nil {
		t.Fatalf("trust payload: %v", err)
	}
	trustPH := sha256.Sum256([]byte(trustText))
	exec := sha256.Sum256(append(chaosPH[:], trustPH[:]...))

	recPayload := []byte("x")
	recPH := sha256.Sum256(recPayload)
	recordID := sha256.Sum256([]byte("record-1"))

	opts := CommitOptions{
		PartitionID:          partitionID,
		PartitionEpoch:       0,
		ExecutionContextHash: exec,
		AuthoritySnapshots: []SnapshotUpsert{
			{
				Type:                 "CONFIG",
				ID:                   "chaos_validation_matrix",
				Version:              "chaos_validation_matrix_v1",
				CanonicalPayloadText: chaosText,
				PayloadHash:          chaosPH,
				Signature:            []byte{0xAA},
			},
			{
				Type:                 "CONFIG",
				ID:                   "trust_snapshot",
				Version:              "v1",
				CanonicalPayloadText: trustText,
				PayloadHash:          trustPH,
				Signature:            []byte{0xAA},
			},
		},
		Records: []RecordDraft{{
			RecordType:            "DECISION",
			RecordVersion:         "v1",
			StageOrder:            3,
			RecordID:              recordID[:],
			LogicalShardID:        logicalShardID,
			CausalParentRefsText:  "{}",
			CanonicalPayloadBytes: recPayload,
			CanonicalPayloadHash:  recPH,
		}},
		PrivateKey: clusterPriv,
		KeyID:      clusterKeyID,
		KeyEpoch:   1,
	}
	if err := CommitPartitionBatch(ctx, pool, opts); err != nil {
		t.Fatalf("commit: %v", err)
	}
	var batchSeq int64
	if err := pool.QueryRow(ctx, `SELECT MAX(batch_commit_seq) FROM batch_commit_records WHERE partition_id = $1`, partitionID).Scan(&batchSeq); err != nil {
		t.Fatalf("batch seq: %v", err)
	}
	if _, err := VerifyCommittedBatch(ctx, pool, partitionID, batchSeq); err == nil {
		t.Fatalf("expected verify failure")
	}
}

func tamperKeyRecordSignature(raw string) (string, error) {
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return "", err
	}
	m["signature"] = strings.Repeat("00", ed25519.SignatureSize)
	b, err := JCSCanonicalJSONBytes(m)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func TestVerifyCommittedBatch_FailsOnIssuerMismatch(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("POSTGRES_DSN not set — skipping DB integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool: %v", err)
	}
	defer pool.Close()

	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 root: %v", err)
	}
	clusterPub, clusterPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 cluster: %v", err)
	}

	partitionID := int64(9007)
	logicalShardID := make([]byte, 32)

	chaosText := `{"authority":"batch_verify_issuer_mismatch"}`
	chaosPH := sha256.Sum256([]byte(chaosText))
	rootEpoch := int64(1)
	rootType := "ROOT"
	scopeID := "scope-7"
	rootKeyID := prd04KeyID(rootType, scopeID, rootEpoch, rootPub)
	clusterEpoch := int64(1)
	clusterType := "CLUSTER"
	clusterKeyID := prd04KeyID(clusterType, scopeID, clusterEpoch, clusterPub)

	rootRec, err := signedKeyRecord(rootPriv, keyRecordInput{
		KeyID:                  rootKeyID,
		KeyType:                rootType,
		ScopeID:                scopeID,
		AuthorityScope:         "cluster",
		KeyEpoch:               rootEpoch,
		PublicKeyHex:           hex.EncodeToString(rootPub),
		AllowedSigningContexts: []string{"key_record_v1"},
		IssuerKeyID:            rootKeyID,
		Status:                 "ACTIVE",
		SigningContext:         "key_record_v1",
	})
	if err != nil {
		t.Fatalf("root key record: %v", err)
	}
	bogusIssuer := strings.Repeat("00", 32)
	clusterRec, err := signedKeyRecord(rootPriv, keyRecordInput{
		KeyID:                  clusterKeyID,
		KeyType:                clusterType,
		ScopeID:                scopeID,
		AuthorityScope:         "cluster",
		KeyEpoch:               clusterEpoch,
		PublicKeyHex:           hex.EncodeToString(clusterPub),
		AllowedSigningContexts: []string{BatchCommitSigningContext},
		IssuerKeyID:            bogusIssuer,
		Status:                 "ACTIVE",
		SigningContext:         "key_record_v1",
	})
	if err != nil {
		t.Fatalf("cluster key record: %v", err)
	}
	trustText, err := trustSnapshotPayload(scopeID, []string{rootRec, clusterRec})
	if err != nil {
		t.Fatalf("trust payload: %v", err)
	}
	trustPH := sha256.Sum256([]byte(trustText))
	exec := sha256.Sum256(append(chaosPH[:], trustPH[:]...))

	recPayload := []byte("x")
	recPH := sha256.Sum256(recPayload)
	recordID := sha256.Sum256([]byte("record-1"))

	opts := CommitOptions{
		PartitionID:          partitionID,
		PartitionEpoch:       0,
		ExecutionContextHash: exec,
		AuthoritySnapshots: []SnapshotUpsert{
			{
				Type:                 "CONFIG",
				ID:                   "chaos_validation_matrix",
				Version:              "chaos_validation_matrix_v1",
				CanonicalPayloadText: chaosText,
				PayloadHash:          chaosPH,
				Signature:            []byte{0xAA},
			},
			{
				Type:                 "CONFIG",
				ID:                   "trust_snapshot",
				Version:              "v1",
				CanonicalPayloadText: trustText,
				PayloadHash:          trustPH,
				Signature:            []byte{0xAA},
			},
		},
		Records: []RecordDraft{{
			RecordType:            "DECISION",
			RecordVersion:         "v1",
			StageOrder:            3,
			RecordID:              recordID[:],
			LogicalShardID:        logicalShardID,
			CausalParentRefsText:  "{}",
			CanonicalPayloadBytes: recPayload,
			CanonicalPayloadHash:  recPH,
		}},
		PrivateKey: clusterPriv,
		KeyID:      clusterKeyID,
		KeyEpoch:   1,
	}
	if err := CommitPartitionBatch(ctx, pool, opts); err != nil {
		t.Fatalf("commit: %v", err)
	}
	var batchSeq int64
	if err := pool.QueryRow(ctx, `SELECT MAX(batch_commit_seq) FROM batch_commit_records WHERE partition_id = $1`, partitionID).Scan(&batchSeq); err != nil {
		t.Fatalf("batch seq: %v", err)
	}
	if _, err := VerifyCommittedBatch(ctx, pool, partitionID, batchSeq); err == nil {
		t.Fatalf("expected verify failure")
	}
}

func TestVerifyCommittedBatch_FailsOnMalformedTrustObject(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("POSTGRES_DSN not set — skipping DB integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool: %v", err)
	}
	defer pool.Close()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}

	partitionID := int64(9008)
	logicalShardID := make([]byte, 32)

	chaosText := `{"authority":"batch_verify_malformed_trust"}`
	chaosPH := sha256.Sum256([]byte(chaosText))
	trustText := `{"verification_scope_id":"scope-8","key_records":"not-an-array"}`
	trustPH := sha256.Sum256([]byte(trustText))
	exec := sha256.Sum256(append(chaosPH[:], trustPH[:]...))

	recPayload := []byte("x")
	recPH := sha256.Sum256(recPayload)
	recordID := sha256.Sum256([]byte("record-1"))

	opts := CommitOptions{
		PartitionID:          partitionID,
		PartitionEpoch:       0,
		ExecutionContextHash: exec,
		AuthoritySnapshots: []SnapshotUpsert{
			{
				Type:                 "CONFIG",
				ID:                   "chaos_validation_matrix",
				Version:              "chaos_validation_matrix_v1",
				CanonicalPayloadText: chaosText,
				PayloadHash:          chaosPH,
				Signature:            []byte{0xAA},
			},
			{
				Type:                 "CONFIG",
				ID:                   "trust_snapshot",
				Version:              "v1",
				CanonicalPayloadText: trustText,
				PayloadHash:          trustPH,
				Signature:            []byte{0xAA},
			},
		},
		Records: []RecordDraft{{
			RecordType:            "DECISION",
			RecordVersion:         "v1",
			StageOrder:            3,
			RecordID:              recordID[:],
			LogicalShardID:        logicalShardID,
			CausalParentRefsText:  "{}",
			CanonicalPayloadBytes: recPayload,
			CanonicalPayloadHash:  recPH,
		}},
		PrivateKey: priv,
		KeyID:      "00",
		KeyEpoch:   1,
	}
	if err := CommitPartitionBatch(ctx, pool, opts); err != nil {
		t.Fatalf("commit: %v", err)
	}
	var batchSeq int64
	if err := pool.QueryRow(ctx, `SELECT MAX(batch_commit_seq) FROM batch_commit_records WHERE partition_id = $1`, partitionID).Scan(&batchSeq); err != nil {
		t.Fatalf("batch seq: %v", err)
	}
	if _, err := VerifyCommittedBatch(ctx, pool, partitionID, batchSeq); err == nil {
		t.Fatalf("expected verify failure")
	}
}

