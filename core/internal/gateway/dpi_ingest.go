package gateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"

	"ransomeye/core/internal/health"
	"ransomeye/core/internal/ingest"
	"ransomeye/core/internal/metrics"
	dpieventpb "ransomeye/proto/dpieventpb"
)

const (
	defaultDPISocketPath      = "/tmp/ransomeye-dpi.sock"
	maxDPITransportFrameBytes = 2048
	dpiFrameLengthBytes       = 4
	DPI_DROP_THRESHOLD_NUM    = 1
	DPI_DROP_THRESHOLD_DEN    = 1000
)

var dpiClassificationNamespace = uuid.MustParse("ae8dc9ae-86cb-4f70-b8c3-fd7d0c56f8bf")

type DropStats struct {
	TotalDropped uint64
}

type DPIIngestOptions struct {
	SocketPath    string
	PublicKeyPath string
	AgentID       string
	TenantID      string
	Hostname      string
	PrimaryIP     string
	DBPool        *pgxpool.Pool
	Scheduler     ingest.VerifiedTelemetryEnqueuer
}

type DPIIngest struct {
	socketPath string
	dbPool     *pgxpool.Pool
	scheduler  ingest.VerifiedTelemetryEnqueuer

	publicKey     ed25519.PublicKey
	agentID       uuid.UUID
	tenantID      uuid.UUID
	bootSessionID uuid.UUID
	hostname      string
	primaryIP     string
	stats         DropStats

	conn      *net.UnixConn
	closeOnce sync.Once
}

func NewDPIIngest(opts DPIIngestOptions) (*DPIIngest, error) {
	if opts.DBPool == nil {
		return nil, errors.New("dpi ingest requires db pool")
	}
	if opts.Scheduler == nil {
		return nil, errors.New("dpi ingest requires scheduler")
	}

	socketPath := strings.TrimSpace(opts.SocketPath)
	if socketPath == "" {
		socketPath = defaultDPISocketPath
	}

	agentID, err := uuid.Parse(strings.TrimSpace(opts.AgentID))
	if err != nil {
		return nil, fmt.Errorf("parse dpi agent id: %w", err)
	}
	tenantID, err := uuid.Parse(strings.TrimSpace(opts.TenantID))
	if err != nil {
		return nil, fmt.Errorf("parse dpi tenant id: %w", err)
	}

	hostname := strings.TrimSpace(opts.Hostname)
	if hostname == "" {
		hostname, err = os.Hostname()
		if err != nil {
			return nil, fmt.Errorf("resolve dpi hostname: %w", err)
		}
	}

	primaryIP := strings.TrimSpace(opts.PrimaryIP)
	if primaryIP == "" {
		return nil, fmt.Errorf("PrimaryIP is required")
	}
	if net.ParseIP(primaryIP) == nil {
		return nil, fmt.Errorf("invalid PrimaryIP: %s", opts.PrimaryIP)
	}

	pub, err := loadDPIPublicKey(strings.TrimSpace(opts.PublicKeyPath))
	if err != nil {
		return nil, err
	}

	return &DPIIngest{
		socketPath:    socketPath,
		dbPool:        opts.DBPool,
		scheduler:     opts.Scheduler,
		publicKey:     pub,
		agentID:       agentID,
		tenantID:      tenantID,
		bootSessionID: uuid.New(),
		hostname:      hostname,
		primaryIP:     primaryIP,
	}, nil
}

func (d *DPIIngest) Serve(ctx context.Context) error {
	if d == nil {
		return errors.New("nil dpi ingest")
	}
	if err := d.ensureAgentSession(ctx); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(d.socketPath), 0o755); err != nil {
		return fmt.Errorf("prepare dpi socket dir: %w", err)
	}
	if err := os.Remove(d.socketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove stale dpi socket: %w", err)
	}

	addr := &net.UnixAddr{Name: d.socketPath, Net: "unixgram"}
	conn, err := net.ListenUnixgram("unixgram", addr)
	if err != nil {
		return fmt.Errorf("listen dpi unixgram %q: %w", d.socketPath, err)
	}
	d.conn = conn
	if err := os.Chmod(d.socketPath, 0o600); err != nil {
		_ = conn.Close()
		return fmt.Errorf("chmod dpi socket: %w", err)
	}

	buf := make([]byte, maxDPITransportFrameBytes)
	for {
		if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			return fmt.Errorf("set dpi socket deadline: %w", err)
		}
		n, _, err := conn.ReadFromUnix(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("read dpi socket: %w", err)
		}

		if err := d.handleFrame(buf[:n]); err != nil {
			log.Printf("[WARN] DPI_INGEST_REJECTED err=%v", err)
		}
	}
}

func (d *DPIIngest) Close() error {
	if d == nil {
		return nil
	}
	var out error
	d.closeOnce.Do(func() {
		if d.conn != nil {
			out = d.conn.Close()
		}
		if err := os.Remove(d.socketPath); err != nil && !errors.Is(err, os.ErrNotExist) && out == nil {
			out = err
		}
	})
	return out
}

func (d *DPIIngest) handleFrame(frame []byte) error {
	envelope, event, frameHash, signature, err := d.verifyTransportFrame(frame)
	if err != nil {
		return err
	}
	d.accountProbeDrops(envelope.GetDroppedBefore(), event.GetSeq())

	verified, err := d.verifiedTelemetryFromEvent(event, frameHash, signature, envelope.GetDroppedBefore())
	if err != nil {
		return err
	}
	return queueAdmissionError(ingest.EnqueueVerifiedTelemetry(d.scheduler, verified))
}

func (d *DPIIngest) verifyTransportFrame(frame []byte) (*dpieventpb.DpiEnvelope, *dpieventpb.DpiEvent, [32]byte, []byte, error) {
	var zeroHash [32]byte
	if len(frame) < dpiFrameLengthBytes+sha256.Size+ed25519.SignatureSize {
		return nil, nil, zeroHash, nil, errors.New("dpi frame truncated")
	}

	payloadLen := binary.BigEndian.Uint32(frame[:dpiFrameLengthBytes])
	expectedLen := dpiFrameLengthBytes + int(payloadLen) + sha256.Size + ed25519.SignatureSize
	if expectedLen != len(frame) {
		return nil, nil, zeroHash, nil, errors.New("dpi frame length mismatch")
	}
	if payloadLen == 0 {
		return nil, nil, zeroHash, nil, errors.New("dpi frame missing payload")
	}

	payloadStart := dpiFrameLengthBytes
	payloadEnd := payloadStart + int(payloadLen)
	hashStart := payloadEnd
	hashEnd := hashStart + sha256.Size

	payload := frame[payloadStart:payloadEnd]
	copy(zeroHash[:], frame[hashStart:hashEnd])
	signature := append([]byte(nil), frame[hashEnd:]...)

	computed := sha256.Sum256(payload)
	if computed != zeroHash {
		return nil, nil, [32]byte{}, nil, errors.New("dpi payload hash mismatch")
	}
	if !ed25519.Verify(d.publicKey, zeroHash[:], signature) {
		return nil, nil, [32]byte{}, nil, errors.New("dpi signature verification failed")
	}

	var envelope dpieventpb.DpiEnvelope
	if err := proto.Unmarshal(payload, &envelope); err != nil {
		return nil, nil, [32]byte{}, nil, fmt.Errorf("dpi envelope decode: %w", err)
	}
	if len(envelope.GetPayload()) == 0 {
		return nil, nil, [32]byte{}, nil, errors.New("dpi envelope missing payload")
	}
	canonicalEnvelope, err := proto.MarshalOptions{Deterministic: true}.Marshal(&envelope)
	if err != nil {
		return nil, nil, [32]byte{}, nil, fmt.Errorf("dpi envelope canonicalize: %w", err)
	}
	if !bytes.Equal(canonicalEnvelope, payload) {
		return nil, nil, [32]byte{}, nil, errors.New("dpi envelope is not canonical deterministic protobuf")
	}

	var event dpieventpb.DpiEvent
	if err := proto.Unmarshal(envelope.GetPayload(), &event); err != nil {
		return nil, nil, [32]byte{}, nil, fmt.Errorf("dpi event decode: %w", err)
	}
	if len(event.GetPayloadHash()) != sha256.Size {
		return nil, nil, [32]byte{}, nil, errors.New("dpi payload_hash must be 32 bytes")
	}
	if event.GetSeq() != envelope.GetSeq() {
		return nil, nil, [32]byte{}, nil, errors.New("dpi envelope seq mismatch")
	}
	canonicalEvent, err := proto.MarshalOptions{Deterministic: true}.Marshal(&event)
	if err != nil {
		return nil, nil, [32]byte{}, nil, fmt.Errorf("dpi event canonicalize: %w", err)
	}
	if !bytes.Equal(canonicalEvent, envelope.GetPayload()) {
		return nil, nil, [32]byte{}, nil, errors.New("dpi event is not canonical deterministic protobuf")
	}

	return &envelope, &event, zeroHash, signature, nil
}

func (d *DPIIngest) verifiedTelemetryFromEvent(
	event *dpieventpb.DpiEvent,
	frameHash [32]byte,
	signature []byte,
	droppedBefore uint64,
) (*ingest.VerifiedTelemetry, error) {
	if event == nil {
		return nil, errors.New("nil dpi event")
	}
	if event.Seq > uint64(^uint64(0)>>1) {
		return nil, errors.New("dpi seq exceeds signed logical clock range")
	}

	var payloadHash [32]byte
	copy(payloadHash[:], event.GetPayloadHash())
	networkTuple := composeDPINetworkTuple(event.GetFlowHash(), event.GetConfidenceFp(), event.GetClassificationId())

	canonical, err := ingest.BuildCanonicalV1(
		event.GetSeq(),
		d.agentID,
		classificationUUID(event.GetClassificationId()),
		ingest.EventTypeCodeNetwork,
		0,
		payloadHash,
		frameHash,
		networkTuple,
		uint64(time.Now().UTC().UnixNano()),
		uuidToBytes16(d.bootSessionID),
	)
	if err != nil {
		return nil, err
	}

	payload := append(make([]byte, 0, len(canonical)), canonical[:]...)
	sigCopy := append(make([]byte, 0, len(signature)), signature...)
	ts := float64(binary.LittleEndian.Uint64(canonical[129:137])) / 1e9

	return &ingest.VerifiedTelemetry{
		Payload:        payload,
		AgentSignature: sigCopy,
		AgentIDStr:     d.agentID.String(),
		EventType:      "NETWORK_EVENT",
		SourceType:     "dpi",
		TimestampUnix:  ts,
		LogicalClock:   int64(event.GetSeq()),
		DroppedCount:   droppedBefore,
	}, nil

}

func (d *DPIIngest) accountProbeDrops(droppedBefore uint64, seq uint64) {
	metrics.IncDPIPacketsTotal(droppedBefore + 1)
	if droppedBefore == 0 {
		return
	}

	d.stats.TotalDropped += droppedBefore
	metrics.IncDPIPacketsDropped(droppedBefore)
	metrics.IncEventsDropped(droppedBefore)

	log.Printf(
		"[ALERT] DPI_PACKET_DROPS logical_clock=%d dropped_before=%d total_dropped=%d",
		seq,
		droppedBefore,
		d.stats.TotalDropped,
	)

	total, dropped := metrics.DPIDropSnapshot()
	ratioPPM := metrics.DPIDropRatio()
	if metrics.DPIThresholdExceeded(dropped, total, DPI_DROP_THRESHOLD_NUM, DPI_DROP_THRESHOLD_DEN) {
		log.Printf(
			"[ALERT] DPI_DROP_RATE_EXCEEDED total_packets=%d dropped_packets=%d drop_ratio_ppm=%d",
			total,
			dropped,
			ratioPPM,
		)
		health.MarkSystemDegraded("DPI_DROPS_EXCEEDED")
	}
}

func (d *DPIIngest) ensureAgentSession(ctx context.Context) error {
	if d.dbPool == nil {
		return errors.New("dpi ingest requires db pool")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	const upsertAgent = `
INSERT INTO agent_sessions (
    agent_id, tenant_id, boot_session_id, hostname, primary_ip,
    agent_type, agent_version, last_heartbeat, status, lamport_clock,
    last_seen_ip
) VALUES (
    $1::uuid, $2::uuid, $3::uuid, $4::text, $5::inet,
    'dpi', 'V0.0', NOW(), 'ACTIVE', 0,
    $5::inet
)
ON CONFLICT (agent_id) DO UPDATE SET
    tenant_id = EXCLUDED.tenant_id,
    boot_session_id = EXCLUDED.boot_session_id,
    hostname = EXCLUDED.hostname,
    primary_ip = EXCLUDED.primary_ip,
    agent_type = 'dpi',
    last_heartbeat = NOW(),
    status = 'ACTIVE',
    last_seen_ip = EXCLUDED.primary_ip,
    updated_at = NOW()
`
	if _, err := d.dbPool.Exec(ctx, upsertAgent, d.agentID, d.tenantID, d.bootSessionID, d.hostname, d.primaryIP); err != nil {
		return fmt.Errorf("upsert dpi agent session: %w", err)
	}

	const upsertBoot = `
INSERT INTO boot_session_id_history (
    agent_id, tenant_id, boot_session_id, first_seen_ip
) VALUES (
    $1::uuid, $2::uuid, $3::uuid, $4::inet
)
ON CONFLICT (agent_id, boot_session_id) DO NOTHING
`
	if _, err := d.dbPool.Exec(ctx, upsertBoot, d.agentID, d.tenantID, d.bootSessionID, d.primaryIP); err != nil {
		return fmt.Errorf("upsert dpi boot session history: %w", err)
	}

	return nil
}

func loadDPIPublicKey(path string) (ed25519.PublicKey, error) {
	if path == "" {
		return nil, errors.New("dpi public key path is required")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read dpi public key: %w", err)
	}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed != "" && len(trimmed) == hex.EncodedLen(ed25519.PublicKeySize) {
		decoded, err := hex.DecodeString(trimmed)
		if err != nil {
			return nil, fmt.Errorf("decode dpi public key hex: %w", err)
		}
		raw = decoded
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("dpi public key length must be %d bytes", ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(append([]byte(nil), raw...)), nil
}

func classificationUUID(classificationID uint32) uuid.UUID {
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], classificationID)
	return uuid.NewSHA1(dpiClassificationNamespace, raw[:])
}

func composeDPINetworkTuple(flowHash uint64, confidenceFP uint32, classificationID uint32) [16]byte {
	var tuple [16]byte
	binary.LittleEndian.PutUint64(tuple[0:8], flowHash)
	binary.LittleEndian.PutUint32(tuple[8:12], confidenceFP)
	binary.LittleEndian.PutUint32(tuple[12:16], classificationID)
	return tuple
}

func uuidToBytes16(id uuid.UUID) [16]byte {
	var out [16]byte
	copy(out[:], id[:])
	return out
}
