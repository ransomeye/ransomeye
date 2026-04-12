package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"gopkg.in/yaml.v3"

	pb "ransomeye/proto/ransomeyepb"
)

const (
	canonicalTelemetryV1Size = 153
	payloadVersionV1         = byte(0x01)
	processEventTypeCode     = uint32(1)
	telemetrySigningContext  = "ransomeye:v1:telemetry:event"
	commonConfigPath         = "/etc/ransomeye/config/common.yaml"
	defaultWormPubPath       = "/etc/ransomeye/worm_signing.pub"
)

type config struct {
	addr           string
	caPath         string
	intermediateCA string
	certPath       string
	keyPath        string
	timeout        time.Duration
	attempts       int
	retryDelay     time.Duration
}

type identity struct {
	keypair  tls.Certificate
	leaf     *x509.Certificate
	public   ed25519.PublicKey
	private  ed25519.PrivateKey
	agentID  uuid.UUID
	hostname string
}

type systemIdentityConfig struct {
	Core struct {
		GRPCEndpoint          string `yaml:"grpc_endpoint"`
		ServerCertFingerprint string `yaml:"server_cert_fingerprint"`
	} `yaml:"core"`
	Identity struct {
		NodeID string `yaml:"node_id"`
		Role   string `yaml:"role"`
	} `yaml:"identity"`
	Security struct {
		CACertPath     string `yaml:"ca_cert_path"`
		ClientCertPath string `yaml:"client_cert_path"`
		ClientKeyPath  string `yaml:"client_key_path"`
	} `yaml:"security"`
	Database struct {
		TLSEnforced               bool   `yaml:"tls_enforced"`
		ExpectedServerFingerprint string `yaml:"expected_server_fingerprint"`
	} `yaml:"database"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	cfg := parseFlags()

	id, err := loadIdentity(cfg.certPath, cfg.keyPath)
	if err != nil {
		return err
	}
	systemIdentityHash, err := loadSystemIdentityHash()
	if err != nil {
		return err
	}

	tlsConfig, err := buildTLSConfig(cfg, id.keypair)
	if err != nil {
		return err
	}

	dialCtx, dialCancel := context.WithTimeout(context.Background(), cfg.timeout)
	defer dialCancel()

	conn, err := grpc.DialContext(
		dialCtx,
		cfg.addr,
		grpc.WithBlock(),
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
	)
	if err != nil {
		return fmt.Errorf("dial core: %w", err)
	}
	defer conn.Close()

	client := pb.NewRansomEyeServiceClient(conn)

	bootSessionID := uuid.New()
	bootSessionText := bootSessionID.String()

	handshakeCtx, handshakeCancel := context.WithTimeout(context.Background(), cfg.timeout)
	defer handshakeCancel()

	handshakeResp, err := client.Handshake(handshakeCtx, &pb.HandshakeRequest{
		AgentUuid:           id.agentID.String(),
		Hostname:            id.hostname,
		PrimaryIp:           dialHost(cfg.addr),
		BootSessionId:       bootSessionText,
		LogicalClock:        0,
		AgentVersion:        "tools/test_ingest",
		BinaryHash:          mustHashExecutable(),
		OsType:              runtime.GOOS,
		OsVersion:           runtime.GOARCH,
		AgentProtoVersion:   "v1",
		MinSupportedByAgent: "v1",
	})
	if err != nil {
		return fmt.Errorf("handshake: %w", err)
	}
	if !handshakeResp.GetAccepted() {
		return fmt.Errorf("handshake rejected: %s", handshakeResp.GetRejectReason())
	}
	if handshakeResp.GetSessionToken() == "" {
		return errors.New("handshake returned empty session_token")
	}

	heartbeatClock := int64(1)
	heartbeatCtx, heartbeatCancel := context.WithTimeout(context.Background(), cfg.timeout)
	defer heartbeatCancel()

	heartbeatResp, err := client.SendHeartbeat(heartbeatCtx, &pb.HeartbeatRequest{
		AgentId:        id.agentID.String(),
		SessionToken:   handshakeResp.GetSessionToken(),
		CpuUsagePct:    0,
		RamUsedMb:      0,
		RamTotalMb:     0,
		TopProcesses:   "[]",
		LoadAvg_1M:     0,
		TpmQuote:       nil,
		BinaryHash:     nil,
		LogicalClock:   heartbeatClock,
		WallClockEpoch: time.Now().UTC().Unix(),
		EventDropCount: 0,
		BootSessionId:  bootSessionText,
	})
	if err != nil {
		return fmt.Errorf("heartbeat: %w", err)
	}
	if !heartbeatResp.GetSessionValid() {
		return errors.New("heartbeat returned session_valid=false")
	}

	baseTelemetryClock := uint64(max64(handshakeResp.GetServerClock(), heartbeatResp.GetServerClock()) + 1)
	processPath, err := executablePath()
	if err != nil {
		return err
	}
	processHash := sha256.Sum256([]byte(processPath))
	fileHash := sha256.Sum256([]byte(processPath))
	var networkTuple [16]byte
	copy(networkTuple[:], []byte(dialHost(cfg.addr)))

	fmt.Printf(
		"HANDSHAKE_OK: session_token=%s server_clock=%d\nSESSION_OK: session_valid=%t server_clock=%d\n",
		handshakeResp.GetSessionToken(),
		handshakeResp.GetServerClock(),
		heartbeatResp.GetSessionValid(),
		heartbeatResp.GetServerClock(),
	)

	var lastErr error
	for attempt := 0; attempt < cfg.attempts; attempt++ {
		logicalClock := baseTelemetryClock + uint64(attempt)
		eventID := uuid.New()
		timestamp := time.Now().UTC().Truncate(time.Millisecond)
		payload := buildCanonicalV1(
			logicalClock,
			id.agentID,
			eventID,
			processEventTypeCode,
			uint32(os.Getpid()),
			processHash,
			fileHash,
			networkTuple,
			uint64(timestamp.UnixNano()),
			bootSessionID,
		)

		req := &pb.TelemetryEnvelope{
			MessageId:          eventID.String(),
			AgentId:            id.agentID.String(),
			SigningContext:     telemetrySigningContext,
			Signature:          signTelemetryPayload(id.private, payload[:]),
			SystemIdentityHash: systemIdentityHash,
			BootSessionId:      bootSessionText,
			Payload:            payload[:],
		}

		sendCtx, sendCancel := context.WithTimeout(context.Background(), cfg.timeout)
		ack, sendErr := client.SendTelemetry(sendCtx, req)
		sendCancel()
		if sendErr == nil {
			fmt.Printf(
				"INGEST_OK: accepted=%t server_clock=%d logical_clock=%d timestamp_unix_milli=%d agent_id=%s boot_session_id=%s event_id=%s\n",
				ack.GetAccepted(),
				ack.GetServerClock(),
				logicalClock,
				timestamp.UnixMilli(),
				id.agentID.String(),
				bootSessionText,
				eventID.String(),
			)
			return nil
		}

		lastErr = sendErr
		if status.Code(sendErr) != codes.ResourceExhausted {
			return fmt.Errorf("send telemetry: %w", sendErr)
		}

		fmt.Fprintf(
			os.Stderr,
			"RETRY: attempt=%d logical_clock=%d error=%s\n",
			attempt+1,
			logicalClock,
			sendErr,
		)
		time.Sleep(cfg.retryDelay)
	}

	return fmt.Errorf("send telemetry after %d attempts: %w", cfg.attempts, lastErr)
}

func parseFlags() config {
	var cfg config
	flag.StringVar(&cfg.addr, "addr", "CORE_GRPC_ADDR", "core gRPC address")
	flag.StringVar(&cfg.caPath, "ca", "/etc/ransomeye/certs/ca.crt", "root CA certificate")
	flag.StringVar(&cfg.intermediateCA, "intermediate-ca", "/etc/ransomeye/pki/intermediate_ca.crt", "intermediate CA certificate")
	flag.StringVar(&cfg.certPath, "cert", "/etc/ransomeye/client.crt", "agent certificate path")
	flag.StringVar(&cfg.keyPath, "key", "/etc/ransomeye/client.key", "agent private key path")
	flag.DurationVar(&cfg.timeout, "timeout", 5*time.Second, "per-RPC timeout")
	flag.IntVar(&cfg.attempts, "attempts", 20, "monotonic telemetry attempts on ResourceExhausted")
	flag.DurationVar(&cfg.retryDelay, "retry-delay", 250*time.Millisecond, "delay between monotonic retries")
	flag.Parse()
	return cfg
}

func loadIdentity(certPath, keyPath string) (identity, error) {
	var out identity

	keypair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return out, fmt.Errorf("load client keypair: %w", err)
	}
	if len(keypair.Certificate) == 0 {
		return out, errors.New("client certificate chain is empty")
	}

	leaf, err := x509.ParseCertificate(keypair.Certificate[0])
	if err != nil {
		return out, fmt.Errorf("parse client certificate: %w", err)
	}

	publicKey, ok := leaf.PublicKey.(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return out, errors.New("client certificate must contain an Ed25519 public key")
	}
	privateKey, ok := keypair.PrivateKey.(ed25519.PrivateKey)
	if !ok || len(privateKey) != ed25519.PrivateKeySize {
		return out, errors.New("client private key must be Ed25519")
	}

	agentID, err := uuid.Parse(leaf.Subject.CommonName)
	if err != nil {
		return out, fmt.Errorf("certificate CN must be agent UUID: %w", err)
	}

	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		hostname = "unknown"
	}

	out = identity{
		keypair:  keypair,
		leaf:     leaf,
		public:   append(ed25519.PublicKey(nil), publicKey...),
		private:  append(ed25519.PrivateKey(nil), privateKey...),
		agentID:  agentID,
		hostname: hostname,
	}
	return out, nil
}

func buildTLSConfig(cfg config, keypair tls.Certificate) (*tls.Config, error) {
	caPEM, err := os.ReadFile(cfg.caPath)
	if err != nil {
		return nil, fmt.Errorf("read CA certificate: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("append root CA")
	}

	if cfg.intermediateCA != "" {
		intermediatePEM, err := os.ReadFile(cfg.intermediateCA)
		if err != nil {
			return nil, fmt.Errorf("read intermediate CA: %w", err)
		}
		if !pool.AppendCertsFromPEM(intermediatePEM) {
			return nil, errors.New("append intermediate CA")
		}
	}

	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		RootCAs:      pool,
		ServerName:   dialHost(cfg.addr),
		Certificates: []tls.Certificate{keypair},
	}, nil
}

func buildCanonicalV1(
	logicalClock uint64,
	agentID uuid.UUID,
	eventID uuid.UUID,
	eventTypeCode uint32,
	auxPID uint32,
	processHash [32]byte,
	fileHash [32]byte,
	networkTuple [16]byte,
	timestampUnixNano uint64,
	bootSessionID uuid.UUID,
) [canonicalTelemetryV1Size]byte {
	var out [canonicalTelemetryV1Size]byte
	out[0] = payloadVersionV1
	binary.LittleEndian.PutUint64(out[1:9], logicalClock)
	copy(out[9:25], agentID[:])
	copy(out[25:41], eventID[:])
	binary.LittleEndian.PutUint32(out[41:45], eventTypeCode)
	binary.LittleEndian.PutUint32(out[45:49], auxPID)
	copy(out[49:81], processHash[:])
	copy(out[81:113], fileHash[:])
	copy(out[113:129], networkTuple[:])
	binary.LittleEndian.PutUint64(out[129:137], timestampUnixNano)
	copy(out[137:153], bootSessionID[:])
	return out
}

func executablePath() (string, error) {
	path, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("resolve executable path: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return filepath.Clean(path), nil
	}
	return filepath.Clean(resolved), nil
}

func mustHashExecutable() []byte {
	path, err := executablePath()
	if err != nil {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	sum := sha256.Sum256(data)
	return sum[:]
}

func dialHost(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return "LOOPBACK_IP"
	}
	return host
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func signTelemetryPayload(privateKey ed25519.PrivateKey, payload []byte) []byte {
	payloadHash := sha256.Sum256(payload)
	signingInput := make([]byte, 0, len(telemetrySigningContext)+sha256.Size)
	signingInput = append(signingInput, telemetrySigningContext...)
	signingInput = append(signingInput, payloadHash[:]...)
	return ed25519.Sign(privateKey, signingInput)
}

func loadSystemIdentityHash() (string, error) {
	configPath := commonConfigPath
	raw, err := os.ReadFile(configPath)
	if err != nil && strings.TrimSpace(os.Getenv("RANSOMEYE_DEV_MODE")) == "true" {
		configPath = "configs/common.yaml"
		raw, err = os.ReadFile(configPath)
	}
	if err != nil {
		return "", fmt.Errorf("read common config: %w", err)
	}

	var cfg systemIdentityConfig
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return "", fmt.Errorf("parse common config: %w", err)
	}
	canonicalConfigBytes, err := canonicalCommonConfigBytes(cfg)
	if err != nil {
		return "", err
	}

	rootCAPEM, err := os.ReadFile(strings.TrimSpace(cfg.Security.CACertPath))
	if err != nil {
		return "", fmt.Errorf("read root CA: %w", err)
	}
	rootCABlock, _ := pem.Decode(rootCAPEM)
	if rootCABlock == nil {
		return "", errors.New("parse root CA: no PEM block")
	}
	rootCACert, err := x509.ParseCertificate(rootCABlock.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse root CA: %w", err)
	}
	rootFingerprint := sha256.Sum256(rootCACert.Raw)

	dbFingerprint, err := hex.DecodeString(strings.ToLower(strings.TrimSpace(cfg.Database.ExpectedServerFingerprint)))
	if err != nil {
		return "", fmt.Errorf("decode database fingerprint: %w", err)
	}
	wormPublicKey, err := os.ReadFile(defaultWormPubPath)
	if err != nil {
		return "", fmt.Errorf("read WORM public key: %w", err)
	}
	if len(wormPublicKey) != ed25519.PublicKeySize {
		return "", fmt.Errorf("invalid WORM public key length: %d", len(wormPublicKey))
	}

	identityMaterial := make([]byte, 0, len(canonicalConfigBytes)+len(rootFingerprint)+len(dbFingerprint)+len(wormPublicKey))
	identityMaterial = append(identityMaterial, canonicalConfigBytes...)
	identityMaterial = append(identityMaterial, rootFingerprint[:]...)
	identityMaterial = append(identityMaterial, dbFingerprint...)
	identityMaterial = append(identityMaterial, wormPublicKey...)
	systemIdentityHash := sha256.Sum256(identityMaterial)
	return hex.EncodeToString(systemIdentityHash[:]), nil
}

func canonicalCommonConfigBytes(cfg systemIdentityConfig) ([]byte, error) {
	endpoint, err := json.Marshal(strings.TrimSpace(cfg.Core.GRPCEndpoint))
	if err != nil {
		return nil, fmt.Errorf("json core.grpc_endpoint: %w", err)
	}
	fingerprint, err := json.Marshal(strings.ToLower(strings.TrimSpace(cfg.Core.ServerCertFingerprint)))
	if err != nil {
		return nil, fmt.Errorf("json core.server_cert_fingerprint: %w", err)
	}
	nodeID, err := json.Marshal(normalizeUUID(cfg.Identity.NodeID))
	if err != nil {
		return nil, fmt.Errorf("json identity.node_id: %w", err)
	}
	role, err := json.Marshal(strings.ToLower(strings.TrimSpace(cfg.Identity.Role)))
	if err != nil {
		return nil, fmt.Errorf("json identity.role: %w", err)
	}
	caCert, err := json.Marshal(strings.TrimSpace(cfg.Security.CACertPath))
	if err != nil {
		return nil, fmt.Errorf("json security.ca_cert_path: %w", err)
	}
	clientCert, err := json.Marshal(strings.TrimSpace(cfg.Security.ClientCertPath))
	if err != nil {
		return nil, fmt.Errorf("json security.client_cert_path: %w", err)
	}
	clientKey, err := json.Marshal(strings.TrimSpace(cfg.Security.ClientKeyPath))
	if err != nil {
		return nil, fmt.Errorf("json security.client_key_path: %w", err)
	}
	dbTLS, err := json.Marshal(cfg.Database.TLSEnforced)
	if err != nil {
		return nil, fmt.Errorf("json database.tls_enforced: %w", err)
	}
	dbFingerprint, err := json.Marshal(strings.ToLower(strings.TrimSpace(cfg.Database.ExpectedServerFingerprint)))
	if err != nil {
		return nil, fmt.Errorf("json database.expected_server_fingerprint: %w", err)
	}

	out := fmt.Sprintf(
		"{\"core\":{\"grpc_endpoint\":%s,\"server_cert_fingerprint\":%s},\"database\":{\"expected_server_fingerprint\":%s,\"tls_enforced\":%s},\"identity\":{\"node_id\":%s,\"role\":%s},\"security\":{\"ca_cert_path\":%s,\"client_cert_path\":%s,\"client_key_path\":%s}}",
		endpoint,
		fingerprint,
		dbFingerprint,
		dbTLS,
		nodeID,
		role,
		caCert,
		clientCert,
		clientKey,
	)
	return []byte(out), nil
}

func normalizeUUID(raw string) string {
	parsed, err := uuid.Parse(strings.TrimSpace(raw))
	if err != nil {
		return strings.TrimSpace(raw)
	}
	return parsed.String()
}
