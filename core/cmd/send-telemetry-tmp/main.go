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
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	"ransomeye/core/internal/config"
	"ransomeye/core/internal/ingest"
	"ransomeye/core/internal/integrity"
	"ransomeye/core/internal/netcfg"
	pb "ransomeye/proto/ransomeyepb"
)

var payloadsHex = []string{
	"01010000000000000011111111111141118111111111111111f469f433a8bb46c7ab349a7bf4770dd2010000008601000098d7003dafffc35faef60f76a6be49850dfce98a466f7e77f550e64b0332ed209a2d15e7bc35f978657919467979fe6295011f48dc872b5bee0c0d24a3b3e072adfd75ef104ec48e570dbf82da7cba4e487877ed12739f1822222222222242228222222222222222",
	"01020000000000000011111111111141118111111111111111dfe7b93aa59447628ea1983aa645354c02000000390b0000373b5e6c57c4ed3b97599bcf323add67f0d4d5b9990c0d885cdb4a1063317acddf3c15bae4974031698b18474595e7e6b8ca06351236b347c9ba4b09bc5d21a2a625ee794d8d4ce2e1c3f7a4d009d64a88ba86ed12739f1822222222222242228222222222222222",
	"01030000000000000011111111111141118111111111111111b12dc71748494d3f85ff6c24225f638903000000ac0200005f5a03855053117d115955fd26d4be200b5b41667d3fab6f1f91fcd7c5385008e77c6d8d7fe423b33699bce72655aa5e6b4969d2f416fc56042c9668710bf7702ff0919afaf2cd6fdcb1e0d22997904ac8fc95ed12739f1822222222222242228222222222222222",
	"01040000000000000011111111111141118111111111111111e05b73699eb4442b880e303aee6d641804000000480f0000898544ec694e041f288e49a4652969d0ad297b247e1b889155322901e3d0c062a5df4f23a92a448ad42c1cc9ca07cf968afb74477f3ef9af6822cc0818d653d5ecb9a3627e76b41dcd2ebf95401e842d083fa5ed12739f1822222222222242228222222222222222",
	"01050000000000000011111111111141118111111111111111da97f8d94e0441c7ac8fd7055109170905000000a40700000af80273d54182b5488a5b7c32aee10306637b1cb978c64899b02c98edcfd5263cf0f289b2042c2d70f015b985c2850a63dcc0d9d40462056c030576423b8c55727aecc621eaf3fa296ab611114a060e4881b4ed12739f1822222222222242228222222222222222",
}

const telemetrySigningContext = "ransomeye:v1:telemetry:event"

type eventResult struct {
	Index           int    `json:"index"`
	LogicalClock    uint64 `json:"logical_clock"`
	EventID         string `json:"event_id"`
	PayloadSHA256   string `json:"payload_sha256"`
	Accepted        bool   `json:"accepted"`
	ServerClock     int64  `json:"server_clock"`
	BootSessionID   string `json:"boot_session_id"`
	AgentID         string `json:"agent_id"`
	ResponseErrText string `json:"response_error,omitempty"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	var (
		addr        string
		caPath      string
		certPath    string
		keyPath     string
		timeout     time.Duration
		maxAttempts int
		retryDelay  time.Duration
		clockOffset uint64
	)

	flag.StringVar(&addr, "addr", net.JoinHostPort(netcfg.LoopbackHost, "50051"), "core gRPC address")
	flag.StringVar(&caPath, "ca", "/opt/ransomeye/core/certs/ca-chain.crt", "CA chain PEM path (full chain)")
	flag.StringVar(&certPath, "cert", "/etc/ransomeye/client.crt", "client certificate path")
	flag.StringVar(&keyPath, "key", "/etc/ransomeye/client.key", "client private key path")
	flag.DurationVar(&timeout, "timeout", 10*time.Second, "per-RPC timeout")
	flag.IntVar(&maxAttempts, "attempts", 50, "max attempts per payload on ResourceExhausted")
	flag.DurationVar(&retryDelay, "retry-delay", 50*time.Millisecond, "delay between ResourceExhausted retries")
	flag.Uint64Var(&clockOffset, "clock-offset", 0, "logical clock offset applied to every payload before signing")
	flag.Parse()

	clientTLS, publicKey, privateKey, err := loadClientIdentity(certPath, keyPath, caPath)
	if err != nil {
		return err
	}
	systemIdentityHash, err := loadSystemIdentityHash()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(
		ctx,
		addr,
		grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)),
		grpc.WithBlock(),
	)
	if err != nil {
		return fmt.Errorf("dial core: %w", err)
	}
	defer conn.Close()

	client := pb.NewRansomEyeServiceClient(conn)
	results := make([]eventResult, 0, len(payloadsHex))
	for idx, payloadHex := range payloadsHex {
		payload, err := hex.DecodeString(payloadHex)
		if err != nil {
			return fmt.Errorf("decode payload %d: %w", idx+1, err)
		}
		if clockOffset != 0 {
			current := binary.LittleEndian.Uint64(payload[1:9])
			binary.LittleEndian.PutUint64(payload[1:9], current+clockOffset)
		}
		view, err := ingest.ParseTelemetryV1(payload)
		if err != nil {
			return fmt.Errorf("parse payload %d: %w", idx+1, err)
		}
		if !publicKeysEqual(publicKey, privateKey.Public().(ed25519.PublicKey)) {
			// This should never happen for the installed validation identity.
			return errors.New("client key public component mismatch")
		}

		payloadHash := sha256.Sum256(payload)
		signingInput := make([]byte, 0, len(telemetrySigningContext)+sha256.Size)
		signingInput = append(signingInput, telemetrySigningContext...)
		signingInput = append(signingInput, payloadHash[:]...)
		sig := ed25519.Sign(privateKey, signingInput)
		req := &pb.TelemetryEnvelope{
			MessageId:          uuid.NewString(),
			SigningContext:     telemetrySigningContext,
			Signature:          sig,
			SystemIdentityHash: systemIdentityHash,
			BootSessionId:      mustUUIDString(view.BootSessionID),
			Payload:            payload,
		}

		sum := sha256.Sum256(payload)
		item := eventResult{
			Index:         idx + 1,
			LogicalClock:  view.LogicalClock,
			EventID:       view.EventID.String(),
			PayloadSHA256: hex.EncodeToString(sum[:]),
			BootSessionID: mustUUIDString(view.BootSessionID),
			AgentID:       view.AgentID.String(),
		}

		var ack *pb.TelemetryAck
		var callErr error
		for attempt := 1; attempt <= maxAttempts; attempt++ {
			callCtx, callCancel := context.WithTimeout(context.Background(), timeout)
			ack, callErr = client.SendTelemetry(callCtx, req)
			callCancel()
			if callErr == nil {
				break
			}
			if status.Code(callErr) != codes.ResourceExhausted || attempt == maxAttempts {
				break
			}
			time.Sleep(retryDelay)
		}
		if callErr != nil {
			item.ResponseErrText = callErr.Error()
			results = append(results, item)
			break
		}

		item.Accepted = ack.GetAccepted()
		item.ServerClock = ack.GetServerClock()
		results = append(results, item)
		if !ack.GetAccepted() {
			break
		}
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(map[string]any{
		"addr":    addr,
		"results": results,
	})
}

func loadClientIdentity(certPath, keyPath, caPath string) (*tls.Config, ed25519.PublicKey, ed25519.PrivateKey, error) {
	keypair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("load client keypair: %w", err)
	}
	if len(keypair.Certificate) == 0 {
		return nil, nil, nil, errors.New("client keypair has no certificate")
	}
	leaf, err := x509.ParseCertificate(keypair.Certificate[0])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse client leaf: %w", err)
	}
	pub, ok := leaf.PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, nil, nil, errors.New("client certificate is not Ed25519")
	}
	priv, ok := keypair.PrivateKey.(ed25519.PrivateKey)
	if !ok {
		return nil, nil, nil, errors.New("client private key is not Ed25519")
	}
	if !publicKeysEqual(pub, priv.Public().(ed25519.PublicKey)) {
		return nil, nil, nil, errors.New("client cert/key public key mismatch")
	}

	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, nil, nil, errors.New("parse CA PEM")
	}

	tlsCfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		RootCAs:      pool,
		Certificates: []tls.Certificate{keypair},
		ServerName:   netcfg.LoopbackHost,
	}
	return tlsCfg, append(ed25519.PublicKey(nil), pub...), priv, nil
}

func publicKeysEqual(a, b ed25519.PublicKey) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func mustUUIDString(in [16]byte) string {
	value, err := uuid.FromBytes(in[:])
	if err != nil {
		return hex.EncodeToString(in[:])
	}
	return value.String()
}

func loadSystemIdentityHash() (string, error) {
	cfg, err := config.LoadVerifiedCommonConfig("", config.IntermediateCACertPath)
	if err != nil {
		return "", fmt.Errorf("load verified common config: %w", err)
	}
	canonicalConfigBytes, err := config.CanonicalJSONBytes(cfg)
	if err != nil {
		return "", fmt.Errorf("canonical common config: %w", err)
	}

	rootCAPEM, err := os.ReadFile(cfg.Security.CACertPath)
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

	dbFingerprint, err := hex.DecodeString(strings.TrimSpace(cfg.Database.ExpectedServerFingerprint))
	if err != nil {
		return "", fmt.Errorf("decode database fingerprint: %w", err)
	}
	wormPublicKey, err := os.ReadFile(integrity.DefaultWormPubPath)
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
