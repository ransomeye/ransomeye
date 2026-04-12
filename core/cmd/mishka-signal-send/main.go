// mishka-signal-send: PRD-03/07/08/16 smoke client — mTLS gRPC SendSignal to ransomeye-core.
//
// The emitter Ed25519 key must match an ACTIVE AGENT entry in the committed trust_snapshot
// (emitter_id = first 16 bytes of the public key, lowercase hex) with an allowed signing_context.
//
// Example:
//
//	go run ./core/cmd/mishka-signal-send -addr 127.0.0.1:50051 \
//	  -ca /opt/ransomeye/core/certs/ca-chain.crt -cert /etc/ransomeye/client.crt -key /etc/ransomeye/client.key \
//	  -emitter-key-hex <64-hex-seed>
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"ransomeye/core/internal/gateway"
	"ransomeye/core/internal/netcfg"
	pb "ransomeye/proto/ransomeyepb"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	addr := flag.String("addr", net.JoinHostPort(netcfg.LoopbackHost, "50051"), "core gRPC address")
	caPath := flag.String("ca", "/opt/ransomeye/core/certs/ca-chain.crt", "PEM CA bundle for core TLS")
	certPath := flag.String("cert", "/etc/ransomeye/client.crt", "client certificate (mTLS)")
	keyPath := flag.String("key", "/etc/ransomeye/client.key", "client private key")
	signingCtx := flag.String("signing-context", "ransomeye:v1:telemetry:event", "must match trust_snapshot allowed context")
	nodeMaterial := flag.String("node-material", "mishka-signal-send", "input to SHA-256 for PRD-03 system_id (64 lowercase hex)")
	payloadJSON := flag.String("payload-json", `{"mishka_slice1_smoke":true,"v":1}`, "JSON object (canonicalized server-side; client pre-canonicalizes for stable hashes)")
	emitterSeedHex := flag.String("emitter-key-hex", "", "64-char hex Ed25519 seed for signal signature")
	logicalClock := flag.Uint64("logical-clock", 0, "first signal for a fresh replay cursor must use 0")
	timeout := flag.Duration("timeout", 15*time.Second, "RPC timeout")
	flag.Parse()

	if len(*emitterSeedHex) != ed25519.SeedSize*2 {
		return fmt.Errorf("-emitter-key-hex must be %d hex chars (Ed25519 seed)", ed25519.SeedSize*2)
	}
	seed, err := hex.DecodeString(*emitterSeedHex)
	if err != nil {
		return fmt.Errorf("decode emitter seed: %w", err)
	}
	emitterPriv := ed25519.NewKeyFromSeed(seed)
	emitterPub := emitterPriv.Public().(ed25519.PublicKey)
	emitterIDHex := hex.EncodeToString(emitterPub[:16])

	sumSys := sha256.Sum256([]byte(*nodeMaterial))
	systemIDHex := hex.EncodeToString(sumSys[:])

	boot := make([]byte, 32)
	if _, err := rand.Read(boot); err != nil {
		return fmt.Errorf("boot_session entropy: %w", err)
	}
	bootHex := hex.EncodeToString(boot)

	canonicalPayload, err := gateway.CanonicalizeStrictJSONRFC8785Like([]byte(*payloadJSON))
	if err != nil {
		return fmt.Errorf("canonicalize payload: %w", err)
	}

	ph := sha256.Sum256(canonicalPayload)
	systemBytes := sumSys[:]
	identityBytes := buildIdentityBytesPRD03(systemBytes, 1, pb.EmitterType_EMITTER_TYPE_AGENT, emitterPub[:16])
	pc := sha256.Sum256(append(append([]byte(nil), canonicalPayload...), identityBytes...))
	partitionCtxHex := hex.EncodeToString(pc[:16])
	payloadHashHex := hex.EncodeToString(ph[:])

	req := &pb.SignalEnvelope{
		ProtocolVersion:      1,
		SigningContext:       *signingCtx,
		SystemId:             systemIDHex,
		IdentityVersion:      1,
		EmitterType:          pb.EmitterType_EMITTER_TYPE_AGENT,
		EmitterId:            emitterIDHex,
		BootSessionId:         bootHex,
		LogicalClock:         *logicalClock,
		PartitionContext:     partitionCtxHex,
		PayloadHash:          payloadHashHex,
		CanonicalPayloadJson: canonicalPayload,
	}
	mid, err := gateway.ComputeSignalMessageID(req)
	if err != nil {
		return fmt.Errorf("message_id: %w", err)
	}
	req.MessageId = mid
	sigIn, err := gateway.ComputeSignalSigningInput(req)
	if err != nil {
		return fmt.Errorf("signing input: %w", err)
	}
	req.Signature = ed25519.Sign(emitterPriv, sigIn)

	tlsCfg, err := clientTLS(*caPath, *certPath, *keyPath)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	conn, err := grpc.DialContext(ctx, *addr,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
		grpc.WithBlock(),
	)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	cli := pb.NewRansomEyeServiceClient(conn)
	ack, err := cli.SendSignal(ctx, req)
	if err != nil {
		return fmt.Errorf("SendSignal: %w", err)
	}
	fmt.Printf("SIGNAL_OK accepted=%v server_clock=%d message_id=%s emitter_id=%s\n",
		ack.GetAccepted(), ack.GetServerClock(), req.GetMessageId(), emitterIDHex)
	return nil
}

func buildIdentityBytesPRD03(systemID []byte, identityVersion byte, emitterType pb.EmitterType, emitter16 []byte) []byte {
	out := make([]byte, 0, 32+1+1+16)
	out = append(out, systemID...)
	out = append(out, identityVersion)
	switch emitterType {
	case pb.EmitterType_EMITTER_TYPE_AGENT:
		out = append(out, 0x01)
	case pb.EmitterType_EMITTER_TYPE_PROBE:
		out = append(out, 0x02)
	default:
		out = append(out, 0x00)
	}
	out = append(out, emitter16...)
	return out
}

func clientTLS(caPath, certPath, keyPath string) (*tls.Config, error) {
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("parse CA PEM")
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load client cert: %w", err)
	}
	return &tls.Config{
		RootCAs:      pool,
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		ServerName:   "127.0.0.1",
	}, nil
}
