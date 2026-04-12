// mishka-enforcement-tether: PRD-12 loopback enforcement stream — holds ReceiveActions open so
// core registers the agent with ActionDispatcher (SOC: GET /api/v1/enforcement/registered-agents).
//
// Client TLS certificate must include URI SAN: urn:ransomeye:agent:<uuid> (same as other agents).
//
// Example:
//
//	go run ./core/cmd/mishka-enforcement-tether \
//	  -addr CORE_GRPC_ADDR \
//	  -ca /opt/ransomeye/core/certs/ca-chain.crt \
//	  -cert /etc/ransomeye/client.crt -key /etc/ransomeye/client.key
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"ransomeye/core/internal/netcfg"
	pb "ransomeye/proto/ransomeyepb"
)

func main() {
	log.SetFlags(0)
	if err := run(); err != nil {
		log.Println(err)
		os.Exit(1)
	}
}

func run() error {
	addr := flag.String("addr", net.JoinHostPort(netcfg.LoopbackHost, "50051"), "core gRPC address")
	caPath := flag.String("ca", "/opt/ransomeye/core/certs/ca-chain.crt", "PEM CA bundle for core TLS")
	certPath := flag.String("cert", "/etc/ransomeye/client.crt", "client certificate (mTLS, must carry urn:ransomeye:agent:… SAN)")
	keyPath := flag.String("key", "/etc/ransomeye/client.key", "client private key")
	dialTimeout := flag.Duration("dial-timeout", 15*time.Second, "dial timeout")
	recvTimeout := flag.Duration("recv-timeout", 0, "if >0, exit after this long with success (smoke test); 0 = run until signal")
	flag.Parse()

	tlsCfg, err := clientTLS(*caPath, *certPath, *keyPath)
	if err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	dialCtx, dialCancel := context.WithTimeout(ctx, *dialTimeout)
	defer dialCancel()

	conn, err := grpc.DialContext(dialCtx, *addr,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
		grpc.WithBlock(),
	)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	streamCtx := ctx
	var streamCancel context.CancelFunc
	if *recvTimeout > 0 {
		streamCtx, streamCancel = context.WithTimeout(ctx, *recvTimeout)
		defer streamCancel()
	}

	cli := pb.NewRansomEyeServiceClient(conn)
	stream, err := cli.ReceiveActions(streamCtx, &pb.ActionStreamRequest{})
	if err != nil {
		return fmt.Errorf("ReceiveActions: %w", err)
	}

	log.Printf("[tether] ReceiveActions stream active; core should list this agent on SOC GET /api/v1/enforcement/registered-agents")

	recvErr := make(chan error, 1)
	go func() {
		for {
			msg, err := stream.Recv()
			if err != nil {
				recvErr <- err
				return
			}
			if msg != nil {
				log.Printf("[tether] action recv type=%v action_id=%q detection_id=%q logical_clock=%d",
					msg.GetActionType(), msg.GetActionId(), msg.GetDetectionId(), msg.GetLogicalClock())
			}
		}
	}()

	select {
	case <-ctx.Done():
		log.Printf("[tether] shutdown: %v", context.Cause(ctx))
		return nil
	case err := <-recvErr:
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			log.Printf("[tether] stream ended (%v)", err)
			return nil
		}
		return fmt.Errorf("stream recv: %w", err)
	}
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
		ServerName:   netcfg.LoopbackHost,
	}, nil
}
