package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"ransomeye/core/internal/enforcement"
	"ransomeye/core/internal/events"
	"ransomeye/core/internal/identity"
	"ransomeye/core/internal/ingest"
	pb "ransomeye/proto/ransomeyepb"
)

const (
	defaultClientCAChain = "/opt/ransomeye/core/certs/ca-chain.crt"
	defaultIntCA         = "" // chain PEM includes intermediate; optional second CA path unused by default
	defaultServerCR      = "/etc/ransomeye/server.crt"
	defaultServerK       = "/etc/ransomeye/server.key"
)

type ServerOptions struct {
	Addr string

	RootCAPath  string
	IntCAPath   string
	ServerCert  string
	ServerKey   string
	TelemetryCh chan *ingest.VerifiedTelemetry
	Handlers    *Handlers

	QueueDepth int
}

type Server struct {
	addr string

	grpcServer *grpc.Server
	lis        net.Listener

	handlers *Handlers
}

func NewServer(opts ServerOptions) (*Server, error) {
	addr := strings.TrimSpace(opts.Addr)
	if addr == "" {
		return nil, fmt.Errorf("core grpc addr is required")
	}

	rootCA := opts.RootCAPath
	if rootCA == "" {
		rootCA = defaultClientCAChain
	}
	intCA := opts.IntCAPath
	if intCA == "" {
		intCA = defaultIntCA
	}
	serverCert := opts.ServerCert
	if serverCert == "" {
		serverCert = defaultServerCR
	}
	serverKey := opts.ServerKey
	if serverKey == "" {
		serverKey = defaultServerK
	}

	var telemetryCh chan *ingest.VerifiedTelemetry
	if opts.TelemetryCh != nil {
		telemetryCh = opts.TelemetryCh
	} else {
		depth := opts.QueueDepth
		if depth <= 0 {
			depth = 1024
		}
		telemetryCh = make(chan *ingest.VerifiedTelemetry, depth)
	}

	tlsCfg, err := newMTLSTLSConfig(rootCA, intCA, serverCert, serverKey)
	if err != nil {
		return nil, err
	}

	creds := credentials.NewTLS(tlsCfg)
	gs := grpc.NewServer(grpc.Creds(creds))

	h := opts.Handlers
	if h == nil {
		h = NewHandlers(telemetryCh, enforcement.NewActionDispatcher(events.PanicBus(), nil), identity.NewSessionManager())
	} else if h.telemetryCh == nil {
		h.telemetryCh = telemetryCh
	}

	h.systemIdentityHash, err = loadSystemIdentityHash()
	if err != nil {
		return nil, fmt.Errorf("load system_identity_hash: %w", err)
	}

	pb.RegisterRansomEyeServiceServer(gs, h)
	pb.RegisterProbeServiceServer(gs, h)

	return &Server{
		addr:       addr,
		grpcServer: gs,
		handlers:   h,
	}, nil
}

func (s *Server) GRPCServer() *grpc.Server {
	return s.grpcServer
}

func (s *Server) TelemetryChan() <-chan *ingest.VerifiedTelemetry {
	if s.handlers == nil {
		return nil
	}
	return s.handlers.telemetryCh
}

func (s *Server) Serve(ctx context.Context) error {
	lis, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("grpc listen %q: %w", s.addr, err)
	}
	s.lis = lis

	errCh := make(chan error, 1)
	go func() {
		if serveErr := s.grpcServer.Serve(lis); serveErr != nil {
			errCh <- serveErr
		}
	}()

	// Caller (e.g. ransomeye-core main) owns GracefulStop after ctx cancel — avoid double-stop races
	// that can stall systemd SIGTERM handling.
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}

func (s *Server) GracefulStop(ctx context.Context) {
	done := make(chan struct{})
	go func() {
		s.grpcServer.GracefulStop()
		close(done)
	}()

	select {
	case <-ctx.Done():
		s.grpcServer.Stop()
	case <-done:
	}
}

func newMTLSTLSConfig(rootCAPath, intCAPath, serverCertPath, serverKeyPath string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(serverCertPath, serverKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load server keypair: %w", err)
	}

	caPool := x509.NewCertPool()
	if err := appendCertFile(caPool, rootCAPath); err != nil {
		return nil, fmt.Errorf("load client ca chain: %w", err)
	}
	if strings.TrimSpace(intCAPath) != "" {
		if err := appendCertFile(caPool, intCAPath); err != nil {
			return nil, fmt.Errorf("load intermediate ca: %w", err)
		}
	}

	// P0: TLS 1.3 only, fail-closed mTLS.
	return &tls.Config{
		MinVersion: tls.VersionTLS13,

		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,

		NextProtos: []string{"h2"},
	}, nil
}

func appendCertFile(pool *x509.CertPool, path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if ok := pool.AppendCertsFromPEM(b); !ok {
		return fmt.Errorf("no certs parsed from %q", path)
	}
	return nil
}
