package sine

import (
	"context"
	"errors"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	sinepb "ransomeye/proto/sine"
)

const bufSize = 1024 * 1024

type recordingSineServer struct {
	sinepb.UnimplementedSineEngineServer
	called int
}

func (s *recordingSineServer) Filter(_ context.Context, req *sinepb.SineRequest) (*sinepb.SineResponse, error) {
	s.called++
	if len(req.GetPayload()) == 0 {
		return &sinepb.SineResponse{Allowed: true, Reasoning: "empty"}, nil
	}
	return &sinepb.SineResponse{Allowed: false, Reasoning: "blocked-by-sine"}, nil
}

type sequenceSineClient struct {
	errs      []error
	responses []*sinepb.SineResponse
	calls     int
}

func (c *sequenceSineClient) Filter(_ context.Context, _ *sinepb.SineRequest, _ ...grpc.CallOption) (*sinepb.SineResponse, error) {
	idx := c.calls
	c.calls++
	if idx < len(c.errs) && c.errs[idx] != nil {
		return nil, c.errs[idx]
	}
	if idx < len(c.responses) && c.responses[idx] != nil {
		return c.responses[idx], nil
	}
	return &sinepb.SineResponse{Allowed: true, Reasoning: "ok"}, nil
}

func TestClientFilter_InvokesGRPC(t *testing.T) {
	srvImpl := &recordingSineServer{}
	lis := bufconn.Listen(bufSize)
	t.Cleanup(func() { _ = lis.Close() })

	s := grpc.NewServer()
	sinepb.RegisterSineEngineServer(s, srvImpl)
	go func() {
		_ = s.Serve(lis)
	}()
	t.Cleanup(s.Stop)

	ctx := context.Background()
	conn, err := grpc.NewClient("passthrough:///buf.net",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return lis.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	c := &Client{raw: sinepb.NewSineEngineClient(conn), cc: conn}
	allowed, err := c.Filter(ctx, []byte{1, 2, 3})
	if err != nil {
		t.Fatalf("Filter: %v", err)
	}
	if allowed {
		t.Fatal("expected allowed=false from SINE stub")
	}
	if srvImpl.called != 1 {
		t.Fatalf("expected SINE Filter invoked once over gRPC, got %d", srvImpl.called)
	}
}

func TestClientFilter_TripsCircuitBreakerAfterThreeFailures(t *testing.T) {
	raw := &sequenceSineClient{
		errs: []error{
			errors.New("transport down"),
			errors.New("transport down"),
			errors.New("transport down"),
		},
	}
	c := &Client{raw: raw}

	for i := 0; i < 2; i++ {
		allowed, err := c.Filter(context.Background(), []byte{9})
		if err != nil {
			t.Fatalf("transient failure %d should be tolerated, got %v", i+1, err)
		}
		if !allowed {
			t.Fatalf("transient failure %d should still allow traffic", i+1)
		}
	}

	allowed, err := c.Filter(context.Background(), []byte{9})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable on sustained failure, got %v", err)
	}
	if allowed {
		t.Fatal("sustained SINE failure must not allow traffic")
	}
	if c.state.FailCount != 3 {
		t.Fatalf("fail count = %d, want 3", c.state.FailCount)
	}
}

func TestClientFilter_ResetsFailureCountAfterSuccess(t *testing.T) {
	raw := &sequenceSineClient{
		errs: []error{
			errors.New("transport down"),
			errors.New("transport down"),
			errors.New("transport down"),
			nil,
			errors.New("transport down"),
		},
		responses: []*sinepb.SineResponse{
			nil,
			nil,
			nil,
			{Allowed: true, Reasoning: "recovered"},
		},
	}
	c := &Client{raw: raw}

	for i := 0; i < 3; i++ {
		_, _ = c.Filter(context.Background(), []byte{9})
	}

	allowed, err := c.Filter(context.Background(), []byte{9})
	if err != nil {
		t.Fatalf("success after degradation should reset breaker, got %v", err)
	}
	if !allowed {
		t.Fatal("expected recovered SINE call to allow traffic")
	}
	if c.state.FailCount != 0 {
		t.Fatalf("fail count after success = %d, want 0", c.state.FailCount)
	}

	allowed, err = c.Filter(context.Background(), []byte{9})
	if err != nil {
		t.Fatalf("first failure after reset should be tolerated, got %v", err)
	}
	if !allowed {
		t.Fatal("first failure after reset should still allow traffic")
	}
	if c.state.FailCount != 1 {
		t.Fatalf("fail count after reset + one failure = %d, want 1", c.state.FailCount)
	}
}
