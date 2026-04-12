package sine

import (
	"context"
	"errors"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"ransomeye/core/internal/health"
	"ransomeye/core/internal/metrics"
	sinepb "ransomeye/proto/sine"
)

// Core→SINE Filter deadline (PRD-08 / pipeline) before breaker accounting.
const filterRPCTimeout = 50 * time.Millisecond

var ErrUnavailable = errors.New("SINE_UNAVAILABLE")

type SineState struct {
	FailCount int
	LastFail  time.Time
}

// Client is a gRPC client to the standalone SINE engine on the local loopback listener.
type Client struct {
	raw sinepb.SineEngineClient
	cc  *grpc.ClientConn

	mu    sync.Mutex
	state SineState
}

// Dial opens an insecure gRPC connection to addr (loopback-only in production).
func Dial(addr string) (*Client, error) {
	cc, err := grpc.NewClient(
		addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, err
	}
	return &Client{
		raw: sinepb.NewSineEngineClient(cc),
		cc:  cc,
	}, nil
}

// Close releases the client connection.
func (c *Client) Close() error {
	if c == nil || c.cc == nil {
		return nil
	}
	return c.cc.Close()
}

// Filter invokes SINE.Filter over gRPC with a bounded deadline.
// First two consecutive transport failures are tolerated; sustained failure degrades fail-closed.
func (c *Client) Filter(ctx context.Context, payload []byte) (allowed bool, err error) {
	if c == nil || c.raw == nil {
		return false, ErrUnavailable
	}
	callCtx, cancel := context.WithTimeout(ctx, filterRPCTimeout)
	defer cancel()
	resp, err := c.raw.Filter(callCtx, &sinepb.SineRequest{Payload: payload})
	if err != nil {
		return c.onFailure()
	}
	c.onSuccess()
	return resp.GetAllowed(), nil
}

func (c *Client) onFailure() (bool, error) {
	metrics.IncSINEFailuresTotal(1)

	c.mu.Lock()
	c.state.FailCount++
	c.state.LastFail = time.Now().UTC()
	failCount := c.state.FailCount
	c.mu.Unlock()

	if failCount < 3 {
		return true, nil
	}

	metrics.SetSINEStateDegraded()
	return false, ErrUnavailable
}

func (c *Client) onSuccess() {
	c.mu.Lock()
	c.state.FailCount = 0
	c.state.LastFail = time.Time{}
	c.mu.Unlock()

	metrics.SetSINEStateOK()
	health.MarkSINEHealthy()
}
