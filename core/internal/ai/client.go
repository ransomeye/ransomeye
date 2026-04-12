package ai

import (
	"context"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"ransomeye/core/internal/config"
	internalaipb "ransomeye/proto/internalai"
)

type ClientOptions struct {
	Addr        string
	DialTimeout time.Duration
}

type Client struct {
	cc   *grpc.ClientConn
	rpc  internalaipb.AIDetectionServiceClient
	addr string
}

func Dial(ctx context.Context, opts ClientOptions) (*Client, error) {
	cfg := config.MustGetVerified()
	addr := cfg.AI.ServiceAddr

	_ = ctx
	_ = opts
	conn, err := grpc.Dial(
		addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		return nil, err
	}

	return &Client{
		cc:   conn,
		rpc:  internalaipb.NewAIDetectionServiceClient(conn),
		addr: addr,
	}, nil
}

func (c *Client) Close() error {
	if c == nil || c.cc == nil {
		return nil
	}
	return c.cc.Close()
}

func (c *Client) EvaluateTelemetry(ctx context.Context, req *internalaipb.EvaluationRequest) (*internalaipb.EvaluationResponse, error) {
	return c.rpc.EvaluateTelemetry(ctx, req)
}
