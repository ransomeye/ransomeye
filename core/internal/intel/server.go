package intel

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	internalaipb "ransomeye/proto/internalai"
)

// IntelServer serves GetIntelIndicator over the configured loopback intel gRPC listener.
type IntelServer struct {
	internalaipb.UnimplementedIntelServiceServer
	db     *sql.DB
	column string // "indicator" or "value" from schema validation (safe for query build)
}

// NewIntelServer returns an IntelServer that uses the given DB and validated column name for lookups.
func NewIntelServer(db *sql.DB, column string) *IntelServer {
	if column != "indicator" && column != "value" {
		column = "value"
	}
	return &IntelServer{db: db, column: column}
}

// GetIntelIndicator looks up an indicator in intel_indicators. Timeout 50 ms; deterministic; no caching.
func (s *IntelServer) GetIntelIndicator(
	ctx context.Context,
	req *internalaipb.IntelRequest,
) (*internalaipb.IntelResponse, error) {
	if req == nil || s.db == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	ctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()

	query := fmt.Sprintf(`
		SELECT confidence
		FROM intel_indicators
		WHERE %s = $1
		AND is_active = TRUE
		LIMIT 1
	`, s.column)
	var confidence float64
	err := s.db.QueryRowContext(ctx, query, req.Indicator).Scan(&confidence)

	if err == sql.ErrNoRows {
		return &internalaipb.IntelResponse{Found: false}, nil
	}
	if err != nil {
		return nil, status.Error(codes.Internal, "db failure")
	}

	return &internalaipb.IntelResponse{
		Found:      true,
		Confidence: float32(confidence),
	}, nil
}
