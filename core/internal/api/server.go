package api

import (
	"context"
	"fmt"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"ransomeye/core/internal/storage"
)

type Server struct {
	dbPool *pgxpool.Pool
}

var latestTelemetry atomic.Value // holds []storage.TelemetryRecord
var telemetryUpdaterOnce sync.Once

func ResolveConfigPath() (string, error) {
	paths := []string{
		"/etc/ransomeye/config/common.yaml",
		"./testdata/common.yaml",
	}

	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			if _, readErr := os.ReadFile(p); readErr == nil {
				return p, nil
			}
		}
		if _, err := os.ReadFile(p); err == nil {
			return p, nil
		}
	}

	return "", fmt.Errorf("no valid config path found")
}

func startTelemetryUpdater(pool *pgxpool.Pool) {
	telemetryUpdaterOnce.Do(func() {
		go func() {
			for {
				ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
				records, err := storage.GetLatestTelemetryWithValidation(ctx, pool, 100)
				cancel()

				if err == nil {
					latestTelemetry.Store(records)
				} else {
					log.Printf("[SOC-VALIDATION-FAIL] %v", err)
				}

				time.Sleep(500 * time.Millisecond)
			}
		}()
	})
}

func NewServer(pool *pgxpool.Pool) (*Server, error) {
	if _, err := ResolveConfigPath(); err != nil {
		return nil, err
	}
	s := &Server{dbPool: pool}
	startTelemetryUpdater(s.dbPool)
	return s, nil
}

func (s *Server) GetLiveTelemetry(ctx context.Context) ([]storage.TelemetryRecord, error) {
	start := time.Now()
	v := latestTelemetry.Load()
	duration := time.Since(start)
	if duration > 50*time.Millisecond {
		log.Printf("[PERF-ALERT] telemetry query slow: %s", duration)
	}
	if v == nil {
		return nil, status.Error(codes.Unavailable, "no telemetry snapshot available")
	}

	records, ok := v.([]storage.TelemetryRecord)
	if !ok {
		return nil, status.Error(codes.Internal, "invalid telemetry snapshot state")
	}

	for i := 1; i < len(records); i++ {
		if records[i].LogicalClock >= records[i-1].LogicalClock {
			return nil, status.Error(codes.Internal, "logical clock ordering violation")
		}
	}

	return records, nil
}
