package bootstrap

import (
	"context"
	"errors"
	"testing"

	"ransomeye/core/internal/config"
)

func TestRunStartupPreflightFailsBeforeSchemaOnMissingThreshold(t *testing.T) {
	schemaCalled := false
	_, err := runStartupPreflight(context.Background(), StartupHooks{
		LoadSignedConfig: func() (config.CommonConfig, error) {
			return config.CommonConfig{
				Backpressure: config.BackpressureConfig{
					DiskThresholdBytes:    int64PtrBootstrap(1024),
					WALLatencyThresholdMS: int64PtrBootstrap(100),
				},
			}, nil
		},
		ValidateDBSchema: func(context.Context, config.CommonConfig) error {
			schemaCalled = true
			return nil
		},
	})
	if err == nil {
		t.Fatal("expected startup failure")
	}
	if schemaCalled {
		t.Fatal("schema validation ran before threshold validation")
	}
}

func TestRunStartupPreflightFailsBeforeSchemaOnInvalidThreshold(t *testing.T) {
	schemaCalled := false
	_, err := runStartupPreflight(context.Background(), StartupHooks{
		LoadSignedConfig: func() (config.CommonConfig, error) {
			return config.CommonConfig{
				Backpressure: config.BackpressureConfig{
					MemoryThreshold:       int64PtrBootstrap(-1),
					DiskThresholdBytes:    int64PtrBootstrap(1024),
					WALLatencyThresholdMS: int64PtrBootstrap(100),
				},
			}, nil
		},
		ValidateDBSchema: func(context.Context, config.CommonConfig) error {
			schemaCalled = true
			return nil
		},
	})
	if err == nil {
		t.Fatal("expected startup failure")
	}
	if schemaCalled {
		t.Fatal("schema validation ran before invalid threshold rejection")
	}
}

func TestRunStartupPreflightFailsClosedOnSchemaMismatch(t *testing.T) {
	loadCalled := false
	schemaCalled := false
	_, err := runStartupPreflight(context.Background(), StartupHooks{
		LoadSignedConfig: func() (config.CommonConfig, error) {
			loadCalled = true
			return config.CommonConfig{
				Backpressure: config.BackpressureConfig{
					MemoryThreshold:       int64PtrBootstrap(10),
					DiskThresholdBytes:    int64PtrBootstrap(1024),
					WALLatencyThresholdMS: int64PtrBootstrap(100),
				},
			}, nil
		},
		ValidateDBSchema: func(context.Context, config.CommonConfig) error {
			schemaCalled = true
			return errors.New("missing column telemetry_events.sequence_id")
		},
	})
	if err == nil {
		t.Fatal("expected startup failure")
	}
	if !loadCalled || !schemaCalled {
		t.Fatal("expected load and schema validation to run")
	}
}

func int64PtrBootstrap(v int64) *int64 {
	return &v
}
