package gateway

import (
	"sync"
	"testing"

	_ "unsafe"

	"ransomeye/core/internal/backpressure"
	"ransomeye/core/internal/config"
)

func seedGatewayBackpressureConfig(t *testing.T) {
	t.Helper()

	cfg := config.CommonConfig{
		Backpressure: config.BackpressureConfig{
			MemoryThreshold:       int64PtrForBackpressureTest(2),
			DiskThresholdBytes:    int64PtrForBackpressureTest(1 << 20),
			WALLatencyThresholdMS: int64PtrForBackpressureTest(250),
		},
	}

	cacheVerifiedCommonConfig(cfg)
	backpressureThresholdsMu.Lock()
	backpressureLoadedThresholds = backpressure.Thresholds{}
	backpressureThresholdsLoaded = false
	backpressureThresholdsMu.Unlock()
}

func int64PtrForBackpressureTest(value int64) *int64 {
	return &value
}

//go:linkname cacheVerifiedCommonConfig ransomeye/core/internal/config.cacheVerifiedCommonConfig
func cacheVerifiedCommonConfig(config.CommonConfig)

//go:linkname backpressureThresholdsMu ransomeye/core/internal/backpressure.thresholdsMu
var backpressureThresholdsMu sync.Mutex

//go:linkname backpressureLoadedThresholds ransomeye/core/internal/backpressure.loadedThresholds
var backpressureLoadedThresholds backpressure.Thresholds

//go:linkname backpressureThresholdsLoaded ransomeye/core/internal/backpressure.thresholdsLoaded
var backpressureThresholdsLoaded bool
