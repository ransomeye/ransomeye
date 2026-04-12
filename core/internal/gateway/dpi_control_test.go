package gateway

import (
	"net"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"ransomeye/core/internal/metrics"
	dpicontrolpb "ransomeye/proto/dpicontrolpb"
)

type stubQueueDepthProvider struct {
	depth    int
	capacity int
}

func (s stubQueueDepthProvider) QueueDepth() int { return s.depth }
func (s stubQueueDepthProvider) Capacity() int   { return s.capacity }

type stubDropStatsProvider struct {
	total   uint64
	dropped uint64
}

func (s stubDropStatsProvider) Snapshot() (uint64, uint64) {
	return s.total, s.dropped
}

type stubCPUSampler struct {
	permille uint32
}

func (s stubCPUSampler) SamplePermille() uint32 { return s.permille }

func TestComputeDPIControlCriticalOnDropRatio(t *testing.T) {
	control := computeDPIControl(0, 65536, 2, 1000, 0)

	if control.GetDropMode() != dpiControlModeCritical {
		t.Fatalf("drop_mode = %d, want %d", control.GetDropMode(), dpiControlModeCritical)
	}
	if control.GetMaxEventsPerSec() != dpiControlCriticalMaxEventsPerSec {
		t.Fatalf("max_events_per_sec = %d, want %d", control.GetMaxEventsPerSec(), dpiControlCriticalMaxEventsPerSec)
	}
}

func TestComputeDPIControlThrottleOnQueueDepth(t *testing.T) {
	control := computeDPIControl(60_000, 65_536, 0, 0, 0)

	if control.GetDropMode() != dpiControlModeThrottle {
		t.Fatalf("drop_mode = %d, want %d", control.GetDropMode(), dpiControlModeThrottle)
	}
	if samplingRateForControl(control) != 4 {
		t.Fatalf("sampling rate = %d, want 4", samplingRateForControl(control))
	}
}

func TestBackpressureResponse(t *testing.T) {
	metrics.SetDPIThrottleMode(0)
	metrics.SetDPISamplingRate(0)
	metrics.SetDPIControlLatency(0)

	socketPath := filepath.Join(t.TempDir(), "dpi_control.sock")
	receiver, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: socketPath, Net: "unixgram"})
	if err != nil {
		t.Fatalf("ListenUnixgram: %v", err)
	}
	defer receiver.Close()

	loop, err := NewDPIControlLoop(DPIControlOptions{
		SocketPath: socketPath,
		Scheduler: stubQueueDepthProvider{
			depth:    60_000,
			capacity: 65_536,
		},
		DropStats:  stubDropStatsProvider{},
		CPUSampler: stubCPUSampler{},
	})
	if err != nil {
		t.Fatalf("NewDPIControlLoop: %v", err)
	}

	if err := loop.publishCurrentControl(); err != nil {
		t.Fatalf("publishCurrentControl: %v", err)
	}

	buf := make([]byte, 256)
	if err := receiver.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	n, _, err := receiver.ReadFromUnix(buf)
	if err != nil {
		t.Fatalf("ReadFromUnix: %v", err)
	}

	var control dpicontrolpb.DpiControl
	if err := proto.Unmarshal(buf[:n], &control); err != nil {
		t.Fatalf("proto.Unmarshal: %v", err)
	}

	if control.GetDropMode() != dpiControlModeThrottle {
		t.Fatalf("drop_mode = %d, want %d", control.GetDropMode(), dpiControlModeThrottle)
	}
	if control.GetMaxEventsPerSec() != dpiControlThrottleMaxEventsPerSec {
		t.Fatalf("max_events_per_sec = %d, want %d", control.GetMaxEventsPerSec(), dpiControlThrottleMaxEventsPerSec)
	}
	if metrics.DPIThrottleMode() != dpiControlModeThrottle {
		t.Fatalf("metrics throttle mode = %d, want %d", metrics.DPIThrottleMode(), dpiControlModeThrottle)
	}
	if metrics.DPISamplingRate() != 4 {
		t.Fatalf("metrics sampling rate = %d, want 4", metrics.DPISamplingRate())
	}
	if metrics.DPIControlLatency() == 0 {
		t.Fatal("dpi control latency metric was not recorded")
	}
}
