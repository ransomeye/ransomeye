package gateway

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	"ransomeye/core/internal/metrics"
	dpicontrolpb "ransomeye/proto/dpicontrolpb"
)

const (
	DefaultDPIControlSocketPath              = "/run/ransomeye/dpi_control.sock"
	dpiControlTick                           = time.Second
	dpiControlModeNormal              uint32 = 0
	dpiControlModeThrottle            uint32 = 1
	dpiControlModeCritical            uint32 = 2
	dpiControlNormalMaxEventsPerSec          = 10_000
	dpiControlThrottleMaxEventsPerSec        = 2_500
	dpiControlCriticalMaxEventsPerSec        = 500
	dpiQueueThrottleNumerator                = 3
	dpiQueueThrottleDenominator              = 4
	dpiCPUThrottlePermille            uint32 = 850
	dpiCPUCriticalPermille            uint32 = 950
)

type dpiQueueDepthProvider interface {
	QueueDepth() int
	Capacity() int
}

type dpiDropStatsProvider interface {
	Snapshot() (total uint64, dropped uint64)
}

type dpiCPUSaturationSampler interface {
	SamplePermille() uint32
}

type dpiControlSender interface {
	Send(socketPath string, payload []byte) (time.Duration, error)
}

type DPIControlOptions struct {
	SocketPath string
	Scheduler  dpiQueueDepthProvider
	DropStats  dpiDropStatsProvider
	CPUSampler dpiCPUSaturationSampler
	Sender     dpiControlSender
}

type DPIControlLoop struct {
	socketPath string
	scheduler  dpiQueueDepthProvider
	dropStats  dpiDropStatsProvider
	cpuSampler dpiCPUSaturationSampler
	sender     dpiControlSender
}

func NewDPIControlLoop(opts DPIControlOptions) (*DPIControlLoop, error) {
	if opts.Scheduler == nil {
		return nil, fmt.Errorf("dpi control loop requires scheduler")
	}

	socketPath := strings.TrimSpace(opts.SocketPath)
	if socketPath == "" {
		socketPath = DefaultDPIControlSocketPath
	}

	dropStats := opts.DropStats
	if dropStats == nil {
		dropStats = liveDPIDropStats{}
	}

	cpuSampler := opts.CPUSampler
	if cpuSampler == nil {
		cpuSampler = &procStatSampler{statPath: "/proc/stat"}
	}

	sender := opts.Sender
	if sender == nil {
		sender = unixgramControlSender{}
	}

	return &DPIControlLoop{
		socketPath: socketPath,
		scheduler:  opts.Scheduler,
		dropStats:  dropStats,
		cpuSampler: cpuSampler,
		sender:     sender,
	}, nil
}

func (d *DPIControlLoop) Run(ctx context.Context) error {
	if d == nil {
		return fmt.Errorf("nil dpi control loop")
	}

	// When no DPI probe is deployed, skip unixgram control traffic (avoids per-second WARN spam).
	if strings.TrimSpace(os.Getenv("RANSOMEYE_DPI_CONTROL_DISABLED")) == "true" {
		<-ctx.Done()
		return nil
	}

	if err := d.publishCurrentControl(); err != nil {
		logControlSendFailure(err)
	}

	ticker := time.NewTicker(dpiControlTick)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := d.publishCurrentControl(); err != nil {
				logControlSendFailure(err)
			}
		}
	}
}

func (d *DPIControlLoop) publishCurrentControl() error {
	control := d.computeControl()
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(control)
	if err != nil {
		d.recordFallbackMetrics()
		return fmt.Errorf("marshal dpi control: %w", err)
	}

	latency, err := d.sender.Send(d.socketPath, payload)
	if err != nil {
		d.recordFallbackMetrics()
		return fmt.Errorf("send dpi control: %w", err)
	}

	latencyMicros := uint64(latency / time.Microsecond)
	if latency > 0 && latencyMicros == 0 {
		latencyMicros = 1
	}
	metrics.SetDPIThrottleMode(control.GetDropMode())
	metrics.SetDPISamplingRate(samplingRateForControl(control))
	metrics.SetDPIControlLatency(latencyMicros)
	return nil
}

func (d *DPIControlLoop) computeControl() *dpicontrolpb.DpiControl {
	total, dropped := d.dropStats.Snapshot()
	return computeDPIControl(
		d.scheduler.QueueDepth(),
		d.scheduler.Capacity(),
		dropped,
		total,
		d.cpuSampler.SamplePermille(),
	)
}

func (d *DPIControlLoop) recordFallbackMetrics() {
	metrics.SetDPIThrottleMode(dpiControlModeNormal)
	metrics.SetDPISamplingRate(1)
	metrics.SetDPIControlLatency(0)
}

func computeDPIControl(
	queueDepth int,
	queueCapacity int,
	dropped uint64,
	total uint64,
	cpuPermille uint32,
) *dpicontrolpb.DpiControl {
	switch {
	case metrics.DPIThresholdExceeded(dropped, total, DPI_DROP_THRESHOLD_NUM, DPI_DROP_THRESHOLD_DEN) ||
		cpuPermille >= dpiCPUCriticalPermille:
		return &dpicontrolpb.DpiControl{
			MaxEventsPerSec: dpiControlCriticalMaxEventsPerSec,
			DropMode:        dpiControlModeCritical,
		}
	case queueShouldThrottle(queueDepth, queueCapacity) || cpuPermille >= dpiCPUThrottlePermille:
		return &dpicontrolpb.DpiControl{
			MaxEventsPerSec: dpiControlThrottleMaxEventsPerSec,
			DropMode:        dpiControlModeThrottle,
		}
	default:
		return &dpicontrolpb.DpiControl{
			MaxEventsPerSec: dpiControlNormalMaxEventsPerSec,
			DropMode:        dpiControlModeNormal,
		}
	}
}

func queueShouldThrottle(depth, capacity int) bool {
	if depth <= 0 || capacity <= 0 {
		return false
	}
	return uint64(depth)*dpiQueueThrottleDenominator >= uint64(capacity)*dpiQueueThrottleNumerator
}

func samplingRateForControl(control *dpicontrolpb.DpiControl) uint32 {
	if control == nil || control.GetDropMode() != dpiControlModeThrottle {
		return 1
	}

	maxRate := control.GetMaxEventsPerSec()
	if maxRate == 0 || maxRate >= dpiControlNormalMaxEventsPerSec {
		return 1
	}

	return uint32((uint64(dpiControlNormalMaxEventsPerSec) + uint64(maxRate) - 1) / uint64(maxRate))
}

func logControlSendFailure(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "[WARN] DPI_CONTROL_SEND_FAILED err=%v\n", err)
	}
}

type liveDPIDropStats struct{}

func (liveDPIDropStats) Snapshot() (total uint64, dropped uint64) {
	return metrics.DPIDropSnapshot()
}

type unixgramControlSender struct{}

func (unixgramControlSender) Send(socketPath string, payload []byte) (time.Duration, error) {
	start := time.Now()
	addr := &net.UnixAddr{Name: socketPath, Net: "unixgram"}
	conn, err := net.DialUnix("unixgram", nil, addr)
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	if _, err := conn.Write(payload); err != nil {
		return 0, err
	}
	return time.Since(start), nil
}

type procStatSampler struct {
	statPath  string
	valid     bool
	lastTotal uint64
	lastIdle  uint64
}

func (s *procStatSampler) SamplePermille() uint32 {
	total, idle, err := readCPUCounters(s.statPath)
	if err != nil {
		return 0
	}
	if !s.valid {
		s.lastTotal = total
		s.lastIdle = idle
		s.valid = true
		return 0
	}

	deltaTotal := total - s.lastTotal
	deltaIdle := idle - s.lastIdle
	s.lastTotal = total
	s.lastIdle = idle

	if deltaTotal == 0 {
		return 0
	}

	busy := deltaTotal
	if deltaIdle < busy {
		busy -= deltaIdle
	} else {
		busy = 0
	}
	return uint32((busy * 1000) / deltaTotal)
}

func readCPUCounters(path string) (total uint64, idle uint64, err error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, err
	}

	line, _, _ := strings.Cut(string(raw), "\n")
	fields := strings.Fields(line)
	if len(fields) < 5 || fields[0] != "cpu" {
		return 0, 0, fmt.Errorf("invalid cpu stat line")
	}

	for idx, field := range fields[1:] {
		value, convErr := strconv.ParseUint(field, 10, 64)
		if convErr != nil {
			return 0, 0, convErr
		}
		total += value
		if idx == 3 || idx == 4 {
			idle += value
		}
	}

	return total, idle, nil
}
