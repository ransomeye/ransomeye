package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	coreperf "ransomeye/core/performance"
)

func main() {
	var (
		profilesFlag     = flag.String("profiles", "1000,10000,50000,100000", "comma-separated EPS targets")
		durationFlag     = flag.Duration("duration", time.Second, "per-scenario duration")
		repetitionsFlag  = flag.Int("repetitions", 3, "number of runs per EPS profile")
		workersFlag      = flag.Int("workers", 0, "worker count; 0 uses GOMAXPROCS")
		maxMemoryFlag    = flag.Uint64("max-memory-mb", 512, "peak heap guard in MiB")
		requireStable    = flag.Bool("require-stable", true, "fail if 3-run stability is not met")
		jsonOutputFlag   = flag.String("json", "tests/performance/sample_output.json", "JSON output path")
		reportOutputFlag = flag.String("report", "tests/performance/performance_report.md", "Markdown report path")
	)
	flag.Parse()

	profiles, err := parseProfiles(*profilesFlag, *durationFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse profiles: %v\n", err)
		os.Exit(2)
	}

	cfg := coreperf.Config{
		Profiles:              profiles,
		Repetitions:           *repetitionsFlag,
		Workers:               *workersFlag,
		MaxMemoryMB:           *maxMemoryFlag,
		RequireStableAcross3:  *requireStable,
		MaxStableDriftPercent: 25,
	}

	report, runErr := coreperf.RunPerformanceValidation(context.Background(), cfg)
	if err := coreperf.WriteJSON(*jsonOutputFlag, report); err != nil {
		fmt.Fprintf(os.Stderr, "write json: %v\n", err)
		os.Exit(1)
	}
	if err := coreperf.WriteMarkdown(*reportOutputFlag, report); err != nil {
		fmt.Fprintf(os.Stderr, "write report: %v\n", err)
		os.Exit(1)
	}
	if runErr != nil {
		fmt.Fprintf(os.Stderr, "performance validation failed: %v\n", runErr)
		os.Exit(1)
	}
}

func parseProfiles(raw string, duration time.Duration) ([]coreperf.LoadProfile, error) {
	parts := strings.Split(raw, ",")
	profiles := make([]coreperf.LoadProfile, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		eps, err := strconv.Atoi(part)
		if err != nil {
			return nil, err
		}
		profiles = append(profiles, coreperf.LoadProfile{EPS: eps, Duration: duration})
	}
	if len(profiles) == 0 {
		return nil, fmt.Errorf("no profiles specified")
	}
	return profiles, nil
}
