package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"ransomeye/core/internal/replay"
)

func main() {
	var inputPath string
	var verify bool

	flag.StringVar(&inputPath, "input", "", "path to .rre replay envelope")
	flag.BoolVar(&verify, "verify", false, "run the same replay twice and assert identical output hash")
	flag.Parse()

	if strings.TrimSpace(inputPath) == "" {
		fmt.Fprintln(os.Stderr, "replay-engine: --input is required")
		os.Exit(2)
	}

	envelope, err := replay.LoadEnvelope(inputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "replay-engine: load input: %v\n", err)
		os.Exit(1)
	}

	if verify {
		run1, run2, err := replay.VerifyEnvelope(context.Background(), envelope)
		if err != nil {
			_ = json.NewEncoder(os.Stderr).Encode(run1)
			_ = json.NewEncoder(os.Stderr).Encode(run2)
			fmt.Fprintf(os.Stderr, "replay-engine: verify failed: %v\n", err)
			os.Exit(1)
		}
		_ = json.NewEncoder(os.Stdout).Encode(run1)
		return
	}

	result, err := replay.RunEnvelope(context.Background(), envelope)
	if err != nil {
		fmt.Fprintf(os.Stderr, "replay-engine: run failed: %v\n", err)
		os.Exit(1)
	}
	_ = json.NewEncoder(os.Stdout).Encode(result)
}
