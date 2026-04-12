package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"ransomeye/core/internal/adversarial"
)

func main() {
	var attack string

	flag.StringVar(&attack, "attack", "all", "attack name or 'all'")
	flag.Parse()

	ctx := context.Background()
	var (
		results []adversarial.Result
		err     error
	)

	switch strings.TrimSpace(attack) {
	case "", "all":
		results, err = adversarial.RunAll(ctx)
	default:
		var result adversarial.Result
		result, err = adversarial.RunScenario(ctx, attack)
		if err == nil {
			results = []adversarial.Result{result}
		}
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "adversarial-harness: %v\n", err)
		os.Exit(1)
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(results); err != nil {
		fmt.Fprintf(os.Stderr, "adversarial-harness: encode output: %v\n", err)
		os.Exit(1)
	}

	for _, result := range results {
		if !result.Pass() {
			os.Exit(1)
		}
	}
}
