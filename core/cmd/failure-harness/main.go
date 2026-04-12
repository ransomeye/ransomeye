package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	corefail "ransomeye/core/failure"
)

func main() {
	var (
		dbMaxConns   = flag.Int("db-max-conns", 4, "maximum postgres pool size for failure validation")
		jsonOutput   = flag.String("json", "tests/failure/sample_output.json", "JSON output path")
		reportOutput = flag.String("report", "tests/failure/validation_report.md", "Markdown report path")
	)
	flag.Parse()

	report, runErr := corefail.RunFailureValidation(context.Background(), corefail.Config{
		DBMaxConns: int32(*dbMaxConns),
	})
	if err := corefail.WriteJSON(*jsonOutput, report); err != nil {
		fmt.Fprintf(os.Stderr, "write json: %v\n", err)
		os.Exit(1)
	}
	if err := corefail.WriteMarkdown(*reportOutput, report); err != nil {
		fmt.Fprintf(os.Stderr, "write report: %v\n", err)
		os.Exit(1)
	}
	if runErr != nil {
		fmt.Fprintf(os.Stderr, "failure validation failed: %v\n", runErr)
		os.Exit(1)
	}
}
