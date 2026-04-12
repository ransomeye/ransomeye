package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"ransomeye/core/internal/dbbootstrap"
)

func main() {
	os.Exit(run())
}

func run() int {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: db-bootstrap <bootstrap|validate|status>")
		return 1
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	switch os.Args[1] {
	case "bootstrap":
		fs := flag.NewFlagSet("bootstrap", flag.ExitOnError)
		mig := fs.String("migrations", "/opt/ransomeye/core/migrations/", "absolute migrations directory")
		if err := fs.Parse(os.Args[2:]); err != nil {
			return 1
		}
		bctx, bc := context.WithTimeout(ctx, 30*time.Minute)
		defer bc()
		if err := dbbootstrap.RunMigrationsAndValidate(bctx, dbbootstrap.Options{MigrationsDir: *mig}); err != nil {
			log.Fatalf("[FATAL] db migrations: %v", err)
		}
		fmt.Println("bootstrap: OK")
		return 0
	case "validate", "status":
		bctx, bc := context.WithTimeout(ctx, 5*time.Minute)
		defer bc()
		rep, ok, err := dbbootstrap.ValidateReport(bctx)
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if jerr := enc.Encode(rep); jerr != nil {
			log.Fatalf("[FATAL] validate: encode JSON: %v", jerr)
		}
		if err != nil {
			log.Fatalf("[FATAL] validate: %v", err)
		}
		if !ok {
			log.Fatalf("[FATAL] validate: overall not PASS")
		}
		return 0
	default:
		fmt.Fprintln(os.Stderr, "usage: db-bootstrap <bootstrap|validate|status>")
		return 1
	}
}
