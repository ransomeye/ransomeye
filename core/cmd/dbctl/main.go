package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/google/uuid"

	coreconfig "ransomeye/core/internal/config"
	dbbase "ransomeye/core/internal/db"
	"ransomeye/core/internal/db/migrator"
	"ransomeye/core/internal/db/validator"
	"ransomeye/core/internal/dbbootstrap"
	"ransomeye/core/internal/replay"
)

type replaySummary struct {
	Status    string `json:"status"`
	Runs      int    `json:"runs,omitempty"`
	Deviation int    `json:"deviation"`
}

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, usage())
		return 1
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	dbConfig, err := loadDBConfigForCLI()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	switch args[0] {
	case "migrate":
		if len(args) != 1 {
			fmt.Fprintln(os.Stderr, usage())
			return 1
		}
		result, err := migrator.Run(ctx, migrator.Config{
			DB: dbConfig,
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Printf("migrate: applied=%d skipped=%d total=%d\n", result.Applied, result.Skipped, result.Total)
		return 0
	case "validate":
		if len(args) != 1 {
			fmt.Fprintln(os.Stderr, usage())
			return 1
		}
		result := validator.Run(ctx, validator.Config{
			DB: dbConfig,
		})
		payload, err := json.Marshal(result)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Println(string(payload))
		if result.Status != "PASS" {
			return 1
		}
		return 0
	case "replay":
		return runReplay(ctx, dbConfig, args[1:])
	case "replay-once":
		return runReplayOnce(ctx, dbConfig, args[1:])
	default:
		fmt.Fprintln(os.Stderr, usage())
		return 1
	}
}

func runReplay(ctx context.Context, dbConfig dbbase.Config, args []string) int {
	fs := flag.NewFlagSet("replay", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var replayID string
	var runs int
	fs.StringVar(&replayID, "id", "", "replay session uuid")
	fs.IntVar(&runs, "runs", 10, "number of cross-process replay runs")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if replayID == "" || runs <= 0 {
		fmt.Fprintln(os.Stderr, "usage: dbctl replay --id <replay_id> [--runs 10]")
		return 1
	}
	if _, err := uuid.Parse(replayID); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	execPath, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	for idx := 0; idx < runs; idx++ {
		cmd := exec.CommandContext(ctx, execPath, "replay-once", "--id", replayID)
		cmd.Env = os.Environ()
		var stdoutBuf, stderrBuf bytes.Buffer
		cmd.Stdout = &stdoutBuf
		cmd.Stderr = &stderrBuf
		err := cmd.Run()
		out := stdoutBuf.Bytes()
		if err != nil {
			if len(out) > 0 {
				if _, parseErr := decodeReplayCheckResult(out); parseErr == nil {
					fmt.Print(string(out))
					return 1
				}
			}
			fmt.Fprintln(os.Stderr, err)
			if stderrBuf.Len() > 0 {
				fmt.Fprint(os.Stderr, stderrBuf.String())
			}
			if len(out) > 0 {
				fmt.Fprint(os.Stderr, string(out))
			}
			return 1
		}
		result, err := decodeReplayCheckResult(out)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			if stderrBuf.Len() > 0 {
				fmt.Fprint(os.Stderr, stderrBuf.String())
			}
			fmt.Fprint(os.Stderr, string(out))
			return 1
		}
		if result.Status != "PASS" {
			_ = json.NewEncoder(os.Stdout).Encode(result)
			return 1
		}
	}

	_ = json.NewEncoder(os.Stdout).Encode(replaySummary{
		Status:    "PASS",
		Runs:      runs,
		Deviation: 0,
	})
	_ = dbConfig
	return 0
}

func runReplayOnce(ctx context.Context, dbConfig dbbase.Config, args []string) int {
	fs := flag.NewFlagSet("replay-once", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var replayID string
	fs.StringVar(&replayID, "id", "", "replay session uuid")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	parsedID, err := uuid.Parse(replayID)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	conn, err := dbbase.Connect(ctx, dbConfig)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer conn.Close(ctx)

	if err := dbbase.VerifyProvisioningSession(ctx, conn, dbConfig, dbConfig.User); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	result, err := replay.VerifyStoredReplay(ctx, conn, parsedID)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	payload, err := json.Marshal(result)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Println(string(payload))
	if result.Status != "PASS" {
		return 1
	}
	return 0
}

func decodeReplayCheckResult(raw []byte) (replay.ReplayCheckResult, error) {
	var result replay.ReplayCheckResult
	if err := json.Unmarshal(raw, &result); err != nil {
		return replay.ReplayCheckResult{}, err
	}
	return result, nil
}

func usage() string {
	return "usage: dbctl <migrate|validate|replay --id <replay_id> [--runs N]>"
}

// loadDBConfigForCLI mirrors core startup: when POSTGRES_DSN is set, credentials and TLS paths come from
// dbbootstrap.EffectiveAppConfig (same as authority-db tests); otherwise fall back to discrete PG* env vars.
func loadDBConfigForCLI() (dbbase.Config, error) {
	cc, err := coreconfig.LoadVerifiedCommonConfig(
		coreconfig.InstalledCommonConfigPath,
		coreconfig.IntermediateCACertPath,
	)
	if err != nil {
		return dbbase.Config{}, err
	}
	fp := strings.TrimSpace(cc.Database.ExpectedServerFingerprint)
	if fp == "" {
		return dbbase.Config{}, fmt.Errorf("Missing PostgreSQL fingerprint — installer misconfiguration")
	}

	if strings.TrimSpace(os.Getenv("POSTGRES_DSN")) != "" {
		cfg, err := dbbootstrap.EffectiveAppConfig()
		if err != nil {
			return dbbase.Config{}, err
		}
		cfg.ExpectedPostgresServerFingerprint = fp
		return cfg, nil
	}
	cfg := dbbase.LoadConfigFromEnv()
	cfg.ExpectedPostgresServerFingerprint = fp
	return cfg, nil
}
