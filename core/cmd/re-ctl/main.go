package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	appdb "ransomeye/core/internal/db"
	coreconfig "ransomeye/core/internal/config"
	"ransomeye/core/internal/netcfg"
	pb "ransomeye/proto/ransomeyepb"
)

const (
	defaultPGPort            = 5432
	canonicalTLSTrustChain   = "/opt/ransomeye/core/certs/ca-chain.crt"
)

type cliConfig struct {
	CoreAddr                 string
	CoreFingerprint          string
	PostgresDSN              string
	PostgresServerFingerprint string
	AdminCert                string
	AdminKey                 string
	AdminCA                  string
	PGSSLRootCert            string
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return usageError("")
	}

	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	coreConn, _, err := newCoreClient(ctx, cfg)
	if err != nil {
		return err
	}
	defer func() { _ = coreConn.Close() }()

	switch args[0] {
	case "agents":
		return runAgents(ctx, cfg, args[1:])
	case "logs":
		return runLogs(ctx, cfg, args[1:])
	case "action":
		return runAction(ctx, cfg, args[1:])
	default:
		return usageError("")
	}
}

func runAgents(ctx context.Context, cfg cliConfig, args []string) error {
	if len(args) == 0 || args[0] != "list" {
		return usageError("usage: re-ctl agents list")
	}

	pool, err := openDB(ctx, cfg)
	if err != nil {
		return err
	}
	defer pool.Close()

	const q = `
SELECT agent_id::text, status, last_heartbeat
FROM agent_sessions
ORDER BY last_heartbeat DESC
`
	rows, err := pool.Query(ctx, q)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var agentID string
		var status string
		var lastHeartbeat time.Time
		if err := rows.Scan(&agentID, &status, &lastHeartbeat); err != nil {
			return err
		}
		fmt.Printf("%s\t%s\t%s\n", agentID, status, lastHeartbeat.UTC().Format(time.RFC3339))
	}
	return rows.Err()
}

func runLogs(ctx context.Context, cfg cliConfig, args []string) error {
	if len(args) == 0 || args[0] != "tail" {
		return usageError("usage: re-ctl logs tail")
	}

	pool, err := openDB(ctx, cfg)
	if err != nil {
		return err
	}
	defer pool.Close()

	var lastSeen time.Time
	for {
		const q = `
SELECT audit_id::text, event_type, actor, details_json, created_at
FROM governance_audit_log
WHERE created_at > $1
ORDER BY created_at ASC
`
		rows, err := pool.Query(ctx, q, lastSeen)
		if err != nil {
			return err
		}

		for rows.Next() {
			var auditID, eventType, actor string
			var details []byte
			var createdAt time.Time
			if err := rows.Scan(&auditID, &eventType, &actor, &details, &createdAt); err != nil {
				rows.Close()
				return err
			}
			lastSeen = createdAt
			fmt.Printf("%s\t%s\t%s\t%s\t%s\n",
				createdAt.UTC().Format(time.RFC3339),
				auditID,
				eventType,
				actor,
				string(details),
			)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(2 * time.Second):
		}
	}
}

func runAction(ctx context.Context, cfg cliConfig, args []string) error {
	if len(args) == 0 || args[0] != "kill" {
		return usageError("usage: re-ctl action kill --agent <id> --pid <pid> --reason <reason>")
	}

	fs := flag.NewFlagSet("kill", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	agentID := fs.String("agent", "", "target agent_id")
	pid := fs.Int("pid", 0, "target process id")
	reason := fs.String("reason", "", "required reason for WORM audit trail")

	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if strings.TrimSpace(*agentID) == "" {
		return errors.New("--agent is required")
	}
	if *pid <= 0 {
		return errors.New("--pid must be > 0")
	}
	if strings.TrimSpace(*reason) == "" {
		return errors.New("--reason is required")
	}

	pool, err := openDB(ctx, cfg)
	if err != nil {
		return err
	}
	defer pool.Close()

	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	actionID := uuid.NewString()
	actor, err := adminActor(cfg.AdminCert)
	if err != nil {
		return err
	}

	params := map[string]any{
		"pid":    *pid,
		"reason": strings.TrimSpace(*reason),
		"source": "re-ctl",
	}
	paramsJSON, err := json.Marshal(params)
	if err != nil {
		return err
	}

	const qAction = `
INSERT INTO actions (
    action_id,
    tenant_id,
    detection_id,
    agent_id,
    action_type,
    action_params,
    status,
    dispatched_by,
    dispatched_at
)
SELECT
    $1::uuid,
    s.tenant_id,
    NULL,
    $2::uuid,
    'KILL_PROCESS',
    $3::jsonb,
    'PENDING',
    $4::text,
    NOW()
FROM agent_sessions s
WHERE s.agent_id = $2::uuid
`
	tag, err := tx.Exec(ctx, qAction, actionID, *agentID, paramsJSON, actor)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("agent_id not found: %s", *agentID)
	}

	auditDetails := map[string]any{
		"action_id": actionID,
		"agent_id":  *agentID,
		"pid":       *pid,
		"reason":    strings.TrimSpace(*reason),
		"source":    "re-ctl",
	}
	auditJSON, err := json.Marshal(auditDetails)
	if err != nil {
		return err
	}

	const qAudit = `
INSERT INTO governance_audit_log (audit_id, tenant_id, event_type, actor, details_json)
SELECT
    gen_random_uuid(),
    s.tenant_id,
    'ACTION_APPROVED',
    $2::text,
    $3::jsonb
FROM agent_sessions s
WHERE s.agent_id = $1::uuid
`
	if _, err := tx.Exec(ctx, qAudit, *agentID, actor, auditJSON); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return err
	}

	fmt.Printf("queued kill action action_id=%s agent_id=%s pid=%d\n", actionID, *agentID, *pid)
	return nil
}

func loadConfig() (cliConfig, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return cliConfig{}, err
	}

	commonCfg, err := coreconfig.LoadVerifiedCommonConfig(
		coreconfig.InstalledCommonConfigPath,
		coreconfig.IntermediateCACertPath,
	)
	if err != nil {
		return cliConfig{}, err
	}
	if err := coreconfig.RequireRole(commonCfg, "core"); err != nil {
		return cliConfig{}, err
	}

	base := filepath.Join(home, ".ransomeye")
	cfg := cliConfig{
		CoreAddr:                  commonCfg.Core.GRPCEndpoint,
		CoreFingerprint:           commonCfg.Core.ServerCertFingerprint,
		PostgresDSN:             strings.TrimSpace(os.Getenv("POSTGRES_DSN")),
		PostgresServerFingerprint: strings.TrimSpace(commonCfg.Database.ExpectedServerFingerprint),
		AdminCert:       filepath.Join(base, "admin.crt"),
		AdminKey:        filepath.Join(base, "admin.key"),
		AdminCA:         canonicalTLSTrustChain,
		PGSSLRootCert:   envOrDefault("PGSSLROOTCERT", canonicalTLSTrustChain),
	}

	if _, err := os.Stat(cfg.AdminCert); err != nil {
		return cliConfig{}, fmt.Errorf("admin mTLS certificate required at %s: %w", cfg.AdminCert, err)
	}
	if _, err := os.Stat(cfg.AdminKey); err != nil {
		return cliConfig{}, fmt.Errorf("admin mTLS key required at %s: %w", cfg.AdminKey, err)
	}
	if _, err := os.Stat(cfg.AdminCA); err != nil {
		return cliConfig{}, fmt.Errorf("admin CA required at %s: %w", cfg.AdminCA, err)
	}
	if cfg.PostgresDSN == "" {
		return cliConfig{}, errors.New("POSTGRES_DSN is required")
	}

	return cfg, nil
}

func newCoreClient(ctx context.Context, cfg cliConfig) (*grpc.ClientConn, pb.RansomEyeServiceClient, error) {
	cert, err := tls.LoadX509KeyPair(cfg.AdminCert, cfg.AdminKey)
	if err != nil {
		return nil, nil, err
	}
	host, _, err := net.SplitHostPort(cfg.CoreAddr)
	if err != nil {
		return nil, nil, err
	}

	caPEM, err := os.ReadFile(cfg.AdminCA)
	if err != nil {
		return nil, nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, nil, errors.New("failed to parse admin CA")
	}

	tlsCfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   host,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("core TLS handshake returned no peer certificate")
			}
			sum := sha256.Sum256(cs.PeerCertificates[0].Raw)
			actual := hex.EncodeToString(sum[:])
			expected := strings.ToLower(strings.TrimSpace(cfg.CoreFingerprint))
			if actual != expected {
				return fmt.Errorf("core certificate fingerprint mismatch: expected %s, got %s", expected, actual)
			}
			return nil
		},
	}
	creds := credentials.NewTLS(tlsCfg)
	conn, err := grpc.DialContext(ctx, cfg.CoreAddr, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, nil, err
	}
	return conn, pb.NewRansomEyeServiceClient(conn), nil
}

func openDB(ctx context.Context, cfg cliConfig) (*pgxpool.Pool, error) {
	dsn := strings.TrimSpace(cfg.PostgresDSN)
	if !strings.Contains(dsn, "sslmode=") {
		sep := " "
		if strings.Contains(dsn, "://") {
			if strings.Contains(dsn, "?") {
				sep = "&"
			} else {
				sep = "?"
			}
		}
		dsn += sep + "sslmode=verify-full"
	}
	if !strings.Contains(strings.ToLower(dsn), "host=") && !strings.Contains(dsn, "://") {
		dsn += fmt.Sprintf(" host=%s port=%d", netcfg.LoopbackHost, defaultPGPort)
	}
	if err := appdb.ValidateInboundPostgresDSN(dsn); err != nil {
		return nil, err
	}
	pc, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	env := appdb.LoadConfigFromEnv()
	dbCfg := appdb.Config{
		User:                              reCtlFirstNonEmpty(strings.TrimSpace(pc.User), env.User),
		Password:                          pc.Password,
		Database:                          reCtlFirstNonEmpty(strings.TrimSpace(pc.Database), env.Database),
		SSLRootCert:                       cfg.PGSSLRootCert,
		SSLClientCert:                     env.SSLClientCert,
		SSLClientKey:                      env.SSLClientKey,
		TLSServerName:                     appdb.DefaultTLSServerName,
		ExpectedPostgresServerFingerprint: cfg.PostgresServerFingerprint,
	}
	return appdb.NewPool(ctx, dbCfg)
}

func reCtlFirstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func adminActor(certPath string) (string, error) {
	pemBytes, err := os.ReadFile(certPath)
	if err != nil {
		return "", err
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return filepath.Base(certPath), nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return filepath.Base(certPath), nil
	}
	return subjectName(cert.Subject), nil
}

func subjectName(subject pkix.Name) string {
	if cn := strings.TrimSpace(subject.CommonName); cn != "" {
		return cn
	}
	return strings.TrimSpace(subject.String())
}

func envOrDefault(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func usageError(extra string) error {
	msg := "usage:\n" +
		"  re-ctl agents list\n" +
		"  re-ctl logs tail\n" +
		"  re-ctl action kill --agent <id> --pid <pid> --reason <reason>"
	if extra != "" {
		msg += "\n" + extra
	}
	return errors.New(msg)
}
