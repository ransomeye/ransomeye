package db

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// NewPool creates a pgxpool with AfterConnect trust validation (single package entrypoint for pools, PRD-02/14).
func NewPool(ctx context.Context, cfg Config) (*pgxpool.Pool, error) {
	pc, err := preparePgxConnConfig(cfg)
	if err != nil {
		return nil, err
	}
	if err := ValidateTLSConfig(pc); err != nil {
		log.Fatalf("[FATAL] %v", err)
	}
	connString := PostgresConnStringForPgxParseOnly(cfg)
	poolCfg, err := pgxpool.ParseConfig(connString)
	if err != nil {
		return nil, fmt.Errorf("parse pool config: %w", err)
	}
	poolCfg.ConnConfig = pc
	if cfg.PoolMaxConns > 0 {
		poolCfg.MaxConns = cfg.PoolMaxConns
	}
	poolCfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
		return verifyPoolConnTrust(ctx, c, cfg)
	}
	poolCfg.PrepareConn = func(ctx context.Context, c *pgx.Conn) (bool, error) {
		if err := VerifyPostgresTransport(c, cfg.SSLClientCert, cfg.User, cfg.ExpectedPostgresServerFingerprint); err != nil {
			log.Fatalf("[FATAL] Pooled connection trust verification failed: %v", err)
		}
		// Set RLS tenant context for single-tenant SYSTEM deployment (PRD-12).
		_, err := c.Exec(ctx, `SELECT set_config('app.tenant_id', '00000000-0000-0000-0000-000000000000', false)`)
		if err != nil {
			return false, err
		}
		return true, nil
	}

	pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	pool, err := pgxpool.NewWithConfig(pctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("pgxpool: %w", err)
	}
	if err := pool.Ping(pctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pgx pool ping: %w", err)
	}
	return pool, nil
}
