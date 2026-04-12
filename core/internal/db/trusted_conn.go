package db

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// TrustedConn wraps pgx.Conn so application SQL cannot run until Trusted is true (set only after the transport trust gate in Connect).
type TrustedConn struct {
	c       *pgx.Conn
	Trusted bool
}

func (t *TrustedConn) requireTrusted() {
	if t == nil || !t.Trusted {
		panic("[FATAL] DB connection used without trust validation")
	}
}

func (t *TrustedConn) raw() *pgx.Conn {
	return t.c
}

// QueryRow executes only after trust validation (fail-closed).
func (t *TrustedConn) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	t.requireTrusted()
	return t.c.QueryRow(ctx, sql, args...)
}

// Query executes only after trust validation (fail-closed).
func (t *TrustedConn) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	t.requireTrusted()
	return t.c.Query(ctx, sql, args...)
}

// Exec executes only after trust validation (fail-closed).
func (t *TrustedConn) Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error) {
	t.requireTrusted()
	return t.c.Exec(ctx, sql, arguments...)
}

// Begin starts a transaction only after trust validation (fail-closed).
func (t *TrustedConn) Begin(ctx context.Context) (pgx.Tx, error) {
	t.requireTrusted()
	return t.c.Begin(ctx)
}

// BeginTx starts a transaction only after trust validation (fail-closed).
func (t *TrustedConn) BeginTx(ctx context.Context, txOptions pgx.TxOptions) (pgx.Tx, error) {
	t.requireTrusted()
	return t.c.BeginTx(ctx, txOptions)
}

// Ping checks connectivity only after trust validation (fail-closed).
func (t *TrustedConn) Ping(ctx context.Context) error {
	t.requireTrusted()
	return t.c.Ping(ctx)
}

// Close closes the connection and clears the trust bit.
func (t *TrustedConn) Close(ctx context.Context) error {
	if t == nil || t.c == nil {
		return nil
	}
	err := t.c.Close(ctx)
	t.Trusted = false
	return err
}

// PgConn exposes low-level protocol access only when trusted (fail-closed).
func (t *TrustedConn) PgConn() *pgconn.PgConn {
	t.requireTrusted()
	return t.c.PgConn()
}
