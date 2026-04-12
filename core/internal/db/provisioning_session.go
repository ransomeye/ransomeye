package db

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// verifyPoolConnTrust runs the same cryptographic + session checks as VerifyProvisioningSession for raw pool/stdlib connections (AfterConnect).
func verifyPoolConnTrust(ctx context.Context, c *pgx.Conn, cfg Config) error {
	if err := VerifyPostgresTransport(c, cfg.SSLClientCert, cfg.User, cfg.ExpectedPostgresServerFingerprint); err != nil {
		return err
	}
	logPostgreSQLTLSDiagnosticsRaw(ctx, c)
	if err := verifyServerSettings(ctx, c); err != nil {
		return err
	}
	return verifyOperationalMTLSSessionRaw(ctx, c, cfg.SSLClientCert, cfg.User)
}

// VerifyProvisioningSession enforces transport-layer TLS trust before reliance on SQL-visible TLS, then server policy and operational mTLS role binding.
func VerifyProvisioningSession(ctx context.Context, t *TrustedConn, cfg Config, wantRole string) error {
	if t == nil || !t.Trusted {
		return errors.New("db: connection not trusted")
	}
	if err := VerifyPostgresTransport(t.c, cfg.SSLClientCert, cfg.User, cfg.ExpectedPostgresServerFingerprint); err != nil {
		return err
	}
	LogPostgreSQLTLSDiagnostics(ctx, t)
	if err := VerifyServerSettings(ctx, t); err != nil {
		return err
	}
	return VerifyOperationalMTLSSession(ctx, t, cfg.SSLClientCert, wantRole)
}
