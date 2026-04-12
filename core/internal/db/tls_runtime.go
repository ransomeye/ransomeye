package db

import (
	"context"
	"log"
	"strings"

	"github.com/jackc/pgx/v5"
)

// LogPostgreSQLTLSDiagnostics records server-reported TLS state for forensics only. It MUST NOT be used for security decisions.
func LogPostgreSQLTLSDiagnostics(ctx context.Context, t *TrustedConn) {
	if t == nil || !t.Trusted {
		return
	}
	logPostgreSQLTLSDiagnosticsRaw(ctx, t.c)
}

func logPostgreSQLTLSDiagnosticsRaw(ctx context.Context, conn *pgx.Conn) {
	if conn == nil {
		return
	}
	var ssl, minProto string
	if err := conn.QueryRow(ctx, `SHOW ssl`).Scan(&ssl); err != nil {
		log.Printf("[BOOTSTRAP] secondary TLS log: SHOW ssl failed: %v", err)
		return
	}
	if err := conn.QueryRow(ctx, `SHOW ssl_min_protocol_version`).Scan(&minProto); err != nil {
		log.Printf("[BOOTSTRAP] secondary TLS log: SHOW ssl_min_protocol_version failed: %v", err)
		return
	}
	var sessVer *string
	_ = conn.QueryRow(ctx, `SELECT version FROM pg_stat_ssl WHERE pid = pg_backend_pid()`).Scan(&sessVer)
	v := ""
	if sessVer != nil {
		v = strings.TrimSpace(*sessVer)
	}
	log.Printf("[BOOTSTRAP] secondary TLS log (non-authoritative): ssl=%q ssl_min=%q pg_stat_ssl.version=%q", ssl, minProto, v)
}
