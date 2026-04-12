package db

import (
	"context"
	"log"
)

// RunTCPTrustGateWithLogs enforces crypto order before application SQL: TLS state → leaf fingerprint → SAN → client PEM → loopback, then secondary logs + server policy + DB session role binding.
func RunTCPTrustGateWithLogs(ctx context.Context, t *TrustedConn, cfg Config, wantRole, logLabel string) error {
	tlsConn, err := TLSConnFromPgx(t.raw())
	if err != nil {
		log.Fatalf("[FATAL] No TLS state — connection is not secure")
	}
	if err := VerifyTLSConnectionState(tlsConn); err != nil {
		log.Fatalf("[FATAL] %v", err)
	}
	st := tlsConn.ConnectionState()
	if !st.HandshakeComplete {
		log.Fatalf("[FATAL] TLS handshake incomplete — connection is not secure")
	}
	if len(st.PeerCertificates) == 0 {
		log.Fatalf("[FATAL] No peer certificate presented")
	}
	if err := VerifyPostgresServerLeafFingerprint(st, cfg.ExpectedPostgresServerFingerprint); err != nil {
		log.Fatalf("[FATAL] %v", err)
	}
	log.Printf("[BOOTSTRAP] Step 1/6: TLS handshake complete, TLS 1.3, server leaf fingerprint OK (%s)", logLabel)

	if err := VerifyServerLeafSAN(&st); err != nil {
		return err
	}
	log.Printf("[BOOTSTRAP] Step 2/6: server leaf SAN verified (%s)", logLabel)

	if err := VerifyClientCertCNMatchesConfig(cfg.SSLClientCert, cfg.User); err != nil {
		return err
	}
	log.Printf("[BOOTSTRAP] Step 3/6: client PEM CN matches configured DB user (pre-SQL) (%s)", logLabel)

	if err := VerifyPostgresTCPRemoteLoopback(t.raw()); err != nil {
		return err
	}
	log.Printf("[BOOTSTRAP] Step 4/6: TCP remote is loopback listener (%s)", logLabel)

	LogPostgreSQLTLSDiagnostics(ctx, t)

	if err := VerifyServerSettings(ctx, t); err != nil {
		return err
	}
	log.Printf("[BOOTSTRAP] Step 5/6: server settings (listen/ssl min) verified (%s)", logLabel)

	if err := VerifyOperationalMTLSSession(ctx, t, cfg.SSLClientCert, wantRole); err != nil {
		return err
	}
	log.Printf("[BOOTSTRAP] Step 6/6: operational DB role authorized + session CN binding (%s)", logLabel)
	return nil
}
