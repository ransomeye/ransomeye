package db

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/jackc/pgx/v5"
)

// AuthorizedOperationalDBRoles are the only PostgreSQL roles permitted for TCP+TLS application sessions (fail-closed).
var AuthorizedOperationalDBRoles = map[string]struct{}{
	"ransomeye":          {},
	"ransomeye_readonly": {},
}

// ClientCertificateCommonName returns the Subject CN from the first PEM certificate in path (fail-closed).
func ClientCertificateCommonName(certPath string) (string, error) {
	certPath = strings.TrimSpace(certPath)
	if certPath == "" {
		return "", fmt.Errorf("client certificate path is empty")
	}
	raw, err := os.ReadFile(certPath)
	if err != nil {
		return "", fmt.Errorf("read client cert %q: %w", certPath, err)
	}
	var leaf *x509.Certificate
	for {
		block, rest := pem.Decode(raw)
		if block == nil {
			break
		}
		raw = rest
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return "", fmt.Errorf("parse client certificate: %w", err)
		}
		leaf = cert
		break
	}
	if leaf == nil {
		return "", fmt.Errorf("no PEM certificate in %q", certPath)
	}
	cn := strings.TrimSpace(leaf.Subject.CommonName)
	if cn == "" {
		return "", fmt.Errorf("client certificate has empty Subject CN (mTLS binding requires CN)")
	}
	return cn, nil
}

// VerifyClientCertCNMatchesConfig requires the client PEM CN to match the expected role before any server identity query (crypto binding to config).
func VerifyClientCertCNMatchesConfig(clientCertPath, wantRole string) error {
	wantRole = strings.TrimSpace(wantRole)
	cn, err := ClientCertificateCommonName(clientCertPath)
	if err != nil {
		return err
	}
	if !strings.EqualFold(cn, wantRole) {
		return fmt.Errorf("[FATAL] client cert CN %q must match configured role %q", cn, wantRole)
	}
	return nil
}

func verifyOperationalMTLSSessionRaw(ctx context.Context, conn *pgx.Conn, clientCertPath, wantRole string) error {
	wantRole = strings.TrimSpace(wantRole)
	cn, err := ClientCertificateCommonName(clientCertPath)
	if err != nil {
		return err
	}
	if !strings.EqualFold(cn, wantRole) {
		return fmt.Errorf("[FATAL] client cert CN %q must match required role %q", cn, wantRole)
	}
	var dbUser string
	if err := conn.QueryRow(ctx, `SELECT current_user`).Scan(&dbUser); err != nil {
		return fmt.Errorf("current_user: %w", err)
	}
	dbUser = strings.TrimSpace(dbUser)
	if !strings.EqualFold(dbUser, cn) {
		return fmt.Errorf("[FATAL] mTLS identity mismatch: cert CN=%s, db role=%s", cn, dbUser)
	}
	if _, ok := AuthorizedOperationalDBRoles[strings.ToLower(dbUser)]; !ok {
		return fmt.Errorf("[FATAL] unauthorized DB role: %s", dbUser)
	}
	return nil
}

// VerifyOperationalMTLSSession requires current_user to match client cert CN and to be an authorized operational role (trusted connection only).
func VerifyOperationalMTLSSession(ctx context.Context, t *TrustedConn, clientCertPath, wantRole string) error {
	if t == nil || !t.Trusted {
		return errors.New("db: connection not trusted")
	}
	return verifyOperationalMTLSSessionRaw(ctx, t.c, clientCertPath, wantRole)
}

// VerifyClientCertCNMatchesSession requires PostgreSQL current_user to equal the client cert Subject CN (case-insensitive).
func VerifyClientCertCNMatchesSession(ctx context.Context, t *TrustedConn, clientCertPath string) (cn string, err error) {
	if t == nil || !t.Trusted {
		return "", errors.New("db: connection not trusted")
	}
	cn, err = ClientCertificateCommonName(clientCertPath)
	if err != nil {
		return "", err
	}
	var dbUser string
	if err := t.c.QueryRow(ctx, `SELECT current_user`).Scan(&dbUser); err != nil {
		return cn, fmt.Errorf("current_user: %w", err)
	}
	if !strings.EqualFold(strings.TrimSpace(dbUser), cn) {
		return cn, fmt.Errorf("[FATAL] mTLS identity mismatch: cert CN=%s, db role=%s", cn, dbUser)
	}
	return cn, nil
}
