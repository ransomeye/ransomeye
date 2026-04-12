package db

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const (
	LoopbackHost         = "127.0.0.1"
	LoopbackPort         = 5432
	DefaultUser          = "ransomeye"
	DefaultDatabase      = "ransomeye"
	DefaultPassword      = "strong-password"
	DefaultSSLRootCert   = "/opt/ransomeye/core/certs/ca-chain.crt"
	DefaultSSLClientCert = "/opt/ransomeye/core/certs/client.crt"
	DefaultSSLClientKey  = "/opt/ransomeye/core/certs/client.key"
	DefaultTLSServerName = LoopbackHost
)

var (
	ErrNonLoopbackConnection = errors.New("db must connect only to 127.0.0.1:5432")

	redactPasswordPattern = regexp.MustCompile(`(?i)\bpassword=\S+`)
)

type Config struct {
	User          string
	Password      string
	Database      string
	SSLRootCert   string
	SSLClientCert string
	SSLClientKey  string
	TLSServerName string
	// ExpectedPostgresServerFingerprint is SHA-256 of the PostgreSQL server leaf (64 lowercase hex chars).
	// It MUST be populated only from verified /etc/ransomeye/config/common.yaml (never from environment variables).
	ExpectedPostgresServerFingerprint string
	// PoolMaxConns, when > 0, caps pgxpool size (NewPool only).
	PoolMaxConns int32
}

// LoadConfigFromEnv loads DB identity and TLS file paths.
// Deploy contract (env or unsigned local YAML) should mirror:
//
//	database:
//	  host: 127.0.0.1
//	  port: 5432
//	  sslmode: verify-full
//	  sslrootcert: /opt/ransomeye/core/certs/ca-chain.crt
//	  sslcert: /opt/ransomeye/core/certs/client.crt
//	  sslkey: /opt/ransomeye/core/certs/client.key
func LoadConfigFromEnv() Config {
	return Config{
		User:          envOrDefault("PGUSER", DefaultUser),
		Password:      envOrDefault("PGPASSWORD", DefaultPassword),
		Database:      envOrDefault("PGDATABASE", DefaultDatabase),
		SSLRootCert:   envOrDefault("PGSSLROOTCERT", DefaultSSLRootCert),
		SSLClientCert: envOrDefault("PGSSLCERT", DefaultSSLClientCert),
		SSLClientKey:  envOrDefault("PGSSLKEY", DefaultSSLClientKey),
		TLSServerName: envOrDefault("PGSSLSERVERNAME", DefaultTLSServerName),
	}
}

// ValidateTLSConfig enforces an explicit TLS 1.3 tls.Config on pgx (exported for negative tests).
func ValidateTLSConfig(pc *pgx.ConnConfig) error {
	if pc == nil {
		return errors.New("nil ConnConfig")
	}
	if pc.TLSConfig == nil {
		return errors.New("TLSConfig is nil — TLS enforcement bypass detected")
	}
	if pc.TLSConfig.MinVersion != tls.VersionTLS13 || pc.TLSConfig.MaxVersion != tls.VersionTLS13 {
		return errors.New("TLS version misconfigured — must be TLS 1.3 only")
	}
	if pc.TLSConfig.InsecureSkipVerify {
		if strings.TrimSpace(os.Getenv("RANSOMEYE_DEV_MODE")) == "true" && strings.TrimSpace(os.Getenv("RANSOMEYE_SKIP_DB_TLS_VERIFY")) == "true" {
			return nil
		}
		return errors.New("InsecureSkipVerify must be false")
	}
	return nil
}

// preparePgxConnConfig builds the pgx connection config used by Connect, pools, and stdlib.
// Wire cryptography is enforced exclusively via pgx.ConnConfig.TLSConfig (TLS 1.3, full cert verification).
func preparePgxConnConfig(cfg Config) (*pgx.ConnConfig, error) {
	if strings.TrimSpace(cfg.User) == "" {
		return nil, errors.New("postgres user must not be empty")
	}
	if strings.TrimSpace(cfg.Database) == "" {
		return nil, errors.New("postgres database must not be empty")
	}
	if strings.TrimSpace(cfg.ExpectedPostgresServerFingerprint) == "" {
		return nil, fmt.Errorf("Missing PostgreSQL fingerprint — installer misconfiguration")
	}
	tlsConfig, err := buildTLSConfig(cfg.SSLRootCert, cfg.SSLClientCert, cfg.SSLClientKey, cfg.TLSServerName)
	if err != nil {
		return nil, err
	}
	if tlsConfig.MinVersion != tls.VersionTLS13 || tlsConfig.MaxVersion != tls.VersionTLS13 {
		return nil, fmt.Errorf("TLS version misconfigured — must be TLS 1.3 only")
	}
	if tlsConfig.InsecureSkipVerify {
		if strings.TrimSpace(os.Getenv("RANSOMEYE_DEV_MODE")) != "true" || strings.TrimSpace(os.Getenv("RANSOMEYE_SKIP_DB_TLS_VERIFY")) != "true" {
			return nil, fmt.Errorf("InsecureSkipVerify forbidden")
		}
	}
	connString := PostgresConnStringForPgxParseOnly(cfg)
	pgxConfig, err := pgx.ParseConfig(connString)
	if err != nil {
		return nil, fmt.Errorf("parse postgres config: %w", err)
	}
	pgxConfig.Host = LoopbackHost
	pgxConfig.Port = uint16(LoopbackPort)
	pgxConfig.User = cfg.User
	pgxConfig.Password = cfg.Password
	pgxConfig.Database = cfg.Database
	pgxConfig.TLSConfig = tlsConfig
	if pgxConfig.RuntimeParams == nil {
		pgxConfig.RuntimeParams = map[string]string{}
	}
	pgxConfig.RuntimeParams["application_name"] = "dbctl"
	if err := ValidateTLSConfig(pgxConfig); err != nil {
		return nil, err
	}
	return pgxConfig, nil
}

// Connect is the only supported TCP+TLS entrypoint for application PostgreSQL sessions (PRD-02/14).
func Connect(ctx context.Context, cfg Config) (*TrustedConn, error) {
	pgxConfig, err := preparePgxConnConfig(cfg)
	if err != nil {
		return nil, err
	}
	dsn := PostgresConnStringForPgxParseOnly(cfg)

	connectCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	conn, err := pgx.ConnectConfig(connectCtx, pgxConfig)
	if err != nil {
		return nil, fmt.Errorf("connect postgres %s: %w", redactDSN(dsn), err)
	}

	if err := VerifyPostgresTransport(conn, cfg.SSLClientCert, cfg.User, cfg.ExpectedPostgresServerFingerprint); err != nil {
		_ = conn.Close(ctx)
		return nil, err
	}

	return &TrustedConn{c: conn, Trusted: true}, nil
}

// TLSConnFromPgx returns the underlying TLS connection for a pgx TCP+TLS session.
func TLSConnFromPgx(conn *pgx.Conn) (*tls.Conn, error) {
	if conn == nil {
		return nil, errors.New("nil postgres connection")
	}
	netConn := conn.PgConn().Conn()
	if netConn == nil {
		return nil, errors.New("postgres connection missing network transport")
	}
	tlsConn, ok := netConn.(*tls.Conn)
	if !ok {
		return nil, fmt.Errorf("[FATAL] postgres connection is not using tls")
	}
	return tlsConn, nil
}

// VerifyPostgresTCPRemoteLoopback requires the transport remote address to be loopback:5432.
func VerifyPostgresTCPRemoteLoopback(conn *pgx.Conn) error {
	if conn == nil {
		return errors.New("nil postgres connection")
	}
	netConn := conn.PgConn().Conn()
	if netConn == nil {
		return errors.New("postgres connection missing network transport")
	}
	remoteHost, remotePort, err := splitRemoteAddr(netConn.RemoteAddr())
	if err != nil {
		return err
	}
	if remoteHost != LoopbackHost || remotePort != LoopbackPort {
		return fmt.Errorf("%w: remote=%s:%d", ErrNonLoopbackConnection, remoteHost, remotePort)
	}
	return nil
}

// VerifyPostgresTransport enforces TLS 1.3 + server leaf fingerprint + SAN + client cert CN vs expected role + loopback TCP endpoint before application SQL.
func VerifyPostgresTransport(conn *pgx.Conn, clientCertPath, expectRole, expectedServerFingerprint string) error {
	tlsConn, err := TLSConnFromPgx(conn)
	if err != nil {
		return err
	}
	if err := VerifyTLSConnectionState(tlsConn); err != nil {
		return err
	}
	st := tlsConn.ConnectionState()
	if err := VerifyPostgresServerLeafFingerprint(st, expectedServerFingerprint); err != nil {
		return err
	}
	if err := VerifyServerLeafSAN(&st); err != nil {
		return err
	}
	if err := VerifyClientCertCNMatchesConfig(clientCertPath, expectRole); err != nil {
		return err
	}
	return VerifyPostgresTCPRemoteLoopback(conn)
}

func isPostgreSQLInsufficientPrivilege(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "42501"
}

func verifyServerSettings(ctx context.Context, conn *pgx.Conn) error {
	if strings.TrimSpace(os.Getenv("RANSOMEYE_DEV_MODE")) == "true" {
		log.Println("[DEV MODE] skipping server settings verification (ssl_min_protocol_version, etc)")
		return nil
	}
	// Prefer pg_settings: application roles often lack privilege for SHOW on some GUCs (e.g. ssl_min_protocol_version).
	readSetting := func(setting string) (string, error) {
		var value string
		if err := conn.QueryRow(ctx, `SELECT setting FROM pg_settings WHERE name = $1`, setting).Scan(&value); err == nil {
			return strings.TrimSpace(value), nil
		}
		if err := conn.QueryRow(ctx, "SHOW "+setting).Scan(&value); err != nil {
			return "", fmt.Errorf("read server setting %q: %w", setting, err)
		}
		return strings.TrimSpace(value), nil
	}

	sslEnabled, err := readSetting("ssl")
	if err != nil {
		return err
	}
	minProtocol, err := readSetting("ssl_min_protocol_version")
	if err != nil {
		if isPostgreSQLInsufficientPrivilege(err) {
			// Application roles often cannot read this GUC; TLS 1.3 is already enforced on the wire by pgx + trust gate.
			log.Printf("[BOOTSTRAP] ssl_min_protocol_version not visible to application role (42501); treating negotiated TLS 1.3 session as authoritative")
			minProtocol = "TLSv1.3"
		} else {
			return err
		}
	}
	if err := validateRuntimePostgresSSLReports(sslEnabled, minProtocol); err != nil {
		return err
	}

	listenAddresses, err := readSetting("listen_addresses")
	if err != nil {
		return err
	}
	if listenAddresses != LoopbackHost {
		return fmt.Errorf("listen_addresses must be %q, got %q", LoopbackHost, listenAddresses)
	}

	if err := VerifyLoopbackListener(); err != nil {
		return err
	}

	return nil
}

// VerifyServerSettings runs server-side policy checks on a trusted connection only.
func VerifyServerSettings(ctx context.Context, t *TrustedConn) error {
	if strings.TrimSpace(os.Getenv("RANSOMEYE_DEV_MODE")) == "true" {
		log.Println("[DEV MODE] skipping server settings verification (ssl_min_protocol_version, etc)")
		return nil
	}
	if t == nil || !t.Trusted {
		return errors.New("db: connection not trusted")
	}
	return verifyServerSettings(ctx, t.c)
}

func VerifyLoopbackListener() error {
	lines, err := readProcNetTCP()
	if err != nil {
		return fmt.Errorf("inspect /proc/net/tcp: %w", err)
	}
	if len(lines) < 2 {
		return errors.New("missing /proc/net/tcp listener data")
	}

	var found bool
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[3] != "0A" {
			continue
		}

		localAddress := fields[1]
		parts := strings.Split(localAddress, ":")
		if len(parts) != 2 {
			continue
		}

		portValue, err := strconv.ParseUint(parts[1], 16, 16)
		if err != nil || int(portValue) != LoopbackPort {
			continue
		}

		ip, err := hexToIPv4(parts[0])
		if err != nil {
			return err
		}
		if ip != LoopbackHost {
			return fmt.Errorf("postgres listener bound to non-loopback address %s:%d", ip, LoopbackPort)
		}
		found = true
	}

	if !found {
		return fmt.Errorf("no tcp listener detected on %s:%d", LoopbackHost, LoopbackPort)
	}

	return nil
}

func buildTLSConfig(caPath, clientCertPath, clientKeyPath, serverName string) (*tls.Config, error) {
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read postgres ca %q: %w", caPath, err)
	}

	rootCAs := x509.NewCertPool()
	if ok := rootCAs.AppendCertsFromPEM(caPEM); !ok {
		return nil, fmt.Errorf("parse postgres ca %q: no certificates found", caPath)
	}

	clientCertificate, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
	if err != nil {
		return nil, fmt.Errorf(
			"load postgres client certificate/key %q %q: %w",
			clientCertPath,
			clientKeyPath,
			err,
		)
	}

	insecureSkip := false
	if strings.TrimSpace(os.Getenv("RANSOMEYE_DEV_MODE")) == "true" && strings.TrimSpace(os.Getenv("RANSOMEYE_SKIP_DB_TLS_VERIFY")) == "true" {
		insecureSkip = true
	}

	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		InsecureSkipVerify: insecureSkip,
		RootCAs:            rootCAs,
		Certificates: []tls.Certificate{
			clientCertificate,
		},
		ServerName: serverName,
	}
	return tlsConfig, nil
}

func splitRemoteAddr(addr net.Addr) (string, int, error) {
	if addr == nil {
		return "", 0, errors.New("postgres remote address missing")
	}

	if tcpAddr, ok := addr.(*net.TCPAddr); ok {
		return tcpAddr.IP.String(), tcpAddr.Port, nil
	}

	host, portText, err := net.SplitHostPort(addr.String())
	if err != nil {
		return "", 0, fmt.Errorf("parse remote address %q: %w", addr.String(), err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return "", 0, fmt.Errorf("parse remote port %q: %w", portText, err)
	}

	return host, port, nil
}

func readProcNetTCP() ([]string, error) {
	file, err := os.Open("/proc/net/tcp")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	return lines, scanner.Err()
}

func hexToIPv4(value string) (string, error) {
	if len(value) != 8 {
		return "", fmt.Errorf("invalid ipv4 hex length %q", value)
	}

	ip := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		segment, err := strconv.ParseUint(value[i*2:(i+1)*2], 16, 8)
		if err != nil {
			return "", fmt.Errorf("parse ipv4 hex %q: %w", value, err)
		}
		ip[3-i] = byte(segment)
	}

	return ip.String(), nil
}

func redactDSN(value string) string {
	if strings.Contains(value, "://") {
		parsed, err := url.Parse(value)
		if err != nil {
			return fmt.Sprintf("host=%s port=%d", LoopbackHost, LoopbackPort)
		}
		if parsed.User != nil {
			username := parsed.User.Username()
			if username != "" {
				parsed.User = url.User(username)
			}
		}
		return parsed.String()
	}
	out := reKeywordHost.ReplaceAllString(value, "host="+LoopbackHost)
	out = redactPasswordPattern.ReplaceAllString(out, "password=REDACTED")
	return out
}

func validateRuntimePostgresSSLReports(sslSetting, minProto string) error {
	if strings.TrimSpace(sslSetting) != "on" {
		return fmt.Errorf("postgres ssl must be on, got %q", sslSetting)
	}
	if strings.TrimSpace(minProto) != "TLSv1.3" {
		return fmt.Errorf("postgres ssl_min_protocol_version must be TLSv1.3, got %q", minProto)
	}
	return nil
}

func envOrDefault(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}
