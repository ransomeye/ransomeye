package identity

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// Fingerprint returns SHA-256 of the certificate's raw DER (deterministic).
func Fingerprint(cert *x509.Certificate) []byte {
	if cert == nil {
		return nil
	}
	sum := sha256.Sum256(cert.Raw)
	return sum[:]
}

// ExtractCertFingerprint returns SHA-256 over the DER-encoded leaf certificate (PRD-04 §3.2).
func ExtractCertFingerprint(cert *x509.Certificate) [32]byte {
	var out [32]byte
	if cert == nil {
		return out
	}
	sum := sha256.Sum256(cert.Raw)
	copy(out[:], sum[:])
	return out
}

// PeerCertFromContext returns the first peer certificate from the mTLS context.
func PeerCertFromContext(ctx context.Context) (*x509.Certificate, error) {
	p, ok := peer.FromContext(ctx)
	if !ok || p == nil || p.AuthInfo == nil {
		return nil, status.Error(codes.Unauthenticated, "missing peer auth info")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "missing tls auth info")
	}
	if len(tlsInfo.State.PeerCertificates) == 0 || tlsInfo.State.PeerCertificates[0] == nil {
		return nil, status.Error(codes.Unauthenticated, "missing client certificate")
	}
	return tlsInfo.State.PeerCertificates[0], nil
}

const sanAgentPrefix = "urn:ransomeye:agent:"
const sanProbePrefix = "urn:ransomeye:probe:"

// ExtractAgentID extracts agent_id from URI SAN only.
// Subject CN is explicitly forbidden for authorization.
func ExtractAgentID(ctx context.Context) (string, error) {
	cert, err := PeerCertFromContext(ctx)
	if err != nil {
		return "", err
	}
	for _, uri := range cert.URIs {
		if uri == nil {
			continue
		}
		raw := strings.ToLower(strings.TrimSpace(uri.String()))
		if !strings.HasPrefix(raw, sanAgentPrefix) {
			continue
		}
		agentID := strings.TrimPrefix(raw, sanAgentPrefix)
		parsed, err := uuid.Parse(agentID)
		if err != nil || parsed.String() != agentID {
			return "", status.Error(codes.Unauthenticated, "invalid agent uri san")
		}
		return agentID, nil
	}
	return "", status.Error(codes.Unauthenticated, "missing agent uri san binding")
}

// ExtractPeerIdentity extracts a single SAN-bound peer identity.
// Returns ("agent", uuid) or ("probe", uuid). Any ambiguity fail-closes.
func ExtractPeerIdentity(ctx context.Context) (string, string, error) {
	cert, err := PeerCertFromContext(ctx)
	if err != nil {
		return "", "", err
	}
	foundKind := ""
	foundID := ""
	for _, uri := range cert.URIs {
		if uri == nil {
			continue
		}
		raw := strings.ToLower(strings.TrimSpace(uri.String()))
		kind := ""
		id := ""
		switch {
		case strings.HasPrefix(raw, sanAgentPrefix):
			kind = "agent"
			id = strings.TrimPrefix(raw, sanAgentPrefix)
		case strings.HasPrefix(raw, sanProbePrefix):
			kind = "probe"
			id = strings.TrimPrefix(raw, sanProbePrefix)
		default:
			continue
		}
		parsed, err := uuid.Parse(id)
		if err != nil || parsed.String() != id {
			return "", "", status.Error(codes.Unauthenticated, "invalid peer uri san")
		}
		if foundKind != "" && (foundKind != kind || foundID != id) {
			return "", "", status.Error(codes.Unauthenticated, "identity xor violation in peer san")
		}
		foundKind = kind
		foundID = id
	}
	if foundKind == "" {
		return "", "", status.Error(codes.Unauthenticated, "missing peer uri san binding")
	}
	return foundKind, foundID, nil
}

// VerifyAgentBinding enforces claimed agent_id equals URI SAN binding.
func VerifyAgentBinding(ctx context.Context, claimedAgentID string) error {
	extracted, err := ExtractAgentID(ctx)
	if err != nil {
		return err
	}
	if extracted != strings.ToLower(strings.TrimSpace(claimedAgentID)) {
		return status.Error(codes.Unauthenticated, "agent_id san mismatch")
	}
	return nil
}

// TLSBindingKey derives a deterministic TLS session binding key.
func TLSBindingKey(ctx context.Context) (string, error) {
	p, ok := peer.FromContext(ctx)
	if !ok || p == nil || p.AuthInfo == nil {
		return "", status.Error(codes.Unauthenticated, "missing peer auth info")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "missing tls auth info")
	}
	if len(tlsInfo.State.PeerCertificates) == 0 || tlsInfo.State.PeerCertificates[0] == nil {
		return "", status.Error(codes.Unauthenticated, "missing client certificate")
	}
	leaf := tlsInfo.State.PeerCertificates[0].Raw
	b := []byte(fmt.Sprintf("%d|%d|%x", tlsInfo.State.Version, tlsInfo.State.CipherSuite, leaf))
	if p.Addr != nil {
		b = append(b, []byte("|"+p.Addr.String())...)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
