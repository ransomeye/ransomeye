package identity

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"net/url"
	"testing"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

func TestExtractAgentIDUsesURISANOnly(t *testing.T) {
	seed := sha256.Sum256([]byte("seed"))
	priv := ed25519.NewKeyFromSeed(seed[:])
	pub := priv.Public().(ed25519.PublicKey)
	uri, _ := url.Parse("urn:ransomeye:agent:f47ac10b-58cc-4372-a567-0e02b2c3d479")
	cert := &x509.Certificate{
		Subject: pkix.Name{CommonName: "forbidden-cn"},
		PublicKey: pub,
		URIs: []*url.URL{uri},
		Raw: []byte("raw"),
	}
	ctx := peer.NewContext(context.Background(), &peer.Peer{
		Addr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 50051},
		AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{cert},
			Version:          tls.VersionTLS13,
			CipherSuite:      tls.TLS_AES_128_GCM_SHA256,
		}},
	})
	got, err := ExtractAgentID(ctx)
	if err != nil {
		t.Fatalf("ExtractAgentID failed: %v", err)
	}
	if got != "f47ac10b-58cc-4372-a567-0e02b2c3d479" {
		t.Fatalf("unexpected agent id %q", got)
	}
}
