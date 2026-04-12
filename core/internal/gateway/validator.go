package gateway

/*
RANSOMEYE CRYPTOGRAPHIC MESSAGE FORMAT (V1)

All signed messages MUST follow deterministic canonical encoding:

message :=
    len(prefix) || prefix ||
    len(payload) || payload ||
    len(agent_id) || agent_id ||
    len(session_id) || session_id ||
    len(fingerprint) || fingerprint

Where:
- len(x) is 4-byte big-endian unsigned integer
- prefix = "RANSOMEYE_EVENT_V1"

Security properties:
- Prevents concatenation ambiguity
- Binds identity to payload
- Deterministic across platforms
- Replay-safe via nonce + timestamp validation

This format MUST NOT change without version bump.
*/

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sync"
	"sync/atomic"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

const (
	telemetrySchemaV1         = 1
	telemetrySkewWindowMillis = int64(5000) // ±5s
	defaultNonceMaxEntries    = 1_048_576   // 1M
	defaultNonceTTLMillis     = int64(10_000)
	nonceTTLMs                = int64(5000) // fixed for replay window
	timestampWindowMs         = int64(5000)
	maxNonceEntries           = 1_000_000 // P0: bounded nonce store (memory DoS fix)
)

type Verifier interface {
	Verify(payload []byte, sig []byte) bool
}

// Identity binds agent, session, and cert fingerprint (do not persist SessionID).
type Identity struct {
	AgentID        string
	SessionID      string
	FingerprintHex string
}

type Validator struct {
	nonces   *NonceCache
	nonceMap map[string]int64
	nonceMu  sync.Mutex
	ttlMs    int64
	maxSkew  int64
}

func NewValidator() *Validator {
	return &Validator{
		nonces:   NewNonceCache(defaultNonceMaxEntries),
		nonceMap: make(map[string]int64),
		ttlMs:    nonceTTLMs,
		maxSkew:  timestampWindowMs,
	}
}

func NewValidatorWithNonceCache(maxEntries int, ttlMs int64, skewMs int64) *Validator {
	if maxEntries <= 0 || ttlMs <= 0 || skewMs <= 0 {
		return nil
	}
	return &Validator{
		nonces:   NewNonceCache(maxEntries),
		nonceMap: make(map[string]int64),
		ttlMs:    nonceTTLMs,
		maxSkew:  timestampWindowMs,
	}
}

func appendWithLength(dst []byte, data []byte) []byte {
	l := uint32(len(data))

	var lenBuf [4]byte
	lenBuf[0] = byte(l >> 24)
	lenBuf[1] = byte(l >> 16)
	lenBuf[2] = byte(l >> 8)
	lenBuf[3] = byte(l)

	dst = append(dst, lenBuf[:]...)
	dst = append(dst, data...)

	return dst
}

func buildMessage(payload []byte, id Identity) []byte {
	prefix := []byte("RANSOMEYE_EVENT_V1")

	msg := make([]byte, 0, len(prefix)+len(payload)+128)

	msg = appendWithLength(msg, prefix)
	msg = appendWithLength(msg, payload)
	msg = appendWithLength(msg, []byte(id.AgentID))
	msg = appendWithLength(msg, []byte(id.SessionID))
	msg = appendWithLength(msg, []byte(id.FingerprintHex))

	return msg
}

func (v *Validator) checkNonce(nonce string, now int64) error {
	v.nonceMu.Lock()
	defer v.nonceMu.Unlock()

	if ts, ok := v.nonceMap[nonce]; ok {
		if now-ts < v.ttlMs {
			return errors.New("replay detected")
		}
	}

	// enforce bounded size (deterministic eviction: oldest scan)
	if len(v.nonceMap) >= maxNonceEntries {
		var oldestKey string
		var oldestTs int64 = now

		for k, ts := range v.nonceMap {
			if ts < oldestTs {
				oldestTs = ts
				oldestKey = k
			}
		}

		delete(v.nonceMap, oldestKey)
	}

	v.nonceMap[nonce] = now
	return nil
}

// NonceCache is a bounded, lock-free replay cache with set-associative LRU-by-lastSeen eviction.
// Memory is capped by maxEntries at construction time.
type NonceCache struct {
	ways    uint32
	mask    uint64
	hashes  []atomic.Uint64
	expMs   []atomic.Int64
	lastMs  []atomic.Uint32
	entries uint64
}

func NewNonceCache(maxEntries int) *NonceCache {
	if maxEntries < 1024 {
		maxEntries = 1024
	}
	// Force power-of-two entries for deterministic masking.
	n := uint64(1)
	for n < uint64(maxEntries) {
		n <<= 1
	}
	ways := uint32(4)
	buckets := n / uint64(ways)
	if buckets < 1 {
		buckets = 1
	}

	size := int(buckets * uint64(ways))
	c := &NonceCache{
		ways:    ways,
		mask:    uint64(buckets - 1),
		hashes:  make([]atomic.Uint64, size),
		expMs:   make([]atomic.Int64, size),
		lastMs:  make([]atomic.Uint32, size),
		entries: uint64(size),
	}
	return c
}

// SeenOnce returns true if nonce is accepted and recorded; false if replayed.
func (c *NonceCache) SeenOnce(nonce []byte, nowMs int64, expMs int64) bool {
	if c == nil || len(nonce) == 0 {
		return false
	}
	h := hash64(nonce)
	if h == 0 {
		h = 1
	}

	b := h & c.mask
	base := uint64(b) * uint64(c.ways)

	// 1) Fast path: check for existing live nonce.
	for i := uint32(0); i < c.ways; i++ {
		idx := int(base + uint64(i))
		if c.hashes[idx].Load() != h {
			continue
		}
		if c.expMs[idx].Load() > nowMs {
			// Replay.
			return false
		}
		// Expired entry with same hash: attempt to refresh in-place.
		c.expMs[idx].Store(expMs)
		c.lastMs[idx].Store(uint32(nowMs))
		return true
	}

	// 2) Insert: choose an expired slot if available; otherwise LRU by lastMs.
	victim := -1
	var victimLast uint32
	for i := uint32(0); i < c.ways; i++ {
		idx := int(base + uint64(i))
		oldH := c.hashes[idx].Load()
		if oldH == 0 {
			victim = idx
			break
		}
		if c.expMs[idx].Load() <= nowMs {
			victim = idx
			break
		}
		l := c.lastMs[idx].Load()
		if victim == -1 || l < victimLast {
			victim = idx
			victimLast = l
		}
	}
	if victim < 0 {
		return false
	}

	old := c.hashes[victim].Load()
	// Lock-free replace: CAS old -> h.
	if !c.hashes[victim].CompareAndSwap(old, h) {
		// Retry once deterministically.
		return c.SeenOnce(nonce, nowMs, expMs)
	}
	c.expMs[victim].Store(expMs)
	c.lastMs[victim].Store(uint32(nowMs))
	return true
}

func telemetryDigest(schemaVersion int32, timestampMs int64, agentID string, nonce []byte, payload []byte) [sha256.Size]byte {
	h := sha256.New()
	var b4 [4]byte
	var b8 [8]byte
	binary.BigEndian.PutUint32(b4[:], uint32(schemaVersion))
	_, _ = h.Write(b4[:])
	binary.BigEndian.PutUint64(b8[:], uint64(timestampMs))
	_, _ = h.Write(b8[:])
	_, _ = h.Write([]byte(agentID))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(nonce)
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(payload)
	var out [sha256.Size]byte
	sum := h.Sum(nil)
	copy(out[:], sum)
	return out
}

func hash64(b []byte) uint64 {
	// FNV-1a 64-bit (deterministic, no alloc).
	const (
		offset64 = 14695981039346656037
		prime64  = 1099511628211
	)
	var h uint64 = offset64
	for _, c := range b {
		h ^= uint64(c)
		h *= prime64
	}
	return h
}

type ed25519Verifier struct {
	pub ed25519.PublicKey
}

func (v ed25519Verifier) Verify(payload []byte, sig []byte) bool {
	if len(v.pub) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(v.pub, payload, sig)
}

// VerifierFromContext builds a signature verifier from the mTLS client certificate public key.
// Fail-closed: any missing/unsupported key returns Unauthenticated.
func VerifierFromContext(ctx context.Context) (Verifier, error) {
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

	pub := tlsInfo.State.PeerCertificates[0].PublicKey
	switch k := pub.(type) {
	case ed25519.PublicKey:
		return ed25519Verifier{pub: k}, nil
	default:
		return nil, status.Error(codes.Unauthenticated, "unsupported client public key type (Ed25519 required)")
	}
}

