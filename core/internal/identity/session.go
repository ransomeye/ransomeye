package identity

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sort"
	"sync"
	"time"
)

const (
	// Ephemeral sessions are memory-only; TTL is enforced to bound memory and revoke stale sessions.
	// In V0.0, heartbeat/telemetry refresh the session via Touch().
	defaultSessionTTL = 15 * time.Minute
)

var (
	ErrInvalidSession = errors.New("invalid session")
	ErrExpiredSession = errors.New("expired session")
)

type AgentSession struct {
	AgentID       string
	BootSessionID string
	TLSBinding    string
	LastSeen      time.Time
}

type SessionManager struct {
	mu       sync.RWMutex
	sessions map[string]AgentSession
	ttl      time.Duration
}

func NewSessionManager() *SessionManager {
	return &SessionManager{
		sessions: make(map[string]AgentSession),
		ttl:      defaultSessionTTL,
	}
}

func (m *SessionManager) CreateSession(identityID, bootSessionID, tlsBinding string) string {
	token := newUUIDv4()
	m.mu.Lock()
	m.sessions[token] = AgentSession{
		AgentID:       identityID,
		BootSessionID: bootSessionID,
		TLSBinding:    tlsBinding,
		LastSeen:      time.Now().UTC(),
	}
	m.mu.Unlock()
	return token
}

// HasFixationConflict returns true if (identity, boot_session_id) exists with a different TLS binding.
func (m *SessionManager) HasFixationConflict(identityID, bootSessionID, tlsBinding string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, s := range m.sessions {
		if s.AgentID == identityID && s.BootSessionID == bootSessionID && s.TLSBinding != tlsBinding {
			return true
		}
	}
	return false
}

func (m *SessionManager) ValidateSession(sessionToken string) (string, error) {
	if sessionToken == "" {
		return "", ErrInvalidSession
	}

	m.mu.RLock()
	s, ok := m.sessions[sessionToken]
	m.mu.RUnlock()
	if !ok {
		return "", ErrInvalidSession
	}

	if time.Since(s.LastSeen) > m.ttl {
		m.mu.Lock()
		delete(m.sessions, sessionToken)
		m.mu.Unlock()
		return "", ErrExpiredSession
	}

	return s.AgentID, nil
}

func (m *SessionManager) Touch(sessionToken string) error {
	if sessionToken == "" {
		return ErrInvalidSession
	}
	m.mu.Lock()
	s, ok := m.sessions[sessionToken]
	if !ok {
		m.mu.Unlock()
		return ErrInvalidSession
	}
	if time.Since(s.LastSeen) > m.ttl {
		delete(m.sessions, sessionToken)
		m.mu.Unlock()
		return ErrExpiredSession
	}
	s.LastSeen = time.Now().UTC()
	m.sessions[sessionToken] = s
	m.mu.Unlock()
	return nil
}

// TouchByBinding deterministically refreshes the lexicographically first live
// session matching the provided agent and boot session identifiers.
func (m *SessionManager) TouchByBinding(identityID, bootSessionID, tlsBinding string) error {
	if identityID == "" || bootSessionID == "" || tlsBinding == "" {
		return ErrInvalidSession
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	matches := make([]string, 0)
	for token, session := range m.sessions {
		if session.AgentID == identityID && session.BootSessionID == bootSessionID && session.TLSBinding == tlsBinding {
			matches = append(matches, token)
		}
	}
	if len(matches) == 0 {
		return ErrInvalidSession
	}

	sort.Strings(matches)
	now := time.Now().UTC()
	sawExpired := false
	for _, token := range matches {
		session, ok := m.sessions[token]
		if !ok {
			continue
		}
		if now.Sub(session.LastSeen) > m.ttl {
			delete(m.sessions, token)
			sawExpired = true
			continue
		}
		session.LastSeen = now
		m.sessions[token] = session
		return nil
	}
	if sawExpired {
		return ErrExpiredSession
	}
	return ErrInvalidSession
}

// SnapshotSessions returns a point-in-time copy of all sessions.
// The returned map and values are safe to read without holding locks.
func (m *SessionManager) SnapshotSessions() map[string]AgentSession {
	m.mu.RLock()
	out := make(map[string]AgentSession, len(m.sessions))
	for k, v := range m.sessions {
		out[k] = v
	}
	m.mu.RUnlock()
	return out
}

// DeleteSession deletes the session token if present and returns the removed session.
func (m *SessionManager) DeleteSession(sessionToken string) (AgentSession, bool) {
	m.mu.Lock()
	s, ok := m.sessions[sessionToken]
	if ok {
		delete(m.sessions, sessionToken)
	}
	m.mu.Unlock()
	return s, ok
}

// DeleteByBinding removes all sessions matching (identity, boot_session_id).
func (m *SessionManager) DeleteByBinding(identity, bootSessionID string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	removed := 0
	for token, s := range m.sessions {
		if s.AgentID == identity && s.BootSessionID == bootSessionID {
			delete(m.sessions, token)
			removed++
		}
	}
	return removed
}

func newUUIDv4() string {
	var b [16]byte
	_, err := rand.Read(b[:])
	if err != nil {
		// crypto/rand failure is fatal for identity; callers will surface as auth failure upstream.
		// We return empty string to avoid panics in hot paths.
		return ""
	}
	b[6] = (b[6] & 0x0f) | 0x40 // Version 4
	b[8] = (b[8] & 0x3f) | 0x80 // Variant RFC 4122

	var out [36]byte
	hex.Encode(out[0:8], b[0:4])
	out[8] = '-'
	hex.Encode(out[9:13], b[4:6])
	out[13] = '-'
	hex.Encode(out[14:18], b[6:8])
	out[18] = '-'
	hex.Encode(out[19:23], b[8:10])
	out[23] = '-'
	hex.Encode(out[24:36], b[10:16])
	return string(out[:])
}
