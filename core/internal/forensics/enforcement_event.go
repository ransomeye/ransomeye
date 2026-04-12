package forensics

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	wormcrypto "ransomeye/core/internal/crypto"
)

type EnforcementEvent struct {
	EventID       string  `json:"event_id"`
	Action        string  `json:"action"`
	Target        string  `json:"target"`
	DecisionScore float64 `json:"decision_score"`
	Timestamp     int64   `json:"timestamp"`
}

type StoredEnforcementEvent struct {
	Event      EnforcementEvent
	FilePath   string
	Nonce      []byte
	Ciphertext []byte
	Signature  []byte
}

type EnforcementEventWriter struct {
	worm *wormcrypto.WORM
	root string
	mu   sync.Mutex
}

type sealedEnforcementEnvelope struct {
	Event           EnforcementEvent `json:"event"`
	NonceBase64     string           `json:"nonce_base64"`
	CipherBase64    string           `json:"ciphertext_base64"`
	SignatureBase64 string           `json:"signature_base64"`
}

func NewEnforcementEventWriter(worm *wormcrypto.WORM) *EnforcementEventWriter {
	return &EnforcementEventWriter{
		worm: worm,
		root: os.Getenv("WORM_STORAGE_PATH"),
	}
}

func (w *EnforcementEventWriter) Record(agentID string, logicalClock int64, event EnforcementEvent) (StoredEnforcementEvent, error) {
	if w == nil || w.worm == nil {
		return StoredEnforcementEvent{}, errors.New("enforcement event writer not initialized")
	}
	if w.root == "" {
		return StoredEnforcementEvent{}, errors.New("WORM_STORAGE_PATH not set")
	}
	if agentID == "" {
		return StoredEnforcementEvent{}, errors.New("agent_id missing")
	}
	if event.EventID == "" || event.Action == "" || event.Target == "" {
		return StoredEnforcementEvent{}, errors.New("enforcement event fields missing")
	}

	path := filepath.Join(w.root, "enforcement", agentID, event.EventID+".sealed")

	w.mu.Lock()
	defer w.mu.Unlock()

	if _, err := os.Stat(path); err == nil {
		return loadStoredEnforcementEvent(path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return StoredEnforcementEvent{}, err
	}

	payload, err := json.Marshal(event)
	if err != nil {
		return StoredEnforcementEvent{}, err
	}
	ciphertext, nonce, err := w.worm.EncryptEvidence(payload)
	if err != nil {
		return StoredEnforcementEvent{}, err
	}
	sig, err := w.worm.SignEvidence(ciphertext, logicalClock, agentID, event.EventID, "enforcement")
	if err != nil {
		return StoredEnforcementEvent{}, err
	}
	if !w.worm.VerifyEvidence(ciphertext, logicalClock, agentID, event.EventID, "enforcement", sig) {
		return StoredEnforcementEvent{}, errors.New("enforcement event signature verification failed before write")
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return StoredEnforcementEvent{}, err
	}

	envelope := sealedEnforcementEnvelope{
		Event:           event,
		NonceBase64:     base64.StdEncoding.EncodeToString(nonce),
		CipherBase64:    base64.StdEncoding.EncodeToString(ciphertext),
		SignatureBase64: base64.StdEncoding.EncodeToString(sig),
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		return StoredEnforcementEvent{}, err
	}

	if err := writeImmutableFile(path, raw); err != nil {
		return StoredEnforcementEvent{}, err
	}

	return StoredEnforcementEvent{
		Event:      event,
		FilePath:   path,
		Nonce:      nonce,
		Ciphertext: ciphertext,
		Signature:  sig,
	}, nil
}

func loadStoredEnforcementEvent(path string) (StoredEnforcementEvent, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return StoredEnforcementEvent{}, err
	}
	var envelope sealedEnforcementEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return StoredEnforcementEvent{}, fmt.Errorf("decode sealed enforcement event: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(envelope.NonceBase64)
	if err != nil {
		return StoredEnforcementEvent{}, err
	}
	ciphertext, err := base64.StdEncoding.DecodeString(envelope.CipherBase64)
	if err != nil {
		return StoredEnforcementEvent{}, err
	}
	sig, err := base64.StdEncoding.DecodeString(envelope.SignatureBase64)
	if err != nil {
		return StoredEnforcementEvent{}, err
	}
	return StoredEnforcementEvent{
		Event:      envelope.Event,
		FilePath:   path,
		Nonce:      nonce,
		Ciphertext: ciphertext,
		Signature:  sig,
	}, nil
}

func writeImmutableFile(path string, raw []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		_ = tmp.Close()
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := tmp.Write(raw); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, 0o444); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	cleanup = false
	return fsyncEnforcementFile(path)
}

func fsyncEnforcementFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
