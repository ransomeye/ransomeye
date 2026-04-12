package keys

import "sync"

type Store struct {
	mu   sync.Mutex
	data map[string]Metadata
}

func NewStore() *Store {
	return &Store{data: make(map[string]Metadata)}
}

func (s *Store) Save(scope string, meta Metadata) error {
	if err := ValidateMetadata(meta); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[scope] = meta
	return nil
}

func (s *Store) Load(scope string) (Metadata, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	meta, ok := s.data[scope]
	return meta, ok
}

func (s *Store) Snapshot() map[string]Metadata {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]Metadata, len(s.data))
	for k, v := range s.data {
		out[k] = v
	}
	return out
}
