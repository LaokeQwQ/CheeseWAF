package store

import (
	"bytes"
	"context"
	"sync"
)

type StandaloneStore struct {
	mu      sync.RWMutex
	objects map[Key][]byte
}

func NewStandaloneStore() *StandaloneStore {
	return &StandaloneStore{objects: map[Key][]byte{}}
}

func (s *StandaloneStore) Get(_ context.Context, key Key) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	value, ok := s.objects[key]
	if !ok {
		return nil, ErrNotFound
	}
	return bytes.Clone(value), nil
}

func (s *StandaloneStore) List(_ context.Context, kind string) (map[Key][]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := map[Key][]byte{}
	for key, value := range s.objects {
		if kind != "" && key.Kind != kind {
			continue
		}
		out[key] = bytes.Clone(value)
	}
	return out, nil
}

func (s *StandaloneStore) Put(_ context.Context, key Key, value []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.objects[key] = bytes.Clone(value)
	return nil
}

func (s *StandaloneStore) Delete(_ context.Context, key Key) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.objects[key]; !ok {
		return ErrNotFound
	}
	delete(s.objects, key)
	return nil
}

func (s *StandaloneStore) Status(_ context.Context) (Status, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return Status{
		Provider:          "standalone",
		MajorityConfirmed: true,
		ReadOnly:          false,
		ObjectCount:       len(s.objects),
	}, nil
}
