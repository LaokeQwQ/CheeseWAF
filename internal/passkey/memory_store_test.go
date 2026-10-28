package passkey

import (
	"bytes"
	"context"
	"slices"
	"sort"
	"sync"
	"time"
)

type memoryStore struct {
	mu       sync.Mutex
	creds    map[string]*Credential
	recovery map[string][][]byte
	audits   []AuditEvent
}

func newMemoryStore() *memoryStore {
	return &memoryStore{
		creds:    make(map[string]*Credential),
		recovery: make(map[string][][]byte),
	}
}

func (m *memoryStore) ListByUser(_ context.Context, userID string) ([]*Credential, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var out []*Credential

	for _, credential := range m.creds {
		if credential.UserID == userID {
			out = append(out, cloneCredential(credential))
		}
	}

	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })

	return out, nil
}

func (m *memoryStore) GetByCredentialID(_ context.Context, credentialID []byte) (*Credential, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, credential := range m.creds {
		if bytes.Equal(credential.CredentialID, credentialID) {
			return cloneCredential(credential), nil
		}
	}

	return nil, ErrNotFound
}

func (m *memoryStore) Create(_ context.Context, credential *Credential) error {
	if credential == nil {
		return ErrInvalidCredential
	}

	if err := credential.Validate(); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.creds[credential.ID]; ok {
		return ErrCredentialExists
	}

	for _, existing := range m.creds {
		if bytes.Equal(existing.CredentialID, credential.CredentialID) {
			return ErrCredentialExists
		}
	}

	m.creds[credential.ID] = cloneCredential(credential)

	return nil
}

func (m *memoryStore) UpdateSignCount(_ context.Context, id string, signCount uint32, lastUsedAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	credential, ok := m.creds[id]
	if !ok {
		return ErrNotFound
	}

	credential.SignCount = signCount
	credential.LastUsedAt = lastUsedAt

	return nil
}

func (m *memoryStore) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.creds[id]; !ok {
		return ErrNotFound
	}

	delete(m.creds, id)

	return nil
}

func (m *memoryStore) DeleteByUser(_ context.Context, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for id, credential := range m.creds {
		if credential.UserID == userID {
			delete(m.creds, id)
		}
	}

	return nil
}

func (m *memoryStore) ReplaceRecoveryCodes(_ context.Context, userID string, hashes [][]byte, _ time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	copied := make([][]byte, len(hashes))
	for i, hash := range hashes {
		copied[i] = slices.Clone(hash)
	}

	m.recovery[userID] = copied

	return nil
}

func (m *memoryStore) ConsumeRecoveryCode(_ context.Context, userID string, hash []byte, _ time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	hashes := m.recovery[userID]
	for i, stored := range hashes {
		if bytes.Equal(stored, hash) {
			m.recovery[userID] = append(hashes[:i:i], hashes[i+1:]...)
			return true, nil
		}
	}

	return false, nil
}

func (m *memoryStore) DeleteRecoveryCodes(_ context.Context, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.recovery, userID)

	return nil
}

func (m *memoryStore) RecordAudit(_ context.Context, event AuditEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.audits = append(m.audits, event)

	return nil
}

func (m *memoryStore) recoveryHashes(userID string) [][]byte {
	m.mu.Lock()
	defer m.mu.Unlock()

	copied := make([][]byte, len(m.recovery[userID]))
	for i, hash := range m.recovery[userID] {
		copied[i] = slices.Clone(hash)
	}

	return copied
}

func (m *memoryStore) auditEvents() []AuditEvent {
	m.mu.Lock()
	defer m.mu.Unlock()

	return slices.Clone(m.audits)
}

func cloneCredential(credential *Credential) *Credential {
	copied := *credential
	copied.CredentialID = slices.Clone(credential.CredentialID)
	copied.PublicKey = slices.Clone(credential.PublicKey)
	copied.Transports = slices.Clone(credential.Transports)
	copied.AAGUID = slices.Clone(credential.AAGUID)
	return &copied
}
