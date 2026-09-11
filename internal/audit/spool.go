package audit

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
)

type SpoolEntry struct {
	Version          uint8  `json:"version"`
	EntryID          string `json:"entry_id"`
	StreamID         string `json:"stream_id"`
	Sequence         uint64 `json:"sequence"`
	RecordHash       string `json:"record_hash"`
	Nonce            []byte `json:"nonce"`
	Ciphertext       []byte `json:"ciphertext"`
	CiphertextDigest string `json:"ciphertext_digest"`
}

type EncryptedSpool interface {
	Put(context.Context, Commit) error
	Entries(context.Context, string) ([]SpoolEntry, error)
	Open(context.Context, SpoolEntry) (Commit, error)
	Ack(context.Context, SpoolEntry) error
	Durable() bool
	Flush(context.Context) error
}

// MemoryEncryptedSpool is a deterministic test double. It never advertises
// durability; production must provide a filesystem/KMS-backed implementation.
type MemoryEncryptedSpool struct {
	mu           sync.Mutex
	aead         cipher.AEAD
	items        []SpoolEntry
	fingerprints map[string]string
	durable      bool
}

func NewMemoryEncryptedSpool(key []byte, durable ...bool) (*MemoryEncryptedSpool, error) {
	if len(key) != 32 {
		return nil, errors.New("audit spool requires a 32-byte AES-256 key")
	}
	block, err := aes.NewCipher(append([]byte(nil), key...))
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	d := false
	if len(durable) > 0 {
		d = durable[0]
	}
	return &MemoryEncryptedSpool{aead: aead, fingerprints: make(map[string]string), durable: d}, nil
}
func (s *MemoryEncryptedSpool) Durable() bool                   { return s != nil && s.durable }
func (s *MemoryEncryptedSpool) Flush(ctx context.Context) error { return contextErr(ctx) }
func (s *MemoryEncryptedSpool) Put(ctx context.Context, commit Commit) error {
	if s == nil || contextErr(ctx) != nil {
		if ctx == nil {
			return context.Canceled
		}
		return ctx.Err()
	}
	if validateCommit(commit) != nil {
		return ErrSpoolCorrupt
	}
	stream, record := commit.Record.Event.StreamID, commit.Record
	id := record.Event.EventID
	encoded, _ := json.Marshal(commit)
	fingerprint := hashBytes(encoded)
	s.mu.Lock()
	defer s.mu.Unlock()
	if prior, ok := s.fingerprints[id]; ok {
		if prior == fingerprint {
			return nil
		}
		return ErrReplayConflict
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return ErrSpoolCorrupt
	}
	aad := spoolAAD(stream, id, record.Sequence, record.Hash)
	ciphertext := s.aead.Seal(nil, nonce, encoded, aad)
	digest := sha256.Sum256(ciphertext)
	s.items = append(s.items, SpoolEntry{Version: 1, EntryID: id, StreamID: stream, Sequence: record.Sequence, RecordHash: record.Hash, Nonce: append([]byte(nil), nonce...), Ciphertext: append([]byte(nil), ciphertext...), CiphertextDigest: hex.EncodeToString(digest[:])})
	s.fingerprints[id] = fingerprint
	return nil
}
func spoolAAD(stream, id string, sequence uint64, hash string) []byte {
	b, _ := json.Marshal(struct {
		Version    uint8  `json:"version"`
		StreamID   string `json:"stream_id"`
		EntryID    string `json:"entry_id"`
		Sequence   uint64 `json:"sequence"`
		RecordHash string `json:"record_hash"`
	}{1, stream, id, sequence, hash})
	return b
}
func (s *MemoryEncryptedSpool) Entries(ctx context.Context, stream string) ([]SpoolEntry, error) {
	if s == nil {
		return nil, ErrSpoolCorrupt
	}
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]SpoolEntry, 0)
	for _, e := range s.items {
		if e.StreamID == stream {
			out = append(out, cloneSpoolEntry(e))
		}
	}
	return out, nil
}
func (s *MemoryEncryptedSpool) Open(ctx context.Context, entry SpoolEntry) (Commit, error) {
	if s == nil {
		return Commit{}, ErrSpoolCorrupt
	}
	if err := contextErr(ctx); err != nil {
		return Commit{}, err
	}
	if entry.Version != 1 || entry.StreamID == "" || entry.EntryID == "" || entry.Sequence == 0 || !isDigest(entry.RecordHash) || len(entry.Nonce) != s.aead.NonceSize() || len(entry.Ciphertext) < 16 || !isDigest(entry.CiphertextDigest) {
		return Commit{}, ErrSpoolCorrupt
	}
	digest := sha256.Sum256(entry.Ciphertext)
	if hex.EncodeToString(digest[:]) != entry.CiphertextDigest {
		return Commit{}, ErrSpoolCorrupt
	}
	plaintext, err := s.aead.Open(nil, entry.Nonce, entry.Ciphertext, spoolAAD(entry.StreamID, entry.EntryID, entry.Sequence, entry.RecordHash))
	if err != nil {
		return Commit{}, ErrSpoolCorrupt
	}
	var commit Commit
	err = decodeStrict(plaintext, &commit)
	for i := range plaintext {
		plaintext[i] = 0
	}
	if err != nil || commit.Record.Event.EventID != entry.EntryID || commit.Record.Event.StreamID != entry.StreamID || commit.Record.Sequence != entry.Sequence || commit.Record.Hash != entry.RecordHash || validateCommit(commit) != nil {
		return Commit{}, ErrSpoolCorrupt
	}
	return cloneCommit(commit), nil
}
func (s *MemoryEncryptedSpool) Ack(ctx context.Context, entry SpoolEntry) error {
	if s == nil {
		return ErrSpoolCorrupt
	}
	if err := contextErr(ctx); err != nil {
		return err
	}
	return nil
}
func cloneSpoolEntry(e SpoolEntry) SpoolEntry {
	e.Nonce = append([]byte(nil), e.Nonce...)
	e.Ciphertext = append([]byte(nil), e.Ciphertext...)
	return e
}
