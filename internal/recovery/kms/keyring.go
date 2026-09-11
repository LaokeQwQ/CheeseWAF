package kms

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
)

// RootKeySource loads a 32-byte key from an OS keychain, TPM, DPAPI adapter,
// or another protected store. Unsupported platforms should return ErrUnsupported.
type RootKeySource interface {
	Available(context.Context) bool
	Load(context.Context) ([]byte, error)
}
type KeySource = RootKeySource

type keyEntry struct {
	Ref     KeyRef
	Data    []byte
	Revoked bool
}
type keyringDocument struct {
	Schema  string
	Entries []keyEntry
}
type sealedKeyringDocument struct {
	Schema     string
	Nonce      []byte
	Ciphertext []byte
}

// EncryptedKeyring keeps encrypted KEKs in memory and in an explicitly
// exported encrypted document. Plaintext KEKs are not retained after calls.
type EncryptedKeyring struct {
	mu      sync.RWMutex
	source  RootKeySource
	entries map[string]keyEntry
}

func NewEncryptedKeyring(source RootKeySource) (*EncryptedKeyring, error) {
	if source == nil {
		return nil, ErrUnsupported
	}
	return &EncryptedKeyring{source: source, entries: make(map[string]keyEntry)}, nil
}

func OpenEncryptedKeyring(ctx context.Context, source RootKeySource, encoded []byte) (*EncryptedKeyring, error) {
	kr, err := NewEncryptedKeyring(source)
	if err != nil {
		return nil, err
	}
	var sealed sealedKeyringDocument
	dec := json.NewDecoder(bytes.NewReader(encoded))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&sealed); err != nil {
		return nil, ErrAuthentication
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, ErrAuthentication
	}
	if sealed.Schema != keyringSchema || len(sealed.Nonce) != chacha20poly1305.NonceSizeX || len(sealed.Ciphertext) < 16 {
		return nil, ErrAuthentication
	}
	root, err := kr.master(ctx)
	if err != nil {
		return nil, err
	}
	defer zero(root)
	a, err := chacha20poly1305.NewX(root)
	if err != nil {
		return nil, ErrUnsupported
	}
	plain, err := a.Open(nil, sealed.Nonce, sealed.Ciphertext, []byte(keyringSchema))
	if err != nil {
		return nil, ErrAuthentication
	}
	defer zero(plain)
	var doc keyringDocument
	dec = json.NewDecoder(bytes.NewReader(plain))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return nil, ErrAuthentication
	}
	if doc.Schema != keyringSchema {
		return nil, ErrAuthentication
	}
	for _, e := range doc.Entries {
		if !validRef(e.Ref) || len(e.Data) < 24+16 || len(e.Data) > maxWrappedSize {
			return nil, ErrAuthentication
		}
		key := refKey(e.Ref)
		if _, ok := kr.entries[key]; ok {
			return nil, ErrAuthentication
		}
		kr.entries[key] = keyEntry{Ref: e.Ref, Data: append([]byte(nil), e.Data...), Revoked: e.Revoked}
	}
	if err := kr.probe(ctx); err != nil && !errors.Is(err, ErrUnsupported) && !errors.Is(err, ErrUnavailable) {
		return nil, err
	}
	return kr, nil
}

const keyringSchema = "cheesewaf-keyring.v1"

func (k *EncryptedKeyring) Put(ctx context.Context, ref KeyRef, kek []byte) error {
	if k == nil || !validRef(ref) || len(kek) != DEKSize {
		return ErrInvalidInput
	}
	input := append([]byte(nil), kek...)
	sealed, err := k.seal(ctx, ref, input)
	zero(input)
	if err != nil {
		return err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	key := refKey(ref)
	if _, ok := k.entries[key]; ok {
		zero(sealed)
		return ErrVersion
	}
	k.entries[key] = keyEntry{Ref: ref, Data: sealed}
	return nil
}
func (k *EncryptedKeyring) Rotate(ctx context.Context, ref KeyRef, kek []byte) error {
	return k.Put(ctx, ref, kek)
}
func (k *EncryptedKeyring) Revoke(ctx context.Context, ref KeyRef) error {
	if err := contextErr(ctx); err != nil {
		return err
	}
	if k == nil || !validRef(ref) {
		return ErrInvalidInput
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	e, ok := k.entries[refKey(ref)]
	if !ok {
		return ErrVersion
	}
	e.Revoked = true
	k.entries[refKey(ref)] = e
	return nil
}
func (k *EncryptedKeyring) Get(ctx context.Context, ref KeyRef) ([]byte, error) {
	if k == nil || !validRef(ref) {
		return nil, ErrInvalidInput
	}
	k.mu.RLock()
	e, ok := k.entries[refKey(ref)]
	k.mu.RUnlock()
	if !ok {
		return nil, ErrVersion
	}
	if e.Revoked {
		return nil, ErrVersion
	}
	return k.open(ctx, e.Ref, e.Data)
}
func (k *EncryptedKeyring) LatestRef() (KeyRef, error) {
	if k == nil {
		return KeyRef{}, ErrInvalidConfig
	}
	k.mu.RLock()
	defer k.mu.RUnlock()
	refs := make([]KeyRef, 0, len(k.entries))
	for _, e := range k.entries {
		if !e.Revoked {
			refs = append(refs, e.Ref)
		}
	}
	if len(refs) == 0 {
		return KeyRef{}, ErrVersion
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].Version < refs[j].Version })
	return refs[len(refs)-1], nil
}
func (k *EncryptedKeyring) MarshalBinary() ([]byte, error) {
	if k == nil {
		return nil, ErrInvalidConfig
	}
	k.mu.RLock()
	defer k.mu.RUnlock()
	entries := make([]keyEntry, 0, len(k.entries))
	for _, e := range k.entries {
		entries = append(entries, keyEntry{Ref: e.Ref, Data: append([]byte(nil), e.Data...), Revoked: e.Revoked})
	}
	sort.Slice(entries, func(i, j int) bool { return refKey(entries[i].Ref) < refKey(entries[j].Ref) })
	plain, err := json.Marshal(keyringDocument{Schema: keyringSchema, Entries: entries})
	if err != nil {
		return nil, ErrInvalidConfig
	}
	root, err := k.master(context.Background())
	if err != nil {
		zero(plain)
		return nil, err
	}
	defer zero(root)
	a, err := chacha20poly1305.NewX(root)
	if err != nil {
		zero(plain)
		return nil, ErrUnsupported
	}
	nonce := make([]byte, a.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		zero(plain)
		return nil, ErrProviderFailure
	}
	ciphertext := a.Seal(nil, nonce, plain, []byte(keyringSchema))
	zero(plain)
	return json.Marshal(sealedKeyringDocument{Schema: keyringSchema, Nonce: nonce, Ciphertext: ciphertext})
}
func (k *EncryptedKeyring) Close() error {
	if k == nil {
		return nil
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	for key, e := range k.entries {
		zero(e.Data)
		delete(k.entries, key)
	}
	return nil
}

func (k *EncryptedKeyring) probe(ctx context.Context) error {
	if k.source == nil {
		return ErrUnsupported
	}
	if !k.source.Available(ctx) {
		root, err := k.source.Load(ctx)
		zero(root)
		if errors.Is(err, ErrUnsupported) {
			return ErrUnsupported
		}
		return ErrUnavailable
	}
	root, err := k.source.Load(ctx)
	if err != nil {
		return classifySource(err)
	}
	defer zero(root)
	if len(root) != 32 {
		return ErrUnsupported
	}
	return nil
}
func (k *EncryptedKeyring) master(ctx context.Context) ([]byte, error) {
	if k == nil || k.source == nil {
		return nil, ErrUnsupported
	}
	if !k.source.Available(ctx) {
		root, err := k.source.Load(ctx)
		zero(root)
		if errors.Is(err, ErrUnsupported) {
			return nil, ErrUnsupported
		}
		return nil, ErrUnavailable
	}
	root, err := k.source.Load(ctx)
	if err != nil {
		return nil, classifySource(err)
	}
	if len(root) != 32 {
		zero(root)
		return nil, ErrUnsupported
	}
	return root, nil
}
func (k *EncryptedKeyring) seal(ctx context.Context, ref KeyRef, plain []byte) ([]byte, error) {
	root, err := k.master(ctx)
	if err != nil {
		return nil, err
	}
	defer zero(root)
	a, err := chacha20poly1305.NewX(root)
	if err != nil {
		return nil, ErrUnsupported
	}
	n := make([]byte, a.NonceSize())
	if _, err := rand.Read(n); err != nil {
		return nil, ErrProviderFailure
	}
	return a.Seal(n, n, plain, refAAD(ref)), nil
}
func (k *EncryptedKeyring) open(ctx context.Context, ref KeyRef, data []byte) ([]byte, error) {
	root, err := k.master(ctx)
	if err != nil {
		return nil, err
	}
	defer zero(root)
	a, err := chacha20poly1305.NewX(root)
	if err != nil {
		return nil, ErrUnsupported
	}
	if len(data) < a.NonceSize()+a.Overhead() {
		return nil, ErrAuthentication
	}
	plain, err := a.Open(nil, data[:a.NonceSize()], data[a.NonceSize():], refAAD(ref))
	if err != nil {
		return nil, ErrAuthentication
	}
	if len(plain) != DEKSize {
		zero(plain)
		return nil, ErrAuthentication
	}
	return plain, nil
}

// KeyringBackend implements Backend with AES-256-GCM DEK wrapping.
type KeyringBackend struct{ keyring *EncryptedKeyring }

func NewKeyringBackend(keyring *EncryptedKeyring) *KeyringBackend {
	return &KeyringBackend{keyring: keyring}
}
func (b *KeyringBackend) Available(ctx context.Context) bool {
	return b != nil && b.keyring != nil && b.keyring.probe(ctx) == nil
}
func (b *KeyringBackend) Wrap(ctx context.Context, ref KeyRef, dek []byte) ([]byte, error) {
	if b == nil || b.keyring == nil {
		return nil, ErrUnsupported
	}
	if err := b.keyring.probe(ctx); err != nil {
		return nil, err
	}
	if len(dek) != DEKSize {
		return nil, ErrInvalidInput
	}
	if b.keyring.hasDifferentTenant(ref) {
		return nil, ErrBinding
	}
	k, err := b.keyring.Get(ctx, ref)
	if err != nil {
		return nil, err
	}
	defer zero(k)
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, ErrUnsupported
	}
	a, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrUnsupported
	}
	n := make([]byte, a.NonceSize())
	if _, err := rand.Read(n); err != nil {
		return nil, ErrProviderFailure
	}
	return a.Seal(n, n, dek, refAAD(ref)), nil
}
func (b *KeyringBackend) Unwrap(ctx context.Context, ref KeyRef, wrapped []byte) ([]byte, error) {
	if b == nil || b.keyring == nil {
		return nil, ErrUnsupported
	}
	if err := b.keyring.probe(ctx); err != nil {
		return nil, err
	}
	if b.keyring.hasDifferentTenant(ref) {
		return nil, ErrBinding
	}
	k, err := b.keyring.Get(ctx, ref)
	if err != nil {
		return nil, err
	}
	defer zero(k)
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, ErrUnsupported
	}
	a, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrUnsupported
	}
	if len(wrapped) < a.NonceSize()+a.Overhead() {
		return nil, ErrAuthentication
	}
	plain, err := a.Open(nil, wrapped[:a.NonceSize()], wrapped[a.NonceSize():], refAAD(ref))
	if err != nil {
		return nil, ErrAuthentication
	}
	if len(plain) != DEKSize {
		zero(plain)
		return nil, ErrAuthentication
	}
	return plain, nil
}
func (b *KeyringBackend) Rotate(ctx context.Context, ref KeyRef) error {
	key := make([]byte, DEKSize)
	if _, err := rand.Read(key); err != nil {
		return ErrProviderFailure
	}
	return b.keyring.Rotate(ctx, ref, key)
}
func (b *KeyringBackend) Revoke(ctx context.Context, ref KeyRef) error {
	return b.keyring.Revoke(ctx, ref)
}

func (k *EncryptedKeyring) hasDifferentTenant(ref KeyRef) bool {
	k.mu.RLock()
	defer k.mu.RUnlock()
	for _, e := range k.entries {
		if e.Ref.KeyID == ref.KeyID && e.Ref.Version == ref.Version && e.Ref.TenantID != ref.TenantID {
			return true
		}
	}
	return false
}

func validRef(ref KeyRef) bool {
	return strict(ref.TenantID) && strict(ref.KeyID) && validVersion(ref.Version)
}
func refKey(ref KeyRef) string { return ref.TenantID + "\x00" + ref.KeyID + "\x00" + ref.Version }
func refAAD(ref KeyRef) []byte {
	var out bytes.Buffer
	out.WriteString("cheesewaf-kms:v1")
	for _, value := range []string{ref.TenantID, ref.KeyID, ref.Version, ref.Scope, ref.Actor} {
		b := []byte(value)
		_ = binary.Write(&out, binary.BigEndian, uint64(len(b)))
		_, _ = out.Write(b)
	}
	_ = binary.Write(&out, binary.BigEndian, ref.PolicyEpoch)
	return out.Bytes()
}
func classifySource(err error) error {
	if errors.Is(err, ErrUnsupported) {
		return ErrUnsupported
	}
	return ErrUnavailable
}
