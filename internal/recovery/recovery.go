// Package recovery defines the pure-Go recovery credential and wrapping-key
// contract. It keeps only digests/ciphertext in manager state and leaves KMS,
// keychain and durable revocation to adapters.
package recovery

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

const SecretSize = 32

var (
	ErrProviderUnavailable = errors.New("recovery key provider unavailable")
	ErrInvalidProvider     = errors.New("invalid recovery key provider")
	ErrInvalidRequest      = errors.New("invalid recovery request")
	ErrNotFound            = errors.New("recovery request not found")
	ErrThresholdNotMet     = errors.New("recovery administrator threshold not met")
	ErrInvalidAdmin        = errors.New("recovery administrator is not authorized")
	ErrConfirmationReplay  = errors.New("recovery confirmation already used")
	ErrAlreadyRecovered    = errors.New("recovery already completed")
	ErrDeliveryConsumed    = errors.New("recovery delivery already consumed")
)

type KeyOperation string

const (
	OperationWrap   KeyOperation = "wrap"
	OperationUnwrap KeyOperation = "unwrap"
	OperationRewrap KeyOperation = "rewrap"
)

// WrappingKeyPermission is an immutable, least-privilege authorization
// snapshot for a KEK operation. Integrations bind it to approval commits.
type WrappingKeyPermission struct {
	TenantID    string
	KeyID       string
	Operation   KeyOperation
	Scope       string
	PolicyEpoch uint64
	Actor       string
	ExpiresAt   time.Time
}

func (p WrappingKeyPermission) Allows(now time.Time, tenant, keyID, scope, actor string, operation KeyOperation, epoch uint64) error {
	if !strictIdentity(p.TenantID) || !strictIdentity(p.KeyID) || !strictIdentity(p.Scope) || !strictIdentity(p.Actor) || p.PolicyEpoch == 0 || p.ExpiresAt.IsZero() {
		return ErrInvalidRequest
	}
	if now.IsZero() || !now.Before(p.ExpiresAt) || p.PolicyEpoch != epoch || p.Operation != operation || p.TenantID != tenant || p.KeyID != keyID || p.Actor != actor || p.Scope != scope || !strictIdentity(tenant) || !strictIdentity(keyID) || !strictIdentity(actor) || !strictIdentity(scope) {
		return ErrInvalidRequest
	}
	return nil
}

// KeyProvider is intentionally compatible with diagnostics.KeyWrapper's
// semantics while adding availability probing for fail-closed selection.
type KeyProvider interface {
	Available(context.Context) bool
	Wrap(context.Context, string, []byte) ([]byte, error)
	Unwrap(context.Context, string, []byte) ([]byte, error)
}

// SelectProvider always prefers an available external KMS. Embedded material
// is accepted only when the caller explicitly approves single-node fallback.
func SelectProvider(kms, embedded KeyProvider, embeddedApproved bool) (KeyProvider, error) {
	if kms != nil && kms.Available(context.Background()) {
		return kms, nil
	}
	if embeddedApproved && embedded != nil && embedded.Available(context.Background()) {
		return embedded, nil
	}
	return nil, ErrProviderUnavailable
}

// EmbeddedProvider is an approved single-node provider. Key is process-local
// key material; production adapters should obtain it from OS keychain/TPM/
// DPAPI and only pass decrypted material for the brief operation lifetime.
type EmbeddedProvider struct{ Key []byte }

func (p *EmbeddedProvider) Available(context.Context) bool { return p != nil && len(p.Key) == 32 }
func (p *EmbeddedProvider) Wrap(ctx context.Context, version string, plaintext []byte) ([]byte, error) {
	return p.crypt(ctx, version, plaintext, true)
}
func (p *EmbeddedProvider) Unwrap(ctx context.Context, version string, wrapped []byte) ([]byte, error) {
	return p.crypt(ctx, version, wrapped, false)
}
func (p *EmbeddedProvider) crypt(ctx context.Context, version string, input []byte, seal bool) ([]byte, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	if !p.Available(ctx) || strings.TrimSpace(version) == "" {
		return nil, ErrInvalidProvider
	}
	b, err := aes.NewCipher(p.Key)
	if err != nil {
		return nil, err
	}
	a, err := cipher.NewGCM(b)
	if err != nil {
		return nil, err
	}
	aad := []byte("cheesewaf-recovery:" + version)
	if seal {
		n := make([]byte, a.NonceSize())
		if _, err = rand.Read(n); err != nil {
			return nil, err
		}
		return a.Seal(n, n, input, aad), nil
	}
	if len(input) < a.NonceSize() {
		return nil, ErrInvalidProvider
	}
	return a.Open(nil, input[:a.NonceSize()], input[a.NonceSize():], aad)
}

// HMACDigest returns a keyed digest suitable for credential metadata. The
// secret and pepper are never retained by this function.
func HMACDigest(secret, pepper []byte) []byte {
	h := hmac.New(sha256.New, pepper)
	_, _ = h.Write(secret)
	return h.Sum(nil)
}

type BeginRequest struct {
	Actor, Scope string
	TTL          time.Duration
}
type Issued struct {
	ID, Secret, Scope string
	ExpiresAt         time.Time
}

// RecoveryCredential is an adapter-friendly alias for an issued credential.
type RecoveryCredential = Issued
type RecoveryManager = Manager
type Confirmation struct{ AdminID, ConfirmationID string }

type TemporaryRevoker interface{ RevokeTemporary(context.Context) error }

type encryptedSecret struct {
	nonce, ciphertext []byte
	digest            [32]byte
}
type record struct {
	id, scope   string
	expires     time.Time
	secret      encryptedSecret
	admins      map[string]struct{}
	recovered   bool
	webConsumed bool
	cliConsumed bool
}
type Manager struct {
	mu      sync.Mutex
	admins  map[string]struct{}
	records map[string]*record
	used    map[string]struct{}
	sealKey [32]byte
}

func NewManager(admins []string) *Manager {
	m := &Manager{admins: map[string]struct{}{}, records: map[string]*record{}, used: map[string]struct{}{}}
	_, _ = rand.Read(m.sealKey[:])
	for _, a := range admins {
		if normalized, ok := strictAdminID(a); ok {
			m.admins[normalized] = struct{}{}
		}
	}
	return m
}

func (m *Manager) Begin(now time.Time, req BeginRequest) (Issued, error) {
	if now.IsZero() || !strictIdentity(req.Actor) || !strictIdentity(req.Scope) {
		return Issued{}, ErrInvalidRequest
	}
	if req.TTL <= 0 {
		req.TTL = 30 * time.Minute
	}
	if req.TTL > 30*time.Minute {
		return Issued{}, ErrInvalidRequest
	}
	secret := make([]byte, SecretSize)
	if _, err := rand.Read(secret); err != nil {
		return Issued{}, err
	}
	idb := make([]byte, 16)
	if _, err := rand.Read(idb); err != nil {
		return Issued{}, err
	}
	id := base64.RawURLEncoding.EncodeToString(idb)
	block, _ := aes.NewCipher(m.sealKey[:])
	a, _ := cipher.NewGCM(block)
	nonce := make([]byte, a.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return Issued{}, err
	}
	ct := a.Seal(nil, nonce, secret, []byte(id))
	digest := sha256.Sum256(secret)
	m.mu.Lock()
	m.records[id] = &record{id: id, scope: req.Scope, expires: now.Add(req.TTL), secret: encryptedSecret{nonce: nonce, ciphertext: ct, digest: digest}, admins: map[string]struct{}{}}
	m.mu.Unlock()
	return Issued{ID: id, Secret: string(secret), Scope: req.Scope, ExpiresAt: now.Add(req.TTL)}, nil
}

func (m *Manager) Confirm(now time.Time, id string, c Confirmation) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.records[id]
	if !ok {
		return 0, ErrNotFound
	}
	if r.recovered {
		return 0, ErrAlreadyRecovered
	}
	if !now.Before(r.expires) {
		return 0, ErrInvalidRequest
	}
	adminID, ok := strictAdminID(c.AdminID)
	if !ok {
		return 0, ErrInvalidAdmin
	}
	if _, ok := m.admins[adminID]; !ok {
		return 0, ErrInvalidAdmin
	}
	cid := strings.TrimSpace(c.ConfirmationID)
	if cid == "" {
		return 0, ErrInvalidRequest
	}
	if _, used := m.used[cid]; used {
		return 0, ErrConfirmationReplay
	}
	m.used[cid] = struct{}{}
	r.admins[adminID] = struct{}{}
	return len(r.admins), nil
}

func (m *Manager) Recover(now time.Time, id string, c Confirmation, revoker TemporaryRevoker) (string, error) {
	m.mu.Lock()
	r, ok := m.records[id]
	if !ok {
		m.mu.Unlock()
		return "", ErrNotFound
	}
	if r.recovered {
		m.mu.Unlock()
		return "", ErrAlreadyRecovered
	}
	if !now.Before(r.expires) {
		m.mu.Unlock()
		return "", ErrInvalidRequest
	}
	adminID, ok := strictAdminID(c.AdminID)
	if !ok {
		m.mu.Unlock()
		return "", ErrInvalidAdmin
	}
	if _, ok := m.admins[adminID]; !ok {
		m.mu.Unlock()
		return "", ErrInvalidAdmin
	}
	cid := strings.TrimSpace(c.ConfirmationID)
	if cid == "" {
		m.mu.Unlock()
		return "", ErrInvalidRequest
	}
	if _, used := m.used[cid]; used {
		m.mu.Unlock()
		return "", ErrConfirmationReplay
	}
	m.used[cid] = struct{}{}
	r.admins[adminID] = struct{}{}
	if len(r.admins) < 2 {
		n := len(r.admins)
		m.mu.Unlock()
		return "", fmt.Errorf("%w: %d of 2", ErrThresholdNotMet, n)
	}
	r.recovered = true
	secret, err := m.decrypt(r)
	m.mu.Unlock()
	if err != nil {
		return "", err
	}
	if revoker != nil {
		if err := revoker.RevokeTemporary(context.Background()); err != nil {
			return "", err
		}
	}
	return string(secret), nil
}

func (m *Manager) decrypt(r *record) ([]byte, error) {
	block, err := aes.NewCipher(m.sealKey[:])
	if err != nil {
		return nil, err
	}
	a, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	s, err := a.Open(nil, r.secret.nonce, r.secret.ciphertext, []byte(r.id))
	if err != nil {
		return nil, err
	}
	d := sha256.Sum256(s)
	if d != r.secret.digest {
		for i := range s {
			s[i] = 0
		}
		return nil, ErrInvalidRequest
	}
	return s, nil
}
func (m *Manager) WebDelivery(id string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.records[id]
	if !ok {
		return "", ErrNotFound
	}
	if r.webConsumed {
		return "", ErrDeliveryConsumed
	}
	s, err := m.decrypt(r)
	if err != nil {
		return "", err
	}
	r.webConsumed = true
	return string(s), nil
}
func (m *Manager) WriteCLIFile(id, path string) error {
	m.mu.Lock()
	r, ok := m.records[id]
	if !ok {
		m.mu.Unlock()
		return ErrNotFound
	}
	if r.cliConsumed {
		m.mu.Unlock()
		return ErrDeliveryConsumed
	}
	s, err := m.decrypt(r)
	if err != nil {
		m.mu.Unlock()
		return err
	}
	r.cliConsumed = true
	m.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(s)
	for i := range s {
		s[i] = 0
	}
	return err
}
func (m *Manager) RemoveCLIFile(path string) error { return os.Remove(path) }

func strictAdminID(value string) (string, bool) {
	if !strictIdentity(value) {
		return "", false
	}
	return value, true
}

// strictIdentity keeps security-sensitive identifiers byte-for-byte stable.
// Callers must reject malformed input rather than normalizing it at a trust
// boundary, so invisible format characters are covered as well as whitespace.
func strictIdentity(value string) bool {
	if value == "" || !utf8.ValidString(value) || value != strings.TrimSpace(value) {
		return false
	}
	return strings.IndexFunc(value, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r) || unicode.Is(unicode.Cf, r)
	}) < 0
}
