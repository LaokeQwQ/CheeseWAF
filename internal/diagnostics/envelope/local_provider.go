package envelope

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"sync"
)

const (
	localWrapMagic       = "cheesewaf-kek-v1"
	localWrapNonceOffset = len(localWrapMagic)
	localWrapMinBytes    = len(localWrapMagic) + NonceSize + DEKSize + GCMTagSize
)

// LocalProvider is an explicit single-node/offline fallback. It keeps KEKs in
// process memory, supports key-version rotation, and has no network or storage
// behavior. Production deployments should provide an external KMS instead.
type LocalProvider struct {
	mu     sync.RWMutex
	keys   map[string][]byte
	closed bool
}

// LocalProviderOptions makes the offline/single-node exception explicit at
// composition time. It exists for integrations that need to reject accidental
// local fallback from configuration.
type LocalProviderOptions struct {
	OfflineFallback bool
	SingleNode      bool
}

// NewLocalProviderWithOptions only permits the embedded provider when both
// offline fallback and single-node operation were deliberately selected.
func NewLocalProviderWithOptions(keyVersion string, kek []byte, options LocalProviderOptions) (*LocalProvider, error) {
	if !options.OfflineFallback || !options.SingleNode {
		return nil, fmt.Errorf("%w: local provider requires explicit offline single-node mode", ErrInvalidProvider)
	}
	return NewLocalProvider(keyVersion, kek)
}

// NewLocalProvider creates an explicit local provider with one KEK version.
// The input key is copied and is never retained by reference. KEKs must be
// exactly 32 bytes so the local wrapper has AES-256 strength.
func NewLocalProvider(keyVersion string, kek []byte) (*LocalProvider, error) {
	if err := validateKeyVersion(keyVersion); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidProvider, err)
	}
	if err := validateKEK(kek); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidProvider, err)
	}
	return &LocalProvider{keys: map[string][]byte{keyVersion: cloneBytes(kek)}}, nil
}

// NewEmbeddedProvider is an explicit compatibility spelling for the offline
// provider; it is never selected implicitly by Seal or Open.
func NewEmbeddedProvider(keyVersion string, kek []byte) (*LocalProvider, error) {
	return NewLocalProvider(keyVersion, kek)
}

// NewOfflineProvider is an explicit spelling for the single-node fallback.
func NewOfflineProvider(keyVersion string, kek []byte) (*LocalProvider, error) {
	return NewLocalProviderWithOptions(keyVersion, kek, LocalProviderOptions{OfflineFallback: true, SingleNode: true})
}

// NewLocalKeyProvider is another compatibility spelling for NewLocalProvider.
func NewLocalKeyProvider(keyVersion string, kek []byte) (*LocalProvider, error) {
	return NewLocalProvider(keyVersion, kek)
}

// Rotate adds a new KEK version. Version identifiers are immutable and remain
// available until Retire is called, allowing resumable rewraps during rotation.
func (p *LocalProvider) Rotate(keyVersion string, kek []byte) error {
	if p == nil {
		return ErrProviderUnavailable
	}
	if err := validateKeyVersion(keyVersion); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidProvider, err)
	}
	if err := validateKEK(kek); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidProvider, err)
	}
	copyOfKey := cloneBytes(kek)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		zeroBytes(copyOfKey)
		return ErrProviderClosed
	}
	if p.keys == nil {
		p.keys = make(map[string][]byte)
	}
	if _, exists := p.keys[keyVersion]; exists {
		zeroBytes(copyOfKey)
		return ErrKeyVersionExists
	}
	p.keys[keyVersion] = copyOfKey
	return nil
}

// Retire removes one key version after all envelopes have been rewrapped.
func (p *LocalProvider) Retire(keyVersion string) error {
	if p == nil {
		return ErrProviderUnavailable
	}
	if err := validateKeyVersion(keyVersion); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidProvider, err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return ErrProviderClosed
	}
	if key := p.keys[keyVersion]; key != nil {
		zeroBytes(key)
		delete(p.keys, keyVersion)
	}
	return nil
}

// Close erases every in-memory KEK and permanently disables this provider.
func (p *LocalProvider) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	for version, key := range p.keys {
		zeroBytes(key)
		delete(p.keys, version)
	}
	p.closed = true
	return nil
}

// OfflineOnly reports that this provider is an in-process, single-node
// fallback and must not be treated as an external KMS implementation.
func (p *LocalProvider) OfflineOnly() bool { return true }

// Available reports whether the explicit local provider still holds KEK
// material. It never probes a network service.
func (p *LocalProvider) Available(context.Context) bool {
	if p == nil {
		return false
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return !p.closed && len(p.keys) > 0
}

// Wrap implements KeyProvider. The wrapped representation contains a local
// format marker, a random nonce, and AES-GCM ciphertext of exactly one DEK.
func (p *LocalProvider) Wrap(ctx context.Context, keyVersion string, dek []byte) ([]byte, error) {
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	if p == nil {
		return nil, ErrProviderUnavailable
	}
	if err := validateKeyVersion(keyVersion); err != nil {
		return nil, err
	}
	if len(dek) != DEKSize {
		return nil, fmt.Errorf("%w: DEK must be %d bytes", ErrKeyWrap, DEKSize)
	}
	key, err := p.copyKey(keyVersion)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("%w: initialize KEK cipher: %v", ErrKeyWrap, err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: initialize KEK AEAD: %v", ErrKeyWrap, err)
	}
	nonce := make([]byte, NonceSize)
	defer zeroBytes(nonce)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("%w: generate wrapping nonce: %v", ErrKeyWrap, err)
	}
	aad := localWrapAAD(keyVersion)
	defer zeroBytes(aad)
	ciphertext := aead.Seal(nil, nonce, dek, aad)
	defer zeroBytes(ciphertext)
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	if p.isClosed() {
		return nil, ErrProviderClosed
	}
	out := make([]byte, 0, len(localWrapMagic)+len(nonce)+len(ciphertext))
	out = append(out, localWrapMagic...)
	out = append(out, nonce...)
	out = append(out, ciphertext...)
	return out, nil
}

// WrapDEK is a compatibility method for adapters that use explicit DEK names.
func (p *LocalProvider) WrapDEK(ctx context.Context, keyVersion string, dek []byte) ([]byte, error) {
	return p.Wrap(ctx, keyVersion, dek)
}

// Unwrap implements KeyProvider and verifies the local wrapper marker and GCM
// tag before returning a fresh 32-byte DEK.
func (p *LocalProvider) Unwrap(ctx context.Context, keyVersion string, wrapped []byte) ([]byte, error) {
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	if p == nil {
		return nil, ErrProviderUnavailable
	}
	if err := validateKeyVersion(keyVersion); err != nil {
		return nil, err
	}
	if len(wrapped) < localWrapMinBytes || len(wrapped) > MaxWrappedDEKBytes {
		return nil, fmt.Errorf("%w: local wrapped DEK length out of bounds", ErrKeyUnwrap)
	}
	if !bytes.Equal(wrapped[:len(localWrapMagic)], []byte(localWrapMagic)) {
		return nil, fmt.Errorf("%w: unknown local wrapper format", ErrKeyUnwrap)
	}
	key, err := p.copyKey(keyVersion)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("%w: initialize KEK cipher: %v", ErrKeyUnwrap, err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: initialize KEK AEAD: %v", ErrKeyUnwrap, err)
	}
	nonceStart := localWrapNonceOffset
	nonceEnd := nonceStart + aead.NonceSize()
	if len(wrapped) <= nonceEnd || len(wrapped)-nonceEnd < aead.Overhead() {
		return nil, fmt.Errorf("%w: malformed local wrapper lengths", ErrKeyUnwrap)
	}
	nonce := wrapped[nonceStart:nonceEnd]
	ciphertext := wrapped[nonceEnd:]
	aad := localWrapAAD(keyVersion)
	defer zeroBytes(aad)
	dek, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		if dek != nil {
			zeroBytes(dek)
		}
		return nil, fmt.Errorf("%w: %v", ErrKeyUnwrap, err)
	}
	if err := contextErr(ctx); err != nil {
		zeroBytes(dek)
		return nil, err
	}
	if len(dek) != DEKSize {
		zeroBytes(dek)
		return nil, fmt.Errorf("%w: unwrapped DEK must be %d bytes", ErrKeyUnwrap, DEKSize)
	}
	if p.isClosed() {
		zeroBytes(dek)
		return nil, ErrProviderClosed
	}
	return dek, nil
}

// UnwrapDEK is a compatibility method for adapters that use explicit DEK names.
func (p *LocalProvider) UnwrapDEK(ctx context.Context, keyVersion string, wrapped []byte) ([]byte, error) {
	return p.Unwrap(ctx, keyVersion, wrapped)
}

func (p *LocalProvider) copyKey(keyVersion string) ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed {
		return nil, ErrProviderClosed
	}
	key := p.keys[keyVersion]
	if len(key) != DEKSize {
		return nil, ErrProviderKeyNotFound
	}
	return cloneBytes(key), nil
}

func (p *LocalProvider) isClosed() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.closed
}

func validateKEK(kek []byte) error {
	if len(kek) != DEKSize {
		return fmt.Errorf("KEK must be exactly %d bytes", DEKSize)
	}
	return nil
}

func localWrapAAD(keyVersion string) []byte {
	return []byte("cheesewaf-local-kek-aad.v1:" + keyVersion)
}
