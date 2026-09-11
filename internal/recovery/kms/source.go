package kms

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

type PasswordFunc func(context.Context) ([]byte, error)
type passwordKeySource struct {
	sealed   passwordEnvelope
	password PasswordFunc
}
type passwordEnvelope struct {
	Schema                  string
	Salt, Nonce, Ciphertext []byte
	Memory, Iterations      uint32
	Parallelism             uint8
}

const passwordSchema = "cheesewaf-password-source.v1"

// NewPasswordKeySource creates a password-protected random root key. The
// password callback is invoked only for derivation and its returned bytes are
// cleared before the call returns.
func NewPasswordKeySource(ctx context.Context, password PasswordFunc) (RootKeySource, []byte, error) {
	if password == nil {
		return nil, nil, ErrUnsupported
	}
	pass, err := password(ctx)
	if err != nil {
		return nil, nil, classifySource(err)
	}
	if !validPassword(pass) {
		zero(pass)
		return nil, nil, ErrInvalidInput
	}
	defer zero(pass)
	root := make([]byte, DEKSize)
	if _, err := rand.Read(root); err != nil {
		return nil, nil, ErrProviderFailure
	}
	defer zero(root)
	e := passwordEnvelope{Schema: passwordSchema, Memory: 32 * 1024, Iterations: 2, Parallelism: 1, Salt: make([]byte, 16)}
	if _, err := rand.Read(e.Salt); err != nil {
		return nil, nil, ErrProviderFailure
	}
	key := argon2.IDKey(pass, e.Salt, e.Iterations, e.Memory, e.Parallelism, DEKSize)
	defer zero(key)
	a, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, ErrUnsupported
	}
	g, err := cipher.NewGCM(a)
	if err != nil {
		return nil, nil, ErrUnsupported
	}
	e.Nonce = make([]byte, g.NonceSize())
	if _, err := rand.Read(e.Nonce); err != nil {
		return nil, nil, ErrProviderFailure
	}
	e.Ciphertext = g.Seal(nil, e.Nonce, root, []byte(passwordSchema))
	sealed, err := json.Marshal(e)
	if err != nil {
		return nil, nil, ErrInvalidConfig
	}
	return &passwordKeySource{sealed: e, password: password}, sealed, nil
}

func OpenPasswordKeySource(encoded []byte, password PasswordFunc) (RootKeySource, error) {
	if password == nil {
		return nil, ErrUnsupported
	}
	var e passwordEnvelope
	dec := json.NewDecoder(bytes.NewReader(encoded))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&e); err != nil {
		return nil, ErrAuthentication
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, ErrAuthentication
	}
	if e.Schema != passwordSchema || len(e.Salt) != 16 || len(e.Nonce) != 12 || len(e.Ciphertext) < 16 || e.Memory < 8*1024 || e.Memory > 256*1024 || e.Iterations == 0 || e.Iterations > 10 || e.Parallelism == 0 {
		return nil, ErrAuthentication
	}
	return &passwordKeySource{sealed: e, password: password}, nil
}
func (s *passwordKeySource) Available(context.Context) bool { return s != nil && s.password != nil }
func (s *passwordKeySource) Load(ctx context.Context) ([]byte, error) {
	if s == nil || s.password == nil {
		return nil, ErrUnsupported
	}
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	pass, err := s.password(ctx)
	if err != nil {
		return nil, classifySource(err)
	}
	if !validPassword(pass) {
		zero(pass)
		return nil, ErrInvalidInput
	}
	defer zero(pass)
	key := argon2.IDKey(pass, s.sealed.Salt, s.sealed.Iterations, s.sealed.Memory, s.sealed.Parallelism, DEKSize)
	defer zero(key)
	a, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrUnsupported
	}
	g, err := cipher.NewGCM(a)
	if err != nil {
		return nil, ErrUnsupported
	}
	root, err := g.Open(nil, s.sealed.Nonce, s.sealed.Ciphertext, []byte(passwordSchema))
	if err != nil {
		return nil, ErrAuthentication
	}
	if len(root) != DEKSize {
		zero(root)
		return nil, ErrAuthentication
	}
	return root, nil
}

type OSKeyKind string

const (
	OSKeychain OSKeyKind = "keychain"
	OSTPM      OSKeyKind = "tpm"
	OSDPAPI    OSKeyKind = "dpapi"
)

type osKeySource struct {
	kind    OSKeyKind
	adapter RootKeySource
}

func NewOSKeySource(kind OSKeyKind, adapter RootKeySource) (RootKeySource, error) {
	if kind != OSKeychain && kind != OSTPM && kind != OSDPAPI {
		return nil, ErrUnsupported
	}
	if adapter == nil {
		return nil, ErrUnsupported
	}
	return &osKeySource{kind: kind, adapter: adapter}, nil
}
func (s *osKeySource) Available(ctx context.Context) bool {
	return s != nil && s.adapter != nil && s.adapter.Available(ctx)
}
func (s *osKeySource) Load(ctx context.Context) ([]byte, error) {
	if s == nil || s.adapter == nil {
		return nil, ErrUnsupported
	}
	root, err := s.adapter.Load(ctx)
	if err != nil {
		return nil, classifySource(err)
	}
	if len(root) != DEKSize {
		zero(root)
		return nil, ErrUnsupported
	}
	return root, nil
}
func (s *osKeySource) Kind() OSKeyKind {
	if s == nil {
		return ""
	}
	return s.kind
}

// SelectRootKeySource fixes provider choice for the lifetime of a keyring.
// OS protection is always tried first; password fallback is legal only for an
// explicitly approved single-node/offline deployment.
func SelectRootKeySource(ctx context.Context, system, offline RootKeySource, policy FallbackPolicy) (RootKeySource, error) {
	if system != nil {
		if system.Available(ctx) {
			if root, err := system.Load(ctx); err == nil {
				zero(root)
				return system, nil
			} else if !errors.Is(err, ErrUnavailable) {
				return nil, err
			}
		} else {
			if _, err := system.Load(ctx); errors.Is(err, ErrUnsupported) {
				return nil, ErrUnsupported
			}
		}
	}
	if policy.allows() && offline != nil && offline.Available(ctx) {
		if root, err := offline.Load(ctx); err == nil {
			zero(root)
			return offline, nil
		} else {
			return nil, err
		}
	}
	return nil, ErrUnavailable
}

func validPassword(pass []byte) bool {
	if len(pass) < 12 || !utf8.Valid(pass) {
		return false
	}
	for _, r := range string(pass) {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}
