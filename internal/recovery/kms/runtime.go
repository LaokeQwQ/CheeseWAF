// Package kms contains the executable KMS and single-node keyring boundary
// used by recovery integrations. It never logs key material or provider
// errors. Durable storage, authentication and network policy remain injected.
package kms

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/LaokeQwQ/CheeseWAF/internal/recovery"
)

const (
	DEKSize        = recovery.SecretSize
	wireSchema     = "cheesewaf-recovery-wrapped.v1"
	maxWrappedSize = 128 << 10
)

var (
	ErrInvalidConfig    = errors.New("invalid KMS runtime configuration")
	ErrInvalidInput     = errors.New("invalid KMS input")
	ErrUnavailable      = errors.New("KMS provider unavailable")
	ErrUnsupported      = errors.New("unsupported key protection")
	ErrPermission       = errors.New("KMS operation not authorized")
	ErrAudit            = errors.New("KMS audit unavailable")
	ErrProviderFailure  = errors.New("KMS provider operation failed")
	ErrAuthentication   = errors.New("wrapped key authentication failed")
	ErrBinding          = errors.New("wrapped key binding mismatch")
	ErrVersion          = errors.New("invalid or revoked key version")
	ErrReplay           = errors.New("recovery confirmation already used")
	ErrRecoveryConsumed = errors.New("recovery credential already consumed")
	ErrRecoveryExpired  = errors.New("recovery credential expired")
	ErrThreshold        = errors.New("two distinct recovery administrators are required")
)

type DeploymentMode string

const (
	HighAvailability DeploymentMode = "ha"
	SingleNode       DeploymentMode = "single-node"
	Offline          DeploymentMode = "offline"
)

type FallbackPolicy struct {
	Approved bool
	Mode     DeploymentMode
}

func (p FallbackPolicy) allows() bool {
	return p.Approved && (p.Mode == SingleNode || p.Mode == Offline)
}

type ProviderKind string

const (
	External ProviderKind = "external"
	Embedded ProviderKind = "embedded"
)

// KeyRef identifies a KEK version. Every field is authenticated in the
// portable wrapped-DEK representation.
type KeyRef struct {
	TenantID, KeyID, Version string
	Scope, Actor             string
	PolicyEpoch              uint64
}
type Binding struct {
	TenantID, KeyID, Scope, Actor string
	PolicyEpoch                   uint64
}

// Backend owns KEK material. Runtime callers only pass DEKs and receive an
// opaque wrapped representation; backends must never return a KEK.
type Backend interface {
	Available(context.Context) bool
	Wrap(context.Context, KeyRef, []byte) ([]byte, error)
	Unwrap(context.Context, KeyRef, []byte) ([]byte, error)
	Rotate(context.Context, KeyRef) error
	Revoke(context.Context, KeyRef) error
}

type Operation string

const (
	Wrap          Operation = "wrap"
	Unwrap        Operation = "unwrap"
	Rewrap        Operation = "rewrap"
	Rotate        Operation = "rotate"
	Revoke        Operation = "revoke"
	IssueRecovery Operation = "issue-recovery"
	Recover       Operation = "recover"
)

type Access struct {
	Binding
	Operation              Operation
	Version, TargetVersion string
	At                     time.Time
}

// Authorizer binds each sensitive operation to an approval/session policy.
// It is called before any backend side effect.
type Authorizer interface {
	Authorize(context.Context, Access) error
}

type Event struct {
	At                                                    time.Time
	Operation                                             Operation
	Result                                                string
	Provider                                              ProviderKind
	TenantID, KeyID, Version, TargetVersion, Scope, Actor string
	PolicyEpoch                                           uint64
}
type AuditSink interface {
	Append(context.Context, Event) error
}

type Options struct {
	Binding    Binding
	External   Backend
	Embedded   Backend
	Fallback   FallbackPolicy
	Authorizer Authorizer
	Audit      AuditSink
	Now        func() time.Time
}

type Runtime struct {
	mu                 sync.RWMutex
	binding            Binding
	external, embedded Backend
	fallback           FallbackPolicy
	authorizer         Authorizer
	audit              AuditSink
	now                func() time.Time
}

func NewRuntime(o Options) (*Runtime, error) {
	if !validBinding(o.Binding) || o.Authorizer == nil || o.Audit == nil {
		return nil, ErrInvalidConfig
	}
	if o.External == nil && o.Embedded == nil {
		return nil, ErrInvalidConfig
	}
	if o.Now == nil {
		o.Now = func() time.Time { return time.Now().UTC() }
	}
	return &Runtime{binding: o.Binding, external: o.External, embedded: o.Embedded, fallback: o.Fallback, authorizer: o.Authorizer, audit: o.Audit, now: o.Now}, nil
}

func (r *Runtime) Binding() Binding { r.mu.RLock(); defer r.mu.RUnlock(); return r.binding }

func (r *Runtime) Wrap(ctx context.Context, version string, dek []byte) ([]byte, error) {
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	if !validVersion(version) || len(dek) != DEKSize {
		return nil, ErrInvalidInput
	}
	b, kind, err := r.chooseForWrap(ctx)
	if err != nil {
		return nil, err
	}
	access := r.access(Wrap, version, "")
	if err := r.authorize(ctx, access, kind); err != nil {
		return nil, err
	}
	ref := KeyRef{TenantID: r.binding.TenantID, KeyID: r.binding.KeyID, Version: version, Scope: r.binding.Scope, Actor: r.binding.Actor, PolicyEpoch: r.binding.PolicyEpoch}
	wrapped, err := b.Wrap(ctx, ref, append([]byte(nil), dek...))
	if err != nil {
		return nil, r.providerError(ctx, access, kind, err)
	}
	if len(wrapped) == 0 || len(wrapped) > maxWrappedSize {
		return nil, r.providerError(ctx, access, kind, ErrInvalidInput)
	}
	out, err := marshalWire(wireValue{Schema: wireSchema, Provider: kind, Ref: ref, Scope: r.binding.Scope, Actor: r.binding.Actor, PolicyEpoch: r.binding.PolicyEpoch, Data: wrapped})
	if err != nil {
		return nil, r.providerError(ctx, access, kind, err)
	}
	if err := r.finish(ctx, access, kind); err != nil {
		return nil, err
	}
	return out, nil
}

func (r *Runtime) Unwrap(ctx context.Context, version string, wrapped []byte) ([]byte, error) {
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	if !validVersion(version) || len(wrapped) == 0 || len(wrapped) > maxWrappedSize {
		return nil, ErrInvalidInput
	}
	w, err := unmarshalWire(wrapped)
	if err != nil {
		return nil, err
	}
	if w.Ref.Version != version || w.Ref.TenantID != r.binding.TenantID || w.Ref.KeyID != r.binding.KeyID || w.Scope != r.binding.Scope || w.Actor != r.binding.Actor || w.PolicyEpoch != r.binding.PolicyEpoch {
		return nil, ErrBinding
	}
	b := r.backendFor(w.Provider)
	if b == nil || !b.Available(ctx) {
		return nil, ErrUnavailable
	}
	access := r.access(Unwrap, version, "")
	if err := r.authorize(ctx, access, w.Provider); err != nil {
		return nil, err
	}
	plain, err := b.Unwrap(ctx, w.Ref, append([]byte(nil), w.Data...))
	if err != nil {
		return nil, r.providerError(ctx, access, w.Provider, err)
	}
	if len(plain) != DEKSize {
		zero(plain)
		return nil, r.providerError(ctx, access, w.Provider, ErrAuthentication)
	}
	if err := r.finish(ctx, access, w.Provider); err != nil {
		zero(plain)
		return nil, err
	}
	return plain, nil
}

func (r *Runtime) Rewrap(ctx context.Context, oldVersion, newVersion string, wrapped []byte) ([]byte, error) {
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	if !validVersion(oldVersion) || !validVersion(newVersion) || oldVersion == newVersion {
		return nil, ErrInvalidInput
	}
	w, err := unmarshalWire(wrapped)
	if err != nil {
		return nil, err
	}
	if w.Ref.Version != oldVersion || w.Ref.TenantID != r.binding.TenantID || w.Ref.KeyID != r.binding.KeyID || w.Scope != r.binding.Scope || w.Actor != r.binding.Actor || w.PolicyEpoch != r.binding.PolicyEpoch {
		return nil, ErrBinding
	}
	source := r.backendFor(w.Provider)
	if source == nil || !source.Available(ctx) {
		return nil, ErrUnavailable
	}
	dest, kind, err := r.chooseForWrap(ctx)
	if err != nil {
		return nil, err
	}
	access := r.access(Rewrap, oldVersion, newVersion)
	if err := r.authorize(ctx, access, kind); err != nil {
		return nil, err
	}
	oldRef := w.Ref
	dek, err := source.Unwrap(ctx, oldRef, append([]byte(nil), w.Data...))
	if err != nil {
		return nil, r.providerError(ctx, access, w.Provider, err)
	}
	if len(dek) != DEKSize {
		zero(dek)
		return nil, r.providerError(ctx, access, w.Provider, ErrAuthentication)
	}
	defer zero(dek)
	newRef := oldRef
	newRef.Version = newVersion
	data, err := dest.Wrap(ctx, newRef, append([]byte(nil), dek...))
	if err != nil {
		return nil, r.providerError(ctx, access, kind, err)
	}
	if len(data) == 0 || len(data) > maxWrappedSize {
		return nil, r.providerError(ctx, access, kind, ErrInvalidInput)
	}
	out, err := marshalWire(wireValue{Schema: wireSchema, Provider: kind, Ref: newRef, Scope: r.binding.Scope, Actor: r.binding.Actor, PolicyEpoch: r.binding.PolicyEpoch, Data: data})
	if err != nil {
		return nil, r.providerError(ctx, access, kind, err)
	}
	if err := r.finish(ctx, access, kind); err != nil {
		return nil, err
	}
	return out, nil
}

func (r *Runtime) Rotate(ctx context.Context, version string) error {
	if err := contextErr(ctx); err != nil {
		return err
	}
	if !validVersion(version) {
		return ErrInvalidInput
	}
	b, kind, err := r.chooseForWrap(ctx)
	if err != nil {
		return err
	}
	a := r.access(Rotate, version, "")
	if err := r.authorize(ctx, a, kind); err != nil {
		return err
	}
	if err := b.Rotate(ctx, KeyRef{TenantID: r.binding.TenantID, KeyID: r.binding.KeyID, Version: version}); err != nil {
		return r.providerError(ctx, a, kind, err)
	}
	return r.finish(ctx, a, kind)
}

func (r *Runtime) Revoke(ctx context.Context, kind ProviderKind, version string) error {
	if err := contextErr(ctx); err != nil {
		return err
	}
	if !validVersion(version) || (kind != External && kind != Embedded) {
		return ErrInvalidInput
	}
	b := r.backendFor(kind)
	if b == nil || !b.Available(ctx) {
		return ErrUnavailable
	}
	a := r.access(Revoke, version, "")
	if err := r.authorize(ctx, a, kind); err != nil {
		return err
	}
	if err := b.Revoke(ctx, KeyRef{TenantID: r.binding.TenantID, KeyID: r.binding.KeyID, Version: version}); err != nil {
		return r.providerError(ctx, a, kind, err)
	}
	return r.finish(ctx, a, kind)
}

func (r *Runtime) chooseForWrap(ctx context.Context) (Backend, ProviderKind, error) {
	if r.external != nil && r.external.Available(ctx) {
		return r.external, External, nil
	}
	if r.fallback.allows() && r.embedded != nil && r.embedded.Available(ctx) {
		return r.embedded, Embedded, nil
	}
	return nil, "", ErrUnavailable
}
func (r *Runtime) backendFor(kind ProviderKind) Backend {
	if kind == External {
		return r.external
	}
	if kind == Embedded {
		return r.embedded
	}
	return nil
}
func (r *Runtime) access(op Operation, version, target string) Access {
	return Access{Binding: r.binding, Operation: op, Version: version, TargetVersion: target, At: r.now().UTC()}
}
func (r *Runtime) authorize(ctx context.Context, a Access, kind ProviderKind) error {
	if !validAccess(a) {
		_ = r.auditEvent(ctx, a, kind, "denied")
		return ErrPermission
	}
	if err := r.authorizer.Authorize(ctx, a); err != nil {
		if auditErr := r.auditEvent(ctx, a, kind, "denied"); auditErr != nil {
			return auditErr
		}
		return ErrPermission
	}
	if err := r.auditEvent(ctx, a, kind, "attempt"); err != nil {
		return err
	}
	return nil
}
func (r *Runtime) finish(ctx context.Context, a Access, kind ProviderKind) error {
	return r.auditEvent(ctx, a, kind, "succeeded")
}
func (r *Runtime) providerError(ctx context.Context, a Access, kind ProviderKind, _ error) error {
	_ = r.auditEvent(ctx, a, kind, "failed")
	if err := contextErr(ctx); err != nil {
		return err
	}
	return ErrProviderFailure
}
func (r *Runtime) auditEvent(ctx context.Context, a Access, kind ProviderKind, result string) error {
	if err := r.audit.Append(ctx, Event{At: a.At, Operation: a.Operation, Result: result, Provider: kind, TenantID: a.TenantID, KeyID: a.KeyID, Version: a.Version, TargetVersion: a.TargetVersion, Scope: a.Scope, Actor: a.Actor, PolicyEpoch: a.PolicyEpoch}); err != nil {
		return ErrAudit
	}
	return nil
}

type Permission struct {
	recovery.WrappingKeyPermission
	Version, TargetVersion string
}

func (p Permission) Allows(a Access) error {
	if !validAccess(a) || !validVersion(p.Version) || (p.TargetVersion != "" && !validVersion(p.TargetVersion)) {
		return ErrPermission
	}
	if p.Version != a.Version || p.TargetVersion != a.TargetVersion {
		return ErrPermission
	}
	if p.Operation != recovery.KeyOperation(a.Operation) {
		return ErrPermission
	}
	if err := p.WrappingKeyPermission.Allows(a.At, a.TenantID, a.KeyID, a.Scope, a.Actor, recovery.KeyOperation(a.Operation), a.PolicyEpoch); err != nil {
		return ErrPermission
	}
	return nil
}

type wireValue struct {
	Schema      string
	Provider    ProviderKind
	Ref         KeyRef
	Scope       string
	Actor       string
	PolicyEpoch uint64
	Data        []byte
}

func marshalWire(w wireValue) ([]byte, error) {
	if w.Schema != wireSchema || (w.Provider != External && w.Provider != Embedded) || !strict(w.Ref.TenantID) || !strict(w.Ref.KeyID) || !validVersion(w.Ref.Version) || !strict(w.Scope) || !strict(w.Actor) || w.PolicyEpoch == 0 || len(w.Data) == 0 {
		return nil, ErrInvalidInput
	}
	b, err := json.Marshal(w)
	if err != nil {
		return nil, ErrInvalidInput
	}
	return b, nil
}
func unmarshalWire(b []byte) (wireValue, error) {
	var w wireValue
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&w); err != nil {
		return wireValue{}, ErrAuthentication
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return wireValue{}, ErrAuthentication
	}
	if len(w.Data) == 0 || len(w.Data) > maxWrappedSize || w.Schema != wireSchema || (w.Provider != External && w.Provider != Embedded) || !validVersion(w.Ref.Version) || !strict(w.Ref.TenantID) || !strict(w.Ref.KeyID) || !strict(w.Scope) || !strict(w.Actor) || w.PolicyEpoch == 0 {
		return wireValue{}, ErrAuthentication
	}
	return w, nil
}

func validBinding(b Binding) bool {
	return strict(b.TenantID) && strict(b.KeyID) && strict(b.Scope) && strict(b.Actor) && b.PolicyEpoch > 0
}
func validAccess(a Access) bool {
	return validBinding(a.Binding) && a.Operation != "" && validVersion(a.Version) && !a.At.IsZero() && (a.TargetVersion == "" || validVersion(a.TargetVersion))
}
func validVersion(v string) bool { return strict(v) }
func strict(v string) bool {
	if v == "" || !utf8.ValidString(v) || v != strings.TrimSpace(v) {
		return false
	}
	return strings.IndexFunc(v, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) }) < 0
}
func contextErr(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	return ctx.Err()
}
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// HashSecret produces metadata only. It is safe to persist and audit; callers
// must clear any plaintext secret as soon as the protected operation ends.
func HashSecret(secret []byte) [32]byte { return sha256.Sum256(secret) }
func EncodeSecret(secret []byte) string { return base64.RawURLEncoding.EncodeToString(secret) }
func DecodeSecret(encoded string) ([]byte, error) {
	if !strict(encoded) {
		return nil, ErrInvalidInput
	}
	b, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(b) != DEKSize {
		return nil, ErrInvalidInput
	}
	return b, nil
}
func EqualSecret(a, b []byte) bool { return bytes.Equal(a, b) }
