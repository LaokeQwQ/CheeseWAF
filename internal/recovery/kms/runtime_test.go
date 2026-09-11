package kms

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/recovery"
)

type testBackend struct {
	mu                                     sync.Mutex
	available                              bool
	wraps, unwraps, rotations, revocations int
	fail                                   error
}

func (b *testBackend) Available(context.Context) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.available
}
func (b *testBackend) Wrap(_ context.Context, ref KeyRef, plain []byte) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.wraps++
	if b.fail != nil {
		return nil, b.fail
	}
	return append([]byte(ref.Version+":"), plain...), nil
}
func (b *testBackend) Unwrap(_ context.Context, ref KeyRef, blob []byte) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.unwraps++
	if b.fail != nil {
		return nil, b.fail
	}
	prefix := []byte(ref.Version + ":")
	if !bytes.HasPrefix(blob, prefix) {
		return nil, ErrAuthentication
	}
	return append([]byte(nil), blob[len(prefix):]...), nil
}
func (b *testBackend) Rotate(context.Context, KeyRef) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.rotations++
	return b.fail
}
func (b *testBackend) Revoke(context.Context, KeyRef) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.revocations++
	return b.fail
}

type testAuthorizer struct {
	mu   sync.Mutex
	deny bool
	seen []Access
}

func (a *testAuthorizer) Authorize(_ context.Context, access Access) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.seen = append(a.seen, access)
	if a.deny {
		return errors.New("sensitive upstream detail")
	}
	return nil
}

type testAudit struct {
	mu     sync.Mutex
	fail   bool
	events []Event
}

func (a *testAudit) Append(_ context.Context, e Event) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.fail {
		return errors.New("sensitive audit detail")
	}
	a.events = append(a.events, e)
	return nil
}
func testBinding() Binding {
	return Binding{TenantID: "tenant-a", KeyID: "key-a", Scope: "cluster", Actor: "admin-a", PolicyEpoch: 7}
}
func testRuntime(t *testing.T, external, embedded Backend, policy FallbackPolicy) (*Runtime, *testAuthorizer, *testAudit) {
	t.Helper()
	auth, audit := &testAuthorizer{}, &testAudit{}
	r, err := NewRuntime(Options{Binding: testBinding(), External: external, Embedded: embedded, Fallback: policy, Authorizer: auth, Audit: audit, Now: func() time.Time { return time.Unix(1000, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	return r, auth, audit
}

func TestRuntimePrefersExternalAndNeverFallsBackAfterOperationFailure(t *testing.T) {
	ext, local := &testBackend{available: true}, &testBackend{available: true}
	r, _, _ := testRuntime(t, ext, local, FallbackPolicy{Approved: true, Mode: SingleNode})
	wrapped, err := r.Wrap(context.Background(), "v1", bytes.Repeat([]byte{0x31}, 32))
	if err != nil || ext.wraps != 1 || local.wraps != 0 {
		t.Fatalf("preference wraps=%d/%d err=%v", ext.wraps, local.wraps, err)
	}
	if plain, err := r.Unwrap(context.Background(), "v1", wrapped); err != nil || len(plain) != 32 {
		t.Fatalf("unwrap err=%v", err)
	}
	ext.fail = errors.New("password=never-print-this")
	if _, err := r.Wrap(context.Background(), "v1", bytes.Repeat([]byte{0x31}, 32)); !errors.Is(err, ErrProviderFailure) || bytes.Contains([]byte(err.Error()), []byte("never-print")) {
		t.Fatalf("unsafe provider failure: %v", err)
	}
	if local.wraps != 0 {
		t.Fatal("failed external operation silently fell back")
	}
}

func TestFallbackRequiresExplicitSingleNodeOrOfflineApproval(t *testing.T) {
	for _, policy := range []FallbackPolicy{{}, {Approved: true}, {Approved: true, Mode: HighAvailability}, {Mode: Offline}} {
		r, _, _ := testRuntime(t, &testBackend{}, &testBackend{available: true}, policy)
		if _, err := r.Wrap(context.Background(), "v1", make([]byte, 32)); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("policy=%+v err=%v", policy, err)
		}
	}
	for _, mode := range []DeploymentMode{SingleNode, Offline} {
		r, _, _ := testRuntime(t, &testBackend{}, &testBackend{available: true}, FallbackPolicy{Approved: true, Mode: mode})
		if _, err := r.Wrap(context.Background(), "v1", make([]byte, 32)); err != nil {
			t.Fatalf("mode=%s err=%v", mode, err)
		}
	}
}

func TestRuntimeRejectsKeyAndPermissionBindingChangesBeforeBackend(t *testing.T) {
	ext := &testBackend{available: true}
	r, auth, audit := testRuntime(t, ext, nil, FallbackPolicy{})
	wrapped, err := r.Wrap(context.Background(), "v1", bytes.Repeat([]byte{0x31}, 32))
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"v2", " v1", "v1\n", "v1\u200b"} {
		if _, err := r.Unwrap(context.Background(), version, wrapped); err == nil {
			t.Fatalf("accepted version %q", version)
		}
	}
	other, _, _ := testRuntime(t, ext, nil, FallbackPolicy{})
	other.binding.TenantID = "tenant-b"
	if _, err := other.Unwrap(context.Background(), "v1", wrapped); !errors.Is(err, ErrBinding) {
		t.Fatalf("tenant mismatch=%v", err)
	}
	auth.deny = true
	if _, err := r.Wrap(context.Background(), "v1", make([]byte, 32)); !errors.Is(err, ErrPermission) {
		t.Fatalf("deny=%v", err)
	}
	auth.deny = false
	audit.fail = true
	if _, err := r.Wrap(context.Background(), "v1", make([]byte, 32)); !errors.Is(err, ErrAudit) {
		t.Fatalf("audit failure=%v", err)
	}
	if ext.wraps != 1 || ext.unwraps != 0 {
		t.Fatalf("unauthorized backend work wraps=%d unwraps=%d", ext.wraps, ext.unwraps)
	}
}

func TestVersionPermissionRequiresExactSourceAndTarget(t *testing.T) {
	now := time.Unix(1000, 0)
	binding := testBinding()
	p := Permission{WrappingKeyPermission: recovery.WrappingKeyPermission{TenantID: binding.TenantID, KeyID: binding.KeyID, Scope: binding.Scope, Actor: binding.Actor, PolicyEpoch: binding.PolicyEpoch, Operation: recovery.OperationRewrap, ExpiresAt: now.Add(time.Minute)}, Version: "v1", TargetVersion: "v2"}
	a := Access{Binding: binding, Operation: Rewrap, Version: "v1", TargetVersion: "v2", At: now}
	if err := p.Allows(a); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Access){"version": func(a *Access) { a.Version = "v0" }, "target": func(a *Access) { a.TargetVersion = "v3" }, "actor whitespace": func(a *Access) { a.Actor = "admin-a " }, "epoch": func(a *Access) { a.PolicyEpoch++ }, "expiry": func(a *Access) { a.At = now.Add(time.Minute) }} {
		t.Run(name, func(t *testing.T) {
			copy := a
			change(&copy)
			if err := p.Allows(copy); !errors.Is(err, ErrPermission) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestRuntimeRotationRevocationAndRewrapAreAuthorizedAndAudited(t *testing.T) {
	ext := &testBackend{available: true}
	r, auth, audit := testRuntime(t, ext, nil, FallbackPolicy{})
	old, err := r.Wrap(context.Background(), "v1", bytes.Repeat([]byte{0x31}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Rotate(context.Background(), "v2"); err != nil {
		t.Fatal(err)
	}
	rotated, err := r.Rewrap(context.Background(), "v1", "v2", old)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Unwrap(context.Background(), "v2", rotated); err != nil {
		t.Fatal(err)
	}
	if err := r.Revoke(context.Background(), External, "v1"); err != nil {
		t.Fatal(err)
	}
	if ext.rotations != 1 || ext.revocations != 1 {
		t.Fatal("lifecycle operation missing")
	}
	if auth.seen[2].Operation != Rewrap || auth.seen[2].Version != "v1" || auth.seen[2].TargetVersion != "v2" {
		t.Fatalf("rewrap access=%+v", auth.seen[2])
	}
	if len(audit.events) != 10 {
		t.Fatalf("events=%d", len(audit.events))
	}
}

func TestRuntimeWireBindsScopeAndEpoch(t *testing.T) {
	ext := &testBackend{available: true}
	r, _, _ := testRuntime(t, ext, nil, FallbackPolicy{})
	wrapped, err := r.Wrap(context.Background(), "v1", bytes.Repeat([]byte{0x31}, 32))
	if err != nil {
		t.Fatal(err)
	}
	var wire wireValue
	if err := json.Unmarshal(wrapped, &wire); err != nil {
		t.Fatal(err)
	}
	wire.Scope = "other-scope"
	tampered, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Unwrap(context.Background(), "v1", tampered); !errors.Is(err, ErrBinding) {
		t.Fatalf("scope binding mismatch=%v", err)
	}
	wire.Scope = "cluster"
	wire.PolicyEpoch++
	tampered, err = json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Unwrap(context.Background(), "v1", tampered); !errors.Is(err, ErrBinding) {
		t.Fatalf("epoch binding mismatch=%v", err)
	}
}
