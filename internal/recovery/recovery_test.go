package recovery

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type testKMS struct{ available bool }

func (k *testKMS) Available(context.Context) bool { return k.available }
func (k *testKMS) Wrap(_ context.Context, version string, plaintext []byte) ([]byte, error) {
	return append([]byte(version+":"), plaintext...), nil
}
func (k *testKMS) Unwrap(_ context.Context, version string, wrapped []byte) ([]byte, error) {
	p := []byte(version + ":")
	if len(wrapped) < len(p) || string(wrapped[:len(p)]) != string(p) {
		return nil, errors.New("bad version")
	}
	return append([]byte(nil), wrapped[len(p):]...), nil
}

func TestProviderSelectionPrefersExternalKMS(t *testing.T) {
	kms := &testKMS{available: true}
	embedded := &EmbeddedProvider{Key: []byte("01234567890123456789012345678901")}
	p, err := SelectProvider(kms, embedded, true)
	if err != nil || p != kms {
		t.Fatalf("expected external KMS, provider=%T err=%v", p, err)
	}
}

func TestProviderSelectionRejectsUnapprovedEmbeddedFallback(t *testing.T) {
	kms := &testKMS{}
	_, err := SelectProvider(kms, &EmbeddedProvider{Key: []byte("01234567890123456789012345678901")}, false)
	if !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("expected unavailable, got %v", err)
	}
}

func TestRecoveryRequiresTwoOfThreeDistinctAdminsAndRevokesTemporaryCredentials(t *testing.T) {
	now := time.Unix(100, 0)
	r := NewManager([]string{"a", "b", "c"})
	issued, err := r.Begin(now, BeginRequest{Actor: "a", Scope: "cluster"})
	if err != nil || issued.Secret == "" {
		t.Fatalf("begin: %+v %v", issued, err)
	}
	if _, err = r.Confirm(now, issued.ID, Confirmation{AdminID: "a", ConfirmationID: "c1"}); err != nil {
		t.Fatal(err)
	}
	if _, err = r.Recover(now, issued.ID, Confirmation{AdminID: "a", ConfirmationID: "c2"}, nil); !errors.Is(err, ErrThresholdNotMet) {
		t.Fatalf("duplicate admin should not meet threshold: %v", err)
	}
	if _, err = r.Recover(now, issued.ID, Confirmation{AdminID: "b", ConfirmationID: "c3"}, recordingRevoker{}); err != nil {
		t.Fatalf("recover: %v", err)
	}
	if _, err = r.Recover(now, issued.ID, Confirmation{AdminID: "c", ConfirmationID: "c3"}, nil); !errors.Is(err, ErrAlreadyRecovered) {
		t.Fatalf("replay should fail: %v", err)
	}
}

func TestRecoveryAdminNormalizationCannotBypassDistinctThreshold(t *testing.T) {
	r := NewManager([]string{"admin-a", "admin-b", "admin-c"})
	now := time.Unix(120, 0)
	issued, err := r.Begin(now, BeginRequest{Actor: "admin-a", Scope: "cluster"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Confirm(now, issued.ID, Confirmation{AdminID: " admin-a ", ConfirmationID: "norm-1"}); !errors.Is(err, ErrInvalidAdmin) {
		t.Fatalf("whitespace admin id accepted: %v", err)
	}
	if count, err := r.Confirm(now, issued.ID, Confirmation{AdminID: "admin-a", ConfirmationID: "norm-1"}); err != nil || count != 1 {
		t.Fatalf("confirmation count=%d err=%v", count, err)
	}
	if count, err := r.Confirm(now, issued.ID, Confirmation{AdminID: "admin-a", ConfirmationID: "norm-2"}); err != nil || count != 1 {
		t.Fatalf("duplicate normalized admin count=%d err=%v", count, err)
	}
	if _, err := r.Recover(now, issued.ID, Confirmation{AdminID: "admin-a", ConfirmationID: "norm-3"}, nil); !errors.Is(err, ErrThresholdNotMet) {
		t.Fatalf("normalized duplicate bypassed threshold: %v", err)
	}
}

func TestRecoveryBeginRejectsWhitespaceAndInvisibleIdentityInputs(t *testing.T) {
	for _, tc := range []struct {
		name  string
		actor string
		scope string
	}{
		{name: "actor leading space", actor: " admin-a", scope: "cluster"},
		{name: "actor trailing space", actor: "admin-a ", scope: "cluster"},
		{name: "actor zero width", actor: "admin-a\u200b", scope: "cluster"},
		{name: "scope newline", actor: "admin-a", scope: "cluster\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := NewManager([]string{"admin-a", "admin-b"})
			if _, err := m.Begin(time.Unix(130, 0), BeginRequest{Actor: tc.actor, Scope: tc.scope}); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("Begin accepted non-canonical identity: %v", err)
			}
		})
	}
}

func TestWrappingKeyPermissionAllowsExactIdentityWithoutTrimming(t *testing.T) {
	now := time.Unix(140, 0)
	permission := WrappingKeyPermission{TenantID: "tenant-a", KeyID: "key-a", Operation: OperationWrap, Scope: "cluster", PolicyEpoch: 1, Actor: "admin-a", ExpiresAt: now.Add(time.Minute)}
	if err := permission.Allows(now, "tenant-a", "key-a", "cluster", "admin-a", OperationWrap, 1); err != nil {
		t.Fatalf("canonical permission rejected: %v", err)
	}
	for _, tc := range []struct {
		name   string
		tenant string
		actor  string
	}{
		{name: "tenant leading space", tenant: " tenant-a"},
		{name: "tenant trailing space", tenant: "tenant-a "},
		{name: "actor zero width", actor: "admin-a\u200b"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tenant, actor := tc.tenant, tc.actor
			if tenant == "" {
				tenant = "tenant-a"
			}
			if actor == "" {
				actor = "admin-a"
			}
			if err := permission.Allows(now, tenant, "key-a", "cluster", actor, OperationWrap, 1); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("Allows accepted non-canonical identity: %v", err)
			}
		})
	}
}

type recordingRevoker struct{}

func (recordingRevoker) RevokeTemporary(context.Context) error { return nil }

func TestWebDeliveryIsOneTimeAndCLIFileIs0600AndRemoved(t *testing.T) {
	r := NewManager([]string{"a", "b", "c"})
	issued, err := r.Begin(time.Unix(200, 0), BeginRequest{Actor: "a", Scope: "cluster"})
	if err != nil {
		t.Fatal(err)
	}
	web, err := r.WebDelivery(issued.ID)
	if err != nil || web == "" {
		t.Fatalf("web delivery: %v", err)
	}
	if _, err = r.WebDelivery(issued.ID); !errors.Is(err, ErrDeliveryConsumed) {
		t.Fatalf("second web delivery: %v", err)
	}
	issued2, _ := r.Begin(time.Unix(201, 0), BeginRequest{Actor: "a", Scope: "cluster"})
	dir := t.TempDir()
	path := filepath.Join(dir, "recovery")
	if err := r.WriteCLIFile(issued2.ID, path); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0600 {
		t.Fatalf("mode=%o", st.Mode().Perm())
	}
	if err := r.RemoveCLIFile(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected removed file, err=%v", err)
	}
}
