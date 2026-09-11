package tokens

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func tokenRequest() CreateRequest {
	return CreateRequest{
		Owner:       "alice",
		Permissions: []string{"rules.read", "sites.write"},
		Resources:   []string{"site:alpha", "api:/v1/rules"},
		PolicyEpoch: 1,
		Note:        "automation",
	}
}

func TestCreateDefaultsTTLAndReturnsSecretOnce(t *testing.T) {
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	m := NewManager()
	issued, err := m.Create(now, tokenRequest())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if issued.Secret == "" || issued.Metadata.ID == "" {
		t.Fatalf("missing one-time credential: %+v", issued)
	}
	if issued.Metadata.ExpiresAt.Sub(now) != DefaultTTL {
		t.Fatalf("default ttl = %s", issued.Metadata.ExpiresAt.Sub(now))
	}
	if issued.Metadata.NeverExpire {
		t.Fatal("default token must expire")
	}
	if got, ok := m.Get(now, issued.Metadata.ID); !ok || got.Note != "automation" {
		t.Fatalf("metadata unavailable: %+v %v", got, ok)
	}
	got, _ := m.Get(now, issued.Metadata.ID)
	got.Permissions[0] = "admin"
	got.Resources[0] = "*"
	again, _ := m.Get(now, issued.Metadata.ID)
	if again.Permissions[0] == "admin" || again.Resources[0] == "*" {
		t.Fatal("metadata snapshot is mutable")
	}
}

func TestCreateRejectsNonCanonicalIdentityFieldsAndPreservesNote(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name   string
		mutate func(*CreateRequest)
	}{
		{name: "owner leading space", mutate: func(req *CreateRequest) { req.Owner = " alice" }},
		{name: "owner control", mutate: func(req *CreateRequest) { req.Owner = "alice\x00" }},
		{name: "owner format character", mutate: func(req *CreateRequest) { req.Owner = "alice\u200b" }},
		{name: "permission trailing space", mutate: func(req *CreateRequest) { req.Permissions = []string{"rules.read "} }},
		{name: "resource embedded tab", mutate: func(req *CreateRequest) { req.Resources = []string{"site:\talpha"} }},
		{name: "scope format character", mutate: func(req *CreateRequest) { req.Resources = nil; req.Scopes = []string{"site:alpha\u200b"} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := tokenRequest()
			tc.mutate(&req)
			if _, err := NewManager().Create(now, req); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("Create accepted non-canonical identity: %v", err)
			}
		})
	}
	req := tokenRequest()
	req.Note = "  visible note  "
	issued, err := NewManager().Create(now, req)
	if err != nil {
		t.Fatalf("Create note: %v", err)
	}
	if issued.Metadata.Note != req.Note {
		t.Fatalf("note = %q, want original display text %q", issued.Metadata.Note, req.Note)
	}
}

func TestAuthorizeRejectsNonCanonicalIdentityInputs(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	m := NewManager()
	issued, err := m.Create(now, tokenRequest())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	cases := []struct {
		name, id, permission, resource string
	}{
		{name: "id leading space", id: " " + issued.Metadata.ID, permission: "rules.read", resource: "site:alpha"},
		{name: "permission format character", id: issued.Metadata.ID, permission: "rules.read\u200b", resource: "site:alpha"},
		{name: "resource control", id: issued.Metadata.ID, permission: "rules.read", resource: "site:\x00alpha"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := m.Authorize(now.Add(time.Minute), tc.id, issued.Secret, tc.permission, tc.resource); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("Authorize error = %v, want ErrInvalidRequest", err)
			}
		})
	}
}

func TestResolveLifetimeEnforcesSafeDefaultsAndBounds(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	resolved, err := ResolveLifetime(now, 0, time.Time{}, false, false)
	if err != nil {
		t.Fatalf("default lifetime: %v", err)
	}
	if !resolved.ExpiresAt.Equal(now.Add(DefaultTTL)) || resolved.NeverExpire {
		t.Fatalf("default lifetime = %+v", resolved)
	}
	if _, err := ResolveLifetime(now, MaxTTL+time.Second, time.Time{}, false, false); !errors.Is(err, ErrTTLExceeded) {
		t.Fatalf("overlong ttl error = %v", err)
	}
	if _, err := ResolveLifetime(now, 0, now.Add(MaxTTL+time.Second), false, false); !errors.Is(err, ErrTTLExceeded) {
		t.Fatalf("overlong absolute expiry error = %v", err)
	}
}

func TestResolveLifetimeNeverExpireRequiresExplicitConfirmation(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	if _, err := ResolveLifetime(now, 0, time.Time{}, true, false); !errors.Is(err, ErrSecondConfirmationRequired) {
		t.Fatalf("missing confirmation error = %v", err)
	}
	resolved, err := ResolveLifetime(now, 0, time.Time{}, true, true)
	if err != nil || !resolved.NeverExpire || !resolved.ExpiresAt.IsZero() {
		t.Fatalf("confirmed non-expiring lifetime = %+v err=%v", resolved, err)
	}
	if _, err := ResolveLifetime(now, time.Hour, time.Time{}, true, true); !errors.Is(err, ErrInvalidTTL) {
		t.Fatalf("non-expiring ttl accepted: %v", err)
	}
}

func TestNeverExpireRequiresExplicitSecondConfirmation(t *testing.T) {
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	m := NewManager()
	req := tokenRequest()
	req.NeverExpire = true
	if _, err := m.Create(now, req); !errors.Is(err, ErrSecondConfirmationRequired) {
		t.Fatalf("without confirmation: %v", err)
	}
	req.ConfirmNeverExpire = true
	issued, err := m.Create(now, req)
	if err != nil {
		t.Fatalf("confirmed create: %v", err)
	}
	if !issued.Metadata.NeverExpire || !issued.Metadata.ExpiresAt.IsZero() {
		t.Fatalf("unexpected non-expiring metadata: %+v", issued.Metadata)
	}
}

func TestAuthorizeBindsPermissionAndResourceAndUpdatesActivity(t *testing.T) {
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	m := NewManager()
	issued, _ := m.Create(now, tokenRequest())
	if _, err := m.Authorize(now.Add(time.Minute), issued.Metadata.ID, issued.Secret, "rules.delete", "site:alpha"); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("permission bypass: %v", err)
	}
	if _, err := m.Authorize(now.Add(time.Minute), issued.Metadata.ID, issued.Secret, "rules.read", "site:beta"); !errors.Is(err, ErrResourceDenied) {
		t.Fatalf("resource bypass: %v", err)
	}
	meta, err := m.Authorize(now.Add(time.Minute), issued.Metadata.ID, issued.Secret, "rules.read", "site:alpha")
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if !meta.LastActivityAt.Equal(now.Add(time.Minute)) {
		t.Fatalf("activity not updated: %+v", meta)
	}
	if _, err := m.Authorize(now.Add(time.Minute), issued.Metadata.ID, "wrong", "rules.read", "site:alpha"); !errors.Is(err, ErrInvalidSecret) {
		t.Fatalf("wrong secret: %v", err)
	}
}

func TestDisableAndRevokeFailClosed(t *testing.T) {
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	m := NewManager()
	issued, _ := m.Create(now, tokenRequest())
	if err := m.Disable(now.Add(time.Minute), issued.Metadata.ID, "incident"); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if _, err := m.Authorize(now.Add(2*time.Minute), issued.Metadata.ID, issued.Secret, "rules.read", "site:alpha"); !errors.Is(err, ErrDisabled) {
		t.Fatalf("disabled token accepted: %v", err)
	}
	issued2, _ := m.Create(now, tokenRequest())
	if err := m.Revoke(now.Add(time.Minute), issued2.Metadata.ID, "owner"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := m.Authorize(now.Add(2*time.Minute), issued2.Metadata.ID, issued2.Secret, "rules.read", "site:alpha"); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked token accepted: %v", err)
	}
}

func TestExpiryAndInactivityCleanupAreDelayedAndEmitNotification(t *testing.T) {
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	m := NewManager()
	req := tokenRequest()
	req.NeverExpire = true
	req.ConfirmNeverExpire = true
	issued, _ := m.Create(now, req)
	if due := m.NextCleanupAt(); !due.Equal(now.Add(CleanupDelay)) {
		t.Fatalf("cleanup due = %s", due)
	}
	if removed := m.Cleanup(now.Add(CleanupDelay - time.Second)); removed != 0 {
		t.Fatalf("cleanup ran early: %d", removed)
	}
	if removed := m.Cleanup(now.Add(CleanupDelay)); removed != 0 {
		t.Fatalf("unexpected cleanup: %d", removed)
	}
	if _, err := m.Authorize(now.Add(180*24*time.Hour), issued.Metadata.ID, issued.Secret, "rules.read", "site:alpha"); !errors.Is(err, ErrInactive) {
		t.Fatalf("inactive token result: %v", err)
	}
	if removed := m.Cleanup(now.Add(180*24*time.Hour + CleanupDelay)); removed != 1 {
		t.Fatalf("removed = %d", removed)
	}
	events := m.Events()
	if len(events) == 0 || events[len(events)-1].Type != EventAutoDestroyed {
		t.Fatalf("missing destroy event: %+v", events)
	}
	events[0].Reason = "tampered"
	if m.Events()[0].Reason == "tampered" {
		t.Fatal("event snapshot is mutable")
	}
}

func TestCleanupDeadlineHasTenMinuteSlidingWindowAndSixtyMinuteCap(t *testing.T) {
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	m := NewManager()
	req := tokenRequest()
	req.TTL = time.Minute
	first, _ := m.Create(now, req)
	if due := m.NextCleanupAt(); !due.Equal(now.Add(10 * time.Minute)) {
		t.Fatalf("initial deadline = %s", due)
	}
	for minute := 9; minute <= 54; minute += 9 {
		issued, err := m.Create(now.Add(time.Duration(minute)*time.Minute), req)
		if err != nil || issued.Metadata.ID == first.Metadata.ID {
			t.Fatalf("create at %dm: id=%q err=%v", minute, issued.Metadata.ID, err)
		}
	}
	if due := m.NextCleanupAt(); !due.Equal(now.Add(60 * time.Minute)) {
		t.Fatalf("deadline must be capped at first creation + 60m: %s", due)
	}
	if removed := m.Cleanup(now.Add(60 * time.Minute)); removed == 0 {
		t.Fatal("cleanup did not run at the capped deadline")
	}
}

func TestCleanupClearsDeadlineWhenNoTokensRemainAndIsIdempotent(t *testing.T) {
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	m := NewManager()
	req := tokenRequest()
	req.TTL = time.Minute
	m.Create(now, req)
	if removed := m.Cleanup(now.Add(10 * time.Minute)); removed != 1 {
		t.Fatalf("removed = %d", removed)
	}
	if !m.NextCleanupAt().IsZero() {
		t.Fatalf("deadline should clear with no pending tokens: %s", m.NextCleanupAt())
	}
	if removed := m.Cleanup(now.Add(20 * time.Minute)); removed != 0 {
		t.Fatalf("repeated cleanup removed = %d", removed)
	}
}

func TestExpiryAndScopeValidation(t *testing.T) {
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	m := NewManager()
	req := tokenRequest()
	req.TTL = time.Hour
	issued, _ := m.Create(now, req)
	if _, err := m.Authorize(now.Add(time.Hour), issued.Metadata.ID, issued.Secret, "rules.read", "site:alpha"); !errors.Is(err, ErrExpired) {
		t.Fatalf("expiry boundary: %v", err)
	}
	if _, err := m.Authorize(now.Add(-time.Second), issued.Metadata.ID, issued.Secret, "rules.read", "site:alpha"); !errors.Is(err, ErrInvalidTime) {
		t.Fatalf("time regression: %v", err)
	}
}

func TestCreateRequiresPolicyEpoch(t *testing.T) {
	req := tokenRequest()
	req.PolicyEpoch = 0
	if _, err := NewManager().Create(time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC), req); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("token without policy epoch accepted: %v", err)
	}
}

func TestConcurrentCreateAndAuthorizeRemainRaceFree(t *testing.T) {
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	m := NewManager()
	issued := make(chan Issued, 64)
	var create sync.WaitGroup
	for i := 0; i < 64; i++ {
		create.Add(1)
		go func() {
			defer create.Done()
			item, err := m.Create(now, tokenRequest())
			if err != nil {
				t.Errorf("create: %v", err)
				return
			}
			issued <- item
		}()
	}
	create.Wait()
	close(issued)
	var authorize sync.WaitGroup
	for item := range issued {
		authorize.Add(1)
		go func(item Issued) {
			defer authorize.Done()
			if _, err := m.Authorize(now.Add(time.Second), item.Metadata.ID, item.Secret, "rules.read", "site:alpha"); err != nil {
				t.Errorf("authorize: %v", err)
			}
		}(item)
	}
	authorize.Wait()
	if got := len(m.List(now.Add(time.Second))); got != 64 {
		t.Fatalf("token count = %d", got)
	}
}
