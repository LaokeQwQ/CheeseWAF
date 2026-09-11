package tokens

import (
	"context"
	"errors"
	"testing"
	"time"
)

func persistedTokenFixture() PersistedToken {
	return PersistedToken{
		ID: "tok_1", Owner: "alice", Permissions: []string{"rules.read"},
		Resources: []string{"site:alpha"}, Scopes: []string{"site:alpha"},
		Note: "automation", PolicyEpoch: 7, Version: 1,
		CreatedAt:      time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC),
		ExpiresAt:      time.Date(2026, 12, 6, 12, 0, 0, 0, time.UTC),
		LastActivityAt: time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC),
		SecretDigest:   "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		LeaseID:        "lease-1",
	}
}

func TestPersistentMutationRequiresDigestAndLease(t *testing.T) {
	fake := NewMemoryPersistence()
	item := persistedTokenFixture()
	if err := fake.Apply(context.Background(), Mutation{TenantID: "tenant-a", Token: item, ExpectedVersion: 0, LeaseID: item.LeaseID, IdempotencyKey: "create-1", Event: Event{Sequence: 1, Type: EventCreated, At: item.CreatedAt, TokenID: item.ID}}); err != nil {
		t.Fatalf("apply valid mutation: %v", err)
	}
	item.SecretDigest = "plaintext-secret"
	if err := fake.Apply(context.Background(), Mutation{TenantID: "tenant-b", Token: item, ExpectedVersion: 0, LeaseID: item.LeaseID, IdempotencyKey: "create-2", Event: Event{Sequence: 1, Type: EventCreated, At: item.CreatedAt, TokenID: item.ID}}); !errors.Is(err, ErrInvalidPersistence) {
		t.Fatalf("plaintext digest accepted: %v", err)
	}
	item = persistedTokenFixture()
	if err := fake.Apply(context.Background(), Mutation{TenantID: "tenant-c", Token: item, ExpectedVersion: 0, LeaseID: item.LeaseID, IdempotencyKey: "create-3", Event: Event{Sequence: 1, Type: EventCreated, At: item.CreatedAt, TokenID: item.ID}}); err != nil {
		t.Fatalf("create token for lease test: %v", err)
	}
	item.Version = 2
	if err := fake.Apply(context.Background(), Mutation{TenantID: "tenant-c", Token: item, ExpectedVersion: 1, LeaseID: "other-lease", IdempotencyKey: "update-3", Event: Event{Sequence: 2, Type: EventDisabled, At: item.CreatedAt, TokenID: item.ID}}); !errors.Is(err, ErrLeaseConflict) {
		t.Fatalf("lease mismatch accepted: %v", err)
	}
}

func TestPersistentMutationRejectsNonCanonicalIdentityFields(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Mutation)
	}{
		{name: "tenant leading space", mutate: func(m *Mutation) { m.TenantID = " tenant-a" }},
		{name: "token id format character", mutate: func(m *Mutation) { m.Token.ID = "tok_1\u200b"; m.Event.TokenID = m.Token.ID }},
		{name: "owner trailing space", mutate: func(m *Mutation) { m.Token.Owner = "alice " }},
		{name: "permission control", mutate: func(m *Mutation) { m.Token.Permissions = []string{"rules.\x00read"} }},
		{name: "resource format character", mutate: func(m *Mutation) { m.Token.Resources = []string{"site:alpha\u200b"} }},
		{name: "scope embedded tab", mutate: func(m *Mutation) { m.Token.Scopes = []string{"site:\talpha"} }},
		{name: "lease leading space", mutate: func(m *Mutation) { m.LeaseID = " lease-1" }},
		{name: "idempotency trailing space", mutate: func(m *Mutation) { m.IdempotencyKey = "create-1 " }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := Mutation{
				TenantID: "tenant-a", Token: persistedTokenFixture(), ExpectedVersion: 0,
				LeaseID: "lease-1", IdempotencyKey: "create-1",
				Event: Event{Sequence: 1, Type: EventCreated, At: time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC), TokenID: "tok_1"},
			}
			tc.mutate(&m)
			if err := validatePersistedMutation(m); !errors.Is(err, ErrInvalidPersistence) {
				t.Fatalf("validate = %v, want ErrInvalidPersistence", err)
			}
		})
	}
}

func TestMemoryPersistenceRejectsTrimmedIdentityLookups(t *testing.T) {
	fake := NewMemoryPersistence()
	item := persistedTokenFixture()
	mutation := Mutation{TenantID: "tenant-a", Token: item, LeaseID: item.LeaseID, IdempotencyKey: "create-1", Event: Event{Sequence: 1, Type: EventCreated, At: item.CreatedAt, TokenID: item.ID}}
	if err := fake.Apply(context.Background(), mutation); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if _, err := fake.Load(context.Background(), " tenant-a", item.ID); !errors.Is(err, ErrInvalidPersistence) {
		t.Fatalf("trimmed lookup error = %v, want ErrInvalidPersistence", err)
	}
}

func TestMemoryPersistenceAtomicStateAndAppendOnlyEvents(t *testing.T) {
	fake := NewMemoryPersistence()
	item := persistedTokenFixture()
	create := Mutation{TenantID: "tenant-a", Token: item, ExpectedVersion: 0, LeaseID: item.LeaseID, IdempotencyKey: "create-1", Event: Event{Sequence: 1, Type: EventCreated, At: item.CreatedAt, TokenID: item.ID}}
	if err := fake.Apply(context.Background(), create); err != nil {
		t.Fatal(err)
	}
	if err := fake.Apply(context.Background(), create); err != nil {
		t.Fatalf("idempotent retry: %v", err)
	}
	updated := item
	updated.Version = 2
	updated.Disabled = true
	update := Mutation{TenantID: "tenant-a", Token: updated, ExpectedVersion: 1, LeaseID: item.LeaseID, IdempotencyKey: "disable-1", Event: Event{Sequence: 2, Type: EventDisabled, At: item.CreatedAt.Add(time.Minute), TokenID: item.ID, Reason: "incident"}}
	if err := fake.Apply(context.Background(), update); err != nil {
		t.Fatal(err)
	}
	if err := fake.Apply(context.Background(), update); err != nil {
		t.Fatalf("idempotent update retry: %v", err)
	}
	conflicting := update
	conflicting.Token.Note = "tampered"
	if err := fake.Apply(context.Background(), conflicting); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("idempotency conflict error=%v", err)
	}
	stale := update
	stale.IdempotencyKey = "disable-stale"
	stale.ExpectedVersion = 1
	if err := fake.Apply(context.Background(), stale); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("version conflict error=%v", err)
	}
	events, err := fake.Events(context.Background(), "tenant-a", item.ID)
	if err != nil || len(events) != 2 {
		t.Fatalf("events=%+v err=%v", events, err)
	}
	destroyed := updated
	destroyed.Version = 3
	if err := fake.Apply(context.Background(), Mutation{TenantID: "tenant-a", Token: destroyed, ExpectedVersion: 2, LeaseID: item.LeaseID, IdempotencyKey: "destroy-1", DeleteToken: true, Event: Event{Sequence: 3, Type: EventAutoDestroyed, At: item.CreatedAt.Add(180 * 24 * time.Hour), TokenID: item.ID, Notification: true}}); err != nil {
		t.Fatalf("destroy event: %v", err)
	}
	if _, err := fake.Load(context.Background(), "tenant-a", item.ID); !errors.Is(err, ErrTokenNotFound) {
		t.Fatalf("deleted token load=%v", err)
	}
	events, err = fake.Events(context.Background(), "tenant-a", item.ID)
	if err != nil || len(events) != 3 || events[2].Notification != true {
		t.Fatalf("cleanup event recovery events=%+v err=%v", events, err)
	}
}

func TestPersistentMutationRejectsInconsistentNonExpiringLifetime(t *testing.T) {
	item := persistedTokenFixture()
	item.NeverExpire = true
	if err := NewMemoryPersistence().Apply(context.Background(), Mutation{
		TenantID: "tenant-lifetime", Token: item, ExpectedVersion: 0, LeaseID: item.LeaseID, IdempotencyKey: "lifetime-1",
		Event: Event{Sequence: 1, Type: EventCreated, At: item.CreatedAt, TokenID: item.ID},
	}); !errors.Is(err, ErrInvalidPersistence) {
		t.Fatalf("non-expiring token with expiry accepted: %v", err)
	}
}

func TestPersistentMutationRejectsExpiryBeforeCreation(t *testing.T) {
	item := persistedTokenFixture()
	item.ExpiresAt = item.CreatedAt.Add(-time.Second)
	if err := NewMemoryPersistence().Apply(context.Background(), Mutation{
		TenantID: "tenant-lifetime", Token: item, ExpectedVersion: 0, LeaseID: item.LeaseID, IdempotencyKey: "lifetime-2",
		Event: Event{Sequence: 1, Type: EventCreated, At: item.CreatedAt, TokenID: item.ID},
	}); !errors.Is(err, ErrInvalidPersistence) {
		t.Fatalf("expiry before creation accepted: %v", err)
	}
}
