package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/tokens"
)

type tokenRowFixture struct {
	includeID      bool
	epoch, version int64
	digest         string
}

func (r tokenRowFixture) Scan(dest ...any) error {
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	values := []any{
		"alice", []byte(`["rules.read"]`), []byte(`["site:alpha"]`), []byte(`["site:alpha"]`), "",
		r.epoch, now, sql.NullTime{}, false, false, false, now, r.digest, "lease-1", r.version,
	}
	if r.includeID {
		values = append([]any{"tok_1"}, values...)
	}
	if len(dest) != len(values) {
		return fmt.Errorf("destination count=%d, want %d", len(dest), len(values))
	}
	for i := range values {
		switch target := dest[i].(type) {
		case *string:
			*target = values[i].(string)
		case *[]byte:
			*target = values[i].([]byte)
		case *int64:
			*target = values[i].(int64)
		case *time.Time:
			*target = values[i].(time.Time)
		case *sql.NullTime:
			*target = values[i].(sql.NullTime)
		case *bool:
			*target = values[i].(bool)
		default:
			return fmt.Errorf("unsupported destination %d: %T", i, dest[i])
		}
	}
	return nil
}

func validMutation() tokens.Mutation {
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	return tokens.Mutation{
		TenantID: "tenant-a", LeaseID: "lease-1", IdempotencyKey: "create-1",
		Token: tokens.PersistedToken{ID: "tok_1", Owner: "alice", Permissions: []string{"rules.read"}, Resources: []string{"site:alpha"}, Scopes: []string{"site:alpha"}, PolicyEpoch: 1, CreatedAt: now, LastActivityAt: now, ExpiresAt: now.Add(24 * time.Hour), SecretDigest: strings.Repeat("a", 64), LeaseID: "lease-1", Version: 1},
		Event: tokens.Event{Sequence: 1, Type: tokens.EventCreated, At: now, TokenID: "tok_1"},
	}
}

func TestNewRejectsNilDB(t *testing.T) {
	if _, err := New(nil); !errors.Is(err, ErrInvalidStore) {
		t.Fatalf("nil db error=%v", err)
	}
}

func TestValidateRejectsPlaintextAndInvalidDigest(t *testing.T) {
	for _, digest := range []string{"secret", strings.Repeat("A", 64), strings.Repeat("g", 64)} {
		m := validMutation()
		m.Token.SecretDigest = digest
		if err := validate(m); !errors.Is(err, tokens.ErrInvalidPersistence) {
			t.Fatalf("digest %q accepted: %v", digest, err)
		}
	}
}

func TestValidateRejectsMissingLeaseAndAuditBinding(t *testing.T) {
	m := validMutation()
	m.Event.TokenID = "other"
	if err := validate(m); !errors.Is(err, tokens.ErrInvalidPersistence) {
		t.Fatalf("event token mismatch accepted: %v", err)
	}
	m = validMutation()
	m.LeaseID = ""
	if err := validate(m); !errors.Is(err, tokens.ErrInvalidPersistence) {
		t.Fatalf("missing lease accepted: %v", err)
	}
}

func TestValidateRejectsNonCanonicalIdentityFields(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*tokens.Mutation)
	}{
		{name: "tenant leading space", mutate: func(m *tokens.Mutation) { m.TenantID = " tenant-a" }},
		{name: "token id format character", mutate: func(m *tokens.Mutation) { m.Token.ID = "tok_1\u200b"; m.Event.TokenID = m.Token.ID }},
		{name: "owner trailing space", mutate: func(m *tokens.Mutation) { m.Token.Owner = "alice " }},
		{name: "permission control", mutate: func(m *tokens.Mutation) { m.Token.Permissions = []string{"rules.\x00read"} }},
		{name: "resource format character", mutate: func(m *tokens.Mutation) { m.Token.Resources = []string{"site:alpha\u200b"} }},
		{name: "scope embedded tab", mutate: func(m *tokens.Mutation) { m.Token.Scopes = []string{"site:\talpha"} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := validMutation()
			tc.mutate(&m)
			if err := validate(m); !errors.Is(err, tokens.ErrInvalidPersistence) {
				t.Fatalf("validate = %v, want ErrInvalidPersistence", err)
			}
		})
	}
}

func TestValidateRejectsInconsistentTokenLifetime(t *testing.T) {
	m := validMutation()
	m.Token.NeverExpire = true
	if err := validate(m); !errors.Is(err, tokens.ErrInvalidPersistence) {
		t.Fatalf("non-expiring token with expiry accepted: %v", err)
	}
	m = validMutation()
	m.Token.ExpiresAt = m.Token.CreatedAt.Add(-time.Second)
	if err := validate(m); !errors.Is(err, tokens.ErrInvalidPersistence) {
		t.Fatalf("expiry before creation accepted: %v", err)
	}
}

func TestValidateRejectsValuesThatCannotFitPostgresBigint(t *testing.T) {
	for _, mutate := range []func(*tokens.Mutation){
		func(m *tokens.Mutation) { m.Token.PolicyEpoch = ^uint64(0) },
		func(m *tokens.Mutation) { m.Token.Version = ^uint64(0) },
		func(m *tokens.Mutation) { m.Event.Sequence = ^uint64(0) },
	} {
		m := validMutation()
		mutate(&m)
		if err := validate(m); !errors.Is(err, tokens.ErrInvalidPersistence) {
			t.Fatalf("BIGINT overflow accepted: %v", err)
		}
	}
}

func TestNilContextAndDBFailClosed(t *testing.T) {
	if err := (&Store{}).Migrate(nil); !errors.Is(err, ErrInvalidStore) {
		t.Fatalf("nil context migration=%v", err)
	}
	if err := (&Store{}).Apply(context.Background(), validMutation()); !errors.Is(err, ErrInvalidStore) {
		t.Fatalf("nil db apply=%v", err)
	}
}

func TestLoadAndListRejectCorruptDatabaseFieldsBeforeUnsignedConversion(t *testing.T) {
	for _, tc := range []struct {
		name           string
		epoch, version int64
		digest         string
	}{
		{name: "negative epoch", epoch: -1, version: 1, digest: strings.Repeat("a", 64)},
		{name: "zero epoch", epoch: 0, version: 1, digest: strings.Repeat("a", 64)},
		{name: "negative version", epoch: 1, version: -1, digest: strings.Repeat("a", 64)},
		{name: "zero version", epoch: 1, version: 0, digest: strings.Repeat("a", 64)},
		{name: "short digest", epoch: 1, version: 1, digest: "abcd"},
		{name: "uppercase digest", epoch: 1, version: 1, digest: strings.Repeat("A", 64)},
		{name: "non-hex digest", epoch: 1, version: 1, digest: strings.Repeat("g", 64)},
	} {
		for _, path := range []struct {
			name string
			scan func(tokenRowFixture, *tokens.PersistedToken) error
		}{
			{name: "load", scan: func(row tokenRowFixture, out *tokens.PersistedToken) error {
				return loadRow(row, out)
			}},
			{name: "list", scan: func(row tokenRowFixture, out *tokens.PersistedToken) error {
				row.includeID = true
				var id string
				return scanToken(row, &id, out)
			}},
		} {
			t.Run(path.name+"/"+tc.name, func(t *testing.T) {
				var out tokens.PersistedToken
				err := path.scan(tokenRowFixture{epoch: tc.epoch, version: tc.version, digest: tc.digest}, &out)
				if !errors.Is(err, tokens.ErrInvalidPersistence) {
					t.Fatalf("corrupt row accepted: %v", err)
				}
				if out.PolicyEpoch != 0 || out.Version != 0 {
					t.Fatalf("corrupt signed values converted: epoch=%d version=%d", out.PolicyEpoch, out.Version)
				}
			})
		}
	}
}

func TestPostgresRoundTripIsAtomicAndIdempotent(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("CHEESEWAF_POSTGRES_TEST_DSN"))
	if dsn == "" {
		t.Skip("CHEESEWAF_POSTGRES_TEST_DSN is not configured")
	}
	ctx := context.Background()
	store, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	tenant := fmt.Sprintf("token-test-%d", time.Now().UnixNano())
	create := validMutation()
	create.TenantID = tenant
	if err := store.Apply(ctx, create); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := store.Apply(ctx, create); err != nil {
		t.Fatalf("idempotent create: %v", err)
	}
	conflict := create
	conflict.Token.Note = "changed"
	if err := store.Apply(ctx, conflict); !errors.Is(err, tokens.ErrIdempotencyConflict) {
		t.Fatalf("idempotency conflict=%v", err)
	}
	current, err := store.Load(ctx, tenant, create.Token.ID)
	if err != nil {
		t.Fatal(err)
	}
	current.Version = 2
	current.Disabled = true
	update := create
	update.IdempotencyKey = "disable-1"
	update.ExpectedVersion = 1
	update.Token = current
	update.Event = tokens.Event{Sequence: 2, Type: tokens.EventDisabled, At: create.Event.At.Add(time.Minute), TokenID: create.Token.ID, Reason: "incident"}
	if err := store.Apply(ctx, update); err != nil {
		t.Fatalf("update: %v", err)
	}
	stale := update
	stale.IdempotencyKey = "stale"
	stale.Token.Version = 3
	if err := store.Apply(ctx, stale); !errors.Is(err, ErrStaleVersion) {
		t.Fatalf("stale update=%v", err)
	}
	destroy := update
	destroy.IdempotencyKey = "destroy-1"
	destroy.ExpectedVersion = 2
	destroy.Token.Version = 3
	destroy.DeleteToken = true
	destroy.Event = tokens.Event{Sequence: 3, Type: tokens.EventAutoDestroyed, At: create.Event.At.Add(180 * 24 * time.Hour), TokenID: create.Token.ID, Notification: true}
	if err := store.Apply(ctx, destroy); err != nil {
		t.Fatalf("destroy: %v", err)
	}
	if _, err := store.Load(ctx, tenant, create.Token.ID); !errors.Is(err, ErrTokenNotFound) {
		t.Fatalf("deleted load=%v", err)
	}
	events, err := store.Events(ctx, tenant, create.Token.ID)
	if err != nil || len(events) != 3 || !events[2].Notification {
		t.Fatalf("events=%+v err=%v", events, err)
	}
	_, _ = store.db.ExecContext(ctx, "DELETE FROM cheesewaf_token_events WHERE tenant_id=$1", tenant)
	_, _ = store.db.ExecContext(ctx, "DELETE FROM cheesewaf_token_idempotency WHERE tenant_id=$1", tenant)
}
