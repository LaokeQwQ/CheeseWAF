package netlease

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
	"golang.org/x/crypto/bcrypt"
)

type administratorStoreStub struct {
	users  []storage.User
	active bool
}

func (s administratorStoreStub) ListUsers(context.Context) ([]storage.User, error) {
	return append([]storage.User(nil), s.users...), nil
}

func (s administratorStoreStub) IsSessionActive(context.Context, string, string, time.Time) (bool, error) {
	return s.active, nil
}

func TestStoreAdministratorAuthenticatorRequiresManagementSessionUnlessExplicitlyLocal(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("correct horse battery staple"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	store := administratorStoreStub{users: []storage.User{{ID: "admin-id", Username: "admin", Role: "admin", PasswordHash: string(hash)}}, active: true}
	now := time.Now().UTC()
	remote := StoreAdministratorAuthenticator{Store: store}

	if err := remote.VerifySession(context.Background(), AdministratorIdentity{ID: "admin-id"}, now); !errors.Is(err, ErrAdministratorSessionDenied) {
		t.Fatalf("remote authenticator accepted absent management session: %v", err)
	}
	identity := AdministratorIdentity{ID: "admin-id", ManagementSessionID: "session-id"}
	if err := remote.VerifySession(context.Background(), identity, now); err != nil {
		t.Fatalf("remote authenticator rejected active management session: %v", err)
	}
	if err := remote.VerifyPassword(context.Background(), identity, "correct horse battery staple"); err != nil {
		t.Fatalf("correct administrator password rejected: %v", err)
	}
	if err := remote.VerifyPassword(context.Background(), identity, "incorrect"); !errors.Is(err, ErrAdministratorPasswordDenied) {
		t.Fatalf("incorrect administrator password accepted: %v", err)
	}

	local := StoreAdministratorAuthenticator{Store: store, AllowLocalWithoutManagementSession: true}
	if err := local.VerifySession(context.Background(), AdministratorIdentity{ID: "admin-id"}, now); err != nil {
		t.Fatalf("explicit local authenticator rejected local confirmation: %v", err)
	}
}
