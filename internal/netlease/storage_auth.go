package netlease

import (
	"context"
	"errors"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
	"golang.org/x/crypto/bcrypt"
)

// AdministratorStore is the narrow persistent boundary used to verify a
// temporary-online administrator. storage.Store satisfies it directly.
type AdministratorStore interface {
	ListUsers(context.Context) ([]storage.User, error)
	IsSessionActive(context.Context, string, string, time.Time) (bool, error)
}

// StoreAdministratorAuthenticator verifies an exact admin record, its
// revocable management session, and its bcrypt password hash. Management
// session validation is the default. A local CLI may explicitly opt out only
// after it has established a trusted local administrative boundary and asks
// for a fresh password confirmation in the same operation.
type StoreAdministratorAuthenticator struct {
	Store                              AdministratorStore
	AllowLocalWithoutManagementSession bool
}

func (a StoreAdministratorAuthenticator) VerifySession(ctx context.Context, identity AdministratorIdentity, now time.Time) error {
	if a.Store == nil || !identity.valid() {
		return ErrAdministratorSessionDenied
	}
	user, err := a.user(ctx, identity.ID)
	if err != nil || user == nil || user.Role != "admin" {
		return ErrAdministratorSessionDenied
	}
	if a.AllowLocalWithoutManagementSession {
		return nil
	}
	if !validOpaque(identity.ManagementSessionID, 256) {
		return ErrAdministratorSessionDenied
	}
	active, err := a.Store.IsSessionActive(ctx, identity.ManagementSessionID, identity.ID, now)
	if err != nil || !active {
		return ErrAdministratorSessionDenied
	}
	return nil
}

func (a StoreAdministratorAuthenticator) VerifyPassword(ctx context.Context, identity AdministratorIdentity, password string) error {
	if a.Store == nil || !identity.valid() || password == "" {
		return ErrAdministratorPasswordDenied
	}
	user, err := a.user(ctx, identity.ID)
	if err != nil || user == nil || user.Role != "admin" {
		return ErrAdministratorPasswordDenied
	}
	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)) != nil {
		return ErrAdministratorPasswordDenied
	}
	return nil
}

func (a StoreAdministratorAuthenticator) user(ctx context.Context, id string) (*storage.User, error) {
	users, err := a.Store.ListUsers(ctx)
	if err != nil {
		return nil, err
	}
	for index := range users {
		if users[index].ID == id {
			copy := users[index]
			return &copy, nil
		}
	}
	return nil, errors.New("administrator not found")
}
