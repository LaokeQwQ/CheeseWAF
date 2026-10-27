package service

import (
	"context"
	"errors"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/tokens"
)

// Authenticate must prove identity without evaluating scope, because the
// management API middleware runs before the router knows the route scope.
// Validate keeps enforcing that scope for callers that do know it.
func TestAuthenticateSkipsScopeButValidateEnforcesIt(t *testing.T) {
	s, clock, _ := serviceFixture(t)
	issued, err := s.Issue(context.Background(), issueRequest())
	if err != nil {
		t.Fatal(err)
	}
	auth := AuthenticateRequest{
		TenantID:       "tenant-a",
		TokenID:        issued.Metadata.ID,
		Secret:         issued.Secret,
		PolicyEpoch:    7,
		IdempotencyKey: "authenticate-1",
	}
	meta, err := s.Authenticate(context.Background(), auth)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if len(meta.Permissions) != 1 || meta.Permissions[0] != "rules.read" {
		t.Fatalf("metadata=%+v", meta)
	}
	if !meta.LastActivityAt.Equal(clock.Now()) {
		t.Fatalf("activity was not recorded: %v", meta.LastActivityAt)
	}

	validate := ValidateRequest{
		TenantID:       "tenant-a",
		TokenID:        issued.Metadata.ID,
		Secret:         issued.Secret,
		PolicyEpoch:    7,
		IdempotencyKey: "validate-1",
	}
	validate.Permission = "write"
	validate.Resource = "site:alpha"
	if _, err := s.Validate(context.Background(), validate); !errors.Is(err, tokens.ErrPermissionDenied) {
		t.Fatalf("validate must deny an unmatched permission, got %v", err)
	}
	validate.IdempotencyKey = "validate-2"
	validate.Permission = "rules.read"
	if _, err := s.Validate(context.Background(), validate); err != nil {
		t.Fatalf("validate must accept the matching scope: %v", err)
	}
	validate.IdempotencyKey = "validate-3"
	validate.Permission = "rules.read"
	validate.Resource = "site:beta"
	if _, err := s.Validate(context.Background(), validate); !errors.Is(err, tokens.ErrResourceDenied) {
		t.Fatalf("validate must deny an unmatched resource, got %v", err)
	}
}

func TestAuthenticateRejectsWrongSecretAndStaleEpoch(t *testing.T) {
	s, _, _ := serviceFixture(t)
	issued, err := s.Issue(context.Background(), issueRequest())
	if err != nil {
		t.Fatal(err)
	}
	base := AuthenticateRequest{TenantID: "tenant-a", TokenID: issued.Metadata.ID, Secret: issued.Secret, PolicyEpoch: 7, IdempotencyKey: "authenticate-2"}
	wrong := base
	wrong.Secret = "not-the-secret"
	if _, err := s.Authenticate(context.Background(), wrong); err == nil {
		t.Fatal("wrong secret must fail")
	}
	stale := base
	stale.IdempotencyKey = "authenticate-3"
	stale.PolicyEpoch = 6
	if _, err := s.Authenticate(context.Background(), stale); err == nil {
		t.Fatal("stale policy epoch must fail")
	}
}
