package passkey

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestGenerateRecoveryCodesStoresOnlyHashes(t *testing.T) {
	store := newMemoryStore()
	service := newTestService(t, store, newTestClock())
	ctx := context.Background()

	codes, err := service.GenerateRecoveryCodes(ctx, "admin", 10)
	if err != nil {
		t.Fatalf("GenerateRecoveryCodes() error = %v", err)
	}

	if len(codes) != 10 {
		t.Fatalf("codes = %d, want 10", len(codes))
	}

	seen := make(map[string]struct{}, len(codes))
	for _, code := range codes {
		if len(code) != recoveryCodeLength+recoveryCodeLength/recoveryCodeGroup-1 {
			t.Fatalf("code %q has unexpected length", code)
		}

		if _, ok := seen[code]; ok {
			t.Fatalf("duplicate code %q", code)
		}

		seen[code] = struct{}{}

		normalized, err := normalizeRecoveryCode(code)
		if err != nil {
			t.Fatalf("normalizeRecoveryCode(%q) error = %v", code, err)
		}

		for _, hash := range store.recoveryHashes("admin") {
			if string(hash) == normalized {
				t.Fatalf("plaintext code was persisted")
			}
		}
	}

	hashes := store.recoveryHashes("admin")
	if len(hashes) != 10 {
		t.Fatalf("stored hashes = %d, want 10", len(hashes))
	}

	for _, hash := range hashes {
		if len(hash) != 32 {
			t.Fatalf("stored hash length = %d, want 32", len(hash))
		}
	}
}

func TestRecoveryCodeOneTimeUse(t *testing.T) {
	store := newMemoryStore()
	service := newTestService(t, store, newTestClock())
	ctx := context.Background()

	codes, err := service.GenerateRecoveryCodes(ctx, "admin", 2)
	if err != nil {
		t.Fatalf("GenerateRecoveryCodes() error = %v", err)
	}

	ok, err := service.ConsumeRecoveryCode(ctx, "admin", strings.ToLower(codes[0]))
	if err != nil || !ok {
		t.Fatalf("first ConsumeRecoveryCode() = %v, %v", ok, err)
	}

	ok, err = service.ConsumeRecoveryCode(ctx, "admin", codes[0])
	if err != nil || ok {
		t.Fatalf("reused ConsumeRecoveryCode() = %v, %v", ok, err)
	}

	ok, err = service.ConsumeRecoveryCode(ctx, "admin", codes[1])
	if err != nil || !ok {
		t.Fatalf("second code ConsumeRecoveryCode() = %v, %v", ok, err)
	}

	ok, err = service.ConsumeRecoveryCode(ctx, "admin", "AAAA-BBBB-CCCC-DDDD")
	if err != nil || ok {
		t.Fatalf("unknown code ConsumeRecoveryCode() = %v, %v", ok, err)
	}

	if _, err := service.ConsumeRecoveryCode(ctx, "admin", "bad code"); !errors.Is(err, ErrInvalidRecoveryCode) {
		t.Fatalf("malformed code error = %v, want ErrInvalidRecoveryCode", err)
	}
}

func TestGenerateRecoveryCodesBounds(t *testing.T) {
	service := newTestService(t, newMemoryStore(), newTestClock())

	for _, count := range []int{-1, MaxRecoveryCodes + 1} {
		if _, err := service.GenerateRecoveryCodes(context.Background(), "admin", count); !errors.Is(err, ErrInvalidRecoveryCode) {
			t.Fatalf("count %d error = %v, want ErrInvalidRecoveryCode", count, err)
		}
	}

	codes, err := service.GenerateRecoveryCodes(context.Background(), "admin", 0)
	if err != nil {
		t.Fatalf("default count error = %v", err)
	}

	if len(codes) != DefaultRecoveryCodeCount {
		t.Fatalf("default count = %d, want %d", len(codes), DefaultRecoveryCodeCount)
	}
}

func TestAdminResetDeletesCredentialsAndAudits(t *testing.T) {
	store := newMemoryStore()
	clock := newTestClock()
	service := newTestService(t, store, clock)
	ctx := context.Background()

	for _, seed := range []byte{1, 2} {
		if err := store.Create(ctx, testCredential("admin", seed)); err != nil {
			t.Fatalf("store.Create() error = %v", err)
		}
	}

	if err := store.Create(ctx, testCredential("operator", 9)); err != nil {
		t.Fatalf("store.Create() error = %v", err)
	}

	if _, err := service.GenerateRecoveryCodes(ctx, "admin", 3); err != nil {
		t.Fatalf("GenerateRecoveryCodes() error = %v", err)
	}

	result, err := service.AdminReset(ctx, "admin", "root", "lost authenticator")
	if err != nil {
		t.Fatalf("AdminReset() error = %v", err)
	}

	if result.CredentialsDeleted != 2 {
		t.Fatalf("CredentialsDeleted = %d, want 2", result.CredentialsDeleted)
	}

	if !result.RecoveryCodesDeleted {
		t.Fatal("RecoveryCodesDeleted = false")
	}

	if !result.AuditRecordedAt.Equal(clock.Now()) {
		t.Fatalf("AuditRecordedAt = %s, want %s", result.AuditRecordedAt, clock.Now())
	}

	records, err := store.ListByUser(ctx, "admin")
	if err != nil {
		t.Fatalf("ListByUser() error = %v", err)
	}

	if len(records) != 0 {
		t.Fatalf("credentials after reset = %d, want 0", len(records))
	}

	if len(store.recoveryHashes("admin")) != 0 {
		t.Fatal("recovery codes were not deleted")
	}

	if records, err := store.ListByUser(ctx, "operator"); err != nil || len(records) != 1 {
		t.Fatalf("other user's credentials changed: %d, %v", len(records), err)
	}

	events := store.auditEvents()
	if len(events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(events))
	}

	if events[0].Type != "passkey.admin_reset" || events[0].UserID != "admin" ||
		events[0].Actor != "root" || events[0].Reason != "lost authenticator" {
		t.Fatalf("unexpected audit event: %+v", events[0])
	}
}

func TestAdminResetRequiresActorAndReason(t *testing.T) {
	service := newTestService(t, newMemoryStore(), newTestClock())

	if _, err := service.AdminReset(context.Background(), "admin", "", "lost key"); !errors.Is(err, ErrInvalidUser) {
		t.Fatalf("empty actor error = %v, want ErrInvalidUser", err)
	}

	if _, err := service.AdminReset(context.Background(), "admin", "root", " "); !errors.Is(err, ErrInvalidUser) {
		t.Fatalf("empty reason error = %v, want ErrInvalidUser", err)
	}
}
