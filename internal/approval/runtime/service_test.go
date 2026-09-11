package runtime

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/api/handler"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
	"golang.org/x/crypto/bcrypt"
)

type runtimeStoreStub struct {
	storage.Store
	user         *storage.User
	active       bool
	consumed     bool
	marked       bool
	atomicCalls  int
	atomicErr    error
	healthCalls  int
	userCalls    int
	sessionCalls int
}

func (s *runtimeStoreStub) Health(context.Context) error {
	s.healthCalls++
	return nil
}

func (s *runtimeStoreStub) GetUserByUsername(context.Context, string) (*storage.User, error) {
	s.userCalls++
	return s.user, nil
}

func (s *runtimeStoreStub) IsSessionActive(context.Context, string, string, time.Time) (bool, error) {
	s.sessionCalls++
	return s.active, nil
}

func (s *runtimeStoreStub) IsTOTPConsumed(context.Context, string, int64, time.Time) (bool, error) {
	return s.consumed, nil
}

func (s *runtimeStoreStub) ConsumeTOTP(context.Context, string, int64, time.Time, time.Time) (bool, error) {
	s.atomicCalls++
	if s.atomicErr != nil {
		return false, s.atomicErr
	}
	if s.consumed {
		return false, nil
	}
	s.marked = true
	s.consumed = true
	return true, nil
}

func (s *runtimeStoreStub) MarkTOTPConsumed(context.Context, string, int64, time.Time) error {
	s.marked = true
	s.consumed = true
	return nil
}

func TestOpenRequiresExplicitProductionDependencies(t *testing.T) {
	if _, err := Open(context.Background(), Options{}); !errors.Is(err, ErrManagementRequired) {
		t.Fatalf("missing management error=%v, want ErrManagementRequired", err)
	}
	stub := &runtimeStoreStub{}
	if _, err := Open(context.Background(), Options{Management: stub}); !errors.Is(err, ErrApprovalDSNRequired) {
		t.Fatalf("missing approval DSN error=%v, want ErrApprovalDSNRequired", err)
	}
	if _, err := Open(context.Background(), Options{Management: stub, ApprovalDSN: "postgres://unused"}); !errors.Is(err, ErrApprovalEpochRequired) {
		t.Fatalf("missing policy epoch error=%v, want ErrApprovalEpochRequired", err)
	}
}

func TestPolicyEpochIsReadOnlyAndNilSafe(t *testing.T) {
	svc := &Service{policyEpoch: 17}
	if got := svc.PolicyEpoch(); got != 17 {
		t.Fatalf("PolicyEpoch=%d, want 17", got)
	}
	var nilService *Service
	if got := nilService.PolicyEpoch(); got != 0 {
		t.Fatalf("nil Service PolicyEpoch=%d, want 0", got)
	}
}

func TestMatchingTOTPCounterRejectsWhitespaceWithoutRewriting(t *testing.T) {
	now := time.Unix(0, 0).UTC()
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	code, err := hotp(secret, 0)
	if err != nil {
		t.Fatal(err)
	}
	if code != "755224" {
		t.Fatalf("HOTP code=%q, want RFC 4226 vector 755224", code)
	}
	if _, ok := matchingTOTPCounter(secret, code, now); !ok {
		t.Fatal("valid TOTP code was rejected")
	}
	if _, ok := matchingTOTPCounter(secret, " "+code, now); ok {
		t.Fatal("TOTP code with leading whitespace was accepted")
	}
}

func TestCredentialVerifiersBindUserAndActiveSession(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("correct-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	stub := &runtimeStoreStub{user: &storage.User{ID: "user-1", Username: "admin", Role: "admin", PasswordHash: string(hash)}, active: true}
	svc := &Service{management: stub, clock: func() time.Time { return time.Unix(0, 0).UTC() }}
	session := handler.ApprovalSession{Subject: "user-1", SessionID: "session-1", Username: "admin"}
	if _, err := svc.verifyPassword(context.Background(), session, "wrong-password"); !errors.Is(err, ErrCredentialRejected) {
		t.Fatalf("wrong password error=%v, want ErrCredentialRejected", err)
	}
	if _, err := svc.verifyPassword(context.Background(), session, "correct-password"); err != nil {
		t.Fatalf("correct password error=%v", err)
	}
	apiTokenSession := session
	apiTokenSession.Subject = "api-token:user-1"
	if _, err := svc.verifyPassword(context.Background(), apiTokenSession, "correct-password"); !errors.Is(err, ErrCredentialRejected) {
		t.Fatalf("api-token subject error=%v, want ErrCredentialRejected", err)
	}
	stub.active = false
	if _, err := svc.verifyPassword(context.Background(), session, "correct-password"); !errors.Is(err, ErrCredentialRejected) {
		t.Fatalf("inactive session error=%v, want ErrCredentialRejected", err)
	}
	if stub.userCalls == 0 || stub.sessionCalls == 0 {
		t.Fatalf("credential verifier did not consult management user/session stores: users=%d sessions=%d", stub.userCalls, stub.sessionCalls)
	}
	stub.active = true
	stub.user.Role = "readonly"
	if _, err := svc.verifyPassword(context.Background(), session, "correct-password"); !errors.Is(err, ErrCredentialRejected) {
		t.Fatalf("readonly user error=%v, want ErrCredentialRejected", err)
	}
}

func TestCredentialVerifierRejectsSessionRoleClaimMismatch(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("correct-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	stub := &runtimeStoreStub{
		user:   &storage.User{ID: "user-1", Username: "admin", Role: "admin", PasswordHash: string(hash)},
		active: true,
	}
	svc := &Service{management: stub, clock: func() time.Time { return time.Unix(0, 0).UTC() }}
	session := handler.ApprovalSession{
		Subject:   "user-1",
		SessionID: "session-1",
		Username:  "admin",
		Role:      "security_admin",
	}
	if _, err := svc.verifyPassword(context.Background(), session, "correct-password"); !errors.Is(err, ErrCredentialRejected) {
		t.Fatalf("mismatched session role error=%v, want ErrCredentialRejected", err)
	}
}

func TestCredentialVerifierUsesExplicitApprovalRoles(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("correct-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	roles := map[string]ApprovalRolePolicy{
		"admin":          {AllowApproval: true},
		"security_admin": {AllowApproval: true, AllowBreakGlass: true},
		"tenant_owner":   {AllowApproval: true, AllowBreakGlass: true, BreakGlassScopes: map[string]struct{}{"tenant:one": {}}},
	}
	for _, role := range []string{"admin", "security_admin", "tenant_owner"} {
		stub := &runtimeStoreStub{user: &storage.User{ID: "user-1", Username: "operator", Role: role, PasswordHash: string(hash)}, active: true}
		svc := &Service{management: stub, authority: NewApprovalAuthorityResolver(roles), clock: func() time.Time { return time.Unix(0, 0).UTC() }}
		session := handler.ApprovalSession{Subject: "user-1", SessionID: "session-1", Username: "operator", Role: role}
		if _, err := svc.verifyPassword(context.Background(), session, "correct-password"); err != nil {
			t.Fatalf("explicit role %q password error=%v", role, err)
		}
	}
}

func TestApprovalAuthorityResolverKeepsBreakGlassExplicit(t *testing.T) {
	resolver := NewApprovalAuthorityResolver(map[string]ApprovalRolePolicy{
		"admin":          {AllowApproval: true, AllowBreakGlass: true},
		"security_admin": {AllowApproval: true, AllowBreakGlass: true},
		"tenant_owner":   {AllowApproval: true, AllowBreakGlass: true, BreakGlassScopes: map[string]struct{}{"tenant:one": {}}},
	})
	if resolver.CanBreakGlass("admin", "site:primary") {
		t.Fatal("ordinary admin was granted Break-glass authority")
	}
	if !resolver.CanBreakGlass("security_admin", "site:primary") {
		t.Fatal("explicit security_admin authority was rejected")
	}
	if resolver.CanBreakGlass("tenant_owner", "") {
		t.Fatal("tenant_owner without scope was granted Break-glass authority")
	}
	if resolver.CanBreakGlass("tenant_owner", "tenant:two") {
		t.Fatal("tenant_owner outside configured scope was granted Break-glass authority")
	}
	if !resolver.CanBreakGlass("tenant_owner", "tenant:one") {
		t.Fatal("tenant_owner in configured scope was rejected")
	}
	if resolver.CanApprove("readonly", "site:primary") || resolver.CanApprove("custom", "site:primary") {
		t.Fatal("readonly or unknown role was granted approval authority")
	}
}

func TestCredentialVerifierRejectsUnknownRoleEvenWithExplicitResolver(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("correct-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	allowAll := approvalAuthorityAllowAll{}
	stub := &runtimeStoreStub{user: &storage.User{ID: "user-1", Username: "operator", Role: "custom", PasswordHash: string(hash)}, active: true}
	svc := &Service{management: stub, authority: allowAll, clock: func() time.Time { return time.Unix(0, 0).UTC() }}
	session := handler.ApprovalSession{Subject: "user-1", SessionID: "session-1", Username: "operator", Role: "custom"}
	if _, err := svc.verifyPassword(context.Background(), session, "correct-password"); !errors.Is(err, ErrCredentialRejected) {
		t.Fatalf("unknown role with explicit resolver error=%v, want ErrCredentialRejected", err)
	}
}

type approvalAuthorityAllowAll struct{}

func (approvalAuthorityAllowAll) CanApprove(string, string) bool    { return true }
func (approvalAuthorityAllowAll) CanBreakGlass(string, string) bool { return true }

func TestTOTPVerifierUsesDurableReplayState(t *testing.T) {
	now := time.Unix(0, 0).UTC()
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	code, err := hotp(secret, 0)
	if err != nil {
		t.Fatal(err)
	}
	stub := &runtimeStoreStub{user: &storage.User{ID: "user-1", Username: "admin", Role: "admin", TwoFAEnabled: true, TwoFASecret: secret}, active: true}
	svc := &Service{management: stub, clock: func() time.Time { return now }}
	session := handler.ApprovalSession{Subject: "user-1", SessionID: "session-1", Username: "admin"}
	if _, err := svc.verifyTOTP(context.Background(), session, code); err != nil {
		t.Fatalf("first TOTP verification error=%v", err)
	}
	if !stub.marked {
		t.Fatal("successful TOTP verification did not persist replay state")
	}
	if stub.atomicCalls != 1 {
		t.Fatalf("atomic TOTP consume calls=%d, want 1", stub.atomicCalls)
	}
	if _, err := svc.verifyTOTP(context.Background(), session, code); !errors.Is(err, ErrCredentialRejected) {
		t.Fatalf("replayed TOTP error=%v, want ErrCredentialRejected", err)
	}
}

func TestTOTPVerifierFailsClosedOnAtomicStorageError(t *testing.T) {
	now := time.Unix(0, 0).UTC()
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	code, err := hotp(secret, 0)
	if err != nil {
		t.Fatal(err)
	}
	stub := &runtimeStoreStub{
		user:      &storage.User{ID: "user-1", Username: "admin", Role: "admin", TwoFAEnabled: true, TwoFASecret: secret},
		active:    true,
		atomicErr: errors.New("storage offline"),
	}
	svc := &Service{management: stub, clock: func() time.Time { return now }}
	session := handler.ApprovalSession{Subject: "user-1", SessionID: "session-1", Username: "admin"}
	if _, err := svc.verifyTOTP(context.Background(), session, code); !errors.Is(err, ErrCredentialUnavailable) {
		t.Fatalf("storage error=%v, want ErrCredentialUnavailable", err)
	}
}

type concurrentRuntimeStore struct {
	storage.Store
	user        *storage.User
	active      bool
	mu          sync.Mutex
	consumed    map[string]time.Time
	atomicCalls int
}

func (s *concurrentRuntimeStore) Health(context.Context) error { return nil }

func (s *concurrentRuntimeStore) GetUserByUsername(context.Context, string) (*storage.User, error) {
	return s.user, nil
}

func (s *concurrentRuntimeStore) IsSessionActive(context.Context, string, string, time.Time) (bool, error) {
	return s.active, nil
}

func (s *concurrentRuntimeStore) IsTOTPConsumed(_ context.Context, userID string, counter int64, now time.Time) (bool, error) {
	s.mu.Lock()
	consumed := s.consumed[totpKey(userID, counter)].After(now)
	s.mu.Unlock()
	return consumed, nil
}

func (s *concurrentRuntimeStore) MarkTOTPConsumed(_ context.Context, userID string, counter int64, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.consumed == nil {
		s.consumed = map[string]time.Time{}
	}
	s.consumed[totpKey(userID, counter)] = expiresAt
	return nil
}

func (s *concurrentRuntimeStore) ConsumeTOTP(_ context.Context, userID string, counter int64, expiresAt, now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.atomicCalls++
	if s.consumed == nil {
		s.consumed = map[string]time.Time{}
	}
	key := totpKey(userID, counter)
	if prior, ok := s.consumed[key]; ok && prior.After(now) {
		return false, nil
	}
	s.consumed[key] = expiresAt
	return true, nil
}

func totpKey(userID string, counter int64) string {
	return fmt.Sprintf("%s:%d", userID, counter)
}

func TestIndependentApprovalServicesAllowOnlyOneConcurrentTOTPConsumer(t *testing.T) {
	now := time.Unix(0, 0).UTC()
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	code, err := hotp(secret, 0)
	if err != nil {
		t.Fatal(err)
	}
	store := &concurrentRuntimeStore{
		user:     &storage.User{ID: "user-1", Username: "admin", Role: "admin", TwoFAEnabled: true, TwoFASecret: secret},
		active:   true,
		consumed: map[string]time.Time{},
	}
	services := []*Service{
		{management: store, clock: func() time.Time { return now }},
		{management: store, clock: func() time.Time { return now }},
	}
	session := handler.ApprovalSession{Subject: "user-1", SessionID: "session-1", Username: "admin"}
	start := make(chan struct{})
	results := make(chan error, len(services))
	for _, service := range services {
		go func(service *Service) {
			<-start
			_, err := service.verifyTOTP(context.Background(), session, code)
			results <- err
		}(service)
	}
	close(start)
	firstSuccess := 0
	for range services {
		if err := <-results; err == nil {
			firstSuccess++
		} else if !errors.Is(err, ErrCredentialRejected) {
			t.Fatalf("unexpected concurrent TOTP error=%v", err)
		}
	}
	if firstSuccess != 1 {
		t.Fatalf("concurrent approval TOTP successes=%d, want exactly 1", firstSuccess)
	}
	store.mu.Lock()
	atomicCalls := store.atomicCalls
	store.mu.Unlock()
	if atomicCalls != 2 {
		t.Fatalf("concurrent approval atomic consume calls=%d, want 2", atomicCalls)
	}
}
