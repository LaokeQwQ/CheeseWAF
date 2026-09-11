// Package runtime assembles the production approval boundary.
//
// The package deliberately owns no management data and never falls back to an
// in-memory approval ledger. The caller owns the management storage.Store;
// this package owns the approval PostgreSQL handle and the Gate HTTP adapter.
package runtime

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/api/handler"
	"github.com/LaokeQwQ/CheeseWAF/internal/approval"
	approvalpostgres "github.com/LaokeQwQ/CheeseWAF/internal/approval/postgres"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidOptions        = errors.New("invalid production approval runtime options")
	ErrManagementRequired    = errors.New("production approval management storage is required")
	ErrManagementHealth      = errors.New("production approval management storage health is unavailable")
	ErrApprovalDSNRequired   = errors.New("production approval PostgreSQL DSN is required")
	ErrApprovalEpochRequired = errors.New("production approval policy epoch is required")
	ErrApprovalEpochMissing  = errors.New("production approval policy epoch checkpoint is missing")
	ErrCredentialRejected    = errors.New("production approval credential was rejected")
	ErrCredentialUnavailable = errors.New("production approval credential verifier is unavailable")
)

type Options struct {
	// Management is the already-open production management PostgreSQL store.
	// It is not closed by Service.Close because the outer serve lifecycle owns it.
	Management storage.Store
	// ApprovalDSN is normally the control-plane PostgreSQL DSN. Approval tables
	// use their own names and are migrated on the same durable control database.
	ApprovalDSN string
	PolicyEpoch uint64
	Clock       func() time.Time
	// ApprovalRoles explicitly grants ordinary approval and, separately,
	// Break-glass authority to exact persisted role names. A nil map keeps the
	// default admin-only ordinary approval policy.
	ApprovalRoles map[string]ApprovalRolePolicy
	// AuthorityResolver overrides ApprovalRoles when a control plane owns a
	// richer role and scope policy. It must fail closed for unproven roles.
	AuthorityResolver approval.AuthorityResolver
}

// ApprovalRolePolicy describes the capabilities granted to one exact role.
// BreakGlassScopes is only consulted for tenant_owner; an empty scope never
// grants tenant-owner emergency authority.
type ApprovalRolePolicy struct {
	AllowApproval    bool
	AllowBreakGlass  bool
	BreakGlassScopes map[string]struct{}
}

type roleAuthorityResolver struct {
	roles map[string]ApprovalRolePolicy
}

// NewApprovalAuthorityResolver creates the explicit authority policy used by
// the runtime and HTTP adapter. A nil map selects the admin-only default;
// passing an empty map denies every role.
func NewApprovalAuthorityResolver(roles map[string]ApprovalRolePolicy) approval.AuthorityResolver {
	if roles == nil {
		roles = map[string]ApprovalRolePolicy{
			"admin": {AllowApproval: true},
		}
	}
	copyRoles := make(map[string]ApprovalRolePolicy, len(roles))
	for role, policy := range roles {
		if _, ok := approval.CanonicalActorRole(role); !ok {
			continue
		}
		policy.BreakGlassScopes = cloneStringSet(policy.BreakGlassScopes)
		copyRoles[role] = policy
	}
	return roleAuthorityResolver{roles: copyRoles}
}

func cloneStringSet(values map[string]struct{}) map[string]struct{} {
	if values == nil {
		return nil
	}
	copyValues := make(map[string]struct{}, len(values))
	for value := range values {
		copyValues[value] = struct{}{}
	}
	return copyValues
}

func (r roleAuthorityResolver) policy(role string) (ApprovalRolePolicy, bool) {
	if _, ok := approval.CanonicalActorRole(role); !ok {
		return ApprovalRolePolicy{}, false
	}
	policy, ok := r.roles[role]
	return policy, ok
}

func (r roleAuthorityResolver) CanApprove(role, _ string) bool {
	policy, ok := r.policy(role)
	return ok && policy.AllowApproval
}

func (r roleAuthorityResolver) CanBreakGlass(role, scope string) bool {
	actorRole, ok := approval.CanonicalActorRole(role)
	if !ok {
		return false
	}
	policy, ok := r.policy(role)
	if !ok || !policy.AllowBreakGlass {
		return false
	}
	if actorRole == approval.RoleTenantOwner {
		if scope == "" {
			return false
		}
		_, ok := policy.BreakGlassScopes[scope]
		return ok
	}
	return actorRole == approval.RoleSecurityAdmin
}

type Service struct {
	management  storage.Store
	store       *approvalpostgres.Store
	gate        *approval.Gate
	http        *handler.ApprovalHTTPHandler
	policyEpoch uint64
	clock       func() time.Time
	authority   approval.AuthorityResolver
	totpMu      sync.Mutex
	closeOnce   sync.Once
	closeErr    error
}

var _ interface {
	Health(context.Context) error
	Close() error
	ApprovalHTTP() *handler.ApprovalHTTPHandler
	PolicyEpoch() uint64
} = (*Service)(nil)

// Open opens, migrates, checkpoints, and restores the durable approval ledger.
// Every security dependency is explicit: management users/sessions/TOTP state
// and the approval PostgreSQL store are required before an HTTP handler exists.
func Open(ctx context.Context, opts Options) (*Service, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if opts.Management == nil {
		return nil, ErrManagementRequired
	}
	if strings.TrimSpace(opts.ApprovalDSN) == "" {
		return nil, ErrApprovalDSNRequired
	}
	if opts.PolicyEpoch == 0 {
		return nil, ErrApprovalEpochRequired
	}
	managementHealth, ok := opts.Management.(interface{ Health(context.Context) error })
	if !ok {
		return nil, ErrManagementHealth
	}
	if err := managementHealth.Health(ctx); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrManagementHealth, err)
	}

	store, err := approvalpostgres.Open(ctx, opts.ApprovalDSN)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*Service, error) {
		_ = store.Close()
		return nil, err
	}
	if err := store.Migrate(ctx); err != nil {
		return fail(err)
	}
	persistedEpoch, err := store.PolicyEpoch(ctx)
	if errors.Is(err, approval.ErrApprovalNotFound) {
		if err := store.CompareAndSetEpoch(ctx, 0, opts.PolicyEpoch); err != nil {
			return fail(fmt.Errorf("%w: initialize checkpoint: %v", ErrApprovalEpochMissing, err))
		}
		persistedEpoch = opts.PolicyEpoch
	} else if err != nil {
		return fail(err)
	}
	if persistedEpoch != opts.PolicyEpoch {
		return fail(fmt.Errorf("%w: durable=%d expected=%d", approval.ErrEpochChanged, persistedEpoch, opts.PolicyEpoch))
	}
	gate, err := approval.NewGateWithPersistence(opts.PolicyEpoch, store)
	if err != nil {
		return fail(err)
	}
	clock := opts.Clock
	if clock == nil {
		clock = time.Now
	}
	if err := gate.Restore(ctx, clock().UTC()); err != nil {
		return fail(fmt.Errorf("restore approval ledger: %w", err))
	}

	authority := opts.AuthorityResolver
	if authority == nil {
		authority = NewApprovalAuthorityResolver(opts.ApprovalRoles)
	}
	service := &Service{management: opts.Management, store: store, gate: gate, policyEpoch: opts.PolicyEpoch, clock: func() time.Time { return clock().UTC() }, authority: authority}
	service.http = handler.NewApprovalHTTPHandler(handler.ApprovalHTTPOptions{
		Gate:              gate,
		Clock:             service.clock,
		SessionValidator:  opts.Management,
		PasswordVerifier:  service.verifyPassword,
		TOTPVerifier:      service.verifyTOTP,
		AuthorityResolver: authority,
	})
	if service.http == nil {
		return fail(ErrInvalidOptions)
	}
	return service, nil
}

func (s *Service) ApprovalHTTP() *handler.ApprovalHTTPHandler {
	if s == nil {
		return nil
	}
	return s.http
}

// PolicyEpoch returns the immutable control-plane epoch bound to this
// approval runtime. It exposes only the fencing generation, never credentials
// or management state.
func (s *Service) PolicyEpoch() uint64 {
	if s == nil {
		return 0
	}
	return s.policyEpoch
}

func (s *Service) Gate() *approval.Gate {
	if s == nil {
		return nil
	}
	return s.gate
}

func (s *Service) Health(ctx context.Context) error {
	if s == nil || s.store == nil || s.management == nil || s.gate == nil || s.http == nil {
		return ErrInvalidOptions
	}
	if ctx == nil {
		ctx = context.Background()
	}
	managementHealth, ok := s.management.(interface{ Health(context.Context) error })
	if !ok {
		return ErrManagementHealth
	}
	if err := managementHealth.Health(ctx); err != nil {
		return fmt.Errorf("%w: %v", ErrManagementHealth, err)
	}
	epoch, err := s.store.PolicyEpoch(ctx)
	if err != nil {
		return err
	}
	if epoch != s.policyEpoch {
		return fmt.Errorf("%w: durable=%d gate=%d", approval.ErrEpochChanged, epoch, s.policyEpoch)
	}
	return nil
}

func (s *Service) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		if s.store != nil {
			s.closeErr = s.store.Close()
		}
	})
	return s.closeErr
}

func (s *Service) approvalAuthority() approval.AuthorityResolver {
	if s != nil && s.authority != nil {
		return s.authority
	}
	return approval.DefaultAuthorityResolver{}
}

func (s *Service) verifyPassword(ctx context.Context, session handler.ApprovalSession, password string) (handler.ApprovalCredentialProof, error) {
	user, err := s.authorizeSession(ctx, session)
	if err != nil {
		return handler.ApprovalCredentialProof{}, err
	}
	if password == "" || bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)) != nil {
		return handler.ApprovalCredentialProof{}, ErrCredentialRejected
	}
	return s.proof(true, false)
}

func (s *Service) verifyTOTP(ctx context.Context, session handler.ApprovalSession, code string) (handler.ApprovalCredentialProof, error) {
	user, err := s.authorizeSession(ctx, session)
	if err != nil {
		return handler.ApprovalCredentialProof{}, err
	}
	if !user.TwoFAEnabled || user.TwoFASecret == "" {
		return handler.ApprovalCredentialProof{}, ErrCredentialRejected
	}
	now := s.clock().UTC()
	counter, ok := matchingTOTPCounter(user.TwoFASecret, code, now)
	if !ok {
		return handler.ApprovalCredentialProof{}, ErrCredentialRejected
	}
	// Keep the verifier's local critical section small while the durable store
	// performs the actual atomic claim. The store is the source of truth across
	// independent Service instances and process restarts.
	s.totpMu.Lock()
	defer s.totpMu.Unlock()
	claimed, err := s.management.ConsumeTOTP(ctx, user.ID, counter, now.Add(120*time.Second), now)
	if err != nil {
		return handler.ApprovalCredentialProof{}, credentialUnavailable("consume TOTP replay state", err)
	}
	if !claimed {
		return handler.ApprovalCredentialProof{}, ErrCredentialRejected
	}
	return s.proof(false, true)
}

func (s *Service) authorizeSession(ctx context.Context, session handler.ApprovalSession) (*storage.User, error) {
	if s == nil || s.management == nil || ctx == nil || session.Subject == "" || session.SessionID == "" || session.Username == "" || strings.HasPrefix(session.Subject, "api-token:") || approval.ValidateIdentifier(session.Subject) != nil || approval.ValidateIdentifier(session.SessionID) != nil || approval.ValidateIdentifier(session.Username) != nil {
		return nil, ErrCredentialRejected
	}
	active, err := s.management.IsSessionActive(ctx, session.SessionID, session.Subject, s.clock().UTC())
	if err != nil {
		return nil, credentialUnavailable("session state", err)
	}
	if !active {
		return nil, ErrCredentialRejected
	}
	user, err := s.management.GetUserByUsername(ctx, session.Username)
	if err != nil {
		return nil, credentialUnavailable("user lookup", err)
	}
	if user == nil || user.ID != session.Subject || user.Username != session.Username || (session.Role != "" && session.Role != user.Role) {
		return nil, ErrCredentialRejected
	}
	if _, ok := approval.CanonicalActorRole(user.Role); !ok || !s.approvalAuthority().CanApprove(user.Role, "") {
		return nil, ErrCredentialRejected
	}
	return user, nil
}

func credentialUnavailable(operation string, err error) error {
	return errors.Join(ErrCredentialUnavailable, handler.ErrApprovalVerifierUnavailable, fmt.Errorf("%s: %w", operation, err))
}

func (s *Service) proof(password, totp bool) (handler.ApprovalCredentialProof, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return handler.ApprovalCredentialProof{}, fmt.Errorf("%w: proof entropy: %v", ErrCredentialUnavailable, err)
	}
	return handler.NewApprovalCredentialProof("proof-"+hex.EncodeToString(buf), password, totp), nil
}

const (
	totpPeriod = int64(30)
	totpDigits = 6
)

func matchingTOTPCounter(secret, code string, now time.Time) (int64, bool) {
	if len(code) != totpDigits {
		return 0, false
	}
	for _, char := range code {
		if char < '0' || char > '9' {
			return 0, false
		}
	}
	counter := now.Unix() / totpPeriod
	for offset := int64(-1); offset <= 1; offset++ {
		step := counter + offset
		expected, err := hotp(secret, step)
		if err == nil && expected == code {
			return step, true
		}
	}
	return 0, false
}

func hotp(secret string, counter int64) (string, error) {
	// Keep the algorithm identical to the management TOTP contract: base32
	// secret, SHA-1 HOTP, six digits, and a +/- one time-step verification window.
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return "", err
	}
	var msg [8]byte
	for i := len(msg) - 1; i >= 0; i-- {
		msg[i] = byte(counter)
		counter >>= 8
	}
	h := hmac.New(sha1.New, key)
	if _, err := h.Write(msg[:]); err != nil {
		return "", err
	}
	mac := h.Sum(nil)
	offset := mac[len(mac)-1] & 0x0f
	bin := (int(mac[offset])&0x7f)<<24 | (int(mac[offset+1])&0xff)<<16 | (int(mac[offset+2])&0xff)<<8 | int(mac[offset+3])&0xff
	mod := 1
	for i := 0; i < totpDigits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", totpDigits, bin%mod), nil
}
