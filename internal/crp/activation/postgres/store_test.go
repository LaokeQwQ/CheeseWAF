package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/approval"
	approvalpostgres "github.com/LaokeQwQ/CheeseWAF/internal/approval/postgres"
	"github.com/LaokeQwQ/CheeseWAF/internal/crp/activation"
	_ "github.com/jackc/pgx/v5/stdlib"
)

type testFenceSource struct {
	fence       activation.Fence
	unavailable bool
}

func (s *testFenceSource) CurrentFence(_ context.Context, _ activation.AuthorizationRequest) (activation.Fence, error) {
	if s == nil || s.unavailable {
		return activation.Fence{}, activation.ErrControlPlaneUnavailable
	}
	return s.fence, nil
}

func (s *testFenceSource) ValidateFence(_ context.Context, authorization activation.Authorization, current activation.Fence) error {
	if s == nil || s.unavailable {
		return activation.ErrControlPlaneUnavailable
	}
	if !authorization.Fence.ExpiresAt.After(time.Now().UTC()) {
		return activation.ErrFenceExpired
	}
	if authorization.Fence.ClusterID != current.ClusterID || authorization.Fence.Token != current.Token || authorization.Fence.Epoch != current.Epoch || authorization.Fence.Revision != current.Revision {
		return activation.ErrStaleFence
	}
	return nil
}

func TestStoreRequiresRealDatabase(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Fatal("New(nil) accepted a non-durable store")
	}
	var typedNil *Store
	if provider, err := NewProvider(typedNil); err == nil || provider != nil {
		t.Fatalf("NewProvider(typed nil) = provider=%v err=%v", provider, err)
	}
	db, err := sql.Open("pgx", "postgres://not-used-for-construction")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := NewWithFenceSource(db, nil); !errors.Is(err, ErrInvalidStore) {
		t.Fatalf("NewWithFenceSource(nil) error=%v, want ErrInvalidStore", err)
	}
	if _, err := OpenWithFenceSource(context.Background(), "", nil); !errors.Is(err, ErrInvalidStore) {
		t.Fatalf("OpenWithFenceSource(nil) error=%v, want ErrInvalidStore", err)
	}
}

func TestProviderCoalescesOnlyItsExactStore(t *testing.T) {
	db, err := sql.Open("pgx", "postgres://not-used-for-construction")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, err := New(db)
	if err != nil {
		t.Fatal(err)
	}
	otherStore, err := New(db)
	if err != nil {
		t.Fatal(err)
	}
	provider, err := NewProvider(store)
	if err != nil {
		t.Fatal(err)
	}
	if !provider.UsesAuthorizationState(store) {
		t.Fatal("provider did not identify its exact store")
	}
	if provider.UsesAuthorizationState(otherStore) {
		t.Fatal("provider coalesced a different Store instance")
	}
	identity := activation.TransportIdentity{ClusterID: "cluster-a", NodeID: "node-a", Role: "waf", CertificateSHA256: strings.Repeat("a", 64)}
	authorization := activation.Authorization{Request: activation.AuthorizationRequest{Identity: identity}}
	if err := provider.ConsumeAfterState(context.Background(), identity, authorization); err != nil {
		t.Fatalf("ConsumeAfterState valid identity error=%v", err)
	}
	otherIdentity := identity
	otherIdentity.NodeID = "node-b"
	if err := provider.ConsumeAfterState(context.Background(), otherIdentity, authorization); !errors.Is(err, activation.ErrAuthorizationBinding) {
		t.Fatalf("ConsumeAfterState identity error=%v, want ErrAuthorizationBinding", err)
	}
}

func TestAuditEventPayloadDigestIsStableAndDetectsBindingChanges(t *testing.T) {
	event := activation.AuthorizationAuditEvent{EventID: "event-1", Operation: "validate", Outcome: "allowed", At: time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC), RequestID: "request-1", PluginKey: "plugin-1", ExpectedRevision: 4}
	first, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	second, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	if HashForTest(first) != HashForTest(second) {
		t.Fatal("same EventID payload was not stable")
	}
	event.ExpectedRevision++
	third, _ := json.Marshal(event)
	if HashForTest(first) == HashForTest(third) {
		t.Fatal("binding mutation retained the same audit digest")
	}
}

func TestValidateRequestBindsClaimToOperation(t *testing.T) {
	identity := activation.TransportIdentity{ClusterID: "cluster-a", NodeID: "node-a", Role: "waf", CertificateSHA256: strings.Repeat("a", 64)}
	request := activation.AuthorizationRequest{SchemaVersion: activation.TransportSchemaVersion, RequestID: "request-1", Identity: identity, Action: "promote", Permission: activation.PermissionActivate, Target: activation.RuntimeTarget{Key: "plugin-1", PluginID: "plugin-1", Namespace: "official", Version: "1.0.0", ReleaseSequence: 1, ManifestIdentity: strings.Repeat("b", 64), ArtifactIdentity: strings.Repeat("c", 64), Revision: 4}, ExpectedRevision: 4, RequestedAt: time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)}
	request.ApprovalClaim = activation.ApprovalClaim{ApprovalID: "approval-1", ConfirmationID: "confirmation-1", Actor: "operator", Scope: activation.ApprovalScope(request), PolicyEpoch: 7, TTL: time.Minute, IssuedAt: request.RequestedAt, ExpiresAt: request.RequestedAt.Add(time.Minute), Nonce: "nonce-1", SessionID: "session-1"}
	request.ApprovalClaim.IntentDigest = activation.ApprovalIntentDigest(request)
	if err := validateRequest(identity, request); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
	request.ApprovalClaim.Scope = "crp:rollback:plugin-1"
	if err := validateRequest(identity, request); err == nil {
		t.Fatal("scope mutation was accepted")
	}
}

// HashForTest intentionally exercises the same SHA-256 primitive used by the
// durable audit adapter without depending on a live database.
func HashForTest(b []byte) string { return approval.HashBytes(b) }

func TestPostgresCRPIntegration(t *testing.T) {
	dsn := os.Getenv("CHEESEWAF_POSTGRES_DSN")
	if strings.TrimSpace(dsn) == "" {
		t.Skip("CHEESEWAF_POSTGRES_DSN is not configured")
	}
	ctx := context.Background()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.PingContext(ctx); err != nil {
		t.Skipf("PostgreSQL unavailable: %v", err)
	}
	fenceSource := &testFenceSource{fence: activation.Fence{ClusterID: "cluster-a", Token: "crp-raft-fence-1", Epoch: 7, Revision: 11, ExpiresAt: time.Now().UTC().Add(2 * time.Minute)}}
	store, err := NewWithFenceSource(db, fenceSource)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	approvalStore, err := approvalpostgres.New(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := approvalStore.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	// A fresh namespace lets this test run repeatedly without mutating an
	// unrelated approval row. The adapter still reads the canonical approval
	// and epoch tables used by the control-plane runtime.
	suffix := strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "-")
	now := time.Now().UTC().Truncate(time.Microsecond)
	identity := activation.TransportIdentity{ClusterID: "cluster-a", NodeID: "node-a", Role: "waf", CertificateSHA256: strings.Repeat("a", 64)}
	request := activation.AuthorizationRequest{SchemaVersion: activation.TransportSchemaVersion, RequestID: "crp-request-" + suffix, Identity: identity, Action: "promote", Permission: activation.PermissionActivate, Target: activation.RuntimeTarget{Key: "plugin-1", PluginID: "plugin-1", Namespace: "official", Version: "1.0.0", ReleaseSequence: 1, ManifestIdentity: strings.Repeat("b", 64), ArtifactIdentity: strings.Repeat("c", 64), Revision: 4}, ExpectedRevision: 4, RequestedAt: now}
	request.ApprovalClaim = activation.ApprovalClaim{ApprovalID: "crp-approval-" + suffix, ConfirmationID: "crp-confirmation-" + suffix, Actor: "operator", Scope: activation.ApprovalScope(request), PolicyEpoch: 7, TTL: time.Minute, IssuedAt: now, ExpiresAt: now.Add(time.Minute), Nonce: "crp-nonce-" + suffix, SessionID: "crp-session-" + suffix}
	request.ApprovalClaim.IntentDigest = activation.ApprovalIntentDigest(request)
	record := approval.Record{ID: request.ApprovalClaim.ApprovalID, Request: approval.Request{ID: request.ApprovalClaim.ApprovalID, Scope: request.ApprovalClaim.Scope, PolicyEpoch: request.ApprovalClaim.PolicyEpoch, TTL: request.ApprovalClaim.TTL, Actor: request.ApprovalClaim.Actor, SessionID: request.ApprovalClaim.SessionID, IntentDigest: request.ApprovalClaim.IntentDigest, Nonce: request.ApprovalClaim.Nonce}, Status: approval.StatusApproved, SubmittedAt: now, ExpiresAt: request.ApprovalClaim.ExpiresAt, Commit: &approval.AuthorizationCommit{RequestID: request.ApprovalClaim.ApprovalID, ConfirmationID: request.ApprovalClaim.ConfirmationID, Actor: request.ApprovalClaim.Actor, Scope: request.ApprovalClaim.Scope, PolicyEpoch: request.ApprovalClaim.PolicyEpoch, TTL: request.ApprovalClaim.TTL, IssuedAt: now, ExpiresAt: request.ApprovalClaim.ExpiresAt, SessionID: request.ApprovalClaim.SessionID, IntentDigest: request.ApprovalClaim.IntentDigest, Nonce: request.ApprovalClaim.Nonce}}
	recordJSON, _ := json.Marshal(record)
	if _, err := db.ExecContext(ctx, `INSERT INTO cheesewaf_approval_epoch(id,policy_epoch) VALUES(1,$1) ON CONFLICT(id) DO UPDATE SET policy_epoch=EXCLUDED.policy_epoch`, int64(request.ApprovalClaim.PolicyEpoch)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO cheesewaf_approvals(request_id,record_json,workflow_digest) VALUES($1,$2,$3)`, record.ID, recordJSON, ""); err != nil {
		t.Fatal(err)
	}
	provider, err := NewProvider(store)
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := provider.Authorize(ctx, identity, request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(ctx, authorization.ID); err != nil {
		t.Fatal(err)
	}
	if err := provider.Validate(ctx, identity, authorization); err != nil {
		t.Fatal(err)
	}

	// A native-raft turnover invalidates a previously minted grant immediately.
	// Validate and Consume must both fail before the old authorization can be
	// used, even though its durable approval row and TTL remain valid.
	fenceSource.fence = activation.Fence{ClusterID: "cluster-a", Token: "crp-raft-fence-2", Epoch: 8, Revision: 12, ExpiresAt: time.Now().UTC().Add(2 * time.Minute)}
	if err := provider.Validate(ctx, identity, authorization); !errors.Is(err, activation.ErrStaleFence) {
		t.Fatalf("Validate stale live fence error=%v, want ErrStaleFence", err)
	}
	if err := store.Consume(ctx, authorization); !errors.Is(err, activation.ErrStaleFence) {
		t.Fatalf("Consume stale live fence error=%v, want ErrStaleFence", err)
	}
	fenceSource.unavailable = true
	if err := provider.Validate(ctx, identity, authorization); !errors.Is(err, activation.ErrControlPlaneUnavailable) {
		t.Fatalf("Validate unavailable live fence error=%v, want ErrControlPlaneUnavailable", err)
	}
	fenceSource.unavailable = false
	fresh, err := provider.Authorize(ctx, identity, request)
	if err != nil {
		t.Fatal(err)
	}
	if err := provider.Validate(ctx, identity, fresh); err != nil {
		t.Fatal(err)
	}
	if err := store.Consume(ctx, fresh); err != nil {
		t.Fatal(err)
	}
	if err := provider.Validate(ctx, identity, fresh); err == nil {
		t.Fatal("consumed authorization remained valid")
	}
	event := activation.AuthorizationAuditEvent{EventID: "crp-event-" + suffix, Operation: "validate", Outcome: "allowed", At: now, Identity: identity, RequestID: request.RequestID, AuthorizationID: authorization.ID, Action: request.Action, Permission: request.Permission, PluginKey: request.Target.Key, ManifestIdentity: request.Target.ManifestIdentity, ExpectedRevision: request.ExpectedRevision}
	if err := store.Append(ctx, event); err != nil {
		t.Fatal(err)
	}
	if err := store.Append(ctx, event); err != nil {
		t.Fatal(err)
	}
}
