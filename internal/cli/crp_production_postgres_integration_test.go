package cli

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/approval"
	approvalpostgres "github.com/LaokeQwQ/CheeseWAF/internal/approval/postgres"
	"github.com/LaokeQwQ/CheeseWAF/internal/crp"
	"github.com/LaokeQwQ/CheeseWAF/internal/crp/activation"
	activationpostgres "github.com/LaokeQwQ/CheeseWAF/internal/crp/activation/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// TestProductionCRPPostgresIntegration is opt-in because it exercises a real
// PostgreSQL server and the production process sidecar launcher over both mTLS
// listeners. Once PostgreSQL is configured, missing process-launcher inputs
// are hard failures rather than additional skips.
func TestProductionCRPPostgresIntegration(t *testing.T) {
	rawDSN := strings.TrimSpace(os.Getenv("CHEESEWAF_POSTGRES_TEST_DSN"))
	if rawDSN == "" {
		t.Skip("CHEESEWAF_POSTGRES_TEST_DSN is not configured")
	}
	registryDirectory := strings.TrimSpace(os.Getenv("CHEESEWAF_CRP_SIDECAR_TEST_REGISTRY_DIR"))
	if registryDirectory == "" {
		t.Fatal("CHEESEWAF_CRP_SIDECAR_TEST_REGISTRY_DIR is required when PostgreSQL integration is enabled")
	}
	ctx := context.Background()
	scopedDSN, db, schema := newProductionCRPPostgresSchema(t, ctx, rawDSN)

	approvalStore, err := approvalpostgres.New(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := approvalStore.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	assertProductionCRPPostgresSchema(t, ctx, db, schema, "cheesewaf_approvals")
	const policyEpoch uint64 = 7
	if err := approvalStore.CompareAndSetEpoch(ctx, 0, policyEpoch); err != nil {
		t.Fatal(err)
	}

	fenceSource := newProductionCRPPostgresFenceSource()
	authorizationStore, err := activationpostgres.OpenWithFenceSource(ctx, scopedDSN, fenceSource)
	if err != nil {
		t.Fatal(err)
	}
	storeClosed := false
	t.Cleanup(func() {
		if !storeClosed {
			_ = authorizationStore.Close()
		}
	})
	if err := authorizationStore.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	assertProductionCRPPostgresSchema(t, ctx, db, schema, "cheesewaf_crp_authorizations")
	provider, err := authorizationStore.Provider()
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	runtimeStore, err := crp.NewRuntimeStore(t.TempDir(), crp.RuntimeStoreOptions{
		Clock:       func() time.Time { return time.Now().UTC() },
		HealthCheck: crp.HealthCheckFunc(func(crp.RuntimeRecord) error { return nil }),
		Revalidate:  crp.RuntimeRevalidateFunc(func(crp.RuntimeRecord) error { return nil }),
	})
	if err != nil {
		t.Fatal(err)
	}
	pkgV1, importedV1 := newCRPActivationAdapterPackageRelease(t, now, "1.0.0", 1, []byte("adapter-test-artifact-v1"))
	stagedV1, err := runtimeStore.Stage(pkgV1, importedV1)
	if err != nil {
		t.Fatal(err)
	}
	currentV1, err := runtimeStore.Promote(stagedV1.Key, stagedV1.Revision, nil)
	if err != nil {
		t.Fatal(err)
	}
	pkgV2, importedV2 := newCRPActivationAdapterPackageRelease(t, now.Add(time.Microsecond), "1.1.0", 2, []byte("adapter-test-artifact-v2"))
	stagedV2, err := runtimeStore.Stage(pkgV2, importedV2)
	if err != nil {
		t.Fatal(err)
	}
	descriptorV1 := productionCRPDescriptorForRecord(currentV1)
	descriptorV2 := productionCRPDescriptorForRecord(stagedV2)
	processBackend := newProductionCRPPostgresProcessBackend(t, registryDirectory, currentV1, stagedV2)

	pki := newProductionCRPPKI(t)
	resolver := func(ctx context.Context, request activation.AuthorizationRequest) (activation.ApprovalClaim, error) {
		claim := productionCRPPostgresClaim(request, policyEpoch, "executor")
		if err := insertProductionCRPApprovedRecord(ctx, db, claim); err != nil {
			return activation.ApprovalClaim{}, err
		}
		return claim, nil
	}
	listenEndpoint := reserveProductionCRPAddress(t)
	sidecarListenEndpoint := reserveProductionCRPAddress(t)
	bundle, err := OpenProductionCRP(ctx, ProductionCRPOptions{
		ListenEndpoint: listenEndpoint, SidecarListenEndpoint: sidecarListenEndpoint,
		ControlEndpoint: "https://" + listenEndpoint,
		SidecarEndpoint: "https://" + sidecarListenEndpoint, CAFile: pki.caFile,
		ServerCertFile: pki.serverCertFile, ServerKeyFile: pki.serverKeyFile,
		ClientCertFile: pki.clientCertFile, ClientKeyFile: pki.clientKeyFile,
		ControlServerName: "control-plane", SidecarServerName: "control-plane",
		ClusterID: "cluster-a", NodeID: "node-a", TransportTimeout: 3 * time.Second,
		Runtime: runtimeStore, State: authorizationStore, Provider: provider,
		Audit: authorizationStore, FenceSource: fenceSource, SidecarBackend: processBackend,
		ApprovalClaimResolver: resolver,
		Policy: activation.Policy{
			AllowedCapabilities: map[string]struct{}{"observe": {}},
			VerifyRecord:        func(context.Context, crp.RuntimeRecord) error { return nil },
		},
		Clock: func() time.Time { return time.Now().UTC() }, AsyncQueueSize: 4,
		AsyncWorkers: 1, OperationTimeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	bundleClosed := false
	t.Cleanup(func() {
		if !bundleClosed {
			_ = bundle.Close()
		}
	})
	if err := bundle.Start(); err != nil {
		t.Fatal(err)
	}

	t.Run("mTLS authorize validate consume", func(t *testing.T) {
		request, claim := productionCRPPostgresAuthorizationRequest(t, bundle.ControlPlane().TransportIdentity(), policyEpoch, "mtls")
		if err := insertProductionCRPApprovedRecord(ctx, db, claim); err != nil {
			t.Fatal(err)
		}
		request.ApprovalClaim = claim
		authorization, err := bundle.ControlPlane().Authorize(ctx, request)
		if err != nil {
			t.Fatal(err)
		}
		if err := bundle.ControlPlane().Validate(ctx, authorization); err != nil {
			t.Fatal(err)
		}
		if authorization.Confirmation == nil {
			t.Fatal("authorization omitted its runtime confirmation")
		}
		if err := bundle.ControlPlane().Consume(ctx, authorization.Confirmation.RuntimeConfirmation()); err != nil {
			t.Fatalf("mTLS consume failed: %v", err)
		}
		if err := authorizationStore.Consume(ctx, authorization); !errors.Is(err, activation.ErrAuthorizationReplay) {
			t.Fatalf("durable replay check error=%v, want ErrAuthorizationReplay", err)
		}
		var consumeAuditRows int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM cheesewaf_crp_authorization_audit WHERE event_json->>'authorization_id'=$1 AND event_json->>'operation'='consume'`, authorization.ID).Scan(&consumeAuditRows); err != nil {
			t.Fatal(err)
		}
		if consumeAuditRows != 1 {
			t.Fatalf("consume audit rows=%d, want exactly one", consumeAuditRows)
		}
	})

	t.Run("consensus turnover invalidates old authorization", func(t *testing.T) {
		request, claim := productionCRPPostgresAuthorizationRequest(t, bundle.ControlPlane().TransportIdentity(), policyEpoch, "stale")
		if err := insertProductionCRPApprovedRecord(ctx, db, claim); err != nil {
			t.Fatal(err)
		}
		request.ApprovalClaim = claim
		authorization, err := bundle.ControlPlane().Authorize(ctx, request)
		if err != nil {
			t.Fatal(err)
		}
		fenceSource.turnover()
		if err := bundle.ControlPlane().Validate(ctx, authorization); err == nil {
			t.Fatal("old authorization validated after epoch/revision/digest/nonce turnover")
		}
		if authorization.Confirmation == nil {
			t.Fatal("authorization omitted its runtime confirmation")
		}
		if err := bundle.ControlPlane().Consume(ctx, authorization.Confirmation.RuntimeConfirmation()); err == nil {
			t.Fatal("old authorization was consumed after epoch/revision/digest/nonce turnover")
		}
	})

	var promoted activation.ActivationResult
	promotionPassed := t.Run("production executor reaches process launcher", func(t *testing.T) {
		executor, err := NewProductionCRPActivationExecutor(bundle.Service())
		if err != nil {
			t.Fatal(err)
		}
		result, err := executor.ExecuteCRPActivation(ctx, activation.AsyncRequest{
			Action: crp.RuntimeActionPromote, Key: stagedV2.Key, ExpectedRevision: stagedV2.Revision,
			Descriptor: descriptorV2,
			Policy:     activation.CanaryPolicy{ObserveProbes: 1, CanaryProbes: 1, ProbeTimeout: time.Second},
		})
		if err != nil {
			t.Fatalf("ProductionCRPActivationExecutor service chain failed: %v", err)
		}
		if result.Phase != activation.PhaseActive || result.Record.Key != stagedV2.Key || result.Record.Version != stagedV2.Version {
			t.Fatalf("activation result=%+v, want active %q version %q", result, stagedV2.Key, stagedV2.Version)
		}
		promoted = result
	})

	if promotionPassed {
		t.Run("production rollback reaches exact previous process", func(t *testing.T) {
			executor, err := NewProductionCRPActivationExecutor(bundle.Service())
			if err != nil {
				t.Fatal(err)
			}
			result, err := executor.ExecuteCRPActivation(ctx, activation.AsyncRequest{
				Action: crp.RuntimeActionRollback, Key: promoted.Record.Key, ExpectedRevision: promoted.Record.Revision,
				Descriptor: descriptorV1,
				Policy:     activation.CanaryPolicy{ObserveProbes: 1, CanaryProbes: 1, ProbeTimeout: time.Second},
			})
			if err != nil {
				t.Fatalf("ProductionCRPActivationExecutor rollback chain failed: %v", err)
			}
			if result.Phase != activation.PhaseRolled || result.Record.Version != currentV1.Version || result.Record.ManifestIdentity != currentV1.ManifestIdentity {
				t.Fatalf("rollback result=%+v, want exact previous version %q manifest %q", result, currentV1.Version, currentV1.ManifestIdentity)
			}
		})
	} else {
		t.Log("rollback subtest not run because its production activation prerequisite failed")
	}

	t.Run("restart preserves replay protection and audit", func(t *testing.T) {
		request, claim := productionCRPPostgresAuthorizationRequest(t, bundle.ControlPlane().TransportIdentity(), policyEpoch, "restart")
		if err := insertProductionCRPApprovedRecord(ctx, db, claim); err != nil {
			t.Fatal(err)
		}
		request.ApprovalClaim = claim
		authorization, err := provider.Authorize(ctx, request.Identity, request)
		if err != nil {
			t.Fatal(err)
		}
		if err := authorizationStore.Append(ctx, activation.AuthorizationAuditEvent{
			EventID: "restart-proof:" + authorization.ID, Operation: "validate", Outcome: "allowed",
			At: time.Now().UTC(), Identity: request.Identity, RequestID: request.RequestID,
			AuthorizationID: authorization.ID, Action: request.Action, Permission: request.Permission,
			PluginKey: request.Target.Key, ManifestIdentity: request.Target.ManifestIdentity,
			ExpectedRevision: request.ExpectedRevision,
		}); err != nil {
			t.Fatal(err)
		}
		if err := authorizationStore.Consume(ctx, authorization); err != nil {
			t.Fatal(err)
		}
		if err := bundle.Close(); err != nil {
			t.Fatal(err)
		}
		bundleClosed = true
		if err := authorizationStore.Close(); err != nil {
			t.Fatal(err)
		}
		storeClosed = true

		reopened, err := activationpostgres.OpenWithFenceSource(ctx, scopedDSN, fenceSource)
		if err != nil {
			t.Fatal(err)
		}
		defer reopened.Close()
		reopenedProvider, err := reopened.Provider()
		if err != nil {
			t.Fatal(err)
		}
		if err := reopenedProvider.Validate(ctx, request.Identity, authorization); !errors.Is(err, activation.ErrAuthorizationReplay) {
			t.Fatalf("reopened Validate error=%v, want ErrAuthorizationReplay", err)
		}
		if err := reopened.Consume(ctx, authorization); !errors.Is(err, activation.ErrAuthorizationReplay) {
			t.Fatalf("reopened Consume error=%v, want ErrAuthorizationReplay", err)
		}
		var auditRows int
		// The audit store intentionally exposes no query API. This connection
		// has a per-test search_path, so this reads only the random test schema.
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM cheesewaf_crp_authorization_audit WHERE event_json->>'authorization_id'=$1`, authorization.ID).Scan(&auditRows); err != nil {
			t.Fatal(err)
		}
		if auditRows == 0 {
			t.Fatal("authorization audit event did not survive store restart")
		}
	})
}

func productionCRPDescriptorForRecord(record crp.RuntimeRecord) activation.SidecarDescriptor {
	return activation.SidecarDescriptor{
		PluginID: record.PluginID, Runtime: "sidecar", Version: record.Version,
		ManifestIdentity: record.ManifestIdentity, ArtifactIdentity: record.ArtifactIdentity,
		Namespace: record.Namespace, Source: "ota", SourceRoot: "root",
		Capabilities: []string{"observe"},
	}
}

func newProductionCRPPostgresProcessBackend(t *testing.T, registryDirectory string, records ...crp.RuntimeRecord) *activation.ProcessSidecarBackend {
	t.Helper()
	if !filepath.IsAbs(registryDirectory) || filepath.Clean(registryDirectory) != registryDirectory {
		t.Fatalf("process sidecar registry directory must be clean and absolute: %q", registryDirectory)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		t.Fatal(err)
	}
	entries := make([]productionProcessSidecarRegistryFileEntry, 0, len(records))
	for _, record := range records {
		entries = append(entries, productionProcessSidecarRegistryFileEntry{
			Identity: productionProcessSidecarRegistryIdentity{
				PluginID: record.PluginID, Namespace: record.Namespace, Version: record.Version,
				ManifestIdentity: record.ManifestIdentity, ArtifactIdentity: record.ArtifactIdentity,
			},
			Executable:       executable,
			Args:             []string{"-test.run=^TestProductionProcessSidecarHelper$"},
			WorkingDirectory: filepath.Dir(executable),
			Environment:      map[string]string{productionProcessSidecarHelperEnvironment: "1"},
		})
	}
	file, err := os.CreateTemp(registryDirectory, "cheesewaf-crp-sidecar-registry-*.json")
	if err != nil {
		t.Fatal(err)
	}
	registryPath := file.Name()
	t.Cleanup(func() { _ = os.Remove(registryPath) })
	document := productionProcessSidecarRegistryFile{SchemaVersion: productionProcessSidecarRegistrySchema, Entries: entries}
	if err := json.NewEncoder(file).Encode(document); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	backend, err := openProductionProcessSidecarBackend(registryPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := backend.Close(closeCtx); err != nil {
			t.Errorf("close process sidecar backend: %v", err)
		}
	})
	return backend
}

type productionCRPPostgresFenceSource struct {
	mu       sync.Mutex
	epoch    uint64
	revision uint64
	digest   string
	nonce    string
}

func newProductionCRPPostgresFenceSource() *productionCRPPostgresFenceSource {
	return &productionCRPPostgresFenceSource{epoch: 7, revision: 11, digest: "digest-a", nonce: "nonce-a"}
}

func (s *productionCRPPostgresFenceSource) CurrentFence(context.Context, activation.AuthorizationRequest) (activation.Fence, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fenceLocked(), nil
}

func (s *productionCRPPostgresFenceSource) ValidateFence(_ context.Context, authorization activation.Authorization, current activation.Fence) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	live := s.fenceLocked()
	if current.ClusterID != live.ClusterID || current.Token != live.Token || current.Epoch != live.Epoch || current.Revision != live.Revision ||
		authorization.Fence.ClusterID != live.ClusterID || authorization.Fence.Token != live.Token || authorization.Fence.Epoch != live.Epoch || authorization.Fence.Revision != live.Revision {
		return activation.ErrStaleFence
	}
	return nil
}

func (s *productionCRPPostgresFenceSource) turnover() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.epoch++
	s.revision++
	s.digest = "digest-b"
	s.nonce = "nonce-b"
}

func (s *productionCRPPostgresFenceSource) fenceLocked() activation.Fence {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%d:%d:%s:%s", s.epoch, s.revision, s.digest, s.nonce)))
	return activation.Fence{
		ClusterID: "cluster-a", Token: hex.EncodeToString(sum[:]), Epoch: s.epoch,
		Revision: s.revision, ExpiresAt: time.Now().UTC().Add(2 * time.Minute),
	}
}

func newProductionCRPPostgresSchema(t *testing.T, ctx context.Context, rawDSN string) (string, *sql.DB, string) {
	t.Helper()
	config, err := pgx.ParseConfig(rawDSN)
	if err != nil {
		t.Fatal(err)
	}
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	schema := "crp_production_it_" + hex.EncodeToString(random)
	quoted := pgx.Identifier{schema}.Sanitize()
	admin := stdlib.OpenDB(*config)
	if err := admin.PingContext(ctx); err != nil {
		_ = admin.Close()
		t.Fatal(err)
	}
	if _, err := admin.ExecContext(ctx, "CREATE SCHEMA "+quoted); err != nil {
		_ = admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.ExecContext(context.Background(), "DROP SCHEMA "+quoted+" CASCADE")
		_ = admin.Close()
	})
	testConfig := config.Copy()
	testConfig.RuntimeParams = make(map[string]string, len(config.RuntimeParams)+1)
	for key, value := range config.RuntimeParams {
		testConfig.RuntimeParams[key] = value
	}
	testConfig.RuntimeParams["search_path"] = schema
	scopedDSN := stdlib.RegisterConnConfig(testConfig)
	db, err := sql.Open("pgx", scopedDSN)
	if err != nil {
		stdlib.UnregisterConnConfig(scopedDSN)
		t.Fatal(err)
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		stdlib.UnregisterConnConfig(scopedDSN)
		t.Fatal(err)
	}
	var activeSchema string
	if err := db.QueryRowContext(ctx, `SELECT current_schema()`).Scan(&activeSchema); err != nil {
		_ = db.Close()
		stdlib.UnregisterConnConfig(scopedDSN)
		t.Fatal(err)
	}
	if activeSchema != schema {
		_ = db.Close()
		stdlib.UnregisterConnConfig(scopedDSN)
		t.Fatalf("PostgreSQL current_schema()=%q, want %q", activeSchema, schema)
	}
	t.Cleanup(func() {
		_ = db.Close()
		stdlib.UnregisterConnConfig(scopedDSN)
	})
	return scopedDSN, db, schema
}

func assertProductionCRPPostgresSchema(t *testing.T, ctx context.Context, db *sql.DB, schema string, relation string) {
	t.Helper()
	var searchPath string
	if err := db.QueryRowContext(ctx, `SHOW search_path`).Scan(&searchPath); err != nil {
		t.Fatal(err)
	}
	var activeSchema string
	if err := db.QueryRowContext(ctx, `SELECT current_schema()`).Scan(&activeSchema); err != nil {
		t.Fatal(err)
	}
	if activeSchema != schema {
		t.Fatalf("PostgreSQL search_path=%q current_schema()=%q, want current schema %q", searchPath, activeSchema, schema)
	}
	var visible sql.NullString
	if err := db.QueryRowContext(ctx, `SELECT to_regclass($1)::text`, relation).Scan(&visible); err != nil {
		t.Fatal(err)
	}
	if !visible.Valid || visible.String != relation {
		t.Fatalf("PostgreSQL search_path=%q cannot resolve relation %q (to_regclass=%q)", searchPath, relation, visible.String)
	}
}

func productionCRPPostgresAuthorizationRequest(t *testing.T, identity activation.TransportIdentity, epoch uint64, suffix string) (activation.AuthorizationRequest, activation.ApprovalClaim) {
	t.Helper()
	request, _ := productionCRPAuthorizationRequest(t, identity, time.Now().UTC().Truncate(time.Microsecond))
	request.RequestID = "postgres-it-request-" + suffix
	claim := productionCRPPostgresClaim(request, epoch, suffix)
	return request, claim
}

func productionCRPPostgresClaim(request activation.AuthorizationRequest, epoch uint64, suffix string) activation.ApprovalClaim {
	issuedAt := request.RequestedAt
	claim := activation.ApprovalClaim{
		ApprovalID:     "postgres-it-approval-" + suffix + "-" + request.RequestID,
		ConfirmationID: "postgres-it-confirmation-" + suffix + "-" + request.RequestID,
		Actor:          "postgres-it-operator", PolicyEpoch: epoch, TTL: 2 * time.Minute,
		IssuedAt: issuedAt, ExpiresAt: issuedAt.Add(2 * time.Minute),
		Nonce:     "postgres-it-nonce-" + suffix + "-" + request.RequestID,
		SessionID: "postgres-it-session-" + suffix,
	}
	claim.Scope = activation.ApprovalScope(request)
	claim.IntentDigest = activation.ApprovalIntentDigest(request)
	return claim
}

func insertProductionCRPApprovedRecord(ctx context.Context, db *sql.DB, claim activation.ApprovalClaim) error {
	record := approval.Record{
		ID: claim.ApprovalID,
		Request: approval.Request{
			ID: claim.ApprovalID, Risk: approval.RiskMedium, Scope: claim.Scope,
			PolicyEpoch: claim.PolicyEpoch, TTL: claim.TTL, Actor: claim.Actor,
			SessionID: claim.SessionID, ConfirmationLanguage: "zh-CN",
			IntentDigest: claim.IntentDigest, WorkflowDigest: claim.WorkflowDigest, Nonce: claim.Nonce,
		},
		Status: approval.StatusApproved, SubmittedAt: claim.IssuedAt, ExpiresAt: claim.ExpiresAt,
		Commit: &approval.AuthorizationCommit{
			RequestID: claim.ApprovalID, ConfirmationID: claim.ConfirmationID, Actor: claim.Actor,
			Scope: claim.Scope, PolicyEpoch: claim.PolicyEpoch, Risk: approval.RiskMedium,
			TTL: claim.TTL, IssuedAt: claim.IssuedAt, ExpiresAt: claim.ExpiresAt,
			WorkflowDigest: claim.WorkflowDigest, SessionID: claim.SessionID,
			ConfirmationLanguage: "zh-CN", IntentDigest: claim.IntentDigest, Nonce: claim.Nonce,
		},
	}
	if err := approval.ValidateRecordForAdapter(record); err != nil {
		return err
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `INSERT INTO cheesewaf_approvals(request_id,record_json,workflow_digest) VALUES($1,$2,$3)`, record.ID, payload, record.Request.WorkflowDigest)
	return err
}
