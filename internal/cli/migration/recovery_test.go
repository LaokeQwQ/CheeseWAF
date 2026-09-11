package migration

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane"
	setupmigration "github.com/LaokeQwQ/CheeseWAF/internal/setup/migration"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

func TestRecoveryRecordRoundTripIsPrivateAndBlocksStartup(t *testing.T) {
	dataDir := t.TempDir()
	migrationDir := filepath.Join(dataDir, "migration")
	if err := os.MkdirAll(migrationDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(migrationDir, 0o755); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)
	record, _ := newRecoveryRecordFixture(t, dataDir, now, "snapshot-1", "admin-1", "migration-1", "cluster-1")
	record.Snapshot.ManagementState = []byte("management")
	record.Snapshot.TokenMetadata = []byte("[]")
	if err := writeRecoveryRecord(dataDir, record); err != nil {
		t.Fatalf("write recovery record: %v", err)
	}
	path, err := recoveryRecordPath(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		t.Fatalf("recovery record mode=%v", info.Mode())
	}
	dirInfo, err := os.Lstat(migrationDir)
	if err != nil {
		t.Fatal(err)
	}
	if dirInfo.Mode().Perm() != 0o700 || dirInfo.Mode()&os.ModeSymlink != 0 || !dirInfo.IsDir() {
		t.Fatalf("migration recovery directory mode=%v", dirInfo.Mode())
	}
	if err := CheckPendingCutover(dataDir); !errors.Is(err, ErrCutoverPending) {
		t.Fatalf("recovery record did not block startup: %v", err)
	}
	got, err := readRecoveryRecord(dataDir)
	if err != nil {
		t.Fatalf("read recovery record: %v", err)
	}
	if got.Snapshot.ID != record.Snapshot.ID || got.CandidateDigest != record.CandidateDigest || string(got.Candidate) != string(record.Candidate) {
		t.Fatalf("recovery record mismatch: %+v", got)
	}
	if err := removeRecoveryRecord(dataDir, record.Snapshot.ID); err != nil {
		t.Fatalf("remove recovery record: %v", err)
	}
	if err := CheckPendingCutover(dataDir); err != nil {
		t.Fatalf("clean data dir remained blocked: %v", err)
	}
}

func TestV1CutoverLedgerIsExplicitlyUnverifiedAndCannotChooseRecoveryDirection(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "v1-ledger.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	createRecoveryMigrationTables(t, db)
	record, _ := newRecoveryRecordFixture(t, t.TempDir(), time.Now().UTC(), "snapshot-v1", "admin-v1", "migration-v1", "cluster-v1")
	record.Snapshot.ManagementState = emptyRecoveryManagementSnapshot(t)
	entry := ledgerEntryForRecoveryRecord(record, time.Now().UTC())
	if _, err := db.Exec(`INSERT INTO cheesewaf_migration_cutovers(snapshot_id,config_digest,candidate_digest,initial_state_hash,token_metadata_digest,actor_id,confirmation_id,cluster_id,committed_at) VALUES(?,?,?,?,?,?,?,?,?)`, entry.SnapshotID, entry.ConfigDigest, entry.CandidateDigest, entry.InitialStateHash, legacyTokenMetadataDigestSentinel, entry.Actor, entry.ConfirmationID, entry.ClusterID, entry.CommittedAt); err != nil {
		t.Fatal(err)
	}
	got, err := readCutoverLedger(context.Background(), db, record.Snapshot.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.TokenMetadataState != tokenMetadataUnverifiedV1 {
		t.Fatalf("token metadata state=%q, want %q", got.TokenMetadataState, tokenMetadataUnverifiedV1)
	}
	if _, err := classifyCutoverState(context.Background(), db, record); !errors.Is(err, ErrCutoverAmbiguous) || !errors.Is(err, ErrCutoverTokenMetadataUnverified) {
		t.Fatalf("v1 ledger selected an unclassified recovery direction: %v", err)
	}
}

func TestRecoveryPayloadsKeepDSNsOnlyInPrivateConfig(t *testing.T) {
	cfg := validRecoveryProductionConfig(t, t.TempDir())
	secrets := []string{
		"ai-recovery-secret",
		"bot-recovery-secret",
		"jwt-recovery-secret",
		"-----BEGIN PRIVATE KEY-----recovery-private-key",
		"clickhouse-recovery-password",
		"elasticsearch-recovery-api-key",
	}
	cfg.AI.APIKey = secrets[0]
	cfg.Protection.Bot.Secret = secrets[1]
	cfg.APISec.Auth.JWTSharedSecret = secrets[2]
	cfg.APISec.Auth.JWTPublicKeyPEM = secrets[3]
	cfg.Storage.ClickHouse.Password = secrets[4]
	cfg.Storage.Elasticsearch.APIKey = secrets[5]
	privateConfig, initialState, err := encodeRecoveryPayloads(cfg)
	if err != nil {
		t.Fatalf("encode recovery payloads: %v", err)
	}
	for _, dsn := range []string{cfg.Storage.ManagementPostgreSQL.DSN, cfg.Storage.ControlPostgreSQL.DSN} {
		if !bytes.Contains(privateConfig, []byte(dsn)) {
			t.Fatalf("private recovery config lost DSN %q", dsn)
		}
		if bytes.Contains(initialState, []byte(dsn)) {
			t.Fatalf("control-plane initial state exposed DSN %q", dsn)
		}
	}
	for _, secret := range secrets {
		if !bytes.Contains(privateConfig, []byte(secret)) {
			t.Fatalf("private recovery config lost secret marker %q", secret)
		}
		if bytes.Contains(initialState, []byte(secret)) {
			t.Fatalf("control-plane initial state exposed secret marker %q", secret)
		}
	}
	var decoded config.Config
	if err := yaml.Unmarshal(privateConfig, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Storage.ManagementPostgreSQL.DSN != cfg.Storage.ManagementPostgreSQL.DSN || decoded.Storage.ControlPostgreSQL.DSN != cfg.Storage.ControlPostgreSQL.DSN {
		t.Fatalf("decoded recovery config lost DSNs: %+v", decoded.Storage)
	}
}

func TestRecoveryPayloadValidationDoesNotResolveAIEndpoint(t *testing.T) {
	cfg := validRecoveryProductionConfig(t, t.TempDir())
	cfg.AI.Enabled = true
	cfg.AI.Provider = "openai"
	cfg.AI.APIBase = "https://recovery-must-not-resolve.invalid/v1"
	cfg.AI.APIKey = "recovery-ai-key"
	cfg.AI.Model = "recovery-model"
	privateConfig, _, err := encodeRecoveryPayloads(cfg)
	if err != nil {
		t.Fatalf("owner-only recovery payload validation performed external endpoint validation: %v", err)
	}
	decoded, err := decodeRecoveryCandidate(privateConfig)
	if err != nil || decoded.AI.APIBase != cfg.AI.APIBase {
		t.Fatalf("decode recovery candidate without endpoint lookup: endpoint=%q err=%v", decoded.AI.APIBase, err)
	}
}

func TestRecoveryPayloadsAllowGeneratedNodeIdentity(t *testing.T) {
	cfg := validRecoveryProductionConfig(t, t.TempDir())
	cfg.Cluster.NodeID = ""
	privateConfig, initialState, err := encodeRecoveryPayloads(cfg)
	if err != nil {
		t.Fatalf("generated native-raft node identity was rejected: %v", err)
	}
	decoded, err := decodeRecoveryCandidate(privateConfig)
	if err != nil || decoded.Cluster.NodeID != "" {
		t.Fatalf("decoded generated node identity=%q err=%v", decoded.Cluster.NodeID, err)
	}
	if _, err := decodeMigrationInitialState(initialState, decoded, digestBytes(privateConfig)); err != nil {
		t.Fatalf("initial-state descriptor rejected generated node identity: %v", err)
	}
}

func TestRecoveryRecordRejectsInsecureOrTrailingData(t *testing.T) {
	dataDir := t.TempDir()
	path, err := recoveryRecordPath(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{} {}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readRecoveryRecord(dataDir); !errors.Is(err, ErrCutoverPending) {
		t.Fatalf("trailing record error=%v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readRecoveryRecord(dataDir); !errors.Is(err, ErrCutoverPending) {
		t.Fatalf("insecure record error=%v", err)
	}
}

func TestPrepareCutoverArtifactsPublishesRecordAndFenceTogether(t *testing.T) {
	dataDir := t.TempDir()
	now := time.Date(2026, 9, 10, 1, 0, 0, 0, time.UTC)
	record, _ := newRecoveryRecordFixture(t, dataDir, now, "snapshot-2", "admin-2", "migration-2", "cluster-2")
	record.Snapshot.ConfigDigest = strings.Repeat("d", 64)
	record.Snapshot.ManagementState = []byte("management")
	if err := prepareCutoverArtifacts(dataDir, record, now); err != nil {
		t.Fatalf("prepare cutover artifacts: %v", err)
	}
	fence, err := readCutoverFence(dataDir)
	if err != nil {
		t.Fatalf("read fence: %v", err)
	}
	if fence.SnapshotID != record.Snapshot.ID || fence.ConfigDigest != record.Snapshot.ConfigDigest || fence.Phase != cutoverFencePending {
		t.Fatalf("unexpected fence: %+v", fence)
	}
	if _, err := readRecoveryRecord(dataDir); err != nil {
		t.Fatalf("read recovery record: %v", err)
	}
	if err := prepareCutoverArtifacts(dataDir, record, now); !errors.Is(err, ErrCutoverPending) {
		t.Fatalf("second prepare error=%v, want pending", err)
	}
	if err := removeCutoverArtifacts(dataDir, record.Snapshot.ID, false); err != nil {
		t.Fatalf("remove cutover artifacts: %v", err)
	}
	if err := CheckPendingCutover(dataDir); err != nil {
		t.Fatalf("removed artifacts still block startup: %v", err)
	}
}

func TestPrepareCutoverArtifactsKeepsRecoveryRecordWhenFencePublicationFails(t *testing.T) {
	dataDir := t.TempDir()
	now := time.Date(2026, 9, 10, 1, 30, 0, 0, time.UTC)
	record, _ := newRecoveryRecordFixture(t, dataDir, now, "snapshot-fence-failure", "admin-fence-failure", "migration-fence-failure", "cluster-fence-failure")
	fencePath, err := cutoverFencePath(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(fencePath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := prepareCutoverArtifacts(dataDir, record, now); err == nil {
		t.Fatal("fence publication failure was not reported")
	}
	got, err := readRecoveryRecord(dataDir)
	if err != nil || got.Snapshot.ID != record.Snapshot.ID {
		t.Fatalf("recoverable journal was removed after fence failure: record=%+v err=%v", got, err)
	}
	if err := CheckPendingCutover(dataDir); !errors.Is(err, ErrCutoverPending) {
		t.Fatalf("fence failure did not block startup: %v", err)
	}
}

func TestRuntimeTemporarySourcePersistsRecoveryMaterialBeforeInvalidation(t *testing.T) {
	ctx := context.Background()
	dataDir := t.TempDir()
	configPath := filepath.Join(dataDir, "cheesewaf.yaml")
	configRaw := []byte("storage:\n  profile: temporary\n")
	if err := os.WriteFile(configPath, configRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := openMigratedSQLite(ctx, filepath.Join(dataDir, "cheesewaf.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Date(2026, 9, 10, 2, 0, 0, 0, time.UTC)
	fixtureRecord, _ := newRecoveryRecordFixture(t, dataDir, now, "snapshot-unused", "admin-3", "migration-3", "cluster-3")
	source := &runtimeTemporarySource{
		db: db, profile: setupmigration.TemporaryProfile, configPath: configPath,
		dataDir: dataDir, expectedDigest: digestBytes(configRaw), now: func() time.Time { return now },
		candidate: fixtureRecord.Candidate, candidateDigest: fixtureRecord.CandidateDigest, initialState: fixtureRecord.InitialState,
		actor: "admin-3", confirmationID: "migration-3", clusterID: "cluster-3", initialStateHash: fixtureRecord.InitialStateHash,
	}
	snapshot, err := source.Snapshot(ctx)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	receipt, err := source.InvalidateTemporaryState(ctx)
	if err != nil || !receipt.Complete() {
		t.Fatalf("invalidate receipt=%+v err=%v", receipt, err)
	}
	record, err := readRecoveryRecord(dataDir)
	if err != nil {
		t.Fatalf("read recovery record: %v", err)
	}
	if record.Snapshot.ID != snapshot.ID || string(record.Snapshot.ManagementState) != string(snapshot.ManagementState) || string(record.Candidate) != string(fixtureRecord.Candidate) || string(record.InitialState) != string(fixtureRecord.InitialState) {
		t.Fatalf("persisted recovery record does not match snapshot: %+v", record)
	}
	if err := source.RestoreTemporaryState(ctx, snapshot, receipt); err != nil {
		t.Fatalf("restore temporary state: %v", err)
	}
	if err := CheckPendingCutover(dataDir); err != nil {
		t.Fatalf("restored state remained fenced: %v", err)
	}
}

func TestTemporaryInvalidationBindsSessionEpochToServeFenceAndRollback(t *testing.T) {
	ctx := context.Background()
	dataDir := t.TempDir()
	configPath := filepath.Join(dataDir, "cheesewaf.yaml")
	configRaw := []byte("storage:\n  profile: temporary\n")
	if err := os.WriteFile(configPath, configRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(dataDir, "cheesewaf.db")
	store, err := storage.OpenSQLite(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(ctx); err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 11, 2, 0, 0, 0, time.UTC)
	user := &storage.User{ID: "migration-admin", Username: "admin", PasswordHash: "hash", Role: "admin"}
	if err := store.CreateUser(ctx, user); err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	session := &storage.Session{ID: "migration-session", UserID: user.ID, Username: user.Username, Role: user.Role, CredentialEpoch: user.CredentialEpoch, IssuedAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := store.CreateSession(ctx, session); err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	active, err := store.IsSessionActive(ctx, session.ID, user.ID, now.Add(time.Minute))
	if err != nil || !active {
		_ = store.Close()
		t.Fatalf("pre-migration session active=%v err=%v", active, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	db, err := openMigratedSQLite(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	fixtureRecord, _ := newRecoveryRecordFixture(t, dataDir, now, "snapshot-session-lifecycle", "migration-admin", "migration-session-confirm", "cluster-session-lifecycle")
	source := &runtimeTemporarySource{
		db: db, profile: setupmigration.TemporaryProfile, configPath: configPath,
		dataDir: dataDir, expectedDigest: digestBytes(configRaw), now: func() time.Time { return now },
		candidate: fixtureRecord.Candidate, candidateDigest: fixtureRecord.CandidateDigest, initialState: fixtureRecord.InitialState,
		actor: fixtureRecord.Actor, confirmationID: fixtureRecord.ConfirmationID, clusterID: fixtureRecord.ClusterID, initialStateHash: fixtureRecord.InitialStateHash,
	}
	snapshot, err := source.Snapshot(ctx)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	receipt, err := source.InvalidateTemporaryState(ctx)
	if err != nil || !receipt.Complete() {
		t.Fatalf("invalidate receipt=%+v err=%v", receipt, err)
	}
	if err := CheckPendingCutover(dataDir); !errors.Is(err, ErrCutoverPending) {
		t.Fatalf("serve fence after invalidation=%v, want pending cutover", err)
	}
	store, err = storage.OpenSQLite(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	active, err = store.IsSessionActive(ctx, session.ID, user.ID, now.Add(time.Minute))
	if err != nil || active {
		_ = store.Close()
		t.Fatalf("invalidated session active=%v err=%v", active, err)
	}
	invalidatedUser, err := store.GetUserByID(ctx, user.ID)
	if err != nil || invalidatedUser == nil || invalidatedUser.CredentialEpoch != user.CredentialEpoch+1 {
		_ = store.Close()
		t.Fatalf("invalidated credential epoch=%d err=%v, want %d", userEpoch(invalidatedUser), err, user.CredentialEpoch+1)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	if err := source.RestoreTemporaryState(ctx, snapshot, receipt); err != nil {
		t.Fatalf("restore temporary state: %v", err)
	}
	if err := CheckPendingCutover(dataDir); err != nil {
		t.Fatalf("serve fence after rollback=%v, want clear", err)
	}
	store, err = storage.OpenSQLite(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	active, err = store.IsSessionActive(ctx, session.ID, user.ID, now.Add(time.Minute))
	if err != nil || !active {
		t.Fatalf("restored session active=%v err=%v", active, err)
	}
	restoredUser, err := store.GetUserByID(ctx, user.ID)
	if err != nil || restoredUser == nil || restoredUser.CredentialEpoch != user.CredentialEpoch {
		t.Fatalf("restored credential epoch=%d err=%v, want %d", userEpoch(restoredUser), err, user.CredentialEpoch)
	}
}

func userEpoch(user *storage.User) uint64 {
	if user == nil {
		return 0
	}
	return user.CredentialEpoch
}

func TestCutoverLedgerIsAtomicWithManagementTransaction(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "ledger.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	createRecoveryMigrationTables(t, db)
	entry := cutoverLedgerEntry{
		SnapshotID: "snapshot-ledger", ConfigDigest: strings.Repeat("a", 64),
		CandidateDigest: strings.Repeat("b", 64), InitialStateHash: strings.Repeat("c", 64),
		TokenDigest: strings.Repeat("d", 64),
		Actor:       "admin-ledger", ConfirmationID: "migration-ledger", ClusterID: "cluster-ledger",
		CommittedAt: time.Date(2026, 9, 10, 3, 0, 0, 0, time.UTC),
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := insertCutoverLedger(ctx, tx, entry); err != nil {
		t.Fatalf("insert cutover ledger: %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, err := readCutoverLedger(ctx, db, entry.SnapshotID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("rolled-back ledger remained visible: %v", err)
	}
	tx, err = db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := insertCutoverLedger(ctx, tx, entry); err != nil {
		t.Fatalf("reinsert cutover ledger: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	got, err := readCutoverLedger(ctx, db, entry.SnapshotID)
	if err != nil {
		t.Fatalf("read committed ledger: %v", err)
	}
	want := entry
	want.TokenMetadataState = tokenMetadataVerified
	if got != want {
		t.Fatalf("ledger=%+v want=%+v", got, want)
	}
}

func TestRuntimeProductionTransactionMigratesLegacyTokenMetadataAndVerifiesRotation(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 10, 3, 30, 0, 0, time.UTC)
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "legacy-token.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	createRecoveryMigrationTables(t, db)
	original := config.ManagementAPITokenConfig{
		ID: "legacy-token-1", Name: "Legacy automation", Prefix: "cwapi_abcd",
		Hash: "sha256:" + strings.Repeat("a", 64), Scopes: []string{"read:rules"}, Notes: "migrated as revoked metadata", Enabled: true,
		CreatedAt: now.Add(-2 * time.Hour), UpdatedAt: now.Add(-time.Hour), LastUsedAt: now.Add(-30 * time.Minute), ExpiresAt: now.Add(time.Hour),
	}
	tokenRaw, err := json.Marshal([]config.ManagementAPITokenConfig{original})
	if err != nil {
		t.Fatal(err)
	}
	rotated := original
	rotated.Enabled = false
	rotated.Hash = ""
	rotated.NeverExpire = false
	rotated.UpdatedAt = now
	rotated.RevokedAt = now
	rotated.ExpiresAt = now
	candidate := config.Default()
	candidate.APISec.ManagementAPI.Tokens = []config.ManagementAPITokenConfig{rotated}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	target := &runtimeProductionTarget{candidate: &candidate, actor: "admin-token-migration", snapshotID: "snapshot-token-migration", now: func() time.Time { return now }}
	productionTx := &runtimeProductionTransaction{target: target, tx: tx}
	snapshot := setupmigration.Snapshot{ID: target.snapshotID, TokenMetadata: tokenRaw}
	if err := productionTx.MigrateTokenMetadata(ctx, snapshot); err != nil {
		t.Fatalf("migrate legacy token metadata: %v", err)
	}
	if err := productionTx.RotateTokenMetadata(ctx, snapshot); err != nil {
		t.Fatalf("verify legacy token rotation: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	var tokenID, status, actor string
	var scopes []byte
	if err := db.QueryRowContext(ctx, `SELECT token_id,status,actor_id,scopes FROM cheesewaf_migration_legacy_tokens WHERE snapshot_id=?`, snapshot.ID).Scan(&tokenID, &status, &actor, &scopes); err != nil {
		t.Fatal(err)
	}
	if tokenID != original.ID || status != migratedLegacyTokenStatus || actor != target.actor || string(scopes) != `["read:rules"]` {
		t.Fatalf("migrated token metadata id=%q status=%q actor=%q scopes=%s", tokenID, status, actor, scopes)
	}
}

func TestRuntimeProductionTransactionRejectsMalformedOrUnrevokedLegacyTokenMetadata(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 10, 3, 45, 0, 0, time.UTC)
	newTransaction := func(t *testing.T, candidate *config.Config) (*runtimeProductionTransaction, *sql.Tx) {
		t.Helper()
		db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "legacy-token-reject.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		createRecoveryMigrationTables(t, db)
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		return &runtimeProductionTransaction{target: &runtimeProductionTarget{candidate: candidate, actor: "admin-token-reject", snapshotID: "snapshot-token-reject", now: func() time.Time { return now }}, tx: tx}, tx
	}

	t.Run("malformed hash", func(t *testing.T) {
		candidate := config.Default()
		productionTx, tx := newTransaction(t, &candidate)
		defer tx.Rollback()
		raw, _ := json.Marshal([]config.ManagementAPITokenConfig{{ID: "legacy-token", Name: "Legacy", Prefix: "cwapi_abcd", Hash: "plaintext", Scopes: []string{"read:rules"}}})
		if err := productionTx.MigrateTokenMetadata(ctx, setupmigration.Snapshot{ID: productionTx.target.snapshotID, TokenMetadata: raw}); !errors.Is(err, setupmigration.ErrTokenMetadataMigration) {
			t.Fatalf("malformed token metadata error=%v", err)
		}
	})

	t.Run("candidate not revoked", func(t *testing.T) {
		original := config.ManagementAPITokenConfig{ID: "legacy-token", Name: "Legacy", Prefix: "cwapi_abcd", Hash: "sha256:" + strings.Repeat("b", 64), Scopes: []string{"read:rules"}, Enabled: true, CreatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour)}
		candidate := config.Default()
		candidate.APISec.ManagementAPI.Tokens = []config.ManagementAPITokenConfig{original}
		productionTx, tx := newTransaction(t, &candidate)
		defer tx.Rollback()
		raw, _ := json.Marshal([]config.ManagementAPITokenConfig{original})
		snapshot := setupmigration.Snapshot{ID: productionTx.target.snapshotID, TokenMetadata: raw}
		if err := productionTx.MigrateTokenMetadata(ctx, snapshot); err != nil {
			t.Fatal(err)
		}
		if err := productionTx.RotateTokenMetadata(ctx, snapshot); !errors.Is(err, setupmigration.ErrTokenMetadataRotation) {
			t.Fatalf("unrevoked candidate error=%v", err)
		}
	})
}

func TestCollectRecoveryConfirmationRequiresDelayExactPhraseAndSecondConfirmation(t *testing.T) {
	waits := make([]time.Duration, 0, 1)
	now := time.Date(2026, 9, 10, 4, 0, 0, 0, time.UTC)
	confirmation, err := CollectRecoveryConfirmation(context.Background(), strings.NewReader("CONFIRM\nyes\n"), &bytes.Buffer{}, RecoveryPromptOptions{
		Actor: "admin-recovery", Language: "en-US", ConfirmationID: "recovery-confirmation",
		Warning: "Recover the interrupted storage cutover.", Now: func() time.Time { return now },
		Wait: func(_ context.Context, delay time.Duration) error { waits = append(waits, delay); return nil },
	})
	if err != nil {
		t.Fatalf("collect recovery confirmation: %v", err)
	}
	if confirmation.Actor != "admin-recovery" || confirmation.ConfirmationID != "recovery-confirmation" || confirmation.Phrase != "CONFIRM" || !confirmation.SecondConfirmation || len(waits) != 1 || waits[0] < setupmigration.WarningDelay {
		t.Fatalf("confirmation=%+v waits=%v", confirmation, waits)
	}
	_, err = CollectRecoveryConfirmation(context.Background(), strings.NewReader("confirm\nyes\n"), &bytes.Buffer{}, RecoveryPromptOptions{
		Actor: "admin-recovery", Language: "en-US", ConfirmationID: "recovery-confirmation",
		Warning: "Recover the interrupted storage cutover.", Wait: func(context.Context, time.Duration) error { return nil },
	})
	if !errors.Is(err, ErrConfirmationPhrase) {
		t.Fatalf("non-exact recovery phrase error=%v", err)
	}
}

func TestClassifyCutoverStateUsesLedgerAndRejectsAmbiguousProductionRows(t *testing.T) {
	ctx := context.Background()
	openDB := func(t *testing.T) *sql.DB {
		t.Helper()
		db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "classification.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		createRecoveryMigrationTables(t, db)
		createRecoveryManagementTables(t, db)
		return db
	}
	record, _ := newRecoveryRecordFixture(t, t.TempDir(), time.Now().UTC(), "snapshot-classify", "admin-classify", "migration-classify", "cluster-classify")
	record.Snapshot.ManagementState = emptyRecoveryManagementSnapshot(t)

	empty := openDB(t)
	direction, err := classifyCutoverState(ctx, empty, record)
	if err != nil || direction != RecoveryRollbackTemporary {
		t.Fatalf("empty production state direction=%q err=%v", direction, err)
	}

	committed := openDB(t)
	tx, err := committed.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	entry := ledgerEntryForRecoveryRecord(record, time.Now().UTC())
	if err := insertCutoverLedger(ctx, tx, entry); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	direction, err = classifyCutoverState(ctx, committed, record)
	if err != nil || direction != RecoveryCompleteProduction {
		t.Fatalf("committed direction=%q err=%v", direction, err)
	}

	ambiguous := openDB(t)
	if _, err := ambiguous.Exec(`INSERT INTO users(id) VALUES(?)`, "unexpected-user"); err != nil {
		t.Fatal(err)
	}
	if _, err := classifyCutoverState(ctx, ambiguous, record); !errors.Is(err, ErrCutoverAmbiguous) {
		t.Fatalf("nonempty production without ledger error=%v", err)
	}
}

func TestClassifyCutoverStateRejectsMatchingLedgerWhenSnapshotRowsAreMissing(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "damaged-classification.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	createRecoveryMigrationTables(t, db)
	createRecoveryManagementTables(t, db)
	record, _ := newRecoveryRecordFixture(t, t.TempDir(), time.Now().UTC(), "snapshot-damaged", "admin-damaged", "migration-damaged", "cluster-damaged")
	record.Snapshot.ManagementState = recoveryManagementSnapshotWithAdmin(t)
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := insertCutoverLedger(ctx, tx, ledgerEntryForRecoveryRecord(record, time.Now().UTC())); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := classifyCutoverState(ctx, db, record); !errors.Is(err, ErrCutoverAmbiguous) {
		t.Fatalf("matching ledger with deleted imported rows error=%v", err)
	}
}

func TestClassifyCutoverStateRequiresMigratedLegacyTokenMetadata(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "token-classification.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	createRecoveryMigrationTables(t, db)
	createRecoveryManagementTables(t, db)
	record, _ := newRecoveryRecordFixture(t, t.TempDir(), time.Now().UTC(), "snapshot-token-classify", "admin-token-classify", "migration-token-classify", "cluster-token-classify")
	record.Snapshot.ManagementState = emptyRecoveryManagementSnapshot(t)
	token := config.ManagementAPITokenConfig{ID: "legacy-token-classify", Name: "Legacy", Prefix: "cwapi_abcd", Hash: "sha256:" + strings.Repeat("c", 64), Scopes: []string{"read:rules"}, Enabled: true}
	record.Snapshot.TokenMetadata, err = json.Marshal([]config.ManagementAPITokenConfig{token})
	if err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := insertCutoverLedger(ctx, tx, ledgerEntryForRecoveryRecord(record, time.Now().UTC())); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := classifyCutoverState(ctx, db, record); !errors.Is(err, ErrCutoverAmbiguous) {
		t.Fatalf("missing migrated legacy token metadata error=%v", err)
	}
	tx, err = db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := insertLegacyTokenMetadata(ctx, tx, record.Snapshot.ID, record.Actor, record.Snapshot.TokenMetadata, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	direction, err := classifyCutoverState(ctx, db, record)
	if err != nil || direction != RecoveryCompleteProduction {
		t.Fatalf("exact legacy token metadata direction=%q err=%v", direction, err)
	}
}

func TestProductionManagementSnapshotVerificationAcceptsExactRowsAndRejectsMutation(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "exact-snapshot.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	createRecoveryManagementTables(t, db)
	raw := recoveryManagementSnapshotWithAdmin(t)
	state, err := decodeManagementSnapshot(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range state.Tables {
		spec, ok := managementSpec(table.Name)
		if !ok || !spec.importToPG {
			continue
		}
		for _, row := range table.Rows {
			values, err := expectedProductionValues(table, row)
			if err != nil {
				t.Fatal(err)
			}
			query := "INSERT INTO " + table.Name + "(" + strings.Join(table.Columns, ",") + ") VALUES(" + sqlitePlaceholders(len(values)) + ")"
			if _, err := db.ExecContext(ctx, query, values...); err != nil {
				t.Fatal(err)
			}
		}
	}
	matches, err := productionManagementMatchesSnapshot(ctx, db, raw)
	if err != nil || !matches {
		t.Fatalf("exact imported snapshot mismatch: matches=%t err=%v", matches, err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE users SET username=? WHERE id=?`, "tampered-admin", "admin-damaged"); err != nil {
		t.Fatal(err)
	}
	matches, err = productionManagementMatchesSnapshot(ctx, db, raw)
	if err != nil || matches {
		t.Fatalf("mutated imported snapshot accepted: matches=%t err=%v", matches, err)
	}
}

func TestVerifyRecoveryCredentialSupportsPasswordAndOneShotTOTPWithoutSession(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "credential.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE users (id TEXT PRIMARY KEY, password_hash TEXT NOT NULL, role TEXT NOT NULL, two_fa_enabled INTEGER NOT NULL, two_fa_secret TEXT NOT NULL); CREATE TABLE totp_consumed (user_id TEXT NOT NULL, counter INTEGER NOT NULL, expires_at TEXT NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY(user_id,counter))`); err != nil {
		t.Fatal(err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("correct horse battery staple"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	const secret = "JBSWY3DPEHPK3PXP"
	if _, err := db.Exec(`INSERT INTO users(id,password_hash,role,two_fa_enabled,two_fa_secret) VALUES(?,?,?,?,?)`, "admin-recovery", string(hash), "admin", 1, secret); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 10, 5, 0, 0, 0, time.UTC)
	if err := verifyRecoveryCredential(ctx, db, recoveryDialectSQLite, "admin-recovery", []byte("correct horse battery staple"), true, now); err != nil {
		t.Fatalf("password recovery credential: %v", err)
	}
	code, err := migrationHOTP(secret, now.Unix()/migrationTOTPPeriod)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyRecoveryCredential(ctx, db, recoveryDialectSQLite, "admin-recovery", []byte(code), false, now); err != nil {
		t.Fatalf("TOTP recovery credential: %v", err)
	}
	if err := verifyRecoveryCredential(ctx, db, recoveryDialectSQLite, "admin-recovery", []byte(code), false, now); !errors.Is(err, ErrCredentialRejected) {
		t.Fatalf("replayed TOTP error=%v", err)
	}
}

func TestRecoveryDirectionRequiresMatchingFencePhase(t *testing.T) {
	for _, pair := range []struct {
		direction RecoveryDirection
		phase     cutoverFencePhase
	}{
		{RecoveryRollbackTemporary, cutoverFenceCommitAttempted},
		{RecoveryRollbackTemporary, cutoverFencePending},
		{RecoveryCompleteProduction, cutoverFencePending},
		{RecoveryCompleteProduction, cutoverFenceCommitAttempted},
	} {
		if err := validateRecoveryDirectionFence(pair.direction, pair.phase); err != nil {
			t.Fatalf("direction=%q phase=%q error=%v", pair.direction, pair.phase, err)
		}
	}
	for _, pair := range []struct {
		direction RecoveryDirection
		phase     cutoverFencePhase
	}{{"unknown", cutoverFencePending}, {RecoveryRollbackTemporary, "unknown"}} {
		if err := validateRecoveryDirectionFence(pair.direction, pair.phase); !errors.Is(err, ErrCutoverAmbiguous) {
			t.Fatalf("invalid direction=%q phase=%q error=%v", pair.direction, pair.phase, err)
		}
	}
}

func TestRecoveryConfirmationExpiresAndCannotBeReused(t *testing.T) {
	now := time.Date(2026, 9, 10, 6, 0, 0, 0, time.UTC)
	record := recoveryRecord{Actor: "admin-once"}
	confirmation := RecoveryConfirmation{Actor: record.Actor, Language: "en-US", Phrase: "CONFIRM", ConfirmationID: "confirm-once", WarningReadAt: now.Add(-setupmigration.WarningDelay), SecondConfirmation: true}
	if err := validateRecoveryConfirmation(confirmation, record, now); err != nil {
		t.Fatalf("fresh confirmation rejected: %v", err)
	}
	if err := validateRecoveryConfirmation(confirmation, record, now.Add(maxRecoveryConfirmationAge+time.Second)); !errors.Is(err, setupmigration.ErrConfirmationRejected) {
		t.Fatalf("expired confirmation error=%v", err)
	}
	plan := &runtimeRecoveryPlan{direction: RecoveryRollbackTemporary, record: record, now: func() time.Time { return now }}
	// The first attempt fails after consuming the in-memory plan because its
	// durable dependencies are intentionally absent.
	if err := plan.Recover(context.Background(), confirmation); err == nil {
		t.Fatal("incomplete recovery plan unexpectedly succeeded")
	}
	if err := plan.Recover(context.Background(), confirmation); !errors.Is(err, ErrRecoveryConsumed) {
		t.Fatalf("second recovery attempt error=%v", err)
	}
}

type recoveryPlanFake struct {
	direction RecoveryDirection
	calls     int
	got       RecoveryConfirmation
	err       error
}

func (p *recoveryPlanFake) Direction() RecoveryDirection { return p.direction }
func (p *recoveryPlanFake) Recover(_ context.Context, confirmation RecoveryConfirmation) error {
	p.calls++
	p.got = confirmation
	return p.err
}

type recoveryCloserFake struct{ closed bool }

func (c *recoveryCloserFake) Close() error { c.closed = true; return nil }

func TestRuntimeRecoveryCommandReadsCredentialThenRunsConfirmedDirection(t *testing.T) {
	now := time.Date(2026, 9, 10, 7, 0, 0, 0, time.UTC)
	dataDir, configPath, record := recoveryCommandFixture(t, now, cutoverFencePending)
	plan := &recoveryPlanFake{direction: RecoveryRollbackTemporary}
	resources := &recoveryCloserFake{}
	var gotRequest runtimeRecoveryBuildRequest
	opts := RuntimeOptions{
		ConfigPath: func() string { return configPath }, DataDir: func() string { return dataDir },
		AcquireExclusive: func(string) (io.Closer, error) { return &recoveryCloserFake{}, nil },
		Now:              func() time.Time { return now }, Random: bytes.NewReader(bytes.Repeat([]byte{1}, 16)),
		Wait: func(context.Context, time.Duration) error { return nil },
		buildRecovery: func(_ context.Context, request runtimeRecoveryBuildRequest) (RuntimeRecoveryPlan, io.Closer, error) {
			gotRequest = request
			gotRequest.Secret = append([]byte(nil), request.Secret...)
			return plan, resources, nil
		},
	}
	cmd := &cobra.Command{Use: "recover"}
	cmd.SetIn(strings.NewReader("correct horse battery staple\nCONFIRM\nyes\n"))
	var output bytes.Buffer
	cmd.SetOut(&output)
	err := runRuntimeRecoveryCommand(cmd, opts, runtimeFlags{actor: record.Actor, language: "en-US", passwordStdin: true})
	if err != nil {
		t.Fatalf("run recovery command: %v", err)
	}
	if gotRequest.Actor != record.Actor || string(gotRequest.Secret) != "correct horse battery staple" || !gotRequest.PasswordMode || plan.calls != 1 || plan.got.Actor != record.Actor || resources.closed != true {
		t.Fatalf("request=%+v plan=%+v resources=%+v", gotRequest, plan, resources)
	}
	if !strings.Contains(output.String(), "direction=rollback-temporary") || !strings.Contains(output.String(), record.Snapshot.ID) {
		t.Fatalf("recovery output=%q", output.String())
	}
}

func TestRuntimeRecoveryCommandUsesDatabaseDirectionWhenFencePhaseIsStale(t *testing.T) {
	now := time.Date(2026, 9, 10, 8, 0, 0, 0, time.UTC)
	dataDir, configPath, record := recoveryCommandFixture(t, now, cutoverFencePending)
	plan := &recoveryPlanFake{direction: RecoveryCompleteProduction}
	opts := RuntimeOptions{
		ConfigPath: func() string { return configPath }, DataDir: func() string { return dataDir },
		AcquireExclusive: func(string) (io.Closer, error) { return &recoveryCloserFake{}, nil },
		Now:              func() time.Time { return now }, Random: bytes.NewReader(bytes.Repeat([]byte{2}, 16)),
		Wait: func(context.Context, time.Duration) error { return nil },
		buildRecovery: func(context.Context, runtimeRecoveryBuildRequest) (RuntimeRecoveryPlan, io.Closer, error) {
			return plan, &recoveryCloserFake{}, nil
		},
	}
	cmd := &cobra.Command{Use: "recover"}
	cmd.SetIn(strings.NewReader("secret\nCONFIRM\nyes\n"))
	cmd.SetOut(io.Discard)
	err := runRuntimeRecoveryCommand(cmd, opts, runtimeFlags{actor: record.Actor, language: "en-US", passwordStdin: true})
	if err != nil || plan.calls != 1 {
		t.Fatalf("database-derived direction was vetoed by stale fence: err=%v calls=%d", err, plan.calls)
	}
}

func TestRuntimeRecoveryCommandRejectsRollbackAfterProductionConfigWasPublished(t *testing.T) {
	now := time.Date(2026, 9, 10, 8, 5, 0, 0, time.UTC)
	dataDir, configPath, record := recoveryCommandFixture(t, now, cutoverFenceCommitAttempted)
	candidate, err := decodeRecoveryCandidate(record.Candidate)
	if err != nil {
		t.Fatal(err)
	}
	if err := config.Save(configPath, candidate); err != nil {
		t.Fatal(err)
	}
	plan := &recoveryPlanFake{direction: RecoveryRollbackTemporary}
	opts := RuntimeOptions{
		ConfigPath: func() string { return configPath }, DataDir: func() string { return dataDir },
		AcquireExclusive: func(string) (io.Closer, error) { return &recoveryCloserFake{}, nil },
		Now:              func() time.Time { return now }, Random: bytes.NewReader(bytes.Repeat([]byte{4}, 16)),
		Wait: func(context.Context, time.Duration) error { return nil },
		buildRecovery: func(context.Context, runtimeRecoveryBuildRequest) (RuntimeRecoveryPlan, io.Closer, error) {
			return plan, &recoveryCloserFake{}, nil
		},
	}
	cmd := &cobra.Command{Use: "recover"}
	cmd.SetIn(strings.NewReader("secret\nCONFIRM\nyes\n"))
	cmd.SetOut(io.Discard)
	err = runRuntimeRecoveryCommand(cmd, opts, runtimeFlags{actor: record.Actor, language: "en-US", passwordStdin: true})
	if !errors.Is(err, ErrCutoverAmbiguous) || plan.calls != 0 {
		t.Fatalf("rollback accepted after production config publication: err=%v calls=%d", err, plan.calls)
	}
}

func TestRuntimeRecoveryCommandRequiresPublishedProductionConfigToMatchJournal(t *testing.T) {
	now := time.Date(2026, 9, 10, 8, 10, 0, 0, time.UTC)
	dataDir, configPath, record := recoveryCommandFixture(t, now, cutoverFenceCommitAttempted)
	candidate, err := decodeRecoveryCandidate(record.Candidate)
	if err != nil {
		t.Fatal(err)
	}
	candidate.Server.AdminListen = "127.0.0.1:9555"
	if err := config.Save(configPath, candidate); err != nil {
		t.Fatal(err)
	}
	plan := &recoveryPlanFake{direction: RecoveryCompleteProduction}
	opts := RuntimeOptions{
		ConfigPath: func() string { return configPath }, DataDir: func() string { return dataDir },
		AcquireExclusive: func(string) (io.Closer, error) { return &recoveryCloserFake{}, nil },
		Now:              func() time.Time { return now }, Random: bytes.NewReader(bytes.Repeat([]byte{5}, 16)),
		Wait: func(context.Context, time.Duration) error { return nil },
		buildRecovery: func(context.Context, runtimeRecoveryBuildRequest) (RuntimeRecoveryPlan, io.Closer, error) {
			return plan, &recoveryCloserFake{}, nil
		},
	}
	cmd := &cobra.Command{Use: "recover"}
	cmd.SetIn(strings.NewReader("secret\nCONFIRM\nyes\n"))
	cmd.SetOut(io.Discard)
	err = runRuntimeRecoveryCommand(cmd, opts, runtimeFlags{actor: record.Actor, language: "en-US", passwordStdin: true})
	if !errors.Is(err, ErrCutoverAmbiguous) || plan.calls != 0 {
		t.Fatalf("drifted production config accepted: err=%v calls=%d", err, plan.calls)
	}
}

func TestRuntimeRecoveryCommandHandlesRecordOnlyCrashWindowUsingPlanDirection(t *testing.T) {
	for _, direction := range []RecoveryDirection{RecoveryRollbackTemporary, RecoveryCompleteProduction} {
		t.Run(string(direction), func(t *testing.T) {
			now := time.Date(2026, 9, 10, 8, 30, 0, 0, time.UTC)
			dataDir, configPath, record := recoveryCommandFixture(t, now, cutoverFencePending)
			fencePath, err := cutoverFencePath(dataDir)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(fencePath); err != nil {
				t.Fatal(err)
			}
			plan := &recoveryPlanFake{direction: direction}
			opts := RuntimeOptions{
				ConfigPath: func() string { return configPath }, DataDir: func() string { return dataDir },
				AcquireExclusive: func(string) (io.Closer, error) { return &recoveryCloserFake{}, nil },
				Now:              func() time.Time { return now }, Random: bytes.NewReader(bytes.Repeat([]byte{3}, 16)),
				Wait: func(context.Context, time.Duration) error { return nil },
				buildRecovery: func(context.Context, runtimeRecoveryBuildRequest) (RuntimeRecoveryPlan, io.Closer, error) {
					return plan, &recoveryCloserFake{}, nil
				},
			}
			cmd := &cobra.Command{Use: "recover"}
			cmd.SetIn(strings.NewReader("secret\nCONFIRM\nyes\n"))
			cmd.SetOut(io.Discard)
			if err := runRuntimeRecoveryCommand(cmd, opts, runtimeFlags{actor: record.Actor, language: "en-US", passwordStdin: true}); err != nil {
				t.Fatalf("record-only recovery direction=%s: %v", direction, err)
			}
			if plan.calls != 1 {
				t.Fatalf("record-only recovery calls=%d", plan.calls)
			}
		})
	}
}

func TestRuntimeRecoveryCommandRejectsConfigChangeWhileAcquiringLease(t *testing.T) {
	now := time.Date(2026, 9, 10, 8, 45, 0, 0, time.UTC)
	dataDir, configPath, record := recoveryCommandFixture(t, now, cutoverFencePending)
	built := false
	opts := RuntimeOptions{
		ConfigPath: func() string { return configPath }, DataDir: func() string { return dataDir },
		AcquireExclusive: func(string) (io.Closer, error) {
			cfg, err := config.Load(configPath)
			if err != nil {
				return nil, err
			}
			cfg.Server.AdminListen = "127.0.0.1:9555"
			if err := config.Save(configPath, cfg); err != nil {
				return nil, err
			}
			return &recoveryCloserFake{}, nil
		},
		buildRecovery: func(context.Context, runtimeRecoveryBuildRequest) (RuntimeRecoveryPlan, io.Closer, error) {
			built = true
			return &recoveryPlanFake{direction: RecoveryRollbackTemporary}, &recoveryCloserFake{}, nil
		},
	}
	cmd := &cobra.Command{Use: "recover"}
	cmd.SetIn(strings.NewReader("secret\nCONFIRM\nyes\n"))
	cmd.SetOut(io.Discard)
	err := runRuntimeRecoveryCommand(cmd, opts, runtimeFlags{actor: record.Actor, language: "en-US", passwordStdin: true})
	if !errors.Is(err, ErrRuntimeConfiguration) || built {
		t.Fatalf("config TOCTOU error=%v builder_called=%t", err, built)
	}
}

func TestRuntimeRecoveryCommandRejectsTemporaryConfigDriftAgainstSnapshot(t *testing.T) {
	now := time.Date(2026, 9, 10, 8, 50, 0, 0, time.UTC)
	dataDir, configPath, record := recoveryCommandFixture(t, now, cutoverFencePending)
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Server.AdminListen = "127.0.0.1:9666"
	if err := config.Save(configPath, cfg); err != nil {
		t.Fatal(err)
	}
	built := false
	opts := RuntimeOptions{
		ConfigPath: func() string { return configPath }, DataDir: func() string { return dataDir },
		AcquireExclusive: func(string) (io.Closer, error) { return &recoveryCloserFake{}, nil },
		buildRecovery: func(context.Context, runtimeRecoveryBuildRequest) (RuntimeRecoveryPlan, io.Closer, error) {
			built = true
			return &recoveryPlanFake{direction: RecoveryRollbackTemporary}, &recoveryCloserFake{}, nil
		},
	}
	cmd := &cobra.Command{Use: "recover"}
	cmd.SetIn(strings.NewReader("secret\nCONFIRM\nyes\n"))
	cmd.SetOut(io.Discard)
	err = runRuntimeRecoveryCommand(cmd, opts, runtimeFlags{actor: record.Actor, language: "en-US", passwordStdin: true})
	if !errors.Is(err, ErrCutoverAmbiguous) || built {
		t.Fatalf("drifted temporary config error=%v builder_called=%t", err, built)
	}
}

func TestRuntimeRecoveryCommandDoesNotResolveConfiguredAIEndpoint(t *testing.T) {
	now := time.Date(2026, 9, 10, 8, 55, 0, 0, time.UTC)
	dataDir, configPath, record := recoveryCommandFixture(t, now, cutoverFencePending)
	current := config.Default()
	current.Setup.DataDir = dataDir
	current.Setup.RuntimeDir = filepath.Join(dataDir, "run")
	current.Storage.SQLite.Path = filepath.Join(dataDir, "cheesewaf.db")
	current.AI.Enabled = true
	current.AI.Provider = "openai"
	current.AI.APIBase = "https://recovery-command-must-not-resolve.invalid/v1"
	current.AI.APIKey = "recovery-command-key"
	current.AI.Model = "recovery-command-model"
	if err := config.Save(configPath, &current); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	record.Snapshot.ConfigDigest = digestBytes(raw)
	candidate, err := decodeRecoveryCandidate(record.Candidate)
	if err != nil {
		t.Fatal(err)
	}
	candidate.AI = current.AI
	privateConfig, initialState, err := encodeRecoveryPayloads(candidate)
	if err != nil {
		t.Fatal(err)
	}
	record.Candidate = privateConfig
	record.CandidateDigest = digestBytes(privateConfig)
	record.InitialState = initialState
	record.InitialStateHash = digestBytes(initialState)
	recoveryPath, _ := recoveryRecordPath(dataDir)
	fencePath, _ := cutoverFencePath(dataDir)
	if err := os.Remove(recoveryPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(fencePath); err != nil {
		t.Fatal(err)
	}
	if err := writeRecoveryRecord(dataDir, record); err != nil {
		t.Fatal(err)
	}
	if err := writeCutoverFence(dataDir, cutoverFence{Version: cutoverFenceVersion, SnapshotID: record.Snapshot.ID, ConfigDigest: record.Snapshot.ConfigDigest, Phase: cutoverFencePending, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	plan := &recoveryPlanFake{direction: RecoveryRollbackTemporary}
	opts := RuntimeOptions{
		ConfigPath: func() string { return configPath }, DataDir: func() string { return dataDir },
		AcquireExclusive: func(string) (io.Closer, error) { return &recoveryCloserFake{}, nil },
		Now:              func() time.Time { return now }, Random: bytes.NewReader(bytes.Repeat([]byte{6}, 16)),
		Wait: func(context.Context, time.Duration) error { return nil },
		buildRecovery: func(context.Context, runtimeRecoveryBuildRequest) (RuntimeRecoveryPlan, io.Closer, error) {
			return plan, &recoveryCloserFake{}, nil
		},
	}
	cmd := &cobra.Command{Use: "recover"}
	cmd.SetIn(strings.NewReader("secret\nCONFIRM\nyes\n"))
	cmd.SetOut(io.Discard)
	if err := runRuntimeRecoveryCommand(cmd, opts, runtimeFlags{actor: record.Actor, language: "en-US", passwordStdin: true}); err != nil {
		t.Fatalf("recovery command performed outbound AI endpoint validation: %v", err)
	}
	if plan.calls != 1 {
		t.Fatalf("recovery plan calls=%d", plan.calls)
	}
}

func recoveryCommandFixture(t *testing.T, now time.Time, phase cutoverFencePhase) (string, string, recoveryRecord) {
	t.Helper()
	dataDir := t.TempDir()
	cfg := config.Default()
	cfg.Setup.DataDir = dataDir
	cfg.Setup.RuntimeDir = filepath.Join(dataDir, "run")
	cfg.Storage.SQLite.Path = filepath.Join(dataDir, "cheesewaf.db")
	configPath := filepath.Join(dataDir, "config", "cheesewaf.yaml")
	if err := config.Save(configPath, &cfg); err != nil {
		t.Fatal(err)
	}
	record, _ := newRecoveryRecordFixture(t, dataDir, now, "snapshot-command", "admin-command", "migration-command", "cluster-command")
	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	record.Snapshot.ConfigDigest = digestBytes(raw)
	record.Snapshot.ManagementState = emptyRecoveryManagementSnapshot(t)
	if err := writeRecoveryRecord(dataDir, record); err != nil {
		t.Fatal(err)
	}
	if err := writeCutoverFence(dataDir, cutoverFence{Version: cutoverFenceVersion, SnapshotID: record.Snapshot.ID, ConfigDigest: record.Snapshot.ConfigDigest, Phase: phase, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	return dataDir, configPath, record
}

type recoveryDurableFake struct {
	state controlplane.State
	err   error
}

func (*recoveryDurableFake) Backend() string                 { return controlplane.DurableBackendPostgreSQL }
func (f *recoveryDurableFake) Prepare(context.Context) error { return f.err }
func (f *recoveryDurableFake) Health(context.Context) error  { return f.err }
func (f *recoveryDurableFake) LoadState(context.Context, string) (controlplane.State, error) {
	return f.state, f.err
}
func (f *recoveryDurableFake) AppendCommit(_ context.Context, commit controlplane.Commit) error {
	if f.err == nil {
		f.state = commit.State
	}
	return f.err
}
func (f *recoveryDurableFake) CheckpointLeadership(_ context.Context, state controlplane.State) error {
	if f.err == nil {
		f.state = state
	}
	return f.err
}

type recoveryConsensusFake struct {
	state   controlplane.State
	fence   controlplane.FenceToken
	machine *controlplane.StateMachine
	err     error
}

func (*recoveryConsensusFake) Backend() string                 { return controlplane.ConsensusBackendNativeRaft }
func (f *recoveryConsensusFake) Prepare(context.Context) error { return f.err }
func (f *recoveryConsensusFake) Health(context.Context) error  { return f.err }
func (f *recoveryConsensusFake) Current(context.Context, string) (controlplane.State, error) {
	return f.state, f.err
}
func (f *recoveryConsensusFake) Propose(_ context.Context, commit controlplane.Commit) error {
	if f.err == nil {
		f.state = commit.State
	}
	return f.err
}
func (f *recoveryConsensusFake) Establish(context.Context, controlplane.State) (controlplane.FenceToken, error) {
	return f.fence, f.err
}
func (f *recoveryConsensusFake) CheckpointLeadership(_ context.Context, _, consensus controlplane.State) (controlplane.State, error) {
	return consensus, f.err
}
func (f *recoveryConsensusFake) Machine() *controlplane.StateMachine { return f.machine }

type recoveryHealthFake struct{ err error }

func (f recoveryHealthFake) Ping(context.Context) error { return f.err }

func TestRuntimeRecoveryPlanCompletesProductionAndRemovesArtifacts(t *testing.T) {
	now := time.Date(2026, 9, 10, 9, 0, 0, 0, time.UTC)
	dataDir := t.TempDir()
	candidate := validRecoveryProductionConfig(t, dataDir)
	record, _ := newRecoveryRecordFixture(t, dataDir, now, "snapshot-forward", "admin-forward", "migration-forward", candidate.Cluster.ClusterID)
	record.Snapshot.ManagementState = emptyRecoveryManagementSnapshot(t)
	managementDB := recoveryLedgerDB(t)
	tx, err := managementDB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := insertCutoverLedger(context.Background(), tx, ledgerEntryForRecoveryRecord(record, now)); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := writeRecoveryRecord(dataDir, record); err != nil {
		t.Fatal(err)
	}
	if err := writeCutoverFence(dataDir, cutoverFence{Version: cutoverFenceVersion, SnapshotID: record.Snapshot.ID, ConfigDigest: record.Snapshot.ConfigDigest, Phase: cutoverFenceCommitAttempted, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	machine, commit := recoveryCommittedControlState(t, record, now)
	durable := &recoveryDurableFake{state: commit.State}
	consensus := &recoveryConsensusFake{state: commit.State, fence: commit.Fence, machine: machine}
	configPath := filepath.Join(dataDir, "config", "cheesewaf.yaml")
	temporary := config.Default()
	temporary.Setup.DataDir = dataDir
	temporary.Setup.RuntimeDir = filepath.Join(dataDir, "run")
	temporary.Storage.SQLite.Path = filepath.Join(dataDir, "cheesewaf.db")
	if err := config.Save(configPath, &temporary); err != nil {
		t.Fatal(err)
	}
	plan := &runtimeRecoveryPlan{
		direction: RecoveryCompleteProduction, record: record, configPath: configPath, dataDir: dataDir,
		now: func() time.Time { return now }, managementDB: managementDB, candidate: candidate,
		control: durable, raft: consensus, redis: recoveryHealthFake{},
	}
	confirmation := RecoveryConfirmation{Actor: record.Actor, Language: "en-US", Phrase: "CONFIRM", ConfirmationID: "confirm-forward", WarningReadAt: now.Add(-setupmigration.WarningDelay), SecondConfirmation: true}
	if err := plan.Recover(context.Background(), confirmation); err != nil {
		t.Fatalf("complete production recovery: %v", err)
	}
	persisted, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Storage.Profile != config.StorageProfileProduction {
		t.Fatalf("persisted profile=%q", persisted.Storage.Profile)
	}
	if err := CheckPendingCutover(dataDir); err != nil {
		t.Fatalf("successful recovery left artifacts: %v", err)
	}
}

func TestRuntimeRecoveryPlanRetainsArtifactsWhenProductionDependencyFails(t *testing.T) {
	now := time.Date(2026, 9, 10, 9, 30, 0, 0, time.UTC)
	dataDir := t.TempDir()
	candidate := validRecoveryProductionConfig(t, dataDir)
	record, _ := newRecoveryRecordFixture(t, dataDir, now, "snapshot-retry", "admin-retry", "migration-retry", candidate.Cluster.ClusterID)
	record.Snapshot.ManagementState = emptyRecoveryManagementSnapshot(t)
	db := recoveryLedgerDB(t)
	tx, _ := db.BeginTx(context.Background(), nil)
	if err := insertCutoverLedger(context.Background(), tx, ledgerEntryForRecoveryRecord(record, now)); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := writeRecoveryRecord(dataDir, record); err != nil {
		t.Fatal(err)
	}
	if err := writeCutoverFence(dataDir, cutoverFence{Version: cutoverFenceVersion, SnapshotID: record.Snapshot.ID, ConfigDigest: record.Snapshot.ConfigDigest, Phase: cutoverFenceCommitAttempted, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	machine, commit := recoveryCommittedControlState(t, record, now)
	plan := &runtimeRecoveryPlan{
		direction: RecoveryCompleteProduction, record: record, dataDir: dataDir, now: func() time.Time { return now }, managementDB: db, candidate: candidate,
		control: &recoveryDurableFake{state: commit.State},
		raft:    &recoveryConsensusFake{state: commit.State, fence: commit.Fence, machine: machine},
		redis:   recoveryHealthFake{err: errors.New("redis unavailable")},
	}
	confirmation := RecoveryConfirmation{Actor: record.Actor, Language: "en-US", Phrase: "CONFIRM", ConfirmationID: "confirm-retry", WarningReadAt: now.Add(-setupmigration.WarningDelay), SecondConfirmation: true}
	if err := plan.Recover(context.Background(), confirmation); !errors.Is(err, setupmigration.ErrPrerequisiteUnavailable) {
		t.Fatalf("dependency failure error=%v", err)
	}
	if err := CheckPendingCutover(dataDir); !errors.Is(err, ErrCutoverPending) {
		t.Fatalf("dependency failure removed recovery artifacts: %v", err)
	}
}

func recoveryLedgerDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "ledger.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	createRecoveryMigrationTables(t, db)
	createRecoveryManagementTables(t, db)
	return db
}

func createRecoveryManagementTables(t *testing.T, db *sql.DB) {
	t.Helper()
	for _, spec := range managementTableSpecs {
		if !spec.importToPG {
			continue
		}
		columns := make([]string, len(spec.columns))
		for index, column := range spec.columns {
			columnType := "BLOB"
			if strings.HasSuffix(column, "_at") {
				columnType = "TIMESTAMP"
			}
			columns[index] = column + " " + columnType
		}
		if _, err := db.Exec(`CREATE TABLE ` + spec.name + ` (` + strings.Join(columns, ",") + `)`); err != nil {
			t.Fatal(err)
		}
	}
}

func createRecoveryMigrationTables(t *testing.T, db *sql.DB) {
	t.Helper()
	if _, err := db.Exec(`CREATE TABLE cheesewaf_migration_cutovers (snapshot_id TEXT PRIMARY KEY, config_digest TEXT NOT NULL, candidate_digest TEXT NOT NULL, initial_state_hash TEXT NOT NULL, token_metadata_digest TEXT NOT NULL, actor_id TEXT NOT NULL, confirmation_id TEXT NOT NULL UNIQUE, cluster_id TEXT NOT NULL, committed_at TIMESTAMP NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE cheesewaf_migration_legacy_tokens (snapshot_id TEXT NOT NULL, token_id TEXT NOT NULL, name TEXT NOT NULL, prefix TEXT NOT NULL, scopes BLOB NOT NULL, notes TEXT NOT NULL, was_enabled INTEGER NOT NULL, never_expire INTEGER NOT NULL, created_at TIMESTAMP, updated_at TIMESTAMP, last_used_at TIMESTAMP, expires_at TIMESTAMP, source_revoked_at TIMESTAMP, migrated_at TIMESTAMP NOT NULL, actor_id TEXT NOT NULL, status TEXT NOT NULL, PRIMARY KEY(snapshot_id,token_id))`); err != nil {
		t.Fatal(err)
	}
}

func emptyRecoveryManagementSnapshot(t *testing.T) []byte {
	t.Helper()
	state := managementSnapshot{Version: managementSnapshotVersion, SQLiteSchemaVersion: supportedSQLiteSchemaVersion}
	for _, spec := range managementTableSpecs {
		state.Tables = append(state.Tables, snapshotTable{Name: spec.name, Columns: append([]string(nil), spec.columns...)})
	}
	raw, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func recoveryManagementSnapshotWithAdmin(t *testing.T) []byte {
	t.Helper()
	var state managementSnapshot
	if err := json.Unmarshal(emptyRecoveryManagementSnapshot(t), &state); err != nil {
		t.Fatal(err)
	}
	created := time.Date(2026, 9, 10, 10, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)
	for index := range state.Tables {
		if state.Tables[index].Name != "users" {
			continue
		}
		state.Tables[index].Rows = [][]snapshotCell{{
			{Kind: "text", Text: "admin-damaged"},
			{Kind: "text", Text: "admin"},
			{Kind: "text", Text: "$2a$04$fixture"},
			{Kind: "text", Text: "admin"},
			{Kind: "integer"},
			{Kind: "text"},
			{Kind: "text", Text: created},
			{Kind: "text", Text: created},
			{Kind: "integer", Integer: 7},
		}}
	}
	raw, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func validRecoveryProductionConfig(t *testing.T, dataDir string) *config.Config {
	t.Helper()
	cfg := config.Default()
	cfg.Storage.Profile = config.StorageProfileProduction
	cfg.Storage.ManagementPostgreSQL.DSN = "postgres://management.invalid/management"
	cfg.Storage.ControlPostgreSQL.DSN = "postgres://control.invalid/control"
	cfg.Storage.Redis.Enabled = true
	cfg.Storage.Redis.Address = "127.0.0.1:6379"
	cfg.Storage.Redis.InstanceID = "redis-a"
	cfg.Cluster.ClusterID = "cluster-recovery"
	cfg.Cluster.NodeID = "node-recovery"
	cfg.Cluster.Consensus.NativeRaft.DataDir = filepath.Join(dataDir, "raft")
	cfg.Setup.DataDir = dataDir
	cfg.Setup.RuntimeDir = filepath.Join(dataDir, "run")
	if err := config.Validate(&cfg); err != nil {
		t.Fatalf("valid recovery production config: %v", err)
	}
	return &cfg
}

func recoveryCommittedControlState(t *testing.T, record recoveryRecord, now time.Time) (*controlplane.StateMachine, controlplane.Commit) {
	t.Helper()
	machine, err := controlplane.NewStateMachine(record.ClusterID, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	leader, err := machine.InstallLeadership(1, "node-recovery")
	if err != nil {
		t.Fatal(err)
	}
	commit, err := machine.Propose(controlplane.Proposal{LeaderID: leader.LeaderID, ExpectedEpoch: leader.Epoch, ExpectedRevision: 0, Version: "cheesewaf-config-v1", Payload: record.InitialState, Digest: record.InitialStateHash, Nonce: record.ConfirmationID})
	if err != nil {
		t.Fatal(err)
	}
	if err := machine.InstallCommit(commit); err != nil {
		t.Fatal(err)
	}
	return machine, commit
}

func newRecoveryRecordFixture(t *testing.T, dataDir string, now time.Time, snapshotID, actor, confirmationID, clusterID string) (recoveryRecord, *config.Config) {
	t.Helper()
	candidate := validRecoveryProductionConfig(t, dataDir)
	candidate.Cluster.ClusterID = clusterID
	if err := config.Validate(candidate); err != nil {
		t.Fatalf("recovery candidate: %v", err)
	}
	privateConfig, initialState, err := encodeRecoveryPayloads(candidate)
	if err != nil {
		t.Fatalf("encode recovery fixture: %v", err)
	}
	return recoveryRecord{
		Version:   recoveryRecordVersion,
		Snapshot:  setupmigration.Snapshot{ID: snapshotID, ConfigDigest: strings.Repeat("a", 64)},
		Candidate: privateConfig, CandidateDigest: digestBytes(privateConfig), InitialState: initialState,
		Actor: actor, ConfirmationID: confirmationID, ClusterID: clusterID, InitialStateHash: digestBytes(initialState), CreatedAt: now,
	}, candidate
}
