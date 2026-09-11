package migration

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/cluster/redis"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane"
	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane/nativeraft"
	controlpostgres "github.com/LaokeQwQ/CheeseWAF/internal/controlplane/postgres"
	setupmigration "github.com/LaokeQwQ/CheeseWAF/internal/setup/migration"
	storagepostgres "github.com/LaokeQwQ/CheeseWAF/internal/storage/postgres"
	"github.com/jackc/pgx/v5"
	_ "github.com/jackc/pgx/v5/stdlib"
)

type runtimePrerequisite struct {
	check func(context.Context) error
}

func (p runtimePrerequisite) Check(ctx context.Context) error {
	if p.check == nil {
		return setupmigration.ErrPrerequisiteUnavailable
	}
	return p.check(ctx)
}

type runtimeResources struct {
	management *storagepostgres.Store
	control    *controlpostgres.Store
	raft       *nativeraft.Runtime
	redis      *redis.RuntimeAdapter
	closeOnce  sync.Once
	closeErr   error
}

func (r *runtimeResources) Close() error {
	if r == nil {
		return nil
	}
	r.closeOnce.Do(func() {
		close := func(fn func() error) {
			if fn == nil {
				return
			}
			if err := fn(); err != nil && r.closeErr == nil {
				r.closeErr = err
			}
		}
		close(func() error {
			if r.redis == nil {
				return nil
			}
			return r.redis.Close()
		})
		close(func() error {
			if r.raft == nil {
				return nil
			}
			return r.raft.Close()
		})
		close(func() error {
			if r.control == nil {
				return nil
			}
			return r.control.Close()
		})
		close(func() error {
			if r.management == nil {
				return nil
			}
			return r.management.Close()
		})
	})
	return r.closeErr
}

type runtimeProductionTarget struct {
	db             *sql.DB
	configPath     string
	candidate      *config.Config
	candidateHash  string
	initialHash    string
	actor          string
	clusterID      string
	now            func() time.Time
	dataDir        string
	snapshotID     string
	control        *controlpostgres.Store
	raft           *nativeraft.Runtime
	initialState   *controlplane.InitialStateRequest
	authorizer     *credentialConfirmationProvider
	confirmationID string
	commitMu       sync.Mutex
}

type runtimeProductionTransaction struct {
	target    *runtimeProductionTarget
	tx        *sql.Tx
	committed bool
	closed    bool
	mu        sync.Mutex
}

func buildRuntimeRunner(ctx context.Context, request runtimeBuildRequest) (Runner, io.Closer, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if request.Config == nil || request.RuntimeConfig == nil || request.Candidate == nil || request.SQLite == nil {
		return nil, nil, ErrRuntimeConfiguration
	}
	if request.Config.Storage.Profile != config.StorageProfileTemporary || request.Candidate.Storage.Profile != config.StorageProfileProduction {
		return nil, nil, setupmigration.ErrProfileMismatch
	}
	configRaw, err := os.ReadFile(request.ConfigPath)
	if err != nil {
		return nil, nil, err
	}
	configDigest := digestBytes(configRaw)
	if request.ConfigPath == "" || configDigest == "" {
		return nil, nil, ErrRuntimeConfiguration
	}
	privateCandidate, payload, err := encodeRecoveryPayloads(request.Candidate)
	if err != nil {
		return nil, nil, err
	}
	source := &runtimeTemporarySource{
		db: request.SQLite, profile: setupmigration.TemporaryProfile, configPath: request.ConfigPath,
		dataDir: request.RuntimeConfig.Setup.DataDir, expectedDigest: configDigest,
		candidate: privateCandidate, candidateDigest: digestBytes(privateCandidate), initialState: payload, actor: request.Authorization.actor,
		confirmationID: request.ConfirmationID, clusterID: request.Candidate.Cluster.ClusterID,
		initialStateHash: digestBytes(payload), now: request.Now,
	}
	authorizer, err := request.Authorization.provider(request.ConfirmationID)
	if err != nil {
		return nil, nil, err
	}
	managementDB, err := sql.Open("pgx", request.Candidate.Storage.ManagementPostgreSQL.DSN)
	if err != nil {
		return nil, nil, setupmigration.ErrPrerequisiteUnavailable
	}
	management, err := storagepostgres.New(managementDB)
	if err != nil {
		_ = managementDB.Close()
		return nil, nil, err
	}
	managementCtx, cancelManagement := dependencyContext(ctx, request.Candidate.Storage.ManagementPostgreSQL.Timeout)
	if err := management.Migrate(managementCtx); err != nil {
		cancelManagement()
		_ = management.Close()
		return nil, nil, setupmigration.ErrPrerequisiteUnavailable
	}
	if err := management.Health(managementCtx); err != nil {
		cancelManagement()
		_ = management.Close()
		return nil, nil, setupmigration.ErrPrerequisiteUnavailable
	}
	cancelManagement()

	controlDSN := strings.TrimSpace(request.Candidate.Storage.ControlPostgreSQL.DSN)
	if controlDSN == "" {
		_ = management.Close()
		return nil, nil, setupmigration.ErrPrerequisiteUnavailable
	}
	controlDB, err := sql.Open("pgx", controlDSN)
	if err != nil {
		_ = management.Close()
		return nil, nil, setupmigration.ErrPrerequisiteUnavailable
	}
	control, err := controlpostgres.New(controlDB)
	if err != nil {
		_ = controlDB.Close()
		_ = management.Close()
		return nil, nil, err
	}
	controlCtx, cancelControl := dependencyContext(ctx, request.Candidate.Storage.ControlPostgreSQL.Timeout)
	if err := control.Prepare(controlCtx); err != nil || control.Health(controlCtx) != nil {
		cancelControl()
		_ = control.Close()
		_ = management.Close()
		return nil, nil, setupmigration.ErrPrerequisiteUnavailable
	}
	cancelControl()

	raftOptions, err := nativeRaftOptionsFromConfig(request.Candidate)
	if err != nil {
		_ = control.Close()
		_ = management.Close()
		return nil, nil, err
	}
	raft, err := nativeraft.New(raftOptions)
	if err != nil {
		_ = control.Close()
		_ = management.Close()
		return nil, nil, setupmigration.ErrPrerequisiteUnavailable
	}
	if err := raft.Prepare(ctx); err != nil || raft.Health(ctx) != nil {
		_ = raft.Close()
		_ = control.Close()
		_ = management.Close()
		return nil, nil, setupmigration.ErrPrerequisiteUnavailable
	}

	redisCfg := redis.Config{Addr: request.Candidate.Storage.Redis.Address, InstanceID: request.Candidate.Storage.Redis.InstanceID, DialTimeout: request.Candidate.Storage.ManagementPostgreSQL.Timeout}
	if !request.Candidate.Storage.Redis.Enabled || strings.TrimSpace(redisCfg.Addr) == "" || strings.TrimSpace(redisCfg.InstanceID) == "" {
		_ = raft.Close()
		_ = control.Close()
		_ = management.Close()
		return nil, nil, setupmigration.ErrPrerequisiteUnavailable
	}
	redisAdapter, err := redis.Open(ctx, redisCfg)
	if err != nil {
		_ = raft.Close()
		_ = control.Close()
		_ = management.Close()
		return nil, nil, setupmigration.ErrPrerequisiteUnavailable
	}
	if err := redisAdapter.Ping(ctx); err != nil {
		_ = redisAdapter.Close()
		_ = raft.Close()
		_ = control.Close()
		_ = management.Close()
		return nil, nil, setupmigration.ErrPrerequisiteUnavailable
	}

	initialState := &controlplane.InitialStateRequest{
		Version: "cheesewaf-config-v1", Payload: payload, Nonce: request.ConfirmationID,
		Confirmation: controlplane.InitialStateConfirmation{ID: request.ConfirmationID, Actor: request.Authorization.actor, Reason: "temporary-to-production migration"},
	}
	target := &runtimeProductionTarget{
		db: managementDB, configPath: request.ConfigPath, candidate: request.Candidate,
		candidateHash: digestBytes(privateCandidate), initialHash: digestBytes(payload),
		actor: request.Authorization.actor, clusterID: request.Candidate.Cluster.ClusterID, now: request.Now,
		dataDir: request.RuntimeConfig.Setup.DataDir,
		control: control, raft: raft, initialState: initialState, authorizer: authorizer, confirmationID: request.ConfirmationID,
	}
	resources := &runtimeResources{management: management, control: control, raft: raft, redis: redisAdapter}
	return setupmigrationRunner(setupmigration.Options{
		Source: source, Target: target,
		PostgreSQL: runtimePrerequisite{check: func(ctx context.Context) error { return management.Health(ctx) }},
		NativeRaft: runtimePrerequisite{check: func(ctx context.Context) error { return raft.Health(ctx) }},
		Redis:      runtimePrerequisite{check: func(ctx context.Context) error { return redisAdapter.Ping(ctx) }},
		Confirmer:  authorizer, Now: request.Now,
	}), resources, nil
}

// setupmigrationRunner is a variable solely to keep the production builder
// replaceable by focused package tests without exposing backend handles.
var setupmigrationRunner = func(opts setupmigration.Options) Runner { return setupmigration.New(opts) }

func nativeRaftOptionsFromConfig(cfg *config.Config) (nativeraft.Options, error) {
	if cfg == nil || !controlplane.ValidIdentity(cfg.Cluster.ClusterID) {
		return nativeraft.Options{}, setupmigration.ErrPrerequisiteUnavailable
	}
	raft := cfg.Cluster.Consensus.NativeRaft
	dataDir := strings.TrimSpace(raft.DataDir)
	if dataDir == "" {
		dataDir = filepath.Join(cfg.Setup.DataDir, "cluster", "native-raft")
	}
	if !filepath.IsAbs(dataDir) {
		dataDir = filepath.Join(cfg.Setup.DataDir, dataDir)
	}
	interconnect := cfg.Cluster.Interconnect
	if strings.TrimSpace(interconnect.CAFile) == "" || strings.TrimSpace(interconnect.CertFile) == "" || strings.TrimSpace(interconnect.KeyFile) == "" {
		return nativeraft.Options{}, setupmigration.ErrPrerequisiteUnavailable
	}
	return nativeraft.Options{Profile: config.StorageProfileProduction, ClusterID: cfg.Cluster.ClusterID, NodeID: cfg.Cluster.NodeID, DataDir: dataDir, BindAddress: raft.Listen, Mode: nativeraft.StartMode(raft.Mode), TLS: &nativeraft.TLSOptions{CAFile: interconnect.CAFile, CertFile: interconnect.CertFile, KeyFile: interconnect.KeyFile}}, nil
}

func (t *runtimeProductionTarget) Begin(ctx context.Context, snapshot setupmigration.Snapshot) (setupmigration.ProductionTransaction, error) {
	if t == nil || t.db == nil || t.candidate == nil {
		return nil, setupmigration.ErrTransactionUnavailable
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if snapshot.ID == "" {
		return nil, setupmigration.ErrTransactionUnavailable
	}
	t.snapshotID = snapshot.ID
	tx, err := t.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(847392104)`); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	for _, spec := range managementTableSpecs {
		if !spec.importToPG {
			continue
		}
		var count int64
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(1) FROM `+spec.name).Scan(&count); err != nil {
			_ = tx.Rollback()
			return nil, err
		}
		if count != 0 {
			_ = tx.Rollback()
			return nil, errors.New("production management target is not empty")
		}
	}
	return &runtimeProductionTransaction{target: t, tx: tx}, nil
}

func (t *runtimeProductionTransaction) MigrateManagementState(ctx context.Context, snapshot setupmigration.Snapshot) error {
	if t == nil || t.tx == nil || t.target == nil {
		return setupmigration.ErrManagementStateMigration
	}
	state, err := decodeManagementSnapshot(snapshot.ManagementState)
	if err != nil {
		return err
	}
	for _, table := range state.Tables {
		spec, ok := managementSpec(table.Name)
		if !ok || !spec.importToPG {
			continue
		}
		for _, row := range table.Rows {
			values, err := pgSnapshotValues(table, row)
			if err != nil {
				return err
			}
			if table.Name == "users" {
				epochIndex := columnIndex(table.Columns, "credential_epoch")
				if epochIndex < 0 {
					return errors.New("user credential epoch is missing")
				}
				epoch, ok := values[epochIndex].(int64)
				if !ok || epoch == int64(^uint64(0)>>1) {
					return errors.New("user credential epoch is invalid")
				}
				values[epochIndex] = epoch + 1
			}
			query := "INSERT INTO " + table.Name + "(" + strings.Join(table.Columns, ",") + ") VALUES(" + pgPlaceholders(len(values)) + ")"
			if _, err := t.tx.ExecContext(ctx, query, values...); err != nil {
				return err
			}
		}
	}
	return insertCutoverLedger(ctx, t.tx, cutoverLedgerEntry{
		SnapshotID:       snapshot.ID,
		ConfigDigest:     snapshot.ConfigDigest,
		CandidateDigest:  t.target.candidateHash,
		InitialStateHash: t.target.initialHash,
		TokenDigest:      digestBytes(snapshot.TokenMetadata),
		Actor:            t.target.actor,
		ConfirmationID:   t.target.confirmationID,
		ClusterID:        t.target.clusterID,
		CommittedAt:      runtimeNow(t.target.now),
	})
}

func (t *runtimeProductionTransaction) MigrateTokenMetadata(ctx context.Context, snapshot setupmigration.Snapshot) error {
	if t == nil || t.tx == nil || t.target == nil || snapshot.ID == "" || snapshot.ID != t.target.snapshotID {
		return setupmigration.ErrTokenMetadataMigration
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := insertLegacyTokenMetadata(ctx, t.tx, snapshot.ID, t.target.actor, snapshot.TokenMetadata, runtimeNow(t.target.now)); err != nil {
		return errors.Join(setupmigration.ErrTokenMetadataMigration, err)
	}
	return nil
}

func (t *runtimeProductionTransaction) RotateTokenMetadata(ctx context.Context, snapshot setupmigration.Snapshot) error {
	if t == nil || t.tx == nil || t.target == nil || t.target.candidate == nil || snapshot.ID == "" || snapshot.ID != t.target.snapshotID {
		return setupmigration.ErrTokenMetadataRotation
	}
	if ctx == nil {
		ctx = context.Background()
	}
	now := runtimeNow(t.target.now)
	if err := validateLegacyTokenRotation(t.target.candidate, snapshot.TokenMetadata, now); err != nil {
		return errors.Join(setupmigration.ErrTokenMetadataRotation, err)
	}
	matches, err := verifyLegacyTokenMetadataTx(ctx, t.tx, snapshot.ID, t.target.actor, snapshot.TokenMetadata)
	if err != nil || !matches {
		return errors.Join(setupmigration.ErrTokenMetadataRotation, ErrRuntimeConfiguration, err)
	}
	return ctx.Err()
}

func (t *runtimeProductionTransaction) Commit(ctx context.Context) error {
	if t == nil || t.target == nil || t.tx == nil {
		return setupmigration.ErrCommitFailed
	}
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return setupmigration.ErrCommitFailed
	}
	t.mu.Unlock()
	t.target.commitMu.Lock()
	defer t.target.commitMu.Unlock()
	if err := markCutoverCommitAttempted(t.target.dataDir, t.target.snapshotID, runtimeNow(nil)); err != nil {
		return err
	}
	if err := t.tx.Commit(); err != nil {
		t.mu.Lock()
		t.closed = true
		t.mu.Unlock()
		return errors.Join(setupmigration.ErrCommitOutcomeUnknown, err)
	}
	t.mu.Lock()
	t.committed, t.closed = true, true
	t.mu.Unlock()
	// The control-plane initial-state request is deliberately performed only
	// after the management transaction is durable. If this step fails the
	// pending fence remains, and serve stays frozen for operator recovery.
	if t.target.control != nil && t.target.raft != nil {
		_, err := controlplane.Bootstrap(ctx, controlplane.StartupOptions{Profile: controlplane.StorageProfileProduction, ClusterID: t.target.candidate.Cluster.ClusterID, Machine: t.target.raft.Machine(), Durable: t.target.control, Consensus: t.target.raft, Fencer: t.target.raft, InitialState: t.target.initialState, InitialAuthorizer: t.target.authorizer})
		if err != nil {
			return errors.Join(setupmigration.ErrCommitOutcomeUnknown, err)
		}
	}
	if err := config.Save(t.target.configPath, t.target.candidate); err != nil {
		return errors.Join(setupmigration.ErrCommitOutcomeUnknown, err)
	}
	if err := removeCutoverArtifacts(t.target.dataDir, t.target.snapshotID, true); err != nil {
		return errors.Join(setupmigration.ErrCommitOutcomeUnknown, err)
	}
	return nil
}

func (t *runtimeProductionTransaction) Rollback(context.Context) error {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		if t.committed {
			return nil
		}
		return nil
	}
	t.closed = true
	if t.tx == nil {
		return nil
	}
	return t.tx.Rollback()
}

func managementSpec(name string) (managementTableSpec, bool) {
	for _, spec := range managementTableSpecs {
		if spec.name == name {
			return spec, true
		}
	}
	return managementTableSpec{}, false
}

func pgSnapshotValues(table snapshotTable, row []snapshotCell) ([]any, error) {
	values := make([]any, len(row))
	for i, cell := range row {
		value, err := cell.value()
		if err != nil {
			return nil, err
		}
		column := table.Columns[i]
		if value == nil {
			values[i] = nil
			continue
		}
		if column == "enable_ssl" || column == "waf_enabled" || column == "enabled" || column == "two_fa_enabled" || column == "is_read" || column == "is_pinned" {
			integer, ok := value.(int64)
			if !ok {
				return nil, errors.New("boolean snapshot value is invalid")
			}
			values[i] = integer != 0
			continue
		}
		if strings.HasSuffix(column, "_at") || column == "created_at" || column == "updated_at" {
			if text, ok := value.(string); ok {
				if text == "" {
					values[i] = nil
					continue
				}
				parsed, err := parseSnapshotTime(text)
				if err != nil {
					return nil, err
				}
				values[i] = parsed
				continue
			}
		}
		if column == "domains" || column == "upstreams" || column == "advanced" {
			text, ok := value.(string)
			if !ok || !json.Valid([]byte(text)) {
				return nil, errors.New("JSON snapshot value is invalid")
			}
			values[i] = text
			continue
		}
		values[i] = value
	}
	return values, nil
}

func parseSnapshotTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid timestamp in management snapshot")
	}
	return parsed.UTC(), nil
}

func pgPlaceholders(count int) string {
	parts := make([]string, count)
	for i := range parts {
		parts[i] = fmt.Sprintf("$%d", i+1)
	}
	return strings.Join(parts, ",")
}

func dependencyContext(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		return parent, func() {}
	}
	return context.WithTimeout(parent, timeout)
}

// Keep pgx in this package's module graph even when a build tag excludes the
// concrete integration path; this also ensures the stdlib driver is linked.
var _ = pgx.ErrNoRows
