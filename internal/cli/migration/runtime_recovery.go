package migration

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/approval"
	"github.com/LaokeQwQ/CheeseWAF/internal/cluster/redis"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane"
	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane/nativeraft"
	controlpostgres "github.com/LaokeQwQ/CheeseWAF/internal/controlplane/postgres"
	setupmigration "github.com/LaokeQwQ/CheeseWAF/internal/setup/migration"
	storagepostgres "github.com/LaokeQwQ/CheeseWAF/internal/storage/postgres"
)

type runtimeRecoveryResources struct {
	management *storagepostgres.Store
	sqlite     *sql.DB
	control    *controlpostgres.Store
	raft       *nativeraft.Runtime
	redis      *redis.RuntimeAdapter
	once       sync.Once
	err        error
}

func (r *runtimeRecoveryResources) Close() error {
	if r == nil {
		return nil
	}
	r.once.Do(func() {
		closeOne := func(close func() error) {
			if close == nil {
				return
			}
			if err := close(); err != nil && r.err == nil {
				r.err = err
			}
		}
		if r.redis != nil {
			closeOne(r.redis.Close)
		}
		if r.raft != nil {
			closeOne(r.raft.Close)
		}
		if r.control != nil {
			closeOne(r.control.Close)
		}
		if r.sqlite != nil {
			closeOne(r.sqlite.Close)
		}
		if r.management != nil {
			closeOne(r.management.Close)
		}
	})
	return r.err
}

type runtimeRecoveryPlan struct {
	direction  RecoveryDirection
	record     recoveryRecord
	configPath string
	dataDir    string
	now        func() time.Time

	managementDB *sql.DB
	source       *runtimeTemporarySource
	candidate    *config.Config
	control      controlplane.DurableBootstrap
	raft         recoveryConsensus
	redis        recoveryHealth
	recoverMu    sync.Mutex
	consumed     bool
}

type recoveryConsensus interface {
	controlplane.ConsensusBootstrap
	controlplane.FenceBootstrap
	controlplane.LeadershipCheckpointStore
	Machine() *controlplane.StateMachine
}

type recoveryHealth interface {
	Ping(context.Context) error
}

func (p *runtimeRecoveryPlan) Direction() RecoveryDirection {
	if p == nil {
		return ""
	}
	return p.direction
}

func (p *runtimeRecoveryPlan) Recover(ctx context.Context, confirmation RecoveryConfirmation) error {
	if p == nil || validateRecoveryConfirmation(confirmation, p.record, runtimeNow(p.now)) != nil {
		return setupmigration.ErrConfirmationRejected
	}
	p.recoverMu.Lock()
	if p.consumed {
		p.recoverMu.Unlock()
		return ErrRecoveryConsumed
	}
	p.consumed = true
	p.recoverMu.Unlock()
	if ctx == nil {
		ctx = context.Background()
	}
	direction, err := classifyCutoverState(ctx, p.managementDB, p.record)
	if err != nil || direction != p.direction {
		return ErrCutoverAmbiguous
	}
	switch p.direction {
	case RecoveryRollbackTemporary:
		if p.source == nil {
			return ErrCutoverAmbiguous
		}
		return p.source.RestoreTemporaryState(ctx, p.record.Snapshot, setupmigration.InvalidationReceipt{Sessions: true, Setup: true, Join: true, CAPTCHA: true, Locks: true})
	case RecoveryCompleteProduction:
		return p.completeProduction(ctx, confirmation)
	default:
		return ErrCutoverAmbiguous
	}
}

func (p *runtimeRecoveryPlan) completeProduction(ctx context.Context, confirmation RecoveryConfirmation) error {
	if p.candidate == nil || p.control == nil || p.raft == nil || p.redis == nil {
		return ErrCutoverAmbiguous
	}
	if err := p.redis.Ping(ctx); err != nil {
		return setupmigration.ErrPrerequisiteUnavailable
	}
	request := &controlplane.InitialStateRequest{
		Version: "cheesewaf-config-v1", Payload: append([]byte(nil), p.record.InitialState...),
		Digest: p.record.InitialStateHash, Nonce: p.record.ConfirmationID,
		Confirmation: controlplane.InitialStateConfirmation{ID: p.record.ConfirmationID, Actor: p.record.Actor, Reason: "recover temporary-to-production migration"},
	}
	authorizer := recoveryInitialStateAuthorizer{record: p.record, confirmation: confirmation, now: p.now}
	if _, err := controlplane.Bootstrap(ctx, controlplane.StartupOptions{
		Profile: controlplane.StorageProfileProduction, ClusterID: p.record.ClusterID,
		Machine: p.raft.Machine(), Durable: p.control, Consensus: p.raft, Fencer: p.raft,
		InitialState: request, InitialAuthorizer: authorizer, LeadershipCheckpoint: p.raft,
	}); err != nil {
		return errors.Join(setupmigration.ErrCommitOutcomeUnknown, err)
	}
	if err := config.Save(p.configPath, p.candidate); err != nil {
		return errors.Join(setupmigration.ErrCommitOutcomeUnknown, err)
	}
	persistedRaw, err := os.ReadFile(p.configPath)
	if err != nil {
		return errors.Join(setupmigration.ErrCommitOutcomeUnknown, err)
	}
	persisted, err := decodeRecoveryRuntimeConfig(persistedRaw)
	if err != nil || persisted.Storage.Profile != config.StorageProfileProduction {
		return errors.Join(setupmigration.ErrCommitOutcomeUnknown, ErrRuntimeConfiguration)
	}
	if err := removeCutoverArtifacts(p.dataDir, p.record.Snapshot.ID, true); err != nil {
		return errors.Join(setupmigration.ErrCommitOutcomeUnknown, err)
	}
	return nil
}

type recoveryInitialStateAuthorizer struct {
	record       recoveryRecord
	confirmation RecoveryConfirmation
	now          func() time.Time
}

func (a recoveryInitialStateAuthorizer) AuthorizeInitialState(_ context.Context, request controlplane.InitialStateRequest) error {
	if validateRecoveryConfirmation(a.confirmation, a.record, runtimeNow(a.now)) != nil ||
		request.Nonce != a.record.ConfirmationID || request.Confirmation.ID != a.record.ConfirmationID ||
		request.Confirmation.Actor != a.record.Actor || request.Digest != a.record.InitialStateHash ||
		digestBytes(request.Payload) != a.record.InitialStateHash || string(request.Payload) != string(a.record.InitialState) {
		return setupmigration.ErrConfirmationRejected
	}
	return nil
}

func validateRecoveryConfirmation(confirmation RecoveryConfirmation, record recoveryRecord, now time.Time) error {
	age := now.Sub(confirmation.WarningReadAt)
	if confirmation.Actor != record.Actor || approvalIdentifierInvalid(confirmation.ConfirmationID) || confirmation.WarningReadAt.IsZero() || confirmation.WarningReadAt.After(now) || age < setupmigration.WarningDelay || age > maxRecoveryConfirmationAge || !confirmation.SecondConfirmation {
		return setupmigration.ErrConfirmationRejected
	}
	language, err := normalizeRecoveryLanguage(confirmation.Language)
	if err != nil || language != confirmation.Language {
		return setupmigration.ErrConfirmationRejected
	}
	phrase, err := expectedRecoveryPhrase(language)
	if err != nil || confirmation.Phrase != phrase {
		return setupmigration.ErrConfirmationRejected
	}
	return nil
}

// These wrappers keep the runtime recovery file focused while preserving the
// same exact language/identifier contracts as the ordinary migration prompt.
func approvalIdentifierInvalid(value string) bool { return strictIdentity(value) != nil }
func normalizeRecoveryLanguage(value string) (string, error) {
	return approval.NormalizeConfirmationLanguage(value)
}
func expectedRecoveryPhrase(language string) (string, error) {
	return approval.ExpectedConfirmationPhrase(language)
}

func buildRuntimeRecovery(ctx context.Context, request runtimeRecoveryBuildRequest) (RuntimeRecoveryPlan, io.Closer, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if request.Current == nil || request.RuntimeConfig == nil || request.ConfigPath == "" || request.DataDir == "" || validateRecoveryRecord(request.Record) != nil || request.Actor != request.Record.Actor || len(request.Secret) == 0 {
		return nil, nil, ErrRuntimeConfiguration
	}
	persistedCandidate, err := decodeRecoveryCandidate(request.Record.Candidate)
	if err != nil {
		return nil, nil, ErrRuntimeConfiguration
	}
	runtimeCandidate, err := config.Clone(persistedCandidate)
	if err != nil {
		return nil, nil, err
	}
	if request.ApplyDataDir != nil {
		if err := request.ApplyDataDir(runtimeCandidate, request.DataDir); err != nil {
			return nil, nil, err
		}
	}
	managementDB, err := sql.Open("pgx", runtimeCandidate.Storage.ManagementPostgreSQL.DSN)
	if err != nil {
		return nil, nil, setupmigration.ErrPrerequisiteUnavailable
	}
	management, err := storagepostgres.New(managementDB)
	if err != nil {
		_ = managementDB.Close()
		return nil, nil, err
	}
	resources := &runtimeRecoveryResources{management: management}
	fail := func(err error) (RuntimeRecoveryPlan, io.Closer, error) {
		_ = resources.Close()
		return nil, nil, err
	}
	managementCtx, cancelManagement := dependencyContext(ctx, runtimeCandidate.Storage.ManagementPostgreSQL.Timeout)
	defer cancelManagement()
	if err := management.Migrate(managementCtx); err != nil || management.Health(managementCtx) != nil {
		return fail(setupmigration.ErrPrerequisiteUnavailable)
	}
	direction, err := classifyCutoverState(ctx, managementDB, request.Record)
	if err != nil {
		return fail(err)
	}
	plan := &runtimeRecoveryPlan{direction: direction, record: request.Record, configPath: request.ConfigPath, dataDir: request.DataDir, now: request.Now, managementDB: managementDB, candidate: persistedCandidate}
	if direction == RecoveryRollbackTemporary {
		sqlite, err := openMigratedSQLite(ctx, request.RuntimeConfig.Storage.SQLite.Path)
		if err != nil {
			return fail(err)
		}
		resources.sqlite = sqlite
		if err := verifyRecoveryCredential(ctx, sqlite, recoveryDialectSQLite, request.Actor, request.Secret, request.PasswordMode, runtimeNow(request.Now)); err != nil {
			return fail(err)
		}
		plan.source = &runtimeTemporarySource{db: sqlite, profile: setupmigration.TemporaryProfile, configPath: request.ConfigPath, dataDir: request.DataDir, expectedDigest: request.Record.Snapshot.ConfigDigest, currentSnapshot: cloneMigrationSnapshot(request.Record.Snapshot)}
		return plan, resources, nil
	}
	if direction != RecoveryCompleteProduction {
		return fail(ErrCutoverAmbiguous)
	}
	if err := verifyRecoveryCredential(ctx, managementDB, recoveryDialectPostgres, request.Actor, request.Secret, request.PasswordMode, runtimeNow(request.Now)); err != nil {
		return fail(err)
	}
	controlDB, err := sql.Open("pgx", strings.TrimSpace(runtimeCandidate.Storage.ControlPostgreSQL.DSN))
	if err != nil {
		return fail(setupmigration.ErrPrerequisiteUnavailable)
	}
	control, err := controlpostgres.New(controlDB)
	if err != nil {
		_ = controlDB.Close()
		return fail(err)
	}
	resources.control = control
	controlCtx, cancelControl := dependencyContext(ctx, runtimeCandidate.Storage.ControlPostgreSQL.Timeout)
	if err := control.Prepare(controlCtx); err != nil || control.Health(controlCtx) != nil {
		cancelControl()
		return fail(setupmigration.ErrPrerequisiteUnavailable)
	}
	cancelControl()
	raftOptions, err := nativeRaftOptionsFromConfig(runtimeCandidate)
	if err != nil {
		return fail(err)
	}
	raft, err := nativeraft.New(raftOptions)
	if err != nil {
		return fail(setupmigration.ErrPrerequisiteUnavailable)
	}
	resources.raft = raft
	if err := raft.Prepare(ctx); err != nil || raft.Health(ctx) != nil {
		return fail(setupmigration.ErrPrerequisiteUnavailable)
	}
	redisCfg := redis.Config{Addr: runtimeCandidate.Storage.Redis.Address, InstanceID: runtimeCandidate.Storage.Redis.InstanceID, DialTimeout: runtimeCandidate.Storage.ManagementPostgreSQL.Timeout}
	if !runtimeCandidate.Storage.Redis.Enabled || strings.TrimSpace(redisCfg.Addr) == "" || strings.TrimSpace(redisCfg.InstanceID) == "" {
		return fail(setupmigration.ErrPrerequisiteUnavailable)
	}
	redisAdapter, err := redis.Open(ctx, redisCfg)
	if err != nil || redisAdapter.Ping(ctx) != nil {
		if redisAdapter != nil {
			_ = redisAdapter.Close()
		}
		return fail(setupmigration.ErrPrerequisiteUnavailable)
	}
	resources.redis = redisAdapter
	plan.control, plan.raft, plan.redis = control, raft, redisAdapter
	return plan, resources, nil
}
