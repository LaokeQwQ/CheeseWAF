package migration

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/approval"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane"
	setupmigration "github.com/LaokeQwQ/CheeseWAF/internal/setup/migration"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

const (
	recoveryRecordVersion      = 1
	recoveryRecordFileName     = "temporary-to-production.recovery.json"
	recoveryRecordMaxBytes     = 128 << 20
	maxRecoveryConfirmationAge = 5 * time.Minute
)

var (
	ErrCutoverLedger                  = errors.New("migration cutover ledger is unavailable")
	ErrCutoverAmbiguous               = errors.New("migration cutover state is ambiguous")
	ErrCutoverTokenMetadataUnverified = errors.New("migration cutover token metadata is unverified from a v1 ledger")
	ErrRecoveryConsumed               = errors.New("migration recovery confirmation was already consumed")
)

type RecoveryDirection string

const (
	RecoveryRollbackTemporary  RecoveryDirection = "rollback-temporary"
	RecoveryCompleteProduction RecoveryDirection = "complete-production"
)

type recoveryDialect string

const (
	recoveryDialectSQLite   recoveryDialect = "sqlite"
	recoveryDialectPostgres recoveryDialect = "postgres"
)

func verifyRecoveryCredential(ctx context.Context, db *sql.DB, dialect recoveryDialect, actor string, secret []byte, passwordMode bool, now time.Time) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if db == nil || approval.ValidateIdentifier(actor) != nil || len(secret) == 0 || (dialect != recoveryDialectSQLite && dialect != recoveryDialectPostgres) {
		return ErrCredentialRejected
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return ErrCredentialRejected
	}
	defer func() { _ = tx.Rollback() }()
	query := `SELECT password_hash,two_fa_enabled,two_fa_secret FROM users WHERE id=? AND role='admin'`
	if dialect == recoveryDialectPostgres {
		query = `SELECT password_hash,two_fa_enabled,two_fa_secret FROM users WHERE id=$1 AND role='admin'`
	}
	var passwordHash, totpSecret string
	var totpEnabled any
	if err := tx.QueryRowContext(ctx, query, actor).Scan(&passwordHash, &totpEnabled, &totpSecret); err != nil {
		return ErrCredentialRejected
	}
	if passwordMode {
		if bcrypt.CompareHashAndPassword([]byte(passwordHash), secret) != nil {
			return ErrCredentialRejected
		}
	} else {
		if !recoveryBool(totpEnabled) || totpSecret == "" {
			return ErrCredentialRejected
		}
		counter, ok := matchingMigrationTOTPCounter(totpSecret, string(secret), now)
		if !ok {
			return ErrCredentialRejected
		}
		var result sql.Result
		if dialect == recoveryDialectPostgres {
			result, err = tx.ExecContext(ctx, `INSERT INTO totp_consumed(user_id,counter,expires_at,created_at) VALUES($1,$2,$3,$4) ON CONFLICT(user_id,counter) DO UPDATE SET expires_at=EXCLUDED.expires_at,created_at=EXCLUDED.created_at WHERE totp_consumed.expires_at<=$5`, actor, counter, now.Add(migrationTOTPConsumedTTL).UTC(), now.UTC(), now.UTC())
		} else {
			formattedNow := now.UTC().Format(time.RFC3339Nano)
			result, err = tx.ExecContext(ctx, `INSERT INTO totp_consumed(user_id,counter,expires_at,created_at) VALUES(?,?,?,?) ON CONFLICT(user_id,counter) DO UPDATE SET expires_at=excluded.expires_at,created_at=excluded.created_at WHERE totp_consumed.expires_at<=?`, actor, counter, now.Add(migrationTOTPConsumedTTL).UTC().Format(time.RFC3339Nano), formattedNow, formattedNow)
		}
		if err != nil {
			return ErrCredentialRejected
		}
		affected, err := result.RowsAffected()
		if err != nil || affected != 1 {
			return ErrCredentialRejected
		}
	}
	if err := tx.Commit(); err != nil {
		return ErrCredentialRejected
	}
	return nil
}

func recoveryBool(value any) bool {
	switch typed := value.(type) {
	case bool:
		return typed
	case int64:
		return typed != 0
	case int:
		return typed != 0
	case []byte:
		return string(typed) == "1" || strings.EqualFold(string(typed), "true") || strings.EqualFold(string(typed), "t")
	case string:
		return typed == "1" || strings.EqualFold(typed, "true") || strings.EqualFold(typed, "t")
	default:
		return false
	}
}

type RecoveryPromptOptions struct {
	Actor          string
	Language       string
	ConfirmationID string
	Warning        string
	Now            func() time.Time
	Wait           func(context.Context, time.Duration) error
}

type RecoveryConfirmation struct {
	Actor              string
	Language           string
	Phrase             string
	ConfirmationID     string
	WarningReadAt      time.Time
	SecondConfirmation bool
}

func CollectRecoveryConfirmation(ctx context.Context, in io.Reader, out io.Writer, opts RecoveryPromptOptions) (RecoveryConfirmation, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if in == nil || out == nil || approval.ValidateIdentifier(opts.Actor) != nil || approval.ValidateIdentifier(opts.ConfirmationID) != nil || strings.TrimSpace(opts.Warning) == "" {
		return RecoveryConfirmation{}, ErrInvalidPromptOptions
	}
	language := opts.Language
	if language == "" {
		language = approval.DefaultConfirmationLanguage
	}
	language, err := approval.NormalizeConfirmationLanguage(language)
	if err != nil {
		return RecoveryConfirmation{}, fmt.Errorf("%w: language", ErrInvalidPromptOptions)
	}
	phrase, err := approval.ExpectedConfirmationPhrase(language)
	if err != nil {
		return RecoveryConfirmation{}, fmt.Errorf("%w: phrase", ErrInvalidPromptOptions)
	}
	wait := opts.Wait
	if wait == nil {
		wait = func(ctx context.Context, delay time.Duration) error {
			timer := time.NewTimer(delay)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-timer.C:
				return nil
			}
		}
	}
	if _, err := fmt.Fprintf(out, "WARNING: %s\nRead this warning for at least %s before continuing.\n", opts.Warning, setupmigration.WarningDelay); err != nil {
		return RecoveryConfirmation{}, err
	}
	if err := wait(ctx, setupmigration.WarningDelay); err != nil {
		return RecoveryConfirmation{}, err
	}
	reader, ok := in.(*bufio.Reader)
	if !ok {
		reader = bufio.NewReader(in)
	}
	if _, err := fmt.Fprintf(out, "Type %q to confirm recovery: ", phrase); err != nil {
		return RecoveryConfirmation{}, err
	}
	rawPhrase, err := readLine(reader)
	if err != nil {
		return RecoveryConfirmation{}, err
	}
	if rawPhrase != phrase {
		return RecoveryConfirmation{}, ErrConfirmationPhrase
	}
	if _, err := fmt.Fprint(out, "Type yes for the second recovery confirmation: "); err != nil {
		return RecoveryConfirmation{}, err
	}
	second, err := readLine(reader)
	if err != nil {
		return RecoveryConfirmation{}, err
	}
	if strings.ToLower(strings.TrimSpace(second)) != "yes" {
		return RecoveryConfirmation{}, ErrSecondConfirmation
	}
	now := time.Now().UTC()
	if opts.Now != nil {
		now = opts.Now().UTC()
	}
	return RecoveryConfirmation{Actor: opts.Actor, Language: language, Phrase: rawPhrase, ConfirmationID: opts.ConfirmationID, WarningReadAt: now.Add(-setupmigration.WarningDelay), SecondConfirmation: true}, nil
}

type cutoverLedgerEntry struct {
	SnapshotID         string
	ConfigDigest       string
	CandidateDigest    string
	InitialStateHash   string
	TokenDigest        string
	TokenMetadataState string
	Actor              string
	ConfirmationID     string
	ClusterID          string
	CommittedAt        time.Time
}

const (
	legacyTokenMetadataDigestSentinel = "0000000000000000000000000000000000000000000000000000000000000000"
	tokenMetadataVerified             = "verified"
	tokenMetadataUnverifiedV1         = "unverified-v1"
)

func insertCutoverLedger(ctx context.Context, tx *sql.Tx, entry cutoverLedgerEntry) error {
	if tx == nil || validateCutoverLedgerEntry(entry) != nil {
		return ErrCutoverLedger
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO cheesewaf_migration_cutovers(snapshot_id,config_digest,candidate_digest,initial_state_hash,token_metadata_digest,actor_id,confirmation_id,cluster_id,committed_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, entry.SnapshotID, entry.ConfigDigest, entry.CandidateDigest, entry.InitialStateHash, entry.TokenDigest, entry.Actor, entry.ConfirmationID, entry.ClusterID, entry.CommittedAt.UTC())
	if err != nil {
		return fmt.Errorf("%w: insert commit evidence", ErrCutoverLedger)
	}
	return nil
}

func readCutoverLedger(ctx context.Context, db *sql.DB, snapshotID string) (cutoverLedgerEntry, error) {
	if db == nil || approval.ValidateIdentifier(snapshotID) != nil {
		return cutoverLedgerEntry{}, ErrCutoverLedger
	}
	return readCutoverLedgerFrom(ctx, db, snapshotID)
}

type cutoverLedgerReader interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func readCutoverLedgerFrom(ctx context.Context, reader cutoverLedgerReader, snapshotID string) (cutoverLedgerEntry, error) {
	if reader == nil || approval.ValidateIdentifier(snapshotID) != nil {
		return cutoverLedgerEntry{}, ErrCutoverLedger
	}
	var entry cutoverLedgerEntry
	err := reader.QueryRowContext(ctx, `SELECT snapshot_id,config_digest,candidate_digest,initial_state_hash,token_metadata_digest,actor_id,confirmation_id,cluster_id,committed_at FROM cheesewaf_migration_cutovers WHERE snapshot_id=$1`, snapshotID).Scan(&entry.SnapshotID, &entry.ConfigDigest, &entry.CandidateDigest, &entry.InitialStateHash, &entry.TokenDigest, &entry.Actor, &entry.ConfirmationID, &entry.ClusterID, &entry.CommittedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return cutoverLedgerEntry{}, sql.ErrNoRows
	}
	if err != nil || validateCutoverLedgerEntry(entry) != nil {
		return cutoverLedgerEntry{}, ErrCutoverLedger
	}
	entry.TokenMetadataState = tokenMetadataVerified
	if entry.TokenDigest == legacyTokenMetadataDigestSentinel {
		entry.TokenMetadataState = tokenMetadataUnverifiedV1
	}
	return entry, nil
}

func validateCutoverLedgerEntry(entry cutoverLedgerEntry) error {
	if approval.ValidateIdentifier(entry.SnapshotID) != nil || approval.ValidateIdentifier(entry.Actor) != nil || approval.ValidateIdentifier(entry.ConfirmationID) != nil || approval.ValidateIdentifier(entry.ClusterID) != nil || entry.CommittedAt.IsZero() {
		return ErrCutoverLedger
	}
	if !validRecoveryDigest(entry.ConfigDigest) || !validRecoveryDigest(entry.CandidateDigest) || !validRecoveryDigest(entry.InitialStateHash) || !validRecoveryDigest(entry.TokenDigest) {
		return ErrCutoverLedger
	}
	return nil
}

func ledgerEntryForRecoveryRecord(record recoveryRecord, committedAt time.Time) cutoverLedgerEntry {
	return cutoverLedgerEntry{
		SnapshotID: record.Snapshot.ID, ConfigDigest: record.Snapshot.ConfigDigest,
		CandidateDigest: record.CandidateDigest, InitialStateHash: record.InitialStateHash, TokenDigest: digestBytes(record.Snapshot.TokenMetadata),
		Actor: record.Actor, ConfirmationID: record.ConfirmationID, ClusterID: record.ClusterID,
		CommittedAt: committedAt.UTC(),
	}
}

func validateRecoveryDirectionFence(direction RecoveryDirection, phase cutoverFencePhase) error {
	if direction != RecoveryRollbackTemporary && direction != RecoveryCompleteProduction {
		return ErrCutoverAmbiguous
	}
	if phase != cutoverFencePending && phase != cutoverFenceCommitAttempted {
		return ErrCutoverAmbiguous
	}
	// The local phase marker is diagnostic evidence only. A process can die
	// after publishing commit-attempted but before calling PostgreSQL Commit,
	// or after PostgreSQL commits while a stale local marker remains. Recovery
	// direction is therefore derived from the ledger and exact table contents,
	// never vetoed by the weaker local marker.
	return nil
}

func classifyCutoverState(ctx context.Context, db *sql.DB, record recoveryRecord) (RecoveryDirection, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if db == nil || validateRecoveryRecord(record) != nil {
		return "", ErrCutoverAmbiguous
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelSerializable})
	if err != nil {
		return "", ErrCutoverAmbiguous
	}
	defer func() { _ = tx.Rollback() }()
	entry, err := readCutoverLedgerFrom(ctx, tx, record.Snapshot.ID)
	if err == nil {
		if entry.TokenMetadataState != tokenMetadataVerified {
			return "", errors.Join(ErrCutoverAmbiguous, ErrCutoverTokenMetadataUnverified)
		}
		if !ledgerMatchesRecoveryRecord(entry, record) {
			return "", ErrCutoverAmbiguous
		}
		matches, verifyErr := productionManagementMatchesSnapshotTx(ctx, tx, record.Snapshot.ManagementState)
		if verifyErr != nil || !matches {
			return "", ErrCutoverAmbiguous
		}
		tokensMatch, verifyErr := verifyLegacyTokenMetadataTx(ctx, tx, record.Snapshot.ID, record.Actor, record.Snapshot.TokenMetadata)
		if verifyErr != nil || !tokensMatch {
			return "", ErrCutoverAmbiguous
		}
		if err := tx.Commit(); err != nil {
			return "", ErrCutoverAmbiguous
		}
		return RecoveryCompleteProduction, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", ErrCutoverAmbiguous
	}
	empty, err := productionManagementEmptyTx(ctx, tx)
	if err != nil || !empty {
		return "", ErrCutoverAmbiguous
	}
	metadataEmpty, err := productionMigrationMetadataEmptyTx(ctx, tx)
	if err != nil || !metadataEmpty {
		return "", ErrCutoverAmbiguous
	}
	if err := tx.Commit(); err != nil {
		return "", ErrCutoverAmbiguous
	}
	return RecoveryRollbackTemporary, nil
}

func ledgerMatchesRecoveryRecord(entry cutoverLedgerEntry, record recoveryRecord) bool {
	return entry.SnapshotID == record.Snapshot.ID && entry.ConfigDigest == record.Snapshot.ConfigDigest &&
		entry.CandidateDigest == record.CandidateDigest && entry.InitialStateHash == record.InitialStateHash &&
		entry.TokenDigest == digestBytes(record.Snapshot.TokenMetadata) &&
		entry.Actor == record.Actor && entry.ConfirmationID == record.ConfirmationID && entry.ClusterID == record.ClusterID
}

func productionManagementEmpty(ctx context.Context, db *sql.DB) (bool, error) {
	if db == nil {
		return false, ErrCutoverAmbiguous
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelSerializable})
	if err != nil {
		return false, ErrCutoverAmbiguous
	}
	defer func() { _ = tx.Rollback() }()
	empty, err := productionManagementEmptyTx(ctx, tx)
	if err != nil || !empty {
		return empty, err
	}
	if err := tx.Commit(); err != nil {
		return false, ErrCutoverAmbiguous
	}
	return true, nil
}

func productionManagementEmptyTx(ctx context.Context, tx *sql.Tx) (bool, error) {
	if tx == nil {
		return false, ErrCutoverAmbiguous
	}
	for _, spec := range managementTableSpecs {
		if !spec.importToPG {
			continue
		}
		var count int64
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(1) FROM `+spec.name).Scan(&count); err != nil {
			return false, ErrCutoverAmbiguous
		}
		if count != 0 {
			return false, nil
		}
	}
	return true, nil
}

func productionMigrationMetadataEmptyTx(ctx context.Context, tx *sql.Tx) (bool, error) {
	if tx == nil {
		return false, ErrCutoverAmbiguous
	}
	for _, table := range []string{"cheesewaf_migration_cutovers", "cheesewaf_migration_legacy_tokens"} {
		var count int64
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(1) FROM `+table).Scan(&count); err != nil {
			return false, ErrCutoverAmbiguous
		}
		if count != 0 {
			return false, nil
		}
	}
	return true, nil
}

// recoveryRecord contains the minimum local material needed to restore the
// temporary last-known-good state or finish a production cutover. It is a
// transient, owner-only runtime artifact and may contain credential hashes or
// configured provider secrets; callers must never log or export it.
type recoveryRecord struct {
	Version          int                     `json:"version"`
	Snapshot         setupmigration.Snapshot `json:"snapshot"`
	Candidate        []byte                  `json:"candidate"`
	CandidateDigest  string                  `json:"candidate_digest"`
	InitialState     []byte                  `json:"initial_state"`
	Actor            string                  `json:"actor"`
	ConfirmationID   string                  `json:"confirmation_id"`
	ClusterID        string                  `json:"cluster_id"`
	InitialStateHash string                  `json:"initial_state_hash"`
	CreatedAt        time.Time               `json:"created_at"`
}

type migrationInitialState struct {
	SchemaVersion     string `json:"schema_version"`
	ConfigDigest      string `json:"config_digest"`
	Profile           string `json:"profile"`
	ClusterID         string `json:"cluster_id"`
	NodeID            string `json:"node_id"`
	ManagementBackend string `json:"management_backend"`
	ControlBackend    string `json:"control_backend"`
	ConsensusBackend  string `json:"consensus_backend"`
	RedisInstanceID   string `json:"redis_instance_id"`
}

const migrationInitialStateSchema = "cheesewaf-migration-initial-state.v1"

// encodeRecoveryPayloads deliberately produces two representations. The
// owner-only YAML record keeps operational secrets needed to reopen production
// dependencies. The control-plane JSON follows Config's public JSON contract,
// which excludes management/control PostgreSQL DSNs.
func encodeRecoveryPayloads(candidate *config.Config) ([]byte, []byte, error) {
	if candidate == nil || candidate.Storage.Profile != config.StorageProfileProduction {
		return nil, nil, ErrRuntimeConfiguration
	}
	privateConfig, err := yaml.Marshal(candidate)
	if err != nil {
		return nil, nil, ErrRuntimeConfiguration
	}
	initialState, err := json.Marshal(migrationInitialState{
		SchemaVersion: migrationInitialStateSchema, ConfigDigest: digestBytes(privateConfig),
		Profile: config.StorageProfileProduction, ClusterID: candidate.Cluster.ClusterID, NodeID: candidate.Cluster.NodeID,
		ManagementBackend: "postgresql", ControlBackend: "postgresql",
		ConsensusBackend: controlplane.ConsensusBackendNativeRaft, RedisInstanceID: candidate.Storage.Redis.InstanceID,
	})
	if err != nil {
		return nil, nil, ErrRuntimeConfiguration
	}
	if _, err := decodeRecoveryCandidate(privateConfig); err != nil {
		return nil, nil, ErrRuntimeConfiguration
	}
	if _, err := decodeMigrationInitialState(initialState, candidate, digestBytes(privateConfig)); err != nil {
		return nil, nil, err
	}
	return privateConfig, initialState, nil
}

func decodeMigrationInitialState(raw []byte, candidate *config.Config, candidateDigest string) (migrationInitialState, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var state migrationInitialState
	if err := decoder.Decode(&state); err != nil {
		return migrationInitialState{}, ErrRuntimeConfiguration
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return migrationInitialState{}, ErrRuntimeConfiguration
	}
	if candidate == nil || state.SchemaVersion != migrationInitialStateSchema || state.ConfigDigest != candidateDigest ||
		state.Profile != config.StorageProfileProduction || state.ClusterID != candidate.Cluster.ClusterID || state.NodeID != candidate.Cluster.NodeID ||
		state.ManagementBackend != "postgresql" || state.ControlBackend != "postgresql" || state.ConsensusBackend != controlplane.ConsensusBackendNativeRaft ||
		state.RedisInstanceID != candidate.Storage.Redis.InstanceID || !controlplane.ValidIdentity(state.ClusterID) ||
		(state.NodeID != "" && !controlplane.ValidIdentity(state.NodeID)) || !controlplane.ValidIdentity(state.RedisInstanceID) {
		return migrationInitialState{}, ErrRuntimeConfiguration
	}
	return state, nil
}

func decodeRecoveryCandidate(raw []byte) (*config.Config, error) {
	if len(raw) == 0 || len(raw) > config.MaxConfigFileBytes {
		return nil, ErrRuntimeConfiguration
	}
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	decoder.KnownFields(true)
	var candidate config.Config
	if err := decoder.Decode(&candidate); err != nil {
		return nil, ErrRuntimeConfiguration
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, ErrRuntimeConfiguration
	}
	if err := validateRecoveryCandidateLocal(&candidate); err != nil {
		return nil, ErrRuntimeConfiguration
	}
	return &candidate, nil
}

// validateRecoveryCandidateLocal validates only the fields required to reopen
// migration dependencies. It must stay free of DNS, HTTP and other egress:
// startup calls readRecoveryRecord solely to fail closed on pending recovery.
func validateRecoveryCandidateLocal(candidate *config.Config) error {
	if candidate == nil || candidate.Storage.Profile != config.StorageProfileProduction {
		return ErrRuntimeConfiguration
	}
	if err := config.ValidateStorageProfile(candidate); err != nil || candidate.Storage.Profile != config.StorageProfileProduction {
		return ErrRuntimeConfiguration
	}
	if candidate.Cluster.NodeID != "" && !controlplane.ValidIdentity(candidate.Cluster.NodeID) {
		return ErrRuntimeConfiguration
	}
	if strings.TrimSpace(candidate.Setup.DataDir) == "" || strings.TrimSpace(candidate.Setup.RuntimeDir) == "" {
		return ErrRuntimeConfiguration
	}
	raft := candidate.Cluster.Consensus.NativeRaft
	if strings.TrimSpace(raft.DataDir) == "" || (raft.Mode != "bootstrap" && raft.Mode != "join") {
		return ErrRuntimeConfiguration
	}
	if err := validateRecoveryHostPort(raft.Listen); err != nil {
		return err
	}
	if err := validateRecoveryHostPort(candidate.Storage.Redis.Address); err != nil {
		return err
	}
	return nil
}

func validateRecoveryHostPort(address string) error {
	host, port, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil || strings.TrimSpace(host) == "" || strings.TrimSpace(port) == "" {
		return ErrRuntimeConfiguration
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return ErrRuntimeConfiguration
	}
	return nil
}

func writeRecoveryRecord(dataDir string, record recoveryRecord) error {
	if err := validateRecoveryRecord(record); err != nil {
		return err
	}
	path, err := recoveryRecordPath(dataDir)
	if err != nil {
		return err
	}
	if err := secureRecoveryDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	if _, err := os.Lstat(path); err == nil {
		return ErrCutoverPending
	} else if !errors.Is(err, os.ErrNotExist) {
		return ErrCutoverPending
	}
	raw, err := json.Marshal(record)
	if err != nil {
		return ErrCutoverPending
	}
	if len(raw)+1 > recoveryRecordMaxBytes {
		return ErrCutoverPending
	}
	raw = append(raw, '\n')
	if err := writePrivateFileAtomic(path, raw, 0o600); err != nil {
		return fmt.Errorf("write migration recovery record: %w", err)
	}
	return nil
}

func prepareCutoverArtifacts(dataDir string, record recoveryRecord, now time.Time) error {
	if err := writeRecoveryRecord(dataDir, record); err != nil {
		return err
	}
	if err := createCutoverFence(dataDir, record.Snapshot.ID, record.Snapshot.ConfigDigest, now); err != nil {
		// The recovery record is the recoverable source of truth and is written
		// first. Keep it if marker publication fails: startup still fails closed
		// because CheckPendingCutover also detects the record, and `migration
		// recover` can classify the actual PostgreSQL state without guessing from
		// a partially created marker.
		return err
	}
	return nil
}

func removeCutoverArtifacts(dataDir, snapshotID string, committed bool) error {
	if err := removeCutoverFence(dataDir, snapshotID, committed); err != nil {
		return err
	}
	return removeRecoveryRecord(dataDir, snapshotID)
}

func readRecoveryRecord(dataDir string) (recoveryRecord, error) {
	path, err := recoveryRecordPath(dataDir)
	if err != nil {
		return recoveryRecord{}, err
	}
	directory := filepath.Dir(path)
	if _, err := os.Lstat(directory); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return recoveryRecord{}, os.ErrNotExist
		}
		return recoveryRecord{}, ErrCutoverPending
	}
	if err := validateRecoveryDirectory(directory); err != nil {
		return recoveryRecord{}, ErrCutoverPending
	}
	info, err := os.Lstat(path)
	if err != nil {
		return recoveryRecord{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() <= 0 || info.Size() > recoveryRecordMaxBytes {
		return recoveryRecord{}, ErrCutoverPending
	}
	file, err := os.Open(path)
	if err != nil {
		return recoveryRecord{}, ErrCutoverPending
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, recoveryRecordMaxBytes+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(raw) > recoveryRecordMaxBytes {
		return recoveryRecord{}, ErrCutoverPending
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var record recoveryRecord
	if err := decoder.Decode(&record); err != nil {
		return recoveryRecord{}, ErrCutoverPending
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return recoveryRecord{}, ErrCutoverPending
	}
	if err := validateRecoveryRecord(record); err != nil {
		return recoveryRecord{}, ErrCutoverPending
	}
	return record, nil
}

func secureRecoveryDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("create migration recovery directory: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return ErrCutoverPending
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return fmt.Errorf("protect migration recovery directory: %w", err)
	}
	return validateRecoveryDirectory(path)
}

func validateRecoveryDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return ErrCutoverPending
	}
	return nil
}

func removeRecoveryRecord(dataDir, snapshotID string) error {
	if approval.ValidateIdentifier(snapshotID) != nil {
		return ErrCutoverPending
	}
	record, err := readRecoveryRecord(dataDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || record.Snapshot.ID != snapshotID {
		return ErrCutoverPending
	}
	path, err := recoveryRecordPath(dataDir)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if dir, openErr := os.Open(filepath.Dir(path)); openErr == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}

func recoveryRecordPath(dataDir string) (string, error) {
	if dataDir == "" {
		return "", ErrRuntimeConfiguration
	}
	abs, err := filepath.Abs(dataDir)
	if err != nil {
		return "", ErrRuntimeConfiguration
	}
	return filepath.Join(filepath.Clean(abs), "migration", recoveryRecordFileName), nil
}

func validateRecoveryRecord(record recoveryRecord) error {
	if record.Version != recoveryRecordVersion || approval.ValidateIdentifier(record.Snapshot.ID) != nil || approval.ValidateIdentifier(record.Actor) != nil || approval.ValidateIdentifier(record.ConfirmationID) != nil || approval.ValidateIdentifier(record.ClusterID) != nil || record.CreatedAt.IsZero() {
		return ErrCutoverPending
	}
	if !validRecoveryDigest(record.Snapshot.ConfigDigest) || !validRecoveryDigest(record.CandidateDigest) || !validRecoveryDigest(record.InitialStateHash) {
		return ErrCutoverPending
	}
	if digestBytes(record.Candidate) != record.CandidateDigest {
		return ErrCutoverPending
	}
	candidate, err := decodeRecoveryCandidate(record.Candidate)
	if err != nil || digestBytes(record.InitialState) != record.InitialStateHash {
		return ErrCutoverPending
	}
	if _, err := decodeMigrationInitialState(record.InitialState, candidate, record.CandidateDigest); err != nil {
		return ErrCutoverPending
	}
	if _, err := decodeLegacyTokenMetadata(record.Snapshot.TokenMetadata); err != nil {
		return ErrCutoverPending
	}
	if len(record.Snapshot.ManagementState)+len(record.Snapshot.TokenMetadata)+len(record.Candidate)+len(record.InitialState) > recoveryRecordMaxBytes {
		return ErrCutoverPending
	}
	return nil
}

func validRecoveryDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && hex.EncodeToString(decoded) == value
}
