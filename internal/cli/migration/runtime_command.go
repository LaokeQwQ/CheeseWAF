package migration

import (
	"bufio"
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/approval"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	setupmigration "github.com/LaokeQwQ/CheeseWAF/internal/setup/migration"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
	"github.com/spf13/cobra"
)

const maxCredentialBytes = 4096

var (
	ErrRuntimeConfiguration = errors.New("migration runtime configuration is invalid")
	ErrRuntimeConfigCopy    = errors.New("migration requires a runtime configuration copy")
	ErrCredentialMode       = errors.New("exactly one credential stdin mode is required")
	ErrCredentialRejected   = errors.New("administrator credential or session was rejected")
	ErrCutoverPending       = errors.New("a temporary-to-production cutover is pending recovery")
)

// RuntimeOptions wires the root CLI to process-owned paths and its exclusive
// service lease. Functions are evaluated after Cobra parses persistent flags.
type RuntimeOptions struct {
	ConfigPath       func() string
	DataDir          func() string
	ApplyDataDir     func(*config.Config, string) error
	AcquireExclusive func(string) (io.Closer, error)
	Now              func() time.Time
	Random           io.Reader
	Wait             func(context.Context, time.Duration) error

	buildRunner   runtimeRunnerBuilder
	buildRecovery runtimeRecoveryBuilder
}

type runtimeRunnerBuilder func(context.Context, runtimeBuildRequest) (Runner, io.Closer, error)

type runtimeRecoveryBuilder func(context.Context, runtimeRecoveryBuildRequest) (RuntimeRecoveryPlan, io.Closer, error)

type RuntimeRecoveryPlan interface {
	Direction() RecoveryDirection
	Recover(context.Context, RecoveryConfirmation) error
}

type runtimeRecoveryBuildRequest struct {
	ConfigPath    string
	DataDir       string
	Current       *config.Config
	RuntimeConfig *config.Config
	Record        recoveryRecord
	Actor         string
	Secret        []byte
	PasswordMode  bool
	Now           func() time.Time
	ApplyDataDir  func(*config.Config, string) error
}

type runtimeBuildRequest struct {
	ConfigPath     string
	Config         *config.Config
	RuntimeConfig  *config.Config
	Candidate      *config.Config
	SQLite         *sql.DB
	Authorization  credentialAuthorization
	ConfirmationID string
	Now            func() time.Time
}

type runtimeFlags struct {
	actor         string
	sessionID     string
	language      string
	passwordStdin bool
	totpStdin     bool
}

// NewRuntimeCommand returns the production command tree exposed as
// `cheesewaf migration temporary-to-production`.
func NewRuntimeCommand(opts RuntimeOptions) *cobra.Command {
	parent := &cobra.Command{
		Use:   "migration",
		Short: "Manage protected storage-profile migrations",
		Args:  cobra.NoArgs,
	}
	flags := runtimeFlags{language: approval.DefaultConfirmationLanguage}
	leaf := &cobra.Command{
		Use:   "temporary-to-production",
		Short: "Migrate temporary management state to production storage",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runRuntimeCommand(cmd, opts, flags)
		},
	}
	leaf.Flags().StringVar(&flags.actor, "actor", "", "immutable administrator user ID")
	leaf.Flags().StringVar(&flags.sessionID, "session-id", "", "active local administrator session ID")
	leaf.Flags().StringVar(&flags.language, "language", approval.DefaultConfirmationLanguage, "confirmation language")
	leaf.Flags().BoolVar(&flags.passwordStdin, "password-stdin", false, "read the administrator password from the first stdin line")
	leaf.Flags().BoolVar(&flags.totpStdin, "totp-stdin", false, "read the administrator TOTP code from the first stdin line")
	parent.AddCommand(leaf)
	recoveryFlags := runtimeFlags{language: approval.DefaultConfirmationLanguage}
	recover := &cobra.Command{
		Use:   "recover",
		Short: "Recover an interrupted temporary-to-production migration",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runRuntimeRecoveryCommand(cmd, opts, recoveryFlags)
		},
	}
	recover.Flags().StringVar(&recoveryFlags.actor, "actor", "", "immutable administrator user ID bound to the recovery record")
	recover.Flags().StringVar(&recoveryFlags.language, "language", approval.DefaultConfirmationLanguage, "confirmation language")
	recover.Flags().BoolVar(&recoveryFlags.passwordStdin, "password-stdin", false, "read the administrator password from the first stdin line")
	recover.Flags().BoolVar(&recoveryFlags.totpStdin, "totp-stdin", false, "read the administrator TOTP code from the first stdin line")
	parent.AddCommand(recover)
	return parent
}

func runRuntimeRecoveryCommand(cmd *cobra.Command, opts RuntimeOptions, flags runtimeFlags) (retErr error) {
	if cmd == nil || opts.ConfigPath == nil || opts.DataDir == nil || opts.AcquireExclusive == nil {
		return ErrRuntimeConfiguration
	}
	if flags.passwordStdin == flags.totpStdin {
		return ErrCredentialMode
	}
	if err := strictIdentity(flags.actor); err != nil {
		return fmt.Errorf("%w: actor", ErrRuntimeConfiguration)
	}
	configPath, err := runtimeConfigPath(opts.ConfigPath())
	if err != nil {
		return err
	}
	initialConfigRaw, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	initialConfigDigest := digestBytes(initialConfigRaw)
	current, err := decodeRecoveryRuntimeConfig(initialConfigRaw)
	if err != nil {
		return err
	}
	runtimeCfg, err := runtimeConfig(current, opts.DataDir(), opts.ApplyDataDir)
	if err != nil {
		return err
	}
	lease, err := opts.AcquireExclusive(runtimeCfg.Setup.RuntimeDir)
	if err != nil {
		return fmt.Errorf("acquire exclusive service lease: %w", err)
	}
	defer func() {
		if closeErr := lease.Close(); retErr == nil && closeErr != nil {
			retErr = fmt.Errorf("close exclusive service lease: %w", closeErr)
		}
	}()

	// Re-read every decision input while the process owns the service lease.
	lockedConfigRaw, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	if digestBytes(lockedConfigRaw) != initialConfigDigest {
		return fmt.Errorf("%w: configuration changed while acquiring the service lease", ErrRuntimeConfiguration)
	}
	current, err = decodeRecoveryRuntimeConfig(lockedConfigRaw)
	if err != nil {
		return err
	}
	runtimeCfg, err = runtimeConfig(current, opts.DataDir(), opts.ApplyDataDir)
	if err != nil {
		return err
	}
	record, err := readRecoveryRecord(runtimeCfg.Setup.DataDir)
	if err != nil {
		return ErrCutoverPending
	}
	if current.Storage.Profile == config.StorageProfileTemporary && digestBytes(lockedConfigRaw) != record.Snapshot.ConfigDigest {
		return ErrCutoverAmbiguous
	}
	fence, err := readCutoverFence(runtimeCfg.Setup.DataDir)
	fencePresent := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return ErrCutoverPending
	}
	if fencePresent && (fence.SnapshotID != record.Snapshot.ID || fence.ConfigDigest != record.Snapshot.ConfigDigest) {
		return ErrCutoverPending
	}
	if flags.actor != record.Actor {
		return ErrCredentialRejected
	}

	reader := bufio.NewReaderSize(cmd.InOrStdin(), maxCredentialBytes+2)
	secret, err := readCredentialLine(reader)
	if err != nil {
		return err
	}
	defer clear(secret)
	builder := opts.buildRecovery
	if builder == nil {
		builder = buildRuntimeRecovery
	}
	plan, resources, err := builder(cmd.Context(), runtimeRecoveryBuildRequest{
		ConfigPath: configPath, DataDir: runtimeCfg.Setup.DataDir, Current: current, RuntimeConfig: runtimeCfg,
		Record: record, Actor: flags.actor, Secret: secret, PasswordMode: flags.passwordStdin,
		Now: opts.Now, ApplyDataDir: opts.ApplyDataDir,
	})
	if err != nil {
		return err
	}
	if plan == nil {
		return ErrCutoverPending
	}
	if resources != nil {
		defer func() {
			if closeErr := resources.Close(); retErr == nil && closeErr != nil {
				retErr = fmt.Errorf("close recovery resources: %w", closeErr)
			}
		}()
	}
	if err := validateRecoveryCurrentConfig(current, record, plan.Direction()); err != nil {
		return err
	}
	if fencePresent {
		if err := validateRecoveryDirectionFence(plan.Direction(), fence.Phase); err != nil {
			return err
		}
	}
	confirmationID, err := newConfirmationID(opts.Random)
	if err != nil {
		return fmt.Errorf("create recovery confirmation: %w", err)
	}
	warning := "PostgreSQL has no committed cutover ledger; restore the temporary last-known-good state and keep production disabled."
	if plan.Direction() == RecoveryCompleteProduction {
		warning = "PostgreSQL confirms the management cutover committed; complete control-plane initialization and publish the production configuration without restoring temporary credentials."
	} else if plan.Direction() != RecoveryRollbackTemporary {
		return ErrCutoverAmbiguous
	}
	confirmation, err := CollectRecoveryConfirmation(cmd.Context(), reader, cmd.OutOrStdout(), RecoveryPromptOptions{
		Actor: flags.actor, Language: flags.language, ConfirmationID: confirmationID, Warning: warning,
		Now: opts.Now, Wait: opts.Wait,
	})
	if err != nil {
		return err
	}
	if err := plan.Recover(cmd.Context(), confirmation); err != nil {
		return err
	}
	_, err = fmt.Fprintf(cmd.OutOrStdout(), "migration recovery committed: direction=%s snapshot=%s\n", plan.Direction(), record.Snapshot.ID)
	return err
}

func validateRecoveryCurrentConfig(current *config.Config, record recoveryRecord, direction RecoveryDirection) error {
	if current == nil || validateRecoveryRecord(record) != nil {
		return ErrCutoverAmbiguous
	}
	switch direction {
	case RecoveryRollbackTemporary:
		if current.Storage.Profile != config.StorageProfileTemporary {
			return ErrCutoverAmbiguous
		}
		return nil
	case RecoveryCompleteProduction:
		switch current.Storage.Profile {
		case config.StorageProfileTemporary:
			return nil
		case config.StorageProfileProduction:
			privateConfig, initialState, err := encodeRecoveryPayloads(current)
			if err != nil || digestBytes(privateConfig) != record.CandidateDigest || digestBytes(initialState) != record.InitialStateHash {
				return ErrCutoverAmbiguous
			}
			return nil
		default:
			return ErrCutoverAmbiguous
		}
	default:
		return ErrCutoverAmbiguous
	}
}

func runRuntimeCommand(cmd *cobra.Command, opts RuntimeOptions, flags runtimeFlags) (retErr error) {
	if cmd == nil || opts.ConfigPath == nil || opts.DataDir == nil || opts.AcquireExclusive == nil {
		return ErrRuntimeConfiguration
	}
	if flags.passwordStdin == flags.totpStdin {
		return ErrCredentialMode
	}
	if err := strictIdentity(flags.actor); err != nil {
		return fmt.Errorf("%w: actor", ErrRuntimeConfiguration)
	}
	if err := strictIdentity(flags.sessionID); err != nil {
		return fmt.Errorf("%w: session", ErrRuntimeConfiguration)
	}
	configPath, err := runtimeConfigPath(opts.ConfigPath())
	if err != nil {
		return err
	}
	initial, err := config.Load(configPath)
	if err != nil {
		return err
	}
	initialRuntime, err := runtimeConfig(initial, opts.DataDir(), opts.ApplyDataDir)
	if err != nil {
		return err
	}
	lease, err := opts.AcquireExclusive(initialRuntime.Setup.RuntimeDir)
	if err != nil {
		return fmt.Errorf("acquire exclusive service lease: %w", err)
	}
	defer func() {
		if closeErr := lease.Close(); retErr == nil && closeErr != nil {
			retErr = fmt.Errorf("close exclusive service lease: %w", closeErr)
		}
	}()

	// Reload under the lease so configuration used for authentication and the
	// cut-over cannot be a pre-lease snapshot.
	persisted, err := config.Load(configPath)
	if err != nil {
		return err
	}
	runtimeCfg, err := runtimeConfig(persisted, opts.DataDir(), opts.ApplyDataDir)
	if err != nil {
		return err
	}
	if filepath.Clean(runtimeCfg.Setup.RuntimeDir) != filepath.Clean(initialRuntime.Setup.RuntimeDir) {
		return fmt.Errorf("%w: runtime directory changed while acquiring the service lease", ErrRuntimeConfiguration)
	}
	if runtimeCfg.Storage.Profile != config.StorageProfileTemporary {
		return setupmigration.ErrProfileMismatch
	}
	now := runtimeNow(opts.Now)
	candidate, err := productionCandidate(persisted, now)
	if err != nil {
		return err
	}

	db, err := openMigratedSQLite(cmd.Context(), runtimeCfg.Storage.SQLite.Path)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := db.Close(); retErr == nil && closeErr != nil {
			retErr = fmt.Errorf("close temporary SQLite: %w", closeErr)
		}
	}()

	reader := bufio.NewReaderSize(cmd.InOrStdin(), maxCredentialBytes+2)
	secret, err := readCredentialLine(reader)
	if err != nil {
		return err
	}
	defer clear(secret)
	authorization, err := verifyCredential(cmd.Context(), db, flags.actor, flags.sessionID, secret, flags.passwordStdin, now)
	if err != nil {
		return err
	}
	confirmationID, err := newConfirmationID(opts.Random)
	if err != nil {
		return fmt.Errorf("create one-time confirmation: %w", err)
	}
	request := runtimeBuildRequest{
		ConfigPath: configPath, Config: persisted, RuntimeConfig: runtimeCfg, Candidate: candidate,
		SQLite: db, Authorization: authorization, ConfirmationID: confirmationID, Now: opts.Now,
	}
	builder := opts.buildRunner
	if builder == nil {
		builder = buildRuntimeRunner
	}
	runner, resources, err := builder(cmd.Context(), request)
	if err != nil {
		return err
	}
	if resources != nil {
		defer func() {
			if closeErr := resources.Close(); retErr == nil && closeErr != nil {
				retErr = fmt.Errorf("close migration resources: %w", closeErr)
			}
		}()
	}

	result, err := Execute(cmd.Context(), reader, cmd.OutOrStdout(), runner, PromptOptions{
		Actor: flags.actor, SessionID: flags.sessionID, Language: flags.language,
		ConfirmationID: confirmationID, PasswordConfirmed: authorization.password,
		TOTPConfirmed: authorization.totp, Local: true, Now: opts.Now, Wait: opts.Wait,
		Warnings: []string{
			"All temporary administrator sessions, setup URLs, join tokens, CAPTCHA receipts, and process-local locks will be invalidated.",
			"The runtime configuration will switch to production and legacy management API tokens will be revoked.",
		},
	})
	if err != nil {
		return err
	}
	if !result.Committed || !result.ManagementStateMigrated {
		return setupmigration.ErrCommitFailed
	}
	_, err = fmt.Fprintf(cmd.OutOrStdout(), "production migration committed: snapshot=%s\n", result.SnapshotID)
	return err
}

func runtimeConfigPath(raw string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", ErrRuntimeConfiguration
	}
	abs, err := filepath.Abs(raw)
	if err != nil {
		return "", fmt.Errorf("%w: config path", ErrRuntimeConfiguration)
	}
	template, templateErr := filepath.Abs(filepath.Join("configs", "cheesewaf.yaml"))
	if templateErr == nil && filepath.Clean(abs) == filepath.Clean(template) {
		return "", ErrRuntimeConfigCopy
	}
	return filepath.Clean(abs), nil
}

func runtimeConfig(persisted *config.Config, dataDir string, apply func(*config.Config, string) error) (*config.Config, error) {
	runtimeCfg, err := config.Clone(persisted)
	if err != nil {
		return nil, err
	}
	if apply != nil {
		if err := apply(runtimeCfg, dataDir); err != nil {
			return nil, err
		}
	}
	if strings.TrimSpace(runtimeCfg.Setup.RuntimeDir) == "" || strings.TrimSpace(runtimeCfg.Storage.SQLite.Path) == "" {
		return nil, ErrRuntimeConfiguration
	}
	return runtimeCfg, nil
}

func productionCandidate(current *config.Config, now time.Time) (*config.Config, error) {
	candidate, err := config.Clone(current)
	if err != nil {
		return nil, err
	}
	candidate.Storage.Profile = config.StorageProfileProduction
	for index := range candidate.APISec.ManagementAPI.Tokens {
		token := &candidate.APISec.ManagementAPI.Tokens[index]
		token.Enabled = false
		token.Hash = ""
		token.NeverExpire = false
		token.UpdatedAt = now
		token.RevokedAt = now
		if token.ExpiresAt.IsZero() || token.ExpiresAt.After(now) {
			token.ExpiresAt = now
		}
	}
	if err := config.Validate(candidate); err != nil {
		return nil, err
	}
	return candidate, nil
}

func openMigratedSQLite(ctx context.Context, path string) (*sql.DB, error) {
	store, err := storage.OpenSQLite(path)
	if err != nil {
		return nil, fmt.Errorf("open temporary SQLite: %w", err)
	}
	if err := store.Migrate(ctx); err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("migrate temporary SQLite: %w", err)
	}
	if err := store.Close(); err != nil {
		return nil, fmt.Errorf("close migrated temporary SQLite: %w", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open temporary SQLite: %w", err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(ctx, `PRAGMA busy_timeout = 5000; PRAGMA foreign_keys = ON; PRAGMA recursive_triggers = ON`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("configure temporary SQLite: %w", err)
	}
	return db, nil
}

func readCredentialLine(reader *bufio.Reader) ([]byte, error) {
	if reader == nil {
		return nil, ErrCredentialRejected
	}
	line, err := reader.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) || len(line) > maxCredentialBytes+1 {
		return nil, fmt.Errorf("%w: credential is too large", ErrCredentialRejected)
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: credential input", ErrCredentialRejected)
	}
	line = bytesWithoutLineEnding(line)
	if len(line) == 0 {
		return nil, ErrCredentialRejected
	}
	return append([]byte(nil), line...), nil
}

func bytesWithoutLineEnding(value []byte) []byte {
	value = bytesTrimSuffix(value, '\n')
	value = bytesTrimSuffix(value, '\r')
	return value
}

func bytesTrimSuffix(value []byte, suffix byte) []byte {
	if len(value) > 0 && value[len(value)-1] == suffix {
		return value[:len(value)-1]
	}
	return value
}

func newConfirmationID(random io.Reader) (string, error) {
	if random == nil {
		random = rand.Reader
	}
	value := make([]byte, 16)
	if _, err := io.ReadFull(random, value); err != nil {
		return "", err
	}
	return fmt.Sprintf("migration-%x", value), nil
}

func runtimeNow(now func() time.Time) time.Time {
	if now == nil {
		return time.Now().UTC()
	}
	return now().UTC()
}
