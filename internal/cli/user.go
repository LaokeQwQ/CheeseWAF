package cli

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	osuser "os/user"
	"path/filepath"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/identity"
	"github.com/LaokeQwQ/CheeseWAF/internal/passpolicy"
	"github.com/LaokeQwQ/CheeseWAF/internal/setup"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/bcrypt"
)

var (
	passwordOptions    cliPasswordOptions
	ensureAdminOptions cliPasswordOptions
	repairUsernameOpts repairUsernameOptions
)

var userCmd = &cobra.Command{
	Use:     "user",
	Aliases: []string{"users"},
	Short:   "管理本地用户",
}

var userPasswordCmd = &cobra.Command{
	Use:     "password USERNAME",
	Aliases: []string{"passwd", "reset-password"},
	Short:   "重置本地用户密码",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		sqlitePath, err := cliSQLitePath()
		if err != nil {
			return err
		}
		opts := passwordOptions
		opts.Input = cmd.InOrStdin()
		if opts.Reset2FA {
			_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "WARNING: --reset-2fa will disable two-factor authentication for this user.")
		}
		generated, err := changeUserPassword(cmd.Context(), sqlitePath, args[0], opts)
		if err != nil {
			return err
		}
		if generated != "" {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Generated password for %s: %s\n", args[0], generated)
		} else {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Password updated for %s\n", args[0])
		}
		if opts.Reset2FA {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Two-factor authentication disabled for %s\n", args[0])
		}
		return nil
	},
}

var userRenameCmd = &cobra.Command{
	Use:     "rename OLD_USERNAME NEW_USERNAME",
	Aliases: []string{"mv", "update-username"},
	Short:   "修改本地用户用户名",
	Args:    cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		sqlitePath, err := cliSQLitePath()
		if err != nil {
			return err
		}
		user, err := renameUser(cmd.Context(), sqlitePath, args[0], args[1])
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Renamed user %s to %s\n", args[0], user.Username)
		return nil
	},
}

var userEnsureAdminCmd = &cobra.Command{
	Use:   "ensure-admin USERNAME",
	Short: "创建或恢复本地管理员用户",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		sqlitePath, err := cliSQLitePath()
		if err != nil {
			return err
		}
		opts := ensureAdminOptions
		opts.Input = cmd.InOrStdin()
		generated, err := ensureAdminUser(cmd.Context(), sqlitePath, args[0], opts)
		if err != nil {
			return err
		}
		if generated != "" {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Generated password for %s: %s\n", args[0], generated)
			return nil
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Administrator %s is ready\n", args[0])
		return nil
	},
}

var userRepairUsernameCmd = &cobra.Command{
	Use:   "repair-username USER_ID NEW_USERNAME",
	Short: "按用户 ID 修复历史非法用户名",
	Long:  "Repair one historical non-canonical username by immutable user ID. The existing runtime database records the rename, all-session revocation, current OS user ID, and required reason in one transaction. Canonical usernames must use user rename; no username is trimmed or merged.",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		sqlitePath, err := cliSQLitePath()
		if err != nil {
			return err
		}
		actor, err := currentRepairActor()
		if err != nil {
			return err
		}
		repair, err := repairUserUsername(cmd.Context(), sqlitePath, args[0], args[1], actor, repairUsernameOpts.Reason)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(cmd.OutOrStdout(), "Repaired user ID %q from %q to %q; revoked %d sessions; audit ID %s\n", repair.UserID, repair.OldUsername, repair.NewUsername, repair.RevokedSessions, repair.ID)
		return err
	},
}

type cliPasswordOptions struct {
	Password      string
	PasswordStdin bool
	Generate      bool
	Reset2FA      bool
	Input         io.Reader
}

type repairUsernameOptions struct {
	Reason string
}

func init() {
	userPasswordCmd.Flags().StringVar(&passwordOptions.Password, "password", "", "New password (prefer --password-stdin for scripts)")
	userPasswordCmd.Flags().BoolVar(&passwordOptions.PasswordStdin, "password-stdin", false, "Read the new password from stdin")
	userPasswordCmd.Flags().BoolVar(&passwordOptions.Generate, "generate", false, "Generate and print a strong temporary password")
	userPasswordCmd.Flags().BoolVar(&passwordOptions.Reset2FA, "reset-2fa", false, "Also disable two-factor authentication for the user")
	userCmd.AddCommand(userPasswordCmd)
	userCmd.AddCommand(userRenameCmd)
	userEnsureAdminCmd.Flags().StringVar(&ensureAdminOptions.Password, "password", "", "Password (prefer --password-stdin for scripts)")
	userEnsureAdminCmd.Flags().BoolVar(&ensureAdminOptions.PasswordStdin, "password-stdin", false, "Read the password from stdin")
	userEnsureAdminCmd.Flags().BoolVar(&ensureAdminOptions.Generate, "generate", false, "Generate and print a strong temporary password")
	userEnsureAdminCmd.Flags().BoolVar(&ensureAdminOptions.Reset2FA, "reset-2fa", false, "Disable two-factor authentication when updating an existing admin")
	userCmd.AddCommand(userEnsureAdminCmd)
	userRepairUsernameCmd.Flags().StringVar(&repairUsernameOpts.Reason, "reason", "", "Required audit reason for repairing the historical username")
	_ = userRepairUsernameCmd.MarkFlagRequired("reason")
	userCmd.AddCommand(userRepairUsernameCmd)
}

func ensureAdminUser(ctx context.Context, sqlitePath, username string, opts cliPasswordOptions) (string, error) {
	if err := identity.ValidateUsername(username); err != nil {
		return "", err
	}
	password, generated, err := resolvePassword(opts)
	if err != nil {
		return "", err
	}
	if err := passpolicy.Validate(password, username); err != nil {
		return "", err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	store, err := storage.OpenSQLite(sqlitePath)
	if err != nil {
		return "", err
	}
	defer store.Close()
	if err := store.Migrate(ctx); err != nil {
		return "", err
	}
	user, err := store.GetUserByUsername(ctx, username)
	if err != nil {
		return "", err
	}
	if user == nil {
		user = &storage.User{Username: username}
	}
	user.PasswordHash = string(hash)
	user.Role = "admin"
	// Preserve existing 2FA unless explicitly requested to clear it.
	if user.ID == "" || opts.Reset2FA {
		user.TwoFAEnabled = false
		user.TwoFASecret = ""
	}
	if user.ID == "" {
		err = store.CreateUser(ctx, user)
	} else {
		err = store.UpdateUser(ctx, user)
	}
	if err != nil {
		return "", err
	}
	if generated {
		return password, nil
	}
	return "", nil
}

func changeUserPassword(ctx context.Context, sqlitePath, username string, opts cliPasswordOptions) (string, error) {
	if err := identity.ValidateUsername(username); err != nil {
		return "", err
	}
	password, generated, err := resolvePassword(opts)
	if err != nil {
		return "", err
	}
	if err := passpolicy.Validate(password, username); err != nil {
		return "", err
	}

	store, err := storage.OpenSQLite(sqlitePath)
	if err != nil {
		return "", err
	}
	defer store.Close()
	if err := store.Migrate(ctx); err != nil {
		return "", err
	}
	user, err := store.GetUserByUsername(ctx, username)
	if err != nil {
		return "", err
	}
	if user == nil {
		return "", fmt.Errorf("user %q not found", username)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	user.PasswordHash = string(hash)
	// Keep 2FA enabled on password reset unless the operator passes --reset-2fa.
	if opts.Reset2FA {
		user.TwoFAEnabled = false
		user.TwoFASecret = ""
	}
	if err := store.UpdateUser(ctx, user); err != nil {
		return "", err
	}
	if generated {
		return password, nil
	}
	return "", nil
}

func renameUser(ctx context.Context, sqlitePath, oldUsername, newUsername string) (*storage.User, error) {
	if strings.TrimSpace(oldUsername) == "" {
		return nil, errors.New("old username is required")
	}
	if err := identity.ValidateUsername(oldUsername); err != nil {
		return nil, err
	}
	if err := identity.ValidateUsername(newUsername); err != nil {
		return nil, err
	}
	if oldUsername == newUsername {
		return nil, errors.New("new username must be different from old username")
	}
	store, err := storage.OpenSQLite(sqlitePath)
	if err != nil {
		return nil, err
	}
	defer store.Close()
	if err := store.Migrate(ctx); err != nil {
		return nil, err
	}
	user, err := store.GetUserByUsername(ctx, oldUsername)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, fmt.Errorf("user %q not found", oldUsername)
	}
	existing, err := store.GetUserByUsername(ctx, newUsername)
	if err != nil {
		return nil, err
	}
	if existing != nil && existing.ID != user.ID {
		return nil, fmt.Errorf("user %q already exists", newUsername)
	}
	user.Username = newUsername
	if err := store.UpdateUser(ctx, user); err != nil {
		return nil, err
	}
	return user, nil
}

func repairUserUsername(ctx context.Context, sqlitePath, userID, newUsername, actor, reason string) (*storage.UserUsernameRepair, error) {
	if err := identity.ValidateUsername(newUsername); err != nil {
		return nil, err
	}
	info, err := os.Stat(sqlitePath)
	if err != nil {
		return nil, fmt.Errorf("repair requires an existing SQLite database: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("repair requires an existing SQLite database that is a regular file")
	}
	store, err := storage.OpenSQLite(sqlitePath)
	if err != nil {
		return nil, err
	}
	defer store.Close()
	if err := store.Migrate(ctx); err != nil {
		return nil, err
	}
	return store.RepairUserUsername(ctx, userID, newUsername, actor, reason)
}

func currentRepairActor() (string, error) {
	operator, err := osuser.Current()
	if err != nil {
		return "", fmt.Errorf("identify current OS user for repair audit: %w", err)
	}
	if operator.Uid == "" {
		return "", errors.New("identify current OS user for repair audit: OS user ID is empty")
	}
	return "os-user:" + operator.Uid, nil
}

func resolvePassword(opts cliPasswordOptions) (string, bool, error) {
	sources := 0
	if opts.Password != "" {
		sources++
	}
	if opts.PasswordStdin {
		sources++
	}
	if opts.Generate {
		sources++
	}
	if sources != 1 {
		return "", false, errors.New("provide exactly one of --password, --password-stdin, or --generate")
	}
	if opts.Generate {
		password, err := generateTemporaryPassword(28)
		return password, true, err
	}
	if opts.PasswordStdin {
		input := opts.Input
		if input == nil {
			input = os.Stdin
		}
		raw, err := io.ReadAll(input)
		if err != nil {
			return "", false, err
		}
		return strings.TrimRight(string(raw), "\r\n"), false, nil
	}
	return opts.Password, false, nil
}

func generateTemporaryPassword(length int) (string, error) {
	if length < 16 {
		length = 16
	}
	alphabet := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^*-_=+?"
	for {
		var builder strings.Builder
		builder.Grow(length)
		for i := 0; i < length; i++ {
			idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
			if err != nil {
				return "", err
			}
			builder.WriteByte(alphabet[idx.Int64()])
		}
		password := builder.String()
		if passwordHasClasses(password) {
			return password, nil
		}
	}
}

func passwordHasClasses(password string) bool {
	// Generator target: all four classes when possible; policy requires ≥3.
	return passpolicy.Classify(password).Count() >= passpolicy.MinClasses &&
		passpolicy.Validate(password, "") == nil
}

func cliSQLitePath() (string, error) {
	if configPath != "" {
		if _, err := os.Stat(configPath); err == nil {
			cfg, err := config.Load(configPath)
			if err != nil {
				return "", err
			}
			// Keep CLI database operations aligned with serve: packaged YAML
			// stores relative paths under the effective --data-dir root.
			if err := applyCLIDataDir(cfg, dataDir); err != nil {
				return "", err
			}
			if strings.TrimSpace(cfg.Storage.SQLite.Path) != "" {
				return cfg.Storage.SQLite.Path, nil
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
	}
	if dataDir == "" {
		dataDir = setup.DefaultDataDir
	}
	return filepath.Join(dataDir, setup.DefaultSQLiteFile), nil
}
