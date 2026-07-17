package cli

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/setup"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/bcrypt"
)

var (
	passwordOptions    cliPasswordOptions
	ensureAdminOptions cliPasswordOptions
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
		opts := ensureAdminOptions
		opts.Input = cmd.InOrStdin()
		generated, err := changeUserPassword(cmd.Context(), sqlitePath, args[0], opts)
		if err != nil {
			return err
		}
		if generated != "" {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Generated password for %s: %s\n", args[0], generated)
			return nil
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Password updated for %s\n", args[0])
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

type cliPasswordOptions struct {
	Password      string
	PasswordStdin bool
	Generate      bool
	Input         io.Reader
}

func init() {
	userPasswordCmd.Flags().StringVar(&passwordOptions.Password, "password", "", "New password (prefer --password-stdin for scripts)")
	userPasswordCmd.Flags().BoolVar(&passwordOptions.PasswordStdin, "password-stdin", false, "Read the new password from stdin")
	userPasswordCmd.Flags().BoolVar(&passwordOptions.Generate, "generate", false, "Generate and print a strong temporary password")
	userCmd.AddCommand(userPasswordCmd)
	userCmd.AddCommand(userRenameCmd)
	userEnsureAdminCmd.Flags().StringVar(&ensureAdminOptions.Password, "password", "", "Password (prefer --password-stdin for scripts)")
	userEnsureAdminCmd.Flags().BoolVar(&ensureAdminOptions.PasswordStdin, "password-stdin", false, "Read the password from stdin")
	userEnsureAdminCmd.Flags().BoolVar(&ensureAdminOptions.Generate, "generate", false, "Generate and print a strong temporary password")
	userCmd.AddCommand(userEnsureAdminCmd)
}

func ensureAdminUser(ctx context.Context, sqlitePath, username string, opts cliPasswordOptions) (string, error) {
	username = strings.TrimSpace(username)
	if len(username) < 3 {
		return "", errors.New("username must contain at least 3 characters")
	}
	password, generated, err := resolvePassword(opts)
	if err != nil {
		return "", err
	}
	if len(password) < 10 {
		return "", errors.New("password must contain at least 10 characters")
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
	user.PasswordHash, user.Role, user.TwoFAEnabled, user.TwoFASecret = string(hash), "admin", false, ""
	if user.ID == "" {
		err = store.CreateUser(ctx, user)
	} else {
		err = store.UpdateUser(ctx, user)
	}
	if err != nil {
		return "", err
	}
	if err := store.RevokeUserSessions(ctx, user.ID, ""); err != nil {
		return "", err
	}
	if generated {
		return password, nil
	}
	return "", nil
}

func changeUserPassword(ctx context.Context, sqlitePath, username string, opts cliPasswordOptions) (string, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return "", errors.New("username is required")
	}
	password, generated, err := resolvePassword(opts)
	if err != nil {
		return "", err
	}
	if len(password) < 10 {
		return "", errors.New("password must contain at least 10 characters")
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
	user.TwoFAEnabled = false
	user.TwoFASecret = ""
	if err := store.UpdateUser(ctx, user); err != nil {
		return "", err
	}
	if generated {
		return password, nil
	}
	return "", nil
}

func renameUser(ctx context.Context, sqlitePath, oldUsername, newUsername string) (*storage.User, error) {
	oldUsername = strings.TrimSpace(oldUsername)
	newUsername = strings.TrimSpace(newUsername)
	if oldUsername == "" {
		return nil, errors.New("old username is required")
	}
	if len(newUsername) < 3 {
		return nil, errors.New("new username must contain at least 3 characters")
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
	if err := store.RevokeUserSessions(ctx, user.ID, ""); err != nil {
		return nil, err
	}
	return user, nil
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
	var lower, upper, digit, special bool
	for _, char := range password {
		switch {
		case char >= 'a' && char <= 'z':
			lower = true
		case char >= 'A' && char <= 'Z':
			upper = true
		case char >= '0' && char <= '9':
			digit = true
		default:
			special = true
		}
	}
	return lower && upper && digit && special
}

func cliSQLitePath() (string, error) {
	if configPath != "" {
		if _, err := os.Stat(configPath); err == nil {
			cfg, err := config.Load(configPath)
			if err != nil {
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
