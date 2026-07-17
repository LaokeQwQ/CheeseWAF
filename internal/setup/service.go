package setup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/LaokeQwQ/CheeseWAF/internal/cli/clilang"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrSetupValidation      = errors.New("setup validation failed")
	ErrSetupAlreadyComplete = errors.New("setup has already completed")

	setupCompletionMu sync.Mutex
)

type SetupPayload struct {
	Username      string `json:"username"`
	Password      string `json:"password"`
	AdminListen   string `json:"admin_listen"`
	AdminStrategy string `json:"admin_strategy"`
	AdminPublic   bool   `json:"admin_public"`
}

type CompleteOptions struct {
	DataDir            string
	ConfigPath         string
	DefaultAdminListen string
	Paths              DefaultPaths
	Config             *config.Config
	Store              storage.Store
	markComplete       func(string) error
	persistUser        func(context.Context, storage.Store, *storage.User, bool) error
}

type CompleteResult struct {
	User   *storage.User
	Config *config.Config
	Paths  DefaultPaths
}

func NeedsSetup(dataDir string) bool {
	lockPath := filepath.Join(normalizeDataDir(dataDir), SetupLockFile)
	_, err := os.Stat(lockPath)
	return os.IsNotExist(err)
}

func MarkComplete(dataDir string) error {
	dataDir = normalizeDataDir(dataDir)
	lockPath := filepath.Join(dataDir, SetupLockFile)
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}
	tmpPath := lockPath + ".partial"
	if err := os.WriteFile(tmpPath, []byte("setup completed\n"), 0o640); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, lockPath); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	// Seed CLI language preference from the host locale once at install time.
	_ = clilang.SaveInstallDefault(dataDir, "")
	return nil
}

func CompleteSetup(ctx context.Context, opts CompleteOptions, payload SetupPayload) (*CompleteResult, error) {
	setupCompletionMu.Lock()
	defer setupCompletionMu.Unlock()

	paths := completePaths(opts)
	payload, err := normalizeSetupPayload(payload, opts.DefaultAdminListen)
	if err != nil {
		return nil, err
	}
	if !NeedsSetup(paths.DataDir) {
		return nil, ErrSetupAlreadyComplete
	}

	store, closeStore, err := setupStore(opts.Store, paths.SQLiteFile)
	if err != nil {
		return nil, err
	}
	if closeStore {
		defer store.Close()
	}
	if err := store.Migrate(ctx); err != nil {
		return nil, err
	}
	users, err := store.ListUsers(ctx)
	if err != nil {
		return nil, err
	}
	if len(users) > 1 || (len(users) == 1 && !strings.EqualFold(users[0].Username, payload.Username)) {
		return nil, ErrSetupAlreadyComplete
	}

	cfg, err := setupConfig(opts.Config, paths.ConfigFile)
	if err != nil {
		return nil, err
	}
	fileState, err := snapshotSetupFiles(paths)
	if err != nil {
		return nil, err
	}
	previousConfig, err := cloneSetupConfig(cfg)
	if err != nil {
		return nil, err
	}
	committed := false
	var previousUser *storage.User
	if len(users) == 1 {
		copy := users[0]
		previousUser = &copy
	}
	defer func() {
		if !committed {
			*cfg = *previousConfig
		}
	}()
	if err := applySetupConfig(cfg, paths, payload); err != nil {
		return nil, err
	}
	if err := config.Validate(cfg); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSetupValidation, err)
	}
	if err := config.Save(paths.ConfigFile, cfg); err != nil {
		return nil, err
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(payload.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	user := &storage.User{
		Username:     payload.Username,
		PasswordHash: string(hash),
		Role:         "admin",
	}
	persistUser := opts.persistUser
	if persistUser == nil {
		persistUser = func(ctx context.Context, store storage.Store, user *storage.User, update bool) error {
			if update {
				return store.UpdateUser(ctx, user)
			}
			return store.CreateUser(ctx, user)
		}
	}
	if len(users) == 1 {
		user.ID = users[0].ID
		if err := persistUser(ctx, store, user, true); err != nil {
			return nil, rollbackSetup(ctx, store, cfg, previousConfig, previousUser, nil, fileState, err)
		}
	} else if err := persistUser(ctx, store, user, false); err != nil {
		return nil, rollbackSetup(ctx, store, cfg, previousConfig, nil, nil, fileState, err)
	}
	markComplete := opts.markComplete
	if markComplete == nil {
		markComplete = MarkComplete
	}
	if err := markComplete(paths.DataDir); err != nil {
		return nil, rollbackSetup(ctx, store, cfg, previousConfig, previousUser, user, fileState, err)
	}
	committed = true
	return &CompleteResult{User: user, Config: cfg, Paths: paths}, nil
}

type setupFileSnapshot struct {
	path   string
	exists bool
	data   []byte
	mode   fs.FileMode
}

func snapshotSetupFiles(paths DefaultPaths) ([]setupFileSnapshot, error) {
	files := []string{
		paths.ConfigFile,
		paths.CertFile,
		paths.KeyFile,
		paths.CAFile,
		paths.CAKeyFile,
		filepath.Join(paths.DataDir, SetupLockFile),
		filepath.Join(paths.DataDir, SetupLockFile) + ".partial",
	}
	snapshots := make([]setupFileSnapshot, 0, len(files))
	seen := make(map[string]struct{}, len(files))
	for _, path := range files {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		clean := filepath.Clean(path)
		if _, ok := seen[clean]; ok {
			continue
		}
		seen[clean] = struct{}{}
		info, err := os.Stat(clean)
		if errors.Is(err, os.ErrNotExist) {
			snapshots = append(snapshots, setupFileSnapshot{path: clean})
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("snapshot setup file %s: %w", clean, err)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("snapshot setup file %s: not a regular file", clean)
		}
		data, err := os.ReadFile(clean)
		if err != nil {
			return nil, fmt.Errorf("snapshot setup file %s: %w", clean, err)
		}
		snapshots = append(snapshots, setupFileSnapshot{path: clean, exists: true, data: data, mode: info.Mode().Perm()})
	}
	return snapshots, nil
}

func restoreSetupFiles(snapshots []setupFileSnapshot) error {
	var restoreErr error
	for index := len(snapshots) - 1; index >= 0; index-- {
		snapshot := snapshots[index]
		if !snapshot.exists {
			if err := os.Remove(snapshot.path); err != nil && !errors.Is(err, os.ErrNotExist) {
				restoreErr = errors.Join(restoreErr, fmt.Errorf("remove setup file %s: %w", snapshot.path, err))
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(snapshot.path), 0o750); err != nil {
			restoreErr = errors.Join(restoreErr, fmt.Errorf("restore setup directory %s: %w", filepath.Dir(snapshot.path), err))
			continue
		}
		tmp := snapshot.path + ".rollback"
		if err := os.WriteFile(tmp, snapshot.data, snapshot.mode); err != nil {
			restoreErr = errors.Join(restoreErr, fmt.Errorf("restore setup file %s: %w", snapshot.path, err))
			continue
		}
		if err := os.Rename(tmp, snapshot.path); err != nil {
			_ = os.Remove(tmp)
			restoreErr = errors.Join(restoreErr, fmt.Errorf("commit restored setup file %s: %w", snapshot.path, err))
		}
	}
	return restoreErr
}

func rollbackSetup(ctx context.Context, store storage.Store, cfg, previousConfig *config.Config, previousUser, persistedUser *storage.User, files []setupFileSnapshot, cause error) error {
	*cfg = *previousConfig
	var rollbackErr error
	if previousUser != nil {
		copy := *previousUser
		if err := store.UpdateUser(ctx, &copy); err != nil {
			rollbackErr = errors.Join(rollbackErr, fmt.Errorf("restore administrator: %w", err))
		}
	} else if persistedUser != nil && persistedUser.ID != "" {
		if err := store.DeleteUser(ctx, persistedUser.ID); err != nil {
			rollbackErr = errors.Join(rollbackErr, fmt.Errorf("remove newly created administrator: %w", err))
		}
	}
	if err := restoreSetupFiles(files); err != nil {
		rollbackErr = errors.Join(rollbackErr, err)
	}
	if rollbackErr != nil {
		return errors.Join(cause, fmt.Errorf("setup rollback failed: %w", rollbackErr))
	}
	return cause
}

func cloneSetupConfig(cfg *config.Config) (*config.Config, error) {
	raw, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	var cloned config.Config
	if err := json.Unmarshal(raw, &cloned); err != nil {
		return nil, err
	}
	return &cloned, nil
}

func SetupErrorStatus(err error) int {
	switch {
	case errors.Is(err, ErrSetupValidation):
		return 400
	case errors.Is(err, ErrSetupAlreadyComplete):
		return 409
	default:
		return 500
	}
}

func normalizeSetupPayload(payload SetupPayload, defaultAdminListen string) (SetupPayload, error) {
	payload.Username = strings.TrimSpace(payload.Username)
	payload.AdminListen = strings.TrimSpace(payload.AdminListen)
	payload.AdminStrategy = strings.TrimSpace(payload.AdminStrategy)
	if payload.Username == "" || len(payload.Username) < 3 {
		return payload, fmt.Errorf("%w: username must contain at least 3 characters", ErrSetupValidation)
	}
	if len(payload.Password) < 10 {
		return payload, fmt.Errorf("%w: password must contain at least 10 characters", ErrSetupValidation)
	}
	if payload.AdminListen == "" {
		payload.AdminListen = defaultAdminListen
	}
	if payload.AdminListen == "" {
		payload.AdminListen = DefaultAdminListen
	}
	if payload.AdminStrategy == "public_tls" {
		payload.AdminPublic = true
	}
	return payload, nil
}

func setupStore(existing storage.Store, sqlitePath string) (storage.Store, bool, error) {
	if existing != nil {
		return existing, false, nil
	}
	store, err := storage.OpenSQLite(sqlitePath)
	if err != nil {
		return nil, false, err
	}
	return store, true, nil
}

func setupConfig(existing *config.Config, configPath string) (*config.Config, error) {
	if existing != nil {
		return existing, nil
	}
	return config.Load(configPath)
}

func applySetupConfig(cfg *config.Config, paths DefaultPaths, payload SetupPayload) error {
	cfg.Server.AdminListen = payload.AdminListen
	cfg.Server.AdminPublic = payload.AdminPublic
	cfg.Server.AdminTLS = config.AdminTLSConfig{
		Enabled:    payload.AdminPublic,
		CertFile:   paths.CertFile,
		KeyFile:    paths.KeyFile,
		SelfSigned: payload.AdminPublic,
	}
	cfg.Setup.DataDir = paths.DataDir
	cfg.Setup.RuntimeDir = paths.RuntimeDir
	cfg.Storage.SQLite.Path = paths.SQLiteFile
	cfg.TLS.CertFile = paths.CertFile
	cfg.TLS.KeyFile = paths.KeyFile
	if cfg.Server.AdminTLS.Enabled && (missing(paths.CertFile) || missing(paths.KeyFile) || missing(paths.CAFile) || missing(paths.CAKeyFile)) {
		if err := GenerateAdminCertificateBundle(paths.CertFile, paths.KeyFile, paths.CAFile, paths.CAKeyFile, adminCertificateHosts(payload.AdminListen), 0); err != nil {
			return err
		}
	}
	_, err := config.EnsureRuntimeSecrets(cfg)
	return err
}

func completePaths(opts CompleteOptions) DefaultPaths {
	paths := opts.Paths
	if paths.DataDir == "" {
		paths.DataDir = opts.DataDir
	}
	if paths.DataDir == "" && opts.Config != nil {
		paths.DataDir = opts.Config.Setup.DataDir
	}
	if paths.DataDir == "" {
		paths.DataDir = DefaultDataDir
	}
	if paths.ConfigFile == "" {
		paths.ConfigFile = opts.ConfigPath
	}
	if paths.ConfigFile == "" {
		paths.ConfigFile = filepath.Join(paths.DataDir, DefaultConfigFile)
	}
	defaults := ResolveDefaultPaths(DefaultOptions{DataDir: paths.DataDir, ConfigPath: paths.ConfigFile})
	if paths.CertDir == "" {
		paths.CertDir = defaults.CertDir
	}
	if paths.CertFile == "" {
		paths.CertFile = defaults.CertFile
	}
	if paths.KeyFile == "" {
		paths.KeyFile = defaults.KeyFile
	}
	if paths.CAFile == "" {
		paths.CAFile = defaults.CAFile
	}
	if paths.CAKeyFile == "" {
		paths.CAKeyFile = defaults.CAKeyFile
	}
	if paths.LogDir == "" {
		paths.LogDir = defaults.LogDir
	}
	if paths.RuntimeDir == "" {
		paths.RuntimeDir = defaults.RuntimeDir
	}
	if paths.SQLiteFile == "" {
		paths.SQLiteFile = defaults.SQLiteFile
	}
	if opts.Config != nil {
		if opts.Config.Storage.SQLite.Path != "" {
			paths.SQLiteFile = opts.Config.Storage.SQLite.Path
		}
		if opts.Config.Server.AdminTLS.CertFile != "" {
			paths.CertFile = opts.Config.Server.AdminTLS.CertFile
		}
		if opts.Config.Server.AdminTLS.KeyFile != "" {
			paths.KeyFile = opts.Config.Server.AdminTLS.KeyFile
		}
		if opts.Config.Setup.RuntimeDir != "" {
			paths.RuntimeDir = opts.Config.Setup.RuntimeDir
		}
	}
	return paths
}

func normalizeDataDir(dataDir string) string {
	if dataDir == "" {
		return DefaultDataDir
	}
	return dataDir
}

func adminCertificateHosts(adminListen string) []string {
	hosts := append([]string(nil), DefaultCertificateHosts...)
	host, _, err := net.SplitHostPort(adminListen)
	if err != nil {
		host = strings.TrimSpace(adminListen)
	}
	host = strings.Trim(host, "[]")
	if host == "" || host == "0.0.0.0" || host == "::" || host == "*" {
		return hosts
	}
	for _, existing := range hosts {
		if strings.EqualFold(existing, host) {
			return hosts
		}
	}
	return append(hosts, host)
}
