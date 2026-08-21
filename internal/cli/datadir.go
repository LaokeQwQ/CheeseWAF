package cli

import (
	"path/filepath"
	"runtime"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

// applyCLIDataDir makes --data-dir the runtime root. Packaged yaml uses
// relative ./data and ./logs paths; those follow the flag, not process cwd.
func applyCLIDataDir(cfg *config.Config, flagDir string) error {
	if cfg == nil {
		return nil
	}
	root := strings.TrimSpace(flagDir)
	if root == "" {
		root = strings.TrimSpace(cfg.Setup.DataDir)
	}
	if root == "" {
		return nil
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	cfg.Setup.DataDir = abs
	cfg.Setup.RuntimeDir = rebaseUnderDataDir(cfg.Setup.RuntimeDir, abs)
	if cfg.Setup.RuntimeDir == "" {
		cfg.Setup.RuntimeDir = filepath.Join(abs, "run")
	}
	cfg.Storage.SQLite.Path = rebaseUnderDataDir(cfg.Storage.SQLite.Path, abs)
	cfg.Server.AdminTLS.CertFile = rebaseUnderDataDir(cfg.Server.AdminTLS.CertFile, abs)
	cfg.Server.AdminTLS.KeyFile = rebaseUnderDataDir(cfg.Server.AdminTLS.KeyFile, abs)
	cfg.TLS.CertFile = rebaseUnderDataDir(cfg.TLS.CertFile, abs)
	cfg.TLS.KeyFile = rebaseUnderDataDir(cfg.TLS.KeyFile, abs)
	cfg.Logging.Output.File.Path = rebaseUnderDataDir(cfg.Logging.Output.File.Path, abs)
	cfg.CAPTCHAAssets.Local.Path = rebaseUnderDataDir(cfg.CAPTCHAAssets.Local.Path, abs)
	cfg.Protection.IP.GeoIP.Database = rebaseUnderDataDir(cfg.Protection.IP.GeoIP.Database, abs)
	cfg.Protection.IP.GeoIP.PrecisionDatabase = rebaseUnderDataDir(cfg.Protection.IP.GeoIP.PrecisionDatabase, abs)
	cfg.APISec.Auth.JWKSCacheFile = rebaseUnderDataDir(cfg.APISec.Auth.JWKSCacheFile, abs)
	cfg.APISec.Auth.JWTPublicKeyFile = rebaseUnderDataDir(cfg.APISec.Auth.JWTPublicKeyFile, abs)
	cfg.APISec.Auth.JWKSFile = rebaseUnderDataDir(cfg.APISec.Auth.JWKSFile, abs)
	cfg.APISec.Audit.Path = rebaseUnderDataDir(cfg.APISec.Audit.Path, abs)
	for i := range cfg.Scheduler.Tasks {
		cfg.Scheduler.Tasks[i].Target = rebaseUnderDataDir(cfg.Scheduler.Tasks[i].Target, abs)
		if !looksLikeURL(cfg.Scheduler.Tasks[i].Recipient) {
			cfg.Scheduler.Tasks[i].Recipient = rebaseUnderDataDir(cfg.Scheduler.Tasks[i].Recipient, abs)
		}
	}
	return nil
}

func looksLikeURL(p string) bool {
	s := strings.ToLower(strings.TrimSpace(p))
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}

func rebaseUnderDataDir(path, dataRoot string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return path
	}
	if filepath.IsAbs(path) {
		return path
	}
	if runtime.GOOS == "windows" && len(path) >= 2 && path[1] == ':' {
		return path
	}
	clean := filepath.ToSlash(filepath.Clean(path))
	clean = strings.TrimPrefix(clean, "./")
	switch {
	case clean == "data":
		return dataRoot
	case strings.HasPrefix(clean, "data/"):
		return filepath.Join(dataRoot, filepath.FromSlash(strings.TrimPrefix(clean, "data/")))
	default:
		return filepath.Join(dataRoot, filepath.FromSlash(clean))
	}
}
