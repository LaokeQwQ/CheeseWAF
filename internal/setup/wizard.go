// Package setup handles first-launch initialization: setup wizard, default config,
// and self-signed certificate generation.
// 首次启动初始化：安装向导、默认配置、自签名证书生成。
package setup

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	// DefaultDataDir is the default data directory for CheeseWAF.
	// 默认数据目录。
	DefaultDataDir = "/var/lib/cheesewaf"

	// SetupLockFile indicates that initial setup has been completed.
	// 标识初始化已完成的锁文件。
	SetupLockFile = ".setup_complete"
)

// Wizard handles the first-launch setup process.
// If a Web UI is available, it serves a browser-based wizard.
// Otherwise, it falls back to a TUI-based setup.
// 首次启动安装向导。优先使用 Web UI 向导，否则回退到 TUI 向导。
type Wizard struct {
	DataDir      string        // 数据目录 / Data directory
	ConfigPath   string        // 配置文件路径 / Config file path
	AdminAPI     string        // 管理 API 地址 / Admin API address
	CertHosts    []string      // 自签名证书 SAN / Self-signed certificate SANs
	CertValidFor time.Duration // 自签名证书有效期 / Self-signed certificate lifetime
}

// NewWizard creates a first-launch wizard with safe defaults.
// 创建带安全默认值的首次启动向导。
func NewWizard(dataDir string) *Wizard {
	return &Wizard{DataDir: dataDir}
}

// NeedsSetup checks if the initial setup has been completed.
// 检查是否需要初始化。
func (w *Wizard) NeedsSetup() bool {
	lockPath := filepath.Join(w.dataDir(), SetupLockFile)
	_, err := os.Stat(lockPath)
	return os.IsNotExist(err)
}

// MarkComplete marks the setup as complete by creating the lock file.
// 标记初始化完成。
func (w *Wizard) MarkComplete() error {
	dataDir := w.dataDir()
	lockPath := filepath.Join(dataDir, SetupLockFile)
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}
	return os.WriteFile(lockPath, []byte("setup completed\n"), 0o644)
}

// PrepareDefaults creates the default directory layout, config file, and
// self-signed admin certificate. It is safe to call repeatedly.
// 准备默认目录、配置文件和管理端自签名证书，可重复调用。
func (w *Wizard) PrepareDefaults() (*DefaultBundle, error) {
	return EnsureDefaults(DefaultOptions{
		DataDir:    w.dataDir(),
		ConfigPath: w.ConfigPath,
		Hostnames:  w.CertHosts,
		ValidFor:   w.CertValidFor,
	})
}

// RunWebWizard starts the web-based setup wizard on the admin port.
// The wizard collects: admin username, password, optional 2FA, and basic site config.
// 启动 Web 安装向导（管理端口），收集管理员账号、密码、可选 2FA 和基础站点配置。
func (w *Wizard) RunWebWizard(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	bundle, err := w.PrepareDefaults()
	if err != nil {
		return err
	}

	// TODO: Phase 1 实现
	// 1. 启动临时 HTTP 服务器（仅提供 setup 页面）
	// 2. 前端展示初始化向导页面
	// 3. 收集管理员账号/密码
	// 4. 生成自签名证书（如果用户没提供自己的）
	// 5. 写入初始配置到 SQLite
	// 6. 调用 MarkComplete()
	fmt.Println("🧀 首次启动 — 请在浏览器中完成初始化向导")
	fmt.Printf("   → 打开 https://%s/setup\n", w.adminAPI())
	fmt.Printf("   → 默认配置: %s\n", bundle.Paths.ConfigFile)
	fmt.Printf("   → 管理端证书: %s\n", bundle.Paths.CertFile)
	return nil
}

func (w *Wizard) dataDir() string {
	if w != nil && w.DataDir != "" {
		return w.DataDir
	}
	return DefaultDataDir
}

func (w *Wizard) adminAPI() string {
	if w != nil && w.AdminAPI != "" {
		return w.AdminAPI
	}
	return DefaultAdminListen
}
