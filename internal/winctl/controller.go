// Package winctl implements the lightweight local service controller used by
// the Windows GUI (and optionally other desktop shells). It reuses CheeseWAF
// CLI process semantics: start via `cheesewaf serve`, stop via PID stop, status
// via the shared runtime PID file. It is intentionally NOT a second admin UI.
package winctl

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/cli"
	"github.com/LaokeQwQ/CheeseWAF/internal/version"
)

// Options configures the local controller.
type Options struct {
	// Binary is the path to cheesewaf(.exe). Empty = sibling of the GUI binary.
	Binary string
	// ConfigPath is passed as --config.
	ConfigPath string
	// DataDir is passed as --data-dir.
	DataDir string
	// AdminURL is the Web console URL opened by the GUI (default local HTTPS).
	AdminURL string
	// Listen is the controller HTTP bind address (must be loopback).
	Listen string
}

// Controller is a pure-Go local service controller.
type Controller struct {
	opts   Options
	mu     sync.Mutex
	cmd    *exec.Cmd
	server *http.Server
}

// New builds a controller with safe defaults.
func New(opts Options) (*Controller, error) {
	if opts.Binary == "" {
		self, err := os.Executable()
		if err != nil {
			return nil, err
		}
		dir := filepath.Dir(self)
		name := "cheesewaf"
		if runtime.GOOS == "windows" {
			name += ".exe"
		}
		candidate := filepath.Join(dir, name)
		if _, err := os.Stat(candidate); err != nil {
			// Fall back to PATH lookup.
			if p, lookErr := exec.LookPath(name); lookErr == nil {
				candidate = p
			}
		}
		opts.Binary = candidate
	}
	if opts.ConfigPath == "" {
		opts.ConfigPath = filepath.Join(".", "data", "cheesewaf.yaml")
	}
	if opts.DataDir == "" {
		opts.DataDir = filepath.Join(".", "data")
	}
	if opts.AdminURL == "" {
		opts.AdminURL = "https://127.0.0.1:9443/__cheesewaf-entry"
	}
	if opts.Listen == "" {
		opts.Listen = "127.0.0.1:17943"
	}
	host, _, err := net.SplitHostPort(opts.Listen)
	if err != nil {
		return nil, fmt.Errorf("invalid listen address: %w", err)
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return nil, fmt.Errorf("controller listen address must be loopback, got %q", opts.Listen)
	}
	// Absolute paths so Start Menu / service launches do not depend on CWD.
	if abs, err := filepath.Abs(opts.ConfigPath); err == nil {
		opts.ConfigPath = abs
	}
	if abs, err := filepath.Abs(opts.DataDir); err == nil {
		opts.DataDir = abs
	}
	if abs, err := filepath.Abs(opts.Binary); err == nil {
		opts.Binary = abs
	}
	// Align CLI status/stop helpers with the same config/data dirs the GUI uses.
	cli.ConfigurePaths(opts.ConfigPath, opts.DataDir)
	return &Controller{opts: opts}, nil
}

// Status returns process status using the shared CLI inspector.
func (c *Controller) Status() (cli.ServiceStatusSnapshot, error) {
	return cli.InspectServiceStatus()
}

// Start launches `cheesewaf serve` detached when not already running.
func (c *Controller) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	snap, err := cli.InspectServiceStatus()
	if err != nil {
		return err
	}
	if snap.Running {
		return nil
	}
	args := []string{"serve", "--config", c.opts.ConfigPath, "--data-dir", c.opts.DataDir}
	cmd := exec.Command(c.opts.Binary, args...)
	cmd.Dir = filepath.Dir(c.opts.Binary)
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := configureDetached(cmd); err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start %s: %w", c.opts.Binary, err)
	}
	// Detach from parent lifetime.
	if cmd.Process != nil {
		_ = cmd.Process.Release()
	}
	c.cmd = cmd
	// Brief wait so PID file can appear.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		s, err := cli.InspectServiceStatus()
		if err == nil && s.Running {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil
}

// Stop stops a running process via CLI semantics.
func (c *Controller) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, err := cli.StopRunningService()
	return err
}

// Restart stops then starts.
func (c *Controller) Restart() error {
	_ = c.Stop()
	time.Sleep(300 * time.Millisecond)
	return c.Start()
}

// Paths returns important filesystem locations for the UI.
func (c *Controller) Paths() map[string]string {
	info := version.Current()
	return map[string]string{
		"binary":     c.opts.Binary,
		"config":     c.opts.ConfigPath,
		"data_dir":   c.opts.DataDir,
		"admin_url":  c.opts.AdminURL,
		"config_dir": filepath.Dir(c.opts.ConfigPath),
		"controller": c.opts.Listen,
		"autostart":  strconv.FormatBool(IsAutostartEnabled()),
		"goos":       runtime.GOOS,
		"goarch":     runtime.GOARCH,
		"version":    info.Version,
		"channel":    info.Channel,
		"edition":    info.Edition,
		"platform":   info.Platform,
	}
}

// OpenAdmin opens the Web console in the default browser.
func (c *Controller) OpenAdmin() error {
	return openURL(c.opts.AdminURL)
}

// OpenConfigDir opens the directory containing the config file.
func (c *Controller) OpenConfigDir() error {
	return openPath(filepath.Dir(c.opts.ConfigPath))
}

// SetAutostart enables or disables login autostart for the GUI/controller.
func (c *Controller) SetAutostart(enable bool) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	// Autostart launches the GUI (which can then start the service), not raw serve.
	return SetAutostart(enable, self, []string{
		"--config", c.opts.ConfigPath,
		"--data-dir", c.opts.DataDir,
	})
}

// Snapshot is a JSON-friendly controller view for the local UI.
type Snapshot struct {
	Status cli.ServiceStatusSnapshot `json:"status"`
	Paths  map[string]string         `json:"paths"`
	Time   string                    `json:"time"`
}

// View builds a snapshot for the UI.
func (c *Controller) View() (Snapshot, error) {
	st, err := c.Status()
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{
		Status: st,
		Paths:  c.Paths(),
		Time:   time.Now().UTC().Format(time.RFC3339),
	}, nil
}
