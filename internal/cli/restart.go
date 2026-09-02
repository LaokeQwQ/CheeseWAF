package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var restartCmd = &cobra.Command{
	Use:   "restart",
	Short: "重启 CheeseWAF 服务",
	RunE:  runRestartCommand,
	Run: func(cmd *cobra.Command, args []string) {
		if err := runRestartCommand(cmd, args); err != nil {
			fmt.Fprintln(cmd.ErrOrStderr(), err)
		}
	},
}

var startDetachedService = startDetachedServiceDefault

func runRestartCommand(cmd *cobra.Command, _ []string) error {
	if _, err := StopRunningService(); err != nil {
		return fmt.Errorf("stop before restart: %w", err)
	}
	if err := startDetachedService(); err != nil {
		return fmt.Errorf("start after restart: %w", err)
	}
	fmt.Fprintln(cmd.OutOrStdout(), "CheeseWAF restarted")
	return nil
}

func startDetachedServiceDefault() error {
	executable, err := executablePath()
	if err != nil || strings.TrimSpace(executable) == "" {
		if err == nil {
			err = fmt.Errorf("executable path is empty")
		}
		return err
	}
	runtimeDir, err := resolveRuntimeDirForCLI()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(runtimeDir, 0o750); err != nil {
		return err
	}
	logPath := filepath.Join(runtimeDir, "serve.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return err
	}
	defer logFile.Close()
	args := []string{"serve", "--config", configPath, "--data-dir", dataDir}
	cmd := exec.Command(executable, args...)
	cmd.Dir = dataDir
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := configureServiceDetached(cmd); err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	if cmd.Process != nil {
		_ = cmd.Process.Release()
	}
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		snapshot, statusErr := inspectServiceStatus()
		if statusErr == nil && snapshot.Running {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	detail := strings.TrimSpace(lastServiceLogSnippet(logPath, 2048))
	if detail == "" {
		detail = "service did not acquire its PID lease"
	}
	return fmt.Errorf("service did not start: %s", detail)
}

func lastServiceLogSnippet(path string, limit int) string {
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) == 0 {
		return ""
	}
	if limit > 0 && len(raw) > limit {
		raw = raw[len(raw)-limit:]
	}
	return string(raw)
}
