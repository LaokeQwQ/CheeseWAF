package cli

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/cli/clilang"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/version"
	"github.com/spf13/cobra"
)

func newLogsCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "logs",
		Short: clilang.T("logs.short"),
	}
	cmd.AddCommand(newLogsPackCommand())
	return cmd
}

func newLogsPackCommand() *cobra.Command {
	var (
		outputPath string
		outputDir  string
		name       string
	)
	cmd := &cobra.Command{
		Use:   "pack",
		Short: clilang.T("logs.pack.short"),
		Long: `Pack CheeseWAF logs into a zip support bundle.

Examples:
  cheesewaf logs pack
  cheesewaf logs pack --dir .
  cheesewaf logs pack --dir D:\support --name incident-42
  cheesewaf logs pack -o ./bundle.zip
  CHEESEWAF_LANG=zh-CN cheesewaf logs pack`,
		RunE: func(cmd *cobra.Command, args []string) error {
			bundlePath, count, err := packLogs(configPath, dataDir, outputPath, outputDir, name)
			if err != nil {
				return fmt.Errorf(clilang.T("logs.pack.failed"), err)
			}
			fmt.Fprintln(cmd.OutOrStdout(), clilang.T("logs.pack.done", bundlePath, count))
			return nil
		},
	}
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Full path of the zip file (overrides --dir/--name)")
	cmd.Flags().StringVar(&outputDir, "dir", "", "Directory for the zip (default: current working directory)")
	cmd.Flags().StringVar(&name, "name", "", "Bundle base name without .zip (default: cheesewaf-logs-<timestamp>)")
	return cmd
}

func packLogs(cfgPath, runtimeDataDir, outputPath, outputDir, name string) (string, int, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil || cfg == nil {
		// Still pack what we can from data-dir defaults.
		def := config.Default()
		cfg = &def
	}
	if runtimeDataDir == "" {
		runtimeDataDir = cfg.Setup.DataDir
	}

	files := collectPackFiles(cfg, runtimeDataDir, cfgPath)
	if len(files) == 0 {
		return "", 0, fmt.Errorf("%s", clilang.T("logs.pack.empty"))
	}

	zipPath, err := resolvePackOutput(outputPath, outputDir, name)
	if err != nil {
		return "", 0, err
	}
	if err := os.MkdirAll(filepath.Dir(zipPath), 0o755); err != nil {
		return "", 0, err
	}

	count, err := writeZipBundle(zipPath, files, cfg, runtimeDataDir)
	if err != nil {
		return "", 0, err
	}
	return zipPath, count, nil
}

func resolvePackOutput(outputPath, outputDir, name string) (string, error) {
	if strings.TrimSpace(outputPath) != "" {
		path := outputPath
		if !strings.HasSuffix(strings.ToLower(path), ".zip") {
			path += ".zip"
		}
		return filepath.Abs(path)
	}
	base := strings.TrimSpace(name)
	if base == "" {
		base = "cheesewaf-logs-" + time.Now().Format("20060102-150405")
	}
	base = strings.TrimSuffix(base, ".zip")
	dir := strings.TrimSpace(outputDir)
	if dir == "" {
		dir = "."
	}
	return filepath.Abs(filepath.Join(dir, base+".zip"))
}

type packFile struct {
	src   string
	name  string // path inside zip
}

func collectPackFiles(cfg *config.Config, runtimeDataDir, cfgPath string) []packFile {
	seen := map[string]struct{}{}
	var out []packFile
	add := func(src, name string) {
		src = filepath.Clean(src)
		if src == "" || src == "." {
			return
		}
		info, err := os.Stat(src)
		if err != nil || info.IsDir() {
			return
		}
		key := strings.ToLower(src)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		if name == "" {
			name = filepath.Base(src)
		}
		out = append(out, packFile{src: src, name: filepath.ToSlash(name)})
	}

	// Access log + rotated siblings in the same directory.
	if cfg != nil && strings.TrimSpace(cfg.Logging.Output.File.Path) != "" {
		logPath := cfg.Logging.Output.File.Path
		add(logPath, filepath.Join("logs", filepath.Base(logPath)))
		dir := filepath.Dir(logPath)
		base := filepath.Base(logPath)
		entries, _ := os.ReadDir(dir)
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := entry.Name()
			// rotation patterns: access.log.1, access.log.2026-01-01.gz, etc.
			if name == base || strings.HasPrefix(name, base+".") {
				add(filepath.Join(dir, name), filepath.Join("logs", name))
			}
		}
	}

	// Setup log directory contents (best-effort).
	if cfg != nil && cfg.Setup.DataDir != "" {
		logDir := filepath.Join(cfg.Setup.DataDir, "logs")
		_ = filepath.Walk(logDir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info == nil || info.IsDir() {
				return nil
			}
			rel, relErr := filepath.Rel(logDir, path)
			if relErr != nil {
				return nil
			}
			add(path, filepath.Join("data-logs", rel))
			return nil
		})
	}

	// API security audit log if configured.
	if cfg != nil && strings.TrimSpace(cfg.APISec.Audit.Path) != "" {
		add(cfg.APISec.Audit.Path, filepath.Join("audit", filepath.Base(cfg.APISec.Audit.Path)))
	}

	// Config file (operators often need it; secrets may be present — documented).
	if strings.TrimSpace(cfgPath) != "" {
		add(cfgPath, "config/"+filepath.Base(cfgPath))
	}

	_ = runtimeDataDir
	return out
}

func writeZipBundle(zipPath string, files []packFile, cfg *config.Config, runtimeDataDir string) (int, error) {
	f, err := os.Create(zipPath)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	zw := zip.NewWriter(f)
	defer zw.Close()

	// Always include a version/manifest text file.
	info := version.Current()
	manifest := fmt.Sprintf(
		"CheeseWAF support bundle\n"+
			"generated_at: %s\n"+
			"version: %s\n"+
			"channel: %s\n"+
			"edition: %s\n"+
			"commit: %s\n"+
			"build_time: %s\n"+
			"go: %s\n"+
			"platform: %s\n"+
			"config: %s\n"+
			"data_dir: %s\n"+
			"cli_lang: %s\n",
		time.Now().UTC().Format(time.RFC3339),
		info.Version, info.Channel, info.Edition, info.Commit, info.BuildTime, info.GoVersion, info.Platform,
		configPath, runtimeDataDir, clilang.Current(),
	)
	if err := writeZipString(zw, "MANIFEST.txt", manifest); err != nil {
		return 0, err
	}
	count := 1
	for _, item := range files {
		if err := writeZipFile(zw, item.src, item.name); err != nil {
			// Skip unreadable files; keep packing the rest.
			continue
		}
		count++
	}
	_ = cfg
	return count, nil
}

func writeZipString(zw *zip.Writer, name, body string) error {
	w, err := zw.Create(name)
	if err != nil {
		return err
	}
	_, err = io.WriteString(w, body)
	return err
}

func writeZipFile(zw *zip.Writer, src, name string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		return err
	}
	header, err := zip.FileInfoHeader(info)
	if err != nil {
		return err
	}
	header.Name = name
	header.Method = zip.Deflate
	w, err := zw.CreateHeader(header)
	if err != nil {
		return err
	}
	_, err = io.Copy(w, in)
	return err
}
