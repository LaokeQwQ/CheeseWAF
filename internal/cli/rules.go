package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
	"github.com/spf13/cobra"
)

var (
	rulesImportFile    string
	rulesImportSite    string
	rulesExportSite    string
	rulesExportFile    string
	rulesExportFormat  string
	rulesExampleFormat string
	rulesExampleFile   string
)

var rulesCmd = &cobra.Command{
	Use:   "rules",
	Short: "导入或导出站点 custom_rules",
}

var rulesImportCmd = &cobra.Command{
	Use:   "import",
	Short: "从 YAML 或 JSON 文件替换站点 custom_rules",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		count, err := importSiteCustomRules(cmd.Context(), rulesImportSite, rulesImportFile)
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "imported %d custom_rules for site %s\n", count, strings.TrimSpace(rulesImportSite))
		return nil
	},
}

var rulesExportCmd = &cobra.Command{
	Use:   "export",
	Short: "导出站点 custom_rules 为 YAML 或 JSON",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		body, err := exportSiteCustomRules(cmd.Context(), rulesExportSite, rulesExportFormat)
		if err != nil {
			return err
		}
		if strings.TrimSpace(rulesExportFile) != "" {
			if err := os.WriteFile(rulesExportFile, body, 0o640); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", rulesExportFile)
			return nil
		}
		_, _ = cmd.OutOrStdout().Write(body)
		return nil
	},
}

var rulesExampleCmd = &cobra.Command{
	Use:   "example",
	Short: "输出 custom_rules 导入模板",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		body, err := config.ExampleCustomRulesDocument(rulesExampleFormat)
		if err != nil {
			return err
		}
		if strings.TrimSpace(rulesExampleFile) != "" {
			if err := os.WriteFile(rulesExampleFile, body, 0o640); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", rulesExampleFile)
			return nil
		}
		_, _ = cmd.OutOrStdout().Write(body)
		return nil
	},
}

func init() {
	rulesImportCmd.Flags().StringVar(&rulesImportSite, "site", "", "Site ID")
	rulesImportCmd.Flags().StringVar(&rulesImportFile, "file", "", "YAML or JSON rules file")
	_ = rulesImportCmd.MarkFlagRequired("site")
	_ = rulesImportCmd.MarkFlagRequired("file")
	rulesExportCmd.Flags().StringVar(&rulesExportSite, "site", "", "Site ID")
	rulesExportCmd.Flags().StringVar(&rulesExportFile, "file", "", "Write export to this path instead of stdout")
	rulesExportCmd.Flags().StringVar(&rulesExportFormat, "format", "yaml", "yaml or json")
	_ = rulesExportCmd.MarkFlagRequired("site")
	rulesExampleCmd.Flags().StringVar(&rulesExampleFormat, "format", "yaml", "yaml or json")
	rulesExampleCmd.Flags().StringVar(&rulesExampleFile, "file", "", "Write template to this path instead of stdout")
	rulesCmd.AddCommand(rulesImportCmd)
	rulesCmd.AddCommand(rulesExportCmd)
	rulesCmd.AddCommand(rulesExampleCmd)
}

func importSiteCustomRules(ctx context.Context, siteID, filePath string) (int, error) {
	siteID = strings.TrimSpace(siteID)
	if siteID == "" {
		return 0, errors.New("site is required")
	}
	filePath = strings.TrimSpace(filePath)
	if filePath == "" {
		return 0, errors.New("file is required")
	}
	data, err := os.ReadFile(filePath)
	if err != nil {
		return 0, fmt.Errorf("read rules file: %w", err)
	}
	parsed, err := config.ParseCustomRules(data)
	if err != nil {
		return 0, err
	}
	prepared, err := config.PrepareCustomRules(parsed)
	if err != nil {
		return 0, err
	}
	sqlitePath, err := cliSQLitePath()
	if err != nil {
		return 0, err
	}
	store, err := storage.OpenSQLite(sqlitePath)
	if err != nil {
		return 0, err
	}
	defer store.Close()
	if err := store.Migrate(ctx); err != nil {
		return 0, err
	}
	site, err := store.GetSite(ctx, siteID)
	if err != nil {
		return 0, err
	}
	if site == nil {
		return 0, fmt.Errorf("site %s not found", siteID)
	}
	previous := append([]storage.SiteCustomRule(nil), site.Advanced.CustomRules...)
	site.Advanced.CustomRules = storage.SiteCustomRulesFromConfig(prepared)
	if err := store.UpdateSite(ctx, site); err != nil {
		return 0, err
	}
	if err := persistSiteCustomRulesToConfig(siteID, prepared); err != nil {
		site.Advanced.CustomRules = previous
		if rollbackErr := store.UpdateSite(ctx, site); rollbackErr != nil {
			return 0, fmt.Errorf("save config: %v; rollback site store: %v", err, rollbackErr)
		}
		return 0, err
	}
	if err := notifyLoadedServiceHangup(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "imported rules but hangup notify failed: %v\n", err)
	}
	return len(prepared), nil
}

func exportSiteCustomRules(ctx context.Context, siteID, format string) ([]byte, error) {
	siteID = strings.TrimSpace(siteID)
	if siteID == "" {
		return nil, errors.New("site is required")
	}
	sqlitePath, err := cliSQLitePath()
	if err != nil {
		return nil, err
	}
	store, err := storage.OpenSQLite(sqlitePath)
	if err != nil {
		return nil, err
	}
	defer store.Close()
	if err := store.Migrate(ctx); err != nil {
		return nil, err
	}
	site, err := store.GetSite(ctx, siteID)
	if err != nil {
		return nil, err
	}
	if site == nil {
		return nil, fmt.Errorf("site %s not found", siteID)
	}
	return config.EncodeCustomRules(storage.SiteCustomRulesToConfig(site.Advanced.CustomRules), format)
}

func persistSiteCustomRulesToConfig(siteID string, rules []config.CustomRuleConfig) error {
	path := strings.TrimSpace(configPath)
	if path == "" {
		return errors.New("config path is empty")
	}
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	found := false
	for index := range cfg.Sites {
		if cfg.Sites[index].ID != siteID && cfg.Sites[index].Name != siteID {
			continue
		}
		cfg.Sites[index].WAF.CustomRules = append([]config.CustomRuleConfig(nil), rules...)
		found = true
		break
	}
	if !found {
		return fmt.Errorf("site %s not found in config %s", siteID, path)
	}
	return config.Save(path, cfg)
}

func notifyLoadedServiceHangup() error {
	runtimeDir := filepath.Join(dataDir, "run")
	if strings.TrimSpace(configPath) != "" {
		if cfg, err := config.Load(configPath); err == nil && strings.TrimSpace(cfg.Setup.RuntimeDir) != "" {
			runtimeDir = cfg.Setup.RuntimeDir
		}
	}
	return signalServiceHangup(runtimeDir)
}
