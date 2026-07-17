// Package clilang provides CLI locale resolution and message catalogs.
package clilang

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const (
	// PrefFile is stored under the data directory (install-time / user preference).
	PrefFile = "cli.lang"
	// EnvVar overrides preference when set (e.g. CHEESEWAF_LANG=zh-CN).
	EnvVar = "CHEESEWAF_LANG"
)

var (
	mu      sync.RWMutex
	current = "en"
	dataDir string
)

// Supported returns available CLI locales.
func Supported() []string {
	return []string{"en", "zh-CN"}
}

// Normalize maps aliases to a supported locale code.
func Normalize(raw string) string {
	tag := strings.TrimSpace(strings.ReplaceAll(raw, "_", "-"))
	if tag == "" {
		return ""
	}
	lower := strings.ToLower(tag)
	switch {
	case lower == "zh" || strings.HasPrefix(lower, "zh-cn") || strings.HasPrefix(lower, "zh-hans") || lower == "cn":
		return "zh-CN"
	case strings.HasPrefix(lower, "zh-tw") || strings.HasPrefix(lower, "zh-hk") || strings.HasPrefix(lower, "zh-hant"):
		// CLI catalog only has simplified Chinese; still prefer zh-CN over English for Chinese users.
		return "zh-CN"
	case strings.HasPrefix(lower, "en"):
		return "en"
	default:
		for _, item := range Supported() {
			if strings.EqualFold(item, tag) {
				return item
			}
		}
		return ""
	}
}

// DetectSystem picks a locale from process environment (LANG / LC_ALL / LC_MESSAGES).
func DetectSystem() string {
	for _, key := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		if value := Normalize(firstLocaleToken(os.Getenv(key))); value != "" {
			return value
		}
	}
	// Windows often sets nothing useful; leave empty for caller fallback.
	return ""
}

func firstLocaleToken(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "C" || raw == "POSIX" {
		return ""
	}
	// en_US.UTF-8 → en_US
	if i := strings.IndexAny(raw, ".@"); i >= 0 {
		raw = raw[:i]
	}
	return raw
}

// Configure sets the active data directory and resolves the effective language.
// Priority: flag > CHEESEWAF_LANG > dataDir/cli.lang > system locale > en
func Configure(flagLang, preferredDataDir string) string {
	mu.Lock()
	defer mu.Unlock()
	if preferredDataDir != "" {
		dataDir = preferredDataDir
	}
	if lang := Normalize(flagLang); lang != "" {
		current = lang
		return current
	}
	if lang := Normalize(os.Getenv(EnvVar)); lang != "" {
		current = lang
		return current
	}
	if dataDir != "" {
		if raw, err := os.ReadFile(filepath.Join(dataDir, PrefFile)); err == nil {
			if lang := Normalize(string(raw)); lang != "" {
				current = lang
				return current
			}
		}
	}
	if lang := DetectSystem(); lang != "" {
		current = lang
		return current
	}
	current = "en"
	return current
}

// Current returns the active CLI language.
func Current() string {
	mu.RLock()
	defer mu.RUnlock()
	return current
}

// Set persists the language preference under dataDir and activates it.
func Set(lang, preferredDataDir string) error {
	normalized := Normalize(lang)
	if normalized == "" {
		return fmt.Errorf("unsupported language %q (supported: %s)", lang, strings.Join(Supported(), ", "))
	}
	dir := preferredDataDir
	if dir == "" {
		mu.RLock()
		dir = dataDir
		mu.RUnlock()
	}
	if dir == "" {
		return fmt.Errorf("data directory is not configured; pass --data-dir")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(dir, PrefFile)
	if err := os.WriteFile(path, []byte(normalized+"\n"), 0o644); err != nil {
		return err
	}
	mu.Lock()
	current = normalized
	dataDir = dir
	mu.Unlock()
	return nil
}

// SaveInstallDefault writes install-time language when no preference exists yet.
func SaveInstallDefault(dir, lang string) error {
	if dir == "" {
		return nil
	}
	path := filepath.Join(dir, PrefFile)
	if _, err := os.Stat(path); err == nil {
		return nil // already set
	}
	normalized := Normalize(lang)
	if normalized == "" {
		normalized = DetectSystem()
	}
	if normalized == "" {
		normalized = "en"
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(normalized+"\n"), 0o644)
}

// T looks up a message key in the active language (falls back to English).
func T(key string, args ...any) string {
	mu.RLock()
	lang := current
	mu.RUnlock()
	msg := lookup(lang, key)
	if msg == "" {
		msg = lookup("en", key)
	}
	if msg == "" {
		msg = key
	}
	if len(args) == 0 {
		return msg
	}
	return fmt.Sprintf(msg, args...)
}

func lookup(lang, key string) string {
	catalog, ok := messages[lang]
	if !ok {
		return ""
	}
	return catalog[key]
}

var messages = map[string]map[string]string{
	"en": {
		"root.short":            "CheeseWAF - high-performance web application firewall",
		"root.long":             "CheeseWAF is a high-performance Web Application Firewall (WAF) built with Go, semantic detection, AI assistant, and TUI management.",
		"version.short":         "Show CheeseWAF version and build information",
		"status.short":          "Show CheeseWAF service status",
		"status.not_running":    "CheeseWAF is not running (pid file not found at %s)",
		"status.running":        "CheeseWAF is running, pid=%d",
		"status.stale":          "CheeseWAF is not running (stale pid file at %s, pid=%d)",
		"status.unknown":        "CheeseWAF status is unknown (pid file at %s, pid=%d)",
		"status.inspect_failed": "failed to inspect CheeseWAF status: %v",
		"lang.short":            "Show or set CLI language",
		"lang.show.short":       "Show the active CLI language",
		"lang.set.short":        "Set CLI language (persisted under data-dir)",
		"lang.current":          "CLI language: %s",
		"lang.saved":            "CLI language saved: %s (%s)",
		"lang.supported":        "Supported: %s",
		"lang.usage":            "Usage: cheesewaf lang set <en|zh-CN>",
		"logs.short":            "Access-log and support-bundle utilities",
		"logs.pack.short":       "Pack logs into a zip support bundle",
		"logs.pack.done":        "Support bundle written: %s (%d files)",
		"logs.pack.empty":       "no log files found to pack",
		"logs.pack.failed":      "failed to pack logs: %v",
	},
	"zh-CN": {
		"root.short":            "CheeseWAF - 高性能 Web 应用防火墙",
		"root.long":             "CheeseWAF 是基于 Go 的高性能 Web 应用防火墙，提供语义检测、AI 助手与 TUI 管理。",
		"version.short":         "查看 CheeseWAF 版本与构建信息",
		"status.short":          "查看 CheeseWAF 服务运行状态",
		"status.not_running":    "CheeseWAF 未运行（未找到 pid 文件：%s）",
		"status.running":        "CheeseWAF 运行中，pid=%d",
		"status.stale":          "CheeseWAF 未运行（pid 文件陈旧：%s，pid=%d）",
		"status.unknown":        "CheeseWAF 状态未知（pid 文件：%s，pid=%d）",
		"status.inspect_failed": "检查 CheeseWAF 状态失败：%v",
		"lang.short":            "查看或设置 CLI 语言",
		"lang.show.short":       "显示当前 CLI 语言",
		"lang.set.short":        "设置 CLI 语言（写入 data-dir）",
		"lang.current":          "CLI 语言：%s",
		"lang.saved":            "CLI 语言已保存：%s（%s）",
		"lang.supported":        "支持：%s",
		"lang.usage":            "用法：cheesewaf lang set <en|zh-CN>",
		"logs.short":            "访问日志与支持包工具",
		"logs.pack.short":       "将日志一键打包为 zip 支持包",
		"logs.pack.done":        "支持包已生成：%s（%d 个文件）",
		"logs.pack.empty":       "未找到可打包的日志文件",
		"logs.pack.failed":      "打包日志失败：%v",
	},
}
