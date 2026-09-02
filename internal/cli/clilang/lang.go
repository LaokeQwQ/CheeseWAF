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

		"setup.short":              "Run the interactive first-install setup wizard",
		"setup.long":               "Run the interactive first-install wizard: language, hardware probe, performance profile, administrator account, and optional external integrations (GeoIP database, Prometheus, VictoriaLogs).",
		"setup.flag.yes":           "Non-interactive: accept defaults and never prompt",
		"setup.flag.username":      "Administrator username",
		"setup.flag.passwordStdin": "Read the administrator password from stdin",
		"setup.flag.profile":       "Performance profile (smart|low|medium|high|custom)",
		"setup.flag.adminListen":   "Admin listener address",
		"setup.flag.skipProbe":     "Skip the hardware probe",
		"setup.flag.skipExternal":  "Skip the external integration step",
		"setup.intro":              "CheeseWAF first-install wizard",
		"setup.introHint":          "Press Enter to accept the value in brackets, type :b to go back, :q to quit, or press Ctrl+C to abort.",
		"setup.aborted":            "Setup aborted. Nothing was written.",
		"setup.quit":               "Setup cancelled. Nothing was written.",
		"setup.needTerminal":       "the setup wizard needs an interactive terminal; pass --yes with --username and --password-stdin for scripted installs",
		"setup.warn.echo":          "warning: cannot disable terminal echo here; the password will be visible",
		"setup.invalidChoice":      "please enter one of: %s",
		"setup.invalidYesNo":       "please answer y or n",
		"setup.invalidProfile":     "unknown profile %q (allowed: smart, low, medium, high, custom)",
		"setup.alreadyComplete":    "setup is already complete; use 'cheesewaf user' to manage administrators",
		"setup.backAtFirstStep":    "already at the first step",

		"setup.lang.title":   "Step 1: language",
		"setup.lang.prompt":  "Select CLI language",
		"setup.lang.current": "current: %s",
		"setup.lang.saved":   "CLI language saved: %s",
		"setup.lang.failed":  "failed to save CLI language: %v",

		"setup.probe.title":       "Step 2: environment probe",
		"setup.probe.running":     "Probing CPU, memory, and disk write throughput (max 30s)...",
		"setup.probe.prompt":      "Run the environment probe now?",
		"setup.probe.cpu":         "CPU logical cores : %d",
		"setup.probe.memory":      "Memory (host est.) : %d MB",
		"setup.probe.disk":        "Disk sequential write: %.1f MB/s",
		"setup.probe.diskUnknown": "Disk sequential write: unavailable",
		"setup.probe.duration":    "Probe duration: %d ms",
		"setup.probe.incomplete":  "Probe incomplete: falling back to the low profile",
		"setup.probe.note":        "note: %s",
		"setup.probe.recommended": "Recommended profile: %s",
		"setup.probe.skipped":     "Probe skipped.",

		"setup.profile.title":       "Step 3: performance profile",
		"setup.profile.prompt":      "Select performance profile",
		"setup.profile.recommend":   "recommended",
		"setup.profile.desc.smart":  "smart - project default; smart scoring at lowest overhead",
		"setup.profile.desc.low":    "low - <=2 cores or <=2 GB RAM; sampling on, smaller body limit",
		"setup.profile.desc.medium": "medium - >=2 cores and >=4 GB RAM; balanced defaults",
		"setup.profile.desc.high":   "high - >=4 cores, >=8 GB RAM and fast disk; strictest defaults",
		"setup.profile.desc.custom": "custom - keep the generated defaults and tune them later",
		"setup.profile.selected":    "Profile: %s",
		"setup.profile.skipped":     "Profile step skipped; generated defaults are kept.",

		"setup.admin.title":         "Step 4: administrator account",
		"setup.admin.username":      "Administrator username",
		"setup.admin.usernameShort": "username needs at least 3 characters",
		"setup.admin.password":      "Password (hidden input)",
		"setup.admin.confirm":       "Confirm password",
		"setup.admin.mismatch":      "passwords do not match, please re-enter",
		"setup.admin.policy":        "Password policy: >=10 characters, at least 3 of upper/lower/non-repeating digit/special, not username-derived.",
		"setup.admin.policyFailed":  "password rejected: %v",
		"setup.admin.generate":      "Generate a strong password instead?",
		"setup.admin.generated":     "Generated administrator password: %s",
		"setup.admin.generatedHint": "Store it now - it is not shown again.",

		"setup.external.title":          "Step 5: external integrations (optional)",
		"setup.external.prompt":         "Configure external integrations now?",
		"setup.external.skipped":        "External integrations skipped; you can edit them later in the config file.",
		"setup.external.db.prompt":      "Configure the GeoIP database?",
		"setup.external.db.standard":    "GeoIP database path (blank to skip)",
		"setup.external.db.precision":   "GeoIP precision database path (blank to skip)",
		"setup.external.db.missing":     "file not found: %s",
		"setup.external.prom.prompt":    "Configure the Prometheus metrics endpoint?",
		"setup.external.prom.path":      "Metrics path",
		"setup.external.prom.public":    "Expose /metrics publicly?",
		"setup.external.prom.badPath":   "metrics path must start with /",
		"setup.external.vlogs.prompt":   "Configure the VictoriaLogs log sink?",
		"setup.external.vlogs.endpoint": "VictoriaLogs endpoint (http:// or https://)",
		"setup.external.vlogs.private":  "Allow a private (RFC1918/link-local/loopback) endpoint?",
		"setup.external.vlogs.badURL":   "invalid endpoint: %v",

		"setup.summary.title":       "Step 6: confirm and write",
		"setup.summary.lang":        "Language            : %s",
		"setup.summary.dataDir":     "Data directory      : %s",
		"setup.summary.config":      "Config file         : %s",
		"setup.summary.profile":     "Performance profile : %s",
		"setup.summary.adminUser":   "Administrator       : %s",
		"setup.summary.password":    "Password            : %s",
		"setup.summary.passwordSet": "(set, hidden)",
		"setup.summary.adminListen": "Admin listener      : %s",
		"setup.summary.geoip":       "GeoIP database      : %s",
		"setup.summary.prom":        "Prometheus          : %s",
		"setup.summary.vlogs":       "VictoriaLogs        : %s",
		"setup.summary.none":        "(not configured)",
		"setup.summary.confirm":     "Write this configuration and create the administrator?",
		"setup.summary.probe":       "Probe result        : %s",

		"setup.write.prepare":       "Preparing directories, default config, and admin certificate...",
		"setup.write.done":          "Setup complete.",
		"setup.write.failed":        "setup failed: %v",
		"setup.write.next":          "Start CheeseWAF with: cheesewaf serve",
		"setup.write.panel":         "Admin panel: https://%s",
		"setup.yes.needCredentials": "--yes requires --password-stdin (password must satisfy the policy)",
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

		"setup.short":              "运行交互式首次安装向导",
		"setup.long":               "运行交互式首次安装向导：语言选择、环境探测、性能档位、管理员账号，以及可选的外部接入（GeoIP 数据库、Prometheus、VictoriaLogs）。",
		"setup.flag.yes":           "非交互模式：全部使用默认值且不进行提问",
		"setup.flag.username":      "管理员用户名",
		"setup.flag.passwordStdin": "从 stdin 读取管理员密码",
		"setup.flag.profile":       "性能档位（smart|low|medium|high|custom）",
		"setup.flag.adminListen":   "管理端监听地址",
		"setup.flag.skipProbe":     "跳过环境探测",
		"setup.flag.skipExternal":  "跳过外部接入配置",
		"setup.intro":              "CheeseWAF 首次安装向导",
		"setup.introHint":          "直接回车使用方括号中的默认值；输入 :b 返回上一步，:q 退出向导，Ctrl+C 中止。",
		"setup.aborted":            "安装已中止，未写入任何配置。",
		"setup.quit":               "安装已取消，未写入任何配置。",
		"setup.needTerminal":       "安装向导需要交互式终端；脚本化安装请使用 --yes 并配合 --username 与 --password-stdin",
		"setup.warn.echo":          "警告：当前环境无法关闭终端回显，密码将明文显示",
		"setup.invalidChoice":      "请输入以下之一：%s",
		"setup.invalidYesNo":       "请输入 y 或 n",
		"setup.invalidProfile":     "未知档位 %q（可选：smart、low、medium、high、custom）",
		"setup.alreadyComplete":    "初始化已完成；管理管理员请使用 cheesewaf user",
		"setup.backAtFirstStep":    "已经是第一步",

		"setup.lang.title":   "第 1 步：语言",
		"setup.lang.prompt":  "选择 CLI 语言",
		"setup.lang.current": "当前：%s",
		"setup.lang.saved":   "CLI 语言已保存：%s",
		"setup.lang.failed":  "保存 CLI 语言失败：%v",

		"setup.probe.title":       "第 2 步：环境检查",
		"setup.probe.running":     "正在探测 CPU、内存与磁盘写入吞吐（最多 30 秒）...",
		"setup.probe.prompt":      "现在运行环境探测？",
		"setup.probe.cpu":         "CPU 逻辑核心数：%d",
		"setup.probe.memory":      "内存（估算）：%d MB",
		"setup.probe.disk":        "磁盘顺序写入：%.1f MB/s",
		"setup.probe.diskUnknown": "磁盘顺序写入：不可用",
		"setup.probe.duration":    "探测耗时：%d 毫秒",
		"setup.probe.incomplete":  "探测未完成：已回退到 low 档位",
		"setup.probe.note":        "提示：%s",
		"setup.probe.recommended": "推荐档位：%s",
		"setup.probe.skipped":     "已跳过环境探测。",

		"setup.profile.title":       "第 3 步：性能档位",
		"setup.profile.prompt":      "选择性能档位",
		"setup.profile.recommend":   "推荐",
		"setup.profile.desc.smart":  "smart - 项目默认；以最低开销启用智能评分",
		"setup.profile.desc.low":    "low - ≤2 核或 ≤2GB 内存；开启采样、降低请求体上限",
		"setup.profile.desc.medium": "medium - ≥2 核且 ≥4GB 内存；均衡默认值",
		"setup.profile.desc.high":   "high - ≥4 核、≥8GB 内存且磁盘较快；最严格默认值",
		"setup.profile.desc.custom": "custom - 保留生成的默认值，稍后再调",
		"setup.profile.selected":    "档位：%s",
		"setup.profile.skipped":     "已跳过档位选择，保留生成的默认值。",

		"setup.admin.title":         "第 4 步：管理员账号",
		"setup.admin.username":      "管理员用户名",
		"setup.admin.usernameShort": "用户名至少需要 3 个字符",
		"setup.admin.password":      "密码（隐藏输入）",
		"setup.admin.confirm":       "确认密码",
		"setup.admin.mismatch":      "两次输入的密码不一致，请重新输入",
		"setup.admin.policy":        "密码策略：长度 ≥10，且包含大写/小写/不重复数字/特殊字符中的至少 3 类，不得包含用户名。",
		"setup.admin.policyFailed":  "密码未通过校验：%v",
		"setup.admin.generate":      "改为自动生成强密码？",
		"setup.admin.generated":     "自动生成的管理员密码：%s",
		"setup.admin.generatedHint": "请立即保存，该密码不会再次显示。",

		"setup.external.title":          "第 5 步：外部接入（可选）",
		"setup.external.prompt":         "现在配置外部接入？",
		"setup.external.skipped":        "已跳过外部接入，稍后可在配置文件中修改。",
		"setup.external.db.prompt":      "配置 GeoIP 数据库？",
		"setup.external.db.standard":    "GeoIP 数据库路径（留空跳过）",
		"setup.external.db.precision":   "GeoIP 精准数据库路径（留空跳过）",
		"setup.external.db.missing":     "文件不存在：%s",
		"setup.external.prom.prompt":    "配置 Prometheus 指标端点？",
		"setup.external.prom.path":      "指标路径",
		"setup.external.prom.public":    "是否公开暴露指标端点？",
		"setup.external.prom.badPath":   "指标路径必须以 / 开头",
		"setup.external.vlogs.prompt":   "配置 VictoriaLogs 日志接收端？",
		"setup.external.vlogs.endpoint": "VictoriaLogs 地址（http:// 或 https://）",
		"setup.external.vlogs.private":  "允许内网地址（RFC1918/链路本地/回环）？",
		"setup.external.vlogs.badURL":   "地址无效：%v",

		"setup.summary.title":       "第 6 步：确认并写入",
		"setup.summary.lang":        "语言                ：%s",
		"setup.summary.dataDir":     "数据目录            ：%s",
		"setup.summary.config":      "配置文件            ：%s",
		"setup.summary.profile":     "性能档位            ：%s",
		"setup.summary.adminUser":   "管理员              ：%s",
		"setup.summary.password":    "密码                ：%s",
		"setup.summary.passwordSet": "（已设置，隐藏）",
		"setup.summary.adminListen": "管理端监听地址      ：%s",
		"setup.summary.geoip":       "GeoIP 数据库        ：%s",
		"setup.summary.prom":        "Prometheus          ：%s",
		"setup.summary.vlogs":       "VictoriaLogs        ：%s",
		"setup.summary.none":        "（未配置）",
		"setup.summary.confirm":     "写入以上配置并创建管理员？",
		"setup.summary.probe":       "探测结果            ：%s",

		"setup.write.prepare":       "正在准备目录、默认配置与管理端证书...",
		"setup.write.done":          "安装完成。",
		"setup.write.failed":        "安装失败：%v",
		"setup.write.next":          "启动 CheeseWAF：cheesewaf serve",
		"setup.write.panel":         "管理面板：https://%s",
		"setup.yes.needCredentials": "--yes 需要配合 --password-stdin（密码须满足策略）",
	},
}
