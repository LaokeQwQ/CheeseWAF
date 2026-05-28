package tui

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

type menuItem struct {
	title string
	lines []string
}

type model struct {
	cursor int
	items  []menuItem
	status string
}

func newModel(opts Options) model {
	snapshot := loadSnapshot(opts)
	return model{
		items: []menuItem{
			{title: "Service status", lines: snapshot.serviceLines()},
			{title: "TLS / HTTP3", lines: snapshot.transportLines()},
			{title: "Monitor alerts", lines: snapshot.monitorLines()},
			{title: "API security", lines: snapshot.apiSecurityLines()},
			{title: "Audit log", lines: snapshot.auditLines()},
			{title: "Admin users", lines: snapshot.userLines()},
			{title: "Quick diagnostics", lines: snapshot.diagnosticLines()},
			{title: "Quit", lines: []string{"Exit CheeseWAF TUI."}},
		},
		status: "Use arrow keys and Enter.",
	}
}

func (m model) Init() tea.Cmd { return nil }

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q", "esc":
			return m, tea.Quit
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if m.cursor < len(m.items)-1 {
				m.cursor++
			}
		case "enter":
			if m.items[m.cursor].title == "Quit" {
				return m, tea.Quit
			}
			m.status = strings.Join(m.items[m.cursor].lines, "\n")
		}
	}
	return m, nil
}

func (m model) View() string {
	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("86")).Render("CheeseWAF TUI")
	help := lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	active := lipgloss.NewStyle().Foreground(lipgloss.Color("86")).Bold(true)
	var b strings.Builder
	b.WriteString(title + "\n\n")
	for i, item := range m.items {
		prefix := "  "
		line := item.title
		if i == m.cursor {
			prefix = "> "
			line = active.Render(line)
		}
		b.WriteString(prefix + line + "\n")
	}
	b.WriteString("\n" + help.Render(m.status) + "\n")
	return b.String()
}

type snapshot struct {
	opts          Options
	cfg           *config.Config
	configErr     error
	pid           string
	logPath       string
	auditPath     string
	accessLines   int
	auditLogLines int
	dataBytes     int64
	logBytes      int64
}

func loadSnapshot(opts Options) snapshot {
	out := snapshot{opts: opts}
	if opts.ConfigPath != "" {
		out.cfg, out.configErr = config.Load(opts.ConfigPath)
	}
	if out.cfg == nil {
		cfg := config.Default()
		out.cfg = &cfg
	}
	if opts.DataDir == "" {
		opts.DataDir = out.cfg.Setup.DataDir
		out.opts.DataDir = opts.DataDir
	}
	out.logPath = out.cfg.Logging.Output.File.Path
	out.auditPath = out.cfg.APISec.Audit.Path
	out.pid = readText(filepath.Join(out.cfg.Setup.RuntimeDir, "cheesewaf.pid"))
	out.accessLines = countLines(out.logPath)
	out.auditLogLines = countLines(out.auditPath)
	out.dataBytes = dirSize(out.cfg.Setup.DataDir)
	out.logBytes = dirSize(filepath.Dir(out.logPath))
	return out
}

func (s snapshot) serviceLines() []string {
	state := "stopped"
	if strings.TrimSpace(s.pid) != "" {
		state = "running, pid=" + strings.TrimSpace(s.pid)
	}
	return []string{
		"Service: " + state,
		"Proxy listen: " + s.cfg.Server.Listen,
		"Admin API: http://" + s.cfg.Server.AdminListen,
		"Sites: " + fmt.Sprint(len(s.cfg.Sites)),
	}
}

func (s snapshot) transportLines() []string {
	http3Addr := s.cfg.Server.ListenHTTP3
	if http3Addr == "" {
		http3Addr = s.cfg.Server.ListenTLS
	}
	if http3Addr == "" {
		http3Addr = ":443"
	}
	return []string{
		"TLS listen: " + fallback(s.cfg.Server.ListenTLS, "disabled"),
		"TLS cert: " + fallback(s.cfg.TLS.CertFile, "not configured"),
		"HTTP/3: " + boolStatus(s.cfg.Server.HTTP3.Enabled),
		"HTTP/3 listen: " + http3Addr,
		"0-RTT: " + boolStatus(s.cfg.Server.HTTP3.ZeroRTT),
	}
}

func (s snapshot) monitorLines() []string {
	return []string{
		"Prometheus: " + boolStatus(s.cfg.Monitor.Prometheus.Enabled) + " " + s.cfg.Monitor.Prometheus.Path,
		"Remote write: " + boolStatus(s.cfg.Monitor.RemoteWrite.Enabled),
		"Alert rules: " + fmt.Sprint(len(s.cfg.Monitor.Alerts.Rules)),
		"Notifiers: " + fmt.Sprint(len(s.cfg.Monitor.Notifiers)),
		"Data size: " + humanBytes(s.dataBytes),
		"Log size: " + humanBytes(s.logBytes),
	}
}

func (s snapshot) apiSecurityLines() []string {
	return []string{
		"API security: " + boolStatus(s.cfg.APISec.Enabled),
		"Discovery: " + boolStatus(s.cfg.APISec.Discovery.Enabled),
		"Validation schemas: " + fmt.Sprint(len(s.cfg.APISec.Validation.Schemas)),
		"Endpoint rate limits: " + fmt.Sprint(len(s.cfg.APISec.RateLimits)),
		"RBAC roles: " + fmt.Sprint(len(s.cfg.APISec.Permissions)),
	}
}

func (s snapshot) auditLines() []string {
	return []string{
		"Audit: " + boolStatus(s.cfg.APISec.Audit.Enabled),
		"Audit path: " + fallback(s.auditPath, "not configured"),
		"Audit entries on disk: " + fmt.Sprint(s.auditLogLines),
		"Access log path: " + fallback(s.logPath, "not configured"),
		"Access log entries on disk: " + fmt.Sprint(s.accessLines),
	}
}

func (s snapshot) userLines() []string {
	return []string{
		"User and role data uses the same SQLite store as Web/API.",
		"RBAC permissions are loaded from apisec.permissions.",
		"Use Web UI or authenticated API for password writes; TUI shows parity status here.",
	}
}

func (s snapshot) diagnosticLines() []string {
	lines := []string{
		"Config: " + fallback(s.opts.ConfigPath, "built-in defaults"),
		"Data dir: " + fallback(s.cfg.Setup.DataDir, "not configured"),
		"Runtime dir: " + fallback(s.cfg.Setup.RuntimeDir, "not configured"),
		"Three-end unified model: " + boolStatus(s.cfg.Setup.ThreeEndUnified),
	}
	if s.configErr != nil {
		lines = append(lines, "Config error: "+s.configErr.Error())
	}
	return lines
}

func readText(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(raw)
}

func countLines(path string) int {
	file, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 4<<20)
	var total int
	for scanner.Scan() {
		total++
	}
	return total
}

func dirSize(root string) int64 {
	if root == "" {
		return 0
	}
	var total int64
	_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err == nil {
			total += info.Size()
		}
		_ = path
		return nil
	})
	return total
}

func boolStatus(enabled bool) string {
	if enabled {
		return "enabled"
	}
	return "disabled"
}

func fallback(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func humanBytes(value int64) string {
	const unit = 1024
	if value < unit {
		return fmt.Sprintf("%d B", value)
	}
	div, exp := int64(unit), 0
	for n := value / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(value)/float64(div), "KMGTPE"[exp])
}
