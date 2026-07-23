package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestBoolStatusAndFallback(t *testing.T) {
	if boolStatus(true) != "enabled" || boolStatus(false) != "disabled" {
		t.Fatalf("boolStatus broken: %q / %q", boolStatus(true), boolStatus(false))
	}
	if fallback("x", "y") != "x" || fallback("  ", "y") != "y" || fallback("", "y") != "y" {
		t.Fatal("fallback broken")
	}
}

func TestHumanBytes(t *testing.T) {
	cases := map[int64]string{
		0:                "0 B",
		512:              "512 B",
		1024:             "1.0 KiB",
		1536:             "1.5 KiB",
		1024 * 1024:      "1.0 MiB",
		5 * 1024 * 1024:  "5.0 MiB",
		1024 * 1024 * 1024: "1.0 GiB",
	}
	for in, want := range cases {
		if got := humanBytes(in); got != want {
			t.Errorf("humanBytes(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestCountLinesAndReadText(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	body := "one\ntwo\nthree\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := countLines(path); got != 3 {
		t.Fatalf("countLines = %d, want 3", got)
	}
	if got := countLines(filepath.Join(dir, "missing.log")); got != 0 {
		t.Fatalf("missing countLines = %d", got)
	}
	if got := readText(path); got != body {
		t.Fatalf("readText = %q", got)
	}
	if got := readText(filepath.Join(dir, "nope")); got != "" {
		t.Fatalf("missing readText = %q", got)
	}
}

func TestDirSize(t *testing.T) {
	if dirSize("") != 0 {
		t.Fatal("empty root should be 0")
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.bin"), []byte("12345"), 0o600); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(root, "nested")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "b.bin"), []byte("abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := dirSize(root); got != 8 {
		t.Fatalf("dirSize = %d, want 8", got)
	}
}

func TestLoadSnapshotFromConfigAndRuntimeArtifacts(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	runtimeDir := filepath.Join(dataDir, "run")
	logDir := filepath.Join(root, "logs")
	if err := os.MkdirAll(runtimeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(logDir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(root, "cheesewaf.yaml")
	yaml := "" +
		"server:\n" +
		"  listen: \"0.0.0.0:8080\"\n" +
		"  admin_listen: \"127.0.0.1:9443\"\n" +
		"  listen_tls: \":8443\"\n" +
		"  http3:\n" +
		"    enabled: true\n" +
		"    zero_rtt: true\n" +
		// cert/key pair required by loader when listen_tls is set

		"setup:\n" +
		"  data_dir: " + quoteYAML(dataDir) + "\n" +
		"  runtime_dir: " + quoteYAML(runtimeDir) + "\n" +
		"  three_end_unified: true\n" +
		"logging:\n" +
		"  output:\n" +
		"    file:\n" +
		"      path: " + quoteYAML(filepath.Join(logDir, "access.log")) + "\n" +
		"monitor:\n" +
		"  prometheus:\n" +
		"    enabled: true\n" +
		"    path: /metrics\n" +
		"  remote_write:\n" +
		"    enabled: false\n" +
		"apisec:\n" +
		"  enabled: true\n" +
		"  discovery:\n" +
		"    enabled: true\n" +
		"  audit:\n" +
		"    enabled: true\n" +
		"    path: " + quoteYAML(filepath.Join(logDir, "audit.log")) + "\n" +
		"sites:\n" +
		"  - id: site-a\n" +
		"    name: Site A\n" +
		"    domains: [a.example.com]\n" +
		"    upstreams:\n" +
		"      - address: 127.0.0.1:9000\n" +
		"        weight: 1\n" +
		"tls:\n" +
		"  cert_file: " + quoteYAML(filepath.Join(dataDir, "certs/server.crt")) + "\n" +
		"  key_file: " + quoteYAML(filepath.Join(dataDir, "certs/server.key")) + "\n"
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runtimeDir, "cheesewaf.pid"), []byte("4242\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(logDir, "access.log"), []byte("a\nb\nc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(logDir, "audit.log"), []byte("x\ny\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "blob.bin"), []byte("1234567890"), 0o600); err != nil {
		t.Fatal(err)
	}

	snap := loadSnapshot(Options{ConfigPath: cfgPath, DataDir: dataDir})
	if snap.configErr != nil {
		t.Fatalf("config load: %v", snap.configErr)
	}
	if strings.TrimSpace(snap.pid) != "4242" {
		t.Fatalf("pid = %q", snap.pid)
	}
	if snap.accessLines != 3 || snap.auditLogLines != 2 {
		t.Fatalf("lines access=%d audit=%d", snap.accessLines, snap.auditLogLines)
	}
	if snap.dataBytes < 10 {
		t.Fatalf("dataBytes = %d", snap.dataBytes)
	}

	service := strings.Join(snap.serviceLines(), "\n")
	for _, needle := range []string{"running, pid=4242", "0.0.0.0:8080", "127.0.0.1:9443", "Sites: 1"} {
		if !strings.Contains(service, needle) {
			t.Fatalf("serviceLines missing %q:\n%s", needle, service)
		}
	}

	transport := strings.Join(snap.transportLines(), "\n")
	for _, needle := range []string{"TLS listen: :8443", "HTTP/3: enabled", "0-RTT: enabled"} {
		if !strings.Contains(transport, needle) {
			t.Fatalf("transportLines missing %q:\n%s", needle, transport)
		}
	}

	monitor := strings.Join(snap.monitorLines(), "\n")
	if !strings.Contains(monitor, "Prometheus: enabled /metrics") {
		t.Fatalf("monitorLines:\n%s", monitor)
	}

	api := strings.Join(snap.apiSecurityLines(), "\n")
	if !strings.Contains(api, "API security: enabled") || !strings.Contains(api, "Discovery: enabled") {
		t.Fatalf("apiSecurityLines:\n%s", api)
	}

	audit := strings.Join(snap.auditLines(), "\n")
	if !strings.Contains(audit, "Audit entries on disk: 2") || !strings.Contains(audit, "Access log entries on disk: 3") {
		t.Fatalf("auditLines:\n%s", audit)
	}

	users := strings.Join(snap.userLines(), "\n")
	if !strings.Contains(users, "SQLite") {
		t.Fatalf("userLines:\n%s", users)
	}

	diag := strings.Join(snap.diagnosticLines(), "\n")
	if !strings.Contains(diag, "Three-end unified model: enabled") {
		t.Fatalf("diagnosticLines:\n%s", diag)
	}
	// Loader normalizes paths; accept either OS or slash form.
	normalizedData := filepath.ToSlash(dataDir)
	if !strings.Contains(diag, dataDir) && !strings.Contains(diag, normalizedData) {
		t.Fatalf("diagnosticLines missing data dir %q:\n%s", dataDir, diag)
	}
}

func TestLoadSnapshotConfigErrorSurfacesInDiagnostics(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(path, []byte("server: [\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	snap := loadSnapshot(Options{ConfigPath: path})
	if snap.configErr == nil {
		t.Fatal("expected config error")
	}
	// Defaults still present so menu remains usable.
	if snap.cfg == nil {
		t.Fatal("expected default cfg fallback")
	}
	diag := strings.Join(snap.diagnosticLines(), "\n")
	if !strings.Contains(diag, "Config error:") {
		t.Fatalf("diagnosticLines:\n%s", diag)
	}
}

func TestLoadSnapshotDefaultsWithoutConfig(t *testing.T) {
	snap := loadSnapshot(Options{})
	if snap.cfg == nil {
		t.Fatal("expected defaults")
	}
	service := strings.Join(snap.serviceLines(), "\n")
	if !strings.Contains(service, "stopped") {
		t.Fatalf("expected stopped service without pid:\n%s", service)
	}
}

func TestNewModelMenuAndKeyNavigation(t *testing.T) {
	m := newModel(Options{})
	if len(m.items) != 8 {
		t.Fatalf("items = %d", len(m.items))
	}
	if m.items[len(m.items)-1].title != "Quit" {
		t.Fatalf("last item = %q", m.items[len(m.items)-1].title)
	}
	if m.Init() != nil {
		t.Fatal("Init should be nil")
	}

	// Move down past end stays clamped.
	for i := 0; i < 20; i++ {
		next, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("j")})
		m = next.(model)
	}
	if m.cursor != len(m.items)-1 {
		t.Fatalf("cursor after downs = %d", m.cursor)
	}
	// Move up past start stays clamped.
	for i := 0; i < 20; i++ {
		next, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("k")})
		m = next.(model)
	}
	if m.cursor != 0 {
		t.Fatalf("cursor after ups = %d", m.cursor)
	}

	// Enter on service status populates status from lines.
	next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = next.(model)
	if cmd != nil {
		t.Fatal("enter on non-quit should not quit")
	}
	if !strings.Contains(m.status, "Service:") {
		t.Fatalf("status after enter:\n%s", m.status)
	}

	// Quit via q.
	m.cursor = 0
	next, cmd = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")})
	if cmd == nil {
		t.Fatal("q should quit")
	}
	_ = next

	// Quit via enter on Quit item.
	m = newModel(Options{})
	m.cursor = len(m.items) - 1
	next, cmd = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd == nil {
		t.Fatal("enter on Quit should quit")
	}
	_ = next
}

func TestViewRendersTitleAndSelection(t *testing.T) {
	m := newModel(Options{})
	m.cursor = 1
	view := m.View()
	if !strings.Contains(view, "CheeseWAF TUI") {
		t.Fatalf("view missing title:\n%s", view)
	}
	if !strings.Contains(view, "TLS / HTTP3") {
		t.Fatalf("view missing menu:\n%s", view)
	}
	if !strings.Contains(view, ">") {
		t.Fatalf("view missing cursor marker:\n%s", view)
	}
}

func quoteYAML(path string) string {
	// Absolute Windows paths need quotes; always quote for safety.
	escaped := strings.ReplaceAll(path, `\`, `/`)
	return `"` + escaped + `"`
}
