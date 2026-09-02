package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/cli/clilang"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/setup"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
	"github.com/spf13/cobra"
)

// newTestWizardIO drives the wizard from an in-memory script instead of a tty,
// so the interactive logic is exercised without a pseudo terminal.
func newTestWizardIO(script string) (*wizardIO, *strings.Builder) {
	out := &strings.Builder{}
	return newWizardIO(strings.NewReader(script), out), out
}

func TestWizardPromptRetriesUntilValid(t *testing.T) {
	term, out := newTestWizardIO("a\nab\nadmin\n")
	value, err := term.prompt("label", "admin", func(v string) error {
		if len(v) < 3 {
			return errors.New("too short")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("prompt: %v", err)
	}
	if value != "admin" {
		t.Fatalf("value = %q", value)
	}
	if !strings.Contains(out.String(), "too short") {
		t.Fatalf("expected retry feedback, got %q", out.String())
	}
}

func TestWizardPromptSentinelsAndEOF(t *testing.T) {
	term, _ := newTestWizardIO(":b\n")
	if _, err := term.prompt("label", "", nil); !errors.Is(err, errWizardBack) {
		t.Fatalf("expected back, got %v", err)
	}

	term, _ = newTestWizardIO(":q\n")
	if _, err := term.prompt("label", "", nil); !errors.Is(err, errWizardQuit) {
		t.Fatalf("expected quit, got %v", err)
	}

	// Exhausted stdin must abort instead of looping forever.
	term, _ = newTestWizardIO("")
	if _, err := term.prompt("label", "", nil); !errors.Is(err, errWizardQuit) {
		t.Fatalf("expected quit on EOF, got %v", err)
	}
}

func TestWizardPromptDefaultAndYesNoAndChoice(t *testing.T) {
	term, _ := newTestWizardIO("\n")
	if value, err := term.prompt("label", "fallback", nil); err != nil || value != "fallback" {
		t.Fatalf("default = %q, %v", value, err)
	}

	term, _ = newTestWizardIO("maybe\ny\n")
	if ok, err := term.promptYesNo("label", false); err != nil || !ok {
		t.Fatalf("yesNo = %v, %v", ok, err)
	}

	term, _ = newTestWizardIO("\n")
	if ok, err := term.promptYesNo("label", true); err != nil || !ok {
		t.Fatalf("yesNo default = %v, %v", ok, err)
	}

	term, out := newTestWizardIO("9\n2\n")
	index, err := term.promptChoice("label", []string{"a", "b"}, 0)
	if err != nil || index != 1 {
		t.Fatalf("choice = %d, %v", index, err)
	}
	if !strings.Contains(out.String(), "1, 2") {
		t.Fatalf("expected allowed-values hint, got %q", out.String())
	}
}

func TestWizardSecretPromptReadsValueWithoutTty(t *testing.T) {
	term, _ := newTestWizardIO("Setup#Rk92pw!\n")
	value, err := term.promptSecret("label", nil)
	if err != nil {
		t.Fatalf("promptSecret: %v", err)
	}
	if value != "Setup#Rk92pw!" {
		t.Fatalf("value = %q", value)
	}
	// No tty here, so nothing must be left in the "echo off" state.
	if term.echoOff {
		t.Fatal("echoOff must stay false when echo cannot be controlled")
	}
}

func TestStepAdminRetriesMismatchAndWeakPassword(t *testing.T) {
	script := strings.Join([]string{
		"ad",         // too short -> retry
		"admin",      // username
		"n",          // do not generate
		"admin12345", // weak -> retry
		"Setup#Rk92pw!",
		"different", // mismatch -> retry whole password entry
		"Setup#Rk92pw!",
		"Setup#Rk92pw!",
	}, "\n") + "\n"
	term, out := newTestWizardIO(script)
	state := &setupState{}
	if err := stepAdmin(term, state); err != nil {
		t.Fatalf("stepAdmin: %v", err)
	}
	if state.username != "admin" || state.password != "Setup#Rk92pw!" {
		t.Fatalf("user=%q", state.username)
	}
	if !strings.Contains(out.String(), clilang.T("setup.admin.mismatch")) {
		t.Fatalf("expected mismatch message, got %q", out.String())
	}
}

func TestStepAdminCanGeneratePassword(t *testing.T) {
	term, _ := newTestWizardIO("operator\ny\n")
	state := &setupState{}
	if err := stepAdmin(term, state); err != nil {
		t.Fatalf("stepAdmin: %v", err)
	}
	if state.username != "operator" || state.password == "" {
		t.Fatalf("generated password missing: %q", state.username)
	}
}

func TestStepExternalValidatesVictoriaLogsAndGeoIP(t *testing.T) {
	script := strings.Join([]string{
		"y",                                     // configure external integrations
		"y",                                     // configure GeoIP
		"/definitely/missing.mmdb",              // missing file -> retry
		"",                                      // skip standard db
		"",                                      // skip precision db
		"n",                                     // leave Prometheus at its defaults
		"y",                                     // configure VictoriaLogs
		"n",                                     // private endpoints not allowed
		"http://127.0.0.1:9428/insert/jsonline", // private -> retry
		"https://vlogs.example.com/insert/jsonline",
	}, "\n") + "\n"
	term, out := newTestWizardIO(script)
	state := &setupState{}
	if err := stepExternal(term, state); err != nil {
		t.Fatalf("stepExternal: %v", err)
	}
	if !state.externalVisited || state.vlogsEndpoint != "https://vlogs.example.com/insert/jsonline" {
		t.Fatalf("vlogs endpoint = %q", state.vlogsEndpoint)
	}
	if state.promEnabled {
		t.Fatal("Prometheus must stay untouched when declined")
	}
	if !strings.Contains(out.String(), "/definitely/missing.mmdb") {
		t.Fatalf("expected missing-file feedback, got %q", out.String())
	}
}

func TestStepExternalRejectsBadPrometheusPath(t *testing.T) {
	term, _ := newTestWizardIO("y\nn\ny\nmetrics\n/metrics\nn\nn\n")
	state := &setupState{}
	if err := stepExternal(term, state); err != nil {
		t.Fatalf("stepExternal: %v", err)
	}
	if !state.promEnabled || state.promPath != "/metrics" || state.promPublic {
		t.Fatalf("prometheus = %+v", state)
	}
}

func TestRunWizardStepsBackNavigation(t *testing.T) {
	visited := []string{}
	first := func(*wizardIO, *setupState) error {
		visited = append(visited, "first")
		return nil
	}
	second := func(*wizardIO, *setupState) error {
		visited = append(visited, "second")
		if len(visited) < 4 {
			return errWizardBack
		}
		return nil
	}
	term, _ := newTestWizardIO("")
	if err := runWizardSteps(term, &setupState{}, []wizardStep{first, second}); err != nil {
		t.Fatalf("runWizardSteps: %v", err)
	}
	if got := strings.Join(visited, ","); got != "first,second,first,second" {
		t.Fatalf("visited = %q", got)
	}
}

func TestRunWizardStepsQuitWritesNothing(t *testing.T) {
	term, out := newTestWizardIO("")
	called := false
	err := runWizardSteps(term, &setupState{}, []wizardStep{
		func(*wizardIO, *setupState) error { return errWizardQuit },
		func(*wizardIO, *setupState) error { called = true; return nil },
	})
	if err != nil {
		t.Fatalf("runWizardSteps: %v", err)
	}
	if called {
		t.Fatal("steps after a quit must not run")
	}
	if !strings.Contains(out.String(), clilang.T("setup.quit")) {
		t.Fatalf("expected quit message, got %q", out.String())
	}
}

func TestApplySetupProfile(t *testing.T) {
	cases := map[setup.HardwareProfile]struct {
		level    string
		requests int
	}{
		setup.ProfileLow:    {config.ProtectionLevelSmart, 50},
		setup.ProfileMedium: {config.ProtectionLevelSmart, 100},
		setup.ProfileHigh:   {config.ProtectionLevelHigh, 200},
	}
	for profile, want := range cases {
		cfg := config.Default()
		applySetupProfile(&cfg, profile)
		if cfg.Protection.Policy.WebAttack != want.level || cfg.Protection.RateLimit.Default.Requests != want.requests {
			t.Fatalf("%s: level=%q requests=%d", profile, cfg.Protection.Policy.WebAttack, cfg.Protection.RateLimit.Default.Requests)
		}
	}
	for _, profile := range []setup.HardwareProfile{setup.ProfileCustom, ""} {
		cfg := config.Default()
		before := cfg.Protection.Policy.WebAttack
		applySetupProfile(&cfg, profile)
		if cfg.Protection.Policy.WebAttack != before {
			t.Fatalf("%q must not change the config", profile)
		}
	}
}

func TestResolveSetupPathsFollowsDataDir(t *testing.T) {
	cmd := &cobra.Command{Use: "setup"}
	cmd.Flags().StringVar(&configPath, "config", "./data/config/cheesewaf.yaml", "")
	cmd.Flags().StringVar(&dataDir, "data-dir", "./data", "")
	defer func() {
		configPath = "./data/config/cheesewaf.yaml"
		dataDir = "./data"
	}()

	directory, file := resolveSetupPaths(cmd)
	if directory != "./data" || file != filepath.Join("data", "config", "cheesewaf.yaml") {
		t.Fatalf("dir=%q file=%q", directory, file)
	}

	dataDir = "/srv/cheesewaf"
	directory, file = resolveSetupPaths(cmd)
	wantFile := filepath.Join(dataDir, "config", "cheesewaf.yaml")
	if directory != dataDir || file != wantFile {
		t.Fatalf("--data-dir must relocate the config: dir=%q file=%q", directory, file)
	}

	if err := cmd.Flags().Set("config", "/etc/cheesewaf.yaml"); err != nil {
		t.Fatal(err)
	}
	if _, file = resolveSetupPaths(cmd); file != "/etc/cheesewaf.yaml" {
		t.Fatalf("explicit --config must win, got %q", file)
	}
}

func TestValidateOptionalFile(t *testing.T) {
	if err := validateOptionalFile("  "); err != nil {
		t.Fatalf("blank must be allowed: %v", err)
	}
	if err := validateOptionalFile(t.TempDir()); err != nil {
		t.Fatalf("existing dir must be allowed: %v", err)
	}
	err := validateOptionalFile(filepath.Join(t.TempDir(), "nope.mmdb"))
	if err == nil || !strings.Contains(err.Error(), "nope.mmdb") {
		t.Fatalf("expected missing-file error, got %v", err)
	}
}

func TestSetupStateCommitWritesConfigAndAdmin(t *testing.T) {
	directory := t.TempDir()
	state := &setupState{
		dataDir:    directory,
		configPath: setup.DefaultConfigPath(directory),
		profile:    setup.ProfileHigh,
		username:   "root-admin",
		password:   "Setup#Rk92pw!",
		// lang is left empty on purpose: persisting it would mutate the
		// process-wide clilang state that other tests rely on.
		adminListen:     "127.0.0.1:9443",
		externalVisited: true,
		promEnabled:     true,
		promPath:        "/custom-metrics",
		vlogsEnabled:    true,
		vlogsEndpoint:   "https://vlogs.example.com/insert/jsonline",
		geoipPrecision:  directory,
	}
	out := &strings.Builder{}
	if err := state.commit(out); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if _, err := os.Stat(filepath.Join(directory, setup.SetupLockFile)); err != nil {
		t.Fatalf("lock file missing: %v", err)
	}

	cfg, err := config.Load(state.configPath)
	if err != nil {
		t.Fatalf("reload config: %v", err)
	}
	if cfg.Protection.Policy.WebAttack != config.ProtectionLevelHigh {
		t.Fatalf("web_attack = %q", cfg.Protection.Policy.WebAttack)
	}
	if cfg.Protection.RateLimit.Default.Requests != 200 {
		t.Fatalf("rate limit = %d", cfg.Protection.RateLimit.Default.Requests)
	}
	if !cfg.Monitor.Prometheus.Enabled || cfg.Monitor.Prometheus.Path != "/custom-metrics" {
		t.Fatalf("prometheus = %+v", cfg.Monitor.Prometheus)
	}
	if !cfg.Storage.VictoriaLogs.Enabled || cfg.Storage.VictoriaLogs.Endpoint != state.vlogsEndpoint {
		t.Fatalf("victorialogs = %+v", cfg.Storage.VictoriaLogs)
	}
	if !cfg.Protection.IP.GeoIP.Enabled || cfg.Protection.IP.GeoIP.PrecisionDatabase != directory {
		t.Fatalf("geoip = %+v", cfg.Protection.IP.GeoIP)
	}

	store, err := storage.OpenSQLite(filepath.Join(directory, setup.DefaultSQLiteFile))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer store.Close()
	user, err := store.GetUserByUsername(t.Context(), "root-admin")
	if err != nil {
		t.Fatalf("load admin: %v", err)
	}
	if user == nil || user.Role != "admin" || user.PasswordHash == "" {
		t.Fatalf("admin user not created: %+v", user)
	}

	// A second commit must be rejected so the wizard cannot re-initialise.
	if err := state.commit(out); !errors.Is(err, setup.ErrSetupAlreadyComplete) {
		t.Fatalf("second commit = %v", err)
	}
}
