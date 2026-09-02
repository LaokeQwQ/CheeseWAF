package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/cli/clilang"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/netguard"
	"github.com/LaokeQwQ/CheeseWAF/internal/passpolicy"
	"github.com/LaokeQwQ/CheeseWAF/internal/setup"
	"github.com/spf13/cobra"
)

type setupCmdOptions struct {
	yes           bool
	username      string
	passwordStdin bool
	profile       string
	adminListen   string
	skipProbe     bool
	skipExternal  bool
}

var setupOpts setupCmdOptions

// languageLabels mirrors clilang.Supported() with human-readable names.
var languageLabels = map[string]string{
	"en":    "English",
	"zh-CN": "简体中文",
}

func newSetupCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "setup",
		Short: clilang.T("setup.short"),
		Long:  clilang.T("setup.long"),
		Args:  cobra.NoArgs,
		RunE:  runSetup,
	}
	flags := cmd.Flags()
	flags.BoolVarP(&setupOpts.yes, "yes", "y", false, clilang.T("setup.flag.yes"))
	flags.StringVar(&setupOpts.username, "username", "", clilang.T("setup.flag.username"))
	flags.BoolVar(&setupOpts.passwordStdin, "password-stdin", false, clilang.T("setup.flag.passwordStdin"))
	flags.StringVar(&setupOpts.profile, "profile", "", clilang.T("setup.flag.profile"))
	flags.StringVar(&setupOpts.adminListen, "admin-listen", "", clilang.T("setup.flag.adminListen"))
	flags.BoolVar(&setupOpts.skipProbe, "skip-probe", false, clilang.T("setup.flag.skipProbe"))
	flags.BoolVar(&setupOpts.skipExternal, "skip-external", false, clilang.T("setup.flag.skipExternal"))
	return cmd
}

// setupState collects everything the wizard gathers. Nothing touches the
// filesystem until commit, so aborting at any prompt leaves no partial config.
type setupState struct {
	dataDir    string
	configPath string

	lang    string
	probe   *setup.ProbeResult
	profile setup.HardwareProfile

	username    string
	password    string
	adminListen string

	externalVisited bool
	geoipStandard   string
	geoipPrecision  string
	promEnabled     bool
	promPath        string
	promPublic      bool
	vlogsEnabled    bool
	vlogsEndpoint   string
	vlogsPrivate    bool
}

type wizardStep func(term *wizardIO, state *setupState) error

func runSetup(cmd *cobra.Command, _ []string) error {
	dataDirectory, configFile := resolveSetupPaths(cmd)
	if !setup.NeedsSetup(dataDirectory) {
		return errors.New(clilang.T("setup.alreadyComplete"))
	}
	out := cmd.OutOrStdout()

	state := &setupState{
		dataDir:     dataDirectory,
		configPath:  configFile,
		adminListen: setup.DefaultAdminListen,
	}
	if listen := strings.TrimSpace(setupOpts.adminListen); listen != "" {
		state.adminListen = listen
	}
	if raw := strings.TrimSpace(setupOpts.profile); raw != "" {
		profile := setup.HardwareProfile(strings.ToLower(raw))
		switch profile {
		case setup.ProfileLow, setup.ProfileMedium, setup.ProfileSmart, setup.ProfileHigh, setup.ProfileCustom:
			state.profile = profile
		default:
			return errors.New(clilang.T("setup.invalidProfile", raw))
		}
	}

	if setupOpts.yes {
		return runSetupNonInteractive(cmd.InOrStdin(), out, state)
	}

	term := newWizardIO(cmd.InOrStdin(), out)
	if !term.interactive {
		return errors.New(clilang.T("setup.needTerminal"))
	}
	stop := installInterruptHandler(term)
	defer stop()

	fmt.Fprintln(out, clilang.T("setup.intro"))
	fmt.Fprintf(out, "  %s\n", clilang.T("setup.introHint"))

	steps := []wizardStep{stepLanguage}
	if !setupOpts.skipProbe {
		steps = append(steps, stepProbe)
	}
	if state.profile == "" {
		steps = append(steps, stepProfile)
	}
	steps = append(steps, stepAdmin)
	if !setupOpts.skipExternal {
		steps = append(steps, stepExternal)
	}
	steps = append(steps, stepSummary)

	return runWizardSteps(term, state, steps)
}

// runWizardSteps walks the step list, translating the back/quit sentinels into
// index movements. A step returning nil advances to the next one.
func runWizardSteps(term *wizardIO, state *setupState, steps []wizardStep) error {
	index := 0
	for index < len(steps) {
		err := steps[index](term, state)
		switch {
		case err == nil:
			index++
		case errors.Is(err, errWizardBack):
			if index == 0 {
				fmt.Fprintln(term.out, clilang.T("setup.backAtFirstStep"))
				continue
			}
			index--
		case errors.Is(err, errWizardQuit):
			fmt.Fprintln(term.out, clilang.T("setup.quit"))
			return nil
		default:
			return err
		}
	}
	return nil
}

// resolveSetupPaths maps the global --data-dir/--config flags onto setup paths.
// An explicit --config always wins; otherwise the config lives under the data
// directory so that --data-dir alone relocates the whole installation.
func resolveSetupPaths(cmd *cobra.Command) (string, string) {
	directory := strings.TrimSpace(dataDir)
	if directory == "" {
		directory = setup.DefaultDataDir
	}
	file := strings.TrimSpace(configPath)
	if file == "" || !cmd.Flags().Changed("config") {
		file = setup.DefaultConfigPath(directory)
	}
	return directory, file
}

func stepLanguage(term *wizardIO, state *setupState) error {
	fmt.Fprintf(term.out, "\n%s\n", clilang.T("setup.lang.title"))
	fmt.Fprintf(term.out, "  %s\n", clilang.T("setup.lang.current", clilang.Current()))
	supported := clilang.Supported()
	labels := make([]string, 0, len(supported))
	for _, code := range supported {
		label := languageLabels[code]
		if label == "" {
			label = code
		}
		labels = append(labels, label)
	}
	defIndex := 0
	for index, code := range supported {
		if code == clilang.Current() {
			defIndex = index
			break
		}
	}
	choice, err := term.promptChoice(clilang.T("setup.lang.prompt"), labels, defIndex)
	if err != nil {
		return err
	}
	selected := supported[choice]
	state.lang = selected
	if selected == clilang.Current() {
		return nil
	}
	// Switch in memory now (persisted after the final confirmation).
	clilang.Configure(selected, state.dataDir)
	fmt.Fprintf(term.out, "  %s\n", clilang.T("setup.lang.saved", selected))
	return nil
}

func stepProbe(term *wizardIO, state *setupState) error {
	fmt.Fprintf(term.out, "\n%s\n", clilang.T("setup.probe.title"))
	run, err := term.promptYesNo(clilang.T("setup.probe.prompt"), true)
	if err != nil {
		return err
	}
	if !run {
		fmt.Fprintf(term.out, "  %s\n", clilang.T("setup.probe.skipped"))
		return nil
	}
	fmt.Fprintf(term.out, "  %s\n", clilang.T("setup.probe.running"))
	// nil context lets RunProbe apply its own 30s bound.
	result := setup.RunProbe(nil, state.dataDir)
	state.probe = &result
	printProbeResult(term.out, &result)
	return nil
}

func printProbeResult(out io.Writer, result *setup.ProbeResult) {
	fmt.Fprintf(out, "  %s\n", clilang.T("setup.probe.cpu", result.CPULogical))
	fmt.Fprintf(out, "  %s\n", clilang.T("setup.probe.memory", result.MemoryTotalMB))
	if result.DiskOK {
		fmt.Fprintf(out, "  %s\n", clilang.T("setup.probe.disk", result.DiskWriteMBps))
	} else {
		fmt.Fprintf(out, "  %s\n", clilang.T("setup.probe.diskUnknown"))
	}
	fmt.Fprintf(out, "  %s\n", clilang.T("setup.probe.duration", result.DurationMS))
	if result.Incomplete {
		fmt.Fprintf(out, "  %s\n", clilang.T("setup.probe.incomplete"))
	}
	for _, note := range result.Notes {
		fmt.Fprintf(out, "  %s\n", clilang.T("setup.probe.note", note))
	}
	fmt.Fprintf(out, "  %s\n", clilang.T("setup.probe.recommended", string(result.Profile)))
}

func stepProfile(term *wizardIO, state *setupState) error {
	fmt.Fprintf(term.out, "\n%s\n", clilang.T("setup.profile.title"))
	profiles := []setup.HardwareProfile{
		setup.ProfileSmart, setup.ProfileLow, setup.ProfileMedium, setup.ProfileHigh, setup.ProfileCustom,
	}
	recommended := setup.ProfileMedium
	if state.probe != nil {
		recommended = state.probe.Profile
	}
	options := make([]string, 0, len(profiles))
	defIndex := 0
	for index, profile := range profiles {
		label := clilang.T("setup.profile.desc." + string(profile))
		if profile == recommended {
			label += "  <" + clilang.T("setup.profile.recommend") + ">"
			defIndex = index
		}
		options = append(options, label)
	}
	choice, err := term.promptChoice(clilang.T("setup.profile.prompt"), options, defIndex)
	if err != nil {
		return err
	}
	state.profile = profiles[choice]
	fmt.Fprintf(term.out, "  %s\n", clilang.T("setup.profile.selected", string(state.profile)))
	return nil
}

func stepAdmin(term *wizardIO, state *setupState) error {
	fmt.Fprintf(term.out, "\n%s\n", clilang.T("setup.admin.title"))
	username, err := term.prompt(clilang.T("setup.admin.username"), "admin", func(value string) error {
		if len(strings.TrimSpace(value)) < 3 {
			return errors.New(clilang.T("setup.admin.usernameShort"))
		}
		return nil
	})
	if err != nil {
		return err
	}
	state.username = strings.TrimSpace(username)

	generate, err := term.promptYesNo(clilang.T("setup.admin.generate"), false)
	if err != nil {
		return err
	}
	if generate {
		password, genErr := generateTemporaryPassword(28)
		if genErr != nil {
			return genErr
		}
		if verr := passpolicy.Validate(password, state.username); verr != nil {
			return errors.New(clilang.T("setup.admin.policyFailed", verr))
		}
		state.password = password
		fmt.Fprintf(term.out, "  %s\n", clilang.T("setup.admin.generated", password))
		fmt.Fprintf(term.out, "  %s\n", clilang.T("setup.admin.generatedHint"))
		return nil
	}

	fmt.Fprintf(term.out, "  %s\n", clilang.T("setup.admin.policy"))
	validate := func(value string) error {
		if verr := passpolicy.Validate(value, state.username); verr != nil {
			return errors.New(clilang.T("setup.admin.policyFailed", verr))
		}
		return nil
	}
	for {
		password, perr := term.promptSecret(clilang.T("setup.admin.password"), validate)
		if perr != nil {
			return perr
		}
		confirm, cerr := term.promptSecret(clilang.T("setup.admin.confirm"), nil)
		if cerr != nil {
			return cerr
		}
		if password != confirm {
			fmt.Fprintf(term.out, "  %s\n", clilang.T("setup.admin.mismatch"))
			continue
		}
		state.password = password
		return nil
	}
}

func stepExternal(term *wizardIO, state *setupState) error {
	fmt.Fprintf(term.out, "\n%s\n", clilang.T("setup.external.title"))
	configure, err := term.promptYesNo(clilang.T("setup.external.prompt"), false)
	if err != nil {
		return err
	}
	if !configure {
		fmt.Fprintf(term.out, "  %s\n", clilang.T("setup.external.skipped"))
		return nil
	}
	state.externalVisited = true

	setupGeoIP, err := term.promptYesNo(clilang.T("setup.external.db.prompt"), false)
	if err != nil {
		return err
	}
	if setupGeoIP {
		standard, perr := term.prompt(clilang.T("setup.external.db.standard"), "", validateOptionalFile)
		if perr != nil {
			return perr
		}
		state.geoipStandard = strings.TrimSpace(standard)
		precision, perr := term.prompt(clilang.T("setup.external.db.precision"), "", validateOptionalFile)
		if perr != nil {
			return perr
		}
		state.geoipPrecision = strings.TrimSpace(precision)
	}

	setupProm, err := term.promptYesNo(clilang.T("setup.external.prom.prompt"), true)
	if err != nil {
		return err
	}
	if setupProm {
		state.promEnabled = true
		path, perr := term.prompt(clilang.T("setup.external.prom.path"), "/metrics", func(value string) error {
			if !strings.HasPrefix(value, "/") {
				return errors.New(clilang.T("setup.external.prom.badPath"))
			}
			return nil
		})
		if perr != nil {
			return perr
		}
		state.promPath = path
		public, perr := term.promptYesNo(clilang.T("setup.external.prom.public"), false)
		if perr != nil {
			return perr
		}
		state.promPublic = public
	}

	setupLogs, err := term.promptYesNo(clilang.T("setup.external.vlogs.prompt"), false)
	if err != nil {
		return err
	}
	if setupLogs {
		private, perr := term.promptYesNo(clilang.T("setup.external.vlogs.private"), false)
		if perr != nil {
			return perr
		}
		state.vlogsPrivate = private
		endpoint, perr := term.prompt(clilang.T("setup.external.vlogs.endpoint"), "", func(value string) error {
			if _, verr := netguard.ValidateURL(value, netguard.URLPolicy{
				Purpose:        "victorialogs endpoint",
				HostPurpose:    "victorialogs endpoint",
				AllowedSchemes: []string{"http", "https"},
				AllowPrivate:   state.vlogsPrivate,
			}); verr != nil {
				return errors.New(clilang.T("setup.external.vlogs.badURL", verr))
			}
			return nil
		})
		if perr != nil {
			return perr
		}
		state.vlogsEnabled = true
		state.vlogsEndpoint = endpoint
	}
	return nil
}

func validateOptionalFile(path string) error {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return nil
	}
	if _, err := os.Stat(trimmed); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return errors.New(clilang.T("setup.external.db.missing", trimmed))
		}
		return err
	}
	return nil
}

func stepSummary(term *wizardIO, state *setupState) error {
	fmt.Fprintf(term.out, "\n%s\n", clilang.T("setup.summary.title"))
	fmt.Fprintf(term.out, "  %s\n", clilang.T("setup.summary.lang", clilang.Current()))
	fmt.Fprintf(term.out, "  %s\n", clilang.T("setup.summary.dataDir", state.dataDir))
	fmt.Fprintf(term.out, "  %s\n", clilang.T("setup.summary.config", state.configPath))
	if state.probe != nil {
		fmt.Fprintf(term.out, "  %s\n", clilang.T("setup.summary.probe", string(state.probe.Profile)))
	}
	profile := string(state.profile)
	if profile == "" {
		profile = string(setup.ProfileCustom)
	}
	fmt.Fprintf(term.out, "  %s\n", clilang.T("setup.summary.profile", profile))
	fmt.Fprintf(term.out, "  %s\n", clilang.T("setup.summary.adminUser", state.username))
	fmt.Fprintf(term.out, "  %s\n", clilang.T("setup.summary.password", clilang.T("setup.summary.passwordSet")))
	fmt.Fprintf(term.out, "  %s\n", clilang.T("setup.summary.adminListen", state.adminListen))

	if !state.externalVisited {
		fmt.Fprintf(term.out, "  %s\n", clilang.T("setup.external.skipped"))
	} else {
		fmt.Fprintf(term.out, "  %s\n", clilang.T("setup.summary.geoip", geoIPSummary(state)))
		fmt.Fprintf(term.out, "  %s\n", clilang.T("setup.summary.prom", prometheusSummary(state)))
		fmt.Fprintf(term.out, "  %s\n", clilang.T("setup.summary.vlogs", victoriaLogsSummary(state)))
	}

	confirmed, err := term.promptYesNo(clilang.T("setup.summary.confirm"), false)
	if err != nil {
		return err
	}
	if !confirmed {
		return errWizardBack
	}
	return state.commit(term.out)
}

func geoIPSummary(state *setupState) string {
	if state.geoipStandard == "" && state.geoipPrecision == "" {
		return clilang.T("setup.summary.none")
	}
	parts := make([]string, 0, 2)
	for _, value := range []string{state.geoipStandard, state.geoipPrecision} {
		if value != "" {
			parts = append(parts, value)
		}
	}
	return strings.Join(parts, ", ")
}

func prometheusSummary(state *setupState) string {
	if !state.promEnabled {
		return clilang.T("setup.summary.none")
	}
	if state.promPublic {
		return state.promPath + " (public)"
	}
	return state.promPath
}

func victoriaLogsSummary(state *setupState) string {
	if !state.vlogsEnabled {
		return clilang.T("setup.summary.none")
	}
	return state.vlogsEndpoint
}

// commit is the only place the wizard writes to disk: it materialises the
// default layout, folds in the wizard choices, then delegates to
// setup.CompleteSetup which validates, saves, creates the administrator and
// rolls back on failure.
func (s *setupState) commit(out io.Writer) error {
	ctx := context.Background()
	fmt.Fprintf(out, "\n%s\n", clilang.T("setup.write.prepare"))
	bundle, err := setup.EnsureDefaults(setup.DefaultOptions{
		DataDir:    s.dataDir,
		ConfigPath: s.configPath,
	})
	if err != nil {
		return err
	}
	cfg, err := config.Load(bundle.Paths.ConfigFile)
	if err != nil {
		return err
	}
	applySetupProfile(cfg, s.profile)
	applySetupExternal(cfg, s)

	if _, err := setup.CompleteSetup(ctx, setup.CompleteOptions{
		DataDir:            s.dataDir,
		ConfigPath:         bundle.Paths.ConfigFile,
		DefaultAdminListen: s.adminListen,
		Paths:              bundle.Paths,
		Config:             cfg,
	}, setup.SetupPayload{
		Username:      s.username,
		Password:      s.password,
		AdminListen:   s.adminListen,
		AdminStrategy: "local",
	}); err != nil {
		return fmt.Errorf("%s: %w", clilang.T("setup.write.failed"), err)
	}
	if s.lang != "" {
		if langErr := clilang.Set(s.lang, s.dataDir); langErr != nil {
			fmt.Fprintf(out, "  %s\n", clilang.T("setup.lang.failed", langErr))
		}
	}
	fmt.Fprintf(out, "\n%s\n", clilang.T("setup.write.done"))
	fmt.Fprintf(out, "  %s\n", clilang.T("setup.write.panel", s.adminListen))
	fmt.Fprintf(out, "  %s\n", clilang.T("setup.write.next"))
	return nil
}

// applySetupProfile maps the chosen tier onto the config knobs that exist.
// ProfileConfig also carries pipeline/challenge/log-sampling values that have
// no counterpart in config.Config, so those are intentionally not applied.
func applySetupProfile(cfg *config.Config, profile setup.HardwareProfile) {
	switch profile {
	case setup.ProfileLow, setup.ProfileMedium, setup.ProfileSmart, setup.ProfileHigh:
	default:
		return
	}
	defaults := setup.ProfileDefaults(profile)
	cfg.Protection.Policy.WebAttack = defaults.WebAttackLevel
	cfg.Protection.RateLimit.Default.Requests = defaults.RateLimitRequests
}

func applySetupExternal(cfg *config.Config, s *setupState) {
	if !s.externalVisited {
		return
	}
	cfg.Protection.IP.GeoIP.Enabled = s.geoipStandard != "" || s.geoipPrecision != ""
	cfg.Protection.IP.GeoIP.Database = s.geoipStandard
	cfg.Protection.IP.GeoIP.PrecisionDatabase = s.geoipPrecision
	if s.promEnabled {
		cfg.Monitor.Prometheus.Enabled = true
		cfg.Monitor.Prometheus.Path = s.promPath
		cfg.Monitor.Prometheus.Public = s.promPublic
	}
	if s.vlogsEnabled {
		cfg.Storage.VictoriaLogs.Enabled = true
		cfg.Storage.VictoriaLogs.Endpoint = s.vlogsEndpoint
		cfg.Storage.VictoriaLogs.AllowPrivateEndpoint = s.vlogsPrivate
	}
}

func runSetupNonInteractive(in io.Reader, out io.Writer, state *setupState) error {
	username := strings.TrimSpace(setupOpts.username)
	if username == "" {
		username = "admin"
	}
	if len(username) < 3 {
		return errors.New(clilang.T("setup.admin.usernameShort"))
	}
	password := ""
	if setupOpts.passwordStdin {
		raw, err := io.ReadAll(in)
		if err != nil {
			return err
		}
		password = strings.TrimRight(string(raw), "\r\n")
	}
	if password == "" {
		return errors.New(clilang.T("setup.yes.needCredentials"))
	}
	if err := passpolicy.Validate(password, username); err != nil {
		return errors.New(clilang.T("setup.admin.policyFailed", err))
	}
	state.username = username
	state.password = password
	state.lang = clilang.Current()

	if !setupOpts.skipProbe {
		// nil context lets RunProbe apply its own 30s bound.
		result := setup.RunProbe(nil, state.dataDir)
		state.probe = &result
		printProbeResult(out, &result)
	}
	if state.profile == "" {
		if state.probe != nil {
			state.profile = state.probe.Profile
		} else {
			state.profile = setup.ProfileMedium
		}
	}
	// External integrations stay at their generated defaults in --yes mode;
	// they can be edited in the config file afterwards.
	return state.commit(out)
}
