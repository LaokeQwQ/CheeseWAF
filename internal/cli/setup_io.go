package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/cli/clilang"
)

// Sentinel commands accepted at every prompt. They are checked before
// validation so they never collide with legitimate values such as
// short usernames or filesystem paths.
const (
	wizardBackCmd = ":b"
	wizardQuitCmd = ":q"
)

var (
	// errWizardBack walks the wizard one step backwards.
	errWizardBack = errors.New("wizard back")
	// errWizardQuit aborts the wizard without writing anything.
	errWizardQuit = errors.New("wizard quit")
)

// wizardIO wraps the terminal used by the setup wizard.
// All reads go through a single bufio.Reader so that one struct owns stdin.
type wizardIO struct {
	reader  *bufio.Reader
	stdin   *os.File
	out     io.Writer
	echoOff bool
	// interactive is false when stdin is not a terminal (piped scripts).
	interactive bool
}

func newWizardIO(in io.Reader, out io.Writer) *wizardIO {
	w := &wizardIO{reader: bufio.NewReader(in), out: out}
	if file, ok := in.(*os.File); ok {
		if stat, err := file.Stat(); err == nil && stat.Mode()&os.ModeCharDevice != 0 {
			w.stdin = file
			w.interactive = true
		}
	}
	return w
}

// readLine returns one trimmed line. A bare EOF (Ctrl-D or exhausted pipe) is
// reported as errWizardQuit so callers never loop forever on a closed stdin.
func (w *wizardIO) readLine() (string, error) {
	text, err := w.reader.ReadString('\n')
	text = strings.TrimRight(text, "\r\n")
	if err != nil {
		if errors.Is(err, io.EOF) {
			if strings.TrimSpace(text) == "" {
				return "", errWizardQuit
			}
			return strings.TrimSpace(text), nil
		}
		return "", err
	}
	return strings.TrimSpace(text), nil
}

// prompt asks for a free-form value, retrying until validate passes.
// An empty answer accepts def.
func (w *wizardIO) prompt(label, def string, validate func(string) error) (string, error) {
	for {
		if def == "" {
			fmt.Fprintf(w.out, "%s: ", label)
		} else {
			fmt.Fprintf(w.out, "%s [%s]: ", label, def)
		}
		raw, err := w.readLine()
		if err != nil {
			return "", err
		}
		switch raw {
		case wizardBackCmd:
			return "", errWizardBack
		case wizardQuitCmd:
			return "", errWizardQuit
		}
		value := raw
		if value == "" {
			value = def
		}
		if validate != nil {
			if verr := validate(value); verr != nil {
				fmt.Fprintf(w.out, "  %v\n", verr)
				continue
			}
		}
		return value, nil
	}
}

// promptSecret reads a value with terminal echo disabled.
// It falls back to a normal read (with a warning) when echo cannot be
// controlled, e.g. on a pipe or an unsupported platform.
func (w *wizardIO) promptSecret(label string, validate func(string) error) (string, error) {
	for {
		fmt.Fprintf(w.out, "%s: ", label)
		value, err := w.readSecret()
		if err != nil {
			return "", err
		}
		if value == wizardBackCmd {
			return "", errWizardBack
		}
		if value == wizardQuitCmd {
			return "", errWizardQuit
		}
		if validate != nil {
			if verr := validate(value); verr != nil {
				fmt.Fprintf(w.out, "  %v\n", verr)
				continue
			}
		}
		return value, nil
	}
}

func (w *wizardIO) readSecret() (string, error) {
	if w.stdin == nil {
		return w.readLine()
	}
	if err := setTerminalEcho(w.stdin.Fd(), false); err != nil {
		// Echo stays on: tell the user instead of silently leaking the password.
		fmt.Fprintln(w.out)
		fmt.Fprintln(w.out, clilang.T("setup.warn.echo"))
		return w.readLine()
	}
	w.echoOff = true
	defer w.restoreEcho()
	text, err := w.readLine()
	// Echo is off, so the newline the user typed was not displayed.
	fmt.Fprintln(w.out)
	return text, err
}

// restoreEcho re-enables terminal echo if this session disabled it.
// It is safe to call multiple times and from the Ctrl-C handler.
func (w *wizardIO) restoreEcho() {
	if !w.echoOff || w.stdin == nil {
		return
	}
	w.echoOff = false
	_ = setTerminalEcho(w.stdin.Fd(), true)
}

// promptYesNo asks a yes/no question, defaulting to def on an empty answer.
func (w *wizardIO) promptYesNo(label string, def bool) (bool, error) {
	hint := "y/N"
	if def {
		hint = "Y/n"
	}
	for {
		fmt.Fprintf(w.out, "%s (%s): ", label, hint)
		raw, err := w.readLine()
		if err != nil {
			return false, err
		}
		switch raw {
		case wizardBackCmd:
			return false, errWizardBack
		case wizardQuitCmd:
			return false, errWizardQuit
		case "":
			return def, nil
		}
		switch strings.ToLower(raw) {
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		}
		fmt.Fprintln(w.out, clilang.T("setup.invalidYesNo"))
	}
}

// promptChoice renders a numbered option list and returns the chosen index.
func (w *wizardIO) promptChoice(label string, options []string, defIndex int) (int, error) {
	for index, option := range options {
		marker := " "
		if index == defIndex {
			marker = "*"
		}
		fmt.Fprintf(w.out, "  %s %d) %s\n", marker, index+1, option)
	}
	allowed := make([]string, 0, len(options))
	for index := range options {
		allowed = append(allowed, strconv.Itoa(index+1))
	}
	for {
		fmt.Fprintf(w.out, "%s [%d]: ", label, defIndex+1)
		raw, err := w.readLine()
		if err != nil {
			return 0, err
		}
		switch raw {
		case wizardBackCmd:
			return 0, errWizardBack
		case wizardQuitCmd:
			return 0, errWizardQuit
		case "":
			return defIndex, nil
		}
		chosen, convErr := strconv.Atoi(raw)
		if convErr != nil || chosen < 1 || chosen > len(options) {
			fmt.Fprintln(w.out, clilang.T("setup.invalidChoice", strings.Join(allowed, ", ")))
			continue
		}
		return chosen - 1, nil
	}
}

// installInterruptHandler aborts the wizard on Ctrl-C. Reading stdin cannot be
// unblocked without raw mode, so the handler restores echo, prints a localized
// message and exits. Nothing has been written at that point: the wizard only
// touches the filesystem in the final confirmation step.
func installInterruptHandler(w *wizardIO) func() {
	if w.stdin == nil {
		return func() {}
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt)
	go func() {
		<-signals
		w.restoreEcho()
		fmt.Fprintln(w.out)
		fmt.Fprintln(w.out, clilang.T("setup.aborted"))
		os.Exit(130)
	}()
	return func() { signal.Stop(signals) }
}
