package cli

import (
	"bytes"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

type temporaryOnlineFailReader struct {
	reads int
}

func (r *temporaryOnlineFailReader) Read(_ []byte) (int, error) {
	r.reads++
	return 0, errors.New("password input must not be read")
}

func TestTemporaryOnlineProbeIsDiscoverableAndRequiresExplicitPasswordStdin(t *testing.T) {
	root := newRootCommand()
	probe, _, err := root.Find([]string{"temporary-online", "probe"})
	if err != nil {
		t.Fatalf("find temporary-online probe: %v", err)
	}
	if probe == nil || probe.Name() != "probe" || probe.Flags().Lookup("password") != nil || probe.Flags().Lookup("password-stdin") == nil {
		t.Fatalf("unexpected temporary-online probe flags: %+v", probe)
	}

	var output bytes.Buffer
	root.SetOut(&output)
	root.SetErr(&output)
	root.SetArgs([]string{
		"temporary-online", "probe",
		"--administrator", "admin",
		"--plugin-id", "plugin-a",
		"--plugin-version", "1",
		"--host", "updates.example.test",
		"--tls-fingerprint", temporaryOnlineTestFingerprint(),
	})
	err = root.Execute()
	if err == nil || !strings.Contains(err.Error(), "password-stdin") {
		t.Fatalf("probe accepted omitted --password-stdin: %v\n%s", err, output.String())
	}
}

func TestRunTemporaryOnlineProbeRejectsMethodAndLimitsBeforeReadingPassword(t *testing.T) {
	base := temporaryOnlineProbeOptions{
		administrator:  "admin",
		passwordStdin:  true,
		pluginID:       "plugin-a",
		pluginVersion:  "1",
		host:           "updates.example.test",
		port:           443,
		method:         http.MethodHead,
		ttl:            time.Minute,
		maxBytes:       1024,
		responseLimit:  512,
		tlsFingerprint: temporaryOnlineTestFingerprint(),
	}

	for _, tc := range []struct {
		name string
		edit func(*temporaryOnlineProbeOptions)
		want string
	}{
		{name: "noncanonical administrator", edit: func(options *temporaryOnlineProbeOptions) { options.administrator = " admin" }, want: "temporary-online administrator"},
		{name: "method", edit: func(options *temporaryOnlineProbeOptions) { options.method = http.MethodPost }, want: "method must be HEAD or GET"},
		{name: "response exceeds lease cap", edit: func(options *temporaryOnlineProbeOptions) { options.responseLimit = options.maxBytes + 1 }, want: "byte limits are invalid"},
		{name: "zero byte cap", edit: func(options *temporaryOnlineProbeOptions) { options.maxBytes = 0 }, want: "byte limits are invalid"},
		{name: "lease TTL exceeds cap", edit: func(options *temporaryOnlineProbeOptions) { options.ttl = 11 * time.Minute }, want: "TTL must be positive and no longer than 10m"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			options := base
			reader := &temporaryOnlineFailReader{}
			options.input = reader
			tc.edit(&options)

			_, err := runTemporaryOnlineProbe(t.Context(), options)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("runTemporaryOnlineProbe() error = %v, want %q", err, tc.want)
			}
			if reader.reads != 0 {
				t.Fatalf("invalid input reached password reader %d time(s)", reader.reads)
			}
		})
	}
}

func TestReadTemporaryOnlinePasswordStripsOnlyOneTerminalLineEnding(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  string
	}{
		{input: " password with spaces \t\r\n", want: " password with spaces \t"},
		{input: "password\n\n", want: "password\n"},
		{input: "password\r", want: "password"},
	} {
		got, err := readTemporaryOnlinePassword(strings.NewReader(tc.input))
		if err != nil {
			t.Fatalf("readTemporaryOnlinePassword(%q): %v", tc.input, err)
		}
		if got != tc.want {
			t.Fatalf("readTemporaryOnlinePassword(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func temporaryOnlineTestFingerprint() string {
	return "sha256:" + strings.Repeat("a", 64)
}
