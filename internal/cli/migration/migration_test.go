package migration

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	setupmigration "github.com/LaokeQwQ/CheeseWAF/internal/setup/migration"
)

type fakeRunner struct {
	calls  int
	req    setupmigration.ConfirmationRequest
	result setupmigration.Result
	err    error
}

func (r *fakeRunner) Run(_ context.Context, req setupmigration.ConfirmationRequest) (setupmigration.Result, error) {
	r.calls++
	r.req = req
	return r.result, r.err
}

func fastPromptOptions() PromptOptions {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	return PromptOptions{
		Actor:             "operator",
		SessionID:         "session-a",
		Language:          "en-US",
		Warnings:          []string{"first warning", "second warning"},
		PasswordConfirmed: true,
		Local:             true,
		Now:               func() time.Time { return now },
		Wait:              func(context.Context, time.Duration) error { return nil },
		ConfirmationID:    "confirm-1",
	}
}

func TestCollectConfirmationWaitsForEveryWarningAndRequiresExactPhrase(t *testing.T) {
	waits := make([]time.Duration, 0, 2)
	opts := fastPromptOptions()
	opts.Wait = func(_ context.Context, d time.Duration) error { waits = append(waits, d); return nil }
	req, err := CollectConfirmation(context.Background(), strings.NewReader("CONFIRM\ny\n"), &strings.Builder{}, opts)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(waits) != 2 || waits[0] < setupmigration.WarningDelay || waits[1] < setupmigration.WarningDelay {
		t.Fatalf("waits=%v, want one >= %s per warning", waits, setupmigration.WarningDelay)
	}
	if req.Language != "en-US" || req.Phrase != "CONFIRM" || !req.SecondConfirmation || !req.PasswordConfirmed || !req.Local {
		t.Fatalf("confirmation=%+v", req)
	}
}

func TestCollectConfirmationRejectsWrongPhraseBeforeRunner(t *testing.T) {
	_, err := CollectConfirmation(context.Background(), strings.NewReader("confirm\ny\n"), &strings.Builder{}, fastPromptOptions())
	if !errors.Is(err, ErrConfirmationPhrase) {
		t.Fatalf("error=%v, want exact phrase rejection", err)
	}
}

func TestExecutePassesConfirmationToRunner(t *testing.T) {
	runner := &fakeRunner{result: setupmigration.Result{Committed: true}}
	result, err := Execute(context.Background(), strings.NewReader("CONFIRM\ny\n"), &strings.Builder{}, runner, fastPromptOptions())
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if runner.calls != 1 || !result.Committed || runner.req.ConfirmationID != "confirm-1" {
		t.Fatalf("calls=%d req=%+v result=%+v", runner.calls, runner.req, result)
	}
}

func TestNewCommandExposesProtectedMigrationWorkflow(t *testing.T) {
	runner := &fakeRunner{result: setupmigration.Result{Committed: true}}
	cmd := NewCommand(runner)
	if cmd == nil || cmd.Use != "migration temporary-to-production" {
		t.Fatalf("command=%v", cmd)
	}
	if cmd.RunE == nil {
		t.Fatal("command has no execution handler")
	}
}

func TestNewRuntimeCommandExposesExplicitRecoveryWithoutSessionBypass(t *testing.T) {
	root := NewRuntimeCommand(RuntimeOptions{})
	recover, _, err := root.Find([]string{"recover"})
	if err != nil || recover == nil || recover.Use != "recover" {
		t.Fatalf("recover command=%v err=%v", recover, err)
	}
	for _, required := range []string{"actor", "language", "password-stdin", "totp-stdin"} {
		if recover.Flags().Lookup(required) == nil {
			t.Fatalf("recovery flag %q is missing", required)
		}
	}
	for _, forbidden := range []string{"session-id", "password-confirmed", "totp-confirmed", "force", "skip-confirmation"} {
		if recover.Flags().Lookup(forbidden) != nil {
			t.Fatalf("unsafe recovery flag %q is exposed", forbidden)
		}
	}
}
