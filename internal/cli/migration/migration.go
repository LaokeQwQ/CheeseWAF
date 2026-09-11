// Package migration exposes the local CLI wrapper for the protected
// temporary-to-production migration contract.
package migration

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/approval"
	setupmigration "github.com/LaokeQwQ/CheeseWAF/internal/setup/migration"
	"github.com/spf13/cobra"
)

var (
	ErrInvalidPromptOptions = errors.New("invalid migration prompt options")
	ErrConfirmationPhrase   = errors.New("migration confirmation phrase is invalid")
	ErrSecondConfirmation   = errors.New("migration second confirmation is required")
	ErrPasswordConfirmation = errors.New("migration password or TOTP confirmation is required")
)

// Runner is the narrow setup/migration execution seam used by the CLI.
type Runner interface {
	Run(context.Context, setupmigration.ConfirmationRequest) (setupmigration.Result, error)
}

// PromptOptions carries non-secret identity and adapter proof into the CLI
// prompt. Password/TOTP verification is performed by the injected provider in
// setup/migration; this layer records only the completed proof.
type PromptOptions struct {
	Actor             string
	SessionID         string
	Language          string
	ConfirmationID    string
	PasswordConfirmed bool
	TOTPConfirmed     bool
	Local             bool
	Warnings          []string
	Now               func() time.Time
	Wait              func(context.Context, time.Duration) error
}

// CollectConfirmation prints each warning and requires a complete warning
// delay for every warning. It then reads the exact server phrase and a second
// confirmation from input. The phrase is never trimmed or case-folded.
func CollectConfirmation(ctx context.Context, in io.Reader, out io.Writer, opts PromptOptions) (setupmigration.ConfirmationRequest, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if in == nil || out == nil || opts.Actor == "" || opts.SessionID == "" || opts.ConfirmationID == "" {
		return setupmigration.ConfirmationRequest{}, ErrInvalidPromptOptions
	}
	language := opts.Language
	if language == "" {
		language = approval.DefaultConfirmationLanguage
	}
	canonical, err := approval.NormalizeConfirmationLanguage(language)
	if err != nil {
		return setupmigration.ConfirmationRequest{}, fmt.Errorf("%w: language", ErrInvalidPromptOptions)
	}
	phrase, err := approval.ExpectedConfirmationPhrase(canonical)
	if err != nil {
		return setupmigration.ConfirmationRequest{}, fmt.Errorf("%w: phrase", ErrInvalidPromptOptions)
	}
	wait := opts.Wait
	if wait == nil {
		wait = func(ctx context.Context, d time.Duration) error {
			timer := time.NewTimer(d)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-timer.C:
				return nil
			}
		}
	}
	warnings := opts.Warnings
	if len(warnings) == 0 {
		warnings = []string{"Switching management storage from temporary SQLite to production PostgreSQL changes the control-plane trust boundary."}
	}
	for _, warning := range warnings {
		if warning == "" {
			return setupmigration.ConfirmationRequest{}, ErrInvalidPromptOptions
		}
		if _, err := fmt.Fprintf(out, "WARNING: %s\nRead this warning for at least %s before continuing.\n", warning, setupmigration.WarningDelay); err != nil {
			return setupmigration.ConfirmationRequest{}, err
		}
		if err := wait(ctx, setupmigration.WarningDelay); err != nil {
			return setupmigration.ConfirmationRequest{}, err
		}
	}
	reader, ok := in.(*bufio.Reader)
	if !ok {
		reader = bufio.NewReader(in)
	}
	if _, err := fmt.Fprintf(out, "Type %q to confirm: ", phrase); err != nil {
		return setupmigration.ConfirmationRequest{}, err
	}
	rawPhrase, err := readLine(reader)
	if err != nil {
		return setupmigration.ConfirmationRequest{}, err
	}
	if rawPhrase != phrase {
		return setupmigration.ConfirmationRequest{}, ErrConfirmationPhrase
	}
	if _, err := fmt.Fprint(out, "Type yes for the second confirmation: "); err != nil {
		return setupmigration.ConfirmationRequest{}, err
	}
	rawSecond, err := readLine(reader)
	if err != nil {
		return setupmigration.ConfirmationRequest{}, err
	}
	answer := strings.ToLower(strings.TrimSpace(rawSecond))
	if answer != "yes" && answer != "y" {
		return setupmigration.ConfirmationRequest{}, ErrSecondConfirmation
	}
	now := time.Now().UTC()
	if opts.Now != nil {
		now = opts.Now().UTC()
	}
	return setupmigration.ConfirmationRequest{
		Actor: opts.Actor, SessionID: opts.SessionID, Language: canonical, Phrase: rawPhrase,
		WarningReadAt: now.Add(-setupmigration.WarningDelay), PasswordConfirmed: opts.PasswordConfirmed,
		TOTPConfirmed: opts.TOTPConfirmed, SecondConfirmation: true, ConfirmationID: opts.ConfirmationID,
		Local: opts.Local,
	}, nil
}

// Execute runs the prompt and then the injected migration runner.
func Execute(ctx context.Context, in io.Reader, out io.Writer, runner Runner, opts PromptOptions) (setupmigration.Result, error) {
	if runner == nil {
		return setupmigration.Result{}, ErrInvalidPromptOptions
	}
	confirmation, err := CollectConfirmation(ctx, in, out, opts)
	if err != nil {
		return setupmigration.Result{}, err
	}
	if !confirmation.PasswordConfirmed && !confirmation.TOTPConfirmed {
		return setupmigration.Result{}, ErrPasswordConfirmation
	}
	return runner.Run(ctx, confirmation)
}

// NewCommand returns the injected contract command used by focused tests and
// embedding callers. The root CLI registers NewRuntimeCommand instead.
func NewCommand(runner Runner) *cobra.Command {
	opts := PromptOptions{Local: true}
	cmd := &cobra.Command{
		Use:   "migration temporary-to-production",
		Short: "Migrate temporary management state to production storage",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			result, err := Execute(cmd.Context(), cmd.InOrStdin(), cmd.OutOrStdout(), runner, opts)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "production migration committed: snapshot=%s\n", result.SnapshotID)
			return err
		},
	}
	cmd.Flags().StringVar(&opts.Actor, "actor", "", "current administrator identity")
	cmd.Flags().StringVar(&opts.SessionID, "session-id", "", "current local administrator session")
	cmd.Flags().StringVar(&opts.Language, "language", approval.DefaultConfirmationLanguage, "confirmation language")
	cmd.Flags().StringVar(&opts.ConfirmationID, "confirmation-id", "", "one-time confirmation ID")
	cmd.Flags().StringSliceVar(&opts.Warnings, "warning", nil, "warning text to display (repeatable)")
	return cmd
}

func readLine(reader *bufio.Reader) (string, error) {
	text, err := reader.ReadString('\n')
	text = strings.TrimSuffix(text, "\n")
	text = strings.TrimSuffix(text, "\r")
	if err != nil {
		if errors.Is(err, io.EOF) && text != "" {
			return text, nil
		}
		return "", err
	}
	return text, nil
}
