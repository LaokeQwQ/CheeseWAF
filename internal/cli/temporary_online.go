package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/identity"
	"github.com/LaokeQwQ/CheeseWAF/internal/netlease"
	"github.com/LaokeQwQ/CheeseWAF/internal/setup"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
	"github.com/spf13/cobra"
)

const temporaryOnlineAuditFile = "netlease.jsonl"

// newTemporaryOnlineCommand intentionally creates no background service. Each
// child command is a single, administrator-confirmed lease and connection.
func newTemporaryOnlineCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "temporary-online",
		Short: "Run one administrator-confirmed temporary HTTPS probe",
		Long:  "Open one pinned HTTPS connection through the temporary-online broker. This command is explicit and one-shot; cheesewaf serve never starts an external network worker from this command.",
	}
	cmd.AddCommand(newTemporaryOnlineProbeCommand())
	return cmd
}

func newTemporaryOnlineProbeCommand() *cobra.Command {
	var options temporaryOnlineProbeOptions
	cmd := &cobra.Command{
		Use:   "probe",
		Short: "Probe one pinned HTTPS target through a one-shot Socket Lease",
		RunE: func(cmd *cobra.Command, _ []string) error {
			options.input = cmd.InOrStdin()
			result, err := runTemporaryOnlineProbe(cmd.Context(), options)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "temporary-online probe status=%d target=%s:%d bytes_sent=%d bytes_received=%d audit=%s\n", result.status, result.host, result.port, result.bytesSent, result.bytesReceived, result.auditPath)
			return err
		},
	}
	cmd.Flags().StringVar(&options.administrator, "administrator", "", "Exact local administrator username")
	cmd.Flags().BoolVar(&options.passwordStdin, "password-stdin", false, "Read the administrator password from stdin")
	cmd.Flags().StringVar(&options.pluginID, "plugin-id", "", "Exact plugin ID bound to this lease")
	cmd.Flags().StringVar(&options.pluginVersion, "plugin-version", "", "Exact plugin version bound to this lease")
	cmd.Flags().StringVar(&options.host, "host", "", "Lowercase HTTPS target hostname")
	cmd.Flags().IntVar(&options.port, "port", 443, "HTTPS target port")
	cmd.Flags().StringVar(&options.path, "path", "/", "Relative HTTPS path")
	cmd.Flags().StringVar(&options.method, "method", http.MethodHead, "Probe method: HEAD or GET")
	cmd.Flags().StringVar(&options.tlsFingerprint, "tls-fingerprint", "", "Required sha256:<lowercase-hex> certificate pin")
	cmd.Flags().DurationVar(&options.ttl, "ttl", time.Minute, "Temporary session and lease TTL (maximum 10m)")
	cmd.Flags().Int64Var(&options.maxBytes, "max-bytes", 1<<20, "Total wire-byte cap for the lease")
	cmd.Flags().Int64Var(&options.responseLimit, "response-limit", 256<<10, "Maximum response body bytes")
	_ = cmd.MarkFlagRequired("administrator")
	_ = cmd.MarkFlagRequired("password-stdin")
	_ = cmd.MarkFlagRequired("plugin-id")
	_ = cmd.MarkFlagRequired("plugin-version")
	_ = cmd.MarkFlagRequired("host")
	_ = cmd.MarkFlagRequired("tls-fingerprint")
	return cmd
}

type temporaryOnlineProbeOptions struct {
	administrator, pluginID, pluginVersion string
	host, path, method, tlsFingerprint     string
	port                                   int
	ttl                                    time.Duration
	maxBytes, responseLimit                int64
	passwordStdin                          bool
	input                                  io.Reader
}

type temporaryOnlineProbeResult struct {
	status                   int
	host, auditPath          string
	port                     int
	bytesSent, bytesReceived int64
}

func runTemporaryOnlineProbe(ctx context.Context, options temporaryOnlineProbeOptions) (temporaryOnlineProbeResult, error) {
	if !options.passwordStdin {
		return temporaryOnlineProbeResult{}, errors.New("temporary-online requires --password-stdin; passwords are never accepted as command-line flags")
	}
	if err := identity.ValidateUsername(options.administrator); err != nil {
		return temporaryOnlineProbeResult{}, fmt.Errorf("temporary-online administrator: %w", err)
	}
	if options.method != http.MethodHead && options.method != http.MethodGet {
		return temporaryOnlineProbeResult{}, errors.New("temporary-online probe method must be HEAD or GET")
	}
	if options.maxBytes <= 0 || options.responseLimit <= 0 || options.responseLimit > options.maxBytes {
		return temporaryOnlineProbeResult{}, errors.New("temporary-online byte limits are invalid")
	}
	if options.ttl <= 0 || options.ttl > netlease.MaxLeaseTTL {
		return temporaryOnlineProbeResult{}, errors.New("temporary-online TTL must be positive and no longer than 10m")
	}
	if options.host == "" || options.host != strings.ToLower(options.host) || netlease.ValidateTLSFingerprint(options.tlsFingerprint) != nil {
		return temporaryOnlineProbeResult{}, errors.New("temporary-online target or TLS fingerprint is invalid")
	}
	target := netlease.Target{Host: options.host, Port: options.port, Protocol: "https"}
	if err := target.Validate(); err != nil {
		return temporaryOnlineProbeResult{}, err
	}
	password, err := readTemporaryOnlinePassword(options.input)
	if err != nil {
		return temporaryOnlineProbeResult{}, err
	}
	sqlitePath, err := cliSQLitePath()
	if err != nil {
		return temporaryOnlineProbeResult{}, err
	}
	store, err := storage.OpenSQLite(sqlitePath)
	if err != nil {
		return temporaryOnlineProbeResult{}, err
	}
	defer store.Close()
	if err := store.Migrate(ctx); err != nil {
		return temporaryOnlineProbeResult{}, err
	}
	administrator, err := store.GetUserByUsername(ctx, options.administrator)
	if err != nil {
		return temporaryOnlineProbeResult{}, err
	}
	if administrator == nil || administrator.Role != "admin" {
		return temporaryOnlineProbeResult{}, errors.New("temporary-online requires an existing administrator account")
	}
	runtimeDataDir := dataDir
	if runtimeDataDir == "" {
		runtimeDataDir = setup.DefaultDataDir
	}
	auditPath := filepath.Join(runtimeDataDir, "audit", temporaryOnlineAuditFile)
	auditSink, err := netlease.NewFileAuditSink(auditPath)
	if err != nil {
		return temporaryOnlineProbeResult{}, err
	}
	authenticator := netlease.StoreAdministratorAuthenticator{Store: store, AllowLocalWithoutManagementSession: true}
	sessions, err := netlease.NewTemporarySessionManager(netlease.TemporarySessionManagerOptions{Authenticator: authenticator})
	if err != nil {
		return temporaryOnlineProbeResult{}, err
	}
	broker, err := netlease.NewBroker(netlease.BrokerConfig{
		Enabled:              true,
		Production:           true,
		Policy:               netlease.NewOfflinePolicyWithEpoch(nil, 1),
		Sessions:             sessions,
		Transport:            netlease.NewStandardTransport(),
		Addresses:            netlease.PublicAddressPolicy{},
		Audit:                auditSink,
		MaxHTTPBodyBytes:     64 << 10,
		MaxHTTPResponseBytes: options.responseLimit,
		OperationTimeout:     options.ttl,
	})
	if err != nil {
		return temporaryOnlineProbeResult{}, err
	}
	response, err := broker.ExecuteTemporaryHTTP(ctx, netlease.TemporaryHTTPExecution{
		Identity:         netlease.AdministratorIdentity{ID: administrator.ID},
		Password:         password,
		PluginID:         options.pluginID,
		PluginVersion:    options.pluginVersion,
		Target:           target,
		TLSFingerprint:   options.tlsFingerprint,
		PolicyEpoch:      1,
		TTL:              options.ttl,
		MaxBytes:         options.maxBytes,
		Method:           options.method,
		Path:             options.path,
		MaxResponseBytes: options.responseLimit,
	})
	if err != nil {
		return temporaryOnlineProbeResult{}, fmt.Errorf("temporary-online transport: %w", err)
	}
	return temporaryOnlineProbeResult{status: response.StatusCode, host: target.Host, port: target.Port, bytesSent: response.BytesSent, bytesReceived: response.BytesReceived, auditPath: auditPath}, nil
}

func readTemporaryOnlinePassword(input io.Reader) (string, error) {
	if input == nil {
		input = os.Stdin
	}
	data, err := io.ReadAll(io.LimitReader(input, 64<<10+1))
	if err != nil {
		return "", err
	}
	if len(data) > 64<<10 {
		return "", errors.New("temporary-online password input exceeds limit")
	}
	password := string(data)
	if strings.HasSuffix(password, "\r\n") {
		password = strings.TrimSuffix(password, "\r\n")
	} else if strings.HasSuffix(password, "\n") || strings.HasSuffix(password, "\r") {
		password = password[:len(password)-1]
	}
	if password == "" {
		return "", errors.New("temporary-online password is required")
	}
	return password, nil
}
