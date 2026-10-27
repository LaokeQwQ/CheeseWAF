package cli

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/audit"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/recovery/kms"
)

// fileRootKeySource reads the 32-byte root key that seals the embedded keyring.
// The file must be private to the process owner; a readable-by-others key is a
// startup error, never a warning.
type fileRootKeySource struct {
	path string
}

func (s fileRootKeySource) Available(context.Context) bool {
	info, err := os.Stat(s.path)
	return err == nil && info.Mode().IsRegular() && info.Size() == 32
}

func (s fileRootKeySource) Load(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	info, err := os.Stat(s.path)
	if err != nil {
		return nil, fmt.Errorf("kms root key: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("kms root key: %s must be a regular file private to the owner", s.path)
	}
	raw, err := os.ReadFile(s.path)
	if err != nil {
		return nil, fmt.Errorf("kms root key: %w", err)
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("kms root key: %s must contain exactly 32 bytes", s.path)
	}
	return raw, nil
}

// internalAuthorizer permits only the envelope operations the serving process
// performs on its own behalf. Rotation and revocation stay unavailable until an
// approval-backed authorizer exists.
type internalAuthorizer struct{}

func (internalAuthorizer) Authorize(_ context.Context, access kms.Access) error {
	switch access.Operation {
	case kms.Wrap, kms.Unwrap, kms.Rewrap:
		return nil
	default:
		return kms.ErrPermission
	}
}

// kmsAuditSink records key operations in the signed audit stream when one is
// composed. Without a stream the runtime still refuses nothing: the KMS runtime
// owns its own audit requirement and was constructed with this sink.
type kmsAuditSink struct {
	stream *audit.Runtime
}

func (s kmsAuditSink) Append(ctx context.Context, event kms.Event) error {
	if s.stream == nil {
		return nil
	}
	outcome := audit.OutcomeSuccess
	if event.Result != "" && event.Result != "success" {
		outcome = audit.OutcomeFailure
	}
	_, err := s.stream.Append(ctx, audit.Event{
		EventID:     fmt.Sprintf("kms-%d-%s", event.At.UnixNano(), event.Operation),
		StreamID:    "api",
		TenantID:    nonEmpty(event.TenantID, "default"),
		Actor:       nonEmpty(event.Actor, "system"),
		Type:        audit.EventTypeKeyOperation,
		Action:      string(event.Operation),
		Resource:    nonEmpty(event.KeyID, "kms"),
		Outcome:     outcome,
		Class:       audit.EventClassNormal,
		At:          event.At,
		PolicyEpoch: maxUint64(event.PolicyEpoch, 1),
	})
	return err
}

func nonEmpty(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func maxUint64(value, floor uint64) uint64 {
	if value < floor {
		return floor
	}
	return value
}

// openKMSRuntime composes the configured key provider. The returned closer
// closes the embedded keyring; it is nil for an external KMS backend.
func openKMSRuntime(cfg config.KMSConfig, policyEpoch uint64, keyVersion string, sink *audit.Runtime) (*kms.Runtime, io.Closer, error) {
	if !cfg.Enabled {
		return nil, nil, nil
	}
	binding := kms.Binding{
		TenantID:    cfg.TenantID,
		KeyID:       cfg.KeyID,
		Scope:       cfg.Scope,
		Actor:       cfg.Actor,
		PolicyEpoch: maxUint64(policyEpoch, 1),
	}
	options := kms.Options{
		Binding:    binding,
		Fallback:   kms.FallbackPolicy{Approved: cfg.Embedded.Approved, Mode: kms.DeploymentMode(cfg.Embedded.Mode)},
		Authorizer: internalAuthorizer{},
		Audit:      kmsAuditSink{stream: sink},
	}
	var closer io.Closer
	if strings.TrimSpace(cfg.Endpoint) != "" {
		client, err := kmsHTTPClient(cfg)
		if err != nil {
			return nil, nil, err
		}
		backend, err := kms.NewHTTPBackend(kms.HTTPOptions{
			Endpoint: cfg.Endpoint,
			Client:   client,
			Token:    fileTokenSource(cfg.TokenFile),
			Timeout:  cfg.Timeout,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("kms external backend: %w", err)
		}
		options.External = backend
	} else {
		source := fileRootKeySource{path: cfg.Embedded.RootKeyFile}
		var (
			keyring *kms.EncryptedKeyring
			err     error
		)
		if _, statErr := os.Stat(cfg.Embedded.KeyringFile); statErr == nil {
			keyring, err = kms.LoadKeyringFile(context.Background(), cfg.Embedded.KeyringFile, source)
		} else if os.IsNotExist(statErr) {
			keyring, err = kms.NewEncryptedKeyring(source)
			if err == nil {
				err = provisionKeyring(context.Background(), keyring, binding, keyVersion)
			}
			if err == nil {
				err = kms.SaveKeyringFile(context.Background(), cfg.Embedded.KeyringFile, keyring)
			}
		} else {
			err = statErr
		}
		if err != nil {
			return nil, nil, fmt.Errorf("kms embedded keyring: %w", err)
		}
		options.Embedded = kms.NewKeyringBackend(keyring)
		closer = keyring
	}
	runtime, err := kms.NewRuntime(options)
	if err != nil {
		if closer != nil {
			_ = closer.Close()
		}
		return nil, nil, fmt.Errorf("kms runtime: %w", err)
	}
	return runtime, closer, nil
}

// provisionKeyring creates the first KEK version. Without it a fresh keyring
// has no entry and every wrap would fail with ErrVersion.
func provisionKeyring(ctx context.Context, keyring *kms.EncryptedKeyring, binding kms.Binding, keyVersion string) error {
	if keyring == nil {
		return kms.ErrUnsupported
	}
	version := strings.TrimSpace(keyVersion)
	if version == "" {
		version = "v1"
	}
	kek := make([]byte, 32)
	if _, err := rand.Read(kek); err != nil {
		return fmt.Errorf("kms keyring: generate kek: %w", err)
	}
	defer func() {
		for i := range kek {
			kek[i] = 0
		}
	}()
	ref := kms.KeyRef{
		TenantID:    binding.TenantID,
		KeyID:       binding.KeyID,
		Version:     version,
		Scope:       binding.Scope,
		Actor:       binding.Actor,
		PolicyEpoch: binding.PolicyEpoch,
	}
	if err := keyring.Rotate(ctx, ref, kek); err != nil {
		return fmt.Errorf("kms keyring: provision version %q: %w", version, err)
	}
	return nil
}

func kmsHTTPClient(cfg config.KMSConfig) (*http.Client, error) {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: cfg.ServerName}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("kms ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("kms ca_file: %s contains no certificates", cfg.CAFile)
		}
		tlsConfig.RootCAs = pool
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

// fileTokenSource reads a bearer token from a private file on every call so key
// rotation does not require a restart.
func fileTokenSource(path string) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		if !filepath.IsAbs(path) {
			return "", fmt.Errorf("kms token_file must be absolute")
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("kms token_file: %w", err)
		}
		token := strings.TrimSpace(string(raw))
		if token == "" || len(token) > 4096 {
			return "", fmt.Errorf("kms token_file contains an invalid token")
		}
		return token, nil
	}
}
