package cli

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/netguard"
	"github.com/LaokeQwQ/CheeseWAF/internal/setup"
	"github.com/spf13/cobra"
)

var loadSystemCertPool = x509.SystemCertPool

func newHealthcheckCommand() *cobra.Command {
	var outboundTLS string
	cmd := &cobra.Command{
		Use:    "healthcheck",
		Short:  "Check whether the local CheeseWAF admin service is ready",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if target := strings.TrimSpace(outboundTLS); target != "" {
				ctx, cancel := context.WithTimeout(cmd.Context(), 15*time.Second)
				defer cancel()
				return probeOutboundTLS(ctx, target)
			}
			cfg, err := config.Load(resolveHealthcheckConfigPath())
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Second)
			defer cancel()
			return checkAdminReadiness(ctx, cfg)
		},
	}
	cmd.Flags().StringVar(&outboundTLS, "outbound-tls", "", "HTTPS URL used to verify the system CA pool")
	return cmd
}

func resolveHealthcheckConfigPath() string {
	candidates := []string{strings.TrimSpace(configPath)}
	if env := strings.TrimSpace(os.Getenv("CHEESEWAF_CONFIG")); env != "" {
		candidates = append(candidates, env)
	}
	if strings.TrimSpace(dataDir) != "" {
		candidates = append(candidates,
			filepath.Join(dataDir, "config", setup.DefaultConfigFile),
			filepath.Join(dataDir, "config", setup.LegacyConfigFile),
			filepath.Join(dataDir, setup.LegacyConfigFile),
			filepath.Join(dataDir, setup.DefaultConfigFile),
		)
	}
	seen := map[string]struct{}{}
	first := ""
	for _, path := range candidates {
		if path == "" {
			continue
		}
		if _, dup := seen[path]; dup {
			continue
		}
		seen[path] = struct{}{}
		if first == "" {
			first = path
		}
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	if first != "" {
		return first
	}
	return configPath
}

func checkAdminReadiness(ctx context.Context, cfg *config.Config) error {
	if cfg == nil {
		return fmt.Errorf("configuration is unavailable")
	}
	host, port, err := net.SplitHostPort(strings.TrimSpace(cfg.Server.AdminListen))
	if err != nil {
		return fmt.Errorf("parse admin listener: %w", err)
	}
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if host == "" || isUnspecifiedHost(host) {
		host = "127.0.0.1"
	}
	scheme := "http"
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if cfg.Server.AdminTLS.Enabled {
		scheme = "https"
		roots, rootErr := loadSystemCertPool()
		if rootErr != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		caFile := filepath.Join(filepath.Dir(cfg.Server.AdminTLS.CertFile), setup.DefaultAdminCAFile)
		if raw, readErr := os.ReadFile(caFile); readErr == nil {
			if !roots.AppendCertsFromPEM(raw) {
				return fmt.Errorf("load admin healthcheck CA: certificate is invalid")
			}
		} else if !os.IsNotExist(readErr) {
			return fmt.Errorf("load admin healthcheck CA: %w", readErr)
		}
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
	}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+net.JoinHostPort(host, port)+"/health/ready", nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("admin readiness request failed: %w", err)
	}
	defer netguard.DrainAndClose(response.Body)
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("admin readiness returned HTTP %d", response.StatusCode)
	}
	return nil
}

func probeOutboundTLS(ctx context.Context, rawURL string) error {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return fmt.Errorf("parse outbound TLS URL: %w", err)
	}
	if parsed.Scheme != "https" || parsed.Host == "" {
		return fmt.Errorf("outbound TLS probe requires an https URL")
	}
	pool, err := loadSystemCertPool()
	if err != nil {
		return fmt.Errorf("load system CA pool: %w", err)
	}
	if pool == nil {
		return fmt.Errorf("system CA pool is empty; install ca-certificates in the runtime image")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}
	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL == nil || req.URL.Scheme != "https" {
				return fmt.Errorf("refusing non-HTTPS redirect from TLS probe")
			}
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("outbound HTTPS probe failed: %w", err)
	}
	netguard.DrainAndClose(response.Body)
	return nil
}

func isUnspecifiedHost(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsUnspecified()
}
