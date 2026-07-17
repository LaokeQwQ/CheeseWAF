package cli

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/setup"
	"github.com/spf13/cobra"
)

func newHealthcheckCommand() *cobra.Command {
	return &cobra.Command{
		Use:    "healthcheck",
		Short:  "Check whether the local CheeseWAF admin service is ready",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(configPath)
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Second)
			defer cancel()
			return checkAdminReadiness(ctx, cfg)
		},
	}
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
		roots, rootErr := x509.SystemCertPool()
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
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4<<10))
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("admin readiness returned HTTP %d", response.StatusCode)
	}
	return nil
}

func isUnspecifiedHost(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsUnspecified()
}
