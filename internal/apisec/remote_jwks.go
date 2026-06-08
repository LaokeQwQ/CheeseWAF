package apisec

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

const (
	defaultJWKSFetchTimeout = 5 * time.Second
	maxRemoteJWKSBytes      = 1 << 20
)

var (
	remoteJWKSClientFactory = newRemoteJWKSHTTPClient
	remoteJWKSURLValidator  = validateRemoteJWKSURL
)

type remoteJWKSSource struct {
	url             string
	cacheFile       string
	refreshInterval time.Duration
	timeout         time.Duration
	client          *http.Client

	mu          sync.RWMutex
	keys        []jwtKey
	lastRefresh time.Time
	lastError   error

	stop        chan struct{}
	done        chan struct{}
	startedOnce sync.Once
	closedOnce  sync.Once
}

func newRemoteJWKSSource(cfg config.APIAuthConfig) (*remoteJWKSSource, error) {
	rawURL := strings.TrimSpace(cfg.JWKSURL)
	if rawURL != "" {
		if err := remoteJWKSURLValidator(rawURL); err != nil {
			return nil, fmt.Errorf("invalid remote JWKS URL: %w", err)
		}
	}
	interval := cfg.JWKSRefresh
	if interval == 0 {
		interval = time.Hour
	}
	if interval > 0 && interval < time.Minute {
		return nil, fmt.Errorf("remote JWKS refresh interval must be at least 1m")
	}
	return &remoteJWKSSource{
		url:             rawURL,
		cacheFile:       strings.TrimSpace(cfg.JWKSCacheFile),
		refreshInterval: interval,
		timeout:         defaultJWKSFetchTimeout,
		client:          remoteJWKSClientFactory(defaultJWKSFetchTimeout),
		stop:            make(chan struct{}),
		done:            make(chan struct{}),
	}, nil
}

func (s *remoteJWKSSource) HasURL() bool {
	return s != nil && s.url != ""
}

func (s *remoteJWKSSource) HasKeys() bool {
	return len(s.Keys()) > 0
}

func (s *remoteJWKSSource) Keys() []jwtKey {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]jwtKey(nil), s.keys...)
}

func (s *remoteJWKSSource) LoadCache() error {
	if s == nil || s.cacheFile == "" {
		return nil
	}
	contents, err := os.ReadFile(s.cacheFile)
	if err != nil {
		if os.IsNotExist(err) && s.HasURL() {
			return nil
		}
		return fmt.Errorf("read JWKS cache file: %w", err)
	}
	keys, err := publicKeysFromJWKS(contents)
	if err != nil {
		return fmt.Errorf("parse JWKS cache file: %w", err)
	}
	s.setKeys(keys, nil)
	return nil
}

func (s *remoteJWKSSource) RefreshOnce() error {
	if s == nil || s.url == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()
	return s.refresh(ctx)
}

func (s *remoteJWKSSource) Start() {
	if s == nil || s.url == "" || s.refreshInterval <= 0 {
		return
	}
	s.startedOnce.Do(func() {
		go s.run()
	})
}

func (s *remoteJWKSSource) Close() {
	if s == nil {
		return
	}
	s.closedOnce.Do(func() {
		close(s.stop)
		if s.url != "" && s.refreshInterval > 0 {
			<-s.done
		}
	})
}

func (s *remoteJWKSSource) run() {
	defer close(s.done)
	ticker := time.NewTicker(s.refreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			_ = s.RefreshOnce()
		case <-s.stop:
			return
		}
	}
}

func (s *remoteJWKSSource) refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		s.setError(err)
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "CheeseWAF-JWKS/0.1")
	resp, err := s.client.Do(req)
	if err != nil {
		s.setError(err)
		return fmt.Errorf("fetch remote JWKS: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		err := fmt.Errorf("fetch remote JWKS: unexpected status %d", resp.StatusCode)
		s.setError(err)
		return err
	}
	limited := io.LimitReader(resp.Body, maxRemoteJWKSBytes+1)
	contents, err := io.ReadAll(limited)
	if err != nil {
		s.setError(err)
		return fmt.Errorf("read remote JWKS: %w", err)
	}
	if len(contents) > maxRemoteJWKSBytes {
		err := fmt.Errorf("remote JWKS exceeds %d bytes", maxRemoteJWKSBytes)
		s.setError(err)
		return err
	}
	keys, err := publicKeysFromJWKS(contents)
	if err != nil {
		s.setError(err)
		return fmt.Errorf("parse remote JWKS: %w", err)
	}
	if err := s.writeCache(contents); err != nil {
		s.setError(err)
		return err
	}
	s.setKeys(keys, nil)
	return nil
}

func (s *remoteJWKSSource) writeCache(contents []byte) error {
	if s.cacheFile == "" {
		return nil
	}
	dir := filepath.Dir(s.cacheFile)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create JWKS cache directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".jwks-cache-*")
	if err != nil {
		return fmt.Errorf("create JWKS cache temp file: %w", err)
	}
	tmpName := tmp.Name()
	_, writeErr := tmp.Write(contents)
	closeErr := tmp.Close()
	if writeErr != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("write JWKS cache temp file: %w", writeErr)
	}
	if closeErr != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("close JWKS cache temp file: %w", closeErr)
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("chmod JWKS cache temp file: %w", err)
	}
	if err := os.Rename(tmpName, s.cacheFile); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("replace JWKS cache file: %w", err)
	}
	return nil
}

func (s *remoteJWKSSource) setKeys(keys []jwtKey, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys = append([]jwtKey(nil), keys...)
	s.lastRefresh = time.Now().UTC()
	s.lastError = err
}

func (s *remoteJWKSSource) setError(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastError = err
}

func validateRemoteJWKSURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if parsed.Scheme != "https" {
		return fmt.Errorf("only https JWKS URLs are allowed")
	}
	if parsed.User != nil {
		return fmt.Errorf("credentials in JWKS URL are not allowed")
	}
	if parsed.Fragment != "" {
		return fmt.Errorf("fragments in JWKS URL are not allowed")
	}
	host := strings.Trim(parsed.Hostname(), "[]")
	if host == "" {
		return fmt.Errorf("host is required")
	}
	if ip := net.ParseIP(host); ip != nil && !publicJWKSIP(ip) {
		return fmt.Errorf("host IP must be public")
	}
	return nil
}

func newRemoteJWKSHTTPClient(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{Timeout: timeout}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				host, port, err := net.SplitHostPort(address)
				if err != nil {
					return nil, err
				}
				ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
				if err != nil {
					return nil, err
				}
				for _, ip := range ips {
					if !publicJWKSIP(ip) {
						return nil, fmt.Errorf("remote JWKS host resolved to non-public IP %s", ip)
					}
				}
				if len(ips) == 0 {
					return nil, fmt.Errorf("remote JWKS host resolved to no IP addresses")
				}
				return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
			},
			TLSHandshakeTimeout:   timeout,
			ResponseHeaderTimeout: timeout,
		},
	}
}

func publicJWKSIP(ip net.IP) bool {
	return ip != nil &&
		ip.IsGlobalUnicast() &&
		!ip.IsLoopback() &&
		!ip.IsPrivate() &&
		!ip.IsLinkLocalUnicast() &&
		!ip.IsLinkLocalMulticast() &&
		!ip.IsMulticast() &&
		!ip.IsUnspecified()
}
