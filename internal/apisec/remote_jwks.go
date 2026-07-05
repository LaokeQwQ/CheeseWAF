package apisec

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/netguard"
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
	running     bool
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
		s.mu.Lock()
		s.running = true
		s.mu.Unlock()
		go s.run()
	})
}

func (s *remoteJWKSSource) Close() {
	if s == nil {
		return
	}
	s.closedOnce.Do(func() {
		s.mu.RLock()
		running := s.running
		s.mu.RUnlock()
		close(s.stop)
		if running {
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
	_, err := netguard.ValidateURL(raw, netguard.URLPolicy{
		Purpose:        "JWKS",
		HostPurpose:    "remote JWKS",
		AllowedSchemes: []string{"https"},
	})
	return err
}

func newRemoteJWKSHTTPClient(timeout time.Duration) *http.Client {
	return netguard.NewHTTPClient(netguard.HTTPClientOptions{
		Timeout: timeout,
		Policy: netguard.URLPolicy{
			Purpose:        "JWKS",
			HostPurpose:    "remote JWKS",
			AllowedSchemes: []string{"https"},
		},
	})
}
