package apisec

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/fsguard"
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
	cacheRoot       string
	cacheRel        string
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
	cacheFile := strings.TrimSpace(cfg.JWKSCacheFile)
	cacheRoot, cacheRel, err := resolveJWKSCachePath(cacheFile, cfg.JWKSCacheRoot)
	if err != nil {
		return nil, err
	}
	return &remoteJWKSSource{
		url:             rawURL,
		cacheFile:       cacheFile,
		cacheRoot:       cacheRoot,
		cacheRel:        cacheRel,
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
	root, err := s.openCacheRoot(false)
	if err != nil {
		if os.IsNotExist(err) && s.HasURL() {
			return nil
		}
		return fmt.Errorf("open JWKS cache root: %w", err)
	}
	defer root.Close()
	info, err := root.Lstat(s.cacheRel)
	if err == nil && (!info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0) {
		return fmt.Errorf("read JWKS cache file: target must be a regular non-symlink file")
	}
	file, err := root.Open(s.cacheRel)
	if err != nil {
		if os.IsNotExist(err) && s.HasURL() {
			return nil
		}
		return fmt.Errorf("read JWKS cache file: %w", err)
	}
	defer file.Close()
	contents, err := io.ReadAll(io.LimitReader(file, maxRemoteJWKSBytes+1))
	if err != nil {
		return fmt.Errorf("read JWKS cache file: %w", err)
	}
	if len(contents) > maxRemoteJWKSBytes {
		return fmt.Errorf("JWKS cache exceeds %d bytes", maxRemoteJWKSBytes)
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
	defer func() { _ = netguard.DrainAndClose(resp.Body) }()
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
	root, err := s.openCacheRoot(true)
	if err != nil {
		return fmt.Errorf("open JWKS cache root: %w", err)
	}
	defer root.Close()
	parent := filepath.Dir(s.cacheRel)
	if parent != "." {
		if err := root.MkdirAll(parent, 0o700); err != nil {
			return fmt.Errorf("create JWKS cache directory: %w", err)
		}
		if err := rejectJWKSCacheSymlinkParents(root, parent); err != nil {
			return err
		}
	}
	if info, statErr := root.Lstat(s.cacheRel); statErr == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("replace JWKS cache file: target must be a regular non-symlink file")
		}
	} else if !os.IsNotExist(statErr) {
		return fmt.Errorf("inspect JWKS cache file: %w", statErr)
	}
	tmpRel, tmp, err := createJWKSCacheTemp(root, parent)
	if err != nil {
		return err
	}
	_, writeErr := tmp.Write(contents)
	syncErr := tmp.Sync()
	closeErr := tmp.Close()
	if writeErr != nil {
		_ = root.Remove(tmpRel)
		return fmt.Errorf("write JWKS cache temp file: %w", writeErr)
	}
	if syncErr != nil {
		_ = root.Remove(tmpRel)
		return fmt.Errorf("sync JWKS cache temp file: %w", syncErr)
	}
	if closeErr != nil {
		_ = root.Remove(tmpRel)
		return fmt.Errorf("close JWKS cache temp file: %w", closeErr)
	}
	if err := root.Rename(tmpRel, s.cacheRel); err != nil {
		_ = root.Remove(tmpRel)
		return fmt.Errorf("replace JWKS cache file: %w", err)
	}
	return nil
}

func resolveJWKSCachePath(cacheFile, configuredRoot string) (string, string, error) {
	if cacheFile == "" {
		return "", "", nil
	}
	root := strings.TrimSpace(configuredRoot)
	if root == "" {
		root = filepath.Dir(cacheFile)
	}
	rootAbs, err := filepath.Abs(filepath.Clean(root))
	if err != nil {
		return "", "", fmt.Errorf("resolve JWKS cache root: %w", err)
	}
	cachePath := filepath.Clean(cacheFile)
	if !filepath.IsAbs(cachePath) {
		candidateAbs, absErr := filepath.Abs(cachePath)
		if absErr == nil {
			if rel, relErr := filepath.Rel(rootAbs, candidateAbs); relErr == nil && filepath.IsLocal(rel) {
				cachePath = candidateAbs
			} else if filepath.IsLocal(cachePath) {
				cachePath = filepath.Join(rootAbs, cachePath)
			}
		}
	}
	rel, err := fsguard.RelUnderRoot(rootAbs, cachePath)
	if err != nil {
		return "", "", fmt.Errorf("JWKS cache file is outside managed root: %w", err)
	}
	return rootAbs, rel, nil
}

func (s *remoteJWKSSource) openCacheRoot(create bool) (*os.Root, error) {
	if create {
		if err := os.MkdirAll(s.cacheRoot, 0o700); err != nil {
			return nil, err
		}
	}
	info, err := os.Lstat(s.cacheRoot)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, fmt.Errorf("JWKS cache root must be a non-symlink directory")
	}
	return os.OpenRoot(s.cacheRoot)
}

func rejectJWKSCacheSymlinkParents(root *os.Root, parent string) error {
	current := ""
	for _, part := range strings.FieldsFunc(parent, func(r rune) bool { return r == '/' || r == '\\' }) {
		if current == "" {
			current = part
		} else {
			current = filepath.Join(current, part)
		}
		info, err := root.Lstat(current)
		if err != nil {
			return fmt.Errorf("inspect JWKS cache directory: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("JWKS cache directory must not contain symlinks")
		}
	}
	return nil
}

func createJWKSCacheTemp(root *os.Root, parent string) (string, *os.File, error) {
	for attempts := 0; attempts < 8; attempts++ {
		var random [12]byte
		if _, err := rand.Read(random[:]); err != nil {
			return "", nil, fmt.Errorf("create JWKS cache temp name: %w", err)
		}
		name := ".jwks-cache-" + hex.EncodeToString(random[:])
		if parent != "." {
			name = filepath.Join(parent, name)
		}
		file, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			return name, file, nil
		}
		if !os.IsExist(err) {
			return "", nil, fmt.Errorf("create JWKS cache temp file: %w", err)
		}
	}
	return "", nil, fmt.Errorf("create JWKS cache temp file: exhausted unique names")
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
