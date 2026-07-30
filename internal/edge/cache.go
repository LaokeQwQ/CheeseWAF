package edge

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

const (
	defaultMaxEntries = 10_000
	evictionBudget    = 16
)

type Cache struct {
	mu         sync.RWMutex
	enabled    bool
	mode       string
	ttl        time.Duration
	status     map[int]struct{}
	paths      []string
	maxBody    int64
	maxEntries int
	items      map[string]cacheEntry
}

type cacheEntry struct {
	expires    time.Time
	lastAccess time.Time
	resp       CapturedResponse
}

func NewCache(cfg config.CachePolicyConfig) *Cache {
	if cfg.TTL <= 0 {
		cfg.TTL = 5 * time.Minute
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = 2 << 20
	}
	// Do not default-cache bare 304 responses; they have no body for later unconditional GETs.
	if len(cfg.StatusCodes) == 0 {
		cfg.StatusCodes = []int{http.StatusOK}
	}
	status := map[int]struct{}{}
	for _, code := range cfg.StatusCodes {
		if code == http.StatusNotModified {
			continue
		}
		status[code] = struct{}{}
	}
	if len(status) == 0 {
		status[http.StatusOK] = struct{}{}
	}
	if cfg.Mode == "" {
		cfg.Mode = "public"
	}
	return &Cache{
		enabled:    cfg.Enabled,
		mode:       strings.ToLower(cfg.Mode),
		ttl:        cfg.TTL,
		status:     status,
		paths:      cfg.PathPrefixes,
		maxBody:    cfg.MaxBodyBytes,
		maxEntries: defaultMaxEntries,
		items:      map[string]cacheEntry{},
	}
}

// WithMaxEntries overrides capacity (tests).
func (c *Cache) WithMaxEntries(n int) *Cache {
	if c != nil && n > 0 {
		c.maxEntries = n
	}
	return c
}

func (c *Cache) Get(r *http.Request) (CapturedResponse, bool) {
	if !c.cacheableRequest(r) {
		return CapturedResponse{}, false
	}
	key := cacheKey(r)
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expireLocked(now)
	entry, ok := c.items[key]
	if !ok || now.After(entry.expires) {
		if ok {
			delete(c.items, key)
		}
		return CapturedResponse{}, false
	}
	entry.lastAccess = now
	c.items[key] = entry
	resp := entry.resp
	resp.Header = resp.Header.Clone()
	resp.Header.Set("X-CheeseWAF-Cache", "HIT")
	return resp, true
}

func (c *Cache) CaptureCandidate(r *http.Request) bool {
	return c.cacheableRequest(r)
}

func (c *Cache) MaxBodyBytes() int64 {
	if c == nil || c.maxBody <= 0 {
		return 0
	}
	return c.maxBody
}

func (c *Cache) Store(r *http.Request, resp CapturedResponse) {
	if !c.cacheableRequest(r) || !c.cacheableResponse(resp) {
		return
	}
	key := cacheKey(r)
	resp.Header = resp.Header.Clone()
	resp.Header.Set("X-CheeseWAF-Cache", "MISS")
	resp.Header.Set("Age", "0")
	resp.Header.Set("Content-Length", strconv.Itoa(len(resp.Body)))
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expireLocked(now)
	if len(c.items) >= c.maxEntries {
		c.evictOldestLocked()
	}
	if len(c.items) >= c.maxEntries {
		for k := range c.items {
			delete(c.items, k)
			break
		}
	}
	c.items[key] = cacheEntry{expires: now.Add(c.ttl), lastAccess: now, resp: resp}
}

func (c *Cache) KeyCount() int {
	if c == nil {
		return 0
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.items)
}

func (c *Cache) cacheableRequest(r *http.Request) bool {
	if c == nil || !c.enabled || r == nil || c.mode == "off" {
		return false
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	if strings.Contains(strings.ToLower(r.Header.Get("Cache-Control")), "no-store") {
		return false
	}
	// Never share authenticated or cookie-bound responses across clients unless
	// private mode with an identity-partitioned cache key.
	if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
		if c.mode != "private" {
			return false
		}
	}
	if r.Header.Get("If-None-Match") != "" || r.Header.Get("If-Modified-Since") != "" {
		return false
	}
	if len(c.paths) == 0 {
		return true
	}
	for _, prefix := range c.paths {
		if strings.HasPrefix(r.URL.Path, prefix) {
			return true
		}
	}
	return false
}

func (c *Cache) cacheableResponse(resp CapturedResponse) bool {
	if _, ok := c.status[resp.Status]; !ok {
		return false
	}
	if resp.Status == http.StatusNotModified {
		return false
	}
	if int64(len(resp.Body)) > c.maxBody {
		return false
	}
	cc := strings.ToLower(resp.Header.Get("Cache-Control"))
	if strings.Contains(cc, "no-store") || strings.Contains(cc, "private") {
		if c.mode != "private" {
			return false
		}
	}
	return resp.Header.Get("Set-Cookie") == ""
}

func cacheKey(r *http.Request) string {
	identity := ""
	if auth := strings.TrimSpace(r.Header.Get("Authorization")); auth != "" {
		sum := sha256.Sum256([]byte(auth))
		identity = "auth:" + hex.EncodeToString(sum[:8])
	} else if cookie := strings.TrimSpace(r.Header.Get("Cookie")); cookie != "" {
		sum := sha256.Sum256([]byte(cookie))
		identity = "cookie:" + hex.EncodeToString(sum[:8])
	}
	return r.Method + " " + r.Host + " " + r.URL.RequestURI() + " " + identity
}

func (c *Cache) expireLocked(now time.Time) {
	budget := evictionBudget
	for key, entry := range c.items {
		if budget <= 0 {
			break
		}
		budget--
		if now.After(entry.expires) {
			delete(c.items, key)
		}
	}
}

func (c *Cache) evictOldestLocked() {
	var oldestKey string
	var oldest time.Time
	first := true
	for key, entry := range c.items {
		if first || entry.lastAccess.Before(oldest) {
			oldest = entry.lastAccess
			oldestKey = key
			first = false
		}
	}
	if oldestKey != "" {
		delete(c.items, oldestKey)
	}
}
