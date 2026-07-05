package edge

import (
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

type Cache struct {
	mu      sync.RWMutex
	enabled bool
	mode    string
	ttl     time.Duration
	status  map[int]struct{}
	paths   []string
	maxBody int64
	items   map[string]cacheEntry
}

type cacheEntry struct {
	expires time.Time
	resp    CapturedResponse
}

func NewCache(cfg config.CachePolicyConfig) *Cache {
	if cfg.TTL <= 0 {
		cfg.TTL = 5 * time.Minute
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = 2 << 20
	}
	if len(cfg.StatusCodes) == 0 {
		cfg.StatusCodes = []int{http.StatusOK, http.StatusNotModified}
	}
	status := map[int]struct{}{}
	for _, code := range cfg.StatusCodes {
		status[code] = struct{}{}
	}
	if cfg.Mode == "" {
		cfg.Mode = "public"
	}
	return &Cache{
		enabled: cfg.Enabled,
		mode:    strings.ToLower(cfg.Mode),
		ttl:     cfg.TTL,
		status:  status,
		paths:   cfg.PathPrefixes,
		maxBody: cfg.MaxBodyBytes,
		items:   map[string]cacheEntry{},
	}
}

func (c *Cache) Get(r *http.Request) (CapturedResponse, bool) {
	if !c.cacheableRequest(r) {
		return CapturedResponse{}, false
	}
	key := cacheKey(r)
	c.mu.RLock()
	entry, ok := c.items[key]
	c.mu.RUnlock()
	if !ok || time.Now().After(entry.expires) {
		if ok {
			c.mu.Lock()
			delete(c.items, key)
			c.mu.Unlock()
		}
		return CapturedResponse{}, false
	}
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
	c.mu.Lock()
	c.items[key] = cacheEntry{expires: time.Now().Add(c.ttl), resp: resp}
	c.mu.Unlock()
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
	if c.mode != "private" && r.Header.Get("Authorization") != "" {
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
	if int64(len(resp.Body)) > c.maxBody {
		return false
	}
	cc := strings.ToLower(resp.Header.Get("Cache-Control"))
	return !strings.Contains(cc, "no-store") && resp.Header.Get("Set-Cookie") == ""
}

func cacheKey(r *http.Request) string {
	return r.Method + " " + r.Host + " " + r.URL.RequestURI()
}
