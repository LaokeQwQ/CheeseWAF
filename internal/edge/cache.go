package edge

import (
	"container/list"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

const (
	defaultMaxEntries    = 10_000
	defaultMaxTotalBytes = 256 << 20 // 256 MiB total cache budget
	cacheEntryOverhead   = 128
)

type Cache struct {
	mu            sync.RWMutex
	enabled       bool
	mode          string
	ttl           time.Duration
	status        map[int]struct{}
	paths         []string
	maxBody       int64
	maxEntries    int
	maxTotalBytes int64
	currentBytes  int64
	items         map[string]*cacheEntry
	lru           *list.List
}

type cacheEntry struct {
	key     string
	expires time.Time
	resp    CapturedResponse
	size    int64
	element *list.Element
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
		enabled:       cfg.Enabled,
		mode:          strings.ToLower(cfg.Mode),
		ttl:           cfg.TTL,
		status:        status,
		paths:         cfg.PathPrefixes,
		maxBody:       cfg.MaxBodyBytes,
		maxEntries:    defaultMaxEntries,
		maxTotalBytes: defaultMaxTotalBytes,
		items:         map[string]*cacheEntry{},
		lru:           list.New(),
	}
}

// WithMaxTotalBytes overrides the aggregate cache budget (tests).
func (c *Cache) WithMaxTotalBytes(n int64) *Cache {
	if c != nil && n > 0 {
		c.maxTotalBytes = n
	}
	return c
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
	entry, ok := c.items[key]
	if !ok || now.After(entry.expires) {
		if ok {
			c.removeLocked(entry)
		}
		return CapturedResponse{}, false
	}
	c.lru.MoveToFront(entry.element)
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
	entrySize := cacheEntrySize(key, resp)
	if entrySize > c.maxTotalBytes {
		return
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if previous := c.items[key]; previous != nil {
		c.removeLocked(previous)
	}
	for (c.currentBytes+entrySize > c.maxTotalBytes || len(c.items) >= c.maxEntries) && len(c.items) > 0 {
		c.evictOldestLocked()
	}
	if c.currentBytes+entrySize > c.maxTotalBytes || len(c.items) >= c.maxEntries {
		return
	}
	entry := &cacheEntry{key: key, expires: now.Add(c.ttl), resp: resp, size: entrySize}
	entry.element = c.lru.PushFront(entry)
	c.items[key] = entry
	c.currentBytes += entrySize
}

func (c *Cache) KeyCount() int {
	if c == nil {
		return 0
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.items)
}

// CurrentBytes returns the accounted aggregate cache size.
func (c *Cache) CurrentBytes() int64 {
	if c == nil {
		return 0
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.currentBytes
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
	return c.cacheableResponseMetadata(resp.Status, resp.Header, int64(len(resp.Body)))
}

// MayStoreResponse reports whether response metadata still makes capture useful.
func (c *Cache) MayStoreResponse(resp *http.Response) bool {
	if c == nil || resp == nil {
		return false
	}
	return c.cacheableResponseMetadata(resp.StatusCode, resp.Header, resp.ContentLength)
}

func (c *Cache) cacheableResponseMetadata(status int, header http.Header, contentLength int64) bool {
	if _, ok := c.status[status]; !ok {
		return false
	}
	if status == http.StatusNotModified {
		return false
	}
	if contentLength > c.maxBody {
		return false
	}
	cc := strings.ToLower(header.Get("Cache-Control"))
	if strings.Contains(cc, "no-store") || strings.Contains(cc, "private") {
		if c.mode != "private" {
			return false
		}
	}
	vary := strings.TrimSpace(header.Get("Vary"))
	if vary != "" && !strings.EqualFold(vary, "Accept-Encoding") {
		return false
	}
	return header.Get("Set-Cookie") == ""
}

func cacheKey(r *http.Request) string {
	digest := sha256.New()
	writeCacheKeyPart(digest, r.Method)
	writeCacheKeyPart(digest, r.Host)
	writeCacheKeyPart(digest, r.URL.RequestURI())
	for _, name := range []string{
		"Authorization",
		"Cookie",
		"Origin",
		"Accept",
		"Accept-Language",
		"Accept-Encoding",
	} {
		writeCacheKeyPart(digest, name)
		values := r.Header.Values(name)
		writeCacheKeyLength(digest, uint64(len(values)))
		for _, value := range values {
			writeCacheKeyPart(digest, value)
		}
	}
	return hex.EncodeToString(digest.Sum(nil))
}

func writeCacheKeyPart(digest hash.Hash, value string) {
	writeCacheKeyLength(digest, uint64(len(value)))
	_, _ = digest.Write([]byte(value))
}

func writeCacheKeyLength(digest hash.Hash, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	_, _ = digest.Write(encoded[:])
}

func cacheEntrySize(key string, resp CapturedResponse) int64 {
	size := int64(cacheEntryOverhead + len(key) + len(resp.Body))
	for name, values := range resp.Header {
		size += int64(len(name))
		for _, value := range values {
			size += int64(len(value))
		}
	}
	return size
}

func (c *Cache) evictOldestLocked() {
	oldest := c.lru.Back()
	if oldest == nil {
		return
	}
	entry, _ := oldest.Value.(*cacheEntry)
	c.removeLocked(entry)
}

func (c *Cache) removeLocked(entry *cacheEntry) {
	if entry == nil {
		return
	}
	current, ok := c.items[entry.key]
	if !ok || current != entry {
		return
	}
	delete(c.items, entry.key)
	if entry.element != nil {
		c.lru.Remove(entry.element)
	}
	c.currentBytes -= entry.size
	if c.currentBytes < 0 {
		c.currentBytes = 0
	}
}
