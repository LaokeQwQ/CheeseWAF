package edge

import (
	"container/list"
	"encoding/binary"
	"hash/maphash"
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
	items         map[[16]byte]*cacheEntry
	lru           *list.List
}

type cacheEntry struct {
	key     [16]byte
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
		items:         map[[16]byte]*cacheEntry{},
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
	ttl := c.responseTTL(resp.Header, time.Now())
	if ttl <= 0 {
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
	entry := &cacheEntry{key: key, expires: now.Add(ttl), resp: resp, size: entrySize}
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
	// Upgrade handshakes are stateful protocol switches, never cacheable HTTP
	// representations. A WebSocket GET must not collide with a normal GET.
	if strings.EqualFold(strings.TrimSpace(r.Header.Get("Upgrade")), "websocket") ||
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") {
		return false
	}
	if anyNonEmptyHeaderValue(r.Header, "Range") || anyNonEmptyHeaderValue(r.Header, "If-Range") {
		return false
	}
	if requestForcesRevalidation(r.Header) {
		return false
	}
	// Never share authenticated or cookie-bound responses across clients unless
	// private mode with an identity-partitioned cache key.
	if anyNonEmptyHeaderValue(r.Header, "Authorization") || anyNonEmptyHeaderValue(r.Header, "Cookie") {
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
	if status == http.StatusPartialContent || anyNonEmptyHeaderValue(header, "Content-Range") {
		return false
	}
	for _, directive := range cacheDirectives(header) {
		switch directive[0] {
		case "no-store", "no-cache", "must-revalidate":
			return false
		case "private":
			if c.mode != "private" {
				return false
			}
		}
	}
	for _, value := range header.Values("Vary") {
		for _, token := range strings.Split(value, ",") {
			if token = strings.TrimSpace(token); token != "" && !strings.EqualFold(token, "Accept-Encoding") {
				return false
			}
		}
	}
	for _, value := range header.Values("Set-Cookie") {
		if strings.TrimSpace(value) != "" {
			return false
		}
	}
	return c.responseTTL(header, time.Now()) > 0
}

func cacheDirectives(header http.Header) [][2]string {
	var out [][2]string
	for _, value := range header.Values("Cache-Control") {
		for _, field := range strings.Split(value, ",") {
			name, value, _ := strings.Cut(strings.TrimSpace(field), "=")
			out = append(out, [2]string{strings.ToLower(strings.TrimSpace(name)), strings.Trim(strings.TrimSpace(value), "\"")})
		}
	}
	return out
}

func requestForcesRevalidation(header http.Header) bool {
	for _, directive := range cacheDirectives(header) {
		if directive[0] == "no-store" || directive[0] == "no-cache" || (directive[0] == "max-age" && directive[1] == "0") {
			return true
		}
	}
	for _, value := range header.Values("Pragma") {
		if strings.EqualFold(strings.TrimSpace(value), "no-cache") {
			return true
		}
	}
	return false
}

func anyNonEmptyHeaderValue(header http.Header, name string) bool {
	for _, value := range header.Values(name) {
		if strings.TrimSpace(value) != "" {
			return true
		}
	}
	return false
}

func (c *Cache) responseTTL(header http.Header, now time.Time) time.Duration {
	ttl := c.ttl
	age := time.Duration(0)
	if value, err := strconv.ParseInt(header.Get("Age"), 10, 64); err == nil && value > 0 {
		if value > int64((1<<63-1)/int64(time.Second)) {
			return 0
		}
		age = time.Duration(value) * time.Second
	}
	if date, err := http.ParseTime(header.Get("Date")); err == nil && now.Sub(date) > age {
		age = now.Sub(date)
	}
	explicitMaxAge := false
	for _, directive := range cacheDirectives(header) {
		if directive[0] != "max-age" && directive[0] != "s-maxage" {
			continue
		}
		explicitMaxAge = true
		seconds, err := strconv.ParseInt(directive[1], 10, 64)
		if err != nil || seconds < 0 || seconds > int64((1<<63-1)/int64(time.Second)) {
			return 0
		}
		remaining := time.Duration(seconds)*time.Second - age
		if remaining < ttl {
			ttl = remaining
		}
	}
	if !explicitMaxAge && header.Get("Expires") != "" {
		expiry, err := http.ParseTime(header.Get("Expires"))
		if err != nil {
			return 0
		}
		if remaining := expiry.Sub(now); remaining < ttl {
			ttl = remaining
		}
	}
	return ttl
}

var cacheKeySeeds = [2]maphash.Seed{maphash.MakeSeed(), maphash.MakeSeed()}

func cacheKey(r *http.Request) [16]byte {
	var key [16]byte
	for n, seed := range cacheKeySeeds {
		var digest maphash.Hash
		digest.SetSeed(seed)
		writeCacheKeyPart(&digest, r.Method)
		scheme := strings.ToLower(r.URL.Scheme)
		if scheme == "" {
			scheme = "http"
			if r.TLS != nil {
				scheme = "https"
			}
		}
		writeCacheKeyPart(&digest, scheme)
		writeCacheKeyPart(&digest, r.Host)
		writeCacheKeyPart(&digest, r.RequestURI) // original public target, before rewrite
		writeCacheKeyPart(&digest, r.URL.RequestURI())
		for _, name := range []string{"Authorization", "Cookie", "Origin", "Accept", "Accept-Language", "Accept-Encoding"} {
			writeCacheKeyPart(&digest, name)
			values := r.Header.Values(name)
			writeCacheKeyLength(&digest, uint64(len(values)))
			for _, value := range values {
				writeCacheKeyPart(&digest, value)
			}
		}
		binary.BigEndian.PutUint64(key[n*8:], digest.Sum64())
	}
	return key
}

func writeCacheKeyPart(digest *maphash.Hash, value string) {
	writeCacheKeyLength(digest, uint64(len(value)))
	_, _ = digest.WriteString(value)
}

func writeCacheKeyLength(digest *maphash.Hash, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	_, _ = digest.Write(encoded[:])
}

func cacheEntrySize(key [16]byte, resp CapturedResponse) int64 {
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
