package semantic

import (
	"sync"
	"sync/atomic"
	"time"
)

const (
	// defaultCacheShards must be a power of two for mask indexing.
	defaultCacheShards = 64
	defaultCacheSize   = 16384
	defaultCacheTTL    = 3 * time.Minute
)

// candidateCache is a pure-Go sharded TTL cache for per-field analysis results.
// It is FP-safe when keyed by analyzer mode, enabled categories fingerprint,
// and the exact candidate text: the same inputs always yield the same hits
// under the same policy.
//
// Eviction is approximate (delete a batch of map keys when full) rather than
// true LRU: under proxy load the O(n) order-list scans cost more than the
// rare extra cold recompute. Sharding still cuts multi-core mutex contention.
// 100% stdlib Go (no CGO, no third-party cache deps).
type candidateCache struct {
	shards  []cacheShard
	mask    uint64
	maxSize int
	ttl     time.Duration
	hits    atomic.Uint64
	misses  atomic.Uint64
}

type cacheShard struct {
	mu    sync.Mutex
	items map[uint64]cacheEntry
}

type cacheEntry struct {
	hits    []Hit
	expires int64 // unix nano
}

func newCandidateCache(maxSize int, ttl time.Duration) *candidateCache {
	if maxSize < 64 {
		maxSize = 64
	}
	if ttl <= 0 {
		ttl = defaultCacheTTL
	}
	shards := defaultCacheShards
	perShard := maxSize / shards
	if perShard < 16 {
		perShard = 16
	}
	c := &candidateCache{
		shards:  make([]cacheShard, shards),
		mask:    uint64(shards - 1),
		maxSize: perShard,
		ttl:     ttl,
	}
	for i := range c.shards {
		c.shards[i].items = make(map[uint64]cacheEntry, perShard)
	}
	return c
}

// processCandidateCache is shared across Analyzer instances. Keys include mode
// and enabled category fingerprint so configs never cross-contaminate.
var processCandidateCache = newCandidateCache(defaultCacheSize, defaultCacheTTL)

// candidateCacheKey hashes mode + enabled-category fingerprint + text using
// pure FNV-1a (no heap hash.Hash allocation on the hot path).
func candidateCacheKey(mode string, catFP uint64, text string) uint64 {
	h := uint64(14695981039346656037)
	h = fnv64aAddString(h, mode)
	h = fnv64aAddByte(h, 0)
	// Mix precomputed category fingerprint without re-sorting every call.
	h = fnv64aAddUint64(h, catFP)
	h = fnv64aAddByte(h, 0)
	if len(text) > maxInputRawBytes {
		text = text[:maxInputRawBytes]
	}
	return fnv64aAddString(h, text)
}

// enabledCategoryFingerprint returns a stable FNV mix of enabled categories.
// Order-independent: categories are mixed in fixed global order.
func enabledCategoryFingerprint(enabled map[string]bool) uint64 {
	// Fixed order matches detector priority; must stay stable across processes.
	const order = "lfi\x00nosqli\x00rce\x00sqli\x00ssrf\x00ssti\x00xss\x00xxe"
	h := uint64(14695981039346656037)
	// Walk the fixed list by scanning null-separated names.
	start := 0
	for i := 0; i <= len(order); i++ {
		if i == len(order) || order[i] == 0 {
			name := order[start:i]
			if enabled[name] {
				h = fnv64aAddString(h, name)
				h = fnv64aAddByte(h, 1)
			} else {
				h = fnv64aAddByte(h, 0)
			}
			start = i + 1
		}
	}
	return h
}

func fnv64aAddString(h uint64, s string) uint64 {
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return h
}

func fnv64aAddByte(h uint64, b byte) uint64 {
	h ^= uint64(b)
	h *= 1099511628211
	return h
}

func fnv64aAddUint64(h, v uint64) uint64 {
	for i := 0; i < 8; i++ {
		h ^= uint64(byte(v))
		h *= 1099511628211
		v >>= 8
	}
	return h
}

func (c *candidateCache) shard(key uint64) *cacheShard {
	return &c.shards[key&c.mask]
}

func (c *candidateCache) get(key uint64) ([]Hit, bool) {
	if c == nil {
		return nil, false
	}
	now := time.Now().UnixNano()
	s := c.shard(key)
	s.mu.Lock()
	entry, ok := s.items[key]
	if !ok {
		s.mu.Unlock()
		c.misses.Add(1)
		return nil, false
	}
	if now > entry.expires {
		delete(s.items, key)
		s.mu.Unlock()
		c.misses.Add(1)
		return nil, false
	}
	// Safe without clone: callers only range Hits and copy Hit values by value.
	// put() always stores a private clone, so cache never shares caller slices.
	hits := entry.hits
	s.mu.Unlock()
	c.hits.Add(1)
	return hits, true
}

func (c *candidateCache) put(key uint64, hits []Hit) {
	if c == nil {
		return
	}
	expires := time.Now().Add(c.ttl).UnixNano()
	stored := cloneHits(hits)
	s := c.shard(key)
	s.mu.Lock()
	if len(s.items) >= c.maxSize {
		if _, exists := s.items[key]; !exists {
			// Approximate eviction: drop ~12.5% of entries (map iteration order).
			evict := len(s.items) / 8
			if evict < 1 {
				evict = 1
			}
			n := 0
			for k := range s.items {
				delete(s.items, k)
				n++
				if n >= evict {
					break
				}
			}
		}
	}
	s.items[key] = cacheEntry{hits: stored, expires: expires}
	s.mu.Unlock()
}

func (c *candidateCache) stats() (hits, misses uint64) {
	if c == nil {
		return 0, 0
	}
	return c.hits.Load(), c.misses.Load()
}

func (c *candidateCache) resetForTest() {
	if c == nil {
		return
	}
	for i := range c.shards {
		s := &c.shards[i]
		s.mu.Lock()
		s.items = make(map[uint64]cacheEntry, c.maxSize)
		s.mu.Unlock()
	}
	c.hits.Store(0)
	c.misses.Store(0)
}

// ResetProcessCacheForTest clears the shared candidate cache (tests only).
func ResetProcessCacheForTest() {
	processCandidateCache.resetForTest()
}

func cloneHits(in []Hit) []Hit {
	if len(in) == 0 {
		return nil
	}
	out := make([]Hit, len(in))
	copy(out, in)
	return out
}
