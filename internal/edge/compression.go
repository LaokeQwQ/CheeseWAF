package edge

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/andybalholm/brotli"
)

type Compressor struct {
	enabled                   bool
	algos                     map[string]struct{}
	preference                []string
	gzipPool                  sync.Pool
	brotliPool                sync.Pool
	compressAuthenticatedHTML bool
	level                     int
	min                       int64
	types                     []string
}

func NewCompressor(cfg config.CompressionPolicyConfig) *Compressor {
	if cfg.Level == 0 {
		cfg.Level = gzip.DefaultCompression
	}
	if cfg.MinBytes <= 0 {
		cfg.MinBytes = 1024
	}
	if len(cfg.Algorithms) == 0 {
		cfg.Algorithms = []string{"gzip", "br"}
	}
	if len(cfg.ContentTypes) == 0 {
		cfg.ContentTypes = []string{"text/", "application/json", "application/javascript", "application/xml", "image/svg+xml"}
	}
	algos := map[string]struct{}{}
	var preference []string
	for _, algo := range cfg.Algorithms {
		algo = normalizeAlgorithm(algo)
		if algo != "" {
			if _, exists := algos[algo]; !exists {
				preference = append(preference, algo)
			}
			algos[algo] = struct{}{}
		}
	}
	compressor := &Compressor{enabled: cfg.Enabled, algos: algos, preference: preference, level: cfg.Level, min: cfg.MinBytes, types: cfg.ContentTypes}
	gzipLevel := cfg.Level
	if gzipLevel < gzip.HuffmanOnly || gzipLevel > gzip.BestCompression {
		gzipLevel = gzip.DefaultCompression
	}
	brotliLevel := cfg.Level
	if brotliLevel < 0 || brotliLevel > 11 {
		brotliLevel = 5
	}
	compressor.gzipPool.New = func() any { writer, _ := gzip.NewWriterLevel(io.Discard, gzipLevel); return writer }
	compressor.brotliPool.New = func() any { return brotli.NewWriterLevel(io.Discard, brotliLevel) }
	return compressor
}

func (c *Compressor) Apply(r *http.Request, resp *CapturedResponse) {
	if c == nil || !c.enabled || r == nil || resp == nil {
		return
	}
	if !c.transformAllowed(r, resp.Status, resp.Header) || int64(len(resp.Body)) < c.min || anyNonEmptyHeaderValue(resp.Header, "Content-Encoding") {
		return
	}
	if !c.allowedType(resp.Header.Get("Content-Type")) {
		return
	}
	encoding := c.negotiateEncoding(r.Header.Get("Accept-Encoding"))
	if encoding == "" {
		return
	}
	buf := compressionBuffers.Get().(*bytes.Buffer)
	buf.Reset()
	defer func() {
		if buf.Cap() <= 2<<20 {
			buf.Reset()
			compressionBuffers.Put(buf)
		}
	}()
	switch encoding {
	case "br":
		zw := c.brotliPool.Get().(*brotli.Writer)
		zw.Reset(buf)
		defer func() { zw.Reset(io.Discard); c.brotliPool.Put(zw) }()
		if _, err := zw.Write(resp.Body); err != nil {
			_ = zw.Close()
			return
		}
		if err := zw.Close(); err != nil {
			return
		}
	case "gzip":
		zw := c.gzipPool.Get().(*gzip.Writer)
		zw.Reset(buf)
		defer func() { zw.Reset(io.Discard); c.gzipPool.Put(zw) }()
		if _, err := zw.Write(resp.Body); err != nil {
			_ = zw.Close()
			return
		}
		if err := zw.Close(); err != nil {
			return
		}
	default:
		return
	}
	if buf.Len() >= len(resp.Body) {
		return
	}
	resp.Body = append([]byte(nil), buf.Bytes()...)
	resp.Header.Set("Content-Encoding", encoding)
	appendVaryHeader(resp.Header, "Accept-Encoding")
	resp.Header.Set("Content-Length", strconv.Itoa(len(resp.Body)))
	resp.Header.Del("Content-MD5")
}

func (c *Compressor) MayApplyRequest(r *http.Request) bool {
	if c == nil || !c.enabled || r == nil {
		return false
	}
	return c.negotiateEncoding(r.Header.Get("Accept-Encoding")) != ""
}

// MayApplyResponse reports whether buffering could produce a compressed response.
func (c *Compressor) MayApplyResponse(r *http.Request, resp *http.Response) bool {
	if !c.MayApplyRequest(r) || resp == nil {
		return false
	}
	if !c.transformAllowed(r, resp.StatusCode, resp.Header) || anyNonEmptyHeaderValue(resp.Header, "Content-Encoding") || !c.allowedType(resp.Header.Get("Content-Type")) {
		return false
	}
	return resp.ContentLength < 0 || resp.ContentLength >= c.min
}

var compressionBuffers = sync.Pool{New: func() any { return new(bytes.Buffer) }}

// SetCompressAuthenticatedHTML explicitly opts authenticated HTML into
// compression; the default avoids coupling attacker text and session secrets.
func (c *Compressor) SetCompressAuthenticatedHTML(enabled bool) {
	c.compressAuthenticatedHTML = enabled
}

func (c *Compressor) transformAllowed(r *http.Request, status int, header http.Header) bool {
	if status == http.StatusPartialContent || anyNonEmptyHeaderValue(header, "Content-Range") {
		return false
	}
	for _, directive := range cacheDirectives(header) {
		if directive[0] == "no-transform" {
			return false
		}
	}
	return c.compressAuthenticatedHTML || !strings.HasPrefix(strings.ToLower(header.Get("Content-Type")), "text/html") ||
		(!anyNonEmptyHeaderValue(r.Header, "Authorization") && !anyNonEmptyHeaderValue(r.Header, "Cookie"))
}

func (c *Compressor) negotiateEncoding(acceptEncoding string) string {
	best, quality := "", 0.0
	for _, algorithm := range c.preference {
		if q := encodingQuality(acceptEncoding, algorithm); q > quality {
			best, quality = algorithm, q
		}
	}
	return best
}

func encodingQuality(header, encoding string) float64 {
	explicit, wildcard := -1.0, 0.0
	for _, item := range strings.Split(header, ",") {
		parts := strings.Split(item, ";")
		token := strings.ToLower(strings.TrimSpace(parts[0]))
		if token != encoding && token != "*" {
			continue
		}
		q := 1.0
		for _, param := range parts[1:] {
			name, value, _ := strings.Cut(strings.TrimSpace(param), "=")
			if strings.EqualFold(name, "q") {
				parsed, err := strconv.ParseFloat(value, 64)
				if err != nil || parsed < 0 || parsed > 1 {
					q = 0
				} else {
					q = parsed
				}
			}
		}
		if token == encoding {
			explicit = q
		} else {
			wildcard = q
		}
	}
	if explicit >= 0 {
		return explicit
	}
	return wildcard
}

func (c *Compressor) allowedType(contentType string) bool {
	contentType = strings.ToLower(contentType)
	for _, item := range c.types {
		item = strings.ToLower(item)
		if strings.HasSuffix(item, "/") {
			if strings.HasPrefix(contentType, item) {
				return true
			}
			continue
		}
		if strings.HasPrefix(contentType, item) {
			return true
		}
	}
	return false
}

func acceptsEncoding(header, encoding string) bool { return encodingQuality(header, encoding) > 0 }

func normalizeAlgorithm(algorithm string) string {
	switch strings.ToLower(strings.TrimSpace(algorithm)) {
	case "br", "brotli":
		return "br"
	case "gzip":
		return "gzip"
	default:
		return ""
	}
}

func appendVary(current, token string) string {
	for _, item := range strings.Split(current, ",") {
		if strings.EqualFold(strings.TrimSpace(item), token) {
			return current
		}
	}
	if strings.TrimSpace(current) == "" {
		return token
	}
	return current + ", " + token
}

func appendVaryHeader(header http.Header, token string) {
	for _, value := range header.Values("Vary") {
		for _, item := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(item), token) {
				return
			}
		}
	}
	header.Add("Vary", token)
}
