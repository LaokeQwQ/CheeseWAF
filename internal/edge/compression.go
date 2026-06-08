package edge

import (
	"bytes"
	"compress/gzip"
	"net/http"
	"strconv"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

type Compressor struct {
	enabled bool
	algos   map[string]struct{}
	level   int
	min     int64
	types   []string
}

func NewCompressor(cfg config.CompressionPolicyConfig) *Compressor {
	if cfg.Level == 0 {
		cfg.Level = gzip.DefaultCompression
	}
	if cfg.MinBytes <= 0 {
		cfg.MinBytes = 1024
	}
	if len(cfg.Algorithms) == 0 {
		cfg.Algorithms = []string{"gzip"}
	}
	if len(cfg.ContentTypes) == 0 {
		cfg.ContentTypes = []string{"text/", "application/json", "application/javascript", "application/xml", "image/svg+xml"}
	}
	algos := map[string]struct{}{}
	for _, algo := range cfg.Algorithms {
		algos[strings.ToLower(algo)] = struct{}{}
	}
	return &Compressor{enabled: cfg.Enabled, algos: algos, level: cfg.Level, min: cfg.MinBytes, types: cfg.ContentTypes}
}

func (c *Compressor) Apply(r *http.Request, resp *CapturedResponse) {
	if c == nil || !c.enabled || r == nil || resp == nil {
		return
	}
	if int64(len(resp.Body)) < c.min || resp.Header.Get("Content-Encoding") != "" {
		return
	}
	if _, ok := c.algos["gzip"]; !ok || !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		return
	}
	if !c.allowedType(resp.Header.Get("Content-Type")) {
		return
	}
	var buf bytes.Buffer
	level := c.level
	if level < gzip.HuffmanOnly || level > gzip.BestCompression {
		level = gzip.DefaultCompression
	}
	zw, err := gzip.NewWriterLevel(&buf, level)
	if err != nil {
		return
	}
	if _, err := zw.Write(resp.Body); err != nil {
		_ = zw.Close()
		return
	}
	if err := zw.Close(); err != nil {
		return
	}
	resp.Body = buf.Bytes()
	resp.Header.Set("Content-Encoding", "gzip")
	resp.Header.Set("Vary", appendVary(resp.Header.Get("Vary"), "Accept-Encoding"))
	resp.Header.Set("Content-Length", strconv.Itoa(len(resp.Body)))
	resp.Header.Del("Content-MD5")
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
