package engine

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
)

// FuzzRequestContext covers the HTTP request -> WAF RequestContext path:
// URL/path parsing, header-derived client IPs, body limits, and normalized
// path invariants.
func FuzzRequestContext(f *testing.F) {
	for _, seed := range []string{
		"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n",
		"POST /api HTTP/1.1\r\nHost: example.test\r\nContent-Length: 4\r\n\r\nbody",
		"GET /%2e%2e/%2e%2e/etc/passwd HTTP/1.1\r\nHost: example.test\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: example.test\r\nX-Forwarded-For: 127.0.0.1\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: example.test\r\nX-Forwarded-For: 10.0.0.1, 192.168.1.1\r\n\r\n",
		"GET /%00 HTTP/1.1\r\nHost: example.test\r\n\r\n",
	} {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(data)))
		if err != nil {
			return
		}
		defer req.Body.Close()
		req.Body = io.NopCloser(bytes.NewReader(nil))
		ctx, err := NewRequestContextDeferredBody(req, "site-fuzz", nil, 1<<20)
		if err != nil {
			return
		}
		if ctx == nil || ctx.Request == nil {
			t.Fatal("nil request context without error")
		}
		if ctx.NormalizedPath != "" && !strings.HasPrefix(ctx.NormalizedPath, "/") {
			t.Fatalf("non-absolute normalized path %q", ctx.NormalizedPath)
		}
	})
}
