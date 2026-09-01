package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRetrySafeRequestRequiresAnExplicitlyEmptyBody(t *testing.T) {
	tests := []struct {
		name string
		make func() *http.Request
		want bool
	}{
		{
			name: "get without body",
			make: func() *http.Request { return httptest.NewRequest(http.MethodGet, "http://example.test/", nil) },
			want: true,
		},
		{
			name: "head without body",
			make: func() *http.Request { return httptest.NewRequest(http.MethodHead, "http://example.test/", nil) },
			want: true,
		},
		{
			name: "get with unknown length body",
			make: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "http://example.test/", strings.NewReader("payload"))
				r.ContentLength = -1
				return r
			},
			want: false,
		},
		{
			name: "get with known body",
			make: func() *http.Request {
				return httptest.NewRequest(http.MethodGet, "http://example.test/", strings.NewReader("payload"))
			},
			want: false,
		},
		{
			name: "head with body",
			make: func() *http.Request {
				return httptest.NewRequest(http.MethodHead, "http://example.test/", strings.NewReader("payload"))
			},
			want: false,
		},
		{
			name: "get with explicit no body",
			make: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
				r.Body = http.NoBody
				return r
			},
			want: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := retrySafeRequest(tc.make()); got != tc.want {
				t.Fatalf("retrySafeRequest()=%v, want %v", got, tc.want)
			}
		})
	}
}

func TestRetrySafeRequestRejectsConsumedUnknownBody(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.test/", strings.NewReader("payload"))
	req.ContentLength = -1
	if _, err := io.ReadAll(req.Body); err != nil {
		t.Fatal(err)
	}
	if retrySafeRequest(req) {
		t.Fatal("GET with an unknown-length body must not be retried after body consumption")
	}
}

func TestPreflightUnknownBodyPreservesRawContentEncoding(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "http://example.test/", strings.NewReader("compressed-bytes"))
	req.ContentLength = -1
	req.Header.Set("Content-Encoding", "br")

	if err := preflightUnknownBody(req, 64); err != nil {
		t.Fatalf("preflightUnknownBody() error = %v", err)
	}
	got, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "compressed-bytes" {
		t.Fatalf("body = %q, want original bytes", got)
	}
	if req.ContentLength != int64(len(got)) {
		t.Fatalf("content length = %d, want %d", req.ContentLength, len(got))
	}
}
