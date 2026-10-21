package intel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func stubResponse(status int, contentType, body string) *http.Response {
	header := http.Header{}
	if contentType != "" {
		header.Set("Content-Type", contentType)
	}
	return &http.Response{
		StatusCode:    status,
		Header:        header,
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}
}

func TestFetcherRejectsUnsafeURLs(t *testing.T) {
	fetcher, err := NewFetcher(FetchOptions{Timeout: 200 * time.Millisecond})
	if err != nil {
		t.Fatalf("new fetcher: %v", err)
	}
	tests := []struct {
		name string
		url  string
	}{
		{name: "file", url: "file:///etc/passwd"},
		{name: "gopher", url: "gopher://127.0.0.1:70/_test"},
		{name: "ftp", url: "ftp://example.test/feed"},
		{name: "loopback", url: "http://127.0.0.1/feed"},
		{name: "ipv6 loopback", url: "http://[::1]/feed"},
		{name: "metadata", url: "http://169.254.169.254/latest/meta-data/"},
		{name: "metadata alternate", url: "http://100.100.100.200/latest/meta-data"},
		{name: "private", url: "http://10.0.0.8/feed"},
		{name: "private 192", url: "http://192.168.1.10/feed"},
		{name: "link local", url: "http://169.254.10.10/feed"},
		{name: "ipv6 link local", url: "http://[fe80::1]/feed"},
		{name: "ipv6 unique local", url: "http://[fd00::1]/feed"},
		{name: "unspecified", url: "http://0.0.0.0/feed"},
		{name: "benchmark range", url: "http://198.18.0.1/feed"},
		{name: "credentials", url: "http://user:pass@example.test/feed"},
		{name: "fragment", url: "http://example.test/feed#token"},
		{name: "short ipv4", url: "http://127.1/feed"},
		{name: "decimal ipv4", url: "http://2130706433/feed"},
		{name: "hex ipv4", url: "http://0x7f000001/feed"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidateFetchURL(test.url); !errors.Is(err, ErrUnsafeURL) {
				t.Fatalf("ValidateFetchURL(%q) = %v, want ErrUnsafeURL", test.url, err)
			}
			_, err := fetcher.Fetch(context.Background(), FetchRequest{URL: test.url})
			if err == nil {
				t.Fatalf("expected %q to be rejected", test.url)
			}
			if !errors.Is(err, ErrUnsafeURL) {
				t.Fatalf("expected ErrUnsafeURL for %q, got %v", test.url, err)
			}
		})
	}
}

func TestFetcherRejectsPrivateResolvedAddress(t *testing.T) {
	fetcher, err := NewFetcher(FetchOptions{
		Timeout: 300 * time.Millisecond,
		Resolver: func(context.Context, string, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("10.0.0.8")}, nil
		},
	})
	if err != nil {
		t.Fatalf("new fetcher: %v", err)
	}
	_, err = fetcher.Fetch(context.Background(), FetchRequest{URL: "https://intel.example.test/feed"})
	if err == nil || !strings.Contains(err.Error(), "non-public IP") {
		t.Fatalf("expected DNS-rebinding guard error, got %v", err)
	}
}

func TestFetcherBodySizeLimit(t *testing.T) {
	fetcher, err := newFetcherForTest(roundTripFunc(func(*http.Request) (*http.Response, error) {
		return stubResponse(http.StatusOK, "text/plain", strings.Repeat("a", 33)), nil
	}), FetchOptions{MaxBodyBytes: 32})
	if err != nil {
		t.Fatalf("new test fetcher: %v", err)
	}
	_, err = fetcher.Fetch(context.Background(), FetchRequest{URL: "https://intel.example.test/feed"})
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("expected ErrResponseTooLarge, got %v", err)
	}
}

func TestFetcherAcceptsBodyAtLimit(t *testing.T) {
	fetcher, err := newFetcherForTest(roundTripFunc(func(*http.Request) (*http.Response, error) {
		return stubResponse(http.StatusOK, "text/plain; charset=utf-8", strings.Repeat("a", 32)), nil
	}), FetchOptions{MaxBodyBytes: 32})
	if err != nil {
		t.Fatalf("new test fetcher: %v", err)
	}
	result, err := fetcher.Fetch(context.Background(), FetchRequest{URL: "https://intel.example.test/feed"})
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(result.Body) != 32 {
		t.Fatalf("expected 32 body bytes, got %d", len(result.Body))
	}
	if result.ContentType != "text/plain" {
		t.Fatalf("expected normalized content type, got %q", result.ContentType)
	}
	sum := sha256.Sum256([]byte(strings.Repeat("a", 32)))
	if result.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("unexpected sha256 %q", result.SHA256)
	}
}

func TestFetcherContentTypePolicy(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		wantErr     bool
		wantType    string
	}{
		{name: "html", contentType: "text/html; charset=utf-8", wantType: "text/html"},
		{name: "json", contentType: "application/json", wantType: "application/json"},
		{name: "image rejected", contentType: "image/png", wantErr: true},
		{name: "missing rejected", contentType: "", wantErr: true},
		{name: "malformed rejected", contentType: "text", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fetcher, err := newFetcherForTest(roundTripFunc(func(*http.Request) (*http.Response, error) {
				return stubResponse(http.StatusOK, test.contentType, "<html>ok</html>"), nil
			}), FetchOptions{})
			if err != nil {
				t.Fatalf("new test fetcher: %v", err)
			}
			result, err := fetcher.Fetch(context.Background(), FetchRequest{URL: "https://intel.example.test/feed"})
			if test.wantErr {
				if !errors.Is(err, ErrUnsupportedContentType) {
					t.Fatalf("expected ErrUnsupportedContentType, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("fetch: %v", err)
			}
			if result.ContentType != test.wantType {
				t.Fatalf("expected %q, got %q", test.wantType, result.ContentType)
			}
		})
	}
}

func TestFetcherRedirectLimit(t *testing.T) {
	requests := 0
	fetcher, err := newFetcherForTest(roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		response := stubResponse(http.StatusFound, "text/html", "")
		response.Header.Set("Location", "https://intel.example.test/hop/"+strconv.Itoa(requests))
		return response, nil
	}), FetchOptions{MaxRedirects: 2})
	if err != nil {
		t.Fatalf("new test fetcher: %v", err)
	}
	_, err = fetcher.Fetch(context.Background(), FetchRequest{URL: "https://intel.example.test/feed"})
	if !errors.Is(err, ErrTooManyRedirects) {
		t.Fatalf("expected ErrTooManyRedirects, got %v", err)
	}
	if requests != 3 {
		t.Fatalf("expected 3 requests before the limit, got %d", requests)
	}
}

func TestFetcherRejectsUnsafeRedirect(t *testing.T) {
	fetcher, err := newFetcherForTest(roundTripFunc(func(*http.Request) (*http.Response, error) {
		response := stubResponse(http.StatusFound, "text/html", "")
		response.Header.Set("Location", "http://127.0.0.1/admin")
		return response, nil
	}), FetchOptions{})
	if err != nil {
		t.Fatalf("new test fetcher: %v", err)
	}
	_, err = fetcher.Fetch(context.Background(), FetchRequest{URL: "https://intel.example.test/feed"})
	if !errors.Is(err, ErrUnsafeURL) {
		t.Fatalf("expected ErrUnsafeURL for redirect, got %v", err)
	}
}

func TestFetcherFollowsSafeRedirect(t *testing.T) {
	requests := 0
	fetcher, err := newFetcherForTest(roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		if requests == 1 {
			response := stubResponse(http.StatusMovedPermanently, "text/html", "")
			response.Header.Set("Location", "https://cdn.example.test/feed")
			response.Request = request
			return response, nil
		}
		response := stubResponse(http.StatusOK, "text/html", "<html>feed</html>")
		response.Request = request
		return response, nil
	}), FetchOptions{})
	if err != nil {
		t.Fatalf("new test fetcher: %v", err)
	}
	result, err := fetcher.Fetch(context.Background(), FetchRequest{URL: "https://intel.example.test/feed"})
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if requests != 2 {
		t.Fatalf("expected 2 requests, got %d", requests)
	}
	if result.URL != "https://cdn.example.test/feed" {
		t.Fatalf("expected final redirect URL, got %q", result.URL)
	}
	if string(result.Body) != "<html>feed</html>" {
		t.Fatalf("unexpected body %q", result.Body)
	}
}

func TestFetcherHandlesNotModified(t *testing.T) {
	fetcher, err := newFetcherForTest(roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Header.Get("If-None-Match") != `"abc"` {
			t.Fatalf("expected conditional request header, got %q", request.Header.Get("If-None-Match"))
		}
		response := stubResponse(http.StatusNotModified, "", "")
		response.Header.Set("ETag", `"abc"`)
		return response, nil
	}), FetchOptions{})
	if err != nil {
		t.Fatalf("new test fetcher: %v", err)
	}
	result, err := fetcher.Fetch(context.Background(), FetchRequest{
		URL:  "https://intel.example.test/feed",
		ETag: `"abc"`,
	})
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if !result.NotModified || len(result.Body) != 0 || result.ETag != `"abc"` {
		t.Fatalf("unexpected not-modified result: %+v", result)
	}
}

func TestFetcherRejectsInvalidConditionalHeader(t *testing.T) {
	fetcher, err := NewFetcher(FetchOptions{})
	if err != nil {
		t.Fatalf("new fetcher: %v", err)
	}
	_, err = fetcher.Fetch(context.Background(), FetchRequest{
		URL:  "https://intel.example.test/feed",
		ETag: "value\r\nInjected: 1",
	})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("expected ErrInvalid, got %v", err)
	}
}

func TestFetcherRejectsInvalidOptions(t *testing.T) {
	tests := []struct {
		name string
		opts FetchOptions
	}{
		{name: "body too large", opts: FetchOptions{MaxBodyBytes: MaxFetchBodyBytes + 1}},
		{name: "negative body", opts: FetchOptions{MaxBodyBytes: -1}},
		{name: "redirects too large", opts: FetchOptions{MaxRedirects: HardMaxRedirects + 1}},
		{name: "negative redirects", opts: FetchOptions{MaxRedirects: -1}},
		{name: "timeout too large", opts: FetchOptions{Timeout: MaxFetchTimeout + time.Second}},
		{name: "negative timeout", opts: FetchOptions{Timeout: -time.Second}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewFetcher(test.opts); !errors.Is(err, ErrInvalid) {
				t.Fatalf("expected ErrInvalid, got %v", err)
			}
		})
	}
}
