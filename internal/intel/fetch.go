package intel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"mime"
	"net/http"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/LaokeQwQ/CheeseWAF/internal/netguard"
)

const (
	// MaxFetchBodyBytes is the hard response body cap for intelligence feeds.
	MaxFetchBodyBytes int64 = 256 << 10
	// DefaultFetchTimeout is the default per-fetch deadline.
	DefaultFetchTimeout = 10 * time.Second
	// MaxFetchTimeout is the largest allowed fetch deadline.
	MaxFetchTimeout = 60 * time.Second
	// DefaultMaxRedirects is the default redirect budget.
	DefaultMaxRedirects = 5
	// HardMaxRedirects is the largest allowed redirect budget.
	HardMaxRedirects = 10
	// DefaultFetcherUserAgent identifies CheeseWAF when fetching feeds.
	DefaultFetcherUserAgent = "CheeseWAF-Intel/1.0"
)

var fetchURLPolicy = netguard.URLPolicy{
	Purpose:        "intel fetch",
	HostPurpose:    "intel source",
	AllowedSchemes: []string{"http", "https"},
}

var defaultFetchContentTypes = []string{
	"text/html",
	"application/xhtml+xml",
	"text/plain",
	"application/json",
	"application/xml",
	"text/xml",
	"application/rss+xml",
	"application/atom+xml",
	"application/feed+json",
}

// FetchOptions configures a Fetcher. Zero values select safe defaults.
type FetchOptions struct {
	Timeout             time.Duration
	MaxBodyBytes        int64
	MaxRedirects        int
	AllowedContentTypes []string
	Resolver            netguard.Resolver
	UserAgent           string
}

// FetchRequest describes one conditional feed request.
type FetchRequest struct {
	URL          string
	ETag         string
	LastModified string
}

// FetchResult is a bounded, normalized feed response.
type FetchResult struct {
	URL          string
	StatusCode   int
	ContentType  string
	Body         []byte
	ETag         string
	LastModified string
	NotModified  bool
	FetchedAt    time.Time
	SHA256       string
}

// Fetcher performs SSRF-safe feed fetches. Redirect targets are revalidated,
// bodies are capped, and content types are allowlisted.
type Fetcher struct {
	client       *http.Client
	timeout      time.Duration
	maxBodyBytes int64
	maxRedirects int
	contentTypes map[string]struct{}
	userAgent    string
	now          func() time.Time
}

// ValidateFetchURL applies the fetcher URL policy without performing DNS or
// network I/O. Hostnames are resolved only when a fetch dials.
func ValidateFetchURL(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("%w: fetch url is required", ErrUnsafeURL)
	}
	if _, err := netguard.ValidateURL(raw, fetchURLPolicy); err != nil {
		return fmt.Errorf("%w: %v", ErrUnsafeURL, err)
	}
	return nil
}

// NewFetcher builds a fetcher whose dialer resolves DNS and rejects non-public
// addresses, and whose redirects are revalidated against the same policy.
func NewFetcher(opts FetchOptions) (*Fetcher, error) {
	fetcher, err := newFetcher(opts)
	if err != nil {
		return nil, err
	}
	client := netguard.NewHTTPClient(netguard.HTTPClientOptions{
		Timeout:  fetcher.timeout,
		Resolver: opts.Resolver,
		Policy:   fetchURLPolicy,
	})
	client.CheckRedirect = fetcher.checkRedirect
	fetcher.client = client
	return fetcher, nil
}

func newFetcher(opts FetchOptions) (*Fetcher, error) {
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = DefaultFetchTimeout
	}
	if timeout < 0 {
		return nil, fmt.Errorf("%w: fetch timeout must not be negative", ErrInvalid)
	}
	if timeout > MaxFetchTimeout {
		return nil, fmt.Errorf("%w: fetch timeout exceeds %s", ErrInvalid, MaxFetchTimeout)
	}
	maxBody := opts.MaxBodyBytes
	if maxBody == 0 {
		maxBody = MaxFetchBodyBytes
	}
	if maxBody < 0 || maxBody > MaxFetchBodyBytes {
		return nil, fmt.Errorf("%w: fetch body limit must be between 1 and %d bytes", ErrInvalid, MaxFetchBodyBytes)
	}
	redirects := opts.MaxRedirects
	if redirects == 0 {
		redirects = DefaultMaxRedirects
	}
	if redirects < 0 || redirects > HardMaxRedirects {
		return nil, fmt.Errorf("%w: redirect limit must be between 1 and %d", ErrInvalid, HardMaxRedirects)
	}
	contentTypes := opts.AllowedContentTypes
	if len(contentTypes) == 0 {
		contentTypes = defaultFetchContentTypes
	}
	allowed := make(map[string]struct{}, len(contentTypes))
	for _, contentType := range contentTypes {
		contentType = strings.ToLower(strings.TrimSpace(contentType))
		if contentType == "" {
			continue
		}
		allowed[contentType] = struct{}{}
	}
	if len(allowed) == 0 {
		return nil, fmt.Errorf("%w: at least one content type must be allowed", ErrInvalid)
	}
	userAgent := strings.TrimSpace(opts.UserAgent)
	if userAgent == "" {
		userAgent = DefaultFetcherUserAgent
	}
	if len(userAgent) > 256 || strings.ContainsAny(userAgent, "\r\n") {
		return nil, fmt.Errorf("%w: invalid user agent", ErrInvalid)
	}
	return &Fetcher{
		timeout:      timeout,
		maxBodyBytes: maxBody,
		maxRedirects: redirects,
		contentTypes: allowed,
		userAgent:    userAgent,
		now:          time.Now,
	}, nil
}

// newFetcherForTest builds a fetcher over a supplied transport while keeping
// the production URL, redirect, size, and content-type policies.
func newFetcherForTest(transport http.RoundTripper, opts FetchOptions) (*Fetcher, error) {
	fetcher, err := newFetcher(opts)
	if err != nil {
		return nil, err
	}
	fetcher.client = &http.Client{
		Transport:     transport,
		Timeout:       fetcher.timeout,
		CheckRedirect: fetcher.checkRedirect,
	}
	return fetcher, nil
}

// Fetch retrieves a feed URL. Errors never panic and wrap a typed sentinel where
// a policy limit was hit.
func (f *Fetcher) Fetch(ctx context.Context, request FetchRequest) (FetchResult, error) {
	if f == nil || f.client == nil {
		return FetchResult{}, fmt.Errorf("%w: fetcher is not configured", ErrInvalid)
	}
	rawURL := strings.TrimSpace(request.URL)
	if rawURL == "" {
		return FetchResult{}, fmt.Errorf("%w: fetch url is required", ErrInvalid)
	}
	if len(rawURL) > maxExtractionURLBytes {
		return FetchResult{}, fmt.Errorf("%w: fetch url exceeds %d bytes", ErrInvalid, maxExtractionURLBytes)
	}
	if err := validateConditionalHeader("etag", request.ETag, maxSourceETagBytes); err != nil {
		return FetchResult{}, err
	}
	if err := validateConditionalHeader("last-modified", request.LastModified, maxSourceLastModifiedSize); err != nil {
		return FetchResult{}, err
	}
	httpRequest, err := netguard.NewRequest(ctx, http.MethodGet, rawURL, nil, fetchURLPolicy)
	if err != nil {
		return FetchResult{}, fmt.Errorf("%w: %v", ErrUnsafeURL, err)
	}
	httpRequest.Header.Set("User-Agent", f.userAgent)
	httpRequest.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,text/plain;q=0.8,application/json;q=0.8")
	if request.ETag != "" {
		httpRequest.Header.Set("If-None-Match", request.ETag)
	}
	if request.LastModified != "" {
		httpRequest.Header.Set("If-Modified-Since", request.LastModified)
	}
	response, err := f.client.Do(httpRequest)
	if err != nil {
		return FetchResult{}, fmt.Errorf("intel: fetch %s: %w", rawURL, err)
	}
	defer func() { _ = response.Body.Close() }()
	result := FetchResult{
		URL:          httpRequest.URL.String(),
		StatusCode:   response.StatusCode,
		ETag:         response.Header.Get("ETag"),
		LastModified: response.Header.Get("Last-Modified"),
		FetchedAt:    f.now().UTC(),
	}
	if response.Request != nil && response.Request.URL != nil {
		result.URL = response.Request.URL.String()
	}
	if response.StatusCode == http.StatusNotModified {
		result.NotModified = true
		result.ContentType = response.Header.Get("Content-Type")
		return result, nil
	}
	if response.StatusCode < http.StatusOK || response.StatusCode > 299 {
		return FetchResult{}, fmt.Errorf("%w: fetch %s returned status %d", ErrInvalid, rawURL, response.StatusCode)
	}
	mediaType, err := normalizeMediaType(response.Header.Get("Content-Type"))
	if err != nil {
		return FetchResult{}, err
	}
	if _, ok := f.contentTypes[mediaType]; !ok {
		return FetchResult{}, fmt.Errorf("%w: %q is not allowed; allowed: %s", ErrUnsupportedContentType, mediaType, f.allowedContentTypeList())
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, f.maxBodyBytes+1))
	if err != nil {
		return FetchResult{}, fmt.Errorf("intel: read response body: %w", err)
	}
	if int64(len(body)) > f.maxBodyBytes {
		return FetchResult{}, fmt.Errorf("%w: more than %d bytes", ErrResponseTooLarge, f.maxBodyBytes)
	}
	sum := sha256.Sum256(body)
	result.ContentType = mediaType
	result.Body = body
	result.SHA256 = hex.EncodeToString(sum[:])
	return result, nil
}

func (f *Fetcher) checkRedirect(request *http.Request, via []*http.Request) error {
	if request == nil || request.URL == nil {
		return fmt.Errorf("%w: redirect is missing a target URL", ErrUnsafeURL)
	}
	if len(via) > f.maxRedirects {
		return fmt.Errorf("%w: limit is %d", ErrTooManyRedirects, f.maxRedirects)
	}
	if _, err := netguard.ValidateURL(request.URL.String(), fetchURLPolicy); err != nil {
		return fmt.Errorf("%w: blocked redirect: %v", ErrUnsafeURL, err)
	}
	return nil
}

func (f *Fetcher) allowedContentTypeList() string {
	values := make([]string, 0, len(f.contentTypes))
	for value := range f.contentTypes {
		values = append(values, value)
	}
	sort.Strings(values)
	return strings.Join(values, ", ")
}

func normalizeMediaType(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("%w: response is missing a content type", ErrUnsupportedContentType)
	}
	mediaType, _, err := mime.ParseMediaType(raw)
	if err != nil {
		return "", fmt.Errorf("%w: malformed content type %q", ErrUnsupportedContentType, raw)
	}
	return strings.ToLower(strings.TrimSpace(mediaType)), nil
}

func validateConditionalHeader(label, value string, max int) error {
	if len(value) > max {
		return fmt.Errorf("%w: %s header exceeds %d bytes", ErrInvalid, label, max)
	}
	if strings.ContainsFunc(value, unicode.IsControl) {
		return fmt.Errorf("%w: %s header contains a control character", ErrInvalid, label)
	}
	return nil
}
