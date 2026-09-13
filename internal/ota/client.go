package ota

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/netguard"
)

// ClientOptions configures the read-only OTA index client. The production
// defaults pin the endpoint to ota.cheesesec.com and require HTTPS.
type ClientOptions struct {
	BaseURL       string
	ExpectedHost  string
	HTTPClient    *http.Client
	MaxIndexBytes int64
	Clock         func() time.Time
}

// Client only reads a channel index. It never writes a package, invokes an
// installer, or changes the running CRP.
type Client struct {
	baseURL       *url.URL
	expectedHost  string
	httpClient    *http.Client
	maxIndexBytes int64
	now           func() time.Time
}

func NewClient(options ClientOptions) (*Client, error) {
	baseURL := options.BaseURL
	if baseURL == "" {
		baseURL = DefaultEndpoint
	}
	expectedHost := options.ExpectedHost
	if expectedHost == "" {
		expectedHost = "ota.cheesesec.com"
	}
	parsed, err := url.Parse(baseURL)
	expectedHost = strings.ToLower(expectedHost)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() != expectedHost || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return nil, fmt.Errorf("%w: BaseURL must be an HTTPS %s origin without credentials or a path", ErrInvalidConfig, expectedHost)
	}
	if _, err := netguard.ValidateURL(parsed.String(), netguard.URLPolicy{
		Purpose:        "OTA index",
		HostPurpose:    "OTA endpoint",
		AllowedSchemes: []string{"https"},
	}); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidConfig, err)
	}
	client := options.HTTPClient
	if client == nil {
		client = netguard.NewHTTPClient(netguard.HTTPClientOptions{
			Timeout: 8 * time.Second,
			Policy: netguard.URLPolicy{
				Purpose:        "OTA index",
				HostPurpose:    "OTA endpoint",
				AllowedSchemes: []string{"https"},
			},
		})
	}
	client = cloneHTTPClient(client)
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return ErrRedirect
	}
	maxBytes := options.MaxIndexBytes
	if maxBytes <= 0 {
		maxBytes = DefaultMaxIndexBytes
	}
	now := options.Clock
	if now == nil {
		now = time.Now
	}
	return &Client{
		baseURL:       parsed,
		expectedHost:  expectedHost,
		httpClient:    client,
		maxIndexBytes: maxBytes,
		now:           now,
	}, nil
}

func (c *Client) channelURL(channel string) (*url.URL, error) {
	if c == nil || c.baseURL == nil {
		return nil, fmt.Errorf("%w: client is nil", ErrInvalidConfig)
	}
	if err := validateChannel(channel); err != nil {
		return nil, err
	}
	return &url.URL{
		Scheme: c.baseURL.Scheme,
		Host:   c.baseURL.Host,
		Path:   "/v1/channels/" + channel + "/index.json",
	}, nil
}

// Check fetches one channel index and returns the newest verified metadata
// candidate above the local sequence fence.
func (c *Client) Check(ctx context.Context, request Request) (Candidate, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	endpoint, err := c.channelURL(request.Channel)
	if err != nil {
		return Candidate{}, err
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return Candidate{}, err
	}
	httpRequest.Header.Set("Accept", "application/json")
	httpRequest.Header.Set("Cache-Control", "no-cache")
	httpRequest.Header.Set("User-Agent", "CheeseWAF-OTA/1")

	response, err := c.httpClient.Do(httpRequest)
	if err != nil {
		if errors.Is(err, ErrRedirect) {
			return Candidate{}, ErrRedirect
		}
		return Candidate{}, fmt.Errorf("OTA index request failed: %w", err)
	}
	defer response.Body.Close()
	if response.Request != nil && response.Request.URL != nil &&
		(response.Request.URL.Scheme != "https" || response.Request.URL.Hostname() != c.expectedHost) {
		return Candidate{}, fmt.Errorf("%w: final response origin is not pinned", ErrInvalidConfig)
	}
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		return Candidate{}, ErrRedirect
	}
	if response.StatusCode != http.StatusOK {
		return Candidate{}, fmt.Errorf("OTA index returned HTTP %d", response.StatusCode)
	}
	mediaType, _, parseErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if parseErr != nil || !strings.EqualFold(mediaType, "application/json") {
		return Candidate{}, ErrNonJSON
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, c.maxIndexBytes+1))
	if err != nil {
		return Candidate{}, fmt.Errorf("read OTA index: %w", err)
	}
	if int64(len(body)) > c.maxIndexBytes {
		return Candidate{}, ErrIndexTooLarge
	}
	index, err := decodeIndex(body)
	if err != nil {
		return Candidate{}, err
	}
	if index.IndexSequence < request.CurrentIndexSequence {
		return Candidate{}, ErrSequenceRollback
	}
	var selected Candidate
	var selectedFound bool
	var sawLowerRelease bool
	for _, candidate := range index.Releases {
		candidate.IndexSequence = index.IndexSequence
		if candidate.ReleaseSequence < request.CurrentReleaseSequence {
			sawLowerRelease = true
			continue
		}
		if candidate.ReleaseSequence == request.CurrentReleaseSequence {
			continue
		}
		if !selectedFound || candidate.ReleaseSequence > selected.ReleaseSequence {
			selected = candidate
			selectedFound = true
		}
	}
	if !selectedFound {
		if sawLowerRelease {
			return Candidate{}, ErrSequenceRollback
		}
		return Candidate{}, ErrUpToDate
	}
	return selected, nil
}

func cloneHTTPClient(client *http.Client) *http.Client {
	if client == nil {
		return &http.Client{}
	}
	clone := *client
	return &clone
}
