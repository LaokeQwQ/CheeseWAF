package engine

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/blockpage"
	"github.com/LaokeQwQ/CheeseWAF/internal/proxytrust"
)

const defaultRequestBodyLimit = 8 << 20

// Cap inflate relative to compressed size to reduce zip-bomb risk.
const maxDecompressionRatio = 20

var ErrRequestBodyTooLarge = errors.New("request body exceeds configured limit")

func NewRequestContext(r *http.Request, siteID string) (*RequestContext, error) {
	return newRequestContext(r, siteID, ClientIP(r), defaultRequestBodyLimit, true)
}

func NewRequestContextWithTrustedProxies(r *http.Request, siteID string, trustedCIDRs []string) (*RequestContext, error) {
	return NewRequestContextWithLimits(r, siteID, trustedCIDRs, defaultRequestBodyLimit)
}

// NewRequestContextWithLimits builds a context and eagerly reads the body.
func NewRequestContextWithLimits(r *http.Request, siteID string, trustedCIDRs []string, maxBodyBytes int64) (*RequestContext, error) {
	return newRequestContext(r, siteID, ClientIPWithTrustedProxies(r, trustedCIDRs), maxBodyBytes, true)
}

// NewRequestContextDeferredBody skips body I/O until EnsureBody (hot-path lazy-once).
func NewRequestContextDeferredBody(r *http.Request, siteID string, trustedCIDRs []string, maxBodyBytes int64) (*RequestContext, error) {
	return newRequestContext(r, siteID, ClientIPWithTrustedProxies(r, trustedCIDRs), maxBodyBytes, false)
}

// TrustedProxyPolicy is an immutable compiled client-IP trust policy.
type TrustedProxyPolicy = proxytrust.Policy

var directClientIPPolicy, _ = proxytrust.Compile(nil, nil)

// NewTrustedProxyPolicy binds provider-specific headers to their own CIDRs.
func NewTrustedProxyPolicy(trustedCIDRs []string, providerCIDRs map[string][]string) (*TrustedProxyPolicy, error) {
	return proxytrust.Compile(trustedCIDRs, providerCIDRs)
}

// NewRequestContextDeferredBodyWithTrustedProxyPolicy uses a precompiled proxy
// policy and skips body I/O until EnsureBody.
func NewRequestContextDeferredBodyWithTrustedProxyPolicy(r *http.Request, siteID string, policy *TrustedProxyPolicy, maxBodyBytes int64) (*RequestContext, error) {
	return newRequestContext(r, siteID, clientIPFromPolicy(r, policy), maxBodyBytes, false)
}

func newRequestContext(r *http.Request, siteID, clientIP string, maxBodyBytes int64, readBody bool) (*RequestContext, error) {
	if maxBodyBytes <= 0 {
		maxBodyBytes = defaultRequestBodyLimit
	}
	reqCtx := &RequestContext{
		Request:      r,
		ClientIP:     clientIP,
		TraceID:      blockpage.NewTraceID(),
		SiteID:       siteID,
		Metadata:     map[string]any{},
		maxBodyBytes: maxBodyBytes,
	}
	if r != nil && r.URL != nil {
		reqCtx.DecodedURI = r.URL.RequestURI()
		if r.ContentLength > maxBodyBytes {
			return nil, ErrRequestBodyTooLarge
		}
	}
	if readBody {
		if err := reqCtx.EnsureBody(); err != nil {
			return nil, err
		}
	}
	return reqCtx, nil
}

// EnsureBody reads and rewinds the request body at most once.
// When Content-Encoding is gzip/deflate, DecodedBody is the decompressed
// payload used by WAF detectors (with decompression limits). Request.Body is
// rewound with the original transfer encoding for the upstream.
func (c *RequestContext) EnsureBody() error {
	if c == nil {
		return errors.New("nil request context")
	}
	if c.bodyLoaded {
		return nil
	}
	if c.Request == nil || c.Request.Body == nil {
		c.bodyLoaded = true
		c.DecodedBody = nil
		return nil
	}
	maxBodyBytes := c.maxBodyBytes
	if maxBodyBytes <= 0 {
		maxBodyBytes = defaultRequestBodyLimit
	}
	if c.Request.ContentLength > maxBodyBytes {
		return ErrRequestBodyTooLarge
	}
	originalBody := c.Request.Body
	raw, err := io.ReadAll(io.LimitReader(originalBody, maxBodyBytes+1))
	if err != nil {
		_ = originalBody.Close()
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return ErrRequestBodyTooLarge
		}
		return err
	}
	if int64(len(raw)) > maxBodyBytes {
		_ = originalBody.Close()
		return ErrRequestBodyTooLarge
	}
	_ = originalBody.Close()

	decoded := raw
	encoding := strings.ToLower(strings.TrimSpace(c.Request.Header.Get("Content-Encoding")))
	if encoding != "" && encoding != "identity" {
		plain, derr := decodeHTTPContentEncoding(raw, encoding, maxBodyBytes)
		if derr != nil {
			return derr
		}
		decoded = plain
	}
	c.DecodedBody = decoded
	c.Request.Body = io.NopCloser(bytes.NewReader(raw))
	c.Request.ContentLength = int64(len(raw))
	c.bodyLoaded = true
	return nil
}

func decodeHTTPContentEncoding(raw []byte, encoding string, maxPlain int64) ([]byte, error) {
	if strings.Contains(encoding, ",") {
		return nil, errors.New("unsupported multi-layer content-encoding")
	}
	var reader io.Reader
	switch encoding {
	case "gzip", "x-gzip":
		gr, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			return nil, err
		}
		defer gr.Close()
		reader = gr
	case "deflate":
		reader = flate.NewReader(bytes.NewReader(raw))
	case "br", "zstd":
		return nil, errors.New("unsupported content-encoding for inspection: " + encoding)
	default:
		return nil, errors.New("unsupported content-encoding for inspection: " + encoding)
	}
	limit := maxPlain
	if ratioCap := int64(len(raw)) * maxDecompressionRatio; ratioCap > 0 && ratioCap < limit {
		limit = ratioCap
	}
	plain, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(plain)) > limit {
		return nil, ErrRequestBodyTooLarge
	}
	return plain, nil
}

type replayBody struct {
	io.Reader
	closer io.Closer
}

func (b replayBody) Close() error {
	if b.closer == nil {
		return nil
	}
	return b.closer.Close()
}

func replayRequestBody(prefix []byte, rest io.ReadCloser) io.ReadCloser {
	return replayBody{
		Reader: io.MultiReader(bytes.NewReader(prefix), rest),
		closer: rest,
	}
}

func ClientIP(r *http.Request) string {
	return clientIPFromPolicy(r, nil)
}

// ClientIPWithTrustedProxies accepts only the standardized forwarding chain.
// Provider-specific headers require ClientIPWithTrustedProxyProviders.
func ClientIPWithTrustedProxies(r *http.Request, trustedCIDRs []string) string {
	return ClientIPWithTrustedProxyProviders(r, trustedCIDRs, nil)
}

// ClientIPWithTrustedProxyProviders resolves provider-specific headers only
// when the socket peer matches that provider's explicitly configured CIDRs.
func ClientIPWithTrustedProxyProviders(r *http.Request, trustedCIDRs []string, providerCIDRs map[string][]string) string {
	policy, err := NewTrustedProxyPolicy(trustedCIDRs, providerCIDRs)
	if err != nil {
		return clientIPFromPolicy(r, nil)
	}
	return clientIPFromPolicy(r, policy)
}

func clientIPFromPolicy(r *http.Request, policy *TrustedProxyPolicy) string {
	if policy == nil {
		policy = directClientIPPolicy
	}
	return policy.ClientIP(r)
}

func (a Action) String() string {
	switch a {
	case ActionBlock:
		return "block"
	case ActionChallenge:
		return "challenge"
	case ActionLog:
		return "log"
	default:
		return "pass"
	}
}

func (s Severity) String() string {
	switch s {
	case SeverityCritical:
		return "critical"
	case SeverityHigh:
		return "high"
	case SeverityMedium:
		return "medium"
	case SeverityLow:
		return "low"
	default:
		return "info"
	}
}
