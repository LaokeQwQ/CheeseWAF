package engine

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/LaokeQwQ/CheeseWAF/internal/blockpage"
	"github.com/LaokeQwQ/CheeseWAF/internal/proxytrust"
)

const defaultRequestBodyLimit = 8 << 20

// A reader that ignores Close can retain one goroutine until it returns. Keep
// those workers globally bounded so an attacker cannot turn slow uploads into
// an unbounded goroutine leak.
const maxInflightBodyReads = 256

var bodyReadSlots = make(chan struct{}, maxInflightBodyReads)

// Cap inflate relative to compressed size to reduce zip-bomb risk.
const maxDecompressionRatio = 20

var ErrRequestBodyTooLarge = errors.New("request body exceeds configured limit")

// ErrRequestBodyReadOverload means all bounded body-reader workers are busy.
// It is an incomplete-inspection condition and must never be treated as clean.
var ErrRequestBodyReadOverload = errors.New("request body inspection overloaded")

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
		Results:      make([]DetectionResult, 0, 8),
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

// EnsureBody reads and rewinds the request body at most once. It preserves the
// historical blocking API for callers that do not have a request context.
func (c *RequestContext) EnsureBody() error {
	return c.EnsureBodyContext(context.Background())
}

// EnsureBodyContext materializes one shared body snapshot and waits for it with
// the caller's context. Only one reader worker is created per RequestContext;
// concurrent callers wait on the same completion channel. Snapshot publication
// is transactional: a read/decode error or cancellation never replaces the
// transport Body with bytes from an incomplete read.
func (c *RequestContext) EnsureBodyContext(ctx context.Context) error {
	if c == nil {
		return errors.New("nil request context")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	c.bodyMu.Lock()
	if c.bodyLoaded || c.bodyErr != nil {
		err := c.bodyErr
		c.bodyMu.Unlock()
		return err
	}
	if c.Request == nil || c.Request.Body == nil {
		// Embedders may provide a semantic snapshot without a transport reader.
		if len(c.DecodedBody) > 0 {
			bodyCopy := append([]byte(nil), c.DecodedBody...)
			c.rawBody = append(c.rawBody[:0], bodyCopy...)
			if c.Request != nil {
				c.Request.Body = io.NopCloser(bytes.NewReader(bodyCopy))
				c.Request.GetBody = func() (io.ReadCloser, error) {
					return io.NopCloser(bytes.NewReader(bodyCopy)), nil
				}
				c.Request.ContentLength = int64(len(bodyCopy))
			}
		} else if c.Request != nil {
			// Always install an explicit empty replay body. A nil/custom reader can
			// otherwise leave an upstream or detector with a closed one-shot body.
			c.Request.Body = http.NoBody
			c.Request.GetBody = func() (io.ReadCloser, error) { return http.NoBody, nil }
			c.Request.ContentLength = 0
		}
		c.bodyLoaded = true
		c.bodyMu.Unlock()
		return nil
	}
	maxBodyBytes := c.maxBodyBytes
	if maxBodyBytes <= 0 {
		maxBodyBytes = defaultRequestBodyLimit
	}
	if c.Request.ContentLength > maxBodyBytes {
		c.bodyErr = ErrRequestBodyTooLarge
		c.bodyLoaded = true
		c.bodyMu.Unlock()
		return c.bodyErr
	}
	if done := c.bodyReadDone; done != nil {
		body := c.bodyReadBody
		closeOnce := c.bodyCloseOnce
		c.bodyMu.Unlock()
		return waitBodyRead(ctx, done, body, closeOnce, c)
	}

	originalBody := c.Request.Body
	encoding := strings.ToLower(strings.TrimSpace(c.Request.Header.Get("Content-Encoding")))
	done := make(chan struct{})
	closeOnce := &sync.Once{}
	c.bodyReadDone = done
	c.bodyReadBody = originalBody
	c.bodyCloseOnce = closeOnce
	// A manually assembled context may contain stale semantic bytes while its
	// live transport body has not been materialized. Do not let a failed attempt
	// expose those bytes as the result of this read.
	c.rawBody = nil
	c.DecodedBody = nil
	c.bodyMu.Unlock()

	select {
	case bodyReadSlots <- struct{}{}:
		go c.readBodyWorker(originalBody, done, maxBodyBytes, encoding, closeOnce)
		return waitBodyRead(ctx, done, originalBody, closeOnce, c)
	default:
		// Admission failure did not consume the source, so leave Request.Body and
		// ContentLength exactly as supplied by the caller.
		c.finishBodyRead(nil, nil, ErrRequestBodyReadOverload, done, originalBody, closeOnce)
		closeBodyReadSource(originalBody, closeOnce)
		return ErrRequestBodyReadOverload
	}
}

func waitBodyRead(ctx context.Context, done chan struct{}, body io.ReadCloser, closeOnce *sync.Once, owner *RequestContext) error {
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-done:
		if owner == nil {
			return nil
		}
		owner.bodyMu.Lock()
		err := owner.bodyErr
		owner.bodyMu.Unlock()
		return err
	case <-ctx.Done():
		ctxErr := ctx.Err()
		if owner == nil {
			closeBodyReadSource(body, closeOnce)
			return ctxErr
		}

		// Cancellation abandons the shared attempt before signaling Close. The
		// reader worker observes bodyLoaded and must discard every byte it may
		// return later, so it cannot race a forwarding path by rewriting Request.
		owner.bodyMu.Lock()
		if owner.bodyLoaded {
			err := owner.bodyErr
			owner.bodyMu.Unlock()
			return err
		}
		if owner.bodyReadDone != done {
			err := owner.bodyErr
			owner.bodyMu.Unlock()
			if err != nil {
				return err
			}
			return ctxErr
		}
		owner.bodyErr = ctxErr
		owner.bodyLoaded = true
		owner.bodyMu.Unlock()

		closeBodyReadSource(body, closeOnce)
		return ctxErr
	}
}

func closeBodyReadSource(body io.Closer, closeOnce *sync.Once) {
	if body == nil || closeOnce == nil {
		return
	}
	defer func() { _ = recover() }()
	closeOnce.Do(func() { _ = body.Close() })
}

func (c *RequestContext) readBodyWorker(originalBody io.ReadCloser, done chan struct{}, maxBodyBytes int64, encoding string, closeOnce *sync.Once) {
	defer func() { <-bodyReadSlots }()
	defer closeBodyReadSource(originalBody, closeOnce)

	var raw []byte
	var readErr error
	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				readErr = fmt.Errorf("request body reader panic: %v", recovered)
			}
		}()
		raw, readErr = io.ReadAll(io.LimitReader(originalBody, maxBodyBytes+1))
	}()
	if readErr != nil {
		var maxErr *http.MaxBytesError
		if errors.As(readErr, &maxErr) {
			readErr = ErrRequestBodyTooLarge
		}
	}
	if readErr == nil && int64(len(raw)) > maxBodyBytes {
		readErr = ErrRequestBodyTooLarge
	}

	var decoded []byte
	if readErr == nil {
		decoded = raw
		if encoding != "" && encoding != "identity" {
			decoded, readErr = decodeHTTPContentEncoding(raw, encoding, maxBodyBytes)
		}
	}
	c.finishBodyRead(raw, decoded, readErr, done, originalBody, closeOnce)
}

func (c *RequestContext) finishBodyRead(raw, decoded []byte, readErr error, done chan struct{}, originalBody io.ReadCloser, closeOnce *sync.Once) {
	if c == nil {
		close(done)
		return
	}
	c.bodyMu.Lock()
	defer c.bodyMu.Unlock()
	// A canceled waiter has already made this attempt terminal. It may have
	// returned while an uncooperative reader was still unwinding; discard the
	// late result and leave every public request field untouched.
	if c.bodyLoaded {
		close(done)
		return
	}

	if readErr == nil {
		// Publish all body state in one critical section only after both transfer
		// reading and semantic decoding completed. No prefix is ever replayed as a
		// complete request after an error.
		c.rawBody = append(c.rawBody[:0], raw...)
		c.DecodedBody = append(c.DecodedBody[:0], decoded...)
		if c.Request != nil {
			bodyCopy := append([]byte(nil), raw...)
			if len(bodyCopy) == 0 {
				c.Request.Body = http.NoBody
				c.Request.GetBody = func() (io.ReadCloser, error) { return http.NoBody, nil }
			} else {
				c.Request.Body = io.NopCloser(bytes.NewReader(bodyCopy))
				c.Request.GetBody = func() (io.ReadCloser, error) {
					return io.NopCloser(bytes.NewReader(bodyCopy)), nil
				}
			}
			c.Request.ContentLength = int64(len(bodyCopy))
		}
	}
	c.bodyErr = readErr
	c.bodyLoaded = true
	c.bodyReadBody = originalBody
	c.bodyCloseOnce = closeOnce
	close(done)
}

// detectionBodySnapshot returns private copies of the body state for a
// semantic detector fork. The copies make the exported DecodedBody slice safe
// even if a third-party detector accidentally mutates its local context after
// the pipeline has moved on. Callers must not use the returned slices to
// mutate the parent request.
func (c *RequestContext) detectionBodySnapshot() (raw, decoded []byte, loaded, bodyPresent bool, err error) {
	if c == nil {
		return nil, nil, false, false, nil
	}
	c.bodyMu.Lock()
	defer c.bodyMu.Unlock()
	raw = append([]byte(nil), c.rawBody...)
	decoded = append([]byte(nil), c.DecodedBody...)
	loaded = c.bodyLoaded
	if c.Request != nil {
		bodyPresent = c.Request.Body != nil
	}
	err = c.bodyErr
	return raw, decoded, loaded, bodyPresent, err
}

// bodyState returns the loaded/error flags and the current live reader without
// copying the body. The non-blocking lock attempt lets pipeline callers keep
// their deadline when a separate reader is currently materializing the
// snapshot; they can fall back to a bounded EnsureBody call in that case.
func (c *RequestContext) bodyState() (loaded bool, err error, body io.ReadCloser, available bool) {
	if c == nil || !c.bodyMu.TryLock() {
		return false, nil, nil, false
	}
	defer c.bodyMu.Unlock()
	if c.Request != nil {
		body = c.Request.Body
	}
	return c.bodyLoaded, c.bodyErr, body, true
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
