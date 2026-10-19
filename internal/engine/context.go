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
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/blockpage"
	"github.com/LaokeQwQ/CheeseWAF/internal/proxytrust"
)

const defaultRequestBodyLimit = 8 << 20

// A reader that ignores Close can retain one goroutine until it returns. Keep
// those workers globally bounded so an attacker cannot turn slow uploads into
// an unbounded goroutine leak.
const maxInflightBodyReads = 256

// Keep a noisy site from consuming every body-reader worker while other sites
// are active. When this is the only active site, admission may use otherwise
// idle global capacity; the global pool remains the hard process bound.
const maxInflightBodyReadsPerSite = 32

var bodyReadSlots = make(chan struct{}, maxInflightBodyReads)
var bodyReadSiteAdmissions = siteAdmission{
	maxActive: maxInflightBodyReadsPerSite,
	maxSites:  1024,
}

// Body snapshots are bounded by bytes as well as worker count. Readers reserve
// capacity before growing their buffers, so a large configured body ceiling
// does not reserve its full size for a small request. The per-site
// ceiling is an admission limit independent of max_body_bytes.
// These reservations cover current buffers and published snapshots; temporary
// old/new allocation overlap during growth or compaction remains GC-managed.
const (
	maxBodyBytesPerSite = 64 << 20
	maxBodyBytesGlobal  = 256 << 20
	bodyReadChunkBytes  = 32 << 10
	bodyReadIdleTimeout = 10 * time.Second
)

var bodyBudget = struct {
	sync.Mutex
	global      int64
	bySite      map[string]int64
	changed     chan struct{}
	reclaimDone chan struct{}
	nextReclaim time.Time
}{bySite: make(map[string]int64), changed: make(chan struct{})}

// Cap inflate relative to compressed size to reduce zip-bomb risk.
const maxDecompressionRatio = 20

var ErrRequestBodyTooLarge = errors.New("request body exceeds configured limit")

// ErrRequestBodyReadOverload means bounded reader or body-byte capacity is full.
// It is an incomplete-inspection condition and must never be treated as clean.
var ErrRequestBodyReadOverload = errors.New("request body inspection overloaded")

// ErrRequestBodyReadTimeout means an upload stopped making progress. Upload
// time is bounded separately from the detector CPU budget.
var ErrRequestBodyReadTimeout = errors.New("request body read idle timeout")

func NewRequestContext(r *http.Request, siteID string) (*RequestContext, error) {
	return newRequestContext(r, siteID, ClientIP(r), defaultRequestBodyLimit, true, nil)
}

func NewRequestContextWithTrustedProxies(r *http.Request, siteID string, trustedCIDRs []string) (*RequestContext, error) {
	return NewRequestContextWithLimits(r, siteID, trustedCIDRs, defaultRequestBodyLimit)
}

// NewRequestContextWithLimits builds a context and eagerly reads the body.
func NewRequestContextWithLimits(r *http.Request, siteID string, trustedCIDRs []string, maxBodyBytes int64) (*RequestContext, error) {
	return newRequestContext(r, siteID, ClientIPWithTrustedProxies(r, trustedCIDRs), maxBodyBytes, true, trustedCIDRs)
}

// NewRequestContextDeferredBody skips body I/O until EnsureBody (hot-path lazy-once).
func NewRequestContextDeferredBody(r *http.Request, siteID string, trustedCIDRs []string, maxBodyBytes int64) (*RequestContext, error) {
	return newRequestContext(r, siteID, ClientIPWithTrustedProxies(r, trustedCIDRs), maxBodyBytes, false, trustedCIDRs)
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
	var trustedCIDRs []string
	if policy != nil {
		trustedCIDRs = policy.AllTrustedCIDRs()
	}
	return newRequestContext(r, siteID, clientIPFromPolicy(r, policy), maxBodyBytes, false, trustedCIDRs)
}

func newRequestContext(r *http.Request, siteID, clientIP string, maxBodyBytes int64, readBody bool, trustedCIDRs []string) (*RequestContext, error) {
	if maxBodyBytes <= 0 {
		maxBodyBytes = defaultRequestBodyLimit
	}
	reqCtx := &RequestContext{
		Request:           r,
		ClientIP:          clientIP,
		TraceID:           blockpage.NewTraceID(),
		SiteID:            siteID,
		TrustedProxyCIDRs: append([]string(nil), trustedCIDRs...),
		Results:           make([]DetectionResult, 0, 8),
		Metadata:          map[string]any{},
		maxBodyBytes:      maxBodyBytes,
	}
	if r != nil && r.URL != nil {
		reqCtx.NormalizedPath, _ = NormalizeRequestPath(r.URL.Path)
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

// EnsureBody reads and rewinds the request body at most once. Callers without
// a request context still receive the independent upload idle bound.
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
	c.bodyReadProgress = time.Now()
	c.bodyReadAbort = make(chan struct{})
	// A manually assembled context may contain stale semantic bytes while its
	// live transport body has not been materialized. Do not let a failed attempt
	// expose those bytes as the result of this read.
	c.rawBody = nil
	c.DecodedBody = nil
	c.bodyMu.Unlock()

	// Enforce the per-site fairness quota before acquiring the process-wide
	// reader slot. The global semaphore remains the independent hard bound.
	siteToken, admitted := bodyReadSiteAdmissions.acquire(c.SiteID)
	if !admitted {
		c.finishBodyRead(nil, nil, ErrRequestBodyReadOverload, done, originalBody, closeOnce)
		closeBodyReadSource(originalBody, closeOnce)
		return ErrRequestBodyReadOverload
	}
	select {
	case bodyReadSlots <- struct{}{}:
		go c.readBodyWorker(originalBody, done, maxBodyBytes, encoding, closeOnce, siteToken)
		return waitBodyRead(ctx, done, originalBody, closeOnce, c)
	default:
		// Admission failure did not consume the source, so leave Request.Body and
		// ContentLength exactly as supplied by the caller.
		siteToken.release()
		c.finishBodyRead(nil, nil, ErrRequestBodyReadOverload, done, originalBody, closeOnce)
		closeBodyReadSource(originalBody, closeOnce)
		return ErrRequestBodyReadOverload
	}
}

func reserveBodyBudget(siteID string, amount int64) bool {
	if amount <= 0 || amount > maxBodyBytesPerSite {
		return false
	}
	bodyBudget.Lock()
	defer bodyBudget.Unlock()
	if bodyBudget.global+amount > maxBodyBytesGlobal {
		return false
	}
	if bodyBudget.bySite[siteID]+amount > maxBodyBytesPerSite {
		return false
	}
	bodyBudget.global += amount
	bodyBudget.bySite[siteID] += amount
	return true
}

func (c *RequestContext) reserveBodyBudget(amount int64) bool {
	if c == nil {
		return false
	}
	c.bodyMu.Lock()
	aborted := c.bodyLoaded
	c.bodyMu.Unlock()
	if aborted || (!reserveBodyBudget(c.SiteID, amount) && !reclaimBodyBudget(c.SiteID, amount)) {
		return false
	}
	c.bodyMu.Lock()
	defer c.bodyMu.Unlock()
	if c.bodyLoaded {
		releaseRetainedBodyBudget(bodyBudgetRelease{c.SiteID, amount})
		return false
	}
	c.bodyReservation += amount
	c.bodyReservationHeld = true
	return true
}

// Reaching the admission ceiling can stop the allocations that would otherwise
// trigger GC. Coalesce and rate-limit pressure collections, then allow pending
// cleanups a short interval to return capacity. Live snapshots remain charged;
// normal admissions never collect or wait here.
func reclaimBodyBudget(siteID string, amount int64) bool {
	bodyBudget.Lock()
	done := bodyBudget.reclaimDone
	if done == nil && !time.Now().Before(bodyBudget.nextReclaim) {
		done = make(chan struct{})
		bodyBudget.reclaimDone = done
		bodyBudget.nextReclaim = time.Now().Add(100 * time.Millisecond)
		go func(done chan struct{}) {
			runtime.GC()
			bodyBudget.Lock()
			bodyBudget.reclaimDone = nil
			close(done)
			bodyBudget.Unlock()
		}(done)
	}
	bodyBudget.Unlock()
	timer := time.NewTimer(100 * time.Millisecond)
	defer timer.Stop()
	for {
		bodyBudget.Lock()
		changed := bodyBudget.changed
		bodyBudget.Unlock()
		if reserveBodyBudget(siteID, amount) {
			return true
		}
		select {
		case <-changed:
		case <-done:
			done = nil
		case <-timer.C:
			return false
		}
	}
}

type bodyBudgetRelease struct {
	siteID string
	bytes  int64
}

func releaseRetainedBodyBudget(reservation bodyBudgetRelease) {
	bodyBudget.Lock()
	bodyBudget.global -= reservation.bytes
	bodyBudget.bySite[reservation.siteID] -= reservation.bytes
	if bodyBudget.bySite[reservation.siteID] <= 0 {
		delete(bodyBudget.bySite, reservation.siteID)
	}
	close(bodyBudget.changed)
	bodyBudget.changed = make(chan struct{})
	bodyBudget.Unlock()
}

// Attach accounting to the backing allocation itself: slices in detector forks,
// GetBody closures and replay readers all keep it alive, including after a
// detector times out. The cleanup argument must never reference the buffer.
func retainBodyBudget(siteID string, body []byte) {
	if cap(body) > 0 {
		runtime.AddCleanup(&body[:cap(body)][0], releaseRetainedBodyBudget, bodyBudgetRelease{siteID, int64(cap(body))})
		runtime.KeepAlive(body)
	}
}

func (c *RequestContext) releaseBodyBudgetLocked() {
	if c == nil || !c.bodyReservationHeld {
		return
	}
	releaseRetainedBodyBudget(bodyBudgetRelease{c.SiteID, c.bodyReservation})
	c.bodyReservation = 0
	c.bodyReservationHeld = false
}

func waitBodyRead(ctx context.Context, done chan struct{}, body io.ReadCloser, closeOnce *sync.Once, owner *RequestContext) error {
	if ctx == nil {
		ctx = context.Background()
	}
	owner.bodyMu.Lock()
	idleTimeout := owner.bodyReadIdleTimeout
	if idleTimeout <= 0 {
		idleTimeout = bodyReadIdleTimeout
	}
	abort := owner.bodyReadAbort
	owner.bodyMu.Unlock()
	timer := time.NewTimer(idleTimeout)
	defer timer.Stop()
	for {
		select {
		case <-done:
			owner.bodyMu.Lock()
			err := owner.bodyErr
			owner.bodyMu.Unlock()
			return err
		case <-abort:
			owner.bodyMu.Lock()
			err := owner.bodyErr
			owner.bodyMu.Unlock()
			return err
		case <-timer.C:
			owner.bodyMu.Lock()
			remaining := idleTimeout - time.Since(owner.bodyReadProgress)
			owner.bodyMu.Unlock()
			if remaining > 0 {
				timer.Reset(remaining)
				continue
			}
			return owner.abortBodyRead(ErrRequestBodyReadTimeout, done, body, closeOnce)
		case <-ctx.Done():
			return owner.abortBodyRead(ctx.Err(), done, body, closeOnce)
		}
	}
}

func (owner *RequestContext) abortBodyRead(ctxErr error, done chan struct{}, body io.ReadCloser, closeOnce *sync.Once) error {
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
	close(owner.bodyReadAbort)
	owner.bodyMu.Unlock()

	// An arbitrary ReadCloser can also block in Close. The read slot remains
	// held until the worker and its deferred Close both finish, bounding these
	// close goroutines without blocking cancellation or the idle timeout. Only
	// the caller that makes this attempt terminal can start a closer.
	go closeBodyReadSource(body, closeOnce)
	return ctxErr
}

func closeBodyReadSource(body io.Closer, closeOnce *sync.Once) {
	if body == nil || closeOnce == nil {
		return
	}
	defer func() { _ = recover() }()
	closeOnce.Do(func() { _ = body.Close() })
}

func (c *RequestContext) readBodyWorker(originalBody io.ReadCloser, done chan struct{}, maxBodyBytes int64, encoding string, closeOnce *sync.Once, siteToken siteAdmissionToken) {
	defer func() { <-bodyReadSlots }()
	defer siteToken.release()
	defer closeBodyReadSource(originalBody, closeOnce)

	var raw []byte
	var readErr error
	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				readErr = fmt.Errorf("request body reader panic: %v", recovered)
			}
		}()
		raw, readErr = c.readBodyWithBudget(originalBody, maxBodyBytes)
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
			decoded, readErr = c.decodeHTTPContentEncoding(raw, encoding, maxBodyBytes)
		}
	}
	c.finishBodyRead(raw, decoded, readErr, done, originalBody, closeOnce)
}

func (c *RequestContext) readBodyWithBudget(body io.Reader, maxBodyBytes int64) ([]byte, error) {
	var buffer []byte
	for {
		c.bodyMu.Lock()
		aborted := c.bodyErr
		c.bodyMu.Unlock()
		if aborted != nil {
			return nil, aborted
		}
		if int64(len(buffer)) >= maxBodyBytes {
			var probe [1]byte
			n, err := body.Read(probe[:])
			if n > 0 {
				return nil, ErrRequestBodyTooLarge
			}
			if errors.Is(err, io.EOF) {
				return c.compactBodyBuffer(buffer), nil
			}
			if err != nil {
				return nil, err
			}
			return buffer, io.ErrNoProgress
		}
		if len(buffer) == cap(buffer) {
			capacity := max(bodyReadChunkBytes, 2*cap(buffer))
			if int64(capacity) > maxBodyBytes {
				capacity = int(maxBodyBytes)
			}
			// Avoid tiny allocator batching, for which runtime cleanup is not
			// guaranteed even after the snapshot becomes unreachable.
			capacity = max(capacity, 32)
			if !c.reserveBodyBudget(int64(capacity - cap(buffer))) {
				return nil, ErrRequestBodyReadOverload
			}
			grown := make([]byte, len(buffer), capacity)
			copy(grown, buffer)
			buffer = grown
		}
		end := min(int64(cap(buffer)), maxBodyBytes)
		readBuffer := buffer[len(buffer):int(end)]
		n, err := body.Read(readBuffer)
		if n > 0 {
			buffer = buffer[:len(buffer)+n]
			c.bodyMu.Lock()
			c.bodyReadProgress = time.Now()
			c.bodyMu.Unlock()
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return c.compactBodyBuffer(buffer), nil
			}
			return nil, err
		}
		if n == 0 {
			return buffer, io.ErrNoProgress
		}
	}
}

func (c *RequestContext) compactBodyBuffer(buffer []byte) []byte {
	capacity := max(len(buffer), 32)
	if len(buffer) == 0 {
		capacity = 0
	}
	if capacity >= cap(buffer) {
		return buffer
	}
	var compact []byte
	if capacity > 0 {
		compact = make([]byte, len(buffer), capacity)
		copy(compact, buffer)
	}
	unused := int64(cap(buffer) - capacity)
	c.bodyMu.Lock()
	c.bodyReservation -= unused
	c.bodyReservationHeld = c.bodyReservation > 0
	releaseRetainedBodyBudget(bodyBudgetRelease{c.SiteID, unused})
	c.bodyMu.Unlock()
	return compact
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
		c.releaseBodyBudgetLocked()
		close(done)
		return
	}

	if readErr == nil {
		if len(raw) == 0 {
			// Empty bodies publish no allocation or replay closure.
			c.releaseBodyBudgetLocked()
			raw, decoded = nil, nil
		} else {
			retainBodyBudget(c.SiteID, raw)
			if cap(decoded) > 0 && &decoded[:cap(decoded)][0] != &raw[0] {
				retainBodyBudget(c.SiteID, decoded)
			}
			c.bodyReservation = 0
			c.bodyReservationHeld = false
		}
		// Publish all body state in one critical section only after both transfer
		// reading and semantic decoding completed. No prefix is ever replayed as a
		// complete request after an error.
		// The reader owns these buffers; publish them once as immutable snapshots.
		c.rawBody = raw
		c.DecodedBody = decoded
		if c.Request != nil {
			bodyCopy := raw
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
	c.releaseBodyBudgetLocked()
	c.bodyReadBody = originalBody
	c.bodyCloseOnce = closeOnce
	close(done)
}

// detectionBodySnapshot returns immutable body state for a detector fork.
// Detectors must never mutate these slices; each request gets an independent
// replay reader so ParseForm does not consume another detector's input.
func (c *RequestContext) detectionBodySnapshot() (raw, decoded []byte, loaded, bodyPresent bool, err error) {
	if c == nil {
		return nil, nil, false, false, nil
	}
	c.bodyMu.Lock()
	defer c.bodyMu.Unlock()
	raw = c.rawBody
	decoded = c.DecodedBody
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

func (c *RequestContext) decodeHTTPContentEncoding(raw []byte, encoding string, maxPlain int64) ([]byte, error) {
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
		fr := flate.NewReader(bytes.NewReader(raw))
		defer fr.Close()
		reader = fr
	case "br", "zstd":
		return nil, errors.New("unsupported content-encoding for inspection: " + encoding)
	default:
		return nil, errors.New("unsupported content-encoding for inspection: " + encoding)
	}
	limit := maxPlain
	if ratioCap := int64(len(raw)) * maxDecompressionRatio; ratioCap > 0 && ratioCap < limit {
		limit = ratioCap
	}
	return c.readBodyWithBudget(reader, limit)
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
