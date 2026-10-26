package proxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/apisec"
	"github.com/LaokeQwQ/CheeseWAF/internal/blockpage"
	"github.com/LaokeQwQ/CheeseWAF/internal/captcha"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/edge"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine/response"
	"github.com/LaokeQwQ/CheeseWAF/internal/fsguard"
	"github.com/LaokeQwQ/CheeseWAF/internal/protection/acl"
	"github.com/LaokeQwQ/CheeseWAF/internal/protection/bot"
	"github.com/LaokeQwQ/CheeseWAF/internal/protection/ip"
	"github.com/LaokeQwQ/CheeseWAF/internal/protection/ratelimit"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
	"github.com/LaokeQwQ/CheeseWAF/internal/timekeeper"
)

var errResponseTamperDetected = errors.New("authenticated response tamper detected")

// Unknown-length body preflight runs in a bounded worker because an arbitrary
// io.ReadCloser is allowed to ignore both context cancellation and Close.
// A finite worker pool prevents such readers from turning request admission
// into an unbounded goroutine leak.
const (
	maxInflightPreflightReads   = 128
	preflightUnknownBodyTimeout = 30 * time.Second
)

var preflightBodySlots = make(chan struct{}, maxInflightPreflightReads)

type requestDetectionPipeline interface {
	Detect(context.Context, *engine.RequestContext) (*engine.DetectionResult, error)
}

// incompleteInputMarker is implemented by the real pipeline. Test doubles that
// only stub Detect keep working: a truncated adapter body then reports the
// plain detection result instead of silently claiming full coverage.
type incompleteInputMarker interface {
	MarkInputIncomplete(*engine.RequestContext, *engine.DetectionResult, string) *engine.DetectionResult
}

type Server struct {
	config           *config.Config
	runtimeMu        sync.RWMutex
	policyUpdateMu   sync.Mutex
	captchaProviders config.CAPTCHAProvidersConfig
	pipeline         requestDetectionPipeline
	pipelineMu       sync.RWMutex
	logSink          storage.LogSink
	renderer         *blockpage.Renderer
	lb               *LoadBalancer
	access           *ip.AccessPolicy
	geoip            *ip.GeoIPPolicy
	intel            *ip.Intel
	acl              *acl.Policy
	bot              *bot.Policy
	limiter          *ratelimit.Limiter
	health           *HealthRegistry
	edgeRuntime      atomic.Pointer[edgeRuntime]
	siteRuntimes     atomic.Pointer[siteRuntimeSet]
	apiSchema        *apisec.Validator
	apiLimit         *apisec.RateLimiter
	apiAuth          *apisec.Authenticator
	apiSecEnabled    bool
	protectionPolicy config.ProtectionPolicyConfig
	protectionConfig config.ProtectionConfig
	apiSecConfig     config.APISecConfig
	certs            *SiteCertificateStore
	clock            timekeeper.Clock
	reviews          ReviewQueue
	promotes         *promoteTable
}

type edgeRuntime struct {
	headers  *edge.HeaderModifier
	cache    *edge.Cache
	compress *edge.Compressor
}

type siteRuntime struct {
	site              config.SiteConfig
	rewriter          *Rewriter
	inspector         *response.Inspector
	trustedProxy      *engine.TrustedProxyPolicy
	trustedProxyCIDRs []string
}

type siteRuntimeSet struct {
	byID map[string]*siteRuntime
}

func newEdgeRuntime(cfg config.EdgeConfig) *edgeRuntime {
	return &edgeRuntime{
		headers:  edge.NewHeaderModifier(cfg.Headers),
		cache:    edge.NewCache(cfg.Cache),
		compress: edge.NewCompressor(cfg.Compression),
	}
}

func newSiteRuntimeSet(sites []config.SiteConfig) (*siteRuntimeSet, error) {
	set := &siteRuntimeSet{byID: make(map[string]*siteRuntime, len(sites))}
	for _, site := range sites {
		trustedProxy, err := engine.NewTrustedProxyPolicy(
			site.WAF.AccessControl.TrustedCIDRs,
			site.WAF.AccessControl.TrustedProxyProviders,
		)
		if err != nil {
			return nil, err
		}
		rewriter, err := NewRewriter(site.WAF.Rewrite)
		if err != nil {
			return nil, err
		}
		inspector, err := response.New(site.WAF.Response)
		if err != nil {
			return nil, err
		}
		set.byID[site.ID] = &siteRuntime{
			site:              site,
			rewriter:          rewriter,
			inspector:         inspector,
			trustedProxy:      trustedProxy,
			trustedProxyCIDRs: trustedProxy.AllTrustedCIDRs(),
		}
	}
	return set, nil
}

func NewServer(cfg *config.Config, pipeline *engine.Pipeline, sink storage.LogSink) (*Server, error) {
	return NewServerWithClock(cfg, pipeline, sink, timekeeper.SystemClock{})
}

func NewServerWithClock(cfg *config.Config, pipeline *engine.Pipeline, sink storage.LogSink, clock timekeeper.Clock) (*Server, error) {
	if clock == nil {
		clock = timekeeper.SystemClock{}
	}
	if cfg.Console.Login.CAPTCHA.Enabled && strings.EqualFold(strings.TrimSpace(cfg.Console.Login.CAPTCHA.Provider), "cap") {
		provider := cfg.CAPTCHAProviders.Cap
		if _, err := captcha.NewCapVerifierFromFile(provider.SiteVerifyEndpoint(), provider.SecretFile, provider.Timeout); err != nil {
			return nil, fmt.Errorf("console login CAPTCHA provider is invalid: %w", err)
		}
	}
	siteRuntimes, err := newSiteRuntimeSet(cfg.Sites)
	if err != nil {
		return nil, err
	}
	access, err := ip.NewAccessPolicy(cfg.Protection.IP)
	if err != nil {
		return nil, err
	}
	geoip, err := ip.NewGeoIPPolicy(cfg.Protection.IP.GeoIP)
	if err != nil {
		return nil, err
	}
	geoipOwned := true
	defer func() {
		if geoipOwned {
			_ = geoip.Close()
		}
	}()
	intel, err := ip.NewIntel(cfg.Protection.IP.ThreatIntel)
	if err != nil {
		return nil, err
	}
	health := NewHealthRegistry(cfg.Sites)
	apiSchema, err := apisec.NewValidator(cfg.APISec.Validation)
	if err != nil {
		return nil, err
	}
	apiLimit, err := apisec.NewRateLimiter(cfg.APISec.RateLimits)
	if err != nil {
		return nil, err
	}
	apiSec := cfg.APISec
	apiSec.Auth.JWKSCacheRoot = filepath.Join(cfg.Setup.DataDir, "apisec")
	apiAuth, err := apisec.NewAuthenticatorWithClock(apiSec, clock)
	if err != nil {
		return nil, err
	}
	apiAuthOwned := true
	defer func() {
		if apiAuthOwned {
			_ = apiAuth.Close()
		}
	}()
	renderer, err := blockpage.NewRendererFromConfig(cfg.BlockPage)
	if err != nil {
		return nil, err
	}
	certs, err := NewSiteCertificateStore(cfg)
	if err != nil {
		return nil, err
	}
	var activePipeline requestDetectionPipeline
	if pipeline != nil {
		activePipeline = pipeline
	}
	botPolicy, err := bot.NewPolicyWithCAPTCHAProviders(cfg.Protection.Bot, cfg.CAPTCHAProviders, clock)
	if err != nil {
		return nil, fmt.Errorf("create bot policy: %w", err)
	}
	server := &Server{
		config:           cfg,
		captchaProviders: cfg.CAPTCHAProviders,
		pipeline:         activePipeline,
		logSink:          sink,
		renderer:         renderer,
		lb:               NewLoadBalancer(cfg.Sites).WithHealth(health),
		access:           access,
		geoip:            geoip,
		intel:            intel,
		acl:              acl.NewPolicy(cfg.Protection.ACL),
		bot:              botPolicy,
		limiter:          ratelimit.New(cfg.Protection.RateLimit.Default, cfg.Protection.RateLimit.Enabled),
		health:           health,
		apiSchema:        apiSchema,
		apiLimit:         apiLimit,
		apiAuth:          apiAuth,
		apiSecEnabled:    cfg.APISec.Enabled,
		protectionPolicy: cfg.Protection.Policy,
		protectionConfig: cfg.Protection,
		apiSecConfig:     cfg.APISec,
		certs:            certs,
		clock:            clock,
		promotes:         newPromoteTable(),
	}
	server.edgeRuntime.Store(newEdgeRuntime(cfg.Edge))
	server.siteRuntimes.Store(siteRuntimes)
	geoipOwned = false
	apiAuthOwned = false
	return server, nil
}

// UpdateEdge atomically replaces all request-time Edge components.
func (s *Server) UpdateEdge(cfg config.EdgeConfig) error {
	if s == nil {
		return nil
	}
	s.edgeRuntime.Store(newEdgeRuntime(cfg))
	return nil
}

func (s *Server) UpdateBlockPage(page config.BlockPageConfig) error {
	if s == nil {
		return nil
	}
	renderer, err := blockpage.NewRendererFromConfig(page)
	if err != nil {
		return err
	}
	s.runtimeMu.Lock()
	s.renderer = renderer
	s.runtimeMu.Unlock()
	return nil
}

func (s *Server) HealthRegistry() *HealthRegistry {
	return s.health
}

// UpdateSites refreshes site routing and certificates. Certificate load errors
// are returned so callers can roll back instead of reporting success with a stale cert.
func (s *Server) UpdateSites(sites []config.SiteConfig) error {
	if s == nil {
		return nil
	}
	runtimes, err := newSiteRuntimeSet(sites)
	if err != nil {
		return err
	}
	nextConfig := *s.config
	nextConfig.Sites = append([]config.SiteConfig(nil), sites...)
	if s.certs != nil {
		if err := s.certs.Update(&nextConfig); err != nil {
			return err
		}
	}
	s.health.UpdateSites(sites)
	s.lb.UpdateSites(sites, s.health)
	s.siteRuntimes.Store(runtimes)
	return nil
}

func (s *Server) UpdatePipeline(pipeline *engine.Pipeline) {
	if s == nil {
		return
	}
	s.pipelineMu.Lock()
	defer s.pipelineMu.Unlock()
	if pipeline == nil {
		s.pipeline = nil
		return
	}
	s.pipeline = pipeline
}

func (s *Server) currentPipeline() requestDetectionPipeline {
	if s == nil {
		return nil
	}
	s.pipelineMu.RLock()
	defer s.pipelineMu.RUnlock()
	return s.pipeline
}

// SiteForHost resolves the enabled site for an adapter-supplied authority.
func (s *Server) SiteForHost(host string) config.SiteConfig {
	if s == nil || s.lb == nil {
		return config.SiteConfig{}
	}
	return s.lb.SiteForHost(host)
}

// Detect runs the live request detection pipeline without proxying. It is used
// by the adapter inspection endpoint; callers own request-body loading.
func (s *Server) Detect(ctx context.Context, reqCtx *engine.RequestContext) (*engine.DetectionResult, error) {
	pipeline := s.currentPipeline()
	if pipeline == nil {
		return nil, nil
	}
	return pipeline.Detect(ctx, reqCtx)
}

func (s *Server) wallNow() time.Time {
	if s != nil && s.clock != nil {
		return s.clock.Now()
	}
	return time.Now()
}

func (s *Server) UpdateAPISec(apiSec config.APISecConfig) error {
	if s == nil {
		return nil
	}
	s.runtimeMu.RLock()
	unchanged := reflect.DeepEqual(s.apiSecConfig, apiSec)
	s.runtimeMu.RUnlock()
	if unchanged {
		return nil
	}
	apiSchema, err := apisec.NewValidator(apiSec.Validation)
	if err != nil {
		return err
	}
	apiLimit, err := apisec.NewRateLimiter(apiSec.RateLimits)
	if err != nil {
		return err
	}
	apiSec.Auth.JWKSCacheRoot = filepath.Join(s.config.Setup.DataDir, "apisec")
	apiAuth, err := apisec.NewAuthenticatorWithClock(apiSec, s.clock)
	if err != nil {
		return err
	}
	s.runtimeMu.Lock()
	oldAuth := s.apiAuth
	s.apiSecConfig = apiSec
	s.apiSchema = apiSchema
	s.apiLimit = apiLimit
	s.apiAuth = apiAuth
	s.apiSecEnabled = apiSec.Enabled
	s.runtimeMu.Unlock()
	if oldAuth != nil {
		_ = oldAuth.Close()
	}
	return nil
}

func (s *Server) UpdateProtection(protection config.ProtectionConfig) error {
	if s == nil {
		return nil
	}
	s.policyUpdateMu.Lock()
	defer s.policyUpdateMu.Unlock()
	access, err := ip.NewAccessPolicy(protection.IP)
	if err != nil {
		return err
	}
	geoip, err := ip.NewGeoIPPolicy(protection.IP.GeoIP)
	if err != nil {
		return err
	}
	intel, err := ip.NewIntel(protection.IP.ThreatIntel)
	if err != nil {
		_ = geoip.Close()
		return err
	}
	s.runtimeMu.RLock()
	providers := s.captchaProviders
	botChanged := !reflect.DeepEqual(s.protectionConfig.Bot, protection.Bot)
	s.runtimeMu.RUnlock()
	var botPolicy *bot.Policy
	if botChanged {
		botPolicy, err = bot.NewPolicyWithCAPTCHAProviders(protection.Bot, providers, s.clock)
		if err != nil {
			_ = geoip.Close()
			return fmt.Errorf("create bot policy: %w", err)
		}
	}
	s.runtimeMu.Lock()
	oldGeoIP := s.geoip
	s.access = access
	s.geoip = geoip
	s.intel = intel
	s.acl = acl.NewPolicy(protection.ACL)
	if botChanged {
		s.bot = botPolicy
	}
	if !reflect.DeepEqual(s.protectionConfig.RateLimit, protection.RateLimit) {
		s.limiter = ratelimit.New(protection.RateLimit.Default, protection.RateLimit.Enabled)
	}
	s.protectionConfig = protection
	s.protectionPolicy = protection.Policy
	s.runtimeMu.Unlock()
	if oldGeoIP != nil {
		_ = oldGeoIP.Close()
	}
	return nil
}

func (s *Server) UpdateCAPTCHAProviders(providers config.CAPTCHAProvidersConfig) error {
	if s == nil {
		return nil
	}
	s.policyUpdateMu.Lock()
	defer s.policyUpdateMu.Unlock()
	s.runtimeMu.RLock()
	protection := s.protectionConfig
	unchanged := reflect.DeepEqual(s.captchaProviders, providers)
	s.runtimeMu.RUnlock()
	if unchanged {
		return nil
	}
	// Provider settings may change for console login alone. Preserve pending
	// challenges and failures unless this Bot policy actually uses Cap.
	usesCap := protection.Bot.Enabled && protection.Bot.CAPTCHA &&
		strings.EqualFold(strings.TrimSpace(protection.Bot.CAPTCHAProvider), "cap")
	var botPolicy *bot.Policy
	if usesCap {
		var err error
		botPolicy, err = bot.NewPolicyWithCAPTCHAProviders(protection.Bot, providers, s.clock)
		if err != nil {
			return fmt.Errorf("create bot policy: %w", err)
		}
	}
	s.runtimeMu.Lock()
	s.captchaProviders = providers
	if usesCap {
		s.bot = botPolicy
	}
	s.runtimeMu.Unlock()
	return nil
}

// Close releases runtime resources after in-flight requests have exited.
func (s *Server) Close() error {
	if s == nil {
		return nil
	}
	s.runtimeMu.Lock()
	geoip := s.geoip
	auth := s.apiAuth
	s.geoip = nil
	s.apiAuth = nil
	s.runtimeMu.Unlock()
	var closeErr error
	if geoip != nil {
		closeErr = geoip.Close()
	}
	if auth != nil {
		if err := auth.Close(); closeErr == nil {
			closeErr = err
		}
	}
	return closeErr
}

func (s *Server) Handler() http.Handler {
	return securityHeaders(http.HandlerFunc(s.handle))
}

func (s *Server) HTTPServer() *http.Server {
	return &http.Server{
		Addr:              s.config.Server.Listen,
		Handler:           withIdleWriteTimeout(s.Handler(), s.config.Server.WriteTimeout),
		ReadHeaderTimeout: s.config.Server.ReadTimeout,
		ReadTimeout:       s.config.Server.ReadTimeout,
		WriteTimeout:      0, // withIdleWriteTimeout applies a rolling deadline to response writes.
		IdleTimeout:       s.config.Server.IdleTimeout,
		MaxHeaderBytes:    maxHeaderBytes(s.config),
	}
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	inboundRequest := r
	s.runtimeMu.RLock()
	runtimeLocked := true
	unlockRuntime := func() {
		if runtimeLocked {
			s.runtimeMu.RUnlock()
			runtimeLocked = false
		}
	}
	lockRuntime := func() {
		if !runtimeLocked {
			s.runtimeMu.RLock()
			runtimeLocked = true
		}
	}
	defer func() {
		lockRuntime()
		s.runtimeMu.RUnlock()
	}()
	start := time.Now()
	site := s.lb.SiteForHost(r.Host)
	// Never fall back to another tenant: unmatched Host gets 421 before bot/WAF.
	if site.ID == "" {
		http.Error(w, "Misdirected Request: no site matches this host", http.StatusMisdirectedRequest)
		return
	}
	siteSet := s.siteRuntimes.Load()
	edgeRT := s.edgeRuntime.Load()
	if siteSet == nil || siteSet.byID[site.ID] == nil || edgeRT == nil {
		http.Error(w, "runtime configuration unavailable", http.StatusServiceUnavailable)
		return
	}
	siteRT := siteSet.byID[site.ID]
	if r.TLS != nil && r.TLS.ServerName != "" && normalizeRequestHost(r.TLS.ServerName) != normalizeRequestHost(r.Host) {
		http.Error(w, "SNI and Host must match", http.StatusMisdirectedRequest)
		return
	}
	if limit := site.WAF.Performance.MaxHeaderBytes; limit > 0 && requestHeaderBytes(r) > limit {
		http.Error(w, "request headers exceed site limit", http.StatusRequestHeaderFieldsTooLarge)
		return
	}
	// Attach trusted proxy CIDRs early so bot clearance cookies and X-Forwarded-Proto
	// decisions stay consistent for the whole request (no per-call re-resolution).
	r = r.WithContext(bot.ContextWithTrustedCIDRs(r.Context(), siteRT.trustedProxyCIDRs))
	policy := config.EffectiveProtectionPolicy(s.protectionPolicy, site.WAF.ProtectionPolicy)
	// Site toggles are explicit runtime gates. A nil legacy pointer inherits the
	// global protection switch; false must disable that feature for this site.
	botEnabled := siteFeatureEnabled(site.WAF.BotEnabled, s.protectionConfig.Bot.Enabled)
	rateLimitEnabled := siteFeatureEnabled(site.WAF.RateLimitEnabled, s.protectionConfig.RateLimit.Enabled)
	aclEnabled := siteFeatureEnabled(site.WAF.ACLEnabled, s.protectionConfig.ACL.Enabled)
	apiSecurityEnabled := siteFeatureEnabled(site.WAF.APISecurityEnabled, s.apiSecEnabled)

	https := requestIsHTTPS(r, siteRT.trustedProxyCIDRs)
	if site.Certificate.ForceHTTPS && !https && r.Method != http.MethodConnect {
		host := r.Host
		if host == "" {
			host = r.URL.Host
		}
		http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), http.StatusMovedPermanently)
		return
	}
	if https && site.Certificate.HSTS {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	}

	// Clean path for bot/IP/path policy only. Keep r.URL.Path unchanged so
	// open-redirect guards (e.g. scheme-relative "//host") still see the raw path.
	requestPath, pathOK := engine.NormalizeRequestPath(r.URL.Path)
	if !pathOK {
		s.block(w, &engine.RequestContext{
			Request:  r,
			ClientIP: siteRT.trustedProxy.ClientIP(r),
			TraceID:  blockpage.NewTraceID(),
			SiteID:   site.ID,
			Metadata: map[string]any{"invalid_path": r.URL.Path},
		}, "invalid_path", "invalid request path", http.StatusBadRequest, start)
		return
	}

	// Protocol enforcement: HTTP smuggling, chunked encoding abuse, header injection
	if violation := engine.DetectProtocolViolations(r); violation != nil {
		s.block(w, &engine.RequestContext{
			Request:  r,
			ClientIP: siteRT.trustedProxy.ClientIP(r),
			TraceID:  blockpage.NewTraceID(),
			SiteID:   site.ID,
			Metadata: map[string]any{"protocol_violation": violation.Type},
		}, "protocol_enforcement", violation.Message, http.StatusBadRequest, start)
		return
	}
	if len(r.Header.Values("Content-Type")) > 1 || len(r.Header.Values("Content-Encoding")) > 1 {
		http.Error(w, "ambiguous content metadata", http.StatusBadRequest)
		return
	}
	if len(r.Trailer) > 0 || len(r.Header.Values("Trailer")) > 0 {
		http.Error(w, "request trailers are not supported", http.StatusBadRequest)
		return
	}
	stripRoutingOverrideHeaders(r.Header)
	mediaType := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0]))
	if strings.HasPrefix(mediaType, "application/grpc") && !site.WAF.GRPCEnabled {
		http.Error(w, "gRPC requires explicit opt-in; message inspection is unavailable", http.StatusUnsupportedMediaType)
		return
	}
	if IsWebSocketUpgrade(r) && !site.WAF.WebSocketEnabled {
		http.Error(w, "WebSocket requires explicit opt-in; frame inspection is unavailable", http.StatusForbidden)
		return
	}
	if IsWebSocketUpgrade(r) && !webSocketOriginAllowed(r, https) {
		http.Error(w, "WebSocket origin is not allowed", http.StatusForbidden)
		return
	}
	r.Header.Del("Sec-WebSocket-Extensions")
	// Rewrites mutate r.URL before the upstream call. Keep the public request
	// identity for exact tamper snapshots and response telemetry.
	publicRequest := r.Clone(r.Context())
	redirect, redirectCode := false, 0
	// This endpoint belongs to the WAF, not the upstream application. Keep its
	// request identity intact so site rewrites cannot divert challenge answers
	// or remove the dedicated body limit. IP/Geo gates still run below.
	if requestPath != botBehaviorVerifyPath {
		redirect, redirectCode = siteRT.rewriter.Apply(r)
	}
	rewritten := publicRequest.URL.RequestURI() != r.URL.RequestURI()
	if rewritten {
		requestPath, pathOK = engine.NormalizeRequestPath(r.URL.Path)
		if !pathOK {
			http.Error(w, "invalid rewritten request path", http.StatusBadRequest)
			return
		}
	}
	policyRequests := []*http.Request{r}
	if rewritten {
		policyRequests = append(policyRequests, publicRequest)
	}
	publicPolicyRequest := func() *http.Request {
		request := publicRequest.Clone(r.Context())
		// The public identity was saved before the body limit and deferred read.
		// Challenge form parsing must use the current capped or replayed body.
		request.Body = r.Body
		request.GetBody = r.GetBody
		request.ContentLength = r.ContentLength
		request.Form = r.Form
		request.PostForm = r.PostForm
		return request
	}

	maxRequestBody := site.WAF.Performance.MaxBodyBytes
	if maxRequestBody <= 0 {
		maxRequestBody = 8 << 20
	}
	// Behavior verify still needs a small body; enforce a tight cap before shared body read.
	if requestPath == botBehaviorVerifyPath || r.URL.Path == botBehaviorVerifyPath {
		const maxVerifyBody = int64(64 << 10)
		if r.ContentLength > maxVerifyBody {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		if maxRequestBody > maxVerifyBody {
			maxRequestBody = maxVerifyBody
		}
	}
	// Keep the same cap on requests that skip body inspection. MaxBytesReader
	// also bounds chunked and HTTP/2 bodies whose ContentLength is unknown.
	if r.Body != nil && r.Body != http.NoBody {
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	}
	// Defer body I/O until APISec/WAF (or verify). IP/geo/bot/rate use headers only.
	reqCtx, err := engine.NewRequestContextDeferredBodyWithTrustedProxyPolicy(r, site.ID, siteRT.trustedProxy, maxRequestBody)
	if err != nil {
		if errors.Is(err, engine.ErrRequestBodyTooLarge) {
			s.proxyError(w, r, site, nil, "request_too_large", "request body exceeds site limit", http.StatusRequestEntityTooLarge, start, err)
			return
		}
		s.proxyError(w, r, site, nil, "proxy_error", "failed to read request", requestBodyReadErrorStatus(err, http.StatusBadRequest), start, err)
		return
	}
	// SiteForHost above is the authoritative tenant/host check. Propagate that
	// provenance so request-aware semantic optimizations may safely compare
	// same-origin references without trusting an arbitrary Host header.
	reqCtx.HostValidated = true
	reqCtx.Metadata["detection_budget"] = site.WAF.SemanticPolicy.DetectionBudget
	reqCtx.Metadata["original_uri"] = publicRequest.URL.RequestURI()
	reqCtx.Metadata["upstream_uri"] = r.URL.RequestURI()
	reqCtx.Metadata["normalized_path"] = requestPath
	accessDecision := ip.AccessDecision{Action: "none"}
	ipAllowed := true
	for _, policyRequest := range policyRequests {
		decision := s.access.Evaluate(reqCtx.ClientIP, site.ID, policyRequest.URL.Path)
		if decision.Matched {
			accessDecision = decision
		}
		// Rewriting cannot remove a path block or let one path's allow rule
		// exempt protections belonging to the other request identity.
		if decision.Action != ip.AccessActionAllow {
			ipAllowed = false
		}
		if decision.Action == ip.AccessActionBlock {
			break
		}
	}
	if accessDecision.Matched {
		reqCtx.Metadata["ip_access_decision"] = accessDecision
	}
	if accessDecision.Action == ip.AccessActionBlock {
		message := "IP access rule blocked the request"
		if accessDecision.RuleName != "" {
			message = "IP access rule blocked the request: " + accessDecision.RuleName
		}
		s.block(w, reqCtx, "ip_access", message, http.StatusForbidden, start)
		return
	}
	fingerprint := clientFingerprint(r)
	if fingerprint != "" {
		if reqCtx.Metadata == nil {
			reqCtx.Metadata = map[string]any{}
		}
		reqCtx.Metadata["client_fingerprint"] = fingerprint
		if fingerprintDenied(site.WAF.SemanticPolicy.FingerprintDeny, fingerprint) {
			reqCtx.Metadata["ua_language_key_observation"] = "configured legacy denylist matched; auxiliary signal only"
		}
	}
	if s.geoip.Blocked(reqCtx.ClientIP) && !ipAllowed {
		s.block(w, reqCtx, "geoip", "GeoIP country is blocked", http.StatusForbidden, start)
		return
	}
	// Behavior verify runs after host/path/protocol/IP/geoip gates so blocked clients
	// cannot burn challenge capacity. Keep before global rate-limit so solvers can finish.
	if requestPath == botBehaviorVerifyPath || r.URL.Path == botBehaviorVerifyPath {
		if err := reqCtx.EnsureBody(); err != nil {
			if errors.Is(err, engine.ErrRequestBodyTooLarge) {
				http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, "failed to read request", requestBodyReadErrorStatus(err, http.StatusBadRequest))
			return
		}
		s.handleBotBehaviorVerify(w, r, site, reqCtx)
		return
	}
	if policy.ThreatIntel != config.ProtectionLevelOff && !ipAllowed {
		decision := s.intel.Evaluate(reqCtx.ClientIP, policy.ThreatIntel)
		if decision.Matched {
			reqCtx.Metadata["threat_intel_decision"] = decision
			switch decision.Action {
			case engine.ActionBlock.String():
				s.blockThreatIntel(w, reqCtx, decision, http.StatusForbidden, start)
				return
			case engine.ActionChallenge.String():
				s.challengeThreatIntel(w, publicPolicyRequest(), reqCtx, decision, start)
				return
			}
		}
	}
	for _, policyRequest := range policyRequests {
		if aclEnabled {
			if result := s.acl.Evaluate(policyRequest); result != nil && result.Detected {
				reqCtx.Metadata["detection"] = result
				switch result.Action {
				case engine.ActionBlock:
					s.blockDetection(w, reqCtx, result, http.StatusForbidden, start)
					return
				case engine.ActionChallenge:
					s.challenge(w, publicPolicyRequest(), reqCtx, result.Category, result.Message, start)
					return
				}
			}
		}
	}
	if botEnabled && policy.BotCC != config.ProtectionLevelOff {
		if result := s.bot.EvaluateForSiteWithWaitingRoomAndPaths(publicPolicyRequest(), reqCtx.ClientIP, site.ID, siteWaitingRoomEnabled(site, s.protectionConfig.Bot.WaitingRoom), r.URL.Path); result != nil && result.Detected && !ipAllowed {
			decision := evaluateBotCCPolicy(policy.BotCC, result)
			reqCtx.Metadata["bot_cc_policy_decision"] = decision
			reqCtx.Metadata["detection"] = result
			switch decision.Action {
			case engine.ActionChallenge.String():
				s.challenge(w, publicPolicyRequest(), reqCtx, result.Category, result.Message, start)
				return
			case engine.ActionBlock.String():
				s.blockDetection(w, reqCtx, result, http.StatusForbidden, start)
				return
			}
		}
	}
	if rateLimitEnabled && policy.BotCC != config.ProtectionLevelOff && !s.limiter.Allow(site.ID+"\x00"+reqCtx.ClientIP) && !ipAllowed {
		result := rateLimitDetection(reqCtx)
		decision := evaluateBotCCPolicy(policy.BotCC, result)
		reqCtx.Metadata["bot_cc_policy_decision"] = decision
		reqCtx.Metadata["detection"] = result
		switch decision.Action {
		case engine.ActionBlock.String():
			s.blockDetection(w, reqCtx, result, http.StatusTooManyRequests, start)
			return
		case engine.ActionChallenge.String():
			s.challenge(w, publicPolicyRequest(), reqCtx, result.Category, result.Message, start)
			return
		}
	}
	// Authentication and endpoint rate limiting are header/path-only checks. Run
	// them before any body admission or read so unauthenticated large uploads
	// cannot consume the bounded body-reader slots and byte budget.
	if apiSecurityEnabled && policy.APISecurity != config.ProtectionLevelOff {
		for _, policyRequest := range policyRequests {
			if finding := s.apiAuth.Evaluate(policyRequest); finding != nil && !ipAllowed {
				result := apiAuthDetection(*finding)
				decision := evaluateAPISecurityPolicy(policy.APISecurity, result)
				decision.Field = finding.Field
				reqCtx.Metadata["api_security_policy_decision"] = decision
				reqCtx.Metadata["api_security_auth_finding"] = finding
				reqCtx.Metadata["detection"] = result
				if decision.Action == engine.ActionBlock.String() {
					s.blockDetection(w, reqCtx, result, apiAuthStatus(*finding), start)
					return
				}
			}
		}
		if !s.apiLimit.AllowRequests(policyRequests, reqCtx.ClientIP) && !ipAllowed {
			result := apiRateLimitDetection(reqCtx)
			decision := evaluateAPISecurityPolicy(policy.APISecurity, result)
			reqCtx.Metadata["api_security_policy_decision"] = decision
			reqCtx.Metadata["detection"] = result
			if decision.Action == engine.ActionBlock.String() {
				s.blockDetection(w, reqCtx, result, http.StatusTooManyRequests, start)
				return
			}
		}
	}
	// Body needed for schema/WAF inspection; it is deliberately deferred until
	// after the cheap API auth/rate-limit gates above.
	if (apiSecurityEnabled && policy.APISecurity != config.ProtectionLevelOff) || (site.WAF.Enabled && site.WAF.Mode != "off" && policy.WebAttack != config.ProtectionLevelOff) {
		if err := reqCtx.EnsureBody(); err != nil {
			if errors.Is(err, engine.ErrRequestBodyTooLarge) {
				s.proxyError(w, r, site, reqCtx, "request_too_large", "request body exceeds site limit", http.StatusRequestEntityTooLarge, start, err)
				return
			}
			s.proxyError(w, r, site, reqCtx, "proxy_error", "failed to read request", requestBodyReadErrorStatus(err, http.StatusBadRequest), start, err)
			return
		}
	}
	if apiSecurityEnabled && policy.APISecurity != config.ProtectionLevelOff {
		for _, policyRequest := range policyRequests {
			if findings := s.apiSchema.ValidateWithBodySize(policyRequest, int64(len(reqCtx.DecodedBody))); len(findings) > 0 {
				result := apiValidationDetection(findings[0])
				decision := evaluateAPISecurityPolicy(policy.APISecurity, result)
				decision.SchemaID = findings[0].SchemaID
				decision.Field = findings[0].Field
				reqCtx.Metadata["api_security_policy_decision"] = decision
				reqCtx.Metadata["api_security_findings"] = findings
				reqCtx.Metadata["detection"] = result
				if decision.Action == engine.ActionBlock.String() {
					s.blockDetection(w, reqCtx, result, http.StatusBadRequest, start)
					return
				}
			}
		}
	}
	if redirect {
		// Same-origin relative redirect only; redirect the validated string, not a re-serialized URL.
		loc := fsguard.SanitizeLocalRedirect(r.URL.RequestURI())
		loc = strings.ReplaceAll(loc, "\\", "/")
		if isLocalURL(loc) {
			http.Redirect(w, r, loc, redirectCode)
		} else {
			http.Redirect(w, r, "/", redirectCode)
		}
		s.writeLog(r.Context(), reqCtx, "redirect", redirectCode, start, nil)
		return
	}
	pipeline := s.currentPipeline()
	if site.WAF.Enabled && site.WAF.Mode != "off" && policy.WebAttack != config.ProtectionLevelOff && pipeline != nil {
		// Commercial fail-mode: detection budget policy tracks web_attack unless overridden.
		if reqCtx.Metadata == nil {
			reqCtx.Metadata = map[string]any{}
		}
		budgetPolicy := config.ResolveBudgetExhaustedPolicy(
			site.WAF.SemanticPolicy.BudgetExhaustedPolicy,
			policy.WebAttack,
		)
		reqCtx.Metadata["budget_exhausted_policy"] = budgetPolicy

		result, err := s.detectRequestIdentities(r.Context(), pipeline, reqCtx, publicRequest, rewritten, policy, site)
		if err != nil {
			if requestBodyTooLarge(err) {
				s.proxyError(w, r, site, reqCtx, "request_too_large", "request body exceeds site limit", http.StatusRequestEntityTooLarge, start, err)
				return
			}
			status := requestBodyReadErrorStatus(err, http.StatusInternalServerError)
			message := "waf pipeline error"
			if status == http.StatusServiceUnavailable {
				message = "request body inspection temporarily unavailable"
			}
			s.proxyError(w, r, site, reqCtx, "proxy_error", message, status, start, err)
			return
		}
		if (result == nil || !result.Detected) && s.promotes.Active(site.ID, s.wallNow()) {
			if promoted := detectionFromReviewCandidate(reqCtx); promoted != nil {
				if reqCtx.Metadata == nil {
					reqCtx.Metadata = map[string]any{}
				}
				reqCtx.Metadata["detection"] = promoted
				s.blockDetection(w, reqCtx, promoted, http.StatusForbidden, start)
				return
			}
		}
		if result != nil && result.Detected {
			decision := evaluateWebAttackPolicyForSite(policy.WebAttack, result, reqCtx.Results, site, reqCtx)
			reqCtx.Metadata["waf_policy_decision"] = decision
			reqCtx.Metadata["detection"] = result
			switch decision.Action {
			case engine.ActionBlock.String():
				s.blockDetection(w, reqCtx, result, http.StatusForbidden, start)
				return
			case engine.ActionChallenge.String():
				s.challenge(w, publicPolicyRequest(), reqCtx, result.Category, result.Message, start)
				return
			case engine.ActionLog.String():
				// Explicit pass-through. Most of the time this is the intended
				// outcome: something was detected but scored below the policy
				// threshold. It is only a fail-open when the analysis never
				// completed, and a WAF that forwards un-analysed traffic is
				// indistinguishable from no WAF — so make that observable
				// instead of letting it fall out of the switch unnoticed.
				if exhausted, _ := reqCtx.Metadata["detection_budget_exhausted"].(bool); exhausted {
					engine.RecordBudgetExhaustedPass()
					log.Printf("waf: detection budget exhausted, forwarding un-analysed request site_id=%q trace_id=%q policy=%q", site.ID, reqCtx.TraceID, policy.WebAttack)
				} else if incomplete, _ := reqCtx.Metadata["detection_input_incomplete"].(bool); incomplete {
					// A closed/observe decision must never be silently reduced to a
					// normal policy log when input coverage was incomplete.
					log.Printf("waf: input analysis incomplete, forwarding according to explicit fail-mode site_id=%q trace_id=%q policy=%q", site.ID, reqCtx.TraceID, policy.WebAttack)
				}
			}
		}
	}
	// Unknown-length request bodies must be fully bounded before any upstream
	// attempt. Streaming a MaxBytesReader directly to the origin can otherwise
	// let the origin process a prefix before the proxy discovers the 413.
	if r.Body != nil && r.Body != http.NoBody && r.ContentLength < 0 {
		if err := preflightUnknownBody(r, maxRequestBody); err != nil {
			if errors.Is(err, engine.ErrRequestBodyTooLarge) {
				s.proxyError(w, r, site, reqCtx, "request_too_large", "request body exceeds site limit", http.StatusRequestEntityTooLarge, start, err)
				return
			}
			s.proxyError(w, r, site, reqCtx, "proxy_error", "failed to read request", requestBodyReadErrorStatus(err, http.StatusBadRequest), start, err)
			return
		}
	}
	if len(r.Trailer) > 0 || len(inboundRequest.Trailer) > 0 {
		http.Error(w, "request trailers are not supported", http.StatusBadRequest)
		return
	}
	edgeRT.headers.Apply(r)
	if cached, ok := edgeRT.cache.Get(r); ok && !rewritten {
		if siteRT.inspector.Enabled() {
			inspectionRequest := responseInspectionRequest(publicRequest, siteRT.trustedProxyCIDRs)
			finding, inspectErr := siteRT.inspector.InspectCaptured(inspectionRequest, cached.Header, cached.Body)
			if inspectErr != nil {
				s.proxyError(w, r, site, reqCtx, "proxy_error", "response inspection failed", http.StatusBadGateway, start, inspectErr)
				return
			}
			if finding != nil {
				cached.Header.Del("X-CheeseWAF-Response-Finding")
				result := recordResponseFinding(reqCtx, finding, site.WAF.Mode)
				if result != nil && result.Action == engine.ActionBlock {
					s.blockDetection(w, reqCtx, result, http.StatusForbidden, start)
					return
				}
			}
		}
		edgeRT.compress.Apply(r, &cached)
		edge.WriteCaptured(w, cached)
		s.writeLog(r.Context(), reqCtx, "cache_hit", cached.Status, start, nil)
		return
	}
	if IsWebSocketUpgrade(r) {
		target, err := s.lb.Next(site, reqCtx.ClientIP)
		if err != nil {
			s.proxyError(w, r, site, reqCtx, "proxy_error", "no upstream", http.StatusBadGateway, start, err)
			return
		}
		release := s.lb.Track(target)
		unlockRuntime()
		proxyErr := proxyWebSocket(r.Context(), w, r, target, site.WAF.Performance.MaxBodyBytes, reqCtx.ClientIP, site.OriginScheme, sitePassHost(site), site.HostHeader, func(fromClient bool, typ byte, payload []byte) error {
			return s.inspectWebSocketMessage(r, site, reqCtx, fromClient, typ, payload)
		}, func(resp *http.Response) error {
			return inspectUpstreamResponse(site, siteRT, publicRequest, reqCtx, resp)
		})
		lockRuntime()
		release()
		if proxyErr != nil {
			if s.blockTamperedResponse(w, reqCtx, proxyErr, start) {
				return
			}
			var ordinary *webSocketOrdinaryResponse
			if errors.As(proxyErr, &ordinary) {
				s.writeLog(r.Context(), reqCtx, "pass", ordinary.status, start, nil)
				return
			}
			if isUpstreamConnectError(proxyErr) {
				s.markUpstreamForSite(site.ID, target, false)
			}
			var handshakeErr *webSocketHandshakeError
			if errors.As(proxyErr, &handshakeErr) {
				s.proxyError(w, r, site, reqCtx, "proxy_error", "upstream WebSocket handshake failed", http.StatusBadGateway, start, proxyErr)
				return
			}
			s.writeLog(r.Context(), reqCtx, "proxy_error", http.StatusBadGateway, start, &storage.LogEntry{Category: "proxy_error", Severity: engine.SeverityHigh.String(), Message: proxyErr.Error()})
			return
		}
		s.markUpstreamForSite(site.ID, target, true)
		s.writeLog(r.Context(), reqCtx, "pass", http.StatusSwitchingProtocols, start, nil)
		return
	}
	retrySafe := retrySafeRequest(r)
	cacheCandidate := retrySafe && !rewritten && edgeRT.cache.CaptureCandidate(r)
	compressCandidate := retrySafe && edgeRT.compress.MayApplyRequest(r)
	if !cacheCandidate && !compressCandidate {
		skip := map[string]struct{}{}
		var lastErr error
		attempts := len(site.Upstreams)
		if attempts < 1 {
			attempts = 1
		}
		for i := 0; i < attempts; i++ {
			target, err := s.lb.nextExcluding(site, reqCtx.ClientIP, skip)
			if err != nil {
				if lastErr != nil {
					err = lastErr
				}
				s.proxyError(w, r, site, reqCtx, "proxy_error", "no upstream", http.StatusBadGateway, start, err)
				return
			}
			skip[upstreamKeyFromURL(target)] = struct{}{}
			rp := NewReverseProxyForSite(target, site.WAF.Performance.ProxyTimeout, reqCtx.ClientIP,
				site.OriginScheme, sitePassHost(site), site.HostHeader)
			var proxyErr error
			rp.ErrorHandler = func(_ http.ResponseWriter, _ *http.Request, err error) {
				proxyErr = err
			}
			rp.ModifyResponse = func(resp *http.Response) error {
				prepareUpstreamResponseTrailers(resp, grpcPassthroughRequest(publicRequest, site), reqCtx)
				if siteRT.inspector.Enabled() {
					return inspectUpstreamResponse(site, siteRT, publicRequest, reqCtx, resp)
				}
				return nil
			}
			recorder := &proxyStatusRecorder{ResponseWriter: w, status: http.StatusOK}
			release := s.lb.Track(target)
			unlockRuntime()
			rp.ServeHTTP(recorder, r)
			lockRuntime()
			release()
			if proxyErr == nil {
				s.markUpstreamForSite(site.ID, target, true)
				s.writeLog(r.Context(), reqCtx, "pass", recorder.status, start, nil)
				return
			}
			lastErr = proxyErr
			if isUpstreamConnectError(proxyErr) {
				s.markUpstreamForSite(site.ID, target, false)
			}
			if s.blockTamperedResponse(w, reqCtx, proxyErr, start) {
				return
			}
			if requestBodyTooLarge(proxyErr) {
				s.proxyError(w, r, site, reqCtx, "request_too_large", "request body exceeds site limit", http.StatusRequestEntityTooLarge, start, proxyErr)
				return
			}
			if recorder.wrote || !shouldRetryUpstream(proxyErr, retrySafe) {
				s.proxyError(w, r, site, reqCtx, "proxy_error", "upstream proxy error", http.StatusBadGateway, start, proxyErr)
				return
			}
		}
		s.proxyError(w, r, site, reqCtx, "proxy_error", "upstream proxy error", http.StatusBadGateway, start, lastErr)
		return
	}
	target, err := s.lb.Next(site, reqCtx.ClientIP)
	if err != nil {
		s.proxyError(w, r, site, reqCtx, "proxy_error", "no upstream", http.StatusBadGateway, start, err)
		return
	}
	captureLimit := edgeCaptureLimit(site, edgeRT.cache, cacheCandidate, compressCandidate)
	capture := edge.NewAdaptiveCaptureWriter(w, captureLimit)
	rp := NewReverseProxyForSite(target, site.WAF.Performance.ProxyTimeout, reqCtx.ClientIP,
		site.OriginScheme, sitePassHost(site), site.HostHeader)
	var proxyErr error
	rp.ErrorHandler = func(_ http.ResponseWriter, _ *http.Request, err error) {
		proxyErr = err
	}
	rp.ModifyResponse = func(resp *http.Response) error {
		prepareUpstreamResponseTrailers(resp, grpcPassthroughRequest(publicRequest, site), reqCtx)
		streaming := response.IsStreamingContentType(resp.Header.Get("Content-Type"))
		cacheResponseCandidate := cacheCandidate && edgeRT.cache.MayStoreResponse(resp)
		compressResponseCandidate := compressCandidate && edgeRT.compress.MayApplyResponse(r, resp)
		tamperTarget := siteRT.inspector.HasTamperSnapshot(responseInspectionRequest(publicRequest, siteRT.trustedProxyCIDRs))
		if streaming && !tamperTarget ||
			(captureLimit > 0 && resp.ContentLength > captureLimit && !tamperTarget) ||
			(!cacheResponseCandidate && !compressResponseCandidate && !tamperTarget) {
			capture.DisableBuffering()
		}
		if siteRT.inspector.Enabled() {
			if err := inspectUpstreamResponse(site, siteRT, publicRequest, reqCtx, resp); err != nil {
				return err
			}
			if tamperTarget && tamperFindingRecorded(reqCtx) {
				// Monitor mode must not retain an unbounded body after reporting
				// an unverifiable target (for example a stream or size overflow).
				capture.DisableBuffering()
			} else if tamperTarget && (streaming || captureLimit <= 0 ||
				(!cacheResponseCandidate && !compressResponseCandidate) ||
				(captureLimit > 0 && resp.ContentLength > captureLimit)) {
				// Verification has completed. Stream when no bounded edge stage
				// still needs the captured body.
				capture.DisableBuffering()
			}
		}
		return nil
	}
	release := s.lb.Track(target)
	unlockRuntime()
	rp.ServeHTTP(capture, r)
	capture.SyncPostCommitHeaders()
	lockRuntime()
	release()
	if capture.Committed() {
		if proxyErr != nil || capture.Err() != nil {
			err := proxyErr
			if err == nil {
				err = capture.Err()
			}
			if s.blockTamperedResponse(w, reqCtx, err, start) {
				return
			}
			if isUpstreamConnectError(err) {
				s.markUpstreamForSite(site.ID, target, false)
			}
			s.writeLog(r.Context(), reqCtx, "proxy_error", capture.Response().Status, start, &storage.LogEntry{
				Category: "proxy_error",
				Severity: engine.SeverityHigh.String(),
				Message:  err.Error(),
			})
			return
		}
		s.markUpstreamForSite(site.ID, target, true)
		s.writeLog(r.Context(), reqCtx, "pass", capture.Response().Status, start, nil)
		return
	}
	if proxyErr != nil {
		if s.blockTamperedResponse(w, reqCtx, proxyErr, start) {
			return
		}
		status := http.StatusBadGateway
		category, message := "proxy_error", "upstream proxy error"
		if requestBodyTooLarge(proxyErr) {
			status = http.StatusRequestEntityTooLarge
			category, message = "request_too_large", "request body exceeds site limit"
		}
		if isUpstreamConnectError(proxyErr) {
			s.markUpstreamForSite(site.ID, target, false)
		}
		s.proxyError(w, r, site, reqCtx, category, message, status, start, proxyErr)
		return
	}
	s.markUpstreamForSite(site.ID, target, true)
	captured := capture.Response()
	if cacheCandidate {
		edgeRT.cache.Store(r, captured)
		captured.Header.Set("X-CheeseWAF-Cache", "MISS")
	}
	edgeRT.compress.Apply(r, &captured)
	edge.WriteCaptured(w, captured)
	s.writeLog(r.Context(), reqCtx, "pass", captured.Status, start, nil)
}

const botBehaviorVerifyPath = "/.well-known/cheesewaf/challenge/v1/verify"

func (s *Server) handleBotBehaviorVerify(w http.ResponseWriter, r *http.Request, site config.SiteConfig, reqCtx *engine.RequestContext) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	clientIP := ""
	if reqCtx != nil {
		clientIP = reqCtx.ClientIP
	}
	if clientIP == "" {
		clientIP = engine.ClientIPWithTrustedProxyProviders(
			r,
			site.WAF.AccessControl.TrustedCIDRs,
			site.WAF.AccessControl.TrustedProxyProviders,
		)
	}
	// Body was size-capped and rewound by EnsureBody on the verify path.
	s.bot.VerifyBehaviorChallenge(w, r, clientIP, site.ID)
}

func inspectUpstreamResponse(site config.SiteConfig, siteRT *siteRuntime, request *http.Request, reqCtx *engine.RequestContext, resp *http.Response) error {
	inspectionRequest := responseInspectionRequest(request, siteRT.trustedProxyCIDRs)
	finding, err := siteRT.inspector.InspectHTTPForRequest(resp, inspectionRequest)
	if err != nil {
		return err
	}
	if finding == nil {
		return nil
	}
	resp.Header.Del("X-CheeseWAF-Response-Finding")
	result := recordResponseFinding(reqCtx, finding, site.WAF.Mode)
	if result != nil && result.Action == engine.ActionBlock {
		return errResponseTamperDetected
	}
	return nil
}

func responseInspectionRequest(request *http.Request, trustedCIDRs []string) *http.Request {
	if request == nil || request.URL == nil || request.URL.Scheme != "" {
		return request
	}
	clone := request.Clone(request.Context())
	clonedURL := *request.URL
	clonedURL.Scheme = "http"
	if requestIsHTTPS(request, trustedCIDRs) {
		clonedURL.Scheme = "https"
	}
	clone.URL = &clonedURL
	return clone
}

func recordResponseFinding(reqCtx *engine.RequestContext, finding *response.Finding, wafMode string) *engine.DetectionResult {
	if reqCtx == nil || finding == nil {
		return nil
	}
	if reqCtx.Metadata == nil {
		reqCtx.Metadata = map[string]any{}
	}
	reqCtx.Metadata["response_finding"] = finding

	action := engine.ActionLog
	// An inspection gap is not evidence that the body contains sensitive data,
	// but it is not evidence of absence either. response.inspection.fail_mode
	// now owns that decision: closed carries a block action, observe and open
	// stay log-only. A monitor/log site never blocks, whatever the policy says.
	switch {
	case !strings.EqualFold(strings.TrimSpace(wafMode), "block"):
		action = engine.ActionLog
	case finding.Action == engine.ActionBlock.String():
		action = engine.ActionBlock
	case finding.Incomplete:
		// open/observe coverage gap: recorded below, never blocked.
		action = engine.ActionLog
	default:
		action = engine.ActionBlock
	}
	result := &engine.DetectionResult{
		Detected: true, DetectorID: finding.DetectorID, Category: finding.Category,
		Severity: parseSeverity(finding.Severity), Action: action,
		Message: finding.Message, Confidence: 0.99, Payload: finding.Pattern,
	}
	reqCtx.Results = append(reqCtx.Results, *result)
	reqCtx.Metadata["detection"] = result
	return result
}

func tamperFindingRecorded(reqCtx *engine.RequestContext) bool {
	if reqCtx == nil || reqCtx.Metadata == nil {
		return false
	}
	finding, _ := reqCtx.Metadata["response_finding"].(*response.Finding)
	return finding != nil && finding.Category == "tamper"
}

func (s *Server) blockTamperedResponse(w http.ResponseWriter, reqCtx *engine.RequestContext, err error, start time.Time) bool {
	if !errors.Is(err, errResponseTamperDetected) || reqCtx == nil || reqCtx.Metadata == nil {
		return false
	}
	result, _ := reqCtx.Metadata["detection"].(*engine.DetectionResult)
	if result == nil {
		return false
	}
	s.blockDetection(w, reqCtx, result, http.StatusForbidden, start)
	return true
}

// isLocalURL reports whether raw is a same-origin relative URL safe for redirects.
func isLocalURL(raw string) bool {
	return fsguard.IsLocalURL(raw)
}

func requestBodyTooLarge(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, engine.ErrRequestBodyTooLarge) {
		return true
	}
	var maxErr *http.MaxBytesError
	return errors.As(err, &maxErr)
}

// requestBodyReadErrorStatus keeps malformed or failed client uploads as 400,
// while exposing bounded reader-pool exhaustion as a transient server-side
// capacity error. The latter is not caused by request syntax and is retryable.
func requestBodyReadErrorStatus(err error, fallback int) int {
	if errors.Is(err, engine.ErrRequestBodyReadOverload) {
		return http.StatusServiceUnavailable
	}
	if errors.Is(err, engine.ErrUnsupportedContentEncoding) {
		return http.StatusUnsupportedMediaType
	}
	return fallback
}

func requestIsHTTPS(r *http.Request, trustedCIDRs []string) bool {
	if r == nil {
		return false
	}
	if r.TLS != nil {
		return true
	}
	if !remoteIPInCIDRs(r.RemoteAddr, trustedCIDRs) {
		return false
	}
	proto := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0])
	return strings.EqualFold(proto, "https")
}

func trustedProxyCIDRs(access config.SiteAccessControlConfig) []string {
	policy, err := engine.NewTrustedProxyPolicy(access.TrustedCIDRs, access.TrustedProxyProviders)
	if err != nil {
		return nil
	}
	return policy.AllTrustedCIDRs()
}

func sitePassHost(site config.SiteConfig) bool {
	if site.PassHost == nil {
		return true
	}
	return *site.PassHost
}

func siteFeatureEnabled(value *bool, global bool) bool {
	if value == nil {
		return global
	}
	return *value
}

func siteWaitingRoomEnabled(site config.SiteConfig, global bool) bool {
	// The site switch is an opt-in extension of the global bot policy. Legacy
	// configs with a global waiting room keep their behavior, while a site can
	// explicitly enable it without changing every tenant.
	return global || site.WAF.AccessControl.WaitingRoom
}

func remoteIPInCIDRs(remoteAddr string, cidrs []string) bool {
	host, _, err := net.SplitHostPort(strings.TrimSpace(remoteAddr))
	if err != nil {
		host = strings.TrimSpace(remoteAddr)
	}
	addr := net.ParseIP(host)
	if addr == nil {
		return false
	}
	for _, raw := range cidrs {
		if candidate := net.ParseIP(strings.TrimSpace(raw)); candidate != nil && candidate.Equal(addr) {
			return true
		}
		_, network, err := net.ParseCIDR(strings.TrimSpace(raw))
		if err == nil && network.Contains(addr) {
			return true
		}
	}
	return false
}

func edgeCaptureLimit(site config.SiteConfig, cache *edge.Cache, cacheCandidate bool, compressCandidate bool) int64 {
	var limit int64
	if cacheCandidate {
		limit = cache.MaxBodyBytes()
	}
	if compressCandidate {
		compressLimit := site.WAF.Performance.MaxBodyBytes
		if compressLimit <= 0 {
			compressLimit = 8 << 20
		}
		if limit == 0 || compressLimit > limit {
			limit = compressLimit
		}
	}
	return limit
}

func retrySafeRequest(r *http.Request) bool {
	if r == nil {
		return false
	}
	// A GET/HEAD with an unknown or non-empty body is not replay-safe: the
	// first attempt may consume it or the origin may assign body semantics.
	// Only an explicitly empty request can be retried across upstreams.
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	if r.ContentLength != 0 {
		return false
	}
	// ContentLength == 0 alone is not evidence of an empty entity: callers may
	// attach an unknown/custom body and leave the default length unchanged.
	return r.Body == nil || r.Body == http.NoBody
}

// preflightUnknownBody buffers only requests whose wire length is unknown so
// an oversized body is rejected before the first upstream read. It preserves
// the original transfer-encoded bytes; decoding belongs to the WAF path.
func preflightUnknownBody(r *http.Request, maxBodyBytes int64) error {
	if r == nil {
		return nil
	}
	return preflightUnknownBodyContext(r.Context(), r, maxBodyBytes)
}

func preflightUnknownBodyContext(ctx context.Context, r *http.Request, maxBodyBytes int64) error {
	if r == nil || r.Body == nil || r.Body == http.NoBody || r.ContentLength >= 0 {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if maxBodyBytes <= 0 {
		maxBodyBytes = 8 << 20
	}
	originalBody := r.Body
	if maxBodyBytes == math.MaxInt64 {
		return errors.New("request body limit is too large")
	}
	select {
	case preflightBodySlots <- struct{}{}:
	default:
		_ = originalBody.Close()
		return engine.ErrRequestBodyReadOverload
	}
	readCtx, cancel := context.WithTimeout(ctx, preflightUnknownBodyTimeout)
	defer cancel()
	closeOnce := &sync.Once{}
	type bodyReadResult struct {
		raw []byte
		err error
	}
	resultCh := make(chan bodyReadResult, 1)
	go func() {
		defer func() { <-preflightBodySlots }()
		defer closeOnce.Do(func() { _ = originalBody.Close() })
		var raw []byte
		var err error
		func() {
			defer func() {
				if recovered := recover(); recovered != nil {
					err = fmt.Errorf("request body reader panic: %v", recovered)
				}
			}()
			raw, err = io.ReadAll(io.LimitReader(originalBody, maxBodyBytes+1))
		}()
		resultCh <- bodyReadResult{raw: raw, err: err}
	}()
	var result bodyReadResult
	select {
	case result = <-resultCh:
	case <-readCtx.Done():
		closeOnce.Do(func() { _ = originalBody.Close() })
		return readCtx.Err()
	}
	if result.err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(result.err, &maxErr) {
			return engine.ErrRequestBodyTooLarge
		}
		return result.err
	}
	if int64(len(result.raw)) > maxBodyBytes {
		return engine.ErrRequestBodyTooLarge
	}
	raw := append([]byte(nil), result.raw...)
	if len(raw) == 0 {
		r.Body = http.NoBody
	} else {
		r.Body = io.NopCloser(bytes.NewReader(raw))
	}
	r.ContentLength = int64(len(raw))
	r.GetBody = func() (io.ReadCloser, error) {
		if len(raw) == 0 {
			return http.NoBody, nil
		}
		return io.NopCloser(bytes.NewReader(raw)), nil
	}
	return nil
}

type proxyStatusRecorder struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (r *proxyStatusRecorder) WriteHeader(status int) {
	r.wrote = true
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *proxyStatusRecorder) Write(b []byte) (int, error) {
	r.wrote = true
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.ResponseWriter.Write(b)
}

func (r *proxyStatusRecorder) Flush() {
	if flusher, ok := r.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (r *proxyStatusRecorder) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}

func (s *Server) proxyError(w http.ResponseWriter, r *http.Request, site config.SiteConfig, reqCtx *engine.RequestContext, category, message string, status int, start time.Time, cause error) {
	if start.IsZero() {
		start = time.Now()
	}
	if category == "" {
		category = "proxy_error"
	}
	if reqCtx == nil {
		reqCtx = &engine.RequestContext{
			Request:  r,
			ClientIP: engine.ClientIPWithTrustedProxyProviders(r, site.WAF.AccessControl.TrustedCIDRs, site.WAF.AccessControl.TrustedProxyProviders),
			TraceID:  blockpage.NewTraceID(),
			SiteID:   site.ID,
			Metadata: map[string]any{},
		}
	}
	if reqCtx.Request == nil {
		reqCtx.Request = r
	}
	if reqCtx.TraceID == "" {
		reqCtx.TraceID = blockpage.NewTraceID()
	}
	if reqCtx.SiteID == "" {
		reqCtx.SiteID = site.ID
	}
	if reqCtx.ClientIP == "" && r != nil {
		reqCtx.ClientIP = engine.ClientIPWithTrustedProxyProviders(r, site.WAF.AccessControl.TrustedCIDRs, site.WAF.AccessControl.TrustedProxyProviders)
	}
	if reqCtx.Metadata == nil {
		reqCtx.Metadata = map[string]any{}
	}
	reqCtx.Metadata["proxy_error"] = message
	if cause != nil {
		reqCtx.Metadata["proxy_error_detail"] = cause.Error()
	}
	s.renderer.RenderRequest(w, r, status, s.blockPageData(reqCtx, category, message))
	s.writeLog(r.Context(), reqCtx, "error", status, start, &storage.LogEntry{
		Category:   category,
		Severity:   "medium",
		DetectorID: "proxy.error",
		Message:    message,
	})
}

func (s *Server) blockDetection(w http.ResponseWriter, reqCtx *engine.RequestContext, result *engine.DetectionResult, status int, start time.Time) {
	if result == nil {
		s.block(w, reqCtx, "unknown", "request blocked", status, start)
		return
	}
	reqCtx.Metadata["detection"] = result
	s.renderer.RenderRequest(w, reqCtx.Request, status, s.blockPageData(reqCtx, result.Category, result.Message))
	s.writeLog(reqCtx.Request.Context(), reqCtx, "block", status, start, &storage.LogEntry{
		Category:   result.Category,
		Severity:   result.Severity.String(),
		DetectorID: result.DetectorID,
		Message:    result.Message,
		Payload:    result.Payload,
		Metadata: map[string]any{
			"confidence":         result.Confidence,
			"detector_id":        result.DetectorID,
			"detection_category": result.Category,
		},
	})
}

func (s *Server) inspectWebSocketMessage(r *http.Request, site config.SiteConfig, parent *engine.RequestContext, fromClient bool, typ byte, payload []byte) error {
	pipeline := s.currentPipeline()
	if pipeline == nil {
		return nil
	}
	message := r.Clone(r.Context())
	message.Body = io.NopCloser(bytes.NewReader(payload))
	message.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(payload)), nil }
	message.ContentLength = int64(len(payload))
	if typ == 1 {
		message.Header.Set("Content-Type", "text/plain")
	} else {
		message.Header.Set("Content-Type", "application/octet-stream")
	}
	ctx, err := engine.NewRequestContextDeferredBodyWithTrustedProxyPolicy(message, parent.SiteID, nil, site.WAF.Performance.MaxBodyBytes)
	if err != nil {
		return err
	}
	ctx.ClientIP = parent.ClientIP
	ctx.Metadata["websocket_direction"] = map[bool]string{true: "client_to_upstream", false: "upstream_to_client"}[fromClient]
	ctx.Metadata["websocket_message_type"] = typ
	result, err := pipeline.Detect(message.Context(), ctx)
	if err != nil {
		return err
	}
	if result == nil || !result.Detected || !strings.EqualFold(site.WAF.Mode, "block") {
		return nil
	}
	s.runtimeMu.RLock()
	globalPolicy := s.protectionPolicy
	s.runtimeMu.RUnlock()
	policy := config.EffectiveProtectionPolicy(globalPolicy, site.WAF.ProtectionPolicy)
	decision := evaluateWebAttackPolicyForSite(policy.WebAttack, result, ctx.Results, site, ctx)
	if decision.Action == engine.ActionBlock.String() || decision.Action == engine.ActionChallenge.String() {
		return fmt.Errorf("WebSocket message rejected: %s", result.Message)
	}
	return nil
}

func (s *Server) blockThreatIntel(w http.ResponseWriter, reqCtx *engine.RequestContext, decision ip.ThreatDecision, status int, start time.Time) {
	s.renderer.RenderRequest(w, reqCtx.Request, status, s.blockPageData(reqCtx, "threat_intel", decision.Message))
	s.writeLog(reqCtx.Request.Context(), reqCtx, "block", status, start, &storage.LogEntry{
		Category:   "threat_intel",
		Severity:   decision.Severity,
		DetectorID: decision.DetectorID,
		Message:    decision.Message,
		Payload:    reqCtx.ClientIP,
	})
}

type webAttackPolicyDecision struct {
	Level  string `json:"level"`
	Action string `json:"action"`
	Reason string `json:"reason"`
	// ParanoiaLevel is the site's configured engine sensitivity
	// (waf.paranoia_level, 0-5). PolicyTier is the separate 0-4 ordinal derived
	// from the web_attack policy string. The two used to share the
	// paranoia_level name, so logs and the console reported a strategy ordinal
	// while operators read it as the site's configured sensitivity level.
	ParanoiaLevel     int     `json:"paranoia_level"`
	PolicyTier        int     `json:"policy_tier"`
	MinimumSeverity   string  `json:"minimum_severity"`
	MinimumConfidence float64 `json:"minimum_confidence"`
	MinimumRiskScore  int     `json:"minimum_risk_score"`
	RiskScore         int     `json:"risk_score"`
	EvidenceCount     int     `json:"evidence_count"`
	ResultSeverity    string  `json:"result_severity"`
	ResultConfidence  float64 `json:"result_confidence"`
	DetectorAction    string  `json:"detector_action"`
	DetectorCategory  string  `json:"detector_category"`
	DetectorID        string  `json:"detector_id"`
	// BlockThreshold/ChallengeThreshold/LogThreshold are the resolved ladder
	// after waf.semantic_policy.action_thresholds and any matching
	// route_overrides were applied. Zero ChallengeThreshold/LogThreshold means
	// "no such tier", i.e. everything below BlockThreshold is logged.
	BlockThreshold     float64 `json:"block_threshold"`
	ChallengeThreshold float64 `json:"challenge_threshold"`
	LogThreshold       float64 `json:"log_threshold"`
	// ActionOverride is the pinned action of the matched route override
	// ("observe"/"challenge"), RouteOverride its path pattern.
	ActionOverride string `json:"action_override,omitempty"`
	RouteOverride  string `json:"route_override,omitempty"`
}

// webAttackLadder is the resolved block/challenge/log confidence ladder for one
// request. A zero Challenge or Log rung means the tier is not configured.
type webAttackLadder struct {
	Block     float64
	Challenge float64
	Log       float64
	// blockSet/challengeSet/logSet record which rungs a scope configured.
	// Without a challenge rung, raising block alone must not open a challenge
	// band that the preset never had.
	blockSet     bool
	challengeSet bool
	logSet       bool
	// Explicit records that an operator configured any rung or pinned an
	// action for this site or route. An explicit ladder is authoritative: the
	// aggregate risk-score escalation that exists for the bare preset must not
	// silently overrule "below log means log".
	Explicit bool
	// Action pins the outcome ("" | observe | challenge).
	Action string
	// RoutePath is the matched override pattern, for diagnostics.
	RoutePath string
}

func evaluateWebAttackPolicy(level string, result *engine.DetectionResult) webAttackPolicyDecision {
	return evaluateWebAttackPolicyWithEvidence(level, result, nil, config.DefaultParanoiaLevel)
}

func evaluateWebAttackPolicyWithEvidence(
	level string,
	result *engine.DetectionResult,
	results []engine.DetectionResult,
	siteParanoiaLevel int,
) webAttackPolicyDecision {
	return evaluateWebAttackPolicyWithLadder(level, result, results, siteParanoiaLevel, webAttackLadder{})
}

// evaluateWebAttackPolicyForSite is the production entry point. It resolves the
// site's waf.semantic_policy action thresholds and the first matching route
// override for this request, then maps the detection onto block/challenge/log.
//
// Only the action a hit is mapped to changes. Detection (severity, confidence,
// detector categories) is untouched, so paranoia_level keeps meaning "how much
// is detected" while this policy decides "how hard to answer".
func evaluateWebAttackPolicyForSite(
	level string,
	result *engine.DetectionResult,
	results []engine.DetectionResult,
	site config.SiteConfig,
	reqCtx *engine.RequestContext,
) webAttackPolicyDecision {
	return evaluateWebAttackPolicyWithLadder(
		level,
		result,
		results,
		site.WAF.ParanoiaLevel,
		resolveWebAttackLadder(level, site.WAF.SemanticPolicy, reqCtx),
	)
}

// resolveWebAttackLadder derives the effective confidence ladder. The base rung
// comes from the web_attack preset; action_thresholds refine it for the site and
// the first matching route override refines it again for one path/parameter.
func resolveWebAttackLadder(level string, policy config.SemanticPolicyConfig, reqCtx *engine.RequestContext) webAttackLadder {
	_, base := webAttackThreshold(level)
	ladder := webAttackLadder{Block: base, Challenge: base}
	if thresholds := policy.ActionThresholds; !thresholds.IsZero() {
		ladder = ladder.withThresholds(thresholds.Block, thresholds.Challenge, thresholds.Log)
	}
	if override, ok := matchSemanticRouteOverride(policy.RouteOverrides, reqCtx); ok {
		ladder.RoutePath = strings.TrimSpace(override.Path)
		ladder.Action = config.NormalizeSemanticAction(override.Action)
		ladder = ladder.withThresholds(override.Block, override.Challenge, override.Log)
	}
	// Reconcile with the preset so a single relaxed rung cannot leave the ladder
	// inverted (e.g. block below an inherited challenge rung).
	if ladder.Challenge > ladder.Block {
		ladder.Challenge = ladder.Block
	}
	if ladder.Log > ladder.Challenge {
		ladder.Log = ladder.Challenge
	}
	ladder.Explicit = ladder.blockSet || ladder.challengeSet || ladder.logSet || ladder.Action != ""
	return ladder
}

// withThresholds applies the non-zero rungs of one scope. A zero rung inherits
// the value from the broader scope (web_attack preset, then action_thresholds),
// so a route override can relax a single rung without restating the others.
func (l webAttackLadder) withThresholds(block, challenge, log float64) webAttackLadder {
	if block > 0 {
		l.Block = block
		l.blockSet = true
		if !l.challengeSet {
			l.Challenge = block
		}
	}
	if challenge > 0 {
		l.Challenge = challenge
		l.challengeSet = true
	}
	if log > 0 {
		l.Log = log
		l.logSet = true
	}
	return l
}

// maxCachedSemanticRoutePatterns bounds the compiled route-override cache; a
// config reload may introduce new patterns, so the cache must not grow forever.
const maxCachedSemanticRoutePatterns = 512

// semanticRoutePatternCache memoises compiled route-override patterns. The
// policy runs per detected request, so recompiling a regexp there would put a
// parser allocation on the hot path.
var (
	semanticRoutePatternCache sync.Map
	semanticRoutePatternCount atomic.Int64
)

func compileSemanticRoutePattern(pattern string) (*regexp.Regexp, bool) {
	if cached, ok := semanticRoutePatternCache.Load(pattern); ok {
		compiled, _ := cached.(*regexp.Regexp)
		return compiled, compiled != nil
	}
	compiled, err := regexp.Compile(pattern)
	if err != nil {
		return nil, false
	}
	if semanticRoutePatternCount.Load() < maxCachedSemanticRoutePatterns {
		if _, loaded := semanticRoutePatternCache.LoadOrStore(pattern, compiled); !loaded {
			semanticRoutePatternCount.Add(1)
		}
	}
	return compiled, true
}

// matchSemanticRouteOverride returns the first override whose path pattern and
// (optional) parameter list match this request.
func matchSemanticRouteOverride(overrides []config.SemanticRouteOverride, reqCtx *engine.RequestContext) (config.SemanticRouteOverride, bool) {
	if len(overrides) == 0 || reqCtx == nil {
		return config.SemanticRouteOverride{}, false
	}
	path := semanticRequestPath(reqCtx)
	if path == "" {
		return config.SemanticRouteOverride{}, false
	}
	param := semanticReviewParamName(reqCtx)
	for _, override := range overrides {
		pattern := strings.TrimSpace(override.Path)
		if pattern == "" {
			continue
		}
		compiled, ok := compileSemanticRoutePattern(pattern)
		if !ok || !compiled.MatchString(path) {
			continue
		}
		if !semanticOverrideMatchesParam(override.Params, param) {
			continue
		}
		return override, true
	}
	return config.SemanticRouteOverride{}, false
}

// semanticRequestPath prefers the canonical path the rest of the WAF policies
// use, and falls back to the raw URL path for contexts built without one.
func semanticRequestPath(reqCtx *engine.RequestContext) string {
	if path := strings.TrimSpace(reqCtx.NormalizedPath); path != "" {
		return path
	}
	if reqCtx.Request != nil && reqCtx.Request.URL != nil {
		return reqCtx.Request.URL.Path
	}
	return ""
}

// semanticReviewParamName reads the parameter that produced the analyzer's
// review candidate. A params-filtered override only applies when the offending
// parameter is known: guessing would silently widen a narrowly scoped rule.
func semanticReviewParamName(reqCtx *engine.RequestContext) string {
	candidate, ok := reqCtx.Metadata["review_candidate"].(map[string]any)
	if !ok || candidate == nil {
		return ""
	}
	name, _ := candidate["name"].(string)
	return strings.TrimSpace(name)
}

func semanticOverrideMatchesParam(params []string, param string) bool {
	if len(params) == 0 {
		return true
	}
	if param == "" {
		return false
	}
	for _, candidate := range params {
		if strings.TrimSpace(candidate) == param {
			return true
		}
	}
	return false
}

func evaluateWebAttackPolicyWithLadder(
	level string,
	result *engine.DetectionResult,
	results []engine.DetectionResult,
	siteParanoiaLevel int,
	ladder webAttackLadder,
) webAttackPolicyDecision {
	if level == "" {
		level = config.ProtectionLevelSmart
	}
	minSeverity, minConfidence := webAttackThreshold(level)
	if ladder.Block <= 0 {
		// Preset behaviour: block at the preset confidence, no extra tiers.
		ladder = webAttackLadder{Block: minConfidence, Challenge: minConfidence}
	}
	riskThreshold := webAttackRiskThreshold(level)
	decision := webAttackPolicyDecision{
		Level:              level,
		Action:             engine.ActionLog.String(),
		Reason:             "detected below policy threshold",
		ParanoiaLevel:      config.EffectiveParanoiaLevel(siteParanoiaLevel),
		PolicyTier:         webAttackParanoiaLevel(level),
		MinimumSeverity:    minSeverity.String(),
		MinimumConfidence:  ladder.Block,
		MinimumRiskScore:   riskThreshold,
		DetectorAction:     engine.ActionPass.String(),
		BlockThreshold:     ladder.Block,
		ChallengeThreshold: ladder.Challenge,
		LogThreshold:       ladder.Log,
		ActionOverride:     ladder.Action,
		RouteOverride:      ladder.RoutePath,
	}
	if result == nil {
		decision.Reason = "no detection result"
		return decision
	}
	decision.ResultSeverity = result.Severity.String()
	decision.ResultConfidence = result.Confidence
	decision.DetectorAction = result.Action.String()
	decision.DetectorCategory = result.Category
	decision.DetectorID = result.DetectorID
	// Operational fail-mode from pipeline budget policy is not a "weak signal".
	// Honor detector action without severity/confidence gates (open/observe/closed).
	if result.Category == "detection_budget" || result.Category == "detection_incomplete" {
		incompleteKind := "detection budget exhausted"
		if result.Category == "detection_incomplete" {
			incompleteKind = "request analysis incomplete"
		}
		switch result.Action {
		case engine.ActionChallenge:
			decision.Action = engine.ActionChallenge.String()
			decision.Reason = incompleteKind + " policy (closed)"
		case engine.ActionBlock:
			decision.Action = engine.ActionBlock.String()
			decision.Reason = incompleteKind + " policy (closed-block)"
		case engine.ActionLog:
			decision.Action = engine.ActionLog.String()
			decision.Reason = incompleteKind + " policy (observe)"
		default:
			decision.Action = engine.ActionLog.String()
			decision.Reason = incompleteKind + " policy (open/pass)"
		}
		return decision
	}
	// Deterministic user-defined custom rules represent explicit administrative intent,
	// not probabilistic weak signals. Honor detector action without severity/confidence gates.
	if result.Category == "custom_rule" {
		switch result.Action {
		case engine.ActionChallenge:
			decision.Action = engine.ActionChallenge.String()
			decision.Reason = "custom rule matched with challenge action"
		case engine.ActionBlock:
			decision.Action = engine.ActionBlock.String()
			decision.Reason = "custom rule matched with block action"
		case engine.ActionLog:
			decision.Action = engine.ActionLog.String()
			decision.Reason = "custom rule matched with log action"
		default:
			decision.Action = engine.ActionPass.String()
			decision.Reason = "custom rule matched with pass action"
		}
		return decision
	}
	evidence := aggregateWebAttackEvidence(result, results)
	decision.RiskScore = evidence.Score
	decision.EvidenceCount = evidence.Count
	if result.Action == engine.ActionPass || result.Action == engine.ActionLog {
		decision.Reason = "detector requested " + result.Action.String()
		return decision
	}
	if level == config.ProtectionLevelOff {
		decision.Reason = "web attack protection disabled"
		return decision
	}
	// A route override may pin the outcome: observe keeps the hit in the log,
	// challenge answers with a challenge page (still gated on the preset
	// minimum severity, so an override cannot promote a weak signal). Neither
	// may fall through to a block: "challenge this route" means the operator
	// does not want a hard block there.
	switch ladder.Action {
	case config.SemanticActionObserve:
		decision.Action = engine.ActionLog.String()
		decision.Reason = "route override forces log"
		return decision
	case config.SemanticActionChallenge:
		if result.Severity >= minSeverity {
			decision.Action = engine.ActionChallenge.String()
			decision.Reason = "route override forces challenge"
		} else {
			decision.Reason = "route override forces challenge but severity is below policy minimum"
		}
		return decision
	}
	if result.Severity >= minSeverity && result.Confidence >= ladder.Block {
		if result.Action == engine.ActionChallenge {
			decision.Action = engine.ActionChallenge.String()
		} else {
			decision.Action = engine.ActionBlock.String()
		}
		decision.Reason = "severity and confidence meet policy threshold"
		return decision
	}
	// The challenge tier only exists when it sits strictly below the block rung;
	// otherwise any hit at the block confidence would fall through to it.
	// Per the design, the severity floor gates blocking and a pinned
	// action=challenge; the configured challenge rung is confidence-only.
	if ladder.Challenge > 0 && ladder.Challenge < ladder.Block && result.Confidence >= ladder.Challenge {
		decision.Action = engine.ActionChallenge.String()
		decision.Reason = "confidence meets challenge threshold"
		return decision
	}
	if ladder.Log > 0 && result.Confidence >= ladder.Log {
		decision.Action = engine.ActionLog.String()
		decision.Reason = "confidence meets log threshold"
		return decision
	}
	// Aggregate risk exists to promote a weak single signal. An operator who
	// configured an explicit ladder for this site/route has already stated how
	// hard such hits should be answered, so the escalation must not overrule it.
	if !ladder.Explicit && evidence.Score >= riskThreshold {
		if evidence.Action == engine.ActionChallenge {
			decision.Action = engine.ActionChallenge.String()
		} else {
			decision.Action = engine.ActionBlock.String()
		}
		decision.Reason = "aggregate risk score meets policy threshold"
		return decision
	}
	return decision
}

func webAttackThreshold(level string) (engine.Severity, float64) {
	switch level {
	case config.ProtectionLevelLow:
		return engine.SeverityCritical, 0.90
	case config.ProtectionLevelHigh:
		return engine.SeverityMedium, 0.78
	case config.ProtectionLevelStrict:
		return engine.SeverityLow, 0.65
	default:
		return engine.SeverityHigh, 0.85
	}
}

func webAttackRiskThreshold(level string) int {
	switch level {
	case config.ProtectionLevelLow:
		return 90
	case config.ProtectionLevelHigh:
		return 48
	case config.ProtectionLevelStrict:
		return 23
	default:
		return 73
	}
}

func webAttackParanoiaLevel(level string) int {
	switch level {
	case config.ProtectionLevelOff:
		return 0
	case config.ProtectionLevelLow:
		return 1
	case config.ProtectionLevelHigh:
		return 3
	case config.ProtectionLevelStrict:
		return 4
	default:
		return 2
	}
}

type webAttackEvidence struct {
	Score  int
	Count  int
	Action engine.Action
}

func aggregateWebAttackEvidence(primary *engine.DetectionResult, results []engine.DetectionResult) webAttackEvidence {
	evidence := webAttackEvidence{Action: engine.ActionLog}
	seen := map[string]struct{}{}
	categories := map[string]struct{}{}
	add := func(result engine.DetectionResult) {
		if !result.Detected || result.Action == engine.ActionPass || result.Action == engine.ActionLog {
			return
		}
		key := webAttackEvidenceKey(result)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		categories[result.Category] = struct{}{}
		score := webAttackResultScore(result)
		if score > evidence.Score {
			evidence.Score = score
			evidence.Action = result.Action
		}
		evidence.Count++
	}
	if primary != nil {
		add(*primary)
	}
	for _, result := range results {
		add(result)
	}
	if evidence.Count > 1 {
		evidence.Score += minInt((evidence.Count-1)*5, 15)
	}
	if len(categories) > 1 {
		evidence.Score += minInt((len(categories)-1)*8, 16)
	}
	if evidence.Score > 100 {
		evidence.Score = 100
	}
	return evidence
}

func webAttackEvidenceKey(result engine.DetectionResult) string {
	category := strings.ToLower(strings.TrimSpace(result.Category))
	payload := strings.TrimSpace(result.Payload)
	if payload != "" {
		return category + "\x00" + payload
	}
	return strings.TrimSpace(result.DetectorID) + "\x00" + category + "\x00" + strings.TrimSpace(result.Message)
}

func webAttackResultScore(result engine.DetectionResult) int {
	confidence := result.Confidence
	if confidence > 1 {
		confidence = confidence / 100
	}
	if confidence < 0 {
		confidence = 0
	}
	if confidence > 1 {
		confidence = 1
	}
	return int(math.Round(float64(webAttackSeverityScore(result.Severity)) * confidence))
}

func webAttackSeverityScore(severity engine.Severity) int {
	switch severity {
	case engine.SeverityCritical:
		return 100
	case engine.SeverityHigh:
		return 86
	case engine.SeverityMedium:
		return 62
	case engine.SeverityLow:
		return 35
	default:
		return 10
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

type botCCPolicyDecision struct {
	Level             string  `json:"level"`
	Action            string  `json:"action"`
	Reason            string  `json:"reason"`
	MinimumSeverity   string  `json:"minimum_severity"`
	MinimumConfidence float64 `json:"minimum_confidence"`
	ResultSeverity    string  `json:"result_severity"`
	ResultConfidence  float64 `json:"result_confidence"`
	DetectorAction    string  `json:"detector_action"`
	DetectorCategory  string  `json:"detector_category"`
	DetectorID        string  `json:"detector_id"`
}

func evaluateBotCCPolicy(level string, result *engine.DetectionResult) botCCPolicyDecision {
	if level == "" {
		level = config.ProtectionLevelSmart
	}
	minSeverity, minConfidence := botCCThreshold(level)
	decision := botCCPolicyDecision{
		Level:             level,
		Action:            engine.ActionLog.String(),
		Reason:            "detected below bot policy threshold",
		MinimumSeverity:   minSeverity.String(),
		MinimumConfidence: minConfidence,
		DetectorAction:    engine.ActionPass.String(),
	}
	if result == nil {
		decision.Reason = "no detection result"
		return decision
	}
	decision.ResultSeverity = result.Severity.String()
	decision.ResultConfidence = result.Confidence
	decision.DetectorAction = result.Action.String()
	decision.DetectorCategory = result.Category
	decision.DetectorID = result.DetectorID
	if result.DetectorID == "bot.waiting_room" && result.Action == engine.ActionChallenge {
		decision.Action = engine.ActionChallenge.String()
		decision.Reason = "waiting room explicitly enabled"
		return decision
	}
	if result.Action == engine.ActionPass || result.Action == engine.ActionLog {
		decision.Reason = "detector requested " + result.Action.String()
		return decision
	}
	if level == config.ProtectionLevelOff {
		decision.Reason = "bot protection disabled"
		return decision
	}
	if result.Severity >= minSeverity && result.Confidence >= minConfidence {
		if result.Action == engine.ActionChallenge {
			decision.Action = engine.ActionChallenge.String()
		} else {
			decision.Action = engine.ActionBlock.String()
		}
		decision.Reason = "severity and confidence meet bot policy threshold"
		return decision
	}
	return decision
}

func botCCThreshold(level string) (engine.Severity, float64) {
	switch level {
	case config.ProtectionLevelLow:
		return engine.SeverityHigh, 0.90
	case config.ProtectionLevelHigh:
		return engine.SeverityLow, 0.72
	case config.ProtectionLevelStrict:
		return engine.SeverityLow, 0.60
	default:
		return engine.SeverityMedium, 0.80
	}
}

func rateLimitDetection(reqCtx *engine.RequestContext) *engine.DetectionResult {
	payload := ""
	if reqCtx != nil {
		payload = reqCtx.ClientIP
	}
	return &engine.DetectionResult{
		Detected:   true,
		DetectorID: "bot.ratelimit",
		Category:   "ratelimit",
		Severity:   engine.SeverityMedium,
		Action:     engine.ActionBlock,
		Message:    "rate limit exceeded",
		Confidence: 0.86,
		Payload:    payload,
	}
}

type apiSecurityPolicyDecision struct {
	Level             string  `json:"level"`
	Action            string  `json:"action"`
	Reason            string  `json:"reason"`
	MinimumSeverity   string  `json:"minimum_severity"`
	MinimumConfidence float64 `json:"minimum_confidence"`
	ResultSeverity    string  `json:"result_severity"`
	ResultConfidence  float64 `json:"result_confidence"`
	DetectorAction    string  `json:"detector_action"`
	DetectorCategory  string  `json:"detector_category"`
	DetectorID        string  `json:"detector_id"`
	SchemaID          string  `json:"schema_id,omitempty"`
	Field             string  `json:"field,omitempty"`
}

func evaluateAPISecurityPolicy(level string, result *engine.DetectionResult) apiSecurityPolicyDecision {
	if level == "" {
		level = config.ProtectionLevelSmart
	}
	minSeverity, minConfidence := apiSecurityThreshold(level)
	decision := apiSecurityPolicyDecision{
		Level:             level,
		Action:            engine.ActionLog.String(),
		Reason:            "detected below API security policy threshold",
		MinimumSeverity:   minSeverity.String(),
		MinimumConfidence: minConfidence,
		DetectorAction:    engine.ActionPass.String(),
	}
	if result == nil {
		decision.Reason = "no detection result"
		return decision
	}
	decision.ResultSeverity = result.Severity.String()
	decision.ResultConfidence = result.Confidence
	decision.DetectorAction = result.Action.String()
	decision.DetectorCategory = result.Category
	decision.DetectorID = result.DetectorID
	if result.Action == engine.ActionPass || result.Action == engine.ActionLog {
		decision.Reason = "detector requested " + result.Action.String()
		return decision
	}
	if level == config.ProtectionLevelOff {
		decision.Reason = "API security disabled"
		return decision
	}
	if level == config.ProtectionLevelLow {
		decision.Reason = "low API security policy records finding without blocking"
		return decision
	}
	// Authentication and endpoint rate limiting are deterministic controls. The
	// detector category is shared with schema findings ("apisec"), so use the
	// stable detector IDs rather than the broad category. Smart/high/strict
	// policies must fail closed even if a future finding carries a lower score;
	// the explicitly permissive low tier keeps recording without blocking.
	deterministicControl := strings.HasPrefix(result.DetectorID, "apisec.auth.") || result.DetectorID == "apisec.ratelimit"
	if deterministicControl || result.Confidence >= 0.99 || (result.Severity >= minSeverity && result.Confidence >= minConfidence) {
		decision.Action = engine.ActionBlock.String()
		decision.Reason = "mandatory API control or severity and confidence meet policy threshold"
		return decision
	}
	return decision
}

func apiSecurityThreshold(level string) (engine.Severity, float64) {
	switch level {
	case config.ProtectionLevelLow:
		return engine.SeverityHigh, 0.90
	case config.ProtectionLevelHigh:
		return engine.SeverityLow, 0.72
	case config.ProtectionLevelStrict:
		return engine.SeverityLow, 0.60
	default:
		return engine.SeverityMedium, 0.82
	}
}

func apiRateLimitDetection(reqCtx *engine.RequestContext) *engine.DetectionResult {
	payload := ""
	if reqCtx != nil {
		payload = reqCtx.ClientIP
	}
	return &engine.DetectionResult{
		Detected:   true,
		DetectorID: "apisec.ratelimit",
		Category:   "apisec",
		Severity:   engine.SeverityMedium,
		Action:     engine.ActionBlock,
		Message:    "API endpoint rate limit exceeded",
		Confidence: 0.86,
		Payload:    payload,
	}
}

func apiAuthDetection(finding apisec.AuthFinding) *engine.DetectionResult {
	detectorID := "apisec.auth"
	switch finding.Kind {
	case "missing":
		detectorID = "apisec.auth.missing"
	case "invalid":
		detectorID = "apisec.auth.invalid"
	case "signature":
		detectorID = "apisec.auth.signature"
	case "issuer":
		detectorID = "apisec.auth.issuer"
	case "audience":
		detectorID = "apisec.auth.audience"
	case "scope":
		detectorID = "apisec.auth.scope"
	}
	return &engine.DetectionResult{
		Detected:   true,
		DetectorID: detectorID,
		Category:   "apisec",
		Severity:   parseSeverity(finding.Severity),
		Action:     engine.ActionBlock,
		Message:    finding.Message,
		Confidence: apiAuthConfidence(finding),
		Payload:    finding.Payload,
	}
}

func apiAuthConfidence(finding apisec.AuthFinding) float64 {
	switch finding.Kind {
	case "signature":
		return 0.93
	case "invalid":
		return 0.91
	case "issuer":
		return 0.89
	case "audience":
		return 0.89
	case "scope":
		return 0.88
	default:
		return 0.88
	}
}

func apiAuthStatus(finding apisec.AuthFinding) int {
	switch finding.Kind {
	case "missing", "invalid", "signature":
		return http.StatusUnauthorized
	default:
		return http.StatusForbidden
	}
}

func apiValidationDetection(finding apisec.ValidationFinding) *engine.DetectionResult {
	detectorID := "apisec.validation"
	if finding.SchemaID != "" {
		detectorID += "." + finding.SchemaID
	}
	return &engine.DetectionResult{
		Detected:   true,
		DetectorID: detectorID,
		Category:   "apisec",
		Severity:   parseSeverity(finding.Severity),
		Action:     engine.ActionBlock,
		Message:    finding.Message,
		Confidence: apiValidationConfidence(finding),
		Payload:    finding.Field,
	}
}

func apiValidationConfidence(finding apisec.ValidationFinding) float64 {
	if finding.Field == "body" {
		return 0.88
	}
	return 0.84
}

func parseSeverity(value string) engine.Severity {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical":
		return engine.SeverityCritical
	case "high":
		return engine.SeverityHigh
	case "low":
		return engine.SeverityLow
	case "info":
		return engine.SeverityInfo
	default:
		return engine.SeverityMedium
	}
}

func (s *Server) block(w http.ResponseWriter, reqCtx *engine.RequestContext, category, message string, status int, start time.Time) {
	s.renderer.RenderRequest(w, reqCtx.Request, status, s.blockPageData(reqCtx, category, message))
	s.writeLog(reqCtx.Request.Context(), reqCtx, "block", status, start, &storage.LogEntry{
		Category: category,
		Message:  message,
	})
}

func (s *Server) blockPageData(reqCtx *engine.RequestContext, attackType, message string) blockpage.Data {
	data := blockpage.Data{
		Timestamp: s.wallNow().UTC(),
		Message:   message,
	}
	if reqCtx != nil {
		data.EventID = reqCtx.TraceID
		data.TraceID = reqCtx.TraceID
		data.ClientIP = reqCtx.ClientIP
		data.SiteID = reqCtx.SiteID
	}
	data.AttackType = attackType
	if s != nil && data.SiteID != "" {
		if set := s.siteRuntimes.Load(); set != nil {
			if runtime := set.byID[data.SiteID]; runtime != nil {
				data.SiteName = strings.TrimSpace(runtime.site.Name)
				if data.SiteName == "" {
					data.SiteName = runtime.site.ID
				}
			}
		}
	}
	return data
}

func (s *Server) challenge(w http.ResponseWriter, r *http.Request, reqCtx *engine.RequestContext, category, message string, start time.Time) {
	if category == "" {
		category = "bot"
	}
	s.bot.ServeChallengeForSiteWithWaitingRoom(w, r, reqCtx.ClientIP, reqCtx.SiteID, s.waitingRoomForSite(reqCtx.SiteID))
	s.writeLog(r.Context(), reqCtx, "challenge", http.StatusForbidden, start, &storage.LogEntry{
		Category: category,
		Message:  message,
	})
}

func (s *Server) challengeThreatIntel(w http.ResponseWriter, r *http.Request, reqCtx *engine.RequestContext, decision ip.ThreatDecision, start time.Time) {
	s.bot.ServeChallengeForSiteWithWaitingRoom(w, r, reqCtx.ClientIP, reqCtx.SiteID, s.waitingRoomForSite(reqCtx.SiteID))
	s.writeLog(r.Context(), reqCtx, "challenge", http.StatusForbidden, start, &storage.LogEntry{
		Category:   "threat_intel",
		Severity:   decision.Severity,
		DetectorID: decision.DetectorID,
		Message:    decision.Message,
		Payload:    reqCtx.ClientIP,
	})
}

func (s *Server) waitingRoomForSite(siteID string) bool {
	if s == nil {
		return false
	}
	global := s.protectionConfig.Bot.WaitingRoom
	set := s.siteRuntimes.Load()
	if set == nil {
		return global
	}
	if runtime := set.byID[siteID]; runtime != nil {
		return siteWaitingRoomEnabled(runtime.site, global)
	}
	return global
}

func (s *Server) writeLog(ctx context.Context, reqCtx *engine.RequestContext, action string, status int, start time.Time, extra *storage.LogEntry) {
	if reqCtx == nil || reqCtx.Request == nil {
		return
	}
	if s.logSink == nil {
		s.enqueueReview(ctx, reqCtx, action)
		return
	}
	s.attachBotRiskMetadata(reqCtx, action)
	entry := &storage.LogEntry{
		ID:         reqCtx.TraceID,
		Timestamp:  s.wallNow().UTC(),
		TraceID:    reqCtx.TraceID,
		SiteID:     reqCtx.SiteID,
		ClientIP:   reqCtx.ClientIP,
		Method:     reqCtx.Request.Method,
		URI:        originalLogURI(reqCtx),
		StatusCode: status,
		Action:     action,
		UserAgent:  reqCtx.Request.UserAgent(),
		Latency:    time.Since(start),
	}
	if len(reqCtx.Metadata) > 0 {
		entry.Metadata = reqCtx.Metadata
	}
	location := s.geoip.Lookup(reqCtx.ClientIP)
	if metadata := location.Metadata(); location.CountryCode != "" || len(metadata) > 0 {
		if location.CountryCode != "" {
			entry.Country = location.CountryCode
		}
		if len(metadata) > 0 {
			if entry.Metadata == nil {
				entry.Metadata = map[string]any{}
			}
			entry.Metadata["geo"] = metadata
		}
	}
	if extra != nil {
		entry.Category = extra.Category
		entry.Severity = extra.Severity
		entry.DetectorID = extra.DetectorID
		entry.Message = extra.Message
		entry.Payload = extra.Payload
	}
	if extra == nil {
		if decision, ok := reqCtx.Metadata["threat_intel_decision"].(ip.ThreatDecision); ok && decision.Matched {
			entry.Category = "threat_intel"
			entry.Severity = decision.Severity
			entry.DetectorID = decision.DetectorID
			entry.Message = decision.Message
			entry.Payload = reqCtx.ClientIP
			if decision.Action == engine.ActionLog.String() && entry.Action == "pass" {
				entry.Action = "log"
			}
		}
		if result, ok := reqCtx.Metadata["detection"].(*engine.DetectionResult); ok && result != nil && result.Detected {
			entry.Category = result.Category
			entry.Severity = result.Severity.String()
			entry.DetectorID = result.DetectorID
			entry.Message = result.Message
			entry.Payload = result.Payload
			// Align with existing event-level fields: keep confidence and
			// detector type queryable in log metadata without a schema migration.
			if entry.Metadata == nil {
				entry.Metadata = map[string]any{}
			}
			entry.Metadata["confidence"] = result.Confidence
			entry.Metadata["detector_id"] = result.DetectorID
			entry.Metadata["detection_category"] = result.Category
			if decision, ok := reqCtx.Metadata["waf_policy_decision"].(webAttackPolicyDecision); ok {
				entry.Metadata["result_confidence"] = decision.ResultConfidence
				entry.Metadata["minimum_confidence"] = decision.MinimumConfidence
				if decision.Action == engine.ActionLog.String() && entry.Action == "pass" {
					entry.Action = "log"
				}
			}
			if decision, ok := reqCtx.Metadata["bot_cc_policy_decision"].(botCCPolicyDecision); ok && decision.Action == engine.ActionLog.String() && entry.Action == "pass" {
				entry.Action = "log"
			}
			if decision, ok := reqCtx.Metadata["api_security_policy_decision"].(apiSecurityPolicyDecision); ok && decision.Action == engine.ActionLog.String() && entry.Action == "pass" {
				entry.Action = "log"
			}
		}
	}
	if skip, ok := reqCtx.Metadata["semantic_skipped"].(string); ok && strings.TrimSpace(skip) != "" && entry.Message == "" && allowlistSkipWorthLogging(reqCtx.Request) {
		entry.Category = "semantic"
		entry.DetectorID = "semantic.analyzer"
		entry.Message = "allowlist: " + skip
		if entry.Action == "pass" {
			entry.Action = "log"
		}
	}
	if finding, ok := reqCtx.Metadata["response_finding"].(*response.Finding); ok && finding != nil {
		entry.Category = finding.Category
		if entry.Category == "" {
			entry.Category = "response"
		}
		entry.Severity = finding.Severity
		entry.Message = finding.Message
		entry.DetectorID = finding.DetectorID
		if entry.DetectorID == "" {
			entry.DetectorID = "response.inspector"
		}
		if entry.Action == "pass" {
			entry.Action = "log"
		}
		if finding.Reason != "" {
			if entry.Metadata == nil {
				entry.Metadata = map[string]any{}
			}
			entry.Metadata["response_finding_reason"] = finding.Reason
		}
		// The failure policy is the operator's exposure decision, so an
		// observe-mode coverage gap has to be visible in the log stream even
		// though it never turns into a block.
		if finding.FailMode != "" {
			if entry.Metadata == nil {
				entry.Metadata = map[string]any{}
			}
			entry.Metadata["response_fail_mode"] = finding.FailMode
		}
	}
	if isPlainAccessLog(entry) && !s.siteAccessLogEnabled(reqCtx.SiteID) {
		s.enqueueReview(ctx, reqCtx, action)
		return
	}
	// P0-2: a failed sink write used to be discarded silently, so events could
	// vanish without a trace. Record it, count it, and log it.
	if err := s.logSink.Write(ctx, entry); err != nil {
		storage.RecordLogWriteFailure()
		// Keep the diagnostic bounded to request-independent identifiers. Sink
		// errors may echo backend responses or serialized request data, including
		// sensitive HTTP headers, so never write the error text to the process log.
		log.Printf("proxy: log sink write failed trace_id=%q site_id=%q action=%q", entry.TraceID, entry.SiteID, entry.Action)
	}
	s.enqueueReview(ctx, reqCtx, action)
}

// attachBotRiskMetadata writes L1 risk_score/risk_band on every bot-enabled request
// and L2 risk_flags on challenge/block (always) or pass/log (0.1% sample).
// Cheap string scoring only — no I/O, no shared locks beyond FailureTracker read paths.
func (s *Server) attachBotRiskMetadata(reqCtx *engine.RequestContext, action string) {
	if s == nil || s.bot == nil || !s.bot.Enabled() || reqCtx == nil || reqCtx.Request == nil {
		return
	}
	if set := s.siteRuntimes.Load(); set != nil {
		if runtime := set.byID[reqCtx.SiteID]; runtime != nil && !siteFeatureEnabled(runtime.site.WAF.BotEnabled, s.protectionConfig.Bot.Enabled) {
			return
		}
	}
	if reqCtx.Metadata == nil {
		reqCtx.Metadata = map[string]any{}
	}
	// Idempotent: first writeLog wins (avoid double assessRisk on multi-write paths).
	if _, ok := reqCtx.Metadata["risk_score"]; ok {
		return
	}
	snap := s.bot.SnapshotRisk(reqCtx.Request, reqCtx.ClientIP, reqCtx.SiteID)
	reqCtx.Metadata["risk_score"] = snap.Score
	reqCtx.Metadata["risk_band"] = snap.Band
	reqCtx.Metadata["risk_confidence"] = snap.Confidence
	sampleKey := reqCtx.TraceID + "\x00" + reqCtx.ClientIP + "\x00" + action
	if bot.ShouldAttachRiskFlags(action, sampleKey, bot.DefaultPassRiskFlagSampleRate) && len(snap.Flags) > 0 {
		reqCtx.Metadata["risk_flags"] = snap.Flags
	}
}

// isPlainAccessLog is true for normal traffic without security signal.
// Security/block/challenge/monitor and detection-bearing "log" entries always persist.
func isPlainAccessLog(entry *storage.LogEntry) bool {
	if entry == nil {
		return false
	}
	action := strings.ToLower(strings.TrimSpace(entry.Action))
	switch action {
	case "pass", "cache_hit", "redirect":
		// keep writing if this pass still carries detection/threat signals
		return entry.Category == "" && entry.DetectorID == "" && entry.Severity == "" && entry.Message == ""
	default:
		return false
	}
}

func (s *Server) siteAccessLogEnabled(siteID string) bool {
	if s == nil {
		return true
	}
	siteID = strings.TrimSpace(siteID)
	set := s.siteRuntimes.Load()
	if set == nil {
		return true
	}
	if runtime := set.byID[siteID]; runtime != nil {
		return runtime.site.WAF.AccessLogOn()
	}
	// Unknown site id: default on so we do not silently drop security-adjacent traffic logs.
	return true
}

func ListenAndServe(ctx context.Context, srv *http.Server) error {
	errCh := make(chan error, 1)
	go func() {
		if srv.TLSConfig != nil {
			errCh <- srv.ListenAndServeTLS("", "")
			return
		}
		errCh <- srv.ListenAndServe()
	}()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		return ctx.Err()
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func requestHeaderBytes(r *http.Request) int {
	n := len(r.Method) + len(r.Host) + len(r.URL.RequestURI()) + 16
	for k, values := range r.Header {
		for _, v := range values {
			n += len(k) + len(v) + 4
		}
	}
	return n
}
func originalLogURI(ctx *engine.RequestContext) string {
	if original, ok := ctx.Metadata["original_uri"].(string); ok {
		return original
	}
	return ctx.Request.URL.RequestURI()
}
