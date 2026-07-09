package proxy

import (
	"context"
	"errors"
	"math"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/apisec"
	"github.com/LaokeQwQ/CheeseWAF/internal/blockpage"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/edge"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine/response"
	"github.com/LaokeQwQ/CheeseWAF/internal/protection/acl"
	"github.com/LaokeQwQ/CheeseWAF/internal/protection/bot"
	"github.com/LaokeQwQ/CheeseWAF/internal/protection/ip"
	"github.com/LaokeQwQ/CheeseWAF/internal/protection/ratelimit"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

type Server struct {
	config     *config.Config
	pipeline   *engine.Pipeline
	pipelineMu sync.RWMutex
	logSink    storage.LogSink
	renderer   *blockpage.Renderer
	lb         *LoadBalancer
	blacklist  *ip.Blacklist
	whitelist  *ip.Whitelist
	access     *ip.AccessPolicy
	geoip      *ip.GeoIPPolicy
	intel      *ip.Intel
	acl        *acl.Policy
	bot        *bot.Policy
	limiter    *ratelimit.Limiter
	health     *HealthRegistry
	headers    *edge.HeaderModifier
	cache      *edge.Cache
	compress   *edge.Compressor
	apiSchema  *apisec.Validator
	apiLimit   *apisec.RateLimiter
	apiAuth    *apisec.Authenticator
	certs      *SiteCertificateStore
}

func NewServer(cfg *config.Config, pipeline *engine.Pipeline, sink storage.LogSink) (*Server, error) {
	blacklist, err := ip.NewBlacklist(cfg.Protection.IP.Blacklist)
	if err != nil {
		return nil, err
	}
	whitelist, err := ip.NewWhitelist(cfg.Protection.IP.Whitelist)
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
	apiAuth, err := apisec.NewAuthenticator(cfg.APISec)
	if err != nil {
		return nil, err
	}
	renderer, err := blockpage.NewRendererFromConfig(cfg.BlockPage)
	if err != nil {
		return nil, err
	}
	certs, err := NewSiteCertificateStore(cfg)
	if err != nil {
		return nil, err
	}
	return &Server{
		config:    cfg,
		pipeline:  pipeline,
		logSink:   sink,
		renderer:  renderer,
		lb:        NewLoadBalancer(cfg.Sites).WithHealth(health),
		blacklist: blacklist,
		whitelist: whitelist,
		access:    access,
		geoip:     geoip,
		intel:     intel,
		acl:       acl.NewPolicy(cfg.Protection.ACL),
		bot:       bot.NewPolicy(cfg.Protection.Bot),
		limiter:   ratelimit.New(cfg.Protection.RateLimit.Default, cfg.Protection.RateLimit.Enabled),
		health:    health,
		headers:   edge.NewHeaderModifier(cfg.Edge.Headers),
		cache:     edge.NewCache(cfg.Edge.Cache),
		compress:  edge.NewCompressor(cfg.Edge.Compression),
		apiSchema: apiSchema,
		apiLimit:  apiLimit,
		apiAuth:   apiAuth,
		certs:     certs,
	}, nil
}

func (s *Server) UpdateBlockPage(page config.BlockPageConfig) error {
	if s == nil {
		return nil
	}
	renderer, err := blockpage.NewRendererFromConfig(page)
	if err != nil {
		return err
	}
	s.config.BlockPage = page
	s.renderer = renderer
	return nil
}

func (s *Server) HealthRegistry() *HealthRegistry {
	return s.health
}

func (s *Server) UpdateSites(sites []config.SiteConfig) {
	if s == nil {
		return
	}
	s.config.Sites = append([]config.SiteConfig(nil), sites...)
	if s.certs != nil {
		_ = s.certs.Update(s.config)
	}
	s.health = NewHealthRegistry(s.config.Sites)
	s.lb.UpdateSites(s.config.Sites, s.health)
}

func (s *Server) UpdatePipeline(pipeline *engine.Pipeline) {
	if s == nil {
		return
	}
	s.pipelineMu.Lock()
	defer s.pipelineMu.Unlock()
	s.pipeline = pipeline
}

func (s *Server) currentPipeline() *engine.Pipeline {
	if s == nil {
		return nil
	}
	s.pipelineMu.RLock()
	defer s.pipelineMu.RUnlock()
	return s.pipeline
}

func (s *Server) UpdateAPISec(apiSec config.APISecConfig) error {
	if s == nil {
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
	apiAuth, err := apisec.NewAuthenticator(apiSec)
	if err != nil {
		return err
	}
	oldAuth := s.apiAuth
	s.config.APISec = apiSec
	s.apiSchema = apiSchema
	s.apiLimit = apiLimit
	s.apiAuth = apiAuth
	if oldAuth != nil {
		_ = oldAuth.Close()
	}
	return nil
}

func (s *Server) UpdateProtection(protection config.ProtectionConfig) error {
	if s == nil {
		return nil
	}
	blacklist, err := ip.NewBlacklist(protection.IP.Blacklist)
	if err != nil {
		return err
	}
	whitelist, err := ip.NewWhitelist(protection.IP.Whitelist)
	if err != nil {
		return err
	}
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
		return err
	}
	apiLimit, err := apisec.NewRateLimiter(s.config.APISec.RateLimits)
	if err != nil {
		return err
	}
	s.config.Protection = protection
	s.blacklist = blacklist
	s.whitelist = whitelist
	s.access = access
	s.geoip = geoip
	s.intel = intel
	s.acl = acl.NewPolicy(protection.ACL)
	s.bot = bot.NewPolicy(protection.Bot)
	s.limiter = ratelimit.New(protection.RateLimit.Default, protection.RateLimit.Enabled)
	s.apiLimit = apiLimit
	return nil
}

func (s *Server) Handler() http.Handler {
	return securityHeaders(http.HandlerFunc(s.handle))
}

func (s *Server) HTTPServer() *http.Server {
	return &http.Server{
		Addr:              s.config.Server.Listen,
		Handler:           s.Handler(),
		ReadHeaderTimeout: s.config.Server.ReadTimeout,
		ReadTimeout:       s.config.Server.ReadTimeout,
		WriteTimeout:      s.config.Server.WriteTimeout,
		IdleTimeout:       s.config.Server.IdleTimeout,
		MaxHeaderBytes:    maxHeaderBytes(s.config),
	}
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	site := s.lb.SiteForHost(r.Host)
	policy := config.EffectiveProtectionPolicy(s.config.Protection.Policy, site.WAF.ProtectionPolicy)

	// Protocol enforcement: HTTP smuggling, chunked encoding abuse, header injection
	if violation := engine.DetectProtocolViolations(r); violation != nil {
		s.block(w, &engine.RequestContext{
			Request:  r,
			ClientIP: engine.ClientIPWithTrustedProxies(r, site.WAF.AccessControl.TrustedCIDRs),
			TraceID:  blockpage.NewTraceID(),
			SiteID:   site.ID,
			Metadata: map[string]any{"protocol_violation": violation.Type},
		}, "protocol_enforcement", violation.Message, http.StatusBadRequest, start)
		return
	}

	reqCtx, err := engine.NewRequestContextWithTrustedProxies(r, site.ID, site.WAF.AccessControl.TrustedCIDRs)
	if err != nil {
		s.proxyError(w, r, site, nil, "proxy_error", "failed to read request", http.StatusBadRequest, start, err)
		return
	}
	accessDecision := s.access.Evaluate(reqCtx.ClientIP, site.ID, r.URL.Path)
	if accessDecision.Matched {
		reqCtx.Metadata["ip_access_decision"] = accessDecision
	}
	ipAllowed := accessDecision.Action == ip.AccessActionAllow
	if accessDecision.Action == ip.AccessActionBlock {
		message := "IP access rule blocked the request"
		if accessDecision.RuleName != "" {
			message = "IP access rule blocked the request: " + accessDecision.RuleName
		}
		s.block(w, reqCtx, "ip_access", message, http.StatusForbidden, start)
		return
	}
	if s.geoip.Blocked(reqCtx.ClientIP) && !ipAllowed {
		s.block(w, reqCtx, "geoip", "GeoIP country is blocked", http.StatusForbidden, start)
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
				s.challengeThreatIntel(w, r, reqCtx, decision, start)
				return
			}
		}
	}
	if result := s.acl.Evaluate(r); result != nil && result.Detected && result.Action == engine.ActionBlock {
		s.block(w, reqCtx, result.Category, result.Message, http.StatusForbidden, start)
		return
	}
	if policy.BotCC != config.ProtectionLevelOff {
		if result := s.bot.Evaluate(r, reqCtx.ClientIP); result != nil && result.Detected && !ipAllowed {
			decision := evaluateBotCCPolicy(policy.BotCC, result)
			reqCtx.Metadata["bot_cc_policy_decision"] = decision
			reqCtx.Metadata["detection"] = result
			switch decision.Action {
			case engine.ActionChallenge.String():
				s.challenge(w, r, reqCtx, result.Category, result.Message, start)
				return
			case engine.ActionBlock.String():
				s.blockDetection(w, reqCtx, result, http.StatusForbidden, start)
				return
			}
		}
	}
	if policy.BotCC != config.ProtectionLevelOff && !s.limiter.Allow(reqCtx.ClientIP) && !ipAllowed {
		result := rateLimitDetection(reqCtx)
		decision := evaluateBotCCPolicy(policy.BotCC, result)
		reqCtx.Metadata["bot_cc_policy_decision"] = decision
		reqCtx.Metadata["detection"] = result
		switch decision.Action {
		case engine.ActionBlock.String():
			s.blockDetection(w, reqCtx, result, http.StatusTooManyRequests, start)
			return
		case engine.ActionChallenge.String():
			s.challenge(w, r, reqCtx, result.Category, result.Message, start)
			return
		}
	}
	if s.config.APISec.Enabled && policy.APISecurity != config.ProtectionLevelOff {
		if finding := s.apiAuth.Evaluate(r); finding != nil && !ipAllowed {
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
		if !s.apiLimit.Allow(r, reqCtx.ClientIP) && !ipAllowed {
			result := apiRateLimitDetection(reqCtx)
			decision := evaluateAPISecurityPolicy(policy.APISecurity, result)
			reqCtx.Metadata["api_security_policy_decision"] = decision
			reqCtx.Metadata["detection"] = result
			if decision.Action == engine.ActionBlock.String() {
				s.blockDetection(w, reqCtx, result, http.StatusTooManyRequests, start)
				return
			}
		}
		if findings := s.apiSchema.Validate(r); len(findings) > 0 {
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
	rewriter, err := NewRewriter(site.WAF.Rewrite)
	if err != nil {
		s.proxyError(w, r, site, reqCtx, "proxy_error", "rewrite configuration error", http.StatusInternalServerError, start, err)
		return
	}
	if redirect, code := rewriter.Apply(r); redirect {
		http.Redirect(w, r, r.URL.String(), code)
		s.writeLog(r.Context(), reqCtx, "redirect", code, start, nil)
		return
	}
	pipeline := s.currentPipeline()
	if site.WAF.Enabled && site.WAF.Mode != "off" && policy.WebAttack != config.ProtectionLevelOff && pipeline != nil {
		result, err := pipeline.Detect(r.Context(), reqCtx)
		if err != nil {
			s.proxyError(w, r, site, reqCtx, "proxy_error", "waf pipeline error", http.StatusInternalServerError, start, err)
			return
		}
		if result != nil && result.Detected {
			decision := evaluateWebAttackPolicyWithEvidence(policy.WebAttack, result, reqCtx.Results)
			reqCtx.Metadata["waf_policy_decision"] = decision
			reqCtx.Metadata["detection"] = result
			switch decision.Action {
			case engine.ActionBlock.String():
				s.blockDetection(w, reqCtx, result, http.StatusForbidden, start)
				return
			case engine.ActionChallenge.String():
				s.challenge(w, r, reqCtx, result.Category, result.Message, start)
				return
			}
		}
	}
	s.headers.Apply(r)
	if cached, ok := s.cache.Get(r); ok {
		s.compress.Apply(r, &cached)
		edge.WriteCaptured(w, cached)
		s.writeLog(r.Context(), reqCtx, "cache_hit", cached.Status, start, nil)
		return
	}
	target, err := s.lb.Next(site, reqCtx.ClientIP)
	if err != nil {
		s.proxyError(w, r, site, reqCtx, "proxy_error", "no upstream", http.StatusBadGateway, start, err)
		return
	}
	if IsWebSocketUpgrade(r) {
		rp := NewReverseProxy(target, site.WAF.Performance.ProxyTimeout)
		var proxyErr error
		rp.ErrorHandler = func(_ http.ResponseWriter, _ *http.Request, err error) {
			proxyErr = err
		}
		rp.ServeHTTP(w, r)
		if proxyErr != nil {
			s.proxyError(w, r, site, reqCtx, "proxy_error", "upstream proxy error", http.StatusBadGateway, start, proxyErr)
			return
		}
		s.writeLog(r.Context(), reqCtx, "pass", http.StatusSwitchingProtocols, start, nil)
		return
	}
	retrySafe := retrySafeRequest(r)
	cacheCandidate := retrySafe && s.cache.CaptureCandidate(r)
	compressCandidate := retrySafe && s.compress.MayApplyRequest(r)
	if !cacheCandidate && !compressCandidate {
		rp := NewReverseProxy(target, site.WAF.Performance.ProxyTimeout)
		var proxyErr error
		rp.ErrorHandler = func(_ http.ResponseWriter, _ *http.Request, err error) {
			proxyErr = err
		}
		if site.WAF.Response.Enabled {
			inspector, err := response.New(site.WAF.Response)
			if err != nil {
				s.proxyError(w, r, site, reqCtx, "proxy_error", "response inspector configuration error", http.StatusInternalServerError, start, err)
				return
			}
			rp.ModifyResponse = func(resp *http.Response) error {
				finding, err := inspector.InspectHTTP(resp)
				if err != nil {
					return err
				}
				if finding != nil {
					resp.Header.Set("X-CheeseWAF-Response-Finding", finding.Message)
					reqCtx.Metadata["response_finding"] = finding
				}
				return nil
			}
		}
		recorder := &proxyStatusRecorder{ResponseWriter: w, status: http.StatusOK}
		rp.ServeHTTP(recorder, r)
		if proxyErr != nil {
			s.proxyError(w, r, site, reqCtx, "proxy_error", "upstream proxy error", http.StatusBadGateway, start, proxyErr)
			return
		}
		s.writeLog(r.Context(), reqCtx, "pass", recorder.status, start, nil)
		return
	}
	capture := edge.NewLimitedCaptureWriter(edgeCaptureLimit(site, s.cache, cacheCandidate, compressCandidate))
	rp := NewReverseProxy(target, site.WAF.Performance.ProxyTimeout)
	var proxyErr error
	rp.ErrorHandler = func(_ http.ResponseWriter, _ *http.Request, err error) {
		proxyErr = err
	}
	if site.WAF.Response.Enabled {
		inspector, err := response.New(site.WAF.Response)
		if err != nil {
			s.proxyError(w, r, site, reqCtx, "proxy_error", "response inspector configuration error", http.StatusInternalServerError, start, err)
			return
		}
		rp.ModifyResponse = func(resp *http.Response) error {
			finding, err := inspector.InspectHTTP(resp)
			if err != nil {
				return err
			}
			if finding != nil {
				resp.Header.Set("X-CheeseWAF-Response-Finding", finding.Message)
				reqCtx.Metadata["response_finding"] = finding
			}
			return nil
		}
	}
	rp.ServeHTTP(capture, r)
	if capture.TooLarge() {
		s.streamWithoutEdgeCapture(w, r, site, reqCtx, target, start)
		return
	}
	if proxyErr != nil {
		s.proxyError(w, r, site, reqCtx, "proxy_error", "upstream proxy error", http.StatusBadGateway, start, proxyErr)
		return
	}
	captured := capture.Response()
	if cacheCandidate {
		s.cache.Store(r, captured)
		captured.Header.Set("X-CheeseWAF-Cache", "MISS")
	}
	s.compress.Apply(r, &captured)
	edge.WriteCaptured(w, captured)
	s.writeLog(r.Context(), reqCtx, "pass", captured.Status, start, nil)
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
	return (r.Method == http.MethodGet || r.Method == http.MethodHead) && r.ContentLength <= 0
}

func (s *Server) streamWithoutEdgeCapture(w http.ResponseWriter, r *http.Request, site config.SiteConfig, reqCtx *engine.RequestContext, target *url.URL, start time.Time) {
	rp := NewReverseProxy(target, site.WAF.Performance.ProxyTimeout)
	var proxyErr error
	rp.ErrorHandler = func(_ http.ResponseWriter, _ *http.Request, err error) {
		proxyErr = err
	}
	if site.WAF.Response.Enabled {
		inspector, err := response.New(site.WAF.Response)
		if err != nil {
			s.proxyError(w, r, site, reqCtx, "proxy_error", "response inspector configuration error", http.StatusInternalServerError, start, err)
			return
		}
		rp.ModifyResponse = func(resp *http.Response) error {
			finding, err := inspector.InspectHTTP(resp)
			if err != nil {
				return err
			}
			if finding != nil {
				resp.Header.Set("X-CheeseWAF-Response-Finding", finding.Message)
				reqCtx.Metadata["response_finding"] = finding
			}
			return nil
		}
	}
	recorder := &proxyStatusRecorder{ResponseWriter: w, status: http.StatusOK}
	rp.ServeHTTP(recorder, r)
	if proxyErr != nil {
		s.proxyError(w, r, site, reqCtx, "proxy_error", "upstream proxy error", http.StatusBadGateway, start, proxyErr)
		return
	}
	s.writeLog(r.Context(), reqCtx, "pass", recorder.status, start, nil)
}

type proxyStatusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *proxyStatusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
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
			ClientIP: engine.ClientIPWithTrustedProxies(r, site.WAF.AccessControl.TrustedCIDRs),
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
		reqCtx.ClientIP = engine.ClientIPWithTrustedProxies(r, site.WAF.AccessControl.TrustedCIDRs)
	}
	if reqCtx.Metadata == nil {
		reqCtx.Metadata = map[string]any{}
	}
	reqCtx.Metadata["proxy_error"] = message
	if cause != nil {
		reqCtx.Metadata["proxy_error_detail"] = cause.Error()
	}
	s.renderer.RenderRequest(w, r, status, blockpage.Data{
		EventID:    reqCtx.TraceID,
		TraceID:    reqCtx.TraceID,
		AttackType: category,
		ClientIP:   reqCtx.ClientIP,
		Message:    message,
		Timestamp:  time.Now().UTC(),
	})
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
	s.renderer.RenderRequest(w, reqCtx.Request, status, blockpage.Data{
		TraceID:    reqCtx.TraceID,
		AttackType: result.Category,
		ClientIP:   reqCtx.ClientIP,
		Message:    result.Message,
		Timestamp:  time.Now().UTC(),
	})
	s.writeLog(reqCtx.Request.Context(), reqCtx, "block", status, start, &storage.LogEntry{
		Category:   result.Category,
		Severity:   result.Severity.String(),
		DetectorID: result.DetectorID,
		Message:    result.Message,
		Payload:    result.Payload,
	})
}

func (s *Server) blockThreatIntel(w http.ResponseWriter, reqCtx *engine.RequestContext, decision ip.ThreatDecision, status int, start time.Time) {
	s.renderer.RenderRequest(w, reqCtx.Request, status, blockpage.Data{
		TraceID:    reqCtx.TraceID,
		AttackType: "threat_intel",
		ClientIP:   reqCtx.ClientIP,
		Message:    decision.Message,
		Timestamp:  time.Now().UTC(),
	})
	s.writeLog(reqCtx.Request.Context(), reqCtx, "block", status, start, &storage.LogEntry{
		Category:   "threat_intel",
		Severity:   decision.Severity,
		DetectorID: decision.DetectorID,
		Message:    decision.Message,
		Payload:    reqCtx.ClientIP,
	})
}

type webAttackPolicyDecision struct {
	Level             string  `json:"level"`
	Action            string  `json:"action"`
	Reason            string  `json:"reason"`
	ParanoiaLevel     int     `json:"paranoia_level"`
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
}

func evaluateWebAttackPolicy(level string, result *engine.DetectionResult) webAttackPolicyDecision {
	return evaluateWebAttackPolicyWithEvidence(level, result, nil)
}

func evaluateWebAttackPolicyWithEvidence(level string, result *engine.DetectionResult, results []engine.DetectionResult) webAttackPolicyDecision {
	if level == "" {
		level = config.ProtectionLevelSmart
	}
	minSeverity, minConfidence := webAttackThreshold(level)
	riskThreshold := webAttackRiskThreshold(level)
	decision := webAttackPolicyDecision{
		Level:             level,
		Action:            engine.ActionLog.String(),
		Reason:            "detected below policy threshold",
		ParanoiaLevel:     webAttackParanoiaLevel(level),
		MinimumSeverity:   minSeverity.String(),
		MinimumConfidence: minConfidence,
		MinimumRiskScore:  riskThreshold,
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
	if result.Severity >= minSeverity && result.Confidence >= minConfidence {
		if result.Action == engine.ActionChallenge {
			decision.Action = engine.ActionChallenge.String()
		} else {
			decision.Action = engine.ActionBlock.String()
		}
		decision.Reason = "severity and confidence meet policy threshold"
		return decision
	}
	if evidence.Score >= riskThreshold {
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
	if result.Severity >= minSeverity && result.Confidence >= minConfidence {
		decision.Action = engine.ActionBlock.String()
		decision.Reason = "severity and confidence meet API security policy threshold"
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
	s.renderer.RenderRequest(w, reqCtx.Request, status, blockpage.Data{
		TraceID:    reqCtx.TraceID,
		AttackType: category,
		ClientIP:   reqCtx.ClientIP,
		Message:    message,
		Timestamp:  time.Now().UTC(),
	})
	s.writeLog(reqCtx.Request.Context(), reqCtx, "block", status, start, &storage.LogEntry{
		Category: category,
		Message:  message,
	})
}

func (s *Server) challenge(w http.ResponseWriter, r *http.Request, reqCtx *engine.RequestContext, category, message string, start time.Time) {
	if category == "" {
		category = "bot"
	}
	s.bot.ServeChallenge(w, r, reqCtx.ClientIP)
	s.writeLog(r.Context(), reqCtx, "challenge", http.StatusForbidden, start, &storage.LogEntry{
		Category: category,
		Message:  message,
	})
}

func (s *Server) challengeThreatIntel(w http.ResponseWriter, r *http.Request, reqCtx *engine.RequestContext, decision ip.ThreatDecision, start time.Time) {
	s.bot.ServeChallenge(w, r, reqCtx.ClientIP)
	s.writeLog(r.Context(), reqCtx, "challenge", http.StatusForbidden, start, &storage.LogEntry{
		Category:   "threat_intel",
		Severity:   decision.Severity,
		DetectorID: decision.DetectorID,
		Message:    decision.Message,
		Payload:    reqCtx.ClientIP,
	})
}

func (s *Server) writeLog(ctx context.Context, reqCtx *engine.RequestContext, action string, status int, start time.Time, extra *storage.LogEntry) {
	if s.logSink == nil || reqCtx == nil || reqCtx.Request == nil {
		return
	}
	entry := &storage.LogEntry{
		ID:         reqCtx.TraceID,
		Timestamp:  time.Now().UTC(),
		TraceID:    reqCtx.TraceID,
		SiteID:     reqCtx.SiteID,
		ClientIP:   reqCtx.ClientIP,
		Method:     reqCtx.Request.Method,
		URI:        reqCtx.Request.URL.RequestURI(),
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
			if decision, ok := reqCtx.Metadata["waf_policy_decision"].(webAttackPolicyDecision); ok && decision.Action == engine.ActionLog.String() && entry.Action == "pass" {
				entry.Action = "log"
			}
			if decision, ok := reqCtx.Metadata["bot_cc_policy_decision"].(botCCPolicyDecision); ok && decision.Action == engine.ActionLog.String() && entry.Action == "pass" {
				entry.Action = "log"
			}
			if decision, ok := reqCtx.Metadata["api_security_policy_decision"].(apiSecurityPolicyDecision); ok && decision.Action == engine.ActionLog.String() && entry.Action == "pass" {
				entry.Action = "log"
			}
		}
	}
	if finding, ok := reqCtx.Metadata["response_finding"].(*response.Finding); ok && finding != nil {
		entry.Category = "response"
		entry.Message = finding.Message
		entry.DetectorID = "response.inspector"
		entry.Action = "log"
	}
	_ = s.logSink.Write(ctx, entry)
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
