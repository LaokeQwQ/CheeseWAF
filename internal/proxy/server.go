package proxy

import (
	"context"
	"errors"
	"net/http"
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
	config    *config.Config
	pipeline  *engine.Pipeline
	logSink   storage.LogSink
	renderer  *blockpage.Renderer
	lb        *LoadBalancer
	blacklist *ip.Blacklist
	whitelist *ip.Whitelist
	geoip     *ip.GeoIPPolicy
	acl       *acl.Policy
	bot       *bot.Policy
	limiter   *ratelimit.Limiter
	health    *HealthRegistry
	headers   *edge.HeaderModifier
	cache     *edge.Cache
	compress  *edge.Compressor
	apiSchema *apisec.Validator
	apiLimit  *apisec.RateLimiter
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
	geoip, err := ip.NewGeoIPPolicy(cfg.Protection.IP.GeoIP)
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
	return &Server{
		config:    cfg,
		pipeline:  pipeline,
		logSink:   sink,
		renderer:  blockpage.NewRenderer(),
		lb:        NewLoadBalancer(cfg.Sites).WithHealth(health),
		blacklist: blacklist,
		whitelist: whitelist,
		geoip:     geoip,
		acl:       acl.NewPolicy(cfg.Protection.ACL),
		bot:       bot.NewPolicy(cfg.Protection.Bot),
		limiter:   ratelimit.New(cfg.Protection.RateLimit.Default, cfg.Protection.RateLimit.Enabled),
		health:    health,
		headers:   edge.NewHeaderModifier(cfg.Edge.Headers),
		cache:     edge.NewCache(cfg.Edge.Cache),
		compress:  edge.NewCompressor(cfg.Edge.Compression),
		apiSchema: apiSchema,
		apiLimit:  apiLimit,
	}, nil
}

func (s *Server) HealthRegistry() *HealthRegistry {
	return s.health
}

func (s *Server) UpdateSites(sites []config.SiteConfig) {
	if s == nil {
		return
	}
	s.config.Sites = append([]config.SiteConfig(nil), sites...)
	s.health = NewHealthRegistry(s.config.Sites)
	s.lb.UpdateSites(s.config.Sites, s.health)
}

func (s *Server) Handler() http.Handler {
	return securityHeaders(http.HandlerFunc(s.handle))
}

func (s *Server) HTTPServer() *http.Server {
	return &http.Server{
		Addr:         s.config.Server.Listen,
		Handler:      s.Handler(),
		ReadTimeout:  s.config.Server.ReadTimeout,
		WriteTimeout: s.config.Server.WriteTimeout,
		IdleTimeout:  s.config.Server.IdleTimeout,
	}
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	site := s.lb.SiteForHost(r.Host)
	policy := config.EffectiveProtectionPolicy(s.config.Protection.Policy, site.WAF.ProtectionPolicy)
	reqCtx, err := engine.NewRequestContext(r, site.ID)
	if err != nil {
		http.Error(w, "failed to read request", http.StatusBadRequest)
		return
	}
	start := time.Now()
	if s.blacklist.Blocked(reqCtx.ClientIP) && !s.whitelist.Allowed(reqCtx.ClientIP) {
		s.block(w, reqCtx, "ip", "IP is blocked", http.StatusForbidden, start)
		return
	}
	if s.geoip.Blocked(reqCtx.ClientIP) && !s.whitelist.Allowed(reqCtx.ClientIP) {
		s.block(w, reqCtx, "geoip", "GeoIP country is blocked", http.StatusForbidden, start)
		return
	}
	if result := s.acl.Evaluate(r); result != nil && result.Detected && result.Action == engine.ActionBlock {
		s.block(w, reqCtx, result.Category, result.Message, http.StatusForbidden, start)
		return
	}
	if policy.BotCC != config.ProtectionLevelOff {
		if result := s.bot.Evaluate(r, reqCtx.ClientIP); result != nil && result.Detected && !s.whitelist.Allowed(reqCtx.ClientIP) {
			if result.Action == engine.ActionChallenge {
				s.challenge(w, r, reqCtx, result.Category, result.Message, start)
				return
			}
			s.block(w, reqCtx, result.Category, result.Message, http.StatusForbidden, start)
			return
		}
	}
	if policy.BotCC != config.ProtectionLevelOff && !s.limiter.Allow(reqCtx.ClientIP) && !s.whitelist.Allowed(reqCtx.ClientIP) {
		s.block(w, reqCtx, "ratelimit", "rate limit exceeded", http.StatusTooManyRequests, start)
		return
	}
	if s.config.APISec.Enabled && policy.APISecurity != config.ProtectionLevelOff {
		if !s.apiLimit.Allow(r, reqCtx.ClientIP) && !s.whitelist.Allowed(reqCtx.ClientIP) {
			s.block(w, reqCtx, "apisec", "API endpoint rate limit exceeded", http.StatusTooManyRequests, start)
			return
		}
		if findings := s.apiSchema.Validate(r); len(findings) > 0 {
			s.block(w, reqCtx, "apisec", findings[0].Message, http.StatusBadRequest, start)
			return
		}
	}
	rewriter, err := NewRewriter(site.WAF.Rewrite)
	if err != nil {
		http.Error(w, "rewrite configuration error", http.StatusInternalServerError)
		return
	}
	if redirect, code := rewriter.Apply(r); redirect {
		http.Redirect(w, r, r.URL.String(), code)
		s.writeLog(r.Context(), reqCtx, "redirect", code, start, nil)
		return
	}
	if site.WAF.Enabled && site.WAF.Mode != "off" && policy.WebAttack != config.ProtectionLevelOff && s.pipeline != nil {
		result, err := s.pipeline.Detect(r.Context(), reqCtx)
		if err != nil {
			http.Error(w, "waf pipeline error", http.StatusInternalServerError)
			return
		}
		if result != nil && result.Detected {
			decision := evaluateWebAttackPolicy(policy.WebAttack, result)
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
		http.Error(w, "no upstream", http.StatusBadGateway)
		return
	}
	if IsWebSocketUpgrade(r) {
		NewReverseProxy(target, site.WAF.Performance.ProxyTimeout).ServeHTTP(w, r)
		s.writeLog(r.Context(), reqCtx, "pass", http.StatusSwitchingProtocols, start, nil)
		return
	}
	capture := edge.NewCaptureWriter()
	rp := NewReverseProxy(target, site.WAF.Performance.ProxyTimeout)
	if site.WAF.Response.Enabled {
		inspector, err := response.New(site.WAF.Response)
		if err != nil {
			http.Error(w, "response inspector configuration error", http.StatusInternalServerError)
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
	captured := capture.Response()
	s.cache.Store(r, captured)
	captured.Header.Set("X-CheeseWAF-Cache", "MISS")
	s.compress.Apply(r, &captured)
	edge.WriteCaptured(w, captured)
	s.writeLog(r.Context(), reqCtx, "pass", captured.Status, start, nil)
}

func (s *Server) blockDetection(w http.ResponseWriter, reqCtx *engine.RequestContext, result *engine.DetectionResult, status int, start time.Time) {
	if result == nil {
		s.block(w, reqCtx, "unknown", "request blocked", status, start)
		return
	}
	reqCtx.Metadata["detection"] = result
	s.renderer.Render(w, status, blockpage.Data{
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

type webAttackPolicyDecision struct {
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

func evaluateWebAttackPolicy(level string, result *engine.DetectionResult) webAttackPolicyDecision {
	if level == "" {
		level = config.ProtectionLevelSmart
	}
	minSeverity, minConfidence := webAttackThreshold(level)
	decision := webAttackPolicyDecision{
		Level:             level,
		Action:            engine.ActionLog.String(),
		Reason:            "detected below policy threshold",
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

func (s *Server) block(w http.ResponseWriter, reqCtx *engine.RequestContext, category, message string, status int, start time.Time) {
	s.renderer.Render(w, status, blockpage.Data{
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
		if result, ok := reqCtx.Metadata["detection"].(*engine.DetectionResult); ok && result != nil && result.Detected {
			entry.Category = result.Category
			entry.Severity = result.Severity.String()
			entry.DetectorID = result.DetectorID
			entry.Message = result.Message
			entry.Payload = result.Payload
			if decision, ok := reqCtx.Metadata["waf_policy_decision"].(webAttackPolicyDecision); ok && decision.Action == engine.ActionLog.String() && entry.Action == "pass" {
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
