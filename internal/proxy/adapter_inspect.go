package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/adapterapi"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

// InspectAdapter evaluates one gateway-supplied inspection request with the
// same site-scoped pipeline and protection policy used by the inline proxy.
// It is intentionally metadata/body-only: no upstream request is made and no
// gateway response is rendered here.
func (s *Server) InspectAdapter(ctx context.Context, request adapterapi.Request) (adapterapi.Decision, error) {
	if s == nil {
		return adapterapi.Decision{}, errors.New("proxy server is required")
	}
	site := s.lb.SiteForHost(request.Authority)
	if site.ID == "" {
		// SiteForHost only indexes enabled sites. Distinguish a configured
		// disabled site (explicitly allow) from an unknown host (block).
		site = s.lb.ConfiguredSiteForHost(request.Authority)
		if site.ID == "" {
			return adapterapi.Decision{
				Action:     adapterapi.ActionBlock,
				StatusCode: http.StatusForbidden,
				Reason:     "no matching site",
			}.Normalized(), nil
		}
	}
	if !site.Enabled || !site.WAF.Enabled || strings.EqualFold(site.WAF.Mode, "off") {
		return adapterapi.Decision{Action: adapterapi.ActionAllow}.Normalized(), nil
	}
	siteSet := s.siteRuntimes.Load()
	if siteSet == nil || siteSet.byID[site.ID] == nil {
		return adapterapi.Decision{}, errors.New("site runtime is unavailable")
	}
	siteRT := siteSet.byID[site.ID]

	target, err := url.ParseRequestURI(request.Path)
	if err != nil {
		return adapterapi.Decision{}, errors.New("invalid adapter path")
	}
	target.Scheme = request.Scheme
	if target.Scheme == "" {
		target.Scheme = "http"
	}
	target.Host = request.Authority
	target.RawQuery = request.Query

	header := make(http.Header, len(request.Headers))
	for name, values := range request.Headers {
		for _, value := range values {
			header.Add(name, value)
		}
	}

	var body io.ReadCloser = http.NoBody
	var contentLength int64
	if request.BodyForwarded {
		body = io.NopCloser(bytes.NewReader(request.Body))
		contentLength = int64(len(request.Body))
	}
	remoteAddr := ""
	if request.Client.IP != "" {
		remoteAddr = net.JoinHostPort(request.Client.IP, "0")
	}
	httpRequest := &http.Request{
		Method:        request.Method,
		URL:           target,
		Host:          request.Authority,
		Header:        header,
		Body:          body,
		ContentLength: contentLength,
		RemoteAddr:    remoteAddr,
		RequestURI:    target.RequestURI(),
	}
	if request.BodyForwarded {
		httpRequest.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(request.Body)), nil
		}
	}

	maxBody := site.WAF.Performance.MaxBodyBytes
	if maxBody <= 0 {
		maxBody = 8 << 20
	}
	reqCtx, err := engine.NewRequestContextDeferredBody(httpRequest, site.ID, siteRT.trustedProxyCIDRs, maxBody)
	if err != nil {
		return adapterapi.Decision{}, err
	}
	if request.Client.IP != "" {
		reqCtx.ClientIP = request.Client.IP
	}
	reqCtx.TraceID = request.RequestID
	reqCtx.HostValidated = true
	if reqCtx.Metadata == nil {
		reqCtx.Metadata = map[string]any{}
	}
	reqCtx.Metadata["detection_budget"] = site.WAF.SemanticPolicy.DetectionBudget
	reqCtx.Metadata["adapter_body_state"] = string(request.BodyState)
	reqCtx.Metadata["adapter_body_encoding"] = request.BodyEncoding
	reqCtx.Metadata["adapter_source"] = string(request.Source)

	s.runtimeMu.RLock()
	protectionPolicy := s.protectionPolicy
	s.runtimeMu.RUnlock()
	policy := config.EffectiveProtectionPolicy(protectionPolicy, site.WAF.ProtectionPolicy)
	reqCtx.Metadata["budget_exhausted_policy"] = config.ResolveBudgetExhaustedPolicy(
		site.WAF.SemanticPolicy.BudgetExhaustedPolicy,
		policy.WebAttack,
	)

	pipeline := s.currentPipeline()
	if pipeline == nil {
		return adapterapi.Decision{}, errors.New("detection pipeline is unavailable")
	}
	result, err := pipeline.Detect(ctx, reqCtx)
	if err != nil {
		return adapterapi.Decision{}, err
	}
	if result == nil || !result.Detected {
		return adapterapi.Decision{Action: adapterapi.ActionAllow}.Normalized(), nil
	}

	decision := evaluateWebAttackPolicyForSite(policy.WebAttack, result, reqCtx.Results, site, reqCtx)
	out := adapterapi.Decision{
		Action:        adapterapi.ActionAllow,
		Reason:        result.Message,
		RuleID:        result.DetectorID,
		PolicyVersion: decision.Level,
		Metadata: map[string]string{
			"category": result.Category,
		},
	}
	switch decision.Action {
	case engine.ActionBlock.String():
		out.Action = adapterapi.ActionBlock
		out.StatusCode = http.StatusForbidden
	case engine.ActionChallenge.String():
		out.Action = adapterapi.ActionChallenge
		out.StatusCode = http.StatusUnauthorized
	case engine.ActionLog.String():
		out.Action = adapterapi.ActionLog
	default:
		out.Action = adapterapi.ActionAllow
	}
	if !strings.EqualFold(site.WAF.Mode, "block") && out.Action == adapterapi.ActionBlock {
		out.Action = adapterapi.ActionLog
		out.StatusCode = 0
	}
	return out.Normalized(), nil
}
