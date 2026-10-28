// Package adapterinspect implements the core-side HTTP contract used by
// CheeseWAF-Adapters when a gateway can forward a bounded request body.
package adapterinspect

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

const (
	// ContractVersion is the adapter inspection wire version.
	ContractVersion = "v1"
	// DefaultMaxBodyBytes bounds a single adapter body.
	DefaultMaxBodyBytes int64 = 8 << 20
	maxJSONBodyBytes    int64 = DefaultMaxBodyBytes/3*4 + (2 << 20)
)

// Request is the subset of the adapter inspection contract consumed here.
// JSON encoding follows Go's []byte base64 behavior used by the adapter client.
type Request struct {
	ContractVersion string              `json:"contract_version"`
	RequestID       string              `json:"request_id,omitempty"`
	Source          string              `json:"source,omitempty"`
	Method          string              `json:"method"`
	Scheme          string              `json:"scheme,omitempty"`
	Authority       string              `json:"authority,omitempty"`
	Path            string              `json:"path"`
	Query           string              `json:"query,omitempty"`
	Headers         map[string][]string `json:"headers,omitempty"`
	BodyForwarded   bool                `json:"body_forwarded,omitempty"`
	Body            []byte              `json:"body,omitempty"`
	BodyTruncated   bool                `json:"body_truncated,omitempty"`
	Client          struct {
		IP        string `json:"ip,omitempty"`
		UserAgent string `json:"user_agent,omitempty"`
	} `json:"client,omitempty"`
}

// Decision is the adapter response contract.
type Decision struct {
	ContractVersion string            `json:"contract_version"`
	Action          string            `json:"action"`
	StatusCode      int               `json:"status_code,omitempty"`
	Reason          string            `json:"reason,omitempty"`
	RuleID          string            `json:"rule_id,omitempty"`
	PolicyVersion   string            `json:"policy_version,omitempty"`
	Headers         map[string]string `json:"headers,omitempty"`
	Metadata        map[string]string `json:"metadata,omitempty"`
}

// Options wires the endpoint to the site registry and the live detection
// pipeline. ResolveSite must return false for unknown hosts.
type Options struct {
	ResolveSite  func(host string) (siteID string, maxBodyBytes int64, ok bool)
	Detect       func(context.Context, *engine.RequestContext) (*engine.DetectionResult, error)
	MaxBodyBytes int64
}

// Handler serves POST /api/v1/adapter/inspect.
type Handler struct {
	opts Options
}

// New returns an adapter inspection handler. It never mutates the incoming
// request and never forwards it to an origin.
func New(opts Options) *Handler {
	if opts.MaxBodyBytes <= 0 {
		opts.MaxBodyBytes = DefaultMaxBodyBytes
	}
	return &Handler{opts: opts}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeDecision(w, Decision{ContractVersion: ContractVersion, Action: "block", StatusCode: http.StatusMethodNotAllowed, Reason: "method not allowed"})
		return
	}
	if h == nil || h.opts.ResolveSite == nil || h.opts.Detect == nil {
		writeDecision(w, Decision{ContractVersion: ContractVersion, Action: "block", StatusCode: http.StatusServiceUnavailable, Reason: "adapter inspection is not configured"})
		return
	}
	var req Request
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxJSONBodyBytes))
	if err := decoder.Decode(&req); err != nil {
		writeDecision(w, Decision{ContractVersion: ContractVersion, Action: "block", StatusCode: http.StatusBadRequest, Reason: "invalid inspection request"})
		return
	}
	if req.ContractVersion != "" && req.ContractVersion != ContractVersion {
		writeDecision(w, Decision{ContractVersion: ContractVersion, Action: "block", StatusCode: http.StatusBadRequest, Reason: "unsupported contract version"})
		return
	}
	if req.Method == "" || req.Path == "" || !strings.HasPrefix(req.Path, "/") || strings.ContainsAny(req.Path, "\r\n") {
		writeDecision(w, Decision{ContractVersion: ContractVersion, Action: "block", StatusCode: http.StatusBadRequest, Reason: "invalid method or path"})
		return
	}
	normalizedPath, pathOK := engine.NormalizeRequestPath(req.Path)
	if !pathOK {
		writeDecision(w, Decision{ContractVersion: ContractVersion, Action: "block", StatusCode: http.StatusBadRequest, Reason: "invalid request path"})
		return
	}
	if req.BodyTruncated || int64(len(req.Body)) > h.opts.MaxBodyBytes {
		writeDecision(w, Decision{ContractVersion: ContractVersion, Action: "block", StatusCode: http.StatusRequestEntityTooLarge, Reason: "request body exceeds inspection limit"})
		return
	}
	host := req.Authority
	siteID, siteMax, ok := h.opts.ResolveSite(host)
	if !ok {
		writeDecision(w, Decision{ContractVersion: ContractVersion, Action: "block", StatusCode: http.StatusBadRequest, Reason: "unknown site"})
		return
	}
	if siteMax > 0 && int64(len(req.Body)) > siteMax {
		writeDecision(w, Decision{ContractVersion: ContractVersion, Action: "block", StatusCode: http.StatusRequestEntityTooLarge, Reason: "request body exceeds site limit"})
		return
	}
	scheme := req.Scheme
	if scheme == "" {
		scheme = "https"
	}
	target := &url.URL{Scheme: scheme, Host: host, Path: normalizedPath, RawQuery: req.Query}
	outReq := &http.Request{
		Method: req.Method, URL: target, Host: host, Header: make(http.Header),
		Body: io.NopCloser(strings.NewReader(string(req.Body))), ContentLength: int64(len(req.Body)),
		RemoteAddr: req.Client.IP,
	}
	for key, values := range req.Headers {
		for _, value := range values {
			outReq.Header.Add(key, value)
		}
	}
	reqCtx, err := engine.NewRequestContextDeferredBody(outReq, siteID, nil, siteMax)
	if err != nil {
		writeDecision(w, Decision{ContractVersion: ContractVersion, Action: "block", StatusCode: http.StatusBadRequest, Reason: "invalid inspection request"})
		return
	}
	reqCtx.NormalizedPath = normalizedPath
	reqCtx.ClientIP = req.Client.IP
	reqCtx.TraceID = req.RequestID
	if err := reqCtx.EnsureBody(); err != nil {
		writeDecision(w, Decision{ContractVersion: ContractVersion, Action: "block", StatusCode: http.StatusBadRequest, Reason: "request body could not be inspected"})
		return
	}
	result, err := h.opts.Detect(r.Context(), reqCtx)
	if err != nil {
		writeDecision(w, Decision{ContractVersion: ContractVersion, Action: "block", StatusCode: http.StatusServiceUnavailable, Reason: "inspection unavailable"})
		return
	}
	decision := Decision{ContractVersion: ContractVersion, Action: "allow", StatusCode: http.StatusNoContent}
	if result != nil && result.Detected {
		decision.Reason = result.Message
		decision.RuleID = result.DetectorID
		switch result.Action {
		case engine.ActionBlock:
			decision.Action = "block"
			decision.StatusCode = http.StatusForbidden
		case engine.ActionChallenge:
			decision.Action = "challenge"
			decision.StatusCode = http.StatusForbidden
		case engine.ActionLog:
			decision.Action = "log"
			decision.StatusCode = http.StatusNoContent
		}
	}
	writeDecision(w, decision)
}

func writeDecision(w http.ResponseWriter, decision Decision) {
	// 204 forbids a response body, and the admin caller needs the decision.
	// The gateway status stays in decision.status_code.
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-CheeseWAF-Decision", decision.Action)
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(decision)
}
