// Package engine defines core interfaces for the WAF detection pipeline.
package engine

import (
	"context"
	"io"
	"net/http"
	"sync"
	"time"
)

// Action represents the action to take when a detection matches.
// Action taken after a detection match.
type Action int

const (
	// ActionPass allows the request to continue.
	ActionPass Action = iota
	// ActionBlock blocks the request.
	ActionBlock
	// ActionChallenge presents a challenge (JS/CAPTCHA).
	ActionChallenge
	// ActionLog logs the request but allows it.
	ActionLog
)

// Severity represents the severity level of a detection.
// Detection severity.
type Severity int

const (
	SeverityInfo     Severity = iota // 信息
	SeverityLow                      // 低
	SeverityMedium                   // 中
	SeverityHigh                     // 高
	SeverityCritical                 // 严重
)

// DetectionResult holds the result of a single detector's analysis.
// Analysis result from a single detector.
type DetectionResult struct {
	Detected   bool     `json:"detected"`    // 是否检测到威胁 / Whether a threat was detected
	DetectorID string   `json:"detector_id"` // 检测器标识 / Detector identifier
	Category   string   `json:"category"`    // 攻击类别 (sqli/xss/rce/lfi...) / Attack category
	Severity   Severity `json:"severity"`    // 严重程度 / Severity level
	Action     Action   `json:"action"`      // 建议动作 / Recommended action
	Message    string   `json:"message"`     // 人类可读描述 / Human-readable description
	Confidence float64  `json:"confidence"`  // 置信度 0.0-1.0 / Confidence score
	Payload    string   `json:"payload"`     // 触发的恶意载荷 / Malicious payload that triggered detection
}

// RequestContext carries all information about the current HTTP request
// through the detection pipeline.
// Carries all state for the current HTTP request through the detection pipeline.
type RequestContext struct {
	Request  *http.Request // 原始 HTTP 请求 / Original HTTP request
	ClientIP string        // 客户端真实 IP / Real client IP
	TraceID  string        // 溯源 ID / Trace ID for block pages
	SiteID   string        // 站点 ID / Site identifier
	// NormalizedPath is the canonical path used by security policies.
	NormalizedPath string
	// HostValidated is true only after the caller has matched Request.Host to
	// an allowed site/tenant. Request-aware same-origin optimizations must not
	// trust a raw, attacker-controlled Host value without this provenance.
	HostValidated bool
	// TrustedProxyCIDRs carries the immutable proxy trust scope used for
	// request-aware protocol decisions (for example X-Forwarded-Proto).
	TrustedProxyCIDRs []string
	DecodedURI        string            // 解码后的 URI / Decoded URI
	DecodedBody       []byte            // 解码后的请求体 / Decoded request body
	Results           []DetectionResult // 检测结果集合 / Detection results
	Metadata          map[string]any    // 扩展元数据 / Extension metadata

	// Lazy body fields (hot path): body is not read until EnsureBody.
	// bodyMu also protects the immutable snapshots used when semantic detector
	// forks are created. Detectors must treat DecodedBody as read-only.
	bodyMu              sync.Mutex
	maxBodyBytes        int64
	bodyLoaded          bool
	rawBody             []byte
	bodyErr             error
	bodyReadDone        chan struct{}
	bodyReadBody        io.ReadCloser
	bodyCloseOnce       *sync.Once
	bodyReservation     int64
	bodyReservationHeld bool
	bodyReadProgress    time.Time
	bodyReadIdleTimeout time.Duration
	bodyReadAbort       chan struct{}
}

// Detector is the core interface for all WAF detection modules.
// Each layer in the detection pipeline implements this interface.
// Core interface for every WAF detection module; each pipeline layer implements it.
type Detector interface {
	// ID returns the unique identifier for this detector.
	// Returns the unique detector identifier.
	ID() string

	// Name returns a human-readable name.
	// Returns a human-readable name.
	Name() string

	// Detect analyzes the request context and returns detection results.
	// Analyzes the request context and returns a detection result.
	Detect(ctx context.Context, reqCtx *RequestContext) (*DetectionResult, error)

	// Priority returns the execution order (lower = earlier).
	// Returns the execution priority (lower runs earlier).
	Priority() int
}
