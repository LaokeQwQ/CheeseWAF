// Package engine defines core interfaces for the WAF detection pipeline.
package engine

import (
	"context"
	"net/http"
)

// Action represents the action to take when a detection matches.
// 检测匹配后的动作。
type Action int

const (
	// ActionPass allows the request to continue. 放行请求。
	ActionPass Action = iota
	// ActionBlock blocks the request. 拦截请求。
	ActionBlock
	// ActionChallenge presents a challenge (JS/CAPTCHA). 发起人机验证。
	ActionChallenge
	// ActionLog logs the request but allows it. 仅记录，不拦截。
	ActionLog
)

// Severity represents the severity level of a detection.
// 检测的严重程度。
type Severity int

const (
	SeverityInfo     Severity = iota // 信息
	SeverityLow                      // 低
	SeverityMedium                   // 中
	SeverityHigh                     // 高
	SeverityCritical                 // 严重
)

// DetectionResult holds the result of a single detector's analysis.
// 单个检测器的分析结果。
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
// 承载当前 HTTP 请求在检测流水线中流转的所有信息。
type RequestContext struct {
	Request     *http.Request     // 原始 HTTP 请求 / Original HTTP request
	ClientIP    string            // 客户端真实 IP / Real client IP
	TraceID     string            // 溯源 ID / Trace ID for block pages
	SiteID      string            // 站点 ID / Site identifier
	DecodedURI  string            // 解码后的 URI / Decoded URI
	DecodedBody []byte            // 解码后的请求体 / Decoded request body
	Results     []DetectionResult // 检测结果集合 / Detection results
	Metadata    map[string]any    // 扩展元数据 / Extension metadata
}

// Detector is the core interface for all WAF detection modules.
// Each layer in the detection pipeline implements this interface.
// 所有 WAF 检测模块的核心接口，检测流水线的每一层都实现此接口。
type Detector interface {
	// ID returns the unique identifier for this detector.
	// 返回检测器的唯一标识。
	ID() string

	// Name returns a human-readable name.
	// 返回人类可读的名称。
	Name() string

	// Detect analyzes the request context and returns detection results.
	// 分析请求上下文并返回检测结果。
	Detect(ctx context.Context, reqCtx *RequestContext) (*DetectionResult, error)

	// Priority returns the execution order (lower = earlier).
	// 返回执行优先级（数值越小越先执行）。
	Priority() int
}
