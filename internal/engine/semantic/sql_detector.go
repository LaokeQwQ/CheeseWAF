package semantic

import (
	"context"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine/decoder"
)

type SQLDetector struct {
	mode string
}

func NewSQLDetector(mode string) *SQLDetector {
	if mode == "" {
		mode = "block"
	}
	return &SQLDetector{mode: mode}
}

func (d *SQLDetector) ID() string    { return "semantic.sql" }
func (d *SQLDetector) Name() string  { return "SQL Injection Semantic Detector" }
func (d *SQLDetector) Priority() int { return 300 }

func (d *SQLDetector) Detect(_ context.Context, reqCtx *engine.RequestContext) (*engine.DetectionResult, error) {
	payload := requestText(reqCtx)
	decoded := decoder.Decode(payload).Text
	candidates := []string{payload, decoded}
	if b64, ok := decoder.TryBase64(decoded); ok {
		candidates = append(candidates, b64)
	}
	for _, candidate := range candidates {
		if detected, reason := looksLikeSQLi(candidate); detected {
			return &engine.DetectionResult{
				Detected:   true,
				DetectorID: d.ID(),
				Category:   "sqli",
				Severity:   engine.SeverityHigh,
				Action:     actionForMode(d.mode),
				Message:    reason,
				Confidence: 0.88,
				Payload:    candidate,
			}, nil
		}
	}
	return nil, nil
}

func looksLikeSQLi(raw string) (bool, string) {
	text := normalize(raw)
	signatures := []string{
		"' or '1'='1",
		"\" or \"1\"=\"1",
		" union select ",
		" union all select ",
		" sleep(",
		" benchmark(",
		" pg_sleep(",
		" information_schema",
		" or 1=1",
		" and 1=1",
		"--",
		"/*",
	}
	for _, sig := range signatures {
		if strings.Contains(text, sig) {
			return true, "SQL injection signature matched: " + strings.TrimSpace(sig)
		}
	}
	words := tokens(text)
	hasUnion := contains(words, "union")
	hasSelect := contains(words, "select")
	hasDrop := contains(words, "drop")
	hasTable := contains(words, "table")
	if hasUnion && hasSelect {
		return true, "SQL injection keyword sequence matched"
	}
	if hasDrop && hasTable {
		return true, "destructive SQL keyword sequence matched"
	}
	compact := compactSQL(text)
	if sqlErrorFunction.MatchString(text) && (contains(words, "select") || contains(words, "concat") || strings.Contains(compact, "select")) {
		return true, "error-based SQL function with query composition matched"
	}
	if sqlStringFunction.MatchString(text) && sqlComparison.MatchString(text) && (contains(words, "or") || contains(words, "and") || strings.Contains(compact, "orchar") || strings.Contains(compact, "andchar")) {
		return true, "SQL function comparison inside boolean predicate matched"
	}
	return false, ""
}

func requestText(reqCtx *engine.RequestContext) string {
	if reqCtx == nil || reqCtx.Request == nil {
		return ""
	}
	var builder strings.Builder
	builder.WriteString(reqCtx.Request.URL.RequestURI())
	builder.WriteByte(' ')
	builder.WriteString(reqCtx.Request.Header.Get("User-Agent"))
	builder.WriteByte(' ')
	builder.Write(reqCtx.DecodedBody)
	return builder.String()
}

func contains(items []string, needle string) bool {
	for _, item := range items {
		if item == needle {
			return true
		}
	}
	return false
}

func actionForMode(mode string) engine.Action {
	switch mode {
	case "monitor":
		return engine.ActionLog
	case "off":
		return engine.ActionPass
	default:
		return engine.ActionBlock
	}
}
