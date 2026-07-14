package semantic

import (
	"context"
	"net/url"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine/decoder"
)

const (
	maxSQLCandidateTexts = 2048
	maxSQLCandidateBytes = 8192
	sqlCandidateOverlap  = 256
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

func (d *SQLDetector) Detect(ctx context.Context, reqCtx *engine.RequestContext) (*engine.DetectionResult, error) {
	for _, candidate := range sqlCandidateTexts(reqCtx) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		// libinjection-style deep tokenization first (fast, high precision)
		if fp, detected := engine.SQLLibinjectionFingerprint(candidate); detected {
			return &engine.DetectionResult{
				Detected:   true,
				DetectorID: d.ID(),
				Category:   "sqli",
				Severity:   engine.SeverityHigh,
				Action:     actionForMode(d.mode),
				Message:    "SQL injection token fingerprint matched: " + truncate(fp, 40),
				Confidence: 0.92,
				Payload:    candidate,
			}, nil
		}
		// Fallback to signature-based detection
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

func sqlCandidateTexts(reqCtx *engine.RequestContext) []string {
	seen := map[string]struct{}{}
	candidates := make([]string, 0, 8)
	addRaw := func(text string) {
		if len(candidates) >= maxSQLCandidateTexts {
			return
		}
		text = strings.TrimSpace(text)
		if text == "" {
			return
		}
		if _, ok := seen[text]; ok {
			return
		}
		seen[text] = struct{}{}
		candidates = append(candidates, text)
	}
	addVariants := func(text string) {
		for _, segment := range sqlCandidateSegments(text) {
			addRaw(segment)
			for _, decoded := range decoder.DecodeAll(segment) {
				addRaw(decoded.Text)
				if b64, ok := decoder.TryBase64(strings.TrimSpace(decoded.Text)); ok {
					addRaw(b64)
				}
			}
		}
	}

	addVariants(requestText(reqCtx))
	if reqCtx == nil || reqCtx.Request == nil {
		return candidates
	}
	for _, values := range reqCtx.Request.URL.Query() {
		for _, value := range values {
			addVariants(value)
		}
	}
	contentType := strings.ToLower(reqCtx.Request.Header.Get("Content-Type"))
	if strings.Contains(contentType, "application/x-www-form-urlencoded") {
		if values, err := url.ParseQuery(string(reqCtx.DecodedBody)); err == nil {
			for _, items := range values {
				for _, value := range items {
					addVariants(value)
				}
			}
		}
	}
	return candidates
}

func sqlCandidateSegments(text string) []string {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil
	}
	if len(text) <= maxSQLCandidateBytes {
		return []string{text}
	}
	segments := make([]string, 0, (len(text)/maxSQLCandidateBytes)+1)
	step := maxSQLCandidateBytes - sqlCandidateOverlap
	for start := 0; start < len(text); start += step {
		end := start + maxSQLCandidateBytes
		if end > len(text) {
			end = len(text)
		}
		segment := strings.TrimSpace(text[start:end])
		if segment != "" {
			segments = append(segments, segment)
		}
		if end == len(text) {
			break
		}
	}
	return segments
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}

func looksLikeSQLi(raw string) (bool, string) {
	text := executableSQLText(raw)
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
	if sqlComment.MatchString(normalize(raw)) && (contains(words, "or") || contains(words, "union") || contains(words, "select") || strings.Contains(compact, "or1=1") || strings.Contains(compact, "unionselect")) {
		return true, "SQL comment sequence with executable query context matched"
	}
	if sqlOrderByInference.MatchString(text) {
		return true, "SQL ORDER/GROUP BY inference with comment matched"
	}
	if sqlHavingInference.MatchString(text) {
		return true, "SQL HAVING inference with comment matched"
	}
	if sqlRegexProbe.MatchString(text) && (contains(words, "and") || contains(words, "or") || strings.Contains(text, "database()") || strings.Contains(text, "version()") || strings.Contains(text, "user()")) {
		return true, "SQL regex or LIKE inference probe matched"
	}
	if sqlProcedureAnalyse.MatchString(text) {
		return true, "MySQL PROCEDURE ANALYSE enumeration primitive matched"
	}
	if sqlTimeFunction.MatchString(text) {
		return true, "SQL time-delay primitive matched"
	}
	if sqlDialectTimeFunction.MatchString(text) && sqlExecutionContext(text, compact) {
		return true, "SQL dialect-specific time-delay primitive matched"
	}
	if sqlDangerousFunc.MatchString(text) && sqlExecutionContext(text, compact) {
		return true, "SQL dialect-specific command or network side effect matched"
	}
	if sqlErrorFunction.MatchString(text) && (contains(words, "select") || contains(words, "concat") || strings.Contains(compact, "select")) {
		return true, "error-based SQL function with query composition matched"
	}
	if sqlStringFunction.MatchString(text) && sqlComparison.MatchString(text) && (contains(words, "or") || contains(words, "and") || strings.Contains(compact, "orchar") || strings.Contains(compact, "andchar")) {
		return true, "SQL function comparison inside boolean predicate matched"
	}
	return false, ""
}

func sqlExecutionContext(text, compact string) bool {
	return strings.Contains(text, "'") ||
		strings.Contains(text, ";") ||
		strings.Contains(text, "--") ||
		strings.Contains(text, "/*") ||
		strings.Contains(text, " select ") ||
		strings.Contains(text, " exec ") ||
		strings.Contains(text, " execute ") ||
		strings.Contains(text, " begin ") ||
		strings.Contains(text, " declare ") ||
		strings.Contains(compact, "unionselect") ||
		strings.Contains(compact, "or1=1")
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
