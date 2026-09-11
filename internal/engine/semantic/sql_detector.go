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
	maxSQLPayloadBytes   = 512
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
		// Deep tokenization first (fast, high precision; libinjection-compatible)
		if fp, detected := engine.SQLLibinjectionFingerprint(candidate); detected {
			fingerprintAllowed := true
			// The nc token also describes ordinary numeric URL slugs such as
			// "123--phone". Require a SQL-shaped line-comment terminator before
			// treating this low-context fingerprint as executable input.
			if strings.Contains(fp, "nc") && strings.Contains(candidate, "--") && !hasSQLNCSemanticContext(candidate) {
				fingerprintAllowed = false
			}
			if strings.Contains(fp, "o(") && !hasSQLOperatorSubqueryContext(candidate) {
				fingerprintAllowed = false
			}
			// EXEC/Ef fingerprints are useful for real stored-procedure payloads,
			// but the short token window also appears in SQL Server documentation.
			// Keep the same statement-boundary guard used by the staged analyzer.
			if (strings.Contains(fp, "Ew") || strings.Contains(fp, "Ef")) && !hasSQLExecFingerprintContext(candidate) {
				fingerprintAllowed = false
			}
			if fingerprintAllowed {
				return &engine.DetectionResult{
					Detected:   true,
					DetectorID: d.ID(),
					Category:   "sqli",
					Severity:   engine.SeverityHigh,
					Action:     actionForMode(d.mode),
					Message:    "SQL injection token fingerprint matched: " + truncate(fp, 40),
					Confidence: 0.92,
					Payload:    truncate(candidate, maxSQLPayloadBytes),
				}, nil
			}
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
				Payload:    truncate(candidate, maxSQLPayloadBytes),
			}, nil
		}
	}
	return nil, nil
}

func sqlCandidateTexts(reqCtx *engine.RequestContext) []string {
	// Dedup stays exact, but the map is only built once the candidate count makes
	// hashing cheaper than the linear compare it replaces. Ordinary requests
	// produce a handful of candidates and never allocate it, matching the
	// dedupMapThreshold policy already used by the analyzer's candidate path.
	var seen map[string]struct{}
	candidates := make([]string, 0, 8)
	addRaw := func(text string) {
		if len(candidates) >= maxSQLCandidateTexts {
			return
		}
		text = strings.TrimSpace(text)
		if text == "" {
			return
		}
		if seen == nil {
			for _, existing := range candidates {
				if existing == text {
					return
				}
			}
			if len(candidates)+1 >= dedupMapThreshold {
				seen = make(map[string]struct{}, 2*dedupMapThreshold)
				for _, existing := range candidates {
					seen[existing] = struct{}{}
				}
				seen[text] = struct{}{}
			}
			candidates = append(candidates, text)
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

// sqlSignatures are matched verbatim against the executable SQL projection.
// Hoisted to package scope so the slice header is static data rather than being
// rebuilt per call. Do not front this with a containsAny pre-filter: the loop
// below already short-circuits on the first hit, so a pre-filter costs a full
// redundant scan on hits and saves nothing on misses.
var sqlSignatures = []string{
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

func looksLikeSQLi(raw string) (bool, string) {
	text := executableSQLText(raw)
	if sqlQuotedAndSelectInjectionShape(text) {
		return true, "SQL quoted AND SELECT subquery predicate matched"
	}
	if sqlQuotedConcatSelectPredicate.MatchString(text) {
		return true, "SQL quoted concatenation SELECT predicate matched"
	}
	for _, sig := range sqlSignatures {
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
	if sqlComment.MatchString(normalize(raw)) && (contains(words, "or") || contains(words, "union") || contains(words, "select") || containsAny(compact, []string{"or1=1", "unionselect"})) {
		return true, "SQL comment sequence with executable query context matched"
	}
	if sqlOrderByInference.MatchString(text) {
		return true, "SQL ORDER/GROUP BY inference with comment matched"
	}
	if sqlHavingInference.MatchString(text) {
		return true, "SQL HAVING inference with comment matched"
	}
	if sqlRegexProbe.MatchString(text) && (contains(words, "and") || contains(words, "or") || containsAny(text, []string{"database()", "version()", "user()"})) {
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
	if sqlErrorFunction.MatchString(text) && (contains(words, "select") || contains(words, "concat") || containsAny(compact, []string{"select"})) {
		return true, "error-based SQL function with query composition matched"
	}
	if sqlStringFunction.MatchString(text) && sqlComparison.MatchString(text) && (contains(words, "or") || contains(words, "and") || containsAny(compact, []string{"orchar", "andchar"})) {
		return true, "SQL function comparison inside boolean predicate matched"
	}
	return false, ""
}

func sqlExecutionContext(text, compact string) bool {
	return containsAny(text, sqlCommonNeedles) || containsAny(compact, sqlCompactNeedles)
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
