package semantic

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf16"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine/decoder"
)

type Analyzer struct {
	mode    string
	enabled map[string]bool
	// catFP is a precomputed fingerprint of enabled categories for cache keys.
	catFP uint64
	// pathAllowlist skips full semantic analysis for matching request paths
	// (exact or trailing-* prefix). Commercial FP ops control surface.
	pathAllowlist []string
	// paramAllowlist skips query/form/json/cookie fields by parameter name
	// (case-insensitive). Does not skip path/uri or headers.
	paramAllowlist map[string]struct{}
}

type InputPoint struct {
	Source string   `json:"source"`
	Name   string   `json:"name"`
	Raw    string   `json:"raw"`
	Layers []string `json:"layers"`
}

type AnalysisReport struct {
	Inputs       []InputPoint `json:"inputs"`
	Hits         []Hit        `json:"hits"`
	AnomalyScore int          `json:"anomaly_score,omitempty"`
	AnomalyNotes []string     `json:"anomaly_notes,omitempty"`
}

type Hit struct {
	Category   string          `json:"category"`
	Source     string          `json:"source"`
	Name       string          `json:"name"`
	Syntax     string          `json:"syntax"`
	Semantics  string          `json:"semantics"`
	Severity   engine.Severity `json:"severity"`
	Confidence float64         `json:"confidence"`
	Payload    string          `json:"payload"`
}

type semanticCandidate struct {
	input InputPoint
	text  string
}

func NewAnalyzer(mode string, categories ...string) *Analyzer {
	if mode == "" {
		mode = "block"
	}
	enabled := map[string]bool{}
	if len(categories) == 0 {
		for _, category := range []string{"sqli", "xss", "rce", "lfi", "xxe", "ssrf", "nosqli", "ssti"} {
			enabled[category] = true
		}
	} else {
		for _, category := range categories {
			category = strings.ToLower(strings.TrimSpace(category))
			if category != "" {
				enabled[category] = true
			}
		}
	}
	return &Analyzer{mode: mode, enabled: enabled, catFP: enabledCategoryFingerprint(enabled)}
}

// SetAllowlists configures commercial path/param skip lists. Safe to call once
// after NewAnalyzer during pipeline build. Empty lists are no-ops.
func (a *Analyzer) SetAllowlists(paths, params []string) {
	if a == nil {
		return
	}
	a.pathAllowlist = normalizePathAllowlist(paths)
	a.paramAllowlist = normalizeParamAllowlist(params)
}

func (a *Analyzer) ID() string    { return "semantic.analyzer" }
func (a *Analyzer) Name() string  { return "Staged Semantic Analyzer" }
func (a *Analyzer) Priority() int { return 290 }

func (a *Analyzer) Detect(ctx context.Context, reqCtx *engine.RequestContext) (*engine.DetectionResult, error) {
	if reqCtx == nil || reqCtx.Request == nil || a.mode == "off" {
		return nil, nil
	}
	start := time.Now()
	outcome, category := OutcomePass, ""
	defer func() {
		ProcessMetrics().RecordAnalysis(time.Since(start), outcome, category)
	}()

	if pathAllowlisted(reqCtx.Request.URL.Path, a.pathAllowlist) {
		if reqCtx.Metadata == nil {
			reqCtx.Metadata = map[string]any{}
		}
		reqCtx.Metadata["semantic_skipped"] = "path_allowlist"
		ProcessMetrics().RecordAllowlistSkip("path")
		return nil, nil
	}

	candidates := a.filterAllowlistedCandidates(extractCandidates(reqCtx))
	report, best, incomplete := a.analyzeAllCandidates(ctx, candidates)
	if reqCtx.Metadata == nil {
		reqCtx.Metadata = map[string]any{}
	}
	reqCtx.Metadata["semantic_analysis"] = report
	if report.AnomalyScore > 0 {
		reqCtx.Metadata["semantic_anomaly_score"] = report.AnomalyScore
	}
	// Only when scanning was cut short by deadline — not a finished pass that
	// merely races the timer after returning.
	if incomplete {
		reqCtx.Metadata["semantic_analysis_incomplete"] = true
	}
	if best == nil {
		return nil, nil
	}
	action := actionForMode(a.mode)
	if a.mode == "block" && !blockableHit(*best) {
		return nil, nil
	}
	if action == engine.ActionBlock {
		outcome = OutcomeBlock
	} else {
		outcome = OutcomeHit
	}
	category = best.Category
	return &engine.DetectionResult{
		Detected:   true,
		DetectorID: a.ID() + "." + best.Category,
		Category:   best.Category,
		Severity:   best.Severity,
		Action:     action,
		Message:    best.Syntax + "; " + best.Semantics,
		Confidence: best.Confidence,
		Payload:    best.Payload,
	}, nil
}

// analyzeAllCandidates runs field analysis. Multi-field requests use a bounded
// worker pool so multi-core CPUs scan independent parameters concurrently while
// preserving FP-first merge rules and stable Input ordering.
// incomplete is true only when the context cancelled mid-scan (fields skipped).
func (a *Analyzer) analyzeAllCandidates(ctx context.Context, candidates []semanticCandidate) (AnalysisReport, *Hit, bool) {
	report := AnalysisReport{Inputs: make([]InputPoint, 0, len(candidates))}
	if len(candidates) == 0 {
		return report, nil, false
	}

	type fieldOut struct {
		input InputPoint
		hits  []Hit
	}

	// Sequential for tiny requests (lower scheduling overhead).
	if len(candidates) < 3 {
		var best *Hit
		anomalyScore := 0
		var anomalyNotes []string
		incomplete := false
		for _, candidate := range candidates {
			if err := ctx.Err(); err != nil {
				incomplete = true
				break
			}
			report.Inputs = append(report.Inputs, candidate.input)
			hits := a.analyzeCandidate(candidate)
			for _, next := range hits {
				if note, pts := anomalyContribution(next); pts > 0 {
					anomalyScore += pts
					if len(anomalyNotes) < 8 {
						anomalyNotes = append(anomalyNotes, note)
					}
				}
				if a.mode == "block" && !blockableHit(next) {
					continue
				}
				report.Hits = append(report.Hits, next)
				if best == nil || betterHit(next, *best) {
					next := next
					best = &next
				}
			}
			if a.mode == "block" && best != nil && best.Severity >= engine.SeverityCritical && best.Confidence >= 0.92 {
				break
			}
		}
		if anomalyScore > 0 {
			report.AnomalyScore = anomalyScore
			report.AnomalyNotes = anomalyNotes
		}
		return report, best, incomplete
	}

	outs := make([]fieldOut, len(candidates))
	workers := runtime.GOMAXPROCS(0)
	if workers > 8 {
		workers = 8
	}
	if workers > len(candidates) {
		workers = len(candidates)
	}
	if workers < 1 {
		workers = 1
	}
	// Atomic work-stealing index avoids per-request channel alloc/scheduling.
	var next atomic.Int64
	var skipped atomic.Bool
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := int(next.Add(1) - 1)
				if i >= len(candidates) {
					return
				}
				if ctx.Err() != nil {
					outs[i] = fieldOut{input: candidates[i].input}
					skipped.Store(true)
					continue
				}
				hits := a.analyzeCandidate(candidates[i])
				outs[i] = fieldOut{input: candidates[i].input, hits: hits}
			}
		}()
	}
	wg.Wait()

	var best *Hit
	anomalyScore := 0
	var anomalyNotes []string
	for i := range outs {
		report.Inputs = append(report.Inputs, outs[i].input)
		for _, next := range outs[i].hits {
			if note, pts := anomalyContribution(next); pts > 0 {
				anomalyScore += pts
				if len(anomalyNotes) < 8 {
					anomalyNotes = append(anomalyNotes, note)
				}
			}
			if a.mode == "block" && !blockableHit(next) {
				continue
			}
			report.Hits = append(report.Hits, next)
			if best == nil || betterHit(next, *best) {
				next := next
				best = &next
			}
		}
	}
	if anomalyScore > 0 {
		report.AnomalyScore = anomalyScore
		report.AnomalyNotes = anomalyNotes
	}
	return report, best, skipped.Load()
}

// anomalyContribution scores weak/strong signals for CRS-like anomaly observability.
// It NEVER decides block/pass by itself — blockableHit remains the only gate.
func anomalyContribution(h Hit) (string, int) {
	if h.Category == "" {
		return "", 0
	}
	pts := 2
	if h.Severity >= engine.SeverityCritical {
		pts = 5
	} else if h.Severity >= engine.SeverityHigh {
		pts = 3
	}
	if h.Confidence >= 0.9 {
		pts++
	}
	note := h.Category
	if h.Name != "" {
		note = h.Category + ":" + h.Name
	}
	return note, pts
}

func (a *Analyzer) analyzeCandidate(candidate semanticCandidate) []Hit {
	// Ultra-cheap prefilter before any hash/lock: ordinary ids/slugs/versions.
	// Not cached — hashing + shard lock costs more than the byte scan itself.
	if looksCleanASCIIField(candidate.text) {
		return nil
	}

	key := candidateCacheKey(a.mode, a.catFP, candidate.text)
	if cached, ok := processCandidateCache.get(key); ok {
		ProcessMetrics().RecordCache(true)
		return cached
	}
	ProcessMetrics().RecordCache(false)

	guesses := guessCategories(candidate.text)
	if len(guesses) == 0 {
		processCandidateCache.put(key, nil)
		return nil
	}
	var hits []Hit
	for _, category := range guesses {
		if !a.enabled[category] {
			continue
		}
		if hit, ok := analyzeSyntaxAndSemantics(category, candidate); ok {
			hits = append(hits, hit)
		}
	}
	processCandidateCache.put(key, hits)
	return hits
}

// looksCleanASCIIField is a pure-Go hot-path prefilter for ordinary business
// identifiers (ids, slugs, versions). Multi-word text, hidden files (.env),
// schemes, and paths never short-circuit — prefer miss risk is zero.
func looksCleanASCIIField(raw string) bool {
	if len(raw) == 0 || len(raw) > 48 {
		return false
	}
	// Multi-word values (including "pwsh -EncodedCommand …") need full analysis.
	if strings.Contains(raw, " ") || strings.Contains(raw, "\t") {
		return false
	}
	// Sensitive basenames look "clean" but must reach LFI detectors (wp-config.php, .env).
	if looksSensitiveFilename(raw) {
		return false
	}
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			continue
		case c == '-' || c == '_':
			continue
		case c == '.':
			// Allow version-like "1.2.3" / "v1.0" but not ".env" / "file.."
			if i == 0 || i == len(raw)-1 {
				return false
			}
			continue
		default:
			return false
		}
	}
	return true
}

func looksSensitiveFilename(raw string) bool {
	lower := strings.ToLower(raw)
	if strings.Contains(lower, "wp-config") || strings.Contains(lower, "id_rsa") ||
		strings.Contains(lower, "passwd") || strings.Contains(lower, "shadow") ||
		strings.Contains(lower, "credentials") || strings.Contains(lower, ".aws") ||
		strings.Contains(lower, ".git") || strings.Contains(lower, ".ssh") ||
		strings.Contains(lower, ".env") || strings.Contains(lower, "htaccess") ||
		strings.Contains(lower, "web.xml") || strings.Contains(lower, "dump.sql") ||
		strings.Contains(lower, "database.sql") {
		return true
	}
	for _, suf := range []string{".php", ".asp", ".aspx", ".jsp", ".cgi", ".ini", ".conf", ".cfg", ".yml", ".yaml", ".sql", ".pem", ".key", ".env"} {
		if strings.HasSuffix(lower, suf) {
			return true
		}
	}
	return false
}

func betterHit(candidate, current Hit) bool {
	candidatePriority := categoryPriority(candidate)
	currentPriority := categoryPriority(current)
	if candidatePriority != currentPriority {
		return candidatePriority > currentPriority
	}
	if candidate.Confidence != current.Confidence {
		return candidate.Confidence > current.Confidence
	}
	return candidate.Severity > current.Severity
}

func categoryPriority(hit Hit) int {
	payload := normalize(hit.Payload)
	decodedPayload := normalize(decoder.Decode(hit.Payload).Text)
	payloadContext := payload + " " + decodedPayload
	context := strings.ToLower(hit.Syntax + " " + hit.Semantics)
	switch hit.Category {
	case "xxe":
		if strings.Contains(payload, "<!doctype") || strings.Contains(payload, "<!entity") ||
			strings.Contains(payload, "xinclude") || strings.Contains(payload, "xi:include") {
			return 95
		}
		return 70
	case "ssrf":
		if strings.Contains(payload, `"url"`) ||
			strings.Contains(payload, "url=") ||
			strings.Contains(hit.Name, "url") ||
			strings.Contains(hit.Name, "uri") ||
			strings.Contains(payload, "/fetch") ||
			strings.Contains(context, "server-side request") ||
			strings.Contains(context, "fetch") {
			return 90
		}
		return 65
	case "rce":
		if strings.Contains(payloadContext, "xp_cmdshell") ||
			strings.Contains(payloadContext, "into outfile") ||
			strings.Contains(payloadContext, "load_file") ||
			strings.Contains(context, "sql server") ||
			strings.Contains(context, "database") {
			return 74
		}
		if rceExecutionSink(hit.Name) {
			return 85
		}
		if strings.Contains(payload, "cmd=") ||
			strings.Contains(payload, "command=") ||
			strings.Contains(payload, "exec=") ||
			rceWhitespaceEvasion.MatchString(payload) ||
			rceInterpreterInline.MatchString(payload) ||
			rcePowerShellSideFx.MatchString(payload) ||
			rceDownloadExecChain.MatchString(payload) ||
			rceReverseShellPrimitive.MatchString(payload) ||
			strings.Contains(context, "download-to-shell") ||
			strings.Contains(context, "reverse connection") ||
			strings.Contains(context, "interpreter inline") {
			return 85
		}
		return 55
	case "lfi":
		if strings.Contains(context, "file") ||
			strings.Contains(payload, "../") ||
			strings.Contains(payload, `..\`) ||
			lfiSensitiveTarget.MatchString(payload) ||
			lfiFileReadSink.MatchString(payload) ||
			lfiCommandReadSink.MatchString(payload) {
			return 80
		}
	case "sqli":
		if strings.Contains(context, "database") ||
			strings.Contains(context, "union select") ||
			strings.Contains(context, "query composition") ||
			strings.Contains(context, "boolean predicate") ||
			strings.Contains(context, "query grammar") ||
			strings.Contains(context, "sql") {
			return 75
		}
		return 75
	case "ssti":
		return 60
	case "xss":
		return 50
	case "nosqli":
		return 45
	}
	return 0
}

const (
	maxInputRawBytes  = 16 << 10 // 16 KiB per field
	maxCandidates     = 64
	maxDecodeVariants = 8
	maxJSONNodes      = 200
	maxJSONDepth      = 8
)

func normalizePathAllowlist(paths []string) []string {
	if len(paths) == 0 {
		return nil
	}
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return out
}

func normalizeParamAllowlist(params []string) map[string]struct{} {
	if len(params) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(params))
	for _, p := range params {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" {
			continue
		}
		out[p] = struct{}{}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// pathAllowlisted reports whether request path matches any allowlist rule.
// Rules: exact match, directory prefix, or trailing-* prefix (prefix must be non-empty).
// Bare "*" / empty rules never match (would disable semantic scanning site-wide).
func pathAllowlisted(path string, rules []string) bool {
	if path == "" || len(rules) == 0 {
		return false
	}
	for _, rule := range rules {
		rule = strings.TrimSpace(rule)
		if rule == "" || rule == "*" {
			continue
		}
		if strings.HasSuffix(rule, "*") {
			prefix := strings.TrimSuffix(rule, "*")
			// Reject "*", "/*", and empty prefixes — those would skip all paths.
			if prefix == "" || prefix == "/" {
				continue
			}
			if strings.HasPrefix(path, prefix) {
				return true
			}
			continue
		}
		if path == rule {
			return true
		}
		// Directory prefix: "/admin" matches "/admin" and "/admin/..."
		if strings.HasPrefix(path, rule) && (len(path) == len(rule) || path[len(rule)] == '/') {
			return true
		}
	}
	return false
}

func (a *Analyzer) filterAllowlistedCandidates(candidates []semanticCandidate) []semanticCandidate {
	if a == nil || len(a.paramAllowlist) == 0 || len(candidates) == 0 {
		return candidates
	}
	kept := make([]semanticCandidate, 0, len(candidates))
	skipped := 0
	for _, c := range candidates {
		if paramAllowlisted(c.input.Source, c.input.Name, a.paramAllowlist) {
			skipped++
			continue
		}
		kept = append(kept, c)
	}
	if skipped > 0 {
		ProcessMetrics().RecordAllowlistSkip("param")
	}
	return kept
}

// paramAllowlisted skips query/form/json/cookie/multipart parameter names only.
func paramAllowlisted(source, name string, allow map[string]struct{}) bool {
	if len(allow) == 0 || name == "" {
		return false
	}
	src := strings.ToLower(source)
	// Accept both short sources and body.* sources used by extractCandidates.
	switch src {
	case "query", "form", "json", "cookie", "multipart",
		"body.form", "body.json", "body.multipart":
		// filename fields are stored as "field.filename" — allowlist the base param.
		base := strings.ToLower(name)
		if i := strings.Index(base, ".filename"); i > 0 {
			base = base[:i]
		}
		if _, ok := allow[base]; ok {
			return true
		}
		_, ok := allow[strings.ToLower(name)]
		return ok
	default:
		return false
	}
}

func extractCandidates(reqCtx *engine.RequestContext) []semanticCandidate {
	if reqCtx == nil || reqCtx.Request == nil {
		return nil
	}
	r := reqCtx.Request
	// Fast-path health/static probes: no query, no body, benign path → zero work.
	if isBenignProbePath(r.URL.Path) && r.URL.RawQuery == "" &&
		(r.Method == http.MethodGet || r.Method == http.MethodHead) &&
		len(reqCtx.DecodedBody) == 0 {
		return nil
	}

	inputs := make([]InputPoint, 0, 16)
	// Path only for ordinary traffic — avoid re-scanning the full RequestURI
	// (which previously doubled work with per-param query extraction).
	pathRaw := r.URL.EscapedPath()
	if pathRaw == "" {
		pathRaw = r.URL.Path
	}
	if pathRaw != "" && pathRaw != "/" {
		inputs = append(inputs, InputPoint{Source: "uri", Name: "path", Raw: clipRaw(pathRaw), Layers: []string{"raw"}})
	}
	queryValues := mergeQueryValues(r.URL.RawQuery, r.URL.Query())
	for key, values := range queryValues {
		inputs = append(inputs, InputPoint{Source: "query", Name: key, Raw: clipRaw(key), Layers: []string{"raw"}})
		for _, value := range values {
			inputs = append(inputs, InputPoint{Source: "query", Name: key, Raw: clipRaw(value), Layers: []string{"raw"}})
		}
	}
	// Suspicious raw query (shell glue) — keep a single fused candidate so
	// payloads that standard ParseQuery splits still get analyzed.
	if raw := r.URL.RawQuery; raw != "" && suspiciousRawQuery(raw) {
		inputs = append(inputs, InputPoint{Source: "uri", Name: "raw_query", Raw: clipRaw(raw), Layers: []string{"raw"}})
	}
	for key, values := range r.Header {
		if skipHeader(key) {
			continue
		}
		for _, value := range values {
			inputs = append(inputs, InputPoint{Source: "header", Name: key, Raw: clipRaw(value), Layers: []string{"raw"}})
		}
	}
	for _, cookie := range r.Cookies() {
		inputs = append(inputs, InputPoint{Source: "cookie", Name: cookie.Name, Raw: clipRaw(cookie.Value), Layers: []string{"raw"}})
	}
	inputs = append(inputs, bodyInputs(r, reqCtx.DecodedBody)...)

	candidates := make([]semanticCandidate, 0, len(inputs)+4)
	seen := make(map[string]struct{}, len(inputs)*2)
	for _, input := range inputs {
		if len(candidates) >= maxCandidates {
			break
		}
		for _, variant := range decodeVariants(input.Raw) {
			if len(candidates) >= maxCandidates {
				break
			}
			text := strings.TrimSpace(variant.text)
			if text == "" {
				continue
			}
			key := input.Source + "\x00" + input.Name + "\x00" + text
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			next := input
			next.Layers = variant.layers
			candidates = append(candidates, semanticCandidate{input: next, text: text})
		}
	}
	return candidates
}

// isBenignProbePath matches common health/static endpoints that should never
// pay for full semantic extraction when they have no query/body.
func isBenignProbePath(path string) bool {
	switch path {
	case "/health", "/healthz", "/ready", "/readyz", "/live", "/livez",
		"/metrics", "/favicon.ico", "/robots.txt", "/":
		return true
	default:
		return false
	}
}

func clipRaw(raw string) string {
	if len(raw) <= maxInputRawBytes {
		return raw
	}
	return raw[:maxInputRawBytes]
}

// mergeQueryValues combines standard and lenient query parsing so attack
// payloads with ';' / '&&' are not truncated while normal traffic stays cheap.
func mergeQueryValues(rawQuery string, parsed url.Values) url.Values {
	if rawQuery == "" {
		return parsed
	}
	needsLenient := len(parsed) == 0 ||
		strings.Contains(rawQuery, ";") ||
		strings.Contains(rawQuery, "&&") ||
		strings.Contains(rawQuery, "||") ||
		strings.Contains(rawQuery, "`") ||
		strings.Contains(rawQuery, "|")
	if !needsLenient {
		return parsed
	}
	lenient := lenientQueryValues(rawQuery)
	if len(parsed) == 0 {
		return lenient
	}
	// Prefer the longer value for each key (lenient usually preserves the payload).
	for k, vs := range lenient {
		if cur, ok := parsed[k]; !ok || valuesTotalLen(vs) > valuesTotalLen(cur) {
			parsed[k] = vs
		}
	}
	return parsed
}

func valuesTotalLen(vs []string) int {
	n := 0
	for _, v := range vs {
		n += len(v)
	}
	return n
}

func suspiciousRawQuery(raw string) bool {
	return strings.Contains(raw, ";") || strings.Contains(raw, "&&") ||
		strings.Contains(raw, "||") || strings.Contains(raw, "`") ||
		strings.Contains(raw, "%3B") || strings.Contains(raw, "%26%26") ||
		strings.Contains(raw, "%7C") || strings.Contains(raw, "$(") ||
		strings.Contains(raw, "%24(")
}

// lenientQueryValues parses query strings that net/url.ParseQuery refuses
// (notably values containing unescaped ';' used by many RCE/SQLi samples).
func lenientQueryValues(rawQuery string) url.Values {
	out := url.Values{}
	if rawQuery == "" {
		return out
	}
	parts := strings.FieldsFunc(rawQuery, func(r rune) bool { return r == '&' })
	// If there is no '&', still try a single key=value (value may contain ';').
	if len(parts) == 0 {
		parts = []string{rawQuery}
	}
	for _, part := range parts {
		if part == "" {
			continue
		}
		key, value, ok := strings.Cut(part, "=")
		if !ok {
			key, value = part, ""
		}
		if unescaped, err := url.QueryUnescape(key); err == nil {
			key = unescaped
		}
		if unescaped, err := url.QueryUnescape(value); err == nil {
			value = unescaped
		}
		if key == "" {
			continue
		}
		out.Add(key, value)
	}
	return out
}

func bodyInputs(r *http.Request, body []byte) []InputPoint {
	if len(body) == 0 {
		return nil
	}
	// charset=utf-16 bodies are often delivered as raw LE/BE bytes; convert before analysis.
	if ct := strings.ToLower(r.Header.Get("Content-Type")); strings.Contains(ct, "utf-16") {
		if decoded, ok := decodeUTF16Payload(string(body)); ok {
			body = []byte(decoded)
		}
	} else if decoded, ok := decodeUTF16Payload(string(body)); ok {
		// BOM-present bodies even without charset declaration (XXE evasion).
		body = []byte(decoded)
	}
	var inputs []InputPoint
	contentType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	switch contentType {
	case "application/x-www-form-urlencoded":
		values, err := url.ParseQuery(string(body))
		if err == nil {
			for key, list := range values {
				inputs = append(inputs, InputPoint{Source: "body.form", Name: key, Raw: key, Layers: []string{"raw"}})
				for _, value := range list {
					inputs = append(inputs, InputPoint{Source: "body.form", Name: key, Raw: value, Layers: []string{"raw"}})
				}
			}
			return inputs
		}
	case "application/json":
		flattenJSONInputs("body.json", "", body, &inputs)
		if len(inputs) > 0 {
			return inputs
		}
	case "multipart/form-data":
		if boundary := boundaryFromContentType(r.Header.Get("Content-Type")); boundary != "" {
			return multipartInputs(body, boundary)
		}
	}
	if json.Valid(body) {
		flattenJSONInputs("body.json", "", body, &inputs)
	}
	if len(inputs) == 0 {
		inputs = append(inputs, InputPoint{Source: "body.raw", Name: "body", Raw: string(body), Layers: []string{"raw"}})
	}
	return inputs
}

func flattenJSONInputs(source, prefix string, raw []byte, inputs *[]InputPoint) {
	var value any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return
	}
	nodes := 0
	flattenJSONValue(source, prefix, value, inputs, 0, &nodes)
}

func flattenJSONValue(source, prefix string, value any, inputs *[]InputPoint, depth int, nodes *int) {
	if depth > maxJSONDepth || *nodes >= maxJSONNodes || len(*inputs) >= maxCandidates {
		return
	}
	*nodes++
	switch typed := value.(type) {
	case map[string]any:
		for key, value := range typed {
			if *nodes >= maxJSONNodes || len(*inputs) >= maxCandidates {
				return
			}
			name := key
			if prefix != "" {
				name = prefix + "." + key
			}
			*inputs = append(*inputs, InputPoint{Source: source, Name: name, Raw: clipRaw(key), Layers: []string{"raw"}})
			flattenJSONValue(source, name, value, inputs, depth+1, nodes)
		}
	case []any:
		for idx, value := range typed {
			if *nodes >= maxJSONNodes {
				return
			}
			flattenJSONValue(source, prefix+"[]", value, inputs, depth+1, nodes)
			_ = idx
		}
	case string:
		*inputs = append(*inputs, InputPoint{Source: source, Name: prefix, Raw: clipRaw(typed), Layers: []string{"raw"}})
	case json.Number, bool, float64:
		*inputs = append(*inputs, InputPoint{Source: source, Name: prefix, Raw: toString(typed), Layers: []string{"raw"}})
	}
}

func boundaryFromContentType(header string) string {
	_, params, err := mime.ParseMediaType(header)
	if err != nil {
		return ""
	}
	return params["boundary"]
}

func multipartInputs(body []byte, boundary string) []InputPoint {
	reader := multipart.NewReader(bytes.NewReader(body), boundary)
	var inputs []InputPoint
	for len(inputs) < 128 {
		part, err := reader.NextPart()
		if err != nil {
			break
		}
		formName := part.FormName()
		fileName := part.FileName()
		name := formName
		if name == "" {
			name = fileName
		}
		if name == "" {
			name = "part"
		}
		// Always inspect attacker-controlled upload filenames (SQLi second-order,
		// webshell.php, null-byte suffix bypass). Content may be empty/binary.
		if fileName != "" {
			inputs = append(inputs, InputPoint{
				Source: "body.multipart",
				Name:   name + ".filename",
				Raw:    fileName,
				Layers: []string{"raw"},
			})
		}
		buf := make([]byte, 64*1024)
		n, _ := part.Read(buf)
		if n == 0 {
			continue
		}
		inputs = append(inputs, InputPoint{Source: "body.multipart", Name: name, Raw: string(buf[:n]), Layers: []string{"raw"}})
	}
	return inputs
}

type decodedVariant struct {
	text   string
	layers []string
}

func decodeVariants(raw string) []decodedVariant {
	// UTF-16 LE/BE BOM payloads (XXE evasion). Expand once into UTF-8 text.
	if utf8FromUTF16, ok := decodeUTF16Payload(raw); ok && utf8FromUTF16 != raw {
		raw = utf8FromUTF16
	}
	// Hot path: plain text without encode markers needs no expansion queue.
	if !needsDeepDecode(raw) {
		return []decodedVariant{{text: raw, layers: []string{"raw"}}}
	}
	queue := []decodedVariant{{text: raw, layers: []string{"raw"}}}
	var out []decodedVariant
	seen := map[string]struct{}{}
	for len(queue) > 0 && len(out) < maxDecodeVariants {
		item := queue[0]
		queue = queue[1:]
		if _, ok := seen[item.text]; ok {
			continue
		}
		seen[item.text] = struct{}{}
		out = append(out, item)
		if len(item.layers) >= 4 {
			continue
		}
		if next := decoder.Decode(item.text); next.Text != item.text {
			queue = append(queue, decodedVariant{text: next.Text, layers: appendLayers(item.layers, next.Layers[1:]...)})
		}
		if unescaped := html.UnescapeString(item.text); unescaped != item.text {
			queue = append(queue, decodedVariant{text: unescaped, layers: appendLayers(item.layers, "html")})
		}
		if b64, ok := decoder.TryBase64(strings.TrimSpace(item.text)); ok && printableRatio(b64) > 0.75 {
			queue = append(queue, decodedVariant{text: b64, layers: appendLayers(item.layers, "base64")})
		}
		if unescaped, ok := decodeUnicodeEscapes(item.text); ok {
			queue = append(queue, decodedVariant{text: unescaped, layers: appendLayers(item.layers, "unicode")})
		}
	}
	return out
}

// decodeUTF16Payload converts UTF-16 LE/BE text (with or without BOM) to UTF-8.
// Used for XXE evasion that wraps entity markup in UTF-16.
func decodeUTF16Payload(raw string) (string, bool) {
	// Some corpora / logs store binary as Go/C hex escapes: \xff\xfe<\x00?...
	if unescaped, ok := unescapeHexByteString(raw); ok {
		if out, ok2 := decodeUTF16FromBytes([]byte(unescaped)); ok2 {
			return out, true
		}
	}
	return decodeUTF16FromBytes([]byte(raw))
}

func decodeUTF16FromBytes(b []byte) (string, bool) {
	if len(b) < 4 {
		return "", false
	}
	var u16 []uint16
	switch {
	case b[0] == 0xff && b[1] == 0xfe:
		// UTF-16 LE BOM
		data := b[2:]
		if len(data)%2 != 0 {
			data = data[:len(data)-1]
		}
		u16 = make([]uint16, 0, len(data)/2)
		for i := 0; i+1 < len(data); i += 2 {
			u16 = append(u16, uint16(data[i])|uint16(data[i+1])<<8)
		}
	case b[0] == 0xfe && b[1] == 0xff:
		// UTF-16 BE BOM
		data := b[2:]
		if len(data)%2 != 0 {
			data = data[:len(data)-1]
		}
		u16 = make([]uint16, 0, len(data)/2)
		for i := 0; i+1 < len(data); i += 2 {
			u16 = append(u16, uint16(data[i])<<8|uint16(data[i+1]))
		}
	default:
		// Heuristic: many NULs in even/odd positions for short XML-looking bodies.
		nulEven, nulOdd := 0, 0
		limit := len(b)
		if limit > 256 {
			limit = 256
		}
		for i := 0; i < limit; i++ {
			if b[i] == 0 {
				if i%2 == 0 {
					nulEven++
				} else {
					nulOdd++
				}
			}
		}
		if nulOdd < limit/6 && nulEven < limit/6 {
			return "", false
		}
		data := b
		if len(data)%2 != 0 {
			data = data[:len(data)-1]
		}
		u16 = make([]uint16, 0, len(data)/2)
		if nulOdd >= nulEven {
			// LE-ish
			for i := 0; i+1 < len(data); i += 2 {
				u16 = append(u16, uint16(data[i])|uint16(data[i+1])<<8)
			}
		} else {
			for i := 0; i+1 < len(data); i += 2 {
				u16 = append(u16, uint16(data[i])<<8|uint16(data[i+1]))
			}
		}
	}
	runes := utf16.Decode(u16)
	out := string(runes)
	if !strings.Contains(strings.ToLower(out), "<!entity") && !strings.Contains(strings.ToLower(out), "<?xml") {
		return "", false
	}
	return out, true
}

// unescapeHexByteString expands \xNN sequences when the payload looks like a
// hex-escaped binary dump (common in corpus exports and some logging layers).
func unescapeHexByteString(raw string) (string, bool) {
	if !strings.Contains(raw, `\x`) && !strings.Contains(raw, `\X`) {
		return "", false
	}
	// Require enough escapes to resemble UTF-16 (many \x00).
	if strings.Count(strings.ToLower(raw), `\x00`) < 3 && !strings.Contains(strings.ToLower(raw), `\xff\xfe`) && !strings.Contains(strings.ToLower(raw), `\xfe\xff`) {
		return "", false
	}
	var b strings.Builder
	b.Grow(len(raw) / 2)
	for i := 0; i < len(raw); {
		if i+3 < len(raw) && raw[i] == '\\' && (raw[i+1] == 'x' || raw[i+1] == 'X') {
			h1, ok1 := fromHex(raw[i+2])
			h2, ok2 := fromHex(raw[i+3])
			if ok1 && ok2 {
				b.WriteByte(h1<<4 | h2)
				i += 4
				continue
			}
		}
		b.WriteByte(raw[i])
		i++
	}
	out := b.String()
	if out == raw {
		return "", false
	}
	return out, true
}

func fromHex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
	}
}

// needsDeepDecode is a pure byte scan: only expand decode layers when markers
// suggest URL/HTML/Base64/Unicode/comment obfuscation may be present.
func needsDeepDecode(raw string) bool {
	if len(raw) == 0 {
		return false
	}
	// Long alphanumeric-only blobs may be base64 shells.
	if len(raw) >= 24 && isMostlyBase64Alphabet(raw) {
		return true
	}
	// Hex-escaped UTF-16 dumps need expansion.
	if strings.Contains(raw, `\x`) || strings.Contains(raw, `\X`) {
		return true
	}
	for i := 0; i < len(raw); i++ {
		switch raw[i] {
		case '%', '&', '+', '\\', '=', '<', '>', ';', '#':
			return true
		case '/':
			// php://, data:, file:// often appear with colon nearby.
			if i+1 < len(raw) && (raw[i+1] == '/' || (i > 0 && raw[i-1] == ':')) {
				return true
			}
		}
	}
	return false
}

func isMostlyBase64Alphabet(raw string) bool {
	ok := 0
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '+', c == '/', c == '=', c == '-', c == '_':
			ok++
		case c == ' ' || c == '\n' || c == '\r' || c == '\t':
			// allow sparse whitespace
		default:
			return false
		}
	}
	return ok*10 >= len(raw)*9
}

func appendLayers(base []string, extra ...string) []string {
	out := append([]string(nil), base...)
	for _, layer := range extra {
		if layer != "" {
			out = append(out, layer)
		}
	}
	return out
}

func decodeUnicodeEscapes(raw string) (string, bool) {
	if !strings.Contains(raw, `\u`) && !strings.Contains(raw, `\x`) {
		return "", false
	}
	changed := false
	out := unicodeEscapePattern.ReplaceAllStringFunc(raw, func(match string) string {
		parts := unicodeEscapePattern.FindStringSubmatch(match)
		hex := parts[1]
		if hex == "" {
			hex = parts[2]
		}
		value, err := strconv.ParseInt(hex, 16, 32)
		if err != nil {
			return match
		}
		changed = true
		return string(rune(value))
	})
	return out, changed
}

func compactSQL(raw string) string {
	text := executableSQLText(raw)
	text = sqlLineComment.ReplaceAllString(text, "")
	text = strings.ReplaceAll(text, "#", "")
	var b strings.Builder
	for _, r := range text {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '=' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func executableSQLText(raw string) string {
	text := normalize(raw)
	text = sqlMySQLVersionComment.ReplaceAllString(text, " $1 ")
	return sqlKeywordBridgeComment.ReplaceAllString(text, "$1$2")
}

func guessCategories(raw string) []string {
	// Fast negative path only for clean identifiers. Dirty/unknown shapes over-scan
	// rather than risk missing attacks (FP-first applies later in blockableHit).
	if looksCleanASCIIField(raw) {
		return nil
	}
	hints := scanAttackHints(raw)
	if hints == 0 {
		hints = hintSQL | hintXSS | hintRCE | hintLFI | hintXXE | hintSSRF | hintNoSQL | hintSSTI
	}
	text := normalize(raw)
	ordered := []string{"sqli", "xss", "rce", "lfi", "xxe", "ssrf", "nosqli", "ssti"}
	scores := map[string]int{}
	if hints&hintSQL != 0 {
		// Cheap substring gates before expensive compactSQL / multi-regex suite.
		cheapSQL := strings.Contains(text, "select") || strings.Contains(text, "union") ||
			strings.Contains(text, " or ") || strings.Contains(text, "or'") || strings.Contains(text, "or\"") ||
			strings.Contains(text, "sleep(") || strings.Contains(text, "benchmark(") ||
			strings.Contains(text, "pg_sleep(") || strings.Contains(text, "waitfor") ||
			strings.Contains(text, "information_schema") || strings.Contains(text, "drop table") ||
			strings.Contains(text, "delete from") || strings.Contains(text, "xp_cmdshell") ||
			strings.Contains(text, "load_file") || strings.Contains(text, "into outfile") ||
			strings.Contains(text, "procedure analyse") || strings.Contains(text, "dbms_lock.sleep") ||
			strings.Contains(text, "sp_oacreate") || strings.Contains(text, "openrowset") ||
			strings.Contains(text, "0x") || strings.Contains(text, "/*") || strings.Contains(text, "--")
		if cheapSQL {
			scores["sqli"] += 2
		} else {
			sqlCompact := compactSQL(text)
			if strings.Contains(sqlCompact, "unionselect") || strings.Contains(sqlCompact, "or1=1") ||
				sqlBooleanTautology.MatchString(text) || sqlEmptyStringTautology.MatchString(text) ||
				sqlQuotedOrPredicate.MatchString(text) || sqlOrderByInference.MatchString(text) ||
				sqlHavingInference.MatchString(text) || sqlRegexProbe.MatchString(text) ||
				sqlMetadataObject.MatchString(text) || sqlSubquery.MatchString(text) ||
				sqlCaseWhen.MatchString(text) || sqlFileData.MatchString(text) ||
				sqlTimeFunction.MatchString(text) || sqlDangerousFunc.MatchString(text) {
				scores["sqli"] += 2
			}
		}
	}
	if hints&hintXSS != 0 {
		if strings.Contains(text, "<script") || strings.Contains(text, ":script") || executableXSSContext(text) || strings.Contains(text, "<svg") || strings.Contains(text, "<img") || strings.Contains(text, "<xss") || strings.Contains(text, "<meta") || strings.Contains(text, "expression(") {
			scores["xss"] += 2
		}
	}
	if hints&hintRCE != 0 {
		if strings.Contains(text, ";") || strings.Contains(text, "&&") || strings.Contains(text, "|") || strings.Contains(text, "$(") || strings.Contains(text, "`") || strings.Contains(text, "$shell") || strings.Contains(text, "$ifs") || strings.Contains(text, "${ifs}") || strings.Contains(text, "/usr/bin/") || strings.Contains(text, "/bin/") || strings.Contains(text, "cmd.exe") || strings.Contains(text, "cmd /c") || strings.Contains(text, "powershell") || strings.Contains(text, "pwsh") || strings.Contains(text, "encodedcommand") || strings.Contains(text, "downloadstring") || strings.Contains(text, "downloadfile") || strings.Contains(text, "webclient") || strings.Contains(text, "tcpclient") || strings.Contains(text, "new-object") || strings.Contains(text, "<?php") || strings.Contains(text, "eval(") || strings.Contains(text, "bash -c") || strings.Contains(text, "sh -c") || strings.Contains(text, "wget ") || strings.Contains(text, "curl ") || strings.Contains(text, "python -c") || strings.Contains(text, "php -r") || strings.Contains(text, "perl -e") || strings.Contains(text, "ld_preload") || strings.Contains(text, "child_process") || rceReverseShellPrimitive.MatchString(text) || rceTemplateExecutionPrimitive.MatchString(text) || rceNetWebClientSideFx.MatchString(text) || rcePowerShellSideFx.MatchString(text) || rceLoaderPrimitive.MatchString(text) {
			scores["rce"] += 2
		}
	}
	if hints&hintLFI != 0 {
		if strings.Contains(text, "../") || strings.Contains(text, `..\`) || strings.Contains(text, "..//") || strings.Contains(text, `..\/`) || lfiEncodedTraversal.MatchString(text) || lfiSensitiveTarget.MatchString(text) || lfiFileReadSink.MatchString(text) || lfiCommandReadSink.MatchString(text) || strings.Contains(text, "file://") || strings.Contains(text, "php://") || strings.Contains(text, "data://") || strings.Contains(text, "phar://") || strings.Contains(text, "expect://") || strings.Contains(text, "docker.sock") || strings.Contains(text, ".aws/") || strings.Contains(text, ".git/") || strings.Contains(text, "/.env") || lfiDotEnvTarget.MatchString(text) || strings.Contains(text, "wp-config") || strings.Contains(text, ".ssh/") || strings.Contains(text, "/var/run/secrets/kubernetes.io/") ||
			// RFI-shaped remote includes: http(s) value often only scores SSRF unless LFI is also opened.
			((strings.Contains(text, "http://") || strings.Contains(text, "https://")) && (strings.Contains(text, ".php") || strings.Contains(text, "shell") || strings.Contains(text, "passwd") || strings.HasSuffix(text, "?"))) {
			scores["lfi"] += 2
		}
	}
	if hints&hintXXE != 0 {
		if strings.Contains(text, "<!doctype") || strings.Contains(text, "<!entity") || strings.Contains(text, "xinclude") || strings.Contains(text, "xi:include") {
			scores["xxe"] += 2
		}
	}
	if hints&hintSSRF != 0 {
		if urlLikePattern.MatchString(text) || schemeRelativeURLPattern.MatchString(text) || strings.Contains(text, "169.254.169.254") || strings.Contains(text, "metadata.google.internal") || looksLikeSSRFTarget(text) {
			scores["ssrf"] += 2
			// Also open LFI analysis for remote-include shapes; field-name gates in
			// analyzeLFI keep documentation/fetch-only traffic from blocking.
			if scores["lfi"] == 0 {
				scores["lfi"] += 1
			}
		}
	}
	if hints&hintNoSQL != 0 {
		if nosqlOperatorToken.MatchString(text) || strings.Contains(text, "$function") || strings.Contains(text, "this.") || strings.Contains(text, "function(") {
			scores["nosqli"] += 2
		}
	}
	if hints&hintSSTI != 0 {
		if sstiTemplateExpression.MatchString(text) {
			scores["ssti"] += 2
		}
	}
	var guesses []string
	for _, category := range ordered {
		if scores[category] > 0 {
			guesses = append(guesses, category)
		}
	}
	return guesses
}

const (
	hintSQL = 1 << iota
	hintXSS
	hintRCE
	hintLFI
	hintXXE
	hintSSRF
	hintNoSQL
	hintSSTI
)

// scanAttackHints does a single ASCII-oriented pass to decide which detector
// families deserve full analysis. Prefer false-positive on the hint (over-scan)
// rather than under-scan that would miss attacks.
func scanAttackHints(raw string) int {
	if len(raw) == 0 {
		return 0
	}
	lower := strings.ToLower(raw)
	var hints int
	// SQL stems (include quote/OR glue without requiring spaces: 'OR' '')
	if strings.Contains(lower, "select") || strings.Contains(lower, "union") ||
		strings.Contains(lower, "sleep") || strings.Contains(lower, "benchmark") ||
		strings.Contains(lower, "waitfor") || strings.Contains(lower, "xp_cmd") ||
		strings.Contains(lower, "information_schema") || strings.Contains(lower, "drop") ||
		strings.Contains(lower, "delete") || strings.Contains(lower, " or ") ||
		strings.Contains(lower, "and ") || strings.Contains(lower, "'or") ||
		strings.Contains(lower, "\"or") || strings.Contains(lower, "or'") ||
		strings.Contains(lower, "or\"") || strings.Contains(lower, "0x") ||
		strings.Contains(lower, "/*") || strings.Contains(lower, "--") ||
		strings.Contains(lower, "having") || strings.Contains(lower, "order by") ||
		strings.Contains(lower, "group by") || strings.Contains(lower, "outfile") ||
		strings.Contains(lower, "load_file") || strings.Contains(lower, "openrowset") ||
		strings.Contains(lower, "dbms_") || strings.Contains(lower, "extractvalue") ||
		strings.Contains(lower, "updatexml") || strings.Contains(lower, "='") ||
		strings.Contains(lower, "=\"") {
		hints |= hintSQL
	}
	// XSS
	if strings.Contains(lower, "<") || strings.Contains(lower, "javascript:") ||
		strings.Contains(lower, "onerror") || strings.Contains(lower, "onload") ||
		strings.Contains(lower, "onclick") || strings.Contains(lower, "srcdoc") ||
		strings.Contains(lower, "expression(") || strings.Contains(lower, "svg") ||
		strings.Contains(lower, "script") {
		hints |= hintXSS
	}
	// RCE
	if strings.Contains(lower, ";") || strings.Contains(lower, "&&") ||
		strings.Contains(lower, "|") || strings.Contains(lower, "$(") ||
		strings.Contains(lower, "`") || strings.Contains(lower, "powershell") ||
		strings.Contains(lower, "pwsh") || strings.Contains(lower, "cmd") ||
		strings.Contains(lower, "bash") || strings.Contains(lower, "curl") ||
		strings.Contains(lower, "wget") || strings.Contains(lower, "python") ||
		strings.Contains(lower, "perl") || strings.Contains(lower, "/bin/") ||
		strings.Contains(lower, "encodedcommand") || strings.Contains(lower, "downloadstring") ||
		strings.Contains(lower, "downloadfile") || strings.Contains(lower, "webclient") ||
		strings.Contains(lower, "tcpclient") || strings.Contains(lower, "invoke-expression") ||
		strings.Contains(lower, "<?php") || strings.Contains(lower, "eval(") ||
		strings.Contains(lower, "whoami") || strings.Contains(lower, "${ifs}") ||
		strings.Contains(lower, "$ifs") || strings.Contains(lower, "/dev/tcp") ||
		strings.Contains(lower, "/dev/udp") || strings.Contains(lower, "</dev/") ||
		strings.Contains(lower, "ncat") || strings.Contains(lower, "netcat") ||
		strings.Contains(lower, "$shell") || strings.Contains(lower, "${shell}") ||
		strings.Contains(lower, "ld_preload") || strings.Contains(lower, "child_process") ||
		strings.Contains(lower, "defineclass") || strings.Contains(lower, "assembly.load") {
		hints |= hintRCE
	}
	// LFI
	if strings.Contains(lower, "..") || strings.Contains(lower, "%2e") ||
		strings.Contains(lower, "etc/") || strings.Contains(lower, "proc/") ||
		strings.Contains(lower, ".env") || strings.Contains(lower, "php://") ||
		strings.Contains(lower, "file://") || strings.Contains(lower, "data://") ||
		strings.Contains(lower, "docker.sock") || strings.Contains(lower, "wp-config") ||
		strings.Contains(lower, ".aws") || strings.Contains(lower, ".git") ||
		strings.Contains(lower, ".ssh") || strings.Contains(lower, "boot.ini") ||
		strings.Contains(lower, "win.ini") || strings.Contains(lower, "passwd") ||
		strings.Contains(lower, "phar://") || strings.Contains(lower, "expect://") {
		hints |= hintLFI
	}
	// XXE
	if strings.Contains(lower, "<!doctype") || strings.Contains(lower, "<!entity") ||
		strings.Contains(lower, "system \"") || strings.Contains(lower, "system '") ||
		strings.Contains(lower, "xinclude") || strings.Contains(lower, "xi:include") {
		hints |= hintXXE
	}
	// SSRF
	if strings.Contains(lower, "http://") || strings.Contains(lower, "https://") ||
		strings.Contains(lower, "://") || strings.Contains(lower, "169.254.") ||
		strings.Contains(lower, "metadata") || strings.Contains(lower, "127.0.0.1") ||
		strings.Contains(lower, "localhost") || strings.Contains(lower, "[::1]") ||
		strings.Contains(lower, "gopher://") || strings.Contains(lower, "dict://") ||
		strings.Contains(lower, "nip.io") || strings.Contains(lower, "sslip.io") ||
		strings.Contains(lower, "rebind") || strings.Contains(lower, "rbndr") ||
		strings.Contains(lower, "localtest.me") {
		hints |= hintSSRF
	}
	// NoSQL — any $-operator token (including $elemMatch / $nin / …).
	if strings.Contains(lower, "$") || strings.Contains(lower, "this.") ||
		strings.Contains(lower, "function(") || strings.Contains(lower, "mapreduce") ||
		strings.Contains(lower, `"map"`) || strings.Contains(lower, `"reduce"`) {
		hints |= hintNoSQL
	}
	// SSTI
	if strings.Contains(lower, "{{") || strings.Contains(lower, "{%") ||
		strings.Contains(lower, "${") || strings.Contains(lower, "#{") ||
		strings.Contains(lower, "<%") || strings.Contains(lower, "__class__") ||
		strings.Contains(lower, "__globals__") || strings.Contains(lower, "popen") ||
		strings.Contains(lower, "objectspace") || strings.Contains(lower, "classloader") {
		hints |= hintSSTI
	}
	return hints
}

func analyzeSyntaxAndSemantics(category string, candidate semanticCandidate) (Hit, bool) {
	switch category {
	case "sqli":
		return analyzeSQL(candidate)
	case "xss":
		return analyzeXSS(candidate)
	case "rce":
		return analyzeRCE(candidate)
	case "lfi":
		return analyzeLFI(candidate)
	case "xxe":
		return analyzeXXE(candidate)
	case "ssrf":
		return analyzeSSRF(candidate)
	case "nosqli":
		return analyzeNoSQL(candidate)
	case "ssti":
		return analyzeSSTI(candidate)
	default:
		return Hit{}, false
	}
}

var (
	sqlBooleanTautology     = regexp.MustCompile(`(?i)(?:'|"|\b)\s*(?:or|and)\s+(?:'?\d+'?|[a-z_][a-z0-9_]*|'[^']*')\s*=\s*(?:'?\d+'?|[a-z_][a-z0-9_]*|'[^']*')`)
	sqlEmptyStringTautology = regexp.MustCompile(`(?i)(?:'|")\s*(?:or|and)\s*(?:''|""|'[^']*'|"[^"]*"|['"])\s*=\s*(?:''|""|'[^']*'|"[^"]*"|['"])`)
	sqlQuotedOrPredicate    = regexp.MustCompile(`(?i)(?:'|")\s*or\s*(?:''|""|'[^']*'|"[^"]*"|[^\s]{1,64})`)
	sqlTimeFunction         = regexp.MustCompile(`(?i)(?:\b(?:sleep|benchmark|pg_sleep)\s*\(|\bwaitfor\s+delay\b)`)
	sqlDialectTimeFunction  = regexp.MustCompile(`(?i)\bdbms_(?:lock|session)\.sleep\s*\(`)
	sqlComment              = regexp.MustCompile(`(?i)(?:--|#|/\*)`)
	sqlDangerousFunc        = regexp.MustCompile(`(?i)\b(?:xp_cmdshell|sp_oa(?:create|method)|openrowset|opendatasource|load_file|into\s+outfile|copy\s+.+\s+to\s+program)\b`)
	sqlErrorFunction        = regexp.MustCompile(`(?i)\b(?:extractvalue|updatexml|xmltype|ctxsys\.drithsx\.sn|utl_inaddr\.get_host_name|utl_http\.request)\s*\(`)
	sqlStringFunction       = regexp.MustCompile(`(?i)\b(?:char|chr|concat|concat_ws|nchar|ascii|substring|substr)\s*\(`)
	sqlComparison           = regexp.MustCompile(`(?i)(?:=|<>|!=|<=>|\blike\b|\bin\b)`)
	sqlOrderByInference     = regexp.MustCompile(`(?i)\b(?:order|group)\s+by\s+\d+\s*(?:--|#|/\*)`)
	sqlHavingInference      = regexp.MustCompile(`(?i)\bhaving\s+(?:\d+|'[^']*'|"[^"]*")\s*=\s*(?:\d+|'[^']*'|"[^"]*")\s*(?:--|#|/\*)`)
	sqlRegexProbe           = regexp.MustCompile(`(?i)\b(?:rlike|regexp|like)\s+(?:binary\s+)?(?:0x[0-9a-f]+|'[^']*'|"[^"]*")`)
	sqlProcedureAnalyse     = regexp.MustCompile(`(?i)\bprocedure\s+analyse\s*\(`)
	sqlMetadataObject       = regexp.MustCompile(`(?i)\b(?:information_schema|pg_catalog|pg_shadow|pg_group|sysibm|syscat|sysobjects|syscolumns|sysusers|master\.\.|sys\.|sqlite_master|mysql\.user|@@(?:version|datadir|hostname|basedir)|current\s+user|session_user|system_user)\b`)
	sqlSubquery             = regexp.MustCompile(`(?is)\(\s*select\b.+?\bfrom\b.+?\)`)
	sqlCaseWhen             = regexp.MustCompile(`(?is)\bcase\s+when\b.+?\bthen\b.+?\belse\b.+?\bend\b`)
	sqlSelectFrom           = regexp.MustCompile(`(?is)\bselect\b.{0,240}\bfrom\b`)
	sqlFileData             = regexp.MustCompile(`(?i)\b(?:load\s+data\s+infile|load_file\s*\(|into\s+outfile|copy\s+\S+\s+to(?:\s+program|\s+['\"/]|\s+[a-z0-9_./\\-]+))\b`)
	sqlMySQLVersionComment  = regexp.MustCompile(`(?is)/\*!\d{0,6}\s*(.*?)\*/`)
	sqlKeywordBridgeComment = regexp.MustCompile(`(?i)\b([a-z]{2,8})/\*.*?\*/([a-z]{2,8})\b`)
	// Boolean-blind shapes that omit FROM (XOR/IF/SELECT WHERE probes).
	sqlIfSelectProbe     = regexp.MustCompile(`(?i)\bif\s*\(\s*\(?\s*select\b`)
	sqlXorSelectProbe    = regexp.MustCompile(`(?i)\bxor\s*\([\s\S]{0,200}\bselect\b`)
	sqlSelectWhere       = regexp.MustCompile(`(?is)\bselect\b.{0,120}\bwhere\b`)
	xssEventPattern      = regexp.MustCompile(`(?i)\bon[a-z0-9_-]{3,}\s*=`)
	unicodeEscapePattern = regexp.MustCompile(`\\(?:u([0-9a-fA-F]{4})|x([0-9a-fA-F]{2}))`)
	// Encoded traversal only — bare %2f/%5c (normal URL path encoding) must NOT match.
	// Matches: %2e%2e%2f, ..%2f, %2e%2e/, double-encoded dots, overlong dots, %c0%af abuse.
	lfiEncodedTraversal           = regexp.MustCompile(`(?i)(?:%25)*(?:%2e){2,}(?:%25)*(?:%2f|%5c)|(?:\.\.(?:%25)*(?:%2f|%5c))|(?:%25)*%2e(?:%25)*%2e[/\\]|%c0%af|%25c0%25af|\.{4,}[/\\]+`)
	lfiDotEnvTarget               = regexp.MustCompile(`(?i)(?:^|[/\\])\.env(?:$|[?#.]|%00|%23)`)
	lfiSensitiveTarget            = regexp.MustCompile(`(?i)(?:^|[/\\])(?:etc/(?:passwd|shadow|group|hosts|hostname|fstab|sudoers|crontab|issue|motd|nginx/nginx\.conf|apache2/apache2\.conf|redis/redis\.conf|mysql/my\.cnf|php/php\.ini|ssh/sshd_config)|proc/(?:self/(?:environ|cmdline|maps|fd/\d+)|version|cpuinfo)|root/\.bash_history|home/[^/\\]+/\.ssh/(?:id_rsa|id_dsa|authorized_keys)|var/log/(?:syslog|auth\.log|nginx/access\.log|nginx/error\.log|apache2/access\.log|apache2/error\.log|httpd-access\.log)|winnt/system32/cmd\.exe|windows/(?:win\.ini|system32/drivers/etc/hosts)|boot\.ini|web-inf/web\.xml|meta-inf/manifest\.mf|\.htaccess|_config\.php|config\.php|config/(?:database|parameters|settings)\.(?:php|ya?ml|json)|wp-config\.php|dump\.sql|database\.sql|id_rsa)(?:$|[?#\x00.]|%00|%23)`)
	nosqlOperatorToken            = regexp.MustCompile(`(?i)(?:^|[.\[\]{"'\s:=,&?])\$(?:jsonschema|elemmatch|function|where|regex|exists|gte|lte|nin|nor|not|expr|eval|all|mod|type|size|ne|eq|gt|lt|in|or|and)(?:$|[.\[\]}\]"'\s:=,&?])`)
	nosqlJSBehavior               = regexp.MustCompile(`(?i)(?:this\.[a-z_][a-z0-9_]*|function\s*\(|return\s+|sleep\s*\(|constructor\s*\[|process\.|emit\s*\()`)
	nosqlMapReducePayload         = regexp.MustCompile(`(?i)(?:"map"\s*:\s*"(?:function\s*\(|function\s+[a-z])|"reduce"\s*:\s*"(?:function\s*\(|function\s+[a-z])|"mapreduce"\s*:)`)
	nosqlWideRegex                = regexp.MustCompile(`(?i)(?:\.\*|\^\.\*\$|\[[^\]]*\])`)
	nosqlOperatorNames            = []string{"$jsonschema", "$elemmatch", "$function", "$where", "$regex", "$exists", "$gte", "$lte", "$nin", "$nor", "$not", "$expr", "$eval", "$all", "$mod", "$type", "$size", "$ne", "$eq", "$gt", "$lt", "$in", "$or", "$and"}
	sstiTemplateExpression        = regexp.MustCompile(`(?is)(?:\{\{.*?\}\}|\{%.*?%\}|\$\{.*?\}|#\{.*?\}|%\{.*?\}|<%=?\s*.*?%>)`)
	sstiArithmeticProbe           = regexp.MustCompile(`(?is)(?:\{\{\s*[-+]?\d+\s*[*+\-/]\s*[-+]?\d+\s*\}\}|\$\{\s*[-+]?\d+\s*[*+\-/]\s*[-+]?\d+\s*\}|<%=?\s*[-+]?\d+\s*[*+\-/]\s*[-+]?\d+\s*%>)`)
	sstiDangerousBehavior         = regexp.MustCompile(`(?i)(?:__class__|__mro__|__subclasses__|__globals__|__builtins__|#(?:context|_memberaccess|request|session)|@[a-z0-9_.]+@|popen\s*\(|os\s*\.\s*(?:system|popen)|__import__\s*\(|\bimport\s*\(|getruntime\s*\(\s*\)\s*\.\s*exec|runtime\.getruntime|java\.lang\.runtime|processbuilder|child_process|execsync|system\s*\(|passthru\s*\(|shell_exec\s*\(|freemarker\.template\.utility\.(?:execute|objectconstructor)|\?new\s*\(|registerundefinedfiltercallback|_self\.env|getfilter\s*\(|constructor\s*\.\s*constructor|t\s*\(\s*java\.lang\.runtime|objectspace\.each_object|classloader\.loadclass|loadclass\s*\(|request\.getclass|application\.getclass|session\.getclass|#set\s*\(\s*\$|\{php\}|smarty\.version|mako\.runtime|velocity\.context|pebble\.extension)`)
	rceNetWebClientSideFx         = regexp.MustCompile(`(?i)(?:new-object\s+system\.net\.(?:webclient|sockets\.tcpclient)|system\.net\.webclient|download(?:file|string)\s*\(|iwr\s+|invoke-webrequest\b)`)
	rcePowerShellReverseShell     = regexp.MustCompile(`(?i)(?:tcpclient\s*\(|getstream\s*\(|net\.sockets\.tcpclient|while\s*\(\s*\$i\s*=\s*\$s\.read)`)
	sqlBlockComment               = regexp.MustCompile(`(?is)/\*.*?\*/`)
	sqlLineComment                = regexp.MustCompile(`(?m)--[^\r\n]*`)
	rceShellControl               = regexp.MustCompile(`(?:;|&&|\|\||\||\$\(|` + "`" + `)`)
	rceWhitespaceEvasion          = regexp.MustCompile(`(?i)\$\{?ifs\}?`)
	rcePowerShellSideFx           = regexp.MustCompile(`(?i)(?:\b(?:powershell|pwsh)(?:\.exe)?\b[^\r\n]{0,200}\b(?:downloadstring|downloadfile|frombase64string|invoke-expression|iex|new-object|net\.webclient)\b)|(?:new-object\s+system\.net\.(?:webclient|sockets\.tcpclient)|(?:download(?:file|string)|invoke-expression|iex)\s*\()`)
	rceEncodedPowerShell          = regexp.MustCompile(`(?i)\b(?:powershell|pwsh)(?:\.exe)?\b[^\r\n]{0,160}\s-(?:e|enc|encodedcommand)\s+[a-z0-9+/=]{12,}`)
	rceInterpreterInline          = regexp.MustCompile(`(?i)(?:^|[=&\s;|])(?:bash|sh|zsh|dash|ksh)\s+-c\s+['"]?(?:id|whoami|cat|curl|wget|uname|nc|ncat|python3?|perl|php|ruby|node|powershell|pwsh)\b|(?:^|[=&\s;|])cmd(?:\.exe)?\s*/c\s+(?:whoami|id|dir|type|powershell|certutil|curl|wget|ping|nslookup)\b|(?:python3?|perl|php|ruby|node|lua)\s+(?:-c|-e|-r)\b`)
	rceDownloadExecChain          = regexp.MustCompile(`(?i)(?:curl|wget|fetch|busybox\s+wget)\s+[^\r\n|;&]+(?:\||;|&&)\s*(?:sh|bash|zsh|dash|ksh|python3?|php|perl|ruby|node)\b`)
	rceReverseShellPrimitive      = regexp.MustCompile(`(?i)(?:/dev/tcp/|/dev/udp/|nc\s+-e|ncat\s+-e|bash\s+-i|sh\s*<\s*/dev/tcp|socket\.socket\s*\(|child_process|require\s*\(\s*['"]child_process['"]\s*\))`)
	rceTemplateExecutionPrimitive = regexp.MustCompile(`(?i)(?:registerundefinedfiltercallback\s*\(\s*['"]exec|filter\s*\(\s*['"]system|system\s*\(|exec\s*\(|popen\s*\(|passthru\s*\(|shell_exec\s*\()`)
	// Generic “unknown exploit” shapes: loader hooks / polyglot runtime without CVE names.
	rceLoaderPrimitive = regexp.MustCompile(`(?i)(?:ld_preload\s*=|dyld_insert_libraries\s*=|process\.dlopen\s*\(|ctypes\.cdll|java\.lang\.classloader|defineclass\s*\(|unsafe\.defineanonymousclass|reflection\.emit|assembly\.load\s*\()`)
	lfiFileReadSink    = regexp.MustCompile(`(?i)(?:file\.read\s*\(|get_user_file\s*\(|readfile\s*\(|file_get_contents\s*\(|open\s*\()[^)]*(?:/etc/|c:[/\\]|boot\.ini|\.ssh/|/proc/|/var/log/)`)
	lfiCommandReadSink = regexp.MustCompile(`(?i)\b(?:cat|type|more|less|head|tail)\s+(?:/etc/|c:[/\\]|boot\.ini|\.ssh/|/proc/|/var/log/)`)
)

func analyzeSQL(candidate semanticCandidate) (Hit, bool) {
	// Probe surfaces before comment-bridging so SELECT/**/WHERE and IF((SELECT
	// shapes stay visible; full analysis still uses bridged executable text.
	normalized := normalize(candidate.text)
	text := executableSQLText(candidate.text)
	words := tokens(text)
	reasons := map[string]bool{}
	if containsOrdered(words, "union", "select") {
		reasons["syntax: UNION SELECT query composition"] = true
	}
	compact := compactSQL(text)
	if strings.Contains(compact, "unionselect") || strings.Contains(compact, "unionallselect") {
		reasons["syntax: obfuscated UNION SELECT query composition"] = true
	}
	if strings.Contains(compact, "or1=1") || strings.Contains(compact, "and1=1") {
		reasons["syntax: obfuscated boolean tautology predicate"] = true
	}
	if sqlBooleanTautology.MatchString(text) {
		reasons["syntax: boolean tautology predicate"] = true
	}
	if sqlEmptyStringTautology.MatchString(text) {
		reasons["syntax: empty-string boolean tautology predicate"] = true
	}
	if sqlQuotedOrPredicate.MatchString(text) {
		reasons["syntax: quoted OR predicate injection"] = true
	}
	if sqlTimeFunction.MatchString(text) {
		reasons["semantics: time-based database side effect"] = true
	}
	if sqlDialectTimeFunction.MatchString(text) && sqlExecutionContext(text, compact) {
		reasons["semantics: dialect-specific database time-delay side effect"] = true
	}
	if sqlSelectFrom.MatchString(text) {
		reasons["syntax: SELECT FROM query grammar"] = true
	}
	if sqlIfSelectProbe.MatchString(normalized) || sqlIfSelectProbe.MatchString(text) ||
		sqlXorSelectProbe.MatchString(normalized) || sqlXorSelectProbe.MatchString(text) {
		reasons["syntax: IF/XOR SELECT boolean-blind probe"] = true
		reasons["semantics: boolean database value inference"] = true
	}
	if (sqlSelectWhere.MatchString(normalized) || sqlSelectWhere.MatchString(text)) &&
		(sqlComment.MatchString(normalized) || strings.Contains(normalized, "/**/") ||
			sqlIfSelectProbe.MatchString(normalized) || sqlXorSelectProbe.MatchString(normalized)) {
		reasons["syntax: SELECT WHERE boolean probe"] = true
	}
	if sqlSubquery.MatchString(text) {
		reasons["syntax: parenthesized SELECT subquery"] = true
	}
	if sqlCaseWhen.MatchString(text) {
		reasons["syntax: CASE WHEN conditional expression"] = true
		reasons["semantics: conditional database value inference"] = true
	}
	if sqlMetadataObject.MatchString(text) || containsOrdered(words, "information_schema") || containsOrdered(words, "pg_catalog") {
		reasons["semantics: database metadata enumeration"] = true
	}
	if (contains(words, "drop") && contains(words, "table")) || (contains(words, "delete") && contains(words, "from")) {
		reasons["semantics: destructive database operation"] = true
	}
	if sqlComment.MatchString(text) && (contains(words, "or") || contains(words, "union") || contains(words, "select")) {
		reasons["syntax: SQL comment used to truncate query"] = true
	}
	if sqlOrderByInference.MatchString(text) {
		reasons["syntax: ORDER/GROUP BY column-count inference with SQL comment"] = true
	}
	if sqlHavingInference.MatchString(text) {
		reasons["syntax: HAVING boolean predicate with SQL comment truncation"] = true
	}
	if sqlRegexProbe.MatchString(text) && (contains(words, "and") || contains(words, "or") || strings.Contains(text, "database()") || strings.Contains(text, "version()") || strings.Contains(text, "user()")) {
		reasons["syntax: SQL regex or LIKE probe in boolean predicate"] = true
		reasons["semantics: database value inference through pattern matching"] = true
	}
	if sqlProcedureAnalyse.MatchString(text) {
		reasons["semantics: MySQL PROCEDURE ANALYSE enumeration primitive"] = true
	}
	if sqlDangerousFunc.MatchString(text) && sqlExecutionContext(text, compact) {
		reasons["semantics: database server file or command side effect"] = true
	}
	if sqlFileData.MatchString(text) {
		reasons["semantics: database file-system import/export primitive"] = true
	}
	if strings.Contains(text, "xp_cmdshell") {
		reasons["semantics: SQL Server command execution primitive"] = true
	}
	if strings.Contains(text, "into outfile") || strings.Contains(text, "load_file") {
		reasons["semantics: database file-system read or write primitive"] = true
	}
	if sqlErrorFunction.MatchString(text) && (contains(words, "select") || contains(words, "concat") || strings.Contains(compact, "select")) {
		reasons["semantics: error-based database function with query composition"] = true
	}
	if sqlStringFunction.MatchString(text) && sqlComparison.MatchString(text) && (contains(words, "or") || contains(words, "and") || strings.Contains(compact, "orchar") || strings.Contains(compact, "andchar")) {
		reasons["syntax: SQL function comparison inside boolean predicate"] = true
	}
	if len(reasons) == 0 || !sqlReasonsBlockable(reasons) {
		return Hit{}, false
	}
	severity := engine.SeverityHigh
	confidence := 0.88 + confidenceBonus(reasons)
	if strings.Contains(text, "xp_cmdshell") || strings.Contains(text, "into outfile") || strings.Contains(text, "load_file") {
		severity = engine.SeverityCritical
		confidence += 0.04
	}
	return hit(candidate, "sqli", severity, confidence, reasons), true
}

func analyzeNoSQL(candidate semanticCandidate) (Hit, bool) {
	text := strings.TrimSpace(candidate.text)
	lowerText := normalize(text)
	name := strings.ToLower(candidate.input.Name)
	if !nosqlStructuredSource(candidate.input.Source) {
		return Hit{}, false
	}
	structuralOperator := nosqlOperatorInPath(name)
	textOperator := nosqlOperatorToken.MatchString(lowerText)
	mapReduce := nosqlMapReducePayload.MatchString(lowerText)
	// JSON often splits map/reduce into separate fields; detect by field name + JS body.
	fieldMapReduce := nosqlMapReduceField(name) && nosqlJSBehavior.MatchString(lowerText)
	if !structuralOperator && !textOperator && !mapReduce && !fieldMapReduce {
		return Hit{}, false
	}
	// Documentation field names normally skip NoSQL. Exception: raw request bodies
	// that carry real operator tokens (e.g. broken/partial JSON with "$eval").
	if !structuralOperator && !mapReduce && !fieldMapReduce && nosqlDocumentationContext(name) {
		if !(candidate.input.Source == "body.raw" && textOperator) {
			return Hit{}, false
		}
	}
	if !structuralOperator && !mapReduce && !fieldMapReduce && !nosqlSensitiveContext(name) && !nosqlLooksLikeStructuredPayload(lowerText) {
		// map/reduce field bodies are structured even without $-operators.
		if !fieldMapReduce {
			return Hit{}, false
		}
	}

	combined := name + " " + lowerText
	reasons := map[string]bool{}
	if structuralOperator {
		reasons["syntax: MongoDB query operator in structured parameter path"] = true
	}
	if textOperator {
		reasons["syntax: MongoDB query operator token"] = true
	}
	if mapReduce || fieldMapReduce {
		reasons["syntax: MongoDB mapReduce JavaScript payload"] = true
		reasons["semantics: mapReduce functions can evaluate attacker-controlled server-side JavaScript"] = true
	}
	if nosqlContainsOperator(combined, "$where") {
		reasons["syntax: server-side JavaScript query operator"] = true
		reasons["semantics: server-side query JavaScript can evaluate attacker-controlled predicates"] = true
	}
	if nosqlContainsOperator(combined, "$function") {
		reasons["syntax: server-side function query operator"] = true
		reasons["semantics: server-side query function can evaluate attacker-controlled JavaScript"] = true
	}
	if nosqlContainsOperator(combined, "$eval") {
		reasons["syntax: server-side JavaScript query operator"] = true
		reasons["semantics: server-side query JavaScript can evaluate attacker-controlled predicates"] = true
	}
	if nosqlContainsOperator(combined, "$expr") {
		reasons["syntax: aggregation expression query operator"] = true
		reasons["semantics: expression operator can replace application-side predicate logic"] = true
	}
	if nosqlContainsOperator(combined, "$jsonschema") {
		reasons["syntax: JSON schema query operator"] = true
		reasons["semantics: injected schema can replace expected server-side query constraints"] = true
	}
	if nosqlContainsOperator(combined, "$or", "$and", "$nor") {
		reasons["syntax: logical query branch operator"] = true
		reasons["semantics: injected branch can bypass expected query predicates"] = true
	}
	if nosqlContainsOperator(combined, "$regex") {
		reasons["syntax: regular-expression query operator"] = true
		if nosqlSensitiveContext(name) || nosqlWideRegex.MatchString(lowerText) {
			reasons["semantics: broad regular expression can turn exact-match checks into wildcard matches"] = true
		}
	}
	if nosqlContainsOperator(combined, "$exists") {
		reasons["semantics: field-presence predicate can bypass required value checks"] = true
	}
	if nosqlContainsOperator(combined, "$ne", "$nin", "$gt", "$gte", "$lt", "$lte", "$not") && nosqlSensitiveContext(name) {
		reasons["semantics: comparison operator can replace credential or filter equality"] = true
	}
	if nosqlJSBehavior.MatchString(lowerText) && (nosqlContainsOperator(combined, "$where", "$function") || strings.Contains(name, "$where") || strings.Contains(name, "$function")) {
		reasons["semantics: query predicate contains executable JavaScript behavior"] = true
	}
	if len(reasons) == 0 {
		return Hit{}, false
	}
	if !hasSemanticReason(reasons) {
		if !structuralOperator || !nosqlSensitiveContext(name) {
			return Hit{}, false
		}
		reasons["semantics: structured query operator can change application query behavior"] = true
	}
	severity := engine.SeverityHigh
	confidence := 0.86 + confidenceBonus(reasons)
	if nosqlContainsOperator(combined, "$where", "$function", "$eval") || mapReduce || fieldMapReduce {
		severity = engine.SeverityCritical
		confidence += 0.02
	}
	return hit(candidate, "nosqli", severity, confidence, reasons), true
}

func nosqlMapReduceField(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return false
	}
	parts := strings.FieldsFunc(n, func(r rune) bool {
		return r == '.' || r == '_' || r == '-' || r == '[' || r == ']'
	})
	for _, part := range parts {
		switch part {
		case "map", "reduce", "finalize", "mapreduce":
			return true
		}
	}
	return false
}

func analyzeSSTI(candidate semanticCandidate) (Hit, bool) {
	text := strings.TrimSpace(candidate.text)
	lowerText := normalize(text)
	if !sstiTemplateExpression.MatchString(lowerText) {
		return Hit{}, false
	}
	reasons := map[string]bool{
		"syntax: server-side template expression delimiter": true,
	}
	dangerous := sstiDangerousBehavior.MatchString(lowerText)
	arithmeticProbe := sstiArithmeticProbe.MatchString(lowerText)
	if dangerous {
		reasons["semantics: template expression reaches introspection or execution primitive"] = true
	}
	if strings.Contains(lowerText, "__globals__") || strings.Contains(lowerText, "__subclasses__") || strings.Contains(lowerText, "__mro__") {
		reasons["semantics: template object graph traversal can escape sandboxed data access"] = true
	}
	if strings.Contains(lowerText, "java.lang.runtime") || strings.Contains(lowerText, "processbuilder") || strings.Contains(lowerText, "freemarker.template.utility.execute") ||
		strings.Contains(lowerText, "classloader.loadclass") || strings.Contains(lowerText, "objectspace.each_object") {
		reasons["semantics: template expression can reach host runtime command execution"] = true
	}
	if arithmeticProbe && sstiProbeContext(candidate.input.Name) {
		reasons["syntax: arithmetic template evaluation probe"] = true
		reasons["semantics: probe attempts to confirm server-side template evaluation"] = true
	}
	if !hasSemanticReason(reasons) {
		return Hit{}, false
	}
	severity := engine.SeverityHigh
	confidence := 0.86 + confidenceBonus(reasons)
	if dangerous {
		severity = engine.SeverityCritical
		confidence += 0.02
	}
	if arithmeticProbe && !dangerous {
		severity = engine.SeverityMedium
		confidence = 0.78 + confidenceBonus(reasons)
	}
	return hit(candidate, "ssti", severity, confidence, reasons), true
}

func analyzeXSS(candidate semanticCandidate) (Hit, bool) {
	text := candidate.text
	reasons := map[string]bool{}
	lower := normalize(text)
	if executableXSSContext(lower) {
		reasons["syntax: executable HTML/JavaScript context"] = true
	}
	if javascriptURLContext.MatchString(lower) {
		reasons["syntax: javascript URL in executable HTML attribute"] = true
	}
	if xssDataURLContext.MatchString(lower) {
		reasons["syntax: executable data URI in HTML attribute"] = true
	}
	if xssSrcdocContext.MatchString(lower) {
		reasons["syntax: iframe srcdoc execution context"] = true
	}
	if xssMetaRefreshContext.MatchString(lower) {
		reasons["syntax: meta refresh javascript navigation"] = true
	}
	if xssStyleExecutionContext.MatchString(lower) {
		reasons["syntax: executable CSS expression or javascript URL"] = true
	}
	if strings.Contains(lower, "document.cookie") || strings.Contains(lower, "localstorage") || strings.Contains(lower, "fetch(") {
		reasons["semantics: browser credential or network side effect"] = true
	}
	if len(reasons) == 0 {
		return Hit{}, false
	}
	return hit(candidate, "xss", engine.SeverityHigh, 0.86+confidenceBonus(reasons), reasons), true
}

func analyzeRCE(candidate semanticCandidate) (Hit, bool) {
	text := strings.TrimSpace(candidate.text)
	lower := normalize(text)
	sink := rceExecutionSink(candidate.input.Name)
	reasons := map[string]bool{}
	for _, pattern := range rcePatterns {
		if pattern.MatchString(text) {
			reasons["syntax: shell metacharacter plus executable command"] = true
		}
	}
	// Bare English ";" must not count outside execution sinks (major FP source in docs).
	if sink && rceShellControl.MatchString(text) {
		reasons["syntax: shell control operator or command substitution"] = true
	} else if !sink && rceShellControlEvidence(lower) {
		reasons["syntax: shell control operator or command substitution"] = true
	}
	if rceWhitespaceEvasion.MatchString(text) {
		reasons["syntax: shell whitespace evasion"] = true
	}
	if sink {
		reasons["context: command execution parameter"] = true
	}
	if rcePowerShellSideFx.MatchString(text) || rceEncodedPowerShell.MatchString(text) || rceNetWebClientSideFx.MatchString(text) {
		reasons["semantics: PowerShell dynamic execution or encoded command"] = true
	}
	if rcePowerShellReverseShell.MatchString(text) {
		reasons["semantics: shell reverse connection primitive"] = true
		reasons["semantics: PowerShell dynamic execution or encoded command"] = true
	}
	if rceInterpreterInline.MatchString(text) {
		reasons["semantics: interpreter inline command execution"] = true
	}
	if rceDownloadExecChain.MatchString(text) {
		reasons["semantics: download-to-shell execution chain"] = true
	}
	if rceReverseShellPrimitive.MatchString(text) {
		reasons["semantics: shell reverse connection primitive"] = true
	}
	// Loader/reflective primitives: only count as RCE evidence when tied to an
	// execution sink or another hard shell/runtime signal (avoid doc FPs like
	// "set LD_PRELOAD=/path" in prose without a command parameter).
	if rceLoaderPrimitive.MatchString(text) {
		if sink || rceShellControlEvidence(lower) || rceInterpreterInline.MatchString(text) ||
			rcePowerShellSideFx.MatchString(text) || rceDownloadExecChain.MatchString(text) ||
			rceReverseShellPrimitive.MatchString(text) {
			reasons["semantics: dynamic loader or reflective code loading primitive"] = true
		}
	}
	// Webshell body often lands as multipart content without a cmd= sink name.
	if strings.Contains(lower, "<?php") && (strings.Contains(lower, "eval(") || strings.Contains(lower, "assert(") || strings.Contains(lower, "system(") || strings.Contains(lower, "passthru(") || strings.Contains(lower, "shell_exec(") || strings.Contains(lower, "phpinfo(")) {
		reasons["syntax: PHP template execution delimiter"] = true
		reasons["semantics: PHP runtime command or include execution"] = true
	}
	// Double-extension / null-byte upload names (shell.php%00.jpg, shell.php.jpg).
	if strings.Contains(lower, ".php") && (strings.Contains(lower, "%00") || strings.Contains(lower, "\x00") || strings.Contains(lower, ".php.") || strings.HasSuffix(strings.TrimSpace(lower), ".php")) &&
		(strings.Contains(candidate.input.Name, "filename") || strings.Contains(lower, "shell") || strings.Contains(lower, "cmd") || strings.Contains(lower, "eval")) {
		reasons["semantics: PHP runtime command or include execution"] = true
		reasons["syntax: null-byte path suffix bypass"] = true
	}
	if rceTemplateExecutionPrimitive.MatchString(text) {
		reasons["semantics: template or language runtime command execution primitive"] = true
	}
	if strings.Contains(lower, "<?php") && (strings.Contains(lower, "system(") || strings.Contains(lower, "passthru(") || strings.Contains(lower, "shell_exec(") || strings.Contains(lower, "exec(") || strings.Contains(lower, "include(") || strings.Contains(lower, "require(") || strings.Contains(lower, "eval(")) {
		reasons["semantics: PHP runtime command or include execution"] = true
	}
	// Language runtime calls (also on path_query when query parse fell back).
	if strings.Contains(lower, "system(") || strings.Contains(lower, "passthru(") || strings.Contains(lower, "shell_exec(") || strings.Contains(lower, "exec(") || strings.Contains(lower, "eval(") || strings.Contains(lower, "include(") || strings.Contains(lower, "require(") || strings.Contains(lower, "popen(") {
		if sink || strings.Contains(lower, "cmd=") || strings.Contains(lower, "command=") || strings.Contains(lower, "exec=") || strings.Contains(candidate.input.Name, "cmd") {
			reasons["semantics: language runtime command or include execution"] = true
		}
	}
	if strings.Contains(lower, "{php}") || strings.Contains(lower, "{/php}") {
		reasons["syntax: PHP template execution delimiter"] = true
		reasons["semantics: PHP template runtime execution"] = true
	}
	if sink && (strings.Contains(lower, "print(") || strings.Contains(lower, "md5(")) && (strings.Contains(lower, ";") || strings.Contains(lower, "${")) {
		reasons["semantics: template or language runtime command execution primitive"] = true
	}
	words := tokens(text)
	for _, command := range []string{"cat", "whoami", "uname", "curl", "wget", "bash", "sh", "zsh", "dash", "pwsh", "powershell", "cmd", "python", "python3", "perl", "php", "ruby", "node", "nc", "ncat", "netcat", "socat", "lua", "iex", "invoke-expression", "sleep", "ping", "nslookup"} {
		if contains(words, command) {
			// Tool names alone in prose are not intent; require sink or hard execution shape.
			if sink || rceShellControlEvidence(lower) || rceWhitespaceEvasion.MatchString(text) || rceInterpreterInline.MatchString(text) || rcePowerShellSideFx.MatchString(text) || rceEncodedPowerShell.MatchString(text) || rceDownloadExecChain.MatchString(text) {
				reasons["semantics: command execution intent"] = true
			}
			break
		}
	}
	if strings.Contains(lower, "/usr/bin/") || strings.Contains(lower, "/bin/") || strings.Contains(lower, "$shell") || strings.Contains(lower, "${shell}") {
		reasons["semantics: fully qualified executable or shell interpreter"] = true
	}
	// $SHELL -c / ${SHELL} -c is a classic env-based interpreter invocation (CRS-style).
	if (strings.Contains(lower, "$shell") || strings.Contains(lower, "${shell}")) &&
		(strings.Contains(lower, " -c ") || strings.Contains(lower, " -c\"") || strings.Contains(lower, " -c'")) {
		reasons["semantics: interpreter inline command execution"] = true
	}
	if len(reasons) < 2 {
		return Hit{}, false
	}
	// Outside execution-parameter sinks, require a hard execution signal (FP-first).
	if !sink && !rceHardSignal(reasons) {
		return Hit{}, false
	}
	return hit(candidate, "rce", engine.SeverityCritical, 0.87+confidenceBonus(reasons), reasons), true
}

var rceShellMetacharCommand = regexp.MustCompile(`(?i)(?:;|&&|\|\||\|)\s*(?:cat|id|whoami|uname|curl|wget|bash|sh|zsh|dash|pwsh|powershell|cmd|python3?|perl|php|ruby|node|nc|ncat|netcat|socat|lua|iex|type|dir|ls|sleep|echo|ping)\b`)

func rceShellControlEvidence(lower string) bool {
	if strings.Contains(lower, "$(") || strings.Contains(lower, "&&") || strings.Contains(lower, "||") {
		return true
	}
	// Markdown fenced code uses ``` which must not count as shell backticks.
	// Only leftover single-backtick command substitution is evidence.
	if strings.Contains(strings.ReplaceAll(lower, "```", ""), "`") {
		return true
	}
	return rceShellMetacharCommand.MatchString(lower)
}

func rceHardSignal(reasons map[string]bool) bool {
	return reasons["syntax: shell metacharacter plus executable command"] ||
		reasons["syntax: shell control operator or command substitution"] ||
		reasons["syntax: shell whitespace evasion"] ||
		reasons["semantics: PowerShell dynamic execution or encoded command"] ||
		reasons["semantics: interpreter inline command execution"] ||
		reasons["semantics: download-to-shell execution chain"] ||
		reasons["semantics: shell reverse connection primitive"] ||
		reasons["semantics: template or language runtime command execution primitive"] ||
		reasons["semantics: fully qualified executable or shell interpreter"] ||
		reasons["semantics: PHP runtime command or include execution"] ||
		reasons["semantics: language runtime command or include execution"] ||
		reasons["semantics: PHP template runtime execution"] ||
		reasons["syntax: PHP template execution delimiter"] ||
		reasons["semantics: dynamic loader or reflective code loading primitive"]
}

func rceExecutionSink(name string) bool {
	normalized := strings.ToLower(strings.TrimSpace(name))
	if normalized == "" || normalized == "path_query" || normalized == "path" || normalized == "raw_query" || normalized == "body" {
		return false
	}
	parts := strings.FieldsFunc(normalized, func(r rune) bool {
		return r == '.' || r == '_' || r == '-' || r == '[' || r == ']'
	})
	for _, part := range parts {
		switch part {
		case "cmd", "command", "exec", "execute", "shell", "system", "process", "run", "script", "payload":
			return true
		}
	}
	return false
}

func analyzeLFI(candidate semanticCandidate) (Hit, bool) {
	text := candidate.text
	reasons := map[string]bool{}
	for _, pattern := range lfiPatterns {
		if pattern.MatchString(text) {
			reasons["syntax: traversal or wrapper path expression"] = true
		}
	}
	lower := normalize(text)
	if lfiEncodedTraversal.MatchString(lower) || strings.Contains(lower, "..//") || strings.Contains(lower, `..\/`) || strings.Contains(lower, "....//") {
		reasons["syntax: encoded or overlong traversal path"] = true
	}
	if strings.Contains(lower, "%00") || strings.Contains(lower, "\x00") {
		reasons["syntax: null-byte path suffix bypass"] = true
	}
	if lfiSensitiveTarget.MatchString(lower) {
		reasons["semantics: sensitive local file target"] = true
	}
	if lfiFileReadSink.MatchString(lower) {
		reasons["semantics: application template reads a local file path"] = true
	}
	if lfiCommandReadSink.MatchString(lower) {
		reasons["semantics: command reads a sensitive local file"] = true
	}
	for _, target := range []string{"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/hosts", "/etc/hostname", "/etc/fstab", "/etc/sudoers", "/etc/crontab", "/etc/nginx/nginx.conf", "/etc/apache2/apache2.conf", "/etc/redis/redis.conf", "/etc/mysql/my.cnf", "/etc/php/php.ini", "/etc/ssh/sshd_config", "/proc/self/environ", "/proc/self/cmdline", "/proc/self/maps", "/proc/version", "/proc/cpuinfo", "/root/.bash_history", "boot.ini", "win.ini", "web-inf/web.xml", "meta-inf/manifest.mf", ".htaccess", ".aws/credentials", ".git/config", ".env", ".ssh/id_rsa", "wp-config", "_config.php", "dump.sql", "database.sql", "/var/log/syslog", "/var/log/auth.log", "/var/log/nginx/access.log", "/var/log/apache2/access.log", "httpd-access.log", "/var/run/secrets/kubernetes.io/serviceaccount/token"} {
		if strings.Contains(lower, target) {
			reasons["semantics: sensitive local file target"] = true
			break
		}
	}
	if strings.Contains(lower, "php://") || strings.Contains(lower, "zip://") || strings.Contains(lower, "phar://") || strings.Contains(lower, "expect://") {
		reasons["syntax: traversal or wrapper path expression"] = true
		reasons["semantics: stream wrapper local file access"] = true
	}
	// data:// wrappers used for inline PHP include/RFI-style LFI.
	if strings.Contains(lower, "data://") && (strings.Contains(lower, "base64") || strings.Contains(lower, "php") || strings.Contains(lower, "text/plain")) {
		reasons["syntax: traversal or wrapper path expression"] = true
		reasons["semantics: stream wrapper local file access"] = true
	}
	if strings.Contains(lower, "docker.sock") || strings.Contains(lower, "/run/docker.sock") || strings.Contains(lower, "/var/run/docker.sock") {
		reasons["semantics: sensitive local file target"] = true
		reasons["syntax: traversal or wrapper path expression"] = true
	}
	// RFI: remote URL into file/include sinks (not plain SSRF fetch fields).
	if lfiRemoteIncludeContext(candidate.input.Name, lower) {
		reasons["syntax: traversal or wrapper path expression"] = true
		reasons["semantics: remote file include target"] = true
	}
	// FP-first: bare filenames without traversal/wrapper/sensitive path must not block.
	if len(reasons) == 0 {
		return Hit{}, false
	}
	if !hasSyntaxReason(reasons) && !hasSemanticReason(reasons) {
		return Hit{}, false
	}
	// Require either (traversal/wrapper) or (sensitive target) — not a lone weak token.
	hasPathSignal := reasons["syntax: traversal or wrapper path expression"] ||
		reasons["syntax: encoded or overlong traversal path"] ||
		reasons["syntax: null-byte path suffix bypass"] ||
		reasons["semantics: sensitive local file target"] ||
		reasons["semantics: stream wrapper local file access"] ||
		reasons["semantics: remote file include target"] ||
		reasons["semantics: application template reads a local file path"] ||
		reasons["semantics: command reads a sensitive local file"]
	if !hasPathSignal {
		return Hit{}, false
	}
	return hit(candidate, "lfi", engine.SeverityHigh, 0.85+confidenceBonus(reasons), reasons), true
}

// lfiRemoteIncludeContext is true when a file/include-style parameter carries a remote URL.
// Excludes documentation fields and pure fetch/url sinks (handled by SSRF).
func lfiRemoteIncludeContext(name, lower string) bool {
	if !(strings.Contains(lower, "http://") || strings.Contains(lower, "https://") || strings.Contains(lower, "ftp://")) {
		return false
	}
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return false
	}
	// Avoid turning every SSRF fetch param into LFI.
	if strings.Contains(n, "url") || strings.Contains(n, "uri") || strings.Contains(n, "callback") || strings.Contains(n, "webhook") || strings.Contains(n, "endpoint") {
		return false
	}
	parts := strings.FieldsFunc(n, func(r rune) bool {
		return r == '.' || r == '_' || r == '-' || r == '[' || r == ']'
	})
	for _, part := range parts {
		switch part {
		case "file", "filename", "path", "page", "include", "require", "template", "tpl", "doc", "document", "view", "lang", "locale":
			return true
		}
	}
	return false
}

func analyzeXXE(candidate semanticCandidate) (Hit, bool) {
	text := strings.TrimSpace(candidate.text)
	lower := normalize(text)
	if !xxePayloadContext(candidate, lower) {
		return Hit{}, false
	}
	reasons := map[string]bool{}
	syntax := strings.Contains(lower, "<!doctype") && strings.Contains(lower, "<!entity")
	external := strings.Contains(lower, "system") || strings.Contains(lower, "public")
	target := xxeDangerousTarget(lower)
	xinclude := strings.Contains(lower, "xinclude") || strings.Contains(lower, "xi:include")
	if syntax {
		reasons["syntax: XML DTD with entity declaration"] = true
	}
	if strings.Contains(lower, "<!entity %") {
		reasons["syntax: XML parameter entity declaration"] = true
	}
	if xinclude {
		reasons["syntax: XML XInclude expansion"] = true
		reasons["semantics: external entity resolution"] = true
	}
	if external {
		reasons["semantics: external entity resolution"] = true
	}
	if target {
		reasons["semantics: file or network disclosure target"] = true
	}
	// Classic XXE: DTD+entity+external+target. XInclude can stand with target.
	if syntax && external && target {
		return hit(candidate, "xxe", engine.SeverityHigh, 0.84+confidenceBonus(reasons), reasons), true
	}
	if xinclude && target {
		return hit(candidate, "xxe", engine.SeverityHigh, 0.83+confidenceBonus(reasons), reasons), true
	}
	return Hit{}, false
}

func xxePayloadContext(candidate semanticCandidate, lower string) bool {
	hasEntity := strings.Contains(lower, "<!entity")
	hasXInclude := strings.Contains(lower, "xinclude") || strings.Contains(lower, "xi:include")
	if !hasEntity && !hasXInclude {
		return false
	}
	if hasEntity && !xxeLooksLikeXMLPayload(lower) {
		return false
	}
	if hasXInclude && !strings.Contains(lower, "<") {
		return false
	}
	source := candidate.input.Source
	name := strings.ToLower(strings.TrimSpace(candidate.input.Name))
	if source == "body.raw" {
		return true
	}
	if xxeDocumentationField(name) {
		return false
	}
	switch source {
	case "query", "body.form", "body.json", "body.multipart":
		return xxePayloadField(name)
	default:
		return false
	}
}

func xxeLooksLikeXMLPayload(lower string) bool {
	trimmed := strings.TrimSpace(lower)
	if strings.HasPrefix(trimmed, "<?xml") ||
		strings.HasPrefix(trimmed, "<!doctype") ||
		strings.HasPrefix(trimmed, "<soap") ||
		strings.HasPrefix(trimmed, "<saml") ||
		strings.HasPrefix(trimmed, "<assertion") ||
		strings.HasPrefix(trimmed, "<svg") {
		return true
	}
	return strings.Contains(trimmed, "<!doctype") && strings.Contains(trimmed, "<!entity")
}

func xxePayloadField(name string) bool {
	if name == "" {
		return false
	}
	parts := strings.FieldsFunc(name, func(r rune) bool {
		return r == '.' || r == '_' || r == '-' || r == '[' || r == ']'
	})
	for _, part := range parts {
		switch part {
		case "xml", "body", "payload", "document", "soap", "saml", "assertion", "metadata", "dtd", "entity":
			return true
		}
	}
	return false
}

func xxeDocumentationField(name string) bool {
	if name == "" {
		return false
	}
	parts := strings.FieldsFunc(name, func(r rune) bool {
		return r == '.' || r == '_' || r == '-' || r == '[' || r == ']'
	})
	for _, part := range parts {
		switch part {
		case "text", "note", "notes", "description", "desc", "docs", "docstring", "markdown", "article", "example", "examples", "content":
			return true
		}
	}
	return false
}

func xxeDangerousTarget(lower string) bool {
	for _, marker := range []string{"file://", "http://", "https://", "ftp://", "php://", "expect://", "gopher://", "dict://", "jar://", "netdoc:", "169.254.169.254", "metadata.google.internal"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	// XInclude / parameter-entity OOB shapes without classic SYSTEM string in same fragment.
	if strings.Contains(lower, "xinclude") || strings.Contains(lower, "xi:include") ||
		(strings.Contains(lower, "<!entity %") && (strings.Contains(lower, "http://") || strings.Contains(lower, "https://") || strings.Contains(lower, "file:"))) {
		return true
	}
	return lfiSensitiveTarget.MatchString(lower)
}

func analyzeSSRF(candidate semanticCandidate) (Hit, bool) {
	if !ssrfFetchSink(candidate) {
		return Hit{}, false
	}
	payload := decoder.Decode(candidate.text).Text
	target, reason, ok := ssrfDangerousTarget(payload)
	if !ok {
		return Hit{}, false
	}
	semantics := "semantics: target resolves to loopback, private, link-local, or metadata network"
	confidence := 0.86
	reasonLower := strings.ToLower(reason)
	if strings.Contains(reasonLower, "file scheme") {
		semantics = "semantics: local file URL scheme would make the server access host files"
		confidence = 0.88
	}
	if strings.Contains(reasonLower, "target host") {
		semantics = "semantics: fetch sink received a bare host that resolves to loopback, private, link-local, or metadata network"
		confidence = 0.84
	}
	if strings.Contains(reasonLower, "rebind") {
		semantics = "semantics: fetch sink points at DNS-rebind helper host used to pivot to internal networks"
		confidence = 0.87
	}
	return Hit{
		Category:   "ssrf",
		Source:     candidate.input.Source,
		Name:       candidate.input.Name,
		Syntax:     "syntax: URL or host parameter accepted by request",
		Semantics:  semantics,
		Severity:   engine.SeverityHigh,
		Confidence: confidence,
		Payload:    strings.TrimSpace(target),
	}, true
}

func ssrfFetchSink(candidate semanticCandidate) bool {
	name := strings.ToLower(strings.TrimSpace(candidate.input.Name))
	if name == "" || name == "path_query" || name == "path" || name == "raw_query" || name == "body" || name == "text" || name == "content" || name == "message" || name == "description" {
		return false
	}
	if candidate.input.Source == "header" {
		switch name {
		case "x-forwarded-host", "x-forwarded-url", "x-original-url", "x-rewrite-url", "forwarded", "referer", "origin":
			return true
		default:
			return strings.Contains(name, "url") || strings.Contains(name, "uri")
		}
	}
	parts := strings.FieldsFunc(name, func(r rune) bool {
		return r == '.' || r == '_' || r == '-' || r == '[' || r == ']'
	})
	for _, part := range parts {
		switch part {
		case "url", "uri", "link", "href", "src", "host", "domain", "endpoint", "callback", "webhook", "redirect", "return", "next", "target", "dest", "destination", "fetch", "proxy", "source", "remote", "image", "avatar", "feed":
			return true
		}
	}
	return false
}

func hit(candidate semanticCandidate, category string, severity engine.Severity, confidence float64, reasons map[string]bool) Hit {
	parts := sortedReasons(reasons)
	var syntax, semantics, context []string
	for _, reason := range parts {
		switch {
		case strings.HasPrefix(reason, "syntax:"):
			syntax = append(syntax, strings.TrimSpace(strings.TrimPrefix(reason, "syntax:")))
		case strings.HasPrefix(reason, "semantics:"):
			semantics = append(semantics, strings.TrimSpace(strings.TrimPrefix(reason, "semantics:")))
		case strings.HasPrefix(reason, "context:"):
			context = append(context, strings.TrimSpace(strings.TrimPrefix(reason, "context:")))
		}
	}
	// Do not invent filler evidence: FP-first blockableHit relies on real signals only.
	syntaxText := "syntax: none"
	if len(syntax) > 0 {
		syntaxText = "syntax: " + strings.Join(syntax, ", ")
	} else if len(context) > 0 {
		syntaxText = "syntax: " + strings.Join(context, ", ")
	}
	semanticsText := "semantics: none"
	if len(semantics) > 0 {
		semanticsText = "semantics: " + strings.Join(semantics, ", ")
	}
	if confidence > 0.99 {
		confidence = 0.99
	}
	return Hit{
		Category:   category,
		Source:     candidate.input.Source,
		Name:       candidate.input.Name,
		Syntax:     syntaxText,
		Semantics:  semanticsText,
		Severity:   severity,
		Confidence: confidence,
		Payload:    strings.TrimSpace(candidate.text),
	}
}

func sortedReasons(reasons map[string]bool) []string {
	out := make([]string, 0, len(reasons))
	for reason := range reasons {
		out = append(out, reason)
	}
	sort.Strings(out)
	return out
}

func confidenceBonus(reasons map[string]bool) float64 {
	if len(reasons) <= 1 {
		return 0
	}
	return float64(len(reasons)-1) * 0.025
}

func hasSemanticReason(reasons map[string]bool) bool {
	for reason := range reasons {
		if strings.HasPrefix(reason, "semantics:") {
			return true
		}
	}
	return false
}

func hasSyntaxReason(reasons map[string]bool) bool {
	for reason := range reasons {
		if strings.HasPrefix(reason, "syntax:") || strings.HasPrefix(reason, "context:") {
			return true
		}
	}
	return false
}

// blockableHit enforces the FP-first policy for production block mode:
// weak single-signal hits must not block legitimate traffic.
// Prefer miss over wrong block.
func blockableHit(h Hit) bool {
	if h.Category == "" || h.Payload == "" {
		return false
	}
	syntaxOK := h.Syntax != "" && !strings.HasSuffix(h.Syntax, "none") && !strings.Contains(h.Syntax, "attack grammar matched")
	semanticsOK := h.Semantics != "" && !strings.HasSuffix(h.Semantics, "none") && !strings.Contains(h.Semantics, "malicious behavior inferred from context")
	if syntaxOK && semanticsOK {
		return true
	}
	switch h.Category {
	case "xss":
		// Executable HTML/JS contexts already embed multi-part structure.
		return syntaxOK && (strings.Contains(h.Syntax, "executable") || strings.Contains(h.Syntax, ",") || strings.Contains(h.Syntax, "javascript") || strings.Contains(h.Syntax, "srcdoc") || strings.Contains(h.Syntax, "data URI"))
	case "rce":
		// analyzeRCE already requires ≥2 reasons.
		return (syntaxOK || semanticsOK) && (strings.Contains(h.Syntax, ",") || semanticsOK || syntaxOK && semanticsOK || strings.Contains(h.Syntax, "shell") || strings.Contains(h.Semantics, "command") || strings.Contains(h.Semantics, "PowerShell") || strings.Contains(h.Semantics, "interpreter") || strings.Contains(h.Semantics, "download"))
	case "xxe":
		return syntaxOK && semanticsOK
	case "sqli":
		// Side-effect-only SQL (time delay, destructive ops, file/cmd primitives) is blockable.
		if semanticsOK {
			return true
		}
		if !syntaxOK {
			return false
		}
		return strings.Contains(h.Syntax, "UNION") ||
			strings.Contains(h.Syntax, "tautology") ||
			strings.Contains(h.Syntax, "comment") ||
			strings.Contains(h.Syntax, "OR predicate") ||
			strings.Contains(h.Syntax, "ORDER/GROUP") ||
			strings.Contains(h.Syntax, "HAVING") ||
			strings.Contains(h.Syntax, "SQL function comparison") ||
			strings.Contains(h.Syntax, "boolean-blind") ||
			strings.Contains(h.Syntax, "SELECT WHERE") ||
			strings.Contains(h.Syntax, ",")
	case "lfi":
		return (syntaxOK && semanticsOK) ||
			(syntaxOK && (strings.Contains(h.Syntax, "wrapper") || strings.Contains(h.Syntax, "traversal"))) ||
			(semanticsOK && strings.Contains(h.Semantics, "sensitive"))
	case "ssrf":
		return syntaxOK || semanticsOK
	case "nosqli", "ssti":
		return syntaxOK && semanticsOK || semanticsOK
	default:
		return syntaxOK && semanticsOK
	}
}

// sqlReasonsBlockable requires multi-signal or high-precision SQL evidence before a Hit is emitted.
func sqlReasonsBlockable(reasons map[string]bool) bool {
	if len(reasons) == 0 {
		return false
	}
	// Any explicit semantic side-effect is enough (time delay, destructive, file/cmd).
	if hasSemanticReason(reasons) {
		return true
	}
	if len(reasons) >= 2 && hasSyntaxReason(reasons) {
		return true
	}
	// High-precision single syntax compositions (not lone SELECT/FROM docs).
	for reason := range reasons {
		if strings.Contains(reason, "UNION") ||
			strings.Contains(reason, "tautology") ||
			strings.Contains(reason, "comment") ||
			strings.Contains(reason, "OR predicate") ||
			strings.Contains(reason, "ORDER/GROUP") ||
			strings.Contains(reason, "HAVING") ||
			strings.Contains(reason, "regex or LIKE") ||
			strings.Contains(reason, "SQL function comparison") ||
			strings.Contains(reason, "boolean-blind") ||
			strings.Contains(reason, "SELECT WHERE") {
			return true
		}
	}
	return false
}

func nosqlStructuredSource(source string) bool {
	switch source {
	case "query", "body.form", "body.json", "body.raw", "cookie":
		return true
	default:
		return false
	}
}

func nosqlOperatorInPath(value string) bool {
	lower := strings.ToLower(value)
	for _, op := range nosqlOperatorNames {
		if lower == op ||
			strings.Contains(lower, "."+op) ||
			strings.Contains(lower, op+"[]") ||
			strings.Contains(lower, "["+op+"]") ||
			strings.Contains(lower, "["+op+"].") {
			return true
		}
	}
	return false
}

func nosqlContainsOperator(value string, operators ...string) bool {
	lower := strings.ToLower(value)
	for _, op := range operators {
		if strings.Contains(lower, strings.ToLower(op)) {
			return true
		}
	}
	return false
}

func nosqlSensitiveContext(name string) bool {
	lower := strings.ToLower(name)
	for _, term := range []string{
		"user", "username", "login", "email", "account", "password", "passwd", "pass", "pwd",
		"auth", "credential", "token", "session", "filter", "query", "where", "selector",
		"criteria", "condition", "search", "role", "tenant", "owner", "id",
	} {
		if strings.Contains(lower, term) {
			return true
		}
	}
	return false
}

func nosqlDocumentationContext(name string) bool {
	lower := strings.ToLower(name)
	for _, term := range []string{"text", "content", "docs", "doc", "documentation", "description", "lesson", "example", "guide", "article", "markdown", "body"} {
		if strings.Contains(lower, term) {
			return true
		}
	}
	return false
}

func nosqlLooksLikeStructuredPayload(text string) bool {
	if !nosqlOperatorToken.MatchString(text) {
		return false
	}
	return strings.Contains(text, "{") ||
		strings.Contains(text, "[") ||
		strings.Contains(text, ":") ||
		strings.Contains(text, "=")
}

func sstiProbeContext(name string) bool {
	lower := strings.ToLower(name)
	for _, excluded := range []string{"text", "content", "body", "markdown", "doc", "docs", "example", "template"} {
		if lower == excluded || strings.Contains(lower, excluded) {
			return false
		}
	}
	for _, term := range []string{
		"name", "display", "username", "nickname", "title", "subject", "q", "query", "search",
		"message", "comment", "redirect", "next", "url", "path", "payload", "value",
	} {
		if lower == term || strings.Contains(lower, term) {
			return true
		}
	}
	return false
}

func containsOrdered(words []string, sequence ...string) bool {
	if len(sequence) == 0 {
		return true
	}
	pos := 0
	for _, word := range words {
		if word == sequence[pos] {
			pos++
			if pos == len(sequence) {
				return true
			}
		}
	}
	return false
}

func printableRatio(value string) float64 {
	if value == "" {
		return 0
	}
	var printable int
	for _, r := range value {
		if r == '\n' || r == '\r' || r == '\t' || (r >= 32 && r < 127) {
			printable++
		}
	}
	return float64(printable) / float64(len([]rune(value)))
}

func skipHeader(key string) bool {
	switch strings.ToLower(key) {
	case "accept", "accept-encoding", "accept-language", "connection", "content-length",
		"content-type", "host", "cache-control", "pragma", "upgrade-insecure-requests",
		"sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "sec-fetch-user",
		"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "dnt", "priority",
		"if-none-match", "if-modified-since", "range", "te", "trailer", "transfer-encoding":
		return true
	default:
		return false
	}
}

func toString(value any) string {
	switch typed := value.(type) {
	case json.Number:
		return typed.String()
	case bool:
		if typed {
			return "true"
		}
		return "false"
	case float64:
		return fmt.Sprint(typed)
	default:
		return ""
	}
}
