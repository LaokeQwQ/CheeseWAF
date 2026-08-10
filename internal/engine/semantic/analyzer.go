package semantic

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
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
	// paranoiaLevel controls block decision sensitivity (0=off, 1=low, 2=default, 3=high, 4=paranoid).
	paranoiaLevel int
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

func NewAnalyzer(mode string, paranoiaLevel int, categories ...string) *Analyzer {
	if mode == "" {
		mode = "block"
	}
	enabled := map[string]bool{}
	if len(categories) == 0 {
		for _, category := range []string{"sqli", "xss", "rce", "lfi", "xxe", "ssrf", "nosqli", "ssti", "webshell", "log4shell"} {
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
	return &Analyzer{mode: mode, enabled: enabled, catFP: enabledCategoryFingerprint(enabled), paranoiaLevel: paranoiaLevel}
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

	candidates := extractCandidatesWithAllowlist(reqCtx, a.paramAllowlist)
	report, best, haveBest, incomplete := a.analyzeAllCandidates(ctx, candidates)
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
	if !haveBest {
		return nil, nil
	}
	action := actionForMode(a.mode)
	if a.mode == "block" && !a.blockableHit(best) {
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
		DetectorID: analyzerDetectorID(best.Category),
		Category:   best.Category,
		Severity:   best.Severity,
		Action:     action,
		Message:    best.Syntax + "; " + best.Semantics,
		Confidence: best.Confidence,
		Payload:    best.Payload,
	}, nil
}

// analyzerDetectorIDs holds the precomputed "semantic.analyzer.<category>"
// strings. Detect built this with a runtime concat on every hit, which is one
// allocation per blocked request for a fixed set of eight categories.
var analyzerDetectorIDs = map[string]string{
	"sqli":       "semantic.analyzer.sqli",
	"xss":        "semantic.analyzer.xss",
	"rce":        "semantic.analyzer.rce",
	"lfi":        "semantic.analyzer.lfi",
	"xxe":        "semantic.analyzer.xxe",
	"ssrf":       "semantic.analyzer.ssrf",
	"nosqli":     "semantic.analyzer.nosqli",
	"ssti":       "semantic.analyzer.ssti",
	"webshell":   "semantic.analyzer.webshell",
	"log4shell":  "semantic.analyzer.log4shell",
	"shellshock": "semantic.analyzer.shellshock",
}

// analyzerDetectorID returns the detector ID for a hit category, falling back to
// the original concat for any category outside the known set.
func analyzerDetectorID(category string) string {
	if id, ok := analyzerDetectorIDs[category]; ok {
		return id
	}
	return "semantic.analyzer." + category
}

// analyzeAllCandidates runs field analysis. Multi-field requests use a bounded
// worker pool so multi-core CPUs scan independent parameters concurrently while
// preserving FP-first merge rules and stable Input ordering.
// incomplete is true only when the context cancelled mid-scan (fields skipped).
// best is only meaningful when haveBest is true; returning it by value keeps the
// winning Hit off the heap (the previous *Hit escaped on every hit).
func (a *Analyzer) analyzeAllCandidates(ctx context.Context, candidates []semanticCandidate) (AnalysisReport, Hit, bool, bool) {
	var merge candidateMerge
	merge.report.Inputs = make([]InputPoint, 0, len(candidates))
	if len(candidates) == 0 {
		return merge.report, Hit{}, false, false
	}

	// Sequential for tiny requests (lower scheduling overhead). Keeps the
	// critical-hit early exit: with one or two fields there is nothing to gain
	// from scanning past a decided block.
	if len(candidates) < 3 {
		incomplete := false
		for _, candidate := range candidates {
			if err := ctx.Err(); err != nil {
				incomplete = true
				break
			}
			merge.report.Inputs = append(merge.report.Inputs, candidate.input)
			merge.add(a.mode, a, a.analyzeCandidate(candidate))
			if a.mode == "block" && merge.haveBest &&
				merge.best.Severity >= engine.SeverityCritical && merge.best.Confidence >= 0.92 {
				break
			}
		}
		merge.finish()
		return merge.report, merge.best, merge.haveBest, incomplete
	}

	// Mid-size requests: byte-for-byte the same report/best/incomplete as the
	// worker pool below (every field scanned, index-ordered merge, no early
	// exit) but without the pool's fixed cost. Spawning goroutines plus the
	// escaping WaitGroup/atomic counter was 6 allocations and more scheduler
	// time than the few extra field scans it overlapped.
	if len(candidates) < parallelCandidateThreshold {
		skipped := false
		for i := range candidates {
			merge.report.Inputs = append(merge.report.Inputs, candidates[i].input)
			if ctx.Err() != nil {
				skipped = true
				continue
			}
			merge.add(a.mode, a, a.analyzeCandidate(candidates[i]))
		}
		merge.finish()
		return merge.report, merge.best, merge.haveBest, skipped
	}

	type fieldOut struct {
		input InputPoint
		hits  []Hit
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
	scan := func() {
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
	}
	// The caller runs as one of the workers, so only workers-1 goroutines are
	// spawned. Same work-stealing distribution, one less handoff per request.
	for w := 1; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			scan()
		}()
	}
	scan()
	wg.Wait()

	for i := range outs {
		merge.report.Inputs = append(merge.report.Inputs, outs[i].input)
		merge.add(a.mode, a, outs[i].hits)
	}
	merge.finish()
	return merge.report, merge.best, merge.haveBest, skipped.Load()
}

// parallelCandidateThreshold is the candidate count at which the bounded worker
// pool starts paying for itself. Below it the sequential mid-size path produces
// identical output for less cost.
const parallelCandidateThreshold = 8

// candidateMerge accumulates per-field results under the FP-first merge rules.
// Shared by the sequential and pooled paths so all three code paths cannot drift
// apart in how they pick best / score anomalies.
type candidateMerge struct {
	report       AnalysisReport
	best         Hit
	haveBest     bool
	anomalyScore int
	anomalyNotes []string
}

func (m *candidateMerge) add(mode string, a *Analyzer, hits []Hit) {
	for _, next := range hits {
		if note, pts := anomalyContribution(next); pts > 0 {
			m.anomalyScore += pts
			if len(m.anomalyNotes) < 8 {
				m.anomalyNotes = append(m.anomalyNotes, note)
			}
		}
		if mode == "block" && !a.blockableHit(next) {
			continue
		}
		m.report.Hits = append(m.report.Hits, next)
		if !m.haveBest || betterHit(next, m.best) {
			m.best = next
			m.haveBest = true
		}
	}
}

// finish folds the anomaly tally into the report. Callers read report/best/
// haveBest directly off the struct so the winning Hit never needs a heap copy.
func (m *candidateMerge) finish() {
	if m.anomalyScore > 0 {
		m.report.AnomalyScore = m.anomalyScore
		m.report.AnomalyNotes = m.anomalyNotes
	}
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

	cacheable := len(candidate.text) <= maxCacheableCandidateBytes
	var key uint64
	if cacheable {
		key = candidateCacheKey(a.mode, a.catFP, candidate.input.Source, candidate.input.Name, candidate.text)
		if cached, ok := processCandidateCache.get(key); ok {
			ProcessMetrics().RecordCache(true)
			return cached
		}
		ProcessMetrics().RecordCache(false)
	}

	guesses := guessCategories(candidate.text)
	if len(guesses) == 0 {
		if cacheable {
			processCandidateCache.put(key, nil)
		}
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
	if cacheable {
		processCandidateCache.put(key, hits)
	}
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
	case "log4shell", "shellshock":
		return 100
	case "webshell":
		return 98
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
		if strings.Contains(payloadContext, "into outfile") ||
			strings.Contains(payloadContext, "xp_cmdshell") ||
			strings.Contains(payloadContext, "openrowset") ||
			strings.Contains(payloadContext, "copy ") && strings.Contains(payloadContext, " to program") {
			return 99
		}
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
	maxInputRawBytes           = 16 << 10 // 16 KiB per field
	maxCacheableCandidateBytes = 2 << 10  // bound process-cache retained payload memory
	maxCandidates              = 64
	// dedupMapThreshold is the candidate count at which the fingerprint map stops
	// being more expensive than the linear exact compare it guards. Below it the
	// map is never allocated; ordinary requests never reach it.
	dedupMapThreshold = 12
	maxDecodeVariants          = 8
	maxJSONNodes               = 200
	maxJSONDepth               = 8
	maxJSONTreeDecodeBytes     = 256 << 10
)

// rawCoverageSignal is not a detector or block decision. It only selects the
// most useful bounded window from an oversized value and promotes suspicious
// inputs when a request exceeds the global candidate budget. Final decisions
// still go through the category-specific syntax and semantic analyzers.
var rawCoverageSignal = regexp.MustCompile(`(?i)(?:\$\{\s*jndi\s*:|<\?(?:php|=)|<!\s*(?:doctype|entity)|<\s*script\b|javascript\s*:|(?:;|&&|\|\||\|)\s*(?:cat|id|whoami|uname|curl|wget|bash|sh|zsh|dash|pwsh|powershell|cmd|python3?|perl|php|ruby|node|nc|ncat|netcat|socat|lua|iex|type|dir|ls|sleep|echo|ping)\b|(?:union(?:\s|%20)+(?:all(?:\s|%20)+)?select|(?:or|and)(?:\s|%20)+\d+(?:\s|%20)*=(?:\s|%20)*\d+)|\.\.[/\\]|%2e%2e(?:%2f|/)|\{\{|\{%|%\{|<%|\$(?:where|function|eval|regex|ne|gt|gte|lt|lte)\b|https?://(?:127(?:\.\d+){3}|169\.254(?:\.\d+){2}|localhost\b)|\(\)\s*\{)`)

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
	return extractCandidatesWithAllowlist(reqCtx, nil)
}

// extractCandidatesWithAllowlist applies parameter exclusions before the
// bounded candidate budget. Filtering after truncation lets an attacker fill
// the budget with allowlisted fields and hide a later unallowlisted payload.
func extractCandidatesWithAllowlist(reqCtx *engine.RequestContext, allow map[string]struct{}) []semanticCandidate {
	if reqCtx == nil || reqCtx.Request == nil {
		return nil
	}
	r := reqCtx.Request
	// Fast-path health/static probes: no query, no body, benign path → zero work.
	if isBenignProbePath(r.URL.Path) && r.URL.RawQuery == "" &&
		(r.Method == http.MethodGet || r.Method == http.MethodHead) &&
		len(reqCtx.DecodedBody) == 0 && !hasInspectableHeaders(r.Header) {
		return nil
	}

	groups := make([][]InputPoint, 0, 5)
	var allowSkipped int
	add := func(group *[]InputPoint, input InputPoint) {
		if paramAllowlisted(input.Source, input.Name, allow) {
			allowSkipped++
			return
		}
		*group = append(*group, input)
	}
	uriInputs := make([]InputPoint, 0, 2)
	// Path only for ordinary traffic — avoid re-scanning the full RequestURI
	// (which previously doubled work with per-param query extraction).
	pathRaw := r.URL.EscapedPath()
	if pathRaw == "" {
		pathRaw = r.URL.Path
	}
	if pathRaw != "" && pathRaw != "/" {
		add(&uriInputs, InputPoint{Source: "uri", Name: "path", Raw: clipRaw(pathRaw), Layers: rawLayersOnly})
	}
	// url.Query() allocates a url.Values map even for an empty RawQuery, and the
	// loop below would then iterate zero times. Skip the whole step instead.
	if r.URL.RawQuery != "" {
		queryValues := mergeQueryValues(r.URL.RawQuery, r.URL.Query())
		queryInputs := make([]InputPoint, 0, len(queryValues)*2)
		// Sort keys to make candidate order deterministic across runs. Map iteration
		// randomness + maxCandidates cap creates an architectural flaw where a payload
		// beyond the cap can be scanned on one request and skipped on the next.
		keys := make([]string, 0, len(queryValues))
		for key := range queryValues {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			values := queryValues[key]
			add(&queryInputs, InputPoint{Source: "query", Name: key, Raw: clipRaw(key), Layers: rawLayersOnly})
			for _, value := range values {
				add(&queryInputs, InputPoint{Source: "query", Name: key, Raw: clipRaw(value), Layers: rawLayersOnly})
			}
		}
		groups = append(groups, queryInputs)
	}
	// Suspicious raw query (shell glue) — keep a single fused candidate so
	// payloads that standard ParseQuery splits still get analyzed.
	if raw := r.URL.RawQuery; raw != "" && suspiciousRawQuery(raw) {
		add(&uriInputs, InputPoint{Source: "uri", Name: "raw_query", Raw: clipRaw(raw), Layers: rawLayersOnly})
	}
	groups = append([][]InputPoint{uriInputs}, groups...)

	headerInputs := make([]InputPoint, 0, len(r.Header))
	// Sort header keys for deterministic order.
	headerKeys := make([]string, 0, len(r.Header))
	for key := range r.Header {
		if !skipHeader(key) {
			headerKeys = append(headerKeys, key)
		}
	}
	sort.Strings(headerKeys)
	for _, key := range headerKeys {
		for _, value := range r.Header[key] {
			add(&headerInputs, InputPoint{Source: "header", Name: key, Raw: clipRaw(value), Layers: rawLayersOnly})
		}
	}
	groups = append(groups, headerInputs)

	cookies := r.Cookies()
	cookieInputs := make([]InputPoint, 0, len(cookies))
	for _, cookie := range cookies {
		add(&cookieInputs, InputPoint{Source: "cookie", Name: cookie.Name, Raw: clipRaw(cookie.Value), Layers: rawLayersOnly})
	}
	groups = append(groups, cookieInputs)
	bodyGroup := make([]InputPoint, 0, 4)
	for _, input := range bodyInputs(r, reqCtx.DecodedBody) {
		add(&bodyGroup, input)
	}
	groups = append(groups, bodyGroup)
	if allowSkipped > 0 {
		ProcessMetrics().RecordAllowlistSkip("param")
	}
	if totalInputPoints(groups) > maxCandidates {
		if priority := priorityInputPoints(groups); len(priority) > 0 {
			groups = append([][]InputPoint{priority}, groups...)
		}
	}

	// Size to the work actually present rather than to the maxCandidates ceiling.
	// Ordinary traffic carries a handful of fields, and the overwhelmingly common
	// case is one variant per field, so reserving 64 slots allocated ~40x more
	// than a typical request ever filled — that single line was 44% of all bytes
	// allocated by the analyzer. The cap still bounds pathological requests.
	expected := totalInputPoints(groups)
	if expected > maxCandidates {
		expected = maxCandidates
	}
	candidates := make([]semanticCandidate, 0, expected)
	// Dedup on a cheap 64-bit fingerprint of source+name+text instead of building
	// a concatenated string key per variant (that concat was 3 allocs/req).
	// Collisions only ever drop a duplicate-looking candidate, so guard with an
	// exact compare against the already-kept candidates before skipping.
	//
	// The map is a performance guard, not the correctness oracle: dedupHit's exact
	// compare is. Skipping requires both a fingerprint hit and an exact match, and
	// any exact duplicate must already have inserted its own fingerprint, so
	// "fingerprint seen AND exact dup" is equivalent to "exact dup" alone. That
	// makes the map safe to omit while the candidate list is short enough for the
	// linear compare to be the cheaper of the two, which is the common case and
	// avoids a 128-bucket map allocation per request.
	var seen map[uint64]struct{}
	// Stack scratch: the overwhelmingly common case is exactly one variant.
	var variantScratch [maxDecodeVariants]decodedVariant
	cursors := make([]fairInputCursor, len(groups))
	for i := range groups {
		cursors[i] = fairInputCursor{inputs: groups[i], right: len(groups[i]) - 1}
	}
	for {
		progressed := false
		for i := range cursors {
			input, ok := cursors[i].next()
			if !ok {
				continue
			}
			progressed = true
			variants := decodeVariantsInto(variantScratch[:0], input.Raw)
			for _, variant := range variants {
				if len(candidates) >= maxCandidates {
					break
				}
				text := strings.TrimSpace(variant.text)
				if text == "" {
					continue
				}
				// Below the threshold the linear exact compare over a short slice
				// beats hashing plus a map probe, so the map is never built. Above
				// it, build the map once and backfill the fingerprints already
				// accepted so the guard stays complete.
				if seen == nil && len(candidates) >= dedupMapThreshold {
					seen = make(map[uint64]struct{}, maxCandidates)
					for i := range candidates {
						seen[candidateDedupKey(candidates[i].input.Source, candidates[i].input.Name, candidates[i].text)] = struct{}{}
					}
				}
				key := candidateDedupKey(input.Source, input.Name, text)
				if seen == nil {
					if dedupHit(candidates, input.Source, input.Name, text) {
						continue
					}
				} else {
					if _, ok := seen[key]; ok && dedupHit(candidates, input.Source, input.Name, text) {
						continue
					}
					seen[key] = struct{}{}
				}
				next := input
				next.Layers = variant.layers
				candidates = append(candidates, semanticCandidate{input: next, text: text})
			}
			if len(candidates) >= maxCandidates {
				break
			}
		}
		if len(candidates) >= maxCandidates || !progressed {
			break
		}
	}
	return candidates
}

// fairInputCursor alternates from the head and tail of a source group. A
// request with many ordinary fields therefore cannot hide a late attack field
// simply by arriving first; the source still receives a bounded, deterministic
// share of the global candidate budget.
type fairInputCursor struct {
	inputs   []InputPoint
	left     int
	right    int
	takeTail bool
}

func totalInputPoints(groups [][]InputPoint) int {
	total := 0
	for _, group := range groups {
		if len(group) > int(^uint(0)>>1)-total {
			return int(^uint(0) >> 1)
		}
		total += len(group)
	}
	return total
}

func priorityInputPoints(groups [][]InputPoint) []InputPoint {
	type rankedInput struct {
		input InputPoint
		score int
	}
	ranked := make([]rankedInput, 0, maxCandidates)
	for _, group := range groups {
		for _, input := range group {
			score := inputCoverageScore(input)
			if score == 0 {
				continue
			}
			ranked = append(ranked, rankedInput{input: input, score: score})
		}
	}
	sort.SliceStable(ranked, func(i, j int) bool { return ranked[i].score > ranked[j].score })
	if len(ranked) > maxCandidates {
		ranked = ranked[:maxCandidates]
	}
	out := make([]InputPoint, len(ranked))
	for i := range ranked {
		out[i] = ranked[i].input
	}
	return out
}

func inputCoverageScore(input InputPoint) int {
	score := 0
	if rawCoverageSignal.MatchString(input.Raw) {
		score += 100
	}
	if needsDeepDecode(input.Raw) {
		score += 20
	}
	name := strings.ToLower(input.Name)
	for _, marker := range []string{"cmd", "command", "exec", "shell", "query", "url", "uri", "redirect", "callback", "file", "path", "template"} {
		if strings.Contains(name, marker) {
			score += 10
			break
		}
	}
	return score
}

func (c *fairInputCursor) next() (InputPoint, bool) {
	if c == nil || c.left > c.right || len(c.inputs) == 0 {
		return InputPoint{}, false
	}
	var input InputPoint
	if c.takeTail {
		input = c.inputs[c.right]
		c.right--
	} else {
		input = c.inputs[c.left]
		c.left++
	}
	c.takeTail = !c.takeTail
	return input, true
}

// candidateDedupKey fingerprints source+name+text with FNV-1a, matching the
// old "source\x00name\x00text" string key without allocating it.
func candidateDedupKey(source, name, text string) uint64 {
	h := uint64(14695981039346656037)
	h = fnv64aAddString(h, source)
	h = fnv64aAddByte(h, 0)
	h = fnv64aAddString(h, name)
	h = fnv64aAddByte(h, 0)
	return fnv64aAddString(h, text)
}

// dedupHit confirms a fingerprint match is a real duplicate. Keeps dedup exact
// so a hash collision can never silently drop a distinct attack candidate.
func dedupHit(candidates []semanticCandidate, source, name, text string) bool {
	for i := range candidates {
		if candidates[i].text == text &&
			candidates[i].input.Source == source &&
			candidates[i].input.Name == name {
			return true
		}
	}
	return false
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

func hasInspectableHeaders(header http.Header) bool {
	for key, values := range header {
		if skipHeader(key) {
			continue
		}
		for _, value := range values {
			if value != "" {
				return true
			}
		}
	}
	return false
}

func clipRaw(raw string) string {
	if len(raw) <= maxInputRawBytes {
		return raw
	}
	if match := rawCoverageSignal.FindStringIndex(raw); match != nil {
		start, end := rawCoverageWindow(len(raw), match[0], match[1])
		return strings.Clone(raw[start:end])
	}
	// Keep both ends: prefix-only clipping lets an attacker hide a payload just
	// beyond the retained window. The separator prevents the two samples from
	// forming a synthetic token across the cut while keeping the allocation
	// bounded for the process cache.
	head := maxInputRawBytes / 2
	tail := maxInputRawBytes - head - 1
	return strings.Clone(raw[:head] + "\n" + raw[len(raw)-tail:])
}

func clipRawBytes(raw []byte) string {
	if len(raw) > maxInputRawBytes {
		if match := rawCoverageSignal.FindIndex(raw); match != nil {
			start, end := rawCoverageWindow(len(raw), match[0], match[1])
			return string(raw[start:end])
		}
		head := maxInputRawBytes / 2
		tail := maxInputRawBytes - head - 1
		out := make([]byte, maxInputRawBytes)
		copy(out, raw[:head])
		out[head] = '\n'
		copy(out[head+1:], raw[len(raw)-tail:])
		return string(out)
	}
	return string(raw)
}

func rawCoverageWindow(length, matchStart, matchEnd int) (int, int) {
	if length <= maxInputRawBytes {
		return 0, length
	}
	center := matchStart + (matchEnd-matchStart)/2
	start := center - maxInputRawBytes/2
	if start < 0 {
		start = 0
	}
	if start > length-maxInputRawBytes {
		start = length - maxInputRawBytes
	}
	return start, start + maxInputRawBytes
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

// bodyInputs extracts the body's input points.
//
// It deliberately builds its own slice rather than appending into the caller's:
// the JSON walkers bound their output with len(*inputs) >= maxCandidates, so
// sharing the caller's slice would make path/query/header inputs consume the
// body's candidate budget and could drop attack fields that are extracted today.
func bodyInputs(r *http.Request, body []byte) []InputPoint {
	if len(body) == 0 {
		return nil
	}
	// charset=utf-16 bodies are often delivered as raw LE/BE bytes; convert before
	// analysis. Both branches ran the same byte-level check, so decode once and
	// operate on []byte directly (the old string(body) round-trip allocated a full
	// copy of every body on the hot path).
	if decoded, ok := decodeUTF16PayloadBytes(body); ok {
		body = []byte(decoded)
	}
	// Pre-sized: growing from nil cost two reallocations for even a two-field
	// body. Capacity does not affect the maxCandidates/maxJSONNodes budgets, which
	// are all length checks, so this is purely fewer reallocations. Four is the
	// smallest capacity that covers a minimal JSON object (key+value per field)
	// without inflating bytes/op for the common small body.
	inputs := make([]InputPoint, 0, 4)
	contentType := requestMediaType(r.Header.Get("Content-Type"))
	switch contentType {
	case "application/x-www-form-urlencoded":
		values, err := url.ParseQuery(string(body))
		if err == nil {
			for key, list := range values {
				inputs = append(inputs, InputPoint{Source: "body.form", Name: key, Raw: key, Layers: rawLayersOnly})
				for _, value := range list {
					inputs = append(inputs, InputPoint{Source: "body.form", Name: key, Raw: value, Layers: rawLayersOnly})
				}
			}
			return withBodyCoverage(body, inputs)
		}
	case "application/json":
		flattenJSONInputs("body.json", "", body, &inputs)
		if len(inputs) > 0 {
			return withBodyCoverage(body, inputs)
		}
	case "multipart/form-data":
		if boundary := boundaryFromContentType(r.Header.Get("Content-Type")); boundary != "" {
			return withBodyCoverage(body, multipartInputs(body, boundary))
		}
	}
	if json.Valid(body) {
		flattenJSONInputs("body.json", "", body, &inputs)
	}
	if len(inputs) == 0 {
		inputs = append(inputs, InputPoint{Source: "body.raw", Name: "body", Raw: clipRawBytes(body), Layers: rawLayersOnly})
	}
	return withBodyCoverage(body, inputs)
}

func withBodyCoverage(body []byte, inputs []InputPoint) []InputPoint {
	if len(inputs) == 0 || (len(body) <= maxInputRawBytes && len(inputs) < maxCandidates) {
		return inputs
	}
	if inputs[0].Source == "body.raw" {
		return inputs
	}
	covered := make([]InputPoint, 0, len(inputs)+1)
	covered = append(covered, InputPoint{
		Source: "body.raw",
		Name:   "body",
		Raw:    clipRawBytes(body),
		Layers: rawLayersOnly,
	})
	return append(covered, inputs...)
}

var (
	hexEscapeMarkerLower = []byte(`\x`)
	hexEscapeMarkerUpper = []byte(`\X`)
)

// decodeUTF16PayloadBytes is the []byte twin of decodeUTF16Payload. It keeps the
// identical decision order (hex-escaped dump first, then raw UTF-16) but avoids
// materialising the body as a string: the hex branch is the only one that needs
// a string, and it is gated on the escape marker actually being present.
func decodeUTF16PayloadBytes(raw []byte) (string, bool) {
	if bytes.Contains(raw, hexEscapeMarkerLower) || bytes.Contains(raw, hexEscapeMarkerUpper) {
		if unescaped, ok := unescapeHexByteString(string(raw)); ok {
			if out, ok2 := decodeUTF16FromBytes([]byte(unescaped)); ok2 {
				return out, true
			}
		}
	}
	return decodeUTF16FromBytes(raw)
}

// knownBodyMediaTypes are the only media types bodyInputs branches on.
var knownBodyMediaTypes = [...]string{
	"application/x-www-form-urlencoded",
	"application/json",
	"multipart/form-data",
}

// requestMediaType extracts the bare media type from a Content-Type header
// without allocating in the common parameterless case (mime.ParseMediaType
// always builds a params map). Headers carrying parameters still go through the
// strict stdlib parse so malformed-parameter handling is unchanged. Any value
// outside knownBodyMediaTypes returns "", which reaches the same default branch
// the previous code did.
func requestMediaType(header string) string {
	if header == "" {
		return ""
	}
	if strings.IndexByte(header, ';') >= 0 {
		mediaType, _, err := mime.ParseMediaType(header)
		if err != nil {
			return ""
		}
		return mediaType
	}
	trimmed := strings.TrimSpace(header)
	for _, known := range knownBodyMediaTypes {
		if len(trimmed) == len(known) && strings.EqualFold(trimmed, known) {
			return known
		}
	}
	return ""
}

func flattenJSONInputs(source, prefix string, raw []byte, inputs *[]InputPoint) {
	// Fast path: walk the bytes directly. Bails on anything it cannot reproduce
	// byte-for-byte (escapes, non-ASCII, trailing garbage, malformed structure),
	// in which case the decoder walk below runs on the untouched input.
	mark := len(*inputs)
	w := jsonWalker{src: raw, source: source, inputs: inputs}
	if w.value(prefix, 0, false) {
		w.skipWS()
		if w.pos == len(raw) {
			return
		}
	}
	// Fast path aborted mid-document: discard whatever it emitted so the decoder
	// walk starts from the same state it would have seen.
	*inputs = (*inputs)[:mark]
	if len(raw) > maxJSONTreeDecodeBytes {
		flattenJSONInputsStream(source, prefix, raw, inputs)
		return
	}
	flattenJSONInputsDecode(source, prefix, raw, inputs)
}

// flattenJSONInputsStream avoids constructing a complete map[string]any tree
// for large JSON bodies the byte walker declines (escaped or non-ASCII text).
// It validates the entire document while retaining a bounded head/tail sample,
// so late fields still receive semantic coverage without body-sized object
// graphs and interface boxing.
func flattenJSONInputsStream(source, prefix string, raw []byte, inputs *[]InputPoint) {
	capacity := maxCandidates - len(*inputs)
	if capacity <= 0 {
		return
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	collector := newJSONInputCollector(capacity)
	if err := streamJSONValue(decoder, source, prefix, 0, &collector); err != nil {
		return
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return
	}
	collector.appendTo(inputs)
}

type jsonInputCollector struct {
	head     []InputPoint
	tail     []InputPoint
	headMax  int
	tailMax  int
	tailNext int
}

func newJSONInputCollector(capacity int) jsonInputCollector {
	if capacity < 0 {
		capacity = 0
	}
	headMax := (capacity + 1) / 2
	return jsonInputCollector{
		head:    make([]InputPoint, 0, headMax),
		tail:    make([]InputPoint, 0, capacity-headMax),
		headMax: headMax,
		tailMax: capacity - headMax,
	}
}

func (c *jsonInputCollector) add(input InputPoint) {
	if len(c.head) < c.headMax {
		c.head = append(c.head, input)
		return
	}
	if c.tailMax == 0 {
		return
	}
	if len(c.tail) < c.tailMax {
		c.tail = append(c.tail, input)
		return
	}
	c.tail[c.tailNext] = input
	c.tailNext = (c.tailNext + 1) % c.tailMax
}

func (c *jsonInputCollector) appendTo(inputs *[]InputPoint) {
	*inputs = append(*inputs, c.head...)
	if len(c.tail) < c.tailMax || c.tailNext == 0 {
		*inputs = append(*inputs, c.tail...)
		return
	}
	*inputs = append(*inputs, c.tail[c.tailNext:]...)
	*inputs = append(*inputs, c.tail[:c.tailNext]...)
}

func streamJSONValue(decoder *json.Decoder, source, prefix string, depth int, collector *jsonInputCollector) error {
	if depth > maxJSONDepth {
		return discardJSONValue(decoder)
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, composite := token.(json.Delim)
	if !composite {
		switch value := token.(type) {
		case string:
			collector.add(InputPoint{Source: source, Name: prefix, Raw: clipRaw(value), Layers: rawLayersOnly})
		case json.Number, bool, float64:
			collector.add(InputPoint{Source: source, Name: prefix, Raw: toString(value), Layers: rawLayersOnly})
		}
		return nil
	}

	switch delim {
	case '{':
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("json object key is not a string")
			}
			name := key
			if prefix != "" {
				name = prefix + "." + key
			}
			collector.add(InputPoint{Source: source, Name: name, Raw: clipRaw(key), Layers: rawLayersOnly})
			if err := streamJSONValue(decoder, source, name, depth+1, collector); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil {
			return err
		}
		if end != json.Delim('}') {
			return fmt.Errorf("json object terminator is %v", end)
		}
		return nil
	case '[':
		name := prefix + "[]"
		for decoder.More() {
			if err := streamJSONValue(decoder, source, name, depth+1, collector); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil {
			return err
		}
		if end != json.Delim(']') {
			return fmt.Errorf("json array terminator is %v", end)
		}
		return nil
	default:
		return fmt.Errorf("unexpected json delimiter %q", delim)
	}
}

func discardJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	if delim != '{' && delim != '[' {
		return fmt.Errorf("unexpected json delimiter %q", delim)
	}
	level := 1
	for level > 0 {
		token, err = decoder.Token()
		if err != nil {
			return err
		}
		if delim, ok = token.(json.Delim); !ok {
			continue
		}
		switch delim {
		case '{', '[':
			level++
		case '}', ']':
			level--
		}
	}
	return nil
}

// flattenJSONInputsDecode is the original decoder-backed walk, kept as the
// authority for every body the byte walker declines.
func flattenJSONInputsDecode(source, prefix string, raw []byte, inputs *[]InputPoint) {
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
			*inputs = append(*inputs, InputPoint{Source: source, Name: name, Raw: clipRaw(key), Layers: rawLayersOnly})
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
		*inputs = append(*inputs, InputPoint{Source: source, Name: prefix, Raw: clipRaw(typed), Layers: rawLayersOnly})
	case json.Number, bool, float64:
		*inputs = append(*inputs, InputPoint{Source: source, Name: prefix, Raw: toString(typed), Layers: rawLayersOnly})
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
	buf := make([]byte, maxInputRawBytes)
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
				Name:   clipRaw(name + ".filename"),
				Raw:    clipRaw(fileName),
				Layers: rawLayersOnly,
			})
		}
		n, err := io.ReadFull(part, buf)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			continue
		}
		if n == 0 {
			continue
		}
		inputs = append(inputs, InputPoint{Source: "body.multipart", Name: clipRaw(name), Raw: string(buf[:n]), Layers: rawLayersOnly})
	}
	return inputs
}

type decodedVariant struct {
	text   string
	layers []string
}

// rawLayersOnly is the immutable {"raw"} layer slice shared by every undecoded
// input point. InputPoint.Layers and decodedVariant.layers are read-only after
// construction (appendLayers copies before extending), so one process-wide
// singleton removes a per-field allocation without any aliasing risk.
var rawLayersOnly = []string{"raw"}

// decodeVariantsInto appends decode variants for raw into dst and returns the
// result. Callers pass a stack-resident scratch array so the common
// single-variant case costs zero allocations.
func decodeVariantsInto(dst []decodedVariant, raw string) []decodedVariant {
	// UTF-16 LE/BE BOM payloads (XXE evasion). Expand once into UTF-8 text.
	if utf8FromUTF16, ok := decodeUTF16Payload(raw); ok && utf8FromUTF16 != raw {
		raw = utf8FromUTF16
	}
	// Hot path: plain text without encode markers needs no expansion queue.
	if !needsDeepDecode(raw) {
		return append(dst, decodedVariant{text: raw, layers: rawLayersOnly})
	}
	return decodeVariantsDeep(dst, raw)
}

// decodeVariantsDeep runs the bounded multi-layer expansion queue. Split out of
// decodeVariantsInto so the hot single-variant path stays inlinable and its
// queue/map allocations never appear on ordinary traffic.
func decodeVariantsDeep(dst []decodedVariant, raw string) []decodedVariant {
	queue := []decodedVariant{{text: raw, layers: rawLayersOnly}}
	out := dst
	base := len(dst) // keep the maxDecodeVariants bound relative to what we add
	seen := map[string]struct{}{}
	for len(queue) > 0 && len(out)-base < maxDecodeVariants {
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
	ordered := []string{"sqli", "xss", "rce", "lfi", "xxe", "ssrf", "nosqli", "ssti", "webshell", "log4shell"}
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
				sqlMetadataObject.MatchString(text) || guardedMatchString2K(sqlSubquery, text) ||
				guardedMatchString2K(sqlCaseWhen, text) || sqlFileData.MatchString(text) ||
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
	if hints&hintWebshell != 0 {
		if (strings.Contains(text, "<?php") || strings.Contains(text, "<?=")) ||
			(strings.Contains(text, "eval(") && (strings.Contains(text, "$_post") || strings.Contains(text, "$_get") || strings.Contains(text, "$_request"))) ||
			strings.Contains(text, "base64_decode") || strings.Contains(text, "gzinflate") ||
			strings.Contains(text, "runtime.getruntime()") || strings.Contains(text, "processbuilder") ||
			strings.Contains(text, "system.diagnostics.process") ||
			(strings.Contains(text, ".php") && (strings.Contains(text, "action=") || strings.Contains(text, "cmd=") || strings.Contains(text, "shell"))) {
			scores["webshell"] += 2
		}
	}
	if hints&hintLog4Shell != 0 {
		if strings.Contains(text, "${jndi:") || strings.Contains(text, "() { :;};") {
			scores["log4shell"] += 2
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
	hintWebshell
	hintLog4Shell
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
		strings.Contains(lower, "%{") || strings.Contains(lower, "${") || strings.Contains(lower, "#{") ||
		strings.Contains(lower, "<%") || strings.Contains(lower, "__class__") ||
		strings.Contains(lower, "__globals__") || strings.Contains(lower, "popen") ||
		strings.Contains(lower, "objectspace") || strings.Contains(lower, "classloader") {
		hints |= hintSSTI
	}
	// Webshell
	if strings.Contains(lower, "<?php") || strings.Contains(lower, "<?=") ||
		strings.Contains(lower, "eval(") || strings.Contains(lower, "system(") ||
		strings.Contains(lower, "shell_exec") || strings.Contains(lower, "passthru") ||
		strings.Contains(lower, "exec(") || strings.Contains(lower, "assert(") ||
		strings.Contains(lower, "$_post") || strings.Contains(lower, "$_get") ||
		strings.Contains(lower, "$_request") || strings.Contains(lower, "$_cookie") ||
		strings.Contains(lower, "base64_decode") || strings.Contains(lower, "gzinflate") ||
		strings.Contains(lower, "runtime.getruntime()") || strings.Contains(lower, "processbuilder") ||
		strings.Contains(lower, "request.getparameter") || strings.Contains(lower, "${param.") ||
		strings.Contains(lower, "system.diagnostics.process") || strings.Contains(lower, "eval(request[") ||
		(strings.Contains(lower, ".php") && (strings.Contains(lower, "action=") || strings.Contains(lower, "cmd=") || strings.Contains(lower, "exec="))) {
		hints |= hintWebshell
	}
	// Log4Shell & Shellshock
	if strings.Contains(lower, "${jndi:") || strings.Contains(lower, "() { :;};") ||
		strings.Contains(lower, "jndi:ldap://") || strings.Contains(lower, "jndi:rmi://") ||
		strings.Contains(lower, "jndi:dns://") {
		hints |= hintLog4Shell
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
	case "webshell":
		return analyzeWebshell(candidate)
	case "log4shell", "shellshock":
		return analyzeLog4Shell(candidate)
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

// sqlCommentTruncationShape returns true if SQL comment markers appear in actual
// injection context (after quote, paren, equals, digit) rather than in prose,
// C code comments, Markdown, or email addresses (user@example.com, list--item).
func sqlCommentTruncationShape(text string) bool {
	lower := strings.ToLower(text)
	// Check for -- (must not be in email or Markdown list context)
	if strings.Contains(text, "--") {
		idx := strings.Index(text, "--")
		if idx > 0 {
			before := text[idx-1]
			// Injection context: quote, paren, digit, equals precedes --
			if before == '\'' || before == '"' || before == ')' || before == '=' ||
				(before >= '0' && before <= '9') {
				return true
			}
			// Check for SQL keyword before --: SELECT--, WHERE--
			if idx >= 6 {
				prevWord := strings.ToLower(text[idx-6 : idx])
				if strings.Contains(prevWord, "select") || strings.Contains(prevWord, "where") ||
					strings.Contains(prevWord, "union") || strings.Contains(prevWord, "order") {
					return true
				}
			}
		}
	}
	// Check for /* (must not be C/Java code comment at line start)
	if strings.Contains(text, "/*") {
		idx := strings.Index(text, "/*")
		// C code comment pattern: line start or after newline
		if idx == 0 || (idx > 0 && (text[idx-1] == '\n' || text[idx-1] == '\r')) {
			// Check next line for typical C comment pattern: * Routine, * Copyright
			if idx+10 < len(text) {
				snippet := text[idx : idx+10]
				if strings.Contains(snippet, "* ") || strings.Contains(snippet, "**") {
					return false // C code comment block
				}
			}
		}
		// Injection context: after quote, paren, or embedded in SQL
		if idx > 0 {
			before := text[idx-1]
			if before == '\'' || before == '"' || before == ')' || before == '=' ||
				(before >= '0' && before <= '9') {
				return true
			}
		}
		// SQL comment obfuscation: SELECT/**/FROM, UNION/**/SELECT
		afterComment := idx + 2
		if afterComment < len(text) {
			closeIdx := strings.Index(text[afterComment:], "*/")
			if closeIdx >= 0 && closeIdx <= 20 {
				// Short comment gap, check if SQL keywords surround it
				afterClose := afterComment + closeIdx + 2
				if afterClose < len(text) {
					nextWord := strings.ToLower(strings.TrimSpace(text[afterClose:min(afterClose+10, len(text))]))
					if strings.HasPrefix(nextWord, "select") || strings.HasPrefix(nextWord, "from") ||
						strings.HasPrefix(nextWord, "union") || strings.HasPrefix(nextWord, "where") {
						return true
					}
				}
			}
		}
	}
	// Check for # (hash comment, less common in prose)
	if strings.Contains(lower, "#") && (strings.Contains(lower, "select") ||
		strings.Contains(lower, "union") || strings.Contains(lower, "where")) {
		return true
	}
	return false
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// sqlUnionSelectInjectionShape returns true if UNION/SELECT appears in actual
// injection context (quote break, comment, semicolon, FROM/WHERE clause) rather
// than documentation prose like "the UNION operator allows SELECT statements".
func sqlUnionSelectInjectionShape(text string) bool {
	lower := strings.ToLower(text)
	// Injection markers: quote, semicolon, comment, parentheses for subquery
	if strings.Contains(text, "'") || strings.Contains(text, "\"") ||
		strings.Contains(text, ";") || strings.Contains(text, "--") ||
		strings.Contains(text, "/*") || strings.Contains(text, "#") {
		return true
	}
	// Real injection continuation: UNION ... SELECT ... FROM/WHERE
	if strings.Contains(lower, "union") && strings.Contains(lower, "select") {
		afterSelect := lower[strings.Index(lower, "select")+6:]
		// Trim leading whitespace/comments
		afterSelect = strings.TrimSpace(afterSelect)
		// Check for FROM, WHERE, or column list indicators
		if strings.Contains(afterSelect, "from") || strings.Contains(afterSelect, "where") ||
			// Column list indicators: number, *, NULL, identifiers followed by comma
			(len(afterSelect) > 0 && (afterSelect[0] >= '0' && afterSelect[0] <= '9' ||
				afterSelect[0] == '*' || strings.HasPrefix(afterSelect, "null"))) {
			return true
		}
	}
	return false
}

func analyzeSQL(candidate semanticCandidate) (Hit, bool) {
	// Probe surfaces before comment-bridging so SELECT/**/WHERE and IF((SELECT
	// shapes stay visible; full analysis still uses bridged executable text.
	normalized := normalize(candidate.text)
	text := executableSQLText(candidate.text)
	words := tokens(text)
	reasons := map[string]bool{}
	if containsOrdered(words, "union", "select") {
		// FP hardening: prose can contain "the UNION operator allows SELECT..." without
		// injection context. Require either: quote/comment/semicolon, or FROM/WHERE after.
		if sqlUnionSelectInjectionShape(text) {
			reasons["syntax: UNION SELECT query composition"] = true
		}
	}
	compact := compactSQL(text)
	// NOTE: deliberately NOT gated by sqlUnionSelectInjectionShape alone. That
	// gate costs 89 attack detections in the 0xlipon-asql family, whose payloads
	// carry "union select" with no quote, comment, or column list — the same
	// bare shape an article uses when naming the technique.
	//
	// plainProseUnionMention adds the discriminator the shape guard lacks:
	// English sentence structure. It suppresses only text that is plainly
	// spaced, carries no SQL companion at all, and reads as a sentence. A
	// working UNION injection must still supply a column list or FROM clause,
	// so it cannot reach this branch.
	if strings.Contains(compact, "unionselect") || strings.Contains(compact, "unionallselect") {
		if !plainProseUnionMention(candidate.text) {
			reasons["syntax: obfuscated UNION SELECT query composition"] = true
		}
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
	if guardedMatchString2K(sqlSelectFrom, text) {
		reasons["syntax: SELECT FROM query grammar"] = true
	}
	if sqlIfSelectProbe.MatchString(normalized) || sqlIfSelectProbe.MatchString(text) ||
		sqlXorSelectProbe.MatchString(normalized) || sqlXorSelectProbe.MatchString(text) {
		reasons["syntax: IF/XOR SELECT boolean-blind probe"] = true
		reasons["semantics: boolean database value inference"] = true
	}
	if (guardedMatchString2K(sqlSelectWhere, normalized) || guardedMatchString2K(sqlSelectWhere, text)) &&
		(sqlComment.MatchString(normalized) || strings.Contains(normalized, "/**/") ||
			sqlIfSelectProbe.MatchString(normalized) || sqlXorSelectProbe.MatchString(normalized)) {
		reasons["syntax: SELECT WHERE boolean probe"] = true
	}
	if guardedMatchString2K(sqlSubquery, text) {
		reasons["syntax: parenthesized SELECT subquery"] = true
	}
	if guardedMatchString2K(sqlCaseWhen, text) {
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
		// FP hardening: C code comments, Markdown, email addresses contain comment-like
		// markers without injection context. Require position-based evidence.
		if sqlCommentTruncationShape(text) {
			reasons["syntax: SQL comment used to truncate query"] = true
		}
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

	// Apply shape guards in order of specificity (most specific first).
	//
	// The guards below classify the *document*, so they must see the document as
	// it arrived — not the bridged, NFKC-normalized detection text. normalize()
	// drops control characters, which includes "\n", whenever the input is not
	// plain ASCII (the ASCII fast path keeps newlines). Feeding it to the guards
	// silently disabled every line-anchored shape (source-file import blocks,
	// roff control lines, changelog version headings, C comment blocks) for any
	// document containing a single non-ASCII byte — a curly quote or one CJK
	// character was enough. Every other detector already passes candidate.text
	// here; this path was the outlier.
	doc := candidate.text

	// Markdown heading date context: Changelog entries (#### 1.6.9 - March 16, 2019)
	if markdownHeadingDateContext(doc) {
		confidence *= 0.4
		if confidence < 0.7 {
			return Hit{}, false
		}
	}

	// Security document context: vulnerability reports, CTF writeups, training
	// material, academic papers, Chinese technical articles, and source files all
	// quote SQL grammar verbatim without composing a query.
	if securityDocumentContext(doc) {
		confidence *= 0.4
		if confidence < 0.7 {
			return Hit{}, false
		}
	}

	// C source code comments: /* packet-nasdaq-itch.c */
	if cSourceCodeCommentContext(doc) {
		confidence *= 0.5
		if confidence < 0.7 {
			return Hit{}, false
		}
	}

	// HTTP protocol context guard: reduce confidence for HTTP protocol documentation
	if httpProtocolContextShape(doc) {
		confidence *= 0.6
		if confidence < 0.7 {
			return Hit{}, false
		}
	}

	// Markdown code block guard: reduce confidence for code examples
	if markdownCodeBlockShape(doc) {
		confidence *= 0.6
		if confidence < 0.7 {
			return Hit{}, false
		}
	}

	// Technical documentation keyword guard: reduce confidence for educational content
	if technicalDocumentationContext(doc) {
		confidence *= 0.7
		if confidence < 0.7 {
			return Hit{}, false
		}
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

	// Security prose quotes MongoDB operators verbatim ("$regex", "$ne") when
	// explaining NoSQL injection. A document-scale article is not a query.
	if securityDocumentContext(text) {
		confidence *= 0.4
		if confidence < 0.7 {
			return Hit{}, false
		}
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

	// Template-expression syntax appears verbatim in webshell writeups, exploit
	// sources, and SSTI tutorials. A document-scale article is not a template.
	if securityDocumentContext(text) {
		confidence *= 0.4
		if confidence < 0.7 {
			return Hit{}, false
		}
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

	confidence := 0.86 + confidenceBonus(reasons)

	// Apply shape guards in order of specificity (most specific first)

	// Vulnerability report context: XSS in vulnerability titles
	if vulnerabilityReportContext(text) {
		confidence *= 0.55
		if confidence < 0.7 {
			return Hit{}, false
		}
	}

	// HTTP protocol context guard: reduce confidence for HTTP protocol documentation
	if httpProtocolContextShape(lower) {
		confidence *= 0.6
		if confidence < 0.7 {
			return Hit{}, false
		}
	}

	// Markdown code block guard: reduce confidence for code examples
	if markdownCodeBlockShape(text) {
		confidence *= 0.6
		if confidence < 0.7 {
			return Hit{}, false
		}
	}

	// Technical documentation keyword guard: reduce confidence for educational content
	if technicalDocumentationContext(text) {
		confidence *= 0.7
		if confidence < 0.7 {
			return Hit{}, false
		}
	}

	return hit(candidate, "xss", engine.SeverityHigh, confidence, reasons), true
}

func analyzeRCE(candidate semanticCandidate) (Hit, bool) {
	text := strings.TrimSpace(candidate.text)
	lower := normalize(text)
	sink := rceExecutionSink(candidate.input.Name)
	reasons := map[string]bool{}
	// Markdown table markup turns "| id |" into a fake pipe-plus-command shape.
	// Outside an execution sink, a table delimiter row means the pipes are cell
	// separators. Inside a sink, table markup earns no trust.
	tableMarkup := !sink && markdownTableShape(text)

	if !tableMarkup {
		for _, pattern := range rcePatterns {
			if guardedMatchString2K(pattern, text) {
				reasons["syntax: shell metacharacter plus executable command"] = true
			}
		}
	}
	// Bare English ";" must not count outside execution sinks (major FP source in docs).
	if sink && guardedMatchString2K(rceShellControl, text) {
		reasons["syntax: shell control operator or command substitution"] = true
	} else if !sink && !tableMarkup && rceShellControlEvidence(lower) {
		reasons["syntax: shell control operator or command substitution"] = true
	}
	if guardedMatchString2K(rceWhitespaceEvasion, text) {
		reasons["syntax: shell whitespace evasion"] = true
	}
	if sink {
		reasons["context: command execution parameter"] = true
	}
	if guardedMatchString2K(rcePowerShellSideFx, text) || guardedMatchString2K(rceEncodedPowerShell, text) || guardedMatchString2K(rceNetWebClientSideFx, text) {
		reasons["semantics: PowerShell dynamic execution or encoded command"] = true
	}
	if guardedMatchString2K(rcePowerShellReverseShell, text) {
		reasons["semantics: shell reverse connection primitive"] = true
		reasons["semantics: PowerShell dynamic execution or encoded command"] = true
	}
	if guardedMatchString2K(rceInterpreterInline, text) {
		reasons["semantics: interpreter inline command execution"] = true
	}
	if guardedMatchString2K(rceDownloadExecChain, text) {
		reasons["semantics: download-to-shell execution chain"] = true
	}
	if guardedMatchString2K(rceReverseShellPrimitive, text) {
		reasons["semantics: shell reverse connection primitive"] = true
	}
	// Loader/reflective primitives: only count as RCE evidence when tied to an
	// execution sink or another hard shell/runtime signal (avoid doc FPs like
	// "set LD_PRELOAD=/path" in prose without a command parameter).
	if guardedMatchString2K(rceLoaderPrimitive, text) {
		if sink || rceShellControlEvidence(lower) || guardedMatchString2K(rceInterpreterInline, text) ||
			guardedMatchString2K(rcePowerShellSideFx, text) || guardedMatchString2K(rceDownloadExecChain, text) ||
			guardedMatchString2K(rceReverseShellPrimitive, text) {
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
	if guardedMatchString2K(rceTemplateExecutionPrimitive, text) {
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
	for command := range rceCommandNames {
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
	// $SHELL -c / ${SHELL} -c is a classic env-based interpreter invocation (CRS-compatible).
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

	confidence := 0.87 + confidenceBonus(reasons)

	// Apply shape guards in order of specificity (most specific first)

	// Security document context: vulnerability reports, CTF writeups, training
	// material, academic papers, Chinese technical articles, and source files all
	// quote shell commands verbatim without invoking them.
	if securityDocumentContext(text) {
		confidence *= 0.4
		if confidence < 0.7 {
			return Hit{}, false
		}
	}

	// PowerShell documentation: technical descriptions of PowerShell features
	if powerShellDocumentationContext(text) {
		confidence *= 0.55
		if confidence < 0.7 {
			return Hit{}, false
		}
	}

	// HTTP header documentation: explaining HTTP headers as examples
	if httpHeaderDocumentationContext(text) {
		confidence *= 0.5
		if confidence < 0.7 {
			return Hit{}, false
		}
	}

	// HTTP protocol context guard: reduce confidence for HTTP protocol documentation
	if httpProtocolContextShape(lower) {
		confidence *= 0.6
		if confidence < 0.7 {
			return Hit{}, false
		}
	}

	// Markdown code block guard: reduce confidence for code examples
	if markdownCodeBlockShape(text) {
		confidence *= 0.6
		if confidence < 0.7 {
			return Hit{}, false
		}
	}

	// Technical documentation keyword guard: reduce confidence for educational content
	if technicalDocumentationContext(text) {
		confidence *= 0.7
		if confidence < 0.7 {
			return Hit{}, false
		}
	}

	return hit(candidate, "rce", engine.SeverityCritical, confidence, reasons), true
}

var rceShellMetacharCommand = regexp.MustCompile(`(?i)(?:;|&&|\|\||\|)\s*(?:cat|id|whoami|uname|curl|wget|bash|sh|zsh|dash|pwsh|powershell|cmd|python3?|perl|php|ruby|node|nc|ncat|netcat|socat|lua|iex|type|dir|ls|sleep|echo|ping)\b`)

// rceCommandNames is the set of executable names that count as command-execution
// intent. It is the single source of truth for both token scanning in analyzeRCE
// and the backtick discrimination in rceShellControlEvidence: a single word in
// backticks that names a real command is substitution, not Markdown inline code.
var rceCommandNames = map[string]bool{
	"cat": true, "whoami": true, "uname": true, "curl": true, "wget": true,
	"bash": true, "sh": true, "zsh": true, "dash": true, "pwsh": true,
	"powershell": true, "cmd": true, "python": true, "python3": true,
	"perl": true, "php": true, "ruby": true, "node": true, "nc": true,
	"ncat": true, "netcat": true, "socat": true, "lua": true, "iex": true,
	"invoke-expression": true, "sleep": true, "ping": true, "nslookup": true,
}

func rceShellControlEvidence(lower string) bool {
	if strings.Contains(lower, "$(") || strings.Contains(lower, "&&") || strings.Contains(lower, "||") {
		return true
	}
	// Markdown fenced code uses ``` which must not count as shell backticks.
	text := strings.ReplaceAll(lower, "```", "")
	if !strings.Contains(text, "`") {
		return rceShellMetacharCommand.MatchString(lower)
	}
	// Backticks present. Distinguish Markdown inline code from shell command substitution.
	// Markdown: `SLEEP`, `UNION`, `SELECT` — single keyword, no spaces/shell meta
	// Shell: `cat /etc/passwd`, `curl http://...`, `$(cmd)` — has spaces or shell syntax
	parts := strings.Split(text, "`")
	if len(parts)%2 == 1 && len(parts) >= 3 {
		// Balanced pairs. Check each backtick-enclosed segment.
		hasShellPattern := false
		for i := 1; i < len(parts); i += 2 {
			content := strings.TrimSpace(parts[i])
			if len(content) == 0 {
				continue // Empty backticks
			}
			// Shell command substitution markers
			if strings.ContainsAny(content, " \t\n;|&><$()") {
				hasShellPattern = true
				break
			}
			// Single-word technical terms (SQL keywords, function names) are Markdown
			// Multi-word or containing shell metachar is shell syntax
			words := strings.Fields(content)
			if len(words) > 1 {
				hasShellPattern = true
				break
			}
			// A single word that is itself a shell command name is command
			// substitution, not prose: report`whoami` executes. Markdown inline
			// code in documentation names APIs and operators (`site:`, `SELECT`),
			// not argv[0] of a real command.
			if len(words) == 1 && rceCommandNames[strings.Trim(words[0], "()$;|&")] {
				hasShellPattern = true
				break
			}
		}
		if !hasShellPattern {
			return false // All backtick pairs are Markdown inline code
		}
	}
	// Unbalanced or contains shell patterns
	return true
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
	// data:// wrappers used for inline PHP include / remote-file LFI.
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

	// RESTful path guard: /api/v1/users/{id}, GET /admin/dashboard, /@username/settings
	if restfulPathShape(text) {
		return Hit{}, false
	}

	confidence := 0.85 + confidenceBonus(reasons)

	// Apply shape guards in order of specificity (most specific first)

	// Book/ISBN documentation: technical books should not trigger LFI
	if bookDocumentationContext(text) {
		confidence *= 0.5
		if confidence < 0.7 {
			return Hit{}, false
		}
	}

	// Security document context: reports, writeups, papers, and source files
	// quote paths like /etc/passwd and file:// URIs as subject matter.
	if securityDocumentContext(text) {
		confidence *= 0.4
		if confidence < 0.7 {
			return Hit{}, false
		}
	}

	// HTTP protocol context guard: reduce confidence for HTTP protocol documentation
	if httpProtocolContextShape(text) {
		confidence *= 0.6
		if confidence < 0.7 {
			return Hit{}, false
		}
	}

	// Markdown code block guard: reduce confidence for code examples
	if markdownCodeBlockShape(text) {
		confidence *= 0.6
		if confidence < 0.7 {
			return Hit{}, false
		}
	}

	// Technical documentation keyword guard: reduce confidence for educational content
	if technicalDocumentationContext(text) {
		confidence *= 0.7
		if confidence < 0.7 {
			return Hit{}, false
		}
	}

	return hit(candidate, "lfi", engine.SeverityHigh, confidence, reasons), true
}

// lfiRemoteIncludeContext is true when a file or include parameter carries a remote URL.
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
func (a *Analyzer) blockableHit(h Hit) bool {
	// Level 0 (Off): never block, only log
	if a.paranoiaLevel == 0 {
		return false
	}

	if h.Category == "" || h.Payload == "" {
		return false
	}
	syntaxOK := h.Syntax != "" && !strings.HasSuffix(h.Syntax, "none") && !strings.Contains(h.Syntax, "attack grammar matched")
	semanticsOK := h.Semantics != "" && !strings.HasSuffix(h.Semantics, "none") && !strings.Contains(h.Semantics, "malicious behavior inferred from context")

	// Level 4 (Paranoid): block on any semantic evidence with confidence >= 0.5
	if a.paranoiaLevel >= 4 {
		return (syntaxOK || semanticsOK) && h.Confidence >= 0.5
	}

	// Level 3 (High): block on confidence >= 0.8 with High severity, or single evidence with Medium+
	if a.paranoiaLevel == 3 {
		if h.Confidence >= 0.8 && (h.Severity == engine.SeverityHigh || h.Severity == engine.SeverityCritical) {
			return true
		}
		if (syntaxOK || semanticsOK) && h.Severity >= engine.SeverityMedium {
			return true
		}
	}

	// Level 1 (Low): require very high confidence (>=0.95) with Critical, or two evidence with High
	if a.paranoiaLevel == 1 {
		if h.Confidence >= 0.95 && h.Severity == engine.SeverityCritical {
			return true
		}
		if syntaxOK && semanticsOK && h.Severity >= engine.SeverityHigh {
			return true
		}
		return false
	}

	// Level 2 (Default): original logic - require two evidence types or specific single evidence
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

// skippedHeaders holds the lowercase header names that carry no
// attacker-controlled semantics worth scanning. Kept as a set so skipHeader can
// fold the key into a stack buffer instead of allocating a lowercased copy
// (strings.ToLower allocated once per request for every canonical header).
var skippedHeaders = map[string]struct{}{
	"accept": {}, "accept-encoding": {}, "accept-language": {}, "connection": {},
	"content-length": {}, "content-type": {}, "host": {}, "cache-control": {},
	"pragma": {}, "upgrade-insecure-requests": {}, "sec-fetch-site": {},
	"sec-fetch-mode": {}, "sec-fetch-dest": {}, "sec-fetch-user": {},
	"sec-ch-ua": {}, "sec-ch-ua-mobile": {}, "sec-ch-ua-platform": {},
	"dnt": {}, "priority": {}, "if-none-match": {}, "if-modified-since": {},
	"range": {}, "te": {}, "trailer": {}, "transfer-encoding": {},
}

// skipHeaderMaxLen is the longest entry in skippedHeaders
// ("upgrade-insecure-requests"). Longer keys can never match.
const skipHeaderMaxLen = 25

func skipHeader(key string) bool {
	if len(key) == 0 || len(key) > skipHeaderMaxLen {
		return false
	}
	var buf [skipHeaderMaxLen]byte
	for i := 0; i < len(key); i++ {
		c := key[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		buf[i] = c
	}
	// The compiler elides the string header for map lookups on a byte slice.
	_, ok := skippedHeaders[string(buf[:len(key)])]
	return ok
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
