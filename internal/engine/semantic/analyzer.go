package semantic

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

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
	// paranoiaLevel is blocking sensitivity 0-5. 0-1 never block.
	paranoiaLevel int
	decodeDepth   int
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
	Isolation  string          `json:"isolation,omitempty"`
}

// ErrSemanticInputIncomplete marks a request whose semantic input could not be
// covered completely. Callers should use errors.Is or the AnalysisIncomplete /
// IncompleteReason methods rather than matching the error string.
var ErrSemanticInputIncomplete = errors.New("semantic input coverage incomplete")

const multipartCoverageIncompleteReason = "multipart_coverage_incomplete"

// InputIncompleteError is returned only when coverage was incomplete and the
// analyzer has no explicit detection result to preserve. Its small behavioral
// interface lets the engine recognize the condition without importing this
// package (which would create an import cycle).
type InputIncompleteError struct {
	Reason string
}

func (e *InputIncompleteError) Error() string {
	if e == nil || strings.TrimSpace(e.Reason) == "" {
		return ErrSemanticInputIncomplete.Error()
	}
	return ErrSemanticInputIncomplete.Error() + ": " + e.Reason
}

func (e *InputIncompleteError) Unwrap() error { return ErrSemanticInputIncomplete }

func (e *InputIncompleteError) AnalysisIncomplete() bool { return e != nil }

func (e *InputIncompleteError) IncompleteReason() string {
	if e == nil {
		return ""
	}
	return e.Reason
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
	return &Analyzer{mode: mode, enabled: enabled, catFP: enabledCategoryFingerprint(enabled), paranoiaLevel: paranoiaLevel, decodeDepth: decoder.DefaultDecodeDepth}
}

// SetDecodeDepth configures bounded nested decoding for this site analyzer.
func (a *Analyzer) SetDecodeDepth(depth int) {
	if a == nil {
		return
	}
	if depth <= 0 {
		depth = decoder.DefaultDecodeDepth
	}
	if depth > decoder.MaxDecodeDepth {
		depth = decoder.MaxDecodeDepth
	}
	a.decodeDepth = depth
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

	candidates := extractCandidatesWithOptions(reqCtx, a.paramAllowlist, a.decodeDepth)
	inputIncompleteErr := semanticInputIncompleteError(reqCtx)
	report, best, haveBest, incomplete := a.analyzeAllCandidates(ctx, candidates)
	if reqCtx.Metadata == nil {
		reqCtx.Metadata = map[string]any{}
	}
	if os.Getenv("CHEESEWAF_SEMANTIC_DEBUG_METADATA") == "1" {
		reqCtx.Metadata["semantic_analysis"] = report
	} else {
		reqCtx.Metadata["semantic_analysis_summary"] = map[string]any{
			"inputs": len(report.Inputs), "hits": len(report.Hits), "anomaly_score": report.AnomalyScore,
		}
	}
	if report.AnomalyScore > 0 {
		reqCtx.Metadata["semantic_anomaly_score"] = report.AnomalyScore
	}
	// Only when scanning was cut short by deadline — not a finished pass that
	// merely races the timer after returning.
	if incomplete {
		reqCtx.Metadata["semantic_analysis_incomplete"] = true
	}
	if !haveBest {
		if review, ok := strongestHit(report.Hits); ok {
			reqCtx.Metadata["review_candidate"] = reviewCandidateMap(review, a.paranoiaLevel)
		}
		return nil, inputIncompleteErr
	}
	reqCtx.Metadata["review_candidate"] = reviewCandidateMap(best, a.paranoiaLevel)
	action := actionForMode(a.mode)
	if a.mode == "block" && !a.blockableHit(best) {
		return nil, inputIncompleteErr
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

func semanticInputIncompleteError(reqCtx *engine.RequestContext) error {
	if reqCtx == nil || reqCtx.Metadata == nil {
		return nil
	}
	incomplete, _ := reqCtx.Metadata["semantic_input_incomplete"].(bool)
	if !incomplete {
		return nil
	}
	reason, _ := reqCtx.Metadata["semantic_input_incomplete_reason"].(string)
	return &InputIncompleteError{Reason: reason}
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

func strongestHit(hits []Hit) (Hit, bool) {
	var best Hit
	found := false
	for _, hit := range hits {
		if !found || betterHit(hit, best) {
			best = hit
			found = true
		}
	}
	return best, found
}

func reviewCandidateMap(hit Hit, level int) map[string]any {
	return map[string]any{
		"category":         hit.Category,
		"severity":         hit.Severity.String(),
		"payload":          hit.Payload,
		"shape":            hit.Isolation,
		"source":           hit.Source,
		"name":             hit.Name,
		"protection_level": level,
		"confidence":       hit.Confidence,
	}
}

// analyzeAllCandidates runs field analysis. Multi-field requests use a bounded
// worker pool so multi-core CPUs scan independent parameters concurrently while
// preserving FP-first merge rules and stable Input ordering.
// incomplete is true when the context cancelled or the explicitly enabled
// fast-abort policy stopped the scan before every field was analyzed.
// best is only meaningful when haveBest is true; returning it by value keeps the
// winning Hit off the heap (the previous *Hit escaped on every hit).
func (a *Analyzer) analyzeAllCandidates(ctx context.Context, candidates []semanticCandidate) (AnalysisReport, Hit, bool, bool) {
	var merge candidateMerge
	merge.report.Inputs = make([]InputPoint, 0, len(candidates))
	if len(candidates) == 0 {
		return merge.report, Hit{}, false, false
	}
	// A request that is already over budget must not enter any scan path. Apart
	// from avoiding needless regex/cache work during cancellation storms, this
	// keeps the report contract consistent across tiny, mid-size, and pooled
	// requests: every extracted input remains visible, but no candidate is
	// presented as analyzed.
	if err := ctx.Err(); err != nil {
		for _, candidate := range candidates {
			merge.report.Inputs = append(merge.report.Inputs, candidate.input)
		}
		return merge.report, Hit{}, false, true
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
	// Seed every slot before workers start. The optional fast-abort path may
	// intentionally leave tail candidates unscanned after a critical hit; a
	// zero-value slot must never be mistaken for a real empty input in the
	// analysis report.
	for i := range candidates {
		outs[i].input = candidates[i].input
	}
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
	var abort atomic.Bool
	fastAbort := os.Getenv("CHEESEWAF_SEMANTIC_FAST_ABORT") == "1"
	var wg sync.WaitGroup
	scan := func() {
		for {
			i := int(next.Add(1) - 1)
			if i >= len(candidates) || abort.Load() {
				return
			}
			if ctx.Err() != nil {
				outs[i] = fieldOut{input: candidates[i].input}
				skipped.Store(true)
				continue
			}
			hits := a.analyzeCandidate(candidates[i])
			if fastAbort {
				for _, h := range hits {
					if h.Severity >= engine.SeverityCritical && h.Confidence >= 0.92 {
						abort.Store(true)
						break
					}
				}
			}
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
	// A fast abort is a deliberate partial scan just like context cancellation:
	// surface it to callers so pipeline policy can avoid treating the report as a
	// complete pass. The seeded inputs above keep report ordering and metadata
	// intact even for candidates that were not reached by a worker.
	return merge.report, merge.best, merge.haveBest, skipped.Load() || abort.Load()
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
		// Keep every hit in the report so detected-but-not-blocked
		// requests can enter the review queue. Blocking still uses haveBest.
		m.report.Hits = append(m.report.Hits, next)
		if mode == "block" && !a.blockableHit(next) {
			continue
		}
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
	bareCommandSinkValue := a.enabled["rce"] && rceBareCommandSinkValueForSource(candidate.input.Source, candidate.input.Name, candidate.text)
	// Ultra-cheap prefilter before any hash/lock: ordinary ids/slugs/versions.
	// A known bare command value such as "id" or "whoami" is a complete payload
	// when it sits in an execution sink, so it must reach the context-aware RCE
	// analyzer. Parameter-name candidates themselves (for example the query key
	// "cmd") are excluded by rceBareCommandSinkValue. Not cached — hashing + shard
	// lock costs more than the byte scan itself.
	if looksCleanASCIIField(candidate.text) && !bareCommandSinkValue {
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

	guesses := guessCategoriesForSource(candidate.text, candidate.input.Name, candidate.input.Source)
	// A javascript: value is meaningful without HTML markup only when the
	// candidate itself came from a URL-valued field. Keep this context check
	// alongside category guessing so such fields are not skipped before
	// analyzeXSS gets a chance to explain the hit.
	if xssJavascriptURLFieldContext(candidate) {
		seenXSS := false
		for _, category := range guesses {
			if category == "xss" {
				seenXSS = true
				break
			}
		}
		if !seenXSS {
			guesses = append(guesses, "xss")
		}
	}
	if xssDataURLFieldContext(candidate) {
		seenXSS := false
		for _, category := range guesses {
			if category == "xss" {
				seenXSS = true
				break
			}
		}
		if !seenXSS {
			guesses = append(guesses, "xss")
		}
	}
	if xssStandaloneJavascriptURLContext(candidate) {
		seenXSS := false
		for _, category := range guesses {
			if category == "xss" {
				seenXSS = true
				break
			}
		}
		if !seenXSS {
			guesses = append(guesses, "xss")
		}
	}
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
		if rceExecutionSinkForSource(hit.Source, hit.Name) {
			return 85
		}
		if strings.Contains(payload, "cmd=") ||
			strings.Contains(payload, "command=") ||
			strings.Contains(payload, "exec=") ||
			(rceWhitespaceEvasionMayMatch(payload) && rceWhitespaceEvasion.MatchString(payload)) ||
			(rceInterpreterInlineMayMatch(payload) && rceInterpreterInline.MatchString(payload)) ||
			(rcePowerShellSideFxMayMatch(payload) && rcePowerShellSideFx.MatchString(payload)) ||
			(rceDownloadExecChainMayMatch(payload) && rceDownloadExecChain.MatchString(payload)) ||
			(rceReverseShellPrimitiveMayMatch(payload) && rceReverseShellPrimitive.MatchString(payload)) ||
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
		// A javascript: or data: URI sitting in a URL-bearing attribute is
		// unambiguous markup execution, so it outranks the SQL reading. Without
		// this, "<img src="java<!-- -->script:alert(1)">" is attributed to sqli:
		// the HTML comment inside the scheme is also "--", which is a SQL comment
		// marker, and sqli sits at 75. The request is still blocked either way,
		// but the responder is told the wrong thing and the miss shows up as an
		// XSS detection gap.
		if javascriptURLContext.MatchString(payload) ||
			xssObfuscatedJavascriptURL.MatchString(payload) ||
			xssDataURLContext.MatchString(payload) ||
			xssSrcdocContext.MatchString(payload) ||
			strings.Contains(context, "data URI in URL-valued") {
			return 78
		}
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
	dedupMapThreshold      = 12
	maxDecodeVariants      = 8
	maxJSONNodes           = 200
	maxJSONDepth           = 8
	maxJSONTreeDecodeBytes = 256 << 10
	// maxMultipartInputs caps how many inspection inputs one multipart body can
	// contribute, bounding the parse work an attacker-controlled upload can
	// trigger. A part yields up to two inputs (filename plus content), so this
	// bounds parts to at least maxMultipartInputs/2 and at most its full value.
	maxMultipartInputs = 128
)

// rawCoverageSignal is not a detector or block decision. It only selects the
// most useful bounded window from an oversized value and promotes suspicious
// inputs when a request exceeds the global candidate budget. Final decisions
// still go through the category-specific syntax and semantic analyzers.
var rawCoverageSignal = regexp.MustCompile(`(?i)(?:\$\{\s*jndi\s*:|\$\{\$\{|\$\{[^}]{0,40}(?::-|:-[^}]|date:)|<\?(?:php|=)|<!\s*(?:doctype|entity)|<\s*script\b|javascript\s*:|data\s*:\s*(?:text/html|application/xhtml\+xml|image/svg\+xml)\s*;\s*base64\s*,|(?:;|&&|\|\||\|)\s*(?:cat|id|whoami|uname|curl|wget|bash|sh|zsh|dash|pwsh|powershell|cmd|python3?|perl|php|ruby|node|nc|ncat|netcat|socat|lua|iex|type|dir|ls|sleep|echo|ping)\b|(?:union(?:\s|%20)+(?:all(?:\s|%20)+)?select|(?:or|and)(?:\s|%20)+\d+(?:\s|%20)*=(?:\s|%20)*\d+|(?:drop(?:\s|%20)+table|delete(?:\s|%20)+from)|(?:order|group)(?:\s|%20)+by(?:\s|%20)+\d+|case(?:\s|%20)+when|select(?:\s|%20)+@@(?:version|datadir|hostname|basedir)\b)|0[xX](?:2[eE]|2[fF]|5[cC])(?:[./\\%0-9a-fA-F]{0,96}0[xX](?:2[eE]|2[fF]|5[cC])){2}|(?:/etc/(?:passwd|shadow|group|hosts|hostname|fstab|sudoers|crontab)|/proc/(?:self/(?:environ|cmdline|maps)|version|cpuinfo)|win\.ini|boot\.ini|wp-config|\.env|\.ssh/id_rsa|\.aws/credentials|docker\.sock|/var/log/|serviceaccount/token)|\.\.[/\\]|%2e%2e(?:%2f|/)|\{\{|\{%|%\{|<%|\$(?:where|function|eval|regex|ne|gt|gte|lt|lte)\b|https?://(?:127(?:\.\d+){3}|169\.254(?:\.\d+){2}|localhost\b)|\(\)\s*\{)`)

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
	return extractCandidatesWithOptions(reqCtx, nil, decoder.DefaultDecodeDepth)
}

// extractCandidatesWithAllowlist applies parameter exclusions before the
// bounded candidate budget. Filtering after truncation lets an attacker fill
// the budget with allowlisted fields and hide a later unallowlisted payload.
func extractCandidatesWithAllowlist(reqCtx *engine.RequestContext, allow map[string]struct{}) []semanticCandidate {
	return extractCandidatesWithOptions(reqCtx, allow, decoder.DefaultDecodeDepth)
}

func extractCandidatesWithOptions(reqCtx *engine.RequestContext, allow map[string]struct{}, decodeDepth int) []semanticCandidate {
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
	// Custom-scheme request targets (for example javascript://...) have no
	// normal URL path, so preserve the target as an explicit URI candidate. The
	// XSS matcher still requires a complete executable scheme value; ordinary
	// HTTP targets are untouched.
	targetRaw := r.URL.RequestURI()
	if r.URL.Scheme != "" {
		targetRaw = r.URL.String()
	} else if targetRaw == "" {
		targetRaw = r.URL.String()
	}
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(targetRaw)), "javascript:") {
		add(&uriInputs, InputPoint{Source: "uri", Name: "target", Raw: clipRaw(targetRaw), Layers: rawLayersOnly})
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
	bodyPoints, bodyIncomplete := bodyInputsWithStatus(r, reqCtx.DecodedBody)
	for _, input := range bodyPoints {
		add(&bodyGroup, input)
	}
	groups = append(groups, bodyGroup)
	if bodyIncomplete {
		markSemanticInputIncomplete(reqCtx, multipartCoverageIncompleteReason)
	}
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
			variants := decodeVariantsInto(variantScratch[:0], input.Raw, decodeDepth)
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
	if allowSkipped > 0 {
		if reqCtx.Metadata == nil {
			reqCtx.Metadata = map[string]any{}
		}
		reqCtx.Metadata["semantic_skipped"] = "param_allowlist"
	}
	return candidates
}

func markSemanticInputIncomplete(reqCtx *engine.RequestContext, reason string) {
	if reqCtx == nil {
		return
	}
	if reqCtx.Metadata == nil {
		reqCtx.Metadata = map[string]any{}
	}
	reqCtx.Metadata["semantic_input_incomplete"] = true
	reqCtx.Metadata["semantic_input_incomplete_reason"] = reason
	// The pipeline already has an analysis-incomplete metadata channel. Mirror
	// input coverage loss onto it so isolated detector forks carry both the
	// precise cause and the aggregate state expected by fail-mode handling.
	reqCtx.Metadata["semantic_analysis_incomplete"] = true
	reqCtx.Metadata["semantic_analysis_incomplete_reason"] = reason
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
	if match := bestRawCoverageMatch(raw); match != nil {
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
		if match := bestRawCoverageMatchBytes(raw); match != nil {
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

// bestRawCoverageMatch chooses the most actionable anchor from an oversized
// value. A first, harmless documentation marker must not hide a later attack
// marker from the bounded window; ties prefer the later occurrence so a
// trailing payload remains visible without retaining the whole body. Matches
// are streamed one at a time, so marker-flooding documents use constant
// temporary memory while still allowing a later high-confidence anchor to win.
func bestRawCoverageMatch(raw string) []int {
	var best []int
	bestScore := -1
	searchStart := 0
	for searchStart < len(raw) {
		relative := rawCoverageSignal.FindStringIndex(raw[searchStart:])
		if relative == nil {
			break
		}
		match := []int{searchStart + relative[0], searchStart + relative[1]}
		score := rawCoverageAnchorScore(raw, match)
		if score >= bestScore {
			best = match
			bestScore = score
		}
		searchStart = match[1]
	}
	return best
}

func bestRawCoverageMatchBytes(raw []byte) []int {
	var best []int
	bestScore := -1
	searchStart := 0
	for searchStart < len(raw) {
		relative := rawCoverageSignal.FindIndex(raw[searchStart:])
		if relative == nil {
			break
		}
		match := []int{searchStart + relative[0], searchStart + relative[1]}
		score := rawCoverageAnchorScoreBytes(raw, match)
		if score >= bestScore {
			best = match
			bestScore = score
		}
		searchStart = match[1]
	}
	return best
}

func rawCoverageAnchorScore(raw string, match []int) int {
	if len(match) != 2 || match[0] < 0 || match[1] > len(raw) || match[0] >= match[1] {
		return -1
	}
	lo := match[0] - 160
	if lo < 0 {
		lo = 0
	}
	hi := match[1] + 160
	if hi > len(raw) {
		hi = len(raw)
	}
	return rawCoverageAnchorScoreWindow(raw[lo:hi], match[0]-lo, match[1]-lo)
}

func rawCoverageAnchorScoreBytes(raw []byte, match []int) int {
	if len(match) != 2 || match[0] < 0 || match[1] > len(raw) || match[0] >= match[1] {
		return -1
	}
	lo := match[0] - 160
	if lo < 0 {
		lo = 0
	}
	hi := match[1] + 160
	if hi > len(raw) {
		hi = len(raw)
	}
	return rawCoverageAnchorScoreWindow(string(raw[lo:hi]), match[0]-lo, match[1]-lo)
}

func rawCoverageAnchorScoreWindow(window string, matchStart, matchEnd int) int {
	// Keep the match slice on the original byte offsets. Unicode lower-casing
	// can change byte length for a few code points; lower the matched ASCII
	// token and the surrounding context independently so offsets cannot drift.
	lower := strings.ToLower(window)
	matched := strings.ToLower(window[matchStart:matchEnd])
	score := 10
	if strings.Contains(matched, "/etc/") || strings.Contains(matched, "/proc/") ||
		strings.Contains(matched, "/var/log/") || strings.Contains(matched, "win.ini") ||
		strings.Contains(matched, "boot.ini") || strings.Contains(matched, "passwd") ||
		strings.Contains(matched, "shadow") || strings.Contains(matched, "wp-config") ||
		strings.Contains(matched, ".env") || strings.Contains(matched, ".ssh/") ||
		strings.Contains(matched, ".aws/") || strings.Contains(matched, "docker.sock") ||
		strings.Contains(matched, "web-inf/") || strings.Contains(matched, "manifest.mf") ||
		strings.Contains(matched, "serviceaccount/token") {
		score += 80
	}
	if strings.Contains(matched, "union") || strings.Contains(matched, "drop") ||
		strings.Contains(matched, "delete") || strings.Contains(matched, "order") ||
		strings.Contains(matched, "group") || strings.Contains(matched, "case") ||
		strings.Contains(matched, "select") {
		score += 60
	}
	if strings.Contains(matched, "0x") {
		score += 20
	}
	for _, marker := range []string{"%00", "../", "\\x00", "--", "/*", "; ", "&&", "||"} {
		if strings.Contains(lower, marker) {
			score += 25
			break
		}
	}
	for _, marker := range []string{"documentation", "example", "guide", "article", "discuss", "tutorial"} {
		if strings.Contains(lower, marker) {
			score -= 20
			break
		}
	}
	return score
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
	inputs, _ := bodyInputsWithStatus(r, body)
	return inputs
}

// bodyInputsWithStatus returns the bounded body candidates plus whether parsing
// had to stop on malformed/truncated multipart input. The status is kept
// separate from the legacy bodyInputs API so callers that only need extraction
// remain source-compatible while the analyzer can surface coverage loss.
func bodyInputsWithStatus(r *http.Request, body []byte) ([]InputPoint, bool) {
	if len(body) == 0 {
		return nil, false
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
	contentTypeHeader := r.Header.Get("Content-Type")
	contentType := requestMediaType(contentTypeHeader)
	switch contentType {
	case "application/x-www-form-urlencoded":
		values, err := url.ParseQuery(string(body))
		if err == nil {
			// url.ParseQuery returns a map. Sort its keys before constructing
			// InputPoints: candidate budgeting/fair traversal is order-sensitive,
			// so ranging the map would make late fields nondeterministically survive
			// the maxCandidates cap.
			keys := make([]string, 0, len(values))
			for key := range values {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				list := values[key]
				inputs = append(inputs, InputPoint{Source: "body.form", Name: key, Raw: key, Layers: rawLayersOnly})
				for _, value := range list {
					inputs = append(inputs, InputPoint{Source: "body.form", Name: key, Raw: value, Layers: rawLayersOnly})
				}
			}
			return withBodyCoverage(body, inputs), false
		}
	case "application/json":
		flattenJSONInputs("body.json", "", body, &inputs)
		if len(inputs) > 0 {
			return withBodyCoverage(body, inputs), false
		}
	case "multipart/form-data":
		if boundary := boundaryFromContentType(r.Header.Get("Content-Type")); boundary != "" {
			multipart, incomplete := multipartInputsWithStatus(body, boundary)
			covered := withBodyCoverage(body, multipart)
			if incomplete {
				covered = ensureBodyRawCoverage(body, covered)
			}
			return covered, incomplete
		}
		// A multipart media type without a valid boundary cannot be parsed
		// faithfully. Keep a bounded raw view and surface the coverage loss.
		return withBodyCoverage(body, []InputPoint{{Source: "body.raw", Name: "body", Raw: clipRawBytes(body), Layers: rawLayersOnly}}), true
	}
	if json.Valid(body) {
		flattenJSONInputs("body.json", "", body, &inputs)
	}
	if len(inputs) == 0 {
		inputs = append(inputs, InputPoint{Source: "body.raw", Name: "body", Raw: clipRawBytes(body), Layers: rawLayersOnly})
	}
	declaredMultipart := isDeclaredMultipartContentType(contentTypeHeader)
	return withBodyCoverage(body, inputs), declaredMultipart
}

func isDeclaredMultipartContentType(header string) bool {
	trimmed := strings.ToLower(strings.TrimSpace(header))
	return trimmed == "multipart/form-data" || strings.HasPrefix(trimmed, "multipart/form-data;")
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

func ensureBodyRawCoverage(body []byte, inputs []InputPoint) []InputPoint {
	for _, input := range inputs {
		if input.Source == "body.raw" && input.Name == "body" {
			return inputs
		}
	}
	covered := make([]InputPoint, 0, len(inputs)+1)
	covered = append(covered, InputPoint{Source: "body.raw", Name: "body", Raw: clipRawBytes(body), Layers: rawLayersOnly})
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
	// Preserve the historical decoder behavior for malformed/trailing documents
	// (it emits the first successfully decoded value) while using a bounded
	// head/tail collector inside the decoder fallback for valid large objects.
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

// flattenJSONInputsDecode is the decoder-backed fallback for bodies the byte
// walker declines. Its bounded collector keeps the fallback deterministic and
// retains a tail sample when the candidate budget is reached.
func flattenJSONInputsDecode(source, prefix string, raw []byte, inputs *[]InputPoint) {
	var value any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return
	}
	capacity := maxCandidates - len(*inputs)
	if capacity <= 0 {
		return
	}
	collector := newJSONInputCollector(capacity)
	nodes := 0
	flattenJSONValueBounded(source, prefix, value, 0, &nodes, &collector)
	collector.appendTo(inputs)
}

// flattenJSONValueBounded walks the decoder's map representation while keeping
// a deterministic head/tail sample once the candidate budget is full. It must
// continue traversing after the head is populated; otherwise a late attack field
// can be hidden behind maxCandidates ordinary fields.
func flattenJSONValueBounded(source, prefix string, value any, depth int, nodes *int, collector *jsonInputCollector) {
	if depth > maxJSONDepth || *nodes >= maxJSONNodes {
		return
	}
	*nodes++
	switch typed := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			value := typed[key]
			if *nodes >= maxJSONNodes {
				return
			}
			name := key
			if prefix != "" {
				name = prefix + "." + key
			}
			collector.add(InputPoint{Source: source, Name: name, Raw: clipRaw(key), Layers: rawLayersOnly})
			flattenJSONValueBounded(source, name, value, depth+1, nodes, collector)
		}
	case []any:
		for idx, value := range typed {
			if *nodes >= maxJSONNodes {
				return
			}
			flattenJSONValueBounded(source, prefix+"[]", value, depth+1, nodes, collector)
			_ = idx
		}
	case string:
		collector.add(InputPoint{Source: source, Name: prefix, Raw: clipRaw(typed), Layers: rawLayersOnly})
	case json.Number, bool, float64:
		collector.add(InputPoint{Source: source, Name: prefix, Raw: toString(typed), Layers: rawLayersOnly})
	}
}

// flattenJSONValue preserves the package-local helper used by older tests and
// callers. New extraction paths use flattenJSONValueBounded directly so they can
// retain a head/tail sample after the candidate budget fills; this wrapper keeps
// the original append-oriented signature for compatibility.
func flattenJSONValue(source, prefix string, value any, inputs *[]InputPoint, depth int, nodes *int) {
	if inputs == nil {
		return
	}
	capacity := maxCandidates - len(*inputs)
	if capacity <= 0 {
		return
	}
	collector := newJSONInputCollector(capacity)
	flattenJSONValueBounded(source, prefix, value, depth, nodes, &collector)
	collector.appendTo(inputs)
}

func boundaryFromContentType(header string) string {
	_, params, err := mime.ParseMediaType(header)
	if err != nil {
		return ""
	}
	return params["boundary"]
}

func multipartInputs(body []byte, boundary string) []InputPoint {
	inputs, _ := multipartInputsWithStatus(body, boundary)
	return inputs
}

func multipartInputsWithStatus(body []byte, boundary string) ([]InputPoint, bool) {
	reader := multipart.NewReader(bytes.NewReader(body), boundary)
	var inputs []InputPoint
	// Read one byte past the per-part cap so an oversized part is distinguishable
	// from an exactly capped, valid part. The candidate remains bounded to the
	// existing maxInputRawBytes window.
	buf := make([]byte, maxInputRawBytes+1)
	incomplete := false
	partsSeen := 0
	appendInput := func(input InputPoint) bool {
		if len(inputs) >= maxMultipartInputs {
			incomplete = true
			return false
		}
		inputs = append(inputs, input)
		return true
	}
	for len(inputs) < maxMultipartInputs && partsSeen < maxMultipartInputs {
		part, err := reader.NextPart()
		if err != nil {
			if err != io.EOF {
				incomplete = true
			}
			break
		}
		partsSeen++
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
			if !appendInput(InputPoint{
				Source: "body.multipart",
				Name:   clipRaw(name + ".filename"),
				Raw:    clipRaw(fileName),
				Layers: rawLayersOnly,
			}) {
				break
			}
		}
		n := 0
		for n < len(buf) {
			m, readErr := part.Read(buf[n:])
			n += m
			if readErr != nil {
				if readErr != io.EOF {
					// A part that cannot reach its framing delimiter is
					// incomplete; retain any bytes read before the error.
					incomplete = true
				}
				break
			}
			if m == 0 {
				break
			}
		}
		if n == 0 {
			continue
		}
		if n > maxInputRawBytes {
			incomplete = true
			n = maxInputRawBytes
		}
		if !appendInput(InputPoint{Source: "body.multipart", Name: clipRaw(name), Raw: string(buf[:n]), Layers: rawLayersOnly}) {
			break
		}
	}
	if (len(inputs) >= maxMultipartInputs || partsSeen >= maxMultipartInputs) && !incomplete {
		// Probe once beyond the cap so exactly-cap-sized, well-formed bodies do
		// not get marked incomplete. Any additional part (or framing error)
		// proves that the inspection budget omitted attacker-controlled bytes.
		if _, err := reader.NextPart(); err != io.EOF {
			incomplete = true
		}
	}
	return inputs, incomplete
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
func decodeVariantsInto(dst []decodedVariant, raw string, decodeDepth int) []decodedVariant {
	// UTF-16 LE/BE BOM payloads (XXE evasion). Expand once into UTF-8 text.
	if utf8FromUTF16, ok := decodeUTF16Payload(raw); ok && utf8FromUTF16 != raw {
		raw = utf8FromUTF16
	}
	// Hot path: plain text without encode markers needs no expansion queue.
	if !needsDeepDecode(raw) {
		return append(dst, decodedVariant{text: raw, layers: rawLayersOnly})
	}
	return decodeVariantsDeep(dst, raw, decodeDepth)
}

// decodeVariantsDeep runs the bounded multi-layer expansion queue. Split out of
// decodeVariantsInto so the hot single-variant path stays inlinable and its
// queue/map allocations never appear on ordinary traffic.
func decodeVariantsDeep(dst []decodedVariant, raw string, decodeDepth int) []decodedVariant {
	if decodeDepth <= 0 {
		decodeDepth = decoder.DefaultDecodeDepth
	}
	if decodeDepth > decoder.MaxDecodeDepth {
		decodeDepth = decoder.MaxDecodeDepth
	}
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
		usedDepth := len(item.layers) - len(rawLayersOnly)
		if usedDepth >= decodeDepth {
			continue
		}
		if next := decoder.DecodeWithDepthPreserveControls(item.text, decodeDepth-usedDepth); next.Text != item.text {
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
	// Avoid converting every ordinary ASCII candidate to []byte.  The byte
	// decoder only has useful work when a BOM or a UTF-16-like NUL pattern is
	// present; the cheap string scan preserves that decision without a temporary
	// allocation on the normal request path.
	if !looksLikeUTF16String(raw) {
		return "", false
	}
	return decodeUTF16FromBytes([]byte(raw))
}

func looksLikeUTF16String(raw string) bool {
	if len(raw) < 4 {
		return false
	}
	if (raw[0] == '\xff' && raw[1] == '\xfe') || (raw[0] == '\xfe' && raw[1] == '\xff') {
		return true
	}
	limit := len(raw)
	if limit > 256 {
		limit = 256
	}
	nulEven, nulOdd := 0, 0
	for i := 0; i < limit; i++ {
		if raw[i] != 0 {
			continue
		}
		if i%2 == 0 {
			nulEven++
		} else {
			nulOdd++
		}
	}
	if nulEven == 0 && nulOdd == 0 {
		return false
	}
	return nulOdd >= limit/6 || nulEven >= limit/6
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
	if strings.Contains(text, "--") {
		text = sqlLineComment.ReplaceAllString(text, "")
	}
	if strings.Contains(text, "#") {
		text = strings.ReplaceAll(text, "#", "")
	}
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
	// The two rewrite expressions only have an effect when a block-comment
	// delimiter is present. Avoid running regexp.ReplaceAllString over every
	// prose candidate; this is a dominant cost for long benign documents.
	if !strings.Contains(text, "/*") {
		return text
	}
	text = sqlMySQLVersionComment.ReplaceAllString(text, " $1 ")
	return sqlKeywordBridgeComment.ReplaceAllString(text, "$1$2")
}

func guessCategoriesForSource(raw, inputName, inputSource string) []string {
	// Fast negative path only for clean identifiers. Dirty/unknown shapes over-scan
	// rather than risk missing attacks (FP-first applies later in blockableHit).
	if looksCleanASCIIField(raw) && !rceBareCommandSinkValueForSource(inputSource, inputName, raw) {
		return nil
	}
	// Long unstructured values are commonly security articles, logs, or source
	// listings. Running every category's regexp suite on those values makes the
	// hot path proportional to document length even when there is no request
	// signal (a sentence containing "select" used to open the SQL suite). Keep a
	// conservative, category-specific marker gate for document-scale candidates.
	// Short values retain the historical over-scan behavior; long attack payloads
	// still pass when they carry a concrete query, script, command, path, template,
	// protocol, or runtime marker. The gate only chooses analyzers -- the existing
	// syntax/semantic and document-context guards still decide block/pass.
	longMask := 0
	if len(raw) >= longCandidateThreshold {
		longMask = longCandidateStrongHints(raw, inputName, inputSource)
		if longMask == 0 {
			return nil
		}
	}
	hints := scanAttackHints(raw)
	if hints == 0 {
		hints = hintSQL | hintXSS | hintRCE | hintLFI | hintXXE | hintSSRF | hintNoSQL | hintSSTI
	}
	if longMask != 0 {
		// Keep only families backed by a strong long-value marker. This prevents a
		// generic word such as "and" from re-opening SQL alongside a real, unrelated
		// marker (for example an embedded <script> sample).
		hints &= longMask
		if hints == 0 {
			hints = longMask
		}
	}
	// Fold overlong UTF-8 before normalising, for the same reason analyzeLFI
	// does: NFKC turns the invalid bytes 0xC0 0xAF into U+FFFD, and the scoring
	// gates here would then see no "../" and give lfi zero score — so
	// analyzeLFI was never called on the very payload it was written to catch.
	foldedRaw := foldOverlongUTF8(raw)
	if lfiUnicodeSeparatorCandidate(foldedRaw, inputSource, inputName) {
		if foldedUnicode, ok := foldLFIUnicodeSeparators(foldedRaw); ok {
			foldedRaw = foldedUnicode
		}
	}
	text := normalize(foldedRaw)
	dataURLFieldContext := xssDataURLFieldContext(semanticCandidate{
		input: InputPoint{Source: inputSource, Name: inputName},
		text:  raw,
	})
	// RCE line-chain detection needs a compatibility-folded view that retains
	// newlines. The general normalized view deliberately strips controls for
	// tokenization, which would otherwise erase `ｉｄ\nｌｓ` before the RCE hint can
	// open the analyzer.
	// When no control rune is present, both normalizers produce the same view;
	// reuse text instead of paying for a second NFKC/lowercase pass on every
	// ordinary attack candidate.
	rceText := text
	if strings.IndexFunc(foldedRaw, unicode.IsControl) >= 0 {
		rceText = normalizePreserveControls(foldedRaw)
	}
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
			strings.Contains(text, "order by") || strings.Contains(text, "group by") ||
			strings.Contains(text, "having ") || strings.Contains(text, "exec ") ||
			strings.Contains(text, "execute ") ||
			strings.Contains(text, "load_file") || strings.Contains(text, "into outfile") ||
			strings.Contains(text, "procedure analyse") || strings.Contains(text, "dbms_lock.sleep") ||
			strings.Contains(text, "sp_oacreate") || strings.Contains(text, "openrowset") ||
			strings.Contains(text, "0x") || strings.Contains(text, "/*") || strings.Contains(text, "--") ||
			longCandidateSQLStrongHint(text)
		if cheapSQL || xpathCheapGate(text) {
			scores["sqli"] += 2
		} else {
			sqlCompact := compactSQL(text)
			if strings.Contains(sqlCompact, "unionselect") || strings.Contains(sqlCompact, "or1=1") ||
				sqlBooleanTautology.MatchString(text) || sqlEmptyStringTautology.MatchString(text) ||
				quotedOrPredicateInjection(text) || sqlOrderByInference.MatchString(text) ||
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
	if dataURLFieldContext {
		scores["xss"] += 2
	}
	if hints&hintRCE != 0 {
		if strings.Contains(rceText, ";") || strings.Contains(rceText, "&&") || strings.Contains(rceText, "|") || strings.Contains(rceText, "$(") || strings.Contains(rceText, "`") || strings.Contains(rceText, "$shell") || strings.Contains(rceText, "$ifs") || strings.Contains(rceText, "${ifs}") || strings.Contains(rceText, "/usr/bin/") || strings.Contains(rceText, "/bin/") || strings.Contains(rceText, "/etc/") || strings.Contains(rceText, "/proc/") || strings.Contains(rceText, "cmd.exe") || strings.Contains(rceText, "cmd /c") || strings.Contains(rceText, "powershell") || strings.Contains(rceText, "pwsh") || strings.Contains(rceText, "encodedcommand") || strings.Contains(rceText, "downloadstring") || strings.Contains(rceText, "downloadfile") || strings.Contains(rceText, "webclient") || strings.Contains(rceText, "tcpclient") || strings.Contains(rceText, "new-object") || strings.Contains(rceText, "<?php") || strings.Contains(rceText, "eval(") || strings.Contains(rceText, "assert(") || strings.Contains(rceText, "getallheaders") || strings.Contains(rceText, "apache_request_headers") || strings.Contains(rceText, "bash -c") || strings.Contains(rceText, "sh -c") || strings.Contains(rceText, "wget ") || strings.Contains(rceText, "curl ") || strings.Contains(rceText, "python -c") || strings.Contains(rceText, "php -r") || strings.Contains(rceText, "perl -e") || strings.Contains(rceText, "ld_preload") || strings.Contains(rceText, "child_process") ||
			(rceInterpreterInlineMayMatch(rceText) && rceInterpreterInline.MatchString(rceText)) ||
			(strings.Contains(rceText, "$shell") || strings.Contains(rceText, "${shell}")) && strings.Contains(rceText, " -c") ||
			rceReverseShellPrimitiveMayMatch(rceText) && rceReverseShellPrimitive.MatchString(rceText) ||
			rceTemplateExecutionPrimitiveMayMatch(rceText) && rceTemplateExecutionPrimitive.MatchString(rceText) ||
			rceNetWebClientSideFxMayMatch(rceText) && rceNetWebClientSideFx.MatchString(rceText) ||
			rcePowerShellSideFxMayMatch(rceText) && rcePowerShellSideFx.MatchString(rceText) ||
			rceLoaderPrimitiveMayMatch(rceText) && rceLoaderPrimitive.MatchString(rceText) ||
			rceNewlineCommandChain(rceText) || rceControlCommandChain(rceText) {
			scores["rce"] += 2
		}
	}
	// A command sink must be analyzed even when its value has no punctuation:
	// `cmd=id` and `exec=whoami` are complete payloads, not ordinary identifiers.
	// analyzeRCE still requires a known command or another execution signal before
	// emitting a hit, so opening this family is safe for values such as `cmd=123`.
	if rceBareCommandSinkValueForSource(inputSource, inputName, rceText) {
		scores["rce"] += 2
	}
	// Explicit command parameters also carry multi-word commands without shell
	// punctuation (for example `cmd=ls -la` or `cmd=python3 -c 'id'`). Keep this
	// gate narrow: only the terminal, unambiguous command-parameter names are
	// eligible, and the value must begin with a known executable plus an argument.
	if rceCommandSinkShapeForSource(inputSource, inputName, rceText) {
		scores["rce"] += 2
	}
	if rceSinkNULPatternIntentForSource(inputSource, inputName, rceText) {
		scores["rce"] += 2
	}
	if hints&hintLFI != 0 {
		if strings.Contains(text, "../") || strings.Contains(text, `..\`) || strings.Contains(text, "..//") || strings.Contains(text, `..\/`) || lfiEncodedTraversal.MatchString(text) || lfiSensitiveTarget.MatchString(text) || lfiWindowsSystemPathMatch(text) || lfiFileReadSink.MatchString(text) || lfiCommandReadSink.MatchString(text) || strings.Contains(text, "file://") || strings.Contains(text, "php://") || strings.Contains(text, "data://") || strings.Contains(text, "phar://") || strings.Contains(text, "expect://") || strings.Contains(text, "docker.sock") || strings.Contains(text, ".aws/") || strings.Contains(text, ".git/") || strings.Contains(text, "/.env") || lfiDotEnvTarget.MatchString(text) || strings.Contains(text, "wp-config") || strings.Contains(text, ".ssh/") || strings.Contains(text, "/var/run/secrets/kubernetes.io/") || lfiSSIDirective.MatchString(text) ||
			lfiHexPathEscapeCandidate(foldedRaw, inputSource, inputName) ||
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
		if nosqlOperatorToken.MatchString(text) || strings.Contains(text, "$function") || strings.Contains(text, "this.") || strings.Contains(text, "function(") || nosqlShellEscapeMatch(text) {
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
			phpGadgetText(text) ||
			(strings.Contains(text, "eval(") && (strings.Contains(text, "$_post") || strings.Contains(text, "$_get") || strings.Contains(text, "$_request") || strings.Contains(text, "$_cookie"))) ||
			strings.Contains(text, "base64_decode") || strings.Contains(text, "gzinflate") ||
			strings.Contains(text, "runtime.getruntime()") || strings.Contains(text, "processbuilder") ||
			strings.Contains(text, "system.diagnostics.process") ||
			(strings.Contains(text, ".php") && (strings.Contains(text, "action=") || strings.Contains(text, "cmd=") || strings.Contains(text, "shell"))) {
			scores["webshell"] += 2
		}
	}
	if hints&hintLog4Shell != 0 {
		if hasLog4ShellLookup(text) || strings.Contains(text, "() { :;};") {
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

// longCandidateThreshold is intentionally above normal query/form values and
// below the bounded 16 KiB candidate window. Values at or above it are treated
// as document-scale for candidate selection; a concrete marker is still enough
// to enter the full category analyzer. The 256-byte boundary keeps short attack
// payloads on the exact historical path while covering the common prose/JSON
// document sizes that caused the regex hot spot.
const longCandidateThreshold = 256

// longCandidateStrongHints returns a necessary-condition mask for expensive
// analyzers on long values. It is deliberately made from bounded substring
// checks and small scans rather than regular expressions: this function runs on
// every long body/document candidate, including benign prose. Returning a
// category means "worth analyzing", never "malicious".
func longCandidateStrongHints(raw, inputName, inputSource string) int {
	lower := strings.ToLower(raw)
	mask := 0

	// SQL: require query composition, a boolean/time/file primitive, or a
	// comment/quote shape that can actually alter a statement. Bare words such as
	// "select"/"union" in an article are intentionally insufficient.
	if longCandidateSQLStrongHint(lower) ||
		strings.Contains(lower, "union select") || strings.Contains(lower, "union/**/select") ||
		strings.Contains(lower, "union/*") || strings.Contains(lower, "or 1=1") ||
		strings.Contains(lower, "and 1=1") || strings.Contains(lower, "or'1'='1") ||
		strings.Contains(lower, "and'1'='1") || strings.Contains(lower, "sleep(") ||
		strings.Contains(lower, "benchmark(") || strings.Contains(lower, "pg_sleep") ||
		strings.Contains(lower, "waitfor delay") || strings.Contains(lower, "xp_cmdshell") ||
		strings.Contains(lower, "information_schema") || strings.Contains(lower, "into outfile") ||
		strings.Contains(lower, "load_file") || strings.Contains(lower, "dbms_lock.sleep") ||
		strings.Contains(lower, "procedure analyse") || strings.Contains(lower, "openrowset") ||
		(strings.Contains(lower, "select") && strings.Contains(lower, " from ") &&
			longCandidateKeywordPair(lower, "select", " from ", 320)) ||
		longCandidateSQLCommentShape(lower) {
		mask |= hintSQL
	}

	// XSS/XXE/webshell/log injection markers. Encoded angle brackets are kept as
	// markers because candidate decoding may be disabled for a large opaque body.
	if strings.Contains(lower, "<script") || strings.Contains(lower, "%3cscript") ||
		strings.Contains(lower, "<svg") || strings.Contains(lower, "%3csvg") ||
		strings.Contains(lower, "javascript:") || strings.Contains(lower, "data:text/html") ||
		strings.Contains(lower, "onerror=") || strings.Contains(lower, "onload=") ||
		strings.Contains(lower, "onclick=") || strings.Contains(lower, "alert(") {
		mask |= hintXSS
	}
	if strings.Contains(lower, "<!doctype") || strings.Contains(lower, "<!entity") ||
		strings.Contains(lower, "xinclude") || strings.Contains(lower, "xi:include") {
		mask |= hintXXE
	}
	if strings.Contains(lower, "<?php") || strings.Contains(lower, "<?=") ||
		strings.Contains(lower, "base64_decode") || strings.Contains(lower, "shell_exec") ||
		strings.Contains(lower, "$_get[") || strings.Contains(lower, "$_post[") ||
		strings.Contains(lower, "runtime.getruntime") || strings.Contains(lower, "processbuilder") {
		mask |= hintWebshell
	}
	if strings.Contains(lower, "${jndi:") || strings.Contains(lower, "${${") ||
		strings.Contains(lower, "() { :;};") {
		mask |= hintLog4Shell
	}

	// RCE: command sinks are authoritative even when the value is a bare command;
	// otherwise require an interpreter, shell boundary, download/exec chain, or a
	// sensitive command target. The sink helpers are source-aware and avoid turning
	// ordinary prose that happens to contain "cmd" into a deep scan.
	if rceBareCommandSinkValueForSource(inputSource, inputName, raw) ||
		rceCommandSinkShapeForSource(inputSource, inputName, raw) ||
		strings.Contains(lower, "bash -c") || strings.Contains(lower, "sh -c") ||
		strings.Contains(lower, "cmd /c") || strings.Contains(lower, "powershell -") ||
		strings.Contains(lower, "pwsh -") || strings.Contains(lower, "encodedcommand") ||
		strings.Contains(lower, "curl ") && (strings.Contains(lower, "|sh") || strings.Contains(lower, "| sh") || strings.Contains(lower, ";sh")) ||
		strings.Contains(lower, "wget ") && (strings.Contains(lower, "|sh") || strings.Contains(lower, "| sh") || strings.Contains(lower, ";sh")) ||
		strings.Contains(lower, "/dev/tcp/") || strings.Contains(lower, "child_process") ||
		strings.Contains(lower, "ld_preload") || strings.Contains(lower, "downloadstring") ||
		strings.Contains(lower, "invoke-expression") || strings.Contains(lower, "eval(") ||
		strings.Contains(lower, "system(") || strings.Contains(lower, "shell_exec(") ||
		longCandidateShellCommandShape(lower) || rceNewlineCommandChain(lower) {
		mask |= hintRCE
	}

	// LFI and SSRF markers are target-oriented. A generic public URL in a long
	// article is not enough; internal metadata targets and explicit file wrappers
	// are. URL-bearing field names retain a narrow path for opaque callback values.
	if strings.Contains(lower, "../") || strings.Contains(lower, `..\`) ||
		strings.Contains(lower, "%2e%2e") || strings.Contains(lower, "/etc/passwd") ||
		strings.Contains(lower, "/etc/shadow") || strings.Contains(lower, "/proc/self") ||
		strings.Contains(lower, ".env") || strings.Contains(lower, "wp-config") ||
		strings.Contains(lower, "php://") || strings.Contains(lower, "file://") ||
		strings.Contains(lower, "docker.sock") || strings.Contains(lower, "boot.ini") ||
		strings.Contains(lower, "win.ini") || lfiSSIDirective.MatchString(lower) ||
		lfiHexPathEscapeCandidate(raw, inputSource, inputName) {
		mask |= hintLFI
	}
	if strings.Contains(lower, "169.254.") || strings.Contains(lower, "127.0.0.1") ||
		strings.Contains(lower, "localhost") || strings.Contains(lower, "metadata.google.internal") ||
		strings.Contains(lower, "gopher://") || strings.Contains(lower, "dict://") ||
		((strings.Contains(lower, "http://") || strings.Contains(lower, "https://")) &&
			longCandidateURLField(inputName)) {
		mask |= hintSSRF
	}

	// NoSQL/SSTI syntax has low-cost, high-specificity delimiters. Do not open
	// these families for ordinary JSON/prose braces or dollar amounts.
	if longCandidateNoSQLOperator(lower) || strings.Contains(lower, "db.") {
		mask |= hintNoSQL
	}
	if strings.Contains(lower, "{{") || strings.Contains(lower, "{%") ||
		strings.Contains(lower, "${") || strings.Contains(lower, "<%") ||
		strings.Contains(lower, "__class__") || strings.Contains(lower, "__globals__") {
		mask |= hintSSTI
	}

	// Compatibility forms (full-width tags, long-s characters in shell names,
	// and similar evasions) are uncommon in benign long text. Re-check one folded
	// view only when the ASCII pass found no marker, preserving recall without
	// making normalization part of the usual negative path.
	if mask == 0 && hintNeedsNormalizedView(raw) {
		folded := normalizePreserveControls(raw)
		if folded != raw {
			mask = longCandidateStrongHintsASCII(strings.ToLower(folded), inputName, inputSource)
		}
	}
	return mask
}

func longCandidateStrongHintsASCII(lower, inputName, inputSource string) int {
	// The folded fallback intentionally shares the same conservative markers but
	// avoids recursively allocating or normalizing a second time.
	mask := 0
	if longCandidateSQLStrongHint(lower) ||
		strings.Contains(lower, "union select") || strings.Contains(lower, "or 1=1") ||
		strings.Contains(lower, "and 1=1") || strings.Contains(lower, "sleep(") ||
		strings.Contains(lower, "xp_cmdshell") || strings.Contains(lower, "information_schema") ||
		strings.Contains(lower, "into outfile") || strings.Contains(lower, "load_file") ||
		(strings.Contains(lower, "select") && strings.Contains(lower, " from ")) || longCandidateSQLCommentShape(lower) {
		mask |= hintSQL
	}
	if strings.Contains(lower, "<script") || strings.Contains(lower, "<svg") ||
		strings.Contains(lower, "javascript:") || strings.Contains(lower, "onerror=") ||
		strings.Contains(lower, "onload=") || strings.Contains(lower, "alert(") {
		mask |= hintXSS
	}
	if strings.Contains(lower, "<!doctype") || strings.Contains(lower, "<!entity") || strings.Contains(lower, "xinclude") {
		mask |= hintXXE
	}
	if strings.Contains(lower, "<?php") || strings.Contains(lower, "base64_decode") ||
		strings.Contains(lower, "shell_exec") || strings.Contains(lower, "processbuilder") {
		mask |= hintWebshell
	}
	if strings.Contains(lower, "${jndi:") || strings.Contains(lower, "() { :;};") {
		mask |= hintLog4Shell
	}
	if rceBareCommandSinkValueForSource(inputSource, inputName, lower) ||
		strings.Contains(lower, "bash -c") || strings.Contains(lower, "sh -c") ||
		strings.Contains(lower, "cmd /c") || strings.Contains(lower, "powershell -") ||
		strings.Contains(lower, "/dev/tcp/") || strings.Contains(lower, "child_process") ||
		strings.Contains(lower, "eval(") || longCandidateShellCommandShape(lower) ||
		rceNewlineCommandChain(lower) {
		mask |= hintRCE
	}
	if strings.Contains(lower, "../") || strings.Contains(lower, "%2e%2e") ||
		strings.Contains(lower, "/etc/passwd") || strings.Contains(lower, ".env") ||
		strings.Contains(lower, "php://") || strings.Contains(lower, "file://") ||
		lfiHexPathEscapeCandidate(lower, inputSource, inputName) {
		mask |= hintLFI
	}
	if strings.Contains(lower, "169.254.") || strings.Contains(lower, "127.0.0.1") ||
		strings.Contains(lower, "localhost") || strings.Contains(lower, "gopher://") {
		mask |= hintSSRF
	}
	if longCandidateNoSQLOperator(lower) || strings.Contains(lower, "db.") {
		mask |= hintNoSQL
	}
	if strings.Contains(lower, "{{") || strings.Contains(lower, "{%") || strings.Contains(lower, "${") ||
		strings.Contains(lower, "<%") || strings.Contains(lower, "__class__") {
		mask |= hintSSTI
	}
	return mask
}

func longCandidateKeywordPair(text, first, second string, maxGap int) bool {
	start := 0
	for start < len(text) {
		i := strings.Index(text[start:], first)
		if i < 0 {
			return false
		}
		i += start + len(first)
		end := strings.Index(text[i:], second)
		if end >= 0 && end <= maxGap {
			return true
		}
		start = i
	}
	return false
}

// longCandidateSQLStrongHint keeps the long-value SQL gate aligned with a small
// set of high-confidence analyzer shapes that are not plain SELECT/FROM prose:
// ordinal ORDER BY probes, prefixed UNION ALL SELECT continuations, destructive
// statement breaks, CASE/WHEN payloads, and server-version reads. Require an
// injection-like prefix so ordinary SQL documentation examples do not reopen
// the SQL analyzer on document-scale bodies.
func longCandidateSQLStrongHint(lower string) bool {
	if longCandidateSQLPrefixedMarker(lower, "union all select") ||
		longCandidateSQLPrefixedMarker(lower, "union distinct select") ||
		longCandidateSQLPrefixedMarker(lower, "drop table") ||
		longCandidateSQLPrefixedMarker(lower, "delete from") ||
		longCandidateSQLPrefixedOrdinalClause(lower, "order by") ||
		longCandidateSQLPrefixedOrdinalClause(lower, "group by") ||
		longCandidateSQLPrefixedCaseWhen(lower) {
		return true
	}
	for _, probe := range []string{"@@version", "@@datadir", "@@hostname", "@@basedir"} {
		if longCandidateSQLPrefixedSelectProbe(lower, probe) {
			return true
		}
	}
	return false
}

func longCandidateSQLPrefixedMarker(lower, marker string) bool {
	return longCandidateSQLPrefixedPhrase(lower, marker)
}

func longCandidateSQLPrefixedOrdinalClause(lower, clause string) bool {
	start := 0
	for start < len(lower) {
		offset := strings.Index(lower[start:], firstSQLWord(clause))
		if offset < 0 {
			return false
		}
		idx := start + offset
		if end, ok := longCandidateSQLPhraseAt(lower, idx, clause); ok &&
			longCandidateSQLPrefixContext(lower, idx) &&
			longCandidateSQLDigitAfter(lower[end:]) {
			return true
		}
		start = idx + len(firstSQLWord(clause))
	}
	return false
}

func longCandidateSQLPrefixedCaseWhen(lower string) bool {
	start := 0
	const marker = "case when"
	for start < len(lower) {
		offset := strings.Index(lower[start:], firstSQLWord(marker))
		if offset < 0 {
			return false
		}
		idx := start + offset
		if end, ok := longCandidateSQLPhraseAt(lower, idx, marker); ok &&
			longCandidateSQLPrefixContext(lower, idx) &&
			longCandidateSQLOrderedWords(lower[end:], "then", "else", "end") {
			return true
		}
		start = idx + len(firstSQLWord(marker))
	}
	return false
}

func longCandidateSQLPrefixedSelectProbe(lower, probe string) bool {
	return longCandidateSQLPrefixedPhrase(lower, "select "+probe)
}

func longCandidateSQLPrefixedPhrase(lower, phrase string) bool {
	start := 0
	for start < len(lower) {
		offset := strings.Index(lower[start:], firstSQLWord(phrase))
		if offset < 0 {
			return false
		}
		idx := start + offset
		if _, ok := longCandidateSQLPhraseAt(lower, idx, phrase); ok && longCandidateSQLPrefixContext(lower, idx) {
			return true
		}
		start = idx + len(firstSQLWord(phrase))
	}
	return false
}

func longCandidateSQLPrefixContext(lower string, index int) bool {
	if index <= 0 {
		return true
	}
	if strings.HasSuffix(lower[:index], "*/") {
		return true
	}
	for i := index - 1; i >= 0 && index-i <= 8; i-- {
		switch lower[i] {
		case ' ', '\t', '\n', '\r':
			continue
		case '\'', '"', ')', ';',
			'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
			'=', '?', '&', '#', '(':
			return true
		default:
			return false
		}
	}
	// A phrase at the beginning of a line is still an executable candidate;
	// document-context guards run after this pre-filter and decide whether it is
	// quoted prose.
	return index <= 8
}

func longCandidateSQLDigitAfter(lower string) bool {
	for i := 0; i < len(lower) && i < 8; i++ {
		switch lower[i] {
		case ' ', '\t', '\n', '\r':
			continue
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
			return true
		default:
			return false
		}
	}
	return false
}

func firstSQLWord(phrase string) string {
	if index := strings.IndexByte(phrase, ' '); index >= 0 {
		return phrase[:index]
	}
	return phrase
}

func longCandidateSQLPhraseAt(lower string, index int, phrase string) (int, bool) {
	if index < 0 || index >= len(lower) {
		return 0, false
	}
	first := firstSQLWord(phrase)
	if !strings.HasPrefix(lower[index:], first) ||
		(index > 0 && isSQLIdentifierByte(lower[index-1])) {
		return 0, false
	}
	position := index + len(first)
	for offset := len(first); offset < len(phrase); {
		if phrase[offset] != ' ' {
			return 0, false
		}
		for offset < len(phrase) && phrase[offset] == ' ' {
			offset++
		}
		if position >= len(lower) || !isSQLWhitespace(lower[position]) {
			return 0, false
		}
		for position < len(lower) && isSQLWhitespace(lower[position]) {
			position++
		}
		wordStart := offset
		for offset < len(phrase) && phrase[offset] != ' ' {
			offset++
		}
		word := phrase[wordStart:offset]
		if position+len(word) > len(lower) || lower[position:position+len(word)] != word {
			return 0, false
		}
		position += len(word)
	}
	if position < len(lower) && isSQLIdentifierByte(lower[position]) {
		return 0, false
	}
	return position, true
}

func longCandidateSQLOrderedWords(lower string, words ...string) bool {
	offset := 0
	for _, word := range words {
		idx := strings.Index(lower[offset:], word)
		for idx >= 0 {
			idx += offset
			end := idx + len(word)
			if (idx == 0 || !isSQLIdentifierByte(lower[idx-1])) &&
				(end == len(lower) || !isSQLIdentifierByte(lower[end])) {
				break
			}
			next := idx + len(word)
			relative := strings.Index(lower[next:], word)
			if relative < 0 {
				idx = -1
				break
			}
			idx = relative + next
		}
		if idx < 0 {
			return false
		}
		offset = idx + len(word)
	}
	return true
}

func isSQLIdentifierByte(value byte) bool {
	return (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') ||
		(value >= '0' && value <= '9') || value == '_'
}

func longCandidateSQLCommentShape(lower string) bool {
	if !(strings.Contains(lower, "--") || strings.Contains(lower, "/*")) {
		return false
	}
	return strings.Contains(lower, "'") || strings.Contains(lower, `"`) ||
		strings.Contains(lower, "union") || strings.Contains(lower, "select") ||
		strings.Contains(lower, "where") || strings.Contains(lower, "=")
}

func longCandidateShellCommandShape(lower string) bool {
	if !(strings.Contains(lower, ";") || strings.Contains(lower, "&&") ||
		strings.Contains(lower, "||") || strings.Contains(lower, "|")) {
		return false
	}
	// The shared marker helper is allocation-free and accepts arbitrary
	// whitespace between the separator and command. Keep the explicit examples
	// below as a cheap fast path for the most common forms.
	if rceShellMetacharCommandMayMatch(lower) {
		return true
	}
	for _, command := range []string{";id", ";whoami", ";cat ", ";curl ", ";wget ", ";bash", ";sh ", "|sh", "| sh", "|bash", "| bash", "&&id", "&& id", "&&whoami", "&& whoami"} {
		if strings.Contains(lower, command) {
			return true
		}
	}
	return false
}

func longCandidateURLField(name string) bool {
	lower := strings.ToLower(name)
	for _, marker := range []string{"url", "uri", "redirect", "callback", "endpoint", "next", "dest", "target", "fetch"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func longCandidateNoSQLOperator(lower string) bool {
	for _, marker := range []string{"$ne", "$eq", "$gt", "$gte", "$lt", "$lte", "$in", "$nin", "$where", "$regex", "$expr", "$function", "$set", "$unset"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
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

// scanAttackHints does a single marker pass to decide which detector families
// deserve full analysis. The probe combines a raw lowercase view (which keeps
// control bytes such as newlines) with an NFKC lowercase view (which exposes
// compatibility-encoded markers). Prefer false-positive on the hint (over-scan)
// rather than under-scan that would miss attacks.
func scanAttackHints(raw string) int {
	if len(raw) == 0 {
		return 0
	}
	rawLower := strings.ToLower(raw)
	// For printable ASCII, NFKC is a no-op and normalize would repeat the same
	// lowercase pass (and often allocate a second string). Only build the
	// compatibility/controls-stripped view when a byte can actually change it.
	normalizedLower := rawLower
	if hintNeedsNormalizedView(raw) {
		normalizedLower = normalize(raw)
	}
	normalizedControlLower := rawLower
	if strings.ContainsAny(raw, "\r\n") {
		normalizedControlLower = normalizePreserveControls(raw)
	}
	lower := rawLower
	if normalizedLower != rawLower {
		// The NUL separator prevents a marker from being synthesized across the
		// two views while allowing either view to satisfy a necessary hint.
		lower += "\x00" + normalizedLower
	}
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
		strings.Contains(lower, "=\"") || strings.Contains(lower, "exec ") ||
		strings.Contains(lower, "execute ") {
		hints |= hintSQL
	}
	// XPath injection. The location path (a "//" axis with a node test) is the
	// real discriminator, but it cannot be gated on cheaply here because "//" is
	// also the URL scheme separator and a line comment in C-family source. The
	// function vocabulary is the practical gate: analyzeSQL resolves whether a
	// location path is actually present before scoring anything.
	//
	// These payloads are why this matters — none of them carries a single SQL
	// keyword, so without this hint the SQL analyzer never ran on them at all:
	//   ' or count(//*) > 0 or ''='
	//   substring(//users/user[1]/concat(password),3,1)='m'
	if xpathCheapGate(lower) {
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
		strings.Contains(lower, "assert(") || strings.Contains(lower, "getallheaders") ||
		strings.Contains(lower, "apache_request_headers") ||
		strings.Contains(lower, "whoami") || strings.Contains(lower, "${ifs}") ||
		strings.Contains(lower, "$ifs") || strings.Contains(lower, "/dev/tcp") ||
		strings.Contains(lower, "/dev/udp") || strings.Contains(lower, "</dev/") ||
		strings.Contains(lower, "ncat") || strings.Contains(lower, "netcat") ||
		strings.Contains(lower, "$shell") || strings.Contains(lower, "${shell}") ||
		strings.Contains(lower, "ld_preload") || strings.Contains(lower, "child_process") ||
		strings.Contains(lower, "defineclass") || strings.Contains(lower, "assembly.load") ||
		lfiCommandReadSink.MatchString(lower) ||
		rceNewlineCommandChain(rawLower) ||
		rceNewlineCommandChain(normalizedControlLower) ||
		rceNewlineCommandChain(normalizedLower) {
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
		strings.Contains(lower, "phar://") || strings.Contains(lower, "expect://") ||
		// Windows drive-absolute paths. ":\" is the marker rather than ":/"
		// because ":/" is in every URL. Without this, a Windows LFI target
		// scored no hint at all and analyzeLFI was never called.
		strings.Contains(lower, ":\\") ||
		lfiSSIDirective.MatchString(lower) ||
		// Textual hex path bytes are only a pre-filter signal here. The
		// source-aware gate in analyzeLFI decides whether the folded view is
		// strong enough to score, so SQL values such as `0x2e` are not decoded
		// globally or treated as LFI by this hint alone.
		lfiHexPathEscapeHint(raw) {
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
		strings.Contains(lower, `"map"`) || strings.Contains(lower, `"reduce"`) ||
		nosqlShellEscapeMatch(lower) {
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
	// Log4Shell & Shellshock (including ${::-j} / ${lower:} wrappers)
	if strings.Contains(lower, "() { :;};") || hasLog4ShellLookup(lower) {
		hints |= hintLog4Shell
	}
	return hints
}

// hintNeedsNormalizedView reports whether normalize(raw) can differ from a
// lowercase ASCII view. Printable ASCII has no compatibility mappings; C0/DEL
// controls may be stripped and non-ASCII bytes may carry compatibility forms or
// invalid UTF-8 that the normalizer must inspect.
func hintNeedsNormalizedView(raw string) bool {
	for i := 0; i < len(raw); i++ {
		b := raw[i]
		if b >= 0x80 || b < 0x20 || b == 0x7f {
			return true
		}
	}
	return false
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

// sstiMixedOperands is the operand alternation for sstiQuotedArithmeticProbe:
// arithmetic where at least one side is a quoted string. The three orderings are
// spelled out because excluding the number-operator-number case is the whole
// point — that shape stays behind the sstiProbeContext parameter-name gate,
// which is what keeps template documentation out of the results.
const sstiMixedOperands = `[-+]?\d+\s*[*\/+]\s*(?:'[^']{0,24}'|"[^"]{0,24}")|` +
	`(?:'[^']{0,24}'|"[^"]{0,24}")\s*[*\/+]\s*[-+]?\d+|` +
	`(?:'[^']{0,24}'|"[^"]{0,24}")\s*[*\/+]\s*(?:'[^']{0,24}'|"[^"]{0,24}")`

// Keep the quoted-AND-SELECT gate tied to database-oriented functions. A
// generic identifier followed by parentheses is common in ordinary prose
// (for example, "menu(item) > options") and is not enough to establish SQL.
const sqlQuotedAndSelectFunctionNames = `(?:ascii|benchmark|cast|char|character|chr|coalesce|concat(?:_ws)?|convert|count|current_user|database|db_name|elt|exists|extractvalue|floor|group_concat|hex|if|ifnull|json_extract|length|len|load_file|lower|md5|mid|nchar|ord|pg_sleep|rand|regexp_like|schema|sha1|sha2|sleep|substr|substring|upper|updatexml|user|version|xmltype)`

var (
	sqlBooleanTautology     = regexp.MustCompile(`(?i)(?:'|"|\b)\s*(?:or|and)\s+(?:'?\d+'?|[a-z_][a-z0-9_]*|'[^']*')\s*=\s*(?:'?\d+'?|[a-z_][a-z0-9_]*|'[^']*')`)
	sqlEmptyStringTautology = regexp.MustCompile(`(?i)(?:'|")\s*(?:or|and)\s*(?:''|""|'[^']*'|"[^"]*"|['"])\s*=\s*(?:''|""|'[^']*'|"[^"]*"|['"])`)
	sqlQuotedOrCompare      = regexp.MustCompile(`(?i)(?:'|")\s*or\s*(?:''|""|'[^']{0,64}'\s*(?:=|<>|!=)|"[^"]{0,64}"\s*(?:=|<>|!=)|\d+\s*(?:=|<>|!=|<|>)\s*\d+|\d+\b|true\b|false\b|null\b)`)
	sqlQuotedOrCall         = regexp.MustCompile(`(?i)(?:'|")\s*or\s*(?:waitfor\b|(?:sleep|benchmark|pg_sleep|if|exists|ascii|substring|substr|ord|mid|concat|char|chr|updatexml|extractvalue|elt|user|version|database|schema|current_user)\s*\()`)
	sqlQuotedOrSubq         = regexp.MustCompile(`(?i)(?:'|")\s*or\s*\(\s*(?:select|exists|if\s*\(|case\s+when|not\s+(?:\d|true|null|\()|\d+\s*=|'[^']*'\s*=)`)
	// A quote breakout followed by AND SELECT is a common boolean/error-based
	// subquery shape. Keep this separate from the broad SELECT/FROM grammar:
	// the latter is intentionally non-blockable on its own because documentation
	// quotes it constantly. The strong-context helper below requires a predicate
	// comparison, FROM/WHERE clause, or SQL comment truncation before scoring.
	sqlQuotedAndSelectProbe     = regexp.MustCompile(`(?i)(?:'|")\s*and\s*\(?\s*select\b`)
	sqlQuotedAndSelectFunction  = regexp.MustCompile(`(?is)^\s*` + sqlQuotedAndSelectFunctionNames + `\s*\([^;\r\n]{0,160}\)\s*\)*\s*(?:=|<>|!=|>=|<=|>|<|like\b|in\b)`)
	sqlQuotedAndSelectLead      = regexp.MustCompile(`(?is)^\s*(?:[-+]?(?:\d+(?:\.\d*)?|\.\d+)|\*|@@?[a-z_][a-z0-9_$]*|null\b|true\b|false\b|['\"][^'\"\r\n]{0,160}['\"]|\(\s*select\b|(?:distinct|all)\s+(?:[a-z_][a-z0-9_$]*|\*)\s+|` + sqlQuotedAndSelectFunctionNames + `\s*\(|[a-z_][a-z0-9_$]*\s+(?:from|where|limit|group|order|having)\b)`)
	sqlQuotedAndSelectFromWhere = regexp.MustCompile(`(?is)\bfrom\b.{0,160}\bwhere\b`)
	// A FROM/WHERE tail must carry a numeric or quoted comparison. This avoids
	// treating natural language such as "select 'a' from the menu where color=red"
	// as an injected subquery while retaining boolean/error probes.
	sqlQuotedAndSelectWherePredicate = regexp.MustCompile(`(?is)\bwhere\b.{0,120}(?:\d+\s*(?:=|<>|!=|>=|<=|>|<|like\b|in\b)\s*(?:\d+|['\"][^'\"\r\n]{0,80}['\"]?)|['\"][^'\"\r\n]{0,80}['\"]\s*(?:=|<>|!=|>=|<=|>|<|like\b|in\b)\s*['\"][^'\"\r\n]{0,80}['\"]?|[a-z_][a-z0-9_$]*\s*(?:=|<>|!=|>=|<=|>|<|like\b|in\b)\s*(?:\d+|['\"][^'\"\r\n]{0,80}['\"]?))`)
	// Oracle/PostgreSQL-style string concatenation probes use `'||(SELECT ...`.
	// Requiring a numeric equality inside the subquery's WHERE clause keeps this
	// distinct from prose that merely quotes a SELECT example.
	sqlQuotedConcatSelectPredicate = regexp.MustCompile(`(?is)(?:^|[A-Za-z0-9_$)\]=+\-])(?:'|\")\s*\|\|\s*\(\s*select\b.{0,240}\bwhere\b.{0,120}\b\d+\s*=\s*\d+\b`)
	sqlQuotedOrIdent               = regexp.MustCompile(`(?i)(?:'|")\s*or\s+[a-z_][a-z0-9_]*\s*(?:=|<>|!=|--|/\*|#(?:\s|$)|like\s*(?:'|\"|0x))`)
	sqlQuotedOrNot                 = regexp.MustCompile(`(?i)(?:'|")\s*or\s+not\s+(?:\d+\s*=|true\b|false\b|null\b|\()`)
	sqlTimeFunction                = regexp.MustCompile(`(?i)(?:\b(?:sleep|benchmark|pg_sleep)\s*\(|\bwaitfor\s+delay\b)`)
	sqlDialectTimeFunction         = regexp.MustCompile(`(?i)\bdbms_(?:lock|session)\.sleep\s*\(|\bdbms_pipe\.receive_message\s*\(`)
	sqlComment                     = regexp.MustCompile(`(?i)(?:--|#|/\*)`)
	sqlNCSemanticWordRE            = regexp.MustCompile(`(?i)\b(?:select|union|from|where|having|order|group|insert|update|delete|drop|exec(?:ute)?|case|when|sleep|benchmark|waitfor|into|outfile|load_file|information_schema|pg_sleep|procedure|analyse|rlike|regexp)\b`)
	sqlDangerousFunc               = regexp.MustCompile(`(?i)\b(?:xp_cmdshell|sp_oa(?:create|method)|openrowset|opendatasource|load_file|into\s+outfile|copy\s+.+\s+to\s+program)\b`)
	sqlErrorFunction               = regexp.MustCompile(`(?i)\b(?:extractvalue|updatexml|xmltype|ctxsys\.drithsx\.sn|utl_inaddr\.get_host_name|utl_http\.request)\s*\(`)
	sqlStringFunction              = regexp.MustCompile(`(?i)\b(?:char|chr|concat|concat_ws|nchar|ascii|substring|substr)\s*\(`)
	sqlComparison                  = regexp.MustCompile(`(?i)(?:=|<>|!=|<=>|\blike\b|\bin\b)`)
	sqlOrderByInference            = regexp.MustCompile(`(?i)\b(?:order|group)\s+by\s+\d+\s*(?:--|#|/\*)`)
	sqlHavingInference             = regexp.MustCompile(`(?i)\bhaving\s+(?:\d+|'[^']*'|"[^"]*")\s*=\s*(?:\d+|'[^']*'|"[^"]*")\s*(?:--|#|/\*)`)
	sqlRegexProbe                  = regexp.MustCompile(`(?i)\b(?:rlike|regexp|like)\s+(?:binary\s+)?(?:0x[0-9a-f]+|'[^']*'|"[^"]*")`)
	sqlProcedureAnalyse            = regexp.MustCompile(`(?i)\bprocedure\s+analyse\s*\(`)
	// The @@ variables begin with a non-word character, so a \b immediately
	// before @@ can never match (both sides are non-word). Keep the ordinary
	// catalog/user names word-bounded, but give server-variable probes their own
	// branch so `SELECT @@version` is visible to the semantic analyzer.
	sqlMetadataObject       = regexp.MustCompile(`(?i)(?:\b(?:information_schema|pg_catalog|pg_shadow|pg_group|sysibm|syscat|sysobjects|syscolumns|sysusers|master\.\.|sys\.|sqlite_master|mysql\.user|current\s+user|session_user|system_user)\b|\brdb\$(?:database|fields|types|collations|functions)\b|@@(?:version|datadir|hostname|basedir)\b)`)
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
	// The trailing alternation is the overlong-UTF-8 family. "%c0%af" is a
	// two-byte encoding of "/" and "%c0%ae" of "."; "%e0%80%af"/"%e0%80%ae" are
	// the three-byte equivalents. A server that decodes percent escapes and
	// then normalises UTF-8 folds them into "../", which is the whole point.
	// Only "%c0%af" and its double-encoded form were covered, so
	// "..%e0%80%af..%e0%80%afetc%e0%80%afpasswd" walked straight through.
	lfiEncodedTraversal            = regexp.MustCompile(`(?i)(?:%25)*(?:%2e){2,}(?:%25)*(?:%2f|%5c)|(?:\.\.(?:%25)*(?:%2f|%5c))|(?:%25)*%2e(?:%25)*%2e[/\\]|%c0%af|%c0%ae|%c1%9c|%e0%80%af|%e0%80%ae|%25c0%25af|%25c0%25ae|%25e0%2580%25af|\.{4,}[/\\]+`)
	lfiRemoteExecutableExtensionRE = regexp.MustCompile(`(?i)\.(?:php\d?|phtml|phar|jsp|jspx|asp|aspx|cgi|pl|shtml|inc)(?:[/\\?#&=\s]|$)`)

	// lfiWindowsSystemPath covers the half of the file-inclusion surface the
	// engine never modelled. Every sensitive target above is Unix-shaped —
	// /etc/passwd, /proc/self/environ, .ssh/id_rsa — so a Windows host's
	// equivalents produced no signal at all and the LFI analyzer was never even
	// invoked: "C:\Windows\System32\drivers\etc\hosts" scored zero hints.
	//
	// The drive-letter prefix is mandatory (a bare "Windows\System32" in prose is
	// ordinary text), and it is paired with either a Windows system directory or
	// a credential/configuration filename, because "C:\Users\bob\notes.txt" is a
	// file path but not an attack.
	//
	// "Program Files" is deliberately absent. It is where every desktop app is
	// installed, so it appears constantly in ordinary prose — release notes,
	// install instructions, crash reports — and matching it turned sentences
	// like "copies files to C:\Program Files\App and starts the service" into
	// high-confidence LFI. ProgramData is kept: it is the machine-wide
	// configuration root, which is exactly what an attacker wants to read.
	lfiWindowsSystemPath = regexp.MustCompile(`(?i)\b[a-z]:[/\\]{1,2}[^\s"']{0,160}?(?:windows|winnt|inetpub|programdata|system32|syswow64|\brepair\b|web\.config|unattend\.xml|secrets?\.(?:ini|json|ya?ml)|\.htpasswd|id_rsa|\bsam\b|(?:settings|config|database|credentials?)\.(?:xml|json|ini|ya?ml))`)

	// lfiWindowsPathTargets are the words lfiWindowsSystemPath needs to find
	// after the drive prefix. They double as a cheap pre-filter: the pattern
	// carries a bounded non-greedy run and fifteen alternatives and costs
	// ~2.7µs per call, which is far too much to spend on every candidate.
	// Requiring one of these substrings first is a strict superset of what the
	// pattern can match.
	lfiWindowsPathTargets = []string{
		"windows", "winnt", "inetpub", "programdata", "system32", "syswow64",
		"repair", "web.config", "unattend", "secrets", ".htpasswd", "id_rsa",
		"config.", "settings.", "database.", "credentials.", "sam",
	}
	// lfiSSIDirective is a Server Side Includes directive. It is file inclusion
	// by another name: the server reads a file, or runs a command, and pastes the
	// result into the page. The engine had no notion of it at all, so the 26
	// verified LFI misses in this family were only ever caught by accident, when
	// the path inside the directive happened to satisfy an unrelated pattern.
	//
	// The leading "<!" tolerates the space-split evasion "<!- -#include", where
	// the two dashes are separated so a naive "<!--#" literal does not match.
	lfiSSIDirective = regexp.MustCompile(`(?i)<!\s*-{1,2}\s*-?\s*#\s*(?:include|exec|echo|fsize|flastmod|config|printenv|set)\b`)

	lfiDotEnvTarget    = regexp.MustCompile(`(?i)(?:^|[/\\])\.env(?:$|[?#.]|%00|%23)`)
	lfiSensitiveTarget = regexp.MustCompile(`(?i)(?:^|[/\\])(?:etc/(?:passwd|shadow|group|hosts|hostname|fstab|sudoers|crontab|issue|motd|nginx/nginx\.conf|apache2/apache2\.conf|redis/redis\.conf|mysql/my\.cnf|php/php\.ini|ssh/sshd_config)|proc/(?:self/(?:environ|cmdline|maps|fd/\d+)|version|cpuinfo)|root/\.bash_history|home/[^/\\]+/\.ssh/(?:id_rsa|id_dsa|authorized_keys)|var/log/(?:syslog|auth\.log|nginx/access\.log|nginx/error\.log|apache2/access\.log|apache2/error\.log|httpd-access\.log)|winnt/system32/cmd\.exe|windows/(?:win\.ini|system32/drivers/etc/hosts)|boot\.ini|web-inf/web\.xml|meta-inf/manifest\.mf|\.htaccess|_config\.php|config\.php|config/(?:database|parameters|settings)\.(?:php|ya?ml|json)|wp-config\.php|dump\.sql|database\.sql|id_rsa)(?:$|[?#\x00.]|%00|%23)`)
	// "set" and "unset" were missing from the operator vocabulary. They are
	// ordinary MongoDB update operators, and they are the ones an injection uses
	// when the goal is to change a field — "{$set:{isAdmin:true}}" — rather than
	// to read one. Without them the payload below scored no NoSQL signal at all
	// and was left to the RCE analyzer, which correctly declined it.
	nosqlOperatorToken = regexp.MustCompile(`(?i)(?:^|[.\[\]{"'\s:=,&?])\$(?:jsonschema|elemmatch|function|where|regex|exists|gte|lte|nin|nor|not|expr|eval|all|mod|type|size|ne|eq|gt|lt|in|or|and|set|unset|rename|inc|push|pull|addtoset)(?:$|[.\[\]}\]"'\s:=,&?])`)

	// nosqlShellEscape matches a breakout out of the host expression and into
	// the MongoDB shell or server-side JavaScript context, where the payload
	// calls a database method directly:
	//
	//	theme=dark'; db.users.update({username:'admin'},{$set:{isAdmin:true}}); //
	//	username=alex' } || db.users.find({isAdmin:true}) --
	//
	// The distinguishing feature is that no query operator is required. The
	// attacker is not injecting into a filter document; they are terminating the
	// surrounding expression and writing their own statement, which is why the
	// operator-based gate — the only one the NoSQL analyzer had — never fired.
	nosqlShellEscape = regexp.MustCompile(`(?i)db\s*\.\s*[a-z_]\w*\s*\.\s*(?:find|findone|update|updatemany|updateone|insert|insertmany|insertone|remove|deleteone|deletemany|aggregate|count|distinct|drop|createcollection|createindex|eval|runcommand|mapreduce|bulkwrite)\s*\(`)

	// nosqlShellEscapeGate is the substring pre-filter for nosqlShellEscape.
	//
	// The full pattern costs ~2µs per call and scanAttackHints runs on every
	// input point of every request, so it cannot be called unguarded: that alone
	// was a 20x pipeline-latency regression. "db." must be present for any of
	// the method alternatives to have a receiver, so checking for it first is a
	// strict superset and costs almost nothing.
	nosqlShellEscapeGate   = "db."
	nosqlJSBehavior        = regexp.MustCompile(`(?i)(?:this\.[a-z_][a-z0-9_]*|function\s*\(|return\s+|sleep\s*\(|constructor\s*\[|process\.|emit\s*\()`)
	nosqlMapReducePayload  = regexp.MustCompile(`(?i)(?:"map"\s*:\s*"(?:function\s*\(|function\s+[a-z])|"reduce"\s*:\s*"(?:function\s*\(|function\s+[a-z])|"mapreduce"\s*:)`)
	nosqlWideRegex         = regexp.MustCompile(`(?i)(?:\.\*|\^\.\*\$|\[[^\]]*\])`)
	nosqlOperatorNames     = []string{"$jsonschema", "$elemmatch", "$function", "$where", "$regex", "$exists", "$gte", "$lte", "$nin", "$nor", "$not", "$expr", "$eval", "$all", "$mod", "$type", "$size", "$ne", "$eq", "$gt", "$lt", "$in", "$or", "$and", "$set", "$unset", "$rename"}
	sstiTemplateExpression = regexp.MustCompile(`(?is)(?:\{\{.*?\}\}|\{%.*?%\}|\$\{.*?\}|#\{.*?\}|%\{.*?\}|<%=?\s*.*?%>)`)
	sstiArithmeticProbe    = regexp.MustCompile(`(?is)(?:\{\{\s*[-+]?\d+\s*[*+\-/]\s*[-+]?\d+\s*\}\}|\$\{\s*[-+]?\d+\s*[*+\-/]\s*[-+]?\d+\s*\}|<%=?\s*[-+]?\d+\s*[*+\-/]\s*[-+]?\d+\s*%>)`)

	// sstiQuotedArithmeticProbe is "{{ 7*'7' }}" and its siblings: arithmetic
	// between a number and a quoted string.
	//
	// This is the canonical Jinja/Twig evaluation probe, and it is not a
	// calculation anyone wants an answer to — it is a question. "7*'7' asks a
	// template engine to multiply an integer by a string; only an engine that
	// really evaluates the expression answers it, with "7777777". Every one of
	// the 36 verified SSTI misses was this exact probe, and the bare-integer
	// pattern above could not see it because the second operand is quoted.
	//
	// It deliberately does not need the parameter-name gate that
	// sstiProbeContext imposes on the integer form. That gate exists because
	// "7*7" is a plausible fragment of ordinary text; "7*'7'" is not, and the
	// corpus delivered it through parameter names the gate does not trust
	// ("greeting", "note", "preview_text").
	// At least one operand must be quoted. That requirement is the entire point
	// of having a second pattern: "7 * 7" is a plausible fragment of ordinary
	// text and stays behind the sstiProbeContext gate, while "7 * '7'" is not.
	// An earlier version allowed two plain numbers here and immediately
	// reproduced the curated corpus's documented benign case —
	// "Template documentation may show {{ 7 * 7 }} as a harmless arithmetic
	// example" — as a detection.
	sstiQuotedArithmeticProbe = regexp.MustCompile(`(?is)(?:\{\{\s*(?:` + sstiMixedOperands + `)\s*\}\}|\$\{\s*(?:` + sstiMixedOperands + `)\s*\}|<%=?\s*(?:` + sstiMixedOperands + `)\s*%>)`)

	// sstiWholeBodyExpression matches a value that is nothing but a single
	// template expression.
	//
	// It decides whether sstiProbeContext applies. That gate exists because
	// "7*7" can be a fragment of ordinary prose — but it can only be applied
	// when there IS a field name to judge. Payloads whose request line cannot be
	// expressed as a URL arrive as the entire body, under the field name "body",
	// which tells us nothing either way; gating on it silently dropped "{{7*7}}"
	// and "${7*7}".
	sstiWholeBodyExpression = regexp.MustCompile(`(?is)^(?:\{\{[^{}]*\}\}|\{%[^{}]*%\}|\$\{[^{}]*\}|#\{[^{}]*\}|%\{[^{}]*\}|<%=?[^%]*%>)$`)
	// Freemarker's exposed beans helper is a high-confidence execution sink,
	// but the exact expression is also commonly quoted in security tutorials.
	// Keep it separate so the analyzer can apply a local documentation guard
	// without weakening the other SSTI dangerous-behaviour signatures.
	sstiFreemarkerBeansRuntimeExec = regexp.MustCompile(`(?i)\bbeans?\s*\.\s*get\s*\([^)]*\)\s*\.\s*exec\s*\(`)
	sstiDangerousBehavior          = regexp.MustCompile(`(?i)(?:__class__|__mro__|__subclasses__|__globals__|__builtins__|#(?:context|_memberaccess|request|session)|@[a-z0-9_.]+@|popen\s*\(|os\s*\.\s*(?:system|popen)|__import__\s*\(|\bimport\s*\(|getruntime\s*\(\s*\)\s*\.\s*exec|runtime\.getruntime|java\.lang\.runtime|processbuilder|child_process|execsync|system\s*\(|passthru\s*\(|shell_exec\s*\(|freemarker\.template\.utility\.(?:execute|objectconstructor)|\?new\s*\(|registerundefinedfiltercallback|_self\.env|getfilter\s*\(|constructor\s*\.\s*constructor|t\s*\(\s*java\.lang\.runtime|objectspace\.each_object|classloader\.loadclass|loadclass\s*\(|request\.getclass|application\.getclass|session\.getclass|#set\s*\(\s*\$|\{php\}|smarty\.version|mako\.runtime|velocity\.context|pebble\.extension)`)
	rceNetWebClientSideFx          = regexp.MustCompile(`(?i)(?:new-object\s+system\.net\.(?:webclient|sockets\.tcpclient)|system\.net\.webclient|download(?:file|string)\s*\(|iwr\s+|invoke-webrequest\b)`)
	rcePowerShellReverseShell      = regexp.MustCompile(`(?i)(?:tcpclient\s*\(|getstream\s*\(|net\.sockets\.tcpclient|while\s*\(\s*\$i\s*=\s*\$s\.read)`)
	sqlBlockComment                = regexp.MustCompile(`(?is)/\*.*?\*/`)
	sqlLineComment                 = regexp.MustCompile(`(?m)--[^\r\n]*`)
	rceShellControl                = regexp.MustCompile(`(?:;|&&|\|\||\||\$\(|` + "`" + `)`)
	rcePureArithmeticExpansion     = regexp.MustCompile(`\$\(\(\s*[-+]?\d(?:\d|[ \t\r\n+*/%-])*\s*\)\)`)
	rceWhitespaceEvasion           = regexp.MustCompile(`(?i)\$\{?ifs\}?`)
	rcePowerShellSideFx            = regexp.MustCompile(`(?i)(?:\b(?:powershell|pwsh)(?:\.exe)?\b[^\r\n]{0,200}\b(?:downloadstring|downloadfile|frombase64string|invoke-expression|iex|new-object|net\.webclient)\b)|(?:new-object\s+system\.net\.(?:webclient|sockets\.tcpclient)|(?:download(?:file|string)|invoke-expression|iex)\s*\()`)
	rceEncodedPowerShell           = regexp.MustCompile(`(?i)\b(?:powershell|pwsh)(?:\.exe)?\b[^\r\n]{0,160}\s-(?:e|enc|encodedcommand)\s+[a-z0-9+/=]{12,}`)
	rceInterpreterInline           = regexp.MustCompile(`(?i)(?:^|[=&\s;|])(?:bash|sh|zsh|dash|ksh)\s+-c\s+['"]?(?:id|whoami|cat|curl|wget|uname|nc|ncat|python3?|perl|php|ruby|node|powershell|pwsh)\b|(?:^|[=&\s;|])cmd(?:\.exe)?\s*/c\s+(?:whoami|id|dir|type|powershell|certutil|curl|wget|ping|nslookup)\b|(?:python3?|perl|php|ruby|node|lua)\s+(?:-c|-e|-r)\b`)
	rceDownloadExecChain           = regexp.MustCompile(`(?i)(?:curl|wget|fetch|busybox\s+wget)\s+[^\r\n|;&]+(?:\||;|&&)\s*(?:sh|bash|zsh|dash|ksh|python3?|php|perl|ruby|node)\b`)
	rceReverseShellPrimitive       = regexp.MustCompile(`(?i)(?:/dev/tcp/|/dev/udp/|nc\s+-e|ncat\s+-e|bash\s+-i|sh\s*<\s*/dev/tcp|socket\.socket\s*\(|child_process|require\s*\(\s*['"]child_process['"]\s*\))`)
	rceTemplateExecutionPrimitive  = regexp.MustCompile(`(?i)(?:registerundefinedfiltercallback\s*\(\s*['"]exec|filter\s*\(\s*['"]system|system\s*\(|exec\s*\(|popen\s*\(|passthru\s*\(|shell_exec\s*\()`)
	// Generic “unknown exploit” shapes: loader hooks / polyglot runtime without CVE names.
	rceLoaderPrimitive = regexp.MustCompile(`(?i)(?:ld_preload\s*=|dyld_insert_libraries\s*=|process\.dlopen\s*\(|ctypes\.cdll|java\.lang\.classloader|defineclass\s*\(|unsafe\.defineanonymousclass|reflection\.emit|assembly\.load\s*\()`)
	lfiFileReadSink    = regexp.MustCompile(`(?i)(?:file\.read\s*\(|get_user_file\s*\(|readfile\s*\(|file_get_contents\s*\(|open\s*\()[^)]*(?:/etc/|c:[/\\]|boot\.ini|\.ssh/|/proc/|/var/log/)`)
	lfiCommandReadSink = regexp.MustCompile(`(?i)\b(?:cat|type|more|less|head|tail)\s+(?:/etc/|c:[/\\]|boot\.ini|\.ssh/|/proc/|/var/log/)`)
)

var (
	// sqlCountStarFrom anchors the heavy time-based blind query: an aggregate
	// whose FROM names a comma-separated list of sources.
	sqlCountStarFrom = regexp.MustCompile(`(?i)count\s*\(\s*\*\s*\)\s+from\s+`)
	// sqlRowExplosion is the Postgres equivalent: the series length is chosen so
	// the query takes seconds, and that duration is the observable channel.
	sqlRowExplosion = regexp.MustCompile(`(?i)generate_series\s*\(\s*1\s*,\s*[1-9]\d{3,}`)
)

// sqlCommentTruncationShape returns true if SQL comment markers appear in actual
// injection context (after quote, paren, equals, digit) rather than in prose,
// C code comments, Markdown, or email addresses (user@example.com, list--item).

// sqlHeavyQueryPrimitive reports the deliberate-resource-exhaustion family of
// time-based blind SQL injection.
//
// 148 of the 172 verified SQL misses were this one shape, and it carries no
// sleep(), no benchmark() and no waitfor — the attacker is not asking the
// database to wait, they are asking it to do pointless work and measuring how
// long it takes:
//
//	select count(*) from all_users t1,all_users t2,all_users t3,all_users t4
//	select count(*) from rdb$fields as t1,rdb$types as t2 where 'x'='x
//	select count(*) from generate_series(1,5000000) and (('wmoo' like 'wmoo
//
// The first two are an aggregate over a comma-separated table list, which is a
// Cartesian product: N row sets multiplied together. Nobody writes that to
// count anything. The third is a Postgres series whose only purpose is its
// length. The existing analyzer saw "SELECT FROM" and stopped there, and a lone
// SELECT/FROM is deliberately not blockable on its own because documentation
// quotes it constantly — so these scored no semantic reason and were dropped.
func sqlHeavyQueryPrimitive(text string) bool {
	if sqlRowExplosion.MatchString(text) {
		return true
	}
	match := sqlCountStarFrom.FindStringIndex(text)
	if match == nil {
		return false
	}
	// Count commas at paren depth zero after the FROM. Depth matters: the comma
	// inside generate_series(1,5000000) is an argument separator, not a table
	// separator, and counting it would make every series call look like a join.
	depth := 0
	for i := match[1]; i < len(text); i++ {
		switch text[i] {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				return true
			}
		case ';', '\n', '\r':
			return false // the statement, or the line, ended
		}
	}
	return false
}

func sqlCommentTruncationShape(text string) bool {
	lower := strings.ToLower(text)
	// Check for -- (must not be in email or Markdown list context)
	if strings.Contains(text, "--") {
		idx := strings.Index(text, "--")
		if idx > 0 {
			// Skip whitespace between the payload and its comment marker.
			// "pass' AnD SeLeCt CoUnT(*) FrOm users > 5 -- " is a working
			// injection, but the marker sits one space past the expression, and
			// reading text[idx-1] literally saw a space instead of the digit —
			// so the whole family of space-separated comment truncations was
			// scored as having no injection context.
			pos := idx
			for pos > 0 && (text[pos-1] == ' ' || text[pos-1] == '\t') {
				pos--
			}
			before := text[pos-1]
			// Injection context: quote, paren, digit, equals precedes --
			if before == '\'' || before == '"' || before == ')' || before == '=' ||
				(before >= '0' && before <= '9') {
				return true
			}
			// Check for SQL keyword before --: SELECT--, WHERE--. The window is
			// 32 bytes rather than 6 because the marker is usually separated
			// from the keyword by the rest of the predicate ("users > 5 -- ").
			windowStart := pos - 32
			if windowStart < 0 {
				windowStart = 0
			}
			prevWord := strings.ToLower(text[windowStart:pos])
			if strings.Contains(prevWord, "select") || strings.Contains(prevWord, "where") ||
				strings.Contains(prevWord, "union") || strings.Contains(prevWord, "order") ||
				strings.Contains(prevWord, "count") || strings.Contains(prevWord, "from") {
				return true
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

func quotedOrPredicateInjection(text string) bool {
	return sqlQuotedOrCompare.MatchString(text) ||
		sqlQuotedOrCall.MatchString(text) ||
		sqlQuotedOrSubq.MatchString(text) ||
		sqlQuotedOrIdent.MatchString(text) ||
		sqlQuotedOrNot.MatchString(text)
}

// sqlQuotedAndSelectInjectionShape recognizes only an injection-shaped
// quote-break followed by AND SELECT. A bare "' and select" phrase is not
// sufficient: the SELECT must carry a predicate/comparison, a FROM/WHERE
// clause, or a comment terminator. This keeps ordinary prose and SQL examples
// behind the existing document/markdown guards while covering scalar and
// aggregate subquery probes.
func sqlQuotedAndSelectInjectionShape(text string) bool {
	for start := 0; start < len(text); {
		loc := sqlQuotedAndSelectProbe.FindStringIndex(text[start:])
		if loc == nil {
			return false
		}
		begin := start + loc[0]
		tailStart := start + loc[1]
		tailEnd := tailStart + 240
		if tailEnd > len(text) {
			tailEnd = len(text)
		}
		tail := text[tailStart:tailEnd]
		// A known database-function result followed by a comparison is strong SQL
		// evidence. Requiring the operand at the beginning of the SELECT tail
		// prevents ordinary prose such as "select (a menu) > options" from
		// satisfying the old, position-free `) >` check.
		if sqlQuotedAndSelectFunction.MatchString(tail) {
			return true
		}
		// Aggregate and existence probes commonly use a FROM/WHERE clause. The
		// lead check excludes narrative phrases whose text merely contains those
		// words later in the sentence.
		if sqlQuotedAndSelectLead.MatchString(tail) &&
			sqlQuotedAndSelectFromWhere.MatchString(tail) &&
			sqlQuotedAndSelectWherePredicate.MatchString(tail) {
			return true
		}
		// SQL line/block comments are only meaningful here when the SELECT tail
		// itself starts with a SQL-shaped operand and the existing positional
		// comment guard confirms a truncation context. A bare prose "--" is not
		// enough.
		if sqlQuotedAndSelectLead.MatchString(tail) && sqlCommentTruncationShape(tail) {
			return true
		}
		start = begin + 1
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
	if quotedOrPredicateInjection(text) {
		reasons["syntax: quoted OR predicate injection"] = true
	}
	if sqlQuotedAndSelectInjectionShape(text) {
		reasons["syntax: quoted AND SELECT subquery predicate"] = true
	}
	if sqlQuotedConcatSelectPredicate.MatchString(text) {
		reasons["syntax: quoted concatenation SELECT predicate"] = true
	}
	if sqlTimeFunction.MatchString(text) {
		reasons["semantics: time-based database side effect"] = true
	}
	// Time-based blind injection does not have to ask the database to sleep. It
	// can simply ask it to work, and measure the response.
	if sqlHeavyQueryPrimitive(text) {
		reasons["semantics: aggregate over a cross-joined or generated row set makes response time observable"] = true
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
	if !sqlReasonsBlockable(reasons) {
		if fp, detected := engine.SQLLibinjectionFingerprint(candidate.text); detected &&
			containsReviewedSQLFingerprint(fp, candidate.text) &&
			!sqlNaturalLanguageFingerprintOnly(candidate, fp) {
			reasons["syntax: SQL token fingerprint matched"] = true
		}
	}
	// XPath injection: same breakout, different grammar. Filed under "sqli" by
	// every corpus we measure against and by the industry generally, so it is
	// attributed to the SQL category rather than a category of its own — adding
	// one would fragment the sqli number for no operational gain.
	if step, isXPath := xpathInjectionShape(text); isXPath {
		reasons["syntax: XPath location path expression ("+step+")"] = true
		reasons["semantics: XPath predicate can traverse document nodes outside the intended query scope"] = true
		if xpathFunctionCall.MatchString(text) && (strings.Contains(text, "count(") || strings.Contains(text, "string-length(")) {
			reasons["semantics: XPath node-count or length probe can infer document contents"] = true
		}
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

	// Compute the attack-evidence window once; both securityDocumentContext and
	// technicalDocumentationContext run on this window so that a prose prefix
	// + filler padding separated from the payload cannot suppress detection
	// via either guard.
	sqlWin := evidenceWindow(doc, []string{
		"xp_cmdshell", "exec master", "union select", "union all select",
		"into outfile", "load_file", "information_schema", "sleep(",
		"benchmark(", "waitfor delay", "pg_sleep", "1=1", "1=0",
		"' or", "\" or", "or 1=", "and 1=",
		"'||", "|| (select", "receive_message", "rdb$database",
	})

	// Security document context: vulnerability reports, CTF writeups, training
	// material, academic papers, Chinese technical articles, and source files all
	// quote SQL grammar verbatim without composing a query.
	if securityDocumentContextWindowed(doc, sqlWin) {
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

	// Technical documentation keyword guard: AND-gate — full document must satisfy techdoc
	// (captures document-level markers like 安全/分析 that appear far from the indicator)
	// AND the local evidence window must also satisfy techdoc (ensures the attack example
	// is surrounded by explanatory prose, not oracle filler padding).
	// Oracle bypass: filler region near payload has no techdoc markers → window returns false.
	// Legitimate doc: explanatory text around examples contains 示例/攻击/vulnerability/etc.
	if technicalDocumentationContext(doc) && technicalDocumentationEvidenceContext(sqlWin) {
		confidence *= 0.7
		if confidence < 0.7 {
			return Hit{}, false
		}
	}

	return hit(candidate, "sqli", severity, confidence, reasons), true
}

// technicalDocumentationEvidenceContext is the local half of the SQL
// documentation guard. The general documentation classifier deliberately
// ignores short strings, but an evidence window at the beginning or end of a
// document can be shorter than that threshold. In that case require both an
// explanatory marker and an SQL/documentation term; a lone keyword such as
// "select" still does not suppress a real payload.
func technicalDocumentationEvidenceContext(text string) bool {
	if len(text) >= 200 {
		return technicalDocumentationContext(text)
	}
	if len(text) < 80 {
		return false
	}
	lower := strings.ToLower(text)
	markers := 0
	for _, marker := range []string{"example", "documentation", "guide", "article", "reference", "tutorial", "without executing", "for defenders"} {
		if strings.Contains(lower, marker) {
			markers++
		}
	}
	if markers == 0 {
		return false
	}
	return strings.Contains(lower, "sql") || strings.Contains(lower, "query") ||
		strings.Contains(lower, "syntax") || strings.Contains(lower, "statement")
}

var reviewedSQLFingerprintWindows = [...]string{"kc", "nc", "Uwk", "Bn", "fws", "Ew", "Ef", "o("}

var sqlNaturalLanguageFields = [...]string{
	"comment", "description", "feedback", "message", "note", "query", "question", "search", "summary", "text", "title",
}

var sqlNaturalLanguageMarkers = [...]string{
	"a", "an", "the", "this", "that", "these", "those", "our", "your", "their", "we", "i", "you", "they",
	"to", "of", "for", "with", "without", "from", "into", "is", "are", "was", "were", "can", "could", "would", "should",
}

// sqlNaturalLanguageFingerprintOnly rejects one narrow low-context class: a
// prose value in a field explicitly meant for human language whose only SQL
// evidence is the libinjection Uwk token window. Strong grammar is evaluated
// before this helper and never reaches it, so quote/comment breakouts,
// tautologies, SELECT/FROM, time functions, metadata access, and obfuscated
// fragments remain blockable. Requiring sentence structure plus the absence of
// SQL punctuation also keeps bare UNION SELECT payloads and compact blind
// probes out of the suppression path.
func sqlNaturalLanguageFingerprintOnly(candidate semanticCandidate, fingerprint string) bool {
	if !strings.Contains(fingerprint, "Uwk") || !sqlNaturalLanguageField(candidate.input.Source, candidate.input.Name) {
		return false
	}
	// Do not suppress a mixed fingerprint. A prose-looking value may still carry
	// an independent comment, EXEC, or operator-subquery window; those stronger
	// signals must retain their normal blocking path.
	for _, window := range reviewedSQLFingerprintWindows {
		if window != "Uwk" && strings.Contains(fingerprint, window) {
			return false
		}
	}
	text := strings.TrimSpace(candidate.text)
	if len(text) < 32 || len(text) > 512 {
		return false
	}
	if strings.ContainsAny(text, "'\";=#()") || strings.Contains(text, "--") || strings.Contains(text, "/*") {
		return false
	}
	lower := strings.ToLower(text)
	words := tokens(text)
	if len(words) < 7 || countWordMarkers(lower, sqlNaturalLanguageMarkers[:]) < 2 {
		return false
	}
	return strings.HasSuffix(text, ".") || strings.HasSuffix(text, "?") || strings.HasSuffix(text, "!")
}

func sqlNaturalLanguageField(source, name string) bool {
	switch strings.ToLower(source) {
	case "query", "form", "json", "multipart", "body.form", "body.json", "body.multipart":
	default:
		return false
	}
	lower := strings.ToLower(strings.TrimSpace(name))
	for _, field := range sqlNaturalLanguageFields {
		if lower == field || strings.HasSuffix(lower, "."+field) || strings.HasSuffix(lower, "_"+field) {
			return true
		}
	}
	return false
}

func containsReviewedSQLFingerprint(fingerprint, raw string) bool {
	for _, window := range reviewedSQLFingerprintWindows {
		if !strings.Contains(fingerprint, window) {
			continue
		}
		if window == "nc" && strings.Contains(raw, "--") && !hasSQLNCSemanticContext(raw) {
			continue
		}
		if window == "o(" && !hasSQLOperatorSubqueryContext(raw) {
			continue
		}
		if (window == "Ew" || window == "Ef") && !hasSQLExecFingerprintContext(raw) {
			continue
		}
		return true
	}
	return false
}

func hasSQLNCTerminatorContext(raw string) bool {
	for offset := 0; offset < len(raw); {
		relative := strings.Index(raw[offset:], "--")
		if relative < 0 {
			return false
		}
		start := offset + relative
		if start+2 == len(raw) {
			return true
		}
		next := raw[start+2]
		if isSQLWhitespace(next) || next == '+' {
			return true
		}
		offset = start + 2
	}
	return false
}

// hasSQLNCSemanticContext keeps a non-terminated double-dash slug from being
// accepted as a SQL comment while retaining payloads that carry SQL grammar
// next to the marker (for example a UNION/SELECT continuation or a quoted
// predicate). Standard line-comment terminators are accepted by the fast path.
func hasSQLNCSemanticContext(raw string) bool {
	if hasSQLNCTerminatorContext(raw) {
		return true
	}
	lower := strings.ToLower(raw)
	for offset := 0; offset < len(lower); {
		relative := strings.Index(lower[offset:], "--")
		if relative < 0 {
			return false
		}
		marker := offset + relative
		start := marker - 160
		if start < 0 {
			start = 0
		}
		window := lower[start:marker]
		if sqlNCSemanticWordRE.MatchString(window) || quotedOrPredicateInjection(window) {
			return true
		}
		offset = marker + 2
	}
	return false
}

// hasSQLOperatorSubqueryContext keeps the short `o(` fingerprint from treating
// ordinary parenthesized telemetry values such as `(direct)` as SQL. A real
// operator-subquery has an SQL clause immediately inside the parentheses and an
// operator at the opening boundary (for example `||(SELECT ...)` or `=(SELECT
// ...)`).
func hasSQLOperatorSubqueryContext(raw string) bool {
	lower := strings.ToLower(raw)
	for offset := 0; offset < len(lower); {
		relative := strings.Index(lower[offset:], "select")
		if relative < 0 {
			return false
		}
		selectAt := offset + relative
		open := strings.LastIndexByte(lower[:selectAt], '(')
		if open >= 0 && selectAt-open <= 16 {
			boundary := open - 1
			for boundary >= 0 && isSQLWhitespace(lower[boundary]) {
				boundary--
			}
			if boundary >= 0 && strings.ContainsRune("|=<>!&^+-*/", rune(lower[boundary])) {
				return true
			}
		}
		offset = selectAt + len("select")
	}
	return false
}

func hasSQLExecFingerprintContext(raw string) bool {
	lower := strings.ToLower(raw)
	for offset := 0; offset < len(lower); {
		relative := strings.Index(lower[offset:], "exec")
		if relative < 0 {
			return false
		}
		start := offset + relative
		if start > 0 {
			boundary := start - 1
			for boundary >= 0 && isSQLWhitespace(lower[boundary]) {
				boundary--
			}
			if boundary >= 0 {
				before := lower[boundary]
				if before != ';' && before != '\'' && before != '"' {
					offset = start + 4
					continue
				}
			}
		}
		end := start + 4
		if strings.HasPrefix(lower[end:], "ute") {
			end += 3
		}
		if end >= len(lower) || !isSQLWhitespace(lower[end]) {
			offset = end
			continue
		}
		for end < len(lower) && isSQLWhitespace(lower[end]) {
			end++
		}
		if end < len(lower) && ((lower[end] >= 'a' && lower[end] <= 'z') || lower[end] == '_') {
			return true
		}
		offset = end
	}
	return false
}

func isSQLWhitespace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\r' || b == '\n'
}

// XPath injection reaches the SQL analyzer because it is filed under "sqli" by
// every public corpus we measure against, and because it genuinely is the same
// attack: break out of a quoted literal and make the back-end evaluate an
// expression the developer did not write. The engine modelled the SQL grammar
// and none of the XPath one, so `' or count(//*) > 0 or ''='` and
// `substring(//users/user[1]/concat(password),3,1)='m'` both passed through
// untouched — 213 of the 676 verified detection misses were this one gap.
//
// The discriminator is the location path, never the function vocabulary.
// "concat(", "count(" and "substring(" are ordinary SQL and ordinary
// JavaScript; what only XPath has is a node test hanging off a "//" axis.

var xpathFunctionCall = regexp.MustCompile(`(?i)\b(?:count|substring|string-length|normalize-space|local-name|namespace-uri|name|text|position|last|translate|starts-with|contains|concat|sum|number|string|boolean|document)\s*\(`)

// foldOverlongUTF8 rewrites overlong UTF-8 sequences into the single ASCII
// character they encode, and leaves everything else byte-for-byte identical.
//
// Only sequences whose computed code point is below 0x80 are rewritten, which
// is exactly the set that cannot be legitimate text: a real two-byte character
// starts at U+0080, so every CJK, Cyrillic or accented sequence decodes above
// the threshold and passes through untouched. The rewrite is therefore confined
// to the overlong forms that exist solely to smuggle an ASCII metacharacter
// past a UTF-8 decoder.
func foldOverlongUTF8(s string) string {
	// Fast path: nothing above 0xBF means no multi-byte sequence at all, and
	// every ordinary request takes it.
	hasLead := false
	for i := 0; i < len(s); i++ {
		if s[i] >= 0xc0 {
			hasLead = true
			break
		}
	}
	if !hasLead {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c >= 0xc0 && c < 0xe0 && i+1 < len(s) && s[i+1]&0xc0 == 0x80:
			if cp := rune(c&0x1f)<<6 | rune(s[i+1]&0x3f); cp < 0x80 {
				b.WriteByte(byte(cp))
				i += 2
				continue
			}
		case c >= 0xe0 && c < 0xf0 && i+2 < len(s) && s[i+1]&0xc0 == 0x80 && s[i+2]&0xc0 == 0x80:
			if cp := rune(c&0x0f)<<12 | rune(s[i+1]&0x3f)<<6 | rune(s[i+2]&0x3f); cp < 0x80 {
				b.WriteByte(byte(cp))
				i += 3
				continue
			}
		}
		b.WriteByte(c)
		i++
	}
	return b.String()
}

// foldLFIUnicodeSeparators canonicalises the one legacy Unicode-escaped path
// separator observed in the quarantined corpus. Older IIS-style canonicalisers
// accepted %u2216 (U+2216 SET MINUS) as a backslash; treating it as a slash in
// this LFI-only analysis view lets the existing traversal and sensitive-target
// rules reason about the path without changing the shared decoder semantics.
// The original candidate is always retained for audit attribution.
func foldLFIUnicodeSeparators(raw string) (string, bool) {
	if !strings.Contains(raw, "%u2216") && !strings.Contains(raw, "%U2216") {
		return raw, false
	}
	var b strings.Builder
	b.Grow(len(raw))
	changed := false
	for i := 0; i < len(raw); {
		if i+6 <= len(raw) && raw[i] == '%' && (raw[i+1] == 'u' || raw[i+1] == 'U') &&
			strings.EqualFold(raw[i+2:i+6], "2216") {
			b.WriteByte('/')
			i += 6
			changed = true
			continue
		}
		b.WriteByte(raw[i])
		i++
	}
	if !changed {
		return raw, false
	}
	return b.String(), true
}

// lfiUnicodeSeparatorCandidate keeps the specialised fold away from ordinary
// Unicode/math prose. A traversal marker is required everywhere; unstructured
// fields additionally need a local sensitive target. Explicit file/path/URI
// fields may use traversal alone, matching the existing LFI field gate.
func lfiUnicodeSeparatorCandidate(raw, source, name string) bool {
	if (!strings.Contains(raw, "%u2216") && !strings.Contains(raw, "%U2216")) || !strings.Contains(raw, "..") {
		return false
	}
	folded, ok := foldLFIUnicodeSeparators(raw)
	if !ok {
		return false
	}
	if lfiHexExplicitPathContext(source, name) {
		return true
	}
	lower := strings.ToLower(folded)
	if lfiSensitiveTarget.MatchString(lower) {
		return true
	}
	for _, marker := range []string{"apache2/logs", ".secret"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// lfiHexPathEscapeHint is a deliberately narrow, raw-input superset for
// textual hexadecimal path bytes. It only opens the LFI family when a value
// carries a NUL boundary and a high-confidence sensitive target; ordinary SQL
// constants such as 0x2e/0x2f therefore remain on their normal SQL path.
// Source-aware callers use lfiHexPathEscapeCandidate when an explicit path
// field supplies the missing context.
func lfiHexPathEscapeHint(raw string) bool {
	if !lfiHexPathEscapeShape(raw) {
		return false
	}
	lower := strings.ToLower(raw)
	return (strings.ContainsRune(raw, 0) || strings.Contains(lower, "%00")) &&
		lfiHexSensitiveTargetMarker(lower) && lfiHexSensitiveTargetNearHexPath(raw)
}

// lfiHexPathEscapeCandidate applies the source/name context that the cheap
// hint cannot see. Generic fields still require a decoded/encoded NUL and a
// sensitive target; explicit path/file/URI fields may use the folded traversal
// itself as the evidence. This prevents global decoding of SQL 0x literals.
func lfiHexPathEscapeCandidate(raw, source, name string) bool {
	if !lfiHexPathEscapeShape(raw) {
		return false
	}
	if lfiHexExplicitPathContext(source, name) {
		return true
	}
	lower := strings.ToLower(raw)
	return (strings.ContainsRune(raw, 0) || strings.Contains(lower, "%00")) &&
		lfiHexSensitiveTargetMarker(lower) && lfiHexSensitiveTargetNearHexPath(raw)
}

func lfiHexExplicitPathContext(source, name string) bool {
	if strings.EqualFold(source, "uri") {
		return true
	}
	lower := strings.ToLower(strings.TrimSpace(name))
	if lower == "" || lower == "body" || lower == "raw_query" || lower == "path_query" {
		return false
	}
	parts := strings.FieldsFunc(lower, func(r rune) bool {
		return r == '.' || r == '_' || r == '-' || r == '[' || r == ']'
	})
	for _, part := range parts {
		switch part {
		case "file", "filename", "filepath", "path", "page", "include", "require", "template", "tpl", "view", "resource":
			return true
		}
	}
	return false
}

// lfiHexPathEscapeShape counts only the three textual byte escapes that can
// form a path separator or traversal dot. Requiring two dots and one separator
// in one punctuation-only cluster keeps a single SQL hex literal, or a prose
// list such as `0x2e, 0x2e, 0x2f`, from opening LFI analysis.
func lfiHexPathEscapeShape(raw string) bool {
	if !strings.Contains(raw, "0x") && !strings.Contains(raw, "0X") {
		return false
	}
	_, _, ok := lfiHexPathEscapeCluster(raw)
	return ok
}

type lfiHexEscapeRange struct {
	start int
	end   int
}

func lfiHexPathEscapeCluster(raw string) (int, int, bool) {
	clusters := lfiHexPathEscapeClusters(raw)
	if len(clusters) == 0 {
		return 0, 0, false
	}
	return clusters[0].start, clusters[0].end, true
}

func lfiHexPathEscapeClusters(raw string) []lfiHexEscapeRange {
	const maxClusterBytes = 96
	var clusters []lfiHexEscapeRange
	for cursor := 0; cursor+4 <= len(raw); {
		start := lfiHexEscapeTokenIndex(raw, cursor)
		if start < 0 {
			break
		}
		value, ok := lfiHexPathEscapeAt(raw, start)
		if !ok {
			cursor = start + 4
			continue
		}
		dots, separators := 0, 0
		if value == 0x2e {
			dots++
		} else {
			separators++
		}
		lastEnd := start + 4
		for pos := lastEnd; pos+4 <= len(raw) && pos-start <= maxClusterBytes; {
			next := lfiHexEscapeTokenIndex(raw, pos)
			if next < 0 {
				break
			}
			if next+4 > len(raw) {
				break
			}
			nextValue, nextOK := lfiHexPathEscapeAt(raw, next)
			if !nextOK || !lfiHexPathEscapeJoiner(raw[lastEnd:next]) {
				break
			}
			if nextValue == 0x2e {
				dots++
			} else {
				separators++
			}
			if dots >= 2 && separators >= 1 {
				clusters = append(clusters, lfiHexEscapeRange{start: start, end: next + 4})
				cursor = next + 4
				break
			}
			lastEnd = next + 4
			pos = lastEnd
		}
		if dots < 2 || separators < 1 {
			cursor = start + 4
		}
	}
	return clusters
}

func lfiHexEscapeTokenIndex(raw string, start int) int {
	for index := start; index+4 <= len(raw); index++ {
		if raw[index] == '0' && (raw[index+1] == 'x' || raw[index+1] == 'X') {
			return index
		}
	}
	return -1
}

func lfiHexPathEscapeJoiner(joiner string) bool {
	for i := 0; i < len(joiner); i++ {
		c := joiner[i]
		if c == '.' || c == '/' || c == '\\' || c == '%' || c == 0 ||
			(c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
			continue
		}
		return false
	}
	return true
}

func lfiHexPathEscapeAt(raw string, index int) (byte, bool) {
	if index < 0 || index+4 > len(raw) || raw[index] != '0' ||
		(raw[index+1] != 'x' && raw[index+1] != 'X') {
		return 0, false
	}
	high, ok := fromHex(raw[index+2])
	if !ok {
		return 0, false
	}
	low, ok := fromHex(raw[index+3])
	if !ok {
		return 0, false
	}
	value := high<<4 | low
	if value != 0x2e && value != 0x2f && value != 0x5c {
		return 0, false
	}
	return value, true
}

func lfiHexSensitiveTargetMarker(lower string) bool {
	for _, marker := range []string{
		"win.ini", "boot.ini", "passwd", "shadow", "wp-config", ".env",
		"id_rsa", "web.xml", "manifest.mf", "docker.sock", "/etc/",
		"/proc/", "/var/log/", "serviceaccount/token",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func lfiHexSensitiveTargetNearHexPath(raw string) bool {
	for _, escapeRange := range lfiHexPathEscapeClusters(raw) {
		lower := strings.ToLower(raw[escapeRange.end:])
		for strings.HasPrefix(lower, "%00") {
			lower = lower[3:]
		}
		for len(lower) > 0 && lower[0] == 0 {
			lower = lower[1:]
		}
		// The separator after the textual-hex traversal may itself be percent
		// encoded. Fold only slash/backslash bytes in this bounded suffix; the
		// full candidate remains untouched for audit attribution.
		lower = strings.ReplaceAll(lower, "%2f", "/")
		lower = strings.ReplaceAll(lower, "%5c", "\\")
		for _, marker := range []string{
			"win.ini", "boot.ini", "passwd", "shadow", "wp-config", ".env",
			"id_rsa", "web.xml", "manifest.mf", "docker.sock", "/etc/",
			"/proc/", "/var/log/", "serviceaccount/token",
		} {
			if strings.HasPrefix(lower, marker) {
				return true
			}
			if index := strings.Index(lower, marker); index > 0 && index <= 96 &&
				(lower[index-1] == '/' || lower[index-1] == '\\') {
				return true
			}
		}
	}
	return false
}

// foldLFIHexPathEscapes returns a view in which only path-byte escapes are
// folded. The original candidate remains untouched for audit payloads and hit
// attribution; callers use this view only for LFI shape analysis.
func foldLFIHexPathEscapes(raw, source, name string) (string, bool) {
	if !lfiHexPathEscapeCandidate(raw, source, name) {
		return raw, false
	}
	clusters := lfiHexPathEscapeClusters(raw)
	if len(clusters) == 0 {
		return raw, false
	}
	var b strings.Builder
	b.Grow(len(raw))
	changed := false
	clusterIndex := 0
	for i := 0; i < len(raw); {
		for clusterIndex < len(clusters) && i >= clusters[clusterIndex].end {
			clusterIndex++
		}
		inCluster := clusterIndex < len(clusters) && i >= clusters[clusterIndex].start && i < clusters[clusterIndex].end
		if inCluster {
			if value, ok := lfiHexPathEscapeAt(raw, i); ok {
				b.WriteByte(value)
				i += 4
				changed = true
				continue
			}
		}
		b.WriteByte(raw[i])
		i++
	}
	if !changed {
		return raw, false
	}
	return b.String(), true
}

func foldLFIHexPathEscapeRange(raw string, escapeRange lfiHexEscapeRange) (string, bool) {
	if escapeRange.start < 0 || escapeRange.end <= escapeRange.start || escapeRange.end > len(raw) {
		return raw, false
	}
	var b strings.Builder
	b.Grow(len(raw))
	changed := false
	for i := 0; i < len(raw); {
		if i >= escapeRange.start && i < escapeRange.end {
			if value, ok := lfiHexPathEscapeAt(raw, i); ok {
				b.WriteByte(value)
				i += 4
				changed = true
				continue
			}
		}
		b.WriteByte(raw[i])
		i++
	}
	if !changed {
		return raw, false
	}
	return b.String(), true
}

// xpathCheapGate is the substring pre-filter that decides whether the SQL
// analyzer is worth running on a candidate at all. It is a deliberate
// superset — the real discrimination happens in analyzeSQL, which additionally
// requires a location path.
//
// It lives here as one function because two callers need it and they must not
// drift apart: scanAttackHints sets hintSQL so the analyzer is invoked, and the
// SQL scoring gate adds sqli to the candidate's score set so the analyzer's
// result is kept. Wiring only the first produced a hit that was then discarded
// because sqli was never in the candidate's categories.
func xpathCheapGate(lower string) bool {
	return strings.Contains(lower, "substring(") || strings.Contains(lower, "string-length(") ||
		strings.Contains(lower, "normalize-space(") || strings.Contains(lower, "local-name(") ||
		strings.Contains(lower, "namespace-uri(") || strings.Contains(lower, "count(//") ||
		strings.Contains(lower, "name(//") || strings.Contains(lower, "document(//")
}

// xpathLocationPathStep returns the first XPath location path in text that is
// specific enough to be evidence.
//
// A bare "//" proves nothing: it is the URL scheme separator, a line comment in
// C-family source, and a Markdown list marker. What makes a step unmistakable
// is the node test that follows — a wildcard, a node-test function, a
// positional predicate, or a second path step. "count(//*)" and
// "//users/user[1]" qualify; "// Package engine provides" does not, which
// matters because the curated corpus contains real source files where a doc
// comment or a "//" import path is ordinary text.
func xpathLocationPathStep(text string) (string, bool) {
	for i := 0; i+1 < len(text); i++ {
		if text[i] != '/' || text[i+1] != '/' {
			continue
		}
		// "http://host" and a longer "//" run are not location paths.
		if i > 0 && (text[i-1] == ':' || text[i-1] == '/') {
			continue
		}
		p := &xpathScanner{s: text, i: i + 2}
		if p.run() {
			return text[i:p.i], true
		}
	}
	return "", false
}

type xpathScanner struct {
	s           string
	i           int
	sawWildcard bool
}

// run consumes one or more "/"-separated node tests and reports whether the
// run carries enough structure to be XPath rather than a URL or a comment.
func (p *xpathScanner) run() bool {
	steps := 0
	hasFunc, hasPredicate := false, false
	for {
		isFunc, ok := p.step()
		if !ok {
			break
		}
		steps++
		if isFunc {
			hasFunc = true
		}
		if p.predicates() > 0 {
			hasPredicate = true
		}
		// Only a single "/" continues the path; "//" starts an axis of its own
		// and belongs to the next iteration of the outer scan.
		if p.i+1 < len(p.s) && p.s[p.i] == '/' && p.s[p.i+1] != '/' {
			p.i++
			continue
		}
		break
	}
	if steps == 0 {
		return false
	}
	// A lone plain-name step with no predicate is a URL host or a comment
	// marker, not a location path.
	return hasFunc || hasPredicate || steps >= 2 || p.sawWildcard
}

func (p *xpathScanner) step() (isFunc, ok bool) {
	for p.i < len(p.s) && (p.s[p.i] == ' ' || p.s[p.i] == '\t') {
		p.i++
	}
	start := p.i
	if p.i < len(p.s) && p.s[p.i] == '*' {
		p.i++
		p.sawWildcard = true
	} else {
		for p.i < len(p.s) && isXPathNameByte(p.s[p.i]) {
			p.i++
		}
	}
	if p.i == start {
		return false, false
	}
	// A trailing "(" marks a node-test function: node(), text(), comment().
	return p.i < len(p.s) && p.s[p.i] == '(', true
}

// predicates consumes a run of balanced "[...]" and returns how many it took.
func (p *xpathScanner) predicates() int {
	n := 0
	for p.i < len(p.s) && p.s[p.i] == '[' {
		end := xpathMatchBracket(p.s, p.i)
		if end < 0 {
			return n // unbalanced predicate: take what we have
		}
		p.i = end
		n++
	}
	return n
}

// xpathMatchBracket returns the offset just past the "]" closing the "[" at
// start, or -1 when the bracket is never closed. Depth-counted so that a
// predicate containing another "[" — "[substring(.,1,1)='a'][1]" — is consumed
// as one unit instead of ending the predicate early.
func xpathMatchBracket(s string, start int) int {
	depth := 0
	for i := start; i < len(s); i++ {
		switch s[i] {
		case '[':
			depth++
		case ']':
			depth--
			if depth == 0 {
				return i + 1
			}
		}
	}
	return -1
}

func isXPathNameByte(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		return true
	}
	return b == '_' || b == '-' || b == '.'
}

// xpathInjectionShape reports whether text carries an XPath location path
// together with corroborating XPath grammar. Both halves are required: the path
// supplies the discrimination and the function call rules out the residual
// cases where a path-like string appears in ordinary content.
func xpathInjectionShape(text string) (step string, ok bool) {
	step, ok = xpathLocationPathStep(text)
	if !ok {
		return "", false
	}
	if !xpathFunctionCall.MatchString(text) {
		return "", false
	}
	return step, true
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
	// Breakout into the MongoDB shell: the payload terminates the host
	// expression and calls a database method, so there may be no operator
	// anywhere in it.
	shellEscape := nosqlShellEscapeMatch(lowerText)
	// JSON often splits map/reduce into separate fields; detect by field name + JS body.
	fieldMapReduce := nosqlMapReduceField(name) && nosqlJSBehavior.MatchString(lowerText)
	if !structuralOperator && !textOperator && !mapReduce && !fieldMapReduce && !shellEscape {
		return Hit{}, false
	}
	// Documentation field names normally skip NoSQL. Exception: raw request bodies
	// that carry real operator tokens (e.g. broken/partial JSON with "$eval").
	//
	// shellEscape is exempt from both gates below. A breakout into the MongoDB
	// shell has no operator *by construction* — that is what distinguishes it
	// from operator injection — so requiring one here would disable the path
	// that was added for it. The corpus demonstrated exactly that:
	// "comment=Nice post!'); db.users.remove({isAdmin:true}); //" was missed
	// while the same payload under a field named "query" was caught, purely
	// because "query" happens to be in nosqlSensitiveContext.
	if !structuralOperator && !mapReduce && !fieldMapReduce && !shellEscape && nosqlDocumentationContext(name) {
		if !(candidate.input.Source == "body.raw" && textOperator) {
			return Hit{}, false
		}
	}
	if !structuralOperator && !mapReduce && !fieldMapReduce && !shellEscape && !nosqlSensitiveContext(name) && !nosqlLooksLikeStructuredPayload(lowerText) {
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
	if shellEscape {
		reasons["syntax: MongoDB shell method call after expression breakout"] = true
		reasons["semantics: breakout can execute arbitrary database statements outside the intended query"] = true
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
		// An operator no ordinary client would send is enough on its own;
		// anything else still needs a sensitive field name to carry the intent.
		if !nosqlInjectionOperatorInPath(name) && (!structuralOperator || !nosqlSensitiveContext(name)) {
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
	// Use evidenceInProseContext so that a prose prefix + filler bypass cannot
	// suppress detection of a real NoSQL injection operator.
	if evidenceInProseContext(text, []string{
		"$where", "$eval", "$function", "$or", "$and", "$regex",
		"$ne", "$nin", "$gt", "$gte", "$lt", "$lte", "$not",
		"mapreduce", "$accumulator", "$expr",
	}) {
		confidence *= 0.4
		if confidence < 0.7 {
			return Hit{}, false
		}
	}

	return hit(candidate, "nosqli", severity, confidence, reasons), true
}

// nosqlShellEscapeMatch is the only way nosqlShellEscape should be consulted.
// The gate exists because the pattern is ~2µs and its callers run per input
// point; see nosqlShellEscapeGate.
func nosqlShellEscapeMatch(lower string) bool {
	if !strings.Contains(lower, nosqlShellEscapeGate) {
		return false
	}
	return nosqlShellEscape.MatchString(lower)
}

// lfiWindowsSystemPathMatch is the only way lfiWindowsSystemPath should be
// consulted. The drive-letter colon and one target word are both required by the
// pattern, so checking them first is a strict superset that costs a fraction as
// much as entering the regexp engine.
func lfiWindowsSystemPathMatch(lower string) bool {
	if !strings.Contains(lower, ":\\") && !strings.Contains(lower, ":/") {
		return false
	}
	for _, target := range lfiWindowsPathTargets {
		if strings.Contains(lower, target) {
			return lfiWindowsSystemPath.MatchString(lower)
		}
	}
	return false
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
	freemarkerRuntimeExec := sstiFreemarkerBeansRuntimeExec.MatchString(lowerText)
	dangerous := sstiDangerousBehavior.MatchString(lowerText) || freemarkerRuntimeExec
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
	// The parameter-name gate can only be applied when a name carries signal.
	// When the whole value is one template expression there is no surrounding
	// prose to be a fragment of, so the gate has nothing to discriminate — and
	// the field name for these payloads is literally "body".
	wholeBody := sstiWholeBodyExpression.MatchString(text)
	if arithmeticProbe && (sstiProbeContext(candidate.input.Name) || wholeBody) {
		reasons["syntax: arithmetic template evaluation probe"] = true
		reasons["semantics: probe attempts to confirm server-side template evaluation"] = true
	}
	// The quoted-operand probe stands on its own: "7*'7'" is not a fragment of
	// ordinary text, so it does not need the parameter-name gate that the
	// integer-only form requires to stay clear of prose.
	if sstiQuotedArithmeticProbe.MatchString(lowerText) {
		reasons["syntax: arithmetic template evaluation probe with mixed operand types"] = true
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
	// Use evidenceInProseContext so that a prose prefix + filler bypass cannot
	// suppress detection of a real template injection payload.
	if evidenceInProseContext(text, []string{
		"{{", "{%", "${", "<#", "#{", "[[",
		"__class__", "__mro__", "__subclasses__", "__globals__",
		"freemarker.template", "classloader", "processbuilder",
		"objectspace", "java.lang.runtime",
	}) {
		confidence *= 0.4
		if confidence < 0.7 {
			return Hit{}, false
		}
	}
	// The beans runtime sink is especially common in educational examples,
	// while a live request normally places it in a short template value.  Apply
	// a locality-aware prose check only to this newly covered shape so the
	// broader SSTI execution signatures retain their existing behavior.
	if freemarkerRuntimeExec {
		// Use the executable expression itself as the anchor.  A prose
		// prefix may mention "FreeMarker" long before the sink; anchoring on
		// that word would make the locality window too short to recognize the
		// nearby documentation markers.
		beansWin := evidenceWindow(text, []string{"beans", ".exec("})
		if technicalDocumentationContext(beansWin) {
			confidence *= 0.4
			if confidence < 0.7 {
				return Hit{}, false
			}
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
	// Keep a specific explanation in addition to the generic executable-context
	// reason so review output identifies this legacy CSS escape precisely.
	if xssCSSExpression.MatchString(lower) {
		reasons["syntax: CSS JavaScript expression escape"] = true
		reasons["semantics: CSS expression body is evaluated as script by the browser"] = true
	}
	if javascriptURLContext.MatchString(lower) {
		reasons["syntax: javascript URL in executable HTML attribute"] = true
	}
	if xssJavascriptURLFieldContext(candidate) {
		reasons["syntax: javascript URL in URL-valued request field"] = true
		reasons["semantics: URL field accepts executable script scheme"] = true
	}
	if xssDataURLFieldContext(candidate) {
		reasons["syntax: executable data URI in URL-valued request field"] = true
		reasons["semantics: URL field carries base64-encoded executable HTML"] = true
	}
	standaloneCandidate := candidate
	standaloneCandidate.text = lower
	if xssStandaloneJavascriptURLContext(standaloneCandidate) {
		reasons["syntax: standalone javascript URL in executable request surface"] = true
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
	if containsAny(lower, []string{"document.cookie", "localstorage", "fetch("}) {
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

	// Compute the attack-evidence window so that a prose prefix + filler padding
	// separated from the payload cannot suppress detection via techdoc markers
	// appearing only in the outer document, not adjacent to the XSS payload.
	xssWin := evidenceWindow(text, []string{
		"<script", "onerror=", "onload=", "javascript:", "alert(",
		"prompt(", "confirm(", "document.cookie", "eval(", "<iframe",
		"svg onload",
	})

	// Technical documentation keyword guard: AND-gate — full document AND local window.
	if technicalDocumentationContext(text) && technicalDocumentationContext(xssWin) {
		confidence *= 0.7
		if confidence < 0.7 {
			return Hit{}, false
		}
	}

	return hit(candidate, "xss", engine.SeverityHigh, confidence, reasons), true
}

func analyzeRCE(candidate semanticCandidate) (Hit, bool) {
	text := strings.TrimSpace(candidate.text)
	// Keep compatibility folding and control boundaries in the primary RCE view.
	// The compact normalized form is still available for control-free values, but
	// must not join tokens across NUL/newline boundaries (for example
	// `new-\x00object`).
	lower := normalizePreserveControls(text)
	normalized := normalize(text)
	// Keep a control-preserving lowercase view for necessary-marker gates. The
	// normalized view intentionally strips controls from non-ASCII text, while
	// the raw regex suite still recognizes newline-separated shell commands.
	rawLower := strings.ToLower(text)
	// `lower` is already the control-preserving NFKC/lowercase view. Reusing it
	// avoids a second full Unicode pass on every RCE candidate.
	normalizedControlLower := lower
	hasControl := strings.IndexFunc(text, unicode.IsControl) >= 0
	matchRCE := func(pattern *regexp.Regexp) bool {
		if guardedMatchString2K(pattern, text) {
			return true
		}
		// Raw text remains the first choice so control-byte/newline semantics are
		// unchanged. Retry the already-computed NFKC view only when compatibility
		// characters prevented the raw regexp from seeing its ASCII grammar.
		if !hasControl && normalized != text && normalized != lower && guardedMatchString2K(pattern, normalized) {
			return true
		}
		return normalizedControlLower != rawLower && guardedMatchString2K(pattern, normalizedControlLower)
	}
	matchRCEValue := func(pattern *regexp.Regexp, value string) bool {
		if guardedMatchString2K(pattern, value) {
			return true
		}
		if strings.IndexFunc(value, unicode.IsControl) >= 0 {
			preservedValue := normalizePreserveControls(value)
			return preservedValue != value && guardedMatchString2K(pattern, preservedValue)
		}
		normalizedValue := normalize(value)
		return normalizedValue != value && guardedMatchString2K(pattern, normalizedValue)
	}
	// A field name such as `cmd.exe` or `command_line` is a useful execution
	// hint, but those names also occur in CI/job metadata where ordinary
	// diagnostic commands (`python --version`, `powershell -Help`, `cmd.exe /?`)
	// are expected.  Keep the historical authority of the short `cmd`/`exec`
	// aliases, while requiring an execution-shaped value for the newer compound
	// aliases.  Strong RCE regexes still provide independent evidence below.
	sink := rceExecutionSinkForValue(candidate.input.Source, candidate.input.Name, text)
	// Compound aliases are common in build metadata.  Keep their interpreter
	// grammar conservative: a plain `python3 -c print(1)` is a diagnostic script,
	// whereas a sink value carrying an OS/process primitive remains actionable.
	narrowSink := rceSinkAllowed(candidate.input.Source, candidate.input.Name) &&
		rceNarrowSinkAlias(candidate.input.Name)
	interpreterInlineEvidence := rceInterpreterInlineMayMatch(lower) &&
		matchRCE(rceInterpreterInline) &&
		(!narrowSink || sink || rceInterpreterDangerousArgument(text))
	// Several later branches consult the same guarded expressions. Compute each
	// marker-gated result once so long documentation values do not repeatedly
	// walk the same regular expression (the result is purely a function of this
	// candidate and its already-normalized view).
	whitespaceEvasionEvidence := rceWhitespaceEvasionMayMatch(lower) && matchRCE(rceWhitespaceEvasion)
	metacharExecutionEvidence := rceMetacharExecutionFunctionMayMatch(lower) && matchRCE(rceMetacharExecutionFunction)
	powerShellSideFxEvidence := rcePowerShellSideFxMayMatch(lower) && matchRCE(rcePowerShellSideFx)
	encodedPowerShellEvidence := rceEncodedPowerShellMayMatch(lower) && matchRCE(rceEncodedPowerShell)
	netWebClientEvidence := rceNetWebClientSideFxMayMatch(lower) && matchRCE(rceNetWebClientSideFx)
	powerShellReverseShellEvidence := rcePowerShellReverseShellMayMatch(lower) && matchRCE(rcePowerShellReverseShell)
	downloadExecEvidence := rceDownloadExecChainMayMatch(lower) && matchRCE(rceDownloadExecChain)
	reverseShellEvidence := rceReverseShellPrimitiveMayMatch(lower) && matchRCE(rceReverseShellPrimitive)
	templateExecutionEvidence := rceTemplateExecutionPrimitiveMayMatch(lower) && matchRCE(rceTemplateExecutionPrimitive)
	loaderEvidence := rceLoaderPrimitiveMayMatch(lower) && matchRCE(rceLoaderPrimitive)
	// A NUL introduced by URL/HTML decoding is a token boundary at an explicit
	// command sink, not whitespace to be stripped. Keep the ordinary views
	// unchanged everywhere else so prose such as `new-\x00object` cannot be
	// reassembled into an executable token.
	controlCommandView := ""
	if sink && rceControlCommandChain(text) {
		controlCommandView = rceControlCommandView(text)
	}
	reasons := map[string]bool{}
	// Markdown table markup turns "| id |" into a fake pipe-plus-command shape.
	// Outside an execution sink, a table delimiter row means the pipes are cell
	// separators. Inside a sink, table markup earns no trust.
	tableMarkup := !sink && markdownTableShape(text)
	tableCommand := tableMarkup && markdownTableHasExecutableCommand(text)
	// A genuine command embedded in a table cell must not inherit the prose
	// exemption. Ordinary documentation tables list bare tool names in one cell
	// and descriptions in another; a cell that starts with a known executable and
	// carries an argument is an execution-shaped payload and is analyzed normally.
	if tableCommand {
		tableMarkup = false
		reasons["syntax: shell metacharacter plus executable command"] = true
		reasons["semantics: command execution intent"] = true
	}

	patternZeroMatched := false
	if !tableMarkup {
		for i, pattern := range rcePatterns {
			if !rcePatternMayMatchViews(i, rawLower, lower) &&
				!rcePatternMayMatch(i, normalizedControlLower) {
				continue
			}
			matched := matchRCE(pattern)
			if !matched && controlCommandView != "" {
				matched = guardedMatchString2K(pattern, controlCommandView)
			}
			if matched {
				// Compound command fields are also used for build metadata and
				// diagnostics.  When the value did not pass the high-confidence
				// sink gate, broad interpreter/binary grammar must not manufacture
				// the two reasons required for a block.  Keep explicit separators
				// and the stronger indexed attack patterns active so a real payload
				// such as `command_line=;id` or an encoded/dynamic PowerShell value
				// still reaches the detector.
				if narrowSink && !sink && rceCompoundDiagnosticPattern(i) {
					continue
				}
				if i == 0 {
					patternZeroMatched = true
				}
				reasons["syntax: shell metacharacter plus executable command"] = true
				if rcePatternCarriesSemanticIntent(i) {
					reasons["semantics: command execution intent"] = true
				}
			}
		}
	}
	// Alias commands such as `arp`, `route`, and `tftp` are intentionally kept
	// out of the backtick/prose vocabulary because they are common words or
	// documentation terms. Only promote them after the indexed shell-command
	// expression itself matched; otherwise a prose fragment like
	// "please review; route details" would mint two reasons without any regex
	// evidence and bypass the hard-signal gate.
	if patternZeroMatched && rceIndexedAliasCommandIntentForSource(text, tableMarkup, candidate.input.Source, candidate.input.Name) {
		reasons["syntax: shell metacharacter plus executable command"] = true
		reasons["semantics: command execution intent"] = true
	}
	// Bare English ";" must not count outside execution sinks (major FP source in docs).
	shellControlText := text
	if strings.Contains(shellControlText, "$((") {
		shellControlText = rcePureArithmeticExpansion.ReplaceAllString(shellControlText, "")
	}
	shellControlEvidence := rceShellControlEvidenceForContext(lower, candidate.input.Source, candidate.input.Name, sink)
	if sink && rceShellControlMayMatch(lower) && matchRCEValue(rceShellControl, shellControlText) {
		reasons["syntax: shell control operator or command substitution"] = true
	} else if !sink && !tableMarkup && shellControlEvidence {
		reasons["syntax: shell control operator or command substitution"] = true
	}
	if metacharExecutionEvidence {
		reasons["syntax: shell separator followed by a language execution function"] = true
		reasons["semantics: host runtime command execution through an interpreter primitive"] = true
	}
	if whitespaceEvasionEvidence {
		reasons["syntax: shell whitespace evasion"] = true
	}
	// Command chaining through newlines carries no shell metacharacter at all,
	// so it needs its own gate: "bio=hello\nid\nls -la /tmp" reaches a shell
	// through eval()/os.system() without ever writing ";", "&&" or "|".
	newlineChain := rceNewlineCommandChain(text) || rceNewlineCommandChain(normalizedControlLower)
	if !newlineChain && controlCommandView != "" {
		newlineChain = rceNewlineCommandChain(controlCommandView)
	}
	if newlineChain && rceNewlineCommandChainAllowed(text, candidate.input.Source, candidate.input.Name) {
		reasons["syntax: newline-separated command chain"] = true
		reasons["semantics: command execution intent"] = true
	}
	if sink {
		reasons["context: command execution parameter"] = true
	}
	if rceBareCommandSinkValueForSource(candidate.input.Source, candidate.input.Name, text) {
		reasons["semantics: bare command in execution sink"] = true
	}
	if rceCommandSinkShapeForSource(candidate.input.Source, candidate.input.Name, text) {
		reasons["semantics: command execution intent"] = true
	}
	if rceSinkNULPatternIntentForSource(candidate.input.Source, candidate.input.Name, text) {
		reasons["semantics: command execution intent"] = true
	}
	if powerShellSideFxEvidence || encodedPowerShellEvidence || netWebClientEvidence {
		reasons["semantics: PowerShell dynamic execution or encoded command"] = true
	}
	if powerShellReverseShellEvidence {
		reasons["semantics: shell reverse connection primitive"] = true
		reasons["semantics: PowerShell dynamic execution or encoded command"] = true
	}
	if interpreterInlineEvidence {
		reasons["semantics: interpreter inline command execution"] = true
	}
	if downloadExecEvidence {
		reasons["semantics: download-to-shell execution chain"] = true
	}
	if reverseShellEvidence {
		reasons["semantics: shell reverse connection primitive"] = true
	}
	// Loader/reflective primitives: only count as RCE evidence when tied to an
	// execution sink or another hard shell/runtime signal (avoid doc FPs like
	// "set LD_PRELOAD=/path" in prose without a command parameter).
	if loaderEvidence {
		if sink || shellControlEvidence ||
			interpreterInlineEvidence ||
			powerShellSideFxEvidence ||
			downloadExecEvidence ||
			reverseShellEvidence {
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
	if templateExecutionEvidence {
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
	// eval(getallheaders()) / eval(apache_request_headers()) reads attacker
	// headers into eval. Same surface rules as delimiter-less PHP gadgets:
	// query/form/json/cookie, not a raw advisory body.
	if phpGadgetAllowed(candidate.input.Source, candidate.input.Name, candidate.text) &&
		(strings.Contains(lower, "eval(") || strings.Contains(lower, "assert(")) &&
		(strings.Contains(lower, "getallheaders") || strings.Contains(lower, "apache_request_headers")) {
		reasons["syntax: PHP header-array evaluation"] = true
		reasons["semantics: language runtime command or include execution"] = true
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
			if sink || shellControlEvidence ||
				whitespaceEvasionEvidence ||
				interpreterInlineEvidence ||
				powerShellSideFxEvidence ||
				encodedPowerShellEvidence ||
				downloadExecEvidence {
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

	// Compute the attack-evidence window once; securityDocumentContext and
	// technicalDocumentationContext both run on this window so that a prose
	// prefix + filler padding separated from the payload cannot suppress
	// detection via either guard.
	rceWin := evidenceWindow(text, []string{
		";cat ", "|cat ", "| cat ", ";id", "|id", "| id",
		"|bash", "| bash", "|sh ", "| sh ", "/bin/sh", "/bin/bash",
		"/etc/passwd", "/etc/shadow", "whoami", "nc ", "netcat",
		"wget ", "curl ", "<?php", "eval(", "system(", "passthru(",
		"shell_exec(", "proc_open(", "popen(", "exec(",
		"runtime.exec", "processbuilder", "() { :;};", "${jndi:",
	})

	// Security document context: vulnerability reports, CTF writeups, training
	// material, academic papers, Chinese technical articles, and source files all
	// quote shell commands verbatim without invoking them.
	if securityDocumentContextWindowed(text, rceWin) {
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

	// Technical documentation keyword guard: AND-gate — full document AND local window.
	if technicalDocumentationContext(text) && technicalDocumentationContext(rceWin) {
		confidence *= 0.7
		if confidence < 0.7 {
			return Hit{}, false
		}
	}

	return hit(candidate, "rce", engine.SeverityCritical, confidence, reasons), true
}

func markdownTableHasExecutableCommand(text string) bool {
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || markdownTableDelimiterRow.MatchString(trimmed) || !markdownTableRowShape(trimmed) {
			continue
		}
		cells := strings.Split(trimmed, "|")
		for cellIndex, cell := range cells {
			fields := strings.Fields(strings.TrimSpace(cell))
			if len(fields) == 0 {
				continue
			}
			if rceCommandTokenKnown(fields[0]) &&
				((len(fields) >= 2 && markdownTableCellHasHardExecutionShape(cell)) ||
					markdownTableExecutionMarker(cells, cellIndex)) {
				return true
			}
		}
	}
	return false
}

func markdownTableCellHasHardExecutionShape(cell string) bool {
	text := strings.TrimSpace(cell)
	if text == "" {
		return false
	}
	lower := strings.ToLower(text)
	if strings.ContainsAny(lower, ";`$()<>") ||
		strings.Contains(lower, "&&") || containsShellLogicalOr(lower) {
		return true
	}
	// Interpreter flags and shell binaries are explicit execution grammar, not
	// ordinary command descriptions. Keep this check narrow so `grep pattern`
	// and `curl URL` tables remain documentation.
	if rceInterpreterInlineMayMatch(lower) && rceInterpreterInline.MatchString(lower) {
		return true
	}
	if strings.Contains(lower, "/etc/") || strings.Contains(lower, "/proc/") ||
		strings.Contains(lower, "/dev/tcp/") || strings.Contains(lower, "php://") ||
		strings.Contains(lower, "data://") || strings.Contains(lower, "file://") {
		return true
	}
	return false
}

func markdownTableExecutionMarker(cells []string, commandIndex int) bool {
	for index, cell := range cells {
		if index == commandIndex {
			continue
		}
		lower := strings.ToLower(strings.TrimSpace(cell))
		switch lower {
		case "execute", "exec", "run", "shell", "command", "invoke", "payload":
			return true
		}
		for _, prefix := range []string{"execute:", "exec:", "command:", "payload:"} {
			if strings.HasPrefix(lower, prefix) {
				return true
			}
		}
	}
	return false
}

// rceIndexedAliasCommandIntent covers executable names that are deliberately
// absent from rceCommandNames because they are common English words in prose
// (for example `arp` and `route`). The indexed shell pattern has already
// established an operator-plus-command shape; this helper supplies the
// semantic reason needed to pass the two-signal threshold without broadening
// the prose/backtick vocabulary. A recognized Markdown table is excluded here
// unless its command cell already forced tableMarkup off above.
func rceIndexedAliasCommandIntentForSource(text string, tableMarkup bool, source, name string) bool {
	if tableMarkup {
		return false
	}
	lower := normalizePreserveControls(text)
	for offset := 0; offset < len(lower); {
		operator := ""
		for _, candidate := range []string{"&&", "||", ";", "|", "\n", "\r"} {
			if strings.HasPrefix(lower[offset:], candidate) {
				operator = candidate
				break
			}
		}
		if operator == "" {
			offset++
			continue
		}
		rest := strings.TrimLeft(lower[offset+len(operator):], " \t\r\n")
		if rest != "" {
			end := len(rest)
			for index, r := range rest {
				if r == ' ' || r == '\t' || r == '\r' || r == '\n' || strings.ContainsRune(";&|", r) {
					end = index
					break
				}
			}
			token := strings.Trim(rest[:end], "()$<>\"'")
			if token != "" && rceIndexedAliasToken(token) &&
				rceIndexedAliasArgumentEvidence(token, rest[end:]) &&
				rceIndexedAliasOperatorIntentForSource(lower[:offset], operator, source, name) {
				return true
			}
		}
		offset += len(operator)
	}
	return false
}

// rceIndexedAliasOperatorIntent rejects an alias-looking command that appears
// after ordinary sentence prose. The indexed shell regexp intentionally stays
// broad for recall, while this second gate only promotes a deliberately small
// alias set (route/arp/tftp/awk/sed/tr). A command at the beginning of a value,
// after a field assignment, or in an explicit execution sink is actionable;
// `The note says; route -n appears in logs.` is not.
func rceIndexedAliasOperatorIntentForSource(prefix, operator, source, name string) bool {
	if rceExecutionSinkForSource(source, name) {
		return true
	}
	if operator == "\n" || operator == "\r" {
		// Newline chaining is still accepted when the command follows a compact
		// value/assignment. A natural-language line such as "The note says" is
		// intentionally not enough context to promote an alias.
		if index := strings.LastIndexAny(prefix, "\n\r"); index >= 0 {
			prefix = prefix[index+1:]
		}
	}
	trimmed := strings.TrimSpace(prefix)
	if trimmed == "" {
		return true
	}
	// A field assignment, shell expansion, quote, or prior operator supplies
	// executable structure even when the command is not at byte zero.
	if strings.ContainsAny(trimmed, "=$()<>\"'`") {
		return true
	}
	// Structured request values can legitimately carry a prose prefix before an
	// injected separator (`hello world;arp -a`). Reject only unmistakable
	// documentation lead-ins; the argument-tail gate below handles sentence
	// prose that follows the alias itself.
	if rceAliasProsePrefix(trimmed) {
		return false
	}
	return true
}

func rceAliasProsePrefix(prefix string) bool {
	fields := strings.Fields(strings.ToLower(prefix))
	if len(fields) == 0 {
		return false
	}
	for _, field := range fields {
		field = strings.Trim(field, ".,!?;:)]}")
		switch field {
		case "a", "an", "appears", "below", "command", "document", "documentation", "docs", "example", "examples", "guide", "in", "manual", "note", "notes", "option", "reference", "reviewed", "see", "shown", "says", "text", "the", "this", "transform", "use", "uses", "value":
			return true
		}
	}
	return false
}

// rceIndexedAliasToken is the deliberately small set of executable aliases
// that are not safe to treat as ordinary backtick/prose command names. Each
// token is already covered by the indexed shell-command expression (or by the
// explicit route addition), and its argument shape is checked separately below.
func rceIndexedAliasToken(token string) bool {
	switch strings.ToLower(rceCommandBase(token)) {
	case "tftp", "arp", "route", "gawk", "awk", "sed", "tr":
		return true
	default:
		return false
	}
}

// rceIndexedAliasArgumentEvidence requires an argv shape that is unlikely to
// be ordinary prose. Flags, paths, quoted scripts, addresses, and numeric
// ports are strong evidence; a bare word such as "route details" is not.
func rceIndexedAliasArgumentEvidence(token, rawArgs string) bool {
	args := strings.TrimSpace(rawArgs)
	if args == "" {
		return false
	}
	lower := strings.ToLower(rceCommandBase(token))
	fields := strings.Fields(args)
	evidenceIndex := -1
	hasShellSyntax := strings.ContainsAny(args, "'\"`$(){}[]<>;/\\")
	if hasShellSyntax {
		evidenceIndex = 0
	}
	for fieldIndex, field := range fields {
		clean := strings.Trim(field, ".,!?;:)]}")
		if clean == "" {
			continue
		}
		if strings.HasPrefix(clean, "-") {
			if evidenceIndex < 0 {
				evidenceIndex = fieldIndex
			}
			continue
		}
		if strings.ContainsAny(clean, "/\\") || allASCIIDigits(clean) {
			if evidenceIndex < 0 {
				evidenceIndex = fieldIndex
			}
			continue
		}
		// A dotted host/version is evidence only when it carries a digit (IP,
		// port, or an explicitly versioned address). A sentence-ending period
		// must never promote an alias-only prose fragment.
		if strings.Contains(clean, ".") && containsASCIIDigit(clean) {
			if evidenceIndex < 0 {
				evidenceIndex = fieldIndex
			}
			continue
		}
		if strings.Contains(clean, ":") && containsASCIIDigit(clean) {
			if evidenceIndex < 0 {
				evidenceIndex = fieldIndex
			}
			continue
		}
	}
	if evidenceIndex >= 0 && !rceAliasTerminalPunctuation(args) && !rceAliasProseTail(fields, evidenceIndex) {
		return true
	}
	// A few aliases use a conventional action word instead of a flag. Keep the
	// vocabulary bounded to avoid turning an English sentence into a command.
	if lower == "route" || lower == "arp" {
		for index, field := range fields {
			switch strings.ToLower(field) {
			case "add", "del", "delete", "change", "flush", "show", "via":
				if !rceAliasProseTail(fields, index) {
					return true
				}
			}
		}
	}
	return false
}

func rceAliasTerminalPunctuation(args string) bool {
	trimmed := strings.TrimSpace(args)
	if trimmed == "" {
		return false
	}
	last, _ := utf8.DecodeLastRuneInString(trimmed)
	return strings.ContainsRune(".!?。！？", last)
}

func rceAliasProseTail(fields []string, evidenceIndex int) bool {
	if evidenceIndex < 0 || evidenceIndex+1 >= len(fields) {
		return false
	}
	for _, field := range fields[evidenceIndex+1:] {
		word := strings.ToLower(strings.Trim(field, ".,!?;:)]}"))
		if rceAliasProseStopword(word) {
			return true
		}
	}
	return false
}

func rceAliasProseStopword(word string) bool {
	switch word {
	case "a", "an", "and", "appears", "as", "at", "below", "be", "details", "documented", "documentation", "docs", "example", "examples", "for", "in", "is", "listed", "logs", "manual", "note", "notes", "of", "on", "shown", "the", "this", "to", "use", "uses", "was", "were", "with":
		return true
	default:
		return false
	}
}

func allASCIIDigits(value string) bool {
	if value == "" {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}
	return true
}

func containsASCIIDigit(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] >= '0' && value[i] <= '9' {
			return true
		}
	}
	return false
}

func rcePatternCarriesSemanticIntent(index int) bool {
	switch index {
	case 5, 10, 15, 16, 17, 18, 19, 20:
		// These indexed expressions encode a complete command primitive: Windows
		// cmd execution, sensitive-file reads, IFS evasion, descriptor/reverse
		// shell wiring, PowerShell obfuscation, variable assignment, or chained
		// decoding. A syntax match is therefore sufficient to supply the second
		// semantic signal without widening the ordinary command vocabulary.
		return true
	default:
		return false
	}
}

// rceCompoundDiagnosticPattern identifies broad indexed expressions whose
// match is common in harmless command metadata (for example `cmd.exe /c dir`,
// `powershell -NoProfile`, or `python -c print(1)`).  These expressions remain
// fully active for ordinary fields and for high-confidence command sinks; they
// are suppressed only when a compound sink name was present but its value did
// not pass the value-aware execution gate.
func rceCompoundDiagnosticPattern(index int) bool {
	switch index {
	case 2, 4, 5, 8, 17, 18:
		return true
	default:
		return false
	}
}

// English words are deliberately absent from the command alternation. See the
// note on rceCommandNames: "who" and "last" were added here and removed again
// after they produced false positives on ordinary prose.
var rceShellMetacharCommand = regexp.MustCompile(`(?i)(?:;|&&|\|\||\|)\s*(?:cat|id|whoami|uname|curl|wget|bash|sh|zsh|dash|pwsh|powershell|cmd|python3?|perl|php|ruby|node|nc|ncat|netcat|netstat|socat|lua|iex|type|dir|ls|sleep|echo|ping|lsof)\b`)

// rceMetacharExecutionFunction matches a shell metacharacter followed by a
// language-level execution function. ";system('id')" is the PHP shape and it
// needs this pattern: the metachar-command regex only names argv[0] of real
// binaries, and a lone template-execution primitive is not a hard signal on its
// own, so analyzeRCE dropped it for having fewer than two reasons.
var rceMetacharExecutionFunction = regexp.MustCompile(`(?i)(?:;|&&|\|\||\|)\s*(?:system|exec|passthru|shell_exec|popen|eval|assert)\s*\(`)

// rceCommandNames is the set of executable names that count as command-execution
// intent. It is the single source of truth for both token scanning in analyzeRCE
// and the backtick discrimination in rceShellControlEvidenceForContext: a single word in
// backticks that names a real command is substitution, not Markdown inline code.
//
// This set must stay consistent with rceShellMetacharCommand above. It had
// drifted: the regex already knew "id", "ls", "echo", "dir" and "type", but
// this map did not, so a payload whose only execution signal was a backtick
// pair — "User-Agent: ReportGen/3.4 `id`" — was classified as Markdown inline
// code and dropped. The backtick discriminator consults this map and nothing
// else, so a command missing here is a command that cannot be detected.
var rceCommandNames = map[string]bool{
	"cat": true, "whoami": true, "uname": true, "curl": true, "wget": true,
	"bash": true, "sh": true, "zsh": true, "dash": true, "pwsh": true,
	"powershell": true, "cmd": true, "python": true, "python3": true,
	"perl": true, "php": true, "ruby": true, "node": true, "nc": true,
	"ncat": true, "netcat": true, "socat": true, "lua": true, "iex": true,
	"invoke-expression": true, "sleep": true, "ping": true, "nslookup": true,
	// Present in rceShellMetacharCommand but missing here:
	"id": true, "ls": true, "echo": true, "dir": true, "type": true,
	// Reconnaissance and host-enumeration commands. Cheap to run and the first
	// thing an injection reaches for, so they carry the same intent as "cat":
	"hostname": true, "ps": true, "uptime": true, "pwd": true, "env": true,
	"printenv": true, "ifconfig": true, "df": true, "du": true,
	"mount": true, "grep": true, "awk": true, "sed": true, "head": true,
	"tail": true, "base64": true, "dig": true, "host": true, "telnet": true,
	"ssh": true, "chmod": true, "chown": true, "rm": true, "cp": true, "mv": true,
	// "netstat" and "lsof" are the only additions from that family that survived
	// measurement. "who", "last", "arp" and "route" were tried and reverted:
	// they are ordinary English words, and adding them turned a benign profile
	// bio — "Tech enthusiast <em>who loves</em> open-source & data science" —
	// into a 0.90-confidence RCE. Two false positives on clean traffic is not a
	// price worth paying for two more corpus rows.
	"netstat": true, "lsof": true,
}

// rceCommandBase reduces a possibly path-qualified command to its basename, so
// that "`/usr/bin/id`" is recognised as the same command as "`id`".
//
// Without this a payload only has to name the absolute path — which is what
// every hard-coded invocation in real code does — and the single-word backtick
// check stops matching. "`/bin/cat /etc/passwd`" happened to work because the
// trailing argument made it two words, which masked the gap.
func rceCommandBase(word string) string {
	word = strings.Trim(word, "()$;|&><\"' \t")
	if idx := strings.LastIndexByte(word, '/'); idx >= 0 {
		word = word[idx+1:]
	}
	if idx := strings.LastIndexByte(word, '\\'); idx >= 0 {
		word = word[idx+1:]
	}
	return word
}

// rceNewlineCommandChain reports command chaining through newlines, the shape
// that reaches a shell through eval(), os.system() or a templating sink:
//
//	bio=hello%0aid%0als%20-la%20/tmp%0a#vault
//	fullname=Alice Newman%0awhoami%0anecho Injected Text
//
// None of these carries ";" , "&&", "|", "$(" or a backtick, so every existing
// RCE gate returned false and the candidate scored zero hints — analyzeRCE was
// never called on them.
//
// Two or more lines whose first word names an executable are required. A single
// command-named line is not enough: it would fire on any multi-line form field
// that happens to mention a tool.
func rceNewlineCommandChain(text string) bool {
	return rceNewlineCommandScan(text).count >= 2
}

func rceNewlineCommandStats(text string) (count, first int) {
	scan := rceNewlineCommandScan(text)
	return scan.count, scan.first
}

// rceNewlineScan is the allocation-free result of one line-oriented command
// pass. The old implementation called strings.Fields for every non-empty line,
// which allocated millions of short slices while scanning documentation. Keep
// the public/package-local helper semantics unchanged, but let callers that
// need more than the count reuse the same pass.
type rceNewlineScan struct {
	count        int
	first        int
	hasArguments bool
}

func rceNewlineCommandScan(text string) (scan rceNewlineScan) {
	scan.first = -1
	lineNumber := 0
	start := 0
	for start <= len(text) {
		end := start
		for end < len(text) && text[end] != '\n' && text[end] != '\r' {
			end++
		}
		line := strings.TrimSpace(text[start:end])
		command, hasArgument, ok := rceNewlineFirstField(line)
		if ok {
			commandKey := rceLowerCommandToken(command)
			knownCommand := rceCommandNames[commandKey]
			if knownCommand {
				if scan.first < 0 {
					scan.first = lineNumber
				}
				scan.count++
			}
			if hasArgument && (knownCommand || rceCommandTokenKnown(commandKey)) {
				scan.hasArguments = true
			}
		}
		if end < len(text) {
			if text[end] == '\r' && end+1 < len(text) && text[end+1] == '\n' {
				start = end + 2
			} else {
				start = end + 1
			}
		} else {
			start = len(text) + 1
		}
		lineNumber++
	}
	return scan
}

// rceNewlineFirstField mirrors the first two-field decisions made by
// strings.Fields without allocating its result slice. strings.Fields uses
// unicode.IsSpace, so keep that exact rune boundary rather than an ASCII-only
// byte check. The returned command is a subslice of line.
func rceNewlineFirstField(line string) (command string, hasArgument bool, ok bool) {
	if line == "" {
		return "", false, false
	}
	start := 0
	for start < len(line) {
		r, size := utf8.DecodeRuneInString(line[start:])
		if !unicode.IsSpace(r) {
			break
		}
		start += size
	}
	if start >= len(line) {
		return "", false, false
	}
	end := start
	for end < len(line) {
		r, size := utf8.DecodeRuneInString(line[end:])
		if unicode.IsSpace(r) {
			break
		}
		end += size
	}
	command = strings.Trim(line[start:end], "()$;|&><\t")
	if command == "" {
		return "", false, false
	}
	for end < len(line) {
		r, size := utf8.DecodeRuneInString(line[end:])
		if !unicode.IsSpace(r) {
			return command, true, true
		}
		end += size
	}
	return command, false, true
}

// rceLowerCommandToken avoids allocating for the overwhelmingly common
// already-lower ASCII command lines. Uppercase/non-ASCII command tokens retain
// strings.ToLower's historical matching behavior.
func rceLowerCommandToken(command string) string {
	for i := 0; i < len(command); i++ {
		if command[i] >= 'A' && command[i] <= 'Z' {
			return strings.ToLower(command)
		}
		if command[i] >= 0x80 {
			return strings.ToLower(command)
		}
	}
	return command
}

// rceControlCommandView turns decoded C0 separators into line boundaries. It
// is intentionally not a general-purpose normalisation: only an explicit
// command sink may call it, because joining/splitting controls in ordinary
// prose would manufacture shell syntax from documentation text.
func rceControlCommandView(text string) string {
	return strings.Map(func(r rune) rune {
		if r == 0 {
			return '\n'
		}
		return r
	}, text)
}

// rceControlCommandChain recognises a command chain whose separators are
// encoded NUL bytes (for example %00id%00ls+-la). Newline chains are handled by
// rceNewlineCommandChain directly; keeping this helper NUL-specific prevents
// unrelated control characters from becoming shell operators by accident.
func rceControlCommandChain(text string) bool {
	if !strings.ContainsRune(text, 0) {
		return false
	}
	return rceNewlineCommandChain(rceControlCommandView(text))
}

// rceNewlineCommandChainHasArguments reports whether at least one executable
// line carries argv beyond the command name. Bare command names in a prose
// list ("id\nls") are common; flags, paths, or a value after the command are
// the extra evidence that makes a line-oriented payload actionable.
func rceNewlineCommandChainHasArguments(text string) bool {
	return rceNewlineCommandScan(text).hasArguments
}

// rceNewlineDocumentationContext catches short command-reference snippets
// before the broad document-scale guards become applicable. These phrases are
// deliberately sentence-level (rather than single words such as "example")
// so an attacker cannot cheaply suppress a real command chain with one prefix.
func rceNewlineDocumentationContext(text string) bool {
	return rceNewlineDocumentationContextFromScan(text, rceNewlineCommandScan(text))
}

func rceNewlineDocumentationContextFromScan(text string, scan rceNewlineScan) bool {
	if scan.count < 2 {
		return false
	}
	// Suppress only a command list with a documentation heading immediately
	// before the first executable line. A generic word such as "documentation"
	// elsewhere in the value is deliberately ignored; otherwise a controllable
	// prose prefix could suppress a real chain later in the value.
	if scan.first <= 0 {
		return false
	}
	// Preserve strings.Split(text, "\n") indexing exactly (including its
	// historical treatment of CR-only separators), but find the target slice
	// without allocating a lowercased copy of the whole document.
	heading, ok := rceNewlineLFLine(text, scan.first-1)
	if !ok {
		return false
	}
	heading = strings.TrimSpace(heading)
	if !strings.HasSuffix(heading, ":") {
		return false
	}
	for _, marker := range []string{"command", "usage", "reference", "example", "guide", "following"} {
		if rceContainsASCIIFold(heading, marker) {
			return true
		}
	}
	return false
}

// rceNewlineLFLine returns the line that strings.Split(text, "\n") would have
// returned at index, without materialising the slice. This intentionally keeps
// the old LF-only documentation-context semantics while the command scanner
// continues to treat CR and CRLF as line boundaries.
func rceNewlineLFLine(text string, index int) (line string, ok bool) {
	if index < 0 {
		return "", false
	}
	start, lineNo := 0, 0
	for pos := 0; ; pos++ {
		if pos == len(text) || text[pos] == '\n' {
			if lineNo == index {
				return text[start:pos], true
			}
			if pos == len(text) {
				return "", false
			}
			lineNo++
			start = pos + 1
		}
	}
}

func rceContainsASCIIFold(text, needle string) bool {
	if needle == "" {
		return true
	}
	if len(text) < len(needle) {
		return false
	}
	for start := 0; start+len(needle) <= len(text); start++ {
		matched := true
		for offset := 0; offset < len(needle); offset++ {
			c := text[start+offset]
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			if c != needle[offset] {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}

// rceNewlineCommandChainAllowed is the context gate for the otherwise purely
// structural newline detector. Explicit command sinks are authoritative. For
// other fields, command arguments plus the absence of documentation context
// are required; structured fields may still carry a bare two-command chain,
// while unstructured body text must provide arguments to avoid log/prose FPs.
func rceNewlineCommandChainAllowed(text, source, name string) bool {
	view := normalizePreserveControls(text)
	scan := rceNewlineCommandScan(view)
	if scan.count < 2 {
		return false
	}
	if rceExecutionSinkForValue(source, name, text) {
		return true
	}
	if rceNewlineDocumentationContextFromScan(view, scan) {
		return false
	}
	// Long-form security and technical documents are handled by the established
	// shape guards. Use the command window for locality-sensitive signatures.
	window := evidenceWindow(view, []string{"\nid", "\nls", "\ncat", "\nwhoami", "\necho", "\nuname", "\ngrep", "\nhead", "\ntail"})
	if len(text) >= documentScaleThreshold &&
		(securityDocumentContextWindowed(view, window) ||
			(technicalDocumentationContext(view) && technicalDocumentationContext(window))) {
		return false
	}
	if scan.hasArguments {
		return true
	}
	// A parsed query/form/JSON field is already a value boundary. Permit a bare
	// chain there, but keep raw/untyped bodies and generic synthetic candidates
	// conservative (the latter are where logs and documentation arrive).
	switch source {
	case "query", "body.form", "body.json", "body.multipart", "cookie":
		return true
	default:
		return false
	}
}

func rceShellControlEvidenceForContext(lower, source, name string, sink bool) bool {
	if strings.Contains(lower, "$((") {
		lower = rcePureArithmeticExpansion.ReplaceAllString(lower, "")
	}
	if strings.Contains(lower, "$(") || strings.Contains(lower, "&&") || strings.Contains(lower, "||") {
		return true
	}
	// Markdown fenced code uses ``` which must not count as shell backticks.
	text := strings.ReplaceAll(lower, "```", "")
	if !strings.Contains(text, "`") {
		return rceShellMetacharCommandMayMatch(lower) && rceShellMetacharCommand.MatchString(lower)
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
			// not argv[0] of a real command. The basename reduction matters:
			// `/usr/bin/id` is the same command as `id`.
			if len(words) == 1 && rceCommandNames[rceCommandBase(words[0])] &&
				rceInlineCommandContextAllowed(source, name, parts, i, content, sink) {
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

func rceInlineCommandContextAllowed(source, name string, parts []string, segmentIndex int, content string, sink bool) bool {
	if sink {
		return true
	}
	if strings.EqualFold(source, "header") {
		// A bare command in an arbitrary header is too ambiguous to block: header
		// values routinely contain Markdown-like backticks or product metadata.
		// Preserve the known version-fingerprint form and explicit shell/path
		// evidence, while keeping `X-Test: `id`` clean.
		if strings.EqualFold(strings.TrimSpace(name), "user-agent") && rceUserAgentCommandContext(parts, segmentIndex) {
			return true
		}
		if strings.ContainsAny(content, "/\\$()") {
			return true
		}
		outside := rceInlineCodeOuterText(parts)
		return strings.ContainsAny(outside, ";|&$<>=")
	}
	return !rceInlineCodeDocumentationContext(parts, segmentIndex, content)
}

// rceInlineCodeDocumentationContext identifies the sentence-shaped Markdown
// form of a single-word inline code span. A lone command name can be a genuine
// shell substitution (for example `report`whoami“), but short documentation
// sentences routinely write `env`, `rm`, or `ssh` as inline code. Requiring a
// sentence-like surrounding context prevents those words from supplying a
// second RCE reason while preserving command spans with argv, paths, or shell
// punctuation.
func rceInlineCodeDocumentationContext(parts []string, segmentIndex int, content string) bool {
	if strings.ContainsAny(content, "/\\=:$") {
		return false
	}
	before := ""
	if segmentIndex > 0 {
		before = parts[segmentIndex-1]
	}
	after := ""
	if segmentIndex+1 < len(parts) {
		after = parts[segmentIndex+1]
	}
	surrounding := strings.TrimSpace(before + " " + after)
	// Evaluate the whole surrounding sentence with all inline-code segments
	// removed. This handles prose containing multiple command names such as
	// `head` and `tail`, where the first span's immediate neighbours alone do
	// not contain the sentence-ending punctuation.
	outer := rceInlineCodeOuterText(parts)
	if outer != "" {
		surrounding = outer
	}
	if surrounding == "" {
		return false
	}
	// Shell punctuation outside the code span is stronger than sentence shape.
	if strings.ContainsAny(surrounding, ";|&$<>") || strings.Contains(surrounding, "$(") {
		return false
	}
	if !strings.ContainsAny(after+surrounding, ".!?。！？") {
		return false
	}
	if len(tokens(surrounding)) < 2 {
		return false
	}
	// Explicit exploit language should not be downgraded to Markdown prose.
	for _, marker := range []string{"payload", "injection", "attacker", "exploit", "vulnerable", "command substitution", "poc", "cve-", "execution"} {
		if strings.Contains(strings.ToLower(surrounding), marker) {
			return false
		}
	}
	return true
}

func rceInlineCodeOuterText(parts []string) string {
	var builder strings.Builder
	for index, part := range parts {
		if index%2 == 0 {
			builder.WriteString(part)
			builder.WriteByte(' ')
		}
	}
	return strings.TrimSpace(builder.String())
}

func rceUserAgentCommandContext(parts []string, segmentIndex int) bool {
	if segmentIndex <= 0 {
		return false
	}
	prefix := strings.TrimSpace(parts[segmentIndex-1])
	if !strings.Contains(prefix, "/") || !containsASCIIDigit(prefix) {
		return false
	}
	first := strings.ToLower(strings.TrimSpace(strings.Fields(prefix)[0]))
	for _, marker := range []string{"reportgen/", "statuscheck/", "statsclient/", "devcrawler/"} {
		if strings.HasPrefix(first, marker) {
			return true
		}
	}
	// A full browser fingerprint with several product tokens is materially
	// different from a short ordinary `Mozilla/5.0 `id`` value. Keep the rich
	// shape eligible because real command-injection traffic commonly appends the
	// substitution after the complete browser token string.
	return strings.Contains(first, "mozilla/") &&
		(strings.Contains(strings.ToLower(prefix), "webkit/") ||
			strings.Contains(strings.ToLower(prefix), "safari/") ||
			strings.Contains(strings.ToLower(prefix), "trident/") ||
			strings.Contains(strings.ToLower(prefix), "compatible;") ||
			len(strings.Fields(prefix)) >= 4)
}

func rceHardSignal(reasons map[string]bool) bool {
	return reasons["syntax: shell metacharacter plus executable command"] ||
		reasons["syntax: shell control operator or command substitution"] ||
		reasons["syntax: newline-separated command chain"] ||
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
		reasons["semantics: bare command in execution sink"] ||
		reasons["syntax: PHP template execution delimiter"] ||
		reasons["semantics: dynamic loader or reflective code loading primitive"]
}

func rceExecutionSink(name string) bool {
	// Normalize the parameter name as well as the value. Compatibility forms
	// such as fullwidth `ｃｍｄ` are equivalent to `cmd` at the HTTP boundary;
	// leaving the name raw would let the clean-field fast path discard a command
	// value before the sink-aware RCE gate sees it.
	normalized := normalizeRCEFieldName(name)
	if normalized == "" || normalized == "path_query" || normalized == "path" || normalized == "raw_query" || normalized == "body" {
		return false
	}
	terminal := rceSinkTerminalPart(normalized)
	if terminal == "" {
		return false
	}
	// A few established spellings use a file-extension or compound suffix rather
	// than ending in the bare word "cmd"/"command". Keep these exact aliases
	// narrow so ordinary fields such as `command_line` are not matched by a broad
	// substring search.
	switch normalized {
	case "cmd.exe", "command_line", "commandline", "cmdline":
		return true
	}
	// Only an explicit command-parameter suffix opens the sink context. Broad
	// substring matching treated ordinary fields such as script_version,
	// payload_id, and process_name as executable sinks and inflated FPs.
	switch terminal {
	case "cmd", "command", "exec", "execute":
		return true
	}
	return false
}

// rceExecutionSinkForSource grants sink authority only to parsed request-value
// sources. A field name alone is not enough: arbitrary headers, raw bodies and
// URI/path candidates routinely contain documentation or product metadata such
// as `X-Command: id` and must not turn a bare word into a blockable RCE hit.
// Shell syntax remains globally eligible; this gate only controls the
// sink-specific bare/shape evidence.
func rceExecutionSinkForSource(source, name string) bool {
	if !rceExecutionSink(name) {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "query", "body.form", "body.json", "body.multipart", "cookie":
		// A generic JSON action named "execute" is common in documentation and
		// job metadata. Keep that one ambiguous spelling behind ordinary syntax
		// evidence; explicit cmd/command/exec fields remain authoritative.
		if strings.EqualFold(rceSinkTerminalName(name), "execute") && strings.EqualFold(strings.TrimSpace(source), "body.json") {
			return false
		}
		return true
	default:
		return false
	}
}

func rceSinkTerminalName(name string) string {
	normalized := normalizeRCEFieldName(name)
	if normalized == "" {
		return ""
	}
	return rceSinkTerminalPart(normalized)
}

// rceSinkTerminalPart returns the final non-empty field segment without
// allocating a []string. Field names are normalized before reaching this
// helper, and the delimiter set is ASCII, so byte scanning is equivalent to
// the previous FieldsFunc implementation even for UTF-8 names.
func rceSinkTerminalPart(normalized string) string {
	end := len(normalized)
	for end > 0 && isRCEFieldDelimiter(normalized[end-1]) {
		end--
	}
	start := end
	for start > 0 && !isRCEFieldDelimiter(normalized[start-1]) {
		start--
	}
	return normalized[start:end]
}

func isRCEFieldDelimiter(c byte) bool {
	switch c {
	case '.', '_', '-', '[', ']':
		return true
	default:
		return false
	}
}

func rceSinkAllowed(source, name string) bool {
	if strings.TrimSpace(source) == "" {
		// Preserve package-local helper semantics for focused unit tests that pass
		// only a field name; production InputPoints always carry a source and take
		// the stricter branch below.
		return rceExecutionSink(name)
	}
	return rceExecutionSinkForSource(source, name)
}

// normalizeRCEFieldName folds compatibility characters while rejecting control
// characters before normalization. normalize intentionally strips controls from
// values, but doing that to a field name could turn an adversarial `c\x00md`
// into a trusted command sink and would also make the key/value self-comparison
// ambiguous.
func normalizeRCEFieldName(name string) string {
	if strings.TrimSpace(name) == "" {
		return ""
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return ""
		}
	}
	return strings.TrimSpace(normalize(name))
}

// rceBareCommandSinkValue identifies a single known command supplied to an
// explicit command parameter. Punctuation, whitespace, and the parameter key
// itself are excluded so query key candidates such as "cmd" never become
// detections.
func rceBareCommandSinkValue(name, raw string) bool {
	if !rceExecutionSink(name) {
		return false
	}
	value := strings.TrimSpace(normalizePreserveControls(raw))
	if value == "" || value == normalizeRCEFieldName(name) {
		return false
	}
	// A single command may be wrapped by an encoded control boundary (for
	// example %00id). Treat only one non-empty control-delimited segment as a
	// bare sink value; never concatenate segments across the boundary.
	if strings.IndexFunc(value, unicode.IsControl) >= 0 {
		segments := strings.FieldsFunc(value, unicode.IsControl)
		if len(segments) == 1 {
			value = strings.TrimSpace(segments[0])
		} else {
			// A NUL embedded inside one command token is an evasion boundary. Only
			// compact it for an already-authoritative sink, and only when the
			// resulting value is still a single known command. Never do this in
			// ordinary prose or non-sink fields.
			compacted := strings.ReplaceAll(value, "\x00", "")
			if compacted == value {
				return false
			}
			value = strings.TrimSpace(compacted)
		}
	}
	if strings.ContainsAny(value, " \t\r\n;|&$`()=/\\") {
		return false
	}
	return rceCommandTokenKnown(value)
}

func rceBareCommandSinkValueForSource(source, name, raw string) bool {
	if !rceSinkAllowed(source, name) {
		return false
	}
	return rceBareCommandSinkValue(name, raw)
}

// rceCommandSinkShape identifies a multi-word command supplied to an explicit
// command parameter. It is a necessary-condition gate for category guessing,
// not a detector on its own: analyzeRCE still requires the sink context plus a
// command token or a stronger execution signal before emitting a hit.
func rceCommandSinkShape(name, raw string) bool {
	if !rceExecutionSink(name) {
		return false
	}
	value := strings.TrimSpace(normalizePreserveControls(raw))
	if value == "" || value == normalizeRCEFieldName(name) {
		return false
	}
	// Controls introduced by decoding are separators, not characters to erase.
	// Evaluate each segment independently so `id\x00ls -la` recognizes the
	// second command while `please\x00review\x00id` remains prose.
	if strings.IndexFunc(value, unicode.IsControl) >= 0 {
		for _, segment := range strings.FieldsFunc(value, unicode.IsControl) {
			if rceCommandSinkShapeSegment(segment) {
				return true
			}
		}
		// Preserve controls for ordinary matching above, then try a NUL-only
		// compacted view. This recovers tokens split as `po\x00wershell` or
		// `py\x00thon3` while retaining every other control boundary.
		compacted := strings.ReplaceAll(value, "\x00", "")
		if compacted != value && rceCommandSinkShapeSegment(compacted) {
			return true
		}
		return false
	}
	return rceCommandSinkShapeSegment(value)
}

func rceCommandSinkShapeForSource(source, name, raw string) bool {
	if !rceSinkAllowed(source, name) {
		return false
	}
	if rceNarrowSinkAlias(name) {
		return rceCommandSinkHighConfidenceShape(raw)
	}
	return rceCommandSinkShape(name, raw)
}

// rceNarrowSinkAlias identifies compound sink spellings that are common in
// build/job metadata as well as in command dispatch APIs.  Unlike the short
// `cmd`, `command`, and `exec` aliases, these names must not promote every
// executable-looking value (for example `python --version`) to RCE.
func rceNarrowSinkAlias(name string) bool {
	switch normalizeRCEFieldName(name) {
	case "cmd.exe", "command_line", "commandline", "cmdline":
		return true
	default:
		return false
	}
}

// rceExecutionSinkForValue is the value-aware sink context used by the full
// analyzer.  Short aliases retain their historical authority; compound aliases
// require either a bare command or a high-confidence execution shape.  This
// keeps category guessing and reason emission aligned, so merely naming a field
// `command_line` cannot create two RCE reasons for a diagnostic command.
func rceExecutionSinkForValue(source, name, raw string) bool {
	if !rceExecutionSinkForSource(source, name) {
		return false
	}
	if !rceNarrowSinkAlias(name) {
		return true
	}
	return rceBareCommandSinkValue(name, raw) || rceCommandSinkHighConfidenceShape(raw)
}

// rceCommandSinkHighConfidenceShape recognizes only command values that carry
// an unmistakable execution primitive. It is intentionally narrower than the
// legacy command-sink shape gate: normal diagnostics/help/version commands and
// ordinary downloads are not sufficient evidence for compound aliases.
func rceCommandSinkHighConfidenceShape(raw string) bool {
	value := strings.TrimSpace(normalizePreserveControls(raw))
	if value == "" {
		return false
	}
	if strings.IndexFunc(value, unicode.IsControl) >= 0 {
		for _, segment := range strings.FieldsFunc(value, unicode.IsControl) {
			if rceCommandSinkHighConfidenceSegment(segment) {
				return true
			}
		}
		// A literal NUL can split an executable token (`po\x00wershell`). Compact
		// only that byte, then run the same high-confidence grammar. Other control
		// boundaries remain separators and are never erased.
		compacted := strings.ReplaceAll(value, "\x00", "")
		return compacted != value && rceCommandSinkHighConfidenceSegment(compacted)
	}
	return rceCommandSinkHighConfidenceSegment(value)
}

func rceCommandSinkHighConfidenceSegment(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	lower := strings.ToLower(value)

	// These indexed expressions encode complete execution primitives. Exclude
	// the broad shell-command, shell-binary, and inline-interpreter patterns;
	// those are handled below with an argument-level danger check.
	for _, index := range []int{3, 5, 6, 7, 10, 12, 13, 14, 15, 16, 18, 19, 20} {
		if index >= len(rcePatterns) || !rcePatternMayMatch(index, lower) {
			continue
		}
		if guardedMatchString2K(rcePatterns[index], value) {
			// The Windows `/c` grammar intentionally includes ordinary
			// diagnostics such as `dir`, `ping`, and `nslookup`.  Promote it
			// only when the command tail carries an execution, credential,
			// sensitive-file, or chaining primitive.
			if index == 5 && !rceWindowsCommandDangerousArgument(value) {
				continue
			}
			// PowerShell's obfuscation expression is broad enough to match
			// harmless `-join` examples.  Require an argument-level danger
			// signal just as we do for the advanced-flag pattern below.
			if index == 18 && !rcePowerShellDangerousArgument(lower) {
				continue
			}
			return true
		}
	}
	// Advanced PowerShell flags are high-risk only when accompanied by an
	// explicit command/dynamic-execution payload; a lone -nop/-hidden is common
	// in legitimate diagnostics and wrappers.
	if rcePatternMayMatch(17, lower) && guardedMatchString2K(rcePatterns[17], value) &&
		rcePowerShellDangerousArgument(lower) {
		return true
	}

	// Inline interpreters are meaningful when their script invokes a shell,
	// process, evaluator, socket, or a known reconnaissance command. Plain
	// `python -c 'print(1)'` and `python --version` remain benign.
	if rceInterpreterInlineMayMatch(lower) && guardedMatchString2K(rceInterpreterInline, value) &&
		rceInterpreterDangerousArgument(value) {
		return true
	}
	// Shell -c forms receive the same argument-level treatment. This retains
	// `cmd.exe /c whoami` via the indexed Windows pattern above while avoiding
	// broad acceptance of `bash -c echo` in metadata fields.
	if rceShellCInvocation(value) && rceDangerousCommandTail(value) {
		return true
	}
	return false
}

func rcePowerShellDangerousArgument(lower string) bool {
	lower = strings.ToLower(lower)
	for _, marker := range []string{
		"-enc ", "-encodedcommand ", "-encodedcommand=", "iex", "invoke-expression",
		"downloadstring", "downloadfile", "webclient", "frombase64string", "tcpclient",
		"start-process", "invoke-command", "invoke-webrequest", "system.net.sockets",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	// Obfuscation operators are meaningful only when their result is fed to a
	// runtime/command primitive.  A standalone `-join ('a','b')` or `.Replace()`
	// is ordinary scripting/documentation and must stay below the sink gate.
	if strings.Contains(lower, "-join") || strings.Contains(lower, ".replace(") ||
		strings.Contains(lower, ".tochar") || strings.Contains(lower, "[convert]::") {
		if rceContainsAny(lower, "iex", "invoke-", "start-process", "download", "webclient", "frombase64", "system(", "exec(", "shell_exec", "eval(", "tcpclient", "/etc/", "\\windows\\", "whoami") {
			return true
		}
	}
	return rcePowerShellCommandTailDangerous(lower)
}

// rcePowerShellCommandTailDangerous distinguishes a PowerShell command that
// merely prints/help-checks from one that reaches a host command, sensitive
// data, a network/process primitive, or a dynamic evaluator.
func rcePowerShellCommandTailDangerous(lower string) bool {
	lower = strings.ToLower(lower)
	for _, marker := range []string{
		"invoke-expression", "invoke-command",
		"start-process", "downloadstring", "downloadfile", "frombase64string",
		"new-object", "webclient", "tcpclient", "system(", "exec(", "eval(",
		"shell_exec", "child_process", "process.", "-enc ", "-encodedcommand ",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	// Sensitive paths are only execution evidence when a command actually reads
	// them. Output/help commands frequently print the path as an example, e.g.
	// `Write-Output "/etc/passwd"`; classify that as data rather than a file
	// access. The quote-aware command parser handles `Get-Content`, `type`,
	// `cat`, and language-level reads below.
	if commandTailReadsSensitiveFile(lower) {
		return true
	}
	// A command tail is parsed by argv[0] and shell separators. Looking for the
	// word `id` anywhere in the tail is unsound: `Write-Output id` and
	// `echo id` are routine diagnostics. Only a command token (or a nested
	// substitution/side-effect primitive) supplies execution evidence.
	if script := commandArgumentAfterInterpreter(lower); script != "" && commandScriptDangerous(script) {
		return true
	}
	return commandScriptDangerous(lower) ||
		(rceContainsWord(lower, "net user") || rceContainsWord(lower, "net localgroup"))
}

// rceWindowsCommandDangerousArgument extracts the command after `cmd.exe /c`
// (or `/k`) and applies a deliberately small danger vocabulary.  Network and
// host diagnostics are not enough by themselves; chaining, credential/user
// enumeration, sensitive paths, and nested dynamic execution are.
func rceWindowsCommandDangerousArgument(value string) bool {
	fields := strings.Fields(strings.ToLower(value))
	for index := 0; index < len(fields); index++ {
		token := strings.Trim(fields[index], "\"'()<>;&|,")
		if !rceCommandBaseIsShell(token) {
			continue
		}
		if index+1 >= len(fields) {
			return false
		}
		flag := strings.Trim(fields[index+1], "\"'()<>;&|,")
		if flag != "/c" && flag != "/k" {
			continue
		}
		if index+2 >= len(fields) {
			return false
		}
		tail := strings.Join(fields[index+2:], " ")
		return rceWindowsCommandTailDangerous(tail)
	}
	return false
}

func rceWindowsCommandTailDangerous(lower string) bool {
	lower = strings.ToLower(lower)
	for _, marker := range []string{
		"net user", "net localgroup", "certutil", "reg save", "reg query hklm",
		"sc create", "sc config", "taskkill", "wmic process", "powershell -enc",
		"powershell -encodedcommand", "pwsh -enc", "pwsh -encodedcommand",
		"downloadstring", "downloadfile", "invoke-expression", "invoke-command",
		"start-process", "frombase64string", "tcpclient", "child_process",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	// A separator in the command tail means the `/c` wrapper is being used to
	// chain commands, even when the first command is a benign diagnostic.
	if len(splitShellCommandSegments(lower)) > 1 || commandSubstitutionOutsideQuotes(lower) {
		return true
	}
	// Evaluate the command token rather than searching the whole tail for `id`.
	// This keeps `echo id`/`dir` diagnostics clean while retaining `whoami`,
	// `type <sensitive path>`, and chained execution commands.
	return commandScriptDangerous(lower) || commandTailReadsSensitiveFile(lower)
}

func rceInterpreterDangerousArgument(value string) bool {
	lower := strings.ToLower(value)
	for _, marker := range []string{
		"os.system", "os.popen", "subprocess", "popen(", "socket", "pty.",
		"__import__", "eval(", "exec(", "compile(", "child_process", "process.",
		"system(", "shell_exec",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	// Python/Perl/Ruby one-liners often read a sensitive file through a language
	// API rather than invoking `cat`. Require an actual read primitive next to the
	// path; a printed documentation string such as `print('cat /etc/passwd')`
	// remains ordinary output.
	if containsLanguageFileRead(lower) {
		return true
	}
	// The inline-interpreter regexp also covers Windows `cmd.exe /c` forms,
	// whose command list contains benign diagnostics.  Reuse the argument-level
	// Windows gate instead of treating the executable name itself as danger.
	if strings.Contains(lower, "cmd.exe") || strings.Contains(lower, "cmd /c") || strings.Contains(lower, "cmd /k") {
		return rceWindowsCommandDangerousArgument(value)
	}
	// Do not treat a quoted identifier in a harmless script (`print("id")`) as
	// a command.  Inspect the first token after an interpreter flag instead;
	// exact command tails such as `-c id` and `-c 'cat /etc/passwd'` remain high
	// confidence while ordinary print/import scripts stay below the compound-sink
	// threshold.
	if script := commandArgumentAfterInterpreter(value); script != "" && commandScriptDangerous(script) {
		return true
	}
	fields := strings.Fields(value)
	for index := 0; index+1 < len(fields); index++ {
		flag := strings.ToLower(strings.Trim(fields[index], "\"'()"))
		if flag != "-c" && flag != "-e" && flag != "-r" && flag != "-S" {
			continue
		}
		tail := strings.TrimSpace(strings.Join(fields[index+1:], " "))
		tail = strings.Trim(tail, "\"'")
		if tail == "" {
			continue
		}
		first := strings.Trim(strings.Fields(tail)[0], "\"'()")
		switch first {
		case "id", "whoami", "cat", "nc", "ncat", "netcat", "bash", "sh", "powershell", "cmd":
			return true
		}
	}
	return false
}

// commandArgumentAfterInterpreter returns the script/command portion of a
// common interpreter invocation. It deliberately understands only the bounded
// flag forms used by the RCE grammar; arbitrary prose is returned unchanged so
// callers can still apply their normal marker checks.
func commandArgumentAfterInterpreter(value string) string {
	fields := strings.Fields(value)
	for i := 0; i < len(fields); i++ {
		token := strings.Trim(fields[i], "\"'()<>;&|,")
		if !commandInterpreterToken(token) {
			continue
		}
		base := commandInterpreterBase(token)
		// Options such as PowerShell's -NoProfile may precede -Command. Scan a
		// bounded argv prefix instead of requiring the execution flag to be the
		// token immediately following the interpreter.
		for j := i + 1; j < len(fields) && j <= i+8; j++ {
			flag := strings.ToLower(strings.Trim(fields[j], "\"'()<>;&|,"))
			switch flag {
			case "-c", "--command", "-e", "-r", "-s", "/c", "/k", "-command", "-encodedcommand", "-enc", "-encoded":
				if j+1 < len(fields) {
					return strings.TrimSpace(strings.Join(fields[j+1:], " "))
				}
				return ""
			}
			// Most interpreter switches are flag-only. Skip the value of the
			// handful of options that consume one argument, so a value beginning
			// with `-c` cannot be mistaken for the command switch.
			if base == "powershell" || base == "pwsh" {
				switch flag {
				case "-w", "-windowstyle", "-executionpolicy", "-ep", "-file", "-f", "-inputformat", "-outputformat":
					if j+1 < len(fields) {
						j++
					}
				}
			}
		}
	}
	return ""
}

func commandInterpreterBase(token string) string {
	return strings.TrimSuffix(strings.ToLower(rceCommandBase(token)), ".exe")
}

func commandInterpreterToken(token string) bool {
	switch commandInterpreterBase(token) {
	case "bash", "sh", "zsh", "dash", "ksh", "tcsh", "csh", "cmd",
		"powershell", "pwsh", "python", "python3", "perl", "php", "ruby", "node", "lua":
		return true
	default:
		return false
	}
}

// commandScriptDangerous evaluates command segments by their first executable
// token. This is intentionally conservative for output/help/diagnostic
// commands: their arguments are data, so a word such as `id` must not by itself
// create an RCE hit. Nested shell substitutions and sensitive-file reads remain
// strong evidence.
func commandScriptDangerous(script string) bool {
	script = strings.TrimSpace(strings.ToLower(script))
	if script == "" {
		return false
	}
	if commandSubstitutionOutsideQuotes(script) {
		return true
	}
	for _, segment := range splitShellCommandSegments(script) {
		segment = strings.TrimSpace(segment)
		if segment == "" {
			continue
		}
		token, rest := firstCommandToken(segment)
		if token == "" {
			continue
		}
		if commandOutputToken(token) {
			// `print(open(...).read())` is an actual file read, while
			// `print('cat /etc/passwd')` is merely output.
			if containsLanguageFileRead(segment) {
				return true
			}
			continue
		}
		if commandTokenDangerous(token) {
			// The interpreter binary is only a wrapper here. Inspect its explicit
			// command/script argument before classifying the invocation; otherwise
			// harmless `bash -c echo id` and `powershell -Command Write-Output id`
			// are promoted solely because the wrapper name is in the danger list.
			if commandInterpreterToken(token) {
				if nested := commandArgumentAfterInterpreter(segment); nested != "" && commandScriptDangerous(nested) {
					return true
				}
				continue
			}
			if commandDiagnosticToken(token) {
				if containsExecutableFileRead(segment) || commandHasExecutionArgument(rest) {
					return true
				}
				continue
			}
			return true
		}
		// A nested interpreter may be wrapped in a path or assignment. Recurse
		// into its -c/-e argument once, retaining the same bounded grammar.
		if nested := commandArgumentAfterInterpreter(segment); nested != "" && commandScriptDangerous(nested) {
			return true
		}
	}
	return false
}

func commandOutputToken(token string) bool {
	switch strings.TrimSuffix(strings.ToLower(rceCommandBase(token)), ".exe") {
	case "echo", "printf", "print", "println", "write-output", "write-host", "out-host", "format-list", "format-table":
		return true
	default:
		return false
	}
}

func commandDiagnosticToken(token string) bool {
	switch strings.TrimSuffix(strings.ToLower(rceCommandBase(token)), ".exe") {
	case "dir", "ls", "ping", "nslookup", "sleep", "uname", "hostname", "pwd", "env", "printenv",
		// Network probes are common in health checks and build diagnostics.  A
		// plain request is not an execution primitive; download-to-shell chains
		// and sensitive-file reads are handled by the surrounding grammar.
		"curl", "wget", "fetch":
		return true
	default:
		return false
	}
}

func commandTokenDangerous(token string) bool {
	switch strings.TrimSuffix(strings.ToLower(rceCommandBase(token)), ".exe") {
	case "id", "whoami", "cat", "head", "tail", "less", "more", "type", "xxd", "hexdump", "od",
		"curl", "wget", "nc", "ncat", "netcat", "net", "certutil", "reg", "sc", "wmic", "taskkill",
		"bash", "sh", "zsh", "dash", "ksh", "tcsh", "csh", "cmd", "powershell", "pwsh",
		"python", "python3", "perl", "php", "ruby", "node", "lua", "rm", "chmod", "chown", "dd",
		"get-content", "getcontent", "gc", "invoke-expression", "invoke-command", "start-process", "remove-item", "set-content":
		return true
	default:
		return false
	}
}

// commandTailReadsSensitiveFile reports a local sensitive-file read while
// preserving quote-aware command semantics. A URL argument to curl/wget and a
// string printed by echo/Write-Output are data, not local file access.
func commandTailReadsSensitiveFile(value string) bool {
	if !containsCommandSensitivePath(value) {
		return false
	}
	script := value
	if nested := commandArgumentAfterInterpreter(value); nested != "" {
		script = nested
	}
	for _, segment := range splitShellCommandSegments(script) {
		segment = strings.TrimSpace(segment)
		if segment == "" {
			continue
		}
		token, _ := firstCommandToken(segment)
		if token == "" || commandOutputToken(token) || commandDiagnosticToken(token) {
			continue
		}
		if commandInterpreterToken(token) {
			if nested := commandArgumentAfterInterpreter(segment); nested != "" && commandTailReadsSensitiveFile(nested) {
				return true
			}
			continue
		}
		if commandTokenDangerous(token) || containsLanguageFileRead(segment) {
			return true
		}
	}
	return false
}

func containsCommandSensitivePath(value string) bool {
	lower := strings.ToLower(value)
	for _, path := range []string{"/etc/passwd", "/etc/shadow", "/etc/hosts", "/proc/", "/root/", "/var/log/", "\\windows\\win.ini", "\\windows\\system32", "\\users\\", "win.ini", "boot.ini", "web.config", ".env", "secrets"} {
		if strings.Contains(lower, path) {
			return true
		}
	}
	return false
}

func commandHasExecutionArgument(rest string) bool {
	rest = strings.TrimSpace(rest)
	if rest == "" {
		return false
	}
	if containsExecutableFileRead(rest) || commandSubstitutionOutsideQuotes(rest) {
		return true
	}
	// Shell separators inside quoted arguments (notably `&` in a URL query
	// string) are data. splitShellCommandSegments only splits operators outside
	// quotes, so its segment count is the execution-shaped signal we want here.
	return len(splitShellCommandSegments(rest)) > 1
}

func containsExecutableFileRead(value string) bool {
	lower := strings.ToLower(value)
	for _, path := range []string{"/etc/passwd", "/etc/shadow", "/etc/hosts", "/proc/", "/root/", "/var/log/", "\\windows\\win.ini", "\\windows\\system32", "\\users\\", "win.ini", "boot.ini", "web.config", ".env"} {
		if strings.Contains(lower, path) {
			return true
		}
	}
	return false
}

func containsLanguageFileRead(value string) bool {
	lower := strings.ToLower(value)
	if !containsExecutableFileRead(lower) {
		return false
	}
	for _, marker := range []string{"open(", "read(", ".read", "readall", "read_text", "get-content", "getcontent", "fileread", "file_get_contents", "readfile", "streamreader"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func firstCommandToken(segment string) (token, rest string) {
	segment = strings.TrimSpace(segment)
	for len(segment) > 0 && strings.ContainsRune("([{", rune(segment[0])) {
		segment = strings.TrimSpace(segment[1:])
	}
	for {
		fields := strings.Fields(segment)
		if len(fields) == 0 {
			return "", ""
		}
		token = strings.Trim(fields[0], "\"'()<>;&|,`$")
		// Strip shell variable assignments before argv[0].
		if strings.Contains(token, "=") && !strings.HasPrefix(token, "=") {
			segment = strings.TrimSpace(strings.TrimPrefix(segment, fields[0]))
			continue
		}
		prefixLen := len(fields[0])
		if prefixLen >= len(segment) {
			return token, ""
		}
		return token, strings.TrimSpace(segment[prefixLen:])
	}
}

func splitShellCommandSegments(value string) []string {
	segments := make([]string, 0, 4)
	start := 0
	var quote byte
	escaped := false
	for i := 0; i < len(value); i++ {
		c := value[i]
		if escaped {
			escaped = false
			continue
		}
		if quote != 0 {
			if quote == '"' && c == '\\' {
				escaped = true
			} else if c == quote {
				quote = 0
			}
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
			continue
		}
		if c == ';' || c == '\n' || c == '\r' {
			segments = append(segments, value[start:i])
			start = i + 1
			continue
		}
		if c == '|' || c == '&' {
			segments = append(segments, value[start:i])
			if i+1 < len(value) && value[i+1] == c {
				i++
			}
			start = i + 1
		}
	}
	segments = append(segments, value[start:])
	return segments
}

func commandSubstitutionOutsideQuotes(value string) bool {
	var quote byte
	escaped := false
	for i := 0; i < len(value); i++ {
		c := value[i]
		if escaped {
			escaped = false
			continue
		}
		if quote != 0 {
			if quote == '"' && c == '\\' {
				escaped = true
			} else if c == quote {
				quote = 0
			}
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
			continue
		}
		if c == '`' || (c == '$' && i+1 < len(value) && value[i+1] == '(') {
			return true
		}
	}
	return false
}

func rceShellCInvocation(value string) bool {
	lower := strings.ToLower(value)
	fields := strings.Fields(lower)
	for index := 0; index+1 < len(fields); index++ {
		token := strings.Trim(fields[index], "\"'()<>;&|")
		if !rceCommandBaseIsShell(token) {
			continue
		}
		next := strings.Trim(fields[index+1], "\"'()<>;&|")
		if next == "-c" || next == "--command" {
			return true
		}
	}
	return false
}

func rceCommandBaseIsShell(token string) bool {
	token = strings.TrimSuffix(strings.ToLower(rceCommandBase(token)), ".exe")
	switch token {
	case "bash", "sh", "zsh", "dash", "ksh", "tcsh", "csh", "cmd":
		return true
	default:
		return false
	}
}

func rceDangerousCommandTail(value string) bool {
	lower := strings.ToLower(value)
	for _, marker := range []string{
		"/etc/passwd", "/etc/shadow", "/proc/", "/root/", "/var/log/", "/dev/tcp/",
		"net user", "net localgroup", "certutil", "downloadstring", "system(",
		"shell_exec", "eval(", "exec(",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	// Treat only operators outside quotes as command chaining. A literal pipe or
	// ampersand in an argument (for example a documented URL or `echo "a|b"`)
	// is data and should not promote a compound metadata field.
	if len(splitShellCommandSegments(lower)) > 1 || commandSubstitutionOutsideQuotes(lower) {
		return true
	}
	// Do not search the complete wrapper string for short command names: in
	// `bash -c echo id`, `id` is an output argument rather than the command.
	// Parse the explicit interpreter argument and classify its first token.
	if script := commandArgumentAfterInterpreter(lower); script != "" {
		return commandScriptDangerous(script)
	}
	return commandScriptDangerous(lower)
}

func rceContainsWord(text, word string) bool {
	if text == "" || word == "" {
		return false
	}
	text = strings.ToLower(text)
	word = strings.ToLower(word)
	for offset := 0; offset < len(text); {
		rel := strings.Index(text[offset:], word)
		if rel < 0 {
			return false
		}
		start := offset + rel
		end := start + len(word)
		beforeOK := start == 0 || !rceWordByte(text[start-1])
		afterOK := end == len(text) || !rceWordByte(text[end])
		if beforeOK && afterOK {
			return true
		}
		offset = start + 1
	}
	return false
}

func rceWordByte(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= '0' && value <= '9' || value == '_'
}

// rceSinkNULPatternIntentForSource retries the indexed RCE grammar after
// removing only decoded NUL bytes inside an authoritative command sink. NUL is
// a common token-splitting evasion (`po\x00wershell`, `py\x00thon3`); compacting
// it globally would turn ordinary documentation into executable-looking words,
// so this path is deliberately limited to parsed command-value sources.
func rceSinkNULPatternIntentForSource(source, name, raw string) bool {
	if !rceSinkAllowed(source, name) || !strings.ContainsRune(raw, 0) {
		return false
	}
	if rceNarrowSinkAlias(name) {
		return rceCommandSinkHighConfidenceShape(raw)
	}
	value := normalizePreserveControls(raw)
	compacted := strings.ReplaceAll(value, "\x00", "")
	if compacted == value || compacted == "" {
		return false
	}
	lower := strings.ToLower(compacted)
	for index, pattern := range rcePatterns {
		if !rcePatternMayMatch(index, lower) {
			continue
		}
		if guardedMatchString2K(pattern, compacted) {
			return true
		}
	}
	// The auxiliary high-confidence expressions are not all part of the indexed
	// battery (for example the loader and template primitives). Try them only on
	// this narrow, sink-authorized compact view.
	for _, pattern := range []*regexp.Regexp{
		rcePowerShellSideFx,
		rceEncodedPowerShell,
		rceInterpreterInline,
		rceDownloadExecChain,
		rceReverseShellPrimitive,
		rceTemplateExecutionPrimitive,
		rceLoaderPrimitive,
	} {
		if guardedMatchString2K(pattern, compacted) {
			return true
		}
	}
	return false
}

func rceCommandSinkShapeSegment(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	fields := strings.Fields(value)
	if len(fields) < 2 {
		return false
	}
	// Scan the executable prefix so environment assignments such as
	// `FOO=bar /bin/sh -c id` still reach the RCE analyzer without making every
	// arbitrary long value expensive. Once the first non-wrapper token is not a
	// known executable, stop: `cmd=please review id` is prose, not a command.
	limit := len(fields)
	if limit > 5 {
		limit = 5
	}
	for index, field := range fields[:limit] {
		rawToken := strings.ToLower(strings.TrimSpace(strings.Trim(field, "\"'")))
		token := strings.Trim(field, "()$;|&><\"'")
		if token == "" {
			continue
		}
		if rawToken == "$shell" || rawToken == "${shell}" {
			return index+2 < len(fields) && strings.EqualFold(fields[index+1], "-c")
		}
		if rceCommandSinkPrefixToken(token) {
			continue
		}
		if rceCommandTokenKnown(token) {
			return true
		}
		return false
	}
	return false
}

func rceCommandSinkPrefixToken(token string) bool {
	lower := strings.ToLower(strings.TrimSpace(token))
	if rceEnvAssignmentToken(lower) {
		return true
	}
	switch lower {
	case "env", "sudo", "doas", "command", "busybox", "timeout", "nice", "nohup":
		return true
	default:
		return false
	}
}

func rceEnvAssignmentToken(token string) bool {
	eq := strings.IndexByte(token, '=')
	if eq <= 0 {
		return false
	}
	key := token[:eq]
	for i, r := range key {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '_' || (i > 0 && r >= '0' && r <= '9') {
			continue
		}
		return false
	}
	return true
}

// rceCommandTokenKnown is the shared executable vocabulary for command-sink
// shape detection and semantic command-intent scoring. The extra aliases cover
// the binary forms present in rcePatterns without adding them to the backtick
// prose discriminator's deliberately conservative map.
func rceCommandTokenKnown(token string) bool {
	token = strings.TrimSpace(strings.ToLower(rceCommandBase(token)))
	token = strings.TrimSuffix(token, ".exe")
	if rceCommandNames[token] {
		return true
	}
	switch token {
	case "ksh", "tcsh", "csh", "fetch", "lynx", "tftp", "arp", "route", "gawk", "tr", "gunzip", "unxz",
		"ab", "ansible", "chef", "cscli", "visudo", "gpgsm", "ssh-keyscan", "nmap", "expect",
		"scp", "rsync", "sendmail":
		return true
	default:
		return rceVersionedInterpreterToken(token)
	}
}

func rceVersionedInterpreterToken(token string) bool {
	for _, prefix := range []string{"python", "perl", "php", "ruby", "node", "lua"} {
		if !strings.HasPrefix(token, prefix) || len(token) == len(prefix) {
			continue
		}
		suffix := token[len(prefix):]
		for _, r := range suffix {
			if (r >= '0' && r <= '9') || r == '.' {
				continue
			}
			return false
		}
		return true
	}
	return false
}

func analyzeLFI(candidate semanticCandidate) (Hit, bool) {
	// Fold overlong UTF-8 before anything normalises the text.
	//
	// "..%c0%af..%c0%afetc%c0%afpasswd" is a traversal whose separators are
	// written as two-byte UTF-8 encodings of "/". Percent-decoding leaves the
	// raw bytes 0xC0 0xAF, which are not valid UTF-8, and normalize() applies
	// NFKC — which replaces every invalid byte with U+FFFD. The traversal is
	// therefore erased before a single pattern runs, and only the escaped
	// spelling could ever have matched. That spelling does not survive to this
	// point: Go's url.Query() has already decoded the parameter by the time the
	// engine builds its input points, so no candidate carries "%c0%af".
	//
	// Fold it back to the character it encodes and the existing traversal
	// patterns see the payload as the server will.
	text := foldOverlongUTF8(candidate.text)
	if lfiUnicodeSeparatorCandidate(text, candidate.input.Source, candidate.input.Name) {
		if foldedUnicode, ok := foldLFIUnicodeSeparators(text); ok {
			text = foldedUnicode
		}
	}
	if folded, ok := foldLFIHexPathEscapes(text, candidate.input.Source, candidate.input.Name); ok {
		text = folded
	}
	controlBoundary := lfiNullByteInternalBoundary(text)
	pathSuffix := lfiNullBytePathSuffixShape(text)
	explicitPathContext := lfiExplicitPathContext(candidate.input.Source, candidate.input.Name)
	reasons := map[string]bool{}
	for index, pattern := range lfiPatterns {
		// Patterns 3 and 6 are sensitive-target signatures. When a decoded NUL
		// sits inside a command word (c\x00at /etc/passwd), those signatures are
		// documentation evidence rather than a path request. Keep them enabled for
		// explicit file/path fields and for a genuine null-byte path suffix.
		if controlBoundary && !explicitPathContext && !pathSuffix && (index == 3 || index == 6) {
			continue
		}
		if pattern.MatchString(text) {
			reasons["syntax: traversal or wrapper path expression"] = true
		}
	}
	lower := normalize(text)
	if strings.IndexFunc(text, unicode.IsControl) >= 0 {
		// Do not compact decoded control boundaries: doing so turns c\x00at into
		// cat and lets a prose command example satisfy the file-read sink regex.
		lower = normalizePreserveControls(text)
	}
	if lfiEncodedTraversal.MatchString(lower) || strings.Contains(lower, "..//") || strings.Contains(lower, `..\/`) || strings.Contains(lower, "....//") {
		reasons["syntax: encoded or overlong traversal path"] = true
	}
	if pathSuffix {
		reasons["syntax: null-byte path suffix bypass"] = true
	}
	if (!controlBoundary || explicitPathContext || pathSuffix) && lfiSensitiveTarget.MatchString(lower) {
		reasons["semantics: sensitive local file target"] = true
	}
	if lfiWindowsSystemPathMatch(lower) {
		reasons["syntax: Windows drive-absolute path expression"] = true
		reasons["semantics: sensitive local file target"] = true
	}
	if lfiSSIDirective.MatchString(lower) {
		reasons["syntax: server-side include directive"] = true
		reasons["semantics: server evaluates the directive to read a local file or run a command"] = true
	}
	if (!controlBoundary || explicitPathContext) && lfiFileReadSink.MatchString(lower) {
		reasons["semantics: application template reads a local file path"] = true
	}
	if !controlBoundary && lfiCommandReadSink.MatchString(lower) {
		reasons["semantics: command reads a sensitive local file"] = true
	}
	for _, target := range []string{"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/hosts", "/etc/hostname", "/etc/fstab", "/etc/sudoers", "/etc/crontab", "/etc/nginx/nginx.conf", "/etc/apache2/apache2.conf", "/etc/redis/redis.conf", "/etc/mysql/my.cnf", "/etc/php/php.ini", "/etc/ssh/sshd_config", "/proc/self/environ", "/proc/self/cmdline", "/proc/self/maps", "/proc/version", "/proc/cpuinfo", "/root/.bash_history", "boot.ini", "win.ini", "web-inf/web.xml", "meta-inf/manifest.mf", ".htaccess", ".aws/credentials", ".git/config", ".env", ".ssh/id_rsa", "wp-config", "_config.php", "dump.sql", "database.sql", "/var/log/syslog", "/var/log/auth.log", "/var/log/nginx/access.log", "/var/log/apache2/access.log", "httpd-access.log", "/var/run/secrets/kubernetes.io/serviceaccount/token"} {
		if (!controlBoundary || explicitPathContext || pathSuffix) && strings.Contains(lower, target) {
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
		reasons["syntax: server-side include directive"] ||
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

	// Compute the attack-evidence window once; securityDocumentContext and
	// technicalDocumentationContext both run on this window so that a prose
	// prefix + filler padding separated from the payload cannot suppress
	// detection via either guard.
	lfiWin := evidenceWindow(text, []string{
		"../", "....//", `..\/`, ".htaccess",
		"/etc/passwd", "/etc/shadow", "/proc/self", "/root/",
		"php://", "phar://", "zip://", "expect://", "data://",
		".ssh/id_rsa", ".aws/credentials", ".git/config", ".env",
		"web-inf/web.xml", "boot.ini", "win.ini", "wp-config",
		"docker.sock", "/var/log/", "#include", "#exec", "#echo",
		"#fsize", "#flastmod", "#config", "#printenv", "#set",
	})

	// Security document context: reports, writeups, papers, and source files
	// quote paths like /etc/passwd and file:// URIs as subject matter.
	securityDocument := securityDocumentContextWindowed(text, lfiWin)
	if reasons["syntax: server-side include directive"] {
		// SSI directives are themselves the evidence.  A report heading far
		// before the directive must not suppress a later executable request;
		// judge the document-shaped guard on the local directive window while
		// retaining the normal full-document diffuse guards for other LFI forms.
		securityDocument = securityDocumentContextWindowed(lfiWin, lfiWin)
	}
	if securityDocument {
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

	// Technical documentation keyword guard: AND-gate — full document AND local window.
	if technicalDocumentationContext(text) && technicalDocumentationContext(lfiWin) {
		confidence *= 0.7
		if confidence < 0.7 {
			return Hit{}, false
		}
	}

	return hit(candidate, "lfi", engine.SeverityHigh, confidence, reasons), true
}

// lfiNullBytePathSuffixShape accepts null-byte bypasses only when the marker
// terminates or extends a path-like token. A marker embedded in a command word
// (c%00at, new-%00object) is an encoding boundary, not evidence that a file
// path was requested.
func lfiNullBytePathSuffixShape(raw string) bool {
	lower := strings.ToLower(raw)
	for offset := 0; offset < len(lower); {
		index := strings.Index(lower[offset:], "%00")
		markerLen := 3
		if index < 0 {
			if nul := strings.IndexByte(lower[offset:], 0); nul < 0 {
				break
			} else {
				index = nul
				markerLen = 1
			}
		}
		index += offset
		before := lower[:index]
		start := strings.LastIndexAny(before, " \t\r\n=&?;|") + 1
		token := before[start:]
		after := lower[index+markerLen:]
		if after == "" {
			if lfiPathLikeToken(token) || strings.HasSuffix(token, "..") {
				return true
			}
		} else {
			next, _ := utf8.DecodeRuneInString(after)
			if strings.ContainsRune("./?#&/\\", next) && (lfiPathLikeToken(token) || strings.Contains(token, "..") || next == '.') {
				return true
			}
			// A traversal segment can be followed directly by a drive/path
			// component after the NUL (`..%00c:/boot.ini`, `..%00wp-config.php`).
			// The two dots are already a strong path signal even without a slash at
			// the byte immediately following the boundary.
			if strings.HasSuffix(token, "..") &&
				(strings.Contains(after, "/") || strings.Contains(after, "\\") ||
					strings.Contains(after, "boot.ini") || strings.Contains(after, "wp-config") ||
					strings.Contains(after, "passwd") || strings.Contains(after, "shadow")) {
				return true
			}
			if unicode.IsSpace(next) && lfiPathLikeToken(token) {
				return true
			}
		}
		offset = index + markerLen
	}
	return false
}

func lfiPathLikeToken(token string) bool {
	if token == "" {
		return false
	}
	return strings.ContainsAny(token, "/\\") ||
		strings.Contains(token, ".php") || strings.Contains(token, ".jsp") ||
		strings.Contains(token, ".asp") || strings.Contains(token, ".aspx") ||
		strings.Contains(token, ".config") || strings.Contains(token, ".ini") ||
		strings.Contains(token, ".yaml") || strings.Contains(token, ".yml") ||
		strings.Contains(token, ".json") || strings.Contains(token, ".txt")
}

func lfiNullByteInternalBoundary(raw string) bool {
	if !strings.Contains(strings.ToLower(raw), "%00") && !strings.ContainsRune(raw, 0) {
		return false
	}
	return !lfiNullBytePathSuffixShape(raw)
}

func lfiExplicitPathContext(source, name string) bool {
	if strings.EqualFold(source, "uri") {
		return true
	}
	lower := strings.ToLower(strings.TrimSpace(name))
	if lower == "" || lower == "body" || lower == "raw_query" || lower == "path_query" {
		return false
	}
	for _, marker := range []string{"file", "filename", "path", "page", "include", "require", "template", "tpl", "view", "document", "resource", "config"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
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
	filenameSink := false
	for _, part := range parts {
		switch part {
		case "file", "path", "page", "include", "require", "template", "tpl", "doc", "document", "view":
			return true
		case "filename":
			// Browser and telemetry payloads commonly use a `filename` field for
			// ordinary remote media/document URLs. Treat that generic field as an
			// include sink only when the remote target has an executable/template
			// extension; explicit include/page/file sinks remain broad so unusual
			// extensionless RFI payloads are not lost.
			filenameSink = true
		}
	}
	return filenameSink && lfiRemoteExecutableExtensionRE.MatchString(lower)
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
	// A raw body that is nothing but a URL is a fetch target whatever the field
	// is called. This is the one input position where a metadata-service address
	// was previously invisible: the corpora that deliver a bare SSRF target with
	// no request line have it moved into the body by the adapter, and requiring
	// a parameter name meant "169.254.169.254" in the body scored nothing.
	if candidate.input.Source == "body.raw" && ssrfWholeBodyTarget(candidate.text) {
		return true
	}
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

// ssrfWholeBodyTarget reports a body consisting entirely of a single URL.
//
// The "entirely" is the whole point: a URL embedded in a sentence is ordinary
// content, but a body whose every byte is "http://169.254.169.254/latest/meta-data/"
// is a fetch request with nowhere to hide. The length bound keeps it cheap and
// rules out bodies that merely begin with a URL.
func ssrfWholeBodyTarget(text string) bool {
	t := strings.TrimSpace(text)
	if t == "" || len(t) > 512 || !strings.Contains(t, "://") {
		return false
	}
	for i := 0; i < len(t); i++ {
		switch t[i] {
		case ' ', '\t', '\n', '\r':
			return false
		}
	}
	return true
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
	payload := strings.TrimSpace(candidate.text)
	if category == "sqli" {
		payload = truncate(payload, maxSQLPayloadBytes)
	}
	return Hit{
		Category:   category,
		Source:     candidate.input.Source,
		Name:       candidate.input.Name,
		Syntax:     syntaxText,
		Semantics:  semanticsText,
		Severity:   severity,
		Confidence: confidence,
		Payload:    payload,
		Isolation:  classifyPayloadIsolation(candidate.text),
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
	// 0=record-only, 1=low: never block.
	if a.paranoiaLevel <= 1 {
		return false
	}

	if h.Category == "" || h.Payload == "" {
		return false
	}
	// Embedded (gadget inside other text) blocks only at 5.
	if h.Isolation == isolationEmbedded && a.paranoiaLevel < 5 {
		return false
	}
	syntaxOK := h.Syntax != "" && !strings.HasSuffix(h.Syntax, "none") && !strings.Contains(h.Syntax, "attack grammar matched")
	semanticsOK := h.Semantics != "" && !strings.HasSuffix(h.Semantics, "none") && !strings.Contains(h.Semantics, "malicious behavior inferred from context")

	// Levels 2-5 share the same evidence bar. Isolation already decided
	// whether an embedded gadget may block (5 only).
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
			strings.Contains(h.Syntax, "quoted AND SELECT") ||
			strings.Contains(h.Syntax, "quoted concatenation SELECT") ||
			strings.Contains(h.Syntax, "comment") ||
			strings.Contains(h.Syntax, "token fingerprint") ||
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
			strings.Contains(reason, "quoted AND SELECT") ||
			strings.Contains(reason, "quoted concatenation SELECT") ||
			strings.Contains(reason, "comment") ||
			strings.Contains(reason, "token fingerprint") ||
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
	// "header" matters more than it looks. A dozen verified misses carried the
	// entire attack in a custom "X-User-Filter" header holding
	// {"$where": "if(this.isAdmin){...}"} while the URL and body were ordinary
	// traffic — and because headers were absent here, NoSQL analysis was skipped
	// for every header on every request. A WAF cannot treat headers as second
	// class: they are attacker-controlled input like any other.
	switch source {
	case "query", "body.form", "body.json", "body.raw", "cookie", "header":
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

// nosqlInjectionOperatorNames is the subset of bracketed query operators that
// no ordinary client has a reason to send. The comparison and negation families
// exist to widen, invert or compute a server-side predicate, which is precisely
// the attack; the range and set families ($gt, $lt, $in, $all, $and, $or) also
// appear in legitimate multi-value filters, so those stay behind the
// sensitive-field gate rather than being trusted on their own.
//
// Splitting the two is what lets "?apikey[$ne]=xyz" and "?secret[$ne]=guessme"
// be detected: both are authentication-bypass injections, and neither field name
// was in nosqlSensitiveContext, so the analyzer used to require a sensitive
// context, decline, and drop them.
var nosqlInjectionOperatorNames = []string{
	"$ne", "$nin", "$not", "$nor", "$where", "$function", "$eval",
	"$expr", "$regex", "$exists", "$set", "$unset", "$jsonschema",
}

// nosqlInjectionOperatorInPath reports a bracketed operator from the subset
// above in a parameter or JSON path.
func nosqlInjectionOperatorInPath(value string) bool {
	lower := strings.ToLower(value)
	for _, op := range nosqlInjectionOperatorNames {
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
