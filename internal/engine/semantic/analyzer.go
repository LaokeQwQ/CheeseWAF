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
	"sort"
	"strconv"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine/decoder"
)

const maxSemanticInputBytes = 256 * 1024

type Analyzer struct {
	mode    string
	enabled map[string]bool
}

type InputPoint struct {
	Source string   `json:"source"`
	Name   string   `json:"name"`
	Raw    string   `json:"raw"`
	Layers []string `json:"layers"`
}

type AnalysisReport struct {
	Inputs []InputPoint `json:"inputs"`
	Hits   []Hit        `json:"hits"`
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
		for _, category := range []string{"sqli", "xss", "rce", "lfi", "xxe", "ssrf"} {
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
	return &Analyzer{mode: mode, enabled: enabled}
}

func (a *Analyzer) ID() string    { return "semantic.analyzer" }
func (a *Analyzer) Name() string  { return "Staged Semantic Analyzer" }
func (a *Analyzer) Priority() int { return 290 }

func (a *Analyzer) Detect(_ context.Context, reqCtx *engine.RequestContext) (*engine.DetectionResult, error) {
	if reqCtx == nil || reqCtx.Request == nil || a.mode == "off" {
		return nil, nil
	}
	candidates := extractCandidates(reqCtx)
	report := AnalysisReport{}
	best := (*Hit)(nil)
	for _, candidate := range candidates {
		report.Inputs = append(report.Inputs, candidate.input)
		for _, hit := range a.analyzeCandidate(candidate) {
			report.Hits = append(report.Hits, hit)
			if best == nil || hit.Confidence > best.Confidence || hit.Severity > best.Severity {
				hit := hit
				best = &hit
			}
		}
	}
	reqCtx.Metadata["semantic_analysis"] = report
	if best == nil {
		return nil, nil
	}
	return &engine.DetectionResult{
		Detected:   true,
		DetectorID: a.ID() + "." + best.Category,
		Category:   best.Category,
		Severity:   best.Severity,
		Action:     actionForMode(a.mode),
		Message:    best.Syntax + "; " + best.Semantics,
		Confidence: best.Confidence,
		Payload:    best.Payload,
	}, nil
}

func (a *Analyzer) analyzeCandidate(candidate semanticCandidate) []Hit {
	guesses := guessCategories(candidate.text)
	if len(guesses) == 0 {
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
	return hits
}

func extractCandidates(reqCtx *engine.RequestContext) []semanticCandidate {
	if reqCtx == nil || reqCtx.Request == nil {
		return nil
	}
	var inputs []InputPoint
	r := reqCtx.Request
	inputs = append(inputs, InputPoint{Source: "uri", Name: "path_query", Raw: r.URL.RequestURI(), Layers: []string{"raw"}})
	for key, values := range r.URL.Query() {
		inputs = append(inputs, InputPoint{Source: "query", Name: key, Raw: key, Layers: []string{"raw"}})
		for _, value := range values {
			inputs = append(inputs, InputPoint{Source: "query", Name: key, Raw: value, Layers: []string{"raw"}})
		}
	}
	for key, values := range r.Header {
		if skipHeader(key) {
			continue
		}
		for _, value := range values {
			inputs = append(inputs, InputPoint{Source: "header", Name: key, Raw: value, Layers: []string{"raw"}})
		}
	}
	for _, cookie := range r.Cookies() {
		inputs = append(inputs, InputPoint{Source: "cookie", Name: cookie.Name, Raw: cookie.Value, Layers: []string{"raw"}})
	}
	inputs = append(inputs, bodyInputs(r, reqCtx.DecodedBody)...)

	var candidates []semanticCandidate
	seen := map[string]struct{}{}
	for _, input := range inputs {
		for _, variant := range decodeVariants(input.Raw) {
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

func bodyInputs(r *http.Request, body []byte) []InputPoint {
	if len(body) == 0 {
		return nil
	}
	if len(body) > maxSemanticInputBytes {
		body = body[:maxSemanticInputBytes]
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
	flattenJSONValue(source, prefix, value, inputs)
}

func flattenJSONValue(source, prefix string, value any, inputs *[]InputPoint) {
	switch typed := value.(type) {
	case map[string]any:
		for key, value := range typed {
			name := key
			if prefix != "" {
				name = prefix + "." + key
			}
			*inputs = append(*inputs, InputPoint{Source: source, Name: name, Raw: key, Layers: []string{"raw"}})
			flattenJSONValue(source, name, value, inputs)
		}
	case []any:
		for idx, value := range typed {
			flattenJSONValue(source, prefix+"[]", value, inputs)
			_ = idx
		}
	case string:
		*inputs = append(*inputs, InputPoint{Source: source, Name: prefix, Raw: typed, Layers: []string{"raw"}})
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
		name := part.FormName()
		if name == "" {
			name = part.FileName()
		}
		if name == "" {
			name = "part"
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
	queue := []decodedVariant{{text: raw, layers: []string{"raw"}}}
	var out []decodedVariant
	seen := map[string]struct{}{}
	for len(queue) > 0 && len(out) < 24 {
		item := queue[0]
		queue = queue[1:]
		if _, ok := seen[item.text]; ok {
			continue
		}
		seen[item.text] = struct{}{}
		out = append(out, item)
		if len(item.layers) >= 6 {
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
	text := normalize(raw)
	text = sqlBlockComment.ReplaceAllString(text, "")
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

func guessCategories(raw string) []string {
	text := normalize(raw)
	ordered := []string{"sqli", "xss", "rce", "lfi", "xxe", "ssrf"}
	scores := map[string]int{}
	sqlCompact := compactSQL(text)
	if strings.Contains(text, "select") || strings.Contains(text, "union") || strings.Contains(text, " or ") || strings.Contains(text, "sleep(") || strings.Contains(text, "waitfor") || strings.Contains(text, "information_schema") || strings.Contains(text, "drop table") || strings.Contains(text, "delete from") || strings.Contains(text, "xp_cmdshell") || strings.Contains(text, "load_file") || strings.Contains(text, "into outfile") || strings.Contains(sqlCompact, "unionselect") || strings.Contains(sqlCompact, "or1=1") {
		scores["sqli"] += 2
	}
	if strings.Contains(text, "<script") || strings.Contains(text, ":script") || strings.Contains(text, "javascript:") || xssEventPattern.MatchString(text) || strings.Contains(text, "<svg") || strings.Contains(text, "<iframe") || strings.Contains(text, "<img") || strings.Contains(text, "<xss") {
		scores["xss"] += 2
	}
	if strings.Contains(text, ";") || strings.Contains(text, "&&") || strings.Contains(text, "|") || strings.Contains(text, "$(") || strings.Contains(text, "`") || strings.Contains(text, "$shell") || strings.Contains(text, "/usr/bin/") || strings.Contains(text, "/bin/") || strings.Contains(text, "cmd.exe") || strings.Contains(text, "powershell") || strings.Contains(text, "wget ") || strings.Contains(text, "curl ") || strings.Contains(text, "python -c") || strings.Contains(text, "php -r") || strings.Contains(text, "perl -e") {
		scores["rce"] += 2
	}
	if strings.Contains(text, "../") || strings.Contains(text, `..\`) || strings.Contains(text, "/etc/passwd") || strings.Contains(text, "boot.ini") || strings.Contains(text, "win.ini") || strings.Contains(text, "file://") || strings.Contains(text, "php://") || strings.Contains(text, ".aws/") || strings.Contains(text, ".git/") || strings.Contains(text, ".env") || strings.Contains(text, "wp-config") || strings.Contains(text, ".ssh/") {
		scores["lfi"] += 2
	}
	if strings.Contains(text, "<!doctype") || strings.Contains(text, "<!entity") {
		scores["xxe"] += 2
	}
	if urlLikePattern.MatchString(text) || strings.Contains(text, "169.254.169.254") || strings.Contains(text, "metadata.google.internal") {
		scores["ssrf"] += 2
	}
	var guesses []string
	for _, category := range ordered {
		if scores[category] > 0 {
			guesses = append(guesses, category)
		}
	}
	return guesses
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
	default:
		return Hit{}, false
	}
}

var (
	sqlBooleanTautology  = regexp.MustCompile(`(?i)(?:'|"|\b)\s*(?:or|and)\s+(?:'?\d+'?|[a-z_][a-z0-9_]*|'[^']*')\s*=\s*(?:'?\d+'?|[a-z_][a-z0-9_]*|'[^']*')`)
	sqlTimeFunction      = regexp.MustCompile(`(?i)(?:\b(?:sleep|benchmark|pg_sleep)\s*\(|\bwaitfor\s+delay\b)`)
	sqlComment           = regexp.MustCompile(`(?i)(?:--|#|/\*)`)
	sqlDangerousFunc     = regexp.MustCompile(`(?i)\b(?:xp_cmdshell|load_file|into\s+outfile|copy\s+.+\s+to\s+program)\b`)
	sqlErrorFunction     = regexp.MustCompile(`(?i)\b(?:extractvalue|updatexml|xmltype|ctxsys\.drithsx\.sn|utl_inaddr\.get_host_name)\s*\(`)
	sqlStringFunction    = regexp.MustCompile(`(?i)\b(?:char|chr|concat|concat_ws|nchar|ascii|substring|substr)\s*\(`)
	sqlComparison        = regexp.MustCompile(`(?i)(?:=|<>|!=|<=>|\blike\b|\bin\b)`)
	xssEventPattern      = regexp.MustCompile(`(?i)\bon[a-z0-9_-]{3,}\s*=`)
	unicodeEscapePattern = regexp.MustCompile(`\\(?:u([0-9a-fA-F]{4})|x([0-9a-fA-F]{2}))`)
	sqlBlockComment      = regexp.MustCompile(`(?is)/\*.*?\*/`)
	sqlLineComment       = regexp.MustCompile(`(?m)--[^\r\n]*`)
)

func analyzeSQL(candidate semanticCandidate) (Hit, bool) {
	text := candidate.text
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
	if sqlTimeFunction.MatchString(text) {
		reasons["semantics: time-based database side effect"] = true
	}
	if containsOrdered(words, "information_schema") || containsOrdered(words, "pg_catalog") {
		reasons["semantics: database metadata enumeration"] = true
	}
	if (contains(words, "drop") && contains(words, "table")) || (contains(words, "delete") && contains(words, "from")) {
		reasons["semantics: destructive database operation"] = true
	}
	if sqlComment.MatchString(text) && (contains(words, "or") || contains(words, "union") || contains(words, "select")) {
		reasons["syntax: SQL comment used to truncate query"] = true
	}
	if sqlDangerousFunc.MatchString(text) {
		reasons["semantics: database server file or command side effect"] = true
	}
	if sqlErrorFunction.MatchString(text) && (contains(words, "select") || contains(words, "concat") || strings.Contains(compact, "select")) {
		reasons["semantics: error-based database function with query composition"] = true
	}
	if sqlStringFunction.MatchString(text) && sqlComparison.MatchString(text) && (contains(words, "or") || contains(words, "and") || strings.Contains(compact, "orchar") || strings.Contains(compact, "andchar")) {
		reasons["syntax: SQL function comparison inside boolean predicate"] = true
	}
	if len(reasons) == 0 {
		return Hit{}, false
	}
	return hit(candidate, "sqli", engine.SeverityHigh, 0.88+confidenceBonus(reasons), reasons), true
}

func analyzeXSS(candidate semanticCandidate) (Hit, bool) {
	text := candidate.text
	reasons := map[string]bool{}
	for _, pattern := range xssPatterns {
		if pattern.MatchString(text) {
			reasons["syntax: executable HTML/JavaScript context"] = true
		}
	}
	lower := normalize(text)
	if javascriptURLContext.MatchString(lower) {
		reasons["syntax: javascript URL in executable HTML attribute"] = true
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
	reasons := map[string]bool{}
	for _, pattern := range rcePatterns {
		if pattern.MatchString(text) {
			reasons["syntax: shell metacharacter plus executable command"] = true
		}
	}
	words := tokens(text)
	for _, command := range []string{"cat", "id", "whoami", "uname", "curl", "wget", "bash", "sh", "powershell", "cmd", "python", "python3", "perl", "php", "ruby", "node", "nc", "ncat", "netcat", "socat", "lua"} {
		if contains(words, command) {
			reasons["semantics: command execution intent"] = true
			break
		}
	}
	if strings.Contains(normalize(text), "/usr/bin/") || strings.Contains(normalize(text), "/bin/") || strings.Contains(text, "$SHELL") || strings.Contains(text, "${SHELL}") {
		reasons["semantics: fully qualified executable or shell interpreter"] = true
	}
	if len(reasons) < 2 {
		return Hit{}, false
	}
	return hit(candidate, "rce", engine.SeverityCritical, 0.87+confidenceBonus(reasons), reasons), true
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
	for _, target := range []string{"/etc/passwd", "/etc/shadow", "/proc/self/environ", "boot.ini", "win.ini", "web-inf/web.xml", ".aws/credentials", ".git/config", ".env", ".ssh/id_rsa", "wp-config"} {
		if strings.Contains(lower, target) {
			reasons["semantics: sensitive local file target"] = true
			break
		}
	}
	if len(reasons) == 0 {
		return Hit{}, false
	}
	return hit(candidate, "lfi", engine.SeverityHigh, 0.85+confidenceBonus(reasons), reasons), true
}

func analyzeXXE(candidate semanticCandidate) (Hit, bool) {
	text := candidate.text
	lower := normalize(text)
	reasons := map[string]bool{}
	if strings.Contains(lower, "<!doctype") && strings.Contains(lower, "<!entity") {
		reasons["syntax: XML DTD with entity declaration"] = true
	}
	if strings.Contains(lower, "system") || strings.Contains(lower, "public") {
		reasons["semantics: external entity resolution"] = true
	}
	if strings.Contains(lower, "file://") || strings.Contains(lower, "http://") || strings.Contains(lower, "https://") {
		reasons["semantics: file or network disclosure target"] = true
	}
	if len(reasons) < 2 {
		return Hit{}, false
	}
	return hit(candidate, "xxe", engine.SeverityHigh, 0.84+confidenceBonus(reasons), reasons), true
}

func analyzeSSRF(candidate semanticCandidate) (Hit, bool) {
	payload := decoder.Decode(candidate.text).Text
	for _, rawURL := range urlLikePattern.FindAllString(payload, -1) {
		parsed, err := url.Parse(rawURL)
		if err != nil || parsed.Hostname() == "" {
			continue
		}
		if isInternalHost(parsed.Hostname()) {
			return Hit{
				Category:   "ssrf",
				Source:     candidate.input.Source,
				Name:       candidate.input.Name,
				Syntax:     "syntax: URL parameter accepted by request",
				Semantics:  "semantics: target resolves to loopback, private, link-local, or metadata network",
				Severity:   engine.SeverityHigh,
				Confidence: 0.86,
				Payload:    rawURL,
			}, true
		}
	}
	return Hit{}, false
}

func hit(candidate semanticCandidate, category string, severity engine.Severity, confidence float64, reasons map[string]bool) Hit {
	parts := sortedReasons(reasons)
	var syntax, semantics []string
	for _, reason := range parts {
		if strings.HasPrefix(reason, "syntax:") {
			syntax = append(syntax, strings.TrimSpace(strings.TrimPrefix(reason, "syntax:")))
		}
		if strings.HasPrefix(reason, "semantics:") {
			semantics = append(semantics, strings.TrimSpace(strings.TrimPrefix(reason, "semantics:")))
		}
	}
	if len(syntax) == 0 {
		syntax = append(syntax, "attack grammar matched")
	}
	if len(semantics) == 0 {
		semantics = append(semantics, "malicious behavior inferred from context")
	}
	if confidence > 0.99 {
		confidence = 0.99
	}
	return Hit{
		Category:   category,
		Source:     candidate.input.Source,
		Name:       candidate.input.Name,
		Syntax:     "syntax: " + strings.Join(syntax, ", "),
		Semantics:  "semantics: " + strings.Join(semantics, ", "),
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
	case "accept", "accept-encoding", "accept-language", "connection", "content-length", "content-type", "host":
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
