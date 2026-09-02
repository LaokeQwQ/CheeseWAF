package security

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// CategoryGeneric is the reporting bucket for attack classes the semantic engine
// does not model: request smuggling, LDAP injection, deserialization gadgets and
// the "other" catch-all used by several bulk-imported datasets. Those samples are
// still counted as attacks for TPR — the bucket only affects the per-category
// breakdown, never detection itself.
const CategoryGeneric = "generic"

// DetectionCategories is the exact category set the semantic engine can emit.
// analyzer.go iterates this same list; keep the two in sync.
var DetectionCategories = []string{
	"sqli", "xss", "rce", "lfi", "xxe", "ssrf", "nosqli", "ssti", "webshell", "log4shell",
}

// rawCategoryAliases maps the attack-class spellings found in bulk-imported
// public datasets onto DetectionCategories. Keys are canonicalised (lowercased,
// non-alphanumerics stripped) before lookup.
var rawCategoryAliases = map[string]string{
	// SQL injection
	"sqli": "sqli", "sql": "sqli", "sqlinjection": "sqli", "sqlinjections": "sqli",
	// Cross-site scripting
	"xss": "xss", "crosssitescripting": "xss", "reflectedxss": "xss", "storedxss": "xss",
	// Remote command execution
	"rce": "rce", "cmdi": "rce", "commandinjection": "rce", "codeinjection": "rce",
	"codeexec": "rce", "oscommand": "rce",
	// Local file inclusion / path traversal
	"lfi": "lfi", "path": "lfi", "pathtraversal": "lfi", "traversal": "lfi",
	"fileinclusion": "lfi", "directorytraversal": "lfi", "rfi": "lfi", "file": "lfi",
	// Server-side request forgery
	"ssrf": "ssrf",
	// NoSQL injection
	"nosqli": "nosqli", "nosql": "nosqli", "nosqlinjection": "nosqli",
	// Server-side template injection
	"ssti": "ssti", "template": "ssti", "templateinjection": "ssti", "sstiinjection": "ssti",
	// XML external entity
	"xxe": "xxe", "xml": "xxe", "xmlexternalentity": "xxe",
	// Webshell
	"webshell": "webshell", "shell": "webshell", "web shell": "webshell",
	// Log4Shell / JNDI
	"log4shell": "log4shell", "log4j": "log4shell", "jndi": "log4shell",
	// Not modelled by the engine — grouped, still counted as attacks.
	"protocol": CategoryGeneric, "smuggling": CategoryGeneric, "requestsmuggling": CategoryGeneric,
	"httpsmuggling": CategoryGeneric, "httpdesync": CategoryGeneric, "ldap": CategoryGeneric,
	"ldapinjection": CategoryGeneric, "deserialization": CategoryGeneric, "insecuredeserialization": CategoryGeneric,
	"other": CategoryGeneric, "unknown": CategoryGeneric, "misc": CategoryGeneric, "": CategoryGeneric,
}

// RawHTTPCase is the lowercase, HTTP-shaped record schema used by the
// bulk-imported public payload collections (ai_waf, httpparams, waf_detection,
// aetherguard). It is deliberately separate from Case because the two schemas
// disagree on three things:
//
//   - the request line is `url` + `data`, not `target` + `body`;
//   - `headers` is a raw HTTP header block string, not a JSON object;
//   - `label` carries the attack class ("sqli", "xss", …) rather than the
//     benign/attack ground truth, which these corpora encode in the file name.
type RawHTTPCase struct {
	Method  string `json:"method"`
	URL     string `json:"url"`
	Data    string `json:"data"`
	Headers string `json:"headers"`
	Label   string `json:"label"`
	Source  string `json:"source"`

	// Optional, corpus-specific. aetherguard records mark 34 samples whose
	// upstream dataset itself does not expect a WAF to fire; callers use this
	// to report those separately instead of burying them in the miss count.
	ExpectedDetection *bool `json:"expected_detection"`
}

// CaseName synthesises a stable identifier for records that ship without one.
// It is used for shard stability and for failure reports only.
func (r RawHTTPCase) CaseName(lineNo int) string {
	source := strings.TrimSpace(r.Source)
	if source == "" {
		source = "raw-http"
	}
	return fmt.Sprintf("%s#%d", source, lineNo)
}

// NormalizeTarget turns a corpus request line into a target url.Parse accepts.
// Several collections store a bare payload with no leading slash
// ("uNiOn/**/SeLeCt/**/1,2,3--%0a"): url.Parse treats that as a relative
// reference, which is legal, but the engine then sees an empty Path and the
// payload lands nowhere useful. Prefixing a slash keeps the payload intact.
//
// Targets that still do not parse are not repaired here: AdaptRawHTTPCase moves
// those payloads into the request body instead, which accepts arbitrary bytes
// and therefore loses nothing.
func NormalizeTarget(raw string) string {
	target := strings.TrimSpace(raw)
	switch {
	case target == "":
		return "/"
	case strings.HasPrefix(target, "/"), strings.Contains(target, "://"):
		return target
	default:
		return "/" + target
	}
}

// parsesAsURL reports whether s is a request target Go can construct a request
// from. url.Parse rejects, among others, invalid percent escapes ("%&(") and
// control characters smuggled into a URI's host ("javascript://%0d%0aalert(1)").
func parsesAsURL(s string) bool {
	_, err := url.Parse(s)
	return err == nil
}

// ParseHeaderBlock parses a raw HTTP header block ("Host: x\r\nAccept: y") into
// a header map. Lines without a colon are skipped rather than failing the whole
// record: these corpora are bulk imports, and one stray line must not silently
// drop an entire attack sample.
func ParseHeaderBlock(block string) map[string]string {
	headers := make(map[string]string)
	for _, line := range strings.Split(block, "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		if line == "" {
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		if name == "" || !validHeaderFieldName(name) {
			continue
		}
		canonical := http.CanonicalHeaderKey(name)
		value = strings.TrimSpace(value)
		if previous, exists := headers[canonical]; exists {
			// Preserve every value in deterministic order. Governance separately
			// hard-quarantines this input shape; joining here prevents the adapter
			// from silently discarding the first occurrence before that audit runs.
			headers[canonical] = previous + ", " + value
		} else {
			headers[canonical] = value
		}
	}
	if len(headers) == 0 {
		return nil
	}
	return headers
}

// validHeaderFieldName rejects header names that Go would refuse to encode,
// so a hostile corpus record cannot poison the request construction.
func validHeaderFieldName(name string) bool {
	return isHTTPToken(name)
}

func isTokenByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	switch c {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		return true
	}
	return false
}

// NormalizeCategory maps a source-specific attack-class label onto the engine's
// detection categories. Unrecognised classes become CategoryGeneric.
func NormalizeCategory(label string) string {
	key := canonicalCategoryKey(label)
	if mapped, ok := rawCategoryAliases[key]; ok {
		return mapped
	}
	for _, category := range DetectionCategories {
		if category == key {
			return category
		}
	}
	return CategoryGeneric
}

func canonicalCategoryKey(label string) string {
	var b strings.Builder
	b.Grow(len(label))
	for i := 0; i < len(label); i++ {
		c := label[i]
		switch {
		case c >= 'a' && c <= 'z':
			b.WriteByte(c)
		case c >= 'A' && c <= 'Z':
			b.WriteByte(c + ('a' - 'A'))
		case c >= '0' && c <= '9':
			b.WriteByte(c)
		}
	}
	return b.String()
}

// Repair markers set in Case.Rationale. Both mean "this row was measured, but
// not in the request position the corpus intended" — callers surface the counts
// so a repaired subset can never be mistaken for a clean one.
const (
	// RationaleRepairedSplitPayload marks a row whose payload was split across
	// `method`/`url` and rebuilt from the intact `data` field.
	RationaleRepairedSplitPayload = "repaired: split-payload row"
	// RationaleRepairedToBody marks a row whose request target could not be
	// expressed as a URL at all, so the payload was moved into the body.
	RationaleRepairedToBody = "repaired: unroutable target moved to body"
)

// IsHTTPMethod reports whether s can be used as an HTTP request method.
//
// The aetherguard corpus was generated by splitting each payload at its first
// space and storing the head in `method`, so rows like
// {"method":"X-Rewrite-URL:","url":"/admin","data":"X-Rewrite-URL: /admin"}
// carry a payload fragment where a verb belongs. Those rows keep the intact
// payload in `data`, which is what makes the repair below lossless.
func IsHTTPMethod(s string) bool {
	return isHTTPToken(s)
}

// isHTTPToken reports whether s is a valid RFC 7230 token: the character set
// both request methods and header field names are restricted to.
func isHTTPToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isTokenByte(s[i]) {
			return false
		}
	}
	return true
}

// AdaptRawHTTPCase converts one bulk-imported record into a Case.
//
// defaultTruth supplies the ground truth for the whole file ("attack" or
// "benign"): these datasets split benign and attack into separate files and use
// `label` for the attack class instead. When defaultTruth is "benign" the record
// label is ignored. When it is "attack" the label is normalised into Category.
// An empty defaultTruth falls back to the record label when that label is itself
// "attack" or "benign".
//
// Rows carrying a payload fragment in `method` are repaired into a POST to "/"
// with the intact `data` payload as the body, and marked with
// RationaleRepairedSplitPayload so callers can count them. Discarding them
// instead would quietly shrink the attack denominator — and since these are
// exactly the exotic samples a WAF is most likely to miss, dropping them makes
// the measured TPR look better than it is.
//
// Rows whose target cannot be expressed as a URL at all are repaired the same
// way, into a POST to "/", and marked with RationaleRepairedToBody.
//
// What remains genuinely unadaptable is a row that carries no usable ground
// truth (an empty defaultTruth plus a label that is neither "attack" nor
// "benign"). Those are returned as an error so callers count and report them
// rather than losing them to the same silent hole.
func AdaptRawHTTPCase(raw RawHTTPCase, name string, defaultTruth string) (Case, error) {
	truth := strings.ToLower(strings.TrimSpace(defaultTruth))
	if truth == "" {
		truth = strings.ToLower(strings.TrimSpace(raw.Label))
	}
	if truth != "attack" && truth != "benign" {
		return Case{}, fmt.Errorf("case %q: unsupported ground truth %q", name, defaultTruth)
	}

	method := strings.ToUpper(strings.TrimSpace(raw.Method))
	target := NormalizeTarget(raw.URL)
	body := raw.Data
	rationale := ""

	switch {
	case !IsHTTPMethod(method):
		// Corrupt row: `data` holds the whole payload, `method`/`url` are the
		// fragments left over from splitting it on whitespace.
		body = firstNonEmpty(raw.Data, strings.TrimSpace(raw.Method)+" "+strings.TrimSpace(raw.URL))
		method, target, rationale = http.MethodPost, "/", RationaleRepairedSplitPayload

	case !parsesAsURL(target):
		// The request line is a payload that no URL can carry: bare "%" escapes
		// such as "%&(", or a scheme whose "host" is really CRLF injection
		// ("javascript://%0d%0aalert(1)"). The body accepts arbitrary bytes, so
		// moving it there measures the payload instead of dropping the sample.
		// raw.URL is passed untrimmed: a trailing CRLF is part of the payload.
		body = firstNonEmpty(raw.Data, raw.URL)
		method, target, rationale = http.MethodPost, "/", RationaleRepairedToBody
	}

	if _, err := url.Parse(target); err != nil {
		return Case{}, fmt.Errorf("case %q: unparseable target: %w", name, err)
	}

	category := ""
	if truth == "attack" {
		category = NormalizeCategory(raw.Label)
	}

	tc := Case{
		Name:         name,
		SourceFamily: strings.TrimSpace(raw.Source),
		Label:        truth,
		Category:     category,
		Method:       method,
		Target:       target,
		Body:         body,
		Header:       ParseHeaderBlock(raw.Headers),
		Rationale:    rationale,
	}
	if err := ValidateCase(tc); err != nil {
		return Case{}, err
	}
	return tc, nil
}

// RawAdaptStats extends JSONLStats with the number of records the adapter had to
// drop. Dropped records are the difference between an honest baseline and a
// flattering one, so callers must surface this number.
type RawAdaptStats struct {
	JSONLStats
	SkippedUnadaptable int
}

// ForEachRawHTTPJSONL streams a lowercase-key JSONL corpus through the adapter.
// It shares ForEachJSONLRaw's line-length bound and sharding contract, so these
// corpora can be sharded exactly like the curated ones.
func ForEachRawHTTPJSONL(r io.Reader, shards, shard int, defaultTruth string, fn func(Case) error) (RawAdaptStats, error) {
	if fn == nil {
		return ForEachRawHTTPJSONLPair(r, shards, shard, defaultTruth, nil)
	}
	return ForEachRawHTTPJSONLPair(r, shards, shard, defaultTruth, func(tc Case, _ RawHTTPCase) error {
		return fn(tc)
	})
}

// ForEachRawHTTPJSONLPair streams adapted cases together with their raw records.
// Callers that need corpus-specific fields the generic Case schema does not
// model — aetherguard's expected_detection, for one — read them off the raw
// record instead of losing them to the conversion.
func ForEachRawHTTPJSONLPair(r io.Reader, shards, shard int, defaultTruth string, fn func(Case, RawHTTPCase) error) (RawAdaptStats, error) {
	var out RawAdaptStats
	totalCases, selectedCases := 0, 0
	stats, err := ForEachJSONLRaw(r, shards, shard, func(line []byte, lineNo int, selected bool) error {
		var raw RawHTTPCase
		if err := json.Unmarshal(line, &raw); err != nil {
			return fmt.Errorf("line %d: %w", lineNo, err)
		}
		name := raw.CaseName(lineNo)
		tc, err := AdaptRawHTTPCase(raw, name, defaultTruth)
		if err != nil {
			out.SkippedUnadaptable++
			return nil
		}
		totalCases++
		if !selected {
			return nil
		}
		selectedCases++
		if fn != nil {
			return fn(tc, raw)
		}
		return nil
	})
	out.JSONLStats = stats
	out.TotalCases = totalCases
	out.SelectedCases = selectedCases
	return out, err
}
