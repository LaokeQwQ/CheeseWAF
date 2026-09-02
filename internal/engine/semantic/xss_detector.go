package semantic

import (
	"context"
	"encoding/base64"
	"net/url"
	"regexp"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine/decoder"
)

var xssPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)<\s*(?:[a-z0-9_-]+\s*:\s*)?script\b`),
	regexp.MustCompile(`(?i)\bon[a-z0-9_-]{3,}\s*=`),
	regexp.MustCompile(`(?i)<\s*(?:[a-z0-9_-]+\s*:\s*)?svg\b[^>]*\bon[a-z0-9_-]{3,}\s*=`),
	regexp.MustCompile(`(?i)<\s*xss\b[^>]*\bon[a-z0-9_-]{3,}\s*=`),
	// Additional attack vectors
	regexp.MustCompile(`(?i)\bonpointer(?:down|move|up|enter|leave|over|out)\s*=`),
	regexp.MustCompile(`(?i)\bontransitionend\s*=`),
	regexp.MustCompile(`(?i)\bonanimationstart\s*=`),
	regexp.MustCompile(`(?i)<\s*embed\b[^>]*\bsrc\s*=\s*['"]?\s*javascript\s*:`),
	regexp.MustCompile(`(?i)<\s*object\b[^>]*\bdata\s*=\s*['"]?\s*javascript\s*:`),
	regexp.MustCompile(`(?i)<\s*math\b[^>]*\bhref\s*=\s*['"]?\s*javascript\s*:`),
	regexp.MustCompile(`(?i)['"]\s*>?\s*<\s*/\s*(?:style|script|title|textarea|math|noscript)\s*>?\s*<\s*img\b`),
	regexp.MustCompile(`(?i)<\s*details\b[^>]*\bontoggle\s*=`),
}

var (
	xssGenericEventAssignment = regexp.MustCompile(`(?i)\bon[a-z0-9_-]{3,}\s*=`)
	xssHTMLTagStart           = regexp.MustCompile(`(?is)<\s*[a-z][^>]{0,256}(?:>|$)`)
)

// dynsrc and lowsrc are legacy <img> attributes that still accept a URL, and
// therefore still accept a javascript: URL.
var javascriptURLContext = regexp.MustCompile(`(?i)<[^>]+\b(?:href|src|srcset|xlink:href|formaction|action|poster|codebase|background|longdesc|profile|usemap|dynsrc|lowsrc)\s*=\s*['"]?\s*javascript\s*:`)

// A bare value=javascript: attribute is not executable: input values and many
// custom elements legitimately carry scheme-looking text. Limit the legacy
// object vector to <param> elements whose name is exactly a URL/code sink.
// Parsing the attributes separately avoids treating prefixes such as "urlish"
// and "codebase" as the executable names "url" and "code".
var (
	xssObjectParamTag       = regexp.MustCompile(`(?is)<\s*param\b[^>]*>`)
	xssObjectParamAttribute = regexp.MustCompile(`(?is)\b([a-z][a-z0-9:_.-]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>]+))`)
	// A complete javascript: URL is itself an execution context when it is the
	// whole field value (for example a redirect target or a raw request body).
	// Keeping the anchor is important: prose and markup attributes may mention
	// the same scheme without executing it.
	xssStandaloneJavascriptURL = regexp.MustCompile(`(?is)^\s*["'` + "`" + `]?\s*javascript\s*:\s*(?:(?:/{2}|/\*.*?\*/\s*)?)(?:\s|%[0-9a-f]{2})*(?:[a-z_][a-z0-9_]*\s*\(|void\s*\()`)
	// URL-valued request fields may carry the scheme without HTML markup. Keep
	// this separate from the whole-value matcher so a field such as
	// "profile_bio" does not become executable merely because it mentions the
	// scheme in prose.
	// Open-redirect payloads sometimes wrap the URL in an empty angle-tag
	// pair before it reaches the URL sink (for example `<>javascript:...`).
	// Accept that one exact wrapper, but do not generalize to arbitrary markup
	// or punctuation: the field-name gate below is what gives this signal its
	// execution context.
	xssJavascriptURLField = regexp.MustCompile(`(?is)^\s*(?:<>\s*)?javascript\s*:\s*(?:(?:/{2}|/\*.*?\*/\s*)?)(?:\s|%[0-9a-f]{2})*(?:[a-z_][a-z0-9_]*\s*\(|void\s*\()`)
)

// xssExecutableURLSchemeTarget validates a complete URL scheme before it is
// treated as an executable request target. Checking a raw prefix (for example
// strings.HasPrefix(raw, "javascript:")) is incomplete: it misses equivalent
// dangerous schemes and can accidentally make scheme-looking text executable
// without first proving that the input is a URL. The request-surface gate is
// applied by xssStandaloneExecutableURLContext; this helper only answers
// whether the parsed URL's scheme and payload are dangerous.
func xssExecutableURLSchemeTarget(raw string) bool {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || len(trimmed) > maxInputRawBytes {
		return false
	}
	parsed, err := url.Parse(trimmed)
	if err != nil || parsed.Scheme == "" {
		return false
	}
	scheme := strings.ToLower(parsed.Scheme)
	if len(parsed.Scheme)+1 >= len(trimmed) {
		return false
	}
	payload := strings.TrimSpace(trimmed[len(parsed.Scheme)+1:])
	switch scheme {
	case "javascript", "vbscript":
		// Both schemes execute their opaque payload directly. The URL surface
		// provides the context, so even a non-call expression is meaningful.
		return payload != ""
	case "data":
		return xssExecutableDataURLPayload(payload)
	default:
		return false
	}
}

func xssExecutableDataURLPayload(payload string) bool {
	metadata, encoded, ok := strings.Cut(payload, ",")
	if !ok {
		return false
	}
	metadata = strings.ToLower(strings.TrimSpace(metadata))
	parts := strings.Split(metadata, ";")
	mediaType := strings.TrimSpace(parts[0])
	base64Payload := false
	for _, part := range parts[1:] {
		if strings.TrimSpace(part) == "base64" {
			base64Payload = true
		}
	}
	switch mediaType {
	case "text/javascript", "application/javascript", "application/ecmascript", "text/ecmascript":
		return strings.TrimSpace(encoded) != ""
	case "text/html", "application/xhtml+xml", "image/svg+xml":
		var decoded string
		if base64Payload {
			for _, encoding := range []*base64.Encoding{
				base64.StdEncoding, base64.RawStdEncoding,
				base64.URLEncoding, base64.RawURLEncoding,
			} {
				bytes, err := encoding.DecodeString(strings.TrimSpace(encoded))
				if err == nil && len(bytes) > 0 {
					decoded = string(bytes)
					break
				}
			}
		} else if unescaped, err := url.PathUnescape(encoded); err == nil {
			decoded = unescaped
		}
		return decoded != "" && executableXSSContext(normalize(decoded))
	default:
		return false
	}
}

func xssJavascriptURLFieldContext(candidate semanticCandidate) bool {
	if !xssJavascriptURLField.MatchString(candidate.text) {
		return false
	}
	return xssURLSinkFieldName(candidate.input.Name)
}

// xssStandaloneExecutableURLContext ties a complete dangerous URL scheme to a
// request surface that can execute it. Free-text fields may mention these
// schemes without navigation or script execution, so they remain data unless
// their field name is an explicit URL sink.
func xssStandaloneExecutableURLContext(candidate semanticCandidate) bool {
	if !xssExecutableURLSchemeTarget(candidate.text) {
		return false
	}
	switch strings.ToLower(candidate.input.Source) {
	case "body.raw":
		return true
	case "uri":
		switch strings.ToLower(candidate.input.Name) {
		case "path", "target":
			return true
		}
	case "query", "form", "json", "cookie", "multipart", "body.form", "body.json", "body.multipart":
		return xssURLSinkFieldName(candidate.input.Name)
	}
	return false
}

func xssURLSinkFieldName(rawName string) bool {
	name := strings.ToLower(strings.TrimSpace(rawName))
	if name == "" {
		return false
	}
	// Split structured names (custom_url, redirect.target) but require an
	// exact token or a conventional URL suffix; prefixes such as urlish and
	// codebase must not inherit the meaning of url/code.
	parts := strings.FieldsFunc(name, func(r rune) bool {
		return r == '.' || r == '_' || r == '-' || r == '[' || r == ']'
	})
	for _, part := range parts {
		switch part {
		case "url", "uri", "href", "redirect", "return", "next", "target", "action", "callback", "dest", "destination", "link", "src", "srcset", "poster", "background", "website", "homepage", "avatar", "image", "feed", "movie":
			return true
		}
	}
	return strings.HasSuffix(name, "url") || strings.HasSuffix(name, "uri") ||
		strings.HasSuffix(name, "href") || strings.HasSuffix(name, "link")
}

// xssDataURLBase64Field is deliberately anchored. A data URI in a free-text
// field is not an execution sink by itself; the field-name gate below supplies
// the missing URL context. Restricting the media types and requiring base64
// keeps ordinary image/data values out of the expensive decode path.
var xssDataURLBase64Field = regexp.MustCompile(`(?is)^\s*data\s*:\s*(?:text/html|application/xhtml\+xml|image/svg\+xml)\s*;\s*base64\s*,\s*([a-z0-9+/_=\-\s]+)\s*$`)

// xssDataURLFieldContext recognizes an executable HTML data URI carried by a
// URL-valued request field. The decoded bytes are checked by the same
// executable-context battery used for markup, so a harmless base64 HTML page
// does not become a hit merely because it uses a URL-looking parameter name.
func xssDataURLFieldContext(candidate semanticCandidate) bool {
	trimmed := strings.TrimSpace(candidate.text)
	name := strings.ToLower(strings.TrimSpace(candidate.input.Name))
	pathSurface := strings.EqualFold(candidate.input.Source, "uri") && name == "path" &&
		asciiFoldPrefix(trimmed, "/data:")
	if !xssURLSinkFieldName(name) && !pathSurface {
		return false
	}
	if !asciiFoldContains(trimmed, "data:") {
		return false
	}
	decoded, ok := decodeXSSDataURL(candidate.text)
	return ok && executableXSSContext(normalize(decoded))
}

func asciiFoldPrefix(text, prefix string) bool {
	if len(text) < len(prefix) {
		return false
	}
	return asciiFoldEqual(text[:len(prefix)], prefix)
}

func asciiFoldContains(text, needle string) bool {
	if needle == "" {
		return true
	}
	if len(text) < len(needle) {
		return false
	}
	for i := 0; i <= len(text)-len(needle); i++ {
		if asciiFoldEqual(text[i:i+len(needle)], needle) {
			return true
		}
	}
	return false
}

func asciiFoldEqual(left, right string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := 0; i < len(left); i++ {
		l, r := left[i], right[i]
		if l >= 'A' && l <= 'Z' {
			l += 'a' - 'A'
		}
		if r >= 'A' && r <= 'Z' {
			r += 'a' - 'A'
		}
		if l != r {
			return false
		}
	}
	return true
}

func decodeXSSDataURL(raw string) (string, bool) {
	match := xssDataURLBase64Field.FindStringSubmatch(strings.TrimSpace(raw))
	if len(match) != 2 {
		// URI paths in the corpus carry one leading slash before the data scheme.
		trimmed := strings.TrimSpace(raw)
		if asciiFoldPrefix(trimmed, "/data:") {
			match = xssDataURLBase64Field.FindStringSubmatch(trimmed[1:])
		}
	}
	if len(match) != 2 || len(match[1]) == 0 || len(match[1]) > maxInputRawBytes {
		return "", false
	}
	encoded := strings.ReplaceAll(match[1], " ", "+")
	for _, encoding := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		decoded, err := encoding.DecodeString(encoded)
		if err != nil || len(decoded) == 0 {
			continue
		}
		if printableRatio(string(decoded)) < 0.65 {
			continue
		}
		return string(decoded), true
	}
	return "", false
}

// xssStandaloneJavascriptURLContext keeps the complete-scheme matcher tied to
// request surfaces that can execute a URL directly. A query/form value with an
// arbitrary name is data until its field identifies a URL sink; path and target
// values, and an unstructured request body, are the explicit URL/script
// surfaces covered here.
func xssStandaloneJavascriptURLContext(candidate semanticCandidate) bool {
	if !xssStandaloneJavascriptURL.MatchString(candidate.text) {
		return false
	}
	switch strings.ToLower(candidate.input.Source) {
	case "body.raw":
		return true
	case "uri":
		switch strings.ToLower(candidate.input.Name) {
		case "path", "target":
			return true
		}
	}
	return false
}

func hasXSSObjectParamExecutableURL(text string) bool {
	for _, tag := range xssObjectParamTag.FindAllString(text, -1) {
		urlSink := false
		executableURLValue := false
		for _, attr := range xssObjectParamAttribute.FindAllStringSubmatch(tag, -1) {
			value := attr[2]
			if value == "" {
				value = attr[3]
			}
			if value == "" {
				value = attr[4]
			}

			switch strings.ToLower(attr[1]) {
			case "name":
				switch strings.ToLower(strings.TrimSpace(value)) {
				case "url", "movie", "src", "data", "code":
					urlSink = true
				}
			case "value":
				executableURLValue = executableURLValue || xssExecutableURLSchemeTarget(value)
			}
		}
		if urlSink && executableURLValue {
			return true
		}
	}
	return false
}

// xssCSSExpression matches the legacy "&{ ... }" script escape only when it is
// embedded in a CSS-bearing HTML attribute. The markup context is required: a
// bare token in a request body or a non-style data attribute is ordinary data.
var xssCSSExpression = regexp.MustCompile(`(?is)<\s*[a-z][^>]*\b(?:style|size|width|height|color|bgcolor|background)\s*=\s*["']?[^>"']*&\s*\{\s*[^}]{0,200}?(?:\b(?:alert|prompt|confirm|eval|expression)\s*\(|\b(?:document|window|location)\s*\.|\bcookie\b|javascript\s*:)`)
var xssDataURLContext = regexp.MustCompile(`(?i)<[^>]+\b(?:href|src|data|xlink:href|formaction|action|content|poster|codebase)\s*=\s*['"]?\s*data\s*:\s*(?:text/html|image/svg\+xml|application/xhtml\+xml)`)
var xssSrcdocContext = regexp.MustCompile(`(?i)<\s*iframe\b[^>]*\bsrcdoc\s*=`)
var xssMetaRefreshContext = regexp.MustCompile(`(?i)<\s*meta\b[^>]*\bcontent\s*=\s*['"]?[^'">]*url\s*=\s*javascript\s*:`)
var xssStyleExecutionContext = regexp.MustCompile(`(?i)<[^>]+\bstyle\s*=\s*['"]?[^>]*(?:\bexpression\s*\(|\burl\s*\(\s*javascript\s*:)`)
var xssCSSInjectionPattern = regexp.MustCompile(`(?i)<\s*style\b[^>]*>|\bstyle\s*=\s*['"]?[^>]*(?:\bexpression\s*\(|behavior\s*:\s*url|@import\s+url\s*\(\s*javascript)`)

// Modern XSS vectors from HTML5sec and PayloadsAllTheThings
var xssModernPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)<\s*(?:animate|set)\b[^>]*\battributename\s*=\s*['"]?(?:xlink:)?href['"]?[^>]*\b(?:values?|from|to)\s*=\s*['"]?\s*javascript\s*:`), // SVG SMIL href animation values/from/to
	regexp.MustCompile(`(?i)<\s*(?:animate|set)\b[^>]*\b(?:values?|from|to)\s*=\s*['"]?\s*javascript\s*:[^>]*\battributename\s*=\s*['"]?(?:xlink:)?href`),      // reversed SMIL attributes
	regexp.MustCompile(`(?i)<\s*button\b[^>]*\bformaction\s*=\s*['"]?\s*javascript\s*:`),                                                                       // button formaction XSS
	regexp.MustCompile(`(?i)<\s*video\b[^>]*\bposter\s*=\s*['"]?\s*javascript\s*:`),                                                                            // video poster XSS
	regexp.MustCompile(`(?i)<\s*(?:audio|source|track)\b[^>]*\bsrc\s*=\s*['"]?\s*javascript\s*:`),                                                              // audio/source XSS
	regexp.MustCompile(`(?i)<\s*svg\b[^>]*\bonload\s*=`),                                                                                                       // SVG onload XSS
	regexp.MustCompile(`(?i)<\?xml-stylesheet\b[^>]*\bhref\s*=\s*['"]?\s*javascript\s*:`),                                                                      // XML stylesheet XSS
	regexp.MustCompile(`(?i)charset\s*=\s*['"]x-imap4-modified-utf7['"]`),                                                                                      // UTF-7 charset XSS
	regexp.MustCompile(`(?i)x-mac-farsi`),                                                                                                                      // Mac Farsi charset XSS
	regexp.MustCompile(`(?i)crypto\.generateCRMFRequest\s*\(`),                                                                                                 // Browser crypto API XSS
	regexp.MustCompile(`(?i)<\s*body\b[^>]*\bonscroll\s*=.*alert`),                                                                                             // scroll-based XSS
	regexp.MustCompile(`(?i)<\s*input\b[^>]*\bonfocus\s*=\s*(?:write|eval)`),                                                                                   // input onfocus XSS
	regexp.MustCompile(`(?i)<\s*input\b[^>]*\bpattern\s*=\s*['"].*\(\(a\+\?\.\)a\)\+\$`),                                                                       // ReDoS via pattern attr
	regexp.MustCompile(`(?i)(?:\\x[0-9a-f]{2}|&#x[0-9a-f]+;){3,}\s*(?:alert|eval|write|prompt|confirm)\s*\(`),                                                  // multi-hex-encoded function call
	regexp.MustCompile(`(?i)style\s*=\s*['"]-o-link(-source)?\s*:\s*['"]?javascript`),                                                                          // Opera CSS link XSS
	regexp.MustCompile(`(?i)<\s*x\b[^>]*\brepeat\s*=`),                                                                                                         // template repeat DoS/XSS
	regexp.MustCompile(`(?i)(?:importScripts|postMessage)\s*\(\s*['"]\s*(?:data|javascript):`),                                                                 // Worker-based XSS
	regexp.MustCompile(`(?i)set\s*\(\s*['"]?(?:innerHTML|outerHTML)\s*['"]?\s*,\s*`),                                                                           // DOM manipulation XSS
	regexp.MustCompile(`(?i)(?:\{\s*\}\s*=\s*alert|_\s*=\s*alert|call\s*\(\s*alert\s*\))`),                                                                     // JS shorthand execution
	regexp.MustCompile(`(?i)(?:\/\*\*\/|\\u[0-9a-f]{4}\\u[0-9a-f]{4})`),                                                                                        // JS comment/unicode obfuscation
	regexp.MustCompile(`(?i)<\s*[a-z0-9]+\b[^>]*\bxlink:href\s*=\s*['"]?data\s*:\s*text\/html`),                                                                // SVG xlink data URI XSS
	regexp.MustCompile(`(?i)<\s*(?:frame|iframe)\b[^>]*\bsrc\s*=\s*['"]?\s*(?:javascript|data):`),                                                              // frame/iframe XSS
	regexp.MustCompile(`(?i)\b(?:\\u[0-9a-f]{4}|\\x[0-9a-f]{2}){2,}\b(?:alert|eval|prompt|confirm|write|open)\b`),                                              // unicode-encoded function name
	regexp.MustCompile(`(?i)(?:&#\d{2,3};){4,}`),                                                                                                               // decimal HTML entity encoding chain
	// A quoted JS string terminated and followed by a call: an injection into a
	// <script> string literal or an inline handler, e.g. `";alert('xss');//`.
	regexp.MustCompile(`(?i)["']\s*;\s*(?:alert|prompt|confirm|eval|document\s*\.\s*(?:cookie|write))\s*\(`),
	// An event-handler attribute whose name carries junk characters. Browsers
	// stop the attribute name at the first character that cannot appear in one,
	// so `<body onload!#$%&()*~+-_.,:;?@[/|\]^`=alert(1)>` is still an onload
	// handler; the junk exists only to break naive `onload=` matching.
	regexp.MustCompile(`(?i)<[^>]+\bon[a-z]{2,20}[^=>\s]{0,40}\s*=\s*['"]?\s*(?:alert|prompt|confirm|eval|document\s*\.\s*(?:cookie|write))\s*[(=]`),
}

// xssSchemeNoise is what browsers and XML parsers throw away from inside a URL
// scheme before they decide what the scheme is: whitespace, HTML comments and
// CDATA section markers.
//
// It is the reason these three are the same vector:
//
//	<img src="jav ascript:alert(1)">
//	<img src="java<!-- -->script:alert(1)">
//	<img src="javas]]><![cdata[cript:alert(1)">
const xssSchemeNoise = `(?:\s|<!--|-->|<!\[cdata\[|]]>)*`

// xssObfuscatedJavascriptURL matches a javascript: URL in a URL-bearing
// attribute with scheme-splitting noise interleaved between the letters.
//
// The pattern is assembled from the word rather than written out, because
// "jav ascript" does not contain the substring "java" — so neither a cheap
// substring gate nor a naive strip-then-match can find it. Stripping noise from
// the whole text first does not work either: it removes the space after the tag
// name too, and "imgsrc" has no word boundary before "src", so \b(?:href|src…)
// stops matching.
var xssObfuscatedJavascriptURL = regexp.MustCompile(`(?i)<[^>]+\b(?:href|src|srcset|xlink:href|formaction|action|poster|codebase|background|longdesc|profile|usemap|dynsrc|lowsrc)\s*=\s*['"]?\s*` +
	xssNoisyWord("javascript") + `\s*:`)

// xssNoisyWord joins the letters of word with xssSchemeNoise so the result still
// matches when an attacker splits the word with any of that noise.
func xssNoisyWord(word string) string {
	var b strings.Builder
	b.Grow(len(word) * (len(xssSchemeNoise) + 2))
	for i := 0; i < len(word); i++ {
		b.WriteString(regexp.QuoteMeta(word[i : i+1]))
		b.WriteString(xssSchemeNoise)
	}
	return b.String()
}

type XSSDetector struct {
	mode string
}

func NewXSSDetector(mode string) *XSSDetector {
	if mode == "" {
		mode = "block"
	}
	return &XSSDetector{mode: mode}
}

func (d *XSSDetector) ID() string    { return "semantic.xss" }
func (d *XSSDetector) Name() string  { return "XSS Semantic Detector" }
func (d *XSSDetector) Priority() int { return 310 }

func (d *XSSDetector) Detect(ctx context.Context, reqCtx *engine.RequestContext) (*engine.DetectionResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	payload := requestText(reqCtx)
	candidates := []string{payload, decoder.Decode(payload).Text, decoder.DeepDecode(payload).Text}
	// requestText intentionally fuses URI, headers and body for the legacy
	// detector. Keep direct javascript URLs tied to their original executable
	// surface before scanning that fused representation, so an arbitrary query
	// value cannot inherit the standalone URL interpretation.
	if surface, ok := standaloneJavascriptURLSurface(reqCtx); ok {
		return &engine.DetectionResult{
			Detected: true, DetectorID: d.ID(), Category: "xss", Severity: engine.SeverityHigh, Action: actionForMode(d.mode),
			Message: "XSS payload pattern matched", Confidence: 0.86, Payload: strings.TrimSpace(surface),
		}, nil
	}
	if surface, ok := standaloneExecutableURLSurface(reqCtx); ok {
		return &engine.DetectionResult{
			Detected: true, DetectorID: d.ID(), Category: "xss", Severity: engine.SeverityHigh, Action: actionForMode(d.mode),
			Message: "XSS executable URL scheme matched", Confidence: 0.88, Payload: strings.TrimSpace(surface),
		}, nil
	}
	if surface, ok := standaloneDataURLSurface(reqCtx); ok {
		return &engine.DetectionResult{
			Detected: true, DetectorID: d.ID(), Category: "xss", Severity: engine.SeverityHigh, Action: actionForMode(d.mode),
			Message: "XSS executable data URI matched", Confidence: 0.90, Payload: strings.TrimSpace(surface),
		}, nil
	}
	for _, candidate := range candidates {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		// Deep tokenization first (fast, pure Go; libinjection-compatible)
		if engine.XSSLibinjectionFingerprint(candidate) {
			return &engine.DetectionResult{
				Detected: true, DetectorID: d.ID(), Category: "xss", Severity: engine.SeverityHigh, Action: actionForMode(d.mode),
				Message: "XSS token fingerprint matched", Confidence: 0.90, Payload: strings.TrimSpace(candidate),
			}, nil
		}
		normalized := normalize(candidate)
		if executableXSSContext(normalized) {
			return &engine.DetectionResult{
				Detected:   true,
				DetectorID: d.ID(),
				Category:   "xss",
				Severity:   engine.SeverityHigh,
				Action:     actionForMode(d.mode),
				Message:    "XSS payload pattern matched",
				Confidence: 0.86,
				Payload:    strings.TrimSpace(candidate),
			}, nil
		}
	}
	return nil, nil
}

func standaloneExecutableURLSurface(reqCtx *engine.RequestContext) (string, bool) {
	if reqCtx == nil || reqCtx.Request == nil || reqCtx.Request.URL == nil || reqCtx.Request.URL.Scheme == "" {
		return "", false
	}
	target := reqCtx.Request.URL.String()
	if xssExecutableURLSchemeTarget(target) {
		return target, true
	}
	return "", false
}

func standaloneJavascriptURLSurface(reqCtx *engine.RequestContext) (string, bool) {
	if reqCtx == nil || reqCtx.Request == nil || reqCtx.Request.URL == nil {
		return "", false
	}
	path := reqCtx.Request.URL.EscapedPath()
	if path == "" {
		path = reqCtx.Request.URL.Path
	}
	if path != "" && xssStandaloneJavascriptURL.MatchString(normalize(path)) {
		return path, true
	}
	if reqCtx.Request.URL.Scheme != "" {
		target := reqCtx.Request.URL.String()
		if xssStandaloneJavascriptURL.MatchString(normalize(target)) {
			return target, true
		}
	}
	if len(reqCtx.DecodedBody) > 0 {
		body := string(reqCtx.DecodedBody)
		if xssStandaloneJavascriptURL.MatchString(normalize(body)) {
			return body, true
		}
	}
	return "", false
}

func standaloneDataURLSurface(reqCtx *engine.RequestContext) (string, bool) {
	if reqCtx == nil || reqCtx.Request == nil || reqCtx.Request.URL == nil {
		return "", false
	}
	path := reqCtx.Request.URL.EscapedPath()
	if path == "" {
		path = reqCtx.Request.URL.Path
	}
	if xssDataURLFieldContext(semanticCandidate{input: InputPoint{Source: "uri", Name: "path"}, text: path}) {
		return path, true
	}
	for name, values := range reqCtx.Request.URL.Query() {
		for _, value := range values {
			candidate := semanticCandidate{input: InputPoint{Source: "query", Name: name}, text: value}
			if xssDataURLFieldContext(candidate) {
				return value, true
			}
		}
	}
	for _, input := range bodyInputs(reqCtx.Request, reqCtx.DecodedBody) {
		candidate := semanticCandidate{input: input, text: input.Raw}
		if xssDataURLFieldContext(candidate) {
			return input.Raw, true
		}
	}
	return "", false
}

// executableXSSContext reports whether the normalized text sits in an
// executable HTML/JS context.
//
// Do NOT put a bare-substring pre-filter in front of this battery. The patterns
// below match whitespace-evaded tags (`< script`), namespaced tags
// (`<xhtml:script`), the generic `on<event>=` family, charset vectors
// (x-mac-farsi, utf7), encoding chains (`&#60;`, `\x61`) and bare JS primitives
// (`/**/`, `call(alert)`) that no small literal set covers. A gate tried here
// dropped 21 of 38 battery-matched payloads, and because heuristicScores also
// calls this, the miss silently removed the xss category from scoring too.
// See TestExecutableXSSContextKeepsFullPatternCoverage.
func executableXSSContext(normalized string) bool {
	for _, pattern := range xssPatterns {
		if pattern.MatchString(normalized) {
			return true
		}
	}
	for _, pattern := range xssModernPatterns {
		if pattern.MatchString(normalized) {
			return true
		}
	}
	if javascriptURLContext.MatchString(normalized) ||
		hasXSSObjectParamExecutableURL(normalized) ||
		xssCSSExpression.MatchString(normalized) ||
		xssDataURLContext.MatchString(normalized) ||
		xssSrcdocContext.MatchString(normalized) ||
		xssMetaRefreshContext.MatchString(normalized) ||
		xssStyleExecutionContext.MatchString(normalized) ||
		xssCSSInjectionPattern.MatchString(normalized) {
		return true
	}
	// Scheme-splitting evasion. Gated on "java" because the cleanup allocates:
	// every obfuscated javascript: URL has to contain that stem somewhere,
	// including the CDATA-split form ("javas]]><![cdata[cript:").
	return xssObfuscatedJavascriptURL.MatchString(normalized)
}

// xssBareEventHandlerNoise rejects a generic on*= token that is not attached
// to an HTML tag and has no executable value. CSS/property names and escaped
// comment fragments such as "style/onload=prompt" are common telemetry or
// parser data; treating the bare token as a browser handler creates a high-FP
// path. Real handlers with markup, a call, a quoted breakout, a scheme, or a
// property access remain visible to the normal pattern battery.
func xssBareEventHandlerNoise(normalized string) bool {
	if !xssGenericEventAssignment.MatchString(normalized) || xssHTMLTagStart.MatchString(normalized) {
		return false
	}
	return !strings.ContainsAny(normalized, `"'()`) &&
		!strings.Contains(normalized, "javascript:") &&
		!strings.Contains(normalized, ".")
}
