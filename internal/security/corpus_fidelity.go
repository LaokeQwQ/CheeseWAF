package security

import (
	"net/http"
	"regexp"
	"sort"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine/decoder"
)

// This file answers a question the detection baseline cannot answer on its own:
// do the committed public corpora actually contain what their labels claim?
//
// The external corpora were bulk-imported. Their `label` field carries an attack
// class, but the class was assigned by whoever generated the dataset, not
// verified against the payload. Measuring TPR against a label that does not
// describe the payload produces a number that looks like a detection gap and is
// really a bookkeeping gap: the ai_waf corpus files 1474 rows under "nosqli" of
// which fewer than 8% carry any MongoDB operator, and the rest are SSRF targets,
// deserialization gadgets, path probes and ordinary form posts.
//
// The signatures below are therefore deliberately NOT the engine. They are an
// independent, deliberately coarse proxy so the measurement is not circular:
// "does this payload contain any recognisable artefact of the class it was filed
// under". Coarse is acceptable because of how the result is used:
//
//   - On an ATTACK row, the absence of any evidence is strong signal. A request
//     carrying no SQL, no XSS, no traversal, nothing, that is labelled an attack
//     is either mislabelled or obfuscated past recognition — and either way it
//     must not silently sit in the denominator of a TPR.
//   - On a BENIGN row, the presence of evidence is WEAK signal. "How do I escape
//     a <script> tag" is ordinary prose that happens to match an XSS signature.
//     FidelityVerdict.Evidence is reported for those rows, never acted on.
//
// This file is production code rather than a _test.go file so that both the
// corpus adapter's own tests and the semantic engine's baseline harness can
// share one signature set instead of drifting apart.

// FidelityDeser is not one of DetectionCategories: the engine does not model
// (de)serialization gadgets. It exists so that a Java or PHP gadget payload
// filed under an unrelated label still shows up as *something*, instead of
// vanishing into the "no evidence" bucket where it would look like a plain
// mislabel.
const FidelityDeser = "deser"

// fidelityClasses is the match order. Order matters only for determinism of the
// returned slice, never for the verdict.
var fidelityClasses = []string{
	"sqli", "xss", "rce", "lfi", "xxe", "ssrf", "nosqli", "ssti", "log4shell", "webshell",
	FidelityDeser,
}

// fidelitySignatures is the proxy evidence set. Every pattern is a literal
// artefact of the attack class, chosen to be high-precision on real payloads at
// the cost of recall: a missed signature makes a row look mislabelled, and that
// is the failure mode this tool is meant to surface for manual review rather
// than hide.
var fidelitySignatures = map[string][]*regexp.Regexp{
	"sqli": {
		regexp.MustCompile(`(?i)\b(?:select\s+.{0,40}\bfrom|union\s+(?:all\s+)?select|insert\s+into|update\s+\w+\s+set|delete\s+from|drop\s+(?:table|database)|information_schema|sysobjects|pg_sleep|sleep\s*\(|benchmark\s*\(|waitfor\s+delay|load_file|outfile|dumpfile|xp_cmdshell|extractvalue|updatexml|group_concat|concat_ws)\b`),
		regexp.MustCompile(`(?i)(?:'\s*(?:or|and)\s*'?\d|'\s*or\s*'1'\s*=\s*'1|"\s*or\s*"1"\s*=\s*"1|or\s+1\s*=\s*1\s*--|'\s*--|'\s*#|;\s*--)`),
		// XPath injection: several corpora file it under "sqli".
		regexp.MustCompile(`(?i)(?:substring\s*\(\s*//|//\w+\s*\[|count\s*\(\s*//|name\s*\(\s*\)|text\s*\(\s*\))`),
	},
	"xss": {
		regexp.MustCompile(`(?i)(?:<\s*/?\s*script|<\s*img[^>]+onerror|<\s*svg[^>]+onload|<\s*iframe|javascript\s*:|on(?:click|error|load|mouseover|focus|blur|submit|toggle)\s*=|alert\s*\(|document\s*\.\s*cookie|confirm\s*\(|prompt\s*\(|String\.fromCharCode|<\s*body[^>]+onload|<\s*a[^>]+href\s*=\s*["']?javascript)`),
	},
	"rce": {
		regexp.MustCompile(`(?i)(?:;\s*(?:cat|ls|id|whoami|pwd|uname|ifconfig|netstat)\b|\|\s*(?:sh|bash|nc|curl|wget)\b|` + "`" + `[^` + "`" + `]{3,}` + "`" + `|\$\([^)]{3,}\)|/bin/(?:sh|bash)|bash\s+-c|sh\s+-c|nc\s+-(?:e|c|l)\b|\bping\s+-c|\bwget\s+http|\bcurl\s+http|passthru\s*\(|\bsystem\s*\(|\bexec\s*\(|p?open\s*\(|subprocess|Runtime\.getRuntime|ProcessBuilder)`),
		regexp.MustCompile(`(?i)(?:%0a|\r?\n)\s*(?:id|ls|cat|whoami|pwd|uname)\s*(?:%0a|\r?\n|$)`),
		regexp.MustCompile(`(?i)(?:&&\s*(?:id|ls|cat|whoami)\b|\|\|\s*(?:id|ls|cat|whoami)\b)`),
	},
	"lfi": {
		// "%c0%af" and "%e0%80%af" are overlong UTF-8 encodings of '/'. They
		// decode to invalid UTF-8, so the pattern has to carry the decoded
		// bytes as well as the escaped spelling; matching only one of the two
		// loses whichever form the corpus happens to store.
		regexp.MustCompile(`(?i)(?:\.\./|\.\.\\|%2e%2e|\.\.(?:%c0%af|\xc0\xaf|%c1%9c|\xc1\x9c|%e0%80%af|\xe0\x80\xaf)|\.\.%uff0e|/etc/(?:passwd|shadow|hosts|group)|c:\\?windows|boot\.ini|web\.config|file\s*:/|/proc/self|win\.ini|system32)`),
	},
	"xxe": {
		regexp.MustCompile(`(?i)(?:<!\s*entity|<!\s*doctype[^\]]{0,200}\[|system\s+"?(?:file|http|php|expect|netdoc)://)`),
	},
	"ssrf": {
		// Loopback, link-local and RFC1918 literals plus the URL schemes whose
		// only real use in a request parameter is reaching something the caller
		// cannot reach directly.
		regexp.MustCompile(`(?i)(?:169\.254\.169\.254|metadata\.google|metadata\.azure|2130706433|0177\.0|0x7f\.(?:0x0){2,3}0x1|\[::1\]|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|dict\s*://|gopher\s*://|file\s*://)`),
	},
	"nosqli": {
		regexp.MustCompile(`(?i)(?:\$(?:where|ne|gt|gte|lt|lte|regex|in|nin|or|and|nor|not|exists|expr|eval|function|accumulator|jsonschema|elemmatch|set|unset|rename)\b|db\s*\.\s*\w+\s*\.\s*(?:update|find|remove|insert|aggregate)|this\s*\.\s*(?:isadmin|role|password|username)|map\s*reduce|\bsleep\s*\(\s*\d{3,})`),
	},
	"ssti": {
		regexp.MustCompile(`(?:\{\{[^}]{1,120}\}\}|\$\{[^}]{1,120}\}|<%=[^%]{1,120}%>|#\{[^}]{1,120}\}|\[\[\s*\$\{|jinja|freemarker|\|\s*attr\s*\(|__class__|request\.application)`),
	},
	"log4shell": {
		regexp.MustCompile(`(?i)(?:\$\{\s*(?:jndi|::-|lower:|upper:|env:|sys:|date:)|jndi\s*:\s*(?:ldap|rmi|dns|nis|iiop|corba)\s*:)`),
	},
	"webshell": {
		regexp.MustCompile(`(?i)(?:<\?php[^>]{0,80}(?:eval|assert|system|passthru|shell_exec|base64_decode)|<%\s*@\s*page|cmd\s*=\s*(?:whoami|id|cat)|\bc99\b|\br57\b|\bwso\b|china\s*chopper)`),
	},
	FidelityDeser: {
		regexp.MustCompile(`(?i)(?:rO0ABX|O:\d+:"|aced0005|__reduce__|posix\.system|javax\.naming|com\.sun\.rowset)`),
	},
}

// transportFidelityHeaders are header names that carry protocol furniture
// rather than attacker-controlled content. Only these are stripped before
// matching.
//
// The list is deliberately short, and Cookie is deliberately NOT on it. These
// corpora hide their payload where a WAF has to look for it: the ai_waf attack
// file carries a time-based blind UNION in a Cookie value while the URL and body
// are an ordinary profile update, so a classifier that skips cookies reports the
// row as "no attack evidence" and the engine's correct detection reads as a
// false positive. User-Agent stays scanned for the same reason — Log4Shell
// arrives there.
//
// Host is the one header that genuinely has to go. Every record ships a
// synthesised Host, and generated domains include literal "localhost", which
// would otherwise make a large share of the benign files look like SSRF.
var transportFidelityHeaders = map[string]bool{
	"Host": true, "Accept": true, "Accept-Encoding": true, "Accept-Language": true,
	"Connection": true, "Content-Length": true, "Content-Type": true,
	"Upgrade-Insecure-Requests": true, "Date": true, "Cache-Control": true,
	"Pragma": true, "Expires": true, "Origin": true, "TE": true, "Trailer": true,
	"Transfer-Encoding": true, "Expect": true, "Keep-Alive": true, "Via": true,
}

// FidelityVerdict is the outcome of checking one adapted Case against the
// signature set. It records what was found, never a conclusion about what the
// label should have been.
type FidelityVerdict struct {
	// Classes are the attack classes with signature evidence, in
	// fidelityClasses order.
	Classes []string
	// InClass reports whether the case's own Category appears in Classes. It is
	// only meaningful for rows labelled "attack"; for benign rows Category is
	// empty and InClass is always false.
	InClass bool
	// NoEvidence reports that no signature of any class matched. On a row the
	// corpus calls an attack, this is the signal that the row cannot be used to
	// measure detection of the class it claims to be.
	NoEvidence bool
}

// FidelityOf checks an adapted Case.
func FidelityOf(tc Case) FidelityVerdict {
	return FidelityOfText(FidelityText(tc), tc.Category)
}

// FidelityText is the payload-bearing text of a Case: the request line, the
// body, and the headers that are not request furniture.
func FidelityText(tc Case) string {
	var b strings.Builder
	b.WriteString(tc.Method)
	b.WriteByte(' ')
	b.WriteString(tc.Target)
	b.WriteByte('\n')
	b.WriteString(tc.Body)
	names := make([]string, 0, len(tc.Header))
	for name := range tc.Header {
		if transportFidelityHeaders[http.CanonicalHeaderKey(name)] {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		b.WriteByte('\n')
		b.WriteString(name)
		b.WriteString(": ")
		b.WriteString(tc.Header[name])
	}
	return b.String()
}

// FidelityOfText matches raw text against every class signature, across every
// decoding layer the request pipeline itself would try, and reports which
// classes have evidence. wantClass, when non-empty, is additionally reported as
// InClass if it appears in the evidence.
func FidelityOfText(text, wantClass string) FidelityVerdict {
	found := make(map[string]bool)
	// Both the untouched text and every decoded layer are matched. Decoding is
	// not enough on its own: DecodeAll returns only decoded forms, so a pattern
	// written against the escaped spelling ("%2e%2e", "%c0%af", "%3Cscript%3E")
	// would never fire, while the decoded form of an overlong sequence is
	// invalid UTF-8 that a rune-based regexp cannot match either. Scanning both
	// ends means an obfuscated payload is caught whichever way round it is
	// written.
	variants := decoder.DecodeAll(text)
	all := make([]string, 0, len(variants)+2)
	all = append(all, text)
	for _, variant := range variants {
		all = append(all, variant.Text)
		// Deep decoding may peel one more layer off an already-decoded value;
		// DecodeAll only base64-decodes the deepest variant, so re-run the
		// URL/HTML pass over it here.
		all = append(all, variant.Raw)
	}
	for _, candidate := range all {
		for _, class := range fidelityClasses {
			if found[class] {
				continue
			}
			for _, pattern := range fidelitySignatures[class] {
				if pattern.MatchString(candidate) {
					found[class] = true
					break
				}
			}
		}
	}
	classes := make([]string, 0, len(found))
	for _, class := range fidelityClasses {
		if found[class] {
			classes = append(classes, class)
		}
	}
	verdict := FidelityVerdict{Classes: classes, NoEvidence: len(classes) == 0}
	if wantClass != "" {
		verdict.InClass = found[wantClass]
	}
	return verdict
}
