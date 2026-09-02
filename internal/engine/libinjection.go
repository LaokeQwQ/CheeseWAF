// Package engine provides SQL token fingerprints and contextual XSS detection.
// The SQL path is a pure Go approximation of libinjection's fingerprint approach.
package engine

import (
	"strings"
	"unicode"
)

// SQL token types (mirrors libinjection SQLi token types)
const (
	tkSQLNone      = 0
	tkSQLKeyword   = 'k' // SQL keyword: SELECT, UNION, FROM, etc.
	tkSQLUnion     = 'U' // UNION keyword
	tkSQLGroup     = 'B' // GROUP keyword
	tkSQLExpr      = 'E' // EXEC keyword
	tkSQLComment   = 'c' // SQL comment -- /**/
	tkSQLString    = 's' // single-quoted string ''
	tkSQLDString   = 'S' // double-quoted string ""
	tkSQLNumber    = 'n' // numeric literal
	tkSQLVariable  = 'v' // placeholder/variable
	tkSQLFunction  = 'f' // function call like sleep(), benchmark()
	tkBareWord     = 'w' // bare identifier
	tkSQLOperator  = 'o' // comparison operator = <> != LIKE IN
	tkSQLLogic     = '&' // logical operator AND OR NOT
	tkSQLOpen      = '(' // open parenthesis
	tkSQLClose     = ')' // close parenthesis
	tkSQLTautology = 't' // boolean tautology (1=1, 'a'='a')
	tkSQLBacktick  = '`' // backtick quoted identifier
)

// Known SQLi fingerprints — token sequences that indicate SQL injection
// Based on libinjection's 5-char fingerprint signatures
var sqliFingerprints = map[string]bool{
	// UNION SELECT patterns
	"UEsn": true, "UEsnS": true, "UEnsn": true, "Ukwn": true,
	// Boolean tautology patterns
	"s&s": true, "s&n": true, "n&n": true, "S&S": true, "w&w": true,
	"sn&n": true, "sns&s": true, "w&n": true,
	// Comment truncation patterns
	"sc": true, "sns": true, "nsc": true,
	// Number-or-string concatenation
	"snf": true, "snsf": true, "wnf": true,
	// Reviewed patterns reachable under this tokenizer's alphabet.
	"kc": true, "nc": true, "Uwk": true, "Bn": true,
	"fws": true, "Ew": true, "Ef": true, "o(": true, "&t": true,
	// Procedure/function attacks
	"f(": true, "f(n": true, "f(s": true,
	// Keyword-from patterns (SELECT ... FROM, EXEC ... FROM)
	"kwk": true, "kwkw": true, "k(k": true, "kkw": true,
	// DB enumeration probes (bare keyword after string)
	"sk": true, "skw": true, "ksk": true,
	// Parenthesized subqueries
	"(k": true, "(U": true, ")U": true,
	// Tautology in parens
	"(&": true, "&)": true, "n&)": true,
	// DB enumeration probes (SELECT keyword then FROM keyword then table)
}

// SQLLibinjectionFingerprint tokenizes an SQL string and returns a fingerprint string.
// Returns empty string if the input doesn't look like SQL.
// If the fingerprint matches known SQLi patterns, the input is SQLi.
func SQLLibinjectionFingerprint(input string) (string, bool) {
	tokens := tokenizeSQL(input)
	if len(tokens) == 0 {
		return "", false
	}
	fp := fingerprint(tokens)
	if len(fp) < 2 {
		return fp, false
	}
	// Scan every 2-to-6-token window for known attack fingerprints.
	for i := 0; i <= len(fp)-2; i++ {
		for j := i + 2; j <= i+6 && j <= len(fp); j++ {
			window := string(fp[i:j])
			if sqliFingerprints[window] {
				return fp, true
			}
		}
	}
	return fp, false
}

func tokenizeSQL(input string) string {
	var tokens strings.Builder
	input = strings.TrimSpace(input)
	for i := 0; i < len(input); {
		// Skip whitespace
		if input[i] == ' ' || input[i] == '\t' || input[i] == '\n' || input[i] == '\r' {
			i++
			continue
		}
		// HTTP media-type wildcards such as `Accept: */*;q=0.8` contain the
		// byte sequence `/*`, but it is not an SQL block comment.  Keep the
		// exception deliberately boundary-aware: a real SQL expression such as
		// `1*/*comment*/2` has non-delimiter bytes after the second `*` and still
		// tokenizes as a comment.  The wildcard is skipped one byte at a time so
		// the surrounding header/value tokens remain available to the fingerprint.
		if isMIMEWildcardAt(input, i) {
			i++
			continue
		}
		if consumed := consumeTautology(input[i:]); consumed > 0 {
			tokens.WriteByte(tkSQLTautology)
			i += consumed
			continue
		}
		token, consumed := nextToken(input[i:])
		if token > 0 {
			tokens.WriteByte(token)
		}
		i += consumed
	}
	return tokens.String()
}

func isMIMEWildcardAt(input string, slash int) bool {
	if slash <= 0 || slash+1 >= len(input) || input[slash] != '/' || input[slash-1] != '*' || input[slash+1] != '*' {
		return false
	}
	// A wildcard is safe to ignore when it is anchored to an HTTP media-type
	// header or an explicitly named JSON accept field.  Looking for the field
	// context prevents a SQL expression such as `1*/* comment */2` from being
	// rewritten merely because a space follows the opening comment marker.
	lineStart := strings.LastIndexAny(input[:slash], "\r\n") + 1
	line := input[lineStart:slash]
	lowerLine := strings.ToLower(line)
	if strings.Contains(lowerLine, "accept:") || strings.Contains(lowerLine, "content-type:") {
		return true
	}
	if mimeJSONAcceptContext(lowerLine) {
		return true
	}

	// Header values are also passed to the engine without their field name.
	// Recognise only a comma-separated media-type list (text/html,*/*), never a
	// generic `*/*` sequence embedded in an expression or source document.
	star := slash - 1
	boundary := star - 1
	for boundary >= lineStart && (line[boundary-lineStart] == ' ' || line[boundary-lineStart] == '\t') {
		boundary--
	}
	if boundary >= lineStart && input[boundary] == ',' {
		segmentStart := boundary - 1
		for segmentStart >= lineStart && input[segmentStart] != ',' {
			segmentStart--
		}
		if looksLikeMIMEType(strings.TrimSpace(input[segmentStart+1 : boundary])) {
			return true
		}
	}

	// A standalone wildcard value is common in an Accept header after the
	// header name has been stripped.  Require either a quality parameter or the
	// complete value; an opening SQL comment followed by prose must not match.
	if boundary < lineStart {
		rest := strings.TrimSpace(input[slash+2:])
		if rest == "" || strings.HasPrefix(strings.ToLower(rest), ";q=") {
			return true
		}
	}
	return false
}

func mimeJSONAcceptContext(lowerLine string) bool {
	for offset := 0; ; {
		index := strings.Index(lowerLine[offset:], `"accept"`)
		if index < 0 {
			return false
		}
		index += offset + len(`"accept"`)
		for index < len(lowerLine) && (lowerLine[index] == ' ' || lowerLine[index] == '\t') {
			index++
		}
		if index < len(lowerLine) && lowerLine[index] == ':' {
			return true
		}
		offset = index
		if offset >= len(lowerLine) {
			return false
		}
	}
}

func looksLikeMIMEType(value string) bool {
	if semi := strings.IndexByte(value, ';'); semi >= 0 {
		value = strings.TrimSpace(value[:semi])
	}
	slash := strings.IndexByte(value, '/')
	if slash <= 0 || slash == len(value)-1 || strings.IndexByte(value[slash+1:], '/') >= 0 {
		return false
	}
	for i := 0; i < len(value); i++ {
		if i == slash {
			continue
		}
		c := value[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || strings.ContainsRune("!#$&^_.+-", rune(c)) {
			continue
		}
		return false
	}
	return true
}

func nextToken(s string) (byte, int) {
	if len(s) == 0 {
		return 0, 0
	}

	switch {
	// Single quoted string
	case s[0] == '\'':
		end := strings.IndexByte(s[1:], '\'')
		if end < 0 {
			end = len(s) - 1
		}
		return tkSQLString, end + 2

	// Double quoted string
	case s[0] == '"':
		end := strings.IndexByte(s[1:], '"')
		if end < 0 {
			end = len(s) - 1
		}
		return tkSQLDString, end + 2

	// Backtick quoted
	case s[0] == '`':
		end := strings.IndexByte(s[1:], '`')
		if end < 0 {
			end = len(s) - 1
		}
		return tkSQLBacktick, end + 2

	// Parentheses
	case s[0] == '(':
		return tkSQLOpen, 1
	case s[0] == ')':
		return tkSQLClose, 1

	// Prepared-statement placeholders and named variables.
	case s[0] == '?':
		return tkSQLVariable, 1
	case s[0] == '$' && len(s) > 1 && s[1] >= '0' && s[1] <= '9':
		return tkSQLVariable, 1 + consumeWhile(s[1:], unicode.IsDigit)
	case s[0] == ':' && len(s) > 1 && (unicode.IsLetter(rune(s[1])) || s[1] == '_'):
		return tkSQLVariable, 1 + consumeWhile(s[1:], func(r rune) bool {
			return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_'
		})

	// Operators and comparisons
	case len(s) >= 2 && (s[:2] == "<>" || s[:2] == "!=" || s[:2] == "<=" || s[:2] == ">=" || s[:2] == "||"):
		return tkSQLOperator, 2
	case s[0] == '=' || s[0] == '<' || s[0] == '>' || s[0] == '!':
		return tkSQLOperator, 1

	// Numeric literal
	case s[0] >= '0' && s[0] <= '9':
		j := consumeWhile(s, unicode.IsDigit)
		if j < len(s) && s[j] == 'x' {
			j++
			j += consumeWhile(s[j:], unicode.IsDigit)
		} // 0x hex
		return tkSQLNumber, j

	// Comments
	case len(s) >= 2 && s[:2] == "--":
		end := strings.Index(s, "\n")
		if end < 0 {
			end = len(s)
		}
		return tkSQLComment, end
	case len(s) >= 2 && s[:2] == "/*":
		end := strings.Index(s, "*/")
		if end < 0 {
			end = len(s)
		}
		return tkSQLComment, end + 2
	case s[0] == '#':
		end := strings.Index(s, "\n")
		if end < 0 {
			end = len(s)
		}
		return tkSQLComment, end
	}

	// Word/alphanumeric — check for keywords
	wordLen := consumeWhile(s, func(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' })
	if wordLen > 0 {
		word := strings.ToUpper(s[:wordLen])
		switch word {
		case "SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER", "TRUNCATE", "GRANT", "REVOKE", "FROM", "WHERE", "TABLE_NAME", "NULL", "INFORMATION_SCHEMA":
			return tkSQLKeyword, wordLen
		case "EXEC", "EXECUTE":
			return tkSQLExpr, wordLen
		case "UNION":
			return tkSQLUnion, wordLen
		case "GROUP", "ORDER", "HAVING":
			if word != "HAVING" {
				if phraseLen := consumeFollowingWord(s, wordLen, "BY"); phraseLen > wordLen {
					return tkSQLGroup, phraseLen
				}
			}
			return tkSQLGroup, wordLen
		case "AND", "OR", "NOT":
			return tkSQLLogic, wordLen
		case "SLEEP", "BENCHMARK", "WAITFOR", "PG_SLEEP", "LOAD_FILE", "XP_CMDSHELL", "DBMS_SQL", "CHAR", "UNHEX", "HEX", "SQLCODE":
			return tkSQLFunction, wordLen
		case "LIKE", "IN", "BETWEEN", "REGEXP", "RLIKE":
			return tkSQLOperator, wordLen
		}
		return tkBareWord, wordLen
	}

	return 0, 1 // skip unknown single char
}

func consumeFollowingWord(s string, offset int, want string) int {
	i := offset
	for i < len(s) && unicode.IsSpace(rune(s[i])) {
		i++
	}
	start := i
	for i < len(s) && unicode.IsLetter(rune(s[i])) {
		i++
	}
	if strings.EqualFold(s[start:i], want) {
		return i
	}
	return offset
}

func consumeTautology(s string) int {
	left, consumed, ok := consumeSQLLiteral(s)
	if !ok {
		return 0
	}
	i := consumed
	for i < len(s) && unicode.IsSpace(rune(s[i])) {
		i++
	}
	if i >= len(s) || s[i] != '=' {
		return 0
	}
	i++
	if i < len(s) && s[i] == '=' {
		i++
	}
	for i < len(s) && unicode.IsSpace(rune(s[i])) {
		i++
	}
	right, rightLen, ok := consumeSQLLiteral(s[i:])
	if !ok || left != right {
		return 0
	}
	return i + rightLen
}

func consumeSQLLiteral(s string) (string, int, bool) {
	if len(s) == 0 {
		return "", 0, false
	}
	if s[0] >= '0' && s[0] <= '9' {
		n := consumeWhile(s, unicode.IsDigit)
		return s[:n], n, true
	}
	if s[0] != '\'' && s[0] != '"' {
		return "", 0, false
	}
	quote := s[0]
	end := strings.IndexByte(s[1:], quote)
	if end < 0 {
		return "", 0, false
	}
	return s[1 : end+1], end + 2, true
}

func consumeWhile(s string, fn func(rune) bool) int {
	i := 0
	for i < len(s) && fn(rune(s[i])) {
		i++
	}
	return i
}

func fingerprint(tokens string) string {
	// Collapse adjacent identical tokens except bare words. Keeping bare-word
	// runs distinguishes compact SQL grammar (SELECT a FROM b => kwkw) from
	// ordinary prose ("select a theme from the menu" => kwwkww).
	var fp strings.Builder
	for i := 0; i < len(tokens); i++ {
		if i > 0 && tokens[i] == tokens[i-1] && tokens[i] != tkBareWord {
			continue // collapse duplicates
		}
		fp.WriteByte(tokens[i])
	}
	return fp.String()
}

// XSSLibinjectionFingerprint retains the historical API name but performs
// context-aware substring matching; it is not a token fingerprint implementation.
func XSSLibinjectionFingerprint(input string) bool {
	lower := strings.ToLower(input)
	if strings.Contains(lower, "<script") ||
		strings.Contains(lower, "onerror=") ||
		strings.Contains(lower, "onload=") ||
		strings.Contains(lower, "<img") ||
		strings.Contains(lower, "<svg") ||
		strings.Contains(lower, "<meta") ||
		strings.Contains(lower, "expression(") {
		return true
	}
	if strings.Contains(lower, "javascript:") && hasHTMLAttributeURLContext(lower, "javascript:") {
		return true
	}
	if strings.Contains(lower, "data:text/html") && hasHTMLAttributeURLContext(lower, "data:text/html") {
		return true
	}
	if strings.Contains(lower, "<iframe") &&
		(strings.Contains(lower, "srcdoc=") ||
			hasHTMLAttributeURLContext(lower, "javascript:") ||
			hasHTMLAttributeURLContext(lower, "data:text/html")) {
		return true
	}
	return false
}

func hasHTMLAttributeURLContext(input, marker string) bool {
	idx := strings.Index(input, marker)
	if idx < 0 {
		return false
	}
	start := strings.LastIndex(input[:idx], "<")
	if start < 0 {
		return false
	}
	if close := strings.LastIndex(input[:idx], ">"); close > start {
		return false
	}
	attrWindow := input[start:idx]
	for _, attr := range []string{"href", "src", "srcset", "xlink:href", "formaction", "action", "poster", "codebase", "background", "longdesc", "profile", "usemap", "data", "content"} {
		if strings.Contains(attrWindow, attr+"=") {
			return true
		}
	}
	return false
}
