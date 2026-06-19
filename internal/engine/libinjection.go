// Package engine provides libinjection-style deep tokenization for SQL and XSS detection.
// Pure Go reimplementation — no CGO dependency. Based on libinjection's token fingerprint approach.
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
	// Stacked queries
	"s;U": true, "s;E": true, "s;k": true,
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
	// Scan every 5-char window for known attack fingerprints
	for i := 0; i < len(fp)-2; i++ {
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
		token, consumed := nextToken(input[i:])
		if token > 0 {
			tokens.WriteByte(token)
		}
		i += consumed
	}
	return tokens.String()
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
		case "SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER", "TRUNCATE", "GRANT", "REVOKE", "EXEC", "EXECUTE":
			return tkSQLKeyword, wordLen
		case "UNION":
			return tkSQLUnion, wordLen
		case "GROUP", "ORDER", "HAVING":
			return tkSQLGroup, wordLen
		case "AND", "OR", "NOT":
			return tkSQLLogic, wordLen
		case "SLEEP", "BENCHMARK", "WAITFOR", "PG_SLEEP":
			return tkSQLFunction, wordLen
		case "LIKE", "IN", "BETWEEN", "REGEXP", "RLIKE":
			return tkSQLOperator, wordLen
		case "INFORMATION_SCHEMA":
			return tkSQLKeyword, wordLen
		}
		return tkBareWord, wordLen
	}

	return 0, 1 // skip unknown single char
}

func consumeWhile(s string, fn func(rune) bool) int {
	i := 0
	for i < len(s) && fn(rune(s[i])) {
		i++
	}
	return i
}

func fingerprint(tokens string) string {
	// Collapse adjacent identical tokens
	var fp strings.Builder
	for i := 0; i < len(tokens); i++ {
		if i > 0 && tokens[i] == tokens[i-1] {
			continue // collapse duplicates
		}
		fp.WriteByte(tokens[i])
	}
	return fp.String()
}

// === XSS libinjection-style tokenizer ===

const (
	tkXSSNone     = 0
	tkXSSTagOpen  = '<'  // <
	tkXSSTagClose = '>'  // >
	tkXSSQuoteD   = '"'  // "
	tkXSSQuoteS   = '\'' // '
	tkXSSEquals   = '='  // =
	tkXSSText     = 'T'  // text content
	tkXSSScript   = 'J'  // javascript: URL
	tkXSSData     = 'D'  // data: URL
	tkXSSEvent    = 'E'  // event handler like onerror, onload
	tkXSSFunc     = 'F'  // function call alert(), eval()
	tkXSSSlash    = '/'  // /
)

// XSSLibinjectionFingerprint detects XSS patterns using token-based analysis
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
