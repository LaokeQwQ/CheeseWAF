package engine

import (
	"net/url"
	"path"
	"strings"
)

// NormalizeRequestPath cleans a URL path for security policy matching.
// It repeatedly URL-decodes (up to a safe cap), then path.Clean, ensures a
// leading "/", and rejects empty paths, NUL bytes, residual encodings, and
// residual ".." segments after cleaning.
func NormalizeRequestPath(raw string) (string, bool) {
	if raw == "" || strings.ContainsRune(raw, 0) {
		return "", false
	}
	decoded, ok := fullyDecodePath(raw, 5)
	if !ok {
		return "", false
	}
	if hasMatrixParentSegment(decoded) {
		return "", false
	}
	cleaned := path.Clean(decoded)
	if cleaned == "" || cleaned == "." {
		return "", false
	}
	if !strings.HasPrefix(cleaned, "/") {
		cleaned = path.Clean("/" + cleaned)
	}
	if cleaned == "" || cleaned == "." {
		return "", false
	}
	// Absolute Clean never retains ".." segments, but guard explicitly.
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") || strings.Contains(cleaned, "/../") || strings.HasSuffix(cleaned, "/..") {
		return "", false
	}
	// Residual percent-encoding after full decode is treated as hostile.
	if strings.Contains(cleaned, "%") {
		return "", false
	}
	return cleaned, true
}

// SecurityPathViews preserves existing raw/clean policy meanings and adds the
// routing interpretation used by backends that strip matrix parameters. Use
// every view for protective requirements, not to broaden allowlist exemptions.
func SecurityPathViews(raw string) ([]string, bool) {
	cleaned, ok := NormalizeRequestPath(raw)
	if !ok {
		return nil, false
	}
	views := []string{raw}
	if cleaned != raw {
		views = append(views, cleaned)
	}
	if !strings.ContainsAny(raw, ";%") {
		return views, true
	}
	decoded, ok := fullyDecodePath(raw, 5)
	if !ok || !strings.ContainsRune(decoded, ';') {
		return views, ok
	}
	var stripped strings.Builder
	stripped.Grow(len(decoded))
	inParameter := false
	for i := 0; i < len(decoded); i++ {
		switch decoded[i] {
		case '/':
			inParameter = false
			stripped.WriteByte('/')
		case ';':
			inParameter = true
		default:
			if !inParameter {
				stripped.WriteByte(decoded[i])
			}
		}
	}
	matrixPath := path.Clean(stripped.String())
	if !strings.HasPrefix(matrixPath, "/") {
		matrixPath = path.Clean("/" + matrixPath)
	}
	for _, view := range views {
		if view == matrixPath {
			return views, true
		}
	}
	return append(views, matrixPath), true
}

func hasMatrixParentSegment(decoded string) bool {
	if !strings.ContainsRune(decoded, ';') {
		return false
	}
	for start := 0; start < len(decoded); {
		if strings.HasPrefix(decoded[start:], "..;") {
			return true
		}
		end := strings.IndexByte(decoded[start:], '/')
		if end < 0 {
			return false
		}
		start += end + 1
	}
	return false
}

// fullyDecodePath repeatedly PathUnescapes until stable or maxRounds.
// Returns false if decoding fails or still looks encoded after maxRounds.
func fullyDecodePath(raw string, maxRounds int) (string, bool) {
	if maxRounds < 1 {
		maxRounds = 1
	}
	cur := raw
	for i := 0; i < maxRounds; i++ {
		next, err := url.PathUnescape(cur)
		if err != nil {
			return "", false
		}
		if next == cur {
			return cur, true
		}
		if strings.ContainsRune(next, 0) {
			return "", false
		}
		cur = next
	}
	// Still changing after max rounds, or residual %XX patterns.
	if strings.Contains(cur, "%") {
		return "", false
	}
	return cur, true
}

// PathMatchesPrefix reports whether requestPath equals prefix or is a child
// under prefix using segment boundaries. Trailing slashes on prefix are ignored
// except that "/" matches every absolute path. Empty prefix matches all paths.
//
// Examples: prefix "/api" or "/api/" matches "/api" and "/api/foo" but not "/apixyz".
func PathMatchesPrefix(requestPath, prefix string) bool {
	if prefix == "" {
		return true
	}
	if requestPath == "" {
		return false
	}
	base := strings.TrimRight(prefix, "/")
	if base == "" {
		return strings.HasPrefix(requestPath, "/")
	}
	return requestPath == base || strings.HasPrefix(requestPath, base+"/")
}

// stripMatrixSegments applies the two-level matrix-parameter policy used by
// servlet containers and IIS: a segment beginning "..;" is a parent-directory
// reference that path.Clean cannot see, so it fails closed; any other segment
// loses its ";" suffix so policy matching sees the path the backend routes on.
//
// This must run before path.Clean. Stripping first would rewrite "/a/..;/b"
// into "/a/../b", which Clean then folds into "/b" and reports as valid, so the
// traversal would pass silently.
