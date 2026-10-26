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
	decoded, ok = stripMatrixSegments(decoded)
	if !ok {
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
func stripMatrixSegments(decoded string) (string, bool) {
	// Fast path: the overwhelming majority of requests carry no matrix
	// parameters, and this function runs once per request on the hot path.
	if !strings.Contains(decoded, ";") {
		return decoded, true
	}
	segments := strings.Split(decoded, "/")
	for i, segment := range segments {
		if strings.HasPrefix(segment, "..;") {
			return "", false
		}
		if idx := strings.IndexByte(segment, ';'); idx >= 0 {
			segments[i] = segment[:idx]
		}
	}
	return strings.Join(segments, "/"), true
}
