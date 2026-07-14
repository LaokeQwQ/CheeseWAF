package engine

import (
	"path"
	"strings"
)

// NormalizeRequestPath cleans a URL path for security policy matching.
// It uses path.Clean, ensures a leading "/", and rejects empty paths,
// NUL bytes, and any residual ".." segments after cleaning.
func NormalizeRequestPath(raw string) (string, bool) {
	if raw == "" || strings.ContainsRune(raw, 0) {
		return "", false
	}
	cleaned := path.Clean(raw)
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
	return cleaned, true
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
