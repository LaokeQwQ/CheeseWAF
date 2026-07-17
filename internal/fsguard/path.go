// Package fsguard centralizes filesystem and URL path safety for operator-configured
// paths and same-origin relative redirects.
package fsguard

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"unicode"
)

// SafeConfigPath returns a cleaned absolute path for operator-configured files
// (credential paths, asset roots, integrity keys).
func SafeConfigPath(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", fmt.Errorf("path is required")
	}
	if strings.ContainsRune(path, 0) {
		return "", fmt.Errorf("path contains NUL")
	}
	for _, r := range path {
		if r < 0x20 || r == 0x7f {
			return "", fmt.Errorf("path contains control characters")
		}
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve path: %w", err)
	}
	clean := filepath.Clean(abs)
	if !filepath.IsAbs(clean) {
		return "", fmt.Errorf("path must be absolute")
	}
	for _, part := range strings.FieldsFunc(clean, func(r rune) bool {
		return r == filepath.Separator || r == '/' || r == '\\'
	}) {
		if part == ".." {
			return "", fmt.Errorf("path must not contain parent segments")
		}
	}
	if clean == "." || clean == string(filepath.Separator) {
		return "", fmt.Errorf("path is not usable")
	}
	base := filepath.Base(clean)
	if base == "" || base == "." || base == ".." || strings.Contains(base, ":") {
		return "", fmt.Errorf("path basename is not usable")
	}
	return clean, nil
}

// SafeConfigPathUnderRoot is SafeConfigPath plus a required containment check
// under root (typically the process data directory). Empty root skips containment.
// When paths exist, symlinks are resolved so a link cannot escape the root.
func SafeConfigPathUnderRoot(path, root string) (string, error) {
	clean, err := SafeConfigPath(path)
	if err != nil {
		return "", err
	}
	root = strings.TrimSpace(root)
	if root == "" {
		return clean, nil
	}
	rootClean, err := SafeConfigPath(root)
	if err != nil {
		return "", fmt.Errorf("root: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(clean); err == nil {
		clean = filepath.Clean(resolved)
	} else if !os.IsNotExist(err) {
		// Path exists but cannot be resolved (ELOOP, permission): fail closed.
		if _, statErr := os.Lstat(clean); statErr == nil {
			return "", fmt.Errorf("resolve path symlinks: %w", err)
		}
	}
	if resolvedRoot, err := filepath.EvalSymlinks(rootClean); err == nil {
		rootClean = filepath.Clean(resolvedRoot)
	}
	sep := string(filepath.Separator)
	if clean != rootClean && !strings.HasPrefix(clean, rootClean+sep) {
		return "", fmt.Errorf("path %q escapes allowed root %q", clean, rootClean)
	}
	return clean, nil
}

// SafePathComponent rejects names that could escape an openat/Mkdirat root.
func SafePathComponent(name string) error {
	if name == "" || name == "." || name == ".." {
		return fmt.Errorf("invalid path component %q", name)
	}
	if strings.ContainsRune(name, 0) || strings.ContainsAny(name, `/\`) {
		return fmt.Errorf("invalid path component %q", name)
	}
	if filepath.Base(name) != name {
		return fmt.Errorf("invalid path component %q", name)
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f || unicode.IsSpace(r) {
			return fmt.Errorf("invalid path component %q", name)
		}
	}
	return nil
}

// SafeRelativeRedirect allows only same-origin relative paths for redirects.
func SafeRelativeRedirect(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "/"
	}
	for _, r := range raw {
		if r < 0x20 || r == 0x7f {
			return "/"
		}
	}
	// Fast reject of absolute / scheme-relative forms before parse.
	lower := strings.ToLower(raw)
	if strings.Contains(lower, "://") || strings.HasPrefix(raw, "//") || strings.HasPrefix(raw, "\\") {
		return "/"
	}
	// Keep only path + query; drop fragment.
	pathPart := raw
	query := ""
	if i := strings.IndexByte(raw, '?'); i >= 0 {
		pathPart = raw[:i]
		query = raw[i+1:]
	}
	if i := strings.IndexByte(pathPart, '#'); i >= 0 {
		pathPart = pathPart[:i]
	}
	pathPart = strings.ReplaceAll(pathPart, "\\", "/")
	// Decode %XX once so encoded backslashes / slashes cannot bypass checks.
	if decoded, err := url.PathUnescape(pathPart); err == nil {
		pathPart = strings.ReplaceAll(decoded, "\\", "/")
	} else {
		return "/"
	}
	if pathPart == "" {
		pathPart = "/"
	}
	if !strings.HasPrefix(pathPart, "/") {
		pathPart = "/" + pathPart
	}
	if len(pathPart) >= 2 {
		switch pathPart[1] {
		case '/', '\\':
			return "/"
		}
	}
	if strings.HasPrefix(pathPart, "//") || strings.Contains(pathPart, "://") || strings.Contains(pathPart, "\\") {
		return "/"
	}
	// Collapse . and .. without allowing escape above root.
	parts := strings.Split(pathPart, "/")
	stack := make([]string, 0, len(parts))
	for _, p := range parts {
		if p == "" || p == "." {
			continue
		}
		if p == ".." {
			if len(stack) == 0 {
				return "/"
			}
			stack = stack[:len(stack)-1]
			continue
		}
		stack = append(stack, p)
	}
	out := "/" + strings.Join(stack, "/")
	if out != "/" && strings.HasSuffix(pathPart, "/") {
		out += "/"
	}
	if query != "" {
		// Reject query control / CRLF smuggling into Location.
		for _, r := range query {
			if r < 0x20 || r == 0x7f {
				return "/"
			}
		}
		out += "?" + query
	}
	if !strings.HasPrefix(out, "/") || strings.HasPrefix(out, "//") {
		return "/"
	}
	if len(out) >= 2 && (out[1] == '/' || out[1] == '\\') {
		return "/"
	}
	return out
}
