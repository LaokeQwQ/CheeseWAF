// Package fsguard centralizes filesystem and URL path safety for operator-configured
// paths and same-origin relative redirects.
package fsguard

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"unicode"
)

const maxSecretFileBytes = 64 << 10

// SafeConfigPath returns a cleaned absolute path for operator-configured files.
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

// RelUnderRoot converts candidate (absolute or relative) into a filepath.IsLocal
// relative path under root. This is the shape CodeQL documents as safe
// (join with a root + local relative component checks).
func RelUnderRoot(root, candidate string) (string, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		return "", fmt.Errorf("root is required")
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	rootAbs = filepath.Clean(rootAbs)
	rootAbs = evalExistingPrefix(rootAbs)

	candidate = strings.TrimSpace(candidate)
	if candidate == "" {
		return "", fmt.Errorf("path is required")
	}
	if strings.ContainsRune(candidate, 0) {
		return "", fmt.Errorf("path contains NUL")
	}

	var rel string
	if filepath.IsAbs(candidate) {
		candAbs := filepath.Clean(candidate)
		candAbs = evalExistingPrefix(candAbs)
		rel, err = filepath.Rel(rootAbs, candAbs)
		if err != nil {
			return "", fmt.Errorf("path not under root: %w", err)
		}
	} else {
		rel = filepath.Clean(candidate)
	}
	// filepath.IsLocal rejects absolute paths, "..", and empty after clean (Go 1.20+).
	if rel == "." {
		return "", fmt.Errorf("path must not be the root itself")
	}
	if !filepath.IsLocal(rel) {
		return "", fmt.Errorf("path must be a local path under root")
	}
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		if part == "" {
			continue
		}
		if err := SafePathComponent(part); err != nil {
			return "", err
		}
	}
	return rel, nil
}

// SafeConfigPathUnderRoot returns root-joined absolute path after RelUnderRoot.
func SafeConfigPathUnderRoot(path, root string) (string, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		return SafeConfigPath(path)
	}
	rel, err := RelUnderRoot(root, path)
	if err != nil {
		return "", err
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Clean(rootAbs), rel), nil
}

// ReadFileUnderRoot reads a file confined under root using os.OpenRoot (no
// absolute user path is passed to os.ReadFile).
func ReadFileUnderRoot(root, path string, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		maxBytes = maxSecretFileBytes
	}
	rootAbs, err := filepath.Abs(strings.TrimSpace(root))
	if err != nil {
		return nil, err
	}
	rootAbs = filepath.Clean(rootAbs)
	rel, err := RelUnderRoot(rootAbs, path)
	if err != nil {
		return nil, err
	}
	rt, err := os.OpenRoot(rootAbs)
	if err != nil {
		return nil, fmt.Errorf("open root: %w", err)
	}
	defer rt.Close()
	f, err := rt.Open(rel)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, maxBytes))
}

// OpenRoot opens an os.Root at an absolute root path that has already been
// confined (typically dataDir or an asset directory under it).
func OpenRoot(root string) (*os.Root, error) {
	rootAbs, err := filepath.Abs(strings.TrimSpace(root))
	if err != nil {
		return nil, err
	}
	rootAbs = filepath.Clean(rootAbs)
	if !filepath.IsAbs(rootAbs) {
		return nil, fmt.Errorf("root must be absolute")
	}
	return os.OpenRoot(rootAbs)
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

// IsLocalRedirect reports whether s is a same-origin relative redirect target.
// This is the exact second-character barrier shape CodeQL documents for
// go/unvalidated-url-redirection and go/bad-redirect-check.
func IsLocalRedirect(s string) bool {
	return len(s) > 0 && s[0] == '/' && (len(s) == 1 || (s[1] != '/' && s[1] != '\\'))
}

// IsLocalURL reports whether raw is a same-origin relative URL safe for
// http.Redirect. The function name matches CodeQL's RedirectCheckBarrier
// (isLocalURL / isValidRedirect), which treats a true result as a barrier.
// Implementation follows CodeQL's documented fix: replace '\', parse, require
// empty Hostname (relative URL).
func IsLocalURL(raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false
	}
	// Browsers treat '\' as '/'; normalize before parse (CodeQL recommendation).
	raw = strings.ReplaceAll(raw, "\\", "/")
	if strings.HasPrefix(raw, "//") {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	// Empty hostname means relative / same-origin path (not //host or scheme://host).
	if u.Hostname() != "" || u.Scheme != "" || u.Opaque != "" || u.User != nil {
		return false
	}
	path := u.EscapedPath()
	if path == "" {
		if u.RawQuery == "" && u.Fragment == "" {
			return false
		}
		path = "/"
	}
	// Second-character rule: not scheme-relative after leading slash.
	if !IsLocalRedirect(path) {
		return false
	}
	return true
}

// SanitizeLocalRedirect returns a same-origin relative path (leading '/',
// second byte neither '/' nor '\\'). Unsafe input collapses to "/".
func SanitizeLocalRedirect(redir string) string {
	redir = strings.TrimSpace(redir)
	if redir == "" {
		return "/"
	}
	for _, r := range redir {
		if r < 0x20 || r == 0x7f {
			return "/"
		}
	}
	// Normalize browser-equivalent separators before any other check.
	redir = strings.ReplaceAll(redir, "\\", "/")
	// Decode %XX once (encoded // or /\ bypasses).
	if decoded, err := pathUnescape(redir); err == nil {
		redir = strings.ReplaceAll(decoded, "\\", "/")
	} else {
		return "/"
	}
	if strings.Contains(strings.ToLower(redir), "://") {
		return "/"
	}
	// Scheme-relative URLs (//host or /\host after normalize) are absolute for browsers.
	if strings.HasPrefix(redir, "//") {
		return "/"
	}
	// Drop fragment; keep query only after path collapse.
	pathPart := redir
	query := ""
	if i := strings.IndexByte(redir, '?'); i >= 0 {
		pathPart = redir[:i]
		query = redir[i+1:]
	}
	if i := strings.IndexByte(pathPart, '#'); i >= 0 {
		pathPart = pathPart[:i]
	}
	if !strings.HasPrefix(pathPart, "/") {
		pathPart = "/" + pathPart
	}
	// Reject before collapse so "//evil" cannot become "/evil".
	if len(pathPart) > 1 && (pathPart[1] == '/' || pathPart[1] == '\\') {
		return "/"
	}
	pathPart = collapseLocalPath(pathPart)
	// CodeQL-recognized second-character guard on the returned value.
	if !IsLocalRedirect(pathPart) {
		return "/"
	}
	if query != "" {
		for _, r := range query {
			if r < 0x20 || r == 0x7f {
				return "/"
			}
		}
		out := pathPart + "?" + query
		if IsLocalRedirect(out) {
			return out
		}
		return "/"
	}
	return pathPart
}

// SafeRelativeRedirect is an alias of SanitizeLocalRedirect.
func SafeRelativeRedirect(raw string) string {
	return SanitizeLocalRedirect(raw)
}

func collapseLocalPath(pathPart string) string {
	pathPart = strings.ReplaceAll(pathPart, "\\", "/")
	if pathPart == "" {
		pathPart = "/"
	}
	if !strings.HasPrefix(pathPart, "/") {
		pathPart = "/" + pathPart
	}
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
	return out
}

func pathUnescape(s string) (string, error) {
	// net/url.PathUnescape without importing cycle issues — thin wrapper.
	return urlPathUnescape(s)
}

// evalExistingPrefix resolves symlinks for the longest existing path prefix
// (needed on macOS where /var -> /private/var).
func evalExistingPrefix(p string) string {
	p = filepath.Clean(p)
	if resolved, err := filepath.EvalSymlinks(p); err == nil {
		return filepath.Clean(resolved)
	}
	rest := make([]string, 0, 8)
	cur := p
	for {
		parent := filepath.Dir(cur)
		if parent == cur {
			return p
		}
		rest = append(rest, filepath.Base(cur))
		if resolved, err := filepath.EvalSymlinks(parent); err == nil {
			// rest is leaf..child order; reverse when joining
			for i, j := 0, len(rest)-1; i < j; i, j = i+1, j-1 {
				rest[i], rest[j] = rest[j], rest[i]
			}
			return filepath.Clean(filepath.Join(append([]string{resolved}, rest...)...))
		}
		cur = parent
	}
}
