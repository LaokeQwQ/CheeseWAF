package engine

import (
	"strings"
	"testing"
)

// CHE-60: request-path parsing boundaries.
//
// The invariants below are the contract the rest of the pipeline relies on:
// every accepted path is absolute, NUL-free, fully decoded, free of parent
// traversal, and stable under re-normalization. A failure here is a parser
// defect, not a detector miss.

func che60PathSeeds() []string {
	return []string{
		"/",
		"",
		"/a/../b",
		"/%252e%252e/",
		"/..;/",
		"/a;b=1/c",
		"/%00",
		"/a%2f%2fb",
		"//host/path",
		"/a/./b/",
		"/%2e%2e%2f",
		"/a%5c..%5cb",
		"/a/.../b",
		"/a//b",
		"/./",
		"/..",
		"/../../etc/passwd",
		"/a/%2e%2e/%2e%2e/",
		"/;x",
		"/a;b/../c",
		"/%7f",
		"/%",
		"/%zz",
		"/bar;v=1/../baz",
		"/a/%00/b",
		"/\u00fc\u00f1\u00ee",
		"/a?b=c",
		"/a#b",
		"/%c0%ae%c0%ae/",
		"/%e0%80%ae%e0%80%ae/",
		"/..%5c..%5cWindows%5cwin.ini",
		"/%2e%2e%5c",
		"/a/%252e%252e/%252e%252e/",
	}
}

func TestCHE60NormalizeRequestPathBoundaries(t *testing.T) {
	for _, raw := range che60PathSeeds() {
		path, ok := NormalizeRequestPath(raw)
		if !ok {
			if path != "" {
				t.Fatalf("rejected path returned non-empty value %q for %q", path, raw)
			}
			continue
		}
		checkCHE60NormalizedPath(t, raw, path)
	}
}

func checkCHE60NormalizedPath(t *testing.T, raw, path string) {
	t.Helper()
	if path == "" || path == "." {
		t.Fatalf("accepted %q but produced unusable path %q", raw, path)
	}
	if !strings.HasPrefix(path, "/") {
		t.Fatalf("accepted %q but path %q is not absolute", raw, path)
	}
	if strings.ContainsRune(path, 0) {
		t.Fatalf("accepted %q but path %q retains a NUL byte", raw, path)
	}
	if strings.Contains(path, "%") {
		t.Fatalf("accepted %q but path %q still looks percent-encoded", raw, path)
	}
	if path == ".." || strings.HasPrefix(path, "../") || strings.Contains(path, "/../") || strings.HasSuffix(path, "/..") {
		t.Fatalf("accepted %q but path %q retains parent traversal", raw, path)
	}
}

// TestCHE60NormalizedPathIsStable pins re-normalization stability. Downstream
// consumers re-normalize rewritten paths and ACL prefixes, so a path that
// changes shape on the second pass would be evaluated under a different view.
func TestCHE60NormalizedPathIsStable(t *testing.T) {
	for _, raw := range che60PathSeeds() {
		path, ok := NormalizeRequestPath(raw)
		if !ok {
			continue
		}
		again, okAgain := NormalizeRequestPath(path)
		if !okAgain {
			t.Fatalf("normalized path %q (from %q) is rejected on the second pass", path, raw)
		}
		if again != path {
			t.Fatalf("path %q from %q is not stable: second pass produced %q", path, raw, again)
		}
	}
}

// TestCHE60SecurityPathViewsContainCleanAndRaw pins the routing-view contract:
// the raw path is always retained, the cleaned path is always present, views
// are unique, and no view smuggles a NUL or residual encoding.
func TestCHE60SecurityPathViewsContainCleanAndRaw(t *testing.T) {
	for _, raw := range che60PathSeeds() {
		views, ok := SecurityPathViews(raw)
		if !ok {
			if views != nil {
				t.Fatalf("invalid path %q produced views %v", raw, views)
			}
			continue
		}
		if len(views) == 0 {
			t.Fatalf("valid path %q produced no views", raw)
		}
		if views[0] != raw {
			t.Fatalf("path %q lost its raw view: first view %q", raw, views[0])
		}
		clean, cleanOK := NormalizeRequestPath(raw)
		if !cleanOK {
			t.Fatalf("path %q produced views but failed normalization", raw)
		}
		found := false
		seen := make(map[string]struct{}, len(views))
		for _, view := range views {
			if strings.ContainsRune(view, 0) {
				t.Fatalf("path %q produced a view containing NUL: %q", raw, view)
			}
			if _, dup := seen[view]; dup {
				t.Fatalf("path %q produced duplicate view %q", raw, view)
			}
			seen[view] = struct{}{}
			if view == clean {
				found = true
			}
		}
		if !found {
			t.Fatalf("path %q views %v do not include the cleaned path %q", raw, views, clean)
		}
	}
}

// FuzzCHE60NormalizeRequestPath explores the same contract on arbitrary input.
func FuzzCHE60NormalizeRequestPath(f *testing.F) {
	for _, seed := range che60PathSeeds() {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 1<<12 {
			return
		}
		path, ok := NormalizeRequestPath(raw)
		if !ok {
			if path != "" {
				t.Fatalf("rejected input %q returned %q", raw, path)
			}
			if views, vok := SecurityPathViews(raw); vok || views != nil {
				t.Fatalf("rejected input %q still produced views %v (ok=%v)", raw, views, vok)
			}
			return
		}
		checkCHE60NormalizedPath(t, raw, path)

		again, okAgain := NormalizeRequestPath(path)
		if !okAgain {
			t.Fatalf("normalized %q from %q rejected on second pass", path, raw)
		}
		if again != path {
			t.Fatalf("normalization of %q is unstable: %q != %q", raw, again, path)
		}

		views, vok := SecurityPathViews(raw)
		if !vok {
			t.Fatalf("accepted path %q had invalid security views", raw)
		}
		seen := make(map[string]struct{}, len(views))
		cleanFound := false
		for _, view := range views {
			if _, dup := seen[view]; dup {
				t.Fatalf("path %q produced duplicate view %q", raw, view)
			}
			seen[view] = struct{}{}
			if strings.ContainsRune(view, 0) {
				t.Fatalf("view for %q contains NUL: %q", raw, view)
			}
			if view == path {
				cleanFound = true
			}
		}
		if !cleanFound {
			t.Fatalf("views %v for %q omit the cleaned path %q", views, raw, path)
		}
	})
}
