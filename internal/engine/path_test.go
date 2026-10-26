package engine

import (
	"reflect"
	"testing"
)

func TestSecurityPathViewsPreserveExistingSpellings(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		path string
		want []string
	}{
		{"/admin", []string{"/admin"}},
		{"//admin/panel", []string{"//admin/panel", "/admin/panel"}},
		{"/admin;v=1/panel", []string{"/admin;v=1/panel", "/admin/panel"}},
		{"/admin%253bv=1/panel", []string{"/admin%253bv=1/panel", "/admin;v=1/panel", "/admin/panel"}},
		{"/;jsessionid=A/admin", []string{"/;jsessionid=A/admin", "/admin"}},
		{"/a/;/b", []string{"/a/;/b", "/a/b"}},
		{"/..foo;bar/z", []string{"/..foo;bar/z", "/..foo/z"}},
	} {
		got, ok := SecurityPathViews(tc.path)
		if !ok || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("SecurityPathViews(%q) = (%q, %v), want %q", tc.path, got, ok, tc.want)
		}
	}
	for _, invalid := range []string{"", "/a/..;/b", "/a/%252e%252e%253b/b", "/%zz", "/a\x00b"} {
		if got, ok := SecurityPathViews(invalid); ok || got != nil {
			t.Errorf("invalid path %q returned (%q, %v)", invalid, got, ok)
		}
	}
}

func BenchmarkNormalizeRequestPath(b *testing.B) {
	for _, input := range []string{"/api/users/42", "/api/users;v=1/42"} {
		b.Run(input, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, ok := NormalizeRequestPath(input); !ok {
					b.Fatal("valid path rejected")
				}
			}
		})
	}
}

func TestNormalizeRequestPath(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in     string
		want   string
		wantOK bool
	}{
		{"/api/foo", "/api/foo", true},
		{"/api/../admin", "/admin", true},
		{"/health/../x", "/x", true},
		{"/admin/./page", "/admin/page", true},
		{"/api/", "/api", true},
		{"/", "/", true},
		{"admin", "/admin", true},
		{"", "", false},
		{"/foo\x00bar", "", false},
		{".", "", false},
		// Multi-pass decode + Clean collapses encoded traversal to the real path.
		{"/..%252fetc%252fpasswd", "/etc/passwd", true},
		{"/%2e%2e/%2e%2e/etc/passwd", "/etc/passwd", true},
		{"/api%2Fusers", "/api/users", true},
		// Matrix parent segments have ambiguous routing semantics. Ordinary
		// semicolon paths keep their existing spelling for allowlist matching.
		{"/a/..;/b", "", false},
		{"/a/%2e%2e%3bmode=1/b", "", false},
		{"/admin;v=1/panel", "/admin;v=1/panel", true},
		{"/..foo;bar/z", "/..foo;bar/z", true},
		// Invalid percent sequences fail closed.
		{"/%zz", "", false},
		// Matrix segments: "..;" is a parent-directory reference that path.Clean
		// cannot see (Tomcat/Jetty/Spring resolve it), so it fails closed.
		{"/a/..;/b", "", false},
		{"/api/v1/x/..;/..;/admin", "", false},
		{"/..%3b/admin", "", false},
		{"/%2e%2e%3b/admin", "", false},
		// Ordinary matrix parameters are stripped so policy matching sees the
		// path the backend will route on.
		{"/a;b=c/d", "/a/d", true},
		{"/;jsessionid=ABC123/admin", "/admin", true},
		{"/a/;/b", "/a/b", true},
		{"/matrix;x=1;y=2/z", "/matrix/z", true},
		// ".." not immediately followed by ";" is not a traversal; rejecting it
		// would break legitimate paths.
		{"/..foo;bar/z", "/..foo/z", true},
	}
	for _, tc := range cases {
		got, ok := NormalizeRequestPath(tc.in)
		if ok != tc.wantOK || got != tc.want {
			t.Fatalf("NormalizeRequestPath(%q) = (%q, %v), want (%q, %v)", tc.in, got, ok, tc.want, tc.wantOK)
		}
	}
}

func TestPathMatchesPrefix(t *testing.T) {
	t.Parallel()
	cases := []struct {
		path, prefix string
		want         bool
	}{
		{"/api", "/api/", true},
		{"/api/foo", "/api/", true},
		{"/api/foo", "/api", true},
		{"/apixyz", "/api", false},
		{"/apixyz", "/api/", false},
		{"/health", "/health", true},
		{"/health/live", "/health", true},
		{"/healthxyz", "/health", false},
		{"/anything", "/", true},
		{"/admin", "", true},
		{"", "/api", false},
	}
	for _, tc := range cases {
		if got := PathMatchesPrefix(tc.path, tc.prefix); got != tc.want {
			t.Fatalf("PathMatchesPrefix(%q, %q) = %v, want %v", tc.path, tc.prefix, got, tc.want)
		}
	}
}
