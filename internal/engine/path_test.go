package engine

import "testing"

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
