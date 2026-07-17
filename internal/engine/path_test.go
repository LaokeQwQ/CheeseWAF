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
