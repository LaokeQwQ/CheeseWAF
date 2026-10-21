package config

import "testing"

func TestNormalizeSiteDomain(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{" Example.COM. ", "example.com"},
		{"*.Example.COM", "*.example.com"},
		{"BÜCHER.example", "xn--bcher-kva.example"},
		{"127.0.0.1", "127.0.0.1"},
		{"[2001:db8::1]", "2001:db8::1"},
	} {
		got, err := normalizeSiteDomain(tc.input)
		if err != nil || got != tc.want {
			t.Errorf("normalizeSiteDomain(%q) = %q, %v; want %q", tc.input, got, err, tc.want)
		}
	}
	for _, input := range []string{"*", "example.com:80", "bad_host.example", "[[127.0.0.1]]", "[example.com]", "a..example", "https://example.com"} {
		if _, err := normalizeSiteDomain(input); err == nil {
			t.Errorf("invalid site domain %q was accepted", input)
		}
	}
}
