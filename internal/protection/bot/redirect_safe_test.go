package bot

import "testing"

func TestSafeRelativeRedirect(t *testing.T) {
	cases := map[string]string{
		"":                      "/",
		"/":                     "/",
		"/ok":                   "/ok",
		"/ok?x=1":               "/ok?x=1",
		"//evil.test":           "/",
		"/\\evil":               "/",
		"https://evil.test/":    "/",
		"http://evil.test/":     "/",
		"//":                    "/",
		"/\tevil":               "/",
		"/ok\nSet-Cookie: x":    "/",
		"ok":                    "/ok",
		"/%5C%5Cevil.example/x": "/",
		"/%2F%2Fevil.example/x": "/",
	}
	for in, want := range cases {
		if got := safeRelativeRedirect(in); got != want {
			t.Fatalf("safeRelativeRedirect(%q)=%q, want %q", in, got, want)
		}
	}
}
