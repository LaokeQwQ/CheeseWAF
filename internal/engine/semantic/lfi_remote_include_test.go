package semantic

import "testing"

func TestLFIRemoteIncludeContextRequiresSinkEvidenceForGenericFilename(t *testing.T) {
	cases := []struct {
		name, field, value string
		want               bool
	}{
		{name: "explicit include remains broad", field: "include", value: "https://attacker.example.test/loader", want: true},
		{name: "explicit require remains broad", field: "require", value: "ftp://attacker.example.test/loader", want: true},
		{name: "filename executable target", field: "filename", value: "https://attacker.example.test/loader.php", want: true},
		{name: "filename remote media", field: "filename", value: "https://cdn.example.test/embed/clip", want: false},
		{name: "filename ordinary document", field: "filename", value: "https://cdn.example.test/assets/report.pdf", want: false},
		{name: "language URL is a fetch value", field: "lang", value: "https://cdn.example.test/locales/en.json", want: false},
		{name: "locale URL is a fetch value", field: "locale", value: "https://cdn.example.test/locales/en.json", want: false},
		{name: "URL field remains SSRF-only", field: "url", value: "https://attacker.example.test/loader.php", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := lfiRemoteIncludeContext(tc.field, tc.value); got != tc.want {
				t.Fatalf("lfiRemoteIncludeContext(%q, %q) = %v, want %v", tc.field, tc.value, got, tc.want)
			}
		})
	}
}

func TestLFIRemoteTelemetryFilenameURLStaysClean(t *testing.T) {
	body := `{"events":[{"clientError":{"stackTrace":{"browserStackInfo":{"filename":"https://media.example.test/embed/clip-123"}}}}]}`
	got := detectOnTarget(t, NewAnalyzer("block", 2), "POST", "/telemetry", "application/json", body)
	if got != nil && got.Detected {
		t.Fatalf("ordinary telemetry filename URL was flagged as %s: %+v", got.Category, got)
	}
}

func TestLFIRemoteIncludeFilenameExecutableURLStillBlocks(t *testing.T) {
	body := `{"filename":"https://attacker.example.test/loader.php"}`
	got := detectOnTarget(t, NewAnalyzer("block", 2), "POST", "/upload", "application/json", body)
	if got == nil || !got.Detected || got.Category != "lfi" {
		t.Fatalf("remote executable filename was not classified as LFI: %+v", got)
	}
}
