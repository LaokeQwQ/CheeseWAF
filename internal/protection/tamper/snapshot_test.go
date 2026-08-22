package tamper

import (
	"errors"
	"strings"
	"testing"
	"time"
)

var testMACKey = []byte("01234567890123456789012345678901")

func TestCompareDetectsBodyAndURLDrift(t *testing.T) {
	snapshot, err := Capture(testMACKey, "/assets/app.js?v=1", []byte("clean"), time.Unix(100, 0))
	if err != nil {
		t.Fatal(err)
	}

	drift, err := Compare(testMACKey, snapshot, snapshot.URL, []byte("changed"))
	if err != nil {
		t.Fatal(err)
	}
	if !drift.Changed || drift.Reason != "size_mismatch" || drift.Expected == drift.Actual {
		t.Fatalf("expected body drift, got %+v", drift)
	}

	drift, err = Compare(testMACKey, snapshot, "/assets/app.js?v=2", []byte("clean"))
	if err != nil {
		t.Fatal(err)
	}
	if !drift.Changed || drift.Reason != "url_mismatch" {
		t.Fatalf("expected URL-bound drift, got %+v", drift)
	}
}

func TestCompareRejectsWrongKeyAndMalformedSnapshot(t *testing.T) {
	snapshot, err := Capture(testMACKey, "/index.html", []byte("clean"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	wrongKey := []byte("abcdefghijklmnopqrstuvwxyzABCDEF")
	drift, err := Compare(wrongKey, snapshot, snapshot.URL, []byte("clean"))
	if err != nil {
		t.Fatal(err)
	}
	if !drift.Changed || drift.Reason != "body_mismatch" {
		t.Fatalf("wrong key did not invalidate snapshot: %+v", drift)
	}

	snapshot.MAC = "not-hex"
	if _, err := Compare(testMACKey, snapshot, snapshot.URL, []byte("clean")); !errors.Is(err, ErrInvalidSnapshot) {
		t.Fatalf("malformed snapshot error = %v", err)
	}
}

func TestVerifierUsesExactCanonicalURL(t *testing.T) {
	snapshot, err := Capture(testMACKey, "HTTPS://EXAMPLE.TEST/assets/app.js#ignored", []byte("clean"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewVerifier(testMACKey, []Snapshot{snapshot})
	if err != nil {
		t.Fatal(err)
	}
	if !verifier.HasSnapshot("https://example.test/assets/app.js") {
		t.Fatal("canonical URL did not resolve to configured snapshot")
	}
	drift, err := verifier.Compare("https://example.test/assets/app.js", []byte("clean"))
	if err != nil || drift.Changed {
		t.Fatalf("matching response drift=%+v err=%v", drift, err)
	}
	if canonical, err := CanonicalURL("https://example.test"); err != nil || canonical != "https://example.test/" {
		t.Fatalf("absolute root canonical=%q err=%v", canonical, err)
	}
}

func TestSnapshotValidationRejectsWeakKeysAndAmbiguousURLs(t *testing.T) {
	if _, err := Capture([]byte("short"), "/", nil, time.Now()); !errors.Is(err, ErrKeyRequired) {
		t.Fatalf("weak key error = %v", err)
	}
	for _, raw := range []string{"", "//other.example/path", "mailto:user@example.test", "/ok\r\nX-Test: value"} {
		if _, err := CanonicalURL(raw); !errors.Is(err, ErrInvalidResourceURL) {
			t.Fatalf("CanonicalURL(%q) error = %v", raw, err)
		}
	}
	if _, err := NewVerifier(testMACKey, []Snapshot{{URL: "/", MAC: strings.Repeat("0", 64), Size: -1}}); !errors.Is(err, ErrInvalidSnapshot) {
		t.Fatalf("negative size error = %v", err)
	}
}
