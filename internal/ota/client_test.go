package ota

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type otaRoundTripper func(*http.Request) (*http.Response, error)

func (f otaRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func validCandidate(sequence uint64) Candidate {
	return Candidate{
		ReleaseID:          "official/demo@1.0.0#1",
		Version:            "1.0.0",
		ReleaseSequence:    sequence,
		ResourceURL:        "https://res.cheesesec.com/sha256/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/demo-v1.crp",
		CRPSHA256:          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ManifestSHA256:     "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		SignatureSetSHA256: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		SourceRoot:         "vendor-root-v1",
		TrustLevel:         "official",
		SignatureStatus:    "verified",
	}
}

func indexBody(t *testing.T, index Index) string {
	t.Helper()
	data, err := json.Marshal(index)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func testClient(t *testing.T, body string, contentType string) *Client {
	t.Helper()
	transport := otaRoundTripper(func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{contentType}},
			Body:       io.NopCloser(strings.NewReader(body)),
			Request:    r,
		}, nil
	})
	client, err := NewClient(ClientOptions{
		HTTPClient: &http.Client{Transport: transport},
		Clock:      func() time.Time { return time.Unix(1_800_000_000, 0).UTC() },
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestNewClientPinsHTTPSOrigin(t *testing.T) {
	for _, raw := range []string{
		"http://ota.cheesesec.com",
		"https://other.example.com",
		"https://ota.cheesesec.com/v1",
		"https://user:pass@ota.cheesesec.com",
	} {
		if _, err := NewClient(ClientOptions{BaseURL: raw}); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("NewClient(%q) error=%v, want ErrInvalidConfig", raw, err)
		}
	}
}

func TestClientCheckBuildsPinnedReadOnlyRequestAndSelectsCandidate(t *testing.T) {
	candidate := validCandidate(3)
	client := testClient(t, indexBody(t, Index{
		APIVersion:    "ota.cheesesec.com/v1",
		IndexSequence: 7,
		Mode:          "pull-only",
		Releases:      []Candidate{candidate},
	}), "application/json; charset=utf-8")

	got, err := client.Check(context.Background(), Request{
		Channel:                "stable",
		CurrentIndexSequence:   6,
		CurrentReleaseSequence: 2,
	})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if got.ReleaseID != candidate.ReleaseID || got.IndexSequence != 7 {
		t.Fatalf("candidate=%+v, want release %s/index 7", got, candidate.ReleaseID)
	}
}

func TestClientCheckRejectsChannelAndSequenceRollbacks(t *testing.T) {
	client := testClient(t, indexBody(t, Index{
		APIVersion:    "ota.cheesesec.com/v1",
		IndexSequence: 4,
		Mode:          "pull-only",
		Releases:      []Candidate{validCandidate(2)},
	}), "application/json")
	if _, err := client.Check(context.Background(), Request{Channel: "preview"}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("invalid channel error=%v", err)
	}
	if _, err := client.Check(context.Background(), Request{Channel: "stable", CurrentIndexSequence: 5}); !errors.Is(err, ErrSequenceRollback) {
		t.Fatalf("index rollback error=%v", err)
	}
	if _, err := client.Check(context.Background(), Request{Channel: "stable", CurrentReleaseSequence: 3}); !errors.Is(err, ErrSequenceRollback) {
		t.Fatalf("release rollback error=%v", err)
	}
}

func TestClientCheckRejectsMalformedAndUnsafeIndexes(t *testing.T) {
	cases := []struct {
		name        string
		body        string
		contentType string
		want        error
	}{
		{
			name:        "unknown field",
			body:        `{"api_version":"ota.cheesesec.com/v1","index_sequence":1,"mode":"pull-only","releases":[],"extra":true}`,
			contentType: "application/json",
			want:        ErrInvalidIndex,
		},
		{
			name:        "non-json",
			body:        "{}",
			contentType: "text/plain",
			want:        ErrNonJSON,
		},
		{
			name: "bad resource binding",
			body: indexBody(t, Index{APIVersion: "ota.cheesesec.com/v1", IndexSequence: 1, Mode: "pull-only", Releases: []Candidate{func() Candidate {
				c := validCandidate(1)
				c.ResourceURL = "https://res.cheesesec.com/sha256/dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd/demo.crp"
				return c
			}()}}),
			contentType: "application/json",
			want:        ErrResourceMismatch,
		},
		{
			name: "withdrawn",
			body: indexBody(t, Index{APIVersion: "ota.cheesesec.com/v1", IndexSequence: 1, Mode: "pull-only", Releases: []Candidate{func() Candidate {
				c := validCandidate(1)
				c.SignatureStatus = "withdrawn"
				return c
			}()}}),
			contentType: "application/json",
			want:        ErrWithdrawnRelease,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := testClient(t, tc.body, tc.contentType)
			_, err := client.Check(context.Background(), Request{Channel: "stable"})
			if !errors.Is(err, tc.want) {
				t.Fatalf("error=%v, want %v", err, tc.want)
			}
		})
	}
}

func TestClientCheckRejectsRedirectOversizeAndSignatureStatus(t *testing.T) {
	redirectClient, err := NewClient(ClientOptions{HTTPClient: &http.Client{Transport: otaRoundTripper(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": []string{"https://evil.example/"}}, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
	})}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := redirectClient.Check(context.Background(), Request{Channel: "stable"}); !errors.Is(err, ErrRedirect) {
		t.Fatalf("redirect error=%v", err)
	}

	largeClient := testClient(t, strings.Repeat("x", 20), "application/json")
	largeClient.maxIndexBytes = 4
	if _, err := largeClient.Check(context.Background(), Request{Channel: "stable"}); !errors.Is(err, ErrIndexTooLarge) {
		t.Fatalf("oversize error=%v", err)
	}
}

func TestClientCheckReturnsUpToDate(t *testing.T) {
	candidate := validCandidate(3)
	client := testClient(t, indexBody(t, Index{APIVersion: "ota.cheesesec.com/v1", IndexSequence: 3, Mode: "pull-only", Releases: []Candidate{candidate}}), "application/json")
	if _, err := client.Check(context.Background(), Request{Channel: "stable", CurrentIndexSequence: 3, CurrentReleaseSequence: 3}); !errors.Is(err, ErrUpToDate) {
		t.Fatalf("up-to-date error=%v", err)
	}
}

func TestFileStateStoreIsAtomicAndStrict(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ota", "state.json")
	store, err := NewFileStateStore(path)
	if err != nil {
		t.Fatal(err)
	}
	state := LastKnownGood{IndexSequence: 4, ReleaseSequence: 3, ReleaseID: "official/demo@1.0.0#1", UpdatedAt: time.Unix(1_800_000_000, 0).UTC()}
	if err := store.Save(context.Background(), state); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got != state {
		t.Fatalf("state=%+v, want %+v", got, state)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if err := validateStateFilePermissions(path, info); err != nil {
		t.Fatalf("state file permissions: %v", err)
	}

	newer := LastKnownGood{IndexSequence: 5, ReleaseSequence: 4, ReleaseID: "official/demo@1.1.0#2", UpdatedAt: time.Unix(1_800_000_100, 0).UTC()}
	if err := store.Save(context.Background(), newer); err != nil {
		t.Fatalf("replace state: %v", err)
	}
	if got, err := store.Load(context.Background()); err != nil || got != newer {
		t.Fatalf("state after replacement=%+v err=%v, want %+v", got, err, newer)
	}
}

func TestFileStateStoreRequiresAbsolutePath(t *testing.T) {
	if _, err := NewFileStateStore("relative/state.json"); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("relative path error=%v", err)
	}
}
