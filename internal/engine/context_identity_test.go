package engine

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type identityWireReader struct {
	*bytes.Reader
	read int
}

func (r *identityWireReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	r.read += n
	return n, err
}
func (*identityWireReader) Close() error { return nil }

type identityForbiddenBody struct{}

func (identityForbiddenBody) Read([]byte) (int, error) { panic("identity body must never be read") }
func (identityForbiddenBody) Close() error             { panic("identity body must never be closed") }

func TestDetectionViewKeepsIdentityAndImmutableBodyIndependent(t *testing.T) {
	var compressed bytes.Buffer
	w := gzip.NewWriter(&compressed)
	_, _ = io.WriteString(w, "field=shared")
	_ = w.Close()
	wire := &identityWireReader{Reader: bytes.NewReader(compressed.Bytes())}
	target := httptest.NewRequest(http.MethodPost, "http://example.test/target?target=1", nil)
	target.Body, target.ContentLength = wire, -1
	target.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	target.Header.Set("Content-Encoding", "gzip")
	source, err := NewRequestContextDeferredBody(target, "site", nil, 4096)
	if err != nil {
		t.Fatal(err)
	}
	source.HostValidated = true
	source.Metadata["nested"] = map[string]string{"policy": "clean"}
	public := httptest.NewRequest(http.MethodPost, "http://example.test/public?public=1", nil)
	public.Body = identityForbiddenBody{}
	a, err := source.DetectionView(public)
	if err != nil {
		t.Fatal(err)
	}
	b, err := source.DetectionView(target)
	if err != nil {
		t.Fatal(err)
	}
	fa := forkRequestContextWithContext(a, context.Background())
	fb := forkRequestContextWithContext(b, context.Background())
	for _, view := range []*RequestContext{fa, fb} {
		if err := view.EnsureBodyContext(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := view.Request.ParseForm(); err != nil || view.Request.Form.Get("field") != "shared" {
			t.Fatalf("body snapshot not replayed: form=%v err=%v", view.Request.Form, err)
		}
		if !view.HostValidated || len(view.Results) != 0 {
			t.Fatal("identity view lost host provenance or inherited detector results")
		}
	}
	if fa.NormalizedPath != "/public" || fa.DecodedURI != "/public?public=1" || fa.Request.RequestURI != "/public?public=1" || fa.Request.Form.Get("target") != "" {
		t.Fatalf("public identity was not isolated: path=%q uri=%q form=%v", fa.NormalizedPath, fa.DecodedURI, fa.Request.Form)
	}
	if fb.NormalizedPath != "/target" || fb.Request.Form.Get("public") != "" {
		t.Fatalf("target identity was contaminated: path=%q form=%v", fb.NormalizedPath, fb.Request.Form)
	}
	a.Metadata["nested"].(map[string]string)["policy"] = "mutated"
	a.Metadata["semantic_skipped"] = true
	a.Results = append(a.Results, DetectionResult{Detected: true})
	if b.Metadata["nested"].(map[string]string)["policy"] != "clean" || b.Metadata["semantic_skipped"] != nil || len(b.Results) != 0 || source.Request.URL.Path != "/target" {
		t.Fatal("identity metadata, evidence, or transport was shared")
	}
	replay, err := source.Request.GetBody()
	if err != nil {
		t.Fatal(err)
	}
	defer replay.Close()
	got, _ := io.ReadAll(replay)
	if wire.read != compressed.Len() || !bytes.Equal(got, compressed.Bytes()) {
		t.Fatal("original wire bytes were reread or rewritten")
	}
}

func TestDetectionBudgetResolverPreservesConfiguredBounds(t *testing.T) {
	p := NewPipeline()
	p.SetDetectionBudget(275 * time.Millisecond)
	if got := p.DetectionBudget(nil); got != 275*time.Millisecond {
		t.Fatalf("pipeline budget=%s", got)
	}
	for _, tc := range []struct {
		value any
		want  time.Duration
	}{{time.Nanosecond, time.Nanosecond}, {time.Duration(0), 100 * time.Millisecond}, {"31ms", 31 * time.Millisecond}, {6 * time.Second, 5 * time.Second}} {
		if got := p.DetectionBudget(&RequestContext{Metadata: map[string]any{"detection_budget": tc.value}}); got != tc.want {
			t.Fatalf("budget(%v)=%s, want %s", tc.value, got, tc.want)
		}
	}
}
