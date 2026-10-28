package adapterinspect

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

func testHandler(detect func(context.Context, *engine.RequestContext) (*engine.DetectionResult, error)) *Handler {
	return New(Options{
		ResolveSite: func(host string) (string, int64, bool) {
			if host != "example.test" {
				return "", 0, false
			}
			return "site-1", 1 << 20, true
		},
		Detect: detect,
	})
}

func postInspect(t *testing.T, h *Handler, req Request) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/adapter/inspect", bytes.NewReader(body)))
	return rec
}

// The admin endpoint always answers 200 with a JSON decision; the status the
// gateway should use travels in status_code. A 204 here would forbid the body.
func decodeDecision(t *testing.T, rec *httptest.ResponseRecorder) Decision {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200 with a JSON decision", rec.Code, rec.Body.String())
	}
	var decision Decision
	if err := json.Unmarshal(rec.Body.Bytes(), &decision); err != nil {
		t.Fatalf("decode decision: %v", err)
	}
	return decision
}
func TestAdapterInspectAllowsCleanRequest(t *testing.T) {
	h := testHandler(func(_ context.Context, reqCtx *engine.RequestContext) (*engine.DetectionResult, error) {
		if reqCtx.SiteID != "site-1" || string(reqCtx.DecodedBody) != "a=1" {
			t.Fatalf("unexpected context: site=%q body=%q", reqCtx.SiteID, reqCtx.DecodedBody)
		}
		return nil, nil
	})
	rec := postInspect(t, h, Request{
		ContractVersion: ContractVersion, Method: http.MethodPost, Authority: "example.test",
		Path: "/upload", Headers: map[string][]string{"Content-Type": {"application/x-www-form-urlencoded"}},
		BodyForwarded: true, Body: []byte("a=1"),
	})
	decision := decodeDecision(t, rec)
	if decision.Action != "allow" {
		t.Fatalf("decision = %+v", decision)
	}
}

func TestAdapterInspectBlocksDetection(t *testing.T) {
	h := testHandler(func(context.Context, *engine.RequestContext) (*engine.DetectionResult, error) {
		return &engine.DetectionResult{Detected: true, Action: engine.ActionBlock, DetectorID: "rce.test", Message: "blocked"}, nil
	})
	rec := postInspect(t, h, Request{ContractVersion: ContractVersion, Method: http.MethodPost, Authority: "example.test", Path: "/", BodyForwarded: true})
	decision := decodeDecision(t, rec)
	if decision.Action != "block" || decision.StatusCode != http.StatusForbidden {
		t.Fatalf("decision = %+v", decision)
	}
}

func TestAdapterInspectRejectsTruncatedBody(t *testing.T) {
	h := testHandler(func(context.Context, *engine.RequestContext) (*engine.DetectionResult, error) { return nil, nil })
	rec := postInspect(t, h, Request{ContractVersion: ContractVersion, Method: http.MethodPost, Authority: "example.test", Path: "/", BodyForwarded: true, BodyTruncated: true})
	decision := decodeDecision(t, rec)
	if decision.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("decision = %+v", decision)
	}
}

func TestAdapterInspectRejectsUnknownSite(t *testing.T) {
	h := testHandler(func(context.Context, *engine.RequestContext) (*engine.DetectionResult, error) { return nil, nil })
	rec := postInspect(t, h, Request{ContractVersion: ContractVersion, Method: http.MethodPost, Authority: "other.test", Path: "/"})
	decision := decodeDecision(t, rec)
	if decision.StatusCode != http.StatusBadRequest {
		t.Fatalf("decision = %+v", decision)
	}
}

func TestAdapterInspectNormalizesTraversalPath(t *testing.T) {
	h := testHandler(func(_ context.Context, reqCtx *engine.RequestContext) (*engine.DetectionResult, error) {
		if reqCtx.NormalizedPath != "/admin" {
			t.Fatalf("normalized path=%q, want /admin", reqCtx.NormalizedPath)
		}
		return nil, nil
	})
	rec := postInspect(t, h, Request{ContractVersion: ContractVersion, Method: http.MethodGet, Authority: "example.test", Path: "/public/../admin"})
	decision := decodeDecision(t, rec)
	if decision.Action != "allow" {
		t.Fatalf("decision = %+v", decision)
	}
}
