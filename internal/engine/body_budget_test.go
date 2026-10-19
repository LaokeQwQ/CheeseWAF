package engine

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBodyReadSmallBodyWithLargeConfiguredCeiling(t *testing.T) {
	body := &budgetProbeBody{Reader: strings.NewReader("small")}
	req := httptest.NewRequest(http.MethodPost, "/upload", body)
	reqCtx, err := NewRequestContextDeferredBody(req, "budget-oversize", nil, 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	if err := reqCtx.EnsureBody(); err != nil {
		t.Fatalf("small body with large configured ceiling was rejected: %v", err)
	}
	if body.reads == 0 {
		t.Fatal("small request body was not read")
	}
}

func TestBodyReadSupportsConfiguredLimitsAboveSiteBudgetFloor(t *testing.T) {
	const bodySize = 17 << 20
	bodyData := strings.Repeat("x", bodySize)
	for _, tc := range []struct {
		name       string
		contentLen int64
	}{
		{name: "known-length", contentLen: bodySize},
		{name: "chunked", contentLen: -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader(bodyData))
			req.ContentLength = tc.contentLen
			reqCtx, err := NewRequestContextDeferredBody(req, "body-32m-"+tc.name, nil, 32<<20)
			if err != nil {
				t.Fatal(err)
			}
			if err := reqCtx.EnsureBody(); err != nil {
				t.Fatalf("body below configured/site limit was rejected: %v", err)
			}
			if got := len(reqCtx.DecodedBody); got != bodySize {
				t.Fatalf("read body length=%d, want %d", got, bodySize)
			}
		})
	}
}

func TestBodyReadRejectsWhenActualBodyExceedsSiteBudget(t *testing.T) {
	const siteID = "body-budget-full"
	if !reserveBodyBudget(siteID, maxBodyBytesPerSite) {
		t.Fatal("failed to occupy site body budget")
	}
	t.Cleanup(func() {
		bodyBudget.Lock()
		reserved := bodyBudget.bySite[siteID]
		bodyBudget.global -= reserved
		delete(bodyBudget.bySite, siteID)
		bodyBudget.Unlock()
	})
	body := &budgetProbeBody{Reader: strings.NewReader("small")}
	req := httptest.NewRequest(http.MethodPost, "/upload", body)
	reqCtx, err := NewRequestContextDeferredBody(req, siteID, nil, 32<<20)
	if err != nil {
		t.Fatal(err)
	}
	if err := reqCtx.EnsureBody(); !errors.Is(err, ErrRequestBodyReadOverload) {
		t.Fatalf("full site quota error=%v, want body overload", err)
	}
	if body.reads != 0 {
		t.Fatalf("quota rejection consumed body %d times", body.reads)
	}
}

func TestBodyReadSiteAdmissionLeavesGlobalCapacityForOtherSites(t *testing.T) {
	tokens := make([]siteAdmissionToken, 0, maxInflightBodyReadsPerSite)
	for i := 0; i < maxInflightBodyReadsPerSite; i++ {
		token, admitted := bodyReadSiteAdmissions.acquire("noisy-site")
		if !admitted {
			t.Fatalf("same-site body admission rejected slot %d/%d", i+1, maxInflightBodyReadsPerSite)
		}
		tokens = append(tokens, token)
	}
	defer func() {
		for _, token := range tokens {
			token.release()
		}
	}()
	if _, admitted := bodyReadSiteAdmissions.acquire("noisy-site"); admitted {
		t.Fatal("same site exceeded its body-reader slot quota")
	}
	quiet, admitted := bodyReadSiteAdmissions.acquire("quiet-site")
	if !admitted {
		t.Fatal("quiet site lost body-reader capacity to noisy site")
	}
	quiet.release()
}

func TestBodyReadSiteBudgetLeavesOtherSiteCapacity(t *testing.T) {
	const perRequest = (8 << 20) - 1
	const noisySite = "budget-noisy"
	var reserved int64
	for reserveBodyBudget(noisySite, perRequest) {
		reserved += perRequest
	}
	t.Cleanup(func() {
		bodyBudget.Lock()
		bodyBudget.global -= reserved
		delete(bodyBudget.bySite, noisySite)
		bodyBudget.Unlock()
	})
	if reserved < maxBodyBytesPerSite-perRequest {
		t.Fatalf("noisy site reserved only %d bytes of %d-byte quota", reserved, maxBodyBytesPerSite)
	}
	if remainder := maxBodyBytesPerSite - reserved; remainder > 0 && !reserveBodyBudget(noisySite, remainder) {
		t.Fatalf("failed to fill remaining site budget: %d bytes", remainder)
	} else {
		reserved += remainder
	}
	if reserveBodyBudget(noisySite, 1) {
		t.Fatal("same site exceeded its body byte budget")
	}
	if !reserveBodyBudget("budget-quiet", perRequest) {
		t.Fatal("other site lost its body byte capacity")
	}
	t.Cleanup(func() {
		bodyBudget.Lock()
		bodyBudget.global -= perRequest
		delete(bodyBudget.bySite, "budget-quiet")
		bodyBudget.Unlock()
	})
}

type budgetProbeBody struct {
	io.Reader
	reads int
}

func (b *budgetProbeBody) Read(p []byte) (int, error) {
	b.reads++
	return b.Reader.Read(p)
}

func (*budgetProbeBody) Close() error { return nil }
