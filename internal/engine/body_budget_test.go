package engine

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestBodyReadRejectsReservationBeyondSiteBudget(t *testing.T) {
	body := &budgetProbeBody{Reader: strings.NewReader("small")}
	req := httptest.NewRequest(http.MethodPost, "/upload", body)
	req.ContentLength = -1
	reqCtx, err := NewRequestContextDeferredBody(req, "budget-oversize", nil, 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	if err := reqCtx.EnsureBody(); !errors.Is(err, ErrRequestBodyReadOverload) {
		t.Fatalf("oversized reservation error=%v, want body overload", err)
	}
	if body.reads != 0 {
		t.Fatalf("admission failure consumed body %d times", body.reads)
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
	var held []*budgetHeldBody
	for range 3 {
		body := &budgetHeldBody{started: make(chan struct{}), release: make(chan struct{})}
		held = append(held, body)
		t.Cleanup(func() { body.Close() })
	}
	done := make([]chan error, len(held))
	for i, body := range held {
		req := httptest.NewRequest(http.MethodPost, "/upload", body)
		req.ContentLength = -1
		reqCtx, err := NewRequestContextDeferredBody(req, "budget-noisy", nil, perRequest)
		if err != nil {
			t.Fatal(err)
		}
		done[i] = make(chan error, 1)
		go func(i int) { done[i] <- reqCtx.EnsureBodyContext(context.Background()) }(i)
		if i < 2 {
			select {
			case <-body.started:
			case <-time.After(time.Second):
				t.Fatal("body read did not start")
			}
		}
	}
	select {
	case err := <-done[2]:
		if !errors.Is(err, ErrRequestBodyReadOverload) {
			t.Fatalf("third same-site request error=%v, want overload", err)
		}
	case <-held[2].started:
		t.Fatal("same site exceeded its body byte budget")
	case <-time.After(time.Second):
		t.Fatal("same-site admission did not finish promptly")
	}
	req := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader("ok"))
	other, err := NewRequestContextDeferredBody(req, "budget-quiet", nil, perRequest)
	if err != nil {
		t.Fatal(err)
	}
	if err := other.EnsureBody(); err != nil {
		t.Fatalf("other site lost its body capacity: %v", err)
	}
	for i := range 2 {
		held[i].Close()
		if err := <-done[i]; err != nil {
			t.Fatal(err)
		}
	}
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

type budgetHeldBody struct {
	started chan struct{}
	release chan struct{}
}

func (b *budgetHeldBody) Read([]byte) (int, error) {
	select {
	case <-b.started:
	default:
		close(b.started)
	}
	<-b.release
	return 0, io.EOF
}

func (b *budgetHeldBody) Close() error {
	select {
	case <-b.release:
	default:
		close(b.release)
	}
	return nil
}
