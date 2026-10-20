package engine

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
	"time"
)

func TestBodyReadEmptyReads(t *testing.T) {
	for _, tc := range []struct {
		name      string
		steps     []bodyEmptyReadStep
		limit     int64
		want      string
		wantErr   error
		wantReads int
	}{
		{name: "empty-then-data", steps: []bodyEmptyReadStep{{empty: 1}, {data: "ok"}}, limit: 4, want: "ok", wantReads: 3},
		{name: "bounded-empty", steps: []bodyEmptyReadStep{{empty: 101}}, limit: 4, wantErr: io.ErrNoProgress, wantReads: 100},
		{name: "data-resets-empty-count", steps: []bodyEmptyReadStep{{empty: 99}, {data: "a"}, {empty: 99}, {data: "b"}, {empty: 99}}, limit: 2, want: "ab", wantReads: 300},
		{name: "probe-empty-then-eof", steps: []bodyEmptyReadStep{{data: "ok"}, {empty: 1}}, limit: 2, want: "ok", wantReads: 3},
		{name: "probe-empty-then-extra-byte", steps: []bodyEmptyReadStep{{data: "ok"}, {empty: 1}, {data: "x", err: io.EOF}}, limit: 2, wantErr: ErrRequestBodyTooLarge, wantReads: 3},
		{name: "bounded-empty-probe", steps: []bodyEmptyReadStep{{data: "ok"}, {empty: 101}}, limit: 2, want: "ok", wantErr: io.ErrNoProgress, wantReads: 101},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &RequestContext{SiteID: "empty-read-" + tc.name}
			defer func() {
				c.bodyMu.Lock()
				defer c.bodyMu.Unlock()
				c.releaseBodyBudgetLocked()
			}()
			reader := &bodyEmptyReadReader{steps: append([]bodyEmptyReadStep(nil), tc.steps...)}
			got, err := c.readBodyWithBudget(reader, tc.limit)
			if !errors.Is(err, tc.wantErr) || string(got) != tc.want {
				t.Fatalf("read = %q, %v; want %q, %v", got, err, tc.want, tc.wantErr)
			}
			if reader.reads != tc.wantReads {
				t.Fatalf("reads = %d, want %d", reader.reads, tc.wantReads)
			}
		})
	}
}

type bodyEmptyReadStep struct {
	empty int
	data  string
	err   error
}

type bodyEmptyReadReader struct {
	steps []bodyEmptyReadStep
	reads int
}

func (r *bodyEmptyReadReader) Read(p []byte) (int, error) {
	r.reads++
	if len(r.steps) == 0 {
		return 0, io.EOF
	}
	step := &r.steps[0]
	if step.empty > 0 {
		step.empty--
		if step.empty == 0 {
			r.steps = r.steps[1:]
		}
		return 0, nil
	}
	n := copy(p, step.data)
	step.data = step.data[n:]
	if step.data != "" {
		return n, nil
	}
	err := step.err
	r.steps = r.steps[1:]
	return n, err
}

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

func TestBodyReadSiteAdmissionCapsLoneSiteAtFairQuota(t *testing.T) {
	admission := siteAdmission{maxActive: maxInflightBodyReadsPerSite, maxSites: 8}
	tokens := make([]siteAdmissionToken, 0, maxInflightBodyReadsPerSite)
	for i := 0; i < maxInflightBodyReadsPerSite; i++ {
		token, admitted := admission.acquire("lone-site")
		if !admitted {
			t.Fatalf("lone site was rejected at fair quota slot %d/%d", i+1, maxInflightBodyReadsPerSite)
		}
		tokens = append(tokens, token)
	}
	if _, admitted := admission.acquire("lone-site"); admitted {
		t.Fatal("lone site bypassed its fair body-reader quota while global capacity was idle")
	}
	for _, token := range tokens {
		token.release()
	}
}

func TestBodyReadSiteAdmissionRestoresFairQuotaWhenSitesCompete(t *testing.T) {
	admission := siteAdmission{maxActive: maxInflightBodyReadsPerSite, maxSites: 8}
	tokens := make([]siteAdmissionToken, 0, maxInflightBodyReadsPerSite)
	for i := 0; i < maxInflightBodyReadsPerSite; i++ {
		token, admitted := admission.acquire("noisy-site")
		if !admitted {
			t.Fatalf("noisy site admission rejected slot %d/%d", i+1, maxInflightBodyReadsPerSite)
		}
		tokens = append(tokens, token)
	}
	quiet, admitted := admission.acquire("quiet-site")
	if !admitted {
		t.Fatal("quiet site was rejected while global capacity remained")
	}
	defer quiet.release()
	defer func() {
		for _, token := range tokens {
			token.release()
		}
	}()
	if _, admitted := admission.acquire("noisy-site"); admitted {
		t.Fatal("noisy site exceeded its fairness quota while another site was active")
	}
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

func TestBodyReadIdleTimeoutReleasesBudget(t *testing.T) {
	const siteID = "body-idle-timeout"
	body := newCloseAwareBlockingBody(nil)
	req := httptest.NewRequest(http.MethodPost, "/upload", body)
	reqCtx, err := NewRequestContextDeferredBody(req, siteID, nil, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	reqCtx.bodyReadIdleTimeout = 25 * time.Millisecond
	if err := reqCtx.EnsureBody(); !errors.Is(err, ErrRequestBodyReadTimeout) {
		t.Fatalf("idle read error=%v, want timeout", err)
	}
	select {
	case <-reqCtx.bodyReadDone:
	case <-time.After(time.Second):
		t.Fatal("idle read did not close and unwind its source")
	}
	if got := bodyBudgetForSite(siteID); got != 0 {
		t.Fatalf("idle read retained %d budget bytes", got)
	}
	if req.Body != body || reqCtx.DecodedBody != nil || req.GetBody != nil {
		t.Fatal("timed out body published replay or inspection bytes")
	}
}

func TestBodyReadIdleTimeoutRetainsUncooperativeReaderBudgetUntilExit(t *testing.T) {
	const siteID = "body-idle-uncooperative"
	release := make(chan struct{})
	defer close(release)
	secondRead := make(chan struct{}, 1)
	body := &partialBlockingBody{prefix: []byte("partial"), release: release, secondRead: secondRead}
	req := httptest.NewRequest(http.MethodPost, "/upload", body)
	reqCtx, err := NewRequestContextDeferredBody(req, siteID, nil, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	reqCtx.bodyReadIdleTimeout = 50 * time.Millisecond
	results := make(chan error, 2)
	go func() { results <- reqCtx.EnsureBody() }()
	<-secondRead
	go func() { results <- reqCtx.EnsureBody() }()
	for range 2 {
		select {
		case err := <-results:
			if !errors.Is(err, ErrRequestBodyReadTimeout) {
				t.Fatalf("idle waiter error=%v, want timeout", err)
			}
		case <-time.After(time.Second):
			t.Fatal("idle timeout did not wake all body waiters")
		}
	}
	if got := bodyBudgetForSite(siteID); got == 0 {
		t.Fatal("blocked reader still holds an allocation but lost its budget")
	}
	// Close deliberately does not unblock this reader. It must remain counted
	// until Read exits, and its late result must never publish a snapshot.
	closeDeadline := time.Now().Add(time.Second)
	for !body.closed.Load() && time.Now().Before(closeDeadline) {
		time.Sleep(time.Millisecond)
	}
	if !body.closed.Load() || req.Body != body || req.GetBody != nil || reqCtx.DecodedBody != nil {
		t.Fatal("idle abort failed to close the original source transactionally")
	}
	release <- struct{}{}
	select {
	case <-reqCtx.bodyReadDone:
	case <-time.After(time.Second):
		t.Fatal("abandoned reader did not finish")
	}
	if got := bodyBudgetForSite(siteID); got != 0 {
		t.Fatalf("finished abandoned reader retained %d budget bytes", got)
	}
}

func TestBodyReadProgressExtendsIdleTimeout(t *testing.T) {
	body := &pacedBody{remaining: 10, delay: 20 * time.Millisecond}
	req := httptest.NewRequest(http.MethodPost, "/upload", body)
	reqCtx, err := NewRequestContextDeferredBody(req, "body-idle-progress", nil, 128)
	if err != nil {
		t.Fatal(err)
	}
	reqCtx.bodyReadIdleTimeout = 100 * time.Millisecond
	started := time.Now()
	if err := reqCtx.EnsureBody(); err != nil {
		t.Fatalf("progressing body was aborted: %v", err)
	}
	if time.Since(started) < reqCtx.bodyReadIdleTimeout || len(reqCtx.DecodedBody) != 10 {
		t.Fatal("test did not span an idle window with a complete body")
	}
}

func TestBodyReadIdleTimeoutDoesNotWaitForBlockingClose(t *testing.T) {
	body := &blockingCloseBody{readRelease: make(chan struct{}), closeRelease: make(chan struct{}), closeStarted: make(chan struct{})}
	defer close(body.closeRelease)
	defer close(body.readRelease)
	req := httptest.NewRequest(http.MethodPost, "/upload", body)
	reqCtx, err := NewRequestContextDeferredBody(req, "body-idle-blocked-close", nil, 128)
	if err != nil {
		t.Fatal(err)
	}
	reqCtx.bodyReadIdleTimeout = 25 * time.Millisecond
	result := make(chan error, 1)
	go func() { result <- reqCtx.EnsureBody() }()
	select {
	case err := <-result:
		if !errors.Is(err, ErrRequestBodyReadTimeout) {
			t.Fatalf("idle error=%v, want timeout", err)
		}
	case <-time.After(time.Second):
		t.Fatal("idle timeout blocked on an uncooperative Close")
	}
	select {
	case <-body.closeStarted:
	case <-time.After(time.Second):
		t.Fatal("idle timeout did not attempt to close its source")
	}
}

func TestBodyReadCancellationDoesNotWaitForBlockingClose(t *testing.T) {
	const siteID = "body-cancel-blocked-close"
	body := &blockingCloseBody{
		readRelease: make(chan struct{}), closeRelease: make(chan struct{}),
		readStarted: make(chan struct{}), closeStarted: make(chan struct{}),
	}
	defer close(body.closeRelease)
	defer close(body.readRelease)
	req := httptest.NewRequest(http.MethodPost, "/upload", body)
	reqCtx, err := NewRequestContextDeferredBody(req, siteID, nil, 128)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- reqCtx.EnsureBodyContext(ctx) }()
	select {
	case <-body.readStarted:
	case <-time.After(time.Second):
		t.Fatal("body Read did not start")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled body error=%v, want context.Canceled", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("body cancellation blocked on an uncooperative Close")
	}
	select {
	case <-body.closeStarted:
	case <-time.After(time.Second):
		t.Fatal("body cancellation did not attempt Close")
	}
	// Even when Read has returned, a blocked Close must retain its admission
	// permit. Otherwise repeated cancellations could create unlimited closers.
	body.readRelease <- struct{}{}
	select {
	case <-reqCtx.bodyReadDone:
	case <-time.After(time.Second):
		t.Fatal("canceled body worker did not finish reading")
	}
	bodyReadSiteAdmissions.mu.Lock()
	active := bodyReadSiteAdmissions.bySite[siteID]
	bodyReadSiteAdmissions.mu.Unlock()
	if active != 1 {
		t.Fatalf("blocked Close lost its admission permit: active=%d", active)
	}
	body.closeRelease <- struct{}{}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		bodyReadSiteAdmissions.mu.Lock()
		active = bodyReadSiteAdmissions.bySite[siteID]
		bodyReadSiteAdmissions.mu.Unlock()
		if active == 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("completed Close leaked its admission permit")
}

func TestBodyBudgetRetainsTimedOutDetectorSnapshot(t *testing.T) {
	const siteID = "body-late-detector-snapshot"
	release, exited, reservation := timedOutBodyDetector(t, siteID)
	for range 3 {
		runtime.GC()
	}
	if got := bodyBudgetForSite(siteID); got != reservation {
		close(release)
		t.Fatalf("detector retained a snapshot after timeout but budget=%d, want %d", got, reservation)
	}
	close(release)
	select {
	case <-exited:
	case <-time.After(time.Second):
		t.Fatal("late detector did not exit")
	}
	waitForBodyBudget(t, siteID, 0)
}

func timedOutBodyDetector(t *testing.T, siteID string) (chan struct{}, <-chan struct{}, int64) {
	t.Helper()
	release := make(chan struct{})
	exited := make(chan struct{})
	pipeline := NewPipeline(&countingDetector{id: "late-body-owner", priority: 300, fn: func(_ context.Context, reqCtx *RequestContext) (*DetectionResult, error) {
		defer close(exited)
		<-release
		runtime.KeepAlive(reqCtx.DecodedBody)
		return &DetectionResult{Action: ActionPass}, nil
	}})
	pipeline.SetDetectionBudget(25 * time.Millisecond)
	req := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader("retained by late detector"))
	reqCtx, err := NewRequestContextWithLimits(req, siteID, nil, 128)
	if err != nil {
		t.Fatal(err)
	}
	reservation := int64(cap(reqCtx.DecodedBody))
	if _, err := pipeline.Detect(context.Background(), reqCtx); err != nil {
		t.Fatal(err)
	}
	return release, exited, reservation
}

func TestBodyBudgetFollowsAllPublishedSnapshotOwners(t *testing.T) {
	for _, ownerKind := range []string{"context", "fork", "slice", "replay", "get-body"} {
		t.Run(ownerKind, func(t *testing.T) {
			siteID := "body-snapshot-owner-" + ownerKind
			retained, reservation := retainedBodyOwner(t, siteID, ownerKind)
			for range 3 {
				runtime.GC()
			}
			if got := bodyBudgetForSite(siteID); got != reservation {
				t.Fatalf("live %s snapshot budget=%d, want %d", ownerKind, got, reservation)
			}
			if getBody, ok := retained.(func() (io.ReadCloser, error)); ok {
				reader, err := getBody()
				if err != nil {
					t.Fatal(err)
				}
				if replay, err := io.ReadAll(reader); err != nil || string(replay) != "retained snapshot" {
					t.Fatalf("retained replay=%q, err=%v", replay, err)
				}
				_ = reader.Close()
			}
			runtime.KeepAlive(retained)
			retained = nil
			waitForBodyBudget(t, siteID, 0)
		})
	}
}

func TestBodyBudgetReservesDecodedAllocationUntilLastSliceIsGone(t *testing.T) {
	const siteID = "body-decoded-snapshot-owner"
	decoded, decodedReservation := retainedDecodedBody(t, siteID)
	waitForBodyBudget(t, siteID, decodedReservation)
	if len(decoded) != 12<<10 {
		t.Fatalf("decoded snapshot length=%d", len(decoded))
	}
	runtime.KeepAlive(decoded)
	decoded = nil
	waitForBodyBudget(t, siteID, 0)
}

func TestBodyBudgetRejectsUnbudgetedDecode(t *testing.T) {
	const siteID = "body-decoded-overload"
	occupied := int64(maxBodyBytesPerSite - 64<<10)
	if !reserveBodyBudget(siteID, occupied) {
		t.Fatal("could not fill the site budget")
	}
	defer releaseRetainedBodyBudget(bodyBudgetRelease{siteID, occupied})
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	plain := make([]byte, 40<<10)
	_, _ = rand.New(rand.NewSource(2)).Read(plain)
	_, _ = writer.Write(plain)
	_ = writer.Close()
	req := httptest.NewRequest(http.MethodPost, "/upload", bytes.NewReader(compressed.Bytes()))
	req.Header.Set("Content-Encoding", "gzip")
	reqCtx, err := NewRequestContextDeferredBody(req, siteID, nil, 64<<10)
	if err != nil {
		t.Fatal(err)
	}
	if err := reqCtx.EnsureBodyContext(context.Background()); !errors.Is(err, ErrRequestBodyReadOverload) {
		t.Fatalf("decode without available budget error=%v, want overload", err)
	}
	if got := bodyBudgetForSite(siteID); got != occupied {
		t.Fatalf("failed decode leaked budget: %d, want %d", got, occupied)
	}
	if reqCtx.DecodedBody != nil || req.GetBody != nil {
		t.Fatal("budget-rejected decode published a snapshot")
	}
}

func TestBodyBudgetRecoversAfterBurstWithoutBackgroundGC(t *testing.T) {
	// A full budget must recover even when Go's normal heap-growth threshold
	// does not trigger another GC. Only production admission may collect here.
	previousGCPercent := debug.SetGCPercent(-1)
	defer debug.SetGCPercent(previousGCPercent)
	const siteID = "body-budget-burst-recovery"
	fillBodyBudgetWithDiscardedRequests(t, siteID)
	if got := bodyBudgetForSite(siteID); got != maxBodyBytesPerSite {
		t.Fatalf("burst budget=%d, want full site ceiling", got)
	}
	deadline := time.Now().Add(time.Second)
	for {
		req := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader("recovered"))
		reqCtx, err := NewRequestContextWithLimits(req, siteID, nil, 128)
		if err == nil {
			if string(reqCtx.DecodedBody) != "recovered" {
				t.Fatal("recovery lost request content")
			}
			break
		}
		if !errors.Is(err, ErrRequestBodyReadOverload) || time.Now().After(deadline) {
			t.Fatalf("discarded burst did not restore admission: %v", err)
		}
	}
}

func fillBodyBudgetWithDiscardedRequests(t *testing.T, siteID string) {
	t.Helper()
	payload := strings.Repeat("x", defaultRequestBodyLimit)
	for range maxBodyBytesPerSite / defaultRequestBodyLimit {
		req := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader(payload))
		if _, err := NewRequestContextWithLimits(req, siteID, nil, defaultRequestBodyLimit); err != nil {
			t.Fatal(err)
		}
	}
}

func BenchmarkRequestBodySnapshot(b *testing.B) {
	for _, sample := range []struct {
		name string
		size int
	}{{"64B", 64}, {"32KiB", 32 << 10}, {"8MiB", defaultRequestBodyLimit}} {
		b.Run(sample.name, func(b *testing.B) {
			payload := strings.Repeat("x", sample.size)
			b.ReportAllocs()
			b.SetBytes(int64(sample.size))
			b.ResetTimer()
			for range b.N {
				req := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader(payload))
				if _, err := NewRequestContextWithLimits(req, "body-benchmark-"+sample.name, nil, defaultRequestBodyLimit); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func retainedBodyOwner(t *testing.T, siteID, ownerKind string) (any, int64) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader("retained snapshot"))
	reqCtx, err := NewRequestContextWithLimits(req, siteID, nil, 128)
	if err != nil {
		t.Fatal(err)
	}
	reservation := int64(cap(reqCtx.rawBody))
	if got := bodyBudgetForSite(siteID); got != reservation {
		t.Fatalf("published snapshot budget=%d, want %d", got, reservation)
	}
	switch ownerKind {
	case "context":
		return reqCtx, reservation
	case "fork":
		return forkRequestContextWithContext(reqCtx, context.Background()), reservation
	case "slice":
		return reqCtx.DecodedBody, reservation
	case "replay":
		return req.Body, reservation
	default:
		return req.GetBody, reservation
	}
}

func retainedDecodedBody(t *testing.T, siteID string) ([]byte, int64) {
	t.Helper()
	plain := make([]byte, 12<<10)
	_, _ = rand.New(rand.NewSource(1)).Read(plain)
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	_, _ = writer.Write(plain)
	_ = writer.Close()
	req := httptest.NewRequest(http.MethodPost, "/upload", bytes.NewReader(compressed.Bytes()))
	req.Header.Set("Content-Encoding", "gzip")
	reqCtx, err := NewRequestContextWithLimits(req, siteID, nil, 64<<10)
	if err != nil {
		t.Fatal(err)
	}
	reservation := int64(cap(reqCtx.rawBody) + cap(reqCtx.DecodedBody))
	if got := bodyBudgetForSite(siteID); got != reservation {
		t.Fatalf("compressed snapshot budget=%d, want raw+decoded %d", got, reservation)
	}
	return reqCtx.DecodedBody, int64(cap(reqCtx.DecodedBody))
}

func bodyBudgetForSite(siteID string) int64 {
	bodyBudget.Lock()
	defer bodyBudget.Unlock()
	return bodyBudget.bySite[siteID]
}

func waitForBodyBudget(t *testing.T, siteID string, want int64) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		runtime.GC()
		if bodyBudgetForSite(siteID) == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("body budget for %s=%d, want %d", siteID, bodyBudgetForSite(siteID), want)
}

type pacedBody struct {
	remaining int
	delay     time.Duration
}

func (b *pacedBody) Read(p []byte) (int, error) {
	if b.remaining == 0 {
		return 0, io.EOF
	}
	time.Sleep(b.delay)
	b.remaining--
	p[0] = 'x'
	return 1, nil
}

func (*pacedBody) Close() error { return nil }

type blockingCloseBody struct {
	readRelease  chan struct{}
	closeRelease chan struct{}
	readStarted  chan struct{}
	closeStarted chan struct{}
}

func (b *blockingCloseBody) Read([]byte) (int, error) {
	if b.readStarted != nil {
		close(b.readStarted)
	}
	<-b.readRelease
	return 0, io.EOF
}

func (b *blockingCloseBody) Close() error {
	close(b.closeStarted)
	<-b.closeRelease
	return nil
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
