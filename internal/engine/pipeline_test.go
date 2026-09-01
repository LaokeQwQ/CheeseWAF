package engine

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestPipelineReturnsLogOnlyDetection(t *testing.T) {
	result := &DetectionResult{
		Detected:   true,
		DetectorID: "test.log",
		Category:   "sqli",
		Severity:   SeverityHigh,
		Action:     ActionLog,
		Confidence: 0.88,
	}
	reqCtx := &RequestContext{}

	got, err := NewPipeline(staticPipelineDetector{id: "log", result: result}).Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || !got.Detected || got.Action != ActionLog || got.DetectorID != "test.log" {
		t.Fatalf("expected log-only detection to be returned, got %#v", got)
	}
	if len(reqCtx.Results) != 1 || reqCtx.Results[0].Action != ActionLog {
		t.Fatalf("expected log-only detection in request results, got %#v", reqCtx.Results)
	}
}

func TestPipelineBlockDetectionOverridesEarlierLogDetection(t *testing.T) {
	logResult := &DetectionResult{
		Detected:   true,
		DetectorID: "test.log",
		Category:   "sqli",
		Severity:   SeverityHigh,
		Action:     ActionLog,
		Confidence: 0.88,
	}
	blockResult := &DetectionResult{
		Detected:   true,
		DetectorID: "test.block",
		Category:   "xss",
		Severity:   SeverityHigh,
		Action:     ActionBlock,
		Confidence: 0.91,
	}
	reqCtx := &RequestContext{}

	got, err := NewPipeline(
		staticPipelineDetector{id: "log", priority: 10, result: logResult},
		staticPipelineDetector{id: "block", priority: 20, result: blockResult},
	).Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.Action != ActionBlock || got.DetectorID != "test.block" {
		t.Fatalf("expected blocking detection to take precedence, got %#v", got)
	}
	if len(reqCtx.Results) != 2 {
		t.Fatalf("expected both detections in request results, got %#v", reqCtx.Results)
	}
}

func TestPipelinePrecomputesDetectorGroups(t *testing.T) {
	pipeline := NewPipeline(
		staticPipelineDetector{id: "semantic", priority: 300},
		staticPipelineDetector{id: "pre-b", priority: 20},
		staticPipelineDetector{id: "pre-a", priority: 10},
	)
	snapshot := pipeline.snapshot.Load()
	if snapshot == nil {
		t.Fatal("pipeline snapshot was not initialized")
	}
	if got := snapshot.preFilters[0].ID(); got != "pre-a" {
		t.Fatalf("pre-filter order = %q, want pre-a", got)
	}
	if len(snapshot.preFilters) != 2 || len(snapshot.semanticGroup) != 1 || snapshot.semanticGroup[0].ID() != "semantic" {
		t.Fatalf("unexpected precomputed groups: pre=%v semantic=%v", len(snapshot.preFilters), len(snapshot.semanticGroup))
	}
}

type staticPipelineDetector struct {
	id       string
	priority int
	result   *DetectionResult
}

type metadataIsolationNode struct {
	Labels []string
	Attrs  map[string]any
}

func (d staticPipelineDetector) ID() string { return d.id }
func (d staticPipelineDetector) Name() string {
	if d.id == "" {
		return "static"
	}
	return d.id
}
func (d staticPipelineDetector) Priority() int { return d.priority }
func (d staticPipelineDetector) Detect(context.Context, *RequestContext) (*DetectionResult, error) {
	return d.result, nil
}

func TestPipelineBudgetExhaustedPolicies(t *testing.T) {
	slow := &countingDetector{
		id: "slow-pre", priority: 10,
		fn: func(ctx context.Context, reqCtx *RequestContext) (*DetectionResult, error) {
			// Exceed the 100ms pipeline budget.
			timer := time.NewTimer(150 * time.Millisecond)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-timer.C:
				return nil, nil
			}
		},
	}

	t.Run("open passes", func(t *testing.T) {
		reqCtx := &RequestContext{Metadata: map[string]any{"budget_exhausted_policy": "open"}}
		got, err := NewPipeline(slow).Detect(context.Background(), reqCtx)
		if err != nil {
			t.Fatal(err)
		}
		if reqCtx.Metadata["detection_budget_exhausted"] != true {
			t.Fatalf("expected budget exhausted flag, got %#v", reqCtx.Metadata)
		}
		if got != nil && got.Detected {
			t.Fatalf("open policy must not detect, got %#v", got)
		}
	})

	t.Run("observe logs", func(t *testing.T) {
		reqCtx := &RequestContext{Metadata: map[string]any{"budget_exhausted_policy": "observe"}}
		got, err := NewPipeline(slow).Detect(context.Background(), reqCtx)
		if err != nil {
			t.Fatal(err)
		}
		if got == nil || !got.Detected || got.Action != ActionLog || got.Category != "detection_budget" {
			t.Fatalf("expected observe log result, got %#v", got)
		}
	})

	t.Run("unset policy challenges", func(t *testing.T) {
		got, err := NewPipeline(slow).Detect(context.Background(), &RequestContext{})
		if err != nil {
			t.Fatal(err)
		}
		if got == nil || !got.Detected || got.Action != ActionChallenge || got.Category != "detection_budget" {
			t.Fatalf("expected default challenge result, got %#v", got)
		}
	})

	t.Run("closed challenges", func(t *testing.T) {
		reqCtx := &RequestContext{Metadata: map[string]any{"budget_exhausted_policy": "closed"}}
		got, err := NewPipeline(slow).Detect(context.Background(), reqCtx)
		if err != nil {
			t.Fatal(err)
		}
		if got == nil || !got.Detected || got.Action != ActionChallenge || got.Category != "detection_budget" {
			t.Fatalf("expected closed challenge result, got %#v", got)
		}
	})

	t.Run("block wins over closed budget", func(t *testing.T) {
		blocker := staticPipelineDetector{
			id: "block-early", priority: 5,
			result: &DetectionResult{
				Detected: true, DetectorID: "block-early", Category: "sqli",
				Severity: SeverityHigh, Action: ActionBlock, Confidence: 0.95,
			},
		}
		// Put a slow detector after the block so budget would fire if we continued;
		// block returns immediately from pre-filter phase before budget.
		reqCtx := &RequestContext{Metadata: map[string]any{"budget_exhausted_policy": "closed"}}
		got, err := NewPipeline(blocker, slow).Detect(context.Background(), reqCtx)
		if err != nil {
			t.Fatal(err)
		}
		if got == nil || got.Action != ActionBlock || got.DetectorID != "block-early" {
			t.Fatalf("expected real block to win, got %#v", got)
		}
	})

	t.Run("single semantic detector closed challenges on budget", func(t *testing.T) {
		// Production hot path: only priority>=290 detector (no pre-filter).
		slowSemantic := &countingDetector{
			id: "slow-semantic", priority: 290,
			fn: func(ctx context.Context, reqCtx *RequestContext) (*DetectionResult, error) {
				timer := time.NewTimer(150 * time.Millisecond)
				defer timer.Stop()
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-timer.C:
					return nil, nil
				}
			},
		}
		reqCtx := &RequestContext{Metadata: map[string]any{"budget_exhausted_policy": "closed"}}
		got, err := NewPipeline(slowSemantic).Detect(context.Background(), reqCtx)
		if err != nil {
			t.Fatal(err)
		}
		if reqCtx.Metadata["detection_budget_exhausted"] != true {
			t.Fatalf("expected budget flag on single-analyzer path, got %#v", reqCtx.Metadata)
		}
		if got == nil || !got.Detected || got.Action != ActionChallenge || got.Category != "detection_budget" {
			t.Fatalf("expected closed challenge on single semantic path, got %#v", got)
		}
	})

	t.Run("clean finish is not challenged when deadline races after success", func(t *testing.T) {
		// Detector finishes successfully; incomplete flag unset → no budget challenge.
		fast := &countingDetector{
			id: "fast-semantic", priority: 290,
			fn: func(ctx context.Context, reqCtx *RequestContext) (*DetectionResult, error) {
				return &DetectionResult{Detected: false, Action: ActionPass}, nil
			},
		}
		reqCtx := &RequestContext{Metadata: map[string]any{"budget_exhausted_policy": "closed"}}
		got, err := NewPipeline(fast).Detect(context.Background(), reqCtx)
		if err != nil {
			t.Fatal(err)
		}
		if reqCtx.Metadata["detection_budget_exhausted"] == true {
			t.Fatalf("clean finish must not mark budget exhausted: %#v", reqCtx.Metadata)
		}
		if got != nil && got.Detected && got.Category == "detection_budget" {
			t.Fatalf("clean finish must not become budget challenge, got %#v", got)
		}
	})
}

func TestPipelineSemanticGroupConcurrentMerge(t *testing.T) {
	var started atomic.Int32
	slow := &countingDetector{
		id: "slow-semantic", priority: 290,
		fn: func(ctx context.Context, reqCtx *RequestContext) (*DetectionResult, error) {
			started.Add(1)
			// Wait until peer also started — proves concurrency.
			deadline := time.Now().Add(200 * time.Millisecond)
			for started.Load() < 2 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if reqCtx.Metadata == nil {
				reqCtx.Metadata = map[string]any{}
			}
			reqCtx.Metadata["from_slow"] = true
			return &DetectionResult{
				Detected: true, DetectorID: "slow-semantic", Category: "sqli",
				Severity: SeverityHigh, Action: ActionLog, Confidence: 0.8,
			}, nil
		},
	}
	fast := &countingDetector{
		id: "fast-semantic", priority: 291,
		fn: func(ctx context.Context, reqCtx *RequestContext) (*DetectionResult, error) {
			started.Add(1)
			deadline := time.Now().Add(200 * time.Millisecond)
			for started.Load() < 2 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if reqCtx.Metadata == nil {
				reqCtx.Metadata = map[string]any{}
			}
			reqCtx.Metadata["semantic_analysis"] = "from_fast"
			return &DetectionResult{
				Detected: true, DetectorID: "fast-semantic", Category: "xss",
				Severity: SeverityHigh, Action: ActionBlock, Confidence: 0.95,
			}, nil
		},
	}
	reqCtx := &RequestContext{SiteID: "s1", Metadata: map[string]any{"pre": true}}
	got, err := NewPipeline(slow, fast).Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.Action != ActionBlock || got.DetectorID != "fast-semantic" {
		t.Fatalf("expected concurrent block winner, got %#v", got)
	}
	if started.Load() < 2 {
		t.Fatalf("expected concurrent start, started=%d", started.Load())
	}
	if reqCtx.Metadata["pre"] != true {
		t.Fatalf("pre-filter metadata lost: %#v", reqCtx.Metadata)
	}
	if reqCtx.Metadata["semantic_analysis"] != "from_fast" {
		t.Fatalf("expected semantic metadata merge, got %#v", reqCtx.Metadata)
	}
	if len(reqCtx.Results) != 2 {
		t.Fatalf("expected 2 results, got %#v", reqCtx.Results)
	}
}

func TestPipelineSemanticForksRequestAndBodyState(t *testing.T) {
	const body = "name=normal&cmd=whoami"
	req := httptest.NewRequest(http.MethodPost, "http://example.test/submit", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	parent, err := NewRequestContextDeferredBody(req, "site-a", nil, 1<<20)
	if err != nil {
		t.Fatal(err)
	}

	type observation struct {
		request *http.Request
		name    string
		cmd     string
	}
	observations := make(chan observation, 2)
	makeDetector := func(id string, priority int) *countingDetector {
		return &countingDetector{id: id, priority: priority, fn: func(_ context.Context, fork *RequestContext) (*DetectionResult, error) {
			if fork == nil || fork.Request == nil {
				return nil, errors.New("semantic fork has no request")
			}
			if err := fork.Request.ParseForm(); err != nil {
				return nil, err
			}
			// ParseForm consumes only this fork's replay reader. Mutating URL and
			// Header here verifies that sibling detectors and the parent do not
			// share those mutable maps either.
			fork.Request.URL.Path = "/mutated/" + id
			fork.Request.Header.Set("X-Fork", id)
			observations <- observation{
				request: fork.Request,
				name:    fork.Request.PostForm.Get("name"),
				cmd:     fork.Request.PostForm.Get("cmd"),
			}
			return nil, nil
		}}
	}

	if _, err := NewPipeline(makeDetector("a", 290), makeDetector("b", 291)).Detect(context.Background(), parent); err != nil {
		t.Fatal(err)
	}
	first, second := <-observations, <-observations
	if first.request == second.request || first.request == req || second.request == req {
		t.Fatal("semantic detectors must receive independent request objects")
	}
	for _, got := range []observation{first, second} {
		if got.name != "normal" || got.cmd != "whoami" {
			t.Fatalf("fork ParseForm values = (%q, %q), want (normal, whoami)", got.name, got.cmd)
		}
		if got.request.Header.Get("X-Fork") == "" || got.request.URL.Path == "/submit" {
			t.Fatalf("fork mutation did not stay on detector request: %+v", got.request)
		}
	}
	if req.Header.Get("X-Fork") != "" || req.URL.Path != "/submit" {
		t.Fatalf("detector mutation escaped to parent request: header=%q path=%q", req.Header.Get("X-Fork"), req.URL.Path)
	}
	if req.Form != nil || req.PostForm != nil {
		t.Fatalf("ParseForm on a fork populated parent form state: form=%v post=%v", req.Form, req.PostForm)
	}
	replayed, err := io.ReadAll(req.Body)
	if err != nil || string(replayed) != body {
		t.Fatalf("parent body was consumed or changed: %q (err=%v)", replayed, err)
	}
}

func TestPipelineMetadataSnapshotsDeepCopyMutableValues(t *testing.T) {
	shared := &metadataIsolationNode{
		Labels: []string{"parent"},
		Attrs:  map[string]any{"nested": []string{"parent"}},
	}
	parent := &RequestContext{Metadata: map[string]any{
		"nested": map[string]any{
			"labels": []string{"parent"},
			"bytes":  []byte("parent"),
			"node":   shared,
		},
		"node_alias": shared,
		"struct_with_slices": metadataIsolationNode{
			Labels: []string{"struct-parent"},
			Attrs:  map[string]any{"value": []int{1}},
		},
		"semantic_analysis": &metadataIsolationNode{Labels: []string{"old"}},
	}}

	forkA := forkRequestContextWithContext(parent, context.Background())
	forkB := forkRequestContextWithContext(parent, context.Background())
	if forkA == nil || forkB == nil {
		t.Fatal("expected detector forks")
	}

	nestedA, ok := forkA.Metadata["nested"].(map[string]any)
	if !ok {
		t.Fatalf("fork nested metadata type = %T, want map[string]any", forkA.Metadata["nested"])
	}
	nodeA, ok := forkA.Metadata["node_alias"].(*metadataIsolationNode)
	if !ok {
		t.Fatalf("fork node metadata type = %T, want *metadataIsolationNode", forkA.Metadata["node_alias"])
	}
	if nodeA == shared {
		t.Fatal("fork retained parent pointer")
	}
	if got := nestedA["node"].(*metadataIsolationNode); got != nodeA {
		t.Fatal("aliases within a fork were not preserved")
	}
	nodeB := forkB.Metadata["node_alias"].(*metadataIsolationNode)
	if nodeB == nodeA {
		t.Fatal("separate forks share a metadata pointer")
	}

	nestedA["labels"].([]string)[0] = "fork-a"
	nestedA["bytes"].([]byte)[0] = 'F'
	nodeA.Labels[0] = "fork-a"
	nodeA.Attrs["nested"].([]string)[0] = "fork-a"
	structA := forkA.Metadata["struct_with_slices"].(metadataIsolationNode)
	structA.Labels[0] = "fork-struct"
	structA.Attrs["value"].([]int)[0] = 99

	parentNested := parent.Metadata["nested"].(map[string]any)
	if parentNested["labels"].([]string)[0] != "parent" || string(parentNested["bytes"].([]byte)) != "parent" {
		t.Fatalf("fork mutation escaped to parent nested metadata: %#v", parentNested)
	}
	if shared.Labels[0] != "parent" || shared.Attrs["nested"].([]string)[0] != "parent" {
		t.Fatalf("fork mutation escaped to parent pointer: %#v", shared)
	}
	if forkB.Metadata["nested"].(map[string]any)["labels"].([]string)[0] != "parent" || nodeB.Labels[0] != "parent" {
		t.Fatalf("separate fork was affected by sibling mutation: %#v", forkB.Metadata)
	}
	structParent := parent.Metadata["struct_with_slices"].(metadataIsolationNode)
	if structParent.Labels[0] != "struct-parent" || structParent.Attrs["value"].([]int)[0] != 1 {
		t.Fatalf("fork mutation escaped to struct metadata: %#v", structParent)
	}

	added := map[string]any{"items": []string{"fork-value"}}
	forkA.Metadata["added_nested"] = added
	forkA.Metadata["semantic_analysis"] = nodeA
	mergeRequestContext(parent, forkA)
	added["items"].([]string)[0] = "changed-after-merge"
	nodeA.Labels[0] = "changed-after-merge"
	if parent.Metadata["added_nested"].(map[string]any)["items"].([]string)[0] != "fork-value" {
		t.Fatal("merge retained a mutable nested map from the fork")
	}
	if parent.Metadata["semantic_analysis"].(*metadataIsolationNode).Labels[0] != "fork-a" {
		t.Fatal("semantic metadata was not copied during merge")
	}
}

func TestPipelineUploadTimeDoesNotConsumeDetectionBudgetOrCloseBody(t *testing.T) {
	release := make(chan struct{})
	readDone := make(chan struct{}, 1)
	readStarted := make(chan struct{}, 1)
	closed := new(atomic.Bool)
	body := &gatedBodyReader{
		payload: []byte("complete-upload"), release: release,
		started: readStarted, done: readDone, closed: closed,
	}
	req := httptest.NewRequest(http.MethodPost, "http://example.test/slow", body)
	req.ContentLength = -1
	reqCtx, err := NewRequestContextDeferredBody(req, "site-a", nil, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	type detection struct {
		result *DetectionResult
		err    error
	}
	detected := make(chan detection, 1)
	go func() {
		result, detectErr := NewPipeline(staticPipelineDetector{id: "semantic", priority: 290}).Detect(context.Background(), reqCtx)
		detected <- detection{result: result, err: detectErr}
	}()
	select {
	case <-readStarted:
	case <-time.After(time.Second):
		t.Fatal("deferred body read did not start")
	}

	// Upload I/O is intentionally outside the detector CPU budget. Holding the
	// body beyond 100ms must neither finish detection nor close the live upload.
	select {
	case got := <-detected:
		t.Fatalf("pipeline returned before upload completed: result=%#v err=%v", got.result, got.err)
	case <-time.After(175 * time.Millisecond):
	}
	if closed.Load() {
		t.Fatal("detector budget closed the live upload body")
	}

	close(release)
	select {
	case <-readDone:
	case <-time.After(time.Second):
		t.Fatal("deferred body reader did not unwind after release")
	}
	got := <-detected
	if got.err != nil {
		t.Fatal(got.err)
	}
	if got.result == nil || got.result.Detected || got.result.Action != ActionPass {
		t.Fatalf("completed upload detection result = %#v", got.result)
	}
	replayed, replayErr := io.ReadAll(req.Body)
	if replayErr != nil || string(replayed) != "complete-upload" {
		t.Fatalf("forward replay = %q, err=%v", replayed, replayErr)
	}
}

func TestPipelineDeferredBodyReadHonorsParentCancellation(t *testing.T) {
	readStarted := make(chan struct{}, 1)
	body := newCloseAwareBlockingBody(readStarted)
	req := httptest.NewRequest(http.MethodPost, "http://example.test/cancel", body)
	req.ContentLength = -1
	originalBody := req.Body
	reqCtx, err := NewRequestContextDeferredBody(req, "site-a", nil, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, detectErr := NewPipeline(staticPipelineDetector{id: "semantic", priority: 290}).Detect(parent, reqCtx)
		done <- detectErr
	}()
	select {
	case <-readStarted:
	case <-time.After(time.Second):
		t.Fatal("deferred body read did not start")
	}
	cancel()
	select {
	case detectErr := <-done:
		if !errors.Is(detectErr, context.Canceled) {
			t.Fatalf("pipeline error = %v, want context.Canceled", detectErr)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("pipeline did not return after parent cancellation")
	}
	if !body.closed.Load() {
		t.Fatal("parent cancellation did not signal cancellation to deferred body reader")
	}
	select {
	case <-body.finished:
	case <-time.After(time.Second):
		t.Fatal("deferred body reader did not unwind after cancellation")
	}
	if req.Body != originalBody || req.ContentLength != -1 || req.GetBody != nil {
		t.Fatalf("canceled read changed request replay state: body_changed=%v length=%d get_body=%v", req.Body != originalBody, req.ContentLength, req.GetBody != nil)
	}
	if len(reqCtx.rawBody) != 0 || len(reqCtx.DecodedBody) != 0 {
		t.Fatalf("canceled read installed a snapshot: raw=%q decoded=%q", reqCtx.rawBody, reqCtx.DecodedBody)
	}
}

func TestEnsureBodyReadFailureDoesNotInstallPartialSnapshot(t *testing.T) {
	wantErr := errors.New("upload read failed")
	body := &partialErrorBody{prefix: []byte("partial"), err: wantErr}
	req := httptest.NewRequest(http.MethodPost, "http://example.test/fail", body)
	req.ContentLength = -1
	originalBody := req.Body
	reqCtx, err := NewRequestContextDeferredBody(req, "site-a", nil, 1<<20)
	if err != nil {
		t.Fatal(err)
	}

	if gotErr := reqCtx.EnsureBodyContext(context.Background()); !errors.Is(gotErr, wantErr) {
		t.Fatalf("EnsureBodyContext error = %v, want %v", gotErr, wantErr)
	}
	if req.Body != originalBody || req.ContentLength != -1 || req.GetBody != nil {
		t.Fatalf("failed read installed partial replay: body_changed=%v length=%d get_body=%v", req.Body != originalBody, req.ContentLength, req.GetBody != nil)
	}
	if len(reqCtx.rawBody) != 0 || len(reqCtx.DecodedBody) != 0 {
		t.Fatalf("failed read installed partial snapshot: raw=%q decoded=%q", reqCtx.rawBody, reqCtx.DecodedBody)
	}
}

func TestEnsureBodyCancellationCannotLateWriteRequestOrPartialSnapshot(t *testing.T) {
	release := make(chan struct{})
	secondRead := make(chan struct{}, 1)
	body := &partialBlockingBody{
		prefix: []byte("partial"), release: release, secondRead: secondRead,
	}
	req := httptest.NewRequest(http.MethodPost, "http://example.test/cancel-partial", body)
	req.ContentLength = -1
	originalBody := req.Body
	reqCtx, err := NewRequestContextDeferredBody(req, "site-a", nil, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	ensureDone := make(chan error, 1)
	go func() { ensureDone <- reqCtx.EnsureBodyContext(ctx) }()
	select {
	case <-secondRead:
	case <-time.After(time.Second):
		t.Fatal("body reader did not block after returning its prefix")
	}
	cancel()
	select {
	case gotErr := <-ensureDone:
		if !errors.Is(gotErr, context.Canceled) {
			t.Fatalf("EnsureBodyContext error = %v, want context.Canceled", gotErr)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("EnsureBodyContext did not return after cancellation")
	}
	if !body.closed.Load() {
		t.Fatal("cancellation did not signal the live reader")
	}

	// Keep reading the public request fields while the abandoned worker exits.
	// Under -race this deterministically catches any late Request.Body or
	// ContentLength replacement; the value checks cover non-race runs.
	var changed atomic.Bool
	stopObserve := make(chan struct{})
	observeDone := make(chan struct{})
	go func() {
		defer close(observeDone)
		for {
			select {
			case <-stopObserve:
				return
			default:
				if req.Body != originalBody || req.ContentLength != -1 || req.GetBody != nil {
					changed.Store(true)
				}
				runtime.Gosched()
			}
		}
	}()
	close(release)
	select {
	case <-reqCtx.bodyReadDone:
	case <-time.After(time.Second):
		t.Fatal("abandoned body worker did not finish")
	}
	close(stopObserve)
	<-observeDone
	if changed.Load() || req.Body != originalBody || req.ContentLength != -1 || req.GetBody != nil {
		t.Fatalf("abandoned worker late-wrote request state: changed=%v length=%d get_body=%v", changed.Load(), req.ContentLength, req.GetBody != nil)
	}
	if len(reqCtx.rawBody) != 0 || len(reqCtx.DecodedBody) != 0 {
		t.Fatalf("abandoned worker installed partial snapshot: raw=%q decoded=%q", reqCtx.rawBody, reqCtx.DecodedBody)
	}
}

func TestPipelinePropagatesDeferredBodyErrorWithPrefilterOnly(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "http://example.test/upload", strings.NewReader("oversized"))
	// Force the unknown-length path so constructor admission does not reject the
	// request before Pipeline.Detect can exercise its bounded EnsureBody call.
	req.ContentLength = -1
	reqCtx, err := NewRequestContextDeferredBody(req, "site-a", nil, 4)
	if err != nil {
		t.Fatal(err)
	}
	var called atomic.Int32
	detector := &countingDetector{
		id: "header-prefilter", priority: 10,
		fn: func(context.Context, *RequestContext) (*DetectionResult, error) {
			called.Add(1)
			return nil, nil
		},
	}
	_, err = NewPipeline(detector).Detect(context.Background(), reqCtx)
	if !errors.Is(err, ErrRequestBodyTooLarge) {
		t.Fatalf("deferred body error = %v, want ErrRequestBodyTooLarge", err)
	}
	if called.Load() != 0 {
		t.Fatalf("prefilter ran after body preparation failed: %d calls", called.Load())
	}
}

func TestEnsureBodyConcurrentCallersShareBoundedSnapshot(t *testing.T) {
	const body = "concurrent-body"
	req := httptest.NewRequest(http.MethodPost, "http://example.test/upload", bytes.NewBufferString(body))
	ctx, err := NewRequestContextDeferredBody(req, "site-a", nil, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	const callers = 16
	errs := make(chan error, callers)
	var wg sync.WaitGroup
	wg.Add(callers)
	for range callers {
		go func() {
			defer wg.Done()
			errs <- ctx.EnsureBody()
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent EnsureBody error: %v", err)
		}
	}
	if got := string(ctx.DecodedBody); got != body {
		t.Fatalf("decoded snapshot = %q, want %q", got, body)
	}
	replayed, err := io.ReadAll(req.Body)
	if err != nil || string(replayed) != body {
		t.Fatalf("parent replay body = %q, err=%v", replayed, err)
	}
}

func TestPipelineSemanticDeadlineIsBoundedAndDropsLateForkWrites(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	finished := make(chan struct{})
	parentReq := httptest.NewRequest(http.MethodPost, "http://example.test/late", strings.NewReader("stable"))
	detector := &countingDetector{
		id: "ignores-context", priority: 290,
		fn: func(_ context.Context, reqCtx *RequestContext) (*DetectionResult, error) {
			close(started)
			<-release
			// This write intentionally happens after the pipeline deadline. The
			// single semantic path must run against an isolated fork so it cannot
			// race or overwrite final budget metadata on the parent request.
			reqCtx.Metadata["late_detector_write"] = true
			reqCtx.Request.Header.Set("X-Late", "true")
			reqCtx.Request.URL.Path = "/late-mutated"
			reqCtx.Request.Body = io.NopCloser(strings.NewReader("late-body"))
			close(finished)
			return &DetectionResult{
				Detected: true, DetectorID: "ignores-context", Category: "rce",
				Severity: SeverityCritical, Action: ActionBlock, Confidence: 0.99,
			}, nil
		},
	}
	parent := &RequestContext{Request: parentReq, Metadata: map[string]any{"budget_exhausted_policy": "closed"}}
	done := make(chan struct {
		result *DetectionResult
		err    error
	}, 1)
	startedAt := time.Now()
	go func() {
		result, err := NewPipeline(detector).Detect(context.Background(), parent)
		done <- struct {
			result *DetectionResult
			err    error
		}{result, err}
	}()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("semantic detector did not start")
	}
	var out struct {
		result *DetectionResult
		err    error
	}
	select {
	case out = <-done:
	case <-time.After(600 * time.Millisecond):
		t.Fatal("pipeline waited for detector that ignored context cancellation")
	}
	if out.err != nil {
		t.Fatalf("pipeline error = %v", out.err)
	}
	if elapsed := time.Since(startedAt); elapsed > 550*time.Millisecond {
		t.Fatalf("pipeline returned after %s despite 100ms budget", elapsed)
	}
	if out.result == nil || out.result.Category != "detection_budget" || out.result.Action != ActionChallenge {
		t.Fatalf("expected budget challenge after semantic timeout, got %#v", out.result)
	}
	if parent.Metadata["detection_analysis_incomplete"] != true {
		t.Fatalf("parent request missing incomplete marker: %#v", parent.Metadata)
	}

	close(release)
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("detector did not finish after release")
	}
	if _, ok := parent.Metadata["late_detector_write"]; ok {
		t.Fatalf("late detector write escaped isolated fork: %#v", parent.Metadata)
	}
	if parentReq.Header.Get("X-Late") != "" || parentReq.URL.Path != "/late" {
		t.Fatalf("late request mutation escaped isolated fork: header=%q path=%q", parentReq.Header.Get("X-Late"), parentReq.URL.Path)
	}
	replayed, err := io.ReadAll(parentReq.Body)
	if err != nil || string(replayed) != "stable" {
		t.Fatalf("late detector changed parent body: %q (err=%v)", replayed, err)
	}
}

func TestPipelineStopsStartingPrefiltersAfterContextCancellation(t *testing.T) {
	started := make(chan struct{})
	var secondCalls atomic.Int32
	first := &countingDetector{
		id: "bounded-pre", priority: 10,
		fn: func(ctx context.Context, _ *RequestContext) (*DetectionResult, error) {
			close(started)
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}
	second := &countingDetector{
		id: "must-not-start", priority: 11,
		fn: func(context.Context, *RequestContext) (*DetectionResult, error) {
			secondCalls.Add(1)
			return nil, nil
		},
	}
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := NewPipeline(first, second).Detect(parent, &RequestContext{})
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("pre-filter did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("pipeline error = %v, want context.Canceled", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("pipeline did not return after parent cancellation")
	}
	if got := secondCalls.Load(); got != 0 {
		t.Fatalf("pre-filter after cancellation was invoked %d times", got)
	}
}

func TestPipelineReusesSharedSemanticWorkers(t *testing.T) {
	workers := runtime.GOMAXPROCS(0)
	if workers > 8 {
		workers = 8
	}
	if workers < 1 {
		workers = 1
	}
	_ = semanticJobs()
	deadline := time.Now().Add(time.Second)
	for sharedSemanticWorkers.started.Load() != int64(workers) && time.Now().Before(deadline) {
		runtime.Gosched()
	}
	started := sharedSemanticWorkers.started.Load()
	if started != int64(workers) {
		t.Fatalf("started workers=%d, want %d", started, workers)
	}

	pipeline := NewPipeline(
		staticPipelineDetector{id: "one", priority: 290},
		staticPipelineDetector{id: "two", priority: 291},
	)
	for range 20 {
		if _, err := pipeline.Detect(context.Background(), &RequestContext{}); err != nil {
			t.Fatal(err)
		}
	}
	if got := sharedSemanticWorkers.started.Load(); got != started {
		t.Fatalf("per-request workers started: before=%d after=%d", started, got)
	}
}

func TestPipelineGuardOverloadAppliesConfiguredFailMode(t *testing.T) {
	tests := []struct {
		name         string
		priority     int
		policy       string
		wantAction   Action
		wantDetected bool
	}{
		{name: "pre-filter open", priority: 10, policy: "open", wantAction: ActionPass},
		{name: "pre-filter observe", priority: 10, policy: "observe", wantAction: ActionLog, wantDetected: true},
		{name: "pre-filter closed", priority: 10, policy: "closed", wantAction: ActionChallenge, wantDetected: true},
		{name: "semantic-only open", priority: 290, policy: "open", wantAction: ActionPass},
		{name: "semantic-only observe", priority: 290, policy: "observe", wantAction: ActionLog, wantDetected: true},
		{name: "semantic-only closed", priority: 290, policy: "closed", wantAction: ActionChallenge, wantDetected: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			saturateGuardSlots(t)
			var called atomic.Int32
			detector := &countingDetector{
				id: "malicious-payload", priority: tc.priority,
				fn: func(context.Context, *RequestContext) (*DetectionResult, error) {
					called.Add(1)
					return &DetectionResult{
						Detected: true, DetectorID: "malicious-payload", Category: "rce",
						Severity: SeverityCritical, Action: ActionBlock, Confidence: 0.99,
					}, nil
				},
			}
			reqCtx := &RequestContext{Metadata: map[string]any{"budget_exhausted_policy": tc.policy}}

			got, err := NewPipeline(detector).Detect(context.Background(), reqCtx)
			if err != nil {
				t.Fatal(err)
			}
			if called.Load() != 0 {
				t.Fatalf("detector ran despite saturated guard capacity: calls=%d", called.Load())
			}
			if got == nil || got.Action != tc.wantAction || got.Detected != tc.wantDetected {
				t.Fatalf("policy %q result = %#v, want action=%s detected=%v", tc.policy, got, tc.wantAction, tc.wantDetected)
			}
			if reqCtx.Metadata["detection_analysis_incomplete"] != true || reqCtx.Metadata["detection_overloaded"] != true {
				t.Fatalf("overload must explicitly mark incomplete analysis: %#v", reqCtx.Metadata)
			}
			if reason := reqCtx.Metadata["detection_analysis_incomplete_reason"]; reason != "guard_overload" {
				t.Fatalf("incomplete reason = %#v, want guard_overload", reason)
			}
			if reqCtx.Metadata["detection_budget_exhausted"] != true {
				t.Fatalf("overload must enter budget fail-mode: %#v", reqCtx.Metadata)
			}
			if tc.policy != "open" && got.Category != "detection_budget" {
				t.Fatalf("fail-mode category = %q, want detection_budget", got.Category)
			}
		})
	}
}

func TestDetectionBudgetHookConcurrentRegistration(t *testing.T) {
	SetDetectionBudgetExhaustedHook(nil)
	t.Cleanup(func() { SetDetectionBudgetExhaustedHook(nil) })

	var calls atomic.Int64
	hook := func() { calls.Add(1) }
	SetDetectionBudgetExhaustedHook(hook)

	const goroutines = 8
	const iterations = 250
	var wg sync.WaitGroup
	for range goroutines {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for range iterations {
				SetDetectionBudgetExhaustedHook(hook)
			}
		}()
		go func() {
			defer wg.Done()
			for range iterations {
				reqCtx := &RequestContext{Metadata: map[string]any{
					"budget_exhausted_policy": "open",
				}}
				_ = finalizeBudgetExhausted(reqCtx, nil)
			}
		}()
	}
	wg.Wait()

	if got, want := calls.Load(), int64(goroutines*iterations); got != want {
		t.Fatalf("hook calls = %d, want %d", got, want)
	}
}

func saturateGuardSlots(t *testing.T) {
	t.Helper()
	waitGuardSlotsIdle(t)
	if got := cap(guardSlots); got != maxInflightGuards {
		t.Fatalf("guard slot capacity = %d, want %d", got, maxInflightGuards)
	}
	n := cap(guardSlots)
	for i := 0; i < n; i++ {
		guardSlots <- struct{}{}
	}
	t.Cleanup(func() {
		for i := 0; i < n; i++ {
			select {
			case <-guardSlots:
			case <-time.After(2 * time.Second):
				t.Errorf("timed out draining guard slot %d/%d", i+1, n)
				return
			}
		}
		waitGuardSlotsIdle(t)
	})
}

func waitGuardSlotsIdle(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for len(guardSlots) > 0 {
		if time.Now().After(deadline) {
			t.Fatalf("guard slots did not drain, leftover=%d", len(guardSlots))
		}
		time.Sleep(time.Millisecond)
	}
}

type countingDetector struct {
	id       string
	priority int
	fn       func(context.Context, *RequestContext) (*DetectionResult, error)
}

type blockingBodyReader struct {
	release <-chan struct{}
	started chan<- struct{}
	done    chan<- struct{}
	closed  *atomic.Bool
}

func (r *blockingBodyReader) Read([]byte) (int, error) {
	if r.started != nil {
		select {
		case r.started <- struct{}{}:
		default:
		}
	}
	<-r.release
	select {
	case r.done <- struct{}{}:
	default:
	}
	return 0, io.EOF
}

func (r *blockingBodyReader) Close() error {
	if r.closed != nil {
		r.closed.Store(true)
	}
	return nil
}

type gatedBodyReader struct {
	payload []byte
	release <-chan struct{}
	started chan<- struct{}
	done    chan<- struct{}
	closed  *atomic.Bool
	once    sync.Once
	offset  int
}

func (r *gatedBodyReader) Read(p []byte) (int, error) {
	r.once.Do(func() {
		if r.started != nil {
			r.started <- struct{}{}
		}
		<-r.release
	})
	if r.offset >= len(r.payload) {
		if r.done != nil {
			select {
			case r.done <- struct{}{}:
			default:
			}
		}
		return 0, io.EOF
	}
	n := copy(p, r.payload[r.offset:])
	r.offset += n
	return n, nil
}

func (r *gatedBodyReader) Close() error {
	if r.closed != nil {
		r.closed.Store(true)
	}
	return nil
}

type closeAwareBlockingBody struct {
	started  chan<- struct{}
	closedCh chan struct{}
	finished chan struct{}
	closed   atomic.Bool
	once     sync.Once
}

func newCloseAwareBlockingBody(started chan<- struct{}) *closeAwareBlockingBody {
	return &closeAwareBlockingBody{
		started: started, closedCh: make(chan struct{}), finished: make(chan struct{}),
	}
}

func (r *closeAwareBlockingBody) Read([]byte) (int, error) {
	if r.started != nil {
		select {
		case r.started <- struct{}{}:
		default:
		}
	}
	<-r.closedCh
	r.once.Do(func() { close(r.finished) })
	return 0, errors.New("body closed")
}

func (r *closeAwareBlockingBody) Close() error {
	if r.closed.CompareAndSwap(false, true) {
		close(r.closedCh)
	}
	return nil
}

type partialErrorBody struct {
	prefix  []byte
	err     error
	emitted bool
}

func (r *partialErrorBody) Read(p []byte) (int, error) {
	if r.emitted {
		return 0, r.err
	}
	r.emitted = true
	return copy(p, r.prefix), r.err
}

func (*partialErrorBody) Close() error { return nil }

type partialBlockingBody struct {
	prefix     []byte
	release    <-chan struct{}
	secondRead chan<- struct{}
	emitted    bool
	closed     atomic.Bool
}

func (r *partialBlockingBody) Read(p []byte) (int, error) {
	if !r.emitted {
		r.emitted = true
		return copy(p, r.prefix), nil
	}
	if r.secondRead != nil {
		select {
		case r.secondRead <- struct{}{}:
		default:
		}
	}
	<-r.release
	return 0, errors.New("body read abandoned")
}

func (r *partialBlockingBody) Close() error {
	r.closed.Store(true)
	return nil
}

func (d *countingDetector) ID() string    { return d.id }
func (d *countingDetector) Name() string  { return d.id }
func (d *countingDetector) Priority() int { return d.priority }
func (d *countingDetector) Detect(ctx context.Context, reqCtx *RequestContext) (*DetectionResult, error) {
	return d.fn(ctx, reqCtx)
}
