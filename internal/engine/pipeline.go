package engine

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Pipeline struct {
	mu       sync.Mutex
	snapshot atomic.Pointer[pipelineSnapshot]
}

type pipelineSnapshot struct {
	detectors     []Detector
	preFilters    []Detector
	semanticGroup []Detector
}

type detectionBudgetExhaustedHook func()

// analysisIncompleteError lets detectors report a completed invocation whose
// input coverage was incomplete. It is intentionally structural so detector
// packages can implement it without creating an import cycle.
type analysisIncompleteError interface {
	error
	AnalysisIncomplete() bool
	IncompleteReason() string
}

type semanticJobOut struct {
	index  int
	result *DetectionResult
	fork   *RequestContext
	err    error
}

type semanticJob struct {
	ctx      context.Context
	detector Detector
	reqCtx   *RequestContext
	index    int
	done     chan<- semanticJobOut
}

var sharedSemanticWorkers struct {
	once    sync.Once
	jobs    chan semanticJob
	started atomic.Int64
}

func semanticJobs() chan semanticJob {
	sharedSemanticWorkers.once.Do(func() {
		workers := runtime.GOMAXPROCS(0)
		if workers > 8 {
			workers = 8
		}
		if workers < 1 {
			workers = 1
		}
		sharedSemanticWorkers.jobs = make(chan semanticJob, maxInflightGuards)
		for range workers {
			go func() {
				sharedSemanticWorkers.started.Add(1)
				for job := range sharedSemanticWorkers.jobs {
					if err := job.ctx.Err(); err != nil {
						job.done <- semanticJobOut{index: job.index, err: err}
						continue
					}
					fork := forkRequestContextWithContext(job.reqCtx, job.ctx)
					result, err := GuardContext(job.ctx, func() (*DetectionResult, error) {
						return job.detector.Detect(job.ctx, fork)
					})
					job.done <- semanticJobOut{index: job.index, result: result, fork: fork, err: err}
				}
			}()
		}
	})
	return sharedSemanticWorkers.jobs
}

// detectionBudgetHook is atomically replaceable because service hot reloads
// can rebuild a pipeline while requests are recording exhausted budgets.
var detectionBudgetHook atomic.Pointer[detectionBudgetExhaustedHook]

// SetDetectionBudgetExhaustedHook installs an optional metrics hook without
// introducing an import cycle with semantic metrics.
func SetDetectionBudgetExhaustedHook(hook func()) {
	if hook == nil {
		detectionBudgetHook.Store(nil)
		return
	}
	callback := detectionBudgetExhaustedHook(hook)
	detectionBudgetHook.Store(&callback)
}

func NewPipeline(detectors ...Detector) *Pipeline {
	p := &Pipeline{}
	for _, detector := range detectors {
		p.Add(detector)
	}
	return p
}

func (p *Pipeline) Add(detector Detector) {
	if detector == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	previous := p.snapshot.Load()
	detectors := make([]Detector, 0, 1)
	if previous != nil {
		detectors = append(detectors, previous.detectors...)
	}
	detectors = append(detectors, detector)
	sort.SliceStable(detectors, func(i, j int) bool {
		return detectors[i].Priority() < detectors[j].Priority()
	})
	p.snapshot.Store(makePipelineSnapshot(detectors))
}

func makePipelineSnapshot(detectors []Detector) *pipelineSnapshot {
	snapshot := &pipelineSnapshot{detectors: append([]Detector(nil), detectors...)}
	for _, detector := range snapshot.detectors {
		if detector.Priority() < 290 {
			snapshot.preFilters = append(snapshot.preFilters, detector)
		} else {
			snapshot.semanticGroup = append(snapshot.semanticGroup, detector)
		}
	}
	return snapshot
}

func (p *Pipeline) Detect(ctx context.Context, reqCtx *RequestContext) (*DetectionResult, error) {
	if reqCtx == nil {
		return nil, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}

	parentCtx := ctx
	snapshot := p.snapshot.Load()
	if snapshot == nil {
		return &DetectionResult{Detected: false, Action: ActionPass, Severity: SeverityInfo}, nil
	}
	var firstDetected *DetectionResult
	preFilters := snapshot.preFilters
	semanticGroup := snapshot.semanticGroup

	// Materialize the transfer body before starting the detector CPU budget.
	// Network upload time is governed by the request/server context, not by the
	// 100ms analysis deadline: timing it as detector work can close a live body
	// and then let open/observe mode forward a truncated request. Once this
	// succeeds, every detector fork replays immutable raw/decoded snapshots.
	if len(preFilters) > 0 || len(semanticGroup) > 0 {
		bodyErr := error(nil)
		loaded, stateErr, originalBody, available := reqCtx.bodyState()
		if available && stateErr != nil {
			// Preserve a cached read/decode error even when an embedder has
			// cleared Request.Body after the failed attempt.
			bodyErr = stateErr
		} else if available && loaded {
			bodyErr = stateErr
		} else if !available || requestBodyNeedsSnapshot(originalBody) {
			// bodyState returns the live reader while holding bodyMu. If another
			// reader is already in flight, it deliberately returns no handle so a
			// timeout cannot accidentally close a replay body installed meanwhile.
			bodyErr = reqCtx.EnsureBodyContext(parentCtx)
		}
		if bodyErr != nil {
			if parentErr := parentCtx.Err(); parentErr != nil {
				return nil, parentErr
			}
			return nil, bodyErr
		}
	}

	// Pipeline-level timeout: 100ms of detector work after body collection.
	ctx, cancel := context.WithTimeout(parentCtx, 100*time.Millisecond)
	defer cancel()

	// Phase 1: pre-filters sequential (IP/ACL/Bot/RateLimit — fast, order-sensitive).
	for _, detector := range preFilters {
		// Do not start another pre-filter after the request budget expires. The
		// synchronous guard intentionally relies on the pre-filter contract that
		// implementations are bounded/non-blocking; this check prevents needless
		// work during cancellation storms without adding a goroutine per request.
		if err := ctx.Err(); err != nil {
			if parentErr := parentCtx.Err(); parentErr != nil {
				return nil, parentErr
			}
			return finalizeBudgetExhausted(reqCtx, firstDetected), nil
		}
		// Pre-filters are order-sensitive, but an implementation must not be able
		// to hold the request path forever by ignoring cancellation. Run each one
		// against an isolated request snapshot so an abandoned detector cannot
		// mutate the parent after the budget expires.
		fork := forkRequestContextWithContext(reqCtx, ctx)
		result, err := GuardContext(ctx, func() (*DetectionResult, error) { return detector.Detect(ctx, fork) })
		if err != nil {
			if errors.Is(err, ErrDetectionOverload) {
				if parentErr := parentCtx.Err(); parentErr != nil {
					return nil, parentErr
				}
				return finalizeGuardOverload(reqCtx, firstDetected), nil
			}
			continue
		}
		mergeRequestContext(reqCtx, fork)
		if result == nil {
			continue
		}
		reqCtx.Results = append(reqCtx.Results, *result)
		if result.Detected && result.Action == ActionBlock {
			return result, nil
		}
		if result.Detected && firstDetected == nil {
			snapshot := *result
			firstDetected = &snapshot
		}
	}

	if err := ctx.Err(); err != nil {
		if parentErr := parentCtx.Err(); parentErr != nil {
			return nil, parentErr
		}
		return finalizeBudgetExhausted(reqCtx, firstDetected), nil
	}

	// Phase 2: multi-threaded semantic group. Each detector gets a forked
	// RequestContext so Metadata/Results writes never race. Merges are
	// deterministic by original detector order (priority sort already applied).
	if len(semanticGroup) == 1 {
		// A single detector still runs behind the context-aware guard. Keep its
		// writes isolated until successful completion so a detector that ignores
		// cancellation cannot race the pipeline's final metadata writes.
		fork := forkRequestContextWithContext(reqCtx, ctx)
		result, err := GuardContext(ctx, func() (*DetectionResult, error) { return semanticGroup[0].Detect(ctx, fork) })
		if err == nil && result != nil {
			mergeRequestContext(reqCtx, fork)
			reqCtx.Results = append(reqCtx.Results, *result)
			if result.Detected && (firstDetected == nil || betterDetectionResult(result, firstDetected)) {
				snapshot := *result
				firstDetected = &snapshot
			}
		}
		if err == nil && result == nil {
			mergeRequestContext(reqCtx, fork)
		}
		if reason, incomplete := detectorIncompleteReason(err); incomplete {
			if parentErr := parentCtx.Err(); parentErr != nil {
				return nil, parentErr
			}
			// GuardContext returned the detector's error rather than timing out, so
			// the fork is stable and safe to merge for incomplete-input evidence.
			mergeRequestContext(reqCtx, fork)
			return finalizeInputIncomplete(reqCtx, firstDetected, reason), nil
		}
		if errors.Is(err, ErrDetectionOverload) {
			if parentErr := parentCtx.Err(); parentErr != nil {
				return nil, parentErr
			}
			return finalizeGuardOverload(reqCtx, firstDetected), nil
		}
		if parentErr := parentCtx.Err(); parentErr != nil {
			return nil, parentErr
		}
		// Budget fail-mode only when analysis did not finish cleanly under the
		// pipeline deadline. A clean pass that races the deadline must not be
		// upgraded to closed/challenge.
		if parentCtx.Err() == nil && budgetAnalysisIncomplete(ctx, reqCtx, err) {
			return finalizeBudgetExhausted(reqCtx, firstDetected), nil
		}
	} else if len(semanticGroup) > 1 {
		outs := make([]semanticJobOut, len(semanticGroup))
		done := make(chan semanticJobOut, len(semanticGroup))
		jobs := semanticJobs()
		submitted := 0
		for i, detector := range semanticGroup {
			job := semanticJob{ctx: ctx, detector: detector, reqCtx: reqCtx, index: i, done: done}
			select {
			case jobs <- job:
				submitted++
			case <-ctx.Done():
				outs[i] = semanticJobOut{index: i, err: ctx.Err()}
			}
		}
		for range submitted {
			out := <-done
			outs[out.index] = out
		}

		// Merge in priority order for stable Results / Metadata.
		var detectErr error
		inputIncompleteReason := ""
		guardOverloaded := false
		for i := range outs {
			out := outs[i]
			if reason, incomplete := detectorIncompleteReason(out.err); incomplete {
				// A typed incomplete error is returned only after the detector exits;
				// unlike a deadline path, its fork can no longer be changing.
				mergeRequestContext(reqCtx, out.fork)
				if inputIncompleteReason == "" {
					inputIncompleteReason = reason
				}
				continue
			}
			if out.err != nil {
				if errors.Is(out.err, ErrDetectionOverload) {
					guardOverloaded = true
				}
				// Prefer context errors for budget incompleteness.
				if detectErr == nil || errors.Is(out.err, context.DeadlineExceeded) || errors.Is(out.err, context.Canceled) {
					detectErr = out.err
				}
				// GuardContext may have returned while the detector is still
				// unwinding. Never merge that fork: its map could still be
				// changing, and late writes must not reach the parent request.
				continue
			}
			if out.fork == nil {
				continue
			}
			mergeRequestContext(reqCtx, out.fork)
			if out.result == nil {
				continue
			}
			reqCtx.Results = append(reqCtx.Results, *out.result)
			if out.result.Detected && (firstDetected == nil || betterDetectionResult(out.result, firstDetected)) {
				snapshot := *out.result
				firstDetected = &snapshot
			}
		}
		if parentCtx.Err() == nil && guardOverloaded {
			return finalizeGuardOverload(reqCtx, firstDetected), nil
		}
		if parentCtx.Err() == nil && budgetAnalysisIncomplete(ctx, reqCtx, detectErr) {
			return finalizeBudgetExhausted(reqCtx, firstDetected), nil
		}
		if parentErr := parentCtx.Err(); parentErr != nil {
			return nil, parentErr
		}
		if inputIncompleteReason != "" {
			return finalizeInputIncomplete(reqCtx, firstDetected, inputIncompleteReason), nil
		}
	}

	if firstDetected != nil {
		return firstDetected, nil
	}
	return &DetectionResult{Detected: false, Action: ActionPass, Severity: SeverityInfo}, nil
}

// requestBodyNeedsSnapshot avoids comparing arbitrary ReadCloser interface
// values directly with http.NoBody: an embedder can provide an uncomparable
// concrete value, and interface equality would panic in that case.
func requestBodyNeedsSnapshot(body io.ReadCloser) bool {
	if body == nil {
		return false
	}
	return reflect.TypeOf(body) != reflect.TypeOf(http.NoBody)
}

func detectorIncompleteReason(err error) (string, bool) {
	if err == nil {
		return "", false
	}
	var incomplete analysisIncompleteError
	if !errors.As(err, &incomplete) || !incomplete.AnalysisIncomplete() {
		return "", false
	}
	reason := strings.TrimSpace(incomplete.IncompleteReason())
	if reason == "" {
		reason = "detector_input_incomplete"
	}
	return reason, true
}

// budgetAnalysisIncomplete reports whether the pipeline deadline stopped
// semantic work early (context error from detector or analyzer incomplete flag).
func budgetAnalysisIncomplete(ctx context.Context, reqCtx *RequestContext, detectErr error) bool {
	if ctx == nil || ctx.Err() == nil {
		return false
	}
	if detectErr != nil && (errors.Is(detectErr, context.DeadlineExceeded) || errors.Is(detectErr, context.Canceled) || ctx.Err() != nil) {
		return true
	}
	if reqCtx != nil && reqCtx.Metadata != nil {
		if incomplete, _ := reqCtx.Metadata["semantic_analysis_incomplete"].(bool); incomplete {
			// A typed input-coverage error also sets the aggregate semantic flag,
			// but is handled separately from a real deadline. When both occur,
			// detectErr above carries the deadline and budget accounting still wins.
			inputIncomplete, _ := reqCtx.Metadata["semantic_input_incomplete"].(bool)
			return !inputIncomplete
		}
	}
	return false
}

func finalizeBudgetExhausted(reqCtx *RequestContext, firstDetected *DetectionResult) *DetectionResult {
	return finalizeAnalysisIncomplete(reqCtx, firstDetected, "pipeline_deadline", true)
}

func finalizeInputIncomplete(reqCtx *RequestContext, firstDetected *DetectionResult, reason string) *DetectionResult {
	return finalizeAnalysisIncomplete(reqCtx, firstDetected, reason, false)
}

// finalizeAnalysisIncomplete applies the commercial open/observe/closed policy
// to either detector-budget exhaustion or a detector that completed without
// covering its whole input. Budget metrics are recorded only for real deadline
// or overload paths; malformed/truncated input has a separate audit identity.
func finalizeAnalysisIncomplete(reqCtx *RequestContext, firstDetected *DetectionResult, reason string, budgetExhausted bool) *DetectionResult {
	if reqCtx == nil {
		reqCtx = &RequestContext{}
	}
	if reqCtx.Metadata == nil {
		reqCtx.Metadata = map[string]any{}
	}
	reqCtx.Metadata["detection_analysis_incomplete"] = true
	if _, exists := reqCtx.Metadata["detection_analysis_incomplete_reason"]; !exists {
		reason = strings.TrimSpace(reason)
		if reason == "" {
			reason = "detector_input_incomplete"
		}
		reqCtx.Metadata["detection_analysis_incomplete_reason"] = reason
	}
	if budgetExhausted {
		reqCtx.Metadata["detection_budget_exhausted"] = true
		if hook := detectionBudgetHook.Load(); hook != nil {
			(*hook)()
		}
	} else {
		reqCtx.Metadata["detection_input_incomplete"] = true
	}

	policy, _ := reqCtx.Metadata["budget_exhausted_policy"].(string)
	policy = strings.ToLower(strings.TrimSpace(policy))
	switch policy {
	case "open", "observe", "closed":
		// keep as-is
	default:
		policy = "closed"
	}
	reqCtx.Metadata["budget_exhausted_policy"] = policy

	// Real block/challenge always wins over budget fail-mode.
	if firstDetected != nil && firstDetected.Detected &&
		(firstDetected.Action == ActionBlock || firstDetected.Action == ActionChallenge) {
		return firstDetected
	}

	detectorID := "pipeline.incomplete"
	category := "detection_incomplete"
	closedMessage := "request analysis incomplete; challenge preferred"
	observeMessage := "request analysis incomplete; observe only"
	if budgetExhausted {
		detectorID = "pipeline.budget"
		category = "detection_budget"
		closedMessage = "detection budget exhausted; challenge preferred for incomplete analysis"
		observeMessage = "detection budget exhausted; observe only"
	}

	switch policy {
	case "closed":
		res := DetectionResult{
			Detected:   true,
			DetectorID: detectorID,
			Category:   category,
			Severity:   SeverityMedium,
			Action:     ActionChallenge,
			Message:    closedMessage,
			Confidence: 0.55,
		}
		reqCtx.Results = append(reqCtx.Results, res)
		return &res
	case "observe":
		if firstDetected != nil && firstDetected.Detected {
			return firstDetected
		}
		res := DetectionResult{
			Detected:   true,
			DetectorID: detectorID,
			Category:   category,
			Severity:   SeverityInfo,
			Action:     ActionLog,
			Message:    observeMessage,
			Confidence: 0.4,
		}
		reqCtx.Results = append(reqCtx.Results, res)
		return &res
	default: // open
		if firstDetected != nil {
			return firstDetected
		}
		return &DetectionResult{Detected: false, Action: ActionPass, Severity: SeverityInfo}
	}
}

func finalizeGuardOverload(reqCtx *RequestContext, firstDetected *DetectionResult) *DetectionResult {
	if reqCtx.Metadata == nil {
		reqCtx.Metadata = map[string]any{}
	}
	reqCtx.Metadata["detection_overloaded"] = true
	reqCtx.Metadata["detection_analysis_incomplete_reason"] = "guard_overload"
	return finalizeBudgetExhausted(reqCtx, firstDetected)
}

// forkRequestContextWithContext creates a detector-owned request snapshot.
// http.Request.Clone deep-copies URL/Header/Form state, while the body is
// rebuilt from RequestContext's immutable transfer/decode snapshots. This is
// important because ParseForm mutates the request (and consumes Body), and a
// timed-out detector may continue unwinding after the pipeline has returned.
func forkRequestContextWithContext(src *RequestContext, detectorCtx context.Context) *RequestContext {
	if src == nil {
		return nil
	}
	rawBody, decodedBody, bodyLoaded, bodyPresent, bodyErr := src.detectionBodySnapshot()
	request := cloneRequestForDetection(src.Request, rawBody, decodedBody, bodyLoaded, bodyPresent, detectorCtx)
	dst := &RequestContext{
		Request:      request,
		ClientIP:     src.ClientIP,
		TraceID:      src.TraceID,
		SiteID:       src.SiteID,
		DecodedURI:   src.DecodedURI,
		DecodedBody:  decodedBody,
		maxBodyBytes: src.maxBodyBytes,
		bodyLoaded:   bodyLoaded,
		rawBody:      rawBody,
		bodyErr:      bodyErr,
	}
	dst.Metadata = cloneMetadata(src.Metadata)
	return dst
}

// metadataCloneVisit identifies a reference-like metadata value while it is
// being copied. Keeping a memo preserves aliases within one fork and prevents
// recursive values from overflowing the stack. Slice length/capacity are part
// of the key because two views can share a backing array while exposing
// different logical values.
type metadataCloneVisit struct {
	typ  reflect.Type
	kind reflect.Kind
	ptr  uintptr
	len  int
	cap  int
}

// cloneMetadata makes an isolated metadata snapshot for a detector fork.
// Metadata is an extension point, so values are not limited to the maps and
// slices currently emitted by built-in detectors. Reflection recursively
// copies maps, slices, arrays, pointers, interfaces, and exported struct
// fields while preserving scalar/immutable values and concrete types.
//
// Map keys are intentionally retained: cloning pointer keys would change map
// lookup identity. Metadata values are the mutable part that must be isolated.
// If an opaque value cannot be copied safely, the value itself is retained as a
// last-resort compatibility fallback; ordinary exported containers are fully
// copied.
func cloneMetadata(src map[string]any) map[string]any {
	if src == nil {
		return nil
	}
	dst := make(map[string]any, len(src)+4)
	memo := make(map[metadataCloneVisit]reflect.Value)
	for key, value := range src {
		cloned := cloneMetadataReflect(reflect.ValueOf(value), memo)
		if !cloned.IsValid() || !cloned.CanInterface() {
			dst[key] = value
			continue
		}
		dst[key] = cloned.Interface()
	}
	return dst
}

func cloneMetadataReflect(value reflect.Value, memo map[metadataCloneVisit]reflect.Value) (out reflect.Value) {
	if !value.IsValid() {
		return value
	}
	// Metadata is supplied by extension code. A value with unusual reflection
	// semantics must not make request detection panic; retain that one value and
	// continue cloning the rest of the snapshot.
	defer func() {
		if recover() != nil {
			out = value
		}
	}()

	switch value.Kind() {
	case reflect.Interface:
		if value.IsNil() {
			return reflect.Zero(value.Type())
		}
		inner := cloneMetadataReflect(value.Elem(), memo)
		if !inner.IsValid() {
			return reflect.Zero(value.Type())
		}
		wrapped := reflect.New(value.Type()).Elem()
		if inner.Type().AssignableTo(value.Type()) || inner.Type().Implements(value.Type()) {
			wrapped.Set(inner)
			return wrapped
		}
		return value

	case reflect.Map:
		if value.IsNil() {
			return reflect.Zero(value.Type())
		}
		visit := metadataCloneVisit{typ: value.Type(), kind: value.Kind(), ptr: value.Pointer()}
		if cloned, ok := memo[visit]; ok {
			return cloned
		}
		cloned := reflect.MakeMapWithSize(value.Type(), value.Len())
		memo[visit] = cloned
		iter := value.MapRange()
		for iter.Next() {
			key := iter.Key()
			item := cloneMetadataReflect(iter.Value(), memo)
			if !item.IsValid() || !item.Type().AssignableTo(value.Type().Elem()) {
				item = iter.Value()
			}
			cloned.SetMapIndex(key, item)
		}
		return cloned

	case reflect.Slice:
		if value.IsNil() {
			return reflect.Zero(value.Type())
		}
		visit := metadataCloneVisit{
			typ: value.Type(), kind: value.Kind(), ptr: value.Pointer(), len: value.Len(), cap: value.Cap(),
		}
		if cloned, ok := memo[visit]; ok {
			return cloned
		}
		cloned := reflect.MakeSlice(value.Type(), value.Len(), value.Len())
		memo[visit] = cloned
		for i := 0; i < value.Len(); i++ {
			item := cloneMetadataReflect(value.Index(i), memo)
			if item.IsValid() && item.Type().AssignableTo(cloned.Index(i).Type()) {
				cloned.Index(i).Set(item)
			}
		}
		return cloned

	case reflect.Array:
		cloned := reflect.New(value.Type()).Elem()
		for i := 0; i < value.Len(); i++ {
			item := cloneMetadataReflect(value.Index(i), memo)
			if item.IsValid() && item.Type().AssignableTo(cloned.Index(i).Type()) {
				cloned.Index(i).Set(item)
			}
		}
		return cloned

	case reflect.Pointer:
		if value.IsNil() {
			return reflect.Zero(value.Type())
		}
		visit := metadataCloneVisit{typ: value.Type(), kind: value.Kind(), ptr: value.Pointer()}
		if cloned, ok := memo[visit]; ok {
			return cloned
		}
		cloned := reflect.New(value.Type().Elem())
		memo[visit] = cloned
		item := cloneMetadataReflect(value.Elem(), memo)
		if item.IsValid() && item.Type().AssignableTo(cloned.Elem().Type()) {
			cloned.Elem().Set(item)
		}
		return cloned

	case reflect.Struct:
		// Start with a value copy so unexported, immutable implementation fields
		// (for example time.Time internals) remain valid. Exported mutable fields
		// are then replaced with recursively cloned values.
		cloned := reflect.New(value.Type()).Elem()
		cloned.Set(value)
		for i := 0; i < value.NumField(); i++ {
			sourceField := value.Field(i)
			destinationField := cloned.Field(i)
			if !sourceField.CanInterface() || !destinationField.CanSet() {
				continue
			}
			item := cloneMetadataReflect(sourceField, memo)
			if item.IsValid() && item.Type().AssignableTo(destinationField.Type()) {
				destinationField.Set(item)
			}
		}
		return cloned

	default:
		// Scalars, funcs, channels, unsafe pointers, and other opaque values are
		// retained. Channels/functions have identity semantics and cannot be
		// meaningfully copied without changing extension behavior.
		return value
	}
}

// cloneRequestForDetection returns a request whose mutable state and body
// reader are independent from the parent request. A missing body snapshot can
// only occur for a manually assembled/deferred RequestContext; in that case we
// use GetBody when available and otherwise deliberately avoid sharing Body.
func cloneRequestForDetection(src *http.Request, rawBody, decodedBody []byte, bodyLoaded, bodyPresent bool, detectorCtx context.Context) *http.Request {
	if src == nil {
		return nil
	}
	cloneCtx := src.Context()
	if detectorCtx != nil {
		cloneCtx = detectorCtx
	}
	request := src.Clone(cloneCtx)

	setReplayBody := func(body []byte, semantic bool) {
		// body is owned by this fork. The closure only ever creates readers, so
		// ParseForm/FormValue calls cannot consume a sibling detector's reader.
		snapshot := body
		request.Body = io.NopCloser(bytes.NewReader(snapshot))
		request.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(snapshot)), nil
		}
		request.ContentLength = int64(len(snapshot))
		if semantic {
			// ParseForm does not decode Content-Encoding. Detector requests expose
			// the semantic body, so retain headers consistent with that body.
			request.Header.Del("Content-Encoding")
			request.Header.Del("Content-Length")
		}
	}

	if bodyLoaded {
		if bodyPresent {
			semantic := strings.TrimSpace(request.Header.Get("Content-Encoding")) != "" && !strings.EqualFold(strings.TrimSpace(request.Header.Get("Content-Encoding")), "identity")
			if semantic {
				setReplayBody(decodedBody, true)
			} else {
				setReplayBody(rawBody, false)
			}
		} else if len(decodedBody) > 0 {
			// Preserve contexts assembled with DecodedBody but no transport body.
			setReplayBody(decodedBody, true)
		} else {
			request.Body = nil
			request.GetBody = nil
		}
		return request
	}

	// A standard bytes.Reader-backed request can provide a non-consuming body
	// clone. Do not retain src.Body when GetBody is unavailable: sharing it would
	// reintroduce the exact ParseForm race this snapshot is intended to remove.
	if src.GetBody != nil {
		if body, err := src.GetBody(); err == nil {
			request.Body = body
			getBody := src.GetBody
			request.GetBody = func() (io.ReadCloser, error) { return getBody() }
			return request
		}
	}
	if len(decodedBody) > 0 {
		setReplayBody(decodedBody, true)
		return request
	}
	request.Body = nil
	request.GetBody = nil
	return request
}

// mergeRequestContext copies forked Metadata keys into parent (fork wins on conflict).
func mergeRequestContext(parent, fork *RequestContext) {
	if parent == nil || fork == nil || len(fork.Metadata) == 0 {
		return
	}
	if parent.Metadata == nil {
		parent.Metadata = make(map[string]any, len(fork.Metadata))
	}
	memo := make(map[metadataCloneVisit]reflect.Value)
	for k, v := range fork.Metadata {
		// Do not clobber parent keys already written by pre-filters unless fork added them.
		if _, exists := parent.Metadata[k]; !exists {
			parent.Metadata[k] = cloneMetadataValue(v, memo)
			continue
		}
		// Semantic keys always take the forked (latest detector) value.
		switch k {
		case "semantic_analysis", "semantic_anomaly_score", "semantic_analysis_incomplete", "semantic_analysis_incomplete_reason",
			"semantic_input_incomplete", "semantic_input_incomplete_reason", "detection_budget_exhausted",
			"detection_input_incomplete", "budget_exhausted_policy", "waf_policy_decision", "semantic_skipped":
			parent.Metadata[k] = cloneMetadataValue(v, memo)
		}
	}
}

func cloneMetadataValue(value any, memo map[metadataCloneVisit]reflect.Value) any {
	cloned := cloneMetadataReflect(reflect.ValueOf(value), memo)
	if !cloned.IsValid() || !cloned.CanInterface() {
		return value
	}
	return cloned.Interface()
}

func betterDetectionResult(next, current *DetectionResult) bool {
	if next == nil {
		return false
	}
	if current == nil {
		return true
	}
	if next.Action != current.Action {
		return actionRank(next.Action) > actionRank(current.Action)
	}
	if next.Severity != current.Severity {
		return next.Severity > current.Severity
	}
	return next.Confidence > current.Confidence
}

func actionRank(action Action) int {
	switch action {
	case ActionBlock:
		return 4
	case ActionChallenge:
		return 3
	case ActionLog:
		return 2
	case ActionPass:
		return 1
	default:
		return 0
	}
}

func (p *Pipeline) Detectors() []Detector {
	snapshot := p.snapshot.Load()
	if snapshot == nil {
		return nil
	}
	out := make([]Detector, len(snapshot.detectors))
	copy(out, snapshot.detectors)
	return out
}
