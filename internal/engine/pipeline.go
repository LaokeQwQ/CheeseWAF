package engine

import (
	"context"
	"errors"
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
					fork := forkRequestContext(job.reqCtx)
					result, err := Guard(func() (*DetectionResult, error) {
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

	// Pipeline-level timeout: 100ms total for all detection (fast-path guarantee)
	parentCtx := ctx
	ctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()

	snapshot := p.snapshot.Load()
	if snapshot == nil {
		return &DetectionResult{Detected: false, Action: ActionPass, Severity: SeverityInfo}, nil
	}
	var firstDetected *DetectionResult
	preFilters := snapshot.preFilters
	semanticGroup := snapshot.semanticGroup

	// Phase 1: pre-filters sequential (IP/ACL/Bot/RateLimit — fast, order-sensitive).
	for _, detector := range preFilters {
		result, err := GuardSync(func() (*DetectionResult, error) { return detector.Detect(ctx, reqCtx) })
		if err != nil {
			if errors.Is(err, ErrDetectionOverload) {
				if parentErr := parentCtx.Err(); parentErr != nil {
					return nil, parentErr
				}
				return finalizeGuardOverload(reqCtx, firstDetected), nil
			}
			continue
		}
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
		// Hot path: single Analyzer — no fork overhead.
		result, err := Guard(func() (*DetectionResult, error) { return semanticGroup[0].Detect(ctx, reqCtx) })
		if err == nil && result != nil {
			reqCtx.Results = append(reqCtx.Results, *result)
			if result.Detected && (firstDetected == nil || betterDetectionResult(result, firstDetected)) {
				snapshot := *result
				firstDetected = &snapshot
			}
		}
		if errors.Is(err, ErrDetectionOverload) {
			if parentErr := parentCtx.Err(); parentErr != nil {
				return nil, parentErr
			}
			return finalizeGuardOverload(reqCtx, firstDetected), nil
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
		guardOverloaded := false
		for i := range outs {
			out := outs[i]
			if out.err != nil {
				if errors.Is(out.err, ErrDetectionOverload) {
					guardOverloaded = true
				}
				// Prefer context errors for budget incompleteness.
				if detectErr == nil || errors.Is(out.err, context.DeadlineExceeded) || errors.Is(out.err, context.Canceled) {
					detectErr = out.err
				}
				if out.fork == nil {
					continue
				}
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
	}

	if firstDetected != nil {
		return firstDetected, nil
	}
	return &DetectionResult{Detected: false, Action: ActionPass, Severity: SeverityInfo}, nil
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
			return true
		}
	}
	return false
}

// finalizeBudgetExhausted marks budget exhaustion, records metrics, and applies
// the commercial fail-mode policy from metadata["budget_exhausted_policy"]:
// open | observe | closed (default closed when unset — matches smart web_attack).
func finalizeBudgetExhausted(reqCtx *RequestContext, firstDetected *DetectionResult) *DetectionResult {
	if reqCtx.Metadata == nil {
		reqCtx.Metadata = map[string]any{}
	}
	reqCtx.Metadata["detection_analysis_incomplete"] = true
	if _, exists := reqCtx.Metadata["detection_analysis_incomplete_reason"]; !exists {
		reqCtx.Metadata["detection_analysis_incomplete_reason"] = "pipeline_deadline"
	}
	reqCtx.Metadata["detection_budget_exhausted"] = true
	if hook := detectionBudgetHook.Load(); hook != nil {
		(*hook)()
	}

	policy, _ := reqCtx.Metadata["budget_exhausted_policy"].(string)
	switch strings.ToLower(strings.TrimSpace(policy)) {
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

	switch policy {
	case "closed":
		// Incomplete analysis under closed policy → challenge (not silent hard-block).
		res := DetectionResult{
			Detected:   true,
			DetectorID: "pipeline.budget",
			Category:   "detection_budget",
			Severity:   SeverityMedium,
			Action:     ActionChallenge,
			Message:    "detection budget exhausted; challenge preferred for incomplete analysis",
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
			DetectorID: "pipeline.budget",
			Category:   "detection_budget",
			Severity:   SeverityInfo,
			Action:     ActionLog,
			Message:    "detection budget exhausted; observe only",
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

// forkRequestContext creates an isolated context for concurrent detectors.
// The underlying *http.Request is shared read-only; Metadata is a shallow copy.
func forkRequestContext(src *RequestContext) *RequestContext {
	if src == nil {
		return nil
	}
	dst := &RequestContext{
		Request:      src.Request,
		ClientIP:     src.ClientIP,
		TraceID:      src.TraceID,
		SiteID:       src.SiteID,
		DecodedURI:   src.DecodedURI,
		DecodedBody:  src.DecodedBody,
		maxBodyBytes: src.maxBodyBytes,
		bodyLoaded:   src.bodyLoaded,
	}
	if len(src.Metadata) > 0 {
		dst.Metadata = make(map[string]any, len(src.Metadata)+4)
		for k, v := range src.Metadata {
			dst.Metadata[k] = v
		}
	}
	return dst
}

// mergeRequestContext copies forked Metadata keys into parent (fork wins on conflict).
func mergeRequestContext(parent, fork *RequestContext) {
	if parent == nil || fork == nil || len(fork.Metadata) == 0 {
		return
	}
	if parent.Metadata == nil {
		parent.Metadata = make(map[string]any, len(fork.Metadata))
	}
	for k, v := range fork.Metadata {
		// Do not clobber parent keys already written by pre-filters unless fork added them.
		if _, exists := parent.Metadata[k]; !exists {
			parent.Metadata[k] = v
			continue
		}
		// Semantic keys always take the forked (latest detector) value.
		switch k {
		case "semantic_analysis", "semantic_anomaly_score", "semantic_analysis_incomplete", "detection_budget_exhausted", "budget_exhausted_policy", "waf_policy_decision", "semantic_skipped":
			parent.Metadata[k] = v
		}
	}
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
