package engine

import (
	"context"
	"errors"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

type Pipeline struct {
	detectors []Detector
	mu        sync.RWMutex
}

// OnDetectionBudgetExhausted is an optional hook for metrics when the 100ms
// semantic budget is exhausted. Set from package main/service wiring to avoid
// import cycles with semantic metrics.
var OnDetectionBudgetExhausted func()

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
	p.detectors = append(p.detectors, detector)
	sort.SliceStable(p.detectors, func(i, j int) bool {
		return p.detectors[i].Priority() < p.detectors[j].Priority()
	})
}

func (p *Pipeline) Detect(ctx context.Context, reqCtx *RequestContext) (*DetectionResult, error) {
	if reqCtx == nil {
		return nil, nil
	}

	// Pipeline-level timeout: 100ms total for all detection (fast-path guarantee)
	parentCtx := ctx
	ctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()

	p.mu.RLock()
	detectors := make([]Detector, len(p.detectors))
	copy(detectors, p.detectors)
	p.mu.RUnlock()

	var firstDetected *DetectionResult

	preFilters := make([]Detector, 0, len(detectors))
	semanticGroup := make([]Detector, 0, len(detectors))
	for _, d := range detectors {
		if d.Priority() < 290 {
			preFilters = append(preFilters, d)
		} else {
			semanticGroup = append(semanticGroup, d)
		}
	}

	// Phase 1: pre-filters sequential (IP/ACL/Bot/RateLimit — fast, order-sensitive).
	for _, detector := range preFilters {
		result, err := Guard(func() (*DetectionResult, error) { return detector.Detect(ctx, reqCtx) })
		if err != nil {
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
		// Budget fail-mode only when analysis did not finish cleanly under the
		// pipeline deadline. A clean pass that races the deadline must not be
		// upgraded to closed/challenge.
		if parentCtx.Err() == nil && budgetAnalysisIncomplete(ctx, reqCtx, err) {
			return finalizeBudgetExhausted(reqCtx, firstDetected), nil
		}
	} else if len(semanticGroup) > 1 {
		type jobOut struct {
			index  int
			result *DetectionResult
			fork   *RequestContext
			err    error
		}
		outs := make([]jobOut, len(semanticGroup))
		workers := len(semanticGroup)
		if max := runtime.GOMAXPROCS(0); workers > max {
			workers = max
		}
		if workers < 1 {
			workers = 1
		}
		jobs := make(chan int, len(semanticGroup))
		var wg sync.WaitGroup
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := range jobs {
					if ctx.Err() != nil {
						outs[i] = jobOut{index: i, err: ctx.Err()}
						continue
					}
					fork := forkRequestContext(reqCtx)
					res, err := Guard(func() (*DetectionResult, error) {
						return semanticGroup[i].Detect(ctx, fork)
					})
					outs[i] = jobOut{index: i, result: res, fork: fork, err: err}
				}
			}()
		}
		for i := range semanticGroup {
			jobs <- i
		}
		close(jobs)
		wg.Wait()

		budgetHit := ctx.Err() != nil && parentCtx.Err() == nil

		// Merge in priority order for stable Results / Metadata.
		for i := range outs {
			out := outs[i]
			if out.err != nil || out.fork == nil {
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
		if budgetHit {
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
// open | observe | closed (default observe when unset — matches smart web_attack).
func finalizeBudgetExhausted(reqCtx *RequestContext, firstDetected *DetectionResult) *DetectionResult {
	if reqCtx.Metadata == nil {
		reqCtx.Metadata = map[string]any{}
	}
	reqCtx.Metadata["detection_budget_exhausted"] = true
	if OnDetectionBudgetExhausted != nil {
		OnDetectionBudgetExhausted()
	}

	policy, _ := reqCtx.Metadata["budget_exhausted_policy"].(string)
	switch strings.ToLower(strings.TrimSpace(policy)) {
	case "open", "observe", "closed":
		// keep as-is
	default:
		policy = "observe"
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

// forkRequestContext creates an isolated context for concurrent detectors.
// The underlying *http.Request is shared read-only; Metadata is a shallow copy.
func forkRequestContext(src *RequestContext) *RequestContext {
	if src == nil {
		return nil
	}
	dst := &RequestContext{
		Request:     src.Request,
		ClientIP:    src.ClientIP,
		TraceID:     src.TraceID,
		SiteID:      src.SiteID,
		DecodedURI:  src.DecodedURI,
		DecodedBody: src.DecodedBody,
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
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]Detector, len(p.detectors))
	copy(out, p.detectors)
	return out
}
