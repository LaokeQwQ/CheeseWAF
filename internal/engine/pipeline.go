package engine

import (
	"context"
	"sort"
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

	// Concurrent detection: run detectors in parallel using bounded workers.
	// Detectors with priority < 300 run first (IP/ACL/bot), then semantic.
	// Within the semantic group (priority >= 290), run concurrently.
	// For simplicity, we detect sequentially for priority-ordered blocking,
	// but semantic detectors can run concurrently within their group.

	preFilters := make([]Detector, 0, len(detectors))
	semanticGroup := make([]Detector, 0, len(detectors))
	for _, d := range detectors {
		if d.Priority() < 290 {
			preFilters = append(preFilters, d)
		} else {
			semanticGroup = append(semanticGroup, d)
		}
	}

	// Phase 1: Run pre-filters sequentially (IP/ACL/Bot/RateLimit - fast, blocking)
	for _, detector := range preFilters {
		result, err := Guard(func() (*DetectionResult, error) { return detector.Detect(ctx, reqCtx) })
		if err != nil {
			continue // Skip failed detectors rather than failing the entire request
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

	// Detectors may enrich request metadata. Serial execution keeps those writes
	// deterministic, honors cancellation, and avoids shared-map races.
	for _, detector := range semanticGroup {
		if err := ctx.Err(); err != nil {
			if parentErr := parentCtx.Err(); parentErr != nil {
				return nil, parentErr
			}
			if reqCtx.Metadata == nil {
				reqCtx.Metadata = map[string]any{}
			}
			reqCtx.Metadata["detection_budget_exhausted"] = true
			if OnDetectionBudgetExhausted != nil {
				OnDetectionBudgetExhausted()
			}
			break
		}
		result, err := Guard(func() (*DetectionResult, error) { return detector.Detect(ctx, reqCtx) })
		if err != nil {
			continue
		}
		if result == nil {
			continue
		}
		reqCtx.Results = append(reqCtx.Results, *result)
		if result.Detected && (firstDetected == nil || betterDetectionResult(result, firstDetected)) {
			snapshot := *result
			firstDetected = &snapshot
		}
	}

	if firstDetected != nil {
		return firstDetected, nil
	}
	return &DetectionResult{Detected: false, Action: ActionPass, Severity: SeverityInfo}, nil
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
