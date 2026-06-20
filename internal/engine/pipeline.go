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
	ctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()

	// Sanitize input before detection
	if reqCtx.Request != nil {
		reqCtx.DecodedBody = sanitizeBody(reqCtx.DecodedBody)
	}

	p.mu.RLock()
	detectors := make([]Detector, len(p.detectors))
	copy(detectors, p.detectors)
	p.mu.RUnlock()

	var mu sync.Mutex
	var firstDetected *DetectionResult
	var wg sync.WaitGroup

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
		mu.Lock()
		reqCtx.Results = append(reqCtx.Results, *result)
		mu.Unlock()
		if result.Detected && result.Action == ActionBlock {
			return result, nil
		}
		if result.Detected && firstDetected == nil {
			snapshot := *result
			mu.Lock()
			firstDetected = &snapshot
			mu.Unlock()
		}
	}

	// Phase 2: Run semantic detectors concurrently with sandbox protection
	results := make([]*DetectionResult, len(semanticGroup))
	for i := range semanticGroup {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			result, err := Guard(func() (*DetectionResult, error) {
				return semanticGroup[idx].Detect(ctx, reqCtx)
			})
			if err != nil {
				results[idx] = nil
				return
			}
			results[idx] = result
		}(i)
	}
	wg.Wait()

	for _, result := range results {
		if result == nil {
			continue
		}
		mu.Lock()
		reqCtx.Results = append(reqCtx.Results, *result)
		mu.Unlock()
		if result.Detected && result.Action == ActionBlock {
			return result, nil
		}
		if result.Detected && firstDetected == nil {
			snapshot := *result
			mu.Lock()
			firstDetected = &snapshot
			mu.Unlock()
		}
	}

	if firstDetected != nil {
		return firstDetected, nil
	}
	return &DetectionResult{Detected: false, Action: ActionPass, Severity: SeverityInfo}, nil
}

func sanitizeBody(body []byte) []byte {
	if len(body) > MaxInputBytes {
		return body[:MaxInputBytes]
	}
	return body
}

func (p *Pipeline) Detectors() []Detector {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]Detector, len(p.detectors))
	copy(out, p.detectors)
	return out
}
