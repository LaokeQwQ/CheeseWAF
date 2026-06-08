package engine

import (
	"context"
	"sort"
)

type Pipeline struct {
	detectors []Detector
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
	p.detectors = append(p.detectors, detector)
	sort.SliceStable(p.detectors, func(i, j int) bool {
		return p.detectors[i].Priority() < p.detectors[j].Priority()
	})
}

func (p *Pipeline) Detect(ctx context.Context, reqCtx *RequestContext) (*DetectionResult, error) {
	if reqCtx == nil {
		return nil, nil
	}
	var firstDetected *DetectionResult
	for _, detector := range p.detectors {
		result, err := detector.Detect(ctx, reqCtx)
		if err != nil {
			return nil, err
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
	if firstDetected != nil {
		return firstDetected, nil
	}
	return &DetectionResult{Detected: false, Action: ActionPass, Severity: SeverityInfo}, nil
}

func (p *Pipeline) Detectors() []Detector {
	out := make([]Detector, len(p.detectors))
	copy(out, p.detectors)
	return out
}
