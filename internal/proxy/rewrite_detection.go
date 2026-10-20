package proxy

import (
	"context"
	"net/http"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

func (s *Server) detectRequestIdentities(ctx context.Context, pipeline requestDetectionPipeline, owner *engine.RequestContext, public *http.Request, rewritten bool, policy config.ProtectionPolicyConfig, site config.SiteConfig) (*engine.DetectionResult, error) {
	if !rewritten {
		return pipeline.Detect(ctx, owner)
	}
	// Fork both identities before detection so one view's semantic skips,
	// evidence, and incomplete-analysis markers cannot contaminate the other.
	publicView, err := owner.DetectionView(public)
	if err != nil {
		return nil, err
	}
	targetView, err := owner.DetectionView(owner.Request)
	if err != nil {
		return nil, err
	}
	var defaultPipeline engine.Pipeline
	budget := defaultPipeline.DetectionBudget(owner)
	if resolver, ok := pipeline.(interface {
		DetectionBudget(*engine.RequestContext) time.Duration
	}); ok {
		budget = resolver.DetectionBudget(owner)
	}
	started := time.Now()
	var selected *engine.RequestContext
	var selectedResult *engine.DetectionResult
	selectedRank := -1
	incompleteAudit := map[string]any{}
	for _, view := range []*engine.RequestContext{publicView, targetView} {
		remaining := budget - time.Since(started)
		if remaining <= 0 {
			// Zero/negative would reset Pipeline to its default budget. A tiny
			// positive budget invokes its existing open/observe/closed finalizer.
			remaining = time.Nanosecond
		}
		view.Metadata["detection_budget"] = remaining
		result, err := pipeline.Detect(ctx, view)
		if err != nil {
			return nil, err
		}
		rank := 0
		if (result == nil || !result.Detected) && s.promotes.Active(site.ID, s.wallNow()) && detectionFromReviewCandidate(view) != nil {
			// Keep handle's direct promotion block: returning the original pass
			// lets it enforce the candidate without ordinary detection thresholds.
			rank = 3
		} else if result != nil && result.Detected {
			decision := evaluateWebAttackPolicyWithEvidence(policy.WebAttack, result, view.Results, site.WAF.ParanoiaLevel)
			switch decision.Action {
			case engine.ActionBlock.String():
				rank = 3
			case engine.ActionChallenge.String():
				rank = 2
			case engine.ActionLog.String():
				rank = 1
			}
		}
		for _, key := range []string{"detection_budget_exhausted", "detection_input_incomplete", "detection_analysis_incomplete", "detection_analysis_incomplete_reason", "semantic_input_incomplete", "semantic_input_incomplete_reason", "semantic_analysis_incomplete", "semantic_analysis_incomplete_reason"} {
			switch value := view.Metadata[key].(type) {
			case bool:
				if value {
					incompleteAudit[key] = true
				}
			case string:
				if value != "" && incompleteAudit[key] == nil {
					incompleteAudit[key] = value
				}
			}
		}
		selectedOperational := selectedResult != nil && (selectedResult.Category == "detection_budget" || selectedResult.Category == "detection_incomplete")
		actualFinding := result != nil && result.Detected && result.Category != "detection_budget" && result.Category != "detection_incomplete"
		candidate := detectionFromReviewCandidate(view) != nil
		selectedCandidate := selected != nil && detectionFromReviewCandidate(selected) != nil
		if rank > selectedRank || (rank == selectedRank && ((selectedOperational && actualFinding) || (candidate && !selectedCandidate))) {
			selected, selectedResult, selectedRank = view, result, rank
		}
		if rank == 3 {
			break
		}
	}
	// Keep the original body owner and transport request alive. Only the chosen
	// identity's audit/evidence is published, never duplicate body evidence.
	owner.Metadata = selected.Metadata
	owner.Results = selected.Results
	owner.Metadata[selectedInspectionURIKey] = selected.Request.URL.RequestURI()
	for key, value := range incompleteAudit {
		if flag, ok := value.(bool); ok && flag {
			owner.Metadata[key] = true
		} else if _, exists := owner.Metadata[key]; !exists {
			owner.Metadata[key] = value
		}
	}
	return selectedResult, nil
}
