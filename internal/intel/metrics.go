package intel

import "sync/atomic"

// Process-wide counters for the intel pipeline. They are intentionally plain
// atomics so the WAF data plane never blocks on metrics collection.
var (
	metricImportsOK       atomic.Uint64
	metricImportsFailed   atomic.Uint64
	metricFeedItemsStored atomic.Uint64
	metricApproved        atomic.Uint64
	metricRejected        atomic.Uint64
)

// MetricSnapshot is a point-in-time copy of the intel counters.
type MetricSnapshot struct {
	ImportsOK          uint64
	ImportsFailed      uint64
	FeedItemsStored    uint64
	CandidatesApproved uint64
	CandidatesRejected uint64
}

// RecordImport increments the URL-import outcome counter.
func RecordImport(ok bool) {
	if ok {
		metricImportsOK.Add(1)
		return
	}
	metricImportsFailed.Add(1)
}

// RecordFeedItemsStored increments the stored feed-item counter.
func RecordFeedItemsStored(count int) {
	if count > 0 {
		metricFeedItemsStored.Add(uint64(count))
	}
}

// RecordCandidateReview increments the human review outcome counter.
func RecordCandidateReview(approved bool) {
	if approved {
		metricApproved.Add(1)
		return
	}
	metricRejected.Add(1)
}

// ProcessMetrics returns the current counters.
func ProcessMetrics() MetricSnapshot {
	return MetricSnapshot{
		ImportsOK:          metricImportsOK.Load(),
		ImportsFailed:      metricImportsFailed.Load(),
		FeedItemsStored:    metricFeedItemsStored.Load(),
		CandidatesApproved: metricApproved.Load(),
		CandidatesRejected: metricRejected.Load(),
	}
}
