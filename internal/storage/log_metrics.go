package storage

import "sync/atomic"

var processLogWriteFailures atomic.Uint64

// RecordLogWriteFailure records an access-log event that the configured sink
// could not persist. The metric is exported through the monitoring endpoint.
func RecordLogWriteFailure() {
	processLogWriteFailures.Add(1)
}

// ProcessLogWriteFailures returns the total number of failed sink writes for
// this process lifetime.
func ProcessLogWriteFailures() uint64 {
	return processLogWriteFailures.Load()
}

// ResetLogWriteFailuresForTest clears the process counter for isolated tests.
func ResetLogWriteFailuresForTest() {
	processLogWriteFailures.Store(0)
}
