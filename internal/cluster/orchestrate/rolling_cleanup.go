package orchestrate

import "time"

// pruneExpiredJobsLocked removes jobs older than rollingJobTTL.
// Must be called with m.mu held.
func (m *RollingManager) pruneExpiredJobsLocked() {
	if m == nil || m.jobs == nil {
		return
	}
	cutoff := m.now().Add(-rollingJobTTL)
	for id, job := range m.jobs {
		if job.CreatedAt.Before(cutoff) {
			clearRollingTargetCredentialsLocked(job)
			delete(m.jobs, id)
		}
	}
}

// pruneOldestJobsLocked removes oldest jobs until count drops to maxRollingJobs/2.
// Must be called with m.mu held.
func (m *RollingManager) pruneOldestJobsLocked() {
	if m == nil || m.jobs == nil || len(m.jobs) < maxRollingJobs {
		return
	}
	type entry struct {
		id      string
		created time.Time
	}
	entries := make([]entry, 0, len(m.jobs))
	for id, job := range m.jobs {
		if job == nil || job.Status == RollingStatusPending || job.Status == RollingStatusRunning {
			continue
		}
		entries = append(entries, entry{id: id, created: job.CreatedAt})
	}
	// Sort by created time ascending (oldest first)
	for i := 0; i < len(entries)-1; i++ {
		for j := i + 1; j < len(entries); j++ {
			if entries[j].created.Before(entries[i].created) {
				entries[i], entries[j] = entries[j], entries[i]
			}
		}
	}
	target := maxRollingJobs / 2
	toRemove := len(m.jobs) - target
	if toRemove <= 0 {
		return
	}
	for i := 0; i < toRemove && i < len(entries); i++ {
		clearRollingTargetCredentialsLocked(m.jobs[entries[i].id])
		delete(m.jobs, entries[i].id)
	}
}
