package engine

import (
	"strings"
	"sync"
)

// siteAdmission is a small, bounded per-site counter layered on top of a
// process-wide semaphore. The process-wide semaphore remains the hard safety
// bound; the per-site counter prevents one tenant from consuming all of it.
//
// A bounded registry is intentional. Site IDs normally come from validated
// configuration, but callers constructing RequestContexts directly must not be
// able to turn this fairness map into an unbounded allocation. Once the
// registry is full, the caller falls back to the global semaphore only.
type siteAdmission struct {
	mu        sync.Mutex
	maxActive int
	maxSites  int
	bySite    map[string]int
}

type siteAdmissionToken struct {
	owner *siteAdmission
	site  string
	held  bool
}

func (a *siteAdmission) init() {
	if a.bySite == nil {
		a.bySite = make(map[string]int)
	}
}

// acquire returns an empty token when the site is blank or the bounded
// registry is full. In either case admission is allowed and only the caller's
// global semaphore applies. A non-empty token means a site-local permit must
// be released exactly once.
func (a *siteAdmission) acquire(siteID string) (siteAdmissionToken, bool) {
	return a.acquireWithGlobalCapacity(siteID, false)
}

// acquireWithGlobalCapacity admits a site-local permit while optionally
// relaxing the configured per-site ceiling when this is the only active site
// and the caller still has process-wide capacity. This keeps the per-site
// limit as a fairness boundary when sites compete, without turning it into an
// arbitrary hard ceiling for a single site on an otherwise idle process.
//
// The caller must provide a snapshot of global capacity. It is intentionally
// advisory: the process-wide semaphore remains the authoritative bound and
// callers must still release their token if global admission subsequently
// fails.
func (a *siteAdmission) acquireWithGlobalCapacity(siteID string, globalCapacityAvailable bool) (siteAdmissionToken, bool) {
	siteID = strings.TrimSpace(siteID)
	if siteID == "" {
		return siteAdmissionToken{}, true
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.init()
	active, exists := a.bySite[siteID]
	if !exists && a.maxSites > 0 && len(a.bySite) >= a.maxSites {
		return siteAdmissionToken{}, true
	}
	if a.maxActive > 0 && active >= a.maxActive && (!globalCapacityAvailable || len(a.bySite) > 1) {
		return siteAdmissionToken{}, false
	}
	a.bySite[siteID] = active + 1
	return siteAdmissionToken{owner: a, site: siteID, held: true}, true
}

func (t siteAdmissionToken) release() {
	if !t.held || t.owner == nil || t.site == "" {
		return
	}
	a := t.owner
	a.mu.Lock()
	if active := a.bySite[t.site]; active <= 1 {
		delete(a.bySite, t.site)
	} else {
		a.bySite[t.site] = active - 1
	}
	a.mu.Unlock()
}
