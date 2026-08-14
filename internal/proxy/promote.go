package proxy

import (
	"sync"
	"time"
)

type promoteTable struct {
	mu    sync.Mutex
	until map[string]time.Time
}

func newPromoteTable() *promoteTable {
	return &promoteTable{until: map[string]time.Time{}}
}

func (p *promoteTable) Arm(siteID string, seconds int, now time.Time) {
	if p == nil || siteID == "" || seconds <= 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	deadline := now.Add(time.Duration(seconds) * time.Second)
	if prev, ok := p.until[siteID]; ok && prev.After(deadline) {
		return
	}
	p.until[siteID] = deadline
}

func (p *promoteTable) Active(siteID string, now time.Time) bool {
	if p == nil || siteID == "" {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	deadline, ok := p.until[siteID]
	if !ok {
		return false
	}
	if !deadline.After(now) {
		delete(p.until, siteID)
		return false
	}
	return true
}
