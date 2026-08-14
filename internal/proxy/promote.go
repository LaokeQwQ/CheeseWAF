package proxy

import (
	"context"
	"sync"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

type promoteTable struct {
	mu    sync.Mutex
	until map[string]time.Time
	store storage.Store
}

func newPromoteTable() *promoteTable {
	return &promoteTable{until: map[string]time.Time{}}
}

func (p *promoteTable) SetStore(store storage.Store) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.store = store
	if store == nil {
		return
	}
	loaded, err := store.ListSitePromotes(context.Background())
	if err != nil || len(loaded) == 0 {
		return
	}
	if p.until == nil {
		p.until = map[string]time.Time{}
	}
	for siteID, until := range loaded {
		p.until[siteID] = until
	}
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
	if p.store != nil {
		_ = p.store.UpsertSitePromote(context.Background(), siteID, deadline)
	}
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
		if p.store != nil {
			_ = p.store.DeleteSitePromote(context.Background(), siteID)
		}
		return false
	}
	return true
}
