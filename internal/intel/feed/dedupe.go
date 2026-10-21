package feed

import (
	"encoding/hex"
	"fmt"
	"sync"
)

// Dedupe tracks accepted identifiers and content hashes per source and
// rejects duplicate or replayed items. It is safe for concurrent use.
type Dedupe struct {
	mu      sync.Mutex
	sources map[string]*dedupeState
}

const maxDedupeEntries = 4096

type dedupeState struct {
	started      bool
	lastSequence uint64
	ids          map[string]struct{}
	hashes       map[string]struct{}
	order        []dedupeEntry
}

type dedupeEntry struct {
	id   string
	hash string
}

// Rejection records an item rejected by Filter.
type Rejection struct {
	Item FeedItem
	Err  error
}

// NewDedupe returns an empty deduplication state.
func NewDedupe() *Dedupe {
	return &Dedupe{sources: make(map[string]*dedupeState)}
}

// Accept records one normalized item at the given source sequence. The
// sequence must not move backwards for a source; equal sequences are allowed
// so one fetch can share the sequence across its items. A repeated external ID
// or content hash is rejected. Accept recomputes the canonical hash and
// rejects a caller-supplied hash that does not match the item content.
func (d *Dedupe) Accept(sourceID string, sequence uint64, item FeedItem) error {
	normalized, err := prepareForDedupe(sourceID, item)
	if err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.acceptLocked(normalized, sequence)
}

// Filter accepts every eligible item and returns the accepted normalized items
// together with the rejections. Items are evaluated in order and accepted
// state is committed as it goes.
func (d *Dedupe) Filter(sourceID string, sequence uint64, items []FeedItem) ([]FeedItem, []Rejection) {
	accepted := make([]FeedItem, 0, len(items))
	rejected := make([]Rejection, 0)
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, item := range items {
		normalized, err := prepareForDedupe(sourceID, item)
		if err == nil {
			err = d.acceptLocked(normalized, sequence)
		}
		if err != nil {
			rejected = append(rejected, Rejection{Item: item, Err: err})
			continue
		}
		accepted = append(accepted, normalized)
	}
	return accepted, rejected
}

// Reset forgets everything recorded for a source. It is intended for an
// explicit operator reset, not routine ingestion.
func (d *Dedupe) Reset(sourceID string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.sources, sourceID)
}

func prepareForDedupe(sourceID string, item FeedItem) (FeedItem, error) {
	if sourceID == "" {
		return FeedItem{}, fmt.Errorf("%w: source id is required", ErrInvalid)
	}
	if item.SourceID != "" && item.SourceID != sourceID {
		return FeedItem{}, fmt.Errorf("%w: item source id %q does not match %q", ErrInvalid, item.SourceID, sourceID)
	}
	normalized, err := Normalize(item)
	if err != nil {
		return FeedItem{}, err
	}
	if item.ContentHash != "" {
		if len(item.ContentHash) != 64 {
			return FeedItem{}, fmt.Errorf("%w: content hash must be sha256 hex", ErrInvalid)
		}
		if _, err := hex.DecodeString(item.ContentHash); err != nil {
			return FeedItem{}, fmt.Errorf("%w: content hash must be sha256 hex", ErrInvalid)
		}
		if item.ContentHash != normalized.ContentHash {
			return FeedItem{}, fmt.Errorf("%w: content hash does not match item content", ErrInvalid)
		}
	}
	normalized.SourceID = sourceID
	return normalized, nil
}

func (d *Dedupe) acceptLocked(item FeedItem, sequence uint64) error {
	if d.sources == nil {
		d.sources = make(map[string]*dedupeState)
	}
	state := d.sources[item.SourceID]
	if state == nil {
		state = &dedupeState{
			ids:    make(map[string]struct{}),
			hashes: make(map[string]struct{}),
		}
		d.sources[item.SourceID] = state
	}
	if state.started && sequence < state.lastSequence {
		return fmt.Errorf("%w: source %q sequence %d is behind %d", ErrReplay, item.SourceID, sequence, state.lastSequence)
	}
	if _, exists := state.ids[item.ExternalID]; exists {
		return fmt.Errorf("%w: source %q external id %q", ErrDuplicate, item.SourceID, item.ExternalID)
	}
	if _, exists := state.hashes[item.ContentHash]; exists {
		return fmt.Errorf("%w: source %q content hash %s", ErrDuplicate, item.SourceID, item.ContentHash)
	}
	state.ids[item.ExternalID] = struct{}{}
	state.hashes[item.ContentHash] = struct{}{}
	state.order = append(state.order, dedupeEntry{id: item.ExternalID, hash: item.ContentHash})
	if len(state.order) > maxDedupeEntries {
		oldest := state.order[0]
		state.order = state.order[1:]
		delete(state.ids, oldest.id)
		delete(state.hashes, oldest.hash)
	}
	state.lastSequence = sequence
	state.started = true
	return nil
}
