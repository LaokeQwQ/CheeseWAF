// Package edr implements the bounded, metadata-only WAF event correlator used
// by the EDR sidecar. It never reads host processes, files, raw requests, or
// network data.
package edr

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	PluginID      = "edr-waf-correlation"
	PluginVersion = "1.0.1"

	maxTrackedKeys  = 4096
	maxEventsPerKey = 256
	suppressionTTL  = 15 * time.Minute
)

// Event is the subset of cheesewaf/waf-security-event/v1 used by the
// correlator. Unknown JSON fields are ignored by the sidecar decoder only
// after the host has already validated the event schema.
type Event struct {
	EventID       string    `json:"event_id"`
	EventType     string    `json:"event_type"`
	ObservedAt    time.Time `json:"observed_at"`
	TenantRef     string    `json:"tenant_ref"`
	SiteRef       string    `json:"site_ref"`
	RouteRef      string    `json:"route_ref"`
	SubjectHash   string    `json:"subject_hash"`
	Severity      string    `json:"severity"`
	Count         int       `json:"count"`
	WindowSeconds int       `json:"window_seconds"`
	EvidenceRefs  []string  `json:"evidence_refs"`
	Metadata      struct {
		RuleFamily      string `json:"rule_family"`
		MethodClass     string `json:"method_class"`
		StatusClass     string `json:"status_class"`
		ChallengeResult string `json:"challenge_result"`
		AuthFactor      string `json:"auth_factor"`
	} `json:"metadata"`
}

// Subject identifies the risk subject in a hint draft.
type Subject struct {
	SubjectType string `json:"subject_type"`
	SubjectHash string `json:"subject_hash"`
	SiteRef     string `json:"site_ref,omitempty"`
	RouteRef    string `json:"route_ref,omitempty"`
}

// Risk is the advisory scoring block in a hint draft.
type Risk struct {
	Score               int    `json:"score"`
	Confidence          int    `json:"confidence"`
	Band                string `json:"band"`
	ProposedDisposition string `json:"proposed_disposition"`
}

// Hint is a risk-hint draft without the host integrity envelope. The host
// validates and signs the final risk-hint/v1 object.
type Hint struct {
	APIVersion    string    `json:"api_version"`
	HintID        string    `json:"hint_id"`
	PluginID      string    `json:"plugin_id"`
	PluginVersion string    `json:"plugin_version"`
	Subject       Subject   `json:"subject"`
	Risk          Risk      `json:"risk"`
	PolicyEpoch   uint64    `json:"policy_epoch"`
	ObservedAt    time.Time `json:"observed_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	EvidenceRefs  []string  `json:"evidence_refs"`
}

type eventRecord struct {
	at     time.Time
	route  string
	kind   string
	family string
}

// keyState keeps one bounded event window per subject key. Route fan-out is
// derived from that window (see countDistinctRoutes) instead of a separate
// route map: an unbounded map keyed by attacker-controlled route_ref let a
// scanner with many distinct paths grow the correlator without limit while
// pruneLocked walked it on every event.
type keyState struct {
	events     []eventRecord
	lastHintAt time.Time
}

// Engine is a bounded in-memory correlator. It deliberately has no
// persistence and no external I/O.
type Engine struct {
	mu        sync.Mutex
	states    map[string]*keyState
	maxKeys   int
	maxPerKey int
	now       func() time.Time
}

// NewEngine creates a correlator with bounded state.
func NewEngine() *Engine {
	return &Engine{
		states:    make(map[string]*keyState),
		maxKeys:   maxTrackedKeys,
		maxPerKey: maxEventsPerKey,
		now:       func() time.Time { return time.Now().UTC() },
	}
}

// Observe processes one event and returns zero or more advisory hints.
func (e *Engine) Observe(event Event, policyEpoch uint64) []Hint {
	if e == nil || strings.TrimSpace(event.EventID) == "" || strings.TrimSpace(event.EventType) == "" {
		return nil
	}
	now := event.ObservedAt.UTC()
	if now.IsZero() {
		now = e.now()
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.pruneLocked(now)

	key := event.TenantRef + "\x00" + event.SiteRef + "\x00" + event.SubjectHash
	state := e.states[key]
	if state == nil {
		if len(e.states) >= e.maxKeys {
			return nil
		}
		state = &keyState{events: make([]eventRecord, 0, 16)}
		e.states[key] = state
	}
	state.events = append(state.events, eventRecord{at: now, route: event.RouteRef, kind: event.EventType, family: event.Metadata.RuleFamily})
	if len(state.events) > e.maxPerKey {
		state.events = state.events[len(state.events)-e.maxPerKey:]
	}
	if !state.lastHintAt.IsZero() && now.Sub(state.lastHintAt) < suppressionTTL {
		return nil
	}

	hint := e.evaluateLocked(key, state, event, now, policyEpoch)
	if hint == nil {
		return nil
	}
	state.lastHintAt = now
	return []Hint{*hint}
}

func (e *Engine) evaluateLocked(key string, state *keyState, event Event, now time.Time, policyEpoch uint64) *Hint {
	var (
		ruleID      string
		score       int
		confidence  int
		band        string
		disposition string
		window      time.Duration
	)
	switch {
	case countEvents(state.events, now, 60*time.Second, "auth_failure") >= 10:
		ruleID, score, confidence, band, disposition, window = "auth-burst", 60, 70, "medium", "review", 60*time.Second
	case countEvents(state.events, now, 5*time.Minute, "challenge_failed") >= 5 &&
		countEvents(state.events, now, 5*time.Minute, "waf_rule_hit") >= 1:
		ruleID, score, confidence, band, disposition, window = "challenge-bypass", 75, 65, "high", "review", 5*time.Minute
	case countEvents(state.events, now, 2*time.Minute, "rate_limit_exceeded") >= 1 &&
		countEvents(state.events, now, 2*time.Minute, "origin_error") >= 1:
		ruleID, score, confidence, band, disposition, window = "rate-limit-origin", 50, 55, "medium", "observe", 2*time.Minute
	case countDistinctRoutes(state.events, now, 5*time.Minute) >= 20:
		ruleID, score, confidence, band, disposition, window = "multi-route-probe", 55, 60, "medium", "review", 5*time.Minute
	default:
		return nil
	}
	evidence := event.EvidenceRefs
	if len(evidence) > 8 {
		evidence = evidence[:8]
	}
	if len(evidence) == 0 {
		evidence = []string{"evidence:" + event.EventID}
	}
	hintID := stableHintID(key, ruleID, now)
	return &Hint{
		APIVersion:    "cheesewaf/risk-hint/v1",
		HintID:        hintID,
		PluginID:      PluginID,
		PluginVersion: PluginVersion,
		Subject:       Subject{SubjectType: "ip", SubjectHash: event.SubjectHash, SiteRef: event.SiteRef, RouteRef: event.RouteRef},
		Risk:          Risk{Score: score, Confidence: confidence, Band: band, ProposedDisposition: disposition},
		PolicyEpoch:   policyEpoch,
		ObservedAt:    now,
		ExpiresAt:     now.Add(window + 5*time.Minute),
		EvidenceRefs:  append([]string(nil), evidence...),
	}
}

func (e *Engine) pruneLocked(now time.Time) {
	cutoff := now.Add(-30 * time.Minute)
	for key, state := range e.states {
		if len(state.events) > 0 && state.events[len(state.events)-1].at.Before(cutoff) {
			delete(e.states, key)
		}
	}
}

func countEvents(events []eventRecord, now time.Time, window time.Duration, kind string) int {
	cutoff := now.Add(-window)
	total := 0
	for _, event := range events {
		if event.kind == kind && !event.at.Before(cutoff) {
			total++
		}
	}
	return total
}

// countDistinctRoutes counts the routes seen inside the window. It reads the
// bounded per-key event window, so route tracking inherits maxEventsPerKey and
// cannot grow beyond it; the 5 minute fan-out window is unchanged. The only
// behaviour change is that a route whose last event has already been evicted by
// the per-key event cap no longer counts - that is the point of the cap, and a
// 20-route fan-out still trips long before 256 events.
func countDistinctRoutes(events []eventRecord, now time.Time, window time.Duration) int {
	cutoff := now.Add(-window)
	seen := make(map[string]struct{}, len(events))
	for _, event := range events {
		if event.route == "" || event.at.Before(cutoff) {
			continue
		}
		seen[event.route] = struct{}{}
	}
	return len(seen)
}

func stableHintID(key, rule string, now time.Time) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%d", key, rule, now.UnixNano())))
	return "hint-" + hex.EncodeToString(sum[:16])
}

// RuleSummary returns the stable rule IDs in lexical order. It is used by
// tests and the sidecar --describe output.
func RuleSummary() []string {
	rules := []string{"auth-burst", "challenge-bypass", "multi-route-probe", "rate-limit-origin"}
	sort.Strings(rules)
	return rules
}
