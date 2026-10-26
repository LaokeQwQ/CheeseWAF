package edr

import (
	"reflect"
	"strconv"
	"testing"
	"time"
)

func testEvent(at time.Time, kind, subject string) Event {
	return Event{
		EventID:       kind + "-" + subject + "-" + at.Format(time.RFC3339Nano),
		EventType:     kind,
		ObservedAt:    at,
		TenantRef:     "tenant-1",
		SiteRef:       "site-1",
		RouteRef:      "/api/login",
		SubjectHash:   subject,
		Severity:      "medium",
		Count:         1,
		WindowSeconds: 60,
		EvidenceRefs:  []string{"evidence:" + kind},
	}
}

func TestAuthBurstEmitsAndSuppresses(t *testing.T) {
	engine := NewEngine()
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	var hints []Hint
	for i := range 10 {
		hints = append(hints, engine.Observe(testEvent(now.Add(time.Duration(i)*time.Second), "auth_failure", "subject-1"), 7)...)
	}
	if len(hints) != 1 {
		t.Fatalf("hints = %d, want 1", len(hints))
	}
	if hints[0].Risk.Band != "medium" || hints[0].PolicyEpoch != 7 {
		t.Fatalf("hint = %#v", hints[0])
	}
	if got := engine.Observe(testEvent(now.Add(11*time.Second), "auth_failure", "subject-1"), 7); len(got) != 0 {
		t.Fatalf("suppressed hint returned %#v", got)
	}
}

func TestChallengeBypass(t *testing.T) {
	engine := NewEngine()
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	for i := range 5 {
		engine.Observe(testEvent(now.Add(time.Duration(i)*time.Second), "challenge_failed", "subject-2"), 1)
	}
	hints := engine.Observe(testEvent(now.Add(6*time.Second), "waf_rule_hit", "subject-2"), 1)
	if len(hints) != 1 || hints[0].Risk.Band != "high" {
		t.Fatalf("hints = %#v", hints)
	}
}

func TestMultiRouteProbe(t *testing.T) {
	engine := NewEngine()
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	var hints []Hint
	for i := range 20 {
		event := testEvent(now.Add(time.Duration(i)*time.Second), "waf_rule_hit", "subject-3")
		event.RouteRef = "/route-" + string(rune('a'+i))
		hints = append(hints, engine.Observe(event, 1)...)
	}
	if len(hints) != 1 {
		t.Fatalf("hints = %#v", hints)
	}
}

// Finding 6: per-key route bookkeeping has to stay bounded by the same limit as
// the event window. Attacker-controlled route_ref values must not grow state
// without limit, while the fan-out rule keeps working on the bounded window.
func TestRouteBookkeepingStaysBounded(t *testing.T) {
	const sent = 1000
	engine := NewEngine()
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	var hints []Hint
	for i := range sent {
		event := testEvent(now.Add(time.Duration(i)*time.Millisecond), "waf_rule_hit", "subject-many-routes")
		event.RouteRef = "/route-" + strconv.Itoa(i)
		hints = append(hints, engine.Observe(event, 1)...)
	}
	if len(hints) == 0 {
		t.Fatal("route fan-out rule never fired for 1000 distinct routes")
	}
	if hints[0].Risk.Score != 55 || hints[0].Risk.ProposedDisposition != "review" {
		t.Fatalf("first hint risk = %#v, want the multi-route-probe scoring", hints[0].Risk)
	}

	key := "tenant-1\x00site-1\x00subject-many-routes"
	engine.mu.Lock()
	state := engine.states[key]
	tracked := len(engine.states)
	retained := 0
	if state != nil {
		retained = stateEntries(state)
	}
	engine.mu.Unlock()
	if state == nil {
		t.Fatal("subject key was not tracked")
	}
	if tracked != 1 {
		t.Fatalf("tracked keys = %d, want 1", tracked)
	}
	if retained > maxEventsPerKey {
		t.Fatalf("key state retains %d entries after %d distinct routes, cap is %d", retained, sent, maxEventsPerKey)
	}
}

// The 5 minute fan-out window must survive the move to a derived count: routes
// whose events fell out of the window must not keep firing the rule.
func TestMultiRouteProbeIgnoresRoutesOutsideWindow(t *testing.T) {
	engine := NewEngine()
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	for i := range 19 {
		event := testEvent(now.Add(time.Duration(i)*time.Second), "waf_rule_hit", "subject-4")
		event.RouteRef = "/stale-" + strconv.Itoa(i)
		if hints := engine.Observe(event, 1); len(hints) != 0 {
			t.Fatalf("hint before threshold: %#v", hints)
		}
	}
	late := testEvent(now.Add(6*time.Minute), "waf_rule_hit", "subject-4")
	late.RouteRef = "/fresh"
	if hints := engine.Observe(late, 1); len(hints) != 0 {
		t.Fatalf("stale routes still counted after the window: %#v", hints)
	}
}

// stateEntries sums the entries a key state retains across its map and slice
// fields. It reflects over the struct so the measurement works against the
// previous implementation too, where route state lived in a separate map.
func stateEntries(state *keyState) int {
	value := reflect.ValueOf(state).Elem()
	total := 0
	for i := range value.NumField() {
		switch value.Field(i).Kind() {
		case reflect.Map, reflect.Slice:
			total += value.Field(i).Len()
		}
	}
	return total
}
