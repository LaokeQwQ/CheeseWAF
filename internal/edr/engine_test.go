package edr

import (
	"fmt"
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

func TestDistinctRouteStateRemainsBounded(t *testing.T) {
	engine := NewEngine()
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	for i := range 4096 {
		event := testEvent(now, "waf_rule_hit", "subject-4")
		event.RouteRef = fmt.Sprintf("/route-%d", i)
		engine.Observe(event, 1)
	}
	state := engine.states["tenant-1\x00site-1\x00subject-4"]
	if len(state.events) != maxEventsPerKey || len(state.routes) != maxEventsPerKey {
		t.Fatalf("state retains %d events and %d routes, want %d each", len(state.events), len(state.routes), maxEventsPerKey)
	}
}

func TestMultiRouteProbeRetainsInfrequentRoutes(t *testing.T) {
	engine := NewEngine()
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	event := testEvent(now, "waf_rule_hit", "subject-5")
	event.RouteRef = "/first"
	engine.Observe(event, 1)
	event.RouteRef = "/repeated"
	for range 1000 {
		if hints := engine.Observe(event, 1); len(hints) != 0 {
			t.Fatalf("probe reported before 20 distinct routes: %#v", hints)
		}
	}
	for i := range 18 {
		event.RouteRef = fmt.Sprintf("/route-%d", i)
		hints := engine.Observe(event, 1)
		if want := i == 17; (len(hints) == 1) != want {
			t.Fatalf("route %d returned %d hints, want hint: %t", i, len(hints), want)
		}
	}
}
