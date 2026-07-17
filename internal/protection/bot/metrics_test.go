package bot

import (
	"testing"
	"time"
)

func TestChallengeMetricsAggregatesPeopleAttemptsAndTypeTrend(t *testing.T) {
	now := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	metrics := NewChallengeMetrics(32, func() time.Time { return now })
	metrics.Record(ChallengeMetricIssued, "site-a", "shape_slider", "198.51.100.10")
	metrics.Record(ChallengeMetricIssued, "site-a", "shape_slider", "198.51.100.10")
	metrics.Record(ChallengeMetricSuccess, "site-a", "shape_slider", "198.51.100.10")
	metrics.Record(ChallengeMetricIssued, "site-a", "text_click", "198.51.100.11")
	metrics.Record(ChallengeMetricFailure, "site-a", "text_click", "198.51.100.11")
	metrics.Record(ChallengeMetricCAPTCHABlocked, "site-a", "text_click", "198.51.100.11")
	metrics.Record(ChallengeMetricIssued, "site-b", "pow", "198.51.100.12")

	snapshot := metrics.Snapshot(ChallengeMetricQuery{Start: now.Add(-time.Hour), End: now.Add(time.Second), Site: "site-a", Bucket: time.Hour})
	if snapshot.Totals.ChallengedPeople != 2 || snapshot.Totals.Challenges != 3 {
		t.Fatalf("unexpected challenge totals: %+v", snapshot.Totals)
	}
	if snapshot.Totals.BlockedPeople != 1 || snapshot.Totals.Blocks != 1 || snapshot.Totals.CAPTCHABlocks != 1 {
		t.Fatalf("unexpected block totals: %+v", snapshot.Totals)
	}
	if snapshot.Totals.Successes != 1 || snapshot.Totals.Failures != 1 || snapshot.Totals.PassRate != 0.5 {
		t.Fatalf("unexpected verification totals: %+v", snapshot.Totals)
	}
	if len(snapshot.Trend) != 2 || snapshot.Trend[0].Type != "shape_slider" || snapshot.Trend[1].Type != "text_click" {
		t.Fatalf("unexpected trend: %+v", snapshot.Trend)
	}
}

func TestChallengeMetricsRingBufferAndTimeRange(t *testing.T) {
	now := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	metrics := NewChallengeMetrics(2, func() time.Time { return now })
	metrics.Record(ChallengeMetricIssued, "site-a", "pow", "one")
	now = now.Add(time.Minute)
	metrics.Record(ChallengeMetricIssued, "site-a", "pow", "two")
	now = now.Add(time.Minute)
	metrics.Record(ChallengeMetricSuccess, "site-a", "pow", "two")

	snapshot := metrics.Snapshot(ChallengeMetricQuery{Start: now.Add(-time.Hour), End: now.Add(time.Second), Bucket: time.Minute})
	if snapshot.Totals.Challenges != 1 || snapshot.Totals.Successes != 1 {
		t.Fatalf("ring buffer did not retain newest events: %+v", snapshot.Totals)
	}
}
