package handler

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	protectionbot "github.com/LaokeQwQ/CheeseWAF/internal/protection/bot"
)

func TestBotMetricsWindow(t *testing.T) {
	cases := map[string]struct {
		window, bucket time.Duration
		ok             bool
	}{
		"": {24 * time.Hour, time.Hour, true}, "1h": {time.Hour, 5 * time.Minute, true}, "6h": {6 * time.Hour, 30 * time.Minute, true}, "7d": {7 * 24 * time.Hour, 6 * time.Hour, true}, "30d": {30 * 24 * time.Hour, 24 * time.Hour, true}, "bad": {0, 0, false},
	}
	for raw, want := range cases {
		_, window, bucket, ok := botMetricsWindow(raw)
		if ok != want.ok || window != want.window || bucket != want.bucket {
			t.Fatalf("%q: got %v %v %v", raw, window, bucket, ok)
		}
	}
}

func TestBotChallengeMetricsResponse(t *testing.T) {
	now := time.Now().UTC()
	protectionbot.ProcessChallengeMetrics().Record(protectionbot.ChallengeMetricIssued, "metrics-test-site", "pow", "203.0.113.250")
	protectionbot.ProcessChallengeMetrics().Record(protectionbot.ChallengeMetricSuccess, "metrics-test-site", "pow", "203.0.113.250")
	h := &Handler{now: func() time.Time { return now.Add(time.Second) }}
	req := httptest.NewRequest("GET", "/api/protection/bot/metrics?range=1h&site_id=metrics-test-site", nil)
	rec := httptest.NewRecorder()
	h.BotChallengeMetrics(rec, req)
	if rec.Code != 200 {
		t.Fatalf("unexpected status %d: %s", rec.Code, rec.Body.String())
	}
	var envelope struct {
		Data botMetricsResponse `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Data.Totals.Challenges != 1 || envelope.Data.Totals.Successes != 1 || envelope.Data.Totals.PassRate != 1 {
		t.Fatalf("unexpected totals: %+v", envelope.Data.Totals)
	}
	if len(envelope.Data.Trend) != 1 || envelope.Data.Trend[0].Type != "pow" {
		t.Fatalf("unexpected trend: %+v", envelope.Data.Trend)
	}
}
