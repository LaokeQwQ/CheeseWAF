package ai

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

func TestSelfLearningDryRunDoesNotCreateRules(t *testing.T) {
	now := time.Date(2026, 6, 18, 3, 30, 0, 0, time.UTC)
	sink := &selfLearningSink{items: repeatedSelfLearningEvents(now, 6)}
	rules := &selfLearningRuleStore{}

	report, err := RunSelfLearning(context.Background(), SelfLearningOptions{
		Config: config.AISelfLearningConfig{
			AutoApply:      false,
			DryRun:         true,
			Interval:       24 * time.Hour,
			MinConfidence:  0.95,
			MinEvents:      5,
			MaxEvents:      100,
			MaxRulesPerRun: 3,
			Action:         "block",
		},
		Sink:  sink,
		Rules: rules,
		Now:   func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("run self learning: %v", err)
	}
	if !report.DryRun || len(report.Candidates) != 1 {
		t.Fatalf("expected one dry-run candidate, got %+v", report)
	}
	if len(report.Applied) != 0 || len(rules.created) != 0 {
		t.Fatalf("dry run must not create rules, report=%+v created=%+v", report.Applied, rules.created)
	}
}

func TestSelfLearningAutoApplyCreatesOnlySafeHighConfidenceRules(t *testing.T) {
	now := time.Date(2026, 6, 18, 3, 30, 0, 0, time.UTC)
	sink := &selfLearningSink{items: repeatedSelfLearningEvents(now, 6)}
	rules := &selfLearningRuleStore{}

	report, err := RunSelfLearning(context.Background(), SelfLearningOptions{
		Config: config.AISelfLearningConfig{
			AutoApply:      true,
			DryRun:         false,
			Interval:       24 * time.Hour,
			MinConfidence:  0.95,
			MinEvents:      5,
			MaxEvents:      100,
			MaxRulesPerRun: 3,
			Action:         "block",
		},
		Sink:  sink,
		Rules: rules,
		Now:   func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("run self learning: %v", err)
	}
	if report.DryRun || len(report.Applied) != 1 || len(rules.created) != 1 {
		t.Fatalf("expected one applied rule, report=%+v created=%+v", report, rules.created)
	}
	rule := rules.created[0]
	if rule.Pattern != "union select" && rule.Pattern != "union\\ select" {
		t.Fatalf("expected escaped union select pattern, got %+v", rule)
	}
	if rule.Action != "block" || !rule.Enabled || rule.Priority != 180 {
		t.Fatalf("unexpected applied rule: %+v", rule)
	}
}

func TestSelfLearningCanWriteRulesBlockedForcesDryRun(t *testing.T) {
	now := time.Date(2026, 6, 18, 3, 30, 0, 0, time.UTC)
	sink := &selfLearningSink{items: repeatedSelfLearningEvents(now, 6)}
	rules := &selfLearningRuleStore{}

	report, err := RunSelfLearning(context.Background(), SelfLearningOptions{
		Config: config.AISelfLearningConfig{
			AutoApply:      true,
			DryRun:         false,
			Interval:       24 * time.Hour,
			MinConfidence:  0.95,
			MinEvents:      5,
			MaxEvents:      100,
			MaxRulesPerRun: 3,
			Action:         "block",
		},
		Sink:  sink,
		Rules: rules,
		Now:   func() time.Time { return now },
		CanWriteRules: func() error {
			return errors.New("configuration writes are frozen: test freeze")
		},
	})
	if err != nil {
		t.Fatalf("run self learning: %v", err)
	}
	if !report.DryRun || report.AutoApply {
		t.Fatalf("expected forced dry-run when CanWriteRules fails, report=%+v", report)
	}
	if len(report.Applied) != 0 || len(rules.created) != 0 {
		t.Fatalf("freeze must not create rules, applied=%+v created=%+v", report.Applied, rules.created)
	}
	if len(report.Candidates) == 0 {
		t.Fatal("expected candidates even when writes are blocked")
	}
	if len(report.Skipped) == 0 {
		t.Fatal("expected skipped entries explaining write block")
	}
	for _, skip := range report.Skipped {
		if !strings.Contains(skip.Reason, "rule writes blocked") || !strings.Contains(skip.Reason, "frozen") {
			t.Fatalf("unexpected skip reason: %q", skip.Reason)
		}
	}
}

func repeatedSelfLearningEvents(now time.Time, count int) []storage.LogEntry {
	out := make([]storage.LogEntry, 0, count)
	for i := 0; i < count; i++ {
		out = append(out, storage.LogEntry{
			ID:        "event",
			TraceID:   "trace",
			SiteID:    "site-a",
			Timestamp: now.Add(-time.Duration(i+1) * time.Hour),
			Action:    "block",
			Category:  "sqli",
			URI:       "/search?q=1%20union%20select%20password",
			Payload:   "1 union select password from users",
		})
	}
	return out
}

type selfLearningSink struct {
	items  []storage.LogEntry
	filter storage.LogFilter
}

func (s *selfLearningSink) Write(context.Context, *storage.LogEntry) error { return nil }

func (s *selfLearningSink) Query(_ context.Context, filter storage.LogFilter) ([]storage.LogEntry, int64, error) {
	s.filter = filter
	out := make([]storage.LogEntry, 0, len(s.items))
	for _, item := range s.items {
		if !filter.StartTime.IsZero() && item.Timestamp.Before(filter.StartTime) {
			continue
		}
		if !filter.EndTime.IsZero() && item.Timestamp.After(filter.EndTime) {
			continue
		}
		out = append(out, item)
	}
	if filter.Limit > 0 && len(out) > filter.Limit {
		out = out[:filter.Limit]
	}
	return out, int64(len(out)), nil
}

func (s *selfLearningSink) Flush(context.Context) error { return nil }
func (s *selfLearningSink) Close() error                { return nil }

type selfLearningRuleStore struct {
	rules   []storage.Rule
	created []storage.Rule
}

func (s *selfLearningRuleStore) ListRules(context.Context, string) ([]storage.Rule, error) {
	return append([]storage.Rule(nil), s.rules...), nil
}

func (s *selfLearningRuleStore) GetRule(context.Context, string) (*storage.Rule, error) {
	return nil, nil
}

func (s *selfLearningRuleStore) CreateRule(_ context.Context, rule *storage.Rule) error {
	s.created = append(s.created, *rule)
	s.rules = append(s.rules, *rule)
	return nil
}

func (s *selfLearningRuleStore) UpdateRule(context.Context, *storage.Rule) error { return nil }
func (s *selfLearningRuleStore) DeleteRule(context.Context, string) error        { return nil }
