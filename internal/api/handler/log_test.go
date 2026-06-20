package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

func TestListLogsEnrichesMissingGeoFromPrecisionDatabase(t *testing.T) {
	precisionDB := filepath.Join(t.TempDir(), "precision.json")
	if err := os.WriteFile(precisionDB, []byte(`{
  "records": [{
    "cidr": "8.8.8.0/24",
    "country_code": "CN",
    "country_name": "China",
    "continent": "AS",
    "region": "Zhejiang",
    "region_code": "ZJ",
    "city": "Hangzhou",
    "lat": 30.259,
    "lon": 120.13,
    "accuracy_radius": 3,
    "source": "test-precision"
  }]
}`), 0o600); err != nil {
		t.Fatalf("write precision database: %v", err)
	}
	cfg := config.Default()
	cfg.Protection.IP.GeoIP.PrecisionDatabase = precisionDB
	sink := &listLogsSink{items: []storage.LogEntry{{
		ID:        "log-geo",
		TraceID:   "trace-geo",
		Timestamp: time.Date(2026, 6, 19, 10, 0, 0, 0, time.UTC),
		ClientIP:  "8.8.8.8",
		Action:    "block",
		Category:  "sqli",
		Country:   "",
	}}}
	handler := New(Options{Config: &cfg, Sink: sink})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/logs?limit=10", nil)
	handler.ListLogs(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected logs ok, code=%d body=%s", recorder.Code, recorder.Body.String())
	}

	var response struct {
		Data struct {
			Items []storage.LogEntry `json:"items"`
			Total int64              `json:"total"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(response.Data.Items) != 1 {
		t.Fatalf("expected one log entry, got %+v", response.Data.Items)
	}
	entry := response.Data.Items[0]
	if entry.Country != "CN" {
		t.Fatalf("expected enriched country CN, got %+v", entry)
	}
	geo, ok := entry.Metadata["geo"].(map[string]any)
	if !ok {
		t.Fatalf("expected geo metadata, got %#v", entry.Metadata)
	}
	for key, want := range map[string]any{
		"country_code": "CN",
		"country_name": "China",
		"region":       "Zhejiang",
		"city":         "Hangzhou",
		"source":       "test-precision",
	} {
		if got := geo[key]; got != want {
			t.Fatalf("geo[%s] = %#v, want %#v; geo=%#v", key, got, want, geo)
		}
	}
}

func TestListLogsKeepsServiceAvailableWhenGeoIPConfigIsInvalid(t *testing.T) {
	cfg := config.Default()
	cfg.Protection.IP.GeoIP.CountryCIDRs = map[string][]string{"CN": {"not-a-cidr"}}
	sink := &listLogsSink{items: []storage.LogEntry{{
		ID:        "log-invalid-geo",
		Timestamp: time.Date(2026, 6, 19, 10, 0, 0, 0, time.UTC),
		ClientIP:  "8.8.4.4",
		Action:    "block",
		Category:  "xss",
	}}}
	handler := New(Options{Config: &cfg, Sink: sink})

	for attempt := 1; attempt <= 2; attempt++ {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/api/logs?limit=10", nil)
		handler.ListLogs(recorder, request)
		if recorder.Code != http.StatusOK {
			t.Fatalf("invalid GeoIP config must not break logs on attempt %d, code=%d body=%s", attempt, recorder.Code, recorder.Body.String())
		}
	}
}

func TestListLogsDoesNotInventGeoForPrivateIP(t *testing.T) {
	cfg := config.Default()
	cfg.Protection.IP.GeoIP.CountryCIDRs = map[string][]string{"CN": {"0.0.0.0/0"}}
	sink := &listLogsSink{items: []storage.LogEntry{{
		ID:        "log-private",
		Timestamp: time.Date(2026, 6, 19, 10, 0, 0, 0, time.UTC),
		ClientIP:  "10.0.0.8",
		Action:    "block",
		Category:  "bot",
	}}}
	handler := New(Options{Config: &cfg, Sink: sink})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/logs?limit=10", nil)
	handler.ListLogs(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected logs ok, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), `"country":"CN"`) {
		t.Fatalf("private IP should not be enriched with public geo data: %s", recorder.Body.String())
	}
}

func TestListLogsDoesNotInventGeoForDocumentationIP(t *testing.T) {
	cfg := config.Default()
	cfg.Protection.IP.GeoIP.CountryCIDRs = map[string][]string{"CN": {"0.0.0.0/0"}}
	sink := &listLogsSink{items: []storage.LogEntry{{
		ID:        "log-documentation-ip",
		Timestamp: time.Date(2026, 6, 19, 10, 0, 0, 0, time.UTC),
		ClientIP:  "203.0.113.8",
		Action:    "block",
		Category:  "bot",
	}}}
	handler := New(Options{Config: &cfg, Sink: sink})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/logs?limit=10", nil)
	handler.ListLogs(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected logs ok, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), `"country":"CN"`) {
		t.Fatalf("documentation IP should not be enriched with public geo data: %s", recorder.Body.String())
	}
}

type listLogsSink struct {
	items []storage.LogEntry
}

func (s *listLogsSink) Write(context.Context, *storage.LogEntry) error {
	return nil
}

func (s *listLogsSink) Query(_ context.Context, filter storage.LogFilter) ([]storage.LogEntry, int64, error) {
	out := append([]storage.LogEntry(nil), s.items...)
	if filter.Limit > 0 && len(out) > filter.Limit {
		out = out[:filter.Limit]
	}
	return out, int64(len(out)), nil
}

func (s *listLogsSink) Flush(context.Context) error {
	return nil
}

func (s *listLogsSink) Close() error {
	return nil
}
