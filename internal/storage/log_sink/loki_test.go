package log_sink

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

type lokiRequest struct {
	path   string
	query  url.Values
	header http.Header
	body   []byte
}

type lokiRecorder struct {
	mu       sync.Mutex
	requests []lokiRequest
	handler  func(r lokiRequest) (int, string)
}

func newLokiRecorder(handler func(r lokiRequest) (int, string)) *lokiRecorder {
	return &lokiRecorder{handler: handler}
}

func (rec *lokiRecorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	request := lokiRequest{
		path:   r.URL.Path,
		query:  r.URL.Query(),
		header: r.Header.Clone(),
		body:   body,
	}
	rec.mu.Lock()
	rec.requests = append(rec.requests, request)
	rec.mu.Unlock()
	status, response := 204, ""
	if rec.handler != nil {
		status, response = rec.handler(request)
	}
	w.WriteHeader(status)
	if response != "" {
		_, _ = io.WriteString(w, response)
	}
}

func (rec *lokiRecorder) snapshot() []lokiRequest {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	return append([]lokiRequest(nil), rec.requests...)
}

func newLokiTestSink(t *testing.T, server *httptest.Server, cfg config.LokiConfig) *LokiSink {
	t.Helper()
	if cfg.Endpoint == "" {
		cfg.Endpoint = server.URL
	}
	sink, err := NewLokiSink(cfg, server.Client())
	if err != nil {
		t.Fatalf("new loki sink: %v", err)
	}
	t.Cleanup(func() { _ = sink.Close() })
	return sink
}

func lokiLine(t *testing.T, entry storage.LogEntry) string {
	t.Helper()
	data, err := json.Marshal(&entry)
	if err != nil {
		t.Fatalf("marshal loki line: %v", err)
	}
	return string(data)
}

func TestLokiWritePushesGroupedStreamsWithJSONLines(t *testing.T) {
	recorder := newLokiRecorder(nil)
	server := httptest.NewServer(recorder)
	defer server.Close()

	sink := newLokiTestSink(t, server, config.LokiConfig{
		TenantID: "tenant-a",
		Username: "loki-user",
		Password: "loki-pass",
		Labels:   map[string]string{"env": "staging"},
	})

	when := time.Date(2026, 5, 28, 8, 0, 0, 0, time.UTC)
	entries := []*storage.LogEntry{
		{ID: "1", Timestamp: when, SiteID: "site-a", Message: "blocked sqli", Action: "block"},
		{ID: "2", Timestamp: when.Add(time.Millisecond), SiteID: "site-a", Message: "blocked xss"},
		{ID: "3", Timestamp: when.Add(2 * time.Millisecond), SiteID: "site-b", Message: "rate limited"},
	}
	for _, entry := range entries {
		if err := sink.Write(t.Context(), entry); err != nil {
			t.Fatalf("write %s: %v", entry.ID, err)
		}
	}
	if err := sink.Flush(t.Context()); err != nil {
		t.Fatalf("flush: %v", err)
	}

	requests := recorder.snapshot()
	if len(requests) == 0 {
		t.Fatal("loki sink did not send a push request")
	}
	streams := map[string]*lokiStream{}
	seen := map[string]int{}
	for _, request := range requests {
		if request.path != lokiPushPath {
			t.Fatalf("unexpected push path %q", request.path)
		}
		if got := request.header.Get("Content-Type"); got != "application/json" {
			t.Fatalf("unexpected content type %q", got)
		}
		if got := request.header.Get("X-Scope-OrgID"); got != "tenant-a" {
			t.Fatalf("unexpected tenant header %q", got)
		}
		username, password, ok := parseBasicAuth(request.header.Get("Authorization"))
		if !ok || username != "loki-user" || password != "loki-pass" {
			t.Fatalf("unexpected basic auth %q", request.header.Get("Authorization"))
		}
		var payload lokiPushPayload
		if err := json.Unmarshal(request.body, &payload); err != nil {
			t.Fatalf("decode push payload: %v", err)
		}
		for _, stream := range payload.Streams {
			if len(stream.Values) == 0 {
				t.Fatal("loki stream carried no values")
			}
			signature := lokiLabelSignature(stream.Stream)
			copied := stream
			streams[signature] = &copied
			for _, value := range stream.Values {
				seen[value[1]]++
				if _, err := strconv.ParseInt(value[0], 10, 64); err != nil {
					t.Fatalf("loki timestamp %q is not nanoseconds: %v", value[0], err)
				}
				var decoded storage.LogEntry
				if err := json.Unmarshal([]byte(value[1]), &decoded); err != nil {
					t.Fatalf("loki line is not a log entry: %v", err)
				}
				if decoded.ID == "" || decoded.Timestamp.IsZero() {
					t.Fatalf("loki line lost identity fields: %s", value[1])
				}
			}
		}
	}

	if len(streams) != 2 {
		t.Fatalf("expected one stream per site, got %d", len(streams))
	}
	signatures := make([]string, 0, len(streams))
	for signature := range streams {
		signatures = append(signatures, signature)
	}
	sort.Strings(signatures)
	for _, signature := range signatures {
		labels := streams[signature].Stream
		if labels["job"] != lokiDefaultJobLabel || labels["env"] != "staging" {
			t.Fatalf("unexpected static labels %v", labels)
		}
	}
	if len(seen) != len(entries) {
		t.Fatalf("push payload delivered %d unique lines, want %d", len(seen), len(entries))
	}
	for _, entry := range entries {
		line := lokiLine(t, *entry)
		if seen[line] == 0 {
			t.Fatalf("missing line for entry %s: %s", entry.ID, line)
		}
	}
}

func TestLokiWriteSurfacesPushRejection(t *testing.T) {
	recorder := newLokiRecorder(func(lokiRequest) (int, string) {
		return http.StatusBadRequest, `{"message":"entry too far behind"}`
	})
	server := httptest.NewServer(recorder)
	defer server.Close()

	sink := newLokiTestSink(t, server, config.LokiConfig{})
	if err := sink.Write(t.Context(), &storage.LogEntry{ID: "rejected"}); err != nil {
		t.Fatalf("write: %v", err)
	}
	err := sink.Flush(t.Context())
	if err == nil || !strings.Contains(err.Error(), "loki returned 400") || !strings.Contains(err.Error(), "entry too far behind") {
		t.Fatalf("expected push rejection to surface, got %v", err)
	}
}

func TestLokiQueryDecodesSortsAndPagesRows(t *testing.T) {
	base := time.Date(2026, 5, 28, 8, 0, 0, 0, time.UTC)
	streams := []map[string]any{
		{
			"stream": map[string]string{"job": lokiDefaultJobLabel, "site_id": "site-a"},
			"values": [][2]string{
				{strconv.FormatInt(base.UnixNano(), 10), lokiLine(t, storage.LogEntry{ID: "1", Timestamp: base, SiteID: "site-a", Message: "first"})},
				{strconv.FormatInt(base.Add(2*time.Second).UnixNano(), 10), lokiLine(t, storage.LogEntry{ID: "3", Timestamp: base.Add(2 * time.Second), SiteID: "site-a", Message: "third"})},
			},
		},
		{
			"stream": map[string]string{"job": lokiDefaultJobLabel},
			"values": [][2]string{
				{strconv.FormatInt(base.Add(time.Second).UnixNano(), 10), lokiLine(t, storage.LogEntry{ID: "2", Timestamp: base.Add(time.Second), Message: "second"})},
			},
		},
	}
	rangeBody, err := json.Marshal(map[string]any{
		"status": "success",
		"data":   map[string]any{"resultType": "streams", "result": streams},
	})
	if err != nil {
		t.Fatalf("marshal range response: %v", err)
	}
	recorder := newLokiRecorder(func(request lokiRequest) (int, string) {
		switch request.path {
		case lokiQueryRangePath:
			return http.StatusOK, string(rangeBody)
		case lokiQueryPath:
			return http.StatusOK, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":[1758960000,"7"]}]}}`
		default:
			return http.StatusNotFound, ""
		}
	})
	server := httptest.NewServer(recorder)
	defer server.Close()

	sink := newLokiTestSink(t, server, config.LokiConfig{})
	items, total, err := sink.Query(t.Context(), storage.LogFilter{Limit: 2, Offset: 1})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if total != 7 {
		t.Fatalf("expected count total 7, got %d", total)
	}
	if len(items) != 2 || items[0].ID != "2" || items[1].ID != "1" {
		t.Fatalf("unexpected page %+v", items)
	}

	var rangeRequest, countRequest *lokiRequest
	for _, request := range recorder.snapshot() {
		request := request
		switch request.path {
		case lokiQueryRangePath:
			rangeRequest = &request
		case lokiQueryPath:
			countRequest = &request
		}
	}
	if rangeRequest == nil || countRequest == nil {
		t.Fatalf("expected range and count requests, got %d", len(recorder.snapshot()))
	}
	if got := rangeRequest.query.Get("limit"); got != "3" {
		t.Fatalf("expected limit offset+page+1 rows, got %q", got)
	}
	if got := rangeRequest.query.Get("direction"); got != "backward" {
		t.Fatalf("unexpected direction %q", got)
	}
	if got := rangeRequest.query.Get("start"); got == "" || rangeRequest.query.Get("end") == "" {
		t.Fatal("range request is missing explicit time bounds")
	}
	if got := rangeRequest.query.Get("query"); !strings.Contains(got, `{job="cheesewaf"}`) {
		t.Fatalf("unexpected logql selector %q", got)
	}
	if got := countRequest.query.Get("query"); !strings.HasPrefix(got, "sum(count_over_time({job=\"cheesewaf\"}") || !strings.Contains(got, "[86400s]") {
		t.Fatalf("unexpected count query %q", got)
	}
}

func TestLokiQueryAppliesLogQLFiltersAndVerifiesRows(t *testing.T) {
	base := time.Date(2026, 5, 28, 8, 0, 0, 0, time.UTC)
	rows := [][2]string{
		{strconv.FormatInt(base.UnixNano(), 10), lokiLine(t, storage.LogEntry{ID: "1", Timestamp: base, ClientIP: "198.51.100.9", Message: "blocked sql injection"})},
		{strconv.FormatInt(base.Add(time.Second).UnixNano(), 10), lokiLine(t, storage.LogEntry{ID: "2", Timestamp: base.Add(time.Second), ClientIP: "198.51.100.10", Message: "allowed request"})},
	}
	body, err := json.Marshal(map[string]any{
		"status": "success",
		"data": map[string]any{"resultType": "streams", "result": []map[string]any{
			{"stream": map[string]string{"job": lokiDefaultJobLabel}, "values": rows},
		}},
	})
	if err != nil {
		t.Fatalf("marshal range response: %v", err)
	}
	recorder := newLokiRecorder(func(request lokiRequest) (int, string) {
		if request.path == lokiQueryPath {
			t.Errorf("search filters must not use the count API")
		}
		return http.StatusOK, string(body)
	})
	server := httptest.NewServer(recorder)
	defer server.Close()

	sink := newLokiTestSink(t, server, config.LokiConfig{})
	items, total, err := sink.Query(t.Context(), storage.LogFilter{
		ClientIP: "198.51.100.9",
		Search:   "blocked",
		Limit:    10,
	})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(items) != 1 || items[0].ID != "1" {
		t.Fatalf("client-side verification did not narrow rows: %+v", items)
	}
	if total != 1 {
		t.Fatalf("expected bounded total for uncountable filter, got %d", total)
	}
	requests := recorder.snapshot()
	if len(requests) != 1 {
		t.Fatalf("expected a single range request, got %d", len(requests))
	}
	query := requests[0].query.Get("query")
	for _, want := range []string{`client_ip`, `198`, `|~ "(?i)blocked"`} {
		if !strings.Contains(query, want) {
			t.Fatalf("logql %q missing %q", query, want)
		}
	}
}

func TestLokiCountOnlySupportsExpressibleFilters(t *testing.T) {
	recorder := newLokiRecorder(func(request lokiRequest) (int, string) {
		return http.StatusOK, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":[1758960000,"42"]}]}}`
	})
	server := httptest.NewServer(recorder)
	defer server.Close()

	sink := newLokiTestSink(t, server, config.LokiConfig{})
	total, supported, err := sink.Count(t.Context(), storage.LogFilter{Action: "block", SiteID: "site-a"})
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if !supported || total != 42 {
		t.Fatalf("unexpected count total=%d supported=%v", total, supported)
	}
	requests := recorder.snapshot()
	if len(requests) != 1 {
		t.Fatalf("expected one count request, got %d", len(requests))
	}
	query := requests[0].query.Get("query")
	if !strings.Contains(query, `site_id="site-a"`) || !strings.Contains(query, `action`) || !strings.Contains(query, `block`) {
		t.Fatalf("count query did not reuse the selector filters: %q", query)
	}

	before := len(requests)
	if _, supported, err := sink.Count(t.Context(), storage.LogFilter{Search: "sqli"}); err != nil || supported {
		t.Fatalf("expected search count to be unsupported, supported=%v err=%v", supported, err)
	}
	if _, supported, err := sink.Count(t.Context(), storage.LogFilter{Tags: []string{"bot"}}); err != nil || supported {
		t.Fatalf("expected tag count to be unsupported, supported=%v err=%v", supported, err)
	}
	if len(recorder.snapshot()) != before {
		t.Fatal("unsupported counts must not query loki")
	}
}

func TestLokiBaseURLNormalizesEndpoint(t *testing.T) {
	tests := []struct {
		endpoint string
		want     string
		wantErr  bool
	}{
		{endpoint: "http://loki:3100", want: "http://loki:3100"},
		{endpoint: "http://loki:3100/", want: "http://loki:3100"},
		{endpoint: "https://loki.example.com/loki/api/v1/push", want: "https://loki.example.com"},
		{endpoint: "https://loki.example.com/grafana/", want: "https://loki.example.com/grafana"},
		{endpoint: "loki:3100", wantErr: true},
		{endpoint: "/relative/path", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.endpoint, func(t *testing.T) {
			got, err := lokiBaseURL(tc.endpoint)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected %q to be rejected, got %q", tc.endpoint, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalize %q: %v", tc.endpoint, err)
			}
			if got != tc.want {
				t.Fatalf("normalize %q = %q, want %q", tc.endpoint, got, tc.want)
			}
		})
	}
}

func TestNewLokiSinkValidatesConfiguration(t *testing.T) {
	if _, err := NewLokiSink(config.LokiConfig{}, nil); err == nil || !strings.Contains(err.Error(), "endpoint is required") {
		t.Fatalf("expected missing endpoint error, got %v", err)
	}
	if _, err := NewLokiSink(config.LokiConfig{Endpoint: "http://loki:3100", Labels: map[string]string{"bad-label": "x"}}, nil); err == nil {
		t.Fatal("expected invalid label name to be rejected")
	}
	if _, err := NewLokiSink(config.LokiConfig{Endpoint: "http://loki:3100", Labels: map[string]string{"__reserved": "x"}}, nil); err == nil {
		t.Fatal("expected reserved label name to be rejected")
	}
	sink, err := NewLokiSink(config.LokiConfig{Endpoint: "http://loki:3100"}, nil)
	if err != nil {
		t.Fatalf("new sink: %v", err)
	}
	defer sink.Close()
	if sink.cfg.Labels["job"] != lokiDefaultJobLabel {
		t.Fatalf("expected default job label, got %v", sink.cfg.Labels)
	}
	if sink.cfg.Timeout != 10*time.Second {
		t.Fatalf("expected default timeout, got %s", sink.cfg.Timeout)
	}
}

func TestNewFromConfigWiresLokiSink(t *testing.T) {
	recorder := newLokiRecorder(nil)
	server := httptest.NewServer(recorder)
	defer server.Close()

	sink, err := NewFromConfig(config.StorageConfig{
		Loki: config.LokiConfig{Enabled: true, Endpoint: server.URL, AllowPrivateEndpoint: true},
	}, filepath.Join(t.TempDir(), "access.log"))
	if err != nil {
		t.Fatalf("new sink: %v", err)
	}
	defer sink.Close()
	if err := sink.Write(context.Background(), &storage.LogEntry{ID: "wired", Message: "through factory"}); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := sink.Flush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if len(recorder.snapshot()) != 1 {
		t.Fatalf("expected one push request, got %d", len(recorder.snapshot()))
	}
}

func TestNewFromConfigBlocksPrivateLokiEndpointByDefault(t *testing.T) {
	recorder := newLokiRecorder(nil)
	server := httptest.NewServer(recorder)
	defer server.Close()

	sink, err := NewFromConfig(config.StorageConfig{
		Loki: config.LokiConfig{Enabled: true, Endpoint: server.URL},
	}, filepath.Join(t.TempDir(), "access.log"))
	if err != nil {
		t.Fatalf("new sink: %v", err)
	}
	defer sink.Close()
	if err := sink.Write(context.Background(), &storage.LogEntry{ID: "blocked-private"}); err != nil {
		t.Fatalf("write: %v", err)
	}
	err = sink.Flush(context.Background())
	if err == nil || !strings.Contains(err.Error(), "public") {
		t.Fatalf("expected private loki endpoint to be blocked, got %v", err)
	}
	if len(recorder.snapshot()) != 0 {
		t.Fatal("blocked loki endpoint must not receive requests")
	}
}

func TestLokiDecodeRowFallsBackToRawLine(t *testing.T) {
	row := lokiValueRow{timestamp: fmt.Sprint(time.Date(2026, 5, 28, 8, 0, 0, 0, time.UTC).UnixNano()), line: "plain text from another writer"}
	entry, err := lokiDecodeRow(row)
	if err != nil {
		t.Fatalf("decode row: %v", err)
	}
	if entry.Message != "plain text from another writer" || !entry.Timestamp.Equal(time.Date(2026, 5, 28, 8, 0, 0, 0, time.UTC)) {
		t.Fatalf("unexpected fallback entry %+v", entry)
	}
}

func parseBasicAuth(header string) (string, string, bool) {
	const prefix = "Basic "
	if !strings.HasPrefix(header, prefix) {
		return "", "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(header, prefix))
	if err != nil {
		return "", "", false
	}
	username, password, ok := strings.Cut(string(decoded), ":")
	return username, password, ok
}
