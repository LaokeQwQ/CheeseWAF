package log_sink

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

func TestRemoteLogSinksSendActualHTTPBatches(t *testing.T) {
	for _, name := range []string{"clickhouse", "victorialogs", "elasticsearch"} {
		t.Run(name, func(t *testing.T) {
			var mu sync.Mutex
			var bodies, paths []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				data, _ := io.ReadAll(r.Body)
				mu.Lock()
				bodies = append(bodies, string(data))
				paths = append(paths, r.URL.Path)
				mu.Unlock()
				_, _ = io.WriteString(w, `{"errors":false}`)
			}))
			defer server.Close()
			var sink storage.LogSink
			var err error
			switch name {
			case "clickhouse":
				sink, err = NewClickHouseSink(config.ClickHouseConfig{Endpoint: server.URL}, server.Client())
			case "victorialogs":
				sink, err = NewVictoriaLogsSink(config.VictoriaLogsConfig{Endpoint: server.URL + "/insert/jsonline"}, server.Client())
			case "elasticsearch":
				sink, err = NewElasticsearchSink(config.ElasticsearchConfig{Enabled: true, Endpoint: server.URL}, server.Client())
			}
			if err != nil {
				t.Fatal(err)
			}
			defer sink.Close()
			for i := range 10 {
				if err := sink.Write(t.Context(), &storage.LogEntry{ID: fmt.Sprint(i), Message: "batch"}); err != nil {
					t.Fatal(err)
				}
			}
			if err := sink.Flush(t.Context()); err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			defer mu.Unlock()
			if len(bodies) != 1 {
				t.Fatalf("10 entries used %d HTTP requests, want one batch", len(bodies))
			}
			lines := strings.Split(strings.TrimSpace(bodies[0]), "\n")
			want := 10
			if name == "elasticsearch" {
				want = 20
				if !strings.HasSuffix(paths[0], "/_bulk") {
					t.Fatalf("not a bulk endpoint: %s", paths[0])
				}
			}
			if len(lines) != want {
				t.Fatalf("batch has %d NDJSON lines, want %d", len(lines), want)
			}
			for _, line := range lines {
				if !json.Valid([]byte(line)) {
					t.Fatalf("invalid batch line: %q", line)
				}
			}
		})
	}
}

func TestElasticsearchBulkItemFailureIsReportedByFlush(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"errors":true,"items":[{"index":{"status":429,"error":{"type":"rejected"}}}]}`)
	}))
	defer server.Close()
	sink, err := NewElasticsearchSink(config.ElasticsearchConfig{Enabled: true, Endpoint: server.URL}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	if err := sink.Write(context.Background(), &storage.LogEntry{ID: "rejected"}); err != nil {
		t.Fatal(err)
	}
	if err := sink.Flush(context.Background()); err == nil {
		t.Fatal("HTTP 200 with rejected bulk items must fail flush")
	}
	if got := sink.AsyncStats().Failed; got != 1 {
		t.Fatalf("failed=%d, want one rejected entry", got)
	}
}
