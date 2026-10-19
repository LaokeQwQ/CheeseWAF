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
			gotBodies := append([]string(nil), bodies...)
			gotPaths := append([]string(nil), paths...)
			mu.Unlock()
			if len(gotBodies) == 0 || len(gotBodies) > 10 {
				t.Fatalf("10 entries used %d HTTP requests, want all entries delivered", len(gotBodies))
			}
			wantLines := 10
			if name == "elasticsearch" {
				wantLines = 20
			}
			gotLines := 0
			for i, body := range gotBodies {
				lines := strings.Split(strings.TrimSpace(body), "\n")
				gotLines += len(lines)
				if name == "elasticsearch" && !strings.HasSuffix(gotPaths[i], "/_bulk") {
					t.Fatalf("not a bulk endpoint: %s", gotPaths[i])
				}
				for _, line := range lines {
					if !json.Valid([]byte(line)) {
						t.Fatalf("invalid batch line: %q", line)
					}
				}
			}
			if gotLines != wantLines {
				t.Fatalf("async delivery used %d NDJSON lines, want %d", gotLines, wantLines)
			}
		})
	}
}

func TestRemoteLogSinksBatchWritersSendOneRequest(t *testing.T) {
	entries := make([]*storage.LogEntry, 10)
	for i := range entries {
		entries[i] = &storage.LogEntry{ID: fmt.Sprint(i), Message: "batch"}
	}
	for _, name := range []string{"clickhouse", "victorialogs", "elasticsearch"} {
		t.Run(name, func(t *testing.T) {
			var bodies, paths []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				data, _ := io.ReadAll(r.Body)
				bodies = append(bodies, string(data))
				paths = append(paths, r.URL.Path)
				_, _ = io.WriteString(w, `{"errors":false}`)
			}))
			defer server.Close()

			var closeSink func() error
			var writeBatch func(context.Context, []*storage.LogEntry) error
			switch name {
			case "clickhouse":
				sink, err := NewClickHouseSink(config.ClickHouseConfig{Endpoint: server.URL}, server.Client())
				if err != nil {
					t.Fatal(err)
				}
				closeSink, writeBatch = sink.Close, sink.writeBatchSync
			case "victorialogs":
				sink, err := NewVictoriaLogsSink(config.VictoriaLogsConfig{Endpoint: server.URL + "/insert/jsonline"}, server.Client())
				if err != nil {
					t.Fatal(err)
				}
				closeSink, writeBatch = sink.Close, sink.writeBatchSync
			case "elasticsearch":
				sink, err := NewElasticsearchSink(config.ElasticsearchConfig{Enabled: true, Endpoint: server.URL}, server.Client())
				if err != nil {
					t.Fatal(err)
				}
				closeSink, writeBatch = sink.Close, sink.writeBatchSync
			}
			defer closeSink()
			if err := writeBatch(context.Background(), entries); err != nil {
				t.Fatal(err)
			}
			if len(bodies) != 1 {
				t.Fatalf("batch writer used %d HTTP requests, want one", len(bodies))
			}
			lines := strings.Split(strings.TrimSpace(bodies[0]), "\n")
			wantLines := 10
			if name == "elasticsearch" {
				wantLines = 20
				if !strings.HasSuffix(paths[0], "/_bulk") {
					t.Fatalf("not a bulk endpoint: %s", paths[0])
				}
			}
			if len(lines) != wantLines {
				t.Fatalf("batch has %d NDJSON lines, want %d", len(lines), wantLines)
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
