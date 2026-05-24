package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine/semantic"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

func TestServerPassesAndBlocks(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	cfg := config.Default()
	cfg.Sites[0].Upstreams = []config.UpstreamConfig{{Address: upstream.URL, Weight: 1}}
	cfg.Protection.IP.Whitelist = nil
	cfg.Protection.IP.Blacklist = nil

	server, err := NewServer(&cfg, engine.NewPipeline(semantic.NewSQLDetector("block"), semantic.NewXSSDetector("block")), noopSink{})
	if err != nil {
		t.Fatal(err)
	}

	passReq := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	passRec := httptest.NewRecorder()
	server.Handler().ServeHTTP(passRec, passReq)
	if passRec.Code != http.StatusOK || strings.TrimSpace(passRec.Body.String()) != "ok" {
		t.Fatalf("expected proxy pass, code=%d body=%q", passRec.Code, passRec.Body.String())
	}

	blockReq := httptest.NewRequest(http.MethodGet, "http://localhost/?id=1%27%20OR%20%271%27%3D%271", nil)
	blockRec := httptest.NewRecorder()
	server.Handler().ServeHTTP(blockRec, blockReq)
	if blockRec.Code != http.StatusForbidden {
		t.Fatalf("expected block, code=%d body=%q", blockRec.Code, blockRec.Body.String())
	}
}

type noopSink struct{}

func (noopSink) Write(context.Context, *storage.LogEntry) error { return nil }
func (noopSink) Query(context.Context, storage.LogFilter) ([]storage.LogEntry, int64, error) {
	return nil, 0, nil
}
func (noopSink) Flush(context.Context) error { return nil }
func (noopSink) Close() error                { return nil }
