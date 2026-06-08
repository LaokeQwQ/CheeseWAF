package traffic

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRecorderWritesJSONLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic.jsonl")
	recorder := NewRecorder(path, 4)
	err := recorder.Write(context.Background(), Entry{ID: "1", Timestamp: time.Now(), Method: "GET", URL: "/", RequestBody: []byte("abcdef")})
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("expected recorded data")
	}
}
