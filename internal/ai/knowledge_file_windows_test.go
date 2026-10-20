package ai

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

func TestKnowledgeFileLoadsWhileAnotherReaderIsOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "knowledge.json")
	if err := os.WriteFile(path, []byte(`[{"id":"a","title":"alpha","content":"first"}]`), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := openKnowledgeFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	cfg := config.AIKnowledgeConfig{Enabled: true, File: path}
	if len(NewKnowledgeBase(cfg).Search("alpha", 1)) != 1 {
		t.Fatal("open reader prevented loading knowledge document")
	}
	first := CachedKnowledgeBase(cfg)
	if len(first.Search("alpha", 1)) != 1 {
		t.Fatal("open reader prevented populating knowledge cache")
	}
	if CachedKnowledgeBase(cfg) != first {
		t.Fatal("open reader prevented reusing knowledge cache")
	}
}
