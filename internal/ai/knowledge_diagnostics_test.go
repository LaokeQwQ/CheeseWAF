package ai

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

func TestKnowledgeRejectedSourceDiagnosticsAndRecovery(t *testing.T) {
	for _, kind := range []string{"directory", "oversized", "symlink", "missing"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "private-source.json")
			switch kind {
			case "directory":
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			case "oversized":
				if err := os.WriteFile(path, bytes.Repeat([]byte("x"), maxKnowledgeFileBytes+1), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink("secret-target", path); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
			}
			var logs bytes.Buffer
			previous := log.Writer()
			log.SetOutput(&logs)
			t.Cleanup(func() { log.SetOutput(previous) })
			cfg := config.AIKnowledgeConfig{Enabled: true, Builtin: true, File: path}
			NewKnowledgeBase(cfg)
			if strings.Count(logs.String(), "ai knowledge:") != 1 || strings.Contains(logs.String(), path) || strings.Contains(logs.String(), "secret-target") {
				t.Fatalf("expected one bounded diagnostic without source paths: %q", logs.String())
			}
			logs.Reset()
			first := CachedKnowledgeBase(cfg)
			if len(first.Search("waf", 1)) == 0 {
				t.Fatal("rejection lost builtin fallback")
			}
			for range 3 {
				if CachedKnowledgeBase(cfg) != first {
					t.Fatal("rejected source was not cached")
				}
			}
			if strings.Count(logs.String(), "ai knowledge:") != 1 {
				t.Fatalf("cache hits repeated diagnostic: %q", logs.String())
			}
			if kind != "missing" {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(path, []byte(`[{"id":"custom","title":"recovered","content":"private-knowledge-content"}]`), 0600); err != nil {
				t.Fatal(err)
			}
			second := CachedKnowledgeBase(cfg)
			if second == first || len(second.Search("recovered", 1)) != 1 {
				t.Fatal("cache failed to load recovered source")
			}
			if CachedKnowledgeBase(cfg) != second {
				t.Fatal("recovered snapshot was not cached")
			}
			if strings.Count(logs.String(), "ai knowledge:") != 1 || strings.Contains(logs.String(), "private-knowledge-content") {
				t.Fatalf("recovery emitted unexpected diagnostic: %q", logs.String())
			}
		})
	}
}
