package index

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/crp"
)

const testHostVersion = "0.4.5"

// validManifestJSON returns a manifest that satisfies crp.ParseManifest.
func validManifestJSON(pluginID, version string, compatibility *crp.HostCompatibility) []byte {
	fields := map[string]any{
		"api_version":      crp.APIVersion,
		"kind":             crp.Kind,
		"name":             pluginID,
		"plugin_id":        pluginID,
		"version":          version,
		"namespace":        "official/" + pluginID,
		"source":           "offline",
		"source_root":      "test-root",
		"release_sequence": 1,
		"digests": map[string]string{
			"md5":    strings.Repeat("a", 32),
			"sha1":   strings.Repeat("b", 40),
			"sha256": strings.Repeat("c", 64),
		},
	}
	if compatibility != nil {
		bounds := map[string]string{}
		if compatibility.Min != "" {
			bounds["min"] = compatibility.Min
		}
		if compatibility.Max != "" {
			bounds["max"] = compatibility.Max
		}
		fields["host_compatibility"] = bounds
	}
	return mustJSON(fields)
}

func mustJSON(value any) []byte {
	data, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return data
}

func writeFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

func TestScanRecordsValidBrokenIncompatibleAndForeignFiles(t *testing.T) {
	dir := t.TempDir()
	validPath := writeFile(t, dir, "valid.json", validManifestJSON("alpha", "1.0.0", nil))
	badPath := writeFile(t, dir, "broken.json", []byte(`{"api_version":`))
	incompatiblePath := writeFile(t, dir, "incompatible.json", validManifestJSON("beta", "1.0.0", &crp.HostCompatibility{Min: "9.0.0"}))
	foreignPath := writeFile(t, dir, "foreign.json", []byte(`{"api_version":"other.example/v1"}`))
	// A directory whose name looks like a manifest must be skipped.
	if err := os.Mkdir(filepath.Join(dir, "nested.json"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	snapshot := Scan(dir, testHostVersion)
	if snapshot == nil || snapshot.Dir != dir || snapshot.ScannedAt.IsZero() {
		t.Fatalf("unexpected snapshot header: %+v", snapshot)
	}
	if len(snapshot.Entries) != 4 {
		t.Fatalf("entries = %d, want 4: %+v", len(snapshot.Entries), snapshot.Entries)
	}

	byPath := map[string]Entry{}
	for _, entry := range snapshot.Entries {
		byPath[entry.Path] = entry
	}

	valid, ok := byPath[validPath]
	if !ok {
		t.Fatalf("valid manifest missing from entries: %+v", snapshot.Entries)
	}
	if valid.Err != nil {
		t.Fatalf("valid manifest has error: %v", valid.Err)
	}
	if valid.Manifest == nil || valid.Manifest.PluginID != "alpha" || valid.APIVersion != crp.APIVersion {
		t.Fatalf("valid manifest not parsed: %+v", valid)
	}
	if string(valid.Raw) != string(validManifestJSON("alpha", "1.0.0", nil)) {
		t.Fatal("raw bytes were not preserved")
	}

	for _, path := range []string{badPath, incompatiblePath, foreignPath} {
		entry, ok := byPath[path]
		if !ok {
			t.Fatalf("%s missing from entries", path)
		}
		if entry.Err == nil {
			t.Fatalf("%s should carry an error", path)
		}
	}
	if !errors.Is(byPath[incompatiblePath].Err, crp.ErrHostIncompatible) {
		t.Fatalf("incompatible error = %v, want ErrHostIncompatible", byPath[incompatiblePath].Err)
	}
	if byPath[incompatiblePath].Manifest == nil {
		t.Fatal("incompatible entry lost its manifest; diagnostics need the declared range")
	}
	if byPath[foreignPath].Manifest != nil {
		t.Fatal("foreign JSON must not be reported as a CRP manifest")
	}

	plugins := snapshot.Plugins(testHostVersion)
	if len(plugins) != 1 || plugins[0].Path != validPath {
		t.Fatalf("plugins = %+v, want only %s", plugins, validPath)
	}

	problems := snapshot.Problems()
	if len(problems) != 3 {
		t.Fatalf("problems = %d, want 3: %+v", len(problems), problems)
	}
	for _, problem := range problems {
		if problem.Err == nil {
			t.Fatalf("problem entry without error: %+v", problem)
		}
	}
}

func TestPluginsFiltersByHostVersion(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "b.json", validManifestJSON("bravo", "1.0.0", &crp.HostCompatibility{Min: "0.4.0", Max: "0.5.0"}))
	writeFile(t, dir, "a.json", validManifestJSON("alpha", "2.0.0", &crp.HostCompatibility{Min: "0.4.0", Max: "0.5.0"}))
	writeFile(t, dir, "c.json", validManifestJSON("charlie", "1.0.0", &crp.HostCompatibility{Min: "0.6.0"}))

	snapshot := Scan(dir, testHostVersion)
	plugins := snapshot.Plugins(testHostVersion)
	if len(plugins) != 2 {
		t.Fatalf("plugins = %d, want 2", len(plugins))
	}
	if plugins[0].Manifest.PluginID != "alpha" || plugins[1].Manifest.PluginID != "bravo" {
		t.Fatalf("plugins not sorted by plugin id: %v, %v", plugins[0].Manifest.PluginID, plugins[1].Manifest.PluginID)
	}

	// A later host version must re-evaluate the compatibility gate.
	if later := snapshot.Plugins("0.6.0"); len(later) != 1 || later[0].Manifest.PluginID != "charlie" {
		t.Fatalf("plugins at 0.6.0 = %+v, want only charlie", later)
	}
}

func TestScanMissingDirectoryReturnsEmptySnapshot(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "does-not-exist")
	snapshot := Scan(dir, testHostVersion)
	if snapshot == nil {
		t.Fatal("nil snapshot for a missing directory")
	}
	if len(snapshot.Entries) != 0 || len(snapshot.Problems()) != 0 || len(snapshot.Plugins(testHostVersion)) != 0 {
		t.Fatalf("missing directory should be empty: %+v", snapshot)
	}
}

func TestSnapshotNilReceiverIsSafe(t *testing.T) {
	var snapshot *Snapshot
	if snapshot.Plugins(testHostVersion) != nil || snapshot.Problems() != nil {
		t.Fatal("nil snapshot must not panic or return entries")
	}
}

// A descriptor is a small JSON document. An oversized file must be reported
// instead of read into memory, and a symlink must be ignored: the watcher
// fingerprints the link, so a changed target would never trigger a reload.
func TestScanSkipsOversizedFilesAndSymlinks(t *testing.T) {
	dir := t.TempDir()
	valid := `{"api_version":"crp.cheesewaf.io/v1","kind":"CheeseWAFResourcePackage","name":"demo","version":"1.0.0","namespace":"official/demo","source_root":"root","source":"offline","release_sequence":1}`
	target := filepath.Join(dir, "target.json")
	if err := os.WriteFile(target, []byte(valid), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "link.json")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	big := filepath.Join(dir, "big.json")
	if err := os.WriteFile(big, bytes.Repeat([]byte("a"), maxIndexedFileBytes+1), 0o600); err != nil {
		t.Fatalf("write big: %v", err)
	}

	snapshot := Scan(dir, "0.4.5")
	if len(snapshot.Entries) != 2 {
		t.Fatalf("expected only regular files, got %d entries", len(snapshot.Entries))
	}
	for _, entry := range snapshot.Entries {
		if filepath.Base(entry.Path) == "link.json" {
			t.Fatal("symlinked descriptor must not be indexed")
		}
	}
	var oversize *Entry
	for index := range snapshot.Entries {
		if filepath.Base(snapshot.Entries[index].Path) == "big.json" {
			oversize = &snapshot.Entries[index]
		}
	}
	if oversize == nil || oversize.Err == nil || !strings.Contains(oversize.Err.Error(), "exceeds") {
		t.Fatalf("oversized file was not rejected: %+v", oversize)
	}
}
