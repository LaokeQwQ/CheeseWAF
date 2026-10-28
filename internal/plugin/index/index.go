// Package index catalogues the CRP plugin manifests in a directory.
//
// Scanning is kept separate from activation so that one broken or
// incompatible file cannot hide the rest of the directory: every file lands
// in a Snapshot, malformed ones carry an error instead of failing the scan,
// and only entries that pass the host compatibility gate are offered to
// activation.
package index

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/crp"
)

// maxIndexedFileBytes bounds one descriptor. A manifest or provider pack is a
// small JSON document; anything larger is not something the index should hold
// in memory, and reading it eagerly would let a stray file exhaust the process
// before validation ever runs.
const maxIndexedFileBytes = 1 << 20

const (
	// maxIndexedFiles and maxIndexedTotalBytes bound one scan. A per-file cap
	// alone still allows count × cap bytes to be retained in the snapshot, so a
	// directory full of large descriptors could exhaust memory before any
	// validation runs.
	maxIndexedFiles      = 512
	maxIndexedTotalBytes = 8 << 20
)

// Entry is one candidate file in the plugin directory. A malformed file is
// recorded with Err set and never fails the whole scan.
type Entry struct {
	Path       string
	APIVersion string
	Manifest   *crp.Manifest // non-nil when the file is a CRP manifest
	Raw        []byte        // the exact bytes, for downstream parsers
	Err        error
}

// Snapshot is an immutable view of one directory scan.
type Snapshot struct {
	Dir       string
	ScannedAt time.Time
	Entries   []Entry
}

// Scan reads every *.json file directly under dir (non-recursive), skips
// directories, and validates CRP manifests. Missing dir is not an error: it
// returns an empty snapshot so the host can start before the dir exists.
//
// A non-empty hostVersion also records crp.ErrHostIncompatible on manifests
// whose declared range excludes the host. The entry keeps its Manifest so
// diagnostics still see what the file claimed.
func Scan(dir, hostVersion string) *Snapshot {
	snapshot := &Snapshot{Dir: dir, ScannedAt: time.Now()}
	dirEntries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return snapshot
		}
		// A permission or I/O failure must still produce a snapshot: callers
		// need the error visible, not a panic or a silently empty index.
		snapshot.Entries = []Entry{{
			Path: dir,
			Err:  fmt.Errorf("read plugin directory %s: %w", dir, err),
		}}
		return snapshot
	}

	hostVersion = strings.TrimSpace(hostVersion)
	entries := make([]Entry, 0, len(dirEntries))
	retained := int64(0)
	for _, dirEntry := range dirEntries {
		if !isManifestCandidate(dirEntry) {
			continue
		}
		if len(entries) >= maxIndexedFiles {
			entries = append(entries, Entry{
				Path: dir,
				Err:  fmt.Errorf("plugin index holds more than %d files; the rest were not read", maxIndexedFiles),
			})
			break
		}
		entry := loadEntry(filepath.Join(dir, dirEntry.Name()), hostVersion)
		retained += int64(len(entry.Raw))
		if retained > maxIndexedTotalBytes {
			// Keep the entry that crossed the budget as a visible problem
			// instead of silently dropping it.
			entry.Err = fmt.Errorf("%s: index exceeds %d bytes", entry.Path, maxIndexedTotalBytes)
			entry.Raw = nil
			entry.Manifest = nil
			entries = append(entries, entry)
			break
		}
		entries = append(entries, entry)
	}
	// os.ReadDir already sorts, but the ordering is part of the public
	// deterministic output contract, so it is enforced here as well.
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	snapshot.Entries = entries
	return snapshot
}

// Plugins returns entries with a CRP manifest that satisfies hostVersion,
// sorted by PluginID (then version) for deterministic output. A manifest that
// Scan marked incompatible is re-evaluated for hostVersion, so the same
// Snapshot stays usable when the requested host version is not the one used
// for scanning. Other load errors are never returned; inspect Problems for
// the reason. An empty hostVersion cannot prove compatibility, so entries
// already marked incompatible stay excluded.
func (s *Snapshot) Plugins(hostVersion string) []Entry {
	if s == nil {
		return nil
	}
	hostVersion = strings.TrimSpace(hostVersion)
	plugins := make([]Entry, 0, len(s.Entries))
	for _, entry := range s.Entries {
		if entry.Manifest == nil {
			continue
		}
		incompatible := errors.Is(entry.Err, crp.ErrHostIncompatible)
		if entry.Err != nil && !incompatible {
			continue
		}
		if hostVersion == "" {
			if incompatible {
				continue
			}
		} else if err := entry.Manifest.HostCompatibility.Check(hostVersion); err != nil {
			continue
		}
		// The returned entry is a copy; drop the scan-time incompatibility so
		// callers do not mistake it for a failure of the requested version.
		entry.Err = nil
		plugins = append(plugins, entry)
	}
	sort.SliceStable(plugins, func(i, j int) bool {
		left, right := plugins[i].Manifest, plugins[j].Manifest
		leftID, rightID := pluginID(left), pluginID(right)
		if leftID != rightID {
			return leftID < rightID
		}
		// Lexical ordering is enough here; activation performs the semantic
		// version comparison that decides which release wins.
		return left.Version < right.Version
	})
	return plugins
}

// Problems returns entries that failed to load, for logging/metrics.
func (s *Snapshot) Problems() []Entry {
	if s == nil {
		return nil
	}
	problems := make([]Entry, 0)
	for _, entry := range s.Entries {
		if entry.Err != nil {
			problems = append(problems, entry)
		}
	}
	sort.SliceStable(problems, func(i, j int) bool { return problems[i].Path < problems[j].Path })
	return problems
}

// pluginID prefers the activation identity and falls back to the display name
// so a manifest without plugin_id still sorts sensibly.
func pluginID(manifest *crp.Manifest) string {
	if manifest.PluginID != "" {
		return manifest.PluginID
	}
	return manifest.Name
}

// isManifestCandidate reports whether a directory entry is a file Scan reads.
// Symlinks are accepted; a link that cannot be read is reported per entry.
func isManifestCandidate(entry os.DirEntry) bool {
	if entry.IsDir() {
		return false
	}
	// Only regular files are candidates. A symlink would be read through, but
	// the watcher fingerprints the link itself, so a changed target would never
	// trigger a reload; a FIFO would block the read and could hang startup.
	if entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
		return false
	}
	return strings.EqualFold(filepath.Ext(entry.Name()), ".json")
}

// loadEntry reads one file and converts every failure into Entry.Err so the
// remaining files stay indexed.
func loadEntry(path, hostVersion string) Entry {
	entry := Entry{Path: path}
	file, err := os.Open(path)
	if err != nil {
		entry.Err = fmt.Errorf("%s: %w", path, err)
		return entry
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		entry.Err = fmt.Errorf("%s: %w", path, err)
		return entry
	}
	if !info.Mode().IsRegular() {
		entry.Err = fmt.Errorf("%s: not a regular file", path)
		return entry
	}
	if info.Size() > maxIndexedFileBytes {
		entry.Err = fmt.Errorf("%s: exceeds %d bytes", path, maxIndexedFileBytes)
		return entry
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxIndexedFileBytes+1))
	if err != nil {
		entry.Err = fmt.Errorf("%s: %w", path, err)
		return entry
	}
	if int64(len(raw)) > maxIndexedFileBytes {
		entry.Err = fmt.Errorf("%s: exceeds %d bytes", path, maxIndexedFileBytes)
		return entry
	}
	entry.Raw = raw

	// The header is decoded separately so callers can tell a foreign file
	// format from a corrupt manifest even though parsing later fails.
	var header struct {
		APIVersion string `json:"api_version"`
	}
	if err := json.Unmarshal(raw, &header); err == nil {
		entry.APIVersion = header.APIVersion
	}

	// A notifier provider pack shares the directory but not the manifest
	// schema; parsing it as a CRP manifest would report every pack as broken.
	// Its own package validates it, so the index only records the bytes.
	if strings.HasPrefix(entry.APIVersion, "crp.cheesewaf.io/notifier/") {
		return entry
	}

	manifest, err := crp.ParseManifest(raw)
	if err != nil {
		entry.Err = fmt.Errorf("%s: %w", path, err)
		return entry
	}
	entry.Manifest = &manifest
	if hostVersion != "" {
		if err := manifest.HostCompatibility.Check(hostVersion); err != nil {
			entry.Err = fmt.Errorf("%s: %w", path, err)
		}
	}
	return entry
}
