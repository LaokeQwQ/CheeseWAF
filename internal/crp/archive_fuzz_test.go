package crp

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"sort"
	"testing"
)

func fuzzArchive(entries map[string][]byte) []byte {
	var out bytes.Buffer
	zw := zip.NewWriter(&out)
	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		h, err := zw.Create(name)
		if err != nil {
			panic(err)
		}
		if _, err := h.Write(entries[name]); err != nil {
			panic(err)
		}
	}
	if err := zw.Close(); err != nil {
		panic(err)
	}
	return out.Bytes()
}

func fuzzValidArchiveEntries() map[string][]byte {
	manifest := Manifest{
		APIVersion:      APIVersion,
		Kind:            Kind,
		Name:            "fuzz-demo",
		PluginID:        "fuzz-demo",
		Version:         "1.0.0",
		Namespace:       "official/fuzz-demo",
		SourceRoot:      "root",
		Source:          "offline",
		ReleaseSequence: 1,
		Artifact:        Artifact{Size: 7},
	}
	artifact := []byte("payload")
	manifest.Artifact.Digests = digestsForTest(artifact)
	raw, err := json.Marshal(manifest)
	if err != nil {
		panic(err)
	}
	return map[string][]byte{
		"manifest.json":            raw,
		"artifact/payload.bin":     artifact,
		"signatures/manifest.json": []byte("[]"),
	}
}

// FuzzParseArchive checks that arbitrary ZIP bytes never panic and that any
// accepted package preserves the parser's size/identity invariants.
func FuzzParseArchive(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("PK"))
	f.Add([]byte("not a zip"))
	f.Add(fuzzArchive(fuzzValidArchiveEntries()))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4<<20 {
			t.Skip()
		}
		pkg, err := ParseArchive(data, ArchiveOptions{
			MaxFiles:           64,
			MaxTotalBytes:      4 << 20,
			MaxManifestBytes:   1 << 20,
			MaxArtifactBytes:   2 << 20,
			MaxSignaturesBytes: 1 << 20,
		})
		if err != nil {
			return
		}
		if len(pkg.Manifest) == 0 || len(pkg.Artifact) == 0 || pkg.Signatures == nil {
			t.Fatal("accepted package is missing required material")
		}
		var manifest Manifest
		if err := json.Unmarshal(pkg.Manifest, &manifest); err != nil {
			t.Fatalf("accepted manifest is not JSON: %v", err)
		}
		if manifest.Artifact.Size != int64(len(pkg.Artifact)) {
			t.Fatalf("artifact size %d does not match bytes %d", manifest.Artifact.Size, len(pkg.Artifact))
		}
	})
}
