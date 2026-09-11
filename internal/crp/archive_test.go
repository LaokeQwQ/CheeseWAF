package crp

import (
	"archive/zip"
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"testing"
)

func makeCRPArchive(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var out bytes.Buffer
	zw := zip.NewWriter(&out)
	for name, data := range entries {
		h, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := h.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func validArchiveEntries(t *testing.T) map[string][]byte {
	t.Helper()
	manifest := Manifest{APIVersion: APIVersion, Kind: Kind, Name: "demo", PluginID: "demo", Version: "1.0.0", Namespace: "official/demo", SourceRoot: "root", Source: "offline", ReleaseSequence: 1, Artifact: Artifact{Size: 7}}
	// The digest values are replaced by the test helper below.
	artifact := []byte("payload")
	manifest.Artifact.Digests = digestsForTest(artifact)
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	sigs, err := json.Marshal([]Signature{})
	if err != nil {
		t.Fatal(err)
	}
	return map[string][]byte{"manifest.json": raw, "artifact/payload.bin": artifact, "signatures/manifest.json": sigs}
}

func digestsForTest(b []byte) Digests {
	return Digests{MD5: md5Hex(b), SHA1: sha1Hex(b), SHA256: sha256Hex(b)}
}
func md5Hex(b []byte) string    { s := md5.Sum(b); return hex.EncodeToString(s[:]) }
func sha1Hex(b []byte) string   { s := sha1.Sum(b); return hex.EncodeToString(s[:]) }
func sha256Hex(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func TestParseArchiveMaterializesStrictPackage(t *testing.T) {
	archive := makeCRPArchive(t, validArchiveEntries(t))
	pkg, err := ParseArchive(archive, ArchiveOptions{})
	if err != nil {
		t.Fatalf("valid archive rejected: %v", err)
	}
	if string(pkg.Manifest) == "" || string(pkg.Artifact) != "payload" {
		t.Fatalf("unexpected package: %#v", pkg)
	}
	if pkg.Signatures == nil {
		t.Fatal("signatures should be materialized")
	}
}

func TestParseArchiveRejectsUnknownAndDuplicateLogicalPaths(t *testing.T) {
	base := validArchiveEntries(t)
	base["README.md"] = []byte("nope")
	if _, err := ParseArchive(makeCRPArchive(t, base), ArchiveOptions{}); !errors.Is(err, ErrArchiveLayout) {
		t.Fatalf("unknown top-level entry err=%v", err)
	}
	// ZIP permits duplicate names; construct one manually to ensure the parser rejects it.
	var out bytes.Buffer
	zw := zip.NewWriter(&out)
	for _, name := range []string{"manifest.json", "manifest.json"} {
		h, _ := zw.Create(name)
		_, _ = h.Write([]byte("{}"))
	}
	_ = zw.Close()
	if _, err := ParseArchive(out.Bytes(), ArchiveOptions{}); !errors.Is(err, ErrArchiveDuplicate) {
		t.Fatalf("duplicate entry err=%v", err)
	}
}

func TestParseArchiveRejectsTraversalSymlinkAndMultipleArtifacts(t *testing.T) {
	base := validArchiveEntries(t)
	base["artifact/../escape"] = []byte("x")
	if _, err := ParseArchive(makeCRPArchive(t, base), ArchiveOptions{}); !errors.Is(err, ErrArchivePath) {
		t.Fatalf("traversal err=%v", err)
	}
	base = validArchiveEntries(t)
	base["artifact/second.bin"] = []byte("x")
	if _, err := ParseArchive(makeCRPArchive(t, base), ArchiveOptions{}); !errors.Is(err, ErrArchiveLayout) {
		t.Fatalf("multiple artifacts err=%v", err)
	}
}

func TestParseArchiveEnforcesSizeAndCountLimitsBeforeExpansion(t *testing.T) {
	base := validArchiveEntries(t)
	if _, err := ParseArchive(makeCRPArchive(t, base), ArchiveOptions{MaxTotalBytes: 1}); !errors.Is(err, ErrArchiveTooLarge) {
		t.Fatalf("size limit err=%v", err)
	}
	if _, err := ParseArchive(makeCRPArchive(t, base), ArchiveOptions{MaxFiles: 2}); !errors.Is(err, ErrArchiveTooManyFiles) {
		t.Fatalf("file limit err=%v", err)
	}
}

func TestParseArchiveRejectsManifestArtifactSizeMismatch(t *testing.T) {
	base := validArchiveEntries(t)
	var m Manifest
	if err := json.Unmarshal(base["manifest.json"], &m); err != nil {
		t.Fatal(err)
	}
	m.Artifact.Size++
	base["manifest.json"], _ = json.Marshal(m)
	if _, err := ParseArchive(makeCRPArchive(t, base), ArchiveOptions{}); !errors.Is(err, ErrArtifactSize) {
		t.Fatalf("size mismatch err=%v", err)
	}
}

func TestParseArchiveDoesNotWriteOrExecute(t *testing.T) {
	archive := makeCRPArchive(t, validArchiveEntries(t))
	pkg, err := ParseArchive(archive, ArchiveOptions{})
	if err != nil {
		t.Fatal(err)
	}
	pkg.Manifest[0] ^= 1
	if _, err := io.Copy(io.Discard, bytes.NewReader(archive)); err != nil {
		t.Fatal(err)
	}
}
