package cli

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/crp"
)

func TestCRPVerifyRequiresExplicitInputs(t *testing.T) {
	cmd := newRootCommand()
	cmd.SetArgs([]string{"crp", "verify"})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "--package") {
		t.Fatalf("expected explicit package error, got %v", err)
	}
}

func TestCRPVerifyPrintsSafeSummary(t *testing.T) {
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	artifact := []byte("artifact")
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest := crp.Manifest{Name: "demo", Version: "1.0.0", Namespace: "official/demo", Source: "offline", SourceRoot: "root-v1", ReleaseSequence: 1, Artifact: crp.Artifact{Name: "demo.bin", Size: int64(len(artifact))}}
	md5sum := md5.Sum(artifact)
	sha1sum := sha1.Sum(artifact)
	sha256sum := sha256.Sum256(artifact)
	manifest.Artifact.Digests = crp.Digests{MD5: hex.EncodeToString(md5sum[:]), SHA1: hex.EncodeToString(sha1sum[:]), SHA256: hex.EncodeToString(sha256sum[:])}
	sig, err := crp.SignManifestWithKeyID(manifest, "k1", private, now)
	if err != nil {
		t.Fatal(err)
	}
	_, private2, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sig2, err := crp.SignManifestWithKeyID(manifest, "k2", private2, now)
	if err != nil {
		t.Fatal(err)
	}
	rawManifest, _ := json.Marshal(manifest)
	rawSigs, _ := json.Marshal([]crp.Signature{sig, sig2})
	archive := makeArchive(t, map[string][]byte{"manifest.json": rawManifest, "artifact/demo.bin": artifact, "signatures/manifest.json": rawSigs})
	dir := t.TempDir()
	pkgPath := filepath.Join(dir, "demo.crp")
	if err := os.WriteFile(pkgPath, archive, 0o600); err != nil {
		t.Fatal(err)
	}
	_, private3, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	roots, _ := json.Marshal([]crp.TrustRoot{{ID: "root-v1", Class: crp.SignerOfficial, NamespacePrefixes: []string{"official/"}, Keys: []crp.TrustKey{{ID: "k1", PublicKey: private.Public().(ed25519.PublicKey), Class: crp.SignerOfficial}, {ID: "k2", PublicKey: private2.Public().(ed25519.PublicKey), Class: crp.SignerOfficial}, {ID: "k3", PublicKey: private3.Public().(ed25519.PublicKey), Class: crp.SignerOfficial}}, Policy: crp.SignaturePolicy{Threshold: 2, Total: 3}, HighRiskPolicy: crp.SignaturePolicy{Threshold: 3, Total: 5}}})
	sources, _ := json.Marshal([]crp.SourceRootRegistration{{ID: "root-v1", NamespacePrefixes: []string{"official/"}, Sources: []string{"offline"}}})
	rootsPath := filepath.Join(dir, "roots.json")
	sourcesPath := filepath.Join(dir, "sources.json")
	_ = os.WriteFile(rootsPath, roots, 0o600)
	_ = os.WriteFile(sourcesPath, sources, 0o600)
	cmd := newRootCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"crp", "verify", "--package", pkgPath, "--trust-roots", rootsPath, "--sources", sourcesPath, "--now", now.Format(time.RFC3339)})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	got := out.String()
	for _, want := range []string{"manifest_identity:", "signature_status: trusted", "artifact_size: 8"} {
		if !strings.Contains(got, want) {
			t.Fatalf("output %q missing %q", got, want)
		}
	}
	if strings.Contains(got, "k1") || strings.Contains(got, "offline") {
		t.Fatalf("output leaked trust/source details: %q", got)
	}
}

func TestCRPVerifyReadBoundedFileRejectsOversize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oversize.json")
	if err := os.WriteFile(path, []byte("12345"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readBoundedFile(path, 4); err == nil {
		t.Fatal("oversized input was accepted")
	}
}

func makeArchive(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	for name, data := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write(data)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}
