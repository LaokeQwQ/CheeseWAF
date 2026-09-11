package cli

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/crp"
)

func TestCRPStageRequiresExplicitInputs(t *testing.T) {
	cmd := newRootCommand()
	cmd.SetArgs([]string{"crp", "stage", "--now", "2026-09-08T12:00:00Z"})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "--package") {
		t.Fatalf("expected explicit package error, got %v", err)
	}
}

func TestCRPStagePersistsStagedOnly(t *testing.T) {
	fixture := writeCRPStageFixture(t, crp.SignerOfficial)
	runtimeRoot := filepath.Join(t.TempDir(), "crp-runtime")
	cmd := newRootCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{
		"crp", "stage",
		"--package", fixture.packagePath,
		"--trust-roots", fixture.rootsPath,
		"--sources", fixture.sourcesPath,
		"--now", fixture.now.Format(time.RFC3339),
		"--runtime-dir", runtimeRoot,
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("stage failed: %v\n%s", err, out.String())
	}
	for _, want := range []string{"stage_status: staged", "plugin_key: demo", "revision: 1", "current_status: none"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("stage output %q missing %q", out.String(), want)
		}
	}
	store, err := crp.NewRuntimeStore(runtimeRoot, crp.RuntimeStoreOptions{
		Clock:       func() time.Time { return fixture.now },
		HealthCheck: crp.HealthCheckFunc(func(crp.RuntimeRecord) error { return nil }),
		Revalidate:  crp.RuntimeRevalidateFunc(func(crp.RuntimeRecord) error { return nil }),
	})
	if err != nil {
		t.Fatal(err)
	}
	staged, err := store.Staged("demo")
	if err != nil {
		t.Fatalf("read staged record: %v", err)
	}
	if staged.Slot != crp.RuntimeSlotStaged || staged.Version != "1.0.0" {
		t.Fatalf("unexpected staged record: %+v", staged)
	}
	if _, err := store.Current("demo"); !errors.Is(err, crp.ErrRuntimeNotFound) {
		t.Fatalf("stage activated current slot: %v", err)
	}
}

func TestCRPStageRejectsConfirmationRequiredPackageByDefault(t *testing.T) {
	fixture := writeCRPStageFixture(t, crp.SignerCommunity)
	runtimeRoot := filepath.Join(t.TempDir(), "crp-runtime")
	cmd := newRootCommand()
	cmd.SetArgs([]string{
		"crp", "stage",
		"--package", fixture.packagePath,
		"--trust-roots", fixture.rootsPath,
		"--sources", fixture.sourcesPath,
		"--now", fixture.now.Format(time.RFC3339),
		"--runtime-dir", runtimeRoot,
	})
	err := cmd.Execute()
	if !errors.Is(err, crp.ErrConfirmationRequired) {
		t.Fatalf("expected confirmation-required error, got %v", err)
	}
	if _, statErr := os.Stat(runtimeRoot); !os.IsNotExist(statErr) {
		t.Fatalf("confirmation failure should not create runtime state, stat=%v", statErr)
	}
}

func TestCRPStageDoesNotExposeConfirmationBypass(t *testing.T) {
	cmd := newRootCommand()
	cmd.SetArgs([]string{"crp", "stage", "--allow-confirmation"})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "unknown flag") {
		t.Fatalf("confirmation bypass flag unexpectedly accepted: %v", err)
	}
}

type crpStageFixture struct {
	now         time.Time
	packagePath string
	rootsPath   string
	sourcesPath string
}

func writeCRPStageFixture(t *testing.T, class crp.SignerClass) crpStageFixture {
	t.Helper()
	dir := t.TempDir()
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	artifact := []byte("demo artifact")
	keyCount := 2
	if class == crp.SignerOfficial {
		keyCount = 3
	}
	keys := make([]ed25519.PrivateKey, keyCount)
	trustKeys := make([]crp.TrustKey, keyCount)
	for i := range keys {
		_, keys[i], _ = ed25519.GenerateKey(rand.Reader)
		trustKeys[i] = crp.TrustKey{ID: "stage-key-" + string(rune('a'+i)), PublicKey: keys[i].Public().(ed25519.PublicKey), Class: class}
	}
	namespace := "official/demo"
	if class == crp.SignerCommunity {
		namespace = "community/acme/demo"
	}
	manifest := crp.Manifest{
		APIVersion:      crp.APIVersion,
		Kind:            crp.Kind,
		Name:            "demo",
		PluginID:        "demo",
		Version:         "1.0.0",
		Namespace:       namespace,
		Source:          "offline",
		SourceRoot:      "stage-root-v1",
		ReleaseSequence: 1,
		Artifact:        crp.Artifact{Name: "demo.bin", Size: int64(len(artifact)), Digests: crp.ComputeDigests(artifact)},
	}
	sigs := make([]crp.Signature, 0, len(keys))
	signCount := len(keys)
	if class == crp.SignerOfficial {
		signCount = 2
	}
	for i := 0; i < signCount; i++ {
		key := keys[i]
		sig, err := crp.SignManifestWithKeyID(manifest, trustKeys[i].ID, key, now)
		if err != nil {
			t.Fatal(err)
		}
		sigs = append(sigs, sig)
	}
	rawManifest, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	rawSigs, err := json.Marshal(sigs)
	if err != nil {
		t.Fatal(err)
	}
	archive := makeCRPStageArchive(t, map[string][]byte{
		"manifest.json":            rawManifest,
		"artifact/demo.bin":        artifact,
		"signatures/manifest.json": rawSigs,
	})
	packagePath := filepath.Join(dir, "demo.crp")
	if err := os.WriteFile(packagePath, archive, 0o600); err != nil {
		t.Fatal(err)
	}
	root := crp.TrustRoot{
		ID:                "stage-root-v1",
		Class:             class,
		NamespacePrefixes: []string{namespace},
		Keys:              trustKeys,
		Policy:            crp.SignaturePolicy{Threshold: 2, Total: 2},
		HighRiskPolicy:    crp.SignaturePolicy{Threshold: 2, Total: 2},
	}
	if class == crp.SignerOfficial {
		root.NamespacePrefixes = []string{"official/"}
		root.Policy = crp.SignaturePolicy{Threshold: 2, Total: 3}
		root.HighRiskPolicy = crp.SignaturePolicy{Threshold: 3, Total: 5}
	}
	roots, err := json.Marshal([]crp.TrustRoot{root})
	if err != nil {
		t.Fatal(err)
	}
	sources, err := json.Marshal([]crp.SourceRootRegistration{{ID: root.ID, NamespacePrefixes: root.NamespacePrefixes, Sources: []string{"offline"}}})
	if err != nil {
		t.Fatal(err)
	}
	rootsPath := filepath.Join(dir, "roots.json")
	sourcesPath := filepath.Join(dir, "sources.json")
	if err := os.WriteFile(rootsPath, roots, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sourcesPath, sources, 0o600); err != nil {
		t.Fatal(err)
	}
	return crpStageFixture{now: now, packagePath: packagePath, rootsPath: rootsPath, sourcesPath: sourcesPath}
}

func makeCRPStageArchive(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	for name, data := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}
