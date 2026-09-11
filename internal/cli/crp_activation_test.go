package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/crp"
	"github.com/LaokeQwQ/CheeseWAF/internal/crp/activation"
)

func TestCRPActivationCommandsExposeTransportSafetyInputs(t *testing.T) {
	for _, operation := range []string{"activate", "rollback"} {
		t.Run(operation, func(t *testing.T) {
			cmd := newRootCommand()
			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&out)
			cmd.SetArgs([]string{"crp", operation, "--help"})
			if err := cmd.Execute(); err != nil {
				t.Fatalf("help failed: %v", err)
			}
			help := out.String()
			for _, want := range []string{
				"--runtime-dir", "--trust-roots", "--sources", "--now", "--descriptor",
				"--plugin", "--expected-revision", "--cluster-id", "--node-id",
				"--control-plane", "--sidecar", "--tls-ca", "--tls-cert", "--tls-key",
				"--transport-timeout", "--operation-timeout", "--observe-probes", "--canary-probes",
			} {
				if !strings.Contains(help, want) {
					t.Fatalf("help output %q missing %q", help, want)
				}
			}
			for _, forbidden := range []string{"--fence-token", "--epoch", "--fence-revision", "--confirm-id", "--confirm-actor", "--allow-confirmation"} {
				if strings.Contains(help, forbidden) {
					t.Fatalf("help output unexpectedly exposes raw authority input %q", forbidden)
				}
			}
		})
	}
}

func TestCRPActivateFailsClosedWithoutControlPlaneOrSidecar(t *testing.T) {
	fixture := writeCRPStageFixture(t, crp.SignerOfficial)
	runtimeRoot := filepath.Join(t.TempDir(), "crp-runtime")
	stage := newRootCommand()
	stage.SetArgs([]string{"crp", "stage", "--package", fixture.packagePath, "--trust-roots", fixture.rootsPath, "--sources", fixture.sourcesPath, "--now", fixture.now.Format(time.RFC3339), "--runtime-dir", runtimeRoot})
	if err := stage.Execute(); err != nil {
		t.Fatalf("stage failed: %v", err)
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
		t.Fatal(err)
	}
	descriptorPath := writeActivationDescriptor(t, staged, "offline", "stage-root-v1")
	cmd := newRootCommand()
	cmd.SetArgs([]string{
		"crp", "activate", "--runtime-dir", runtimeRoot,
		"--trust-roots", fixture.rootsPath, "--sources", fixture.sourcesPath,
		"--now", fixture.now.Format(time.RFC3339), "--descriptor", descriptorPath,
		"--plugin", "demo", "--expected-revision", "1", "--cluster-id", "cluster-a",
	})
	err = cmd.Execute()
	if !errors.Is(err, activation.ErrControlPlaneUnavailable) {
		t.Fatalf("activate err=%v, want control-plane unavailable", err)
	}
	if _, err := store.Staged("demo"); err != nil {
		t.Fatalf("staged record was removed: %v", err)
	}
	if _, err := store.Current("demo"); !errors.Is(err, crp.ErrRuntimeNotFound) {
		t.Fatalf("activation created current record: %v", err)
	}
}

func TestCRPActivateVerifiesTrustAndSourceBeforeUnavailableAdapters(t *testing.T) {
	fixture := writeCRPStageFixture(t, crp.SignerOfficial)
	runtimeRoot := filepath.Join(t.TempDir(), "missing-runtime")
	descriptorPath := filepath.Join(t.TempDir(), "descriptor.json")
	if err := os.WriteFile(descriptorPath, []byte(`{"plugin_id":"demo","runtime":"sidecar"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	badRoots := filepath.Join(t.TempDir(), "bad-roots.json")
	if err := os.WriteFile(badRoots, []byte(`{"bad":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := newRootCommand()
	cmd.SetArgs([]string{
		"crp", "activate", "--runtime-dir", runtimeRoot,
		"--trust-roots", badRoots, "--sources", fixture.sourcesPath,
		"--now", fixture.now.Format(time.RFC3339), "--descriptor", descriptorPath,
		"--plugin", "demo", "--expected-revision", "1", "--cluster-id", "cluster-a",
	})
	err := cmd.Execute()
	if err == nil || errors.Is(err, activation.ErrControlPlaneUnavailable) {
		t.Fatalf("verification was not performed before unavailable adapter error: %v", err)
	}
	if _, statErr := os.Stat(runtimeRoot); !os.IsNotExist(statErr) {
		t.Fatalf("verification failure should not create runtime directory, stat=%v", statErr)
	}
}

func TestCRPActivationRejectsLegacyAuthorityFlags(t *testing.T) {
	for _, operation := range []string{"activate", "rollback"} {
		cmd := newRootCommand()
		cmd.SetArgs([]string{"crp", operation, "--fence-token", "injected"})
		if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "unknown flag") {
			t.Fatalf("%s accepted a legacy fence flag: %v", operation, err)
		}
	}
}

func TestCRPActivationRejectsWhitespaceIdentity(t *testing.T) {
	cmd := newRootCommand()
	cmd.SetArgs([]string{"crp", "activate", "--runtime-dir", "/tmp/runtime", "--trust-roots", "/tmp/roots", "--sources", "/tmp/sources", "--now", "2026-09-08T12:00:00Z", "--descriptor", "/tmp/descriptor", "--plugin", " demo", "--expected-revision", "1", "--cluster-id", "cluster-a"})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "strict non-whitespace ASCII identity") {
		t.Fatalf("whitespace identity error=%v", err)
	}
}

func TestCRPActivateRejectsDescriptorSourceBeforeTransport(t *testing.T) {
	fixture := writeCRPStageFixture(t, crp.SignerOfficial)
	runtimeRoot := filepath.Join(t.TempDir(), "crp-runtime")
	stage := newRootCommand()
	stage.SetArgs([]string{"crp", "stage", "--package", fixture.packagePath, "--trust-roots", fixture.rootsPath, "--sources", fixture.sourcesPath, "--now", fixture.now.Format(time.RFC3339), "--runtime-dir", runtimeRoot})
	if err := stage.Execute(); err != nil {
		t.Fatal(err)
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
		t.Fatal(err)
	}
	descriptorPath := writeActivationDescriptor(t, staged, "peer", "stage-root-v1")
	cmd := newRootCommand()
	cmd.SetArgs([]string{
		"crp", "activate", "--runtime-dir", runtimeRoot,
		"--trust-roots", fixture.rootsPath, "--sources", fixture.sourcesPath,
		"--now", fixture.now.Format(time.RFC3339), "--descriptor", descriptorPath,
		"--plugin", "demo", "--expected-revision", "1", "--cluster-id", "cluster-a",
	})
	err = cmd.Execute()
	if !errors.Is(err, activation.ErrInvalidDescriptor) || errors.Is(err, activation.ErrControlPlaneUnavailable) {
		t.Fatalf("descriptor source mismatch error=%v, want ErrInvalidDescriptor before transport", err)
	}
}

func TestSelectCRPRollbackRecordUsesCurrentRevisionForCAS(t *testing.T) {
	reader := staticCRPActivationRuntimeReader{
		current:  crp.RuntimeRecord{Key: "demo", Revision: 8, Version: "2.0.0"},
		previous: crp.RuntimeRecord{Key: "demo", Revision: 4, Version: "1.0.0"},
	}
	target, err := selectCRPActivationRecord(reader, crpActivationActionRollback, "demo", 8)
	if err != nil {
		t.Fatal(err)
	}
	if target.Version != "1.0.0" || target.Revision != 4 {
		t.Fatalf("rollback target=%+v, want previous record", target)
	}
	if _, err := selectCRPActivationRecord(reader, crpActivationActionRollback, "demo", 4); !errors.Is(err, crp.ErrRuntimeConflict) {
		t.Fatalf("previous revision accepted as rollback CAS: %v", err)
	}
}

type staticCRPActivationRuntimeReader struct {
	current  crp.RuntimeRecord
	staged   crp.RuntimeRecord
	previous crp.RuntimeRecord
}

func (r staticCRPActivationRuntimeReader) Current(string) (crp.RuntimeRecord, error) {
	return r.current, nil
}

func (r staticCRPActivationRuntimeReader) Staged(string) (crp.RuntimeRecord, error) {
	return r.staged, nil
}

func (r staticCRPActivationRuntimeReader) Previous(string) (crp.RuntimeRecord, error) {
	return r.previous, nil
}

func writeActivationDescriptor(t *testing.T, record crp.RuntimeRecord, source, sourceRoot string) string {
	t.Helper()
	descriptor := activation.SidecarDescriptor{
		PluginID:         record.PluginID,
		Runtime:          "sidecar",
		Version:          record.Version,
		ManifestIdentity: record.ManifestIdentity,
		ArtifactIdentity: record.ArtifactIdentity,
		Namespace:        record.Namespace,
		Source:           source,
		SourceRoot:       sourceRoot,
		Capabilities:     []string{"observe"},
	}
	raw, err := json.Marshal(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "descriptor.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
