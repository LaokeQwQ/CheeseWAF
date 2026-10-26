//go:build !windows

package activation

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/duckdb"
	"github.com/LaokeQwQ/CheeseWAF/internal/plugin/hostapi"
)

func buildDuckDBRunner(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test source")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
	directory := canonicalSecureTestDirectory(t)
	output := filepath.Join(directory, "cheesewaf-duckdb-runner")
	command := exec.Command("go", "build", "-o", output, "./cmd/cheesewaf-duckdb-runner")
	command.Dir = root
	if data, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build DuckDB runner: %v\n%s", err, data)
	}
	if err := os.Chmod(output, 0o700); err != nil {
		t.Fatal(err)
	}
	return output
}

func TestDuckDBRunnerExecutesJob(t *testing.T) {
	executable := buildDuckDBRunner(t)
	directory := canonicalSecureTestDirectory(t)
	fakeDuckDB := filepath.Join(directory, "duckdb")
	if err := os.WriteFile(fakeDuckDB, []byte("#!/bin/sh\nprintf '%s' '[{\"severity\":\"high\",\"subject_hash\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"count\":2}]'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	identity := ProcessSidecarIdentity{
		PluginID: "duckdb-analysis", Namespace: "official/duckdb", Version: "1.0.0",
		ManifestIdentity: strings.Repeat("e", 64), ArtifactIdentity: strings.Repeat("f", 64),
	}
	entry := ProcessSidecarRegistryEntry{
		Identity: identity, Executable: executable, WorkingDirectory: filepath.Dir(executable),
		Environment: map[string]string{"CHEESEWAF_DUCKDB_BIN": fakeDuckDB},
	}
	backend, err := NewProcessSidecarBackend(ProcessSidecarBackendOptions{
		Registry:  []ProcessSidecarRegistryEntry{entry},
		Admission: allowProcessSidecarTestAdmission,
		DataPlaneFactory: func(id ProcessSidecarIdentity, hostToPlugin, pluginToHost *os.File) (ProcessDataPlane, error) {
			return hostapi.NewSession(pluginToHost, hostToPlugin, hostapi.SessionOptions{
				Identity: hostapi.Identity{
					PluginID: id.PluginID, Namespace: id.Namespace, Version: id.Version,
					ManifestIdentity: id.ManifestIdentity, ArtifactIdentity: id.ArtifactIdentity,
				},
				Capabilities: []hostapi.Capability{
					hostapi.CapabilityAnalysisSubmit, hostapi.CapabilityHealth, hostapi.CapabilityConfigRead,
				},
			})
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close(context.Background())

	descriptor := SidecarDescriptor{
		PluginID: identity.PluginID, Runtime: "sidecar", Version: identity.Version,
		Namespace: identity.Namespace, Source: "offline", SourceRoot: "root",
		ManifestIdentity: identity.ManifestIdentity, ArtifactIdentity: identity.ArtifactIdentity,
		Capabilities: []string{"observe", "health"},
	}
	target := RuntimeTarget{
		Key: identity.PluginID, PluginID: identity.PluginID, Namespace: identity.Namespace,
		Version: identity.Version, ReleaseSequence: 1,
		ManifestIdentity: identity.ManifestIdentity, ArtifactIdentity: identity.ArtifactIdentity, Revision: 1,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	process, err := backend.Start(ctx, SidecarLaunchSpec{Descriptor: descriptor, Target: target})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	defer process.Stop(context.Background())
	session := process.(*processSidecarProcess).DataPlane().(*hostapi.Session)

	template, err := duckdb.LoadTemplate("duckdb-template:security-summary-v1", []byte(`SELECT severity, subject_hash, "count" FROM audit_events WHERE occurred_at >= ? AND occurred_at < ?`))
	if err != nil {
		t.Fatal(err)
	}
	job := map[string]any{
		"snapshot_ref": "snapshot-1", "snapshot_manifest_sha256": strings.Repeat("b", 64),
		"snapshot_paths": []string{"/sandbox/snapshot/a.parquet"},
		"template_id":    template.ID, "template_sql": template.SQL, "template_sha256": template.SHA256,
		"window_from": "2026-10-24T11:00:00Z", "window_to": "2026-10-24T12:00:00Z",
		"engine_version": "1.3.0", "execution_profile_ref": "duckdb-read-only-snapshot-v1",
		"execution_profile_sha256": strings.Repeat("c", 64),
	}
	raw, err := json.Marshal(job)
	if err != nil {
		t.Fatal(err)
	}
	if err := session.SendJob(ctx, raw); err != nil {
		t.Fatalf("send job: %v", err)
	}
	select {
	case result := <-session.Results():
		if result.Kind != hostapi.ResultAnalysis {
			t.Fatalf("result = %#v", result)
		}
		var record map[string]any
		if err := json.Unmarshal(result.Payload, &record); err != nil {
			t.Fatal(err)
		}
		if record["plugin_id"] != "duckdb-analysis" {
			t.Fatalf("record = %#v", record)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for analysis record")
	}
}
