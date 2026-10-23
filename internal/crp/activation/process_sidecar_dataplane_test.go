package activation

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/plugin/hostapi"
)

func buildConformancePlugin(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test source")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
	directory := canonicalSecureTestDirectory(t)
	output := filepath.Join(directory, "cheesewaf-plugin-conformance")
	command := exec.Command("go", "build", "-o", output, "./cmd/cheesewaf-plugin-conformance")
	command.Dir = root
	if data, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build conformance plugin: %v\n%s", err, data)
	}
	if err := os.Chmod(output, 0o700); err != nil {
		t.Fatal(err)
	}
	return output
}

func TestProcessDataPlaneRoundTrip(t *testing.T) {
	executable := buildConformancePlugin(t)
	identity := ProcessSidecarIdentity{
		PluginID: "conformance", Namespace: "official/conformance", Version: "1.0.0",
		ManifestIdentity: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ArtifactIdentity: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}
	entry := ProcessSidecarRegistryEntry{
		Identity: identity, Executable: executable,
		WorkingDirectory: filepath.Dir(executable), Environment: map[string]string{},
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
					hostapi.CapabilityEventsSubscribe, hostapi.CapabilityHintsSubmit,
					hostapi.CapabilityAnalysisSubmit, hostapi.CapabilityHealth,
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
		Capabilities: []string{"observe", "hint", "health"},
	}
	target := RuntimeTarget{
		Key: "conformance", PluginID: identity.PluginID, Namespace: identity.Namespace,
		Version: identity.Version, ReleaseSequence: 1,
		ManifestIdentity: identity.ManifestIdentity, ArtifactIdentity: identity.ArtifactIdentity, Revision: 1,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	process, err := backend.Start(ctx, SidecarLaunchSpec{Descriptor: descriptor, Target: target})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	defer process.Stop(context.Background())

	concrete, ok := process.(*processSidecarProcess)
	if !ok {
		t.Fatalf("process type = %T", process)
	}
	dataPlane := concrete.DataPlane()
	if dataPlane == nil {
		t.Fatal("data plane was not attached")
	}
	session, ok := dataPlane.(*hostapi.Session)
	if !ok {
		t.Fatalf("data plane type = %T", dataPlane)
	}

	if err := session.SendEvent(ctx, json.RawMessage(`{"event_id":"evt-1"}`)); err != nil {
		t.Fatalf("send event: %v", err)
	}
	select {
	case result := <-session.Results():
		if result.Kind != hostapi.ResultHint {
			t.Fatalf("result = %#v", result)
		}
		if err := session.SendHintReceipt(ctx, result.Sequence, true, ""); err != nil {
			t.Fatalf("send receipt: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for hint")
	}
	if err := process.Stop(ctx); err != nil {
		t.Fatalf("stop: %v", err)
	}
}
