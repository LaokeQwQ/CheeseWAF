package activation

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/edr"
	"github.com/LaokeQwQ/CheeseWAF/internal/plugin/hostapi"
)

func buildEDRSidecar(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test source")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
	directory := canonicalSecureTestDirectory(t)
	output := filepath.Join(directory, "cheesewaf-edr-sidecar")
	command := exec.Command("go", "build", "-o", output, "./cmd/cheesewaf-edr-sidecar")
	command.Dir = root
	if data, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build EDR sidecar: %v\n%s", err, data)
	}
	if err := os.Chmod(output, 0o700); err != nil {
		t.Fatal(err)
	}
	return output
}

func TestEDRSidecarEmitsAuthBurstHint(t *testing.T) {
	executable := buildEDRSidecar(t)
	identity := ProcessSidecarIdentity{
		PluginID: edr.PluginID, Namespace: "official/edr", Version: edr.PluginVersion,
		ManifestIdentity: strings.Repeat("c", 64), ArtifactIdentity: strings.Repeat("d", 64),
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
					hostapi.CapabilityHealth, hostapi.CapabilityConfigRead,
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
		Capabilities: []string{"observe", "hint", "health", "candidate_snapshot"},
	}
	target := RuntimeTarget{
		Key: edr.PluginID, PluginID: identity.PluginID, Namespace: identity.Namespace,
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

	if err := session.SendConfig(ctx, hostapi.Config{Revision: 1, Values: map[string]any{"policy_epoch": 7}}); err != nil {
		t.Fatalf("config: %v", err)
	}
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	// Exceed the client's 64-receipt buffer so a missing consumer fails here.
	for subject := range 66 {
		for i := range 10 {
			event := edr.Event{
				EventID: fmt.Sprintf("evt-%d-%d", subject, i), EventType: "auth_failure",
				ObservedAt: now.Add(time.Duration(i) * time.Second),
				TenantRef:  "tenant-1", SiteRef: "site-1", RouteRef: "/login",
				SubjectHash: fmt.Sprintf("%064x", subject+1), Severity: "medium", Count: 1,
				WindowSeconds: 60, EvidenceRefs: []string{"evidence:evt"},
			}
			raw, err := json.Marshal(event)
			if err != nil {
				t.Fatal(err)
			}
			if err := session.SendEvent(ctx, raw); err != nil {
				t.Fatalf("subject %d event %d: %v", subject, i, err)
			}
		}
		select {
		case hint := <-session.Results():
			if hint.Kind != hostapi.ResultHint {
				t.Fatalf("subject %d: no hint produced: %#v", subject, hint)
			}
			var decoded map[string]any
			if err := json.Unmarshal(hint.Payload, &decoded); err != nil {
				t.Fatal(err)
			}
			if decoded["plugin_id"] != edr.PluginID || decoded["policy_epoch"] != float64(7) {
				t.Fatalf("hint = %#v", decoded)
			}
			if err := session.SendHintReceipt(ctx, hint.Sequence, true, ""); err != nil {
				t.Fatalf("subject %d receipt: %v", subject, err)
			}
		case <-ctx.Done():
			t.Fatalf("subject %d: timed out waiting for hint", subject)
		}
	}
}
