//go:build !windows

package activation

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/plugin/hostapi"
)

func conformanceEntry(executable, pluginID string, crash bool) ProcessSidecarRegistryEntry {
	environment := map[string]string{}
	if crash {
		environment["CHEESEWAF_CONFORMANCE_CRASH"] = "1"
	}
	return ProcessSidecarRegistryEntry{
		Identity: ProcessSidecarIdentity{
			PluginID: pluginID, Namespace: "official/" + pluginID, Version: "1.0.0",
			ManifestIdentity: strings.Repeat("a", 64), ArtifactIdentity: strings.Repeat("b", 64),
		},
		Executable: executable, WorkingDirectory: filepath.Dir(executable), Environment: environment,
	}
}

func conformanceSpec(entry ProcessSidecarRegistryEntry) SidecarLaunchSpec {
	descriptor := SidecarDescriptor{
		PluginID: entry.Identity.PluginID, Runtime: "sidecar", Version: entry.Identity.Version,
		Namespace: entry.Identity.Namespace, Source: "offline", SourceRoot: "root",
		ManifestIdentity: entry.Identity.ManifestIdentity, ArtifactIdentity: entry.Identity.ArtifactIdentity,
		Capabilities: []string{"observe", "hint", "health"},
	}
	target := RuntimeTarget{
		Key: entry.Identity.PluginID, PluginID: entry.Identity.PluginID, Namespace: entry.Identity.Namespace,
		Version: entry.Identity.Version, ReleaseSequence: 1,
		ManifestIdentity: entry.Identity.ManifestIdentity, ArtifactIdentity: entry.Identity.ArtifactIdentity, Revision: 1,
	}
	return SidecarLaunchSpec{Descriptor: descriptor, Target: target}
}

func TestProcessDataPlaneCrashIsIsolated(t *testing.T) {
	executable := buildConformancePlugin(t)
	crashEntry := conformanceEntry(executable, "conformance-crash", true)
	normalEntry := conformanceEntry(executable, "conformance-normal", false)
	backend, err := NewProcessSidecarBackend(ProcessSidecarBackendOptions{
		Registry:  []ProcessSidecarRegistryEntry{crashEntry, normalEntry},
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

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	crashProcess, err := backend.Start(ctx, conformanceSpec(crashEntry))
	if err != nil {
		t.Fatalf("start crash plugin: %v", err)
	}
	crashConcrete := crashProcess.(*processSidecarProcess)
	crashSession := crashConcrete.DataPlane().(*hostapi.Session)
	crashCtx, crashCancel := context.WithTimeout(ctx, 2*time.Second)
	defer crashCancel()
	if err := crashSession.SendEvent(crashCtx, json.RawMessage(`{"event_id":"crash"}`)); err == nil {
		t.Fatal("crash plugin unexpectedly acknowledged the event")
	}
	select {
	case <-crashConcrete.done:
	case <-time.After(2 * time.Second):
		t.Fatal("crash plugin process was not reaped")
	}

	normalProcess, err := backend.Start(ctx, conformanceSpec(normalEntry))
	if err != nil {
		t.Fatalf("start normal plugin after crash: %v", err)
	}
	defer normalProcess.Stop(context.Background())
	normalConcrete := normalProcess.(*processSidecarProcess)
	normalSession := normalConcrete.DataPlane().(*hostapi.Session)
	if err := normalSession.SendEvent(ctx, json.RawMessage(`{"event_id":"ok"}`)); err != nil {
		t.Fatalf("normal plugin event after crash: %v", err)
	}
	select {
	case result := <-normalSession.Results():
		if result.Kind != hostapi.ResultHint {
			t.Fatalf("normal result = %#v", result)
		}
	case <-ctx.Done():
		t.Fatal("normal plugin did not produce a hint")
	}
}
