package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/crp/activation"
)

const productionProcessSidecarHelperEnvironment = "CHEESEWAF_PRODUCTION_PROCESS_SIDECAR_HELPER"

// TestProductionProcessSidecarHelper is deliberately a real child process.
// The parent only gives it an explicit, registry-defined environment.
func TestProductionProcessSidecarHelper(t *testing.T) {
	if os.Getenv(productionProcessSidecarHelperEnvironment) != "1" {
		return
	}
	reader := bufio.NewReader(os.Stdin)
	wantSequence := uint64(1)
	mode := activation.SidecarModeObserve
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			os.Exit(91)
		}
		var request productionProcessSidecarHelperRequest
		decoder := json.NewDecoder(strings.NewReader(string(line)))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&request); err != nil || request.SchemaVersion != "cheesewaf-crp-sidecar-process.v1" || request.Sequence != wantSequence {
			os.Exit(92)
		}
		wantSequence++
		switch request.Operation {
		case "start":
			if request.Sequence != 1 || request.Mode != activation.SidecarModeObserve {
				os.Exit(93)
			}
		case "mode":
			if mode == activation.SidecarModeObserve && request.Mode != activation.SidecarModeCanary || mode == activation.SidecarModeCanary && request.Mode != activation.SidecarModeActive || mode == activation.SidecarModeActive {
				os.Exit(93)
			}
			mode = request.Mode
		case "probe", "stop":
			if request.Mode != mode {
				os.Exit(93)
			}
		default:
			os.Exit(93)
		}
		acknowledgement := productionProcessSidecarHelperAcknowledgement{
			SchemaVersion: request.SchemaVersion,
			Sequence:      request.Sequence,
			Operation:     request.Operation,
			Status:        "ok",
			Mode:          mode,
		}
		if err := json.NewEncoder(os.Stdout).Encode(acknowledgement); err != nil {
			os.Exit(94)
		}
		if request.Operation == "stop" {
			os.Exit(0)
		}
	}
}

type productionProcessSidecarHelperRequest struct {
	SchemaVersion string                 `json:"schema_version"`
	Sequence      uint64                 `json:"sequence"`
	Operation     string                 `json:"operation"`
	Mode          activation.SidecarMode `json:"mode"`
	Identity      struct {
		PluginID         string `json:"plugin_id"`
		Namespace        string `json:"namespace"`
		Version          string `json:"version"`
		ManifestIdentity string `json:"manifest_identity"`
		ArtifactIdentity string `json:"artifact_identity"`
	} `json:"identity"`
}

type productionProcessSidecarHelperAcknowledgement struct {
	SchemaVersion string                 `json:"schema_version"`
	Sequence      uint64                 `json:"sequence"`
	Operation     string                 `json:"operation"`
	Status        string                 `json:"status"`
	Mode          activation.SidecarMode `json:"mode"`
}

func TestOpenProductionProcessSidecarBackendRejectsUnsafeRegistryInput(t *testing.T) {
	base := secureProductionProcessSidecarRegistryDirectory(t)
	valid := productionProcessSidecarRegistryJSON(t)

	tests := []struct {
		name  string
		path  string
		write func(string) error
	}{
		{
			name: "unknown field",
			path: filepath.Join(base, "unknown.json"),
			write: func(path string) error {
				return os.WriteFile(path, productionProcessSidecarRegistryWithTopLevelField(t, valid, `"command":"/bin/sh"`), 0o600)
			},
		},
		{
			name: "trailing JSON value",
			path: filepath.Join(base, "trailing.json"),
			write: func(path string) error {
				return os.WriteFile(path, append(valid, []byte("\n{}")...), 0o600)
			},
		},
		{
			name: "wrong schema version",
			path: filepath.Join(base, "schema.json"),
			write: func(path string) error {
				return os.WriteFile(path, []byte(strings.Replace(string(valid), productionProcessSidecarRegistrySchema, "cheesewaf-crp-process-sidecar-registry.v0", 1)), 0o600)
			},
		},
		{
			name: "empty registry",
			path: filepath.Join(base, "empty.json"),
			write: func(path string) error {
				return os.WriteFile(path, []byte(`{"schema_version":"cheesewaf-crp-process-sidecar-registry.v1","entries":[]}`), 0o600)
			},
		},
		{
			name: "unsafe mode",
			path: filepath.Join(base, "unsafe-mode.json"),
			write: func(path string) error {
				if err := os.WriteFile(path, valid, 0o600); err != nil {
					return err
				}
				return os.Chmod(path, 0o622)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.write(test.path); err != nil {
				t.Fatal(err)
			}
			backend, err := openProductionProcessSidecarBackend(test.path)
			if backend != nil || err == nil || !errors.Is(err, ErrProductionCRPConfig) {
				t.Fatalf("openProductionProcessSidecarBackend() = backend:%v error:%v, want ErrProductionCRPConfig", backend, err)
			}
			if test.name == "unknown field" && !strings.Contains(err.Error(), "unknown field") {
				t.Fatalf("unknown field error=%v, want strict decoder rejection", err)
			}
		})
	}

	t.Run("symlink", func(t *testing.T) {
		target := filepath.Join(base, "target.json")
		if err := os.WriteFile(target, valid, 0o600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(base, "registry-link.json")
		if err := os.Symlink(target, link); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
		if backend, err := openProductionProcessSidecarBackend(link); backend != nil || err == nil || !errors.Is(err, ErrProductionCRPConfig) {
			t.Fatalf("openProductionProcessSidecarBackend() = backend:%v error:%v, want symlink rejection", backend, err)
		}
	})

	t.Run("relative path", func(t *testing.T) {
		if backend, err := openProductionProcessSidecarBackend("registry.json"); backend != nil || err == nil || !errors.Is(err, ErrProductionCRPConfig) {
			t.Fatalf("openProductionProcessSidecarBackend() = backend:%v error:%v, want relative path rejection", backend, err)
		}
	})

	t.Run("writable parent", func(t *testing.T) {
		parent := filepath.Join(base, "writable-parent")
		if err := os.Mkdir(parent, 0o700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(parent, "registry.json")
		if err := os.WriteFile(path, valid, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(parent, 0o722); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(parent, 0o700) })
		if backend, err := openProductionProcessSidecarBackend(path); backend != nil || err == nil || !errors.Is(err, ErrProductionCRPConfig) {
			t.Fatalf("openProductionProcessSidecarBackend() = backend:%v error:%v, want parent permission rejection", backend, err)
		}
	})
}

func TestProductionProcessSidecarAdmissionFailsClosedWithoutResourceContainment(t *testing.T) {
	if err := productionProcessSidecarAdmission(context.Background(), activation.ProcessSidecarAdmissionRequest{}); err != nil {
		t.Fatalf("zero resource request error = %v", err)
	}
	for _, resources := range []activation.ResourceRequest{
		{CPUmilli: 1},
		{MemoryBytes: 1},
		{PIDs: 1},
		{CPUmilli: -1},
	} {
		err := productionProcessSidecarAdmission(context.Background(), activation.ProcessSidecarAdmissionRequest{Resources: resources})
		if !errors.Is(err, activation.ErrProcessSidecarAdmission) {
			t.Fatalf("resources=%+v error=%v, want ErrProcessSidecarAdmission", resources, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := productionProcessSidecarAdmission(ctx, activation.ProcessSidecarAdmissionRequest{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled admission error=%v, want context.Canceled", err)
	}
}

func TestOpenProductionProcessSidecarBackendRunsRegisteredHelperProcess(t *testing.T) {
	directory := secureProductionProcessSidecarRegistryDirectory(t)
	path := filepath.Join(directory, "registry.json")
	if err := os.WriteFile(path, productionProcessSidecarRegistryJSON(t), 0o600); err != nil {
		t.Fatal(err)
	}
	backend, err := openProductionProcessSidecarBackend(path)
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close(t.Context())
	process, err := backend.Start(t.Context(), productionProcessSidecarLaunchSpec())
	if err != nil {
		t.Fatal(err)
	}
	if err := process.Probe(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := process.Stop(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func productionProcessSidecarRegistryJSON(t *testing.T) []byte {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Dir(executable)
	return []byte(`{
  "schema_version": "cheesewaf-crp-process-sidecar-registry.v1",
  "entries": [{
    "identity": {
      "plugin_id": "process-sidecar-test",
      "namespace": "default",
      "version": "1.0.0",
      "manifest_identity": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "artifact_identity": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    },
    "executable": "` + executable + `",
    "args": ["-test.run=^TestProductionProcessSidecarHelper$"],
    "working_directory": "` + directory + `",
    "environment": {"CHEESEWAF_PRODUCTION_PROCESS_SIDECAR_HELPER":"1"}
  }]
}`)
}

func productionProcessSidecarRegistryWithTopLevelField(t *testing.T, document []byte, field string) []byte {
	t.Helper()
	trimmed := strings.TrimSpace(string(document))
	if !strings.HasSuffix(trimmed, "}") {
		t.Fatal("registry fixture is not a JSON object")
	}
	return []byte(strings.TrimSuffix(trimmed, "}") + "," + field + "}")
}

func productionProcessSidecarLaunchSpec() activation.SidecarLaunchSpec {
	manifest := strings.Repeat("a", 64)
	artifact := strings.Repeat("b", 64)
	descriptor := activation.SidecarDescriptor{
		PluginID:         "process-sidecar-test",
		Runtime:          "sidecar",
		Namespace:        "default",
		Version:          "1.0.0",
		ManifestIdentity: manifest,
		ArtifactIdentity: artifact,
		Source:           "ota",
		SourceRoot:       "root",
		Capabilities:     []string{"observe"},
	}
	return activation.SidecarLaunchSpec{
		Descriptor: descriptor,
		Target: activation.RuntimeTarget{
			Key:              "process-sidecar-test",
			PluginID:         descriptor.PluginID,
			Namespace:        descriptor.Namespace,
			Version:          descriptor.Version,
			ReleaseSequence:  1,
			ManifestIdentity: descriptor.ManifestIdentity,
			ArtifactIdentity: descriptor.ArtifactIdentity,
			Revision:         1,
		},
	}
}

func secureProductionProcessSidecarRegistryDirectory(t *testing.T) string {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory
}
