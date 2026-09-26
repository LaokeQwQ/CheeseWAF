package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/crp/activation"
)

const (
	productionProcessSidecarRegistrySchema = "cheesewaf-crp-process-sidecar-registry.v1"
	productionProcessSidecarRegistryMax    = int64(1 << 20)
)

// productionProcessSidecarRegistryFile is deliberately separate from the
// activation package's runtime types. It is a startup-only, operator-managed
// allowlist; launcher requests never carry an executable, command, argument,
// environment, or working-directory field.
type productionProcessSidecarRegistryFile struct {
	SchemaVersion string                                      `json:"schema_version"`
	Entries       []productionProcessSidecarRegistryFileEntry `json:"entries"`
}

type productionProcessSidecarRegistryFileEntry struct {
	Identity         productionProcessSidecarRegistryIdentity `json:"identity"`
	Executable       string                                   `json:"executable"`
	Args             []string                                 `json:"args"`
	WorkingDirectory string                                   `json:"working_directory"`
	Environment      map[string]string                        `json:"environment"`
}

type productionProcessSidecarRegistryIdentity struct {
	PluginID         string `json:"plugin_id"`
	Namespace        string `json:"namespace"`
	Version          string `json:"version"`
	ManifestIdentity string `json:"manifest_identity"`
	ArtifactIdentity string `json:"artifact_identity"`
}

// openProductionProcessSidecarBackend loads the runtime-only process
// allowlist. NewProcessSidecarBackend then validates every converted entry
// again and revalidates launch paths immediately before every child process.
func openProductionProcessSidecarBackend(path string) (*activation.ProcessSidecarBackend, error) {
	var document productionProcessSidecarRegistryFile
	if err := readProductionProcessSidecarRegistry(path, &document); err != nil {
		return nil, fmt.Errorf("%w: read process sidecar registry: %v", ErrProductionCRPConfig, err)
	}
	if document.SchemaVersion != productionProcessSidecarRegistrySchema {
		return nil, fmt.Errorf("%w: process sidecar registry schema_version must be %q", ErrProductionCRPConfig, productionProcessSidecarRegistrySchema)
	}
	entries := make([]activation.ProcessSidecarRegistryEntry, 0, len(document.Entries))
	for _, entry := range document.Entries {
		entries = append(entries, activation.ProcessSidecarRegistryEntry{
			Identity: activation.ProcessSidecarIdentity{
				PluginID:         entry.Identity.PluginID,
				Namespace:        entry.Identity.Namespace,
				Version:          entry.Identity.Version,
				ManifestIdentity: entry.Identity.ManifestIdentity,
				ArtifactIdentity: entry.Identity.ArtifactIdentity,
			},
			Executable:       entry.Executable,
			Args:             append([]string(nil), entry.Args...),
			WorkingDirectory: entry.WorkingDirectory,
			Environment:      cloneProductionProcessSidecarEnvironment(entry.Environment),
		})
	}
	backend, err := activation.NewProcessSidecarBackend(activation.ProcessSidecarBackendOptions{
		Registry:  entries,
		Admission: productionProcessSidecarAdmission,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: process sidecar registry admission: %v", ErrProductionCRPConfig, err)
	}
	return backend, nil
}

func cloneProductionProcessSidecarEnvironment(environment map[string]string) map[string]string {
	if environment == nil {
		return nil
	}
	cloned := make(map[string]string, len(environment))
	for key, value := range environment {
		cloned[key] = value
	}
	return cloned
}

func readProductionProcessSidecarRegistry(path string, destination any) error {
	if path == "" || path != strings.TrimSpace(path) || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("registry path must be clean, absolute, and have no surrounding whitespace")
	}
	if err := validateProductionProcessSidecarRegistryPath(path); err != nil {
		return err
	}
	before, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect registry: %w", err)
	}
	if err := validateProductionProcessSidecarRegistryFileInfo(path, before); err != nil {
		return err
	}
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open registry: %w", err)
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat opened registry: %w", err)
	}
	if !os.SameFile(before, after) {
		return errors.New("registry changed while being opened")
	}
	if err := validateProductionProcessSidecarRegistryFileInfo(path, after); err != nil {
		return err
	}
	data, err := io.ReadAll(io.LimitReader(file, productionProcessSidecarRegistryMax+1))
	if err != nil {
		return fmt.Errorf("read registry: %w", err)
	}
	if int64(len(data)) > productionProcessSidecarRegistryMax {
		return fmt.Errorf("registry exceeds %d bytes", productionProcessSidecarRegistryMax)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode registry: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("registry contains a trailing JSON value")
		}
		return fmt.Errorf("decode registry trailing JSON: %w", err)
	}
	return nil
}

func validateProductionProcessSidecarRegistryPath(path string) error {
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("inspect registry path component %q: %w", current, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("registry path component %q is a symlink", current)
		}
		if current == path {
			if err := validateProductionProcessSidecarRegistryFileInfo(path, info); err != nil {
				return err
			}
		} else {
			if !info.IsDir() {
				return fmt.Errorf("registry parent %q is not a directory", current)
			}
			if info.Mode().Perm()&0o022 != 0 {
				return fmt.Errorf("registry parent %q is group/world writable (mode %04o)", current, info.Mode().Perm())
			}
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
	}
}

func validateProductionProcessSidecarRegistryFileInfo(path string, info os.FileInfo) error {
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("registry %q is not a regular file", path)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("registry %q is group/world writable (mode %04o)", path, info.Mode().Perm())
	}
	if info.Size() < 1 || info.Size() > productionProcessSidecarRegistryMax {
		return fmt.Errorf("registry %q must contain between 1 and %d bytes", path, productionProcessSidecarRegistryMax)
	}
	return nil
}

// productionProcessSidecarAdmission refuses resource requests because the
// portable ProcessSidecarBackend does not create cgroups, job objects, or
// another resource-enforcement boundary. It is used only by
// openProductionProcessSidecarBackend: that constructor has already passed
// entries through the backend's secure registry/path validation, and the
// backend creates and owns a dedicated process group for each accepted child.
func productionProcessSidecarAdmission(ctx context.Context, request activation.ProcessSidecarAdmissionRequest) error {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	if request.Resources != (activation.ResourceRequest{}) {
		return fmt.Errorf("%w: resource requests require an externally enforced containment provider", activation.ErrProcessSidecarAdmission)
	}
	return nil
}
