package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/crp"
	"github.com/spf13/cobra"
)

var (
	crpVerifyPackage    string
	crpVerifyTrustRoots string
	crpVerifySources    string
	crpVerifyNow        string
)

const (
	crpVerifyMaxArchiveBytes = int64(1 << 30)
	crpVerifyMaxJSONBytes    = int64(1 << 20)
)

func newCRPCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "crp", Short: "Inspect and verify CRP packages"}
	verify := &cobra.Command{Use: "verify", Short: "Verify a local CRP package without installing or activating it", Args: cobra.NoArgs, RunE: runCRPVerify}
	verify.Flags().StringVar(&crpVerifyPackage, "package", "", "Path to a local .crp ZIP archive")
	verify.Flags().StringVar(&crpVerifyTrustRoots, "trust-roots", "", "JSON file containing explicit trust roots")
	verify.Flags().StringVar(&crpVerifySources, "sources", "", "JSON file containing explicit source registrations")
	verify.Flags().StringVar(&crpVerifyNow, "now", "", "RFC3339 verification time")
	cmd.AddCommand(verify)
	cmd.AddCommand(newCRPActivateCommand())
	cmd.AddCommand(newCRPRollbackCommand())
	return cmd
}

func runCRPVerify(cmd *cobra.Command, _ []string) error {
	packagePath := strings.TrimSpace(crpVerifyPackage)
	trustPath := strings.TrimSpace(crpVerifyTrustRoots)
	sourcesPath := strings.TrimSpace(crpVerifySources)
	nowText := strings.TrimSpace(crpVerifyNow)
	if packagePath == "" {
		return errors.New("--package is required")
	}
	if trustPath == "" {
		return errors.New("--trust-roots is required; default trust is disabled")
	}
	if sourcesPath == "" {
		return errors.New("--sources is required; default sources are disabled")
	}
	if nowText == "" {
		return errors.New("--now is required")
	}
	now, err := time.Parse(time.RFC3339, nowText)
	if err != nil {
		return fmt.Errorf("parse --now: %w", err)
	}
	archive, err := readBoundedFile(packagePath, crpVerifyMaxArchiveBytes)
	if err != nil {
		return fmt.Errorf("read CRP package: %w", err)
	}
	pkg, err := crp.ParseArchive(archive, crp.ArchiveOptions{MaxFiles: 64, MaxTotalBytes: crpVerifyMaxArchiveBytes, MaxManifestBytes: crpVerifyMaxJSONBytes, MaxArtifactBytes: crpVerifyMaxArchiveBytes, MaxSignaturesBytes: crpVerifyMaxJSONBytes})
	if err != nil {
		return err
	}
	roots, err := loadTrustRoots(trustPath)
	if err != nil {
		return err
	}
	registrations, err := loadSourceRegistrations(sourcesPath)
	if err != nil {
		return err
	}
	trust, err := crp.NewTrustStore(roots)
	if err != nil {
		return err
	}
	registry, err := crp.NewSourceRegistry(registrations)
	if err != nil {
		return err
	}
	result, err := crp.Import(pkg, crp.ImportOptions{MaxManifestBytes: crpVerifyMaxJSONBytes, MaxArtifactBytes: crpVerifyMaxArchiveBytes, SourceRegistry: registry, TrustStore: trust, Now: now})
	if err != nil {
		return err
	}
	out := cmd.OutOrStdout()
	_, _ = fmt.Fprintf(out, "manifest_identity: %s\n", result.ContentIdentity)
	_, _ = fmt.Fprintf(out, "signature_status: %s\n", result.SignatureReport.Status)
	_, _ = fmt.Fprintf(out, "artifact_size: %d\n", result.ArtifactSize)
	return nil
}

func readJSONFile(path string) ([]byte, error) {
	data, err := readBoundedFile(path, crpVerifyMaxJSONBytes)
	if err != nil {
		return nil, fmt.Errorf("read JSON file: %w", err)
	}
	return data, nil
}

func readBoundedFile(name string, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		return nil, errors.New("file size limit must be positive")
	}
	info, err := os.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", name)
	}
	if info.Size() > maxBytes {
		return nil, fmt.Errorf("%s exceeds size limit of %d bytes", name, maxBytes)
	}
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("%s exceeds size limit of %d bytes", name, maxBytes)
	}
	return data, nil
}

func decodeStrict(data []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			return errors.New("trailing JSON data")
		}
		return err
	}
	return nil
}

func loadTrustRoots(path string) ([]crp.TrustRoot, error) {
	data, err := readJSONFile(path)
	if err != nil {
		return nil, err
	}
	var roots []crp.TrustRoot
	if err := decodeStrict(data, &roots); err == nil {
		return roots, nil
	}
	var wrapper struct {
		TrustRoots []crp.TrustRoot `json:"trust_roots"`
	}
	if err := decodeStrict(data, &wrapper); err != nil {
		return nil, fmt.Errorf("parse trust roots JSON: %w", err)
	}
	return wrapper.TrustRoots, nil
}

func loadSourceRegistrations(path string) ([]crp.SourceRootRegistration, error) {
	data, err := readJSONFile(path)
	if err != nil {
		return nil, err
	}
	var registrations []crp.SourceRootRegistration
	if err := decodeStrict(data, &registrations); err == nil {
		return registrations, nil
	}
	var wrapper struct {
		Sources []crp.SourceRootRegistration `json:"sources"`
	}
	if err := decodeStrict(data, &wrapper); err != nil {
		return nil, fmt.Errorf("parse sources JSON: %w", err)
	}
	return wrapper.Sources, nil
}
