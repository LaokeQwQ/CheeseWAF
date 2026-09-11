package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/crp"
	"github.com/spf13/cobra"
)

const (
	crpStageMaxArchiveBytes = crpVerifyMaxArchiveBytes
	crpStageMaxJSONBytes    = crpVerifyMaxJSONBytes
)

type crpStageOptions struct {
	packagePath    string
	trustRootsPath string
	sourcesPath    string
	runtimeDir     string
	now            time.Time
	highRisk       bool
}

// newCRPStageCommand admits a local CRP into the staged slot only. It never
// promotes a release, starts a plugin, or contacts a network source.
func newCRPStageCommand() *cobra.Command {
	var (
		packagePath    string
		trustRootsPath string
		sourcesPath    string
		runtimeDir     string
		nowText        string
		highRisk       bool
	)
	cmd := &cobra.Command{
		Use:   "stage",
		Short: "Verify and persist a local CRP package in the staged slot",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			packageValue := strings.TrimSpace(packagePath)
			if packageValue == "" {
				return errors.New("--package is required")
			}
			trustValue := strings.TrimSpace(trustRootsPath)
			if trustValue == "" {
				return errors.New("--trust-roots is required; default trust is disabled")
			}
			sourcesValue := strings.TrimSpace(sourcesPath)
			if sourcesValue == "" {
				return errors.New("--sources is required; default sources are disabled")
			}
			runtimeValue := strings.TrimSpace(runtimeDir)
			if runtimeValue == "" {
				return errors.New("--runtime-dir is required; staged state must use an explicit runtime directory")
			}
			nowValue := strings.TrimSpace(nowText)
			if nowValue == "" {
				return errors.New("--now is required")
			}
			now, err := time.Parse(time.RFC3339, nowValue)
			if err != nil {
				return fmt.Errorf("parse --now: %w", err)
			}
			return runCRPStage(cmd, crpStageOptions{
				packagePath:    packageValue,
				trustRootsPath: trustValue,
				sourcesPath:    sourcesValue,
				runtimeDir:     runtimeValue,
				now:            now,
				highRisk:       highRisk,
			})
		},
	}
	cmd.Flags().StringVar(&packagePath, "package", "", "Path to a local .crp ZIP archive")
	cmd.Flags().StringVar(&trustRootsPath, "trust-roots", "", "JSON file containing explicit trust roots")
	cmd.Flags().StringVar(&sourcesPath, "sources", "", "JSON file containing explicit source registrations")
	cmd.Flags().StringVar(&runtimeDir, "runtime-dir", "", "Explicit local CRP runtime state directory")
	cmd.Flags().StringVar(&nowText, "now", "", "RFC3339 verification time")
	cmd.Flags().BoolVar(&highRisk, "high-risk", false, "Apply the high-risk signature threshold")
	return cmd
}

func runCRPStage(cmd *cobra.Command, opts crpStageOptions) error {
	if opts.packagePath == "" {
		return errors.New("--package is required")
	}
	if opts.trustRootsPath == "" {
		return errors.New("--trust-roots is required; default trust is disabled")
	}
	if opts.sourcesPath == "" {
		return errors.New("--sources is required; default sources are disabled")
	}
	if opts.runtimeDir == "" {
		return errors.New("--runtime-dir is required; staged state must use an explicit runtime directory")
	}

	archive, err := readBoundedFile(opts.packagePath, crpStageMaxArchiveBytes)
	if err != nil {
		return fmt.Errorf("read CRP package: %w", err)
	}
	pkg, err := crp.ParseArchive(archive, crp.ArchiveOptions{
		MaxFiles:           crp.DefaultArchiveMaxFiles,
		MaxTotalBytes:      crpStageMaxArchiveBytes,
		MaxManifestBytes:   crpStageMaxJSONBytes,
		MaxArtifactBytes:   crpStageMaxArchiveBytes,
		MaxSignaturesBytes: crpStageMaxJSONBytes,
	})
	if err != nil {
		return err
	}
	roots, err := loadTrustRoots(opts.trustRootsPath)
	if err != nil {
		return err
	}
	registrations, err := loadSourceRegistrations(opts.sourcesPath)
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
	imported, err := crp.Import(pkg, crp.ImportOptions{
		MaxManifestBytes:  crpStageMaxJSONBytes,
		MaxArtifactBytes:  crpStageMaxArchiveBytes,
		SourceRegistry:    registry,
		TrustStore:        trust,
		HighRisk:          opts.highRisk,
		AllowConfirmation: false,
		Now:               opts.now,
	})
	if err != nil {
		return err
	}
	runtimeRoot, err := filepath.Abs(opts.runtimeDir)
	if err != nil {
		return fmt.Errorf("resolve --runtime-dir: %w", err)
	}
	clock := func() time.Time { return opts.now }
	store, err := crp.NewRuntimeStore(runtimeRoot, crp.RuntimeStoreOptions{
		Clock: clock,
		HealthCheck: crp.HealthCheckFunc(func(record crp.RuntimeRecord) error {
			return validateCRPRuntimeRecord(runtimeRoot, record)
		}),
		Revalidate: crp.RuntimeRevalidateFunc(func(record crp.RuntimeRecord) error {
			return revalidateCRPRuntimeRecord(runtimeRoot, trust, registry, opts.now, opts.highRisk, record)
		}),
	})
	if err != nil {
		return err
	}
	record, err := store.Stage(pkg, imported)
	if err != nil {
		return err
	}
	snapshot, err := store.Snapshot(record.Key)
	if err != nil {
		return err
	}
	current := "none"
	if snapshot.Current != nil {
		current = snapshot.Current.Version
	}
	out := cmd.OutOrStdout()
	status := "staged"
	if record.Slot != crp.RuntimeSlotStaged {
		status = "already_current"
	}
	_, _ = fmt.Fprintf(out, "stage_status: %s\n", status)
	_, _ = fmt.Fprintf(out, "plugin_key: %s\n", record.Key)
	_, _ = fmt.Fprintf(out, "version: %s\n", record.Version)
	_, _ = fmt.Fprintf(out, "revision: %d\n", record.Revision)
	_, _ = fmt.Fprintf(out, "manifest_identity: %s\n", record.ManifestIdentity)
	_, _ = fmt.Fprintf(out, "artifact_identity: %s\n", record.ArtifactIdentity)
	_, _ = fmt.Fprintf(out, "requires_confirmation: %t\n", record.RequiresConfirm)
	_, _ = fmt.Fprintf(out, "current_status: %s\n", current)
	return nil
}

func revalidateCRPRuntimeRecord(root string, trust crp.TrustStore, registry crp.SourceRegistry, now time.Time, highRisk bool, record crp.RuntimeRecord) error {
	manifestBytes, err := readCRPRuntimeFile(root, record.ManifestPath, crpStageMaxJSONBytes)
	if err != nil {
		return fmt.Errorf("read staged manifest: %w", err)
	}
	artifact, err := readCRPRuntimeFile(root, record.ArtifactPath, crpStageMaxArchiveBytes)
	if err != nil {
		return fmt.Errorf("read staged artifact: %w", err)
	}
	signatureBytes, err := readCRPRuntimeFile(root, record.SignaturesPath, crpStageMaxJSONBytes)
	if err != nil {
		return fmt.Errorf("read staged signatures: %w", err)
	}
	var signatures []crp.Signature
	if err := decodeStrict(signatureBytes, &signatures); err != nil {
		return fmt.Errorf("parse staged signatures: %w", err)
	}
	result, err := crp.Import(crp.Package{Manifest: manifestBytes, Artifact: artifact, Signatures: signatures}, crp.ImportOptions{
		MaxManifestBytes:  crpStageMaxJSONBytes,
		MaxArtifactBytes:  crpStageMaxArchiveBytes,
		SourceRegistry:    registry,
		TrustStore:        trust,
		HighRisk:          highRisk,
		AllowConfirmation: false,
		Now:               now,
	})
	if err != nil {
		return err
	}
	if result.ContentIdentity != record.ManifestIdentity || result.ArtifactSize != int64(len(artifact)) {
		return crp.ErrRuntimeIdentityMismatch
	}
	requiresConfirmation := result.SignatureReport.Status == crp.VerificationNeedsConfirmation || result.SignatureReport.Required >= 3
	if requiresConfirmation != record.RequiresConfirm {
		return crp.ErrRuntimeIdentityMismatch
	}
	return validateCRPRuntimeRecord(root, record)
}

func validateCRPRuntimeRecord(root string, record crp.RuntimeRecord) error {
	manifestBytes, err := readCRPRuntimeFile(root, record.ManifestPath, crpStageMaxJSONBytes)
	if err != nil {
		return fmt.Errorf("read runtime manifest: %w", err)
	}
	artifact, err := readCRPRuntimeFile(root, record.ArtifactPath, crpStageMaxArchiveBytes)
	if err != nil {
		return fmt.Errorf("read runtime artifact: %w", err)
	}
	manifest, err := crp.ParseManifest(manifestBytes)
	if err != nil {
		return fmt.Errorf("parse runtime manifest: %w", err)
	}
	artifactSum := sha256.Sum256(artifact)
	if record.ArtifactIdentity != hex.EncodeToString(artifactSum[:]) {
		return crp.ErrRuntimeIdentityMismatch
	}
	manifestIdentity, err := crp.ContentIdentity(manifest)
	if err != nil || manifestIdentity != record.ManifestIdentity {
		return crp.ErrRuntimeIdentityMismatch
	}
	key := manifest.PluginID
	if key == "" {
		key = manifest.Name
	}
	if record.Key != key || record.Namespace != manifest.Namespace || record.Version != manifest.Version || record.ReleaseSequence != manifest.ReleaseSequence {
		return crp.ErrRuntimeIdentityMismatch
	}
	if err := manifest.Verify(artifact); err != nil {
		return err
	}
	return nil
}

func readCRPRuntimeFile(root, relative string, maxBytes int64) ([]byte, error) {
	if root == "" || relative == "" || filepath.IsAbs(relative) {
		return nil, crp.ErrRuntimePath
	}
	relativePath := filepath.FromSlash(relative)
	clean := filepath.Clean(relativePath)
	if clean == "." || clean != relativePath || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return nil, crp.ErrRuntimePath
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	target := filepath.Join(rootAbs, clean)
	rel, err := filepath.Rel(rootAbs, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, crp.ErrRuntimePath
	}
	current := rootAbs
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		info, statErr := os.Lstat(current)
		if statErr != nil {
			return nil, statErr
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, crp.ErrRuntimeSymlink
		}
	}
	return readBoundedFile(target, maxBytes)
}
