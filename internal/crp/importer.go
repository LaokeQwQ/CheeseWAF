package crp

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const (
	DefaultMaxManifestBytes int64 = 1 << 20
	DefaultMaxArtifactBytes int64 = 1 << 30
)

var (
	ErrManifestTooLarge = errors.New("CRP manifest exceeds import size limit")
	ErrArtifactTooLarge = errors.New("CRP artifact exceeds import size limit")
	ErrImporterConfig   = errors.New("invalid CRP importer configuration")
)

// Package is an already materialized CRP. Import never interprets it as a
// path, opens files, contacts a source, or starts background work.
type Package struct {
	Manifest   []byte
	Artifact   []byte
	Signatures []Signature
}

// ImportOptions contains only immutable, in-memory admission context. Zero
// limits select conservative defaults.
type ImportOptions struct {
	MaxManifestBytes  int64
	MaxArtifactBytes  int64
	SourceRegistry    SourceRegistry
	TrustStore        TrustStore
	CurrentRelease    Release
	HighRisk          bool
	AllowConfirmation bool
	Now               time.Time
}

type ImportResult struct {
	Manifest        Manifest
	ArtifactSize    int64
	ContentIdentity string
	SignatureReport SignatureReport
	// admission is intentionally opaque. Runtime installation must not trust
	// a caller-created or modified result or any mutable presentation fields.
	// In particular, the confirmation decision and threshold are kept here
	// instead of being derived from SignatureReport at install time.
	admission importAdmission
}

// importAdmission is a sealed capability produced only by Import. The fields
// are deliberately unexported so callers can inspect SignatureReport without
// being able to lower a threshold or clear a required confirmation before
// handing the result to the runtime installer.
type importAdmission struct {
	verified             bool
	packageFingerprint   string
	reportFingerprint    string
	requiredSignatures   int
	requiresConfirmation bool
}

// Import performs deterministic, offline CRP admission. It validates size,
// strict manifest syntax, source-root binding, all artifact digests, version
// fencing, and the configured signature threshold. No input is mutated.
func Import(pkg Package, opts ImportOptions) (ImportResult, error) {
	manifestLimit := opts.MaxManifestBytes
	if manifestLimit == 0 {
		manifestLimit = DefaultMaxManifestBytes
	}
	artifactLimit := opts.MaxArtifactBytes
	if artifactLimit == 0 {
		artifactLimit = DefaultMaxArtifactBytes
	}
	if manifestLimit < 0 || artifactLimit < 0 {
		return ImportResult{}, ErrImporterConfig
	}
	if opts.Now.IsZero() {
		return ImportResult{}, fmt.Errorf("%w: verification time is required", ErrImporterConfig)
	}
	if int64(len(pkg.Manifest)) > manifestLimit {
		return ImportResult{}, fmt.Errorf("%w: got %d, limit %d", ErrManifestTooLarge, len(pkg.Manifest), manifestLimit)
	}
	if int64(len(pkg.Artifact)) > artifactLimit {
		return ImportResult{}, fmt.Errorf("%w: got %d, limit %d", ErrArtifactTooLarge, len(pkg.Artifact), artifactLimit)
	}
	manifest, err := ParseManifest(pkg.Manifest)
	if err != nil {
		return ImportResult{}, err
	}
	if err := opts.SourceRegistry.Validate(manifest); err != nil {
		return ImportResult{}, err
	}
	if err := manifest.ValidateUpgrade(opts.CurrentRelease); err != nil {
		return ImportResult{}, err
	}
	if err := manifest.Verify(pkg.Artifact); err != nil {
		return ImportResult{}, err
	}
	report, err := opts.TrustStore.VerifyManifest(manifest, pkg.Signatures, VerificationOptions{
		Now: opts.Now, HighRisk: opts.HighRisk, AllowConfirmation: opts.AllowConfirmation,
	})
	if err != nil {
		return ImportResult{Manifest: manifest, ArtifactSize: int64(len(pkg.Artifact)), SignatureReport: report}, err
	}
	identity, err := ContentIdentity(manifest)
	if err != nil {
		return ImportResult{}, err
	}
	return ImportResult{
		Manifest:        manifest,
		ArtifactSize:    int64(len(pkg.Artifact)),
		ContentIdentity: identity,
		SignatureReport: report,
		admission: importAdmission{
			verified:             true,
			packageFingerprint:   fingerprintPackage(pkg),
			reportFingerprint:    fingerprintSignatureReport(report),
			requiredSignatures:   report.Required,
			requiresConfirmation: report.Status == VerificationNeedsConfirmation || report.Required >= 3,
		},
	}, nil
}

func fingerprintPackage(pkg Package) string {
	signatures, _ := json.Marshal(pkg.Signatures)
	hash := sha256.New()
	_, _ = hash.Write([]byte("cheesewaf-crp-import-v1\n"))
	_, _ = hash.Write(pkg.Manifest)
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(pkg.Artifact)
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(signatures)
	return fmt.Sprintf("%x", hash.Sum(nil))
}

func fingerprintSignatureReport(report SignatureReport) string {
	b, _ := json.Marshal(report)
	hash := sha256.Sum256(append([]byte("cheesewaf-crp-admission-v1\n"), b...))
	return fmt.Sprintf("%x", hash[:])
}
