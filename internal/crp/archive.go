package crp

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
)

const (
	DefaultArchiveMaxFiles           int   = 64
	DefaultArchiveMaxTotalBytes      int64 = 1 << 30
	DefaultArchiveMaxManifestBytes   int64 = 1 << 20
	DefaultArchiveMaxArtifactBytes   int64 = 1 << 30
	DefaultArchiveMaxSignaturesBytes int64 = 1 << 20
)

var (
	ErrArchiveLayout       = errors.New("invalid CRP archive layout")
	ErrArchivePath         = errors.New("invalid CRP archive path")
	ErrArchiveDuplicate    = errors.New("duplicate CRP archive entry")
	ErrArchiveTooLarge     = errors.New("CRP archive exceeds uncompressed size limit")
	ErrArchiveTooManyFiles = errors.New("CRP archive contains too many entries")
	ErrArchiveEntry        = errors.New("invalid CRP archive entry")
	ErrArchiveConfig       = errors.New("invalid CRP archive limits")
)

type ArchiveOptions struct {
	MaxFiles                                                              int
	MaxTotalBytes, MaxManifestBytes, MaxArtifactBytes, MaxSignaturesBytes int64
}

func (o ArchiveOptions) withDefaults() (ArchiveOptions, error) {
	if o.MaxFiles == 0 {
		o.MaxFiles = DefaultArchiveMaxFiles
	}
	if o.MaxTotalBytes == 0 {
		o.MaxTotalBytes = DefaultArchiveMaxTotalBytes
	}
	if o.MaxManifestBytes == 0 {
		o.MaxManifestBytes = DefaultArchiveMaxManifestBytes
	}
	if o.MaxArtifactBytes == 0 {
		o.MaxArtifactBytes = DefaultArchiveMaxArtifactBytes
	}
	if o.MaxSignaturesBytes == 0 {
		o.MaxSignaturesBytes = DefaultArchiveMaxSignaturesBytes
	}
	if o.MaxFiles < 1 || o.MaxTotalBytes < 0 || o.MaxManifestBytes < 0 || o.MaxArtifactBytes < 0 || o.MaxSignaturesBytes < 0 {
		return ArchiveOptions{}, ErrArchiveConfig
	}
	return o, nil
}

// ParseArchive materializes a strict CRP archive in memory only.
func ParseArchive(data []byte, opts ArchiveOptions) (Package, error) {
	opts, err := opts.withDefaults()
	if err != nil {
		return Package{}, err
	}
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return Package{}, fmt.Errorf("%w: %v", ErrArchiveEntry, err)
	}
	if len(r.File) > opts.MaxFiles {
		return Package{}, fmt.Errorf("%w: got %d, limit %d", ErrArchiveTooManyFiles, len(r.File), opts.MaxFiles)
	}
	seen := make(map[string]struct{}, len(r.File))
	var total uint64
	var manifestData, artifactData, signatureData []byte
	var artifactPath string
	for _, f := range r.File {
		name, err := archiveEntryName(f.Name)
		if err != nil {
			return Package{}, err
		}
		if _, ok := seen[name]; ok {
			return Package{}, fmt.Errorf("%w: %q", ErrArchiveDuplicate, name)
		}
		seen[name] = struct{}{}
		if f.FileInfo().IsDir() || f.Mode()&os.ModeSymlink != 0 || !f.Mode().IsRegular() {
			return Package{}, fmt.Errorf("%w: %q must be a regular file", ErrArchiveEntry, name)
		}
		if f.UncompressedSize64 > uint64(^uint64(0)>>1) {
			return Package{}, fmt.Errorf("%w: %q size overflows int64", ErrArchiveTooLarge, name)
		}
		if total > uint64(opts.MaxTotalBytes) || f.UncompressedSize64 > uint64(opts.MaxTotalBytes)-total {
			return Package{}, fmt.Errorf("%w: %q", ErrArchiveTooLarge, name)
		}
		total += f.UncompressedSize64
		limit := opts.MaxTotalBytes
		switch {
		case name == "manifest.json":
			limit = opts.MaxManifestBytes
		case name == "signatures/manifest.json":
			limit = opts.MaxSignaturesBytes
		case strings.HasPrefix(name, "artifact/"):
			if artifactPath != "" {
				return Package{}, fmt.Errorf("%w: artifact must contain exactly one file", ErrArchiveLayout)
			}
			artifactPath = name
			limit = opts.MaxArtifactBytes
		default:
			return Package{}, fmt.Errorf("%w: unexpected entry %q", ErrArchiveLayout, name)
		}
		if f.UncompressedSize64 > uint64(limit) {
			return Package{}, fmt.Errorf("%w: %q", ErrArchiveTooLarge, name)
		}
		b, err := readArchiveEntry(f, limit)
		if err != nil {
			return Package{}, err
		}
		switch {
		case name == "manifest.json":
			manifestData = b
		case name == "signatures/manifest.json":
			signatureData = b
		default:
			artifactData = b
		}
	}
	if manifestData == nil || artifactData == nil || signatureData == nil {
		return Package{}, fmt.Errorf("%w: manifest, one artifact, and signatures are required", ErrArchiveLayout)
	}
	manifest, err := ParseManifest(manifestData)
	if err != nil {
		return Package{}, err
	}
	if manifest.Artifact.Size != int64(len(artifactData)) {
		return Package{}, ErrArtifactSize
	}
	if manifest.Artifact.Name != "" && path.Base(artifactPath) != manifest.Artifact.Name {
		return Package{}, fmt.Errorf("%w: manifest artifact name %q does not match %q", ErrArchiveLayout, manifest.Artifact.Name, artifactPath)
	}
	signatures, err := parseArchiveSignatures(signatureData)
	if err != nil {
		return Package{}, err
	}
	return Package{Manifest: append([]byte(nil), manifestData...), Artifact: append([]byte(nil), artifactData...), Signatures: signatures}, nil
}

func archiveEntryName(raw string) (string, error) {
	if raw == "" || strings.Contains(raw, `\`) || strings.HasPrefix(raw, "/") || strings.Contains(raw, ":") {
		return "", fmt.Errorf("%w: %q", ErrArchivePath, raw)
	}
	clean := path.Clean(raw)
	if clean != raw || clean == "." || strings.HasPrefix(clean, "../") || clean == ".." {
		return "", fmt.Errorf("%w: %q", ErrArchivePath, raw)
	}
	if strings.HasSuffix(raw, "/") {
		return "", fmt.Errorf("%w: directory %q is not allowed", ErrArchiveLayout, raw)
	}
	return clean, nil
}
func readArchiveEntry(f *zip.File, limit int64) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, fmt.Errorf("%w: open %q: %v", ErrArchiveEntry, f.Name, err)
	}
	defer rc.Close()
	readLimit := limit
	if limit < int64(^uint64(0)>>1) {
		readLimit++
	}
	b, err := io.ReadAll(io.LimitReader(rc, readLimit))
	if err != nil {
		return nil, fmt.Errorf("%w: read %q: %v", ErrArchiveEntry, f.Name, err)
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%w: %q", ErrArchiveTooLarge, f.Name)
	}
	return b, nil
}
func parseArchiveSignatures(data []byte) ([]Signature, error) {
	var signatures []Signature
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&signatures); err != nil {
		return nil, fmt.Errorf("%w: signatures: %v", ErrSignature, err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("%w: signatures trailing JSON", ErrSignature)
		}
		return nil, fmt.Errorf("%w: signatures trailing data: %v", ErrSignature, err)
	}
	out := make([]Signature, len(signatures))
	copy(out, signatures)
	return out, nil
}
