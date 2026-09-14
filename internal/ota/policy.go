package ota

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	DefaultEndpoint      = "https://ota.cheesesec.com"
	DefaultMaxIndexBytes = 1 << 20
)

var (
	ErrInvalidConfig     = errors.New("invalid OTA client configuration")
	ErrInvalidIndex      = errors.New("invalid OTA index")
	ErrInvalidCandidate  = errors.New("invalid OTA candidate")
	ErrRedirect          = errors.New("OTA redirect is not allowed")
	ErrSequenceRollback  = errors.New("OTA sequence would move backwards")
	ErrSignatureRejected = errors.New("OTA candidate signature was rejected")
	ErrWithdrawnRelease  = errors.New("OTA candidate has been withdrawn")
	ErrResourceMismatch  = errors.New("OTA resource URL does not match the CRP digest")
	ErrUpToDate          = errors.New("OTA index has no newer release")
	ErrIndexTooLarge     = errors.New("OTA index exceeds the configured size limit")
	ErrNonJSON           = errors.New("OTA endpoint did not return JSON")
	ErrStateInvalid      = errors.New("invalid OTA last-known-good state")
	ErrStateNotFound     = errors.New("OTA last-known-good state is not present")
)

var (
	sha256Pattern    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	versionPattern   = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+){0,2}(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`)
	identityPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,127}$`)
	releaseIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@+#-]{0,127}$`)
	resourcePattern  = regexp.MustCompile(`^/sha256/([0-9a-f]{64})/([A-Za-z0-9][A-Za-z0-9._+-]*)$`)
)

var allowedChannels = map[string]struct{}{
	"stable": {},
	"canary": {},
	"dev":    {},
}

var allowedTrustLevels = map[string]struct{}{
	"official":    {},
	"enterprise":  {},
	"community":   {},
	"personal":    {},
	"test":        {},
	"development": {},
}

// Candidate is a verified metadata candidate. The edge only attests to the
// published index fields; CRP signature and source-root verification still
// happens in the local importer before staging or activation.
type Candidate struct {
	ReleaseID          string `json:"release_id"`
	Version            string `json:"version"`
	ReleaseSequence    uint64 `json:"release_sequence"`
	ResourceURL        string `json:"resource_url"`
	CRPSHA256          string `json:"crp_sha256"`
	ManifestSHA256     string `json:"manifest_sha256"`
	SignatureSetSHA256 string `json:"signature_set_sha256"`
	SourceRoot         string `json:"source_root"`
	TrustLevel         string `json:"trust_level"`
	SignatureStatus    string `json:"signature_status"`
	IndexSequence      uint64 `json:"-"`
}

// Index is the strict OTA index format published by CheeseSec_Plugin.
type Index struct {
	APIVersion    string      `json:"api_version"`
	IndexSequence uint64      `json:"index_sequence"`
	Mode          string      `json:"mode"`
	Releases      []Candidate `json:"releases"`
}

// Request contains the local last-known-good sequence fence.
type Request struct {
	Channel                string
	CurrentIndexSequence   uint64
	CurrentReleaseSequence uint64
}

// LastKnownGood records the sequence accepted by the local control plane.
type LastKnownGood struct {
	IndexSequence   uint64    `json:"index_sequence"`
	ReleaseSequence uint64    `json:"release_sequence"`
	ReleaseID       string    `json:"release_id"`
	UpdatedAt       time.Time `json:"updated_at"`
}

func validateChannel(channel string) error {
	if _, ok := allowedChannels[channel]; !ok {
		return fmt.Errorf("%w: channel %q is not stable, canary, or dev", ErrInvalidConfig, channel)
	}
	return nil
}

func validateSHA(value, field string) error {
	if !sha256Pattern.MatchString(value) {
		return fmt.Errorf("%w: %s must be 64 lowercase hexadecimal characters", ErrInvalidCandidate, field)
	}
	return nil
}

func validateCandidate(candidate Candidate) error {
	if !releaseIDPattern.MatchString(candidate.ReleaseID) {
		return fmt.Errorf("%w: release_id is not canonical", ErrInvalidCandidate)
	}
	if !versionPattern.MatchString(candidate.Version) {
		return fmt.Errorf("%w: version is not semantic version text", ErrInvalidCandidate)
	}
	if err := validateSHA(candidate.CRPSHA256, "crp_sha256"); err != nil {
		return err
	}
	if err := validateSHA(candidate.ManifestSHA256, "manifest_sha256"); err != nil {
		return err
	}
	if err := validateSHA(candidate.SignatureSetSHA256, "signature_set_sha256"); err != nil {
		return err
	}
	if candidate.SourceRoot == "" || strings.Contains(candidate.SourceRoot, "..") || !identityPattern.MatchString(candidate.SourceRoot) {
		return fmt.Errorf("%w: source_root is not canonical", ErrInvalidCandidate)
	}
	if _, ok := allowedTrustLevels[candidate.TrustLevel]; !ok {
		return fmt.Errorf("%w: trust_level is not supported", ErrInvalidCandidate)
	}
	resource, err := url.Parse(candidate.ResourceURL)
	if err != nil || resource.Scheme != "https" || resource.Host != "res.cheesesec.com" || resource.User != nil || resource.RawQuery != "" || resource.Fragment != "" {
		return fmt.Errorf("%w: resource_url must be an HTTPS content-addressed URL", ErrInvalidCandidate)
	}
	match := resourcePattern.FindStringSubmatch(resource.EscapedPath())
	if match == nil || match[1] != candidate.CRPSHA256 || strings.Contains(match[2], "..") || strings.ContainsAny(match[2], `\\%`) {
		return fmt.Errorf("%w: resource_url is not bound to crp_sha256", ErrResourceMismatch)
	}
	if candidate.SignatureStatus == "withdrawn" {
		return ErrWithdrawnRelease
	}
	if candidate.SignatureStatus != "verified" {
		return fmt.Errorf("%w: status=%q", ErrSignatureRejected, candidate.SignatureStatus)
	}
	return nil
}

func decodeIndex(data []byte) (Index, error) {
	var index Index
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&index); err != nil {
		return Index{}, fmt.Errorf("%w: %v", ErrInvalidIndex, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return Index{}, fmt.Errorf("%w: trailing JSON data", ErrInvalidIndex)
		}
		return Index{}, fmt.Errorf("%w: invalid trailing JSON: %v", ErrInvalidIndex, err)
	}
	if index.APIVersion != "ota.cheesesec.com/v1" || index.Mode != "pull-only" {
		return Index{}, fmt.Errorf("%w: api_version or mode is not supported", ErrInvalidIndex)
	}
	seen := make(map[string]struct{}, len(index.Releases))
	for idx := range index.Releases {
		candidate := index.Releases[idx]
		if _, ok := seen[candidate.ReleaseID]; ok {
			return Index{}, fmt.Errorf("%w: duplicate release_id %q", ErrInvalidIndex, candidate.ReleaseID)
		}
		seen[candidate.ReleaseID] = struct{}{}
		if err := validateCandidate(candidate); err != nil {
			return Index{}, err
		}
	}
	return index, nil
}

func validateLastKnownGood(state LastKnownGood) error {
	if state.ReleaseID != "" && !releaseIDPattern.MatchString(state.ReleaseID) {
		return fmt.Errorf("%w: release_id is not canonical", ErrStateInvalid)
	}
	if state.UpdatedAt.IsZero() {
		return fmt.Errorf("%w: updated_at is required", ErrStateInvalid)
	}
	return nil
}

// FileStateStore persists only last-known-good sequence metadata. It never
// stores credentials, CRP bytes, or signing material.
type FileStateStore struct{ Path string }

func NewFileStateStore(path string) (*FileStateStore, error) {
	if path == "" || !filepath.IsAbs(path) {
		return nil, fmt.Errorf("%w: state path must be absolute", ErrInvalidConfig)
	}
	return &FileStateStore{Path: path}, nil
}

func (s *FileStateStore) Load(_ context.Context) (LastKnownGood, error) {
	if s == nil || s.Path == "" {
		return LastKnownGood{}, fmt.Errorf("%w: state store is not configured", ErrStateInvalid)
	}
	info, err := os.Lstat(s.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return LastKnownGood{}, ErrStateNotFound
		}
		return LastKnownGood{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return LastKnownGood{}, fmt.Errorf("%w: state file must be a regular file", ErrStateInvalid)
	}
	if err := validateStateFilePermissions(s.Path, info); err != nil {
		return LastKnownGood{}, fmt.Errorf("%w: %v", ErrStateInvalid, err)
	}
	file, err := os.Open(s.Path)
	if err != nil {
		return LastKnownGood{}, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 16<<10+1))
	if err != nil {
		return LastKnownGood{}, err
	}
	if len(data) > 16<<10 {
		return LastKnownGood{}, fmt.Errorf("%w: state file is too large", ErrStateInvalid)
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	var state LastKnownGood
	if err := decoder.Decode(&state); err != nil {
		return LastKnownGood{}, fmt.Errorf("%w: %v", ErrStateInvalid, err)
	}
	if err := validateLastKnownGood(state); err != nil {
		return LastKnownGood{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return LastKnownGood{}, fmt.Errorf("%w: state file contains trailing JSON", ErrStateInvalid)
	}
	return state, nil
}

func (s *FileStateStore) Save(_ context.Context, state LastKnownGood) error {
	if s == nil || s.Path == "" {
		return fmt.Errorf("%w: state store is not configured", ErrStateInvalid)
	}
	if err := validateLastKnownGood(state); err != nil {
		return err
	}
	if current, err := s.Load(context.Background()); err == nil {
		if state.IndexSequence < current.IndexSequence || state.ReleaseSequence < current.ReleaseSequence {
			return ErrSequenceRollback
		}
	} else if !errors.Is(err, ErrStateNotFound) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o700); err != nil {
		return err
	}
	if info, err := os.Lstat(s.Path); err == nil && (info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular()) {
		return fmt.Errorf("%w: state file must be a regular file", ErrStateInvalid)
	}
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(s.Path), ".ota-state-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := protectStateFile(temporaryName); err != nil {
		_ = temporary.Close()
		return err
	}
	writer := bufio.NewWriter(temporary)
	if _, err := writer.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := writer.Flush(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := replaceStateFileAtomic(temporaryName, s.Path); err != nil {
		return err
	}
	info, err := os.Lstat(s.Path)
	if err != nil {
		return err
	}
	if err := validateStateFilePermissions(s.Path, info); err != nil {
		return fmt.Errorf("%w: %v", ErrStateInvalid, err)
	}
	return nil
}
