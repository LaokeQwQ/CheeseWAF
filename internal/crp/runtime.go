package crp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

var (
	ErrRuntimeNotFound             = errors.New("CRP runtime record not found")
	ErrRuntimeConfig               = errors.New("invalid CRP runtime configuration")
	ErrRuntimeUnverified           = errors.New("CRP runtime package was not admitted by the importer")
	ErrRuntimeIdentityMismatch     = errors.New("CRP runtime import identity does not match the package")
	ErrRuntimePath                 = errors.New("unsafe CRP runtime plugin path")
	ErrRuntimeSymlink              = errors.New("CRP runtime refuses symlink content")
	ErrRuntimeCorrupt              = errors.New("CRP runtime state is corrupt")
	ErrRuntimeConflict             = errors.New("CRP runtime state revision conflict")
	ErrRuntimeBusy                 = errors.New("CRP runtime state is busy")
	ErrRuntimeLockUnavailable      = errors.New("CRP runtime lock is unavailable")
	ErrRuntimeHealthCheck          = errors.New("CRP runtime health check failed")
	ErrRuntimeConfirmationRequired = errors.New("CRP runtime confirmation is required")
	ErrRuntimeConfirmationReplay   = errors.New("CRP runtime confirmation was already consumed")
	ErrRuntimeAuthorization        = errors.New("CRP runtime authorization was rejected")
)

// runtimeLockFileName is a permanent sentinel. The file itself is never
// removed or replaced: the OS advisory lock on its inode is the lease, and a
// process crash releases that lease without stale-file garbage collection.
const runtimeLockFileName = ".runtime.lock"

type RuntimeSlot string

const (
	RuntimeSlotStaged   RuntimeSlot = "staged"
	RuntimeSlotCurrent  RuntimeSlot = "current"
	RuntimeSlotPrevious RuntimeSlot = "previous"
)

type RuntimeAction string

const (
	RuntimeActionPromote      RuntimeAction = "promote"
	RuntimeActionRollback     RuntimeAction = "rollback"
	RuntimeActionStage        RuntimeAction = "stage"
	maxRuntimeConfirmationTTL               = 24 * time.Hour
)

type RuntimeRecord struct {
	Key              string
	PluginID         string
	Name             string
	Namespace        string
	Version          string
	ReleaseSequence  uint64
	ManifestIdentity string
	ArtifactIdentity string
	ArtifactPath     string
	ManifestPath     string
	SignaturesPath   string
	Slot             RuntimeSlot
	Revision         uint64
	RequiresConfirm  bool
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

type RuntimeSnapshot struct {
	Key      string
	Revision uint64
	Current  *RuntimeRecord
	Staged   *RuntimeRecord
	Previous *RuntimeRecord
}

type RuntimeEvent struct {
	Revision         uint64
	Action           RuntimeAction
	ManifestIdentity string
	Actor            string
	At               time.Time
}

type Confirmation struct {
	ID               string
	Actor            string
	Action           RuntimeAction
	PluginKey        string
	ManifestIdentity string
	ExpectedRevision uint64
	AuthorizedAt     time.Time
	ExpiresAt        time.Time
}

type HealthChecker interface{ Check(RuntimeRecord) error }
type HealthCheckFunc func(RuntimeRecord) error

func (f HealthCheckFunc) Check(record RuntimeRecord) error { return f(record) }

type RuntimeAuthorizer interface{ Authorize(Confirmation) error }

type RuntimeAuthorizerFunc func(Confirmation) error

func (f RuntimeAuthorizerFunc) Authorize(confirmation Confirmation) error {
	return f(confirmation)
}

type RuntimeRevalidator interface{ Revalidate(RuntimeRecord) error }

type RuntimeRevalidateFunc func(RuntimeRecord) error

func (f RuntimeRevalidateFunc) Revalidate(record RuntimeRecord) error {
	return f(record)
}

type RuntimeStoreOptions struct {
	Clock       func() time.Time
	HealthCheck HealthChecker
	Authorizer  RuntimeAuthorizer
	Revalidate  RuntimeRevalidator
}

type runtimePluginState struct {
	Revision uint64
	Current  *RuntimeRecord
	Staged   *RuntimeRecord
	Previous *RuntimeRecord
	Events   []RuntimeEvent
	Used     map[string]time.Time
}

type runtimeDiskState struct {
	Schema  int
	Plugins map[string]runtimePluginState
}

type RuntimeStore struct {
	mu         sync.Mutex
	root       string
	statePath  string
	clock      func() time.Time
	health     HealthChecker
	authorizer RuntimeAuthorizer
	revalidate RuntimeRevalidator
	state      runtimeDiskState
}

var runtimeKeyPattern = regexp.MustCompile("^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")

func NewRuntimeStore(root string, opts RuntimeStoreOptions) (*RuntimeStore, error) {
	if root == "" || root != strings.TrimSpace(root) {
		return nil, fmt.Errorf("%w: root is required", ErrRuntimeConfig)
	}
	root = filepath.Clean(root)
	if root == "." || !filepath.IsAbs(root) {
		return nil, fmt.Errorf("%w: root must be an absolute path", ErrRuntimeConfig)
	}
	if opts.Clock == nil {
		opts.Clock = time.Now
	}
	if opts.HealthCheck == nil || opts.Revalidate == nil {
		return nil, fmt.Errorf("%w: health checker and revalidator are required", ErrRuntimeConfig)
	}
	if err := ensureRuntimeDirectory(root); err != nil {
		return nil, err
	}
	for _, rel := range []string{"artifacts", filepath.Join("artifacts", "sha256"), "plugins"} {
		if err := ensureManagedDirectory(root, rel); err != nil {
			return nil, fmt.Errorf("%w: create managed directory: %v", ErrRuntimeConfig, err)
		}
	}
	if err := ensureRuntimeLockFile(root); err != nil {
		return nil, fmt.Errorf("%w: initialize runtime lock: %v", ErrRuntimeConfig, err)
	}
	s := &RuntimeStore{root: root, statePath: filepath.Join(root, "state.json"), clock: opts.Clock, health: opts.HealthCheck, authorizer: opts.Authorizer, revalidate: opts.Revalidate, state: runtimeDiskState{Schema: 1, Plugins: map[string]runtimePluginState{}}}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *RuntimeStore) Stage(pkg Package, imported ImportResult) (RuntimeRecord, error) {
	if s == nil {
		return RuntimeRecord{}, ErrRuntimeConfig
	}
	manifest, err := s.verifyImportedPackage(pkg, imported)
	if err != nil {
		return RuntimeRecord{}, err
	}
	key, err := runtimePluginKey(manifest)
	if err != nil {
		return RuntimeRecord{}, err
	}
	if err := s.validatePluginPath(key); err != nil {
		return RuntimeRecord{}, err
	}
	artifactID := artifactIdentity(pkg.Artifact)
	manifestID, err := ContentIdentity(manifest)
	if err != nil {
		return RuntimeRecord{}, err
	}

	// Read the current plugin state under the mutex, then release it before
	// doing filesystem I/O or invoking the external revalidator. The latter
	// is allowed to inspect this store, and must never be called while s.mu is
	// held. The revision is checked again before committing below.
	s.mu.Lock()
	if err := s.refreshStateLocked(); err != nil {
		s.mu.Unlock()
		return RuntimeRecord{}, err
	}
	state := clonePluginState(s.state.Plugins[key])
	if state.Current != nil {
		if err := manifest.ValidateUpgrade(Release{Version: state.Current.Version, Sequence: state.Current.ReleaseSequence}); err != nil {
			s.mu.Unlock()
			return RuntimeRecord{}, err
		}
		if state.Current.Version == manifest.Version && state.Current.ReleaseSequence == manifest.ReleaseSequence {
			if state.Current.ManifestIdentity == manifestID && state.Current.ArtifactIdentity == artifactID {
				s.mu.Unlock()
				return cloneRuntimeRecord(*state.Current), nil
			}
			s.mu.Unlock()
			return RuntimeRecord{}, ErrRuntimeConflict
		}
		if manifest.ReleaseSequence <= state.Current.ReleaseSequence {
			s.mu.Unlock()
			return RuntimeRecord{}, ErrDowngrade
		}
	}
	if state.Staged != nil {
		// Staging is idempotent only for the exact same manifest *and*
		// artifact. An artifact may be rewrapped by a different manifest or
		// signature set; returning the old record would silently discard the
		// new policy metadata.
		if state.Staged.ManifestIdentity == manifestID && state.Staged.ArtifactIdentity == artifactID {
			s.mu.Unlock()
			return cloneRuntimeRecord(*state.Staged), nil
		}
		s.mu.Unlock()
		return RuntimeRecord{}, ErrRuntimeConflict
	}
	baseRevision := state.Revision
	s.mu.Unlock()

	if err := s.persistArtifact(artifactID, pkg.Artifact); err != nil {
		return RuntimeRecord{}, err
	}
	manifestPath, signaturesPath, err := s.persistMetadata(key, manifestID, pkg.Manifest, pkg.Signatures)
	if err != nil {
		return RuntimeRecord{}, err
	}
	now := s.clock().UTC()
	record := RuntimeRecord{Key: key, PluginID: manifest.PluginID, Name: manifest.Name, Namespace: manifest.Namespace, Version: manifest.Version, ReleaseSequence: manifest.ReleaseSequence, ManifestIdentity: manifestID, ArtifactIdentity: artifactID, ArtifactPath: filepath.ToSlash(filepath.Join("artifacts", "sha256", artifactID)), ManifestPath: manifestPath, SignaturesPath: signaturesPath, Slot: RuntimeSlotStaged, Revision: baseRevision + 1, RequiresConfirm: imported.admission.requiresConfirmation, CreatedAt: now, UpdatedAt: now}
	if err := s.revalidate.Revalidate(record); err != nil {
		return RuntimeRecord{}, fmt.Errorf("%w: %v", ErrRuntimeUnverified, err)
	}

	// Re-enter the critical section only for a revision-checked commit. The
	// non-blocking process lease serializes writers, and the durable snapshot
	// is reloaded while it is held. A concurrent stage/promote may have won
	// while revalidation was running; in that case return its exact same record
	// as an idempotent result, or report a conflict for a different candidate.
	s.mu.Lock()
	defer s.mu.Unlock()
	// Re-read the durable snapshot under the process lease. Never persist a
	// clone of s.state here: another RuntimeStore/process may have committed a
	// different plugin since this store was opened.
	lease, err := acquireRuntimeLease(s.root)
	if err != nil {
		return RuntimeRecord{}, err
	}
	defer lease.Close()
	diskState, err := s.loadDiskState()
	if err != nil {
		return RuntimeRecord{}, err
	}
	live := clonePluginState(diskState.Plugins[key])
	if live.Revision != baseRevision {
		if live.Current != nil && live.Current.ManifestIdentity == manifestID && live.Current.ArtifactIdentity == artifactID {
			return cloneRuntimeRecord(*live.Current), nil
		}
		if live.Staged != nil && live.Staged.ManifestIdentity == manifestID && live.Staged.ArtifactIdentity == artifactID {
			return cloneRuntimeRecord(*live.Staged), nil
		}
		return RuntimeRecord{}, ErrRuntimeConflict
	}
	if live.Current != nil {
		if err := manifest.ValidateUpgrade(Release{Version: live.Current.Version, Sequence: live.Current.ReleaseSequence}); err != nil {
			return RuntimeRecord{}, err
		}
		if live.Current.Version == manifest.Version && live.Current.ReleaseSequence == manifest.ReleaseSequence {
			if live.Current.ManifestIdentity == manifestID && live.Current.ArtifactIdentity == artifactID {
				return cloneRuntimeRecord(*live.Current), nil
			}
			return RuntimeRecord{}, ErrRuntimeConflict
		}
		if manifest.ReleaseSequence <= live.Current.ReleaseSequence {
			return RuntimeRecord{}, ErrDowngrade
		}
	}
	if live.Staged != nil {
		if live.Staged.ManifestIdentity == manifestID && live.Staged.ArtifactIdentity == artifactID {
			return cloneRuntimeRecord(*live.Staged), nil
		}
		return RuntimeRecord{}, ErrRuntimeConflict
	}
	record.Revision = live.Revision + 1
	live.Revision = record.Revision
	live.Staged = &record
	if live.Used == nil {
		live.Used = map[string]time.Time{}
	}
	next := cloneRuntimeDiskState(diskState)
	next.Plugins[key] = live
	if err := s.persistState(next); err != nil {
		return RuntimeRecord{}, err
	}
	s.state = next
	return cloneRuntimeRecord(record), nil
}

func (s *RuntimeStore) validatePluginPath(key string) error {
	if err := ensureManagedDirectory(s.root, "plugins"); err != nil {
		return err
	}
	path := filepath.Join(s.root, "plugins", key)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return ErrRuntimeSymlink
	}
	if !info.IsDir() {
		return ErrRuntimePath
	}
	return nil
}

func (s *RuntimeStore) Promote(key string, expectedRevision uint64, confirmation *Confirmation) (RuntimeRecord, error) {
	return s.transition(key, expectedRevision, RuntimeActionPromote, confirmation)
}
func (s *RuntimeStore) Rollback(key string, expectedRevision uint64, confirmation *Confirmation) (RuntimeRecord, error) {
	return s.transition(key, expectedRevision, RuntimeActionRollback, confirmation)
}

func (s *RuntimeStore) transition(key string, expectedRevision uint64, action RuntimeAction, confirmation *Confirmation) (RuntimeRecord, error) {
	if s == nil {
		return RuntimeRecord{}, ErrRuntimeConfig
	}
	s.mu.Lock()
	if err := s.refreshStateLocked(); err != nil {
		s.mu.Unlock()
		return RuntimeRecord{}, err
	}
	if action != RuntimeActionPromote && action != RuntimeActionRollback {
		s.mu.Unlock()
		return RuntimeRecord{}, ErrRuntimeConfig
	}
	if err := validateRuntimeKey(key); err != nil {
		s.mu.Unlock()
		return RuntimeRecord{}, err
	}
	state, ok := s.state.Plugins[key]
	if !ok {
		s.mu.Unlock()
		return RuntimeRecord{}, ErrRuntimeNotFound
	}
	if state.Revision != expectedRevision {
		s.mu.Unlock()
		return RuntimeRecord{}, ErrRuntimeConflict
	}
	var target *RuntimeRecord
	if action == RuntimeActionPromote {
		target = state.Staged
	} else {
		target = state.Previous
	}
	if target == nil {
		s.mu.Unlock()
		return RuntimeRecord{}, ErrRuntimeNotFound
	}
	if target.RequiresConfirm || action == RuntimeActionRollback {
		if err := validateConfirmationFields(state, key, action, *target, expectedRevision, confirmation, s.clock().UTC()); err != nil {
			s.mu.Unlock()
			return RuntimeRecord{}, err
		}
		if s.authorizer == nil {
			s.mu.Unlock()
			return RuntimeRecord{}, ErrRuntimeAuthorization
		}
	}
	targetCopy := cloneRuntimeRecord(*target)
	s.mu.Unlock()
	if err := s.revalidate.Revalidate(targetCopy); err != nil {
		return RuntimeRecord{}, fmt.Errorf("%w: %v", ErrRuntimeUnverified, err)
	}
	if err := s.health.Check(targetCopy); err != nil {
		return RuntimeRecord{}, fmt.Errorf("%w: %v", ErrRuntimeHealthCheck, err)
	}
	if s.authorizer != nil && confirmation != nil {
		if err := s.authorizer.Authorize(*confirmation); err != nil {
			return RuntimeRecord{}, fmt.Errorf("%w: %v", ErrRuntimeAuthorization, err)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	lease, err := acquireRuntimeLease(s.root)
	if err != nil {
		return RuntimeRecord{}, err
	}
	defer lease.Close()
	diskState, err := s.loadDiskState()
	if err != nil {
		return RuntimeRecord{}, err
	}
	live, ok := diskState.Plugins[key]
	if !ok || live.Revision != expectedRevision {
		return RuntimeRecord{}, ErrRuntimeConflict
	}
	if liveTarget := runtimeTarget(live, action); liveTarget == nil || liveTarget.ManifestIdentity != targetCopy.ManifestIdentity {
		return RuntimeRecord{}, ErrRuntimeConflict
	}
	if targetCopy.RequiresConfirm || action == RuntimeActionRollback {
		if err := validateConfirmationFields(live, key, action, *runtimeTarget(live, action), expectedRevision, confirmation, s.clock().UTC()); err != nil {
			return RuntimeRecord{}, err
		}
	}
	state = clonePluginState(live)
	target = runtimeTarget(state, action)
	now := s.clock().UTC()
	newRevision := state.Revision + 1
	if action == RuntimeActionPromote {
		if state.Current != nil {
			previous := cloneRuntimeRecord(*state.Current)
			previous.Slot = RuntimeSlotPrevious
			previous.UpdatedAt = now
			state.Previous = &previous
		}
		current := cloneRuntimeRecord(*target)
		current.Slot, current.Revision, current.UpdatedAt = RuntimeSlotCurrent, newRevision, now
		state.Current = &current
		state.Staged = nil
	} else {
		oldCurrent := state.Current
		current := cloneRuntimeRecord(*target)
		current.Slot, current.Revision, current.UpdatedAt = RuntimeSlotCurrent, newRevision, now
		state.Current = &current
		if oldCurrent != nil {
			old := cloneRuntimeRecord(*oldCurrent)
			old.Slot, old.UpdatedAt = RuntimeSlotPrevious, now
			state.Previous = &old
		}
		state.Staged = nil
	}
	state.Revision = newRevision
	state.Events = append(state.Events, RuntimeEvent{Revision: newRevision, Action: action, ManifestIdentity: target.ManifestIdentity, Actor: confirmationActor(confirmation), At: now})
	if confirmation != nil {
		if state.Used == nil {
			state.Used = map[string]time.Time{}
		}
		state.Used[confirmation.ID] = now
	}
	next := cloneRuntimeDiskState(diskState)
	next.Plugins[key] = state
	if err := s.persistState(next); err != nil {
		return RuntimeRecord{}, err
	}
	s.state = next
	return cloneRuntimeRecord(*state.Current), nil
}

func (s *RuntimeStore) Current(key string) (RuntimeRecord, error) {
	return s.slot(key, RuntimeSlotCurrent)
}
func (s *RuntimeStore) Staged(key string) (RuntimeRecord, error) {
	return s.slot(key, RuntimeSlotStaged)
}
func (s *RuntimeStore) Previous(key string) (RuntimeRecord, error) {
	return s.slot(key, RuntimeSlotPrevious)
}

func (s *RuntimeStore) Get(key string, slot RuntimeSlot) (RuntimeRecord, error) {
	return s.slot(key, slot)
}

func (s *RuntimeStore) slot(key string, slot RuntimeSlot) (RuntimeRecord, error) {
	if s == nil {
		return RuntimeRecord{}, ErrRuntimeConfig
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := validateRuntimeKey(key); err != nil {
		return RuntimeRecord{}, err
	}
	state, ok := s.state.Plugins[key]
	if !ok {
		return RuntimeRecord{}, ErrRuntimeNotFound
	}
	var record *RuntimeRecord
	switch slot {
	case RuntimeSlotCurrent:
		record = state.Current
	case RuntimeSlotStaged:
		record = state.Staged
	case RuntimeSlotPrevious:
		record = state.Previous
	}
	if record == nil {
		return RuntimeRecord{}, ErrRuntimeNotFound
	}
	return cloneRuntimeRecord(*record), nil
}

func (s *RuntimeStore) Snapshot(key string) (RuntimeSnapshot, error) {
	if s == nil {
		return RuntimeSnapshot{}, ErrRuntimeConfig
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := validateRuntimeKey(key); err != nil {
		return RuntimeSnapshot{}, err
	}
	state, ok := s.state.Plugins[key]
	if !ok {
		return RuntimeSnapshot{}, ErrRuntimeNotFound
	}
	return RuntimeSnapshot{Key: key, Revision: state.Revision, Current: cloneOptional(state.Current), Staged: cloneOptional(state.Staged), Previous: cloneOptional(state.Previous)}, nil
}

func (s *RuntimeStore) verifyImportedPackage(pkg Package, imported ImportResult) (Manifest, error) {
	manifest, err := ParseManifest(pkg.Manifest)
	if err != nil {
		return Manifest{}, err
	}
	if _, err := runtimePluginKey(manifest); err != nil {
		return Manifest{}, err
	}
	if err := manifest.Verify(pkg.Artifact); err != nil {
		return Manifest{}, err
	}
	if imported.Manifest != manifest || imported.ArtifactSize != int64(len(pkg.Artifact)) {
		return Manifest{}, ErrRuntimeIdentityMismatch
	}
	identity, err := ContentIdentity(manifest)
	if err != nil || imported.ContentIdentity != identity {
		return Manifest{}, ErrRuntimeIdentityMismatch
	}
	if !imported.admission.verified || imported.admission.packageFingerprint == "" || imported.admission.packageFingerprint != fingerprintPackage(pkg) {
		return Manifest{}, ErrRuntimeUnverified
	}
	if imported.admission.requiredSignatures < 1 ||
		imported.admission.reportFingerprint == "" ||
		imported.admission.reportFingerprint != fingerprintSignatureReport(imported.SignatureReport) ||
		imported.SignatureReport.Status == VerificationRejected {
		return Manifest{}, ErrRuntimeUnverified
	}
	return manifest, nil
}

func validateConfirmationFields(state runtimePluginState, key string, action RuntimeAction, target RuntimeRecord, revision uint64, confirmation *Confirmation, now time.Time) error {
	if confirmation == nil || !validRuntimeField(confirmation.ID) || !validRuntimeField(confirmation.Actor) {
		return ErrRuntimeConfirmationRequired
	}
	if used := state.Used[confirmation.ID]; used != (time.Time{}) {
		return ErrRuntimeConfirmationReplay
	}
	if confirmation.Action != action || confirmation.PluginKey != key || confirmation.ManifestIdentity != target.ManifestIdentity || confirmation.ExpectedRevision != revision || confirmation.ExpiresAt.IsZero() || !confirmation.ExpiresAt.After(now) || confirmation.AuthorizedAt.IsZero() || confirmation.AuthorizedAt.After(now) || !confirmation.ExpiresAt.After(confirmation.AuthorizedAt) || confirmation.ExpiresAt.Sub(confirmation.AuthorizedAt) > maxRuntimeConfirmationTTL {
		return ErrRuntimeAuthorization
	}
	return nil
}

func validRuntimeField(value string) bool {
	if value == "" || value != strings.TrimSpace(value) {
		return false
	}
	for _, r := range value {
		if r < '!' || r > '~' {
			return false
		}
	}
	return true
}

func runtimeTarget(state runtimePluginState, action RuntimeAction) *RuntimeRecord {
	if action == RuntimeActionPromote {
		return state.Staged
	}
	return state.Previous
}

func clonePluginState(state runtimePluginState) runtimePluginState {
	out := state
	out.Current = cloneOptional(state.Current)
	out.Staged = cloneOptional(state.Staged)
	out.Previous = cloneOptional(state.Previous)
	out.Events = append([]RuntimeEvent(nil), state.Events...)
	out.Used = make(map[string]time.Time, len(state.Used))
	for key, value := range state.Used {
		out.Used[key] = value
	}
	return out
}

func cloneRuntimeDiskState(state runtimeDiskState) runtimeDiskState {
	out := runtimeDiskState{Schema: state.Schema, Plugins: make(map[string]runtimePluginState, len(state.Plugins))}
	for key, value := range state.Plugins {
		out.Plugins[key] = clonePluginState(value)
	}
	return out
}

func (s *RuntimeStore) persistArtifact(identity string, artifact []byte) error {
	if err := ensureManagedDirectory(s.root, filepath.Join("artifacts", "sha256")); err != nil {
		return err
	}
	path := filepath.Join(s.root, "artifacts", "sha256", identity)
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return ErrRuntimeSymlink
		}
		if info.Mode().Perm()&0o077 != 0 {
			return ErrRuntimePath
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if artifactIdentity(data) != identity {
			return ErrRuntimeCorrupt
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".artifact-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(artifact); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		if info, statErr := os.Lstat(path); statErr == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm()&0o077 == 0 {
			data, readErr := os.ReadFile(path)
			if readErr == nil && artifactIdentity(data) == identity {
				return nil
			}
			return ErrRuntimeCorrupt
		}
		return err
	}
	return syncRuntimeDirectory(filepath.Dir(path))
}

func (s *RuntimeStore) persistMetadata(key, identity string, manifest []byte, signatures []Signature) (string, string, error) {
	dir := filepath.Join(s.root, "plugins", key, "metadata")
	if err := ensureManagedDirectory(s.root, filepath.Join("plugins", key, "metadata")); err != nil {
		return "", "", err
	}
	sigBytes, err := json.Marshal(signatures)
	if err != nil {
		return "", "", err
	}
	manifestPath := filepath.Join(dir, identity+".manifest.json")
	signaturesPath := filepath.Join(dir, identity+".signatures.json")
	if err := persistRuntimeFile(manifestPath, manifest); err != nil {
		return "", "", err
	}
	if err := persistRuntimeFile(signaturesPath, sigBytes); err != nil {
		return "", "", err
	}
	return filepath.ToSlash(filepath.Join("plugins", key, "metadata", identity+".manifest.json")), filepath.ToSlash(filepath.Join("plugins", key, "metadata", identity+".signatures.json")), nil
}

func persistRuntimeFile(path string, data []byte) error {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return ErrRuntimeSymlink
		}
		if info.Mode().Perm()&0o077 != 0 {
			return ErrRuntimePath
		}
		old, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if string(old) != string(data) {
			return ErrRuntimeConflict
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".metadata-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		if info, statErr := os.Lstat(path); statErr == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm()&0o077 == 0 {
			old, readErr := os.ReadFile(path)
			if readErr == nil && string(old) == string(data) {
				return nil
			}
			return ErrRuntimeConflict
		}
		return err
	}
	return syncRuntimeDirectory(filepath.Dir(path))
}

func (s *RuntimeStore) load() error {
	state, err := s.loadDiskState()
	if err != nil {
		return err
	}
	s.state = state
	for key, plugin := range state.Plugins {
		for _, record := range []*RuntimeRecord{plugin.Current, plugin.Staged, plugin.Previous} {
			if record == nil {
				continue
			}
			if err := s.revalidate.Revalidate(*record); err != nil {
				return fmt.Errorf("%w: revalidate loaded %s: %v", ErrRuntimeUnverified, key, err)
			}
		}
	}
	return nil
}

// loadDiskState reads and validates the durable snapshot without invoking
// external callbacks. Callers use it while holding the runtime lease for a
// write, or under s.mu for a read refresh. The snapshot is replaced by
// persistState with rename, so readers observe either the old or new complete
// JSON document.
func (s *RuntimeStore) loadDiskState() (runtimeDiskState, error) {
	info, err := os.Lstat(s.statePath)
	if errors.Is(err, os.ErrNotExist) {
		return runtimeDiskState{Schema: 1, Plugins: map[string]runtimePluginState{}}, nil
	}
	if err != nil {
		return runtimeDiskState{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return runtimeDiskState{}, ErrRuntimeSymlink
	}
	if info.Mode().Perm()&0o077 != 0 {
		return runtimeDiskState{}, ErrRuntimeCorrupt
	}
	f, err := os.Open(s.statePath)
	if err != nil {
		return runtimeDiskState{}, err
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	var state runtimeDiskState
	if err := dec.Decode(&state); err != nil {
		return runtimeDiskState{}, fmt.Errorf("%w: %v", ErrRuntimeCorrupt, err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return runtimeDiskState{}, ErrRuntimeCorrupt
	}
	if state.Schema != 1 || state.Plugins == nil {
		return runtimeDiskState{}, ErrRuntimeCorrupt
	}
	for key, plugin := range state.Plugins {
		if err := validateRuntimeKey(key); err != nil {
			return runtimeDiskState{}, fmt.Errorf("%w: %v", ErrRuntimeCorrupt, err)
		}
		if err := validateStateRecords(key, plugin); err != nil {
			return runtimeDiskState{}, err
		}
		for _, record := range []*RuntimeRecord{plugin.Current, plugin.Staged, plugin.Previous} {
			if record == nil {
				continue
			}
			if err := s.validateLoadedRecord(key, *record); err != nil {
				return runtimeDiskState{}, err
			}
		}
	}
	return state, nil
}

func (s *RuntimeStore) refreshStateLocked() error {
	state, err := s.loadDiskState()
	if err != nil {
		return err
	}
	s.state = state
	return nil
}

func (s *RuntimeStore) validateLoadedRecord(key string, record RuntimeRecord) error {
	if record.ArtifactIdentity != artifactIdentityFromHex(record.ArtifactIdentity) || record.ManifestIdentity != artifactIdentityFromHex(record.ManifestIdentity) {
		return ErrRuntimeCorrupt
	}
	expectedArtifact := filepath.ToSlash(filepath.Join("artifacts", "sha256", record.ArtifactIdentity))
	expectedManifest := filepath.ToSlash(filepath.Join("plugins", key, "metadata", record.ManifestIdentity+".manifest.json"))
	expectedSignatures := filepath.ToSlash(filepath.Join("plugins", key, "metadata", record.ManifestIdentity+".signatures.json"))
	if record.ArtifactPath != expectedArtifact || record.ManifestPath != expectedManifest || record.SignaturesPath != expectedSignatures {
		return ErrRuntimeCorrupt
	}
	artifactPath := filepath.Join(s.root, filepath.FromSlash(record.ArtifactPath))
	info, err := os.Lstat(artifactPath)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return ErrRuntimeCorrupt
	}
	artifact, err := os.ReadFile(artifactPath)
	if err != nil || artifactIdentity(artifact) != record.ArtifactIdentity {
		return ErrRuntimeCorrupt
	}
	manifestPath := filepath.Join(s.root, filepath.FromSlash(record.ManifestPath))
	manifestInfo, err := os.Lstat(manifestPath)
	if err != nil || manifestInfo.Mode()&os.ModeSymlink != 0 || !manifestInfo.Mode().IsRegular() || manifestInfo.Mode().Perm()&0o077 != 0 {
		return ErrRuntimeCorrupt
	}
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		return ErrRuntimeCorrupt
	}
	manifest, err := ParseManifest(manifestBytes)
	if err != nil {
		return fmt.Errorf("%w: manifest metadata: %v", ErrRuntimeCorrupt, err)
	}
	manifestIdentity, err := ContentIdentity(manifest)
	derivedKey, keyErr := runtimePluginKey(manifest)
	if err != nil || keyErr != nil || derivedKey != key || manifestIdentity != record.ManifestIdentity || manifest.PluginID != record.PluginID || manifest.Name != record.Name || manifest.Namespace != record.Namespace || manifest.Version != record.Version || manifest.ReleaseSequence != record.ReleaseSequence {
		return ErrRuntimeCorrupt
	}
	if err := manifest.Verify(artifact); err != nil {
		return fmt.Errorf("%w: artifact metadata: %v", ErrRuntimeCorrupt, err)
	}
	signaturePath := filepath.Join(s.root, filepath.FromSlash(record.SignaturesPath))
	signatureInfo, err := os.Lstat(signaturePath)
	if err != nil || signatureInfo.Mode()&os.ModeSymlink != 0 || !signatureInfo.Mode().IsRegular() || signatureInfo.Mode().Perm()&0o077 != 0 {
		return ErrRuntimeCorrupt
	}
	signatureBytes, err := os.ReadFile(signaturePath)
	if err != nil {
		return ErrRuntimeCorrupt
	}
	if _, err := parseArchiveSignatures(signatureBytes); err != nil {
		return fmt.Errorf("%w: signature metadata: %v", ErrRuntimeCorrupt, err)
	}
	return nil
}

func artifactIdentityFromHex(value string) string {
	if len(value) != sha256.Size*2 {
		return ""
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || hex.EncodeToString(decoded) != value {
		return ""
	}
	return value
}

func (s *RuntimeStore) persistState(state runtimeDiskState) error {
	b, err := json.Marshal(state)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(s.root, ".state-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := replaceRuntimeFile(tmpName, s.statePath); err != nil {
		return err
	}
	return syncRuntimeDirectory(s.root)
}

func ensureRuntimeDirectory(root string) error {
	info, err := os.Lstat(root)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return ErrRuntimePath
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	} else if err := os.MkdirAll(root, 0o700); err != nil {
		return err
	}
	info, err = os.Lstat(root)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return ErrRuntimePath
	}
	if info.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(root, 0o700); err != nil {
			return ErrRuntimePath
		}
		info, err = os.Lstat(root)
		if err != nil || info.Mode().Perm()&0o077 != 0 {
			return ErrRuntimePath
		}
	}
	return nil
}

func ensureManagedDirectory(root, relative string) error {
	if filepath.IsAbs(relative) || relative == "." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || relative == ".." {
		return ErrRuntimePath
	}
	current := root
	for _, part := range strings.Split(relative, string(filepath.Separator)) {
		if part == "" || part == "." || part == ".." {
			return ErrRuntimePath
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			if err := os.Mkdir(current, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
				return err
			}
			info, err = os.Lstat(current)
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return ErrRuntimeSymlink
		}
		if info.Mode().Perm()&0o077 != 0 {
			if err := os.Chmod(current, 0o700); err != nil {
				return ErrRuntimePath
			}
			info, err = os.Lstat(current)
			if err != nil || info.Mode().Perm()&0o077 != 0 {
				return ErrRuntimePath
			}
		}
	}
	return nil
}

func validateRuntimeKey(key string) error {
	if !runtimeKeyPattern.MatchString(key) || key == "." || key == ".." {
		return fmt.Errorf("%w: %q", ErrRuntimePath, key)
	}
	return nil
}
func runtimePluginKey(m Manifest) (string, error) {
	key := m.PluginID
	if key == "" {
		key = m.Name
	}
	if key != strings.TrimSpace(key) {
		return "", fmt.Errorf("%w: %q", ErrRuntimePath, key)
	}
	if err := validateRuntimeKey(key); err != nil {
		return "", err
	}
	return key, nil
}
func artifactIdentity(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
func cloneRuntimeRecord(in RuntimeRecord) RuntimeRecord { return in }
func cloneOptional(in *RuntimeRecord) *RuntimeRecord {
	if in == nil {
		return nil
	}
	out := cloneRuntimeRecord(*in)
	return &out
}
func confirmationActor(c *Confirmation) string {
	if c == nil {
		return ""
	}
	return c.Actor
}
func validateStateRecords(key string, state runtimePluginState) error {
	if state.Revision == 0 && (state.Current != nil || state.Staged != nil || state.Previous != nil || len(state.Events) != 0 || len(state.Used) != 0) {
		return ErrRuntimeCorrupt
	}
	if state.Current != nil && state.Current.Slot != RuntimeSlotCurrent {
		return ErrRuntimeCorrupt
	}
	if state.Staged != nil && state.Staged.Slot != RuntimeSlotStaged {
		return ErrRuntimeCorrupt
	}
	if state.Previous != nil && state.Previous.Slot != RuntimeSlotPrevious {
		return ErrRuntimeCorrupt
	}
	if state.Staged != nil && state.Staged.Revision != state.Revision {
		return ErrRuntimeCorrupt
	}
	if state.Staged == nil && state.Current != nil && state.Current.Revision != state.Revision {
		return ErrRuntimeCorrupt
	}
	seen := make(map[string]struct{}, 3)
	for _, record := range []*RuntimeRecord{state.Current, state.Staged, state.Previous} {
		if record == nil {
			continue
		}
		if record.Key != key || record.ArtifactIdentity == "" || record.ManifestIdentity == "" || record.ArtifactPath == "" || record.Revision == 0 {
			return ErrRuntimeCorrupt
		}
		if record.Revision > state.Revision {
			return ErrRuntimeCorrupt
		}
		identity := record.ManifestIdentity + "/" + record.ArtifactIdentity
		if _, exists := seen[identity]; exists {
			return ErrRuntimeCorrupt
		}
		seen[identity] = struct{}{}
		if err := validateRuntimeKey(record.Key); err != nil {
			return ErrRuntimeCorrupt
		}
		if record.Slot != RuntimeSlotCurrent && record.Slot != RuntimeSlotStaged && record.Slot != RuntimeSlotPrevious {
			return ErrRuntimeCorrupt
		}
	}
	return nil
}
