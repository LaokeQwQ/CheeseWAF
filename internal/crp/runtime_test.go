package crp

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func runtimePackage(t *testing.T, pluginID, version string, sequence uint64, artifact []byte) (Package, ImportResult) {
	t.Helper()
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	keys := make([]ed25519.PrivateKey, 3)
	trustKeys := make([]TrustKey, 3)
	for i := range keys {
		_, keys[i], _ = ed25519.GenerateKey(rand.Reader)
		trustKeys[i] = TrustKey{ID: "runtime-" + string(rune('a'+i)), PublicKey: keys[i].Public().(ed25519.PublicKey), Class: SignerOfficial}
	}
	m := testManifest(artifact)
	m.PluginID = pluginID
	m.Name = pluginID
	m.Version = version
	m.ReleaseSequence = sequence
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	sig1, err := SignManifestWithKeyID(m, "runtime-a", keys[0], now)
	if err != nil {
		t.Fatal(err)
	}
	sig2, err := SignManifestWithKeyID(m, "runtime-b", keys[1], now)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewSourceRegistry([]SourceRootRegistration{{ID: "vendor-root-v1", NamespacePrefixes: []string{"official/"}, Sources: []string{"ota"}}})
	if err != nil {
		t.Fatal(err)
	}
	trust, err := NewTrustStore([]TrustRoot{{ID: "vendor-root-v1", Class: SignerOfficial, NamespacePrefixes: []string{"official/"}, Keys: trustKeys}})
	if err != nil {
		t.Fatal(err)
	}
	pkg := Package{Manifest: raw, Artifact: append([]byte(nil), artifact...), Signatures: []Signature{sig1, sig2}}
	result, err := Import(pkg, ImportOptions{SourceRegistry: registry, TrustStore: trust, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	return pkg, result
}

func runtimeConfirmation(key string, action RuntimeAction, manifestID string, revision uint64, at time.Time) *Confirmation {
	return &Confirmation{
		ID:               "confirm-" + string(action) + "-" + manifestID[:8],
		Actor:            "operator-1",
		Action:           action,
		PluginKey:        key,
		ManifestIdentity: manifestID,
		ExpectedRevision: revision,
		AuthorizedAt:     at.Add(-time.Second),
		ExpiresAt:        at.Add(time.Hour),
	}
}

func runtimeAuthorizer() RuntimeAuthorizer {
	return RuntimeAuthorizerFunc(func(Confirmation) error { return nil })
}

func TestRuntimeStagePromoteRollbackPersistsSafeState(t *testing.T) {
	root := t.TempDir()
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	var healthCalls atomic.Int32
	store, err := NewRuntimeStore(root, RuntimeStoreOptions{
		Clock: func() time.Time { return now },
		HealthCheck: HealthCheckFunc(func(record RuntimeRecord) error {
			healthCalls.Add(1)
			if record.Slot != RuntimeSlotStaged && record.Slot != RuntimeSlotPrevious {
				return errors.New("unexpected slot")
			}
			return nil
		}),
		Revalidate: RuntimeRevalidateFunc(func(RuntimeRecord) error { return nil }),
		Authorizer: runtimeAuthorizer(),
	})
	if err != nil {
		t.Fatal(err)
	}
	pkg1, imported1 := runtimePackage(t, "rate-limit", "1.0.0", 1, []byte("artifact-one"))
	staged, err := store.Stage(pkg1, imported1)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	if staged.Revision != 1 || staged.ManifestIdentity != imported1.ContentIdentity {
		t.Fatalf("staged=%+v, want revision 1 and manifest identity %q", staged, imported1.ContentIdentity)
	}
	wantArtifact := sha256.Sum256(pkg1.Artifact)
	if staged.ArtifactIdentity != hex.EncodeToString(wantArtifact[:]) || staged.ArtifactIdentity == staged.ManifestIdentity {
		t.Fatalf("artifact identity=%q manifest identity=%q", staged.ArtifactIdentity, staged.ManifestIdentity)
	}
	if _, err := store.Current("rate-limit"); !errors.Is(err, ErrRuntimeNotFound) {
		t.Fatalf("current before promote err=%v", err)
	}
	current, err := store.Promote("rate-limit", staged.Revision, nil)
	if err != nil {
		t.Fatalf("promote: %v", err)
	}
	if current.Revision != 2 || current.Slot != RuntimeSlotCurrent {
		t.Fatalf("current=%+v", current)
	}
	if _, err := store.Staged("rate-limit"); !errors.Is(err, ErrRuntimeNotFound) {
		t.Fatalf("staged after promote err=%v", err)
	}
	pkg2, imported2 := runtimePackage(t, "rate-limit", "1.1.0", 2, []byte("artifact-two"))
	staged2, err := store.Stage(pkg2, imported2)
	if err != nil {
		t.Fatalf("stage second: %v", err)
	}
	current2, err := store.Promote("rate-limit", staged2.Revision, nil)
	if err != nil {
		t.Fatalf("promote second: %v", err)
	}
	previous, err := store.Previous("rate-limit")
	if err != nil || previous.ManifestIdentity != current.ManifestIdentity {
		t.Fatalf("previous=%+v err=%v", previous, err)
	}
	confirmation := runtimeConfirmation("rate-limit", RuntimeActionRollback, previous.ManifestIdentity, current2.Revision, now)
	rolled, err := store.Rollback("rate-limit", current2.Revision, confirmation)
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if rolled.Revision <= current2.Revision || rolled.ManifestIdentity != previous.ManifestIdentity || rolled.Slot != RuntimeSlotCurrent {
		t.Fatalf("rolled=%+v", rolled)
	}
	if healthCalls.Load() != 3 {
		t.Fatalf("health calls=%d, want 3", healthCalls.Load())
	}
	if _, err := store.Rollback("rate-limit", rolled.Revision, confirmation); !errors.Is(err, ErrRuntimeConfirmationReplay) {
		t.Fatalf("confirmation replay err=%v", err)
	}
	reopened, err := NewRuntimeStore(root, RuntimeStoreOptions{Clock: func() time.Time { return now }, HealthCheck: HealthCheckFunc(func(RuntimeRecord) error { return nil }), Revalidate: RuntimeRevalidateFunc(func(RuntimeRecord) error { return nil }), Authorizer: runtimeAuthorizer()})
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := reopened.Current("rate-limit")
	if err != nil || loaded.ManifestIdentity != rolled.ManifestIdentity || loaded.ArtifactIdentity != rolled.ArtifactIdentity {
		t.Fatalf("reopened current=%+v err=%v", loaded, err)
	}
	artifactPath := filepath.Join(root, "artifacts", "sha256", rolled.ArtifactIdentity)
	info, err := os.Lstat(artifactPath)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("artifact mode/type=%v", info.Mode())
	}
}

func TestRuntimeRejectsUnverifiedMismatchedAndDowngradeInputsWithoutState(t *testing.T) {
	root := t.TempDir()
	store, err := NewRuntimeStore(root, RuntimeStoreOptions{Clock: time.Now, HealthCheck: HealthCheckFunc(func(RuntimeRecord) error { return nil }), Revalidate: RuntimeRevalidateFunc(func(RuntimeRecord) error { return nil }), Authorizer: runtimeAuthorizer()})
	if err != nil {
		t.Fatal(err)
	}
	pkg, imported := runtimePackage(t, "rate-limit", "1.0.0", 1, []byte("artifact"))
	unverified := imported
	unverified.SignatureReport.Status = VerificationRejected
	if _, err := store.Stage(pkg, unverified); !errors.Is(err, ErrRuntimeUnverified) {
		t.Fatalf("unverified stage err=%v", err)
	}
	badArtifact := pkg
	badArtifact.Artifact = append([]byte(nil), pkg.Artifact...)
	badArtifact.Artifact[0] ^= 1
	if _, err := store.Stage(badArtifact, imported); !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("digest mismatch stage err=%v", err)
	}
	badIdentity := imported
	badIdentity.ContentIdentity = "0000000000000000000000000000000000000000000000000000000000000000"
	if _, err := store.Stage(pkg, badIdentity); !errors.Is(err, ErrRuntimeIdentityMismatch) {
		t.Fatalf("identity mismatch stage err=%v", err)
	}
	if _, err := store.Snapshot("rate-limit"); !errors.Is(err, ErrRuntimeNotFound) {
		t.Fatalf("snapshot after rejected stages err=%v", err)
	}
	// A valid imported package cannot be staged over a newer current release.
	valid, err := store.Stage(pkg, imported)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Promote("rate-limit", valid.Revision, nil); err != nil {
		t.Fatal(err)
	}
	pkgOld, importedOld := runtimePackage(t, "rate-limit", "0.9.0", 0, []byte("old"))
	if _, err := store.Stage(pkgOld, importedOld); !errors.Is(err, ErrDowngrade) {
		t.Fatalf("downgrade stage err=%v", err)
	}
}

func TestRuntimePromotionHealthConfirmationAndRevisionConflictsAreAtomic(t *testing.T) {
	root := t.TempDir()
	now := time.Date(2026, 9, 7, 13, 0, 0, 0, time.UTC)
	allowHealth := false
	store, err := NewRuntimeStore(root, RuntimeStoreOptions{
		Clock: func() time.Time { return now },
		HealthCheck: HealthCheckFunc(func(RuntimeRecord) error {
			if !allowHealth {
				return errors.New("unhealthy")
			}
			return nil
		}),
		Revalidate: RuntimeRevalidateFunc(func(RuntimeRecord) error { return nil }),
		Authorizer: runtimeAuthorizer(),
	})
	if err != nil {
		t.Fatal(err)
	}
	pkg, imported := runtimePackage(t, "rate-limit", "1.0.0", 1, []byte("artifact"))
	staged, err := store.Stage(pkg, imported)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Promote("rate-limit", staged.Revision, nil); !errors.Is(err, ErrRuntimeHealthCheck) {
		t.Fatalf("unhealthy promote err=%v", err)
	}
	state, err := store.Snapshot("rate-limit")
	if err != nil || state.Revision != staged.Revision || state.Current != nil || state.Staged == nil {
		t.Fatalf("state after failed health check=%+v err=%v", state, err)
	}
	allowHealth = true
	current, err := store.Promote("rate-limit", staged.Revision, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Promote("rate-limit", staged.Revision, nil); !errors.Is(err, ErrRuntimeConflict) {
		t.Fatalf("stale promotion err=%v", err)
	}
	if current.Revision != staged.Revision+1 {
		t.Fatalf("current revision=%d, want %d", current.Revision, staged.Revision+1)
	}
}

func TestRuntimeRejectsUnsafePluginPathAndManagedSymlink(t *testing.T) {
	root := t.TempDir()
	store, err := NewRuntimeStore(root, RuntimeStoreOptions{Clock: time.Now, HealthCheck: HealthCheckFunc(func(RuntimeRecord) error { return nil }), Revalidate: RuntimeRevalidateFunc(func(RuntimeRecord) error { return nil }), Authorizer: runtimeAuthorizer()})
	if err != nil {
		t.Fatal(err)
	}
	pkg, imported := runtimePackage(t, "safe-plugin", "1.0.0", 1, []byte("artifact"))
	var manifest Manifest
	if err := json.Unmarshal(pkg.Manifest, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.PluginID = "../escape"
	manifest.Name = "../escape"
	pkg.Manifest, _ = json.Marshal(manifest)
	imported.Manifest = manifest
	imported.ContentIdentity, _ = ContentIdentity(manifest)
	if _, err := store.Stage(pkg, imported); !errors.Is(err, ErrRuntimePath) {
		t.Fatalf("unsafe plugin path err=%v", err)
	}
	outside := filepath.Join(root, "outside")
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	plugins := filepath.Join(root, "plugins")
	if err := os.Symlink(outside, filepath.Join(plugins, "safe-plugin")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := store.Stage(runtimePackageMust(t, "safe-plugin", "1.0.0", 1, []byte("artifact"))); !errors.Is(err, ErrRuntimeSymlink) {
		t.Fatalf("managed symlink err=%v", err)
	}
}

func TestRuntimeHealthCheckCanReadStateWithoutDeadlock(t *testing.T) {
	root := t.TempDir()
	var store *RuntimeStore
	done := make(chan struct{})
	var healthErr error
	store, err := NewRuntimeStore(root, RuntimeStoreOptions{
		Clock:      time.Now,
		Revalidate: RuntimeRevalidateFunc(func(RuntimeRecord) error { return nil }),
		Authorizer: runtimeAuthorizer(),
		HealthCheck: HealthCheckFunc(func(record RuntimeRecord) error {
			_, healthErr = store.Snapshot(record.Key)
			close(done)
			return healthErr
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	pkg, imported := runtimePackage(t, "deadlock-check", "1.0.0", 1, []byte("artifact"))
	staged, err := store.Stage(pkg, imported)
	if err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() { _, err := store.Promote("deadlock-check", staged.Revision, nil); finished <- err }()
	select {
	case err := <-finished:
		if err != nil {
			t.Fatalf("promote: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("promotion blocked while health check read the runtime state")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("health callback was not reached")
	}
}

func TestRuntimeStageRevalidationCanReadStateWithoutDeadlockBasic(t *testing.T) {
	root := t.TempDir()
	var store *RuntimeStore
	reached := make(chan struct{})
	store, err := NewRuntimeStore(root, RuntimeStoreOptions{
		Clock:       time.Now,
		HealthCheck: HealthCheckFunc(func(RuntimeRecord) error { return nil }),
		Revalidate: RuntimeRevalidateFunc(func(record RuntimeRecord) error {
			_, _ = store.Snapshot(record.Key)
			close(reached)
			return nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	pkg, imported := runtimePackage(t, "stage-deadlock-check", "1.0.0", 1, []byte("artifact"))
	done := make(chan error, 1)
	go func() {
		_, err := store.Stage(pkg, imported)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("stage: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("stage blocked while revalidation read runtime state")
	}
	select {
	case <-reached:
	case <-time.After(time.Second):
		t.Fatal("revalidation callback was not reached")
	}
}

func TestRuntimeTightensPermissiveRuntimePermissions(t *testing.T) {
	options := RuntimeStoreOptions{Clock: time.Now, HealthCheck: HealthCheckFunc(func(RuntimeRecord) error { return nil }), Revalidate: RuntimeRevalidateFunc(func(RuntimeRecord) error { return nil })}
	root := t.TempDir()
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRuntimeStore(root, options); err != nil {
		t.Fatalf("tighten permissive root: %v", err)
	}
	if info, err := os.Lstat(root); err != nil || info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("runtime root permissions were not tightened: mode=%v err=%v", infoMode(info), err)
	}

	root = t.TempDir()
	store, err := NewRuntimeStore(root, options)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "plugins"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRuntimeStore(root, options); err != nil {
		t.Fatalf("tighten permissive managed directory: %v", err)
	}
	if info, err := os.Lstat(filepath.Join(root, "plugins")); err != nil || info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("managed directory permissions were not tightened: mode=%v err=%v", infoMode(info), err)
	}
	_ = store
}

func infoMode(info os.FileInfo) os.FileMode {
	if info == nil {
		return 0
	}
	return info.Mode()
}

func TestRuntimeRejectsPermissiveStateAndExistingContent(t *testing.T) {
	options := RuntimeStoreOptions{Clock: time.Now, HealthCheck: HealthCheckFunc(func(RuntimeRecord) error { return nil }), Revalidate: RuntimeRevalidateFunc(func(RuntimeRecord) error { return nil })}
	root := t.TempDir()
	store, err := NewRuntimeStore(root, options)
	if err != nil {
		t.Fatal(err)
	}
	pkg, imported := runtimePackage(t, "permission-check", "1.0.0", 1, []byte("artifact"))
	staged, err := store.Stage(pkg, imported)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "state.json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRuntimeStore(root, options); !errors.Is(err, ErrRuntimeCorrupt) {
		t.Fatalf("permissive state file accepted: %v", err)
	}

	root = t.TempDir()
	store, err = NewRuntimeStore(root, options)
	if err != nil {
		t.Fatal(err)
	}
	artifact := []byte("preexisting")
	pkg, imported = runtimePackage(t, "existing-content", "1.0.0", 1, artifact)
	artifactID := artifactIdentity(artifact)
	path := filepath.Join(root, "artifacts", "sha256", artifactID)
	if err := os.WriteFile(path, artifact, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Stage(pkg, imported); !errors.Is(err, ErrRuntimePath) {
		t.Fatalf("permissive preexisting artifact accepted: %v", err)
	}
	_ = staged
}

func TestRuntimeStateWriteFailureDoesNotMutateMemory(t *testing.T) {
	root := t.TempDir()
	store, err := NewRuntimeStore(root, RuntimeStoreOptions{Clock: time.Now, HealthCheck: HealthCheckFunc(func(RuntimeRecord) error { return nil }), Revalidate: RuntimeRevalidateFunc(func(RuntimeRecord) error { return nil }), Authorizer: runtimeAuthorizer()})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "state.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	pkg, imported := runtimePackage(t, "atomic-state", "1.0.0", 1, []byte("artifact"))
	if _, err := store.Stage(pkg, imported); err == nil {
		t.Fatal("stage unexpectedly succeeded with a directory at state.json")
	}
	if _, err := store.Snapshot("atomic-state"); !errors.Is(err, ErrRuntimeNotFound) {
		t.Fatalf("failed state write changed in-memory state: %v", err)
	}
}

func TestRuntimeRollbackRequiresExternalAuthorizer(t *testing.T) {
	root := t.TempDir()
	store, err := NewRuntimeStore(root, RuntimeStoreOptions{Clock: time.Now, HealthCheck: HealthCheckFunc(func(RuntimeRecord) error { return nil }), Revalidate: RuntimeRevalidateFunc(func(RuntimeRecord) error { return nil })})
	if err != nil {
		t.Fatal(err)
	}
	first, firstImport := runtimePackage(t, "authorization-check", "1.0.0", 1, []byte("one"))
	staged, err := store.Stage(first, firstImport)
	if err != nil {
		t.Fatal(err)
	}
	current, err := store.Promote("authorization-check", staged.Revision, nil)
	if err != nil {
		t.Fatal(err)
	}
	second, secondImport := runtimePackage(t, "authorization-check", "1.1.0", 2, []byte("two"))
	staged, err = store.Stage(second, secondImport)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Promote("authorization-check", staged.Revision, nil); err != nil {
		t.Fatal(err)
	}
	previous, err := store.Previous("authorization-check")
	if err != nil {
		t.Fatal(err)
	}
	confirmation := runtimeConfirmation("authorization-check", RuntimeActionRollback, previous.ManifestIdentity, current.Revision+2, time.Now().UTC())
	if _, err := store.Rollback("authorization-check", current.Revision+2, confirmation); !errors.Is(err, ErrRuntimeAuthorization) {
		t.Fatalf("rollback without external authorizer err=%v", err)
	}
}

func TestRuntimeRestartRejectsTamperedArtifact(t *testing.T) {
	root := t.TempDir()
	options := RuntimeStoreOptions{Clock: time.Now, HealthCheck: HealthCheckFunc(func(RuntimeRecord) error { return nil }), Revalidate: RuntimeRevalidateFunc(func(RuntimeRecord) error { return nil }), Authorizer: runtimeAuthorizer()}
	store, err := NewRuntimeStore(root, options)
	if err != nil {
		t.Fatal(err)
	}
	pkg, imported := runtimePackage(t, "tamper-check", "1.0.0", 1, []byte("artifact"))
	staged, err := store.Stage(pkg, imported)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, staged.ArtifactPath), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRuntimeStore(root, options); !errors.Is(err, ErrRuntimeCorrupt) {
		t.Fatalf("restart accepted tampered artifact: %v", err)
	}
}

func TestRuntimeRestartRevalidatesLoadedRecords(t *testing.T) {
	root := t.TempDir()
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	var revalidations atomic.Int32
	options := RuntimeStoreOptions{
		Clock:       func() time.Time { return now },
		HealthCheck: HealthCheckFunc(func(RuntimeRecord) error { return nil }),
		Revalidate: RuntimeRevalidateFunc(func(RuntimeRecord) error {
			revalidations.Add(1)
			return nil
		}),
	}
	store, err := NewRuntimeStore(root, options)
	if err != nil {
		t.Fatal(err)
	}
	pkg, imported := runtimePackage(t, "restart-revalidate", "1.0.0", 1, []byte("artifact"))
	if _, err := store.Stage(pkg, imported); err != nil {
		t.Fatal(err)
	}
	before := revalidations.Load()
	if _, err := NewRuntimeStore(root, options); err != nil {
		t.Fatal(err)
	}
	if revalidations.Load() <= before {
		t.Fatalf("restart did not revalidate loaded record: before=%d after=%d", before, revalidations.Load())
	}
}

func TestRuntimeRestartRejectsInconsistentRecordMetadata(t *testing.T) {
	root := t.TempDir()
	options := RuntimeStoreOptions{Clock: time.Now, HealthCheck: HealthCheckFunc(func(RuntimeRecord) error { return nil }), Revalidate: RuntimeRevalidateFunc(func(RuntimeRecord) error { return nil })}
	store, err := NewRuntimeStore(root, options)
	if err != nil {
		t.Fatal(err)
	}
	pkg, imported := runtimePackage(t, "metadata-check", "1.0.0", 1, []byte("artifact"))
	if _, err := store.Stage(pkg, imported); err != nil {
		t.Fatal(err)
	}
	stateBytes, err := os.ReadFile(filepath.Join(root, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	var state runtimeDiskState
	if err := json.Unmarshal(stateBytes, &state); err != nil {
		t.Fatal(err)
	}
	state.Plugins["metadata-check"].Staged.PluginID = "other-plugin"
	state.Plugins["metadata-check"].Staged.Slot = RuntimeSlotCurrent
	mutated, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "state.json"), mutated, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRuntimeStore(root, options); !errors.Is(err, ErrRuntimeCorrupt) {
		t.Fatalf("inconsistent runtime record accepted: %v", err)
	}
}

func TestRuntimeRequiresRevalidationAndHealthCallbacks(t *testing.T) {
	root := t.TempDir()
	if _, err := NewRuntimeStore(root, RuntimeStoreOptions{}); !errors.Is(err, ErrRuntimeConfig) {
		t.Fatalf("missing safety callbacks err=%v, want ErrRuntimeConfig", err)
	}
}

func TestRuntimeStageRevalidationCanReadStateWithoutDeadlock(t *testing.T) {
	root := t.TempDir()
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	var store *RuntimeStore
	reached := make(chan struct{}, 1)
	store, err := NewRuntimeStore(root, RuntimeStoreOptions{
		Clock:       func() time.Time { return now },
		HealthCheck: HealthCheckFunc(func(RuntimeRecord) error { return nil }),
		Revalidate: RuntimeRevalidateFunc(func(record RuntimeRecord) error {
			select {
			case reached <- struct{}{}:
			default:
			}
			_, snapshotErr := store.Snapshot(record.Key)
			if snapshotErr != nil && !errors.Is(snapshotErr, ErrRuntimeNotFound) {
				return snapshotErr
			}
			return nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	pkg, imported := runtimePackage(t, "stage-revalidate-read", "1.0.0", 1, []byte("artifact"))
	finished := make(chan error, 1)
	go func() {
		_, stageErr := store.Stage(pkg, imported)
		finished <- stageErr
	}()
	select {
	case stageErr := <-finished:
		if stageErr != nil {
			t.Fatalf("stage: %v", stageErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("stage blocked while revalidator read the runtime state")
	}
	select {
	case <-reached:
	case <-time.After(time.Second):
		t.Fatal("stage revalidator was not reached")
	}
}

func TestRuntimeAdmissionReportMutationCannotLowerConfirmation(t *testing.T) {
	root := t.TempDir()
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	store, err := NewRuntimeStore(root, RuntimeStoreOptions{
		Clock:       func() time.Time { return now },
		HealthCheck: HealthCheckFunc(func(RuntimeRecord) error { return nil }),
		Revalidate:  RuntimeRevalidateFunc(func(RuntimeRecord) error { return nil }),
	})
	if err != nil {
		t.Fatal(err)
	}
	pkg, imported := confirmationRuntimePackage(t, "community-runtime", "1.0.0", 1, []byte("community-artifact"))
	if imported.SignatureReport.Status != VerificationNeedsConfirmation {
		t.Fatalf("fixture report=%+v, want confirmation status", imported.SignatureReport)
	}
	if !imported.admission.requiresConfirmation || imported.admission.requiredSignatures < 1 {
		t.Fatalf("fixture admission=%+v, want sealed confirmation decision", imported.admission)
	}
	tampered := imported
	tampered.SignatureReport.Status = VerificationTrusted
	tampered.SignatureReport.Required = 0
	if _, err := store.Stage(pkg, tampered); !errors.Is(err, ErrRuntimeUnverified) {
		t.Fatalf("tampered report stage err=%v, want ErrRuntimeUnverified", err)
	}
	staged, err := store.Stage(pkg, imported)
	if err != nil {
		t.Fatalf("original admission stage: %v", err)
	}
	if !staged.RequiresConfirm {
		t.Fatalf("staged record lost sealed confirmation requirement: %+v", staged)
	}
}

func TestRuntimeConfirmationRejectsInvalidLifetime(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	for name, lifetime := range map[string]struct{ authorizedAt, expiresAt time.Time }{
		"reversed": {authorizedAt: now.Add(time.Hour), expiresAt: now.Add(2 * time.Hour)},
		"too-long": {authorizedAt: now.Add(-time.Minute), expiresAt: now.Add(48 * time.Hour)},
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			store, err := NewRuntimeStore(root, RuntimeStoreOptions{
				Clock:       func() time.Time { return now },
				HealthCheck: HealthCheckFunc(func(RuntimeRecord) error { return nil }),
				Revalidate:  RuntimeRevalidateFunc(func(RuntimeRecord) error { return nil }),
				Authorizer:  runtimeAuthorizer(),
			})
			if err != nil {
				t.Fatal(err)
			}
			pkg, imported := confirmationRuntimePackage(t, "confirmation-lifetime", "1.0.0", 1, []byte("artifact"))
			staged, err := store.Stage(pkg, imported)
			if err != nil {
				t.Fatal(err)
			}
			confirmation := &Confirmation{ID: "confirm-" + name, Actor: "operator-1", Action: RuntimeActionPromote, PluginKey: "confirmation-lifetime", ManifestIdentity: staged.ManifestIdentity, ExpectedRevision: staged.Revision, AuthorizedAt: lifetime.authorizedAt, ExpiresAt: lifetime.expiresAt}
			if _, err := store.Promote("confirmation-lifetime", staged.Revision, confirmation); !errors.Is(err, ErrRuntimeAuthorization) && !errors.Is(err, ErrRuntimeConfirmationRequired) {
				t.Fatalf("invalid confirmation accepted: %v", err)
			}
		})
	}
}

func TestRuntimeStagedIdempotenceRequiresManifestIdentity(t *testing.T) {
	root := t.TempDir()
	store, err := NewRuntimeStore(root, RuntimeStoreOptions{
		Clock:       time.Now,
		HealthCheck: HealthCheckFunc(func(RuntimeRecord) error { return nil }),
		Revalidate:  RuntimeRevalidateFunc(func(RuntimeRecord) error { return nil }),
	})
	if err != nil {
		t.Fatal(err)
	}
	artifact := []byte("same-artifact")
	pkg1, imported1 := runtimePackage(t, "staged-identity", "1.0.0", 1, artifact)
	first, err := store.Stage(pkg1, imported1)
	if err != nil {
		t.Fatalf("first stage: %v", err)
	}
	pkg2, imported2 := runtimePackage(t, "staged-identity", "1.1.0", 2, artifact)
	if imported1.ContentIdentity == imported2.ContentIdentity {
		t.Fatal("fixture manifests unexpectedly have the same content identity")
	}
	if _, err := store.Stage(pkg2, imported2); !errors.Is(err, ErrRuntimeConflict) {
		t.Fatalf("same artifact/different manifest stage err=%v, want ErrRuntimeConflict", err)
	}
	current, err := store.Staged("staged-identity")
	if err != nil {
		t.Fatal(err)
	}
	if current.ManifestIdentity != first.ManifestIdentity || current.ArtifactIdentity != first.ArtifactIdentity {
		t.Fatalf("staged record changed after conflicting candidate: %+v", current)
	}
}

func confirmationRuntimePackage(t *testing.T, pluginID, version string, sequence uint64, artifact []byte) (Package, ImportResult) {
	t.Helper()
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	m := testManifest(artifact)
	m.PluginID = pluginID
	m.Name = pluginID
	m.Namespace = "community/alice/" + pluginID
	m.SourceRoot = "community-root"
	m.Source = "ota"
	m.Version = version
	m.ReleaseSequence = sequence
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := SignManifestWithKeyID(m, "alice", private, now)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewSourceRegistry([]SourceRootRegistration{{ID: "community-root", NamespacePrefixes: []string{"community/alice/"}, Sources: []string{"ota"}}})
	if err != nil {
		t.Fatal(err)
	}
	trust, err := NewTrustStore([]TrustRoot{{ID: "community-root", Class: SignerCommunity, NamespacePrefixes: []string{"community/alice/"}, Keys: []TrustKey{{ID: "alice", PublicKey: private.Public().(ed25519.PublicKey), Class: SignerCommunity}}}})
	if err != nil {
		t.Fatal(err)
	}
	pkg := Package{Manifest: raw, Artifact: append([]byte(nil), artifact...), Signatures: []Signature{signature}}
	result, err := Import(pkg, ImportOptions{SourceRegistry: registry, TrustStore: trust, Now: now, AllowConfirmation: true})
	if err != nil {
		t.Fatal(err)
	}
	return pkg, result
}

func runtimePackageMust(t *testing.T, pluginID, version string, sequence uint64, artifact []byte) (Package, ImportResult) {
	t.Helper()
	return runtimePackage(t, pluginID, version, sequence, artifact)
}
