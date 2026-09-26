package materializer

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane/desiredstate"
)

func testStoreReceipt(t *testing.T, phase Phase) Receipt {
	t.Helper()
	commit := testCommit(t, 1, 1, "nonce-1")
	receipt, err := NewReceipt(commit, phase)
	if err != nil {
		t.Fatal(err)
	}
	return receipt
}

func TestJournalStoreRoundTripAndPermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "materializer")
	store, err := NewJournalStore(dir, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	receipt := testStoreReceipt(t, PhasePrepared)
	if err := store.SaveJournal(receipt); err != nil {
		t.Fatal(err)
	}
	got, err := store.LoadJournal()
	if err != nil {
		t.Fatal(err)
	}
	if !sameCommit(got, receipt) || got.Phase != receipt.Phase {
		t.Fatalf("loaded receipt=%+v, want %+v", got, receipt)
	}
	for _, name := range []string{JournalPrimaryName, JournalBackupName} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("%s mode=%o, want 0600", name, info.Mode().Perm())
		}
	}
	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if dirInfo.Mode().Perm() != 0700 {
		t.Fatalf("directory mode=%o, want 0700", dirInfo.Mode().Perm())
	}
}

func TestJournalStoreLKGRequiresApplied(t *testing.T) {
	store, err := NewJournalStore(t.TempDir(), Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveLKG(testStoreReceipt(t, PhaseRuntimeApplied)); err == nil {
		t.Fatal("runtime_applied LKG unexpectedly accepted")
	}
	applied := testStoreReceipt(t, PhaseApplied)
	if err := store.SaveLKG(applied); err != nil {
		t.Fatal(err)
	}
	got, err := store.LoadLKG()
	if err != nil || !sameCommit(got, applied) || got.Phase != PhaseApplied {
		t.Fatalf("LKG=%+v err=%v", got, err)
	}
}

func TestJournalStoreRejectsCorruptUnknownTrailingAndOversizedRecords(t *testing.T) {
	store, err := NewJournalStore(t.TempDir(), Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveJournal(testStoreReceipt(t, PhasePrepared)); err != nil {
		t.Fatal(err)
	}
	primary := filepath.Join(store.Directory(), JournalPrimaryName)
	original, err := os.ReadFile(primary)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"trailing":  append(append([]byte(nil), original...), []byte(`{}`)...),
		"unknown":   []byte(strings.TrimSuffix(string(original), "}") + `,"unexpected":true}`),
		"oversized": append(append([]byte(nil), original...), make([]byte, MaxReceiptBytes)...),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(primary, data, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(store.Directory(), JournalBackupName), data, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := store.LoadJournal(); err == nil || !errors.Is(err, ErrReceiptCorrupt) {
				t.Fatalf("LoadJournal err=%v, want ErrReceiptCorrupt", err)
			}
			if err := os.WriteFile(primary, original, 0600); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestJournalStoreRejectsSymlinkAndUnsafePermissions(t *testing.T) {
	root := t.TempDir()
	store, err := NewJournalStore(root, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveJournal(testStoreReceipt(t, PhasePrepared)); err != nil {
		t.Fatal(err)
	}
	primary := filepath.Join(root, JournalPrimaryName)
	target := filepath.Join(root, "target")
	if err := os.Rename(primary, target); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, primary); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := store.LoadJournal(); err == nil || !errors.Is(err, ErrReceiptCorrupt) {
		t.Fatal("symlink receipt unexpectedly accepted")
	}
	if err := os.Remove(primary); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(target, primary); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(primary, 0640); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadJournal(); err == nil || !errors.Is(err, ErrReceiptCorrupt) {
		t.Fatalf("unsafe permission err=%v, want ErrReceiptCorrupt", err)
	}

	unsafeDir := filepath.Join(root, "unsafe")
	if err := os.Mkdir(unsafeDir, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := NewJournalStore(unsafeDir, Hooks{}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(unsafeDir)
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatalf("journal directory mode=%o err=%v, want 0700", info.Mode().Perm(), err)
	}
}

func TestJournalStorePrimaryBackupBehavior(t *testing.T) {
	store, err := NewJournalStore(t.TempDir(), Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	first := testStoreReceipt(t, PhasePrepared)
	if err := store.SaveJournal(first); err != nil {
		t.Fatal(err)
	}
	primary := filepath.Join(store.Directory(), JournalPrimaryName)
	backup := filepath.Join(store.Directory(), JournalBackupName)
	if err := os.WriteFile(primary, []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := store.LoadJournal()
	if err != nil || !sameCommit(got, first) {
		t.Fatalf("valid backup fallback got=%+v err=%v", got, err)
	}
	second := first.Clone()
	second.Commit.Revision = 2
	second.Commit.Nonce = "nonce-2"
	second.Payload = append([]byte(nil), first.Payload...)
	if err := os.WriteFile(primary, mustEncode(t, second), 0600); err != nil {
		t.Fatal(err)
	}
	third := first.Clone()
	third.Commit.Revision = 2
	third.Commit.Nonce = "nonce-3"
	if err := os.WriteFile(backup, mustEncode(t, third), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadJournal(); !errors.Is(err, ErrReceiptAmbiguous) {
		t.Fatalf("mismatched primary/backup err=%v, want ErrReceiptAmbiguous", err)
	}
}

func TestJournalStoreFaultSeamFailsClosed(t *testing.T) {
	called := 0
	store, err := NewJournalStore(t.TempDir(), Hooks{
		SyncFile: func(*os.File) error { return errors.New("injected fsync failure") },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveJournal(testStoreReceipt(t, PhasePrepared)); err == nil {
		t.Fatal("injected fsync failure unexpectedly succeeded")
	}
	if _, err := store.LoadJournal(); !errors.Is(err, ErrReceiptNotFound) {
		t.Fatalf("failed write left journal=%v, want ErrReceiptNotFound", err)
	}
	store, err = NewJournalStore(t.TempDir(), Hooks{
		Rename: func(_, _ string) error {
			called++
			return errors.New("injected rename failure")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveJournal(testStoreReceipt(t, PhasePrepared)); err == nil || called == 0 {
		t.Fatalf("injected rename failure err=%v calls=%d", err, called)
	}
}

func TestJournalStoreRejectsStaleOrConflictingSave(t *testing.T) {
	store, err := NewJournalStore(t.TempDir(), Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	first := testStoreReceipt(t, PhasePrepared)
	if err := store.SaveJournal(first); err != nil {
		t.Fatal(err)
	}
	stale := first.Clone()
	stale.Commit.Revision = 0
	if err := store.SaveJournal(stale); !errors.Is(err, ErrReceiptCorrupt) {
		t.Fatalf("invalid stale receipt err=%v, want corruption", err)
	}
	conflict := first.Clone()
	conflict.Commit.Nonce = "nonce-conflict"
	if err := store.SaveJournal(conflict); !errors.Is(err, ErrCommitConflict) {
		t.Fatalf("same-revision conflict err=%v, want ErrCommitConflict", err)
	}
	newer := testStoreReceipt(t, PhasePrepared)
	newer.Commit.Revision = 2
	newer.Commit.Nonce = "nonce-2"
	if err := store.SaveJournal(newer); err != nil {
		t.Fatalf("newer journal save: %v", err)
	}
	if err := store.SaveJournal(first); !errors.Is(err, ErrStaleRevision) {
		t.Fatalf("historical journal save err=%v, want ErrStaleRevision", err)
	}
}

func TestJournalStoreLKGIsMonotonicAndIdempotent(t *testing.T) {
	store, err := NewJournalStore(t.TempDir(), Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	first := testStoreReceipt(t, PhaseApplied)
	if err := store.SaveLKG(first); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveLKG(first.Clone()); err != nil {
		t.Fatalf("idempotent LKG save: %v", err)
	}
	newer := first.Clone()
	newer.Commit.Revision = 2
	newer.Commit.Nonce = "nonce-2"
	if err := store.SaveLKG(newer); err != nil {
		t.Fatalf("newer LKG save: %v", err)
	}
	if err := store.SaveLKG(first); !errors.Is(err, ErrStaleRevision) {
		t.Fatalf("older LKG save err=%v, want ErrStaleRevision", err)
	}
	conflict := newer.Clone()
	conflict.Commit.Nonce = "nonce-conflict"
	if err := store.SaveLKG(conflict); !errors.Is(err, ErrCommitConflict) {
		t.Fatalf("same-revision LKG conflict err=%v, want ErrCommitConflict", err)
	}
}

func TestJournalStoreRepairsSingleFailedMirrorOnExactRetry(t *testing.T) {
	failed := false
	store, err := NewJournalStore(t.TempDir(), Hooks{
		Rename: func(oldPath, newPath string) error {
			if failed && strings.HasSuffix(newPath, JournalBackupName) {
				failed = false
				return errors.New("injected backup rename failure")
			}
			return os.Rename(oldPath, newPath)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	oldReceipt := testStoreReceipt(t, PhasePrepared)
	if err := store.SaveJournal(oldReceipt); err != nil {
		t.Fatal(err)
	}
	newReceipt := oldReceipt.Clone()
	newReceipt.Commit.Revision = 2
	newReceipt.Commit.Nonce = "nonce-2"
	failed = true
	if err := store.SaveJournal(newReceipt); err == nil {
		t.Fatal("partial mirror save unexpectedly succeeded")
	}
	if _, err := store.LoadJournal(); !errors.Is(err, ErrReceiptAmbiguous) {
		t.Fatalf("partial valid mirror load err=%v, want ambiguity", err)
	}
	if err := store.SaveJournal(newReceipt); err != nil {
		t.Fatalf("exact retry did not repair mirror: %v", err)
	}
	got, err := store.LoadJournal()
	if err != nil || !sameReceipt(got, newReceipt) {
		t.Fatalf("repaired journal=%+v err=%v", got, err)
	}
	if err := store.SaveJournal(oldReceipt); !errors.Is(err, ErrStaleRevision) {
		t.Fatalf("old retry err=%v, want ErrStaleRevision", err)
	}
}

func TestJournalStoreExactRetrySyncsDirectoryAfterPostRenameFailure(t *testing.T) {
	dir := t.TempDir()
	failAfterBackupRename := false
	syncCalls := 0
	store, err := NewJournalStore(dir, Hooks{
		SyncDir: func(path string) error {
			syncCalls++
			if failAfterBackupRename && syncCalls == 2 {
				return errors.New("injected post-backup-rename directory sync failure")
			}
			file, err := os.Open(path)
			if err != nil {
				return err
			}
			defer file.Close()
			return file.Sync()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	receipt := testStoreReceipt(t, PhasePrepared)
	failAfterBackupRename = true
	if err := store.SaveJournal(receipt); err == nil {
		t.Fatal("post-rename directory sync failure unexpectedly succeeded")
	}
	beforeRetry := syncCalls
	failAfterBackupRename = false
	if err := store.SaveJournal(receipt); err != nil {
		t.Fatalf("exact retry did not re-sync directory: %v", err)
	}
	if syncCalls != beforeRetry+1 {
		t.Fatalf("exact retry sync calls=%d, want %d", syncCalls, beforeRetry+1)
	}
}

func TestJournalStoreRuntimeReceiptExactRetrySyncsDirectory(t *testing.T) {
	syncCalls := 0
	store, err := NewJournalStore(t.TempDir(), Hooks{
		SyncDir: func(path string) error {
			syncCalls++
			file, err := os.Open(path)
			if err != nil {
				return err
			}
			defer file.Close()
			return file.Sync()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	digest, err := ConfigDigest(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := NewRuntimeReceipt(RuntimeRequest{
		Commit:         testStoreReceipt(t, PhasePrepared).Commit,
		IdempotencyKey: "runtime-receipt-retry",
		ConfigDigest:   digest,
		Config:         &cfg,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveRuntimeReceiptContext(context.Background(), receipt); err != nil {
		t.Fatal(err)
	}
	beforeRetry := syncCalls
	if err := store.SaveRuntimeReceiptContext(context.Background(), receipt); err != nil {
		t.Fatalf("exact runtime receipt retry: %v", err)
	}
	if syncCalls != beforeRetry+1 {
		t.Fatalf("exact runtime receipt retry sync calls=%d, want %d", syncCalls, beforeRetry+1)
	}
}

func TestRuntimeReceiptRejectsInvalidCommitIdentity(t *testing.T) {
	cfg := config.Default()
	digest, err := ConfigDigest(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	invalid := RuntimeReceipt{Schema: runtimeReceiptSchema, ConfigDigest: digest, IdempotencyKey: "key"}
	if err := invalid.Validate(); !errors.Is(err, ErrReceiptCorrupt) {
		t.Fatalf("invalid runtime receipt error=%v, want corruption", err)
	}
	store, err := NewJournalStore(t.TempDir(), Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveRuntimeReceiptContext(context.Background(), invalid); !errors.Is(err, ErrReceiptCorrupt) {
		t.Fatalf("invalid runtime receipt save error=%v, want corruption", err)
	}
}

func TestJournalStoreRuntimeReceiptRejectsSameCommitDifferentIntent(t *testing.T) {
	store, err := NewJournalStore(t.TempDir(), Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	digest, err := ConfigDigest(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	request := RuntimeRequest{Commit: testStoreReceipt(t, PhasePrepared).Commit, IdempotencyKey: "key-a", ConfigDigest: digest, Config: &cfg}
	first, err := NewRuntimeReceipt(request)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveRuntimeReceiptContext(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	request.IdempotencyKey = "key-b"
	second, err := NewRuntimeReceipt(request)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveRuntimeReceiptContext(context.Background(), second); !errors.Is(err, ErrCommitConflict) {
		t.Fatalf("same-commit different intent error=%v, want conflict", err)
	}
}

func TestJournalStoresShareDirectoryLeaseAcrossInstances(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "materializer")
	first, err := NewJournalStore(dir, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewJournalStore(dir, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	receipt := testStoreReceipt(t, PhasePrepared)
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, store := range []*JournalStore{first, second} {
		store := store
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- store.SaveJournalContext(context.Background(), receipt)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("same-directory store save: %v", err)
		}
	}
	got, err := second.LoadJournalContext(context.Background())
	if err != nil || !sameReceipt(got, receipt) {
		t.Fatalf("shared journal=%+v err=%v", got, err)
	}
}

func TestJournalStoreRepairsSameCommitPhaseTransitionOnExactRetry(t *testing.T) {
	failBackup := false
	store, err := NewJournalStore(t.TempDir(), Hooks{
		Rename: func(oldPath, newPath string) error {
			if failBackup && strings.HasSuffix(newPath, JournalBackupName) {
				failBackup = false
				return errors.New("injected backup rename failure")
			}
			return os.Rename(oldPath, newPath)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	prepared := testStoreReceipt(t, PhasePrepared)
	if err := store.SaveJournal(prepared); err != nil {
		t.Fatal(err)
	}
	yamlPersisted := prepared.Clone()
	yamlPersisted.Phase = PhaseBaselinePersisted
	failBackup = true
	if err := store.SaveJournal(yamlPersisted); err == nil {
		t.Fatal("same-commit phase transition partial mirror save unexpectedly succeeded")
	}

	primary, err := readReceipt(filepath.Join(store.Directory(), JournalPrimaryName))
	if err != nil || !sameReceipt(primary, yamlPersisted) {
		t.Fatalf("primary=%+v err=%v, want yaml_persisted receipt", primary, err)
	}
	backup, err := readReceipt(filepath.Join(store.Directory(), JournalBackupName))
	if err != nil || !sameReceipt(backup, prepared) {
		t.Fatalf("backup=%+v err=%v, want prepared receipt", backup, err)
	}
	if _, err := store.LoadJournal(); !errors.Is(err, ErrReceiptAmbiguous) {
		t.Fatalf("partial valid mirror load err=%v, want ambiguity", err)
	}

	if err := store.SaveJournal(yamlPersisted); err != nil {
		t.Fatalf("exact same-commit phase retry did not repair mirror: %v", err)
	}
	got, err := store.LoadJournal()
	if err != nil || !sameReceipt(got, yamlPersisted) {
		t.Fatalf("repaired journal=%+v err=%v", got, err)
	}
}

func TestJournalStoreRejectsUnsafeExactMirrorRepair(t *testing.T) {
	prepared := testStoreReceipt(t, PhasePrepared)
	yamlPersisted := prepared.Clone()
	yamlPersisted.Phase = PhaseBaselinePersisted

	cases := []struct {
		name   string
		target Receipt
		other  Receipt
		want   error
	}{
		{
			name:   "phase regression",
			target: prepared,
			other:  yamlPersisted,
			want:   ErrPhaseRegression,
		},
		{
			name:   "different receipt",
			target: yamlPersisted,
			other: func() Receipt {
				r := prepared.Clone()
				r.Commit.Nonce = "nonce-other"
				return r
			}(),
			want: ErrCommitConflict,
		},
		{
			name:   "different payload",
			target: yamlPersisted,
			other: func() Receipt {
				r := prepared.Clone()
				payload, digest, err := desiredstate.EncodeProtectionPolicy(config.ProtectionPolicyConfig{
					WebAttack: config.ProtectionLevelStrict, APISecurity: config.ProtectionLevelHigh,
					BotCC: config.ProtectionLevelLow, ThreatIntel: config.ProtectionLevelOff,
				})
				if err != nil {
					t.Fatal(err)
				}
				r.Payload = payload
				r.Commit.Digest = digest
				return r
			}(),
			want: ErrCommitConflict,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store, err := NewJournalStore(t.TempDir(), Hooks{})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(store.Directory(), JournalPrimaryName), mustEncode(t, tc.target), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(store.Directory(), JournalBackupName), mustEncode(t, tc.other), 0600); err != nil {
				t.Fatal(err)
			}
			if err := store.SaveJournal(tc.target); !errors.Is(err, tc.want) {
				t.Fatalf("unsafe exact retry err=%v, want %v", err, tc.want)
			}
		})
	}
}

func TestJournalStoreRequiresExactTargetToRepairDivergentMirrors(t *testing.T) {
	store, err := NewJournalStore(t.TempDir(), Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	prepared := testStoreReceipt(t, PhasePrepared)
	yamlPersisted := prepared.Clone()
	yamlPersisted.Phase = PhaseBaselinePersisted
	runtimeApplied := prepared.Clone()
	runtimeApplied.Phase = PhaseRuntimeApplied
	if err := os.WriteFile(filepath.Join(store.Directory(), JournalPrimaryName), mustEncode(t, prepared), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store.Directory(), JournalBackupName), mustEncode(t, yamlPersisted), 0600); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveJournal(runtimeApplied); !errors.Is(err, ErrReceiptAmbiguous) {
		t.Fatalf("non-exact divergent mirror repair err=%v, want ErrReceiptAmbiguous", err)
	}
}

func TestJournalStoreRestoreJournalFromLKG(t *testing.T) {
	store, err := NewJournalStore(t.TempDir(), Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	lkg := testStoreReceipt(t, PhaseApplied)
	if err := store.SaveLKG(lkg); err != nil {
		t.Fatal(err)
	}
	if err := store.RestoreJournalFromLKG(); err != nil {
		t.Fatalf("restore journal: %v", err)
	}
	got, err := store.LoadJournal()
	if err != nil || !sameReceipt(got, lkg) {
		t.Fatalf("restored journal=%+v err=%v", got, err)
	}
	if err := store.RestoreJournalFromLKG(); err != nil {
		t.Fatalf("idempotent restore: %v", err)
	}
	newer := testStoreReceipt(t, PhasePrepared)
	newer.Commit.Revision = 2
	newer.Commit.Nonce = "nonce-2"
	if err := store.SaveJournal(newer); err != nil {
		t.Fatal(err)
	}
	if err := store.RestoreJournalFromLKG(); !errors.Is(err, ErrStaleRevision) {
		t.Fatalf("stale LKG restore err=%v, want ErrStaleRevision", err)
	}
}

func mustEncode(t *testing.T, receipt Receipt) []byte {
	t.Helper()
	data, err := encodeReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
