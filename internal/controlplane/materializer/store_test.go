package materializer

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
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

func mustEncode(t *testing.T, receipt Receipt) []byte {
	t.Helper()
	data, err := encodeReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
