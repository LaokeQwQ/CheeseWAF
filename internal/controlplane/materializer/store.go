package materializer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const (
	JournalPrimaryName = "journal.json"
	JournalBackupName  = "journal.backup.json"
	LKGPrimaryName     = "lkg.json"
	LKGBackupName      = "lkg.backup.json"
)

// Hooks are a deliberately narrow fault-injection seam. Production uses the
// OS implementations; tests can fail a specific durability boundary without
// depending on HTTP, PG, Redis, or a runtime handler.
type Hooks struct {
	SyncFile func(*os.File) error
	SyncDir  func(string) error
	Rename   func(string, string) error
}

type JournalStore struct {
	mu    sync.Mutex
	dir   string
	hooks Hooks
}

func NewJournalStore(dir string, hooks Hooks) (*JournalStore, error) {
	if dir == "" {
		return nil, errors.New("materializer journal directory is required")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("resolve materializer journal directory: %w", err)
	}
	if err := ensurePrivateDir(abs); err != nil {
		return nil, err
	}
	canonical, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, fmt.Errorf("resolve materializer journal directory: %w", err)
	}
	abs = canonical
	if hooks.SyncFile == nil {
		hooks.SyncFile = func(f *os.File) error { return f.Sync() }
	}
	if hooks.SyncDir == nil {
		hooks.SyncDir = func(path string) error {
			f, err := os.Open(path)
			if err != nil {
				return err
			}
			defer f.Close()
			return f.Sync()
		}
	}
	if hooks.Rename == nil {
		hooks.Rename = os.Rename
	}
	return &JournalStore{dir: abs, hooks: hooks}, nil
}

func (s *JournalStore) Directory() string {
	if s == nil {
		return ""
	}
	return s.dir
}

func (s *JournalStore) SaveJournal(receipt Receipt) error {
	return s.SaveJournalContext(context.Background(), receipt)
}

func (s *JournalStore) SaveJournalContext(ctx context.Context, receipt Receipt) error {
	if s == nil {
		return errors.New("materializer journal store is nil")
	}
	if err := receipt.Validate(); err != nil {
		return err
	}
	return s.withDirectoryLease(ctx, func() error {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.saveTransition("journal", JournalPrimaryName, JournalBackupName, receipt, ValidateTransition)
	})
}

func (s *JournalStore) SaveLKG(receipt Receipt) error {
	return s.SaveLKGContext(context.Background(), receipt)
}

func (s *JournalStore) SaveLKGContext(ctx context.Context, receipt Receipt) error {
	if receipt.Phase != PhaseApplied {
		return fmt.Errorf("materializer LKG must be applied, got %q", receipt.Phase)
	}
	if s == nil {
		return errors.New("materializer journal store is nil")
	}
	if err := receipt.Validate(); err != nil {
		return err
	}
	return s.withDirectoryLease(ctx, func() error {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.saveTransition("LKG", LKGPrimaryName, LKGBackupName, receipt, validateLKGTransition)
	})
}

func (s *JournalStore) LoadJournal() (Receipt, error) {
	return s.LoadJournalContext(context.Background())
}

func (s *JournalStore) LoadJournalContext(ctx context.Context) (receipt Receipt, err error) {
	if s == nil {
		return Receipt{}, errors.New("materializer journal store is nil")
	}
	err = s.withDirectoryLease(ctx, func() error {
		s.mu.Lock()
		defer s.mu.Unlock()
		receipt, err = s.loadMirror("journal", JournalPrimaryName, JournalBackupName)
		return err
	})
	return receipt, err
}

func (s *JournalStore) LoadLKG() (Receipt, error) {
	return s.LoadLKGContext(context.Background())
}

func (s *JournalStore) LoadLKGContext(ctx context.Context) (receipt Receipt, err error) {
	if s == nil {
		return Receipt{}, errors.New("materializer journal store is nil")
	}
	err = s.withDirectoryLease(ctx, func() error {
		s.mu.Lock()
		defer s.mu.Unlock()
		receipt, err = s.loadMirror("LKG", LKGPrimaryName, LKGBackupName)
		return err
	})
	return receipt, err
}

// RestoreJournalFromLKG makes a verified applied LKG receipt the journal's
// current record. New callers should supply the exact LKG they already loaded
// for the transaction; the zero-argument form remains for existing recovery
// callers and reads the mirrored LKG under the store lock. It never permits an
// older LKG to overwrite a newer journal; repeating the same restore is
// idempotent.
func (s *JournalStore) RestoreJournalFromLKG(receipts ...Receipt) error {
	return s.RestoreJournalFromLKGContext(context.Background(), receipts...)
}

func (s *JournalStore) RestoreJournalFromLKGContext(ctx context.Context, receipts ...Receipt) error {
	if s == nil {
		return errors.New("materializer journal store is nil")
	}
	if len(receipts) > 1 {
		return fmt.Errorf("materializer journal recovery accepts at most one LKG receipt")
	}
	return s.withDirectoryLease(ctx, func() error {
		s.mu.Lock()
		defer s.mu.Unlock()
		var lkg Receipt
		if len(receipts) == 1 {
			lkg = receipts[0]
		} else {
			var err error
			lkg, err = s.loadMirror("LKG", LKGPrimaryName, LKGBackupName)
			if err != nil {
				return err
			}
		}
		if lkg.Phase != PhaseApplied {
			return fmt.Errorf("materializer LKG must be applied, got %q", lkg.Phase)
		}
		if err := lkg.Validate(); err != nil {
			return err
		}
		return s.saveTransition("journal restore", JournalPrimaryName, JournalBackupName, lkg, validateRestoreTransition)
	})
}

// Load returns the journal and LKG independently. A missing record is
// surfaced as ErrReceiptNotFound; callers must decide whether startup can
// proceed without a local known-good configuration.
func (s *JournalStore) Load() (journal Receipt, lkg Receipt, err error) {
	return s.LoadContext(context.Background())
}

func (s *JournalStore) LoadContext(ctx context.Context) (journal Receipt, lkg Receipt, err error) {
	if s == nil {
		return Receipt{}, Receipt{}, errors.New("materializer journal store is nil")
	}
	err = s.withDirectoryLease(ctx, func() error {
		s.mu.Lock()
		defer s.mu.Unlock()
		journal, err = s.loadMirror("journal", JournalPrimaryName, JournalBackupName)
		if err != nil && !errors.Is(err, ErrReceiptNotFound) {
			return err
		}
		lkgErr := error(nil)
		lkg, lkgErr = s.loadMirror("LKG", LKGPrimaryName, LKGBackupName)
		if lkgErr != nil && !errors.Is(lkgErr, ErrReceiptNotFound) {
			return lkgErr
		}
		if errors.Is(err, ErrReceiptNotFound) && errors.Is(lkgErr, ErrReceiptNotFound) {
			return ErrReceiptNotFound
		}
		return nil
	})
	return journal, lkg, err
}

func (s *JournalStore) withDirectoryLease(ctx context.Context, fn func() error) error {
	if s == nil {
		return errors.New("materializer journal store is nil")
	}
	if ctx == nil {
		return ErrNilContext
	}
	if lease, ok := ctx.Value(directoryLeaseContextKey{}).(*directoryLease); ok && lease != nil && lease.dir == s.dir {
		return fn()
	}
	lease, _, err := acquireDirectoryLease(ctx, s.dir)
	if err != nil {
		return err
	}
	defer lease.Close()
	return fn()
}

type transitionValidator func(previous *Receipt, next Receipt) error

func (s *JournalStore) saveTransition(label, primaryName, backupName string, receipt Receipt, validate transitionValidator) error {
	if err := ensurePrivateDir(s.dir); err != nil {
		return err
	}
	data, err := encodeReceipt(receipt)
	if err != nil {
		return err
	}
	primary, primaryErr := readReceipt(filepath.Join(s.dir, primaryName))
	backup, backupErr := readReceipt(filepath.Join(s.dir, backupName))
	if errors.Is(primaryErr, ErrReceiptUnsafe) || errors.Is(backupErr, ErrReceiptUnsafe) {
		return fmt.Errorf("persist %s: unsafe mirror: primary=%v backup=%v", label, primaryErr, backupErr)
	}
	// A retry after a mirror-side failure can know the exact intended receipt.
	// Repair only the non-matching side. If neither mirror is that exact target,
	// retain the normal monotonic/ambiguous-mirror checks below.
	primaryExact := primaryErr == nil && sameReceipt(primary, receipt)
	backupExact := backupErr == nil && sameReceipt(backup, receipt)
	if primaryExact && backupExact {
		if err := s.hooks.SyncDir(s.dir); err != nil {
			return fmt.Errorf("sync exact %s directory: %w", label, err)
		}
		return nil
	}
	// An exact target receipt can repair one stale or failed mirror only after
	// the other valid mirror proves it is a legal forward transition. This
	// covers a crash after the primary phase update and before the backup
	// phase update without accepting phase rollback or a conflicting receipt.
	if primaryExact {
		if backupErr == nil {
			if err := validate(&backup, receipt); err != nil {
				return err
			}
		}
		return s.writeOne(backupName, data)
	}
	if backupExact {
		if primaryErr == nil {
			if err := validate(&primary, receipt); err != nil {
				return err
			}
		}
		return s.writeOne(primaryName, data)
	}
	if primaryErr == nil && backupErr == nil && !sameReceipt(primary, backup) {
		if primary.Commit.Epoch == backup.Commit.Epoch && primary.Commit.Revision == backup.Commit.Revision {
			return fmt.Errorf("%w: %s mirrors disagree", ErrReceiptAmbiguous, label)
		}
		current := primary
		otherName := backupName
		if newerReceipt(backup, primary) {
			current = backup
			otherName = primaryName
		}
		if err := validate(&current, receipt); err != nil {
			return err
		}
		if !sameReceipt(current, receipt) {
			return fmt.Errorf("%w: %s target is not current mirror", ErrReceiptAmbiguous, label)
		}
		return s.writeOne(otherName, data)
	}
	var previous *Receipt
	switch {
	case primaryErr == nil && backupErr == nil:
		previous = &primary
	case primaryErr == nil:
		previous = &primary
	case backupErr == nil:
		previous = &backup
	case errors.Is(primaryErr, ErrReceiptNotFound) && errors.Is(backupErr, ErrReceiptNotFound):
		// First write; the validator enforces the initial phase contract.
	default:
		return fmt.Errorf("%w: %s primary=%v backup=%v", ErrReceiptCorrupt, label, primaryErr, backupErr)
	}
	if err := validate(previous, receipt); err != nil {
		return err
	}
	return s.saveMirrorEncoded(label, primaryName, backupName, data)
}

func newerReceipt(a, b Receipt) bool {
	if a.Commit.Epoch != b.Commit.Epoch {
		return a.Commit.Epoch > b.Commit.Epoch
	}
	return a.Commit.Revision > b.Commit.Revision
}

func (s *JournalStore) saveMirror(label, primaryName, backupName string, receipt Receipt) error {
	data, err := encodeReceipt(receipt)
	if err != nil {
		return err
	}
	return s.saveMirrorEncoded(label, primaryName, backupName, data)
}

func (s *JournalStore) saveMirrorEncoded(label, primaryName, backupName string, data []byte) error {
	if s == nil {
		return errors.New("materializer journal store is nil")
	}
	if err := ensurePrivateDir(s.dir); err != nil {
		return err
	}
	if err := s.writeOne(primaryName, data); err != nil {
		return fmt.Errorf("persist %s primary: %w", label, err)
	}
	if err := s.writeOne(backupName, data); err != nil {
		return fmt.Errorf("persist %s backup: %w", label, err)
	}
	return nil
}

func sameReceipt(a, b Receipt) bool {
	return sameCommit(a, b) && a.Phase == b.Phase
}

func validateLKGTransition(previous *Receipt, next Receipt) error {
	if previous == nil {
		return nil
	}
	if previous.Commit.ClusterID != next.Commit.ClusterID {
		return fmt.Errorf("%w: LKG cluster changed", ErrCommitConflict)
	}
	if next.Commit.Epoch < previous.Commit.Epoch {
		return ErrStaleEpoch
	}
	if next.Commit.Epoch == previous.Commit.Epoch {
		if next.Commit.LeaderID != previous.Commit.LeaderID {
			return fmt.Errorf("%w: LKG leader changed within epoch", ErrCommitConflict)
		}
		if next.Commit.Revision < previous.Commit.Revision {
			return ErrStaleRevision
		}
		if next.Commit.Revision == previous.Commit.Revision && !sameReceipt(*previous, next) {
			return ErrCommitConflict
		}
	}
	return nil
}

func validateRestoreTransition(previous *Receipt, next Receipt) error {
	if previous == nil {
		return nil
	}
	if sameReceipt(*previous, next) {
		return nil
	}
	if previous.Commit.ClusterID != next.Commit.ClusterID {
		return fmt.Errorf("%w: journal/LKG cluster changed", ErrCommitConflict)
	}
	if next.Commit.Epoch < previous.Commit.Epoch {
		return ErrStaleEpoch
	}
	if next.Commit.Epoch == previous.Commit.Epoch {
		if next.Commit.LeaderID != previous.Commit.LeaderID {
			return fmt.Errorf("%w: journal/LKG leader changed within epoch", ErrCommitConflict)
		}
		if next.Commit.Revision < previous.Commit.Revision {
			return ErrStaleRevision
		}
		if next.Commit.Revision == previous.Commit.Revision {
			if next.Phase == PhaseApplied && previous.Phase != PhaseApplied && sameCommit(*previous, next) {
				return nil
			}
			return ErrCommitConflict
		}
	}
	if next.Phase != PhaseApplied {
		return fmt.Errorf("%w: restored LKG must be applied", ErrInvalidPhase)
	}
	return nil
}

func (s *JournalStore) writeOne(name string, data []byte) error {
	path := filepath.Join(s.dir, name)
	if err := validateTargetPath(path, true); err != nil {
		return err
	}
	// A random temp name avoids reusing a stale file or following a malicious
	// symlink. The directory itself has already been checked as private.
	temp, err := os.CreateTemp(s.dir, ".materializer-*.tmp")
	if err != nil {
		return fmt.Errorf("create receipt temp: %w", err)
	}
	tempPath := temp.Name()
	removeTemp := true
	defer func() {
		_ = temp.Close()
		if removeTemp {
			_ = os.Remove(tempPath)
		}
	}()
	if err := temp.Chmod(0600); err != nil {
		return fmt.Errorf("chmod receipt temp: %w", err)
	}
	if _, err := temp.Write(data); err != nil {
		return fmt.Errorf("write receipt temp: %w", err)
	}
	if err := s.hooks.SyncFile(temp); err != nil {
		return fmt.Errorf("sync receipt temp: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close receipt temp: %w", err)
	}
	if err := validateTargetPath(tempPath, false); err != nil {
		return err
	}
	if err := validateTargetPath(path, true); err != nil {
		return err
	}
	if err := s.hooks.Rename(tempPath, path); err != nil {
		return fmt.Errorf("rename receipt temp: %w", err)
	}
	removeTemp = false
	if err := s.hooks.SyncDir(s.dir); err != nil {
		return fmt.Errorf("sync receipt directory: %w", err)
	}
	return nil
}

func (s *JournalStore) loadMirror(label, primaryName, backupName string) (Receipt, error) {
	if s == nil {
		return Receipt{}, errors.New("materializer journal store is nil")
	}
	if err := ensurePrivateDir(s.dir); err != nil {
		return Receipt{}, err
	}
	primary, primaryErr := readReceipt(filepath.Join(s.dir, primaryName))
	backup, backupErr := readReceipt(filepath.Join(s.dir, backupName))
	if errors.Is(primaryErr, ErrReceiptUnsafe) || errors.Is(backupErr, ErrReceiptUnsafe) {
		return Receipt{}, fmt.Errorf("%w: %s primary=%v backup=%v", ErrReceiptCorrupt, label, primaryErr, backupErr)
	}
	primaryOK := primaryErr == nil
	backupOK := backupErr == nil
	if primaryOK && backupOK {
		if !sameCommit(primary, backup) || primary.Phase != backup.Phase {
			return Receipt{}, fmt.Errorf("%w: %s", ErrReceiptAmbiguous, label)
		}
		return primary, nil
	}
	if primaryOK {
		if backupErr != nil && !errors.Is(backupErr, ErrReceiptNotFound) {
			// A valid primary is enough to determine the current record; the
			// damaged backup is retained for operator diagnosis and never erased.
			return primary, nil
		}
		return primary, nil
	}
	if backupOK {
		return backup, nil
	}
	if errors.Is(primaryErr, ErrReceiptNotFound) && errors.Is(backupErr, ErrReceiptNotFound) {
		return Receipt{}, ErrReceiptNotFound
	}
	return Receipt{}, fmt.Errorf("%w: %s primary=%v backup=%v", ErrReceiptCorrupt, label, primaryErr, backupErr)
}

func readReceipt(path string) (Receipt, error) {
	if err := validateTargetPath(path, false); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Receipt{}, ErrReceiptNotFound
		}
		return Receipt{}, err
	}
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Receipt{}, ErrReceiptNotFound
		}
		return Receipt{}, fmt.Errorf("open receipt: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return Receipt{}, fmt.Errorf("stat receipt: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return Receipt{}, fmt.Errorf("%w: receipt is not a regular 0600 file", ErrReceiptCorrupt)
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxReceiptBytes+1))
	if err != nil {
		return Receipt{}, fmt.Errorf("read receipt: %w", err)
	}
	if len(data) > MaxReceiptBytes {
		return Receipt{}, fmt.Errorf("%w: receipt exceeds %d bytes", ErrReceiptCorrupt, MaxReceiptBytes)
	}
	return decodeReceipt(data)
}

func ensurePrivateDir(path string) error {
	if path == "" {
		return errors.New("materializer journal directory is required")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	if err := ensureNoSymlinkComponents(abs); err != nil {
		return err
	}
	info, err := os.Lstat(abs)
	if err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("materializer journal directory is a symlink")
	}
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(abs, 0700); err != nil {
			return fmt.Errorf("create materializer journal directory: %w", err)
		}
		info, err = os.Lstat(abs)
	}
	if err != nil {
		return fmt.Errorf("stat materializer journal directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("materializer journal directory is not a regular directory")
	}
	if info.Mode().Perm() != 0700 {
		if err := os.Chmod(abs, 0700); err != nil {
			return fmt.Errorf("materializer journal directory must be 0700: %w", err)
		}
		info, err = os.Lstat(abs)
		if err != nil || info.Mode().Perm() != 0700 {
			return fmt.Errorf("materializer journal directory must be 0700")
		}
	}
	canonical, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return fmt.Errorf("resolve materializer journal directory: %w", err)
	}
	if err := ensureNoSymlinkComponents(canonical); err != nil {
		return err
	}
	return nil
}

func ensureNoSymlinkComponents(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	volume := filepath.VolumeName(abs)
	rest := strings.TrimPrefix(abs, volume)
	current := volume
	if strings.HasPrefix(rest, string(filepath.Separator)) {
		current += string(filepath.Separator)
		rest = strings.TrimPrefix(rest, string(filepath.Separator))
	}
	for _, part := range strings.Split(rest, string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("stat materializer path component: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			if isKnownSystemAlias(current) {
				continue
			}
			return fmt.Errorf("materializer path component is a symlink: %s", current)
		}
	}
	return nil
}

// macOS exposes /var (and sometimes /tmp) as fixed aliases into /private.
// These aliases are outside an application's control; user-created links in
// the target path remain rejected. The comparison uses the resolved component
// rather than trusting the basename.
func isKnownSystemAlias(path string) bool {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return false
	}
	for _, alias := range []string{"/var", "/tmp", "/etc", "/private"} {
		if path == alias {
			return strings.HasPrefix(resolved, "/private/") || resolved == "/private"
		}
	}
	return false
}

func validateTargetPath(path string, allowMissing bool) error {
	if err := ensureNoSymlinkComponents(filepath.Dir(path)); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if allowMissing {
			return nil
		}
		return os.ErrNotExist
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: receipt path is a symlink: %s", ErrReceiptUnsafe, path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%w: receipt path is not regular: %s", ErrReceiptUnsafe, path)
	}
	if info.Mode().Perm() != 0600 {
		return fmt.Errorf("%w: receipt path must be 0600: %s", ErrReceiptUnsafe, path)
	}
	return nil
}
