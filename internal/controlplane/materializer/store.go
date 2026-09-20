package materializer

import (
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
	if s != nil {
		s.mu.Lock()
		defer s.mu.Unlock()
	}
	if err := receipt.Validate(); err != nil {
		return err
	}
	if s == nil {
		return errors.New("materializer journal store is nil")
	}
	previous, err := s.loadMirror("journal", JournalPrimaryName, JournalBackupName)
	if errors.Is(err, ErrReceiptNotFound) {
		err = ValidateTransition(nil, receipt)
	} else if err == nil {
		err = ValidateTransition(&previous, receipt)
	}
	if err != nil {
		return err
	}
	return s.saveMirror("journal", JournalPrimaryName, JournalBackupName, receipt)
}

func (s *JournalStore) SaveLKG(receipt Receipt) error {
	if s != nil {
		s.mu.Lock()
		defer s.mu.Unlock()
	}
	if receipt.Phase != PhaseApplied {
		return fmt.Errorf("materializer LKG must be applied, got %q", receipt.Phase)
	}
	if s == nil {
		return errors.New("materializer journal store is nil")
	}
	previous, err := s.loadMirror("LKG", LKGPrimaryName, LKGBackupName)
	if errors.Is(err, ErrReceiptNotFound) {
		err = nil
	} else if err == nil {
		err = validateLKGTransition(previous, receipt)
	}
	if err != nil {
		return err
	}
	return s.saveMirror("LKG", LKGPrimaryName, LKGBackupName, receipt)
}

// RestoreJournalFromLKG repairs a lost journal from an already validated
// applied LKG. It is intentionally separate from SaveJournal: a normal
// journal must always begin at prepared, while this recovery path proves that
// the completed receipt already exists in both LKG mirrors.
func (s *JournalStore) RestoreJournalFromLKG(receipt Receipt) error {
	if s != nil {
		s.mu.Lock()
		defer s.mu.Unlock()
	}
	if s == nil {
		return errors.New("materializer journal store is nil")
	}
	if receipt.Phase != PhaseApplied {
		return fmt.Errorf("materializer journal recovery requires applied LKG, got %q", receipt.Phase)
	}
	if err := receipt.Validate(); err != nil {
		return err
	}
	current, err := s.loadMirror("journal", JournalPrimaryName, JournalBackupName)
	if err == nil {
		if sameCommit(current, receipt) && current.Phase == PhaseApplied {
			return nil
		}
		return ErrReceiptAmbiguous
	}
	if !errors.Is(err, ErrReceiptNotFound) {
		return err
	}
	return s.saveMirror("journal", JournalPrimaryName, JournalBackupName, receipt)
}

func (s *JournalStore) LoadJournal() (Receipt, error) {
	if s != nil {
		s.mu.Lock()
		defer s.mu.Unlock()
	}
	return s.loadMirror("journal", JournalPrimaryName, JournalBackupName)
}

func (s *JournalStore) LoadLKG() (Receipt, error) {
	if s != nil {
		s.mu.Lock()
		defer s.mu.Unlock()
	}
	receipt, err := s.loadMirror("LKG", LKGPrimaryName, LKGBackupName)
	if err != nil {
		return Receipt{}, err
	}
	if receipt.Phase != PhaseApplied {
		return Receipt{}, fmt.Errorf("%w: LKG phase is %q", ErrReceiptCorrupt, receipt.Phase)
	}
	return receipt, nil
}

// Load returns the journal and LKG independently. A missing record is
// surfaced as ErrReceiptNotFound; callers must decide whether startup can
// proceed without a local known-good configuration.
func (s *JournalStore) Load() (journal Receipt, lkg Receipt, err error) {
	journal, err = s.LoadJournal()
	if err != nil && !errors.Is(err, ErrReceiptNotFound) {
		return Receipt{}, Receipt{}, err
	}
	lkg, lkgErr := s.LoadLKG()
	if lkgErr != nil && !errors.Is(lkgErr, ErrReceiptNotFound) {
		return Receipt{}, Receipt{}, lkgErr
	}
	if errors.Is(err, ErrReceiptNotFound) && errors.Is(lkgErr, ErrReceiptNotFound) {
		return Receipt{}, Receipt{}, ErrReceiptNotFound
	}
	return journal, lkg, nil
}

func (s *JournalStore) saveMirror(label, primaryName, backupName string, receipt Receipt) error {
	if s == nil {
		return errors.New("materializer journal store is nil")
	}
	data, err := encodeReceipt(receipt)
	if err != nil {
		return err
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

func validateLKGTransition(previous, next Receipt) error {
	if err := previous.Validate(); err != nil {
		return err
	}
	if next.Phase != PhaseApplied {
		return ErrInvalidPhase
	}
	if previous.Commit.ClusterID != next.Commit.ClusterID {
		return ErrCommitConflict
	}
	if next.Commit.Epoch < previous.Commit.Epoch {
		return ErrStaleEpoch
	}
	if next.Commit.Epoch == previous.Commit.Epoch {
		if next.Commit.LeaderID != previous.Commit.LeaderID {
			return ErrCommitConflict
		}
		if next.Commit.Revision < previous.Commit.Revision {
			return ErrStaleRevision
		}
		if next.Commit.Revision == previous.Commit.Revision && !sameCommit(previous, next) {
			return ErrCommitConflict
		}
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
	if isProtectedSystemRoot(abs) {
		return fmt.Errorf("materializer journal directory must be a dedicated child, got %s", abs)
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

func isProtectedSystemRoot(path string) bool {
	clean := filepath.Clean(path)
	for _, root := range []string{"/", "/etc", "/var", "/tmp", "/private"} {
		if clean == root {
			return true
		}
	}
	return false
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
