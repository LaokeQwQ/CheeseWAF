package materializer

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const materializerLockName = ".materializer.lock"

var materializerSequencers sync.Map

type directorySequencer struct {
	token chan struct{}
}

type directoryLease struct {
	dir       string
	file      *os.File
	sequencer *directorySequencer
	once      sync.Once
	seqOnce   sync.Once
}

type directoryLeaseContextKey struct{}

func sequencerFor(dir string) *directorySequencer {
	created := &directorySequencer{token: make(chan struct{}, 1)}
	created.token <- struct{}{}
	actual, _ := materializerSequencers.LoadOrStore(dir, created)
	return actual.(*directorySequencer)
}

func acquireDirectoryLease(ctx context.Context, dir string) (*directoryLease, context.Context, error) {
	if ctx == nil {
		return nil, nil, ErrNilContext
	}
	if existing, ok := ctx.Value(directoryLeaseContextKey{}).(*directoryLease); ok && existing != nil && existing.dir == dir {
		return existing, ctx, nil
	}
	sequencer := sequencerFor(dir)
	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	case <-sequencer.token:
	}
	releaseSequencer := true
	defer func() {
		if releaseSequencer {
			sequencer.token <- struct{}{}
		}
	}()

	path := filepath.Join(dir, materializerLockName)
	if err := validateTargetPath(path, true); err != nil {
		return nil, nil, fmt.Errorf("validate materializer lock: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, nil, fmt.Errorf("open materializer lock: %w", err)
	}
	closeFile := true
	defer func() {
		if closeFile {
			_ = file.Close()
		}
	}()
	if err := validateOpenedLockFile(path, file); err != nil {
		return nil, nil, err
	}

	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		locked, lockErr := tryLockMaterializerFile(file)
		if lockErr != nil {
			return nil, nil, fmt.Errorf("lock materializer directory: %w", lockErr)
		}
		if locked {
			lease := &directoryLease{dir: dir, file: file, sequencer: sequencer}
			closeFile = false
			releaseSequencer = false
			return lease, context.WithValue(ctx, directoryLeaseContextKey{}, lease), nil
		}
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

func validateOpenedLockFile(path string, file *os.File) error {
	if err := validateTargetPath(path, false); err != nil {
		return fmt.Errorf("validate materializer lock: %w", err)
	}
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("stat materializer lock path: %w", err)
	}
	fileInfo, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat materializer lock file: %w", err)
	}
	if !os.SameFile(pathInfo, fileInfo) || !fileInfo.Mode().IsRegular() || fileInfo.Mode().Perm() != 0o600 {
		return fmt.Errorf("%w: materializer lock is not the validated 0600 regular file", ErrReceiptUnsafe)
	}
	return nil
}

func (l *directoryLease) Close() error {
	if l == nil {
		return nil
	}
	var result error
	l.once.Do(func() {
		if l.file != nil {
			unlockErr := unlockMaterializerFile(l.file)
			closeErr := l.file.Close()
			result = errors.Join(unlockErr, closeErr)
		}
		l.ReleaseSequencer()
	})
	return result
}

// ReleaseSequencer ends the in-process admission wait independently from the
// OS lease. A timed-out callback may still be executing and must retain the
// flock so another process cannot replay its runtime side effect. Keeping the
// two releases separate makes that invariant explicit and prevents a hung
// callback from permanently consuming the process-local token.
func (l *directoryLease) ReleaseSequencer() {
	if l == nil || l.sequencer == nil {
		return
	}
	l.seqOnce.Do(func() { l.sequencer.token <- struct{}{} })
}

func contextRetainingDirectoryLease(ctx context.Context) context.Context {
	if ctx == nil {
		return nil
	}
	return context.WithoutCancel(ctx)
}
