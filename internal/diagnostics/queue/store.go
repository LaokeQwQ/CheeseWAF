// Package queue implements the local, durable half of diagnostic delivery.
//
// The queue deliberately stores opaque ciphertext bytes. Encryption and
// decryption are supplied through EnvelopeCodec, so this package never opens
// a network connection, calls a KMS, or depends on a concrete envelope type.
package queue

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
)

const (
	stateSchema       = 1
	defaultMaxItems   = 128
	defaultMaxBytes   = int64(16 << 20)
	defaultTTL        = 24 * time.Hour
	defaultHistoryTTL = time.Hour
	defaultAttempts   = 3
	defaultRetryDelay = 100 * time.Millisecond
	stateFileName     = "state.json"
	backupFileName    = "state.json.bak"
	lockFileName      = ".queue.lock"
)

var (
	ErrInvalidConfig       = errors.New("invalid diagnostic queue configuration")
	ErrInvalidRequest      = errors.New("invalid diagnostic queue request")
	ErrCodecRequired       = errors.New("diagnostic queue requires an envelope codec for plaintext")
	ErrCorrupt             = errors.New("diagnostic queue state is corrupt")
	ErrUnsafePath          = errors.New("diagnostic queue path is unsafe")
	ErrQueueFull           = errors.New("diagnostic queue is full")
	ErrByteQuota           = errors.New("diagnostic queue byte quota exceeded")
	ErrIdempotencyConflict = errors.New("diagnostic queue idempotency conflict")
	ErrNotFound            = errors.New("diagnostic queue item not found")
	ErrExpired             = errors.New("diagnostic queue item expired")
	ErrEmpty               = errors.New("diagnostic queue is empty")
	ErrPaused              = errors.New("diagnostic queue is paused")
	ErrClosed              = errors.New("diagnostic queue is closed")
	ErrWorkerRunning       = errors.New("diagnostic queue worker is already running")
	ErrInvalidState        = errors.New("invalid diagnostic queue item state")
	ErrAttemptsExceeded    = errors.New("diagnostic queue retry attempts exceeded")
	ErrCleanup             = errors.New("diagnostic queue cleanup failed")
	ErrUnsupportedSchema   = errors.New("unsupported diagnostic queue state schema")
)

var (
	ErrQuotaExceeded = ErrByteQuota
	ErrQueueClosed   = ErrClosed
	ErrStateCorrupt  = ErrCorrupt
	ErrIdempotency   = ErrIdempotencyConflict
)

type State string

const (
	StateQueued     State = "queued"
	StateRetrying   State = "retrying"
	StateProcessing State = "processing"
	StateUploading  State = StateProcessing
	StateClaimed    State = StateProcessing
	StatePending    State = StateQueued
	StateCompleted  State = "completed"
	StateFailed     State = "failed"
	StateExpired    State = "expired"
	StateCanceled   State = "canceled"
)

// EnvelopeCodec is the narrow dependency used when a caller submits
// plaintext. Implementations normally adapt a diagnostics envelope package.
type EnvelopeCodec interface {
	Seal(context.Context, []byte) ([]byte, error)
	Open(context.Context, []byte) ([]byte, error)
}

type Codec = EnvelopeCodec

type EnvelopeSealer interface {
	Seal(context.Context, []byte) ([]byte, error)
}

type EnvelopeOpener interface {
	Open(context.Context, []byte) ([]byte, error)
}

// EnvelopeStore is an optional integration boundary for callers that keep
// envelope serialization elsewhere. Store never invokes it.
type EnvelopeStore interface {
	PutEnvelope(context.Context, []byte) error
	GetEnvelope(context.Context, string) ([]byte, error)
	DeleteEnvelope(context.Context, string) error
}

type SealFunc func(context.Context, []byte) ([]byte, error)

func (f SealFunc) Seal(ctx context.Context, plaintext []byte) ([]byte, error) {
	if f == nil {
		return nil, ErrCodecRequired
	}
	return f(ctx, plaintext)
}

type OpenFunc func(context.Context, []byte) ([]byte, error)

func (f OpenFunc) Open(ctx context.Context, ciphertext []byte) ([]byte, error) {
	if f == nil {
		return nil, ErrCodecRequired
	}
	return f(ctx, ciphertext)
}

type CodecFunc struct {
	SealFn SealFunc
	OpenFn OpenFunc
}

func (f CodecFunc) Seal(ctx context.Context, plaintext []byte) ([]byte, error) {
	return f.SealFn.Seal(ctx, plaintext)
}

func (f CodecFunc) Open(ctx context.Context, ciphertext []byte) ([]byte, error) {
	return f.OpenFn.Open(ctx, ciphertext)
}

type Metadata struct {
	TenantID      string
	PluginID      string
	PluginVersion string
	Target        string
	LeaseID       string
	PolicyEpoch   uint64
}

type Request struct {
	ID, UploadID                           string
	TenantID, PluginID, PluginVersion      string
	Target, LeaseID, IdempotencyKey        string
	PolicyEpoch                            uint64
	Plaintext                              []byte
	Payload, Data                          []byte
	Ciphertext, Envelope, EncryptedPayload []byte
	CreatedAt, ExpiresAt                   time.Time
	TTL                                    time.Duration
	MaxAttempts                            int
	Metadata                               Metadata
}

type EnqueueRequest = Request

type Item struct {
	ID, UploadID                      string
	TenantID, PluginID, PluginVersion string
	Target, LeaseID, IdempotencyKey   string
	PolicyEpoch                       uint64
	ObjectDigest                      string
	Digest                            string
	Ciphertext, Envelope              []byte
	Payload, EncryptedPayload         []byte
	Size, Bytes                       int64
	State                             State
	Attempt, MaxAttempts              int
	CreatedAt, ExpiresAt, UpdatedAt   time.Time
	AvailableAt                       time.Time
	LastError                         string
}

type Entry = Item
type Record = Item

type Receipt struct {
	ID, UploadID         string
	ObjectDigest, Digest string
	State                State
	Size                 int64
	Attempt, MaxAttempts int
	CreatedAt, ExpiresAt time.Time
}

type Status = Item

type CleanupPolicy struct {
	DeletePlaintextAfterSeal   bool
	DeleteCiphertextOnSuccess  bool
	DeleteCiphertextOnFailure  bool
	DeleteCiphertextOnExpiry   bool
	RetainSuccessfulCiphertext bool
	DeleteOnSuccess            bool
	DeleteOnFailure            bool
	DeleteOnExpiry             bool
}

type DeletePolicy string

const (
	DeleteNever             DeletePolicy = "never"
	DeleteAfterSuccess      DeletePolicy = "after_success"
	DeleteAfterFailure      DeletePolicy = "after_failure"
	DeleteAfterExpiry       DeletePolicy = "after_expiry"
	DeleteAfterTerminal     DeletePolicy = "after_terminal"
	DeleteCiphertextSuccess DeletePolicy = DeleteAfterSuccess
)

type Config struct {
	Root, Directory, Path      string
	RootDir, QueueDir, DataDir string
	Codec                      any
	MaxItems                   int
	MaxBytes                   int64
	MaxQueueItems              int
	MaxQueueBytes              int64
	TTL                        time.Duration
	HistoryTTL                 time.Duration
	RetryDelay                 time.Duration
	MaxAttempts                int
	Clock                      func() time.Time
	Cleanup                    CleanupPolicy
	DeletePolicy               DeletePolicy
	DeletePlaintextAfterSeal   bool
	DeleteCiphertextOnSuccess  bool
	DeleteCiphertextOnFailure  bool
	DeleteCiphertextOnExpiry   bool
	RetainSuccessfulCiphertext bool
}

type QueueConfig = Config
type StoreConfig = Config

type Stats struct {
	Pending, Queued, Retrying, Processing int
	Completed, Failed, Expired, Canceled  int
	Items                                 int
	Bytes                                 int64
	Paused                                bool
	Corrupt                               int
	LastError                             error
}

type Handler func(context.Context, Item) error
type DeliveryFunc = Handler

type diskEntry struct {
	ID, UploadID                      string
	TenantID, PluginID, PluginVersion string
	Target, LeaseID, IdempotencyKey   string
	PolicyEpoch                       uint64
	ObjectDigest                      string
	Size                              int64
	State                             State
	Attempt, MaxAttempts              int
	CreatedAt, ExpiresAt, UpdatedAt   time.Time
	AvailableAt                       time.Time
	RetainUntil                       time.Time
	Fingerprint                       string
	LastError                         string
}

type diskState struct {
	Schema   int
	Paused   bool
	Sequence uint64
	Entries  map[string]diskEntry
}

type Store struct {
	mu                    sync.Mutex
	rootMu                *sync.Mutex
	root                  string
	statePath, backupPath string
	objectsPath, shaPath  string
	lockPath              string
	cfg                   Config
	state                 diskState
	corrupt               int
	closed                bool
	workerCancel          context.CancelFunc
	workerDone            chan struct{}
	workerRunning         bool
	workerErr             error
	wake                  chan struct{}
	workerLease           *sync.Mutex
}

type Queue = Store

var rootLocks sync.Map
var workerLocks sync.Map

func rootLock(root string) *sync.Mutex {
	if v, ok := rootLocks.Load(root); ok {
		return v.(*sync.Mutex)
	}
	m := &sync.Mutex{}
	v, _ := rootLocks.LoadOrStore(root, m)
	return v.(*sync.Mutex)
}

func workerLock(root string) *sync.Mutex {
	if v, ok := workerLocks.Load(root); ok {
		return v.(*sync.Mutex)
	}
	m := &sync.Mutex{}
	v, _ := workerLocks.LoadOrStore(root, m)
	return v.(*sync.Mutex)
}

func New(args ...any) (*Store, error) {
	var root string
	var cfg Config
	for _, arg := range args {
		switch v := arg.(type) {
		case string:
			root = v
		case Config:
			cfg = v
		case *Config:
			if v != nil {
				cfg = *v
			}
		default:
			return nil, fmt.Errorf("%w: unsupported constructor argument %T", ErrInvalidConfig, arg)
		}
	}
	return newStore(root, cfg)
}

func NewStore(args ...any) (*Store, error) {
	var root string
	var cfg Config
	for _, arg := range args {
		switch v := arg.(type) {
		case string:
			root = v
		case Config:
			cfg = v
		case *Config:
			if v != nil {
				cfg = *v
			}
		default:
			return nil, fmt.Errorf("%w: unsupported constructor argument %T", ErrInvalidConfig, arg)
		}
	}
	return newStore(root, cfg)
}

func NewQueue(args ...any) (*Queue, error) {
	return NewStore(args...)
}

func Open(args ...any) (*Store, error) {
	return NewStore(args...)
}

func newStore(root string, cfg Config) (*Store, error) {
	if root == "" {
		root = cfg.Root
		if root == "" {
			root = cfg.Directory
		}
		if root == "" {
			root = cfg.Path
		}
		if root == "" {
			root = cfg.RootDir
		}
		if root == "" {
			root = cfg.QueueDir
		}
		if root == "" {
			root = cfg.DataDir
		}
	}
	if root == "" || root != strings.TrimSpace(root) {
		return nil, fmt.Errorf("%w: root is required and must not contain surrounding whitespace", ErrInvalidConfig)
	}
	root, err := filepath.Abs(filepath.Clean(root))
	if err != nil || root == string(filepath.Separator) {
		return nil, fmt.Errorf("%w: invalid root", ErrInvalidConfig)
	}
	if cfg.MaxItems <= 0 {
		cfg.MaxItems = cfg.MaxQueueItems
	}
	if cfg.MaxItems <= 0 {
		cfg.MaxItems = defaultMaxItems
	}
	if cfg.MaxBytes <= 0 {
		cfg.MaxBytes = cfg.MaxQueueBytes
	}
	if cfg.MaxBytes <= 0 {
		cfg.MaxBytes = defaultMaxBytes
	}
	if cfg.TTL <= 0 {
		cfg.TTL = defaultTTL
	}
	if cfg.HistoryTTL <= 0 {
		cfg.HistoryTTL = defaultHistoryTTL
	}
	if cfg.RetryDelay <= 0 {
		cfg.RetryDelay = defaultRetryDelay
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = defaultAttempts
	}
	if cfg.MaxAttempts > defaultAttempts {
		cfg.MaxAttempts = defaultAttempts
	}
	if cfg.Clock == nil {
		cfg.Clock = func() time.Time { return time.Now().UTC() }
	}
	normalizeCleanup(&cfg)
	if err := ensureDir(root, 0o700); err != nil {
		return nil, fmt.Errorf("%w: root: %v", ErrInvalidConfig, err)
	}
	objects := filepath.Join(root, "objects")
	shaPath := filepath.Join(objects, "sha256")
	for _, dir := range []string{objects, shaPath} {
		if err := ensureDir(dir, 0o700); err != nil {
			return nil, fmt.Errorf("%w: directory: %v", ErrInvalidConfig, err)
		}
	}
	lockPath := filepath.Join(root, lockFileName)
	if err := ensureFile(lockPath, 0o600); err != nil {
		return nil, fmt.Errorf("%w: lock: %v", ErrInvalidConfig, err)
	}
	s := &Store{
		root: root, rootMu: rootLock(root), cfg: cfg,
		statePath: filepath.Join(root, stateFileName), backupPath: filepath.Join(root, backupFileName),
		objectsPath: objects, shaPath: shaPath, lockPath: lockPath,
		wake:        make(chan struct{}, 1),
		state:       diskState{Schema: stateSchema, Entries: make(map[string]diskEntry)},
		workerLease: workerLock(root),
	}
	s.rootMu.Lock()
	s.mu.Lock()
	err = s.loadInitialLocked()
	s.mu.Unlock()
	s.rootMu.Unlock()
	if err != nil {
		return nil, err
	}
	return s, nil
}

func normalizeCleanup(cfg *Config) {
	c := &cfg.Cleanup
	c.DeletePlaintextAfterSeal = c.DeletePlaintextAfterSeal || cfg.DeletePlaintextAfterSeal
	c.DeleteCiphertextOnSuccess = c.DeleteCiphertextOnSuccess || c.DeleteOnSuccess || cfg.DeleteCiphertextOnSuccess
	c.DeleteCiphertextOnFailure = c.DeleteCiphertextOnFailure || c.DeleteOnFailure || cfg.DeleteCiphertextOnFailure
	c.DeleteCiphertextOnExpiry = c.DeleteCiphertextOnExpiry || c.DeleteOnExpiry || cfg.DeleteCiphertextOnExpiry
	c.RetainSuccessfulCiphertext = c.RetainSuccessfulCiphertext || cfg.RetainSuccessfulCiphertext
	if !c.DeletePlaintextAfterSeal && !c.DeleteCiphertextOnSuccess && !c.DeleteCiphertextOnFailure && !c.DeleteCiphertextOnExpiry && !c.RetainSuccessfulCiphertext {
		c.DeletePlaintextAfterSeal = true
		c.DeleteCiphertextOnSuccess = true
		c.DeleteCiphertextOnExpiry = true
	}
	if c.RetainSuccessfulCiphertext {
		c.DeleteCiphertextOnSuccess = false
	}
	switch cfg.DeletePolicy {
	case DeleteAfterSuccess:
		c.DeleteCiphertextOnSuccess = true
	case DeleteAfterFailure:
		c.DeleteCiphertextOnFailure = true
	case DeleteAfterExpiry:
		c.DeleteCiphertextOnExpiry = true
	case DeleteAfterTerminal:
		c.DeleteCiphertextOnSuccess = true
		c.DeleteCiphertextOnFailure = true
		c.DeleteCiphertextOnExpiry = true
	case DeleteNever:
		c.DeleteCiphertextOnSuccess = false
		c.DeleteCiphertextOnFailure = false
		c.DeleteCiphertextOnExpiry = false
	}
}

func (s *Store) now() time.Time { return s.cfg.Clock().UTC() }

func contextOrBackground(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

func checkContext(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	return ctx.Err()
}

func (s *Store) lock() error {
	if s == nil {
		return ErrClosed
	}
	s.rootMu.Lock()
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		s.rootMu.Unlock()
		return ErrClosed
	}
	return nil
}

func (s *Store) unlock() {
	s.mu.Unlock()
	s.rootMu.Unlock()
}

func ensureDir(path string, mode os.FileMode) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(path, mode); err != nil {
			return err
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return ErrUnsafePath
	}
	if info.Mode().Perm() != mode.Perm() {
		if err := os.Chmod(path, mode.Perm()); err != nil {
			return ErrUnsafePath
		}
		info, err = os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != mode.Perm() {
			return ErrUnsafePath
		}
	}
	return nil
}

func ensureFile(path string, mode os.FileMode) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		f, createErr := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, mode.Perm())
		if createErr != nil {
			if !errors.Is(createErr, os.ErrExist) {
				return createErr
			}
			info, err = os.Lstat(path)
		} else {
			if syncErr := f.Sync(); syncErr != nil {
				_ = f.Close()
				return syncErr
			}
			if closeErr := f.Close(); closeErr != nil {
				return closeErr
			}
			return syncDir(filepath.Dir(path))
		}
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return ErrUnsafePath
	}
	if info.Mode().Perm() != mode.Perm() {
		if err := os.Chmod(path, mode.Perm()); err != nil {
			return ErrUnsafePath
		}
	}
	return nil
}

func syncDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := f.Sync(); err != nil {
		// Some filesystems do not support directory fsync. The rename remains
		// atomic; report only errors other than the platform's unsupported case.
		if errors.Is(err, os.ErrInvalid) || errors.Is(err, os.ErrPermission) {
			return nil
		}
		return err
	}
	return nil
}

func (s *Store) readStateLocked() (diskState, bool, error) {
	read := func(path string) (diskState, error) {
		data, err := readSecureFile(path)
		if err != nil {
			return diskState{}, err
		}
		var state diskState
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&state); err != nil {
			return diskState{}, fmt.Errorf("%w: decode: %v", ErrCorrupt, err)
		}
		var extra any
		if err := dec.Decode(&extra); err != io.EOF {
			return diskState{}, fmt.Errorf("%w: trailing data", ErrCorrupt)
		}
		if state.Schema != stateSchema {
			return diskState{}, fmt.Errorf("%w: %d", ErrUnsupportedSchema, state.Schema)
		}
		if state.Entries == nil {
			state.Entries = make(map[string]diskEntry)
		}
		return state, nil
	}
	state, err := read(s.statePath)
	if err == nil {
		return state, false, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		backup, backupErr := read(s.backupPath)
		if backupErr == nil {
			return backup, true, nil
		}
		return diskState{}, false, err
	}
	if backup, backupErr := read(s.backupPath); backupErr == nil {
		return backup, true, nil
	}
	return diskState{Schema: stateSchema, Entries: make(map[string]diskEntry)}, true, nil
}

func readSecureFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, ErrUnsafePath
	}
	if info.Mode().Perm() != 0o600 {
		if err := os.Chmod(path, 0o600); err != nil {
			return nil, ErrUnsafePath
		}
	}
	return os.ReadFile(path)
}

func (s *Store) persistStateLocked() error {
	if s.state.Schema == 0 {
		s.state.Schema = stateSchema
	}
	if s.state.Entries == nil {
		s.state.Entries = make(map[string]diskEntry)
	}
	data, err := json.Marshal(s.state)
	if err != nil {
		return fmt.Errorf("%w: marshal state: %v", ErrCorrupt, err)
	}
	if old, readErr := os.ReadFile(s.statePath); readErr == nil && validStateBytes(old) {
		if backupErr := atomicWriteFile(s.backupPath, old, 0o600); backupErr != nil {
			return fmt.Errorf("%w: backup state: %v", ErrCorrupt, backupErr)
		}
	}
	if err := atomicWriteFile(s.statePath, data, 0o600); err != nil {
		return fmt.Errorf("%w: persist state: %v", ErrCorrupt, err)
	}
	return nil
}

func validStateBytes(data []byte) bool {
	var state diskState
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if dec.Decode(&state) != nil || state.Schema != stateSchema {
		return false
	}
	var extra any
	return dec.Decode(&extra) == io.EOF
}

func atomicWriteFile(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := ensureDir(dir, 0o700); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return ErrUnsafePath
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.OpenFile(filepath.Join(dir, fmt.Sprintf(".%s.tmp-%d", filepath.Base(path), time.Now().UnixNano())), os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode.Perm())
	if err != nil {
		return err
	}
	tmpName := f.Name()
	defer os.Remove(tmpName)
	if err := f.Chmod(mode.Perm()); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	return syncDir(dir)
}

func (s *Store) objectPath(digest string) string {
	return filepath.Join(s.shaPath, digest)
}

// ObjectPath returns the canonical content-addressed ciphertext path. It is
// useful for backup tooling and intentionally never exposes plaintext.
func (s *Store) ObjectPath(digest string) string {
	if s == nil || !validDigest(digest) {
		return ""
	}
	return s.objectPath(digest)
}

func (s *Store) verifyObject(digest string, size int64) (bool, error) {
	if !validDigest(digest) {
		return false, ErrCorrupt
	}
	path := s.objectPath(digest)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return false, ErrUnsafePath
	}
	if info.Mode().Perm() != 0o600 {
		if err := os.Chmod(path, 0o600); err != nil {
			return false, ErrUnsafePath
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	defer wipe(data)
	if size >= 0 && int64(len(data)) != size {
		return false, ErrCorrupt
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:]) == digest, nil
}

func (s *Store) writeObject(digest string, data []byte) error {
	if !validDigest(digest) {
		return ErrCorrupt
	}
	path := s.objectPath(digest)
	if ok, err := s.verifyObject(digest, int64(len(data))); err != nil {
		if ok {
			return nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	} else if ok {
		return nil
	}
	if err := atomicWriteFile(path, data, 0o600); err != nil {
		if ok, verifyErr := s.verifyObject(digest, int64(len(data))); verifyErr == nil && ok {
			return nil
		}
		return err
	}
	return nil
}

func (s *Store) removeObjectBestEffort(digest string) error {
	if !validDigest(digest) {
		return nil
	}
	err := os.Remove(s.objectPath(digest))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err == nil {
		_ = syncDir(s.shaPath)
	}
	return err
}

func (s *Store) cleanupOrphansLocked() bool {
	entries := make(map[string]struct{}, len(s.state.Entries))
	for _, e := range s.state.Entries {
		keep := activeState(e.State)
		if e.State == StateCompleted {
			keep = !s.cfg.Cleanup.DeleteCiphertextOnSuccess
		}
		if e.State == StateFailed {
			keep = !s.cfg.Cleanup.DeleteCiphertextOnFailure
		}
		if e.State == StateCanceled {
			keep = false
		}
		if e.State == StateExpired {
			keep = !s.cfg.Cleanup.DeleteCiphertextOnExpiry
		}
		if validDigest(e.ObjectDigest) && keep {
			entries[e.ObjectDigest] = struct{}{}
		}
	}
	changed := false
	items, err := os.ReadDir(s.shaPath)
	if err != nil {
		return false
	}
	for _, item := range items {
		name := item.Name()
		path := filepath.Join(s.shaPath, name)
		if item.IsDir() || strings.HasPrefix(name, ".") {
			if strings.HasPrefix(name, ".") {
				_ = os.Remove(path)
			}
			continue
		}
		if _, ok := entries[name]; !ok || !validDigest(name) {
			if os.Remove(path) == nil {
				changed = true
			}
		}
	}
	return changed
}

func wipe(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

func cloneBytes(data []byte) []byte { return append([]byte(nil), data...) }

// Enqueue seals plaintext through the configured codec, or accepts an opaque
// encrypted field already present on req. The caller's plaintext slice is not
// modified; an internal copy is wiped after Seal returns.
func (s *Store) Enqueue(ctx context.Context, req Request) (Receipt, error) {
	ctx = contextOrBackground(ctx)
	if err := checkContext(ctx); err != nil {
		return Receipt{}, err
	}
	normalizeRequest(&req)
	if err := validateRequest(req); err != nil {
		return Receipt{}, err
	}
	if data, ok := requestCiphertext(req); ok {
		return s.enqueueOpaque(ctx, req, data)
	}
	if len(req.Plaintext) == 0 && len(req.Payload) > 0 {
		req.Plaintext = req.Payload
	}
	if len(req.Plaintext) == 0 && len(req.Data) > 0 {
		req.Plaintext = req.Data
	}
	if len(req.Plaintext) == 0 {
		return Receipt{}, fmt.Errorf("%w: no payload", ErrInvalidRequest)
	}
	if s == nil || s.cfg.Codec == nil {
		return Receipt{}, ErrCodecRequired
	}
	plain := cloneBytes(req.Plaintext)
	sealed, err := sealWithCodec(ctx, s.cfg.Codec, plain)
	if s.cfg.Cleanup.DeletePlaintextAfterSeal {
		wipe(plain)
	}
	if err != nil {
		wipe(sealed)
		return Receipt{}, err
	}
	if len(sealed) == 0 {
		return Receipt{}, fmt.Errorf("%w: codec returned empty envelope", ErrInvalidRequest)
	}
	return s.enqueueOpaque(ctx, req, sealed)
}

func sealWithCodec(ctx context.Context, codec any, plaintext []byte) ([]byte, error) {
	if codec == nil {
		return nil, ErrCodecRequired
	}
	sealer, ok := codec.(EnvelopeSealer)
	if !ok || sealer == nil {
		return nil, ErrCodecRequired
	}
	return sealer.Seal(ctx, plaintext)
}

// EnqueueEncrypted admits bytes that have already been sealed by an envelope
// adapter. It never invokes the codec and is the fastest WAF-safe path.
func (s *Store) EnqueueEncrypted(ctx context.Context, req Request, ciphertext []byte) (Receipt, error) {
	if len(ciphertext) == 0 {
		return Receipt{}, fmt.Errorf("%w: empty ciphertext", ErrInvalidRequest)
	}
	req.Plaintext = nil
	normalizeRequest(&req)
	req.Payload, req.Envelope, req.EncryptedPayload = nil, nil, nil
	req.Ciphertext = cloneBytes(ciphertext)
	return s.enqueueOpaque(contextOrBackground(ctx), req, ciphertext)
}

func (s *Store) EnqueuePlaintext(ctx context.Context, req Request, plaintext []byte) (Receipt, error) {
	req.Plaintext = cloneBytes(plaintext)
	req.Payload, req.Ciphertext, req.Envelope, req.EncryptedPayload = nil, nil, nil, nil
	return s.Enqueue(ctx, req)
}

func (s *Store) Submit(ctx context.Context, req Request) (Receipt, error) {
	return s.Enqueue(ctx, req)
}

func (s *Store) Put(ctx context.Context, req Request) (Receipt, error) {
	return s.Enqueue(ctx, req)
}

func (s *Store) EnqueueBytes(ctx context.Context, idempotencyKey string, ciphertext []byte) (Receipt, error) {
	return s.EnqueueEncrypted(ctx, Request{IdempotencyKey: idempotencyKey}, ciphertext)
}

func requestCiphertext(req Request) ([]byte, bool) {
	for _, data := range [][]byte{req.Ciphertext, req.Envelope, req.EncryptedPayload} {
		if len(data) > 0 {
			return data, true
		}
	}
	// Payload is treated as plaintext only when no explicit encrypted field is
	// present. This makes old callers that used Payload continue to work with a
	// configured codec while preserving an explicit Ciphertext escape hatch.
	return nil, false
}

func validateRequest(req Request) error {
	if req.IdempotencyKey == "" || !validIdentifier(req.IdempotencyKey) {
		return ErrInvalidRequest
	}
	for _, value := range []string{req.ID, req.UploadID, req.TenantID, req.PluginID, req.PluginVersion, req.Target, req.LeaseID} {
		if value != "" && !validIdentifier(value) {
			return ErrInvalidRequest
		}
	}
	if !req.ExpiresAt.IsZero() && !req.CreatedAt.IsZero() && req.ExpiresAt.Before(req.CreatedAt) {
		return ErrInvalidRequest
	}
	if req.MaxAttempts < 0 {
		return ErrInvalidRequest
	}
	return nil
}

func normalizeRequest(req *Request) {
	if req == nil {
		return
	}
	if req.TenantID == "" {
		req.TenantID = req.Metadata.TenantID
	}
	if req.PluginID == "" {
		req.PluginID = req.Metadata.PluginID
	}
	if req.PluginVersion == "" {
		req.PluginVersion = req.Metadata.PluginVersion
	}
	if req.Target == "" {
		req.Target = req.Metadata.Target
	}
	if req.LeaseID == "" {
		req.LeaseID = req.Metadata.LeaseID
	}
	if req.PolicyEpoch == 0 {
		req.PolicyEpoch = req.Metadata.PolicyEpoch
	}
}

func (s *Store) enqueueOpaque(ctx context.Context, req Request, data []byte) (Receipt, error) {
	if s == nil {
		return Receipt{}, ErrClosed
	}
	if err := checkContext(ctx); err != nil {
		return Receipt{}, err
	}
	if err := validateRequest(req); err != nil {
		return Receipt{}, err
	}
	if len(data) == 0 || int64(len(data)) > s.cfg.MaxBytes {
		return Receipt{}, ErrByteQuota
	}
	digest := digestBytes(data)
	fingerprint := requestFingerprint(req, data)
	if err := s.lock(); err != nil {
		return Receipt{}, err
	}
	defer s.unlock()
	if err := s.refreshLocked(false); err != nil {
		return Receipt{}, err
	}
	if err := s.expireLocked(); err != nil {
		return Receipt{}, err
	}
	if existing, ok := findIdempotency(s.state.Entries, req.IdempotencyKey); ok {
		if existing.State == StateExpired {
			return Receipt{}, ErrExpired
		}
		if existing.Fingerprint != fingerprint {
			return Receipt{}, ErrIdempotencyConflict
		}
		return receiptFromDisk(existing), nil
	}
	items, bytesUsed := activeUsage(s.state.Entries)
	if items >= s.cfg.MaxItems {
		return Receipt{}, ErrQueueFull
	}
	if bytesUsed > s.cfg.MaxBytes-int64(len(data)) {
		return Receipt{}, ErrByteQuota
	}
	now := s.now()
	created := req.CreatedAt
	if created.IsZero() {
		created = now
	} else {
		created = created.UTC()
	}
	expires := req.ExpiresAt
	if expires.IsZero() {
		ttl := req.TTL
		if ttl <= 0 {
			ttl = s.cfg.TTL
		}
		if ttl > s.cfg.TTL {
			ttl = s.cfg.TTL
		}
		expires = created.Add(ttl)
	} else {
		expires = expires.UTC()
		maxExpires := created.Add(s.cfg.TTL)
		if expires.After(maxExpires) {
			expires = maxExpires
		}
	}
	if !now.Before(expires) {
		return Receipt{}, ErrExpired
	}
	id := req.ID
	if id == "" {
		s.state.Sequence++
		id = fmt.Sprintf("upload-%d", s.state.Sequence)
	}
	if _, exists := s.state.Entries[id]; exists {
		return Receipt{}, ErrIdempotencyConflict
	}
	maxAttempts := req.MaxAttempts
	if maxAttempts <= 0 || maxAttempts > s.cfg.MaxAttempts {
		maxAttempts = s.cfg.MaxAttempts
	}
	uploadID := req.UploadID
	if uploadID == "" {
		uploadID = id
	}
	e := diskEntry{
		ID: id, UploadID: uploadID, TenantID: req.TenantID, PluginID: req.PluginID,
		PluginVersion: req.PluginVersion, Target: req.Target, LeaseID: req.LeaseID,
		IdempotencyKey: req.IdempotencyKey, PolicyEpoch: req.PolicyEpoch,
		ObjectDigest: digest, Size: int64(len(data)), State: StateQueued,
		Attempt: 0, MaxAttempts: maxAttempts, CreatedAt: created, ExpiresAt: expires,
		UpdatedAt: now, AvailableAt: now, RetainUntil: expires, Fingerprint: fingerprint,
	}
	if err := s.writeObject(digest, data); err != nil {
		return Receipt{}, fmt.Errorf("%w: write object: %v", ErrCorrupt, err)
	}
	s.state.Entries[id] = e
	if err := s.persistStateLocked(); err != nil {
		// State did not commit; remove the orphan object. The operation remains
		// an error but never affects the WAF request path beyond this return.
		delete(s.state.Entries, id)
		if !s.objectReferencedLocked(digest) {
			_ = s.removeObjectBestEffort(digest)
		}
		return Receipt{}, err
	}
	s.signal()
	return receiptFromDisk(e), nil
}

func digestBytes(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func requestFingerprint(req Request, data []byte) string {
	// Bind all routing/security identity fields and the bytes' digest. The
	// plaintext itself is never put in the manifest or this fingerprint.
	canonical := struct {
		TenantID, PluginID, PluginVersion, Target, LeaseID, IdempotencyKey string
		PolicyEpoch                                                        uint64
		PayloadDigest                                                      string
	}{req.TenantID, req.PluginID, req.PluginVersion, req.Target, req.LeaseID, req.IdempotencyKey, req.PolicyEpoch, digestBytes(data)}
	b, _ := json.Marshal(canonical)
	return digestBytes(b)
}

func findIdempotency(entries map[string]diskEntry, key string) (diskEntry, bool) {
	for _, e := range entries {
		if e.IdempotencyKey == key {
			return e, true
		}
	}
	return diskEntry{}, false
}

func activeUsage(entries map[string]diskEntry) (int, int64) {
	var n int
	var bytesUsed int64
	for _, e := range entries {
		switch e.State {
		case StateQueued, StateRetrying, StateProcessing:
			n++
			bytesUsed += e.Size
		}
	}
	return n, bytesUsed
}

func receiptFromDisk(e diskEntry) Receipt {
	return Receipt{ID: e.ID, UploadID: e.UploadID, ObjectDigest: e.ObjectDigest, Digest: e.ObjectDigest, State: e.State, Size: e.Size, Attempt: e.Attempt, MaxAttempts: e.MaxAttempts, CreatedAt: e.CreatedAt, ExpiresAt: e.ExpiresAt}
}

func itemFromDisk(e diskEntry, data []byte) Item {
	copyData := cloneBytes(data)
	return Item{ID: e.ID, UploadID: e.UploadID, TenantID: e.TenantID, PluginID: e.PluginID, PluginVersion: e.PluginVersion, Target: e.Target, LeaseID: e.LeaseID, IdempotencyKey: e.IdempotencyKey, PolicyEpoch: e.PolicyEpoch, ObjectDigest: e.ObjectDigest, Digest: e.ObjectDigest, Ciphertext: copyData, Envelope: cloneBytes(copyData), Payload: cloneBytes(copyData), EncryptedPayload: cloneBytes(copyData), Size: e.Size, Bytes: e.Size, State: e.State, Attempt: e.Attempt, MaxAttempts: e.MaxAttempts, CreatedAt: e.CreatedAt, ExpiresAt: e.ExpiresAt, UpdatedAt: e.UpdatedAt, AvailableAt: e.AvailableAt, LastError: e.LastError}
}

func (s *Store) refreshLocked(recoverProcessing bool) error {
	loaded, _, err := s.readStateLocked()
	if err != nil {
		return err
	}
	if recoverProcessing {
		now := s.now()
		for id, e := range loaded.Entries {
			if e.State == StateProcessing {
				e.State = StateQueued
				e.AvailableAt = now
				e.UpdatedAt = now
				loaded.Entries[id] = e
			}
		}
	}
	s.state = loaded
	return nil
}

func (s *Store) loadInitialLocked() error {
	loaded, recovered, err := s.readStateLocked()
	if err != nil {
		return err
	}
	s.state = loaded
	changed := recovered
	now := s.now()
	for id, e := range s.state.Entries {
		if e.ID == "" {
			e.ID = id
			changed = true
		}
		if e.State == StateProcessing {
			e.State = StateQueued
			e.AvailableAt = now
			e.UpdatedAt = now
			changed = true
		}
		if e.State == "" {
			e.State = StateQueued
			changed = true
		}
		if e.RetainUntil.IsZero() {
			e.RetainUntil = e.ExpiresAt
			changed = true
		}
		if !validDiskEntry(e) {
			s.corrupt++
			delete(s.state.Entries, id)
			changed = true
			continue
		}
		if activeState(e.State) && !now.Before(e.ExpiresAt) {
			e.State = StateExpired
			e.UpdatedAt = now
			e.RetainUntil = retentionDeadline(e.ExpiresAt, now, s.cfg.HistoryTTL)
			changed = true
		}
		if activeState(e.State) {
			ok, verifyErr := s.verifyObject(e.ObjectDigest, e.Size)
			if verifyErr != nil || !ok {
				s.corrupt++
				delete(s.state.Entries, id)
				_ = s.removeObjectBestEffort(e.ObjectDigest)
				changed = true
				continue
			}
		}
		s.state.Entries[id] = e
	}
	if s.cleanupOrphansLocked() {
		changed = true
	}
	if changed {
		return s.persistStateLocked()
	}
	return nil
}

func validDiskEntry(e diskEntry) bool {
	if e.ID == "" || !validIdentifier(e.ID) || !validDigest(e.ObjectDigest) || e.Size <= 0 || !validState(e.State) || e.Attempt < 0 || e.MaxAttempts <= 0 || e.CreatedAt.IsZero() || e.ExpiresAt.IsZero() || e.Fingerprint == "" || !validDigest(e.Fingerprint) {
		return false
	}
	if e.UploadID != "" && !validIdentifier(e.UploadID) {
		return false
	}
	if e.IdempotencyKey == "" || !validIdentifier(e.IdempotencyKey) {
		return false
	}
	for _, value := range []string{e.TenantID, e.PluginID, e.PluginVersion, e.Target, e.LeaseID} {
		if value != "" && !validIdentifier(value) {
			return false
		}
	}
	return true
}

func validState(state State) bool {
	switch state {
	case StateQueued, StateRetrying, StateProcessing, StateCompleted, StateFailed, StateExpired, StateCanceled:
		return true
	default:
		return false
	}
}

func activeState(state State) bool {
	return state == StateQueued || state == StateRetrying || state == StateProcessing
}

func validDigest(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validIdentifier(value string) bool {
	if value == "" || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) || unicode.IsSpace(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}

func (s *Store) expireLocked() error {
	now := s.now()
	changed := false
	var cleanup []string
	for id, e := range s.state.Entries {
		if activeState(e.State) && !now.Before(e.ExpiresAt) {
			e.State = StateExpired
			e.UpdatedAt = now
			e.AvailableAt = time.Time{}
			e.RetainUntil = retentionDeadline(e.ExpiresAt, now, s.cfg.HistoryTTL)
			s.state.Entries[id] = e
			changed = true
			if s.cfg.Cleanup.DeleteCiphertextOnExpiry {
				cleanup = append(cleanup, e.ObjectDigest)
			}
			continue
		}
		if !activeState(e.State) && !e.RetainUntil.IsZero() && !now.Before(e.RetainUntil) {
			delete(s.state.Entries, id)
			cleanup = append(cleanup, e.ObjectDigest)
			changed = true
		}
	}
	if !changed {
		return nil
	}
	if err := s.persistStateLocked(); err != nil {
		return err
	}
	for _, digest := range cleanup {
		if !s.objectReferencedLocked(digest) {
			_ = s.removeObjectBestEffort(digest)
		}
	}
	return nil
}

func (s *Store) objectReferencedLocked(digest string) bool {
	for _, e := range s.state.Entries {
		if e.ObjectDigest == digest && activeState(e.State) {
			return true
		}
		if e.ObjectDigest == digest && e.State == StateCompleted && !s.cfg.Cleanup.DeleteCiphertextOnSuccess {
			return true
		}
		if e.ObjectDigest == digest && e.State == StateFailed && !s.cfg.Cleanup.DeleteCiphertextOnFailure {
			return true
		}
		if e.ObjectDigest == digest && e.State == StateExpired && !s.cfg.Cleanup.DeleteCiphertextOnExpiry {
			return true
		}
	}
	return false
}

// Claim atomically selects the oldest item nearest to TTL, marks it as
// processing, increments Attempt, and returns a private ciphertext copy.
func (s *Store) Claim(ctx context.Context) (*Item, error) {
	ctx = contextOrBackground(ctx)
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if err := s.lock(); err != nil {
		return nil, err
	}
	defer s.unlock()
	if err := s.refreshLocked(false); err != nil {
		return nil, err
	}
	hadExpired := false
	now := s.now()
	for _, e := range s.state.Entries {
		if activeState(e.State) && !now.Before(e.ExpiresAt) {
			hadExpired = true
			break
		}
	}
	if err := s.expireLocked(); err != nil {
		return nil, err
	}
	if s.state.Paused {
		return nil, ErrPaused
	}
	entries := make([]diskEntry, 0, len(s.state.Entries))
	for _, e := range s.state.Entries {
		if (e.State == StateQueued || e.State == StateRetrying) && (e.AvailableAt.IsZero() || !now.Before(e.AvailableAt)) {
			entries = append(entries, e)
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		if !entries[i].ExpiresAt.Equal(entries[j].ExpiresAt) {
			return entries[i].ExpiresAt.Before(entries[j].ExpiresAt)
		}
		if !entries[i].CreatedAt.Equal(entries[j].CreatedAt) {
			return entries[i].CreatedAt.Before(entries[j].CreatedAt)
		}
		return entries[i].ID < entries[j].ID
	})
	if len(entries) == 0 {
		if hadExpired {
			return nil, ErrExpired
		}
		return nil, ErrEmpty
	}
	e := entries[0]
	data, err := readSecureFile(s.objectPath(e.ObjectDigest))
	if err != nil || int64(len(data)) != e.Size || digestBytes(data) != e.ObjectDigest {
		wipe(data)
		delete(s.state.Entries, e.ID)
		s.corrupt++
		_ = s.persistStateLocked()
		_ = s.removeObjectBestEffort(e.ObjectDigest)
		return nil, ErrCorrupt
	}
	e.Attempt++
	if e.Attempt > e.MaxAttempts {
		wipe(data)
		e.State = StateFailed
		e.LastError = ErrAttemptsExceeded.Error()
		e.UpdatedAt = now
		e.RetainUntil = retentionDeadline(e.ExpiresAt, now, s.cfg.HistoryTTL)
		s.state.Entries[e.ID] = e
		if err := s.persistStateLocked(); err != nil {
			return nil, err
		}
		return nil, ErrAttemptsExceeded
	}
	e.State = StateProcessing
	e.UpdatedAt = now
	e.AvailableAt = time.Time{}
	s.state.Entries[e.ID] = e
	if err := s.persistStateLocked(); err != nil {
		wipe(data)
		return nil, err
	}
	item := itemFromDisk(e, data)
	wipe(data)
	return &item, nil
}

func (s *Store) Next(ctx context.Context) (*Item, error) { return s.Claim(ctx) }

func (s *Store) Complete(ctx context.Context, id string, success bool) error {
	return s.CompleteWithError(ctx, id, success, nil)
}

func (s *Store) CompleteWithError(ctx context.Context, id string, success bool, cause error) error {
	ctx = contextOrBackground(ctx)
	if err := checkContext(ctx); err != nil {
		return err
	}
	if !validIdentifier(id) {
		return ErrNotFound
	}
	if err := s.lock(); err != nil {
		return err
	}
	defer s.unlock()
	if err := s.refreshLocked(false); err != nil {
		return err
	}
	if err := s.expireLocked(); err != nil {
		return err
	}
	e, ok := s.state.Entries[id]
	if !ok {
		return ErrNotFound
	}
	if e.State == StateExpired {
		return ErrExpired
	}
	if e.State != StateProcessing {
		return ErrInvalidState
	}
	now := s.now()
	e.UpdatedAt = now
	e.RetainUntil = retentionDeadline(e.ExpiresAt, now, s.cfg.HistoryTTL)
	e.AvailableAt = time.Time{}
	deleteCiphertext := false
	if success {
		e.State = StateCompleted
		e.LastError = ""
		deleteCiphertext = s.cfg.Cleanup.DeleteCiphertextOnSuccess
	} else {
		if cause != nil {
			e.LastError = safeError(cause)
		} else {
			e.LastError = "worker reported failure"
		}
		if e.Attempt >= e.MaxAttempts {
			e.State = StateFailed
			deleteCiphertext = s.cfg.Cleanup.DeleteCiphertextOnFailure
		} else {
			e.State = StateRetrying
			e.AvailableAt = now.Add(s.cfg.RetryDelay)
		}
	}
	s.state.Entries[id] = e
	if err := s.persistStateLocked(); err != nil {
		return err
	}
	if deleteCiphertext && !s.objectReferencedLocked(e.ObjectDigest) {
		if err := s.removeObjectBestEffort(e.ObjectDigest); err != nil {
			s.workerErr = fmt.Errorf("%w: %v", ErrCleanup, err)
			return s.workerErr
		}
	}
	if e.State == StateRetrying {
		s.signal()
	}
	if e.State == StateFailed {
		return ErrAttemptsExceeded
	}
	return nil
}

func safeError(err error) string {
	if err == nil {
		return ""
	}
	text := err.Error()
	if len(text) > 512 {
		text = text[:512]
	}
	text = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, text)
	lower := strings.ToLower(text)
	for _, marker := range []string{"secret", "token", "password", "cookie", "authorization", "credential", "private_key", "privatekey"} {
		if strings.Contains(lower, marker) {
			return "worker error (sensitive detail redacted)"
		}
	}
	return text
}

func retentionDeadline(expiresAt, now time.Time, historyTTL time.Duration) time.Time {
	deadline := now.Add(historyTTL)
	if !expiresAt.IsZero() && expiresAt.After(deadline) {
		return expiresAt
	}
	return deadline
}

func (s *Store) Retry(ctx context.Context, id string, reason ...string) error {
	ctx = contextOrBackground(ctx)
	if err := checkContext(ctx); err != nil {
		return err
	}
	if !validIdentifier(id) {
		return ErrNotFound
	}
	if err := s.lock(); err != nil {
		return err
	}
	defer s.unlock()
	if err := s.refreshLocked(false); err != nil {
		return err
	}
	if err := s.expireLocked(); err != nil {
		return err
	}
	e, ok := s.state.Entries[id]
	if !ok {
		return ErrNotFound
	}
	if e.State == StateExpired {
		return ErrExpired
	}
	if e.State != StateRetrying && e.State != StateFailed {
		return ErrInvalidState
	}
	if e.Attempt >= e.MaxAttempts {
		return ErrAttemptsExceeded
	}
	okObject, err := s.verifyObject(e.ObjectDigest, e.Size)
	if err != nil || !okObject {
		return ErrCorrupt
	}
	e.State = StateQueued
	e.AvailableAt = s.now()
	e.UpdatedAt = e.AvailableAt
	if len(reason) > 0 && reason[0] != "" {
		e.LastError = safeError(errors.New(reason[0]))
	}
	s.state.Entries[id] = e
	if err := s.persistStateLocked(); err != nil {
		return err
	}
	s.signal()
	return nil
}

func (s *Store) Cancel(ctx context.Context, id string, reason ...string) error {
	ctx = contextOrBackground(ctx)
	if err := checkContext(ctx); err != nil {
		return err
	}
	if !validIdentifier(id) {
		return ErrNotFound
	}
	if err := s.lock(); err != nil {
		return err
	}
	defer s.unlock()
	if err := s.refreshLocked(false); err != nil {
		return err
	}
	e, ok := s.state.Entries[id]
	if !ok {
		return ErrNotFound
	}
	if !activeState(e.State) {
		return ErrInvalidState
	}
	now := s.now()
	e.State = StateCanceled
	e.UpdatedAt = now
	e.RetainUntil = retentionDeadline(e.ExpiresAt, now, s.cfg.HistoryTTL)
	e.AvailableAt = time.Time{}
	if len(reason) > 0 {
		e.LastError = safeError(errors.New(reason[0]))
	}
	s.state.Entries[id] = e
	if err := s.persistStateLocked(); err != nil {
		return err
	}
	if !s.objectReferencedLocked(e.ObjectDigest) {
		_ = s.removeObjectBestEffort(e.ObjectDigest)
	}
	return nil
}

func (s *Store) signal() {
	if s == nil || s.wake == nil {
		return
	}
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// ReadEnvelope returns a copy of the persisted ciphertext. It never invokes
// EnvelopeCodec.Open, so plaintext cannot accidentally cross this boundary.
func (s *Store) ReadEnvelope(ctx context.Context, id string) ([]byte, error) {
	ctx = contextOrBackground(ctx)
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if !validIdentifier(id) {
		return nil, ErrNotFound
	}
	if err := s.lock(); err != nil {
		return nil, err
	}
	defer s.unlock()
	if err := s.refreshLocked(false); err != nil {
		return nil, err
	}
	if err := s.expireLocked(); err != nil {
		return nil, err
	}
	e, ok := s.state.Entries[id]
	if !ok {
		return nil, ErrNotFound
	}
	if e.State == StateExpired {
		return nil, ErrExpired
	}
	data, err := readSecureFile(s.objectPath(e.ObjectDigest))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != e.Size || digestBytes(data) != e.ObjectDigest {
		wipe(data)
		return nil, ErrCorrupt
	}
	return cloneBytes(data), nil
}

func (s *Store) Get(ctx context.Context, id string) (Item, error) {
	data, err := s.ReadEnvelope(ctx, id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			// Terminal items whose ciphertext was deleted remain observable as
			// metadata through Status, but Get follows the durable-object API.
			status, statusErr := s.Status(ctx, id)
			if statusErr == nil && !activeState(status.State) {
				return status, nil
			}
		}
		return Item{}, err
	}
	status, err := s.Status(ctx, id)
	if err != nil {
		wipe(data)
		return Item{}, err
	}
	item := itemFromStatus(status, data)
	wipe(data)
	return item, nil
}

func itemFromStatus(status Item, data []byte) Item {
	status.Ciphertext = cloneBytes(data)
	status.Envelope = cloneBytes(data)
	return status
}

func (s *Store) Status(ctx context.Context, id string) (Item, error) {
	ctx = contextOrBackground(ctx)
	if err := checkContext(ctx); err != nil {
		return Item{}, err
	}
	if !validIdentifier(id) {
		return Item{}, ErrNotFound
	}
	if err := s.lock(); err != nil {
		return Item{}, err
	}
	defer s.unlock()
	if err := s.refreshLocked(false); err != nil {
		return Item{}, err
	}
	if err := s.expireLocked(); err != nil {
		return Item{}, err
	}
	e, ok := s.state.Entries[id]
	if !ok {
		return Item{}, ErrNotFound
	}
	if e.State == StateExpired {
		return itemFromDisk(e, nil), ErrExpired
	}
	return itemFromDisk(e, nil), nil
}

func (s *Store) Delete(ctx context.Context, id string) error {
	ctx = contextOrBackground(ctx)
	if err := checkContext(ctx); err != nil {
		return err
	}
	if !validIdentifier(id) {
		return ErrNotFound
	}
	if err := s.lock(); err != nil {
		return err
	}
	defer s.unlock()
	if err := s.refreshLocked(false); err != nil {
		return err
	}
	e, ok := s.state.Entries[id]
	if !ok {
		return ErrNotFound
	}
	delete(s.state.Entries, id)
	if err := s.persistStateLocked(); err != nil {
		return err
	}
	if !s.objectReferencedLocked(e.ObjectDigest) {
		if err := s.removeObjectBestEffort(e.ObjectDigest); err != nil {
			return fmt.Errorf("%w: %v", ErrCleanup, err)
		}
	}
	return nil
}

func (s *Store) Stats() Stats {
	if s == nil {
		return Stats{}
	}
	if err := s.lock(); err != nil {
		return Stats{LastError: err}
	}
	defer s.unlock()
	if err := s.refreshLocked(false); err != nil {
		return Stats{LastError: err}
	}
	if err := s.expireLocked(); err != nil {
		return Stats{LastError: err, Paused: s.state.Paused}
	}
	var out Stats
	out.Paused = s.state.Paused
	out.Corrupt = s.corrupt
	for _, e := range s.state.Entries {
		out.Items++
		switch e.State {
		case StateQueued:
			out.Queued++
			out.Pending++
			out.Bytes += e.Size
		case StateRetrying:
			out.Retrying++
			out.Pending++
			out.Bytes += e.Size
		case StateProcessing:
			out.Processing++
			out.Pending++
			out.Bytes += e.Size
		case StateCompleted:
			out.Completed++
		case StateFailed:
			out.Failed++
		case StateExpired:
			out.Expired++
		case StateCanceled:
			out.Canceled++
		}
	}
	out.LastError = s.workerErr
	return out
}

func (s *Store) Len() int {
	return s.Stats().Pending
}

func (s *Store) Pending() int {
	return s.Stats().Pending
}

func (s *Store) Paused() bool {
	if s == nil {
		return false
	}
	if err := s.lock(); err != nil {
		return false
	}
	defer s.unlock()
	_ = s.refreshLocked(false)
	return s.state.Paused
}

func (s *Store) IsPaused() bool { return s.Paused() }

func (s *Store) Pause(ctxs ...context.Context) error {
	ctx := context.Background()
	if len(ctxs) > 0 && ctxs[0] != nil {
		ctx = ctxs[0]
	}
	if err := checkContext(ctx); err != nil {
		return err
	}
	if err := s.lock(); err != nil {
		return err
	}
	defer s.unlock()
	if err := s.refreshLocked(false); err != nil {
		return err
	}
	if s.state.Paused {
		return nil
	}
	s.state.Paused = true
	return s.persistStateLocked()
}

func (s *Store) Resume(ctxs ...context.Context) error {
	ctx := context.Background()
	if len(ctxs) > 0 && ctxs[0] != nil {
		ctx = ctxs[0]
	}
	if err := checkContext(ctx); err != nil {
		return err
	}
	if err := s.lock(); err != nil {
		return err
	}
	defer s.unlock()
	if err := s.refreshLocked(false); err != nil {
		return err
	}
	if !s.state.Paused {
		return nil
	}
	s.state.Paused = false
	if err := s.persistStateLocked(); err != nil {
		return err
	}
	s.signal()
	return nil
}

func (s *Store) SetPaused(paused bool) error {
	if paused {
		return s.Pause()
	}
	return s.Resume()
}

func (s *Store) WorkerError() error {
	if s == nil {
		return ErrClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.workerErr
}

// Start launches exactly one local worker. Handler errors are converted into
// durable retry/failure states; they are not returned on the caller's request
// goroutine and never panic the WAF process.
func (s *Store) Start(ctx context.Context, handler Handler) error {
	if s == nil {
		return ErrClosed
	}
	if handler == nil {
		return ErrInvalidConfig
	}
	ctx = contextOrBackground(ctx)
	if err := checkContext(ctx); err != nil {
		return err
	}
	if s.workerLease == nil || !s.workerLease.TryLock() {
		return ErrWorkerRunning
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		s.workerLease.Unlock()
		return ErrClosed
	}
	if s.workerRunning {
		s.mu.Unlock()
		s.workerLease.Unlock()
		return ErrWorkerRunning
	}
	workerCtx, cancel := context.WithCancel(ctx)
	s.workerCancel = cancel
	s.workerDone = make(chan struct{})
	s.workerRunning = true
	s.workerErr = nil
	done := s.workerDone
	s.mu.Unlock()
	go s.runWorker(workerCtx, handler, done)
	return nil
}

func (s *Store) Run(ctx context.Context, handler Handler) error {
	return s.Start(ctx, handler)
}

func (s *Store) StartWorker(ctx context.Context, handler Handler) error {
	return s.Start(ctx, handler)
}

func (s *Store) runWorker(ctx context.Context, handler Handler, done chan struct{}) {
	defer close(done)
	defer func() {
		s.mu.Lock()
		s.workerRunning = false
		s.workerCancel = nil
		s.mu.Unlock()
		if s.workerLease != nil {
			s.workerLease.Unlock()
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		item, err := s.Claim(ctx)
		if err == nil && item != nil {
			handlerErr := invokeHandler(ctx, handler, *item)
			if handlerErr == nil {
				if completeErr := s.Complete(ctx, item.ID, true); completeErr != nil {
					if errors.Is(completeErr, context.Canceled) || errors.Is(completeErr, context.DeadlineExceeded) {
						return
					}
					s.setWorkerError(fmt.Errorf("complete successful diagnostic item %s: %w", item.ID, completeErr))
					// The handler may already have completed an external side effect.
					// Stop instead of silently continuing or re-running work while
					// durable queue completion is uncertain.
					return
				}
			} else {
				completeErr := s.CompleteWithError(ctx, item.ID, false, handlerErr)
				if completeErr != nil && !errors.Is(completeErr, ErrAttemptsExceeded) && !errors.Is(completeErr, context.Canceled) {
					s.setWorkerError(fmt.Errorf("record failed diagnostic item %s: %w", item.ID, completeErr))
					return
				}
			}
			continue
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return
		}
		if !errors.Is(err, ErrEmpty) && !errors.Is(err, ErrPaused) && !errors.Is(err, ErrExpired) && !errors.Is(err, ErrAttemptsExceeded) && !errors.Is(err, ErrCorrupt) {
			s.setWorkerError(err)
		}
		wait := s.cfg.RetryDelay
		if wait <= 0 {
			wait = defaultRetryDelay
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return
		case <-s.wake:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		case <-timer.C:
		}
	}
}

func (s *Store) setWorkerError(err error) {
	if s == nil || err == nil {
		return
	}
	s.mu.Lock()
	s.workerErr = err
	s.mu.Unlock()
}

func invokeHandler(ctx context.Context, handler Handler, item Item) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("worker panic: %v", recovered)
		}
	}()
	return handler(ctx, item)
}

// Stop cancels the worker and waits for it to leave. It is safe to call more
// than once and does not delete pending durable items.
func (s *Store) Stop() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	cancel := s.workerCancel
	done := s.workerDone
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
	return nil
}

func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	_ = s.Stop()
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()
	return nil
}

func (s *Store) Snapshot(ctx context.Context) ([]Item, error) {
	ctx = contextOrBackground(ctx)
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if err := s.lock(); err != nil {
		return nil, err
	}
	defer s.unlock()
	if err := s.refreshLocked(false); err != nil {
		return nil, err
	}
	if err := s.expireLocked(); err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(s.state.Entries))
	for id := range s.state.Entries {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]Item, 0, len(ids))
	for _, id := range ids {
		e := s.state.Entries[id]
		out = append(out, itemFromDisk(e, nil))
	}
	return out, nil
}

func (s *Store) List(ctx context.Context) ([]Item, error) { return s.Snapshot(ctx) }

// Purge removes terminal history whose retention window has elapsed. It is
// intentionally explicit so callers can schedule it without a background
// timer storm.
func (s *Store) Purge(ctx context.Context) error {
	ctx = contextOrBackground(ctx)
	if err := checkContext(ctx); err != nil {
		return err
	}
	if err := s.lock(); err != nil {
		return err
	}
	defer s.unlock()
	return s.expireLocked()
}
