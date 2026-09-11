package netlease

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

var ErrAuditUnavailable = errors.New("netlease audit sink is unavailable")

// AuditSink persists metadata-only egress events. Implementations must never
// retain request or response payloads.
type AuditSink interface {
	Append(context.Context, AuditEvent) error
}

// DurableAuditSink lets production wiring reject a test-only in-memory sink.
type DurableAuditSink interface {
	AuditSink
	Durable() bool
}

// FileAuditSink is a synchronous, append-only JSONL sink for the temporary
// runtime. Each write is synced before a broker proceeds with an external
// socket, so a missing/unwritable audit path fails the request closed.
type FileAuditSink struct {
	mu   sync.Mutex
	path string
}

func NewFileAuditSink(path string) (*FileAuditSink, error) {
	if path == "" {
		return nil, ErrAuditUnavailable
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve netlease audit path: %w", err)
	}
	abs = filepath.Clean(abs)
	if filepath.Base(abs) == "." || filepath.Base(abs) == string(filepath.Separator) {
		return nil, ErrAuditUnavailable
	}
	return &FileAuditSink{path: abs}, nil
}

func (s *FileAuditSink) Durable() bool { return s != nil && s.path != "" }

func (s *FileAuditSink) Append(ctx context.Context, event AuditEvent) error {
	if s == nil || s.path == "" || !validAuditEvent(event) {
		return ErrAuditUnavailable
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal netlease audit event: %w", err)
	}
	data = append(data, '\n')
	s.mu.Lock()
	defer s.mu.Unlock()
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create netlease audit directory: %w", err)
	}
	info, err := os.Lstat(dir)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return ErrAuditUnavailable
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("protect netlease audit directory: %w", err)
	}
	if info, err := os.Lstat(s.path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return ErrAuditUnavailable
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect netlease audit path: %w", err)
	}
	file, err := os.OpenFile(s.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open netlease audit path: %w", err)
	}
	defer file.Close()
	info, err = file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return ErrAuditUnavailable
	}
	if err := file.Chmod(0o600); err != nil {
		return fmt.Errorf("protect netlease audit path: %w", err)
	}
	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("write netlease audit event: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync netlease audit event: %w", err)
	}
	return nil
}

func validAuditEvent(event AuditEvent) bool {
	if !validOpaque(event.LeaseID, 256) || !safeAuditToken(event.Action) || !safeAuditToken(event.Result) || event.At.IsZero() {
		return false
	}
	if !validOpaque(event.PluginID, 256) || !validOpaque(event.PluginVersion, 128) || !validOpaque(event.OperatorID, 256) || event.PolicyEpoch == 0 {
		return false
	}
	target := Target{Host: event.TargetHost, Port: event.TargetPort, Protocol: event.TargetProtocol}
	if event.TargetHost == "" || target.Validate() != nil {
		return false
	}
	if ValidateTLSFingerprint(event.TLSFingerprint) != nil || event.Bytes < 0 || event.BytesSent < 0 || event.BytesReceived < 0 || event.Bytes != event.BytesSent+event.BytesReceived || event.Requests < 0 {
		return false
	}
	if event.ConfirmationID != "" && !validOpaque(event.ConfirmationID, 256) {
		return false
	}
	if event.ResourceID != "" && !validOpaque(event.ResourceID, 256) {
		return false
	}
	return true
}

// MemoryAuditSink is intentionally non-durable and exists only for unit tests
// and local adapter tests. NewBroker rejects it in Production mode.
type MemoryAuditSink struct {
	mu     sync.Mutex
	events []AuditEvent
	err    error
}

func NewMemoryAuditSinkForTesting() *MemoryAuditSink { return &MemoryAuditSink{} }

func (s *MemoryAuditSink) Durable() bool { return false }

func (s *MemoryAuditSink) Append(_ context.Context, event AuditEvent) error {
	if s == nil || !validAuditEvent(event) {
		return ErrAuditUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	s.events = append(s.events, event)
	return nil
}

func (s *MemoryAuditSink) Events() []AuditEvent {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]AuditEvent(nil), s.events...)
}

func (s *MemoryAuditSink) SetErrorForTesting(err error) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.err = err
	s.mu.Unlock()
}
