package integration

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/audit"
	"github.com/LaokeQwQ/CheeseWAF/internal/diagnostics"
	"github.com/LaokeQwQ/CheeseWAF/internal/diagnostics/envelope"
	"github.com/LaokeQwQ/CheeseWAF/internal/diagnostics/queue"
)

type testUploader struct {
	mu      sync.Mutex
	calls   []UploadRequest
	entered chan struct{}
	release chan struct{}
	fail    bool
}

type flakyUploader struct {
	mu       sync.Mutex
	attempts int
	failFor  int
}

type commitFailReplayGuard struct {
	commitErr error
	reserve   atomic.Int32
	commit    atomic.Int32
	release   atomic.Int32
}

func (g *commitFailReplayGuard) CheckAndMark(context.Context, string) error { return g.commitErr }
func (g *commitFailReplayGuard) Reserve(context.Context, string) error {
	g.reserve.Add(1)
	return nil
}
func (g *commitFailReplayGuard) Commit(context.Context, string) error {
	g.commit.Add(1)
	return g.commitErr
}
func (g *commitFailReplayGuard) Release(context.Context, string) error {
	g.release.Add(1)
	return nil
}

func (u *flakyUploader) Upload(_ context.Context, _ UploadRequest) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.attempts++
	if u.attempts <= u.failFor {
		return errors.New("temporary")
	}
	return nil
}

func (u *testUploader) Upload(_ context.Context, req UploadRequest) error {
	u.mu.Lock()
	u.calls = append(u.calls, cloneUploadRequest(req))
	u.mu.Unlock()
	if u.entered != nil {
		u.entered <- struct{}{}
	}
	if u.release != nil {
		<-u.release
	}
	if u.fail {
		return errors.New("temporary upload failure")
	}
	return nil
}

func integrationRequest(key string) diagnostics.Request {
	return diagnostics.Request{
		Package: diagnostics.Package{Kind: diagnostics.KindSanitized, Metadata: map[string]string{"status": "ok"}},
		Target:  "external", PluginID: "plugin-a", PluginVersion: "1.0.0", PolicyEpoch: 1,
		LeaseID: "lease-a", IdempotencyKey: key,
	}
}

func newTestRuntime(t *testing.T, uploader UploadAdapter) *Runtime {
	t.Helper()
	provider, err := envelope.NewLocalProvider("kek-v1", []byte("01234567890123456789012345678901"))
	if err != nil {
		t.Fatal(err)
	}
	auditRuntime, err := audit.NewRuntime(audit.RuntimeOptions{Journal: audit.NewMemoryJournal(), StreamID: "diagnostics", QueueCapacity: 16})
	if err != nil {
		t.Fatal(err)
	}
	rt, err := NewRuntime(Config{
		QueueRoot: t.TempDir(), TenantID: "tenant-a", Actor: "operator-a", KeyVersion: "kek-v1",
		Provider: provider, Uploader: uploader, Audit: auditRuntime, PollInterval: time.Millisecond,
		QueueConfig: queue.Config{MaxItems: 4, MaxBytes: 1 << 20, TTL: time.Hour, RetryDelay: 100 * time.Millisecond},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rt.Close(); _ = auditRuntime.Close(); _ = provider.Close() })
	return rt
}

func TestRuntimeRecoversQueuedEnvelopeAfterRestart(t *testing.T) {
	root := t.TempDir()
	provider, err := envelope.NewLocalProvider("kek-v1", []byte("01234567890123456789012345678901"))
	if err != nil {
		t.Fatal(err)
	}
	uploader := &testUploader{}
	rt, err := NewRuntime(Config{QueueRoot: root, TenantID: "tenant-a", Actor: "operator-a", KeyVersion: "kek-v1", Provider: provider, Uploader: uploader, QueueConfig: queue.Config{MaxItems: 4, MaxBytes: 1 << 20, TTL: time.Hour}})
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := rt.Submit(context.Background(), integrationRequest("restart"))
	if err != nil {
		t.Fatal(err)
	}
	if err := rt.Close(); err != nil {
		t.Fatal(err)
	}
	rt, err = NewRuntime(Config{QueueRoot: root, TenantID: "tenant-a", Actor: "operator-a", KeyVersion: "kek-v1", Provider: provider, Uploader: uploader, PollInterval: time.Millisecond, QueueConfig: queue.Config{MaxItems: 4, MaxBytes: 1 << 20, TTL: time.Hour}})
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	if err := rt.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := rt.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	status, err := rt.Status(context.Background(), receipt.UploadID)
	if err != nil || status.State != queue.StateCompleted {
		t.Fatalf("status=%#v err=%v", status, err)
	}
}

func TestRuntimeDropsCorruptEnvelopeObjectOnRestart(t *testing.T) {
	root := t.TempDir()
	provider, err := envelope.NewLocalProvider("kek-v1", []byte("01234567890123456789012345678901"))
	if err != nil {
		t.Fatal(err)
	}
	uploader := &testUploader{}
	rt, err := NewRuntime(Config{QueueRoot: root, TenantID: "tenant-a", Actor: "operator-a", KeyVersion: "kek-v1", Provider: provider, Uploader: uploader})
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := rt.Submit(context.Background(), integrationRequest("corrupt"))
	if err != nil {
		t.Fatal(err)
	}
	_ = rt.Close()
	if err := os.WriteFile(filepath.Join(root, "objects", "sha256", receipt.ObjectDigest), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	rt, err = NewRuntime(Config{QueueRoot: root, TenantID: "tenant-a", Actor: "operator-a", KeyVersion: "kek-v1", Provider: provider, Uploader: uploader})
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	if _, err := rt.Status(context.Background(), receipt.UploadID); !errors.Is(err, queue.ErrNotFound) {
		t.Fatalf("corrupt item status err=%v", err)
	}
}

func TestRuntimeExpiresQueuedUpload(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	clock := func() time.Time { return now }
	provider, err := envelope.NewLocalProvider("kek-v1", []byte("01234567890123456789012345678901"))
	if err != nil {
		t.Fatal(err)
	}
	rt, err := NewRuntime(Config{QueueRoot: t.TempDir(), TenantID: "tenant-a", Actor: "operator-a", KeyVersion: "kek-v1", Provider: provider, Uploader: &testUploader{}, BrokerConfig: diagnostics.Config{TTL: time.Minute, Now: clock}, QueueConfig: queue.Config{TTL: time.Minute, Clock: clock}})
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	receipt, err := rt.Submit(context.Background(), integrationRequest("expire"))
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	if _, err := rt.Status(context.Background(), receipt.UploadID); !errors.Is(err, queue.ErrExpired) {
		t.Fatalf("expiry err=%v", err)
	}
}

func TestRuntimeReplayGuardReservesEnvelopeIdentity(t *testing.T) {
	guard := envelope.NewMemoryReplayGuard(8)
	uploader := &testUploader{}
	provider, err := envelope.NewLocalProvider("kek-v1", []byte("01234567890123456789012345678901"))
	if err != nil {
		t.Fatal(err)
	}
	rt, err := NewRuntime(Config{QueueRoot: t.TempDir(), TenantID: "tenant-a", Actor: "operator-a", KeyVersion: "kek-v1", Provider: provider, Uploader: uploader, ReplayGuard: guard, QueueConfig: queue.Config{RetainSuccessfulCiphertext: true}})
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	receipt, err := rt.Submit(context.Background(), integrationRequest("replay"))
	if err != nil {
		t.Fatal(err)
	}
	if err := rt.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := rt.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	raw, err := rt.Queue().ReadEnvelope(context.Background(), receipt.UploadID)
	if err != nil {
		t.Fatal(err)
	}
	env, err := envelope.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	id := env.ID
	if id == "" {
		id = env.EnvelopeID
	}
	if !guard.Seen(id) {
		t.Fatalf("replay guard did not reserve %q", id)
	}
	if err := guard.CheckAndMark(context.Background(), id); !errors.Is(err, envelope.ErrReplay) {
		t.Fatalf("second reservation err=%v", err)
	}
}

func TestRuntimeDoesNotPersistPlaintextPackage(t *testing.T) {
	root := t.TempDir()
	provider, err := envelope.NewLocalProvider("kek-v1", []byte("01234567890123456789012345678901"))
	if err != nil {
		t.Fatal(err)
	}
	rt, err := NewRuntime(Config{QueueRoot: root, TenantID: "tenant-a", Actor: "operator-a", KeyVersion: "kek-v1", Provider: provider, Uploader: &testUploader{}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rt.Submit(context.Background(), integrationRequest("disk-secret")); err != nil {
		t.Fatal(err)
	}
	_ = rt.Close()
	var foundPlaintext bool
	_ = filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil || info.IsDir() {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr == nil && strings.Contains(string(data), "\\\"status\\\":\\\"ok\\\"") {
			foundPlaintext = true
		}
		return nil
	})
	if foundPlaintext {
		t.Fatal("plaintext diagnostic package persisted")
	}
}

func TestRuntimePauseResumeAndRetry(t *testing.T) {
	uploader := &flakyUploader{failFor: 1}
	rt := newTestRuntime(t, uploader)
	if err := rt.Pause(context.Background()); err != nil {
		t.Fatal(err)
	}
	receipt, err := rt.Submit(context.Background(), integrationRequest("pause-retry"))
	if err != nil {
		t.Fatal(err)
	}
	if err := rt.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := rt.Wait(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("paused wait err=%v", err)
	}
	if err := rt.Resume(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := rt.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	status, err := rt.Status(context.Background(), receipt.UploadID)
	if err != nil || status.State != queue.StateCompleted || status.Attempt != 2 {
		t.Fatalf("status=%#v err=%v", status, err)
	}
}

func TestRuntimeConcurrentSubmissionsRemainBoundedAndIdempotent(t *testing.T) {
	rt := newTestRuntime(t, &testUploader{})
	const n = 4
	var wg sync.WaitGroup
	results := make(chan Receipt, n)
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			receipt, err := rt.Submit(context.Background(), integrationRequest("concurrent-"+string(rune('a'+i))))
			if err != nil {
				errs <- err
				return
			}
			results <- receipt
		}(i)
	}
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for receipt := range results {
		if seen[receipt.UploadID] {
			t.Fatalf("duplicate upload id %q", receipt.UploadID)
		}
		seen[receipt.UploadID] = true
	}
	if len(seen) != n {
		t.Fatalf("accepted=%d want=%d", len(seen), n)
	}
}

func TestRuntimeAuditEventsAndOutboxContainMetadataOnly(t *testing.T) {
	provider, err := envelope.NewLocalProvider("kek-v1", []byte("01234567890123456789012345678901"))
	if err != nil {
		t.Fatal(err)
	}
	journal := audit.NewMemoryJournal()
	outbox := audit.NewMemorySIEMOutboxAdapter()
	auditRuntime, err := audit.NewRuntime(audit.RuntimeOptions{Journal: journal, StreamID: "diagnostics", QueueCapacity: 32, Outboxes: []audit.OutboxAdapter{outbox}})
	if err != nil {
		t.Fatal(err)
	}
	rt, err := NewRuntime(Config{QueueRoot: t.TempDir(), TenantID: "tenant-a", Actor: "operator-a", KeyVersion: "kek-v1", Provider: provider, Uploader: &testUploader{}, Audit: auditRuntime, PollInterval: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	receipt, err := rt.Submit(context.Background(), integrationRequest("audit"))
	if err != nil {
		t.Fatal(err)
	}
	if err := rt.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := rt.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := rt.Audit().Verify(context.Background()); err != nil {
		t.Fatal(err)
	}
	deliveries := outbox.Deliveries()
	if len(deliveries) == 0 {
		t.Fatal("audit outbox was not dispatched")
	}
	rows, err := journal.Records(context.Background(), "diagnostics", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.Event.Resource != "diagnostic/"+receipt.UploadID {
			t.Fatalf("unexpected resource=%q", row.Event.Resource)
		}
		encoded, _ := json.Marshal(row.Event)
		if strings.Contains(string(encoded), "\\\"status\\\":\\\"ok\\\"") {
			t.Fatal("plaintext package entered audit event")
		}
	}
}

func TestRuntimeAllocatesFreshQueueIDAfterRestartCollision(t *testing.T) {
	root := t.TempDir()
	provider, err := envelope.NewLocalProvider("kek-v1", []byte("01234567890123456789012345678901"))
	if err != nil {
		t.Fatal(err)
	}
	first, err := NewRuntime(Config{QueueRoot: root, TenantID: "tenant-a", Actor: "operator-a", KeyVersion: "kek-v1", Provider: provider, Uploader: &testUploader{}})
	if err != nil {
		t.Fatal(err)
	}
	firstReceipt, err := first.Submit(context.Background(), integrationRequest("first"))
	if err != nil {
		t.Fatal(err)
	}
	_ = first.Close()
	second, err := NewRuntime(Config{QueueRoot: root, TenantID: "tenant-a", Actor: "operator-a", KeyVersion: "kek-v1", Provider: provider, Uploader: &testUploader{}})
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	secondReceipt, err := second.Submit(context.Background(), integrationRequest("second"))
	if err != nil {
		t.Fatal(err)
	}
	if secondReceipt.UploadID == firstReceipt.UploadID {
		t.Fatalf("queue ID collision: %q", secondReceipt.UploadID)
	}
}

func TestSubmitPersistsEnvelopeBeforeWorkerUpload(t *testing.T) {
	uploader := &testUploader{entered: make(chan struct{}, 1), release: make(chan struct{})}
	rt := newTestRuntime(t, uploader)
	started := time.Now()
	receipt, err := rt.Submit(context.Background(), integrationRequest("idem-1"))
	if err != nil {
		t.Fatal(err)
	}
	if receipt.UploadID == "" || receipt.State != diagnostics.StateQueued {
		t.Fatalf("receipt=%#v", receipt)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("submit blocked: %v", elapsed)
	}
	uploader.mu.Lock()
	calls := len(uploader.calls)
	uploader.mu.Unlock()
	if calls != 0 {
		t.Fatalf("upload called on request thread: %d", calls)
	}
	if err := rt.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-uploader.entered:
	case <-time.After(time.Second):
		t.Fatal("worker did not upload")
	}
	close(uploader.release)
	if err := rt.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	status, err := rt.Status(context.Background(), receipt.UploadID)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != queue.StateCompleted {
		t.Fatalf("status=%#v", status)
	}
}

func TestUploadFailureLeavesRetryableItemAndAuditMetadataOnly(t *testing.T) {
	uploader := &testUploader{fail: true}
	rt := newTestRuntime(t, uploader)
	receipt, err := rt.Submit(context.Background(), integrationRequest("idem-fail"))
	if err != nil {
		t.Fatal(err)
	}
	if err := rt.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	var status queue.Item
	var statusErr error
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		status, statusErr = rt.Status(context.Background(), receipt.UploadID)
		if statusErr == nil && (status.State == queue.StateRetrying || status.State == queue.StateFailed) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if statusErr != nil {
		t.Fatal(statusErr)
	}
	if status.State != queue.StateRetrying && status.State != queue.StateFailed {
		t.Fatalf("status=%#v", status)
	}
	if status.LastError == "" {
		t.Fatal("missing failure reason")
	}
	uploader.mu.Lock()
	defer uploader.mu.Unlock()
	if len(uploader.calls) == 0 || len(uploader.calls[0].Envelope) == 0 {
		t.Fatalf("calls=%#v", uploader.calls)
	}
	for _, call := range uploader.calls {
		if string(call.Envelope) == "{\\\"kind\\\":\\\"sanitized\\\",\\\"metadata\\\":{\\\"status\\\":\\\"ok\\\"}}" {
			t.Fatal("plaintext package reached uploader")
		}
	}
}

func TestRuntimeReplayGuardReleasesAfterUploadFailure(t *testing.T) {
	guard := envelope.NewMemoryReplayGuard(8)
	uploader := &flakyUploader{failFor: 1}
	provider, err := envelope.NewLocalProvider("kek-v1", []byte("01234567890123456789012345678901"))
	if err != nil {
		t.Fatal(err)
	}
	rt, err := NewRuntime(Config{
		QueueRoot: t.TempDir(), TenantID: "tenant-a", Actor: "operator-a", KeyVersion: "kek-v1",
		Provider: provider, Uploader: uploader, ReplayGuard: guard, PollInterval: time.Millisecond,
		QueueConfig: queue.Config{MaxItems: 4, MaxBytes: 1 << 20, TTL: time.Hour, RetryDelay: time.Millisecond},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	defer provider.Close()
	receipt, err := rt.Submit(context.Background(), integrationRequest("replay-retry"))
	if err != nil {
		t.Fatal(err)
	}
	if err := rt.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := rt.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	status, err := rt.Status(context.Background(), receipt.UploadID)
	if err != nil || status.State != queue.StateCompleted || status.Attempt != 2 {
		t.Fatalf("status=%#v err=%v", status, err)
	}
	if got := guard.Len(); got != 1 {
		t.Fatalf("replay guard entries=%d, want one committed identity", got)
	}
	uploader.mu.Lock()
	attempts := uploader.attempts
	uploader.mu.Unlock()
	if attempts != 2 {
		t.Fatalf("uploader attempts=%d, want 2", attempts)
	}
}

func TestRuntimeReplayGuardSuppressesConcurrentDuplicate(t *testing.T) {
	guard := envelope.NewMemoryReplayGuard(8)
	uploader := &testUploader{entered: make(chan struct{}, 1), release: make(chan struct{})}
	rt := newRuntimeWithReplayGuard(t, uploader, guard)
	receipt, err := rt.Submit(context.Background(), integrationRequest("replay-concurrent"))
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := rt.Queue().Claim(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if claimed.UploadID != receipt.UploadID {
		t.Fatalf("claimed upload id=%q, want %q", claimed.UploadID, receipt.UploadID)
	}
	first := *claimed
	first.Ciphertext = append([]byte(nil), claimed.Ciphertext...)
	first.Envelope, first.Payload, first.EncryptedPayload = nil, nil, nil
	second := *claimed
	second.Ciphertext = append([]byte(nil), claimed.Ciphertext...)
	second.Envelope, second.Payload, second.EncryptedPayload = nil, nil, nil

	firstErr := make(chan error, 1)
	go func() { firstErr <- rt.handle(context.Background(), first) }()
	select {
	case <-uploader.entered:
	case <-time.After(time.Second):
		t.Fatal("first uploader call did not start")
	}
	secondErr := rt.handle(context.Background(), second)
	if !errors.Is(secondErr, envelope.ErrReplay) {
		t.Fatalf("second concurrent handle err=%v, want replay", secondErr)
	}
	close(uploader.release)
	if err := <-firstErr; err != nil {
		t.Fatalf("first handle err=%v", err)
	}
	uploader.mu.Lock()
	calls := len(uploader.calls)
	uploader.mu.Unlock()
	if calls != 1 {
		t.Fatalf("uploader calls=%d, want one", calls)
	}
}

func TestRuntimeTamperedEnvelopeDoesNotConsumeReplayReservation(t *testing.T) {
	guard := envelope.NewMemoryReplayGuard(8)
	uploader := &testUploader{}
	rt := newRuntimeWithReplayGuard(t, uploader, guard)
	receipt, err := rt.Submit(context.Background(), integrationRequest("replay-tamper"))
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := rt.Queue().Claim(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if claimed.UploadID != receipt.UploadID {
		t.Fatalf("claimed upload id=%q, want %q", claimed.UploadID, receipt.UploadID)
	}
	tampered := *claimed
	decoded, err := envelope.Decode(claimed.Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	decoded.Ciphertext = append([]byte(nil), decoded.Ciphertext...)
	decoded.Ciphertext[0] ^= 1
	tampered.Ciphertext, err = envelope.Encode(decoded)
	if err != nil {
		t.Fatal(err)
	}
	tampered.Envelope, tampered.Payload, tampered.EncryptedPayload = nil, nil, nil
	if err := rt.handle(context.Background(), tampered); !errors.Is(err, envelope.ErrAuthentication) {
		t.Fatalf("tampered handle err=%v", err)
	}
	if guard.Len() != 0 {
		t.Fatalf("tampered envelope consumed replay entries=%d", guard.Len())
	}
	original := *claimed
	original.Ciphertext = append([]byte(nil), claimed.Ciphertext...)
	original.Envelope, original.Payload, original.EncryptedPayload = nil, nil, nil
	if err := rt.handle(context.Background(), original); err != nil {
		t.Fatalf("original handle err=%v", err)
	}
	if guard.Len() != 1 {
		t.Fatalf("valid envelope did not commit replay entry: %d", guard.Len())
	}
}

func TestRuntimeAuditsReplayCommitFailureWithoutRepeatingSuccessfulUpload(t *testing.T) {
	ctx := context.Background()
	provider, err := envelope.NewLocalProvider("kek-v1", []byte("01234567890123456789012345678901"))
	if err != nil {
		t.Fatal(err)
	}
	journal := audit.NewMemoryJournal()
	auditRuntime, err := audit.NewRuntime(audit.RuntimeOptions{Journal: journal, StreamID: "diagnostics", QueueCapacity: 16})
	if err != nil {
		t.Fatal(err)
	}
	guard := &commitFailReplayGuard{commitErr: errors.New("replay commit unavailable")}
	uploader := &testUploader{}
	rt, err := NewRuntime(Config{
		QueueRoot: t.TempDir(), TenantID: "tenant-a", Actor: "operator-a", KeyVersion: "kek-v1",
		Provider: provider, Uploader: uploader, ReplayGuard: guard, Audit: auditRuntime,
		QueueConfig: queue.Config{MaxItems: 4, MaxBytes: 1 << 20, TTL: time.Hour},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rt.Close(); _ = auditRuntime.Close(); _ = provider.Close() })
	receipt, err := rt.Submit(ctx, integrationRequest("replay-commit-failure"))
	if err != nil {
		t.Fatal(err)
	}
	item, err := rt.Queue().Claim(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if item.UploadID != receipt.UploadID {
		t.Fatalf("claimed upload id=%q, want %q", item.UploadID, receipt.UploadID)
	}
	if err := rt.handle(ctx, *item); err != nil {
		t.Fatalf("successful upload was converted into a retry: %v", err)
	}
	if guard.reserve.Load() != 1 || guard.commit.Load() != 1 || guard.release.Load() != 0 {
		t.Fatalf("replay lifecycle reserve=%d commit=%d release=%d", guard.reserve.Load(), guard.commit.Load(), guard.release.Load())
	}
	uploader.mu.Lock()
	uploadCalls := len(uploader.calls)
	uploader.mu.Unlock()
	if uploadCalls != 1 {
		t.Fatalf("uploader calls=%d, want one", uploadCalls)
	}
	if err := auditRuntime.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	records, err := journal.Records(ctx, "diagnostics", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, record := range records {
		if record.Event.Action == "replay_commit" && record.Event.Outcome == audit.OutcomeFailure {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("replay commit failure was not audited")
	}
}

func newRuntimeWithReplayGuard(t *testing.T, uploader UploadAdapter, guard envelope.ReplayGuard) *Runtime {
	t.Helper()
	provider, err := envelope.NewLocalProvider("kek-v1", []byte("01234567890123456789012345678901"))
	if err != nil {
		t.Fatal(err)
	}
	rt, err := NewRuntime(Config{
		QueueRoot: t.TempDir(), TenantID: "tenant-a", Actor: "operator-a", KeyVersion: "kek-v1",
		Provider: provider, Uploader: uploader, ReplayGuard: guard,
		QueueConfig: queue.Config{MaxItems: 4, MaxBytes: 1 << 20, TTL: time.Hour},
	})
	if err != nil {
		provider.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rt.Close(); _ = provider.Close() })
	return rt
}
