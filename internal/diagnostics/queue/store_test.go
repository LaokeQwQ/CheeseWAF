package queue

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type testCodec struct {
	mu      sync.Mutex
	sealed  [][]byte
	entered chan struct{}
	release chan struct{}
}

func (c *testCodec) Seal(_ context.Context, plaintext []byte) ([]byte, error) {
	c.mu.Lock()
	c.sealed = append(c.sealed, plaintext)
	c.mu.Unlock()
	if c.entered != nil {
		c.entered <- struct{}{}
	}
	if c.release != nil {
		<-c.release
	}
	out := append([]byte("sealed:"), plaintext...)
	for i := len("sealed:"); i < len(out); i++ {
		out[i] ^= 0xa5
	}
	return out, nil
}

func (c *testCodec) Open(_ context.Context, ciphertext []byte) ([]byte, error) {
	data := bytes.TrimPrefix(ciphertext, []byte("sealed:"))
	out := append([]byte(nil), data...)
	for i := range out {
		out[i] ^= 0xa5
	}
	return out, nil
}

func encryptedRequest(key string, data ...[]byte) Request {
	var ciphertext []byte
	if len(data) > 0 {
		ciphertext = data[0]
	}
	return Request{
		TenantID: "tenant-a", PluginID: "plugin-a", PluginVersion: "1.0.0",
		Target: "audit", PolicyEpoch: 1, LeaseID: "lease-a",
		IdempotencyKey: key, Ciphertext: append([]byte(nil), ciphertext...),
	}
}

func TestStorePersistsEncryptedItemAcrossRestartAndDeletesObjectOnSuccess(t *testing.T) {
	root := t.TempDir()
	data := []byte("opaque-ciphertext")
	s, err := NewStore(root, Config{MaxItems: 4, MaxBytes: 1024, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := s.EnqueueEncrypted(context.Background(), encryptedRequest("idem-1"), data)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.ID == "" || receipt.ObjectDigest == "" {
		t.Fatalf("incomplete receipt: %#v", receipt)
	}
	digest := sha256.Sum256(data)
	wantDigest := hex.EncodeToString(digest[:])
	if receipt.ObjectDigest != wantDigest {
		t.Fatalf("digest=%q want %q", receipt.ObjectDigest, wantDigest)
	}
	if _, err := os.Stat(filepath.Join(root, "objects", "sha256", wantDigest)); err != nil {
		t.Fatalf("content addressed object missing: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s, err = NewStore(root, Config{MaxItems: 4, MaxBytes: 1024, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	item, err := s.Claim(context.Background())
	if err != nil || item == nil {
		t.Fatalf("claim after restart: item=%#v err=%v", item, err)
	}
	if item.ID != receipt.ID || !bytes.Equal(item.Ciphertext, data) {
		t.Fatalf("recovered item=%#v", item)
	}
	if err := s.Complete(context.Background(), item.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "objects", "sha256", wantDigest)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("successful item retained ciphertext: %v", err)
	}
	if got, err := s.Status(context.Background(), item.ID); err != nil || got.State != StateCompleted {
		t.Fatalf("status=%#v err=%v", got, err)
	}
}

func TestStoreRequeuesProcessingItemAfterCrashLikeRestart(t *testing.T) {
	root := t.TempDir()
	s, err := NewStore(root, Config{MaxItems: 4, MaxBytes: 1024, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.EnqueueEncrypted(context.Background(), encryptedRequest("crash"), []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := s.Claim(context.Background())
	if err != nil || claimed.Attempt != 1 {
		t.Fatalf("first claim=%#v err=%v", claimed, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = NewStore(root, Config{MaxItems: 4, MaxBytes: 1024, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := s.Claim(context.Background())
	if err != nil || recovered.ID != r.ID || recovered.Attempt != 2 {
		t.Fatalf("recovered claim=%#v err=%v", recovered, err)
	}
}

func TestStoreDropsCorruptObjectDuringRecovery(t *testing.T) {
	root := t.TempDir()
	data := []byte("ciphertext")
	s, err := NewStore(root, Config{MaxItems: 4, MaxBytes: 1024, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := s.EnqueueEncrypted(context.Background(), encryptedRequest("idem-corrupt"), data)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	objectPath := filepath.Join(root, "objects", "sha256", receipt.ObjectDigest)
	if err := os.WriteFile(objectPath, []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	s, err = NewStore(root, Config{MaxItems: 4, MaxBytes: 1024, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	stats := s.Stats()
	if stats.Corrupt != 1 || stats.Pending != 0 {
		t.Fatalf("corrupt recovery stats=%#v", stats)
	}
	if _, err := s.Claim(context.Background()); !errors.Is(err, ErrEmpty) {
		t.Fatalf("claim after corruption err=%v", err)
	}
}

func TestStoreEnforcesItemAndByteQuotaIncludingClaimedItems(t *testing.T) {
	root := t.TempDir()
	s, err := NewStore(root, Config{MaxItems: 1, MaxBytes: 5, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	first, err := s.EnqueueEncrypted(context.Background(), encryptedRequest("idem-first"), []byte("12345"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.EnqueueEncrypted(context.Background(), encryptedRequest("idem-second"), []byte("x")); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("item quota err=%v", err)
	}
	item, err := s.Claim(context.Background())
	if err != nil || item.ID != first.ID {
		t.Fatalf("claim=%#v err=%v", item, err)
	}
	if _, err := s.EnqueueEncrypted(context.Background(), encryptedRequest("idem-third"), []byte("x")); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("claimed item did not reserve quota: %v", err)
	}
	if err := s.Complete(context.Background(), first.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.EnqueueEncrypted(context.Background(), encryptedRequest("idem-too-large"), []byte("123456")); !errors.Is(err, ErrByteQuota) {
		t.Fatalf("byte quota err=%v", err)
	}
}

func TestStoreIdempotencyPauseAndResumePersist(t *testing.T) {
	root := t.TempDir()
	s, err := NewStore(root, Config{MaxItems: 4, MaxBytes: 1024, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	req := encryptedRequest("idem-same")
	first, err := s.EnqueueEncrypted(context.Background(), req, []byte("same"))
	if err != nil {
		t.Fatal(err)
	}
	again, err := s.EnqueueEncrypted(context.Background(), req, []byte("same"))
	if err != nil || again.ID != first.ID {
		t.Fatalf("idempotent enqueue: %#v err=%v", again, err)
	}
	conflict := req
	conflict.Target = "other"
	if _, err := s.EnqueueEncrypted(context.Background(), conflict, []byte("same")); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("idempotency conflict err=%v", err)
	}
	if err := s.Pause(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Claim(context.Background()); !errors.Is(err, ErrPaused) {
		t.Fatalf("paused claim err=%v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = NewStore(root, Config{MaxItems: 4, MaxBytes: 1024, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if !s.Paused() {
		t.Fatal("pause state was not durable")
	}
	if err := s.Resume(); err != nil {
		t.Fatal(err)
	}
	item, err := s.Claim(context.Background())
	if err != nil || item.ID != first.ID {
		t.Fatalf("resumed claim=%#v err=%v", item, err)
	}
}

func TestStoreSealingWipesInternalPlaintextAndPersistsNoPlaintext(t *testing.T) {
	root := t.TempDir()
	codec := &testCodec{}
	s, err := NewStore(root, Config{Codec: codec, MaxItems: 4, MaxBytes: 1024, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("diagnostic plaintext")
	req := encryptedRequest("idem-plain", nil)
	req.Plaintext = secret
	if _, err := s.Enqueue(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	codec.mu.Lock()
	sealed := append([]byte(nil), codec.sealed[0]...)
	codec.mu.Unlock()
	if !bytes.Equal(sealed, make([]byte, len(sealed))) {
		t.Fatalf("codec retained plaintext bytes: %q", sealed)
	}
	var found bool
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr == nil && !d.IsDir() {
			data, _ := os.ReadFile(path)
			if bytes.Contains(data, secret) {
				found = true
			}
		}
		return nil
	})
	if found {
		t.Fatal("plaintext leaked into queue files")
	}
}

func TestStoreWorkerIsSingleConcurrentWorker(t *testing.T) {
	root := t.TempDir()
	s, err := NewStore(root, Config{MaxItems: 32, MaxBytes: 1 << 20, TTL: time.Hour, MaxAttempts: 1})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 16; i++ {
		if _, err := s.EnqueueEncrypted(context.Background(), encryptedRequest("worker-"+string(rune('a'+i))), []byte("payload")); err != nil {
			t.Fatal(err)
		}
	}
	var active, maxActive atomic.Int32
	var handled atomic.Int32
	done := make(chan struct{})
	if err := s.Start(context.Background(), func(_ context.Context, item Item) error {
		n := active.Add(1)
		for {
			old := maxActive.Load()
			if n <= old || maxActive.CompareAndSwap(old, n) {
				break
			}
		}
		time.Sleep(time.Millisecond)
		active.Add(-1)
		if handled.Add(1) == 16 {
			close(done)
		}
		_ = item
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatalf("worker handled %d items", handled.Load())
	}
	if maxActive.Load() != 1 {
		t.Fatalf("concurrent worker count=%d", maxActive.Load())
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestStoreWorkerSurfacesSuccessfulCompletionFailureAndStops(t *testing.T) {
	root := t.TempDir()
	s, err := NewStore(root, Config{MaxItems: 4, MaxBytes: 1024, TTL: time.Hour, MaxAttempts: 1, RetryDelay: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	receipt, err := s.EnqueueEncrypted(context.Background(), encryptedRequest("completion-error"), []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	var handled atomic.Int32
	handlerDone := make(chan struct{})
	if err := s.Start(context.Background(), func(ctx context.Context, item Item) error {
		handled.Add(1)
		// Simulate a handler whose external side effect and queue completion
		// succeeded before runWorker performs its own completion step. The
		// second completion must be observable instead of silently discarded.
		if err := s.Complete(ctx, item.ID, true); err != nil {
			return err
		}
		close(handlerDone)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-handlerDone:
	case <-time.After(2 * time.Second):
		t.Fatal("worker handler did not run")
	}
	deadline := time.Now().Add(2 * time.Second)
	var workerErr error
	for time.Now().Before(deadline) {
		workerErr = s.WorkerError()
		if workerErr != nil {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !errors.Is(workerErr, ErrInvalidState) {
		t.Fatalf("WorkerError()=%v, want ErrInvalidState", workerErr)
	}
	if handled.Load() != 1 {
		t.Fatalf("handler calls=%d, want one", handled.Load())
	}
	status, err := s.Status(context.Background(), receipt.ID)
	if err != nil || status.State != StateCompleted {
		t.Fatalf("status=%#v err=%v", status, err)
	}
}

func TestStoreUsesSecureModesAndContentAddressedPath(t *testing.T) {
	root := t.TempDir()
	s, err := NewStore(root, Config{MaxItems: 4, MaxBytes: 1024, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.EnqueueEncrypted(context.Background(), encryptedRequest("mode"), []byte("bytes"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{root, filepath.Join(root, "objects"), filepath.Join(root, "objects", "sha256"), filepath.Join(root, "state.json"), filepath.Join(root, "objects", "sha256", r.ObjectDigest)} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		want := os.FileMode(0700)
		if !info.IsDir() {
			want = 0600
		}
		if info.Mode().Perm() != want {
			t.Fatalf("%s mode=%o want %o", path, info.Mode().Perm(), want)
		}
	}
}

func TestStoreExpiresItemsAndRejectsExpiredIdempotency(t *testing.T) {
	root := t.TempDir()
	now := time.Unix(100, 0).UTC()
	s, err := NewStore(root, Config{MaxItems: 4, MaxBytes: 1024, TTL: time.Minute, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	req := encryptedRequest("expire")
	if _, err := s.EnqueueEncrypted(context.Background(), req, []byte("x")); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	if _, err := s.Claim(context.Background()); !errors.Is(err, ErrExpired) {
		t.Fatalf("claim expiry err=%v", err)
	}
	if _, err := s.EnqueueEncrypted(context.Background(), req, []byte("x")); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired idempotency err=%v", err)
	}
}

func TestStoreRejectsUnsafeIdempotencyWhitespace(t *testing.T) {
	root := t.TempDir()
	s, err := NewStore(root, Config{})
	if err != nil {
		t.Fatal(err)
	}
	req := encryptedRequest(" bad", []byte("x"))
	if _, err := s.EnqueueEncrypted(context.Background(), req, []byte("x")); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("unsafe idempotency err=%v", err)
	}
	if strings.TrimSpace(req.IdempotencyKey) == req.IdempotencyKey {
		t.Fatal("test key unexpectedly normalized")
	}
}

func TestStoreWorkerRetriesBeforeTerminalFailure(t *testing.T) {
	root := t.TempDir()
	s, err := NewStore(root, Config{MaxItems: 4, MaxBytes: 1024, TTL: time.Hour, MaxAttempts: 2, RetryDelay: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := s.EnqueueEncrypted(context.Background(), encryptedRequest("retry-worker"), []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	var attempts atomic.Int32
	done := make(chan struct{})
	if err := s.Start(context.Background(), func(_ context.Context, _ Item) error {
		if attempts.Add(1) == 2 {
			close(done)
		}
		return errors.New("temporary")
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("worker attempts=%d", attempts.Load())
	}
	if err := s.Stop(); err != nil {
		t.Fatal(err)
	}
	status, err := s.Status(context.Background(), receipt.ID)
	if err != nil || status.State != StateFailed {
		t.Fatalf("status=%#v err=%v", status, err)
	}
}

func TestStoreConcurrentSameIdempotencyKeyHasOneDurableEntry(t *testing.T) {
	root := t.TempDir()
	s, err := NewStore(root, Config{MaxItems: 64, MaxBytes: 1 << 20, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	const workers = 32
	results := make(chan Receipt, workers)
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := s.EnqueueEncrypted(context.Background(), encryptedRequest("same-race"), []byte("same"))
			results <- r
			errs <- err
		}()
	}
	wg.Wait()
	close(results)
	close(errs)
	var id string
	for r := range results {
		if id == "" {
			id = r.ID
		}
		if r.ID != id {
			t.Fatalf("duplicate idempotent IDs: %q and %q", id, r.ID)
		}
	}
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent enqueue error: %v", err)
		}
	}
	if got := s.Stats().Pending; got != 1 {
		t.Fatalf("pending=%d want 1", got)
	}
}

func TestStoreCanRetainCiphertextAfterSuccessfulDeliveryByPolicy(t *testing.T) {
	root := t.TempDir()
	s, err := NewStore(root, Config{MaxItems: 4, MaxBytes: 1024, TTL: time.Hour, Cleanup: CleanupPolicy{RetainSuccessfulCiphertext: true}})
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("retain-me")
	r, err := s.EnqueueEncrypted(context.Background(), encryptedRequest("retain"), data)
	if err != nil {
		t.Fatal(err)
	}
	item, err := s.Claim(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Complete(context.Background(), item.ID, true); err != nil {
		t.Fatal(err)
	}
	got, err := s.ReadEnvelope(context.Background(), r.ID)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("retained ciphertext=%q err=%v", got, err)
	}
}
