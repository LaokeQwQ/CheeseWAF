package extensions

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/audit"
)

type ingressSink struct {
	mu      sync.Mutex
	events  []audit.Event
	err     error
	started chan struct{}
	block   <-chan struct{}
}

func (s *ingressSink) Append(_ context.Context, event audit.Event) (audit.Record, error) {
	if s.started != nil {
		select {
		case <-s.started:
		default:
			close(s.started)
		}
	}
	if s.block != nil {
		<-s.block
	}
	s.mu.Lock()
	s.events = append(s.events, event)
	err := s.err
	s.mu.Unlock()
	return audit.Record{}, err
}

func (s *ingressSink) snapshot() []audit.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]audit.Event(nil), s.events...)
}

func TestIngressAcceptsOnlyVerifiedMetadataAndDeduplicates(t *testing.T) {
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sink := &ingressSink{}
	ingress, err := NewIngress(IngressOptions{
		Keys:     map[string]TrustKey{"host-v1": {ID: "host-v1", PublicKey: private.Public().(ed25519.PublicKey)}},
		PluginID: "jev", PluginVersion: "1.2.3", TenantRef: "tenant:demo", SiteRef: "site:demo", PolicyEpoch: 7,
		StreamID: "extensions", MaxTTL: 10 * time.Minute, Now: func() time.Time { return now }, Sink: sink,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ingress.Close()
	wire := signedIngressOutput(t, private, now, "evt-1", 1, `{"risk":"medium"}`)
	first, err := ingress.Submit(context.Background(), wire)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	second, err := ingress.Submit(context.Background(), wire)
	if err != nil {
		t.Fatalf("duplicate submit: %v", err)
	}
	if !second.Duplicate || first.PayloadDigest == "" || first.EventID != "evt-1" || first.Sequence != 1 {
		t.Fatalf("receipts = %#v %#v", first, second)
	}
	if err := ingress.Flush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}
	events := sink.snapshot()
	if len(events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(events))
	}
	if events[0].Actor != "jev" || events[0].TenantID != "tenant:demo" || events[0].Resource != "plugin:jev" || events[0].PolicyEpoch != 7 || events[0].EvidenceDigest != first.PayloadDigest {
		t.Fatalf("audit event leaked or lost binding: %#v", events[0])
	}
}

func TestIngressRejectsScopeIdentityAndReplayConflict(t *testing.T) {
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ingress, err := NewIngress(IngressOptions{
		Keys:     map[string]TrustKey{"host-v1": {ID: "host-v1", PublicKey: private.Public().(ed25519.PublicKey)}},
		PluginID: "edr", PluginVersion: "0.3.0", TenantRef: "tenant:demo", SiteRef: "site:demo", PolicyEpoch: 9,
		StreamID: "extensions", MaxTTL: 10 * time.Minute, Now: func() time.Time { return now }, Sink: OutputSinkFunc(func(context.Context, audit.Event) (audit.Record, error) { return audit.Record{}, nil }),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ingress.Close()
	wrongPlugin := signedIngressOutputWith(t, private, now, OutputClaims{APIVersion: SecurityEventAPIVersion, PluginID: "jev", PluginVersion: "0.3.0", EventID: "evt-1", Sequence: 1, TenantRef: "tenant:demo", SiteRef: "site:demo", PolicyEpoch: 9, ObservedAt: now, ExpiresAt: now.Add(time.Minute)}, `{}`)
	if _, err := ingress.Submit(context.Background(), wrongPlugin); !errors.Is(err, ErrOutputRejected) {
		t.Fatalf("plugin mismatch error = %v", err)
	}
	wrongTenant := signedIngressOutputWith(t, private, now, OutputClaims{APIVersion: SecurityEventAPIVersion, PluginID: "edr", PluginVersion: "0.3.0", EventID: "evt-2", Sequence: 1, TenantRef: "tenant:other", SiteRef: "site:demo", PolicyEpoch: 9, ObservedAt: now, ExpiresAt: now.Add(time.Minute)}, `{}`)
	if _, err := ingress.Submit(context.Background(), wrongTenant); !errors.Is(err, ErrOutputRejected) {
		t.Fatalf("tenant mismatch error = %v", err)
	}
	first := signedIngressOutputWith(t, private, now, OutputClaims{APIVersion: SecurityEventAPIVersion, PluginID: "edr", PluginVersion: "0.3.0", EventID: "evt-3", Sequence: 4, TenantRef: "tenant:demo", SiteRef: "site:demo", PolicyEpoch: 9, ObservedAt: now, ExpiresAt: now.Add(time.Minute)}, `{"action":"observe"}`)
	if _, err := ingress.Submit(context.Background(), first); err != nil {
		t.Fatalf("first replay fixture: %v", err)
	}
	conflict := signedIngressOutputWith(t, private, now, OutputClaims{APIVersion: SecurityEventAPIVersion, PluginID: "edr", PluginVersion: "0.3.0", EventID: "evt-3", Sequence: 4, TenantRef: "tenant:demo", SiteRef: "site:demo", PolicyEpoch: 9, ObservedAt: now, ExpiresAt: now.Add(time.Minute)}, `{"action":"contain"}`)
	if _, err := ingress.Submit(context.Background(), conflict); !errors.Is(err, ErrIngressReplay) {
		t.Fatalf("conflicting replay error = %v", err)
	}
	if _, err := ingress.Submit(context.Background(), signedIngressOutputWith(t, private, now, OutputClaims{APIVersion: SecurityEventAPIVersion, PluginID: "edr", PluginVersion: "0.3.0", EventID: "evt-5", Sequence: 6, TenantRef: "tenant:demo", SiteRef: "site:demo", PolicyEpoch: 9, ObservedAt: now, ExpiresAt: now.Add(time.Minute)}, `{}`)); !errors.Is(err, ErrIngressSequenceGap) {
		t.Fatalf("sequence gap error = %v", err)
	}
	if _, err := ingress.Submit(context.Background(), signedIngressOutputWith(t, private, now, OutputClaims{APIVersion: SecurityEventAPIVersion, PluginID: "edr", PluginVersion: "0.3.0", EventID: "evt-4", Sequence: 5, TenantRef: "tenant:demo", SiteRef: "site:demo", PolicyEpoch: 9, ObservedAt: now, ExpiresAt: now.Add(time.Minute)}, `{}`)); err != nil {
		t.Fatalf("contiguous sequence: %v", err)
	}
	if _, err := ingress.Submit(context.Background(), signedIngressOutputWith(t, private, now, OutputClaims{APIVersion: SecurityEventAPIVersion, PluginID: "edr", PluginVersion: "0.3.0", EventID: "evt-old", Sequence: 2, TenantRef: "tenant:demo", SiteRef: "site:demo", PolicyEpoch: 9, ObservedAt: now, ExpiresAt: now.Add(time.Minute)}, `{}`)); !errors.Is(err, ErrIngressSequenceOld) {
		t.Fatalf("stale sequence error = %v", err)
	}
}

func TestIngressQueueIsBoundedAndRetriesAuditFailure(t *testing.T) {
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	sink := &ingressSink{started: started, block: release}
	ingress, err := NewIngress(IngressOptions{Keys: map[string]TrustKey{"host-v1": {ID: "host-v1", PublicKey: private.Public().(ed25519.PublicKey)}}, PluginID: "duckdb", PluginVersion: "1.0.0", TenantRef: "tenant:demo", SiteRef: "site:demo", PolicyEpoch: 3, StreamID: "extensions", MaxTTL: time.Minute, QueueCapacity: 1, Now: func() time.Time { return now }, Sink: sink})
	if err != nil {
		t.Fatal(err)
	}
	defer ingress.Close()
	if _, err := ingress.Submit(context.Background(), signedIngressOutputWith(t, private, now, outputClaims("e1", 1), `{}`)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("audit worker did not start")
	}
	if _, err := ingress.Submit(context.Background(), signedIngressOutputWith(t, private, now, outputClaims("e2", 2), `{}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := ingress.Submit(context.Background(), signedIngressOutputWith(t, private, now, outputClaims("e3", 3), `{}`)); !errors.Is(err, ErrIngressQueueFull) {
		t.Fatalf("queue error = %v", err)
	}
	close(release)
	if err := ingress.Flush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}

	var fail atomic.Bool
	fail.Store(true)
	failedSink := OutputSinkFunc(func(context.Context, audit.Event) (audit.Record, error) {
		if fail.Load() {
			return audit.Record{}, errors.New("test audit failure")
		}
		return audit.Record{}, nil
	})
	retryIngress, err := NewIngress(IngressOptions{Keys: map[string]TrustKey{"host-v1": {ID: "host-v1", PublicKey: private.Public().(ed25519.PublicKey)}}, PluginID: "duckdb", PluginVersion: "1.0.0", TenantRef: "tenant:demo", SiteRef: "site:demo", PolicyEpoch: 3, StreamID: "retry", MaxTTL: time.Minute, Now: func() time.Time { return now }, Sink: failedSink})
	if err != nil {
		t.Fatal(err)
	}
	defer retryIngress.Close()
	retryWire := signedIngressOutputWith(t, private, now, outputClaims("retry", 1), `{}`)
	if _, err := retryIngress.Submit(context.Background(), retryWire); err != nil {
		t.Fatal(err)
	}
	if err := retryIngress.Flush(context.Background()); !errors.Is(err, ErrIngressAuditFailed) {
		t.Fatalf("audit failure = %v", err)
	}
	fail.Store(false)
	receipt, err := retryIngress.Submit(context.Background(), retryWire)
	if err != nil || receipt.Duplicate {
		t.Fatalf("retry receipt = %#v err=%v", receipt, err)
	}
	if err := retryIngress.Flush(context.Background()); err != nil {
		t.Fatalf("retry flush: %v", err)
	}
}

func outputClaims(eventID string, sequence uint64) OutputClaims {
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	return OutputClaims{APIVersion: AnalysisRecordAPIVersion, PluginID: "duckdb", PluginVersion: "1.0.0", EventID: eventID, Sequence: sequence, TenantRef: "tenant:demo", SiteRef: "site:demo", PolicyEpoch: 3, ObservedAt: now, ExpiresAt: now.Add(time.Minute)}
}

func signedIngressOutput(t *testing.T, private ed25519.PrivateKey, now time.Time, eventID string, sequence uint64, data string) []byte {
	return signedIngressOutputWith(t, private, now, OutputClaims{APIVersion: RiskHintAPIVersion, PluginID: "jev", PluginVersion: "1.2.3", EventID: eventID, Sequence: sequence, TenantRef: "tenant:demo", SiteRef: "site:demo", PolicyEpoch: 7, ObservedAt: now, ExpiresAt: now.Add(5 * time.Minute)}, data)
}

func signedIngressOutputWith(t *testing.T, private ed25519.PrivateKey, now time.Time, claims OutputClaims, data string) []byte {
	t.Helper()
	claims.Data = json.RawMessage(data)
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signer := Signer{KeyID: "host-v1", PrivateKey: private, Now: func() time.Time { return now }, MaxTTL: 10 * time.Minute}
	attested, err := signer.Sign(payload, now)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(attested)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

// A successful entry must not clear the failure reported for a different one.
func TestIngressFlushKeepsFailuresFromOtherEntries(t *testing.T) {
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	failFirst := true
	sink := OutputSinkFunc(func(_ context.Context, event audit.Event) (audit.Record, error) {
		mu.Lock()
		defer mu.Unlock()
		if failFirst {
			failFirst = false
			return audit.Record{}, errors.New("audit down")
		}
		return audit.Record{Event: event}, nil
	})
	ingress, err := NewIngress(IngressOptions{
		Keys:     map[string]TrustKey{"host-v1": {ID: "host-v1", PublicKey: private.Public().(ed25519.PublicKey)}},
		PluginID: "jev", PluginVersion: "1.2.3", TenantRef: "tenant:demo", SiteRef: "site:demo", PolicyEpoch: 7,
		StreamID: "extensions", MaxTTL: 10 * time.Minute, Now: func() time.Time { return now }, Sink: sink,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ingress.Close()
	if _, err := ingress.Submit(context.Background(), signedIngressOutput(t, private, now, "evt-a", 1, `{}`)); err != nil {
		t.Fatal(err)
	}
	if err := ingress.Flush(context.Background()); err == nil {
		t.Fatal("first failure was not reported")
	}
	if _, err := ingress.Submit(context.Background(), signedIngressOutput(t, private, now, "evt-b", 2, `{}`)); err != nil {
		t.Fatal(err)
	}
	if err := ingress.Flush(context.Background()); err == nil {
		t.Fatal("later success hid the earlier failed entry")
	}
}

// The replay map must stay bounded; successes are evicted oldest-first.
func TestIngressSeenMapStaysBounded(t *testing.T) {
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ingress, err := NewIngress(IngressOptions{
		Keys:     map[string]TrustKey{"host-v1": {ID: "host-v1", PublicKey: private.Public().(ed25519.PublicKey)}},
		PluginID: "jev", PluginVersion: "1.2.3", TenantRef: "tenant:demo", SiteRef: "site:demo", PolicyEpoch: 7,
		StreamID: "extensions", MaxTTL: 10 * time.Minute, Now: func() time.Time { return now }, QueueCapacity: 8,
		Sink: OutputSinkFunc(func(_ context.Context, event audit.Event) (audit.Record, error) {
			return audit.Record{Event: event}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ingress.Close()
	for seq := uint64(1); seq <= uint64(ingress.seenCap)+64; seq++ {
		wire := signedIngressOutput(t, private, now, "evt-"+strconv.FormatUint(seq, 10), seq, `{}`)
		// The worker drains asynchronously; wait for admission instead of
		// racing the bounded queue.
		for attempt := 0; ; attempt++ {
			_, err := ingress.Submit(context.Background(), wire)
			if err == nil {
				break
			}
			if (!errors.Is(err, ErrIngressQueueFull) && !errors.Is(err, ErrIngressBacklogFull)) || attempt >= 5000 {
				t.Fatalf("submit %d: %v", seq, err)
			}
			time.Sleep(time.Millisecond)
		}
	}
	if err := ingress.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	ingress.mu.Lock()
	seen := len(ingress.seen)
	ingress.mu.Unlock()
	if seen > ingress.seenCap {
		t.Fatalf("seen map grew to %d (cap %d)", seen, ingress.seenCap)
	}
}

// A first admission rejected by a full queue must be retriable as new work; a
// phantom entry would answer the retry as a duplicate and never advance the
// sequence, so the next submission fails with a gap.
func TestIngressQueueFullAdmissionIsRetriable(t *testing.T) {
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	started := make(chan struct{})
	var once sync.Once
	sink := OutputSinkFunc(func(ctx context.Context, event audit.Event) (audit.Record, error) {
		once.Do(func() { close(started) })
		select {
		case <-release:
		case <-ctx.Done():
		}
		return audit.Record{Event: event}, nil
	})
	ingress, err := NewIngress(IngressOptions{
		Keys:     map[string]TrustKey{"host-v1": {ID: "host-v1", PublicKey: private.Public().(ed25519.PublicKey)}},
		PluginID: "jev", PluginVersion: "1.2.3", TenantRef: "tenant:demo", SiteRef: "site:demo", PolicyEpoch: 7,
		StreamID: "extensions", MaxTTL: 10 * time.Minute, Now: func() time.Time { return now }, QueueCapacity: 1, Sink: sink,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ingress.Close()
	if _, err := ingress.Submit(context.Background(), signedIngressOutput(t, private, now, "evt-1", 1, `{}`)); err != nil {
		t.Fatalf("submit 1: %v", err)
	}
	<-started // the worker holds the first append; the queue is now empty
	if _, err := ingress.Submit(context.Background(), signedIngressOutput(t, private, now, "evt-2", 2, `{}`)); err != nil {
		t.Fatalf("submit 2: %v", err)
	}
	third := signedIngressOutput(t, private, now, "evt-3", 3, `{}`)
	if _, err := ingress.Submit(context.Background(), third); !errors.Is(err, ErrIngressQueueFull) {
		t.Fatalf("third submit error = %v, want queue full", err)
	}
	close(release)
	if err := ingress.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	receipt, err := ingress.Submit(context.Background(), third)
	if err != nil {
		t.Fatalf("retry after queue full: %v", err)
	}
	if receipt.Duplicate {
		t.Fatal("rejected admission was treated as an accepted duplicate")
	}
	if _, err := ingress.Submit(context.Background(), signedIngressOutput(t, private, now, "evt-4", 4, `{}`)); err != nil {
		t.Fatalf("sequence gap after retry: %v", err)
	}
}

// Close must drain the queue before cancelling; a cancellation-aware sink would
// otherwise reject outputs the caller already handed over.
func TestIngressCloseDrainsQueuedOutputs(t *testing.T) {
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var saved int
	sink := OutputSinkFunc(func(ctx context.Context, event audit.Event) (audit.Record, error) {
		if err := ctx.Err(); err != nil {
			return audit.Record{}, err
		}
		mu.Lock()
		saved++
		mu.Unlock()
		return audit.Record{Event: event}, nil
	})
	ingress, err := NewIngress(IngressOptions{
		Keys:     map[string]TrustKey{"host-v1": {ID: "host-v1", PublicKey: private.Public().(ed25519.PublicKey)}},
		PluginID: "jev", PluginVersion: "1.2.3", TenantRef: "tenant:demo", SiteRef: "site:demo", PolicyEpoch: 7,
		StreamID: "extensions", MaxTTL: 10 * time.Minute, Now: func() time.Time { return now }, QueueCapacity: 8, Sink: sink,
	})
	if err != nil {
		t.Fatal(err)
	}
	for seq := uint64(1); seq <= 4; seq++ {
		if _, err := ingress.Submit(context.Background(), signedIngressOutput(t, private, now, "evt-"+strconv.FormatUint(seq, 10), seq, `{}`)); err != nil {
			t.Fatal(err)
		}
	}
	if err := ingress.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if saved != 4 {
		t.Fatalf("saved %d outputs, want 4", saved)
	}
}

// Failed entries are retained for retry; new sequences must stop at the cap so
// retained state cannot grow without bound.
func TestIngressRejectsNewWorkWhenRetainedStateIsFull(t *testing.T) {
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sink := OutputSinkFunc(func(context.Context, audit.Event) (audit.Record, error) {
		return audit.Record{}, errors.New("audit down")
	})
	ingress, err := NewIngress(IngressOptions{
		Keys:     map[string]TrustKey{"host-v1": {ID: "host-v1", PublicKey: private.Public().(ed25519.PublicKey)}},
		PluginID: "jev", PluginVersion: "1.2.3", TenantRef: "tenant:demo", SiteRef: "site:demo", PolicyEpoch: 7,
		StreamID: "extensions", MaxTTL: 10 * time.Minute, Now: func() time.Time { return now }, QueueCapacity: 8, Sink: sink,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ingress.Close()
	var seq uint64 = 1
	for ; seq <= uint64(ingress.seenCap); seq++ {
		wire := signedIngressOutput(t, private, now, "evt-"+strconv.FormatUint(seq, 10), seq, `{}`)
		for attempt := 0; ; attempt++ {
			if _, err := ingress.Submit(context.Background(), wire); err == nil {
				break
			} else if !errors.Is(err, ErrIngressQueueFull) || attempt >= 200 {
				t.Fatalf("submit %d: %v", seq, err)
			}
			time.Sleep(time.Millisecond)
		}
	}
	if err := ingress.Flush(context.Background()); err == nil {
		t.Fatal("flush hid the failing appends")
	}
	fresh := signedIngressOutput(t, private, now, "evt-new", seq, `{}`)
	if _, err := ingress.Submit(context.Background(), fresh); !errors.Is(err, ErrIngressBacklogFull) {
		t.Fatalf("new entry at cap error = %v, want backlog full", err)
	}
}

// Close must report queued outputs that could not be saved.
func TestIngressCloseReportsFailedAppends(t *testing.T) {
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ingress, err := NewIngress(IngressOptions{
		Keys:     map[string]TrustKey{"host-v1": {ID: "host-v1", PublicKey: private.Public().(ed25519.PublicKey)}},
		PluginID: "jev", PluginVersion: "1.2.3", TenantRef: "tenant:demo", SiteRef: "site:demo", PolicyEpoch: 7,
		StreamID: "extensions", MaxTTL: 10 * time.Minute, Now: func() time.Time { return now },
		Sink: OutputSinkFunc(func(context.Context, audit.Event) (audit.Record, error) {
			return audit.Record{}, errors.New("audit down")
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ingress.Submit(context.Background(), signedIngressOutput(t, private, now, "evt-1", 1, `{}`)); err != nil {
		t.Fatal(err)
	}
	if err := ingress.Close(); err == nil {
		t.Fatal("close hid a failed queued output")
	}
}

func TestIngressBacklogFullMapsToTooManyRequests(t *testing.T) {
	recorder := httptest.NewRecorder()
	writeOutputTransportSubmitError(recorder, ErrIngressBacklogFull)
	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", recorder.Code)
	}
}

// Sequence validation happens before eviction, so a rejected submission must
// not remove a saved receipt.
func TestIngressRejectsGapWithoutEvictingSavedReceipt(t *testing.T) {
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ingress, err := NewIngress(IngressOptions{
		Keys:     map[string]TrustKey{"host-v1": {ID: "host-v1", PublicKey: private.Public().(ed25519.PublicKey)}},
		PluginID: "jev", PluginVersion: "1.2.3", TenantRef: "tenant:demo", SiteRef: "site:demo", PolicyEpoch: 7,
		StreamID: "extensions", MaxTTL: 10 * time.Minute, Now: func() time.Time { return now },
		Sink: OutputSinkFunc(func(_ context.Context, e audit.Event) (audit.Record, error) { return audit.Record{Event: e}, nil }),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ingress.Close()
	ingress.mu.Lock()
	ingress.seenCap = 1
	ingress.seen["saved"] = ingressEntry{digest: "d", at: now}
	ingress.hasSeq, ingress.lastSeq = true, 5
	ingress.mu.Unlock()
	wire := signedIngressOutput(t, private, now, "evt-gap", 7, `{}`)
	if _, err := ingress.Submit(context.Background(), wire); !errors.Is(err, ErrIngressSequenceGap) {
		t.Fatalf("gap error = %v", err)
	}
	ingress.mu.Lock()
	defer ingress.mu.Unlock()
	if _, ok := ingress.seen["saved"]; !ok {
		t.Fatal("rejected submission evicted a saved receipt")
	}
}

// An evicted success must come back when the queue refuses the new entry.
func TestIngressRestoresEvictedReceiptWhenQueueRejects(t *testing.T) {
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	started := make(chan struct{})
	var once sync.Once
	ingress, err := NewIngress(IngressOptions{
		Keys:     map[string]TrustKey{"host-v1": {ID: "host-v1", PublicKey: private.Public().(ed25519.PublicKey)}},
		PluginID: "jev", PluginVersion: "1.2.3", TenantRef: "tenant:demo", SiteRef: "site:demo", PolicyEpoch: 7,
		StreamID: "extensions", MaxTTL: 10 * time.Minute, Now: func() time.Time { return now }, QueueCapacity: 1,
		Sink: OutputSinkFunc(func(ctx context.Context, e audit.Event) (audit.Record, error) {
			once.Do(func() { close(started) })
			select {
			case <-release:
			case <-ctx.Done():
			}
			return audit.Record{Event: e}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ingress.Submit(context.Background(), signedIngressOutput(t, private, now, "evt-1", 1, `{}`)); err != nil {
		t.Fatal(err)
	}
	<-started
	ingress.mu.Lock()
	ingress.seenCap = 2
	ingress.seen["saved"] = ingressEntry{digest: "d", at: now}
	ingress.mu.Unlock()
	ingress.queue <- queuedOutput{key: "dummy"}
	wire := signedIngressOutput(t, private, now, "evt-2", 2, `{}`)
	if _, err := ingress.Submit(context.Background(), wire); !errors.Is(err, ErrIngressQueueFull) {
		t.Fatalf("submit error = %v, want queue full", err)
	}
	ingress.mu.Lock()
	_, saved := ingress.seen["saved"]
	ingress.mu.Unlock()
	if !saved {
		t.Fatal("queue rejection did not restore the evicted receipt")
	}
	close(release)
	if err := ingress.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	_ = ingress.Close()
}
