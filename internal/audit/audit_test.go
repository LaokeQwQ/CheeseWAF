package audit

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func testEvent(id string, class EventClass) Event {
	return Event{
		EventID: id, StreamID: "control", TenantID: "tenant-a", Actor: "admin",
		Type: EventTypeConfigChanged, Action: "config.write", Resource: "site:example",
		Outcome: OutcomeSuccess, CorrelationID: "corr-" + id, SessionID: "session-1",
		PolicyEpoch: 7, Class: class, At: time.Unix(1700000000, 0).UTC(),
	}
}

func TestMemoryJournalEnforcesAppendOnlyHashChainAndIdempotentReplay(t *testing.T) {
	j := NewMemoryJournalWithDurability(true)
	rt, err := NewRuntime(RuntimeOptions{Journal: j, StreamID: "control", CheckpointEvery: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	for i := 0; i < 3; i++ {
		if _, err := rt.Append(context.Background(), testEvent(fmt.Sprintf("e-%d", i), EventClassCritical)); err != nil {
			t.Fatal(err)
		}
	}
	if err := rt.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	rows, err := j.Records(context.Background(), "control", 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 || rows[0].Sequence != 1 || rows[2].Sequence != 3 {
		t.Fatalf("rows=%+v", rows)
	}
	if rows[1].PreviousHash != rows[0].Hash || rows[2].PreviousHash != rows[1].Hash {
		t.Fatal("hash chain is not linked")
	}
	bad := rows[1]
	bad.Event.Action = "config.other"
	bad.Hash = hashRecord(bad)
	if err := j.Append(context.Background(), Commit{Record: bad}); !errors.Is(err, ErrReplayConflict) {
		t.Fatalf("replay conflict=%v", err)
	}
	if err := j.Append(context.Background(), Commit{Record: rows[2]}); err != nil {
		t.Fatalf("same commit should be idempotent: %v", err)
	}
}

func TestCheckpointSignatureVerificationAndCorruptionDetection(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer := Ed25519Signer{ID: "audit-key-1", PrivateKey: priv}
	j := NewMemoryJournalWithDurability(true)
	rt, err := NewRuntime(RuntimeOptions{Journal: j, StreamID: "control", Signer: signer, CheckpointEvery: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	if _, err := rt.Append(context.Background(), testEvent("checkpoint", EventClassCritical)); err != nil {
		t.Fatal(err)
	}
	rows, err := j.Records(context.Background(), "control", 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatal(rows)
	}
	cp, err := j.Checkpoint(context.Background(), "control", 1)
	if err != nil || cp == nil {
		t.Fatalf("checkpoint=%+v err=%v", cp, err)
	}
	if err := VerifyCheckpoint("control", rows[0], *cp, map[string]ed25519.PublicKey{"audit-key-1": pub}); err != nil {
		t.Fatal(err)
	}
	if err := VerifyCheckpoint("control", rows[0], Checkpoint{Sequence: cp.Sequence, Hash: strings.Repeat("a", 64), KeyID: cp.KeyID, Signature: cp.Signature, At: cp.At}, map[string]ed25519.PublicKey{"audit-key-1": pub}); !errors.Is(err, ErrCheckpointInvalid) {
		t.Fatalf("tampered checkpoint err=%v", err)
	}
	if err := corruptJournalForTest(j, "control", 0, func(r *Record) { r.Event.Action = "tampered" }); err != nil {
		t.Fatal(err)
	}
	if _, err := j.Records(context.Background(), "control", 0, 10); !errors.Is(err, ErrCorruptChain) {
		t.Fatalf("corruption err=%v", err)
	}
}

func TestRuntimeCriticalSynchronousNormalAsyncAndBoundedQueue(t *testing.T) {
	j := NewMemoryJournalWithDurability(true)
	rt, err := NewRuntime(RuntimeOptions{Journal: j, StreamID: "control", QueueCapacity: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	if _, err := rt.Append(context.Background(), testEvent("critical", EventClassCritical)); err != nil {
		t.Fatal(err)
	}
	if _, err := rt.Append(context.Background(), testEvent("normal-1", EventClassNormal)); err != nil {
		t.Fatal(err)
	}
	if _, err := rt.Append(context.Background(), testEvent("normal-2", EventClassNormal)); err != nil && !errors.Is(err, ErrQueueFull) {
		t.Fatal(err)
	}
	if err := rt.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	rows, err := j.Records(context.Background(), "control", 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) < 2 || rows[0].Event.EventID != "critical" {
		t.Fatalf("rows=%+v", rows)
	}
}

func TestRuntimeRejectsCriticalWithoutDurableChannel(t *testing.T) {
	j := NewMemoryJournal()
	rt, err := NewRuntime(RuntimeOptions{Journal: j, StreamID: "control"})
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	if _, err := rt.Append(context.Background(), testEvent("must-persist", EventClassCritical)); !errors.Is(err, ErrNoDurableChannel) {
		t.Fatalf("err=%v", err)
	}
}

func TestEncryptedSpoolDoesNotContainPlaintextAndReplayIsIdempotent(t *testing.T) {
	key := []byte(strings.Repeat("k", 32))
	spool, err := NewMemoryEncryptedSpool(key, true)
	if err != nil {
		t.Fatal(err)
	}
	j := NewMemoryJournalWithDurability(false)
	rt, err := NewRuntime(RuntimeOptions{Journal: j, Spool: spool, StreamID: "control"})
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	e := testEvent("spooled", EventClassNormal)
	if _, err := rt.Append(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	if err := rt.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	sealed, err := spool.Entries(context.Background(), "control")
	if err != nil || len(sealed) != 1 {
		t.Fatalf("entries=%d err=%v", len(sealed), err)
	}
	raw, _ := json.Marshal(sealed[0])
	if strings.Contains(string(raw), "config.write") || strings.Contains(string(raw), "example") {
		t.Fatalf("spool leaked event data: %s", raw)
	}
	if err := rt.Replay(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := rt.Replay(context.Background()); err != nil {
		t.Fatal(err)
	}
	rows, err := j.Records(context.Background(), "control", 0, 10)
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows=%d err=%v", len(rows), err)
	}
	if err := corruptSpoolForTest(spool, 0); err != nil {
		t.Fatal(err)
	}
	if err := rt.Replay(context.Background()); !errors.Is(err, ErrSpoolCorrupt) {
		t.Fatalf("corrupt replay err=%v", err)
	}
}

func corruptJournalForTest(j *MemoryJournal, stream string, index int, mutate func(*Record)) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	state := j.streams[stream]
	if state == nil || index < 0 || index >= len(state.commits) || mutate == nil {
		return ErrInvalidRecord
	}
	mutate(&state.commits[index].Record)
	return nil
}
func corruptSpoolForTest(s *MemoryEncryptedSpool, index int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if index < 0 || index >= len(s.items) || len(s.items[index].Ciphertext) == 0 {
		return ErrSpoolCorrupt
	}
	s.items[index].Ciphertext[0] ^= 0xff
	return nil
}

func TestConcurrentCriticalAppendsRemainMonotonic(t *testing.T) {
	j := NewMemoryJournalWithDurability(true)
	rt, err := NewRuntime(RuntimeOptions{Journal: j, StreamID: "control"})
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	const n = 64
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := rt.Append(context.Background(), testEvent(fmt.Sprintf("concurrent-%d", i), EventClassCritical))
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	rows, err := j.Records(context.Background(), "control", 0, n+1)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != n {
		t.Fatalf("got %d rows", len(rows))
	}
	for i, row := range rows {
		if row.Sequence != uint64(i+1) {
			t.Fatalf("row %d sequence=%d", i, row.Sequence)
		}
	}
}

func TestOutboxMemoryAdaptersAreMetadataOnlyAndIdempotent(t *testing.T) {
	a := NewMemoryOutboxAdapter(OutboxTargetSIEM, true)
	d := Delivery{DeliveryID: "d-1", Target: OutboxTargetSIEM, StreamID: "control", Sequence: 1, EventID: "e-1", RecordHash: strings.Repeat("a", 64)}
	if err := a.Deliver(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	if err := a.Deliver(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	if got := len(a.Deliveries()); got != 1 {
		t.Fatalf("deliveries=%d", got)
	}
	if err := a.Deliver(context.Background(), Delivery{DeliveryID: "d-1", Target: OutboxTargetSIEM, StreamID: "control", Sequence: 1, EventID: "e-1", RecordHash: strings.Repeat("b", 64)}); !errors.Is(err, ErrOutboxConflict) {
		t.Fatalf("conflict=%v", err)
	}
	encoded, _ := json.Marshal(a.Deliveries())
	if strings.Contains(string(encoded), "payload") || strings.Contains(string(encoded), "secret") {
		t.Fatalf("metadata adapter contains forbidden field: %s", encoded)
	}
}
