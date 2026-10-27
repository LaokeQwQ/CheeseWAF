package audit

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fileJournalCommit(sequence uint64, previous string, event Event, deliveries []Delivery) Commit {
	record := Record{Sequence: sequence, Event: event, PreviousHash: previous}
	record.Hash = hashRecord(record)
	for i := range deliveries {
		deliveries[i].StreamID = event.StreamID
		deliveries[i].Sequence = sequence
		deliveries[i].EventID = event.EventID
		deliveries[i].RecordHash = record.Hash
	}
	return Commit{Record: record, Outbox: deliveries}
}

func TestFileJournalPersistsSignedChainAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	journal, err := OpenFileJournal(filepath.Join(dir, "audit"))
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := NewRuntime(RuntimeOptions{Journal: journal, StreamID: "control", Signer: testSigner(), CheckpointEvery: 1})
	if err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		if _, err := runtime.Append(context.Background(), testEvent("e-"+string(rune('a'+i)), EventClassCritical)); err != nil {
			t.Fatal(err)
		}
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenFileJournal(filepath.Join(dir, "audit"))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if !reopened.Durable() {
		t.Fatal("file journal must report durable")
	}
	rows, err := reopened.Records(context.Background(), "control", 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 || rows[0].Sequence != 1 || rows[2].Sequence != 3 {
		t.Fatalf("rows=%+v", rows)
	}
	if rows[1].PreviousHash != rows[0].Hash || rows[2].PreviousHash != rows[1].Hash {
		t.Fatal("hash chain is not linked across reopen")
	}
	if err := reopened.Verify(context.Background(), "control"); err != nil {
		t.Fatalf("verify: %v", err)
	}
	checkpoint, err := reopened.Checkpoint(context.Background(), "control", 3)
	if err != nil || checkpoint == nil || len(checkpoint.Signature) == 0 {
		t.Fatalf("checkpoint=%+v err=%v", checkpoint, err)
	}
}

func TestFileJournalRejectsSequenceAndReplayConflicts(t *testing.T) {
	journal, err := OpenFileJournal(filepath.Join(t.TempDir(), "audit"))
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	event := testEvent("e-1", EventClassCritical)
	first := fileJournalCommit(1, "", event, nil)
	if err := journal.Append(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if err := journal.Append(context.Background(), first); err != nil {
		t.Fatalf("identical replay must be idempotent: %v", err)
	}

	gap := fileJournalCommit(3, first.Record.Hash, testEvent("e-3", EventClassCritical), nil)
	if err := journal.Append(context.Background(), gap); !errors.Is(err, ErrSequenceConflict) {
		t.Fatalf("gap append err=%v, want ErrSequenceConflict", err)
	}

	conflict := fileJournalCommit(1, "", testEvent("e-2", EventClassCritical), nil)
	if err := journal.Append(context.Background(), conflict); !errors.Is(err, ErrReplayConflict) {
		t.Fatalf("conflict append err=%v, want ErrReplayConflict", err)
	}

	brokenLink := fileJournalCommit(2, strings.Repeat("a", 64), testEvent("e-4", EventClassCritical), nil)
	if err := journal.Append(context.Background(), brokenLink); !errors.Is(err, ErrSequenceConflict) {
		t.Fatalf("broken link err=%v, want ErrSequenceConflict", err)
	}
}

func TestFileJournalDetectsCorruptStreamAndKeepsOutboxAcks(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "audit")
	journal, err := OpenFileJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	event := testEvent("e-outbox", EventClassCritical)
	commit := fileJournalCommit(1, "", event, []Delivery{{
		DeliveryID: "delivery-1",
		Target:     OutboxTargetSIEM,
		CreatedAt:  time.Unix(1700000000, 0).UTC(),
	}})
	if err := journal.Append(context.Background(), commit); err != nil {
		t.Fatal(err)
	}
	pending, err := journal.PendingOutbox(context.Background(), "control", 10)
	if err != nil || len(pending) != 1 {
		t.Fatalf("pending=%+v err=%v", pending, err)
	}
	if err := journal.AckOutbox(context.Background(), pending[0]); err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenFileJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if pending, err := reopened.PendingOutbox(context.Background(), "control", 10); err != nil || len(pending) != 0 {
		t.Fatalf("pending after ack reload=%+v err=%v", pending, err)
	}

	streamPath := filepath.Join(dir, "control.jsonl")
	raw, err := os.ReadFile(streamPath)
	if err != nil {
		t.Fatal(err)
	}
	raw[10] ^= 0xff
	if err := os.WriteFile(streamPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	corrupt, err := OpenFileJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer corrupt.Close()
	if _, err := corrupt.Records(context.Background(), "control", 0, 10); !errors.Is(err, ErrCorruptChain) {
		t.Fatalf("corrupt stream err=%v, want ErrCorruptChain", err)
	}
}

func TestOpenFileJournalRequiresAbsoluteDirectory(t *testing.T) {
	if _, err := OpenFileJournal("relative/audit"); err == nil {
		t.Fatal("relative journal directory must be rejected")
	}
}
