package hostapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func receiptFrame(sequence uint64) Frame {
	return Frame{
		Type: FrameHintReceipt, SchemaVersion: ProtocolVersion, Sequence: sequence,
		Payload: json.RawMessage(`{"accepted":true}`),
	}
}

func rejectedReceiptFrame(sequence uint64) Frame {
	return Frame{
		Type: FrameHintReceipt, SchemaVersion: ProtocolVersion, Sequence: sequence,
		Payload: json.RawMessage(`{"accepted":false,"error_code":"plugin_error"}`),
	}
}

// The sidecars must drain Receipts for the life of the session. Without a
// reader the 64-slot buffer fills, publishReceipt reports ErrResultBacklog and
// the client tears the connection down — at receipt 65, while the lifecycle
// process is still alive.
func TestReceiptBacklogDisconnectsWithoutDrain(t *testing.T) {
	client := &Client{receipts: make(chan Receipt, 64)}
	for i := uint64(1); i <= 64; i++ {
		if err := client.publishReceipt(ResultHint, receiptFrame(i)); err != nil {
			t.Fatalf("receipt %d before capacity: %v", i, err)
		}
	}
	if err := client.publishReceipt(ResultHint, receiptFrame(65)); !errors.Is(err, ErrResultBacklog) {
		t.Fatalf("65th receipt error = %v, want ErrResultBacklog", err)
	}
}

// With a drainer attached the same sequence must not block. Retrying on
// ErrResultBacklog is the contract: a drained channel always makes room, an
// undrained one never does.
func TestDrainReceiptsKeepsBacklogClearAndReportsRejections(t *testing.T) {
	client := &Client{receipts: make(chan Receipt, 64)}
	var log bytes.Buffer
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		drainReceipts(client.receipts, "test data plane", &log)
	}()

	push := func(frame Frame) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for {
			err := client.publishReceipt(ResultHint, frame)
			if err == nil {
				return
			}
			if !errors.Is(err, ErrResultBacklog) {
				t.Fatalf("receipt %d: %v", frame.Sequence, err)
			}
			if time.Now().After(deadline) {
				t.Fatalf("receipt %d never drained", frame.Sequence)
			}
			time.Sleep(time.Millisecond)
		}
	}

	for i := uint64(1); i <= 200; i++ {
		push(receiptFrame(i))
	}
	push(rejectedReceiptFrame(201))
	close(client.receipts)
	<-drained

	if !strings.Contains(log.String(), "host rejected hint receipt 201: plugin_error") {
		t.Fatalf("rejected receipt was not reported: %q", log.String())
	}
}
