package netguard

import (
	"bytes"
	"io"
	"testing"
)

type trackedResponseBody struct {
	*bytes.Reader
	closed bool
}

func (b *trackedResponseBody) Close() error {
	b.closed = true
	return nil
}

func TestDrainAndCloseConsumesBodyAndClosesIt(t *testing.T) {
	body := &trackedResponseBody{Reader: bytes.NewReader(bytes.Repeat([]byte("x"), 32<<10))}
	if err := DrainAndClose(body); err != nil {
		t.Fatal(err)
	}
	if !body.closed {
		t.Fatal("response body was not closed")
	}
	if remaining, err := io.ReadAll(body); err != nil || len(remaining) != 0 {
		t.Fatalf("response body was not drained: remaining=%d err=%v", len(remaining), err)
	}
}

func TestDrainAndCloseBoundsLargeBodies(t *testing.T) {
	total := 2 * maxResponseDrainBytes
	body := &trackedResponseBody{Reader: bytes.NewReader(bytes.Repeat([]byte("x"), total))}
	if err := DrainAndClose(body); err != nil {
		t.Fatal(err)
	}
	if !body.closed {
		t.Fatal("response body was not closed")
	}
	remaining, err := io.ReadAll(body)
	if err != nil {
		t.Fatal(err)
	}
	wantRemaining := total - (maxResponseDrainBytes + 1)
	if len(remaining) != wantRemaining {
		t.Fatalf("remaining bytes = %d, want %d after bounded drain", len(remaining), wantRemaining)
	}
}

func TestDrainAndCloseAllowsNilBody(t *testing.T) {
	if err := DrainAndClose(nil); err != nil {
		t.Fatal(err)
	}
}
