package tamper

import (
	"testing"
	"time"
)

func TestCompareDetectsDrift(t *testing.T) {
	snapshot := Capture("https://example.test/", []byte("clean"), time.Now())
	drift := Compare(snapshot, []byte("changed"))
	if !drift.Changed || drift.Expected == drift.Actual {
		t.Fatalf("expected drift, got %+v", drift)
	}
}
