package proxy

import (
	"testing"
	"time"
)

func TestPromoteTableArmsAndExpires(t *testing.T) {
	table := newPromoteTable()
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	table.Arm("site-a", 10, now)
	if !table.Active("site-a", now.Add(9*time.Second)) {
		t.Fatal("expected active inside window")
	}
	if table.Active("site-a", now.Add(10*time.Second)) {
		t.Fatal("expected expired at deadline")
	}
	if table.Active("site-b", now) {
		t.Fatal("other site must stay inactive")
	}
}

func TestPromoteTableKeepsLaterDeadline(t *testing.T) {
	table := newPromoteTable()
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	table.Arm("site-a", 30, now)
	table.Arm("site-a", 5, now.Add(time.Second))
	if !table.Active("site-a", now.Add(20*time.Second)) {
		t.Fatal("shorter later arm must not cut an existing longer window")
	}
}
