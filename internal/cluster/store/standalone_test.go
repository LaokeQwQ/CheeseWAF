package store

import (
	"context"
	"errors"
	"testing"
)

func TestStandaloneStoreRoundTripCopiesValues(t *testing.T) {
	ctx := context.Background()
	s := NewStandaloneStore()
	key := Key{Kind: "Node", ID: "waf-a"}
	value := []byte(`{"id":"waf-a"}`)
	if err := s.Put(ctx, key, value); err != nil {
		t.Fatal(err)
	}
	value[0] = 'X'
	got, err := s.Get(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"id":"waf-a"}` {
		t.Fatalf("stored value was mutated: %s", got)
	}
	got[0] = 'Y'
	gotAgain, err := s.Get(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotAgain) != `{"id":"waf-a"}` {
		t.Fatalf("returned value was not copied: %s", gotAgain)
	}
}

func TestStandaloneStoreStatus(t *testing.T) {
	ctx := context.Background()
	s := NewStandaloneStore()
	if err := s.Put(ctx, Key{Kind: "Node", ID: "waf-a"}, []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	status, err := s.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if status.Provider != "standalone" || !status.MajorityConfirmed || status.ObjectCount != 1 {
		t.Fatalf("unexpected status: %+v", status)
	}
	if _, err := s.Get(ctx, Key{Kind: "Node", ID: "missing"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing object error=%v, want ErrNotFound", err)
	}
}
