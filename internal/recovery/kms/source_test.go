package kms

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

func TestPasswordKeySourceRoundTripsWithoutStoringPassword(t *testing.T) {
	password := []byte("correct horse battery staple")
	source, sealed, err := NewPasswordKeySource(context.Background(), func(context.Context) ([]byte, error) { return append([]byte(nil), password...), nil })
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, password) {
		t.Fatal("password persisted in key source")
	}
	root, err := source.Load(context.Background())
	if err != nil || len(root) != 32 {
		t.Fatalf("load=%d err=%v", len(root), err)
	}
	opened, err := OpenPasswordKeySource(sealed, func(context.Context) ([]byte, error) { return append([]byte(nil), password...), nil })
	if err != nil {
		t.Fatal(err)
	}
	root2, err := opened.Load(context.Background())
	if err != nil || !bytes.Equal(root, root2) {
		t.Fatalf("reopen err=%v", err)
	}
	for i := range root {
		root[i] = 0
	}
	for i := range root2 {
		root2[i] = 0
	}
	wrong, _ := OpenPasswordKeySource(sealed, func(context.Context) ([]byte, error) { return []byte("wrong password"), nil })
	if _, err := wrong.Load(context.Background()); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("wrong password=%v", err)
	}
}

func TestOSKeySourceAndPreferredSelectionFailClosed(t *testing.T) {
	adapter := fakeOSSource{key: bytes.Repeat([]byte{0x41}, 32)}
	osSource, err := NewOSKeySource(OSKeychain, adapter)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := osSource.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got, err := SelectRootKeySource(context.Background(), osSource, nil, FallbackPolicy{Approved: true, Mode: SingleNode}); err != nil || got != osSource {
		t.Fatalf("preferred source=%v err=%v", got, err)
	}
	unsupported, err := NewOSKeySource(OSKeychain, fakeOSSource{unsupported: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SelectRootKeySource(context.Background(), unsupported, nil, FallbackPolicy{}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unsupported source=%v", err)
	}
	if _, err := NewOSKeySource("unknown", adapter); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unknown source=%v", err)
	}
}

type fakeOSSource struct {
	key         []byte
	unsupported bool
}

func (s fakeOSSource) Available(context.Context) bool { return !s.unsupported && len(s.key) == 32 }
func (s fakeOSSource) Load(context.Context) ([]byte, error) {
	if s.unsupported {
		return nil, ErrUnsupported
	}
	return append([]byte(nil), s.key...), nil
}
