package deploy

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestAuthorizationSingleUseBoundAndAtomic(t *testing.T) {
	s := NewAuthorizationStore(AuthorizationStoreOptions{NewToken: func() (string, error) { return "token", nil }})
	target := AuthorizationTarget{" Node.EXAMPLE.com ", " root ", 0, "sha256:abc"}
	a, e := s.Issue("task", target)
	if e != nil || a.Handle != "token" {
		t.Fatal(a, e)
	}
	var n atomic.Int32
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if s.Consume("token", AuthorizationTarget{"node.example.com", "root", 22, "SHA256:abc"}) == nil {
				n.Add(1)
			}
		}()
	}
	wg.Wait()
	if n.Load() != 1 {
		t.Fatalf("consumes=%d", n.Load())
	}
}
func TestAuthorizationRejectsChangeAndExpiry(t *testing.T) {
	now := time.Unix(1, 0)
	s := NewAuthorizationStore(AuthorizationStoreOptions{TTL: time.Minute, Now: func() time.Time { return now }, NewToken: func() (string, error) { return "token", nil }})
	target := AuthorizationTarget{"node", "root", 22, "SHA256:abc"}
	s.Issue("task", target)
	if s.Consume("token", AuthorizationTarget{"other", "root", 22, "SHA256:abc"}) == nil {
		t.Fatal("changed target accepted")
	}
	now = now.Add(time.Minute)
	if s.Consume("token", target) == nil {
		t.Fatal("expired accepted")
	}
}

func TestAuthorizationGetByTaskStopsAfterConsumption(t *testing.T) {
	s := NewAuthorizationStore(AuthorizationStoreOptions{NewToken: func() (string, error) { return "token", nil }})
	target := AuthorizationTarget{"node", "root", 22, "SHA256:abc"}
	if _, err := s.Issue("task", target); err != nil {
		t.Fatal(err)
	}
	if auth, ok := s.GetByTask("task"); !ok || auth.Handle != "token" {
		t.Fatalf("task authorization missing: %+v %v", auth, ok)
	}
	if err := s.Consume("token", target); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.GetByTask("task"); ok {
		t.Fatal("consumed task authorization remained visible")
	}
}
