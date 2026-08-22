package deploy

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestAuthorizationSingleUseBoundAndAtomic(t *testing.T) {
	s := NewAuthorizationStore(AuthorizationStoreOptions{NewToken: func() (string, error) { return "token", nil }})
	target := AuthorizationTarget{Host: " Node.EXAMPLE.com ", User: " root ", Port: 0, HostKeySHA256: "sha256:abc"}
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
			if s.Consume("token", AuthorizationTarget{Host: "node.example.com", User: "root", Port: 22, HostKeySHA256: "SHA256:abc"}) == nil {
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
	target := AuthorizationTarget{Host: "node", User: "root", Port: 22, HostKeySHA256: "SHA256:abc"}
	s.Issue("task", target)
	if s.Consume("token", AuthorizationTarget{Host: "other", User: "root", Port: 22, HostKeySHA256: "SHA256:abc"}) == nil {
		t.Fatal("changed target accepted")
	}
	now = now.Add(time.Minute)
	if s.Consume("token", target) == nil {
		t.Fatal("expired accepted")
	}
}

func TestAuthorizationGetByTaskStopsAfterConsumption(t *testing.T) {
	s := NewAuthorizationStore(AuthorizationStoreOptions{NewToken: func() (string, error) { return "token", nil }})
	target := AuthorizationTarget{Host: "node", User: "root", Port: 22, HostKeySHA256: "SHA256:abc"}
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

func TestAuthorizationBindsActionAndBinaryFingerprint(t *testing.T) {
	s := NewAuthorizationStore(AuthorizationStoreOptions{NewToken: func() (string, error) { return "token", nil }})
	issued := AuthorizationTarget{Host: "node", User: "root", Port: 22, HostKeySHA256: "SHA256:abc", Action: "install", BinarySHA256: "sha256:deadbeef"}
	if _, err := s.Issue("task", issued); err != nil {
		t.Fatal(err)
	}
	if err := s.Consume("token", AuthorizationTarget{Host: "node", User: "root", Port: 22, HostKeySHA256: "SHA256:abc", Action: "install", BinarySHA256: "sha256:deadbeef"}); err != nil {
		t.Fatalf("matching fingerprint rejected: %v", err)
	}
}

func TestAuthorizationRejectsActionChange(t *testing.T) {
	s := NewAuthorizationStore(AuthorizationStoreOptions{NewToken: func() (string, error) { return "token", nil }})
	issued := AuthorizationTarget{Host: "node", User: "root", Port: 22, HostKeySHA256: "SHA256:abc", Action: "install"}
	if _, err := s.Issue("task", issued); err != nil {
		t.Fatal(err)
	}
	if err := s.Consume("token", AuthorizationTarget{Host: "node", User: "root", Port: 22, HostKeySHA256: "SHA256:abc", Action: "rollback"}); err == nil {
		t.Fatal("changed action accepted")
	}
}

func TestAuthorizationEmptyActionStaysUsableForDeploy(t *testing.T) {
	s := NewAuthorizationStore(AuthorizationStoreOptions{NewToken: func() (string, error) { return "token", nil }})
	issued := AuthorizationTarget{Host: "node", User: "root", Port: 22, HostKeySHA256: "SHA256:abc"}
	if _, err := s.Issue("task", issued); err != nil {
		t.Fatal(err)
	}
	if err := s.Consume("token", AuthorizationTarget{Host: "node", User: "root", Port: 22, HostKeySHA256: "SHA256:abc", Action: "install"}); err != nil {
		t.Fatalf("unbound action should still allow deploy: %v", err)
	}
	if err := s.Consume("token", AuthorizationTarget{Host: "node", User: "root", Port: 22, HostKeySHA256: "SHA256:abc", Action: "install"}); err == nil {
		t.Fatal("single-use token must not be reused")
	}
}
