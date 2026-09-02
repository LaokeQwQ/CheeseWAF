package deploy

import (
	"reflect"
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

func TestBoundAuthorizationReturnsNormalizedResolvedAddressesOnce(t *testing.T) {
	s := NewAuthorizationStore(AuthorizationStoreOptions{NewToken: func() (string, error) { return "bound-token", nil }})
	target := AuthorizationTarget{
		Host:          " Node.EXAMPLE.com. ",
		User:          " root ",
		Port:          22,
		HostKeySHA256: "sha256:abc",
		ResolvedIPs:   []string{"2001:4860:4860::8888", "8.8.8.8", "8.8.8.8"},
	}
	if _, err := s.IssueBound("check-task", target); err != nil {
		t.Fatal(err)
	}

	consumed, err := s.ConsumeBound("bound-token", AuthorizationTarget{
		Host:          "node.example.com.",
		User:          "root",
		Port:          22,
		HostKeySHA256: "SHA256:abc",
		Action:        "install",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"8.8.8.8", "2001:4860:4860::8888"}
	if !reflect.DeepEqual(consumed.ResolvedIPs, want) {
		t.Fatalf("bound addresses = %v, want %v", consumed.ResolvedIPs, want)
	}
	consumed.ResolvedIPs[0] = "1.1.1.1"
	if _, err := s.ConsumeBound("bound-token", AuthorizationTarget{Host: "node.example.com.", User: "root", Port: 22, HostKeySHA256: "SHA256:abc"}); err == nil {
		t.Fatal("bound authorization replay was accepted")
	}
}

func TestBoundAuthorizationRejectsMissingWrongTargetAndUnboundRecord(t *testing.T) {
	target := AuthorizationTarget{Host: "node.example.com", User: "root", Port: 22, HostKeySHA256: "SHA256:abc", ResolvedIPs: []string{"8.8.8.8"}}
	s := NewAuthorizationStore(AuthorizationStoreOptions{NewToken: func() (string, error) { return "bound-token", nil }})
	if _, err := s.IssueBound("check-task", target); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumeBound("", AuthorizationTarget{Host: "node.example.com", User: "root", Port: 22, HostKeySHA256: "SHA256:abc"}); err == nil {
		t.Fatal("missing authorization was accepted")
	}
	if _, err := s.ConsumeBound("bound-token", AuthorizationTarget{Host: "other.example.com", User: "root", Port: 22, HostKeySHA256: "SHA256:abc"}); err == nil {
		t.Fatal("authorization for the wrong target was accepted")
	}
	if _, err := s.ConsumeBound("bound-token", AuthorizationTarget{Host: "node.example.com", User: "root", Port: 22, HostKeySHA256: "SHA256:abc"}); err != nil {
		t.Fatalf("wrong-target attempt consumed the valid authorization: %v", err)
	}

	legacy := NewAuthorizationStore(AuthorizationStoreOptions{NewToken: func() (string, error) { return "legacy-token", nil }})
	if _, err := legacy.Issue("legacy", AuthorizationTarget{Host: "node.example.com", User: "root", Port: 22}); err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.ConsumeBound("legacy-token", AuthorizationTarget{Host: "node.example.com", User: "root", Port: 22}); err == nil {
		t.Fatal("unbound legacy authorization was accepted for network execution")
	}
}

func TestBoundAuthorizationRejectsInvalidOrEmptyResolvedSet(t *testing.T) {
	s := NewAuthorizationStore(AuthorizationStoreOptions{})
	for _, addresses := range [][]string{nil, {}, {"not-an-ip"}} {
		_, err := s.IssueBound("task", AuthorizationTarget{Host: "node.example.com", User: "root", Port: 22, ResolvedIPs: addresses})
		if err == nil {
			t.Fatalf("invalid bound addresses %v were accepted", addresses)
		}
	}
}

func TestBoundAuthorizationWhitespaceHandleCannotBeReplayed(t *testing.T) {
	s := NewAuthorizationStore(AuthorizationStoreOptions{NewToken: func() (string, error) { return "bound-token", nil }})
	target := AuthorizationTarget{Host: "node.example.com", User: "root", Port: 22, ResolvedIPs: []string{"8.8.8.8"}}
	if _, err := s.IssueBound("task", target); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumeBound(" bound-token ", target); err != nil {
		t.Fatalf("normalized handle was rejected: %v", err)
	}
	if _, err := s.ConsumeBound("bound-token", target); err == nil {
		t.Fatal("authorization consumed with whitespace remained replayable")
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
