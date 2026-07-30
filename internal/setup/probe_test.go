package setup

import (
	"context"
	"testing"
	"time"
)

func TestRunProbeCompletesWithinDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res := RunProbe(ctx, t.TempDir())
	if res.CPULogical < 1 {
		t.Fatalf("cpu logical = %d", res.CPULogical)
	}
	if res.SuggestedConfig.MaxBodyBytes <= 0 {
		t.Fatal("expected suggested config")
	}
	switch res.Profile {
	case ProfileLow, ProfileMedium, ProfileHigh:
	default:
		t.Fatalf("unexpected profile %q", res.Profile)
	}
}

func TestProfileDefaultsBarrel(t *testing.T) {
	low := ProfileDefaults(ProfileLow)
	high := ProfileDefaults(ProfileHigh)
	if low.ChallengeCapacity >= high.ChallengeCapacity {
		t.Fatalf("low capacity should be below high")
	}
}

func TestDraftStoreLifecycle(t *testing.T) {
	s := NewDraftStore(time.Minute)
	d, err := s.Create()
	if err != nil || d.ID == "" {
		t.Fatalf("create: %v %#v", err, d)
	}
	if !s.SetPassword(d.ID, "Secret123!") {
		t.Fatal("set password")
	}
	pw, ok := s.Password(d.ID)
	if !ok || pw != "Secret123!" {
		t.Fatalf("password = %q ok=%v", pw, ok)
	}
	out, ok := s.Get(d.ID)
	if !ok || out.PasswordSet != true {
		t.Fatalf("get: %#v", out)
	}
	// Password must not appear in cloned JSON view.
	if out.password != "" {
		t.Fatal("password leaked into clone")
	}
	s.Delete(d.ID)
	if _, ok := s.Get(d.ID); ok {
		t.Fatal("expected deleted")
	}
}
