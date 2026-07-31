package orchestrate

import (
	"context"
	"sync"
	"testing"
	"time"
)

type fakeDeployStarter struct {
	mu    sync.Mutex
	calls []string
	fail  map[string]bool
}

func (f *fakeDeployStarter) StartInstall(_ context.Context, target RollingTarget) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := "install-" + target.Host
	f.calls = append(f.calls, id)
	return id, nil
}

func (f *fakeDeployStarter) StartRestart(_ context.Context, target RollingTarget) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := "restart-" + target.Host
	f.calls = append(f.calls, id)
	return id, nil
}

func (f *fakeDeployStarter) WaitTask(_ context.Context, taskID string) (bool, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail[taskID] {
		return false, "forced failure", nil
	}
	return true, "ok", nil
}

func TestRollingUpgradeSucceedsSequentially(t *testing.T) {
	starter := &fakeDeployStarter{fail: map[string]bool{}}
	mgr := NewRollingManager(starter, func() string { return "job-1" }, func() time.Time {
		return time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	})
	restart := true
	pause := "1ms"
	job, err := mgr.Start(context.Background(), RollingUpgradeRequest{
		Targets: []RollingTarget{
			{Host: "a.example", User: "root"},
			{Host: "b.example", User: "root"},
		},
		PauseBetween:   pause,
		RestartService: &restart,
	})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		got, err := mgr.Get(job.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.Status == RollingStatusSucceeded {
			if len(got.Steps) != 2 || got.Steps[1].Status != RollingStatusSucceeded {
				t.Fatalf("steps: %+v", got.Steps)
			}
			return
		}
		if got.Status == RollingStatusFailed {
			t.Fatalf("unexpected failure: %+v", got)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out waiting for rolling job")
}

func TestRollingUpgradeStopsOnFailure(t *testing.T) {
	starter := &fakeDeployStarter{fail: map[string]bool{"install-a.example": true}}
	mgr := NewRollingManager(starter, func() string { return "job-2" }, time.Now().UTC)
	stop := true
	restart := false
	job, err := mgr.Start(context.Background(), RollingUpgradeRequest{
		Targets: []RollingTarget{
			{Host: "a.example", User: "root"},
			{Host: "b.example", User: "root"},
		},
		StopOnFailure:  &stop,
		RestartService: &restart,
		PauseBetween:   "1ms",
	})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		got, _ := mgr.Get(job.ID)
		if got.Status == RollingStatusFailed {
			if got.Steps[0].Status != RollingStatusFailed {
				t.Fatalf("first step should fail: %+v", got.Steps[0])
			}
			if got.Steps[1].Status != RollingStatusPending && got.Steps[1].Stage != RollingStepQueued {
				t.Fatalf("second step should not complete after stop-on-failure: %+v", got.Steps[1])
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out waiting for failed rolling job")
}
