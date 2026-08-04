package orchestrate

import (
	"context"
	"fmt"
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

func TestRollingAutoRollbackOnFailure(t *testing.T) {
	starter := &fakeDeployStarter{fail: map[string]bool{"install-b.example": true}}
	idSeq := 0
	mgr := NewRollingManager(starter, func() string {
		idSeq++
		return fmt.Sprintf("job-rb-%d", idSeq)
	}, time.Now().UTC)

	stop := true
	restart := false
	auto := true
	job, err := mgr.Start(context.Background(), RollingUpgradeRequest{
		Targets: []RollingTarget{
			{Host: "a.example", User: "root"},
			{Host: "b.example", User: "root"},
		},
		StopOnFailure:  &stop,
		RestartService: &restart,
		AutoRollback:   &auto,
		PauseBetween:   "1ms",
	})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		got, _ := mgr.Get(job.ID)
		if got.Status == RollingStatusFailed && got.RollbackJobID != "" {
			rb, err := mgr.Get(got.RollbackJobID)
			if err != nil {
				t.Fatal(err)
			}
			// Wait for rollback to finish.
			rbDeadline := time.Now().Add(2 * time.Second)
			for time.Now().Before(rbDeadline) {
				rb, _ = mgr.Get(got.RollbackJobID)
				if rb.Status == RollingStatusSucceeded {
					if rb.RollbackOf != job.ID {
						t.Fatalf("rollback_of=%q want %q", rb.RollbackOf, job.ID)
					}
					if len(rb.Steps) != 1 || rb.Steps[0].Host != "a.example" {
						t.Fatalf("rollback should only reinstall succeeded host a: %+v", rb.Steps)
					}
					return
				}
				if rb.Status == RollingStatusFailed {
					t.Fatalf("rollback failed: %+v", rb)
				}
				time.Sleep(10 * time.Millisecond)
			}
			t.Fatal("timed out waiting for rollback job")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out waiting for auto-rollback")
}

func TestStartRollbackManual(t *testing.T) {
	starter := &fakeDeployStarter{fail: map[string]bool{}}
	idSeq := 0
	mgr := NewRollingManager(starter, func() string {
		idSeq++
		return fmt.Sprintf("job-m-%d", idSeq)
	}, time.Now().UTC)
	restart := false
	job, err := mgr.Start(context.Background(), RollingUpgradeRequest{
		Targets: []RollingTarget{
			{Host: "a.example", User: "root"},
			{Host: "b.example", User: "root"},
		},
		RestartService: &restart,
		PauseBetween:   "1ms",
	})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		got, _ := mgr.Get(job.ID)
		if got.Status == RollingStatusSucceeded {
			rb, err := mgr.StartRollback(context.Background(), job.ID)
			if err != nil {
				t.Fatal(err)
			}
			if rb.RollbackOf != job.ID {
				t.Fatalf("rollback_of=%q", rb.RollbackOf)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out waiting for success before manual rollback")
}
