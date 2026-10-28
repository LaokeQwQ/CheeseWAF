//go:build linux || darwin

package activation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

const (
	processSidecarDescendantHelperEnv = "CHEESEWAF_PROCESS_DESCENDANT_HELPER"
	processSidecarDescendantRecordEnv = "CHEESEWAF_PROCESS_DESCENDANT_RECORD"
	processSidecarDescendantStderrEnv = "CHEESEWAF_PROCESS_DESCENDANT_STDERR"
)

type processSidecarDescendantRecord struct {
	LeaderPID int `json:"leader_pid"`
	ChildPID  int `json:"child_pid"`
	PGID      int `json:"pgid"`
}

// The descendant deliberately remains alive when its leader exits. Inheriting
// stderr also catches exec.Cmd.Wait being held open by an internal copy pipe.
func TestProcessSidecarDescendantLifecycleHelper(t *testing.T) {
	if os.Getenv(processSidecarDescendantHelperEnv) == "" {
		return
	}
	decoder := json.NewDecoder(os.Stdin)
	var descendant *exec.Cmd
	for {
		var request processSidecarRequest
		if err := decoder.Decode(&request); err != nil {
			os.Exit(90)
		}
		if request.SchemaVersion != ProcessSidecarProtocolVersion || request.Identity != processSidecarTestIdentity() {
			os.Exit(91)
		}
		switch request.Operation {
		case "start":
			if descendant != nil {
				os.Exit(92)
			}
			descendant = exec.Command("/bin/sleep", "30")
			if os.Getenv(processSidecarDescendantStderrEnv) == "inherit" {
				descendant.Stderr = os.Stderr
			}
			if err := descendant.Start(); err != nil {
				os.Exit(93)
			}
			group, err := syscall.Getpgid(descendant.Process.Pid)
			if err != nil {
				_ = descendant.Process.Kill()
				_ = descendant.Wait()
				os.Exit(94)
			}
			raw, _ := json.Marshal(processSidecarDescendantRecord{
				LeaderPID: os.Getpid(), ChildPID: descendant.Process.Pid, PGID: group,
			})
			if err := os.WriteFile(os.Getenv(processSidecarDescendantRecordEnv), raw, 0o600); err != nil {
				_ = descendant.Process.Kill()
				_ = descendant.Wait()
				os.Exit(95)
			}
			writeProcessSidecarHelperAck(request, SidecarModeObserve, "ok", "")
		case "stop":
			writeProcessSidecarHelperAck(request, SidecarModeObserve, "ok", "")
			os.Exit(0)
		default:
			os.Exit(96)
		}
	}
}

func TestProcessSidecarBackendTerminatesDescendantsAfterLeaderExit(t *testing.T) {
	for _, exit := range []string{"clean-stop", "crash"} {
		for _, stderr := range []string{"discard", "inherit"} {
			t.Run(exit+"/stderr-"+stderr, func(t *testing.T) {
				recordPath := filepath.Join(t.TempDir(), "descendant.json")
				entry := processSidecarTestEntry(t, "normal")
				entry.Args = []string{"-test.run=^TestProcessSidecarDescendantLifecycleHelper$"}
				entry.Environment = map[string]string{
					processSidecarDescendantHelperEnv: "1",
					processSidecarDescendantRecordEnv: recordPath,
					processSidecarDescendantStderrEnv: stderr,
				}
				backend, err := NewProcessSidecarBackend(ProcessSidecarBackendOptions{
					Registry: []ProcessSidecarRegistryEntry{entry}, Admission: allowProcessSidecarTestAdmission,
					OperationTimeout: 3 * time.Second, StopTimeout: 3 * time.Second,
				})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
					defer cancel()
					_ = backend.Close(ctx)
				})
				// Register this last so a failed assertion cannot leave a descendant
				// holding stderr open while backend cleanup waits for the leader.
				t.Cleanup(func() { cleanupProcessSidecarDescendant(t, recordPath) })
				process, err := backend.Start(t.Context(), processSidecarTestSpec())
				if err != nil {
					t.Fatal(err)
				}
				concrete := process.(*processSidecarProcess)
				record := readProcessSidecarDescendantRecord(t, recordPath)
				if record.LeaderPID != concrete.cmd.Process.Pid || record.PGID != record.LeaderPID || record.ChildPID <= 0 || record.ChildPID == record.LeaderPID {
					t.Fatalf("descendant did not inherit the sidecar process group: %+v", record)
				}
				if running, err := processSidecarDescendantRunning(record.ChildPID); err != nil || !running {
					t.Fatalf("descendant was not running before leader exit: running=%v, error=%v", running, err)
				}
				if exit == "clean-stop" {
					ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
					defer cancel()
					if err := process.Stop(ctx); err != nil {
						t.Fatalf("clean Stop() failed with a live descendant: %v", err)
					}
				} else if err := concrete.cmd.Process.Kill(); err != nil {
					t.Fatalf("crash sidecar leader: %v", err)
				}
				assertProcessSidecarReaped(t, process)
				deadline := time.Now().Add(time.Second)
				for {
					running, err := processSidecarDescendantRunning(record.ChildPID)
					if err != nil {
						t.Fatal(err)
					}
					if !running {
						break
					}
					if time.Now().After(deadline) {
						t.Fatalf("descendant %d in group %d survived leader exit", record.ChildPID, record.PGID)
					}
					time.Sleep(10 * time.Millisecond)
				}
			})
		}
	}
}

func readProcessSidecarDescendantRecord(t *testing.T, path string) processSidecarDescendantRecord {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var record processSidecarDescendantRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		t.Fatal(err)
	}
	return record
}

func cleanupProcessSidecarDescendant(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return
	}
	record := readProcessSidecarDescendantRecord(t, path)
	if record.ChildPID <= 0 || record.LeaderPID <= 0 || record.ChildPID == record.LeaderPID || record.PGID != record.LeaderPID {
		t.Errorf("refusing descendant cleanup with invalid process record: %+v", record)
		return
	}
	group, err := syscall.Getpgid(record.ChildPID)
	if errors.Is(err, syscall.ESRCH) {
		return
	}
	if err != nil || group != record.PGID {
		t.Errorf("refusing descendant cleanup after process group changed: group=%d, record=%+v, error=%v", group, record, err)
		return
	}
	if err := syscall.Kill(record.ChildPID, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		t.Errorf("cleanup descendant: %v", err)
	}
}

func processSidecarDescendantRunning(pid int) (bool, error) {
	if err := syscall.Kill(pid, 0); err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return false, nil
		}
		return false, err
	}
	// A terminated grandchild may remain a zombie until its new parent reaps
	// it. Zombies have stopped executing and must not be counted as survivors.
	output, err := exec.Command("/bin/ps", "-o", "stat=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() == 1 && len(strings.TrimSpace(string(output))) == 0 {
			return false, nil
		}
		return false, fmt.Errorf("inspect descendant %d: %w", pid, err)
	}
	state := strings.TrimSpace(string(output))
	return state != "" && !strings.HasPrefix(state, "Z"), nil
}
