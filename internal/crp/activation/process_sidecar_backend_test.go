//go:build !windows

package activation

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const processSidecarHelperEnvironment = "CHEESEWAF_PROCESS_SIDECAR_HELPER"

// TestProcessSidecarBackendHelper is a real child process used by the backend
// tests. os.Exit prevents the go test runner from appending PASS output to the
// line-oriented protocol after the stop acknowledgement.
func TestProcessSidecarBackendHelper(t *testing.T) {
	behavior := os.Getenv(processSidecarHelperEnvironment)
	if behavior == "" {
		return
	}
	reader := bufio.NewReader(os.Stdin)
	wantSequence := uint64(1)
	mode := SidecarModeObserve
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			os.Exit(90)
		}
		decoder := json.NewDecoder(strings.NewReader(string(line)))
		decoder.DisallowUnknownFields()
		var request processSidecarRequest
		if err := decoder.Decode(&request); err != nil {
			os.Exit(91)
		}
		if request.SchemaVersion != ProcessSidecarProtocolVersion || request.Sequence != wantSequence || request.Identity != processSidecarTestIdentity() {
			os.Exit(92)
		}
		wantSequence++
		if os.Getenv("CHEESEWAF_SECRET_SHOULD_NOT_LEAK") != "" {
			writeProcessSidecarHelperAck(request, mode, "error", "secret_leaked")
			continue
		}
		switch request.Operation {
		case "start":
			if request.Mode != SidecarModeObserve || request.Sequence != 1 {
				os.Exit(93)
			}
			if behavior == "start-malformed" {
				_, _ = fmt.Fprintln(os.Stdout, "{not-json")
				continue
			}
			if behavior == "stderr-flood" {
				_, _ = os.Stderr.Write(make([]byte, 4<<20))
			}
			writeProcessSidecarHelperAck(request, mode, "ok", "")
		case "mode":
			if !validSidecarTransition(mode, request.Mode) {
				writeProcessSidecarHelperAck(request, mode, "error", "invalid_transition")
				continue
			}
			mode = request.Mode
			writeProcessSidecarHelperAck(request, mode, "ok", "")
		case "probe":
			if request.Mode != mode {
				os.Exit(94)
			}
			switch behavior {
			case "malformed":
				_, _ = fmt.Fprintln(os.Stdout, "{not-json")
			case "oversize":
				_, _ = fmt.Fprintln(os.Stdout, strings.Repeat("x", defaultProcessMessageBytes+1))
			case "stale":
				request.Sequence--
				writeProcessSidecarHelperAck(request, mode, "ok", "")
			case "extra":
				_, _ = fmt.Fprintf(os.Stdout, `{"schema_version":%q,"sequence":%d,"operation":"probe","status":"ok","mode":%q,"extra":true}`+"\n", ProcessSidecarProtocolVersion, request.Sequence, mode)
			case "duplicate":
				_, _ = fmt.Fprintf(os.Stdout, `{"schema_version":%q,"sequence":%d,"sequence":%d,"operation":"probe","status":"ok","mode":%q}`+"\n", ProcessSidecarProtocolVersion, request.Sequence, request.Sequence, mode)
			case "trailing":
				ack := processSidecarAcknowledgement{SchemaVersion: ProcessSidecarProtocolVersion, Sequence: request.Sequence, Operation: request.Operation, Status: "ok", Mode: mode}
				raw, _ := json.Marshal(ack)
				_, _ = fmt.Fprintf(os.Stdout, "%s {}\n", raw)
			case "timeout":
				_, _ = reader.ReadByte()
			case "crash":
				os.Exit(41)
			default:
				writeProcessSidecarHelperAck(request, mode, "ok", "")
			}
		case "stop":
			writeProcessSidecarHelperAck(request, mode, "ok", "")
			if behavior == "stubborn" {
				signals := make(chan os.Signal, 1)
				signal.Notify(signals, os.Interrupt)
				<-signals
			}
			os.Exit(0)
		default:
			os.Exit(95)
		}
	}
}

func writeProcessSidecarHelperAck(request processSidecarRequest, mode SidecarMode, status, errorCode string) {
	acknowledgement := processSidecarAcknowledgement{
		SchemaVersion: ProcessSidecarProtocolVersion, Sequence: request.Sequence,
		Operation: request.Operation, Status: status, Mode: mode, ErrorCode: errorCode,
	}
	raw, _ := json.Marshal(acknowledgement)
	_, _ = os.Stdout.Write(append(raw, '\n'))
}

func TestProcessSidecarBackendRunsBoundLifecycleWithExplicitEnvironment(t *testing.T) {
	t.Setenv("CHEESEWAF_SECRET_SHOULD_NOT_LEAK", "must-not-cross-exec")
	entry := processSidecarTestEntry(t, "normal")
	admissions := make(chan ProcessSidecarAdmissionRequest, 1)
	backend := newProcessSidecarTestBackend(t, entry, func(_ context.Context, request ProcessSidecarAdmissionRequest) error {
		admissions <- request
		request.Definition.Args[0] = "mutated"
		request.Definition.Environment[processSidecarHelperEnvironment] = "crash"
		return nil
	})

	// Mutation after construction must not affect the trusted snapshot.
	entry.Args[0] = "mutated-after-construction"
	entry.Environment[processSidecarHelperEnvironment] = "crash"
	spec := processSidecarTestSpec()
	spec.Descriptor.Metadata = map[string]string{
		"command": "/bin/sh", "args": "-c", "working_directory": "/tmp",
	}
	spec.Descriptor.Resources = ResourceRequest{CPUmilli: 10, MemoryBytes: 4096, PIDs: 2}
	process, err := backend.Start(t.Context(), spec)
	if err != nil {
		t.Fatal(err)
	}
	admission := <-admissions
	if admission.Identity != processSidecarTestIdentity() || admission.Resources != spec.Descriptor.Resources {
		t.Fatalf("admission request = %+v", admission)
	}
	if err := process.Probe(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := process.SetMode(t.Context(), SidecarModeCanary); err != nil {
		t.Fatal(err)
	}
	if err := process.Probe(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := process.SetMode(t.Context(), SidecarModeActive); err != nil {
		t.Fatal(err)
	}
	if err := process.Stop(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := process.Stop(t.Context()); err != nil {
		t.Fatalf("idempotent stop: %v", err)
	}
	if err := backend.Close(t.Context()); err != nil {
		t.Fatalf("idempotent backend close: %v", err)
	}
}

func TestProcessSidecarBackendRequiresExactRegisteredIdentity(t *testing.T) {
	backend := newProcessSidecarTestBackend(t, processSidecarTestEntry(t, "normal"), allowProcessSidecarTestAdmission)
	spec := processSidecarTestSpec()
	spec.Descriptor.ArtifactIdentity = strings.Repeat("c", 64)
	spec.Target.ArtifactIdentity = spec.Descriptor.ArtifactIdentity
	if _, err := backend.Start(t.Context(), spec); !errors.Is(err, ErrProcessSidecarRegistry) {
		t.Fatalf("Start() error = %v, want ErrProcessSidecarRegistry", err)
	}
	if err := backend.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestProcessSidecarBackendRejectsConflictingRegistryIdentity(t *testing.T) {
	entry := processSidecarTestEntry(t, "normal")
	_, err := NewProcessSidecarBackend(ProcessSidecarBackendOptions{
		Registry: []ProcessSidecarRegistryEntry{entry, entry}, Admission: allowProcessSidecarTestAdmission,
	})
	if !errors.Is(err, ErrProcessSidecarConfig) {
		t.Fatalf("NewProcessSidecarBackend() error = %v, want ErrProcessSidecarConfig", err)
	}
}

func TestProcessSidecarBackendFailsClosedWithoutAdmission(t *testing.T) {
	_, err := NewProcessSidecarBackend(ProcessSidecarBackendOptions{Registry: []ProcessSidecarRegistryEntry{processSidecarTestEntry(t, "normal")}})
	if !errors.Is(err, ErrProcessSidecarConfig) {
		t.Fatalf("NewProcessSidecarBackend() error = %v, want ErrProcessSidecarConfig", err)
	}
}

func TestProcessSidecarBackendFailsClosedWhenAdmissionRejects(t *testing.T) {
	denied := errors.New("containment unavailable")
	backend := newProcessSidecarTestBackend(t, processSidecarTestEntry(t, "normal"), func(context.Context, ProcessSidecarAdmissionRequest) error {
		return denied
	})
	if _, err := backend.Start(t.Context(), processSidecarTestSpec()); !errors.Is(err, ErrProcessSidecarAdmission) || !errors.Is(err, denied) {
		t.Fatalf("Start() error = %v, want admission denial", err)
	}
}

func TestProcessSidecarBackendReapsFailedStartHandshakeAndDrainsStderr(t *testing.T) {
	malformed := newProcessSidecarTestBackend(t, processSidecarTestEntry(t, "start-malformed"), allowProcessSidecarTestAdmission)
	if _, err := malformed.Start(t.Context(), processSidecarTestSpec()); !errors.Is(err, ErrProcessSidecarProtocol) {
		t.Fatalf("malformed Start() error = %v, want ErrProcessSidecarProtocol", err)
	}
	malformed.mu.Lock()
	tracked := len(malformed.processes)
	malformed.mu.Unlock()
	if tracked != 0 {
		t.Fatalf("failed start left %d tracked processes", tracked)
	}

	stderr := newProcessSidecarTestBackend(t, processSidecarTestEntry(t, "stderr-flood"), allowProcessSidecarTestAdmission)
	process, err := stderr.Start(t.Context(), processSidecarTestSpec())
	if err != nil {
		t.Fatalf("stderr flood blocked start: %v", err)
	}
	if err := process.Stop(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestProcessSidecarBackendRejectsMalformedOversizeStaleAndNonStrictAcknowledgements(t *testing.T) {
	for _, behavior := range []string{"malformed", "oversize", "stale", "extra", "duplicate", "trailing"} {
		t.Run(behavior, func(t *testing.T) {
			backend := newProcessSidecarTestBackend(t, processSidecarTestEntry(t, behavior), allowProcessSidecarTestAdmission)
			process, err := backend.Start(t.Context(), processSidecarTestSpec())
			if err != nil {
				t.Fatal(err)
			}
			if err := process.Probe(t.Context()); !errors.Is(err, ErrProcessSidecarProtocol) {
				t.Fatalf("Probe() error = %v, want ErrProcessSidecarProtocol", err)
			}
			if err := process.SetMode(t.Context(), SidecarModeCanary); !errors.Is(err, ErrProcessSidecarExited) {
				t.Fatalf("SetMode() after protocol failure = %v, want ErrProcessSidecarExited", err)
			}
			assertProcessSidecarReaped(t, process)
		})
	}
}

func TestProcessSidecarBackendTimesOutAndReapsUnresponsiveChild(t *testing.T) {
	backend, err := NewProcessSidecarBackend(ProcessSidecarBackendOptions{
		Registry:  []ProcessSidecarRegistryEntry{processSidecarTestEntry(t, "timeout")},
		Admission: allowProcessSidecarTestAdmission, OperationTimeout: 500 * time.Millisecond,
		StopTimeout: 50 * time.Millisecond, MaxMessageBytes: defaultProcessMessageBytes,
	})
	if err != nil {
		t.Fatal(err)
	}
	process, err := backend.Start(t.Context(), processSidecarTestSpec())
	if err != nil {
		t.Fatal(err)
	}
	// The start handshake launches a fresh race-instrumented test process and
	// is substantially slower on macOS runners. Keep that setup allowance
	// separate from the short operation timeout this test is exercising.
	backend.operationTimeout = 50 * time.Millisecond
	if err := process.Probe(t.Context()); !errors.Is(err, ErrProcessSidecarProtocol) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Probe() error = %v, want protocol deadline", err)
	}
	assertProcessSidecarReaped(t, process)
}

func TestProcessSidecarBackendFailsClosedOnCrash(t *testing.T) {
	backend := newProcessSidecarTestBackend(t, processSidecarTestEntry(t, "crash"), allowProcessSidecarTestAdmission)
	process, err := backend.Start(t.Context(), processSidecarTestSpec())
	if err != nil {
		t.Fatal(err)
	}
	if err := process.Probe(t.Context()); err == nil || !errors.Is(err, ErrProcessSidecarProtocol) && !errors.Is(err, ErrProcessSidecarExited) {
		t.Fatalf("Probe() crash error = %v", err)
	}
	if err := process.SetMode(t.Context(), SidecarModeCanary); err == nil {
		t.Fatal("SetMode() after crash unexpectedly succeeded")
	}
	assertProcessSidecarReaped(t, process)
}

func TestProcessSidecarBackendForceKillsAndReapsAfterGracefulStopTimeout(t *testing.T) {
	backend, err := NewProcessSidecarBackend(ProcessSidecarBackendOptions{
		Registry:  []ProcessSidecarRegistryEntry{processSidecarTestEntry(t, "stubborn")},
		Admission: allowProcessSidecarTestAdmission, OperationTimeout: time.Second,
		StopTimeout: 50 * time.Millisecond, MaxMessageBytes: defaultProcessMessageBytes,
	})
	if err != nil {
		t.Fatal(err)
	}
	process, err := backend.Start(t.Context(), processSidecarTestSpec())
	if err != nil {
		t.Fatal(err)
	}
	first := process.Stop(t.Context())
	if !errors.Is(first, ErrProcessSidecarProtocol) || !errors.Is(first, context.DeadlineExceeded) {
		t.Fatalf("Stop() error = %v, want graceful timeout", first)
	}
	if second := process.Stop(t.Context()); second == nil || second.Error() != first.Error() {
		t.Fatalf("repeated Stop() error = %v, want retained %v", second, first)
	}
	assertProcessSidecarReaped(t, process)
}

func TestProcessSidecarBackendSerializesConcurrentOperations(t *testing.T) {
	backend := newProcessSidecarTestBackend(t, processSidecarTestEntry(t, "normal"), allowProcessSidecarTestAdmission)
	process, err := backend.Start(t.Context(), processSidecarTestSpec())
	if err != nil {
		t.Fatal(err)
	}
	const callers = 32
	start := make(chan struct{})
	results := make(chan error, callers)
	var wait sync.WaitGroup
	for i := 0; i < callers; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			results <- process.Probe(t.Context())
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatalf("concurrent Probe() error = %v", err)
		}
	}
	if err := process.Stop(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestProcessSidecarBackendCloseStopsAndReapsActiveChildren(t *testing.T) {
	backend := newProcessSidecarTestBackend(t, processSidecarTestEntry(t, "normal"), allowProcessSidecarTestAdmission)
	process, err := backend.Start(t.Context(), processSidecarTestSpec())
	if err != nil {
		t.Fatal(err)
	}
	if err := backend.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	assertProcessSidecarReaped(t, process)
	if err := backend.Close(t.Context()); err != nil {
		t.Fatalf("repeated Close() error = %v", err)
	}
	if _, err := backend.Start(t.Context(), processSidecarTestSpec()); !errors.Is(err, ErrProcessSidecarClosed) {
		t.Fatalf("Start() after Close() error = %v, want ErrProcessSidecarClosed", err)
	}
}

func newProcessSidecarTestBackend(t *testing.T, entry ProcessSidecarRegistryEntry, admission ProcessSidecarAdmissionHook) *ProcessSidecarBackend {
	t.Helper()
	backend, err := NewProcessSidecarBackend(ProcessSidecarBackendOptions{
		Registry: []ProcessSidecarRegistryEntry{entry}, Admission: admission,
		OperationTimeout: 5 * time.Second, StopTimeout: 5 * time.Second, MaxMessageBytes: defaultProcessMessageBytes,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close(context.Background()) })
	return backend
}

func processSidecarTestEntry(t *testing.T, behavior string) ProcessSidecarRegistryEntry {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		t.Fatal(err)
	}
	return ProcessSidecarRegistryEntry{
		Identity: processSidecarTestIdentity(), Executable: executable,
		Args:             []string{"-test.run=^TestProcessSidecarBackendHelper$"},
		WorkingDirectory: filepath.Dir(executable),
		Environment:      map[string]string{processSidecarHelperEnvironment: behavior},
	}
}

func processSidecarTestIdentity() ProcessSidecarIdentity {
	return ProcessSidecarIdentity{
		PluginID: "rate-limit", Namespace: "official/security", Version: "1.0.0",
		ManifestIdentity: strings.Repeat("a", 64), ArtifactIdentity: strings.Repeat("b", 64),
	}
}

func processSidecarTestSpec() SidecarLaunchSpec {
	descriptor := launcherDescriptor()
	return SidecarLaunchSpec{Descriptor: descriptor, Target: runtimeTarget(launcherRecord(descriptor))}
}

func allowProcessSidecarTestAdmission(context.Context, ProcessSidecarAdmissionRequest) error {
	return nil
}

func assertProcessSidecarReaped(t *testing.T, process SidecarLauncherProcess) {
	t.Helper()
	concrete, ok := process.(*processSidecarProcess)
	if !ok {
		t.Fatalf("process type = %T", process)
	}
	select {
	case <-concrete.done:
	case <-time.After(time.Second):
		t.Fatal("child was not reaped")
	}
}
