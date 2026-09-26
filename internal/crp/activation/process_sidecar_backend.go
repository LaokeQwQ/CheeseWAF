package activation

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// ProcessSidecarProtocolVersion is the wire version implemented by trusted
	// child executables over one bounded JSON object per stdin/stdout line.
	ProcessSidecarProtocolVersion  = "cheesewaf-crp-sidecar-process.v1"
	defaultProcessOperationTimeout = 5 * time.Second
	defaultProcessStopTimeout      = 3 * time.Second
	defaultProcessMessageBytes     = 64 << 10
	maxProcessMessageBytes         = 1 << 20
	maxProcessRegistryEntries      = 256
	maxProcessArguments            = 128
	maxProcessArgumentBytes        = 64 << 10
	maxProcessEnvironmentBytes     = 64 << 10
)

var (
	ErrProcessSidecarConfig    = errors.New("CRP process sidecar configuration is invalid")
	ErrProcessSidecarRegistry  = errors.New("CRP process sidecar registry lookup failed")
	ErrProcessSidecarAdmission = errors.New("CRP process sidecar admission failed")
	ErrProcessSidecarProtocol  = errors.New("CRP process sidecar protocol failed")
	ErrProcessSidecarExited    = errors.New("CRP process sidecar exited")
	ErrProcessSidecarClosed    = errors.New("CRP process sidecar backend is closed")
)

// ProcessSidecarIdentity is the complete registry key for a trusted sidecar
// executable. Runtime targets and descriptors may select this exact key, but
// can never supply a command, path, argument, environment, or working directory.
type ProcessSidecarIdentity struct {
	PluginID         string `json:"plugin_id"`
	Namespace        string `json:"namespace"`
	Version          string `json:"version"`
	ManifestIdentity string `json:"manifest_identity"`
	ArtifactIdentity string `json:"artifact_identity"`
}

// ProcessSidecarRegistryEntry is trusted startup configuration. Every launch
// field is fixed by the registry and defensively copied by the constructor.
// Environment is explicit: the parent environment is never inherited.
type ProcessSidecarRegistryEntry struct {
	Identity         ProcessSidecarIdentity
	Executable       string
	Args             []string
	WorkingDirectory string
	Environment      map[string]string
}

// ProcessSidecarAdmissionRequest is passed only to the trusted admission hook.
// The hook must establish or verify externally enforced resource containment
// for this exact launch, or return an error. The portable Go backend does not
// claim that descriptor resource requests have been enforced by itself.
type ProcessSidecarAdmissionRequest struct {
	Identity   ProcessSidecarIdentity
	Definition ProcessSidecarRegistryEntry
	Resources  ResourceRequest
}

// ProcessSidecarAdmissionHook is a mandatory fail-closed integration point
// for platform policy such as a preconfigured cgroup, job object, sandbox, or
// service manager. Returning nil asserts that containment exists for the exact
// immutable registry entry and resource request.
type ProcessSidecarAdmissionHook func(context.Context, ProcessSidecarAdmissionRequest) error

type ProcessSidecarBackendOptions struct {
	Registry         []ProcessSidecarRegistryEntry
	Admission        ProcessSidecarAdmissionHook
	OperationTimeout time.Duration
	StopTimeout      time.Duration
	MaxMessageBytes  int
}

// ProcessSidecarBackend launches only startup-registered executables and owns
// every child until it has been reaped.
type ProcessSidecarBackend struct {
	registry         map[ProcessSidecarIdentity]ProcessSidecarRegistryEntry
	admission        ProcessSidecarAdmissionHook
	operationTimeout time.Duration
	stopTimeout      time.Duration
	maxMessageBytes  int

	mu        sync.Mutex
	processes map[*processSidecarProcess]struct{}
	closed    bool
	starts    sync.WaitGroup
	closeCtx  context.Context
	close     context.CancelFunc
}

func NewProcessSidecarBackend(opts ProcessSidecarBackendOptions) (*ProcessSidecarBackend, error) {
	if len(opts.Registry) == 0 || len(opts.Registry) > maxProcessRegistryEntries {
		return nil, fmt.Errorf("%w: registry must contain between 1 and %d entries", ErrProcessSidecarConfig, maxProcessRegistryEntries)
	}
	if opts.Admission == nil {
		return nil, fmt.Errorf("%w: admission hook is required", ErrProcessSidecarConfig)
	}
	if opts.OperationTimeout == 0 {
		opts.OperationTimeout = defaultProcessOperationTimeout
	}
	if opts.StopTimeout == 0 {
		opts.StopTimeout = defaultProcessStopTimeout
	}
	if opts.MaxMessageBytes == 0 {
		opts.MaxMessageBytes = defaultProcessMessageBytes
	}
	if opts.OperationTimeout <= 0 || opts.StopTimeout <= 0 || opts.MaxMessageBytes < 256 || opts.MaxMessageBytes > maxProcessMessageBytes {
		return nil, fmt.Errorf("%w: invalid timeout or message bound", ErrProcessSidecarConfig)
	}

	registry := make(map[ProcessSidecarIdentity]ProcessSidecarRegistryEntry, len(opts.Registry))
	for i, entry := range opts.Registry {
		cloned, err := validateAndCloneProcessRegistryEntry(entry)
		if err != nil {
			return nil, fmt.Errorf("%w: registry entry %d: %v", ErrProcessSidecarConfig, i, err)
		}
		if _, conflict := registry[cloned.Identity]; conflict {
			return nil, fmt.Errorf("%w: duplicate identity %+v", ErrProcessSidecarConfig, cloned.Identity)
		}
		registry[cloned.Identity] = cloned
	}
	closeCtx, closeBackend := context.WithCancel(context.Background())
	return &ProcessSidecarBackend{
		registry: registry, admission: opts.Admission,
		operationTimeout: opts.OperationTimeout, stopTimeout: opts.StopTimeout,
		maxMessageBytes: opts.MaxMessageBytes, processes: make(map[*processSidecarProcess]struct{}),
		closeCtx: closeCtx, close: closeBackend,
	}, nil
}

func (b *ProcessSidecarBackend) Start(ctx context.Context, spec SidecarLaunchSpec) (SidecarLauncherProcess, error) {
	if b == nil {
		return nil, ErrProcessSidecarClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validateLauncherDescriptor(spec.Descriptor, spec.Target); err != nil {
		return nil, err
	}
	identity := processIdentityForSpec(spec)

	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil, ErrProcessSidecarClosed
	}
	entry, ok := b.registry[identity]
	b.starts.Add(1)
	b.mu.Unlock()
	defer b.starts.Done()
	if !ok {
		return nil, fmt.Errorf("%w: identity %+v is not registered", ErrProcessSidecarRegistry, identity)
	}
	launchContext, cancelLaunch := context.WithCancel(ctx)
	stopCloseCancellation := context.AfterFunc(b.closeCtx, cancelLaunch)
	defer func() {
		stopCloseCancellation()
		cancelLaunch()
	}()
	entry = cloneProcessRegistryEntry(entry)
	if err := validateProcessLaunchPaths(entry); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrProcessSidecarConfig, err)
	}
	request := ProcessSidecarAdmissionRequest{
		Identity: identity, Definition: cloneProcessRegistryEntry(entry), Resources: spec.Descriptor.Resources,
	}
	if err := b.admission(launchContext, request); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrProcessSidecarAdmission, err)
	}
	b.mu.Lock()
	closed := b.closed
	b.mu.Unlock()
	if closed {
		return nil, ErrProcessSidecarClosed
	}
	// Admission may involve an external policy engine. Revalidate immediately
	// before exec so a path mutation during that round trip fails closed.
	if err := validateProcessLaunchPaths(entry); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrProcessSidecarConfig, err)
	}

	cmd := exec.Command(entry.Executable, entry.Args...)
	cmd.Dir = entry.WorkingDirectory
	cmd.Env = processEnvironment(entry.Environment)
	cmd.Stderr = io.Discard
	if err := configureProcessSidecarCommand(cmd); err != nil {
		return nil, fmt.Errorf("%w: configure process: %v", ErrProcessSidecarConfig, err)
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("%w: stdin pipe: %v", ErrProcessSidecarProtocol, err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return nil, fmt.Errorf("%w: stdout pipe: %v", ErrProcessSidecarProtocol, err)
	}
	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		return nil, fmt.Errorf("%w: start executable: %v", ErrProcessSidecarExited, err)
	}

	process := &processSidecarProcess{
		backend: b, identity: identity, cmd: cmd, stdin: stdin,
		stdout: bufio.NewReaderSize(stdout, b.maxMessageBytes+1),
		mode:   SidecarModeObserve, done: make(chan struct{}),
	}
	go process.wait()
	process.mu.Lock()
	startErr := process.roundTripLocked(launchContext, "start", SidecarModeObserve, b.operationTimeout)
	process.mu.Unlock()
	if startErr != nil {
		return nil, fmt.Errorf("%w: start handshake: %w", ErrProcessSidecarProtocol, startErr)
	}

	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		_ = process.Stop(context.Background())
		return nil, ErrProcessSidecarClosed
	}
	select {
	case <-process.done:
		b.mu.Unlock()
		return nil, process.exitedError()
	default:
	}
	b.processes[process] = struct{}{}
	b.mu.Unlock()
	return process, nil
}

// Close prevents new launches, stops every tracked child, and waits until all
// of them have been reaped. Repeated calls are safe.
func (b *ProcessSidecarBackend) Close(ctx context.Context) error {
	if b == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	b.mu.Lock()
	b.closed = true
	b.close()
	b.mu.Unlock()
	startsDone := make(chan struct{})
	go func() {
		b.starts.Wait()
		close(startsDone)
	}()
	select {
	case <-startsDone:
	case <-ctx.Done():
		return ctx.Err()
	}
	b.mu.Lock()
	processes := make([]*processSidecarProcess, 0, len(b.processes))
	for process := range b.processes {
		processes = append(processes, process)
	}
	b.mu.Unlock()
	var closeErr error
	for _, process := range processes {
		if err := process.Stop(ctx); err != nil {
			closeErr = errors.Join(closeErr, err)
		}
	}
	return closeErr
}

type processSidecarProcess struct {
	backend  *ProcessSidecarBackend
	identity ProcessSidecarIdentity
	cmd      *exec.Cmd
	stdin    io.WriteCloser
	stdout   *bufio.Reader
	done     chan struct{}

	waitMu  sync.Mutex
	waitErr error

	mu       sync.Mutex
	sequence uint64
	mode     SidecarMode
	// unusable is set after a protocol round trip has failed. The failed round
	// trip already closes stdin and attempts to reap the child, but a child can
	// still be between its final write and exit. Do not let that small race turn
	// into another command written to a closed or untrusted protocol stream.
	unusable      bool
	stopAttempted bool
	stopErr       error
}

func (p *processSidecarProcess) SetMode(ctx context.Context, mode SidecarMode) error {
	if p == nil || p.backend == nil {
		return ErrProcessSidecarExited
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.stopAttempted || p.unusable {
		return ErrProcessSidecarExited
	}
	if !validSidecarTransition(p.mode, mode) {
		return fmt.Errorf("%w: invalid transition %s to %s", ErrProcessSidecarProtocol, p.mode, mode)
	}
	if err := p.roundTripLocked(ctx, "mode", mode, p.backend.operationTimeout); err != nil {
		p.unusable = true
		return err
	}
	p.mode = mode
	return nil
}

func (p *processSidecarProcess) Probe(ctx context.Context) error {
	if p == nil || p.backend == nil {
		return ErrProcessSidecarExited
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.stopAttempted || p.unusable {
		return ErrProcessSidecarExited
	}
	err := p.roundTripLocked(ctx, "probe", p.mode, p.backend.operationTimeout)
	if err != nil {
		p.unusable = true
	}
	return err
}

func (p *processSidecarProcess) Stop(ctx context.Context) error {
	if p == nil || p.backend == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.stopAttempted {
		return p.stopErr
	}
	p.stopAttempted = true
	if p.unusable {
		p.stopErr = p.killAndWaitLocked()
		return p.stopErr
	}
	if err := p.exitedErrorLocked(); err != nil {
		p.stopErr = err
		return err
	}

	stopErr := p.roundTripLocked(ctx, "stop", p.mode, p.backend.stopTimeout)
	_ = p.stdin.Close()
	if stopErr == nil {
		stopErr = p.waitForExitLocked(ctx, p.backend.stopTimeout)
	}
	if stopErr != nil {
		killErr := p.killAndWaitLocked()
		stopErr = errors.Join(stopErr, killErr)
	}
	p.stopErr = stopErr
	return stopErr
}

func (p *processSidecarProcess) wait() {
	err := p.cmd.Wait()
	p.waitMu.Lock()
	p.waitErr = err
	p.waitMu.Unlock()
	close(p.done)
	if p.backend != nil {
		p.backend.mu.Lock()
		delete(p.backend.processes, p)
		p.backend.mu.Unlock()
	}
}

type processSidecarRequest struct {
	SchemaVersion string                 `json:"schema_version"`
	Sequence      uint64                 `json:"sequence"`
	Operation     string                 `json:"operation"`
	Mode          SidecarMode            `json:"mode"`
	Identity      ProcessSidecarIdentity `json:"identity"`
}

type processSidecarAcknowledgement struct {
	SchemaVersion string      `json:"schema_version"`
	Sequence      uint64      `json:"sequence"`
	Operation     string      `json:"operation"`
	Status        string      `json:"status"`
	Mode          SidecarMode `json:"mode"`
	ErrorCode     string      `json:"error_code,omitempty"`
}

type processSidecarRoundTripResult struct {
	ack processSidecarAcknowledgement
	err error
}

func (p *processSidecarProcess) roundTripLocked(ctx context.Context, operation string, mode SidecarMode, timeout time.Duration) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := p.exitedErrorLocked(); err != nil {
		return err
	}
	p.sequence++
	request := processSidecarRequest{
		SchemaVersion: ProcessSidecarProtocolVersion, Sequence: p.sequence,
		Operation: operation, Mode: mode, Identity: p.identity,
	}
	raw, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("%w: encode request: %v", ErrProcessSidecarProtocol, err)
	}
	if len(raw)+1 > p.backend.maxMessageBytes {
		return fmt.Errorf("%w: request exceeds %d bytes", ErrProcessSidecarProtocol, p.backend.maxMessageBytes)
	}
	operationContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	result := make(chan processSidecarRoundTripResult, 1)
	go func() {
		message := append(raw, '\n')
		written, err := p.stdin.Write(message)
		if err == nil && written != len(message) {
			err = io.ErrShortWrite
		}
		if err != nil {
			result <- processSidecarRoundTripResult{err: fmt.Errorf("write request: %w", err)}
			return
		}
		ack, err := p.readAcknowledgement()
		result <- processSidecarRoundTripResult{ack: ack, err: err}
	}()

	var response processSidecarRoundTripResult
	select {
	case response = <-result:
	case <-p.done:
		// The child may write a final acknowledgement and exit immediately.
		// Closing stdout guarantees the single reader finishes, so prefer its
		// protocol result over racing the wait notification.
		response = <-result
	case <-operationContext.Done():
		killErr := p.killAndWaitLocked()
		return errors.Join(fmt.Errorf("%w: %s: %w", ErrProcessSidecarProtocol, operation, operationContext.Err()), killErr)
	}
	if response.err != nil {
		killErr := p.killAndWaitLocked()
		return errors.Join(fmt.Errorf("%w: %s acknowledgement: %v", ErrProcessSidecarProtocol, operation, response.err), killErr)
	}
	ack := response.ack
	if ack.SchemaVersion != ProcessSidecarProtocolVersion || ack.Sequence != p.sequence || ack.Operation != operation || ack.Mode != mode {
		killErr := p.killAndWaitLocked()
		return errors.Join(fmt.Errorf("%w: acknowledgement binding mismatch", ErrProcessSidecarProtocol), killErr)
	}
	if ack.Status == "ok" {
		if ack.ErrorCode != "" {
			killErr := p.killAndWaitLocked()
			return errors.Join(fmt.Errorf("%w: success acknowledgement contains error", ErrProcessSidecarProtocol), killErr)
		}
		return nil
	}
	if ack.Status == "error" && validProcessErrorCode(ack.ErrorCode) {
		killErr := p.killAndWaitLocked()
		return errors.Join(fmt.Errorf("%w: child rejected %s with %s", ErrProcessSidecarProtocol, operation, ack.ErrorCode), killErr)
	}
	killErr := p.killAndWaitLocked()
	return errors.Join(fmt.Errorf("%w: invalid acknowledgement status", ErrProcessSidecarProtocol), killErr)
}

func (p *processSidecarProcess) readAcknowledgement() (processSidecarAcknowledgement, error) {
	line, err := p.stdout.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) || len(line) > p.backend.maxMessageBytes {
		return processSidecarAcknowledgement{}, fmt.Errorf("message exceeds %d bytes", p.backend.maxMessageBytes)
	}
	if err != nil {
		return processSidecarAcknowledgement{}, err
	}
	if len(bytes.TrimSpace(line)) == 0 {
		return processSidecarAcknowledgement{}, errors.New("empty acknowledgement")
	}
	if err := validateProcessAcknowledgementShape(line); err != nil {
		return processSidecarAcknowledgement{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	var acknowledgement processSidecarAcknowledgement
	if err := decoder.Decode(&acknowledgement); err != nil {
		return processSidecarAcknowledgement{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return processSidecarAcknowledgement{}, errors.New("trailing JSON value")
		}
		return processSidecarAcknowledgement{}, fmt.Errorf("trailing JSON: %w", err)
	}
	return acknowledgement, nil
}

func validateProcessAcknowledgementShape(line []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(line))
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok || delimiter != '{' {
		return errors.New("acknowledgement must be a JSON object")
	}
	allowed := map[string]bool{
		"schema_version": false,
		"sequence":       false,
		"operation":      false,
		"status":         false,
		"mode":           false,
		"error_code":     true,
	}
	seen := make(map[string]struct{}, len(allowed))
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return err
		}
		key, ok := keyToken.(string)
		if !ok {
			return errors.New("acknowledgement key is not a string")
		}
		_, known := allowed[key]
		if !known {
			return fmt.Errorf("unknown acknowledgement field %q", key)
		}
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("duplicate acknowledgement field %q", key)
		}
		seen[key] = struct{}{}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return err
		}
	}
	if _, err := decoder.Token(); err != nil {
		return err
	}
	for key, optional := range allowed {
		if _, present := seen[key]; !present && !optional {
			return fmt.Errorf("missing acknowledgement field %q", key)
		}
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return fmt.Errorf("trailing JSON: %w", err)
	}
	return nil
}

func (p *processSidecarProcess) exitedErrorLocked() error {
	select {
	case <-p.done:
		return p.exitedError()
	default:
		return nil
	}
}

func (p *processSidecarProcess) exitedError() error {
	p.waitMu.Lock()
	err := p.waitErr
	p.waitMu.Unlock()
	if err == nil {
		return ErrProcessSidecarExited
	}
	return fmt.Errorf("%w: %v", ErrProcessSidecarExited, err)
}

func (p *processSidecarProcess) waitForExitLocked(ctx context.Context, timeout time.Duration) error {
	if ctx == nil {
		ctx = context.Background()
	}
	waitContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	select {
	case <-p.done:
		p.waitMu.Lock()
		err := p.waitErr
		p.waitMu.Unlock()
		if err != nil {
			return fmt.Errorf("%w: graceful exit: %v", ErrProcessSidecarExited, err)
		}
		return nil
	case <-waitContext.Done():
		return fmt.Errorf("%w: graceful stop: %w", ErrProcessSidecarProtocol, waitContext.Err())
	}
}

func (p *processSidecarProcess) killAndWaitLocked() error {
	_ = p.stdin.Close()
	select {
	case <-p.done:
		return nil
	default:
	}
	if err := killProcessSidecarCommand(p.cmd); err != nil {
		select {
		case <-p.done:
			return nil
		default:
			return fmt.Errorf("force kill: %w", err)
		}
	}
	<-p.done
	return nil
}

func processIdentityForSpec(spec SidecarLaunchSpec) ProcessSidecarIdentity {
	return ProcessSidecarIdentity{
		PluginID: spec.Descriptor.PluginID, Namespace: spec.Descriptor.Namespace,
		Version: spec.Descriptor.Version, ManifestIdentity: spec.Descriptor.ManifestIdentity,
		ArtifactIdentity: spec.Descriptor.ArtifactIdentity,
	}
}

func validateAndCloneProcessRegistryEntry(entry ProcessSidecarRegistryEntry) (ProcessSidecarRegistryEntry, error) {
	if !validTransportField(entry.Identity.PluginID, 128) || !validTransportField(entry.Identity.Namespace, 256) || !validTransportField(entry.Identity.Version, 128) || !validHexDigest(entry.Identity.ManifestIdentity) || !validHexDigest(entry.Identity.ArtifactIdentity) {
		return ProcessSidecarRegistryEntry{}, errors.New("identity is invalid")
	}
	if len(entry.Args) > maxProcessArguments {
		return ProcessSidecarRegistryEntry{}, fmt.Errorf("argument count exceeds %d", maxProcessArguments)
	}
	argumentBytes := 0
	for _, argument := range entry.Args {
		if strings.IndexByte(argument, 0) >= 0 || len(argument) > 4096 {
			return ProcessSidecarRegistryEntry{}, errors.New("argument contains NUL or exceeds 4096 bytes")
		}
		argumentBytes += len(argument)
	}
	if argumentBytes > maxProcessArgumentBytes {
		return ProcessSidecarRegistryEntry{}, fmt.Errorf("arguments exceed %d bytes", maxProcessArgumentBytes)
	}
	environmentBytes := 0
	for key, value := range entry.Environment {
		if !validProcessEnvironmentKey(key) || strings.IndexByte(value, 0) >= 0 || len(value) > 16384 {
			return ProcessSidecarRegistryEntry{}, fmt.Errorf("environment entry %q is invalid", key)
		}
		environmentBytes += len(key) + len(value) + 2
	}
	if environmentBytes > maxProcessEnvironmentBytes {
		return ProcessSidecarRegistryEntry{}, fmt.Errorf("environment exceeds %d bytes", maxProcessEnvironmentBytes)
	}
	cloned := cloneProcessRegistryEntry(entry)
	if cloned.WorkingDirectory == "" && filepath.IsAbs(cloned.Executable) {
		cloned.WorkingDirectory = filepath.Dir(cloned.Executable)
	}
	if err := validateProcessLaunchPaths(cloned); err != nil {
		return ProcessSidecarRegistryEntry{}, err
	}
	return cloned, nil
}

func validateProcessLaunchPaths(entry ProcessSidecarRegistryEntry) error {
	if err := validateSecureProcessPath(entry.Executable, false); err != nil {
		return fmt.Errorf("executable: %w", err)
	}
	if err := validateSecureProcessPath(entry.WorkingDirectory, true); err != nil {
		return fmt.Errorf("working directory: %w", err)
	}
	return nil
}

func validateSecureProcessPath(path string, directory bool) error {
	if err := validateProcessPathSecuritySupported(); err != nil {
		return err
	}
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("path must be clean and absolute")
	}
	current := path
	first := true
	for {
		info, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("inspect %q: %w", current, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("path component %q is a symlink", current)
		}
		if first && !directory {
			if !info.Mode().IsRegular() {
				return errors.New("executable is not a regular file")
			}
			if err := validateProcessExecutableMode(info.Mode()); err != nil {
				return err
			}
			if info.Mode().Perm()&0o022 != 0 {
				return fmt.Errorf("executable is group/world writable (mode %04o)", info.Mode().Perm())
			}
		} else {
			if !info.IsDir() {
				return fmt.Errorf("path component %q is not a directory", current)
			}
			if info.Mode().Perm()&0o022 != 0 {
				return fmt.Errorf("directory %q is group/world writable (mode %04o)", current, info.Mode().Perm())
			}
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
		first = false
	}
	return nil
}

func cloneProcessRegistryEntry(entry ProcessSidecarRegistryEntry) ProcessSidecarRegistryEntry {
	entry.Args = append([]string(nil), entry.Args...)
	if entry.Environment != nil {
		environment := make(map[string]string, len(entry.Environment))
		for key, value := range entry.Environment {
			environment[key] = value
		}
		entry.Environment = environment
	}
	return entry
}

func processEnvironment(environment map[string]string) []string {
	keys := make([]string, 0, len(environment))
	for key := range environment {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]string, 0, len(keys))
	for _, key := range keys {
		result = append(result, key+"="+environment[key])
	}
	return result
}

func validProcessEnvironmentKey(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for i, r := range value {
		if r == '_' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || i > 0 && r >= '0' && r <= '9' {
			continue
		}
		return false
	}
	return true
}

func validProcessErrorCode(value string) bool {
	if !validTransportField(value, 128) {
		return false
	}
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}
