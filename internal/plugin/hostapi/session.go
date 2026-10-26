package hostapi

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

var (
	ErrSessionState  = errors.New("plugin host session is not ready")
	ErrHandshake     = errors.New("plugin host handshake failed")
	ErrSessionClosed = errors.New("plugin host session is closed")
	ErrProtocol      = errors.New("plugin host protocol violation")
	ErrAckTimeout    = errors.New("plugin host acknowledgement timed out")
	ErrAckRejected   = errors.New("plugin host request was rejected")
	ErrResultBacklog = errors.New("plugin host result backlog is full")
)

// State is the host-side session lifecycle.
type State string

const (
	StateNew         State = "new"
	StateHandshaking State = "handshaking"
	StateReady       State = "ready"
	StateDraining    State = "draining"
	StateClosed      State = "closed"
	StateFailed      State = "failed"
)

// HelloPayload is sent by the host before any capability is active.
type HelloPayload struct {
	Challenge     string       `json:"challenge"`
	Plugin        Identity     `json:"plugin"`
	Capabilities  []Capability `json:"capabilities"`
	MaxFrameBytes int          `json:"max_frame_bytes"`
}

// ReadyPayload is the plugin's handshake response. The plugin must echo the
// challenge and may only accept a subset of the host-granted capabilities.
type ReadyPayload struct {
	Challenge            string       `json:"challenge"`
	PluginID             string       `json:"plugin_id"`
	Version              string       `json:"version"`
	AcceptedCapabilities []Capability `json:"accepted_capabilities"`
}

// Config is a non-secret configuration revision.
type Config struct {
	Revision uint64         `json:"revision"`
	Values   map[string]any `json:"values"`
}

// ConfigAck is the plugin's response to a config frame.
type ConfigAck struct {
	Revision  uint64    `json:"revision"`
	Accepted  bool      `json:"accepted"`
	ErrorCode ErrorCode `json:"error_code,omitempty"`
}

// ResultKind classifies a plugin-originated frame.
type ResultKind string

const (
	ResultHint     ResultKind = "hint"
	ResultAnalysis ResultKind = "analysis"
	ResultHealth   ResultKind = "health"
	ResultError    ResultKind = "error"
)

// Result is a validated-by-shape plugin frame delivered to the host consumer.
// Semantic validation and attestation happen outside this package.
type Result struct {
	Kind     ResultKind
	Sequence uint64
	Payload  json.RawMessage
}

// SessionOptions configures one host-side session.
type SessionOptions struct {
	Identity      Identity
	Capabilities  []Capability
	Challenge     []byte
	MaxFrameBytes int
	AckTimeout    time.Duration
}

// Session is the host side of the local plugin data plane. It is not safe to
// call Start more than once; all other exported methods are safe for
// concurrent use after Start.
type Session struct {
	in  io.Reader
	out io.WriteCloser

	reader *bufio.Reader
	opts   SessionOptions

	writeMu sync.Mutex
	mu      sync.Mutex
	state   State
	nextSeq uint64
	pending map[uint64]chan Frame
	drainCh chan struct{}
	results chan Result
	done    chan struct{}
	close   sync.Once
	err     error
}

func helloFrame(payload HelloPayload) Frame {
	raw, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}
	return Frame{Type: FrameHello, SchemaVersion: ProtocolVersion, Payload: raw}
}

// NewSession creates a session in StateNew.
func NewSession(in io.Reader, out io.WriteCloser, opts SessionOptions) (*Session, error) {
	if in == nil || out == nil {
		return nil, fmt.Errorf("%w: reader and writer are required", ErrHandshake)
	}
	if opts.Identity.PluginID == "" || opts.Identity.Version == "" {
		return nil, fmt.Errorf("%w: plugin identity is required", ErrHandshake)
	}
	if opts.MaxFrameBytes <= 0 {
		opts.MaxFrameBytes = MaxFrameBytes
	}
	if opts.AckTimeout <= 0 {
		opts.AckTimeout = 10 * time.Second
	}
	if len(opts.Challenge) == 0 {
		challenge := make([]byte, 32)
		if _, err := rand.Read(challenge); err != nil {
			return nil, err
		}
		opts.Challenge = challenge
	}
	for _, capability := range opts.Capabilities {
		if !capability.Valid() {
			return nil, fmt.Errorf("%w: capability %q", ErrHandshake, capability)
		}
	}
	return &Session{
		in:      in,
		out:     out,
		reader:  bufio.NewReaderSize(in, opts.MaxFrameBytes+1),
		opts:    opts,
		state:   StateNew,
		nextSeq: 1,
		pending: make(map[uint64]chan Frame),
		drainCh: make(chan struct{}),
		results: make(chan Result, 256),
		done:    make(chan struct{}),
	}, nil
}

// State returns the current lifecycle state.
func (s *Session) State() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

// Results returns plugin-originated frames. The channel is closed when the
// session ends.
func (s *Session) Results() <-chan Result { return s.results }

// Start performs the challenge/response handshake and starts the read loop.
func (s *Session) Start(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	s.mu.Lock()
	if s.state != StateNew {
		s.mu.Unlock()
		return fmt.Errorf("%w: start from %s", ErrSessionState, s.state)
	}
	s.state = StateHandshaking
	challenge := base64.StdEncoding.EncodeToString(s.opts.Challenge)
	hello := helloFrame(HelloPayload{
		Challenge:     challenge,
		Plugin:        s.opts.Identity,
		Capabilities:  append([]Capability(nil), s.opts.Capabilities...),
		MaxFrameBytes: s.opts.MaxFrameBytes,
	})
	s.mu.Unlock()
	if err := s.writeFrameContext(ctx, hello); err != nil {
		return err
	}

	type readResult struct {
		frame Frame
		err   error
	}
	readyCh := make(chan readResult, 1)
	go func() {
		frame, err := s.readFrame()
		readyCh <- readResult{frame: frame, err: err}
	}()
	var first readResult
	select {
	case first = <-readyCh:
	case <-ctx.Done():
		s.fail(ctx.Err())
		return ctx.Err()
	case <-s.done:
		return ErrSessionClosed
	}
	if first.err != nil {
		s.fail(first.err)
		return first.err
	}
	if first.frame.Type != FrameReady {
		err := fmt.Errorf("%w: expected ready, got %s", ErrHandshake, first.frame.Type)
		s.fail(err)
		return err
	}
	var ready ReadyPayload
	if err := json.Unmarshal(first.frame.Payload, &ready); err != nil {
		s.fail(err)
		return fmt.Errorf("%w: %v", ErrHandshake, err)
	}
	if ready.Challenge != challenge {
		err := fmt.Errorf("%w: challenge mismatch", ErrHandshake)
		s.fail(err)
		return err
	}
	if ready.PluginID != s.opts.Identity.PluginID || ready.Version != s.opts.Identity.Version {
		err := fmt.Errorf("%w: identity mismatch", ErrHandshake)
		s.fail(err)
		return err
	}
	if err := validateAcceptedCapabilities(s.opts.Capabilities, ready.AcceptedCapabilities); err != nil {
		s.fail(err)
		return err
	}

	s.mu.Lock()
	if s.state != StateHandshaking {
		s.mu.Unlock()
		return fmt.Errorf("%w: state changed during handshake", ErrSessionState)
	}
	s.state = StateReady
	s.mu.Unlock()
	go s.readLoop()
	return nil
}

func validateAcceptedCapabilities(granted, accepted []Capability) error {
	allowed := make(map[Capability]struct{}, len(granted))
	for _, capability := range granted {
		allowed[capability] = struct{}{}
	}
	seen := make(map[Capability]struct{}, len(accepted))
	for _, capability := range accepted {
		if !capability.Valid() {
			return fmt.Errorf("%w: unknown capability %q", ErrHandshake, capability)
		}
		if _, ok := allowed[capability]; !ok {
			return fmt.Errorf("%w: capability %q was not granted", ErrHandshake, capability)
		}
		if _, duplicate := seen[capability]; duplicate {
			return fmt.Errorf("%w: duplicate capability %q", ErrHandshake, capability)
		}
		seen[capability] = struct{}{}
	}
	return nil
}

// SendEvent sends one event and waits for event_ack.
func (s *Session) SendEvent(ctx context.Context, payload json.RawMessage) error {
	return s.sendAndWait(ctx, FrameEvent, payload, FrameEventAck)
}

// SendJob sends one DuckDB job and waits for job_ack.
func (s *Session) SendJob(ctx context.Context, payload json.RawMessage) error {
	return s.sendAndWait(ctx, FrameJob, payload, FrameJobAck)
}

// SendConfig sends a config revision and waits for config_ack.
func (s *Session) SendConfig(ctx context.Context, cfg Config) error {
	payload, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	return s.sendAndWait(ctx, FrameConfig, payload, FrameConfigAck)
}

// SendHintReceipt acknowledges a plugin hint.
func (s *Session) SendHintReceipt(ctx context.Context, sequence uint64, accepted bool, code ErrorCode) error {
	return s.sendOneWay(ctx, FrameHintReceipt, sequence, map[string]any{"accepted": accepted, "error_code": code})
}

// SendAnalysisReceipt acknowledges a plugin analysis record.
func (s *Session) SendAnalysisReceipt(ctx context.Context, sequence uint64, accepted bool, code ErrorCode) error {
	return s.sendOneWay(ctx, FrameAnalysisReceipt, sequence, map[string]any{"accepted": accepted, "error_code": code})
}

// Drain asks the plugin to stop accepting events, flush, and report drained.
func (s *Session) Drain(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	s.mu.Lock()
	if s.state != StateReady {
		s.mu.Unlock()
		return fmt.Errorf("%w: drain from %s", ErrSessionState, s.state)
	}
	s.state = StateDraining
	sequence := s.nextSeq
	s.nextSeq++
	s.mu.Unlock()
	if err := s.writeFrameContext(ctx, Frame{Type: FrameDrain, SchemaVersion: ProtocolVersion, Sequence: sequence}); err != nil {
		return err
	}
	select {
	case <-s.drainCh:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-s.done:
		return ErrSessionClosed
	}
}

// Shutdown sends the final shutdown frame. It does not wait for an ack.
func (s *Session) Shutdown(ctx context.Context) error {
	return s.sendOneWay(ctx, FrameShutdown, 0, nil)
}

func (s *Session) sendAndWait(ctx context.Context, frameType FrameType, payload json.RawMessage, ackType FrameType) error {
	if ctx == nil {
		ctx = context.Background()
	}
	s.mu.Lock()
	if s.state != StateReady {
		s.mu.Unlock()
		return fmt.Errorf("%w: send from %s", ErrSessionState, s.state)
	}
	sequence := s.nextSeq
	s.nextSeq++
	ackCh := make(chan Frame, 1)
	s.pending[sequence] = ackCh
	s.mu.Unlock()

	if err := s.writeFrameContext(ctx, Frame{Type: frameType, SchemaVersion: ProtocolVersion, Sequence: sequence, Payload: payload}); err != nil {
		s.dropPending(sequence)
		return err
	}
	select {
	case ack := <-ackCh:
		if ack.Type != ackType {
			s.fail(fmt.Errorf("%w: ack %s for %s", ErrProtocol, ack.Type, frameType))
			return ErrProtocol
		}
		err := ackVerdict(ackType, ack.Payload)
		if errors.Is(err, ErrProtocol) {
			s.fail(err)
		}
		return err
	case <-time.After(s.opts.AckTimeout):
		s.dropPending(sequence)
		s.fail(ErrAckTimeout)
		return ErrAckTimeout
	case <-ctx.Done():
		s.dropPending(sequence)
		return ctx.Err()
	case <-s.done:
		return ErrSessionClosed
	}
}

func (s *Session) sendOneWay(ctx context.Context, frameType FrameType, sequence uint64, payload any) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	if s.state != StateReady && s.state != StateDraining {
		s.mu.Unlock()
		return fmt.Errorf("%w: send from %s", ErrSessionState, s.state)
	}
	if sequence == 0 {
		sequence = s.nextSeq
		s.nextSeq++
	}
	s.mu.Unlock()
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return s.writeFrameContext(ctx, Frame{Type: frameType, SchemaVersion: ProtocolVersion, Sequence: sequence, Payload: raw})
}

// ackVerdict interprets a plugin acknowledgement payload. The plugin reports
// handler failures as accepted:false instead of a protocol error, so a matching
// frame type alone does not mean the host request succeeded.
func ackVerdict(ackType FrameType, payload json.RawMessage) error {
	var body struct {
		Accepted  *bool     `json:"accepted"`
		ErrorCode ErrorCode `json:"error_code"`
	}
	if err := json.Unmarshal(payload, &body); err != nil {
		return fmt.Errorf("%w: %s payload: %v", ErrProtocol, ackType, err)
	}
	if body.Accepted == nil {
		return fmt.Errorf("%w: %s payload has no accepted field", ErrProtocol, ackType)
	}
	if *body.Accepted {
		return nil
	}
	if body.ErrorCode == "" {
		return fmt.Errorf("%w: %s rejected the request", ErrAckRejected, ackType)
	}
	return fmt.Errorf("%w: %s rejected the request with %s", ErrAckRejected, ackType, body.ErrorCode)
}

func (s *Session) writeFrameContext(ctx context.Context, frame Frame) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	raw, err := EncodeFrame(frame, s.opts.MaxFrameBytes)
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	written := make(chan error, 1)
	go func() {
		s.writeMu.Lock()
		defer s.writeMu.Unlock()
		_, err := s.out.Write(raw)
		written <- err
	}()
	select {
	case err := <-written:
		if err != nil {
			s.fail(err)
		}
		return err
	case <-ctx.Done():
		// A blocked pipe write cannot observe ctx, so the only way to release
		// it is to close the owned connection. The interrupted frame may be
		// partially written, which leaves the stream unusable.
		s.fail(ctx.Err())
		return ctx.Err()
	}
}

func (s *Session) readFrame() (Frame, error) {
	line, err := s.reader.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) || len(line) > s.opts.MaxFrameBytes+1 {
		return Frame{}, ErrFrameTooLarge
	}
	if err != nil {
		return Frame{}, err
	}
	if len(bytes.TrimSpace(line)) == 0 {
		return Frame{}, fmt.Errorf("%w: empty frame", ErrInvalidFrame)
	}
	return DecodeFrame(bytes.TrimSuffix(line, []byte{'\n'}), s.opts.MaxFrameBytes)
}

func (s *Session) readLoop() {
	defer s.closeResults()
	for {
		frame, err := s.readFrame()
		if err != nil {
			s.fail(err)
			return
		}
		if err := s.dispatch(frame); err != nil {
			s.fail(err)
			return
		}
	}
}

func (s *Session) dispatch(frame Frame) error {
	switch frame.Type {
	case FrameEventAck, FrameJobAck, FrameConfigAck:
		s.mu.Lock()
		ackCh := s.pending[frame.Sequence]
		delete(s.pending, frame.Sequence)
		s.mu.Unlock()
		if ackCh == nil {
			return fmt.Errorf("%w: unexpected ack sequence %d", ErrProtocol, frame.Sequence)
		}
		ackCh <- frame
		return nil
	case FrameHint:
		return s.publish(Result{Kind: ResultHint, Sequence: frame.Sequence, Payload: frame.Payload})
	case FrameAnalysis:
		return s.publish(Result{Kind: ResultAnalysis, Sequence: frame.Sequence, Payload: frame.Payload})
	case FrameHealth:
		return s.publish(Result{Kind: ResultHealth, Sequence: frame.Sequence, Payload: frame.Payload})
	case FrameError:
		return s.publish(Result{Kind: ResultError, Sequence: frame.Sequence, Payload: frame.Payload})
	case FrameDrained:
		select {
		case <-s.drainCh:
		default:
			close(s.drainCh)
		}
		return nil
	default:
		return fmt.Errorf("%w: unexpected frame %s", ErrProtocol, frame.Type)
	}
}

func (s *Session) publish(result Result) error {
	select {
	case s.results <- result:
		return nil
	default:
		return ErrResultBacklog
	}
}

func (s *Session) dropPending(sequence uint64) {
	s.mu.Lock()
	delete(s.pending, sequence)
	s.mu.Unlock()
}

func (s *Session) fail(err error) {
	if err == nil {
		err = ErrSessionClosed
	}
	s.mu.Lock()
	if s.state == StateClosed || s.state == StateFailed {
		s.mu.Unlock()
		return
	}
	s.state = StateFailed
	s.err = err
	s.mu.Unlock()
	s.close.Do(func() {
		close(s.done)
		_ = s.out.Close()
		if closer, ok := s.in.(io.Closer); ok {
			_ = closer.Close()
		}
	})
}

func (s *Session) closeResults() {
	s.close.Do(func() {
		close(s.done)
		_ = s.out.Close()
		if closer, ok := s.in.(io.Closer); ok {
			_ = closer.Close()
		}
	})
	s.mu.Lock()
	if s.state != StateFailed {
		s.state = StateClosed
	}
	s.mu.Unlock()
	close(s.results)
}

// Close closes the session. It is idempotent.
func (s *Session) Close() error {
	s.fail(ErrSessionClosed)
	return nil
}

// Err returns the terminal session error, if any.
func (s *Session) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}
