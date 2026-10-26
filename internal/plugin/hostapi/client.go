package hostapi

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
)

var (
	ErrClientState = errors.New("plugin host client is not ready")
	ErrClientHello = errors.New("plugin host client rejected hello")
)

// ClientOptions configures one plugin-side session.
type ClientOptions struct {
	Identity      Identity
	Capabilities  []Capability
	MaxFrameBytes int
}

// Handler receives host-originated requests. Returning an error is reported to
// the host as a rejected acknowledgement; the client keeps running unless the
// error is ErrClientState.
type Handler interface {
	OnConfig(context.Context, Config) error
	OnEvent(context.Context, json.RawMessage) error
	OnJob(context.Context, json.RawMessage) error
	OnDrain(context.Context) error
	OnShutdown(context.Context) error
}

// Receipt is the plugin-side view of a host receipt for a hint/analysis frame.
type Receipt struct {
	Kind     ResultKind
	Sequence uint64
	Accepted bool
	Code     ErrorCode
}

// Client is the plugin side of the local data plane.
type Client struct {
	in  io.Reader
	out io.WriteCloser

	reader *bufio.Reader
	opts   ClientOptions

	writeMu  sync.Mutex
	mu       sync.Mutex
	state    State
	nextSeq  uint64
	receipts chan Receipt
	done     chan struct{}
	close    sync.Once
	err      error
}

// NewClient creates a client in StateNew.
func NewClient(in io.Reader, out io.WriteCloser, opts ClientOptions) (*Client, error) {
	if in == nil || out == nil {
		return nil, fmt.Errorf("%w: reader and writer are required", ErrClientHello)
	}
	if opts.Identity.PluginID == "" || opts.Identity.Version == "" {
		return nil, fmt.Errorf("%w: plugin identity is required", ErrClientHello)
	}
	if opts.MaxFrameBytes <= 0 {
		opts.MaxFrameBytes = MaxFrameBytes
	}
	for _, capability := range opts.Capabilities {
		if !capability.Valid() {
			return nil, fmt.Errorf("%w: capability %q", ErrClientHello, capability)
		}
	}
	return &Client{
		in:       in,
		out:      out,
		reader:   bufio.NewReaderSize(in, opts.MaxFrameBytes+1),
		opts:     opts,
		state:    StateNew,
		nextSeq:  1,
		receipts: make(chan Receipt, 64),
		done:     make(chan struct{}),
	}, nil
}

// State returns the current client lifecycle state.
func (c *Client) State() State {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

// Receipts returns hint/analysis receipts from the host.
func (c *Client) Receipts() <-chan Receipt { return c.receipts }

// Run performs the handshake and processes host frames until shutdown, error,
// or context cancellation.
func (c *Client) Run(ctx context.Context, handler Handler) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if handler == nil {
		return fmt.Errorf("%w: handler is required", ErrClientHello)
	}
	c.mu.Lock()
	if c.state != StateNew {
		c.mu.Unlock()
		return fmt.Errorf("%w: run from %s", ErrClientState, c.state)
	}
	c.state = StateHandshaking
	c.mu.Unlock()
	// Run is the single writer to receipts, so closing it here cannot race a
	// send and lets consumers range over Receipts until the session ends.
	defer close(c.receipts)
	// A blocked read on an owned pipe never observes ctx, so cancellation has
	// to tear the connection down to make readFrame return.
	stopCancellation := context.AfterFunc(ctx, func() { c.fail(ctx.Err()) })
	defer stopCancellation()

	first, err := c.readFrame()
	if err != nil {
		return c.failRun(ctx, err)
	}
	if first.Type != FrameHello {
		return c.failRun(ctx, fmt.Errorf("%w: expected hello, got %s", ErrClientHello, first.Type))
	}
	var hello HelloPayload
	if err := json.Unmarshal(first.Payload, &hello); err != nil {
		return c.failRun(ctx, fmt.Errorf("%w: %v", ErrClientHello, err))
	}
	if hello.Plugin.PluginID != c.opts.Identity.PluginID || hello.Plugin.Version != c.opts.Identity.Version || hello.Plugin.Namespace != c.opts.Identity.Namespace {
		return c.failRun(ctx, fmt.Errorf("%w: host identity mismatch", ErrClientHello))
	}
	accepted, err := negotiateClientCapabilities(c.opts.Capabilities, hello.Capabilities)
	if err != nil {
		return c.failRun(ctx, err)
	}
	ready := Frame{
		Type: FrameReady, SchemaVersion: ProtocolVersion,
		Payload: mustMarshal(ReadyPayload{
			Challenge: hello.Challenge, PluginID: c.opts.Identity.PluginID,
			Version: c.opts.Identity.Version, AcceptedCapabilities: accepted,
		}),
	}
	if err := c.writeFrame(ready); err != nil {
		return c.failRun(ctx, err)
	}
	c.mu.Lock()
	c.state = StateReady
	c.mu.Unlock()

	for {
		frame, err := c.readFrame()
		if err != nil {
			return c.failRun(ctx, err)
		}
		if err := c.dispatch(ctx, handler, frame); err != nil {
			return c.failRun(ctx, err)
		}
		if frame.Type == FrameShutdown {
			c.closeSession()
			return nil
		}
	}
}

// failRun records the terminal error. When cancellation tore the connection
// down under a blocked read or write, the context cause is the real reason and
// the transport error is only its symptom.
func (c *Client) failRun(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		c.fail(ctxErr)
		return ctxErr
	}
	c.fail(err)
	return err
}

func negotiateClientCapabilities(requested, granted []Capability) ([]Capability, error) {
	grantedSet := make(map[Capability]struct{}, len(granted))
	for _, capability := range granted {
		if !capability.Valid() {
			return nil, fmt.Errorf("%w: host granted unknown capability %q", ErrClientHello, capability)
		}
		grantedSet[capability] = struct{}{}
	}
	if len(requested) == 0 {
		return append([]Capability(nil), granted...), nil
	}
	accepted := make([]Capability, 0, len(requested))
	for _, capability := range requested {
		if _, ok := grantedSet[capability]; !ok {
			return nil, fmt.Errorf("%w: host did not grant %q", ErrClientHello, capability)
		}
		accepted = append(accepted, capability)
	}
	return accepted, nil
}

func (c *Client) dispatch(ctx context.Context, handler Handler, frame Frame) error {
	switch frame.Type {
	case FrameConfig:
		var cfg Config
		if err := json.Unmarshal(frame.Payload, &cfg); err != nil {
			return fmt.Errorf("%w: config: %v", ErrProtocol, err)
		}
		if err := handler.OnConfig(ctx, cfg); err != nil {
			return c.ack(FrameConfigAck, frame.Sequence, ConfigAck{Revision: cfg.Revision, Accepted: false, ErrorCode: ErrorPlugin})
		}
		return c.ack(FrameConfigAck, frame.Sequence, ConfigAck{Revision: cfg.Revision, Accepted: true})
	case FrameEvent:
		if err := handler.OnEvent(ctx, frame.Payload); err != nil {
			return c.ack(FrameEventAck, frame.Sequence, EventAck{Sequence: frame.Sequence, Accepted: false, ErrorCode: ErrorPlugin})
		}
		return c.ack(FrameEventAck, frame.Sequence, EventAck{Sequence: frame.Sequence, Accepted: true})
	case FrameJob:
		if err := handler.OnJob(ctx, frame.Payload); err != nil {
			return c.ack(FrameJobAck, frame.Sequence, JobAck{Sequence: frame.Sequence, Accepted: false, ErrorCode: ErrorPlugin})
		}
		return c.ack(FrameJobAck, frame.Sequence, JobAck{Sequence: frame.Sequence, Accepted: true})
	case FrameDrain:
		if err := handler.OnDrain(ctx); err != nil {
			return err
		}
		return c.writeFrame(Frame{Type: FrameDrained, SchemaVersion: ProtocolVersion, Sequence: frame.Sequence})
	case FrameShutdown:
		return handler.OnShutdown(ctx)
	case FrameHintReceipt:
		return c.publishReceipt(ResultHint, frame)
	case FrameAnalysisReceipt:
		return c.publishReceipt(ResultAnalysis, frame)
	case FrameError:
		return fmt.Errorf("%w: host error", ErrProtocol)
	default:
		return fmt.Errorf("%w: unexpected frame %s", ErrProtocol, frame.Type)
	}
}

// EventAck is the plugin's acknowledgement of one event frame.
type EventAck struct {
	Sequence  uint64    `json:"sequence"`
	Accepted  bool      `json:"accepted"`
	ErrorCode ErrorCode `json:"error_code,omitempty"`
}

// JobAck is the plugin's acknowledgement of one job frame.
type JobAck struct {
	Sequence  uint64    `json:"sequence"`
	Accepted  bool      `json:"accepted"`
	ErrorCode ErrorCode `json:"error_code,omitempty"`
}

func (c *Client) ack(frameType FrameType, sequence uint64, payload any) error {
	return c.writeFrame(Frame{Type: frameType, SchemaVersion: ProtocolVersion, Sequence: sequence, Payload: mustMarshal(payload)})
}

func (c *Client) publishReceipt(kind ResultKind, frame Frame) error {
	var body struct {
		Accepted  bool      `json:"accepted"`
		ErrorCode ErrorCode `json:"error_code"`
	}
	if err := json.Unmarshal(frame.Payload, &body); err != nil {
		return fmt.Errorf("%w: receipt: %v", ErrProtocol, err)
	}
	select {
	case c.receipts <- Receipt{Kind: kind, Sequence: frame.Sequence, Accepted: body.Accepted, Code: body.ErrorCode}:
	default:
		return ErrResultBacklog
	}
	return nil
}

// SendHint sends one hint draft to the host. The host validates and attests it.
func (c *Client) SendHint(payload json.RawMessage) error {
	return c.sendPluginFrame(FrameHint, payload)
}

// SendAnalysis sends one analysis draft to the host.
func (c *Client) SendAnalysis(payload json.RawMessage) error {
	return c.sendPluginFrame(FrameAnalysis, payload)
}

// SendHealth reports plugin health.
func (c *Client) SendHealth(payload json.RawMessage) error {
	return c.sendPluginFrame(FrameHealth, payload)
}

func (c *Client) sendPluginFrame(frameType FrameType, payload json.RawMessage) error {
	c.mu.Lock()
	if c.state != StateReady && c.state != StateDraining {
		c.mu.Unlock()
		return fmt.Errorf("%w: send from %s", ErrClientState, c.state)
	}
	sequence := c.nextSeq
	c.nextSeq++
	c.mu.Unlock()
	return c.writeFrame(Frame{Type: frameType, SchemaVersion: ProtocolVersion, Sequence: sequence, Payload: payload})
}

func (c *Client) writeFrame(frame Frame) error {
	raw, err := EncodeFrame(frame, c.opts.MaxFrameBytes)
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	_, err = c.out.Write(raw)
	return err
}

func (c *Client) readFrame() (Frame, error) {
	line, err := c.reader.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) || len(line) > c.opts.MaxFrameBytes+1 {
		return Frame{}, ErrFrameTooLarge
	}
	if err != nil {
		return Frame{}, err
	}
	if len(bytes.TrimSpace(line)) == 0 {
		return Frame{}, fmt.Errorf("%w: empty frame", ErrInvalidFrame)
	}
	return DecodeFrame(bytes.TrimSuffix(line, []byte{'\n'}), c.opts.MaxFrameBytes)
}

func (c *Client) fail(err error) {
	if err == nil {
		err = ErrSessionClosed
	}
	c.mu.Lock()
	if c.state == StateClosed || c.state == StateFailed {
		c.mu.Unlock()
		return
	}
	c.state = StateFailed
	c.err = err
	c.mu.Unlock()
	c.closeSession()
}

func (c *Client) closeSession() {
	c.mu.Lock()
	if c.state != StateFailed {
		c.state = StateClosed
	}
	c.mu.Unlock()
	c.close.Do(func() {
		close(c.done)
		_ = c.out.Close()
		if closer, ok := c.in.(io.Closer); ok {
			_ = closer.Close()
		}
	})
}

// Close closes the client. It is idempotent.
func (c *Client) Close() error {
	c.fail(ErrSessionClosed)
	return nil
}

// Err returns the terminal client error, if any.
func (c *Client) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

func mustMarshal(value any) json.RawMessage {
	raw, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return raw
}

// drainReceipts consumes acknowledgements until the channel closes and reports
// the rejected ones. It is separate so the drain contract is testable without
// standing up a full data-plane session.
func drainReceipts(receipts <-chan Receipt, label string, log io.Writer) {
	for receipt := range receipts {
		if receipt.Accepted || log == nil {
			continue
		}
		fmt.Fprintf(log, "%s: host rejected %s receipt %d: %s\n", label, receipt.Kind, receipt.Sequence, receipt.Code)
	}
}

// StartDataPlane runs the client until the context is cancelled or the host
// shuts the session down, and drains the receipt stream for the same lifetime.
// A receipt acknowledges a hint or analysis draft; the client refuses further
// work once 64 receipts queue up, so an undrained stream would disconnect the
// sidecar at receipt 65 while its lifecycle process stayed alive. Rejections
// are written to log instead of being dropped silently.
func StartDataPlane(ctx context.Context, client *Client, handler Handler, label string, log io.Writer) {
	if client == nil {
		return
	}
	go func() {
		drained := make(chan struct{})
		go func() {
			defer close(drained)
			drainReceipts(client.Receipts(), label, log)
		}()
		if err := client.Run(ctx, handler); err != nil && ctx.Err() == nil && log != nil {
			fmt.Fprintf(log, "%s: %v\n", label, err)
		}
		// Run closes the receipt channel, so this only waits for the last
		// queued acknowledgements to be reported.
		<-drained
	}()
}
