package redis

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// PoolConfig configures the small RESP2 connection pool used by RuntimeAdapter.
// It intentionally exposes only the settings needed by the short-state adapter;
// callers cannot inject arbitrary transports or disable command deadlines.
type PoolConfig struct {
	Addr           string
	Network        string
	Username       string
	Password       string
	DB             int
	TLSConfig      *tls.Config
	Size           int
	AcquireTimeout time.Duration
	DialTimeout    time.Duration
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
}

var (
	ErrPoolClosed  = errors.New("redis connection pool is closed")
	ErrPoolTimeout = errors.New("redis connection pool acquire timed out")
	ErrProtocol    = errors.New("invalid redis protocol reply")
)

const releaseCompareDeleteScript = "if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]) else return 0 end"
const (
	maxRESPLine  = 1 << 20
	maxRESPBulk  = 8 << 20
	maxRESPArray = 1024
)

// Pool is a bounded, reusable connection pool. A slot is held for the whole
// request/response exchange, so a connection is never used concurrently.
type Pool struct {
	cfg       PoolConfig
	available chan *pooledConn
	tokens    chan struct{}
	done      chan struct{}
	mu        sync.Mutex
	closed    bool
	all       map[*pooledConn]struct{}
}

type pooledConn struct {
	conn net.Conn
	read *bufio.Reader
}

func NewPool(cfg PoolConfig) (*Pool, error) {
	if strings.TrimSpace(cfg.Addr) == "" {
		return nil, fmt.Errorf("redis address is required")
	}
	if cfg.Network == "" {
		cfg.Network = "tcp"
	}
	if cfg.DB < 0 {
		return nil, fmt.Errorf("redis database must not be negative")
	}
	if cfg.Size <= 0 {
		cfg.Size = 1
	}
	if cfg.Size > 128 {
		cfg.Size = 128
	}
	if cfg.AcquireTimeout <= 0 {
		cfg.AcquireTimeout = time.Second
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 3 * time.Second
	}
	if cfg.ReadTimeout <= 0 {
		cfg.ReadTimeout = 3 * time.Second
	}
	if cfg.WriteTimeout <= 0 {
		cfg.WriteTimeout = 3 * time.Second
	}
	p := &Pool{
		cfg:       cfg,
		available: make(chan *pooledConn, cfg.Size),
		tokens:    make(chan struct{}, cfg.Size),
		done:      make(chan struct{}),
		all:       make(map[*pooledConn]struct{}),
	}
	for i := 0; i < cfg.Size; i++ {
		p.tokens <- struct{}{}
	}
	return p, nil
}

func OpenPool(ctx context.Context, cfg PoolConfig) (*Pool, error) {
	p, err := NewPool(cfg)
	if err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := p.Ping(ctx); err != nil {
		_ = p.Close()
		return nil, err
	}
	return p, nil
}

func (p *Pool) acquire(ctx context.Context) (*pooledConn, error) {
	if p == nil {
		return nil, ErrPoolClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	p.mu.Lock()
	closed := p.closed
	p.mu.Unlock()
	if closed {
		return nil, ErrPoolClosed
	}
	timer := time.NewTimer(p.cfg.AcquireTimeout)
	defer timer.Stop()
	select {
	case <-p.tokens:
	case <-p.done:
		return nil, ErrPoolClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
		return nil, ErrPoolTimeout
	}
	select {
	case c := <-p.available:
		if c != nil {
			return c, nil
		}
	case <-p.done:
		p.releaseToken()
		return nil, ErrPoolClosed
	default:
	}
	c, err := p.dial(ctx)
	if err != nil {
		p.releaseToken()
		return nil, err
	}
	return c, nil
}

func (p *Pool) releaseToken() {
	select {
	case p.tokens <- struct{}{}:
	default:
	}
}

func (p *Pool) release(c *pooledConn, healthy bool) {
	if c == nil {
		p.releaseToken()
		return
	}
	p.mu.Lock()
	closed := p.closed
	if healthy && !closed {
		select {
		case p.available <- c:
			p.releaseToken()
			p.mu.Unlock()
			return
		default:
		}
	}
	delete(p.all, c)
	p.mu.Unlock()
	_ = c.conn.Close()
	p.releaseToken()
}

func (p *Pool) dial(ctx context.Context) (*pooledConn, error) {
	d := net.Dialer{Timeout: p.cfg.DialTimeout}
	var conn net.Conn
	var err error
	if p.cfg.TLSConfig != nil {
		conn, err = tls.DialWithDialer(&d, p.cfg.Network, p.cfg.Addr, p.cfg.TLSConfig)
	} else {
		conn, err = d.DialContext(ctx, p.cfg.Network, p.cfg.Addr)
	}
	if err != nil {
		return nil, err
	}
	c := &pooledConn{conn: conn, read: bufio.NewReader(conn)}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		_ = conn.Close()
		return nil, ErrPoolClosed
	}
	p.all[c] = struct{}{}
	p.mu.Unlock()
	if p.cfg.Password != "" || p.cfg.Username != "" {
		args := []string{"AUTH"}
		if p.cfg.Username != "" {
			args = append(args, p.cfg.Username)
		}
		args = append(args, p.cfg.Password)
		if _, err := p.roundTrip(ctx, c, args...); err != nil {
			p.discard(c)
			return nil, err
		}
	}
	if p.cfg.DB != 0 {
		if _, err := p.roundTrip(ctx, c, "SELECT", strconv.Itoa(p.cfg.DB)); err != nil {
			p.discard(c)
			return nil, err
		}
	}
	return c, nil
}

func (p *Pool) discard(c *pooledConn) {
	if c == nil {
		return
	}
	p.mu.Lock()
	delete(p.all, c)
	p.mu.Unlock()
	_ = c.conn.Close()
}

// Do executes one allow-listed RESP command and returns a scalar or []any.
// RuntimeAdapter only uses the commands below; rejecting everything else keeps
// this boundary from becoming a general-purpose Redis tunnel.
func (p *Pool) Do(ctx context.Context, args ...string) (any, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := validateCommand(args); err != nil {
		return nil, err
	}
	c, err := p.acquire(ctx)
	if err != nil {
		return nil, err
	}
	v, err := p.roundTrip(ctx, c, args...)
	if err != nil {
		p.release(c, false)
		return nil, err
	}
	p.release(c, true)
	return v, nil
}

func (p *Pool) Ping(ctx context.Context) error {
	v, err := p.Do(ctx, "PING")
	if err != nil {
		return err
	}
	if s, ok := v.(string); !ok || !strings.EqualFold(s, "PONG") {
		return fmt.Errorf("%w: expected PONG, got %v", ErrProtocol, v)
	}
	return nil
}

func (p *Pool) roundTrip(ctx context.Context, c *pooledConn, args ...string) (any, error) {
	if c == nil || c.conn == nil {
		return nil, ErrPoolClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	writeDeadline := time.Now().Add(p.cfg.WriteTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(writeDeadline) {
		writeDeadline = d
	}
	if err := c.conn.SetWriteDeadline(writeDeadline); err != nil {
		return nil, err
	}
	if err := writeRESP(c.conn, args...); err != nil {
		return nil, err
	}
	readDeadline := time.Now().Add(p.cfg.ReadTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(readDeadline) {
		readDeadline = d
	}
	if err := c.conn.SetReadDeadline(readDeadline); err != nil {
		return nil, err
	}
	return readRESP(c.read)
}

func (p *Pool) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	close(p.done)
	connections := make([]*pooledConn, 0, len(p.all))
	for c := range p.all {
		connections = append(connections, c)
	}
	p.all = make(map[*pooledConn]struct{})
	for {
		select {
		case c := <-p.available:
			if c != nil {
				_ = c.conn.Close()
			}
		default:
			p.mu.Unlock()
			for _, c := range connections {
				_ = c.conn.Close()
			}
			return nil
		}
	}
}

func writeRESP(w io.Writer, args ...string) error {
	var b strings.Builder
	fmt.Fprintf(&b, "*%d\r\n", len(args))
	for _, arg := range args {
		if strings.ContainsAny(arg, "\r\n") {
			return fmt.Errorf("%w: argument contains CR/LF", ErrProtocol)
		}
		fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(arg), arg)
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func validateCommand(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%w: empty command", ErrProtocol)
	}
	switch strings.ToUpper(args[0]) {
	case "PING":
		if len(args) != 1 {
			return fmt.Errorf("%w: PING takes no arguments", ErrProtocol)
		}
	case "GET", "DEL", "EXISTS":
		if len(args) != 2 || args[1] == "" {
			return fmt.Errorf("%w: %s requires one key", ErrProtocol, args[0])
		}
	case "SET":
		if len(args) != 5 && len(args) != 6 {
			return fmt.Errorf("%w: SET shape is key value PX milliseconds [NX]", ErrProtocol)
		}
		if args[1] == "" || !strings.EqualFold(args[3], "PX") {
			return fmt.Errorf("%w: SET requires PX", ErrProtocol)
		}
		ms, err := strconv.ParseInt(args[4], 10, 64)
		if err != nil || ms <= 0 {
			return fmt.Errorf("%w: SET TTL must be positive milliseconds", ErrProtocol)
		}
		if len(args) == 6 && !strings.EqualFold(args[5], "NX") {
			return fmt.Errorf("%w: unsupported SET option", ErrProtocol)
		}
	case "EVAL":
		if len(args) != 5 || args[1] != releaseCompareDeleteScript || args[2] != "1" || args[3] == "" || args[4] == "" {
			return fmt.Errorf("%w: only compare-delete EVAL is permitted", ErrProtocol)
		}
	default:
		return fmt.Errorf("redis command %q is not allowed", args[0])
	}
	return nil
}

func readRESP(r *bufio.Reader) (any, error) {
	return readRESPDepth(r, 0)
}

func readRESPDepth(r *bufio.Reader, depth int) (any, error) {
	if depth > maxRESPArray {
		return nil, fmt.Errorf("%w: reply nesting too deep", ErrProtocol)
	}
	line, err := r.ReadString('\n')
	if err != nil {
		if len(line) > maxRESPLine {
			return nil, fmt.Errorf("%w: reply line too long", ErrProtocol)
		}
		return nil, err
	}
	if len(line) > maxRESPLine {
		return nil, fmt.Errorf("%w: reply line too long", ErrProtocol)
	}
	if len(line) < 3 || line[len(line)-2:] != "\r\n" {
		return nil, fmt.Errorf("%w: malformed line", ErrProtocol)
	}
	payload := line[:len(line)-2]
	if payload == "" {
		return nil, fmt.Errorf("%w: empty reply", ErrProtocol)
	}
	switch payload[0] {
	case '+':
		return payload[1:], nil
	case '-':
		return nil, errors.New(strings.TrimSpace(payload[1:]))
	case ':':
		n, err := strconv.ParseInt(payload[1:], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%w: integer: %v", ErrProtocol, err)
		}
		return n, nil
	case '$':
		n, err := strconv.Atoi(payload[1:])
		if err != nil || n < -1 {
			return nil, fmt.Errorf("%w: bulk length", ErrProtocol)
		}
		if n == -1 {
			return nil, nil
		}
		if n > maxRESPBulk {
			return nil, fmt.Errorf("%w: bulk reply too large", ErrProtocol)
		}
		b := make([]byte, n+2)
		if _, err := io.ReadFull(r, b); err != nil {
			return nil, err
		}
		if len(b) < 2 || b[len(b)-2] != '\r' || b[len(b)-1] != '\n' {
			return nil, fmt.Errorf("%w: bulk terminator", ErrProtocol)
		}
		return append([]byte(nil), b[:n]...), nil
	case '*':
		n, err := strconv.Atoi(payload[1:])
		if err != nil || n < -1 {
			return nil, fmt.Errorf("%w: array length", ErrProtocol)
		}
		if n == -1 {
			return nil, nil
		}
		if n > maxRESPArray {
			return nil, fmt.Errorf("%w: array reply too large", ErrProtocol)
		}
		out := make([]any, n)
		for i := range out {
			out[i], err = readRESPDepth(r, depth+1)
			if err != nil {
				return nil, err
			}
		}
		return out, nil
	default:
		return nil, fmt.Errorf("%w: unknown prefix %q", ErrProtocol, payload[0])
	}
}
