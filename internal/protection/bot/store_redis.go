package bot

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// RedisBackend is an optional R2 shared challenge store.
// It uses a minimal RESP client over TCP so we do not add a Redis SDK dependency.
// Fail-closed by default: Add/Consume return errors/false when the connection is down.
type RedisBackend struct {
	addr      string
	db        int
	password  string
	prefix    string
	failOpen  bool
	useTLS    bool
	mu        sync.Mutex
	conn      net.Conn
	lastError error
}

// NewRedisBackend parses redis URL and prefers loopback/private hosts.
func NewRedisBackend(cfg BackendConfig) (*RedisBackend, error) {
	u, err := url.Parse(cfg.RedisURL)
	if err != nil {
		return nil, fmt.Errorf("redis url: %w", err)
	}
	if u.Scheme != "redis" && u.Scheme != "rediss" {
		return nil, fmt.Errorf("unsupported redis scheme %q", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return nil, errors.New("redis host required")
	}
	// Prefer loopback/private for SSRF safety; hostnames allowed for operator mesh.
	if ip := net.ParseIP(host); ip != nil && !ip.IsLoopback() && !ip.IsPrivate() {
		return nil, fmt.Errorf("redis host %q must be loopback or private for safety", host)
	}
	port := u.Port()
	if port == "" {
		port = "6379"
	}
	db := 0
	if strings.TrimPrefix(u.Path, "/") != "" {
		db, _ = strconv.Atoi(strings.TrimPrefix(u.Path, "/"))
	}
	pass, _ := u.User.Password()
	prefix := strings.TrimSpace(cfg.KeyPrefix)
	if prefix == "" {
		prefix = "cheesewaf:challenge:"
	}
	return &RedisBackend{
		addr:     net.JoinHostPort(host, port),
		db:       db,
		password: pass,
		prefix:   prefix,
		failOpen: cfg.FailOpen,
		useTLS:   u.Scheme == "rediss",
	}, nil
}

func (r *RedisBackend) Add(ctx context.Context, jti, owner string, exp time.Time) error {
	if jti == "" || exp.IsZero() {
		return errors.New("jti and expiration required")
	}
	ttl := time.Until(exp)
	if ttl <= 0 {
		return errors.New("challenge already expired")
	}
	key := r.prefix + jti
	val := owner
	if val == "" {
		val = "1"
	}
	err := r.do(ctx, "SET", key, val, "PX", strconv.FormatInt(ttl.Milliseconds(), 10), "NX")
	if err != nil {
		if r.failOpen {
			return nil
		}
		return err
	}
	return nil
}

func (r *RedisBackend) Consume(ctx context.Context, jti string) bool {
	if jti == "" {
		return false
	}
	key := r.prefix + jti
	// GETDEL when available; fallback GET+DEL.
	raw, err := r.doString(ctx, "GETDEL", key)
	if err != nil {
		// Fallback for older Redis.
		raw, err = r.doString(ctx, "GET", key)
		if err != nil {
			return r.failOpen
		}
		if raw == "" {
			return false
		}
		_ = r.do(ctx, "DEL", key)
		return true
	}
	return raw != ""
}

func (r *RedisBackend) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.conn != nil {
		err := r.conn.Close()
		r.conn = nil
		return err
	}
	return nil
}

func (r *RedisBackend) ensureConn(ctx context.Context) (net.Conn, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.conn != nil {
		return r.conn, nil
	}
	d := net.Dialer{Timeout: 3 * time.Second}
	var conn net.Conn
	var err error
	if r.useTLS {
		conn, err = tls.DialWithDialer(&d, "tcp", r.addr, &tls.Config{MinVersion: tls.VersionTLS12})
	} else {
		conn, err = d.DialContext(ctx, "tcp", r.addr)
	}
	if err != nil {
		r.lastError = err
		return nil, err
	}
	r.conn = conn
	if r.password != "" {
		if err := r.writeCommand(conn, "AUTH", r.password); err != nil {
			_ = conn.Close()
			r.conn = nil
			return nil, err
		}
		if _, err := r.readReply(conn); err != nil {
			_ = conn.Close()
			r.conn = nil
			return nil, err
		}
	}
	if r.db != 0 {
		if err := r.writeCommand(conn, "SELECT", strconv.Itoa(r.db)); err != nil {
			_ = conn.Close()
			r.conn = nil
			return nil, err
		}
		if _, err := r.readReply(conn); err != nil {
			_ = conn.Close()
			r.conn = nil
			return nil, err
		}
	}
	return conn, nil
}

func (r *RedisBackend) do(ctx context.Context, args ...string) error {
	conn, err := r.ensureConn(ctx)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if err := r.writeCommand(conn, args...); err != nil {
		_ = conn.Close()
		r.conn = nil
		return err
	}
	_, err = r.readReply(conn)
	if err != nil {
		_ = conn.Close()
		r.conn = nil
	}
	return err
}

func (r *RedisBackend) doString(ctx context.Context, args ...string) (string, error) {
	conn, err := r.ensureConn(ctx)
	if err != nil {
		return "", err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if err := r.writeCommand(conn, args...); err != nil {
		_ = conn.Close()
		r.conn = nil
		return "", err
	}
	v, err := r.readReply(conn)
	if err != nil {
		_ = conn.Close()
		r.conn = nil
		return "", err
	}
	if v == nil {
		return "", nil
	}
	s, _ := v.(string)
	return s, nil
}

func (r *RedisBackend) writeCommand(conn net.Conn, args ...string) error {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("*%d\r\n", len(args)))
	for _, a := range args {
		b.WriteString(fmt.Sprintf("$%d\r\n%s\r\n", len(a), a))
	}
	_, err := conn.Write([]byte(b.String()))
	return err
}

func (r *RedisBackend) readReply(conn net.Conn) (any, error) {
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	line := string(buf[:n])
	if len(line) == 0 {
		return nil, errors.New("empty redis reply")
	}
	switch line[0] {
	case '+': // simple string
		s := strings.TrimSuffix(line[1:], "\r\n")
		return s, nil
	case '-': // error
		return nil, errors.New(strings.TrimSpace(line[1:]))
	case '$': // bulk
		// $n\r\npayload\r\n or $-1
		parts := strings.SplitN(line, "\r\n", 3)
		if len(parts) < 2 {
			return nil, errors.New("bad bulk reply")
		}
		if strings.HasPrefix(parts[0], "$-1") {
			return nil, nil
		}
		if len(parts) >= 2 {
			return parts[1], nil
		}
		return "", nil
	case ':': // integer
		return strings.TrimSpace(line[1:]), nil
	default:
		return strings.TrimSpace(line), nil
	}
}
