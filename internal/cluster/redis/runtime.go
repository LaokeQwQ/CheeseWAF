package redis

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

var (
	ErrAdapterClosed    = errors.New("redis runtime adapter is closed")
	ErrUnknownInstance  = errors.New("redis instance identity is unknown")
	ErrFailClosed       = errors.New("redis operation failed closed")
	ErrRedisUnavailable = errors.New("redis is unavailable")
	ErrRedisTimeout     = errors.New("redis operation timed out")
	ErrLeaseBusy        = errors.New("redis lease or lock is already held")
	ErrCacheMiss        = errors.New("redis cache miss")
	ErrEpochRegression  = errors.New("policy epoch cannot move backwards")
)

const (
	defaultRuntimePrefix = "cheesewaf:runtime:"
	defaultIdentityKey   = "instance_id"
	defaultMaxLocalTTL   = 30 * time.Second
	defaultMaxLocalItems = 1024
	maxRuntimeKey        = 512
	maxRuntimeValue      = 4 << 20
)

// Config configures RuntimeAdapter. URL/RedisURL and Addr are aliases so the
// adapter can be used from either URL-oriented or pgx-style address config.
// InstanceID is mandatory: the adapter never claims an unlabelled Redis server
// as the current instance.
type Config struct {
	URL            string
	RedisURL       string
	Addr           string
	Username       string
	Password       string
	DB             int
	TLSConfig      *tls.Config
	Prefix         string
	IdentityKey    string
	InstanceID     string
	Epoch          uint64
	PolicyEpoch    uint64
	PoolSize       int
	AcquireTimeout time.Duration
	DialTimeout    time.Duration
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
	Policy         Policy
	Now            func() time.Time
	LocalState     *LocalState
}

// RuntimeConfig is kept as a descriptive alias for callers that prefer an
// explicit name at dependency-injection boundaries.
type RuntimeConfig = Config

// CommandClient is the replaceable command boundary used by RuntimeAdapter.
// Pool implements it; tests and embedding applications may provide a bounded
// fake without changing adapter behavior. Replies are scalar RESP2 values:
// string, []byte, int64, nil, or []any for arrays.
type CommandClient interface {
	Do(context.Context, ...string) (any, error)
	Close() error
}

// Handle is a short-lived Redis lease/lock reservation. It is intentionally a
// value type: callers must retain the token and pass the complete handle back
// to Validate/Release. Durable authorization must remain in the control plane.
type Handle struct {
	Token       string
	Key         string
	Epoch       uint64
	ExpiresAt   time.Time
	Mode        Mode
	Operation   Operation
	fingerprint string
}

// Lease is a compatibility alias for callers that use lease terminology for
// both leases and locks.
type Lease = Handle

type RuntimeAdapter struct {
	client  CommandClient
	cfg     Config
	local   *LocalState
	now     func() time.Time
	mu      sync.RWMutex
	status  Status
	lastErr error
	closed  bool
}

// New constructs an adapter without performing network I/O. Call Open when a
// startup probe is desired; both constructors retain the adapter on an
// unavailable/unknown Redis so Evaluate-based degradation remains available.
func New(cfg Config) (*RuntimeAdapter, error) {
	cfg, err := normalizeConfig(cfg)
	if err != nil {
		return nil, err
	}
	p, err := NewPool(PoolConfig{
		Addr: cfg.Addr, Network: "tcp", Username: cfg.Username, Password: cfg.Password, DB: cfg.DB,
		TLSConfig: cfg.TLSConfig, Size: cfg.PoolSize, AcquireTimeout: cfg.AcquireTimeout,
		DialTimeout: cfg.DialTimeout, ReadTimeout: cfg.ReadTimeout, WriteTimeout: cfg.WriteTimeout,
	})
	if err != nil {
		return nil, err
	}
	return newRuntimeAdapter(cfg, p), nil
}

// Open constructs an adapter and probes PING plus the configured identity key.
// Availability and identity failures are recorded as status and do not discard
// the adapter, allowing bounded local fallback and cache-miss behavior. Config
// and protocol-shape errors are returned.
func Open(ctx context.Context, cfg Config) (*RuntimeAdapter, error) {
	a, err := New(cfg)
	if err != nil {
		return nil, err
	}
	if err := a.Refresh(ctx); err != nil {
		if !errors.Is(err, ErrUnknownInstance) && !isAvailabilityError(err) {
			_ = a.Close()
			return nil, err
		}
	}
	return a, nil
}

// NewWithClient injects a replaceable command client. It is useful for tests,
// embedded Redis proxies, and environments that already own connection pooling.
func NewWithClient(cfg Config, client CommandClient) (*RuntimeAdapter, error) {
	if isNilCommandClient(client) {
		return nil, errors.New("redis command client is required")
	}
	cfg, err := normalizeConfig(cfg)
	if err != nil {
		return nil, err
	}
	return newRuntimeAdapter(cfg, client), nil
}

// OpenWithClient is NewWithClient followed by the same non-destructive probe as
// Open.
func OpenWithClient(ctx context.Context, cfg Config, client CommandClient) (*RuntimeAdapter, error) {
	a, err := NewWithClient(cfg, client)
	if err != nil {
		return nil, err
	}
	if err := a.Refresh(ctx); err != nil && !errors.Is(err, ErrUnknownInstance) && !isAvailabilityError(err) {
		_ = a.Close()
		return nil, err
	}
	return a, nil
}

// NewRuntimeAdapter is an explicit constructor alias.
func NewRuntimeAdapter(cfg Config) (*RuntimeAdapter, error) { return New(cfg) }

func newRuntimeAdapter(cfg Config, client CommandClient) *RuntimeAdapter {
	local := cfg.LocalState
	if local == nil {
		local = NewLocalState(cfg.Policy)
	}
	now := cfg.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &RuntimeAdapter{client: client, cfg: cfg, local: local, now: now, status: StatusUnavailable}
}

func normalizeConfig(cfg Config) (Config, error) {
	if cfg.InstanceID == "" {
		return Config{}, errors.New("redis instance identity is required")
	}
	if err := validateRuntimeIdentity(cfg.InstanceID); err != nil {
		return Config{}, err
	}
	rawURL := strings.TrimSpace(cfg.URL)
	if rawURL == "" {
		rawURL = strings.TrimSpace(cfg.RedisURL)
	}
	if rawURL == "" && strings.Contains(cfg.Addr, "://") {
		rawURL = strings.TrimSpace(cfg.Addr)
	}
	if rawURL != "" {
		u, err := url.Parse(rawURL)
		if err != nil || (u.Scheme != "redis" && u.Scheme != "rediss") || u.Hostname() == "" {
			return Config{}, fmt.Errorf("invalid redis URL")
		}
		if cfg.Addr == "" || strings.Contains(cfg.Addr, "://") {
			port := u.Port()
			if port == "" {
				port = "6379"
			}
			cfg.Addr = net.JoinHostPort(u.Hostname(), port)
		}
		if cfg.Username == "" && u.User != nil {
			cfg.Username = u.User.Username()
		}
		if cfg.Password == "" && u.User != nil {
			if pass, ok := u.User.Password(); ok {
				cfg.Password = pass
			}
		}
		if cfg.DB == 0 && strings.Trim(u.Path, "/") != "" {
			db, err := strconv.Atoi(strings.Trim(u.Path, "/"))
			if err != nil || db < 0 {
				return Config{}, errors.New("invalid redis database")
			}
			cfg.DB = db
		}
		if u.Scheme == "rediss" && cfg.TLSConfig == nil {
			cfg.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname()}
		}
	}
	if strings.TrimSpace(cfg.Addr) == "" {
		return Config{}, errors.New("redis address is required")
	}
	if ip := net.ParseIP(strings.Split(cfg.Addr, ":")[0]); ip != nil && !ip.IsLoopback() && !ip.IsPrivate() {
		return Config{}, errors.New("redis address must be loopback or private")
	}
	if cfg.Prefix == "" {
		cfg.Prefix = defaultRuntimePrefix
	}
	if err := validateRuntimePart(cfg.Prefix, "redis key prefix", maxRuntimeKey); err != nil {
		return Config{}, err
	}
	if !strings.HasSuffix(cfg.Prefix, ":") {
		cfg.Prefix += ":"
	}
	if cfg.IdentityKey == "" {
		cfg.IdentityKey = cfg.Prefix + defaultIdentityKey
	}
	if err := validateRuntimePart(cfg.IdentityKey, "redis identity key", maxRuntimeKey); err != nil {
		return Config{}, err
	}
	if cfg.Epoch != 0 && cfg.PolicyEpoch != 0 && cfg.Epoch != cfg.PolicyEpoch {
		return Config{}, ErrEpochMismatch
	}
	if cfg.Epoch == 0 {
		cfg.Epoch = cfg.PolicyEpoch
	}
	if cfg.Policy.MaxLocalTTL <= 0 {
		cfg.Policy.MaxLocalTTL = defaultMaxLocalTTL
	}
	if cfg.Policy.MaxLocalEntries <= 0 {
		cfg.Policy.MaxLocalEntries = defaultMaxLocalItems
	}
	if cfg.PoolSize <= 0 {
		cfg.PoolSize = 4
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
	return cfg, nil
}

func validateRuntimePart(value, label string, max int) error {
	if value == "" || len(value) > max || strings.ContainsAny(value, "\r\n\x00") {
		return fmt.Errorf("invalid %s", label)
	}
	return nil
}

func validateRuntimeIdentity(value string) error {
	if value == "" || len(value) > 128 || !utf8.ValidString(value) {
		return errors.New("invalid instance identity")
	}
	for _, r := range value {
		if unicode.IsSpace(r) || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return errors.New("invalid instance identity")
		}
	}
	return nil
}

func (a *RuntimeAdapter) Status() Status {
	if a == nil {
		return StatusUnavailable
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.status
}

func (a *RuntimeAdapter) LastError() error {
	if a == nil {
		return ErrAdapterClosed
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.lastErr
}

// Epoch returns the adapter's optional current policy epoch. A zero value means
// callers must supply and validate an epoch per operation.
func (a *RuntimeAdapter) Epoch() uint64 {
	if a == nil {
		return 0
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.cfg.Epoch
}

// SetEpoch changes the local fence used by subsequent operations. It does not
// mutate Redis and therefore cannot make an uncommitted control-plane epoch
// authoritative; callers should invoke it only after durable consensus commit.
func (a *RuntimeAdapter) SetEpoch(epoch uint64) error {
	if a == nil {
		return ErrAdapterClosed
	}
	if epoch == 0 {
		return ErrEpochRequired
	}
	a.mu.Lock()
	if a.cfg.Epoch != 0 && epoch < a.cfg.Epoch {
		a.mu.Unlock()
		return ErrEpochRegression
	}
	a.cfg.Epoch = epoch
	a.cfg.PolicyEpoch = epoch
	a.mu.Unlock()
	if a.local != nil {
		a.local.InvalidateBeforeEpoch(epoch)
	}
	return nil
}

// Ping verifies both transport liveness and the configured instance identity.
func (a *RuntimeAdapter) Ping(ctx context.Context) error { return a.Refresh(ctx) }

// Refresh performs a fresh PING and identity read. Unknown identity is a safe,
// non-current status rather than an automatic failover.
func (a *RuntimeAdapter) Refresh(ctx context.Context) error {
	if a == nil {
		return ErrAdapterClosed
	}
	a.mu.RLock()
	closed := a.closed
	a.mu.RUnlock()
	if closed {
		return ErrAdapterClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	a.mu.RLock()
	client := a.client
	identityKey := a.cfg.IdentityKey
	expectedID := a.cfg.InstanceID
	a.mu.RUnlock()
	if client == nil {
		return a.recordProbeError(ErrRedisUnavailable)
	}
	v, err := client.Do(ctx, "PING")
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			a.recordStatus(StatusUnavailable, ctxErr)
			return ctxErr
		}
		return a.recordProbeError(err)
	}
	if a.isClosed() {
		return ErrAdapterClosed
	}
	if s, ok := scalarString(v); !ok || !strings.EqualFold(s, "PONG") {
		return a.recordProbeError(fmt.Errorf("%w: expected PONG", ErrProtocol))
	}
	v, err = client.Do(ctx, "GET", identityKey)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			a.recordStatus(StatusUnavailable, ctxErr)
			return ctxErr
		}
		return a.recordProbeError(err)
	}
	if a.isClosed() {
		return ErrAdapterClosed
	}
	identity, ok := scalarString(v)
	if !ok || identity == "" || identity != expectedID {
		return a.recordStatus(StatusUnknownInstance, ErrUnknownInstance)
	}
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return ErrAdapterClosed
	}
	a.status = StatusAvailable
	a.lastErr = nil
	a.mu.Unlock()
	return nil
}

func (a *RuntimeAdapter) recordProbeError(err error) error {
	if errors.Is(err, ErrProtocol) {
		a.recordStatus(StatusUnavailable, err)
		return err
	}
	status := StatusUnavailable
	if isTimeoutError(err) {
		status = StatusTimeout
	}
	a.recordStatus(status, err)
	if status == StatusTimeout {
		return fmt.Errorf("%w: %v", ErrRedisTimeout, err)
	}
	return fmt.Errorf("%w: %v", ErrRedisUnavailable, err)
}

func (a *RuntimeAdapter) recordStatus(status Status, err error) error {
	a.mu.Lock()
	a.status = status
	a.lastErr = err
	a.mu.Unlock()
	return err
}

func (a *RuntimeAdapter) isClosed() bool {
	if a == nil {
		return true
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.closed
}

func isNilCommandClient(client CommandClient) bool {
	if client == nil {
		return true
	}
	v := reflect.ValueOf(client)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}

func (a *RuntimeAdapter) evaluate(ctx context.Context, op Operation, epoch uint64, ttl time.Duration) (Decision, Status, error) {
	if a == nil {
		return Decision{}, StatusUnavailable, ErrAdapterClosed
	}
	a.mu.RLock()
	closed := a.closed
	a.mu.RUnlock()
	if closed {
		return Decision{}, StatusUnavailable, ErrAdapterClosed
	}
	if epoch == 0 {
		return Decision{}, StatusUnavailable, ErrEpochRequired
	}
	a.mu.RLock()
	configuredEpoch := a.cfg.Epoch
	policy := a.cfg.Policy
	a.mu.RUnlock()
	if configuredEpoch != 0 && epoch != configuredEpoch {
		return Decision{}, StatusUnavailable, ErrEpochMismatch
	}
	if ttl <= 0 {
		return Decision{}, StatusUnavailable, ErrInvalidTTL
	}
	probeErr := a.Refresh(ctx)
	status := a.Status()
	decision, err := Evaluate(policy, op, status, epoch, ttl)
	if err != nil {
		return Decision{}, status, err
	}
	return decision, status, probeErr
}

func (a *RuntimeAdapter) Acquire(ctx context.Context, op Operation, key string, epoch uint64, ttl time.Duration) (Handle, error) {
	if op != OperationLease && op != OperationLock {
		return Handle{}, ErrInvalidLease
	}
	if err := validateKey(key); err != nil {
		return Handle{}, err
	}
	decision, status, probeErr := a.evaluate(ctx, op, epoch, ttl)
	if probeErr != nil && decision.Mode == ModeRedis {
		return Handle{}, probeErr
	}
	if decision.Mode == ModeLocal {
		token, err := a.local.Reserve(op, key, epoch, decision.TTL, a.now())
		if err != nil {
			return Handle{}, err
		}
		return newHandle(a.now, op, key, epoch, token, decision.TTL, ModeLocal), nil
	}
	if decision.Mode == ModeFailClosed {
		return Handle{}, failClosed(status, probeErr)
	}
	if decision.Mode != ModeRedis {
		return Handle{}, ErrFailClosed
	}
	token, err := randomToken()
	if err != nil {
		return Handle{}, err
	}
	redisKey := a.stateKey(op, key, epoch)
	v, err := a.client.Do(ctx, "SET", redisKey, token, "PX", strconv.FormatInt(ttl.Milliseconds(), 10), "NX")
	if err != nil {
		status = statusFromError(err)
		if status == StatusUnavailable || status == StatusTimeout {
			decision, _ = Evaluate(a.policySnapshot(), op, status, epoch, ttl)
			if decision.Mode == ModeLocal {
				localToken, localErr := a.local.Reserve(op, key, epoch, decision.TTL, a.now())
				if localErr == nil {
					return newHandle(a.now, op, key, epoch, localToken, decision.TTL, ModeLocal), nil
				}
			}
		}
		return Handle{}, failClosed(status, err)
	}
	if isNilReply(v) {
		return Handle{}, ErrLeaseBusy
	}
	if s, ok := scalarString(v); !ok || !strings.EqualFold(s, "OK") {
		return Handle{}, fmt.Errorf("%w: unexpected SET reply", ErrProtocol)
	}
	return newHandle(a.now, op, key, epoch, token, ttl, ModeRedis), nil
}

func (a *RuntimeAdapter) AcquireLease(ctx context.Context, key string, epoch uint64, ttl time.Duration) (Handle, error) {
	return a.Acquire(ctx, OperationLease, key, epoch, ttl)
}

func (a *RuntimeAdapter) AcquireLock(ctx context.Context, key string, epoch uint64, ttl time.Duration) (Handle, error) {
	return a.Acquire(ctx, OperationLock, key, epoch, ttl)
}

func newHandle(now func() time.Time, op Operation, key string, epoch uint64, token string, ttl time.Duration, mode Mode) Handle {
	if now == nil {
		now = time.Now
	}
	h := Handle{Token: token, Key: key, Epoch: epoch, ExpiresAt: now().Add(ttl), Mode: mode, Operation: op}
	h.fingerprint = handleFingerprint(h)
	return h
}

func (a *RuntimeAdapter) Validate(ctx context.Context, h Handle) error {
	if a == nil {
		return ErrAdapterClosed
	}
	if err := validateHandle(h); err != nil {
		return err
	}
	if configuredEpoch := a.Epoch(); configuredEpoch != 0 && h.Epoch != configuredEpoch {
		return ErrEpochMismatch
	}
	if h.Mode == ModeLocal {
		return a.local.Valid(h.Token, h.Operation, h.Key, h.Epoch, a.now())
	}
	if h.Mode != ModeRedis {
		return ErrInvalidLease
	}
	remaining := h.ExpiresAt.Sub(a.now())
	if remaining <= 0 {
		return ErrExpired
	}
	decision, status, probeErr := a.evaluate(ctx, h.Operation, h.Epoch, remaining)
	if probeErr != nil && decision.Mode == ModeRedis {
		return probeErr
	}
	if decision.Mode != ModeRedis {
		return failClosed(status, probeErr)
	}
	v, err := a.client.Do(ctx, "GET", a.stateKey(h.Operation, h.Key, h.Epoch))
	if err != nil {
		return failClosed(statusFromError(err), err)
	}
	token, ok := scalarString(v)
	if !ok || token != h.Token {
		return ErrInvalidLease
	}
	return nil
}

func (a *RuntimeAdapter) Release(ctx context.Context, h Handle) error {
	if a == nil {
		return ErrAdapterClosed
	}
	if err := validateHandle(h); err != nil {
		return err
	}
	if configuredEpoch := a.Epoch(); configuredEpoch != 0 && h.Epoch != configuredEpoch {
		return ErrEpochMismatch
	}
	if h.Mode == ModeLocal {
		return a.local.Release(h.Token, h.Operation, h.Key, h.Epoch)
	}
	if h.Mode != ModeRedis {
		return ErrInvalidLease
	}
	remaining := h.ExpiresAt.Sub(a.now())
	if remaining <= 0 {
		return ErrExpired
	}
	decision, status, probeErr := a.evaluate(ctx, h.Operation, h.Epoch, remaining)
	if probeErr != nil && decision.Mode == ModeRedis {
		return probeErr
	}
	if decision.Mode != ModeRedis {
		return failClosed(status, probeErr)
	}
	v, err := a.client.Do(ctx, "EVAL", releaseCompareDeleteScript, "1", a.stateKey(h.Operation, h.Key, h.Epoch), h.Token)
	if err != nil {
		return failClosed(statusFromError(err), err)
	}
	n, ok := scalarInt(v)
	if !ok {
		return fmt.Errorf("%w: invalid release reply", ErrProtocol)
	}
	if n != 1 {
		return ErrInvalidLease
	}
	return nil
}

func validateHandle(h Handle) error {
	if h.Token == "" || h.Key == "" || h.Epoch == 0 || h.ExpiresAt.IsZero() || (h.Operation != OperationLease && h.Operation != OperationLock) {
		return ErrInvalidLease
	}
	if h.fingerprint != "" && h.fingerprint != handleFingerprint(h) {
		if h.Epoch != 0 {
			return ErrEpochMismatch
		}
		return ErrInvalidLease
	}
	return nil
}

func handleFingerprint(h Handle) string {
	return fmt.Sprintf("%d\x00%s\x00%s\x00%d", h.Operation, h.Key, h.Token, h.Epoch)
}

func (a *RuntimeAdapter) MarkBlacklist(ctx context.Context, key string, epoch uint64, ttl time.Duration) error {
	if err := validateKey(key); err != nil {
		return err
	}
	decision, status, probeErr := a.evaluate(ctx, OperationBlacklist, epoch, ttl)
	if probeErr != nil && decision.Mode == ModeRedis {
		return probeErr
	}
	if decision.Mode != ModeRedis {
		return failClosed(status, probeErr)
	}
	v, err := a.client.Do(ctx, "SET", a.stateKey(OperationBlacklist, key, epoch), blacklistValue(a.instanceID(), epoch), "PX", strconv.FormatInt(ttl.Milliseconds(), 10))
	if err != nil {
		return failClosed(statusFromError(err), err)
	}
	if s, ok := scalarString(v); !ok || !strings.EqualFold(s, "OK") {
		return fmt.Errorf("%w: unexpected blacklist reply", ErrProtocol)
	}
	return nil
}

func (a *RuntimeAdapter) IsBlacklisted(ctx context.Context, key string, epoch uint64) (bool, error) {
	if err := validateKey(key); err != nil {
		return true, err
	}
	decision, status, probeErr := a.evaluate(ctx, OperationBlacklist, epoch, time.Second)
	if probeErr != nil && decision.Mode == ModeRedis {
		return true, probeErr
	}
	if decision.Mode != ModeRedis {
		return true, failClosed(status, probeErr)
	}
	v, err := a.client.Do(ctx, "GET", a.stateKey(OperationBlacklist, key, epoch))
	if err != nil {
		return true, failClosed(statusFromError(err), err)
	}
	value, ok := scalarString(v)
	if !ok {
		if isNilReply(v) {
			return false, nil
		}
		return true, fmt.Errorf("%w: invalid blacklist reply", ErrProtocol)
	}
	return value == blacklistValue(a.instanceID(), epoch), nil
}

func (a *RuntimeAdapter) PutCache(ctx context.Context, key string, value []byte, epoch uint64, ttl time.Duration) error {
	if err := validateKey(key); err != nil {
		return err
	}
	if len(value) > maxRuntimeValue {
		return errors.New("redis cache value is too large")
	}
	decision, status, probeErr := a.evaluate(ctx, OperationCache, epoch, ttl)
	if probeErr != nil && decision.Mode == ModeRedis {
		return probeErr
	}
	if decision.Mode == ModeCacheMiss {
		if status != StatusUnknownInstance && a.local != nil {
			_ = a.local.PutCache(key, value, epoch, ttl, a.now())
		}
		return nil
	}
	if decision.Mode != ModeRedis {
		return failClosed(status, probeErr)
	}
	payload := encodeCacheValue(epoch, value)
	v, err := a.client.Do(ctx, "SET", a.stateKey(OperationCache, key, epoch), payload, "PX", strconv.FormatInt(ttl.Milliseconds(), 10))
	if err != nil {
		if a.local != nil {
			_ = a.local.PutCache(key, value, epoch, ttl, a.now())
		}
		return nil
	}
	if s, ok := scalarString(v); !ok || !strings.EqualFold(s, "OK") {
		return fmt.Errorf("%w: unexpected cache reply", ErrProtocol)
	}
	if a.local != nil {
		_ = a.local.PutCache(key, value, epoch, ttl, a.now())
	}
	return nil
}

func (a *RuntimeAdapter) GetCache(ctx context.Context, key string, epoch uint64) ([]byte, bool, error) {
	if err := validateKey(key); err != nil {
		return nil, false, err
	}
	decision, status, evalErr := a.evaluate(ctx, OperationCache, epoch, time.Second)
	if evalErr != nil {
		// Input, protocol and caller-context errors must never be converted
		// into a cache lookup. Only availability and unknown-instance errors
		// have an explicit cache-miss degradation policy.
		if !isAvailabilityError(evalErr) && !errors.Is(evalErr, ErrUnknownInstance) {
			return nil, false, evalErr
		}
	}
	if decision.Mode == ModeRedis && a.Status() == StatusUnavailable && a.LastError() != nil {
		return nil, false, a.LastError()
	}
	if decision.Mode == ModeCacheMiss {
		if status == StatusUnavailable || status == StatusTimeout {
			if value, ok := a.local.GetCache(key, epoch, a.now()); ok {
				return value, true, nil
			}
		}
		return nil, false, nil
	}
	if decision.Mode != ModeRedis {
		return nil, false, nil
	}
	v, err := a.client.Do(ctx, "GET", a.stateKey(OperationCache, key, epoch))
	if err != nil {
		if isAvailabilityFailure(err) {
			a.recordStatus(statusFromError(err), err)
			if value, ok := a.local.GetCache(key, epoch, a.now()); ok {
				return value, true, nil
			}
			return nil, false, nil
		}
		return nil, false, err
	}
	payload, ok := scalarString(v)
	if !ok {
		return nil, false, nil
	}
	value, ok := decodeCacheValue(epoch, payload)
	if !ok {
		return nil, false, nil
	}
	return value, true, nil
}

func isAvailabilityFailure(err error) bool {
	if err == nil || errors.Is(err, ErrProtocol) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	return isAvailabilityError(err) || statusFromError(err) == StatusUnavailable || statusFromError(err) == StatusTimeout
}

func (a *RuntimeAdapter) stateKey(op Operation, key string, epoch uint64) string {
	return a.prefix() + operationName(op) + ":e" + strconv.FormatUint(epoch, 10) + ":" + digestKey(key)
}

func (a *RuntimeAdapter) policySnapshot() Policy {
	if a == nil {
		return Policy{}
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.cfg.Policy
}

func (a *RuntimeAdapter) instanceID() string {
	if a == nil {
		return ""
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.cfg.InstanceID
}

func (a *RuntimeAdapter) prefix() string {
	if a == nil {
		return ""
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.cfg.Prefix
}

func operationName(op Operation) string {
	switch op {
	case OperationLease:
		return "lease"
	case OperationLock:
		return "lock"
	case OperationBlacklist:
		return "blacklist"
	case OperationCache:
		return "cache"
	default:
		return "unknown"
	}
}

func digestKey(key string) string {
	h := sha256.Sum256([]byte(key))
	return hex.EncodeToString(h[:])
}

func validateKey(key string) error {
	if key == "" || len(key) > maxRuntimeKey || strings.ContainsAny(key, "\r\n\x00") {
		return errors.New("invalid redis state key")
	}
	return nil
}

func randomToken() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func blacklistValue(instance string, epoch uint64) string {
	return instance + "\x00" + strconv.FormatUint(epoch, 10)
}

func encodeCacheValue(epoch uint64, value []byte) string {
	return "v1:" + strconv.FormatUint(epoch, 10) + ":" + base64.RawStdEncoding.EncodeToString(value)
}

func decodeCacheValue(epoch uint64, payload string) ([]byte, bool) {
	prefix := "v1:" + strconv.FormatUint(epoch, 10) + ":"
	if !strings.HasPrefix(payload, prefix) {
		return nil, false
	}
	v, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(payload, prefix))
	return v, err == nil
}

func scalarString(v any) (string, bool) {
	switch x := v.(type) {
	case string:
		return x, true
	case []byte:
		return string(x), true
	default:
		return "", false
	}
}

func scalarInt(v any) (int64, bool) {
	switch x := v.(type) {
	case int:
		return int64(x), true
	case int64:
		return x, true
	case string:
		n, err := strconv.ParseInt(strings.TrimSpace(x), 10, 64)
		return n, err == nil
	case []byte:
		n, err := strconv.ParseInt(strings.TrimSpace(string(x)), 10, 64)
		return n, err == nil
	default:
		return 0, false
	}
}

func isNilReply(v any) bool { return v == nil }

func statusFromError(err error) Status {
	if isTimeoutError(err) || errors.Is(err, context.DeadlineExceeded) {
		return StatusTimeout
	}
	return StatusUnavailable
}

func isTimeoutError(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func isAvailabilityError(err error) bool {
	return errors.Is(err, ErrRedisUnavailable) || errors.Is(err, ErrRedisTimeout) || errors.Is(err, context.DeadlineExceeded) || isTimeoutError(err)
}

func failClosed(status Status, cause error) error {
	if status == StatusUnknownInstance || errors.Is(cause, ErrUnknownInstance) {
		if cause == nil {
			return fmt.Errorf("%w: %w", ErrFailClosed, ErrUnknownInstance)
		}
		return fmt.Errorf("%w: %w", ErrFailClosed, ErrUnknownInstance)
	}
	if cause == nil {
		return ErrFailClosed
	}
	return fmt.Errorf("%w: %v", ErrFailClosed, cause)
}

func (a *RuntimeAdapter) Close() error {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return nil
	}
	a.closed = true
	a.status = StatusUnavailable
	a.mu.Unlock()
	if a.client == nil {
		return nil
	}
	return a.client.Close()
}
