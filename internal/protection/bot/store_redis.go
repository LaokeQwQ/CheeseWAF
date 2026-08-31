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

// RedisBackend is a shared challenge store for multi-node deployments.
// It uses a minimal RESP client over TCP so we do not add a Redis SDK dependency.
// Fail-closed by default: Add/Consume return errors/false when the connection is
// down. FailOpen=true turns availability failures into permissive answers but
// never turns a real "out of capacity" answer into a success.
//
// Key namespace (all keys live under KeyPrefix, default "cheesewaf:challenge:"):
//
//	j:<jti>          string, the pending challenge. Value is a length prefixed
//	                "owner/peer" pair for entries created through Commit, or a
//	                bare owner for entries created by Add (see Consume).
//	r:<id>          hash, one outstanding reservation. Holds owner/peer/expiry/
//	                started flag/rate bucket so Commit and Rollback can release
//	                exactly what ReserveScoped took.
//	seq             counter handing out reservation ids.
//	c:t             counter, entries + reservations (the global capacity).
//	c:c             counter, outstanding reservations (the concurrency cap).
//	c:eo:<owner>    counter, committed entries per owner.
//	c:ep:<peer>     counter, committed entries per peer.
//	c:ro:<owner>    counter, outstanding reservations per owner.
//	c:rp:<peer>     counter, outstanding reservations per peer.
//	rt:g:<bucket>   counter, issuances in the current global rate bucket.
//	rt:o:<o>:<bkt>  counter, issuances in the current owner rate bucket.
//	rt:p:<p>:<bkt>  counter, issuances in the current peer rate bucket.
//
// Every key above carries a TTL. Counters are refreshed on each write to outlive
// whatever they count plus redisCounterSlack, so a counter that drifts because an
// entry expired on its own (instead of being consumed) resets itself instead of
// permanently exhausting capacity.
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
	limits    redisLimits
	resTTL    time.Duration
}

// redisLimits is the normalized form of ChallengeStoreConfig used by the Lua
// scripts.
type redisLimits struct {
	capacity                              int
	perOwnerCapacity, perPeerCapacity     int
	concurrentCapacity                    int
	perOwnerConcurrent, perPeerConcurrent int
	rateWindow                            time.Duration
	globalRate, perOwnerRate, perPeerRate int
}

// redisCounterSlack extends every counter TTL past the lifetime of the entries
// it counts so natural expiry self-heals instead of leaking.
const redisCounterSlack = time.Minute

// NewRedisBackend parses the redis URL, verifies the server answers PING and
// returns a ready backend. Prefer loopback/private hosts.
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
	limits := cfg.Limits
	limits.applyDefaults()
	resTTL := cfg.ReservationTTL
	if resTTL <= 0 {
		resTTL = generationReservationTTL
	}
	r := &RedisBackend{
		addr:     net.JoinHostPort(host, port),
		db:       db,
		password: pass,
		prefix:   prefix,
		failOpen: cfg.FailOpen,
		useTLS:   u.Scheme == "rediss",
		resTTL:   resTTL,
		limits: redisLimits{
			capacity:           limits.Capacity,
			perOwnerCapacity:   limits.PerOwnerCapacity,
			perPeerCapacity:    limits.PerPeerCapacity,
			concurrentCapacity: limits.ConcurrentCapacity,
			perOwnerConcurrent: limits.PerOwnerConcurrent,
			perPeerConcurrent:  limits.PerPeerConcurrent,
			rateWindow:         limits.RateWindow,
			globalRate:         limits.GlobalRate,
			perOwnerRate:       limits.PerOwnerRate,
			perPeerRate:        limits.PerPeerRate,
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := r.do(ctx, "PING"); err != nil {
		_ = r.Close()
		return nil, fmt.Errorf("redis handshake: %w", err)
	}
	return r, nil
}

func (r *RedisBackend) entryKey(jti string) string { return r.prefix + "j:" + jti }

func (r *RedisBackend) Add(ctx context.Context, jti, owner string, exp time.Time) error {
	if jti == "" || exp.IsZero() {
		return errors.New("jti and expiration required")
	}
	ttl := time.Until(exp)
	if ttl <= 0 {
		return errors.New("challenge already expired")
	}
	val := owner
	if val == "" {
		val = "1"
	}
	// Entries created here take no capacity slot, so Consume must not decrement
	// any counter for them. The bare owner value (no length prefix) is what tells
	// the consume script apart from a Commit-created entry.
	err := r.do(ctx, "SET", r.entryKey(jti), val, "PX", strconv.FormatInt(ttl.Milliseconds(), 10), "NX")
	if err != nil {
		if r.failOpen {
			return nil
		}
		return err
	}
	return nil
}

// Consume deletes the jti and releases the capacity it held. Returns false if
// missing, expired, or already used.
func (r *RedisBackend) Consume(ctx context.Context, jti string) bool {
	if jti == "" {
		return false
	}
	n, err := r.doInt(ctx, "EVAL", redisConsumeScript, "0", r.prefix, jti)
	if err != nil {
		return r.failOpen
	}
	return n == 1
}

// ReserveScoped claims one capacity slot for owner/peer. The returned
// reservation must be committed or rolled back.
func (r *RedisBackend) ReserveScoped(ctx context.Context, owner, peer string, exp time.Time) (*ChallengeReservation, error) {
	now := time.Now()
	if exp.IsZero() {
		return nil, errors.New("challenge expiration required")
	}
	if !now.Before(exp) {
		return nil, errors.New("challenge already expired")
	}
	// The lease bounds how long this reservation can hold its slot while the
	// caller generates the puzzle; it never outlives the requested expiry.
	expires := exp
	if lease := now.Add(r.resTTL); lease.Before(expires) {
		expires = lease
	}
	leaseMS := expires.Sub(now).Milliseconds()
	if leaseMS < 1 {
		leaseMS = 1
	}
	slackMS := redisCounterSlack.Milliseconds()
	windowMS := r.limits.rateWindow.Milliseconds()
	rateOn := "0"
	if windowMS > 0 {
		rateOn = "1"
	}
	bucketMS := windowMS
	if bucketMS < 1 {
		bucketMS = 1
	}
	raw, err := r.doString(ctx, "EVAL", redisReserveScript, "0",
		r.prefix,
		strconv.FormatInt(now.UnixMilli(), 10),
		strconv.FormatInt(leaseMS, 10),
		strconv.FormatInt(expires.UnixMilli(), 10),
		strconv.Itoa(r.limits.capacity),
		strconv.Itoa(r.limits.concurrentCapacity),
		strconv.Itoa(r.limits.perOwnerCapacity),
		strconv.Itoa(r.limits.perPeerCapacity),
		strconv.Itoa(r.limits.perOwnerConcurrent),
		strconv.Itoa(r.limits.perPeerConcurrent),
		rateOn,
		strconv.Itoa(r.limits.globalRate),
		strconv.Itoa(r.limits.perOwnerRate),
		strconv.Itoa(r.limits.perPeerRate),
		strconv.FormatInt(windowMS+leaseMS+slackMS, 10),
		boolFlag(owner != ""),
		boolFlag(peer != ""),
		owner,
		peer,
		strconv.FormatInt(slackMS, 10),
		strconv.FormatInt(now.UnixMilli()/bucketMS, 10),
	)
	if err != nil {
		if r.failOpen {
			// No accounting happened, so hand back an untracked reservation that
			// Commit will publish without counters.
			return &ChallengeReservation{owner: owner, peer: peer, expires: expires}, nil
		}
		return nil, fmt.Errorf("redis reserve: %w", err)
	}
	code, id, ok := splitCodeID(raw)
	if !ok {
		return nil, fmt.Errorf("redis reserve: unexpected reply %q", raw)
	}
	switch code {
	case redisReserveOK:
		return &ChallengeReservation{id: id, owner: owner, peer: peer, expires: expires}, nil
	case redisReserveCapacity:
		return nil, ErrChallengeCapacity
	case redisReserveRateLimited:
		return nil, errors.New("challenge issuance rate reached")
	default:
		return nil, fmt.Errorf("redis reserve: unexpected code %d", code)
	}
}

// Start marks generation as begun, which makes the rate token irrevocable.
func (r *RedisBackend) Start(ctx context.Context, reservation *ChallengeReservation) error {
	if reservation == nil {
		return errors.New("challenge reservation required")
	}
	if !reservationTracked(reservation) {
		return nil
	}
	n, err := r.doInt(ctx, "EVAL", redisStartScript, "0", r.prefix,
		strconv.FormatUint(reservation.id, 10), strconv.FormatInt(time.Now().UnixMilli(), 10))
	if err != nil {
		if r.failOpen {
			return nil
		}
		return fmt.Errorf("redis start: %w", err)
	}
	switch n {
	case redisStartOK:
		return nil
	case redisStartStale:
		return errors.New("challenge reservation is stale")
	case redisStartExpired:
		return errors.New("challenge reservation expired")
	case redisStartAlreadyStarted:
		return errors.New("challenge reservation was already started")
	default:
		return fmt.Errorf("redis start: unexpected code %d", n)
	}
}

// Commit publishes jti and releases the reservation. Callers must Rollback when
// it fails.
func (r *RedisBackend) Commit(ctx context.Context, reservation *ChallengeReservation, jti string, exp time.Time) error {
	if reservation == nil || jti == "" || exp.IsZero() {
		return errors.New("challenge reservation, jti, and expiration required")
	}
	ttlMS := time.Until(exp).Milliseconds()
	if ttlMS < 1 {
		_ = r.Rollback(ctx, reservation)
		return errors.New("challenge already expired")
	}
	if !reservationTracked(reservation) {
		// Fail-open reservation: publish without accounting. A bare value keeps
		// Consume from decrementing counters that were never incremented.
		if err := r.do(ctx, "SET", r.entryKey(jti), "1", "PX", strconv.FormatInt(ttlMS, 10), "NX"); err != nil && !r.failOpen {
			return fmt.Errorf("redis commit: %w", err)
		}
		return nil
	}
	n, err := r.doInt(ctx, "EVAL", redisCommitScript, "0", r.prefix,
		strconv.FormatUint(reservation.id, 10), jti,
		strconv.FormatInt(time.Now().UnixMilli(), 10),
		strconv.FormatInt(ttlMS, 10),
		strconv.FormatInt(redisCounterSlack.Milliseconds(), 10))
	if err != nil {
		if r.failOpen {
			return nil
		}
		_ = r.Rollback(ctx, reservation)
		return fmt.Errorf("redis commit: %w", err)
	}
	switch n {
	case redisCommitOK:
		return nil
	case redisCommitStale:
		return errors.New("challenge reservation is stale")
	case redisCommitDuplicate:
		_ = r.Rollback(ctx, reservation)
		return errors.New("duplicate jti")
	case redisCommitNotStarted:
		_ = r.Rollback(ctx, reservation)
		return errors.New("challenge work was not started")
	case redisCommitExpired:
		_ = r.Rollback(ctx, reservation)
		return errors.New("challenge reservation expired")
	default:
		_ = r.Rollback(ctx, reservation)
		return fmt.Errorf("redis commit: unexpected code %d", n)
	}
}

// Rollback releases the capacity held by reservation.
func (r *RedisBackend) Rollback(ctx context.Context, reservation *ChallengeReservation) bool {
	if reservation == nil {
		return false
	}
	if !reservationTracked(reservation) {
		// Nothing was reserved in Redis, so there is nothing to release.
		return true
	}
	n, err := r.doInt(ctx, "EVAL", redisRollbackScript, "0", r.prefix, strconv.FormatUint(reservation.id, 10))
	if err != nil {
		return false
	}
	// redisRollbackUnknown means the reservation was already gone: committed,
	// released, or its lease expired. There is nothing left to give back.
	return n == redisRollbackReleased
}

// AddScopedWithPeer runs the full lifecycle for callers that do not need to do
// work between reserving and publishing.
func (r *RedisBackend) AddScopedWithPeer(ctx context.Context, jti, owner, peer string, exp time.Time) error {
	reservation, err := r.ReserveScoped(ctx, owner, peer, exp)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			r.Rollback(ctx, reservation)
		}
	}()
	if err := r.Start(ctx, reservation); err != nil {
		return err
	}
	if err := r.Commit(ctx, reservation, jti, exp); err != nil {
		return err
	}
	committed = true
	return nil
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

// reservationTracked reports whether the reservation holds real Redis capacity.
// Id 0 marks the synthetic reservation handed out while fail-open.
func reservationTracked(r *ChallengeReservation) bool { return r != nil && r.id != 0 }

func boolFlag(v bool) string {
	if v {
		return "1"
	}
	return "0"
}

// splitCodeID parses the "code:id" reply of the reserve script.
func splitCodeID(raw string) (code int64, id uint64, ok bool) {
	i := strings.IndexByte(raw, ':')
	if i < 0 {
		return 0, 0, false
	}
	code, err := strconv.ParseInt(raw[:i], 10, 64)
	if err != nil {
		return 0, 0, false
	}
	if rest := raw[i+1:]; rest != "" {
		id, err = strconv.ParseUint(rest, 10, 64)
		if err != nil {
			return 0, 0, false
		}
	}
	return code, id, true
}

// Reply codes shared between the Go side and the Lua scripts. Scripts only ever
// return integers or a single string, because the minimal RESP reader below does
// not parse nested arrays.
const (
	redisReserveOK           = 0
	redisReserveCapacity     = 1
	redisReserveRateLimited  = 2
	redisStartOK             = 0
	redisStartStale          = 1
	redisStartExpired        = 2
	redisStartAlreadyStarted = 3
	redisCommitOK            = 0
	redisCommitStale         = 1
	redisCommitDuplicate     = 2
	redisCommitNotStarted    = 3
	redisCommitExpired       = 4
	redisRollbackReleased    = 0
	redisRollbackUnknown     = 1
)

// redisReserveScript takes one capacity slot and one rate token, records the
// reservation and returns "<code>:<id>".
const redisReserveScript = `
local p       = ARGV[1]
local now     = tonumber(ARGV[2])
local lease   = tonumber(ARGV[3])
local expires = tonumber(ARGV[4])
local cap     = tonumber(ARGV[5])
local concCap = tonumber(ARGV[6])
local oCap    = tonumber(ARGV[7])
local pCap    = tonumber(ARGV[8])
local oConc   = tonumber(ARGV[9])
local pConc   = tonumber(ARGV[10])
local rateOn  = ARGV[11] == '1'
local gRate   = tonumber(ARGV[12])
local oRate   = tonumber(ARGV[13])
local pRate   = tonumber(ARGV[14])
local rateTTL = tonumber(ARGV[15])
local oScoped = ARGV[16] == '1'
local pScoped = ARGV[17] == '1'
local owner   = ARGV[18]
local peer    = ARGV[19]
local slack   = tonumber(ARGV[20])
local bucket  = ARGV[21]

local total = p .. 'c:t'
local conc  = p .. 'c:c'
local oRes  = p .. 'c:ro:' .. owner
local pRes  = p .. 'c:rp:' .. peer
local oEnt  = p .. 'c:eo:' .. owner
local pEnt  = p .. 'c:ep:' .. peer
local rtG   = p .. 'rt:g:' .. bucket
local rtO   = p .. 'rt:o:' .. owner .. ':' .. bucket
local rtP   = p .. 'rt:p:' .. peer .. ':' .. bucket

local function num(key) return tonumber(redis.call('GET', key) or '0') end
local function touch(key, ttl)
  if ttl > 0 and redis.call('PTTL', key) < ttl then redis.call('PEXPIRE', key, ttl) end
end

if num(total) + 1 > cap then return '1:0' end
if num(conc) + 1 > concCap then return '1:0' end
if oScoped and num(oEnt) + num(oRes) + 1 > oCap then return '1:0' end
if oScoped and num(oRes) + 1 > oConc then return '1:0' end
if pScoped and num(pEnt) + num(pRes) + 1 > pCap then return '1:0' end
if pScoped and num(pRes) + 1 > pConc then return '1:0' end
if rateOn then
  if num(rtG) + 1 > gRate then return '2:0' end
  if oScoped and num(rtO) + 1 > oRate then return '2:0' end
  if pScoped and num(rtP) + 1 > pRate then return '2:0' end
end

local id  = redis.call('INCR', p .. 'seq')
local rec = p .. 'r:' .. id
redis.call('INCR', total)
redis.call('INCR', conc)
if oScoped then redis.call('INCR', oRes) end
if pScoped then redis.call('INCR', pRes) end
if rateOn then
  redis.call('INCR', rtG)
  redis.call('PEXPIRE', rtG, rateTTL)
  if oScoped then redis.call('INCR', rtO); redis.call('PEXPIRE', rtO, rateTTL) end
  if pScoped then redis.call('INCR', rtP); redis.call('PEXPIRE', rtP, rateTTL) end
end

local ttl = (expires - now) + slack
touch(total, ttl)
touch(conc, lease + slack)
if oScoped then touch(oRes, lease + slack) touch(oEnt, ttl) end
if pScoped then touch(pRes, lease + slack) touch(pEnt, ttl) end

redis.call('HSET', rec,
  'owner', owner, 'peer', peer, 'exp', tostring(expires),
  'started', '0', 'os', ARGV[16], 'ps', ARGV[17],
  'rate', ARGV[11], 'bucket', bucket)
redis.call('PEXPIRE', rec, lease)
return '0:' .. tostring(id)
`

// redisStartScript flips the reservation to started so the rate token can no
// longer be refunded.
const redisStartScript = `
local rec = ARGV[1] .. 'r:' .. ARGV[2]
local now = tonumber(ARGV[3])
if redis.call('EXISTS', rec) == 0 then return 1 end
local exp = tonumber(redis.call('HGET', rec, 'exp') or '0')
if now >= exp then return 2 end
if redis.call('HGET', rec, 'started') == '1' then return 3 end
redis.call('HSET', rec, 'started', '1')
return 0
`

// redisCommitScript moves the reservation into a published jti. Total capacity
// is unchanged: a reservation becomes an entry.
const redisCommitScript = `
local p        = ARGV[1]
local id       = ARGV[2]
local jti      = ARGV[3]
local now      = tonumber(ARGV[4])
local entryTTL = tonumber(ARGV[5])
local slack    = tonumber(ARGV[6])

local function touch(key, ttl)
  if ttl > 0 and redis.call('PTTL', key) < ttl then redis.call('PEXPIRE', key, ttl) end
end

local rec = p .. 'r:' .. id
if redis.call('EXISTS', rec) == 0 then return 1 end
local f = redis.call('HMGET', rec, 'exp', 'started', 'owner', 'peer', 'os', 'ps')
if now >= tonumber(f[1] or '0') then return 4 end
local jkey = p .. 'j:' .. jti
if redis.call('EXISTS', jkey) == 1 then return 2 end
if f[2] ~= '1' then return 3 end

local owner, peer = f[3] or '', f[4] or ''
local oScoped, pScoped = f[5] == '1', f[6] == '1'
local oEnt = p .. 'c:eo:' .. owner
local pEnt = p .. 'c:ep:' .. peer

redis.call('SET', jkey, string.len(owner) .. ':' .. owner .. string.len(peer) .. ':' .. peer, 'PX', entryTTL)
redis.call('DECR', p .. 'c:c')
if oScoped then redis.call('DECR', p .. 'c:ro:' .. owner) redis.call('INCR', oEnt) end
if pScoped then redis.call('DECR', p .. 'c:rp:' .. peer) redis.call('INCR', pEnt) end
local ttl = entryTTL + slack
if oScoped then touch(oEnt, ttl) end
if pScoped then touch(pEnt, ttl) end
redis.call('DEL', rec)
return 0
`

// redisRollbackScript gives back everything reserve took. The rate token is only
// refunded when generation never started, matching the in-process store.
const redisRollbackScript = `
local p   = ARGV[1]
local id  = ARGV[2]
local rec = p .. 'r:' .. id
if redis.call('EXISTS', rec) == 0 then return 1 end
local f = redis.call('HMGET', rec, 'started', 'owner', 'peer', 'os', 'ps', 'rate', 'bucket')
local owner, peer = f[2] or '', f[3] or ''
local oScoped, pScoped = f[4] == '1', f[5] == '1'

redis.call('DECR', p .. 'c:t')
redis.call('DECR', p .. 'c:c')
if oScoped then redis.call('DECR', p .. 'c:ro:' .. owner) end
if pScoped then redis.call('DECR', p .. 'c:rp:' .. peer) end
if f[6] == '1' and f[1] ~= '1' then
  local b = f[7] or '0'
  redis.call('DECR', p .. 'rt:g:' .. b)
  if oScoped then redis.call('DECR', p .. 'rt:o:' .. owner .. ':' .. b) end
  if pScoped then redis.call('DECR', p .. 'rt:p:' .. peer .. ':' .. b) end
end
redis.call('DEL', rec)
return 0
`

// redisConsumeScript deletes a jti and releases its capacity. An entry written by
// Add (bare owner, no length prefix) carries no capacity and is only deleted.
const redisConsumeScript = `
local p    = ARGV[1]
local jkey = p .. 'j:' .. ARGV[2]
local v    = redis.call('GET', jkey)
if not v then return 0 end
redis.call('DEL', jkey)

local sep = string.find(v, ':', 1, true)
if not sep then return 1 end
local olen = tonumber(string.sub(v, 1, sep - 1))
if not olen then return 1 end
local owner = string.sub(v, sep + 1, sep + olen)
local rest  = string.sub(v, sep + olen + 1)
local sep2  = string.find(rest, ':', 1, true)
if not sep2 then return 1 end
local plen = tonumber(string.sub(rest, 1, sep2 - 1))
if not plen then return 1 end
local peer = string.sub(rest, sep2 + 1, sep2 + plen)

redis.call('DECR', p .. 'c:t')
if owner ~= '' then redis.call('DECR', p .. 'c:eo:' .. owner) end
if peer ~= '' then redis.call('DECR', p .. 'c:ep:' .. peer) end
return 1
`

// ensureConnLocked dials and authenticates. Caller must hold r.mu.
func (r *RedisBackend) ensureConnLocked(ctx context.Context) (net.Conn, error) {
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
	_, err := r.doReply(ctx, args...)
	return err
}

func (r *RedisBackend) doString(ctx context.Context, args ...string) (string, error) {
	v, err := r.doReply(ctx, args...)
	if err != nil {
		return "", err
	}
	if v == nil {
		return "", nil
	}
	s, _ := v.(string)
	return s, nil
}

// doInt reads an integer reply. Lua scripts that need to report both a status and
// a value return a "code:id" string instead and use doString.
func (r *RedisBackend) doInt(ctx context.Context, args ...string) (int64, error) {
	s, err := r.doString(ctx, args...)
	if err != nil {
		return 0, err
	}
	if strings.TrimSpace(s) == "" {
		return 0, nil
	}
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("redis reply %q: %w", s, err)
	}
	return n, nil
}

func (r *RedisBackend) doReply(ctx context.Context, args ...string) (any, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	conn, err := r.ensureConnLocked(ctx)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if err := r.writeCommand(conn, args...); err != nil {
		_ = conn.Close()
		r.conn = nil
		return nil, err
	}
	v, err := r.readReply(conn)
	if err != nil {
		_ = conn.Close()
		r.conn = nil
		return nil, err
	}
	return v, nil
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
