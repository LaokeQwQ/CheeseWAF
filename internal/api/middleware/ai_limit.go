package middleware

import (
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultAIMaxRequests = 10
	defaultAIMaxInFlight = 2
	defaultAIMaxSubjects = 4096
	defaultAIWindow      = time.Minute
	defaultAISubjectTTL  = 10 * time.Minute
)

type AIRequestLimitOptions struct {
	MaxRequests int
	MaxInFlight int
	MaxSubjects int
	Window      time.Duration
	SubjectTTL  time.Duration
	Now         func() time.Time
}

type aiRequestLimitState struct {
	windowStart time.Time
	requests    int
	inFlight    int
	lastSeen    time.Time
}

// AIRequestLimiter bounds paid AI work per authenticated principal. The map is
// TTL-pruned and capacity-bounded so arbitrary API-token subjects cannot grow it forever.
type AIRequestLimiter struct {
	mu          sync.Mutex
	states      map[string]*aiRequestLimitState
	maxRequests int
	maxInFlight int
	maxSubjects int
	window      time.Duration
	subjectTTL  time.Duration
	now         func() time.Time
}

func NewAIRequestLimiter(options AIRequestLimitOptions) *AIRequestLimiter {
	if options.MaxRequests <= 0 {
		options.MaxRequests = defaultAIMaxRequests
	}
	if options.MaxInFlight <= 0 {
		options.MaxInFlight = defaultAIMaxInFlight
	}
	if options.MaxSubjects <= 0 {
		options.MaxSubjects = defaultAIMaxSubjects
	}
	if options.Window <= 0 {
		options.Window = defaultAIWindow
	}
	if options.SubjectTTL <= 0 {
		options.SubjectTTL = defaultAISubjectTTL
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	return &AIRequestLimiter{
		states:      make(map[string]*aiRequestLimitState),
		maxRequests: options.MaxRequests,
		maxInFlight: options.MaxInFlight,
		maxSubjects: options.MaxSubjects,
		window:      options.Window,
		subjectTTL:  options.SubjectTTL,
		now:         options.Now,
	}
}

func (l *AIRequestLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, _ := r.Context().Value(UserContextKey).(*Claims)
		key := aiRequestSubjectKey(claims)
		if key == "" {
			writeUnauthorized(w)
			return
		}
		release, code, retryAfter := l.acquire(key)
		if release == nil {
			if retryAfter > 0 {
				w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Round(time.Second)/time.Second)))
			}
			writeAPIError(w, http.StatusTooManyRequests, code, "AI request budget exceeded")
			return
		}
		defer release()
		next.ServeHTTP(w, r)
	})
}

func aiRequestSubjectKey(claims *Claims) string {
	if claims == nil {
		return ""
	}
	subject := strings.TrimSpace(claims.Subject)
	if subject == "" {
		return ""
	}
	return strings.TrimSpace(claims.Role) + ":" + subject
}

func (l *AIRequestLimiter) acquire(key string) (func(), string, time.Duration) {
	if l == nil {
		return nil, "AI_RATE_LIMITED", defaultAIWindow
	}
	now := l.now().UTC()
	l.mu.Lock()
	l.pruneLocked(now)
	state := l.states[key]
	if state == nil {
		if len(l.states) >= l.maxSubjects {
			l.evictOldestInactiveLocked()
		}
		if len(l.states) >= l.maxSubjects {
			l.mu.Unlock()
			return nil, "AI_RATE_LIMIT_CAPACITY", l.subjectTTL
		}
		state = &aiRequestLimitState{windowStart: now}
		l.states[key] = state
	}
	if now.Sub(state.windowStart) >= l.window {
		state.windowStart = now
		state.requests = 0
	}
	state.lastSeen = now
	if state.inFlight >= l.maxInFlight {
		l.mu.Unlock()
		return nil, "AI_CONCURRENCY_LIMITED", time.Second
	}
	if state.requests >= l.maxRequests {
		retryAfter := l.window - now.Sub(state.windowStart)
		l.mu.Unlock()
		return nil, "AI_RATE_LIMITED", retryAfter
	}
	state.requests++
	state.inFlight++
	l.mu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			if current := l.states[key]; current != nil {
				if current.inFlight > 0 {
					current.inFlight--
				}
				current.lastSeen = l.now().UTC()
			}
			l.mu.Unlock()
		})
	}, "", 0
}

func (l *AIRequestLimiter) pruneLocked(now time.Time) {
	for key, state := range l.states {
		if state.inFlight == 0 && now.Sub(state.lastSeen) >= l.subjectTTL {
			delete(l.states, key)
		}
	}
}

func (l *AIRequestLimiter) evictOldestInactiveLocked() {
	var oldestKey string
	var oldest time.Time
	for key, state := range l.states {
		if state.inFlight != 0 {
			continue
		}
		if oldestKey == "" || state.lastSeen.Before(oldest) {
			oldestKey = key
			oldest = state.lastSeen
		}
	}
	if oldestKey != "" {
		delete(l.states, oldestKey)
	}
}
