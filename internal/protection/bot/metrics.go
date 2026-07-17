package bot

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"sync"
	"time"
)

const defaultChallengeMetricCapacity = 50000

type ChallengeMetricEventType string

const (
	ChallengeMetricIssued         ChallengeMetricEventType = "issued"
	ChallengeMetricSuccess        ChallengeMetricEventType = "success"
	ChallengeMetricFailure        ChallengeMetricEventType = "failure"
	ChallengeMetricBlocked        ChallengeMetricEventType = "blocked"
	ChallengeMetricCAPTCHABlocked ChallengeMetricEventType = "captcha_blocked"
)

type ChallengeMetricEvent struct {
	At         time.Time
	Site       string
	Type       string
	ClientHash string
	Event      ChallengeMetricEventType
}

type ChallengeMetricQuery struct {
	Start  time.Time
	End    time.Time
	Site   string
	Bucket time.Duration
}

type ChallengeMetricTotals struct {
	ChallengedPeople int64   `json:"challenged_people"`
	Challenges       int64   `json:"challenges"`
	BlockedPeople    int64   `json:"blocked_people"`
	Blocks           int64   `json:"blocks"`
	CAPTCHABlocks    int64   `json:"captcha_blocks"`
	Successes        int64   `json:"successes"`
	Failures         int64   `json:"failures"`
	PassRate         float64 `json:"pass_rate"`
}

type ChallengeMetricPoint struct {
	Time      time.Time `json:"time"`
	Type      string    `json:"type"`
	Issued    int64     `json:"issued"`
	Successes int64     `json:"successes"`
	Failures  int64     `json:"failures"`
	Blocks    int64     `json:"blocks"`
}

type ChallengeMetricSnapshot struct {
	Start  time.Time              `json:"start"`
	End    time.Time              `json:"end"`
	Bucket time.Duration          `json:"-"`
	Totals ChallengeMetricTotals  `json:"totals"`
	Trend  []ChallengeMetricPoint `json:"trend"`
}

type ChallengeMetrics struct {
	mu       sync.RWMutex
	events   []ChallengeMetricEvent
	next     int
	full     bool
	capacity int
	salt     [32]byte
	now      func() time.Time
}

func NewChallengeMetrics(capacity int, now func() time.Time) *ChallengeMetrics {
	if capacity < 1 {
		capacity = defaultChallengeMetricCapacity
	}
	if now == nil {
		now = time.Now
	}
	m := &ChallengeMetrics{events: make([]ChallengeMetricEvent, capacity), capacity: capacity, now: now}
	if _, err := rand.Read(m.salt[:]); err != nil {
		m.salt = sha256.Sum256([]byte(time.Now().UTC().String()))
	}
	return m
}

var processChallengeMetrics = NewChallengeMetrics(defaultChallengeMetricCapacity, time.Now)

func ProcessChallengeMetrics() *ChallengeMetrics { return processChallengeMetrics }

func (m *ChallengeMetrics) Record(event ChallengeMetricEventType, site, kind, client string) {
	if m == nil {
		return
	}
	h := sha256.New()
	_, _ = h.Write(m.salt[:])
	_, _ = h.Write([]byte(strings.TrimSpace(client)))
	record := ChallengeMetricEvent{At: m.now().UTC(), Site: strings.TrimSpace(site), Type: normalizeMetricType(kind), ClientHash: hex.EncodeToString(h.Sum(nil)), Event: event}
	m.mu.Lock()
	m.events[m.next] = record
	m.next = (m.next + 1) % m.capacity
	if m.next == 0 {
		m.full = true
	}
	m.mu.Unlock()
}

func (m *ChallengeMetrics) Snapshot(query ChallengeMetricQuery) ChallengeMetricSnapshot {
	if m == nil {
		return ChallengeMetricSnapshot{}
	}
	end := query.End.UTC()
	if end.IsZero() {
		end = m.now().UTC()
	}
	start := query.Start.UTC()
	if start.IsZero() || !start.Before(end) {
		start = end.Add(-24 * time.Hour)
	}
	bucket := query.Bucket
	if bucket <= 0 {
		bucket = time.Hour
	}
	site := strings.TrimSpace(query.Site)
	m.mu.RLock()
	count := m.next
	if m.full {
		count = len(m.events)
	}
	events := make([]ChallengeMetricEvent, 0, count)
	for i := 0; i < count; i++ {
		idx := i
		if m.full {
			idx = (m.next + i) % len(m.events)
		}
		events = append(events, m.events[idx])
	}
	m.mu.RUnlock()

	challenged := map[string]struct{}{}
	blocked := map[string]struct{}{}
	points := map[string]*ChallengeMetricPoint{}
	var totals ChallengeMetricTotals
	for _, event := range events {
		if event.At.Before(start) || !event.At.Before(end) || (site != "" && event.Site != site) {
			continue
		}
		at := event.At.Truncate(bucket)
		key := at.Format(time.RFC3339Nano) + "\x00" + event.Type
		point := points[key]
		if point == nil {
			point = &ChallengeMetricPoint{Time: at, Type: event.Type}
			points[key] = point
		}
		switch event.Event {
		case ChallengeMetricIssued:
			totals.Challenges++
			challenged[event.ClientHash] = struct{}{}
			point.Issued++
		case ChallengeMetricSuccess:
			totals.Successes++
			point.Successes++
		case ChallengeMetricFailure:
			totals.Failures++
			point.Failures++
		case ChallengeMetricBlocked:
			totals.Blocks++
			blocked[event.ClientHash] = struct{}{}
			point.Blocks++
		case ChallengeMetricCAPTCHABlocked:
			totals.Blocks++
			totals.CAPTCHABlocks++
			blocked[event.ClientHash] = struct{}{}
			point.Blocks++
		}
	}
	totals.ChallengedPeople = int64(len(challenged))
	totals.BlockedPeople = int64(len(blocked))
	if attempts := totals.Successes + totals.Failures; attempts > 0 {
		totals.PassRate = float64(totals.Successes) / float64(attempts)
	}
	trend := make([]ChallengeMetricPoint, 0, len(points))
	for _, point := range points {
		trend = append(trend, *point)
	}
	sort.Slice(trend, func(i, j int) bool {
		if trend[i].Time.Equal(trend[j].Time) {
			return trend[i].Type < trend[j].Type
		}
		return trend[i].Time.Before(trend[j].Time)
	})
	return ChallengeMetricSnapshot{Start: start, End: end, Bucket: bucket, Totals: totals, Trend: trend}
}

func normalizeMetricType(kind string) string {
	kind = strings.ToLower(strings.TrimSpace(kind))
	if kind == "" {
		return "unknown"
	}
	return kind
}
