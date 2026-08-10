package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/LaokeQwQ/CheeseWAF/internal/timekeeper"
)

const (
	defaultAuditFileBytes int64 = 8 << 20
	defaultAuditBackups         = 3
	defaultDeniedAuditPerMinute = 120
	maxAuditQueryLimit          = 1000
	maxAuditLineBytes           = 24 << 10
	auditReadBufferBytes        = 16 << 10

	maxAuditSubjectBytes  = 128
	maxAuditUserBytes     = 128
	maxAuditRoleBytes     = 64
	maxAuditMethodBytes   = 16
	maxAuditPathBytes     = 2048
	maxAuditRemoteIPBytes = 64
	maxAuditTargetBytes   = 512
	maxAuditMessageBytes  = 1024
)

type AuditEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Subject   string    `json:"subject,omitempty"`
	User      string    `json:"user"`
	Role      string    `json:"role"`
	Method    string    `json:"method"`
	Path      string    `json:"path"`
	Status    int       `json:"status"`
	RemoteIP  string    `json:"remote_ip"`
	LatencyMS int64     `json:"latency_ms"`
	Target    string    `json:"target,omitempty"`
	Message   string    `json:"message,omitempty"`
}

type Auditor struct {
	path         string
	mu           sync.Mutex
	now          func() time.Time
	maxFileBytes int64
	maxBackups   int
	quotaChecked bool
	deniedMu     sync.Mutex
	deniedStart  time.Time
	deniedCount  int
	deniedLimit  int
}

func NewAuditor(path string) *Auditor {
	return NewAuditorWithClock(path, timekeeper.SystemClock{})
}

func NewAuditorWithClock(path string, clock timekeeper.Clock) *Auditor {
	return &Auditor{
		path:         path,
		now:          utcNowFunc(clock),
		maxFileBytes: defaultAuditFileBytes,
		maxBackups:   defaultAuditBackups,
		deniedLimit:  defaultDeniedAuditPerMinute,
	}
}

func (a *Auditor) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		start := time.Now()
		next.ServeHTTP(recorder, r)
		now := a.nowUTC()
		if (recorder.status == http.StatusUnauthorized || recorder.status == http.StatusForbidden) && !a.allowDeniedAudit(now) {
			return
		}
		claims, _ := r.Context().Value(UserContextKey).(*Claims)
		entry := AuditEntry{
			Timestamp: now,
			Method:    r.Method,
			Path:      r.URL.Path,
			Status:    recorder.status,
			RemoteIP:  r.RemoteAddr,
			LatencyMS: time.Since(start).Milliseconds(),
		}
		if claims != nil {
			entry.Subject = claims.Subject
			entry.User = claims.Username
			entry.Role = claims.Role
		}
		entry = normalizeAuditEntry(entry)
		if err := a.Write(context.WithoutCancel(r.Context()), entry); err != nil {
			log.Printf("audit: write failed method=%q path=%q status=%d: %v", entry.Method, entry.Path, entry.Status, err)
		}
	})
}

func (a *Auditor) allowDeniedAudit(now time.Time) bool {
	if a == nil {
		return false
	}
	limit := a.deniedLimit
	if limit <= 0 {
		limit = defaultDeniedAuditPerMinute
	}
	a.deniedMu.Lock()
	defer a.deniedMu.Unlock()
	if a.deniedStart.IsZero() || now.Before(a.deniedStart) || now.Sub(a.deniedStart) >= time.Minute {
		a.deniedStart = now
		a.deniedCount = 0
	}
	if a.deniedCount >= limit {
		return false
	}
	a.deniedCount++
	return true
}

func (a *Auditor) nowUTC() time.Time {
	if a == nil || a.now == nil {
		return timekeeper.SystemClock{}.Now().UTC()
	}
	return a.now()
}

func (a *Auditor) Write(ctx context.Context, entry AuditEntry) error {
	if a == nil || a.path == "" {
		return nil
	}
	if err := ctx.Err(); err != nil {
		log.Printf("audit: context cancelled before write path=%s: %v", a.path, err)
		return err
	}
	if err := os.MkdirAll(filepath.Dir(a.path), 0o750); err != nil {
		log.Printf("audit: mkdir failed path=%s: %v", a.path, err)
		return err
	}
	data, err := marshalAuditEntry(entry)
	if err != nil {
		log.Printf("audit: marshal failed: %v", err)
		return err
	}
	data = append(data, '\n')
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.prepareWriteLocked(int64(len(data))); err != nil {
		log.Printf("audit: rotate failed path=%s: %v", a.path, err)
		return err
	}
	file, err := os.OpenFile(a.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		log.Printf("audit: open failed path=%s: %v", a.path, err)
		return err
	}
	defer file.Close()
	if _, err = file.Write(data); err != nil {
		log.Printf("audit: write failed path=%s: %v", a.path, err)
		return err
	}
	return nil
}

func (a *Auditor) Query(limit int) ([]AuditEntry, error) {
	if a == nil || a.path == "" {
		return nil, nil
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > maxAuditQueryLimit {
		limit = maxAuditQueryLimit
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	entries := make([]AuditEntry, 0, limit)
	for _, path := range a.queryPathsLocked() {
		err := a.readFileReverseLocked(path, func(data []byte) bool {
			var entry AuditEntry
			if err := json.Unmarshal(data, &entry); err != nil {
				return true
			}
			entries = append(entries, normalizeAuditEntry(entry))
			return len(entries) < limit
		})
		if err != nil {
			return nil, err
		}
		if len(entries) == limit {
			break
		}
	}
	for left, right := 0, len(entries)-1; left < right; left, right = left+1, right-1 {
		entries[left], entries[right] = entries[right], entries[left]
	}
	return entries, nil
}

func marshalAuditEntry(entry AuditEntry) ([]byte, error) {
	data, err := json.Marshal(normalizeAuditEntry(entry))
	if err != nil {
		return nil, err
	}
	if len(data) > maxAuditLineBytes {
		return nil, fmt.Errorf("audit entry is %d bytes, maximum is %d", len(data), maxAuditLineBytes)
	}
	return data, nil
}

func normalizeAuditEntry(entry AuditEntry) AuditEntry {
	if !entry.Timestamp.IsZero() {
		entry.Timestamp = entry.Timestamp.UTC()
	}
	entry.Subject = truncateAuditField(entry.Subject, maxAuditSubjectBytes)
	entry.User = truncateAuditField(entry.User, maxAuditUserBytes)
	entry.Role = truncateAuditField(entry.Role, maxAuditRoleBytes)
	entry.Method = truncateAuditField(entry.Method, maxAuditMethodBytes)
	entry.Path = truncateAuditField(entry.Path, maxAuditPathBytes)
	entry.RemoteIP = truncateAuditField(entry.RemoteIP, maxAuditRemoteIPBytes)
	entry.Target = truncateAuditField(entry.Target, maxAuditTargetBytes)
	entry.Message = truncateAuditField(entry.Message, maxAuditMessageBytes)
	return entry
}

func truncateAuditField(value string, maxBytes int) string {
	if maxBytes <= 0 {
		return ""
	}
	value = strings.ToValidUTF8(value, "\uFFFD")
	if len(value) <= maxBytes {
		return value
	}
	end := maxBytes
	for end > 0 && !utf8.ValidString(value[:end]) {
		end--
	}
	return value[:end]
}

func (a *Auditor) rotationLimits() (int64, int) {
	maxBytes := a.maxFileBytes
	if maxBytes <= 0 {
		maxBytes = defaultAuditFileBytes
	}
	backups := a.maxBackups
	if backups < 0 {
		backups = 0
	}
	return maxBytes, backups
}

func (a *Auditor) prepareWriteLocked(writeBytes int64) error {
	maxBytes, backups := a.rotationLimits()
	if writeBytes > maxBytes {
		return fmt.Errorf("audit entry is %d bytes, file budget is %d", writeBytes, maxBytes)
	}
	if !a.quotaChecked {
		if err := a.cleanupBackupsLocked(maxBytes, backups); err != nil {
			return err
		}
		a.quotaChecked = true
	}
	info, err := os.Stat(a.path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Size() > maxBytes {
		return os.Remove(a.path)
	}
	if info.Size()+writeBytes <= maxBytes {
		return nil
	}
	return a.rotateLocked(maxBytes, backups)
}

func (a *Auditor) cleanupBackupsLocked(maxBytes int64, backups int) error {
	dir := filepath.Dir(a.path)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	prefix := filepath.Base(a.path) + "."
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}
		index, err := strconv.Atoi(strings.TrimPrefix(entry.Name(), prefix))
		if err != nil || index < 1 {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if index <= backups && info.Size() <= maxBytes {
			continue
		}
		if err := os.Remove(filepath.Join(dir, entry.Name())); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func (a *Auditor) rotateLocked(maxBytes int64, backups int) error {
	if err := a.cleanupBackupsLocked(maxBytes, backups); err != nil {
		return err
	}
	if backups == 0 {
		return os.Remove(a.path)
	}
	for index := backups; index >= 2; index-- {
		source := a.path + "." + strconv.Itoa(index-1)
		target := a.path + "." + strconv.Itoa(index)
		if err := os.Remove(target); err != nil && !os.IsNotExist(err) {
			return err
		}
		if err := os.Rename(source, target); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	firstBackup := a.path + ".1"
	if err := os.Remove(firstBackup); err != nil && !os.IsNotExist(err) {
		return err
	}
	return os.Rename(a.path, firstBackup)
}

func (a *Auditor) queryPathsLocked() []string {
	_, backups := a.rotationLimits()
	paths := make([]string, 0, backups+1)
	paths = append(paths, a.path)
	for index := 1; index <= backups; index++ {
		paths = append(paths, a.path+"."+strconv.Itoa(index))
	}
	return paths
}

func (a *Auditor) readFileReverseLocked(path string, visit func([]byte) bool) error {
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer file.Close()

	maxBytes, _ := a.rotationLimits()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	start := int64(0)
	if info.Size() > maxBytes {
		start = info.Size() - maxBytes
	}
	completeAtStart := start == 0
	if !completeAtStart {
		var previous [1]byte
		if _, err := file.ReadAt(previous[:], start-1); err != nil {
			return err
		}
		completeAtStart = previous[0] == '\n'
	}
	return readBoundedAuditLinesReverse(file, start, info.Size(), completeAtStart, visit)
}

func readBoundedAuditLinesReverse(reader io.ReaderAt, start, end int64, completeAtStart bool, visit func([]byte) bool) error {
	buffer := make([]byte, auditReadBufferBytes)
	reversedLine := make([]byte, 0, maxAuditLineBytes)
	oversized := false
	visitLine := func() bool {
		defer func() {
			reversedLine = reversedLine[:0]
			oversized = false
		}()
		if oversized || len(reversedLine) == 0 {
			return true
		}
		for left, right := 0, len(reversedLine)-1; left < right; left, right = left+1, right-1 {
			reversedLine[left], reversedLine[right] = reversedLine[right], reversedLine[left]
		}
		if reversedLine[len(reversedLine)-1] == '\r' {
			reversedLine = reversedLine[:len(reversedLine)-1]
		}
		return len(reversedLine) == 0 || visit(reversedLine)
	}
	for position := end; position > start; {
		readBytes := int64(len(buffer))
		if remaining := position - start; remaining < readBytes {
			readBytes = remaining
		}
		position -= readBytes
		n, err := reader.ReadAt(buffer[:int(readBytes)], position)
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		if n != int(readBytes) {
			return io.ErrUnexpectedEOF
		}
		for index := n - 1; index >= 0; index-- {
			if buffer[index] == '\n' {
				if !visitLine() {
					return nil
				}
				continue
			}
			if oversized {
				continue
			}
			if len(reversedLine) == maxAuditLineBytes {
				reversedLine = reversedLine[:0]
				oversized = true
				continue
			}
			reversedLine = append(reversedLine, buffer[index])
		}
	}
	if completeAtStart {
		visitLine()
	}
	return nil
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *statusRecorder) Flush() {
	if flusher, ok := r.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (r *statusRecorder) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}
