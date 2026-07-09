package log_sink

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

const (
	defaultFileSinkRecentCache = 20000
	maxFileSinkQueryLimit      = 1000
)

type FileSink struct {
	mu           sync.Mutex
	file         *os.File
	writer       *bufio.Writer
	recent       []storage.LogEntry
	recentStart  int
	recentCount  int
	recentMax    int
	total        int64
	actionTotals map[string]int64
}

func NewFileSink(path string) (*FileSink, error) {
	if path == "" {
		return nil, fmt.Errorf("log path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, err
	}
	sink := &FileSink{
		file:         file,
		writer:       bufio.NewWriterSize(file, 64*1024),
		recentMax:    fileSinkRecentCacheLimit(),
		actionTotals: map[string]int64{},
	}
	if err := sink.loadIndex(path); err != nil {
		_ = file.Close()
		return nil, err
	}
	return sink, nil
}

func (s *FileSink) Write(_ context.Context, entry *storage.LogEntry) error {
	if entry == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	if _, err := s.writer.Write(data); err != nil {
		return err
	}
	if err := s.writer.WriteByte('\n'); err != nil {
		return err
	}
	s.indexEntryLocked(*entry)
	return nil
}

func (s *FileSink) Query(ctx context.Context, filter storage.LogFilter) ([]storage.LogEntry, int64, error) {
	if s == nil || s.file == nil {
		return nil, 0, fmt.Errorf("file sink is closed")
	}
	path, recent, total, actionTotals, err := s.snapshot(ctx)
	if err != nil {
		return nil, 0, err
	}
	limit := normalizedLimit(filter.Limit)
	if items, matchedTotal, ok := queryRecent(filter, recent, total, actionTotals, limit); ok {
		return items, matchedTotal, nil
	}
	return s.scanQuery(ctx, path, filter, limit)
}

func (s *FileSink) Count(ctx context.Context, filter storage.LogFilter) (int64, bool, error) {
	if s == nil || s.file == nil {
		return 0, false, fmt.Errorf("file sink is closed")
	}
	path, recent, total, actionTotals, err := s.snapshot(ctx)
	if err != nil {
		return 0, false, err
	}
	if count, ok := countRecent(filter, recent, total, actionTotals); ok {
		return count, true, nil
	}
	count, err := scanCount(ctx, path, filter)
	return count, true, err
}

func (s *FileSink) snapshot(ctx context.Context) (string, []storage.LogEntry, int64, map[string]int64, error) {
	if err := ctx.Err(); err != nil {
		return "", nil, 0, nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.writer.Flush(); err != nil {
		return "", nil, 0, nil, err
	}
	actionTotals := make(map[string]int64, len(s.actionTotals))
	for action, count := range s.actionTotals {
		actionTotals[action] = count
	}
	return s.file.Name(), s.recentSnapshotLocked(), s.total, actionTotals, nil
}

func (s *FileSink) scanQuery(ctx context.Context, path string, filter storage.LogFilter, limit int) ([]storage.LogEntry, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 4<<20)
	var matched []storage.LogEntry
	var total int64
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return nil, total, err
		}
		var entry storage.LogEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			continue
		}
		if !matches(entry, filter) {
			continue
		}
		total++
		matched = append(matched, entry)
	}
	sort.SliceStable(matched, func(i, j int) bool {
		return matched[i].Timestamp.After(matched[j].Timestamp)
	})
	return pageLogs(matched, total, filter.Offset, limit), total, scanner.Err()
}

func (s *FileSink) loadIndex(path string) error {
	if s.recentMax < 0 {
		s.recentMax = 0
	}
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 4<<20)
	for scanner.Scan() {
		var entry storage.LogEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			continue
		}
		s.indexEntryLocked(entry)
	}
	return scanner.Err()
}

func (s *FileSink) indexEntryLocked(entry storage.LogEntry) {
	s.total++
	s.actionTotals[entry.Action]++
	if s.recentMax <= 0 {
		return
	}
	if len(s.recent) < s.recentMax {
		s.recent = append(s.recent, entry)
		s.recentCount = len(s.recent)
		return
	}
	s.recent[s.recentStart] = entry
	s.recentStart = (s.recentStart + 1) % len(s.recent)
	s.recentCount = len(s.recent)
}

func (s *FileSink) recentSnapshotLocked() []storage.LogEntry {
	if s.recentCount == 0 {
		return nil
	}
	out := make([]storage.LogEntry, s.recentCount)
	for i := 0; i < s.recentCount; i++ {
		out[i] = s.recent[(s.recentStart+i)%len(s.recent)]
	}
	return out
}

func (s *FileSink) Flush(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writer.Flush()
}

func (s *FileSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.writer.Flush(); err != nil {
		return err
	}
	return s.file.Close()
}

func fileSinkRecentCacheLimit() int {
	raw := strings.TrimSpace(os.Getenv("CHEESEWAF_FILE_SINK_CACHE_LIMIT"))
	if raw == "" {
		return defaultFileSinkRecentCache
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 0 {
		return defaultFileSinkRecentCache
	}
	return value
}

func normalizedLimit(limit int) int {
	if limit <= 0 {
		return 100
	}
	if limit > maxFileSinkQueryLimit {
		return maxFileSinkQueryLimit
	}
	return limit
}

func queryRecent(filter storage.LogFilter, recent []storage.LogEntry, total int64, actionTotals map[string]int64, limit int) ([]storage.LogEntry, int64, bool) {
	if !canUseRecent(filter, recent, total, limit) {
		return nil, 0, false
	}
	matched := filterRecent(recent, filter)
	matchedTotal := int64(len(matched))
	if !hasTimeFilter(filter) && simpleCountFilter(filter) {
		if filter.Action == "" {
			matchedTotal = total
		} else {
			matchedTotal = actionTotals[filter.Action]
		}
		if matchedTotal > int64(len(matched)) && requiredRows(filter.Offset, limit) > len(matched) {
			return nil, 0, false
		}
	}
	return pageLogs(matched, matchedTotal, filter.Offset, limit), matchedTotal, true
}

func countRecent(filter storage.LogFilter, recent []storage.LogEntry, total int64, actionTotals map[string]int64) (int64, bool) {
	if !hasTimeFilter(filter) && simpleCountFilter(filter) {
		if filter.Action == "" {
			return total, true
		}
		return actionTotals[filter.Action], true
	}
	if !timeRangeCoveredByRecent(filter, recent, total) {
		return 0, false
	}
	return int64(len(filterRecent(recent, filter))), true
}

func canUseRecent(filter storage.LogFilter, recent []storage.LogEntry, total int64, limit int) bool {
	if len(recent) == 0 {
		return total == 0
	}
	if timeRangeCoveredByRecent(filter, recent, total) {
		return true
	}
	if hasTimeFilter(filter) || filter.TraceID != "" || filter.SiteID != "" || filter.ClientIP != "" || filter.Category != "" || len(filter.Tags) > 0 {
		return false
	}
	if !simpleCountFilter(filter) {
		return false
	}
	return requiredRows(filter.Offset, limit) <= len(recent)
}

func timeRangeCoveredByRecent(filter storage.LogFilter, recent []storage.LogEntry, total int64) bool {
	if int64(len(recent)) == total {
		return true
	}
	if !hasTimeFilter(filter) || filter.StartTime.IsZero() || len(recent) == 0 {
		return false
	}
	oldest := recent[0].Timestamp
	if oldest.IsZero() {
		return false
	}
	return !filter.StartTime.Before(oldest)
}

func simpleCountFilter(filter storage.LogFilter) bool {
	return filter.SiteID == "" &&
		filter.ClientIP == "" &&
		filter.Category == "" &&
		filter.TraceID == "" &&
		len(filter.Tags) == 0
}

func hasTimeFilter(filter storage.LogFilter) bool {
	return !filter.StartTime.IsZero() || !filter.EndTime.IsZero()
}

func requiredRows(offset, limit int) int {
	if offset < 0 {
		offset = 0
	}
	if limit < 0 {
		limit = 0
	}
	maxInt := int(^uint(0) >> 1)
	if offset > maxInt-limit {
		return maxInt
	}
	return offset + limit
}

func filterRecent(recent []storage.LogEntry, filter storage.LogFilter) []storage.LogEntry {
	matched := make([]storage.LogEntry, 0, min(len(recent), normalizedLimit(filter.Limit)))
	for i := len(recent) - 1; i >= 0; i-- {
		entry := recent[i]
		if matches(entry, filter) {
			matched = append(matched, entry)
		}
	}
	return matched
}

func pageLogs(matched []storage.LogEntry, total int64, offset, limit int) []storage.LogEntry {
	start := offset
	if start < 0 {
		start = 0
	}
	if start >= len(matched) {
		return []storage.LogEntry{}
	}
	end := start + limit
	if end > len(matched) {
		end = len(matched)
	}
	return append([]storage.LogEntry(nil), matched[start:end]...)
}

func scanCount(ctx context.Context, path string, filter storage.LogFilter) (int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 4<<20)
	var total int64
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		var entry storage.LogEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			continue
		}
		if matches(entry, filter) {
			total++
		}
	}
	return total, scanner.Err()
}

func matches(entry storage.LogEntry, filter storage.LogFilter) bool {
	if filter.SiteID != "" && entry.SiteID != filter.SiteID {
		return false
	}
	if filter.ClientIP != "" && entry.ClientIP != filter.ClientIP {
		return false
	}
	if filter.Category != "" && entry.Category != filter.Category {
		return false
	}
	if filter.Action != "" && entry.Action != filter.Action {
		return false
	}
	if filter.TraceID != "" && entry.TraceID != filter.TraceID {
		return false
	}
	if !filter.StartTime.IsZero() && entry.Timestamp.Before(filter.StartTime) {
		return false
	}
	if !filter.EndTime.IsZero() && entry.Timestamp.After(filter.EndTime) {
		return false
	}
	for _, tag := range filter.Tags {
		if !hasTag(entry.Tags, tag) {
			return false
		}
	}
	return true
}

func hasTag(tags []string, want string) bool {
	for _, tag := range tags {
		if strings.EqualFold(tag, want) {
			return true
		}
	}
	return false
}
