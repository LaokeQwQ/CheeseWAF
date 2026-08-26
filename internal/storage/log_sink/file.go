package log_sink

import (
	"bufio"
	"container/heap"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

const (
	defaultFileSinkRecentCache = 20000
	defaultFileSinkCacheBytes  = 64 << 20
	maxFileSinkCacheBytes      = 256 << 20
	maxFileSinkQueryLimit      = 1000
	maxFileSinkBackups         = 100
	maxFileSinkWriteLineBytes  = 1 << 20
	maxFileSinkScanLineBytes   = 4 << 20
	maxFileSinkQueryWindow     = maxFileSinkQueryLimit
)

const truncatedLogValue = "[truncated]"

type FileSink struct {
	mu             sync.Mutex
	path           string
	file           *os.File
	writer         *bufio.Writer
	maxSizeBytes   int64
	maxBackups     int
	currentSize    int64
	recent         []storage.LogEntry
	recentSizes    []int
	recentStart    int
	recentCount    int
	recentMax      int
	recentBytes    int64
	recentMaxBytes int64
	total          int64
	actionTotals   map[string]int64
	indexValid     bool
}

func NewFileSink(path string) (*FileSink, error) {
	return NewFileSinkWithRotation(path, 0, 0)
}

func NewFileSinkWithRotation(path string, maxSizeBytes int64, maxBackups int) (*FileSink, error) {
	if path == "" {
		return nil, fmt.Errorf("log path is required")
	}
	if maxSizeBytes < 0 {
		return nil, fmt.Errorf("maximum log size must be non-negative")
	}
	if maxBackups < 0 || maxBackups > maxFileSinkBackups {
		return nil, fmt.Errorf("maximum log backups must be between 0 and %d", maxFileSinkBackups)
	}
	path = filepath.Clean(path)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	if maxSizeBytes > 0 {
		if err := pruneFileSinkBackups(path, maxBackups); err != nil {
			return nil, err
		}
	}
	sink := &FileSink{
		path:           path,
		maxSizeBytes:   maxSizeBytes,
		maxBackups:     maxBackups,
		recentMax:      fileSinkRecentCacheLimit(),
		recentMaxBytes: fileSinkRecentCacheByteLimit(),
		actionTotals:   map[string]int64{},
	}
	if err := sink.openActiveLocked(); err != nil {
		return nil, err
	}
	if err := sink.loadIndex(); err != nil {
		_ = sink.file.Close()
		return nil, err
	}
	return sink, nil
}

func (s *FileSink) Write(_ context.Context, entry *storage.LogEntry) error {
	if entry == nil {
		return nil
	}
	s.mu.Lock()
	if s.file == nil || s.writer == nil {
		s.mu.Unlock()
		return fmt.Errorf("file sink is closed")
	}
	lineLimit := int64(maxFileSinkWriteLineBytes)
	if s.maxSizeBytes > 0 && s.maxSizeBytes-1 < lineLimit {
		lineLimit = s.maxSizeBytes - 1
	}
	s.mu.Unlock()
	if lineLimit <= 0 {
		return fmt.Errorf("maximum log size is too small")
	}
	data, stored, err := marshalBoundedLogEntry(*entry, int(lineLimit))
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file == nil || s.writer == nil {
		return fmt.Errorf("file sink is closed")
	}
	recordSize := int64(len(data) + 1)
	if s.maxSizeBytes > 0 && s.currentSize > 0 && s.currentSize+recordSize > s.maxSizeBytes {
		if err := s.rotateLocked(); err != nil {
			return err
		}
	}
	if _, err := s.writer.Write(data); err != nil {
		return err
	}
	if err := s.writer.WriteByte('\n'); err != nil {
		return err
	}
	s.currentSize += recordSize
	if s.indexValid {
		s.indexEntryLocked(stored, len(data))
	}
	return nil
}

func (s *FileSink) Query(ctx context.Context, filter storage.LogFilter) ([]storage.LogEntry, int64, error) {
	if s == nil {
		return nil, 0, fmt.Errorf("file sink is closed")
	}
	paths, recent, total, actionTotals, indexValid, err := s.snapshot(ctx)
	if err != nil {
		return nil, 0, err
	}
	limit := normalizedLimit(filter.Limit)
	if _, err := boundedQueryWindow(filter.Offset, limit); err != nil {
		return nil, 0, err
	}
	if indexValid {
		if items, matchedTotal, ok := queryRecent(filter, recent, total, actionTotals, limit); ok {
			return items, matchedTotal, nil
		}
	}
	return s.scanQuery(ctx, paths, filter, limit)
}

func (s *FileSink) Count(ctx context.Context, filter storage.LogFilter) (int64, bool, error) {
	if s == nil {
		return 0, false, fmt.Errorf("file sink is closed")
	}
	paths, recent, total, actionTotals, indexValid, err := s.snapshot(ctx)
	if err != nil {
		return 0, false, err
	}
	if indexValid {
		if count, ok := countRecent(filter, recent, total, actionTotals); ok {
			return count, true, nil
		}
	}
	count, err := scanCount(ctx, paths, filter)
	return count, true, err
}

func (s *FileSink) snapshot(ctx context.Context) ([]string, []storage.LogEntry, int64, map[string]int64, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, 0, nil, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file == nil || s.writer == nil {
		return nil, nil, 0, nil, false, fmt.Errorf("file sink is closed")
	}
	if err := s.writer.Flush(); err != nil {
		return nil, nil, 0, nil, false, err
	}
	actionTotals := make(map[string]int64, len(s.actionTotals))
	for action, count := range s.actionTotals {
		actionTotals[action] = count
	}
	return s.segmentPathsLocked(), s.recentSnapshotLocked(), s.total, actionTotals, s.indexValid, nil
}

func (s *FileSink) scanQuery(ctx context.Context, paths []string, filter storage.LogFilter, limit int) ([]storage.LogEntry, int64, error) {
	window := requiredRows(filter.Offset, limit)
	matched := &logQueryHeap{
		entries:   make([]retainedLogEntry, 0, min(window, maxFileSinkQueryLimit)),
		ascending: filter.Ascending,
	}
	var total int64
	var sequence int64
	err := scanFileSinkSegments(ctx, paths, func(entry storage.LogEntry, _ int) {
		if !matches(entry, filter) {
			return
		}
		total++
		candidate := retainedLogEntry{entry: entry, sequence: sequence}
		sequence++
		if matched.Len() < window {
			heap.Push(matched, candidate)
		} else if window > 0 && preferableLogEntry(candidate, matched.entries[0], filter.Ascending) {
			heap.Pop(matched)
			heap.Push(matched, candidate)
		}
	})
	if err != nil {
		return nil, total, err
	}
	sort.SliceStable(matched.entries, func(i, j int) bool {
		comparison := compareRetainedLogEntries(matched.entries[i], matched.entries[j])
		if filter.Ascending {
			return comparison < 0
		}
		return comparison > 0
	})
	page := make([]storage.LogEntry, len(matched.entries))
	for i := range matched.entries {
		page[i] = matched.entries[i].entry
	}
	return pageLogs(page, total, filter.Offset, limit), total, nil
}

// logQueryHeap retains only the newest offset+limit matches while scanQuery
// still counts every match. The root is the least desirable retained row so a
// newer row can replace it in O(log(offset+limit)) time.
type logQueryHeap struct {
	entries   []retainedLogEntry
	ascending bool
}

type retainedLogEntry struct {
	entry    storage.LogEntry
	sequence int64
}

func (h logQueryHeap) Len() int { return len(h.entries) }

func (h logQueryHeap) Less(i, j int) bool {
	comparison := compareRetainedLogEntries(h.entries[i], h.entries[j])
	if h.ascending {
		// An ascending query retains the oldest rows, so its newest row is
		// the least desirable item and stays at the root.
		return comparison > 0
	}
	// A descending query retains the newest rows, so its oldest row is
	// the least desirable item and stays at the root.
	return comparison < 0
}

func (h logQueryHeap) Swap(i, j int) { h.entries[i], h.entries[j] = h.entries[j], h.entries[i] }

func (h *logQueryHeap) Push(value any) {
	h.entries = append(h.entries, value.(retainedLogEntry))
}

func (h *logQueryHeap) Pop() any {
	old := h.entries
	last := len(old) - 1
	value := old[last]
	old[last] = retainedLogEntry{}
	h.entries = old[:last]
	return value
}

func preferableLogEntry(candidate, current retainedLogEntry, ascending bool) bool {
	comparison := compareRetainedLogEntries(candidate, current)
	if ascending {
		return comparison < 0
	}
	return comparison > 0
}

func compareRetainedLogEntries(left, right retainedLogEntry) int {
	if left.entry.Timestamp.Before(right.entry.Timestamp) {
		return -1
	}
	if left.entry.Timestamp.After(right.entry.Timestamp) {
		return 1
	}
	leftID := logEntryKeyID(left.entry)
	rightID := logEntryKeyID(right.entry)
	if leftID < rightID {
		return -1
	}
	if leftID > rightID {
		return 1
	}
	if left.sequence > right.sequence {
		return -1
	}
	if left.sequence < right.sequence {
		return 1
	}
	return 0
}

func (s *FileSink) loadIndex() error {
	recentMax := max(0, s.recentMax)
	indexed := FileSink{
		recentMax:      recentMax,
		recentMaxBytes: s.recentMaxBytes,
		actionTotals:   map[string]int64{},
	}
	if err := scanFileSinkSegments(context.Background(), s.segmentPathsLocked(), func(entry storage.LogEntry, size int) {
		indexed.indexEntryLocked(entry, size)
	}); err != nil {
		s.indexValid = false
		return err
	}
	s.recent = indexed.recent
	s.recentSizes = indexed.recentSizes
	s.recentStart = indexed.recentStart
	s.recentCount = indexed.recentCount
	s.recentMax = recentMax
	s.recentBytes = indexed.recentBytes
	s.total = indexed.total
	s.actionTotals = indexed.actionTotals
	s.indexValid = true
	return nil
}

func (s *FileSink) indexEntryLocked(entry storage.LogEntry, size int) {
	s.total++
	s.actionTotals[entry.Action]++
	if s.recentMax <= 0 || s.recentMaxBytes <= 0 {
		return
	}
	if size <= 0 {
		size = 1
	}
	if int64(size) > s.recentMaxBytes {
		// The cache must remain a contiguous suffix of the log. Keeping older
		// rows while omitting this row could make a time-range query incomplete.
		s.clearRecentLocked()
		return
	}
	for s.recentCount > 0 && (s.recentCount >= s.recentMax || s.recentBytes+int64(size) > s.recentMaxBytes) {
		s.evictOldestRecentLocked()
	}
	s.recent = append(s.recent, entry)
	s.recentSizes = append(s.recentSizes, size)
	s.recentCount++
	s.recentBytes += int64(size)
}

func (s *FileSink) recentSnapshotLocked() []storage.LogEntry {
	if s.recentCount == 0 {
		return nil
	}
	out := make([]storage.LogEntry, s.recentCount)
	copy(out, s.recent[s.recentStart:s.recentStart+s.recentCount])
	return out
}

func (s *FileSink) evictOldestRecentLocked() {
	if s.recentCount <= 0 || s.recentStart >= len(s.recent) {
		s.clearRecentLocked()
		return
	}
	s.recentBytes -= int64(s.recentSizes[s.recentStart])
	s.recent[s.recentStart] = storage.LogEntry{}
	s.recentSizes[s.recentStart] = 0
	s.recentStart++
	s.recentCount--
	if s.recentCount == 0 {
		s.clearRecentLocked()
		return
	}
	if s.recentStart >= 1024 && s.recentStart*2 >= len(s.recent) {
		copy(s.recent, s.recent[s.recentStart:])
		copy(s.recentSizes, s.recentSizes[s.recentStart:])
		s.recent = s.recent[:s.recentCount]
		s.recentSizes = s.recentSizes[:s.recentCount]
		s.recentStart = 0
	}
}

func (s *FileSink) clearRecentLocked() {
	clear(s.recent)
	clear(s.recentSizes)
	s.recent = s.recent[:0]
	s.recentSizes = s.recentSizes[:0]
	s.recentStart = 0
	s.recentCount = 0
	s.recentBytes = 0
}

func (s *FileSink) Flush(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file == nil || s.writer == nil {
		return fmt.Errorf("file sink is closed")
	}
	return s.writer.Flush()
}

func (s *FileSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file == nil || s.writer == nil {
		return nil
	}
	if err := s.writer.Flush(); err != nil {
		return err
	}
	err := s.file.Close()
	s.file = nil
	s.writer = nil
	return err
}

func (s *FileSink) openActiveLocked() error {
	file, err := os.OpenFile(s.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return err
	}
	s.file = file
	s.writer = bufio.NewWriterSize(file, 64*1024)
	s.currentSize = info.Size()
	return nil
}

func (s *FileSink) segmentPathsLocked() []string {
	paths := make([]string, 0, s.maxBackups+1)
	for index := s.maxBackups; index >= 1; index-- {
		path := fileSinkBackupPath(s.path, index)
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
			paths = append(paths, path)
		}
	}
	if s.path != "" {
		if info, err := os.Stat(s.path); err == nil && info.Mode().IsRegular() {
			paths = append(paths, s.path)
		}
	}
	return paths
}

func (s *FileSink) rotateLocked() error {
	if s.maxSizeBytes <= 0 {
		return nil
	}
	if err := s.writer.Flush(); err != nil {
		return err
	}
	if err := s.file.Close(); err != nil {
		return err
	}
	s.file = nil
	s.writer = nil

	var rotateErr error
	if s.maxBackups == 0 {
		rotateErr = os.Truncate(s.path, 0)
	} else {
		for index := s.maxBackups; index >= 1; index-- {
			destination := fileSinkBackupPath(s.path, index)
			if err := os.Remove(destination); err != nil && !os.IsNotExist(err) {
				rotateErr = err
				break
			}
			source := s.path
			if index > 1 {
				source = fileSinkBackupPath(s.path, index-1)
			}
			if err := os.Rename(source, destination); err != nil && !os.IsNotExist(err) {
				rotateErr = err
				break
			}
		}
	}
	if err := s.openActiveLocked(); err != nil {
		if rotateErr == nil {
			rotateErr = err
		}
		return rotateErr
	}
	indexErr := s.loadIndex()
	if rotateErr != nil {
		return rotateErr
	}
	return indexErr
}

func fileSinkBackupPath(path string, index int) string {
	return fmt.Sprintf("%s.%d", path, index)
}

func pruneFileSinkBackups(path string, maxBackups int) error {
	directory := filepath.Dir(path)
	base := filepath.Base(path) + "."
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, base) {
			continue
		}
		index, err := strconv.Atoi(strings.TrimPrefix(name, base))
		if err != nil || index <= maxBackups {
			continue
		}
		if err := os.Remove(filepath.Join(directory, name)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
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

func fileSinkRecentCacheByteLimit() int64 {
	raw := strings.TrimSpace(os.Getenv("CHEESEWAF_FILE_SINK_CACHE_BYTES"))
	if raw == "" {
		return defaultFileSinkCacheBytes
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value < 0 {
		return defaultFileSinkCacheBytes
	}
	return min(value, int64(maxFileSinkCacheBytes))
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
	if hasTimeFilter(filter) || hasKeysetFilter(filter) || filter.ID != "" || filter.TraceID != "" || filter.SiteID != "" || filter.ClientIP != "" || filter.Category != "" || filter.Search != "" || filter.Kind != "" || len(filter.Tags) > 0 {
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
		filter.ID == "" &&
		filter.Search == "" &&
		filter.Kind == "" &&
		!hasKeysetFilter(filter) &&
		len(filter.Tags) == 0
}

func hasTimeFilter(filter storage.LogFilter) bool {
	return !filter.StartTime.IsZero() || !filter.EndTime.IsZero()
}

func hasKeysetFilter(filter storage.LogFilter) bool {
	return !filter.WatermarkTime.IsZero() || filter.WatermarkID != "" ||
		!filter.BeforeTime.IsZero() || filter.BeforeID != "" ||
		!filter.AfterTime.IsZero() || filter.AfterID != ""
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

func boundedQueryWindow(offset, limit int) (int, error) {
	if offset < 0 {
		offset = 0
	}
	if limit < 0 {
		limit = 0
	}
	if limit > maxFileSinkQueryLimit {
		limit = maxFileSinkQueryLimit
	}
	if offset > maxFileSinkQueryWindow-limit {
		return 0, fmt.Errorf("log query offset exceeds maximum window of %d rows", maxFileSinkQueryWindow)
	}
	return offset + limit, nil
}

func filterRecent(recent []storage.LogEntry, filter storage.LogFilter) []storage.LogEntry {
	matched := make([]storage.LogEntry, 0, min(len(recent), normalizedLimit(filter.Limit)))
	for _, entry := range recent {
		if matches(entry, filter) {
			matched = append(matched, entry)
		}
	}
	sort.SliceStable(matched, func(i, j int) bool {
		comparison := compareLogEntries(matched[i], matched[j])
		if filter.Ascending {
			return comparison < 0
		}
		return comparison > 0
	})
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

func scanCount(ctx context.Context, paths []string, filter storage.LogFilter) (int64, error) {
	var total int64
	err := scanFileSinkSegments(ctx, paths, func(entry storage.LogEntry, _ int) {
		if matches(entry, filter) {
			total++
		}
	})
	return total, err
}

func scanFileSinkSegments(ctx context.Context, paths []string, visit func(storage.LogEntry, int)) error {
	for _, path := range paths {
		if err := ctx.Err(); err != nil {
			return err
		}
		file, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}
		reader := bufio.NewReaderSize(file, 64*1024)
		for {
			line, oversized, readErr := readBoundedLogLine(ctx, reader, maxFileSinkScanLineBytes)
			if readErr != nil {
				if readErr == io.EOF {
					break
				}
				_ = file.Close()
				return fmt.Errorf("scan log segment %q: %w", path, readErr)
			}
			if oversized {
				continue
			}
			var entry storage.LogEntry
			if err := json.Unmarshal(line, &entry); err != nil {
				continue
			}
			visit(entry, len(line))
		}
		closeErr := file.Close()
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}

func readBoundedLogLine(ctx context.Context, reader *bufio.Reader, maxBytes int) ([]byte, bool, error) {
	if maxBytes <= 0 {
		return nil, false, fmt.Errorf("maximum scan line size must be positive")
	}
	var line []byte
	oversized := false
	readAny := false
	for {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}
		fragment, err := reader.ReadSlice('\n')
		if len(fragment) > 0 {
			readAny = true
		}
		if err == io.EOF && !readAny {
			return nil, false, io.EOF
		}
		content := fragment
		if err == nil && len(content) > 0 {
			content = content[:len(content)-1]
		}
		if !oversized {
			if len(line) == 0 && (err == nil || err == io.EOF) && len(content) <= maxBytes {
				return content, false, nil
			}
			if len(content) > maxBytes-len(line) {
				oversized = true
				line = nil
			} else {
				line = append(line, content...)
			}
		}
		switch err {
		case nil:
			return line, oversized, nil
		case bufio.ErrBufferFull:
			continue
		case io.EOF:
			return line, oversized, nil
		default:
			return nil, false, err
		}
	}
}

func marshalBoundedLogEntry(entry storage.LogEntry, maxBytes int) ([]byte, storage.LogEntry, error) {
	if maxBytes <= 0 {
		return nil, storage.LogEntry{}, fmt.Errorf("maximum log line size must be positive")
	}
	fieldLimit := min(64<<10, max(16, maxBytes/8))
	for fieldLimit >= 16 {
		bounded := boundLogEntry(entry, fieldLimit)
		data, err := json.Marshal(&bounded)
		if err != nil {
			return nil, storage.LogEntry{}, err
		}
		if len(data) <= maxBytes {
			var stored storage.LogEntry
			if err := json.Unmarshal(data, &stored); err != nil {
				return nil, storage.LogEntry{}, err
			}
			return data, stored, nil
		}
		fieldLimit /= 2
	}
	minimal := storage.LogEntry{
		ID:         truncateUTF8(entry.ID, 16),
		Timestamp:  entry.Timestamp,
		TraceID:    truncateUTF8(entry.TraceID, 16),
		SiteID:     truncateUTF8(entry.SiteID, 16),
		StatusCode: entry.StatusCode,
		Action:     truncateUTF8(entry.Action, 16),
		Category:   truncateUTF8(entry.Category, 16),
		Severity:   truncateUTF8(entry.Severity, 16),
		Message:    truncatedLogValue,
		Latency:    entry.Latency,
		Metadata:   map[string]any{"file_sink_truncated": true},
	}
	data, err := json.Marshal(&minimal)
	if err != nil {
		return nil, storage.LogEntry{}, err
	}
	if len(data) > maxBytes {
		return nil, storage.LogEntry{}, fmt.Errorf("maximum log size %d is too small for a log record", maxBytes+1)
	}
	return data, minimal, nil
}

func boundLogEntry(entry storage.LogEntry, fieldLimit int) storage.LogEntry {
	identityLimit := min(4<<10, max(16, fieldLimit/4))
	entry.ID = truncateUTF8(entry.ID, identityLimit)
	entry.TraceID = truncateUTF8(entry.TraceID, identityLimit)
	entry.SiteID = truncateUTF8(entry.SiteID, identityLimit)
	entry.ClientIP = truncateUTF8(entry.ClientIP, identityLimit)
	entry.Method = truncateUTF8(entry.Method, identityLimit)
	entry.Action = truncateUTF8(entry.Action, identityLimit)
	entry.DetectorID = truncateUTF8(entry.DetectorID, identityLimit)
	entry.Category = truncateUTF8(entry.Category, identityLimit)
	entry.Severity = truncateUTF8(entry.Severity, identityLimit)
	entry.Country = truncateUTF8(entry.Country, identityLimit)
	entry.URI = truncateUTF8(entry.URI, fieldLimit)
	entry.Message = truncateUTF8(entry.Message, fieldLimit)
	entry.Payload = truncateUTF8(entry.Payload, fieldLimit)
	entry.UserAgent = truncateUTF8(entry.UserAgent, fieldLimit)
	if len(entry.Tags) > 32 {
		entry.Tags = entry.Tags[:32]
	}
	entry.Tags = append([]string(nil), entry.Tags...)
	for index := range entry.Tags {
		entry.Tags[index] = truncateUTF8(entry.Tags[index], min(1024, identityLimit))
	}
	metadataBudget := min(32<<10, fieldLimit*2)
	entry.Metadata = boundMetadata(entry.Metadata, &metadataBudget, 0)
	return entry
}

func boundMetadata(metadata map[string]any, budget *int, depth int) map[string]any {
	if len(metadata) == 0 || budget == nil || *budget <= 0 {
		return nil
	}
	out := make(map[string]any, min(len(metadata), 32)+1)
	count := 0
	for key, value := range metadata {
		if count >= 32 || *budget <= 0 {
			out["file_sink_truncated"] = true
			break
		}
		boundedKey := takeMetadataString(key, budget, 1024)
		if boundedKey == "" {
			boundedKey = truncatedLogValue
		}
		out[boundedKey] = boundMetadataValue(reflect.ValueOf(value), budget, depth+1)
		count++
	}
	return out
}

func boundMetadataValue(value reflect.Value, budget *int, depth int) any {
	if !value.IsValid() {
		return nil
	}
	if depth > 4 || budget == nil || *budget <= 0 {
		return truncatedLogValue
	}
	*budget = *budget - 1
	if value.Kind() == reflect.Interface || value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return nil
		}
		return boundMetadataValue(value.Elem(), budget, depth+1)
	}
	if value.Type() == reflect.TypeOf(time.Time{}) && value.CanInterface() {
		return value.Interface()
	}
	switch value.Kind() {
	case reflect.String:
		return takeMetadataString(value.String(), budget, min(4096, *budget))
	case reflect.Bool:
		return value.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return value.Int()
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return value.Uint()
	case reflect.Float32, reflect.Float64:
		number := value.Float()
		if math.IsNaN(number) || math.IsInf(number, 0) {
			return truncatedLogValue
		}
		return number
	case reflect.Slice, reflect.Array:
		length := min(value.Len(), 32)
		out := make([]any, 0, length+1)
		for index := 0; index < length && *budget > 0; index++ {
			out = append(out, boundMetadataValue(value.Index(index), budget, depth+1))
		}
		if value.Len() > length {
			out = append(out, truncatedLogValue)
		}
		return out
	case reflect.Map:
		if value.Type().Key().Kind() != reflect.String {
			return truncatedLogValue
		}
		out := make(map[string]any, min(value.Len(), 32)+1)
		iterator := value.MapRange()
		count := 0
		for iterator.Next() && count < 32 && *budget > 0 {
			key := takeMetadataString(iterator.Key().String(), budget, 1024)
			out[key] = boundMetadataValue(iterator.Value(), budget, depth+1)
			count++
		}
		if value.Len() > count {
			out["file_sink_truncated"] = true
		}
		return out
	case reflect.Struct:
		typeInfo := value.Type()
		out := make(map[string]any, min(value.NumField(), 32))
		for index := 0; index < value.NumField() && len(out) < 32 && *budget > 0; index++ {
			fieldInfo := typeInfo.Field(index)
			field := value.Field(index)
			if fieldInfo.PkgPath != "" || !field.CanInterface() {
				continue
			}
			name := strings.Split(fieldInfo.Tag.Get("json"), ",")[0]
			if name == "-" {
				continue
			}
			if name == "" {
				name = fieldInfo.Name
			}
			name = takeMetadataString(name, budget, 1024)
			out[name] = boundMetadataValue(field, budget, depth+1)
		}
		return out
	default:
		return truncatedLogValue
	}
}

func takeMetadataString(value string, budget *int, limit int) string {
	if budget == nil || *budget <= 0 || limit <= 0 {
		return truncatedLogValue
	}
	limit = min(limit, *budget)
	bounded := truncateUTF8(value, limit)
	*budget -= min(*budget, len(bounded))
	return bounded
}

func truncateUTF8(value string, limit int) string {
	if limit <= 0 {
		return ""
	}
	if len(value) <= limit {
		if utf8.ValidString(value) {
			return value
		}
		return strings.ToValidUTF8(value, "?")
	}
	if limit <= len(truncatedLogValue) {
		return truncatedLogValue[:limit]
	}
	prefixLimit := limit - len(truncatedLogValue)
	for prefixLimit > 0 && !utf8.RuneStart(value[prefixLimit]) {
		prefixLimit--
	}
	prefix := strings.ToValidUTF8(value[:prefixLimit], "?")
	return prefix + truncatedLogValue
}

func matches(entry storage.LogEntry, filter storage.LogFilter) bool {
	if filter.ID != "" && logEntryKeyID(entry) != filter.ID {
		return false
	}
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
	if !withinLogKeyset(entry, filter) {
		return false
	}
	if !matchesLogKind(entry, filter.Kind) {
		return false
	}
	if filter.Search != "" && !matchesLogSearch(entry, filter.Search) {
		return false
	}
	for _, tag := range filter.Tags {
		if !hasTag(entry.Tags, tag) {
			return false
		}
	}
	return true
}

func withinLogKeyset(entry storage.LogEntry, filter storage.LogFilter) bool {
	if !filter.WatermarkTime.IsZero() || filter.WatermarkID != "" {
		comparison := compareLogFilterKey(entry, filter.WatermarkTime, filter.WatermarkID)
		if filter.Ascending {
			if comparison <= 0 {
				return false
			}
		} else if comparison >= 0 {
			return false
		}
	}
	if (!filter.BeforeTime.IsZero() || filter.BeforeID != "") && compareLogFilterKey(entry, filter.BeforeTime, filter.BeforeID) >= 0 {
		return false
	}
	if (!filter.AfterTime.IsZero() || filter.AfterID != "") && compareLogFilterKey(entry, filter.AfterTime, filter.AfterID) <= 0 {
		return false
	}
	return true
}

func compareLogFilterKey(entry storage.LogEntry, timestamp time.Time, id string) int {
	if timestamp.IsZero() {
		entryID := logEntryKeyID(entry)
		if entryID < id {
			return -1
		}
		if entryID > id {
			return 1
		}
		return 0
	}
	return compareLogEntryKey(entry, timestamp, id)
}

func compareLogEntries(left, right storage.LogEntry) int {
	return compareLogEntryKey(left, right.Timestamp, logEntryKeyID(right))
}

func compareLogEntryKey(entry storage.LogEntry, timestamp time.Time, id string) int {
	if entry.Timestamp.Before(timestamp) {
		return -1
	}
	if entry.Timestamp.After(timestamp) {
		return 1
	}
	entryID := logEntryKeyID(entry)
	if entryID < id {
		return -1
	}
	if entryID > id {
		return 1
	}
	return 0
}

func logEntryKeyID(entry storage.LogEntry) string {
	if entry.ID != "" {
		return entry.ID
	}
	return entry.TraceID
}

func matchesLogKind(entry storage.LogEntry, kind string) bool {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "", "all":
		return true
	case "security":
		return isSecurityLogEntry(entry)
	case "access":
		return isAccessLogEntry(entry)
	default:
		return false
	}
}

func isSecurityLogEntry(entry storage.LogEntry) bool {
	action := strings.ToLower(strings.TrimSpace(entry.Action))
	return entry.Category != "" || entry.DetectorID != "" || entry.Severity != "" ||
		action == "block" || action == "challenge" || action == "log" || action == "monitor" ||
		entry.StatusCode == 403 || entry.StatusCode == 429
}

func isAccessLogEntry(entry storage.LogEntry) bool {
	if isSecurityLogEntry(entry) {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(entry.Action)) {
	case "", "pass", "cache_hit", "redirect":
		return true
	default:
		return false
	}
}

func matchesLogSearch(entry storage.LogEntry, search string) bool {
	search = strings.ToLower(strings.TrimSpace(search))
	if search == "" {
		return true
	}
	fields := [...]string{
		logEntryKeyID(entry), entry.TraceID, entry.SiteID, entry.ClientIP, entry.Method,
		entry.URI, entry.Action, entry.DetectorID, entry.Category, entry.Severity,
		entry.Message, entry.Payload, entry.UserAgent, entry.Country,
	}
	for _, field := range fields {
		if strings.Contains(strings.ToLower(field), search) {
			return true
		}
	}
	return false
}

func hasTag(tags []string, want string) bool {
	for _, tag := range tags {
		if strings.EqualFold(tag, want) {
			return true
		}
	}
	return false
}
