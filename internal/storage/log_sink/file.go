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
	maxFileSinkQueryLimit      = 1000
	maxFileSinkBackups         = 100
	maxFileSinkWriteLineBytes  = 1 << 20
	maxFileSinkScanLineBytes   = 4 << 20
	maxFileSinkQueryWindow     = maxFileSinkQueryLimit
)

const truncatedLogValue = "[truncated]"

type FileSink struct {
	mu           sync.Mutex
	path         string
	file         *os.File
	writer       *bufio.Writer
	maxSizeBytes int64
	maxBackups   int
	currentSize  int64
	recent       []storage.LogEntry
	recentStart  int
	recentCount  int
	recentMax    int
	total        int64
	actionTotals map[string]int64
	indexValid   bool
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
		path:         path,
		maxSizeBytes: maxSizeBytes,
		maxBackups:   maxBackups,
		recentMax:    fileSinkRecentCacheLimit(),
		actionTotals: map[string]int64{},
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
	defer s.mu.Unlock()
	if s.file == nil || s.writer == nil {
		return fmt.Errorf("file sink is closed")
	}
	lineLimit := int64(maxFileSinkWriteLineBytes)
	if s.maxSizeBytes > 0 && s.maxSizeBytes-1 < lineLimit {
		lineLimit = s.maxSizeBytes - 1
	}
	if lineLimit <= 0 {
		return fmt.Errorf("maximum log size is too small")
	}
	data, stored, err := marshalBoundedLogEntry(*entry, int(lineLimit))
	if err != nil {
		return err
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
		s.indexEntryLocked(stored)
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
	matched := make(logQueryHeap, 0, min(window, maxFileSinkQueryLimit))
	var total int64
	var sequence int64
	err := scanFileSinkSegments(ctx, paths, func(entry storage.LogEntry) {
		if !matches(entry, filter) {
			return
		}
		total++
		candidate := retainedLogEntry{entry: entry, sequence: sequence}
		sequence++
		if len(matched) < window {
			heap.Push(&matched, candidate)
		} else if window > 0 && newerLogEntry(candidate, matched[0]) {
			heap.Pop(&matched)
			heap.Push(&matched, candidate)
		}
	})
	if err != nil {
		return nil, total, err
	}
	sort.SliceStable(matched, func(i, j int) bool {
		if matched[i].entry.Timestamp.Equal(matched[j].entry.Timestamp) {
			return matched[i].sequence < matched[j].sequence
		}
		return matched[i].entry.Timestamp.After(matched[j].entry.Timestamp)
	})
	page := make([]storage.LogEntry, len(matched))
	for i := range matched {
		page[i] = matched[i].entry
	}
	return pageLogs(page, total, filter.Offset, limit), total, nil
}

// logQueryHeap retains only the newest offset+limit matches while scanQuery
// still counts every match. The root is the least desirable retained row so a
// newer row can replace it in O(log(offset+limit)) time.
type logQueryHeap []retainedLogEntry

type retainedLogEntry struct {
	entry    storage.LogEntry
	sequence int64
}

func (h logQueryHeap) Len() int { return len(h) }

func (h logQueryHeap) Less(i, j int) bool {
	if h[i].entry.Timestamp.Equal(h[j].entry.Timestamp) {
		// Stable newest-first sorting keeps the earlier file row first, so a
		// later equal-timestamp row is the first one evicted from the window.
		return h[i].sequence > h[j].sequence
	}
	return h[i].entry.Timestamp.Before(h[j].entry.Timestamp)
}

func (h logQueryHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }

func (h *logQueryHeap) Push(value any) {
	*h = append(*h, value.(retainedLogEntry))
}

func (h *logQueryHeap) Pop() any {
	old := *h
	last := len(old) - 1
	value := old[last]
	old[last] = retainedLogEntry{}
	*h = old[:last]
	return value
}

func newerLogEntry(candidate, current retainedLogEntry) bool {
	if candidate.entry.Timestamp.Equal(current.entry.Timestamp) {
		return candidate.sequence < current.sequence
	}
	return candidate.entry.Timestamp.After(current.entry.Timestamp)
}

func (s *FileSink) loadIndex() error {
	recentMax := max(0, s.recentMax)
	indexed := FileSink{
		recentMax:    recentMax,
		actionTotals: map[string]int64{},
	}
	if err := scanFileSinkSegments(context.Background(), s.segmentPathsLocked(), func(entry storage.LogEntry) {
		indexed.indexEntryLocked(entry)
	}); err != nil {
		s.indexValid = false
		return err
	}
	s.recent = indexed.recent
	s.recentStart = indexed.recentStart
	s.recentCount = indexed.recentCount
	s.recentMax = recentMax
	s.total = indexed.total
	s.actionTotals = indexed.actionTotals
	s.indexValid = true
	return nil
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

func scanCount(ctx context.Context, paths []string, filter storage.LogFilter) (int64, error) {
	var total int64
	err := scanFileSinkSegments(ctx, paths, func(entry storage.LogEntry) {
		if matches(entry, filter) {
			total++
		}
	})
	return total, err
}

func scanFileSinkSegments(ctx context.Context, paths []string, visit func(storage.LogEntry)) error {
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
			visit(entry)
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
