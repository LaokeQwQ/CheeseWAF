package log_sink

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

type FileSink struct {
	mu     sync.Mutex
	file   *os.File
	writer *bufio.Writer
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
	return &FileSink{file: file, writer: bufio.NewWriterSize(file, 64*1024)}, nil
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
	return s.writer.WriteByte('\n')
}

func (s *FileSink) Query(ctx context.Context, filter storage.LogFilter) ([]storage.LogEntry, int64, error) {
	if s == nil || s.file == nil {
		return nil, 0, fmt.Errorf("file sink is closed")
	}
	s.mu.Lock()
	if err := s.writer.Flush(); err != nil {
		s.mu.Unlock()
		return nil, 0, err
	}
	path := s.file.Name()
	s.mu.Unlock()

	file, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer file.Close()

	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}
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
	start := filter.Offset
	if start < 0 {
		start = 0
	}
	if start >= len(matched) {
		return []storage.LogEntry{}, total, scanner.Err()
	}
	end := start + limit
	if end > len(matched) {
		end = len(matched)
	}
	out := append([]storage.LogEntry(nil), matched[start:end]...)
	return out, total, scanner.Err()
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
