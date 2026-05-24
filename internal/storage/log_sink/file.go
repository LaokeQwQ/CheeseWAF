package log_sink

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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

func (s *FileSink) Query(context.Context, storage.LogFilter) ([]storage.LogEntry, int64, error) {
	return []storage.LogEntry{}, 0, nil
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
