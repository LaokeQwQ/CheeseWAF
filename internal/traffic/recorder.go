package traffic

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

type Entry struct {
	ID             string      `json:"id"`
	Timestamp      time.Time   `json:"timestamp"`
	Method         string      `json:"method"`
	URL            string      `json:"url"`
	RequestHeader  http.Header `json:"request_header"`
	RequestBody    []byte      `json:"request_body,omitempty"`
	StatusCode     int         `json:"status_code"`
	ResponseHeader http.Header `json:"response_header"`
	ResponseBody   []byte      `json:"response_body,omitempty"`
}

type Recorder struct {
	path         string
	maxBodyBytes int
}

func NewRecorder(path string, maxBodyBytes int) *Recorder {
	if maxBodyBytes <= 0 {
		maxBodyBytes = 64 << 10
	}
	return &Recorder{path: path, maxBodyBytes: maxBodyBytes}
}

func (r *Recorder) Write(ctx context.Context, entry Entry) error {
	if r == nil || r.path == "" {
		return fmt.Errorf("traffic recorder path is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	entry.Timestamp = entry.Timestamp.UTC()
	entry.RequestBody = trim(entry.RequestBody, r.maxBodyBytes)
	entry.ResponseBody = trim(entry.ResponseBody, r.maxBodyBytes)
	if err := os.MkdirAll(filepath.Dir(r.path), 0o750); err != nil {
		return err
	}
	file, err := os.OpenFile(r.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	defer file.Close()
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	if _, err := file.Write(append(data, '\n')); err != nil {
		return err
	}
	return nil
}

func trim(body []byte, max int) []byte {
	if len(body) <= max {
		return append([]byte(nil), body...)
	}
	return append([]byte(nil), body[:max]...)
}
