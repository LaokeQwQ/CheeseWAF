package edge

import (
	"errors"
	"io"
	"net/http"
)

var ErrCaptureBodyTooLarge = errors.New("captured response body exceeds configured limit")

type CapturedResponse struct {
	Status int
	Header http.Header
	Body   []byte
}

type CaptureWriter struct {
	header      http.Header
	status      int
	body        []byte
	maxBody     int64
	writtenBody int64
	tooLarge    bool
	destination http.ResponseWriter
	committed   bool
	writeErr    error
}

func NewCaptureWriter() *CaptureWriter {
	return &CaptureWriter{header: make(http.Header), status: http.StatusOK}
}

func NewLimitedCaptureWriter(maxBody int64) *CaptureWriter {
	writer := NewCaptureWriter()
	writer.maxBody = maxBody
	return writer
}

// NewAdaptiveCaptureWriter buffers a response while it fits within maxBody.
// Once the limit is exceeded it commits the buffered prefix and streams the
// remainder to destination, preserving the single upstream request.
func NewAdaptiveCaptureWriter(destination http.ResponseWriter, maxBody int64) *CaptureWriter {
	writer := NewLimitedCaptureWriter(maxBody)
	writer.destination = destination
	return writer
}

func (w *CaptureWriter) Header() http.Header {
	return w.header
}

func (w *CaptureWriter) WriteHeader(status int) {
	if w.committed {
		return
	}
	w.status = status
}

func (w *CaptureWriter) Write(body []byte) (int, error) {
	if w.writeErr != nil {
		return 0, w.writeErr
	}
	if w.committed {
		n, err := w.destination.Write(body)
		if err != nil {
			w.writeErr = err
		}
		return n, err
	}
	next := w.writtenBody + int64(len(body))
	if w.maxBody > 0 && next > w.maxBody {
		w.tooLarge = true
		if err := w.commit(); err != nil {
			w.writeErr = err
			return 0, err
		}
		n, err := w.destination.Write(body)
		if err != nil {
			w.writeErr = err
		}
		return n, err
	}
	w.body = append(w.body, body...)
	w.writtenBody = next
	return len(body), nil
}

func (w *CaptureWriter) Flush() {
	if w == nil || w.destination == nil {
		return
	}
	if !w.committed {
		w.tooLarge = true
		if err := w.commit(); err != nil {
			w.writeErr = err
			return
		}
	}
	if flusher, ok := w.destination.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *CaptureWriter) commit() error {
	if w == nil || w.committed {
		return nil
	}
	if w.destination == nil {
		return errors.New("capture writer has no streaming destination")
	}
	copyHeader(w.destination.Header(), w.header)
	status := w.status
	if status == 0 {
		status = http.StatusOK
	}
	w.destination.WriteHeader(status)
	w.committed = true
	if len(w.body) == 0 {
		return nil
	}
	_, err := w.destination.Write(w.body)
	if err == nil {
		w.body = nil
	}
	return err
}

func (w *CaptureWriter) TooLarge() bool {
	return w != nil && w.tooLarge
}

func (w *CaptureWriter) Committed() bool {
	return w != nil && w.committed
}

func (w *CaptureWriter) Err() error {
	if w == nil {
		return nil
	}
	return w.writeErr
}

func (w *CaptureWriter) Response() CapturedResponse {
	return CapturedResponse{Status: w.status, Header: w.header.Clone(), Body: append([]byte(nil), w.body...)}
}

func WriteCaptured(w http.ResponseWriter, resp CapturedResponse) {
	copyHeader(w.Header(), resp.Header)
	if resp.Status == 0 {
		resp.Status = http.StatusOK
	}
	w.WriteHeader(resp.Status)
	_, _ = w.Write(resp.Body)
}

func copyHeader(destination, source http.Header) {
	for key, values := range source {
		destination.Del(key)
		for _, value := range values {
			destination.Add(key, value)
		}
	}
}

var _ http.Flusher = (*CaptureWriter)(nil)
var _ io.Writer = (*CaptureWriter)(nil)
