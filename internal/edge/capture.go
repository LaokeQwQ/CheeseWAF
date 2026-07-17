package edge

import (
	"errors"
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
}

func NewCaptureWriter() *CaptureWriter {
	return &CaptureWriter{header: make(http.Header), status: http.StatusOK}
}

func NewLimitedCaptureWriter(maxBody int64) *CaptureWriter {
	writer := NewCaptureWriter()
	writer.maxBody = maxBody
	return writer
}

func (w *CaptureWriter) Header() http.Header {
	return w.header
}

func (w *CaptureWriter) WriteHeader(status int) {
	w.status = status
}

func (w *CaptureWriter) Write(body []byte) (int, error) {
	if w.tooLarge {
		return len(body), nil
	}
	next := w.writtenBody + int64(len(body))
	if w.maxBody > 0 && next > w.maxBody {
		w.tooLarge = true
		return len(body), nil
	}
	w.body = append(w.body, body...)
	w.writtenBody = next
	return len(body), nil
}

func (w *CaptureWriter) TooLarge() bool {
	return w != nil && w.tooLarge
}

func (w *CaptureWriter) Response() CapturedResponse {
	return CapturedResponse{Status: w.status, Header: w.header.Clone(), Body: append([]byte(nil), w.body...)}
}

func WriteCaptured(w http.ResponseWriter, resp CapturedResponse) {
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	if resp.Status == 0 {
		resp.Status = http.StatusOK
	}
	w.WriteHeader(resp.Status)
	_, _ = w.Write(resp.Body)
}
