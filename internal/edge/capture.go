package edge

import "net/http"

type CapturedResponse struct {
	Status int
	Header http.Header
	Body   []byte
}

type CaptureWriter struct {
	header http.Header
	status int
	body   []byte
}

func NewCaptureWriter() *CaptureWriter {
	return &CaptureWriter{header: make(http.Header), status: http.StatusOK}
}

func (w *CaptureWriter) Header() http.Header {
	return w.header
}

func (w *CaptureWriter) WriteHeader(status int) {
	w.status = status
}

func (w *CaptureWriter) Write(body []byte) (int, error) {
	w.body = append(w.body, body...)
	return len(body), nil
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
