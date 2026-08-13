package ai

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"testing"
)

type aiRoundTripFunc func(*http.Request) (*http.Response, error)

func (fn aiRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func TestAIResponseLimitTransportBoundsJSONAndStreams(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		limit       int64
	}{
		{name: "json", contentType: "application/json", limit: 32},
		{name: "stream", contentType: "text/event-stream", limit: 64},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			transport := &aiResponseLimitTransport{
				jsonLimit:   32,
				streamLimit: 64,
				base: aiRoundTripFunc(func(*http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Header:     http.Header{"Content-Type": []string{test.contentType}},
						Body:       io.NopCloser(bytes.NewReader(bytes.Repeat([]byte("x"), int(test.limit+1)))),
					}, nil
				}),
			}
			response, err := transport.RoundTrip(&http.Request{})
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if !errors.Is(err, errAIResponseTooLarge) {
				t.Fatalf("read error = %v, want response-too-large", err)
			}
			if int64(len(body)) != test.limit {
				t.Fatalf("read %d bytes, want %d", len(body), test.limit)
			}
		})
	}
}
