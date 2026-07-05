package realtime

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"nhooyr.io/websocket"
)

func TestWSHandlerRejectsCrossOriginHandshake(t *testing.T) {
	server := newRealtimeWSTestServer(t)
	ctx := context.Background()

	sameOrigin, _, err := websocket.Dial(ctx, server.URL, &websocket.DialOptions{
		HTTPHeader: map[string][]string{"Origin": {server.HTTPURL}},
	})
	if err != nil {
		t.Fatalf("same-origin websocket dial failed: %v", err)
	}
	_ = sameOrigin.Close(websocket.StatusNormalClosure, "test complete")

	crossOrigin, response, err := websocket.Dial(ctx, server.URL, &websocket.DialOptions{
		HTTPHeader: map[string][]string{"Origin": {"https://evil.example.test"}},
	})
	if err == nil {
		_ = crossOrigin.Close(websocket.StatusNormalClosure, "unexpected success")
		t.Fatal("expected cross-origin websocket dial to be rejected")
	}
	if response == nil || response.StatusCode != 403 {
		t.Fatalf("expected cross-origin websocket dial to return 403, response=%v err=%v", response, err)
	}
}

type realtimeWSTestServer struct {
	URL     string
	HTTPURL string
}

func newRealtimeWSTestServer(t *testing.T) realtimeWSTestServer {
	t.Helper()
	hub := NewHub()
	server := httptest.NewServer(http.HandlerFunc(hub.WSHandler))
	t.Cleanup(server.Close)
	return realtimeWSTestServer{
		URL:     "ws" + strings.TrimPrefix(server.URL, "http"),
		HTTPURL: server.URL,
	}
}
