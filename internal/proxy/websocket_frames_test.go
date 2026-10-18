package proxy

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
	"nhooyr.io/websocket"
)

type reviewFramePipeline struct{}

func (reviewFramePipeline) Detect(_ context.Context, ctx *engine.RequestContext) (*engine.DetectionResult, error) {
	if err := ctx.EnsureBody(); err != nil {
		return nil, err
	}
	if bytes.Contains(ctx.DecodedBody, []byte("ATTACK")) {
		return &engine.DetectionResult{Detected: true, Category: "sqli", Action: engine.ActionBlock, Severity: engine.SeverityCritical, Confidence: 1, Message: "attack"}, nil
	}
	return nil, nil
}

func TestReviewWebSocketMessageInspectedBeforeOrigin(t *testing.T) {
	received := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled})
		if err != nil {
			return
		}
		defer conn.CloseNow()
		_, data, err := conn.Read(r.Context())
		if err == nil {
			received <- string(data)
		}
	}))
	defer upstream.Close()
	cfg := reviewProxyConfig(upstream.URL)
	cfg.Sites[0].WAF.WebSocketEnabled = true
	cfg.Sites[0].WAF.Enabled = true
	cfg.Sites[0].WAF.Mode = "block"
	server, err := NewServer(&cfg, engine.NewPipeline(), noopSink{})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	server.pipeline = reviewFramePipeline{}
	frontend := httptest.NewServer(server.Handler())
	defer frontend.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(frontend.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	_ = conn.Write(ctx, websocket.MessageText, []byte("ATTACK"))
	_, _, err = conn.Read(ctx)
	if err == nil || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("attack was not rejected promptly: %v", err)
	}
	select {
	case data := <-received:
		t.Fatalf("uninspected message reached origin: %q", data)
	default:
	}
}

func reviewWireFrame(opcode byte, fin, masked bool, payload []byte) []byte {
	first := opcode
	if fin {
		first |= 0x80
	}
	frame := []byte{first, 0}
	if len(payload) < 126 {
		frame[1] = byte(len(payload))
	} else {
		frame[1] = 126
		frame = binary.BigEndian.AppendUint16(frame, uint16(len(payload)))
	}
	if masked {
		frame[1] |= 0x80
		frame = append(frame, 1, 2, 3, 4)
	}
	for i, b := range payload {
		if masked {
			b ^= byte(i%4 + 1)
		}
		frame = append(frame, b)
	}
	return frame
}

type reviewFrameConn struct {
	bytes.Buffer
	closed bool
}

func (c *reviewFrameConn) Close() error { c.closed = true; return nil }

func TestReviewWebSocketFragmentsHeldUntilInspected(t *testing.T) {
	base := &reviewFrameConn{}
	filtered := newWebSocketFrameTunnel(base, 1024, func(_ bool, _ byte, data []byte) error {
		if bytes.Equal(data, []byte("ATTACK")) {
			return errors.New("blocked")
		}
		return nil
	})
	defer filtered.Close()
	first := reviewWireFrame(1, false, true, []byte("ATT"))
	if _, err := filtered.Write(first); err != nil {
		t.Fatal(err)
	}
	if base.Len() != 0 {
		t.Fatal("partial uninspected message released upstream")
	}
	if _, err := filtered.Write(reviewWireFrame(0, true, true, []byte("ACK"))); err == nil {
		t.Fatal("fragmented attack passed")
	}
	if base.Len() != 0 {
		t.Fatal("blocked frame released upstream")
	}
}

func TestReviewWebSocketRejectsCompressionAndOversizedFrames(t *testing.T) {
	for _, frame := range [][]byte{{0xc1, 0x80, 1, 2, 3, 4}, {0x81, 0xfe, 0x10, 0x00}} {
		base := &reviewFrameConn{}
		filtered := newWebSocketFrameTunnel(base, 1024, nil)
		if _, err := filtered.Write(frame); err == nil {
			t.Fatal("invalid frame passed")
		}
		filtered.Close()
	}
}

func TestReviewWebSocketRejectsReservedCloseStatus(t *testing.T) {
	base := &reviewFrameConn{}
	base.Buffer.Write(reviewWireFrame(8, true, false, binary.BigEndian.AppendUint16(nil, 2000)))
	filtered := newWebSocketFrameTunnel(base, 1024, nil)
	defer filtered.Close()
	if _, err := io.ReadAll(filtered); err == nil {
		t.Fatal("reserved WebSocket close status passed")
	}
}

func TestReviewWebSocketResponseMessageInspected(t *testing.T) {
	base := &reviewFrameConn{}
	base.Buffer.Write(reviewWireFrame(1, true, false, []byte("SECRET")))
	filtered := newWebSocketFrameTunnel(base, 1024, func(client bool, _ byte, data []byte) error {
		if !client && bytes.Equal(data, []byte("SECRET")) {
			return errors.New("sensitive")
		}
		return nil
	})
	defer filtered.Close()
	data, err := io.ReadAll(filtered)
	if err == nil || len(data) != 0 {
		t.Fatalf("sensitive response released: %q %v", data, err)
	}
}

func TestReviewWebSocketAllowedMessageRoundTrips(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled})
		if err != nil {
			return
		}
		defer conn.CloseNow()
		typ, data, err := conn.Read(r.Context())
		if err == nil {
			_ = conn.Write(r.Context(), typ, append([]byte("echo:"), data...))
		}
	}))
	defer upstream.Close()
	cfg := reviewProxyConfig(upstream.URL)
	cfg.Sites[0].WAF.WebSocketEnabled = true
	server, err := NewServer(&cfg, engine.NewPipeline(), noopSink{})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	frontend := httptest.NewServer(server.Handler())
	defer frontend.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(frontend.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	if err := conn.Write(ctx, websocket.MessageText, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	typ, data, err := conn.Read(ctx)
	if err != nil || typ != websocket.MessageText || string(data) != "echo:hello" {
		t.Fatalf("valid WebSocket exchange failed: type=%v data=%q err=%v", typ, data, err)
	}
}

func TestReviewWebSocketRejectsForeignOrigin(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
	}))
	defer upstream.Close()
	cfg := reviewProxyConfig(upstream.URL)
	cfg.Sites[0].WAF.WebSocketEnabled = true
	server, err := NewServer(&cfg, engine.NewPipeline(), noopSink{})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	frontend := httptest.NewServer(server.Handler())
	defer frontend.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	header := http.Header{"Origin": {"https://attacker.example"}}
	_, response, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(frontend.URL, "http"), &websocket.DialOptions{HTTPHeader: header})
	if err == nil {
		t.Fatal("foreign Origin unexpectedly upgraded")
	}
	if response == nil || response.StatusCode != http.StatusForbidden {
		t.Fatalf("foreign Origin status = %v, want 403", response)
	}
}
