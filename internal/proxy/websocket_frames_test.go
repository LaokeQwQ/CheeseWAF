package proxy

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
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

type reviewActionLogPipeline struct{}

func (reviewActionLogPipeline) Detect(_ context.Context, ctx *engine.RequestContext) (*engine.DetectionResult, error) {
	if err := ctx.EnsureBody(); err != nil {
		return nil, err
	}
	if bytes.Contains(ctx.DecodedBody, []byte("LOG_ONLY")) {
		return &engine.DetectionResult{Detected: true, Category: "custom_rule", Action: engine.ActionLog, Severity: engine.SeverityHigh, Confidence: 1, Message: "log only"}, nil
	}
	return nil, nil
}

func TestWebSocketPassesRewrittenURIAndAppliesSiteIdentityPolicy(t *testing.T) {
	type observed struct {
		path, query, host, xff, realIP, forwardedHost, forwardedProto string
	}
	got := make(chan observed, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- observed{r.URL.Path, r.URL.RawQuery, r.Host, r.Header.Get("X-Forwarded-For"), r.Header.Get("X-Real-IP"), r.Header.Get("X-Forwarded-Host"), r.Header.Get("X-Forwarded-Proto")}
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true, CompressionMode: websocket.CompressionDisabled})
		if err != nil {
			return
		}
		defer conn.CloseNow()
		_, payload, err := conn.Read(r.Context())
		if err == nil {
			_ = conn.Write(r.Context(), websocket.MessageText, payload)
		}
	}))
	defer upstream.Close()
	target, err := url.Parse(upstream.URL + "/base?origin=1")
	if err != nil {
		t.Fatal(err)
	}
	cfg := reviewProxyConfig(target.String())
	cfg.Sites[0].WAF.WebSocketEnabled = true
	cfg.Sites[0].WAF.Rewrite = []config.RewriteRuleConfig{{ID: "ws-route", Enabled: true, Pattern: "^/public$", Replacement: "/private?rewritten=1"}}
	cfg.Sites[0].OriginScheme = "http"
	cfg.Sites[0].PassHost = new(bool)
	cfg.Sites[0].HostHeader = "origin.example.test"
	cfg.Sites[0].WAF.AccessControl.TrustedCIDRs = []string{"127.0.0.1/32"}
	server, err := NewServer(&cfg, engine.NewPipeline(), noopSink{})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	frontend := httptest.NewServer(server.Handler())
	defer frontend.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	header := http.Header{"X-Forwarded-For": {"198.51.100.42"}, "X-Real-IP": {"198.51.100.99"}}
	conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(frontend.URL, "http")+"/public?client=2", &websocket.DialOptions{HTTPHeader: header})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	if err := conn.Write(ctx, websocket.MessageText, []byte("ok")); err != nil {
		t.Fatal(err)
	}
	if _, payload, err := conn.Read(ctx); err != nil || string(payload) != "ok" {
		t.Fatalf("websocket echo failed: payload=%q err=%v", payload, err)
	}
	select {
	case request := <-got:
		if request.path != "/base/private" || request.query != "origin=1&rewritten=1" {
			t.Errorf("upstream URI = %s?%s, want /base/private?origin=1&rewritten=1", request.path, request.query)
		}
		if request.host != "origin.example.test" {
			t.Errorf("upstream Host = %q, want configured override", request.host)
		}
		if request.xff != "198.51.100.42" || request.realIP != "198.51.100.42" {
			t.Errorf("forwarded identity = xff %q real-ip %q", request.xff, request.realIP)
		}
		if request.forwardedHost != "localhost" && !strings.HasPrefix(request.forwardedHost, "127.0.0.1:") {
			t.Errorf("X-Forwarded-Host = %q, want original public host", request.forwardedHost)
		}
		if request.forwardedProto != "http" {
			t.Errorf("X-Forwarded-Proto = %q, want http", request.forwardedProto)
		}
	case <-ctx.Done():
		t.Fatal("upstream did not receive the WebSocket handshake")
	}
}

func TestWebSocketPassHostUsesPublicHost(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "http://public.example.test/", nil)
	if got := webSocketHost(r, "origin.example.test", true, ""); got != "public.example.test" {
		t.Fatalf("pass_host Host = %q, want public host", got)
	}
	if got := webSocketHost(r, "origin.example.test", false, ""); got != "origin.example.test" {
		t.Fatalf("non-pass_host Host = %q, want origin host", got)
	}
	if got := webSocketHost(r, "origin.example.test", true, "configured.example.test"); got != "configured.example.test" {
		t.Fatalf("configured Host = %q, want override", got)
	}
}

func TestWebSocketPreservesUpstreamCookieAndSubprotocol(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "session=issued; Path=/; HttpOnly")
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			Subprotocols:    []string{"chat.v2"},
			CompressionMode: websocket.CompressionDisabled,
		})
		if err != nil {
			return
		}
		defer conn.CloseNow()
		if typ, payload, err := conn.Read(r.Context()); err == nil {
			_ = conn.Write(r.Context(), typ, payload)
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
	conn, response, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(frontend.URL, "http"), &websocket.DialOptions{
		Subprotocols: []string{"chat.v1", "chat.v2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	if got := conn.Subprotocol(); got != "chat.v2" {
		t.Fatalf("client subprotocol = %q, want chat.v2", got)
	}
	if response == nil || response.Header.Get("Set-Cookie") != "session=issued; Path=/; HttpOnly" {
		t.Fatalf("upgrade Set-Cookie = %v, want upstream session cookie", response)
	}
	if err := conn.Write(ctx, websocket.MessageText, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	if typ, payload, err := conn.Read(ctx); err != nil || typ != websocket.MessageText || string(payload) != "hello" {
		t.Fatalf("websocket echo = (%v, %q, %v), want text hello", typ, payload, err)
	}
}

func TestWebSocketOriginSchemeOverridesUpstreamScheme(t *testing.T) {
	target, _ := url.Parse("http://origin.example.test/base")
	request, _ := url.Parse("/rewritten?x=1")
	got, err := webSocketUpstreamURL(target, request, "https")
	if err != nil {
		t.Fatal(err)
	}
	if got.Scheme != "wss" || got.Host != "origin.example.test" || got.Path != "/base/rewritten" || got.RawQuery != "x=1" {
		t.Fatalf("websocket upstream URL = %s, want wss://origin.example.test/base/rewritten?x=1", got)
	}
}

func TestWebSocketActionLogDetectionDoesNotDisconnectMessage(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled})
		if err != nil {
			return
		}
		defer conn.CloseNow()
		typ, payload, err := conn.Read(r.Context())
		if err == nil {
			_ = conn.Write(r.Context(), typ, append([]byte("echo:"), payload...))
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
	server.pipeline = reviewActionLogPipeline{}
	frontend := httptest.NewServer(server.Handler())
	defer frontend.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(frontend.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	if err := conn.Write(ctx, websocket.MessageText, []byte("LOG_ONLY")); err != nil {
		t.Fatal(err)
	}
	if _, payload, err := conn.Read(ctx); err != nil || string(payload) != "echo:LOG_ONLY" {
		t.Fatalf("ActionLog message did not pass through: payload=%q err=%v", payload, err)
	}
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
