package proxy

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"nhooyr.io/websocket"
)

func webSocketIdleTestPair(t *testing.T, ctx context.Context) (peer, bridge *websocket.Conn) {
	t.Helper()
	return webSocketIdleTestPairWithTransport(t, ctx, nil)
}

type webSocketIdleTestResponseWriter struct {
	http.ResponseWriter
	wrap func(net.Conn) net.Conn
}

func (w webSocketIdleTestResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, buffer, err := w.ResponseWriter.(http.Hijacker).Hijack()
	if err == nil && w.wrap != nil {
		conn = w.wrap(conn)
		buffer.Writer.Reset(conn)
	}
	return conn, buffer, err
}

func webSocketIdleTestPairWithTransport(t *testing.T, ctx context.Context, wrap func(net.Conn) net.Conn) (peer, bridge *websocket.Conn) {
	t.Helper()
	accepted := make(chan *websocket.Conn, 1)
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(webSocketIdleTestResponseWriter{ResponseWriter: w, wrap: wrap}, r, &websocket.AcceptOptions{InsecureSkipVerify: true, CompressionMode: websocket.CompressionDisabled})
		if err != nil {
			return
		}
		defer conn.CloseNow()
		accepted <- conn
		<-release
	}))
	t.Cleanup(func() { close(release); server.Close() })
	peer, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.CloseNow() })
	select {
	case bridge = <-accepted:
		return peer, bridge
	case <-ctx.Done():
		t.Fatal("WebSocket test handshake did not complete")
		return nil, nil
	}
}

func TestWebSocketBridgeKeepsActiveOneWayMessages(t *testing.T) {
	for _, fromClient := range []bool{false, true} {
		t.Run(map[bool]string{false: "server push", true: "client upload"}[fromClient], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			client, clientBridge := webSocketIdleTestPair(t, ctx)
			upstream, upstreamBridge := webSocketIdleTestPair(t, ctx)
			done := make(chan error, 1)
			const idle = time.Second
			go func() { done <- bridgeWebSocketMessages(ctx, clientBridge, upstreamBridge, idle, nil) }()
			source, destination := upstream, client
			if fromClient {
				source, destination = client, upstream
			}
			// Only one direction sends data, for longer than an idle period.
			ticks := time.NewTicker(50 * time.Millisecond)
			defer ticks.Stop()
			for n := range 24 {
				select {
				case <-ticks.C:
				case err := <-done:
					t.Fatalf("active one-way bridge closed at message %d: %v", n, err)
				case <-ctx.Done():
					t.Fatal("active one-way bridge did not make progress")
				}
				if err := source.Write(ctx, websocket.MessageText, []byte("active")); err != nil {
					t.Fatalf("active write %d: %v", n, err)
				}
				if typ, payload, err := destination.Read(ctx); err != nil || typ != websocket.MessageText || string(payload) != "active" {
					t.Fatalf("active message %d lost: type=%v payload=%q err=%v", n, typ, payload, err)
				}
			}
			cancel()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("cancel did not stop the active bridge")
			}
		})
	}
}

type blockedWebSocketWriteConn struct {
	net.Conn
	started, closed chan struct{}
	writeOnce       sync.Once
	closeOnce       sync.Once
}

func (c *blockedWebSocketWriteConn) Write([]byte) (int, error) {
	c.writeOnce.Do(func() { close(c.started) })
	<-c.closed
	return 0, net.ErrClosed
}

func (c *blockedWebSocketWriteConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

func TestWebSocketBridgeBoundsBlockedWriteDespiteReverseActivity(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	blocked := &blockedWebSocketWriteConn{started: make(chan struct{}), closed: make(chan struct{})}
	client, clientBridge := webSocketIdleTestPairWithTransport(t, ctx, func(conn net.Conn) net.Conn {
		blocked.Conn = conn
		return blocked
	})
	upstream, upstreamBridge := webSocketIdleTestPair(t, ctx)
	done := make(chan error, 1)
	const idle = time.Second
	go func() { done <- bridgeWebSocketMessages(ctx, clientBridge, upstreamBridge, idle, nil) }()
	if err := upstream.Write(ctx, websocket.MessageText, []byte("blocked at client transport")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-blocked.started:
	case <-ctx.Done():
		t.Fatal("bridge did not start the blocked transport write")
	}
	var reverseMessages atomic.Int64
	pumped := make(chan struct{})
	go func() {
		defer close(pumped)
		ticks := time.NewTicker(50 * time.Millisecond)
		defer ticks.Stop()
		for {
			select {
			case <-ticks.C:
			case <-ctx.Done():
				return
			}
			if err := client.Write(ctx, websocket.MessageText, []byte("reverse is active")); err != nil {
				return
			}
			if _, _, err := upstream.Read(ctx); err != nil {
				return
			}
			reverseMessages.Add(1)
		}
	}()
	select {
	case <-done:
		if reverseMessages.Load() < 3 {
			t.Fatalf("bridge closed before reverse activity was established: messages=%d", reverseMessages.Load())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reverse traffic kept a blocked write alive")
	}
	cancel()
	select {
	case <-pumped:
	case <-time.After(5 * time.Second):
		t.Fatal("reverse traffic worker outlived the bridge")
	}
}

func TestWebSocketBridgeClosesAfterBothDirectionsIdle(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, clientBridge := webSocketIdleTestPair(t, ctx)
	_, upstreamBridge := webSocketIdleTestPair(t, ctx)
	done := make(chan error, 1)
	const idle = 30 * time.Millisecond
	go func() { done <- bridgeWebSocketMessages(ctx, clientBridge, upstreamBridge, idle, nil) }()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("idle bridge did not close")
	}
}

func TestWebSocketBridgeStopsOnCancellationAndPeerClose(t *testing.T) {
	for _, closePeer := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancel", true: "peer close"}[closePeer], func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			handshakeCtx, handshakeCancel := context.WithTimeout(ctx, 5*time.Second)
			defer handshakeCancel()
			client, clientBridge := webSocketIdleTestPair(t, handshakeCtx)
			_, upstreamBridge := webSocketIdleTestPair(t, handshakeCtx)
			done := make(chan error, 1)
			go func() { done <- bridgeWebSocketMessages(ctx, clientBridge, upstreamBridge, time.Hour, nil) }()
			if closePeer {
				_ = client.CloseNow()
			} else {
				cancel()
			}
			select {
			case err := <-done:
				if !closePeer && err != nil && !errors.Is(err, context.Canceled) {
					t.Fatalf("cancellation error = %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("bridge outlived cancellation or peer close")
			}
		})
	}
}

func TestWebSocketBridgeKeepsQueuedErrorWhenCanceled(t *testing.T) {
	for _, cause := range []error{errors.New("WebSocket message rejected"), errors.New("upstream write failed"), io.EOF, context.Canceled} {
		for range 100 {
			ctx, cancel := context.WithCancel(context.Background())
			errs := make(chan error, 1)
			errs <- cause
			cancel()
			got := waitWebSocketBridgeResult(ctx, errs)
			if cause == io.EOF || cause == context.Canceled {
				if got != nil {
					t.Fatalf("ordinary shutdown became an error: %v", got)
				}
			} else if got != cause {
				t.Fatalf("queued connection cause lost to shared cancellation: got %v want %v", got, cause)
			}
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := waitWebSocketBridgeResult(ctx, make(chan error)); !errors.Is(err, context.Canceled) {
		t.Fatalf("external cancellation without worker result changed: %v", err)
	}
}
