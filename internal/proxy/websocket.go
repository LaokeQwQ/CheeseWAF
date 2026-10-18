package proxy

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"nhooyr.io/websocket"
)

type webSocketHandshakeError struct{ err error }

func (e *webSocketHandshakeError) Error() string { return e.err.Error() }
func (e *webSocketHandshakeError) Unwrap() error { return e.err }

type webSocketOrdinaryResponse struct{ status int }

func (e *webSocketOrdinaryResponse) Error() string {
	return "upstream returned an ordinary HTTP response"
}

func IsWebSocketUpgrade(r *http.Request) bool {
	if r == nil {
		return false
	}
	key, err := base64.StdEncoding.DecodeString(r.Header.Get("Sec-WebSocket-Key"))
	return r.Method == http.MethodGet && r.ProtoMajor == 1 && r.ProtoMinor >= 1 && err == nil && len(key) == 16 && r.Header.Get("Sec-WebSocket-Version") == "13" && headerHasToken(r.Header, "Connection", "upgrade") && strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
}

func headerHasToken(header http.Header, key, token string) bool {
	for _, value := range header.Values(key) {
		for _, item := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(item), token) {
				return true
			}
		}
	}
	return false
}

// A browser may only upgrade from the same scheme and authority. Non-browser
// clients may omit Origin; a literal null origin is never trusted.
func webSocketOriginAllowed(r *http.Request, https bool) bool {
	values := r.Header.Values("Origin")
	if len(values) == 0 {
		return true
	}
	if len(values) != 1 {
		return false
	}
	origin, err := url.Parse(values[0])
	scheme := "http"
	if https {
		scheme = "https"
	}
	return err == nil && origin.User == nil && strings.EqualFold(origin.Scheme, scheme) && strings.EqualFold(origin.Host, r.Host) && origin.Path == "" && origin.RawQuery == "" && origin.Fragment == ""
}

// proxyWebSocket bridges complete WebSocket messages so callers can inspect
// them before they are released to the other side. The websocket package
// validates masking, fragmentation, control frames, and close payloads while
// SetReadLimit bounds the message allocation.
func proxyWebSocket(ctx context.Context, w http.ResponseWriter, r *http.Request, target *url.URL, limit int64, inspect func(bool, byte, []byte) error, inspectResponse func(*http.Response) error) error {
	if target == nil {
		return fmt.Errorf("nil WebSocket upstream")
	}
	upstream := *target
	switch strings.ToLower(upstream.Scheme) {
	case "http":
		upstream.Scheme = "ws"
	case "https":
		upstream.Scheme = "wss"
	case "ws", "wss":
	default:
		return fmt.Errorf("unsupported WebSocket upstream scheme %q", upstream.Scheme)
	}
	header := r.Header.Clone()
	for _, name := range stripClientForwardHeaders {
		deleteHeaderAliases(header, name)
	}
	header.Del("Sec-WebSocket-Extensions")
	header.Set("X-Forwarded-Host", r.Host)
	header.Set("X-Forwarded-Proto", "http")
	header.Set("X-Forwarded-Port", "80")
	if r.TLS != nil {
		header.Set("X-Forwarded-Proto", "https")
		header.Set("X-Forwarded-Port", "443")
	}
	upstreamConn, response, err := websocket.Dial(ctx, upstream.String(), &websocket.DialOptions{
		HTTPHeader:      header,
		Host:            target.Host,
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		if response != nil && response.StatusCode != http.StatusSwitchingProtocols {
			defer response.Body.Close()
			if inspectResponse != nil {
				if inspectErr := inspectResponse(response); inspectErr != nil {
					return inspectErr
				}
			}
			for name, values := range response.Header {
				for _, value := range values {
					w.Header().Add(name, value)
				}
			}
			w.WriteHeader(response.StatusCode)
			_, copyErr := io.Copy(w, response.Body)
			if copyErr != nil {
				return copyErr
			}
			return &webSocketOrdinaryResponse{status: response.StatusCode}
		}
		return &webSocketHandshakeError{err: fmt.Errorf("WebSocket upstream handshake: %w", err)}
	}
	defer upstreamConn.CloseNow()
	clientConn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true,
		CompressionMode:    websocket.CompressionDisabled,
	})
	if err != nil {
		return err
	}
	defer clientConn.CloseNow()
	if limit <= 0 || limit > maxWebSocketMessage {
		limit = maxWebSocketMessage
	}
	clientConn.SetReadLimit(limit)
	upstreamConn.SetReadLimit(limit)

	bridgeCtx, cancel := context.WithTimeout(ctx, webSocketLifetime)
	defer cancel()
	errs := make(chan error, 2)
	var once sync.Once
	bridge := func(dst, src *websocket.Conn, fromClient bool) {
		defer func() { once.Do(cancel) }()
		for {
			readCtx, readCancel := context.WithTimeout(bridgeCtx, webSocketIdleTimeout)
			typ, payload, readErr := src.Read(readCtx)
			readCancel()
			if readErr != nil {
				errs <- readErr
				return
			}
			if inspect != nil && typ != websocket.MessageBinary && typ != websocket.MessageText {
				errs <- fmt.Errorf("unsupported WebSocket message type %v", typ)
				return
			}
			if inspect != nil {
				if inspect(fromClient, byte(typ), payload) != nil {
					errs <- fmt.Errorf("WebSocket message rejected")
					return
				}
			}
			if writeErr := dst.Write(bridgeCtx, typ, payload); writeErr != nil {
				errs <- writeErr
				return
			}
		}
	}
	go bridge(upstreamConn, clientConn, true)
	go bridge(clientConn, upstreamConn, false)
	select {
	case err := <-errs:
		if err == context.Canceled || err == io.EOF {
			return nil
		}
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}
