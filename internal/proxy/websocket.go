package proxy

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/protection/bot"
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
func proxyWebSocket(ctx context.Context, w http.ResponseWriter, r *http.Request, target *url.URL, limit int64, clientIP, originScheme string, passHost bool, hostHeader string, inspect func(bool, byte, []byte) error, inspectResponse func(*http.Response) error) error {
	if target == nil {
		return fmt.Errorf("nil WebSocket upstream")
	}
	upstream, err := webSocketUpstreamURL(target, r.URL, originScheme)
	if err != nil {
		return err
	}
	header := r.Header.Clone()
	stripWebSocketHopHeaders(header)
	for _, name := range stripClientForwardHeaders {
		deleteHeaderAliases(header, name)
	}
	// websocket.Dial writes these headers from DialOptions. Remove client
	// supplied values first so duplicate or stale handshake fields cannot be
	// forwarded to the origin.
	for _, name := range []string{
		"Sec-WebSocket-Key", "Sec-WebSocket-Version",
		"Sec-WebSocket-Protocol", "Sec-WebSocket-Extensions", "Sec-WebSocket-Accept",
	} {
		deleteHeaderAliases(header, name)
	}
	if r.Host != "" {
		header.Set("X-Forwarded-Host", r.Host)
	}
	forwardedProto, forwardedPort := "http", "80"
	if requestIsHTTPS(r, bot.TrustedCIDRsFromContext(r.Context())) {
		forwardedProto, forwardedPort = "https", "443"
	}
	header.Set("X-Forwarded-Proto", forwardedProto)
	header.Set("X-Forwarded-Port", forwardedPort)
	if clientIP = normalizedClientIP(clientIP); clientIP == "" {
		clientIP = peerIP(r.RemoteAddr)
	}
	if clientIP != "" {
		header.Set("X-Forwarded-For", clientIP)
		header.Set("X-Real-IP", clientIP)
	}
	upstreamHost := webSocketHost(r, upstream.Host, passHost, hostHeader)
	subprotocols := webSocketSubprotocols(r.Header)
	upstreamConn, response, err := websocket.Dial(ctx, upstream.String(), &websocket.DialOptions{
		HTTPHeader:      header,
		Host:            upstreamHost,
		Subprotocols:    subprotocols,
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
			responseHeader := response.Header.Clone()
			stripWebSocketHopHeaders(responseHeader)
			for name, values := range responseHeader {
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
	if response != nil {
		responseHeader := response.Header.Clone()
		stripWebSocketHopHeaders(responseHeader)
		for name, values := range responseHeader {
			// Accept owns the protocol response fields. Preserve other origin
			// handshake metadata, including Set-Cookie and application headers.
			if isWebSocketHandshakeHeader(name) {
				continue
			}
			for _, value := range values {
				w.Header().Add(name, value)
			}
		}
	}
	selectedSubprotocol := upstreamConn.Subprotocol()
	var acceptedSubprotocols []string
	if selectedSubprotocol != "" {
		acceptedSubprotocols = []string{selectedSubprotocol}
	}
	clientConn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true,
		Subprotocols:       acceptedSubprotocols,
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
	return bridgeWebSocketMessages(ctx, clientConn, upstreamConn, webSocketIdleTimeout, inspect)
}

func bridgeWebSocketMessages(ctx context.Context, clientConn, upstreamConn *websocket.Conn, idleTimeout time.Duration, inspect func(bool, byte, []byte) error) error {
	bridgeCtx, cancel := context.WithTimeout(ctx, webSocketLifetime)
	var timerMu sync.Mutex
	lastActivity := time.Now()
	closed := false
	var idle *time.Timer
	idle = time.AfterFunc(idleTimeout, func() {
		timerMu.Lock()
		defer timerMu.Unlock()
		if closed {
			return
		}
		// A callback may already be waiting for the lock when activity resets
		// the timer. Check the latest activity before closing the whole bridge.
		if remaining := idleTimeout - time.Since(lastActivity); remaining > 0 {
			idle.Reset(remaining)
			return
		}
		closed = true
		cancel()
	})
	touch := func() {
		timerMu.Lock()
		defer timerMu.Unlock()
		if !closed {
			lastActivity = time.Now()
			idle.Reset(idleTimeout)
		}
	}
	var workers sync.WaitGroup
	defer func() {
		timerMu.Lock()
		closed = true
		idle.Stop()
		timerMu.Unlock()
		cancel()
		workers.Wait()
	}()
	errs := make(chan error, 2)
	bridge := func(dst, src *websocket.Conn, fromClient bool) {
		defer workers.Done()
		defer cancel()
		for {
			typ, payload, readErr := src.Read(bridgeCtx)
			if readErr != nil {
				errs <- readErr
				return
			}
			touch()
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
			// Activity in the reverse direction must not keep a blocked write alive.
			writeCtx, writeCancel := context.WithTimeout(bridgeCtx, idleTimeout)
			writeErr := dst.Write(writeCtx, typ, payload)
			writeCancel()
			if writeErr != nil {
				errs <- writeErr
				return
			}
			touch()
		}
	}
	workers.Add(2)
	go bridge(upstreamConn, clientConn, true)
	go bridge(clientConn, upstreamConn, false)
	return waitWebSocketBridgeResult(bridgeCtx, errs)
}

func waitWebSocketBridgeResult(ctx context.Context, errs <-chan error) error {
	var err error
	select {
	case err = <-errs:
	case <-ctx.Done():
		select {
		case err = <-errs:
		default:
			return ctx.Err()
		}
	}
	if ctx.Err() != nil && errors.Is(err, net.ErrClosed) {
		// Cancellation closes the sockets, and the read may report the closed
		// connection before the context error; surface the cancellation.
		return ctx.Err()
	}
	if err == context.Canceled || err == io.EOF {
		return nil
	}
	return err
}

func stripWebSocketHopHeaders(header http.Header) {
	hopHeaders := map[string]bool{
		"connection": true, "proxy-connection": true, "keep-alive": true,
		"proxy-authenticate": true, "proxy-authorization": true,
		"te": true, "trailer": true, "transfer-encoding": true, "upgrade": true,
	}
	// Connection options belong to one transport leg. Remove their fields
	// before Dial or Accept replaces Connection for the next handshake.
	for name, values := range header {
		if !strings.EqualFold(name, "Connection") {
			continue
		}
		for _, value := range values {
			for _, option := range strings.Split(value, ",") {
				if option = strings.TrimSpace(option); option != "" {
					hopHeaders[strings.ToLower(strings.ReplaceAll(option, "_", "-"))] = true
				}
			}
		}
	}
	for name := range header {
		if hopHeaders[strings.ToLower(strings.ReplaceAll(name, "_", "-"))] {
			delete(header, name)
		}
	}
}

func isWebSocketHandshakeHeader(name string) bool {
	switch strings.ToLower(name) {
	case "connection", "upgrade", "sec-websocket-accept", "sec-websocket-protocol", "sec-websocket-extensions":
		return true
	default:
		return false
	}
}

func webSocketSubprotocols(header http.Header) []string {
	var subprotocols []string
	for _, value := range header.Values("Sec-WebSocket-Protocol") {
		for _, protocol := range strings.Split(value, ",") {
			if protocol = strings.TrimSpace(protocol); protocol != "" {
				subprotocols = append(subprotocols, protocol)
			}
		}
	}
	return subprotocols
}

func webSocketUpstreamURL(target, request *url.URL, originScheme string) (*url.URL, error) {
	if target == nil {
		return nil, fmt.Errorf("nil WebSocket upstream")
	}
	upstream := *target
	if scheme := strings.ToLower(strings.TrimSpace(originScheme)); scheme == "http" || scheme == "https" {
		upstream.Scheme = scheme
	}
	switch strings.ToLower(upstream.Scheme) {
	case "http":
		upstream.Scheme = "ws"
	case "https":
		upstream.Scheme = "wss"
	case "ws", "wss":
	default:
		return nil, fmt.Errorf("unsupported WebSocket upstream scheme %q", upstream.Scheme)
	}
	if request != nil {
		upstream.Path, upstream.RawPath = joinUpstreamPath(target, request)
		upstream.RawQuery = joinUpstreamQuery(target.RawQuery, request.RawQuery)
		upstream.ForceQuery = target.ForceQuery || request.ForceQuery
	}
	return &upstream, nil
}

func webSocketHost(r *http.Request, originHost string, passHost bool, configuredHost string) string {
	if configuredHost = strings.TrimSpace(configuredHost); configuredHost != "" {
		return configuredHost
	}
	if passHost && r != nil && strings.TrimSpace(r.Host) != "" {
		return r.Host
	}
	return originHost
}

func joinUpstreamPath(target, request *url.URL) (path, rawPath string) {
	basePath, requestPath := target.EscapedPath(), request.EscapedPath()
	if basePath == "" {
		basePath = "/"
	}
	if requestPath == "" {
		requestPath = "/"
	}
	if !strings.HasPrefix(basePath, "/") {
		basePath = "/" + basePath
	}
	if !strings.HasPrefix(requestPath, "/") {
		requestPath = "/" + requestPath
	}
	joined := strings.TrimSuffix(basePath, "/") + "/" + strings.TrimPrefix(requestPath, "/")
	if joined == "" {
		joined = "/"
	}
	path, _ = url.PathUnescape(joined)
	if path == "" {
		path = "/"
	}
	if joined == path {
		return path, ""
	}
	return path, joined
}

func joinUpstreamQuery(targetQuery, requestQuery string) string {
	if targetQuery == "" {
		return requestQuery
	}
	if requestQuery == "" {
		return targetQuery
	}
	return targetQuery + "&" + requestQuery
}
