package proxy

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

const (
	maxWebSocketMessage  = 1 << 20
	webSocketIdleTimeout = 60 * time.Second
	webSocketLifetime    = time.Hour
)

type webSocketFrameTunnel struct {
	conn                                                            io.ReadWriteCloser
	reader                                                          *bufio.Reader
	limit                                                           int64
	inspect                                                         func(bool, byte, []byte) error
	incoming, outgoing                                              webSocketMessage
	writeBuffer, readBuffer                                         []byte
	closeOnce                                                       sync.Once
	timerMu                                                         sync.Mutex
	idle, lifetime                                                  *time.Timer
	closed                                                          bool
	framesIn, framesOut, bytesIn, bytesOut, messagesIn, messagesOut atomic.Uint64
}

type webSocketMessage struct {
	opcode        byte
	payload, wire []byte
	fragments     int
	window        time.Time
	frames        int
}

func newWebSocketFrameTunnel(conn io.ReadWriteCloser, limit int64, inspect func(bool, byte, []byte) error) *webSocketFrameTunnel {
	if limit <= 0 || limit > maxWebSocketMessage {
		limit = maxWebSocketMessage
	}
	t := &webSocketFrameTunnel{conn: conn, reader: bufio.NewReader(conn), limit: limit, inspect: inspect}
	t.idle = time.AfterFunc(webSocketIdleTimeout, func() { _ = t.Close() })
	t.lifetime = time.AfterFunc(webSocketLifetime, func() { _ = t.Close() })
	return t
}

func (t *webSocketFrameTunnel) Close() error {
	var err error
	t.closeOnce.Do(func() {
		t.timerMu.Lock()
		t.closed = true
		t.idle.Stop()
		t.lifetime.Stop()
		t.timerMu.Unlock()
		err = t.conn.Close()
	})
	return err
}

func (t *webSocketFrameTunnel) touch() {
	t.timerMu.Lock()
	defer t.timerMu.Unlock()
	if !t.closed {
		t.idle.Reset(webSocketIdleTimeout)
	}
}

// frameLength checks the header before allocating or waiting for its payload.
func (t *webSocketFrameTunnel) frameLength(raw []byte, client bool) (int, error) {
	if len(raw) < 2 {
		return 0, nil
	}
	opcode := raw[0] & 15
	if raw[0]&0x70 != 0 || (raw[1]&0x80 != 0) != client {
		return 0, errors.New("unsupported WebSocket extension or invalid masking")
	}
	if opcode != 0 && opcode != 1 && opcode != 2 && opcode != 8 && opcode != 9 && opcode != 10 {
		return 0, errors.New("invalid WebSocket opcode")
	}
	length := uint64(raw[1] & 127)
	header := 2
	switch length {
	case 126:
		if len(raw) < 4 {
			return 0, nil
		}
		length = uint64(binary.BigEndian.Uint16(raw[2:4]))
		header = 4
		// RFC 6455 requires the minimal length encoding; a 16-bit value below
		// 126 should have used the 7-bit form.
		if length < 126 {
			return 0, errors.New("noncanonical WebSocket length")
		}
	case 127:
		if len(raw) < 10 {
			return 0, nil
		}
		length = binary.BigEndian.Uint64(raw[2:10])
		header = 10
		if length < 65536 || length>>63 != 0 {
			return 0, errors.New("invalid WebSocket length")
		}
	}
	if length > uint64(t.limit) {
		return 0, errors.New("WebSocket frame exceeds message limit")
	}
	if opcode >= 8 && (length > 125 || raw[0]&128 == 0) {
		return 0, errors.New("invalid WebSocket control frame")
	}
	if client {
		header += 4
	}
	return header + int(length), nil
}

func (t *webSocketFrameTunnel) process(raw []byte, client bool) ([]byte, error) {
	state := &t.outgoing
	if client {
		state = &t.incoming
		t.framesIn.Add(1)
		t.bytesIn.Add(uint64(len(raw)))
	} else {
		t.framesOut.Add(1)
		t.bytesOut.Add(uint64(len(raw)))
	}
	now := time.Now()
	if now.Sub(state.window) >= time.Second {
		state.window = now
		state.frames = 0
	}
	state.frames++
	if state.frames > 256 {
		return nil, errors.New("WebSocket frame rate exceeds limit")
	}
	opcode := raw[0] & 15
	fin := raw[0]&128 != 0
	header := 2
	switch raw[1] & 127 {
	case 126:
		header = 4
	case 127:
		header = 10
	}
	var mask []byte
	if client {
		mask = raw[header : header+4]
		header += 4
	}
	payload := append([]byte(nil), raw[header:]...)
	for i := range payload {
		if client {
			payload[i] ^= mask[i%4]
		}
	}
	if opcode >= 8 {
		if opcode == 8 {
			if len(payload) == 1 {
				return nil, errors.New("invalid WebSocket close payload")
			}
			if len(payload) >= 2 {
				code := binary.BigEndian.Uint16(payload)
				if code < 1000 || code >= 5000 || (code >= 1016 && code < 3000) || code == 1004 || code == 1005 || code == 1006 || code == 1015 || !utf8.Valid(payload[2:]) {
					return nil, errors.New("invalid WebSocket close status")
				}
			}
		}
		t.touch()
		return raw, nil
	}
	if opcode == 0 {
		if state.opcode == 0 {
			return nil, errors.New("unexpected WebSocket continuation")
		}
	} else {
		if state.opcode != 0 {
			return nil, errors.New("interleaved WebSocket messages")
		}
		state.opcode = opcode
	}
	if int64(len(state.payload)+len(payload)) > t.limit || state.fragments >= 1024 {
		return nil, errors.New("WebSocket message exceeds limit")
	}
	state.fragments++
	state.payload = append(state.payload, payload...)
	state.wire = append(state.wire, raw...)
	if !fin {
		t.touch()
		return nil, nil
	}
	if state.opcode == 1 && !utf8.Valid(state.payload) {
		return nil, errors.New("invalid WebSocket text encoding")
	}
	if t.inspect != nil {
		if err := t.inspect(client, state.opcode, state.payload); err != nil {
			return nil, err
		}
	}
	if client {
		t.messagesIn.Add(1)
	} else {
		t.messagesOut.Add(1)
	}
	result := state.wire
	state.opcode = 0
	state.payload = nil
	state.wire = nil
	state.fragments = 0
	t.touch()
	return result, nil
}

func (t *webSocketFrameTunnel) Read(dst []byte) (int, error) {
	for len(t.readBuffer) == 0 {
		header, err := t.reader.Peek(2)
		if err != nil {
			return 0, err
		}
		needed := 2
		switch header[1] & 127 {
		case 126:
			needed = 4
		case 127:
			needed = 10
		}
		header, err = t.reader.Peek(needed)
		if err != nil {
			return 0, err
		}
		length, err := t.frameLength(header, false)
		if err != nil {
			_ = t.Close()
			return 0, err
		}
		frame := make([]byte, length)
		if _, err = io.ReadFull(t.reader, frame); err != nil {
			return 0, err
		}
		t.readBuffer, err = t.process(frame, false)
		if err != nil {
			_ = t.Close()
			return 0, err
		}
	}
	n := copy(dst, t.readBuffer)
	t.readBuffer = t.readBuffer[n:]
	return n, nil
}

func (t *webSocketFrameTunnel) Write(src []byte) (int, error) {
	t.writeBuffer = append(t.writeBuffer, src...)
	for len(t.writeBuffer) > 0 {
		length, err := t.frameLength(t.writeBuffer, true)
		if err != nil {
			_ = t.Close()
			return 0, err
		}
		if length == 0 || len(t.writeBuffer) < length {
			return len(src), nil
		}
		ready, err := t.process(t.writeBuffer[:length], true)
		if err != nil {
			_ = t.Close()
			return 0, err
		}
		if len(ready) > 0 {
			if _, err = t.conn.Write(ready); err != nil {
				return 0, fmt.Errorf("write inspected WebSocket frame: %w", err)
			}
		}
		t.writeBuffer = t.writeBuffer[length:]
	}
	t.writeBuffer = nil
	return len(src), nil
}
