package timekeeper

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

const testNTPEpochOffset = int64(2_208_988_800)

type sequenceClock struct {
	mu    sync.Mutex
	times []time.Time
	next  int
}

func (c *sequenceClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.times) == 0 {
		return time.Time{}
	}
	if c.next >= len(c.times) {
		return c.times[len(c.times)-1]
	}
	now := c.times[c.next]
	c.next++
	return now
}

type fakeDialer struct {
	conn    net.Conn
	err     error
	network string
	address string
}

func (d *fakeDialer) DialContext(_ context.Context, network, address string) (net.Conn, error) {
	d.network = network
	d.address = address
	return d.conn, d.err
}

type packetConn struct {
	mu          sync.Mutex
	response    []byte
	responder   func([]byte) []byte
	written     []byte
	closed      bool
	readErr     error
	writeErr    error
	deadlineErr error
}

func (c *packetConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.readErr != nil {
		return 0, c.readErr
	}
	if len(c.response) == 0 {
		return 0, errors.New("no scripted response")
	}
	n := copy(p, c.response)
	c.response = nil
	return n, nil
}

func (c *packetConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	c.written = append([]byte(nil), p...)
	if c.responder != nil {
		c.response = c.responder(c.written)
	}
	return len(p), nil
}

func (c *packetConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return nil
}

func (*packetConn) LocalAddr() net.Addr  { return fakeAddr("local") }
func (*packetConn) RemoteAddr() net.Addr { return fakeAddr("remote") }
func (c *packetConn) SetDeadline(time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.deadlineErr
}
func (*packetConn) SetReadDeadline(time.Time) error  { return nil }
func (*packetConn) SetWriteDeadline(time.Time) error { return nil }

type fakeAddr string

func (a fakeAddr) Network() string { return "udp" }
func (a fakeAddr) String() string  { return string(a) }

func TestUDPClientQueriesValidResponse(t *testing.T) {
	t1 := time.Date(2026, time.July, 15, 12, 0, 0, 0, time.UTC)
	t2 := t1.Add(125 * time.Millisecond)
	t3 := t1.Add(250 * time.Millisecond)
	t4 := t1.Add(500 * time.Millisecond)
	conn := &packetConn{responder: func(request []byte) []byte {
		if len(request) != 48 {
			t.Fatalf("request length = %d, want 48", len(request))
		}
		if request[0] != 0x23 {
			t.Fatalf("request LI/VN/mode = %#x, want %#x", request[0], byte(0x23))
		}
		if got, want := binary.BigEndian.Uint64(request[40:48]), testWireTimestamp(t1); got != want {
			t.Fatalf("request transmit timestamp = %#x, want %#x", got, want)
		}
		return testResponse(request, t2, t3, 2, 125*time.Millisecond, 250*time.Millisecond)
	}}
	dialer := &fakeDialer{conn: conn}
	client := NewUDPClient()
	client.Dialer = dialer
	client.Clock = &sequenceClock{times: []time.Time{t1, t4}}

	sample, err := client.Query(context.Background(), "time.test")
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}
	if dialer.network != "udp" || dialer.address != "time.test:123" {
		t.Fatalf("DialContext() = %q, %q, want udp, time.test:123", dialer.network, dialer.address)
	}
	if sample.Source != "time.test" || sample.Stratum != 2 {
		t.Fatalf("source/stratum = %q/%d, want time.test/2", sample.Source, sample.Stratum)
	}
	if sample.RTT != 375*time.Millisecond {
		t.Fatalf("RTT = %v, want 375ms", sample.RTT)
	}
	if sample.Offset != -62500*time.Microsecond {
		t.Fatalf("Offset = %v, want -62.5ms", sample.Offset)
	}
	if sample.RootDelay != 125*time.Millisecond || sample.RootDispersion != 250*time.Millisecond {
		t.Fatalf("root delay/dispersion = %v/%v, want 125ms/250ms", sample.RootDelay, sample.RootDispersion)
	}
	if !conn.closed {
		t.Fatal("connection was not closed")
	}
}

func TestUDPClientRejectsInvalidResponses(t *testing.T) {
	t1 := time.Date(2026, time.July, 15, 12, 0, 0, 0, time.UTC)
	t2 := t1.Add(125 * time.Millisecond)
	t3 := t1.Add(250 * time.Millisecond)
	tests := []struct {
		name   string
		t4     time.Time
		mutate func([]byte)
		want   string
	}{
		{"server mode", time.Time{}, func(packet []byte) { packet[0] = 0x23 }, "mode"},
		{"version", time.Time{}, func(packet []byte) { packet[0] = 0x14 }, "version"},
		{"originate", time.Time{}, func(packet []byte) { packet[31] ^= 1 }, "originate"},
		{"leap unsynchronized", time.Time{}, func(packet []byte) { packet[0] = 0xe4 }, "unsynchronized"},
		{"stratum above 15", time.Time{}, func(packet []byte) { packet[1] = 16 }, "stratum"},
		{"zero receive", time.Time{}, func(packet []byte) { clear(packet[32:40]) }, "receive timestamp"},
		{"zero transmit", time.Time{}, func(packet []byte) { clear(packet[40:48]) }, "transmit timestamp"},
		{"negative RTT", time.Time{}, func(packet []byte) {
			binary.BigEndian.PutUint64(packet[40:48], testWireTimestamp(t1.Add(750*time.Millisecond)))
		}, "negative NTP RTT"},
		{"excessive RTT", t1.Add(3 * time.Second), nil, "RTT"},
		{"excessive offset", time.Time{}, func(packet []byte) {
			binary.BigEndian.PutUint64(packet[32:40], testWireTimestamp(t1.Add(6*time.Second)))
			binary.BigEndian.PutUint64(packet[40:48], testWireTimestamp(t1.Add(6125*time.Millisecond)))
		}, "offset"},
		{"negative root delay", time.Time{}, func(packet []byte) {
			binary.BigEndian.PutUint32(packet[4:8], testSignedFixed(-125*time.Millisecond))
		}, "root delay"},
		{"excessive root delay", time.Time{}, func(packet []byte) {
			binary.BigEndian.PutUint32(packet[4:8], testSignedFixed(3*time.Second))
		}, "root delay"},
		{"excessive root dispersion", time.Time{}, func(packet []byte) {
			binary.BigEndian.PutUint32(packet[8:12], testUnsignedFixed(3*time.Second))
		}, "root dispersion"},
		{"excessive root distance", t1.Add(1625 * time.Millisecond), func(packet []byte) {
			binary.BigEndian.PutUint32(packet[4:8], testSignedFixed(2*time.Second))
			binary.BigEndian.PutUint32(packet[8:12], testUnsignedFixed(1500*time.Millisecond))
		}, "root distance"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t4 := test.t4
			if t4.IsZero() {
				t4 = t1.Add(500 * time.Millisecond)
			}
			conn := &packetConn{responder: func(request []byte) []byte {
				response := testResponse(request, t2, t3, 2, 125*time.Millisecond, 250*time.Millisecond)
				if test.mutate != nil {
					test.mutate(response)
				}
				return response
			}}
			client := NewUDPClient()
			client.Dialer = &fakeDialer{conn: conn}
			client.Clock = &sequenceClock{times: []time.Time{t1, t4}}

			_, err := client.Query(context.Background(), "time.test")
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Query() error = %v, want error containing %q", err, test.want)
			}
			if !conn.closed {
				t.Fatal("connection was not closed after rejected response")
			}
		})
	}
}

func TestUDPClientReturnsKissOfDeathCode(t *testing.T) {
	t1 := time.Date(2026, time.July, 15, 12, 0, 0, 0, time.UTC)
	conn := &packetConn{responder: func(request []byte) []byte {
		response := testResponse(request, t1.Add(125*time.Millisecond), t1.Add(250*time.Millisecond), 0, 0, 0)
		copy(response[12:16], "RATE")
		return response
	}}
	client := NewUDPClient()
	client.Dialer = &fakeDialer{conn: conn}
	client.Clock = &sequenceClock{times: []time.Time{t1, t1.Add(500 * time.Millisecond)}}

	_, err := client.Query(context.Background(), "time.test")
	var kod *KoDError
	if !errors.As(err, &kod) {
		t.Fatalf("Query() error = %v, want *KoDError", err)
	}
	if kod.Code != "RATE" {
		t.Fatalf("KoD code = %q, want RATE", kod.Code)
	}
	if !conn.closed {
		t.Fatal("connection was not closed after KoD response")
	}
}

func TestUDPClientDecodesEraNearLocalPivotAndAcceptsVersion3(t *testing.T) {
	t1 := time.Date(2040, time.January, 2, 3, 4, 5, 0, time.UTC)
	conn := &packetConn{responder: func(request []byte) []byte {
		response := testResponse(request, t1.Add(125*time.Millisecond), t1.Add(250*time.Millisecond), 3, 0, 0)
		response[0] = 0x1c
		return response
	}}
	client := NewUDPClient()
	client.Dialer = &fakeDialer{conn: conn}
	client.Clock = &sequenceClock{times: []time.Time{t1, t1.Add(500 * time.Millisecond)}}

	sample, err := client.Query(context.Background(), "time.test:9123")
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}
	if sample.RTT != 375*time.Millisecond || sample.Offset != -62500*time.Microsecond {
		t.Fatalf("era-decoded RTT/offset = %v/%v, want 375ms/-62.5ms", sample.RTT, sample.Offset)
	}
}

func TestUDPClientPropagatesCancellationAndTimeout(t *testing.T) {
	tests := []struct {
		name    string
		timeout time.Duration
		cancel  bool
		want    error
	}{
		{"context cancellation", time.Second, true, context.Canceled},
		{"client timeout", 20 * time.Millisecond, false, context.DeadlineExceeded},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			conn := newBlockingConn()
			client := NewUDPClient()
			client.Dialer = &fakeDialer{conn: conn}
			client.Clock = &sequenceClock{times: []time.Time{time.Now(), time.Now()}}
			client.Timeout = test.timeout
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			go func() {
				_, err := client.Query(ctx, "time.test")
				result <- err
			}()
			select {
			case <-conn.readStarted:
			case <-time.After(time.Second):
				t.Fatal("Query() did not reach Read")
			}
			if test.cancel {
				cancel()
			}
			select {
			case err := <-result:
				if !errors.Is(err, test.want) {
					t.Fatalf("Query() error = %v, want %v", err, test.want)
				}
			case <-time.After(time.Second):
				t.Fatal("Query() did not return after cancellation/deadline")
			}
			if !conn.closed {
				t.Fatal("connection was not closed after cancellation/deadline")
			}
		})
	}
}

func TestUDPClientClosesConnectionOnTransportErrors(t *testing.T) {
	tests := []struct {
		name string
		conn *packetConn
	}{
		{"deadline", &packetConn{deadlineErr: errors.New("deadline failed")}},
		{"write", &packetConn{writeErr: errors.New("write failed")}},
		{"read", &packetConn{readErr: errors.New("read failed")}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := NewUDPClient()
			client.Dialer = &fakeDialer{conn: test.conn}
			client.Clock = &sequenceClock{times: []time.Time{time.Now(), time.Now()}}
			if _, err := client.Query(context.Background(), "time.test"); err == nil {
				t.Fatal("Query() error = nil, want transport error")
			}
			if !test.conn.closed {
				t.Fatal("connection was not closed after transport error")
			}
		})
	}
}

type blockingConn struct {
	*packetConn
	mu            sync.Mutex
	deadlineCalls int
	readOnce      sync.Once
	unblockOnce   sync.Once
	readStarted   chan struct{}
	unblock       chan struct{}
}

func newBlockingConn() *blockingConn {
	return &blockingConn{
		packetConn:  &packetConn{},
		readStarted: make(chan struct{}),
		unblock:     make(chan struct{}),
	}
}

func (c *blockingConn) Read([]byte) (int, error) {
	c.readOnce.Do(func() { close(c.readStarted) })
	<-c.unblock
	return 0, fakeTimeoutError{}
}

func (c *blockingConn) SetDeadline(time.Time) error {
	c.mu.Lock()
	c.deadlineCalls++
	calls := c.deadlineCalls
	c.mu.Unlock()
	if calls > 1 {
		c.unblockOnce.Do(func() { close(c.unblock) })
	}
	return nil
}

type fakeTimeoutError struct{}

func (fakeTimeoutError) Error() string   { return "fake timeout" }
func (fakeTimeoutError) Timeout() bool   { return true }
func (fakeTimeoutError) Temporary() bool { return true }

func testResponse(request []byte, receive, transmit time.Time, stratum uint8, rootDelay, rootDispersion time.Duration) []byte {
	response := make([]byte, 48)
	response[0] = 0x24
	response[1] = stratum
	binary.BigEndian.PutUint32(response[4:8], uint32(rootDelay*65536/time.Second))
	binary.BigEndian.PutUint32(response[8:12], uint32(rootDispersion*65536/time.Second))
	copy(response[24:32], request[40:48])
	binary.BigEndian.PutUint64(response[32:40], testWireTimestamp(receive))
	binary.BigEndian.PutUint64(response[40:48], testWireTimestamp(transmit))
	return response
}

func testWireTimestamp(value time.Time) uint64 {
	seconds := uint64(value.Unix() + testNTPEpochOffset)
	fraction := uint64(value.Nanosecond()) << 32 / uint64(time.Second)
	return seconds<<32 | fraction
}

func testSignedFixed(value time.Duration) uint32 {
	return uint32(int32(value * 65_536 / time.Second))
}

func testUnsignedFixed(value time.Duration) uint32 {
	return uint32(value * 65_536 / time.Second)
}
