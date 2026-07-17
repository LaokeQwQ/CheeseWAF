package timekeeper

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

const (
	ntpPacketSize               = 48
	ntpEpochOffsetSeconds       = int64(2_208_988_800)
	ntpEraSeconds               = int64(1) << 32
	DefaultUDPTimeout           = 2 * time.Second
	DefaultUDPMaxRTT            = 2 * time.Second
	DefaultUDPMaxOffset         = 5 * time.Second
	DefaultUDPMaxRootDelay      = 2 * time.Second
	DefaultUDPMaxRootDispersion = 2 * time.Second
	DefaultUDPMaxRootDistance   = 3 * time.Second
)

// Client queries a time source for one NTP sample.
type Client interface {
	Query(context.Context, string) (Sample, error)
}

// Sample contains the timing and quality values from one NTP exchange.
type Sample struct {
	Source         string
	Offset         time.Duration
	RTT            time.Duration
	Stratum        uint8
	RootDelay      time.Duration
	RootDispersion time.Duration
}

// Dialer creates a connected UDP transport.
type Dialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

// KoDError reports an NTP kiss-of-death response and its reference code.
type KoDError struct {
	Code string
}

// Error implements error.
func (e *KoDError) Error() string {
	return fmt.Sprintf("NTP kiss-of-death response: %s", e.Code)
}

// UDPClient is a standard-library NTP client with replaceable side effects.
type UDPClient struct {
	Dialer            Dialer
	Clock             Clock
	Timeout           time.Duration
	MaxRTT            time.Duration
	MaxOffset         time.Duration
	MaxRootDelay      time.Duration
	MaxRootDispersion time.Duration
	MaxRootDistance   time.Duration
}

// NewUDPClient returns a client configured with conservative production defaults.
func NewUDPClient() *UDPClient {
	return &UDPClient{
		Dialer:            &net.Dialer{},
		Clock:             SystemClock{},
		Timeout:           DefaultUDPTimeout,
		MaxRTT:            DefaultUDPMaxRTT,
		MaxOffset:         DefaultUDPMaxOffset,
		MaxRootDelay:      DefaultUDPMaxRootDelay,
		MaxRootDispersion: DefaultUDPMaxRootDispersion,
		MaxRootDistance:   DefaultUDPMaxRootDistance,
	}
}

// Query performs one connected UDP NTP exchange.
func (c *UDPClient) Query(ctx context.Context, source string) (Sample, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	dialer, clock, limits := c.dependencies()
	queryCtx, cancel := context.WithTimeout(ctx, limits.timeout)
	defer cancel()

	conn, err := dialer.DialContext(queryCtx, "udp", ntpAddress(source))
	if err != nil {
		return Sample{}, queryContextError(queryCtx, fmt.Errorf("dial NTP source %q: %w", source, err))
	}
	defer conn.Close()
	deadline, _ := queryCtx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return Sample{}, fmt.Errorf("set NTP deadline: %w", err)
	}
	stopCancellation := context.AfterFunc(queryCtx, func() {
		_ = conn.SetDeadline(time.Now())
	})
	defer stopCancellation()

	t1 := clock.Now()
	request := make([]byte, ntpPacketSize)
	request[0] = 0x23
	binary.BigEndian.PutUint64(request[40:48], encodeNTPTimestamp(t1))
	written, err := conn.Write(request)
	if err != nil {
		return Sample{}, queryContextError(queryCtx, fmt.Errorf("write NTP request: %w", err))
	}
	if written != len(request) {
		return Sample{}, io.ErrShortWrite
	}

	packet := make([]byte, 512)
	n, err := conn.Read(packet)
	t4 := clock.Now()
	if err != nil {
		return Sample{}, queryContextError(queryCtx, fmt.Errorf("read NTP response: %w", err))
	}
	if n < ntpPacketSize {
		return Sample{}, fmt.Errorf("short NTP response: got %d bytes", n)
	}
	packet = packet[:n]
	header := packet[0]
	mode := header & 0x07
	if mode != 4 {
		return Sample{}, fmt.Errorf("invalid NTP server mode %d", mode)
	}
	version := header >> 3 & 0x07
	if version != 3 && version != 4 {
		return Sample{}, fmt.Errorf("unsupported NTP version %d", version)
	}
	if header>>6 == 3 {
		return Sample{}, errors.New("NTP server is unsynchronized")
	}
	if !equalTimestamp(packet[24:32], request[40:48]) {
		return Sample{}, errors.New("NTP originate timestamp does not match request")
	}
	stratum := packet[1]
	if stratum == 0 {
		code := strings.TrimRight(string(packet[12:16]), "\x00 ")
		return Sample{}, &KoDError{Code: code}
	}
	if stratum > 15 {
		return Sample{}, fmt.Errorf("invalid NTP stratum %d", stratum)
	}
	receiveRaw := binary.BigEndian.Uint64(packet[32:40])
	if receiveRaw == 0 {
		return Sample{}, errors.New("NTP receive timestamp is zero")
	}
	transmitRaw := binary.BigEndian.Uint64(packet[40:48])
	if transmitRaw == 0 {
		return Sample{}, errors.New("NTP transmit timestamp is zero")
	}

	t2 := decodeNTPTimestamp(receiveRaw, t4)
	t3 := decodeNTPTimestamp(transmitRaw, t4)
	rtt := t4.Sub(t1) - t3.Sub(t2)
	if rtt < 0 {
		return Sample{}, fmt.Errorf("negative NTP RTT %v", rtt)
	}
	if rtt > limits.maxRTT {
		return Sample{}, fmt.Errorf("NTP RTT %v exceeds limit %v", rtt, limits.maxRTT)
	}
	offset := (t2.Sub(t1) + t3.Sub(t4)) / 2
	if absoluteDuration(offset) > limits.maxOffset {
		return Sample{}, fmt.Errorf("NTP offset %v exceeds limit %v", offset, limits.maxOffset)
	}
	rootDelay := decodeSignedFixed(binary.BigEndian.Uint32(packet[4:8]))
	if rootDelay < 0 {
		return Sample{}, fmt.Errorf("negative NTP root delay %v", rootDelay)
	}
	if rootDelay > limits.maxRootDelay {
		return Sample{}, fmt.Errorf("NTP root delay %v exceeds limit %v", rootDelay, limits.maxRootDelay)
	}
	rootDispersion := decodeUnsignedFixed(binary.BigEndian.Uint32(packet[8:12]))
	if rootDispersion > limits.maxRootDispersion {
		return Sample{}, fmt.Errorf("NTP root dispersion %v exceeds limit %v", rootDispersion, limits.maxRootDispersion)
	}
	rootDistance, overflow := positiveDurationSum(rtt/2, rootDelay/2, rootDispersion)
	if overflow || rootDistance > limits.maxRootDistance {
		return Sample{}, fmt.Errorf("NTP root distance %v exceeds limit %v", rootDistance, limits.maxRootDistance)
	}
	return Sample{
		Source:         source,
		Offset:         offset,
		RTT:            rtt,
		Stratum:        stratum,
		RootDelay:      rootDelay,
		RootDispersion: rootDispersion,
	}, nil
}

type clientLimits struct {
	timeout           time.Duration
	maxRTT            time.Duration
	maxOffset         time.Duration
	maxRootDelay      time.Duration
	maxRootDispersion time.Duration
	maxRootDistance   time.Duration
}

func (c *UDPClient) dependencies() (Dialer, Clock, clientLimits) {
	defaults := NewUDPClient()
	if c == nil {
		c = defaults
	}
	dialer := c.Dialer
	if dialer == nil {
		dialer = defaults.Dialer
	}
	clock := c.Clock
	if clock == nil {
		clock = defaults.Clock
	}
	return dialer, clock, clientLimits{
		timeout:           positiveOrDefault(c.Timeout, defaults.Timeout),
		maxRTT:            positiveOrDefault(c.MaxRTT, defaults.MaxRTT),
		maxOffset:         positiveOrDefault(c.MaxOffset, defaults.MaxOffset),
		maxRootDelay:      positiveOrDefault(c.MaxRootDelay, defaults.MaxRootDelay),
		maxRootDispersion: positiveOrDefault(c.MaxRootDispersion, defaults.MaxRootDispersion),
		maxRootDistance:   positiveOrDefault(c.MaxRootDistance, defaults.MaxRootDistance),
	}
}

func positiveOrDefault(value, fallback time.Duration) time.Duration {
	if value <= 0 {
		return fallback
	}
	return value
}

func ntpAddress(source string) string {
	if _, _, err := net.SplitHostPort(source); err == nil {
		return source
	}
	host := source
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	}
	return net.JoinHostPort(host, "123")
}

func queryContextError(ctx context.Context, err error) error {
	if contextErr := ctx.Err(); contextErr != nil {
		return contextErr
	}
	return err
}

func encodeNTPTimestamp(value time.Time) uint64 {
	seconds := uint64(value.Unix() + ntpEpochOffsetSeconds)
	fraction := uint64(value.Nanosecond()) << 32 / uint64(time.Second)
	return seconds<<32 | fraction
}

func decodeNTPTimestamp(raw uint64, pivot time.Time) time.Time {
	seconds := int64(uint32(raw >> 32))
	pivotSeconds := pivot.Unix() + ntpEpochOffsetSeconds
	pivotEra := floorDiv(pivotSeconds, ntpEraSeconds)
	best := pivotEra*ntpEraSeconds + seconds
	bestDistance := absoluteSeconds(best - pivotSeconds)
	for _, era := range []int64{pivotEra - 1, pivotEra + 1} {
		candidate := era*ntpEraSeconds + seconds
		if distance := absoluteSeconds(candidate - pivotSeconds); distance < bestDistance {
			best = candidate
			bestDistance = distance
		}
	}
	fraction := raw & 0xffff_ffff
	nanoseconds := int64(fraction * uint64(time.Second) >> 32)
	return time.Unix(best-ntpEpochOffsetSeconds, nanoseconds)
}

func floorDiv(value, divisor int64) int64 {
	quotient := value / divisor
	if value < 0 && value%divisor != 0 {
		quotient--
	}
	return quotient
}

func absoluteSeconds(value int64) int64 {
	if value < 0 {
		return -value
	}
	return value
}

func absoluteDuration(value time.Duration) time.Duration {
	if value == time.Duration(-1<<63) {
		return time.Duration(1<<63 - 1)
	}
	if value < 0 {
		return -value
	}
	return value
}

func positiveDurationSum(values ...time.Duration) (time.Duration, bool) {
	const maximum = time.Duration(1<<63 - 1)
	var total time.Duration
	for _, value := range values {
		if value > maximum-total {
			return maximum, true
		}
		total += value
	}
	return total, false
}

func decodeSignedFixed(raw uint32) time.Duration {
	return time.Duration(int64(int32(raw)) * int64(time.Second) / 65_536)
}

func decodeUnsignedFixed(raw uint32) time.Duration {
	return time.Duration(int64(raw) * int64(time.Second) / 65_536)
}

func equalTimestamp(left, right []byte) bool {
	return len(left) == 8 && len(right) == 8 && binary.BigEndian.Uint64(left) == binary.BigEndian.Uint64(right)
}

var _ Client = (*UDPClient)(nil)
var _ Dialer = (*net.Dialer)(nil)
