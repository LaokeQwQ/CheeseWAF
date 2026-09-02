package monitor

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/golang/snappy"
)

func TestRemoteWriteRejectsPrivateEndpointByDefault(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("remote_write should not dial a private endpoint by default")
	}))
	defer server.Close()

	writer := NewRemoteWriter(config.RemoteWriteConfig{
		Enabled:  true,
		Endpoint: server.URL,
	}, nil)

	err := writer.Push(context.Background(), Snapshot{})
	if err == nil || !strings.Contains(err.Error(), "remote_write endpoint host IP must be public") {
		t.Fatalf("expected private endpoint guard error, got %v", err)
	}
}

func TestRemoteWriteAllowsPrivateEndpointWhenExplicit(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if got := r.Header.Get("Content-Type"); got != "application/x-protobuf" {
			t.Fatalf("unexpected content type %q", got)
		}
		if got := r.Header.Get("Content-Encoding"); got != "snappy" {
			t.Fatalf("unexpected content encoding %q", got)
		}
		if got := r.Header.Get("X-Prometheus-Remote-Write-Version"); got != "0.1.0" {
			t.Fatalf("unexpected remote write version %q", got)
		}
		compressed, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read remote write body: %v", err)
		}
		payload, err := snappy.Decode(nil, compressed)
		if err != nil {
			t.Fatalf("decode snappy body: %v", err)
		}
		series, err := readRepeatedMessage(payload, 1)
		if err != nil {
			t.Fatalf("decode WriteRequest body: %v", err)
		}
		labels, err := readRepeatedMessage(series, 1)
		if err != nil {
			t.Fatalf("decode TimeSeries labels: %v", err)
		}
		if got := readStringField(labels, 2); got != "cheesewaf_blocked_total" {
			t.Fatalf("unexpected first remote metric %q", got)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	writer := NewRemoteWriter(config.RemoteWriteConfig{
		Enabled:              true,
		Endpoint:             server.URL,
		AllowPrivateEndpoint: true,
	}, nil)

	if err := writer.Push(context.Background(), Snapshot{GeneratedAt: time.UnixMilli(1700000000123), Requests: 1}); err != nil {
		t.Fatalf("expected remote_write to allow explicitly trusted private endpoint: %v", err)
	}
	if requests != 1 {
		t.Fatalf("expected one remote_write request, got %d", requests)
	}
}

func TestEncodeRemoteWriteUsesPrometheusWriteRequest(t *testing.T) {
	payload := encodeRemoteWrite(Snapshot{
		GeneratedAt: time.UnixMilli(1700000000123),
		Requests:    7,
		Blocked:     3,
	})
	decoded, err := snappy.Decode(nil, snappy.Encode(nil, payload))
	if err != nil {
		t.Fatalf("snappy round trip: %v", err)
	}
	series, err := readRepeatedMessage(decoded, 1)
	if err != nil {
		t.Fatalf("decode WriteRequest: %v", err)
	}
	labels, err := readRepeatedMessage(series, 1)
	if err != nil {
		t.Fatalf("decode TimeSeries labels: %v", err)
	}
	if got := readStringField(labels, 1); got != "__name__" {
		t.Fatalf("label name = %q, want __name__", got)
	}
	if got := readStringField(labels, 2); got != "cheesewaf_blocked_total" {
		t.Fatalf("first metric name = %q, want cheesewaf_blocked_total", got)
	}
	sample, err := readRepeatedMessage(series, 2)
	if err != nil {
		t.Fatalf("decode sample: %v", err)
	}
	if got := readInt64Field(sample, 2); got != 1700000000123 {
		t.Fatalf("sample timestamp = %d, want 1700000000123", got)
	}
	if got := readFloat64Field(sample, 1); got != 3 {
		t.Fatalf("sample value = %v, want 3", got)
	}
}

func readRepeatedMessage(data []byte, wantedField byte) ([]byte, error) {
	for len(data) > 0 {
		field, wire, n := consumeUvarint(data)
		if n <= 0 {
			return nil, errMalformedRemoteWrite
		}
		data = data[n:]
		if wire != 2 {
			var err error
			data, err = skipWire(data, wire)
			if err != nil {
				return nil, err
			}
			continue
		}
		length, n := consumeRawUvarint(data)
		if n <= 0 || length > uint64(len(data)-n) {
			return nil, errMalformedRemoteWrite
		}
		message := data[n : n+int(length)]
		if field == uint64(wantedField) {
			return message, nil
		}
		data = data[n+int(length):]
	}
	return nil, errMalformedRemoteWrite
}

func readStringField(data []byte, wantedField byte) string {
	for len(data) > 0 {
		field, wire, n := consumeUvarint(data)
		data = data[n:]
		if wire != 2 {
			data, _ = skipWire(data, wire)
			continue
		}
		length, n := consumeRawUvarint(data)
		value := data[n : n+int(length)]
		data = data[n+int(length):]
		if field == uint64(wantedField) {
			return string(value)
		}
	}
	return ""
}

func readInt64Field(data []byte, wantedField byte) int64 {
	for len(data) > 0 {
		field, wire, n := consumeUvarint(data)
		data = data[n:]
		if wire != 0 {
			data, _ = skipWire(data, wire)
			continue
		}
		value, n := consumeRawUvarint(data)
		data = data[n:]
		if field == uint64(wantedField) {
			return int64(value)
		}
	}
	return 0
}

func readFloat64Field(data []byte, wantedField byte) float64 {
	for len(data) > 0 {
		field, wire, n := consumeUvarint(data)
		data = data[n:]
		if wire != 1 {
			data, _ = skipWire(data, wire)
			continue
		}
		if len(data) < 8 {
			return 0
		}
		value := math.Float64frombits(binary.LittleEndian.Uint64(data[:8]))
		data = data[8:]
		if field == uint64(wantedField) {
			return value
		}
	}
	return 0
}

func consumeUvarint(data []byte) (uint64, byte, int) {
	value, n := consumeRawUvarint(data)
	if n <= 0 {
		return 0, 0, n
	}
	return value >> 3, byte(value & 7), n
}

func consumeRawUvarint(data []byte) (uint64, int) {
	return binary.Uvarint(data)
}

func skipWire(data []byte, wire byte) ([]byte, error) {
	switch wire {
	case 0:
		_, n := binary.Uvarint(data)
		if n <= 0 {
			return nil, errMalformedRemoteWrite
		}
		return data[n:], nil
	case 1:
		if len(data) < 8 {
			return nil, errMalformedRemoteWrite
		}
		return data[8:], nil
	default:
		return nil, errMalformedRemoteWrite
	}
}

var errMalformedRemoteWrite = errors.New("malformed remote write protobuf")
