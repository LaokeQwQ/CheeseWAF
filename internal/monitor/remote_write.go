package monitor

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/netguard"
	"github.com/golang/snappy"
)

type RemoteWriter struct {
	cfg    config.RemoteWriteConfig
	client *http.Client
}

func NewRemoteWriter(cfg config.RemoteWriteConfig, client *http.Client) *RemoteWriter {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if client == nil {
		client = netguard.NewHTTPClient(netguard.HTTPClientOptions{
			Timeout: cfg.Timeout,
			Policy:  remoteWriteURLPolicy(cfg.AllowPrivateEndpoint),
		})
	}
	return &RemoteWriter{cfg: cfg, client: client}
}

func (w *RemoteWriter) Push(ctx context.Context, snapshot Snapshot) error {
	if w == nil || !w.cfg.Enabled {
		return nil
	}
	if w.cfg.Endpoint == "" {
		return fmt.Errorf("remote_write endpoint is required")
	}
	body := encodeRemoteWrite(snapshot)
	compressed := snappy.Encode(nil, body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.cfg.Endpoint, bytes.NewReader(compressed))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-protobuf")
	req.Header.Set("Content-Encoding", "snappy")
	req.Header.Set("X-Prometheus-Remote-Write-Version", "0.1.0")
	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	defer netguard.DrainAndClose(resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("remote_write returned %s", resp.Status)
	}
	return nil
}

type remoteWriteLabel struct {
	name  string
	value string
}

func encodeRemoteWrite(snapshot Snapshot) []byte {
	// Keep the wire encoder local so remote_write does not depend on the much
	// larger Prometheus client registry; this is the standard WriteRequest
	// schema used by Prometheus and VictoriaMetrics remote-write endpoints.
	values := Values(snapshot)
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	timestamp := snapshot.GeneratedAt
	if timestamp.IsZero() {
		timestamp = time.Now().UTC()
	}
	timestampMillis := timestamp.UnixMilli()

	var request []byte
	for _, encodedName := range names {
		name, labelValue, _ := strings.Cut(encodedName, ":")
		labels := []remoteWriteLabel{{name: "__name__", value: name}}
		if labelValue != "" {
			labels = append(labels, remoteWriteLabel{name: "area", value: labelValue})
		}
		sort.Slice(labels, func(i, j int) bool { return labels[i].name < labels[j].name })

		var series []byte
		for _, label := range labels {
			var encodedLabel []byte
			encodedLabel = appendStringField(encodedLabel, 1, label.name)
			encodedLabel = appendStringField(encodedLabel, 2, label.value)
			series = appendMessageField(series, 1, encodedLabel)
		}
		var sample []byte
		sample = appendFixed64Field(sample, 1, values[encodedName])
		sample = appendInt64Field(sample, 2, timestampMillis)
		series = appendMessageField(series, 2, sample)
		request = appendMessageField(request, 1, series)
	}
	return request
}

func appendMessageField(dst []byte, field int, message []byte) []byte {
	dst = appendTag(dst, field, 2)
	dst = appendUvarint(dst, uint64(len(message)))
	return append(dst, message...)
}

func appendStringField(dst []byte, field int, value string) []byte {
	return appendMessageField(dst, field, []byte(value))
}

func appendFixed64Field(dst []byte, field int, value float64) []byte {
	dst = appendTag(dst, field, 1)
	var encoded [8]byte
	binary.LittleEndian.PutUint64(encoded[:], math.Float64bits(value))
	return append(dst, encoded[:]...)
}

func appendInt64Field(dst []byte, field int, value int64) []byte {
	dst = appendTag(dst, field, 0)
	return appendUvarint(dst, uint64(value))
}

func appendTag(dst []byte, field, wireType int) []byte {
	return appendUvarint(dst, uint64(field<<3|wireType))
}

func appendUvarint(dst []byte, value uint64) []byte {
	var encoded [10]byte
	n := binary.PutUvarint(encoded[:], value)
	return append(dst, encoded[:n]...)
}

func remoteWriteURLPolicy(allowPrivate bool) netguard.URLPolicy {
	return netguard.URLPolicy{
		Purpose:        "remote_write",
		HostPurpose:    "remote_write endpoint",
		AllowedSchemes: []string{"http", "https"},
		AllowPrivate:   allowPrivate,
	}
}
