package response

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/protection/tamper"
)

func TestLargeResponseLimitStillInspectsSmallSensitiveBody(t *testing.T) {
	for _, limit := range []int64{16 << 20, 64 << 20, 1 << 30} {
		inspector, err := New(config.ResponseInspectionConfig{Enabled: true, MaxBodyBytes: limit, SensitivePatterns: []string{"secret-token"}})
		if err != nil {
			t.Fatal(err)
		}
		for _, compressed := range []bool{false, true} {
			body := []byte("secret-token")
			header := make(http.Header)
			if compressed {
				var encoded bytes.Buffer
				writer := gzip.NewWriter(&encoded)
				_, _ = writer.Write(body)
				_ = writer.Close()
				body = encoded.Bytes()
				header.Set("Content-Encoding", "gzip")
			}
			resp := &http.Response{Header: header, Body: io.NopCloser(bytes.NewReader(body))}
			finding, err := inspector.InspectHTTP(resp)
			if err != nil || finding == nil || finding.Pattern != "secret-token" || finding.Reason != "" {
				t.Fatalf("limit=%d gzip=%t: small response skipped: finding=%+v err=%v", limit, compressed, finding, err)
			}
			replayed, err := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if err != nil || !bytes.Equal(replayed, body) {
				t.Fatalf("limit=%d gzip=%t: wire response changed", limit, compressed)
			}
		}
	}
}

func TestLargeResponseLimitStillVerifiesSmallTamperTarget(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	snapshot, err := tamper.Capture(key, "/asset.js", []byte("clean"), time.Unix(100, 0))
	if err != nil {
		t.Fatal(err)
	}
	inspector, err := New(config.ResponseInspectionConfig{
		Enabled: true, MaxBodyBytes: 1 << 30, TamperKey: string(key),
		TamperSnapshots: []config.TamperSnapshotConfig{{URL: snapshot.URL, MAC: snapshot.MAC, Size: snapshot.Size}},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp := &http.Response{Header: make(http.Header), Body: io.NopCloser(strings.NewReader("evil!"))}
	finding, err := inspector.InspectHTTPForRequest(resp, mustResponseRequest(t, http.MethodGet, "https://example.test/asset.js"))
	if err != nil || finding == nil || finding.DetectorID != "protection.tamper" || finding.Severity != "critical" {
		t.Fatalf("small tamper target skipped: finding=%+v err=%v", finding, err)
	}
	_ = resp.Body.Close()
}

func TestResponseInspectionMemoryExhaustionPreservesBodyAndReleasesReservation(t *testing.T) {
	before := inspectionMemory.Load()
	reserved := int64(maxInspectionMemory - (64 << 10))
	inspectionMemory.Add(reserved)
	defer inspectionMemory.Add(-reserved)
	body := strings.Repeat("x", 100<<10)
	reader := strings.NewReader(body)
	original := &trackingReadCloser{Reader: reader}
	inspector, err := New(config.ResponseInspectionConfig{Enabled: true, MaxBodyBytes: 1 << 30})
	if err != nil {
		t.Fatal(err)
	}
	resp := &http.Response{Header: make(http.Header), Body: original}
	finding, err := inspector.InspectHTTP(resp)
	if err != nil || finding == nil || finding.Reason != "memory_budget" {
		t.Fatalf("memory exhaustion got finding=%+v err=%v", finding, err)
	}
	if got := inspectionMemory.Load(); got != before+reserved {
		t.Fatalf("inspection leaked memory reservation: got %d want %d", got, before+reserved)
	}
	if reader.Len() <= 0 || reader.Len() >= len(body) {
		t.Fatal("test did not exhaust memory after capturing a partial response")
	}
	replayed, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil || string(replayed) != body || !original.closed {
		t.Fatalf("memory exhaustion changed response: bytes=%d closed=%t err=%v", len(replayed), original.closed, err)
	}
}

func TestCompressedResponseMemoryExhaustionPreservesWireBody(t *testing.T) {
	before := inspectionMemory.Load()
	reserved := int64(maxInspectionMemory - (48 << 10))
	inspectionMemory.Add(reserved)
	defer inspectionMemory.Add(-reserved)
	seed := make([]byte, 8192)
	x := uint32(1)
	for index := range seed {
		x = x*1664525 + 1013904223
		seed[index] = byte(x >> 24)
	}
	var encoded bytes.Buffer
	writer := gzip.NewWriter(&encoded)
	_, _ = writer.Write(bytes.Repeat(seed, 8))
	_ = writer.Close()
	inspector, _ := New(config.ResponseInspectionConfig{Enabled: true, MaxBodyBytes: 1 << 30})
	resp := &http.Response{Header: http.Header{"Content-Encoding": {"gzip"}}, Body: io.NopCloser(bytes.NewReader(encoded.Bytes()))}
	finding, err := inspector.InspectHTTP(resp)
	if err != nil || finding == nil || finding.Reason != "memory_budget" {
		t.Fatalf("decoded allocation did not share the memory pool: finding=%+v err=%v", finding, err)
	}
	if got := inspectionMemory.Load(); got != before+reserved {
		t.Fatalf("decoded allocation leaked reservation: got %d want %d", got, before+reserved)
	}
	replayed, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil || !bytes.Equal(replayed, encoded.Bytes()) {
		t.Fatal("decoded memory exhaustion changed wire body")
	}
}

func TestMemoryExhaustedTamperTargetIsUnverifiableWithoutReadingBody(t *testing.T) {
	before := inspectionMemory.Load()
	inspectionMemory.Add(maxInspectionMemory)
	defer inspectionMemory.Add(-maxInspectionMemory)
	key := []byte("01234567890123456789012345678901")
	snapshot, _ := tamper.Capture(key, "/asset.js", []byte("clean"), time.Unix(100, 0))
	inspector, err := New(config.ResponseInspectionConfig{
		Enabled: true, MaxBodyBytes: 1 << 30, TamperKey: string(key),
		TamperSnapshots: []config.TamperSnapshotConfig{{URL: snapshot.URL, MAC: snapshot.MAC, Size: snapshot.Size}},
	})
	if err != nil {
		t.Fatal(err)
	}
	body := &countingResponseBody{Reader: strings.NewReader("evil!")}
	resp := &http.Response{Header: make(http.Header), Body: body}
	finding, err := inspector.InspectHTTPForRequest(resp, mustResponseRequest(t, http.MethodGet, "https://example.test/asset.js"))
	if err != nil || finding == nil || finding.DetectorID != "protection.tamper" || finding.Reason != "memory_budget" || body.reads != 0 {
		t.Fatalf("unverifiable tamper target: finding=%+v reads=%d err=%v", finding, body.reads, err)
	}
	if inspectionMemory.Load() != before+maxInspectionMemory {
		t.Fatal("failed admission changed the memory accounting")
	}
	replayed, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil || string(replayed) != "evil!" {
		t.Fatal("unverifiable tamper body was not preserved")
	}
}

type countingResponseBody struct {
	io.Reader
	reads int
}

func (r *countingResponseBody) Read(p []byte) (int, error) { r.reads++; return r.Reader.Read(p) }
func (*countingResponseBody) Close() error                 { return nil }

type noProgressResponseBody struct{ reads int }

func (r *noProgressResponseBody) Read([]byte) (int, error) {
	r.reads++
	if r.reads > 100 {
		return 0, errors.New("reader was retried without a progress bound")
	}
	return 0, nil
}
func (*noProgressResponseBody) Close() error { return nil }

func TestResponseInspectionBoundsConsecutiveEmptyReads(t *testing.T) {
	before := inspectionMemory.Load()
	inspector, _ := New(config.ResponseInspectionConfig{Enabled: true, MaxBodyBytes: 1 << 30})
	body := &noProgressResponseBody{}
	resp := &http.Response{Header: make(http.Header), Body: body}
	finding, err := inspector.InspectHTTP(resp)
	if finding != nil || !errors.Is(err, io.ErrNoProgress) || body.reads != 100 {
		t.Fatalf("empty read loop was not bounded: finding=%+v err=%v reads=%d", finding, err, body.reads)
	}
	if inspectionMemory.Load() != before {
		t.Fatal("failed body read leaked its memory reservation")
	}
}
