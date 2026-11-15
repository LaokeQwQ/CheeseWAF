package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
	"github.com/LaokeQwQ/CheeseWAF/internal/proxytrust"
)

// CHE-60: proxy forwarding-identity and response-trailer boundaries.
//
// These tests pin the trust boundary between client-supplied headers and the
// identity the proxy rebuilds upstream, plus the trailer surface the proxy
// exposes to clients. A failure here is a smuggling or spoofing defect, not a
// detector miss.

// TestCHE60ForwardedIdentityHeaderAliasBecomesPeerIP proves underscore and
// case variants of forwarding headers cannot smuggle a spoofed identity
// upstream: every stripped alias either disappears or is rebuilt from the
// socket peer, but never carries the client-supplied value onward.
func TestCHE60ForwardedIdentityHeaderAliasBecomesPeerIP(t *testing.T) {
	aliases := []string{
		"X_Forwarded_For",
		"x_forwarded_proto",
		"X-Forwarded-for",
		"x-FORWARDED-host",
		"FORWARDED",
		"forwarded",
	}
	received := make(chan http.Header, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.Header.Clone()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL)
	proxy := NewReverseProxy(target, time.Second)

	req := httptest.NewRequest(http.MethodGet, "http://app.example.test/path", nil)
	req.RemoteAddr = "192.0.2.10:1234"
	for _, alias := range aliases {
		req.Header[alias] = []string{"203.0.113.99"}
	}
	proxy.ServeHTTP(httptest.NewRecorder(), req)

	got := <-received
	for key, values := range got {
		normalized := strings.ToLower(strings.ReplaceAll(key, "_", "-"))
		isForwardingHeader := normalized == "x-forwarded-for" || normalized == "forwarded" ||
			normalized == "x-forwarded-host" || normalized == "x-forwarded-proto"
		if !isForwardingHeader {
			continue
		}
		for _, v := range values {
			if v == "203.0.113.99" {
				t.Fatalf("alias %q smuggled the spoofed identity upstream as %q", key, v)
			}
		}
	}
	if v := got.Get("X-Forwarded-For"); v != "192.0.2.10" {
		t.Fatalf("X-Forwarded-For = %q, want socket peer 192.0.2.10", v)
	}
}

// TestCHE60ForwardedIdentityChainedForHeaderIsReplacedNotAppended proves the
// proxy replaces any client-supplied chain with the single validated peer.
// Appending would let a client inject arbitrary chain positions that upstream
// middlewares may trust.
func TestCHE60ForwardedIdentityChainedForHeaderIsReplacedNotAppended(t *testing.T) {
	received := make(chan http.Header, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.Header.Clone()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL)
	proxy := NewReverseProxy(target, time.Second)

	req := httptest.NewRequest(http.MethodGet, "http://app.example.test/path", nil)
	req.RemoteAddr = "192.0.2.10:1234"
	req.Header.Set("X-Forwarded-For", "198.51.100.1, 203.0.113.99")
	proxy.ServeHTTP(httptest.NewRecorder(), req)

	got := <-received
	values := got.Values("X-Forwarded-For")
	if len(values) != 1 || values[0] != "192.0.2.10" {
		t.Fatalf("X-Forwarded-For = %v, want exactly one rebuilt value [192.0.2.10]", values)
	}
}

// TestCHE60ForwardedIdentityProviderHeaderSpoofNeverSurvives proves every
// provider identity header the trust policy knows about is dropped, and the
// rebuilt identity carries only the socket peer, never the spoofed value.
func TestCHE60ForwardedIdentityProviderHeaderSpoofNeverSurvives(t *testing.T) {
	received := make(chan http.Header, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.Header.Clone()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL)
	proxy := NewReverseProxy(target, time.Second)

	spoofedValue := "203.0.113.99"
	req := httptest.NewRequest(http.MethodGet, "http://app.example.test/path", nil)
	req.RemoteAddr = "192.0.2.10:1234"
	for _, name := range append([]string{"Cf-Connecting-Ip", "True-Client-Ip", "X-Real-Ip"}, proxytrust.ProviderIdentityHeaders()...) {
		req.Header[name] = []string{spoofedValue}
	}
	proxy.ServeHTTP(httptest.NewRecorder(), req)

	got := <-received
	for _, name := range proxytrust.ProviderIdentityHeaders() {
		for key, values := range got {
			if strings.EqualFold(key, name) {
				for _, v := range values {
					if v == spoofedValue {
						t.Fatalf("spoofed provider header %s leaked upstream as %q", name, v)
					}
				}
			}
		}
	}
	// X-Real-IP is rebuilt from the socket peer, which is the documented
	// replacement behavior, and must never carry the spoofed value.
	if v := got.Get("X-Real-IP"); v != "192.0.2.10" {
		t.Fatalf("X-Real-IP = %q, want socket peer rebuild", v)
	}
}

// TestCHE60TrailerPreReadDeclarationKeepsAllowedNilEntries models the state
// net/http produces before the body is read: declared trailers appear in the
// Trailer map with nil values. The pre-read sanitize must keep allowed
// declarations and drop non-allowed ones, recording both in metadata.
func TestCHE60TrailerPreReadDeclarationKeepsAllowedNilEntries(t *testing.T) {
	reqCtx := &engine.RequestContext{Metadata: make(map[string]any)}
	resp := &http.Response{
		Header: http.Header{"Trailer": []string{"Grpc-Status, X-Should-Drop"}},
		Trailer: http.Header{
			"Grpc-Status":   nil,
			"X-Should-Drop": nil,
		},
		Body: io.NopCloser(strings.NewReader("")),
	}
	sanitizeResponseTrailerState(resp, true, reqCtx)
	if v := resp.Header.Get("Trailer"); v != "Grpc-Status" {
		t.Fatalf("Trailer declaration = %q, want only Grpc-Status", v)
	}
	if v := resp.Trailer.Get("X-Should-Drop"); v != "" {
		t.Fatalf("non-allowed trailer X-Should-Drop survived: %q", v)
	}
	if observed := reqCtx.Metadata["upstream_trailers"]; !strings.Contains(strings.Join(stringSlice(observed), ","), "Grpc-Status") {
		t.Fatalf("metadata upstream_trailers = %#v, want Grpc-Status observed", observed)
	}
	if dropped := reqCtx.Metadata["upstream_trailers_dropped"]; !strings.Contains(strings.Join(stringSlice(dropped), ","), "X-Should-Drop") {
		t.Fatalf("metadata upstream_trailers_dropped = %#v, want X-Should-Drop recorded", dropped)
	}
}

func stringSlice(v any) []string {
	switch values := v.(type) {
	case []string:
		return values
	case string:
		return []string{values}
	}
	return nil
}

// TestCHE60TrailerDeclarationDeduplicatesCanonicalNames covers repeated and
// whitespace-padded declarations from a hostile upstream: the rebuilt
// declaration is a sorted, deduplicated canonical list.
func TestCHE60TrailerDeclarationDeduplicatesCanonicalNames(t *testing.T) {
	resp := &http.Response{
		Header: http.Header{"Trailer": []string{
			" Grpc-Status , grpc-status ,\tGrpc-Message,",
		}},
		Trailer: http.Header{
			"Grpc-Status":  nil,
			"grpc-message": nil,
		},
		Body: io.NopCloser(strings.NewReader("")),
	}
	sanitizeResponseTrailerState(resp, true, nil)
	if v := resp.Header.Get("Trailer"); v != "Grpc-Message, Grpc-Status" {
		t.Fatalf("Trailer declaration = %q, want deduplicated canonical list", v)
	}
}

// TestCHE60TrailerNonGRPCStripsEverythingIncludingDeclaration proves a
// non-gRPC response loses both trailer values and the declaration header.
func TestCHE60TrailerNonGRPCStripsEverythingIncludingDeclaration(t *testing.T) {
	reqCtx := &engine.RequestContext{Metadata: make(map[string]any)}
	resp := &http.Response{
		Header:  http.Header{"Trailer": []string{"X-Attack, X-Other"}},
		Trailer: http.Header{"X-Attack": {"payload"}, "X-Other": nil},
		Body:    io.NopCloser(strings.NewReader("body")),
	}
	sanitizeResponseTrailerState(resp, false, reqCtx)
	if len(resp.Trailer) != 0 || resp.Header.Get("Trailer") != "" {
		t.Fatalf("non-gRPC trailers survived: header=%#v trailer=%#v", resp.Header, resp.Trailer)
	}
	if dropped := reqCtx.Metadata["upstream_trailers_dropped"]; !strings.Contains(strings.Join(stringSlice(dropped), ","), "X-Attack") {
		t.Fatalf("metadata upstream_trailers_dropped = %#v, want X-Attack recorded", dropped)
	}
}

// TestCHE60TrailerBodyFinalizeIsOnceAndIdempotent proves the wrapping trailer
// body sanitizes exactly once regardless of how many reads/Close calls occur,
// and that a second wrap is refused.
func TestCHE60TrailerBodyFinalizeIsOnceAndIdempotent(t *testing.T) {
	resp := &http.Response{
		Header:  http.Header{"Trailer": []string{"X-Evil, Grpc-Status"}},
		Trailer: http.Header{"X-Evil": {"1"}, "Grpc-Status": {"0"}},
		Body:    io.NopCloser(strings.NewReader("body")),
	}
	prepareUpstreamResponseTrailers(resp, true, nil)

	buf := make([]byte, 4)
	if _, err := io.ReadFull(resp.Body, buf); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := resp.Body.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if v := resp.Trailer.Get("X-Evil"); v != "" {
		t.Fatalf("non-allowed trailer X-Evil survived: %q", v)
	}
	if v := resp.Trailer.Get("Grpc-Status"); v != "0" {
		t.Fatalf("Grpc-Status trailer = %q, want 0", v)
	}

	prepareUpstreamResponseTrailers(resp, true, nil)
	wrapped, ok := resp.Body.(*responseTrailerBody)
	if !ok {
		t.Fatal("prepareUpstreamResponseTrailers must not double-wrap the body")
	}
	for i := 0; i < 2; i++ {
		if err := wrapped.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if v := resp.Trailer.Get("Grpc-Status"); v != "0" {
		t.Fatalf("Grpc-Status trailer = %q after repeated Close, want 0", v)
	}
}
