package kms

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPBackendWrapUnwrapAndLifecycleUseBoundReference(t *testing.T) {
	ref := KeyRef{TenantID: "tenant-a", KeyID: "key-a", Version: "v1"}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-only-token" {
			t.Error("missing authentication")
			w.WriteHeader(401)
			return
		}
		if r.URL.Path == "/health" {
			w.WriteHeader(204)
			return
		}
		var input transportRequest
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		if input.Ref != ref {
			t.Errorf("ref=%+v", input.Ref)
		}
		switch r.URL.Path {
		case "/v1/wrap":
			_ = json.NewEncoder(w).Encode(transportResponse{Ref: ref, Ciphertext: append([]byte("wrapped:"), input.Plaintext...)})
		case "/v1/unwrap":
			_ = json.NewEncoder(w).Encode(transportResponse{Ref: ref, Plaintext: append([]byte(nil), input.Ciphertext[len("wrapped:"):]...)})
		case "/v1/rotate", "/v1/revoke":
			w.WriteHeader(204)
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	b, err := NewHTTPBackend(HTTPOptions{Endpoint: server.URL, Client: server.Client(), Token: func(context.Context) (string, error) { return "test-only-token", nil }})
	if err != nil {
		t.Fatal(err)
	}
	if !b.Available(context.Background()) {
		t.Fatal("healthy TLS KMS unavailable")
	}
	plain := bytes.Repeat([]byte{0x31}, 32)
	wrapped, err := b.Wrap(context.Background(), ref, plain)
	if err != nil {
		t.Fatal(err)
	}
	got, err := b.Unwrap(context.Background(), ref, wrapped)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("round trip err=%v", err)
	}
	if err := b.Rotate(context.Background(), ref); err != nil {
		t.Fatal(err)
	}
	if err := b.Revoke(context.Background(), ref); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPBackendRejectsInsecureEndpointRedirectAndSensitiveErrors(t *testing.T) {
	if _, err := NewHTTPBackend(HTTPOptions{Endpoint: "http://kms.example", Token: func(context.Context) (string, error) { return "secret", nil }}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("insecure endpoint=%v", err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://example.com/steal")
		w.WriteHeader(302)
		_, _ = w.Write([]byte("password=secret"))
	}))
	defer server.Close()
	b, err := NewHTTPBackend(HTTPOptions{Endpoint: server.URL, Client: server.Client(), Token: func(context.Context) (string, error) { return "secret", nil }})
	if err != nil {
		t.Fatal(err)
	}
	if b.Available(context.Background()) {
		t.Fatal("redirect accepted as available")
	}
	_, err = b.Wrap(context.Background(), KeyRef{TenantID: "tenant", KeyID: "key", Version: "v1"}, make([]byte, 32))
	if !errors.Is(err, ErrProviderFailure) || bytes.Contains([]byte(err.Error()), []byte("secret")) {
		t.Fatalf("unsafe response err=%v", err)
	}
}
