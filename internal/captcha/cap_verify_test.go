package captcha

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCapVerifierBoundsNetworkCallsAcrossInstances(t *testing.T) {
	const capacity = 32
	entered := make(chan struct{}, capacity+1)
	release := make(chan struct{})
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		entered <- struct{}{}
		select {
		case <-release:
			_, _ = w.Write([]byte(`{"success":true}`))
		case <-r.Context().Done():
		}
	}))
	defer server.Close()
	var pending sync.WaitGroup
	var releaseOnce sync.Once
	finish := func() { releaseOnce.Do(func() { close(release) }); pending.Wait() }
	defer func() {
		finish()
	}()
	for i := 0; i < capacity; i++ {
		verifier, err := NewCapVerifier(server.URL, "secret", 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		pending.Add(1)
		go func() {
			defer pending.Done()
			_, _ = verifier.Verify(context.Background(), "token")
		}()
	}
	for i := 0; i < capacity; i++ {
		select {
		case <-entered:
		case <-time.After(2 * time.Second):
			t.Fatal("admitted verification did not reach provider")
		}
	}
	verifier, err := NewCapVerifier(server.URL, "secret", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	valid, err := verifier.Verify(ctx, "overflow-token")
	if valid || err == nil {
		t.Fatalf("saturated verifier accepted work: valid=%v err=%v", valid, err)
	}
	if got := calls.Load(); got != capacity {
		t.Fatalf("new verifier bypassed shared capacity: provider calls=%d want %d", got, capacity)
	}
	finish()
	if valid, err := verifier.Verify(context.Background(), "after-release"); !valid || err != nil {
		t.Fatalf("successful verifications leaked global capacity: valid=%v err=%v", valid, err)
	}
}

func TestCapVerifierPeerLimitAndCancellationRelease(t *testing.T) {
	const peer = "203.0.113.62"
	entered := make(chan struct{}, 8)
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer server.Close()
	defer close(release)
	verifier, err := NewCapVerifier(server.URL, "secret", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	var pending sync.WaitGroup
	var cancels []context.CancelFunc
	defer func() {
		for _, cancel := range cancels {
			cancel()
		}
		pending.Wait()
	}()
	results := make(chan error, 6)
	start := func(clientIP string) {
		ctx, cancel := context.WithCancel(context.Background())
		cancels = append(cancels, cancel)
		pending.Add(1)
		go func() {
			defer pending.Done()
			_, err := verifier.VerifyForPeer(ctx, "token", clientIP)
			results <- err
		}()
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("admitted peer did not reach provider")
		}
	}
	for i := 0; i < maxCapVerifyPerPeer; i++ {
		if i%2 == 0 {
			start(peer)
		} else {
			start("::ffff:" + peer)
		}
	}
	if valid, err := verifier.VerifyForPeer(context.Background(), "overflow", peer); valid || !errors.Is(err, errCapVerifyBusy) {
		t.Fatalf("same peer exceeded capacity: valid=%v err=%v", valid, err)
	}
	// One client's saturation must not exhaust another client's reservation.
	start("203.0.113.63")
	cancels[0]()
	select {
	case err := <-results:
		if !errors.Is(err, errCapRequest) {
			t.Fatalf("cancelled verification err=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled verification did not unwind")
	}
	start(peer)
}

func TestCapVerifierErrorsReleasePeerCapacity(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"negative decision", http.StatusOK, `{"success":false}`},
		{"provider error", http.StatusBadGateway, "provider detail"},
		{"malformed response", http.StatusOK, `{"success":`},
		{"oversized response", http.StatusOK, strings.Repeat("x", maxCapResponseBytes+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			verifier := newTestCapVerifier(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if calls.Add(1) > maxCapVerifyPerPeer {
					_, _ = w.Write([]byte(`{"success":true}`))
					return
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			for i := 0; i < maxCapVerifyPerPeer; i++ {
				valid, err := verifier.VerifyForPeer(context.Background(), "token", "203.0.113.64")
				if valid || errors.Is(err, errCapVerifyBusy) {
					t.Fatalf("attempt %d failed through leaked capacity: valid=%v err=%v", i, valid, err)
				}
			}
			if valid, err := verifier.VerifyForPeer(context.Background(), "token", "203.0.113.64"); !valid || err != nil {
				t.Fatalf("failed verification leaked capacity: valid=%v err=%v", valid, err)
			}
		})
	}
}

func TestCapVerifierVerifySendsSiteverifyPayload(t *testing.T) {
	const secret = "site-secret"
	const token = "one-use-token"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", r.Method)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", got)
		}
		var got struct {
			Secret   string `json:"secret"`
			Response string `json:"response"`
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("decode request body: %v", err)
		}
		if got.Secret != secret || got.Response != token {
			t.Errorf("payload = %#v, want secret and token", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	defer server.Close()

	verifier, err := NewCapVerifier(server.URL+"/siteverify", secret, time.Second)
	if err != nil {
		t.Fatalf("NewCapVerifier: %v", err)
	}
	valid, err := verifier.Verify(context.Background(), token)
	if err != nil || !valid {
		t.Fatalf("Verify() = (%v, %v), want (true, nil)", valid, err)
	}
}

func TestCapVerifierFalseDecision(t *testing.T) {
	verifier := newTestCapVerifier(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"success":false}`))
	}))
	valid, err := verifier.Verify(context.Background(), "token")
	if err != nil || valid {
		t.Fatalf("Verify() = (%v, %v), want (false, nil)", valid, err)
	}
}

func TestCapVerifierRejectsNon2xx(t *testing.T) {
	verifier := newTestCapVerifier(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "provider detail", http.StatusBadGateway)
	}))
	valid, err := verifier.Verify(context.Background(), "private-token")
	if valid || !errors.Is(err, errCapResponse) {
		t.Fatalf("Verify() = (%v, %v), want response error", valid, err)
	}
	assertDoesNotLeakCredentials(t, err, "private-token", "private-secret", "provider detail")
}

func TestCapVerifierRejectsMalformedAndOversizedResponses(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "invalid json", body: `{"success":`},
		{name: "success is not boolean", body: `{"success":"true"}`},
		{name: "missing success", body: `{}`},
		{name: "null success", body: `{"success":null}`},
		{name: "trailing json", body: `{"success":true} {}`},
		{name: "oversized", body: `{"success":true,"padding":"` + strings.Repeat("x", maxCapResponseBytes) + `"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verifier := newTestCapVerifier(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(tt.body))
			}))
			valid, err := verifier.Verify(context.Background(), "token")
			if valid || !errors.Is(err, errCapResponse) {
				t.Fatalf("Verify() = (%v, %v), want response error", valid, err)
			}
		})
	}
}

func TestCapVerifierDoesNotFollowRedirects(t *testing.T) {
	var targetHits int
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetHits++
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	defer target.Close()

	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", target.URL)
		w.WriteHeader(http.StatusFound)
	}))
	defer redirect.Close()

	verifier, err := NewCapVerifier(redirect.URL, "private-secret", time.Second)
	if err != nil {
		t.Fatalf("NewCapVerifier: %v", err)
	}
	valid, err := verifier.Verify(context.Background(), "private-token")
	if valid || !errors.Is(err, errCapResponse) {
		t.Fatalf("Verify() = (%v, %v), want redirect response error", valid, err)
	}
	if targetHits != 0 {
		t.Fatalf("redirect target received %d requests, want none", targetHits)
	}
	assertDoesNotLeakCredentials(t, err, "private-token", "private-secret")
}

func TestNewCapVerifierEndpointValidation(t *testing.T) {
	tests := []struct {
		endpoint string
		valid    bool
	}{
		{endpoint: "https://cap.example/siteverify", valid: true},
		{endpoint: "http://127.0.0.1:8443/siteverify", valid: true},
		{endpoint: "http://[::1]:8443/siteverify", valid: true},
		{endpoint: "http://localhost:8443/siteverify", valid: true},
		{endpoint: "http://cap.example/siteverify"},
		{endpoint: "https://user:pass@cap.example/siteverify"},
		{endpoint: "https://cap.example/siteverify?secret=x"},
		{endpoint: "https://cap.example/siteverify#"},
		{endpoint: "https://cap.example/siteverify#fragment"},
		{endpoint: "/siteverify"},
		{endpoint: "ftp://127.0.0.1/siteverify"},
	}
	for _, tt := range tests {
		t.Run(tt.endpoint, func(t *testing.T) {
			_, err := NewCapVerifier(tt.endpoint, "secret", time.Second)
			if (err == nil) != tt.valid {
				t.Fatalf("NewCapVerifier() error = %v, valid = %v", err, tt.valid)
			}
		})
	}
}

func TestCapVerifierRejectsInvalidInputs(t *testing.T) {
	if _, err := NewCapVerifier("https://cap.example", " \t", time.Second); !errors.Is(err, errCapInvalidSecret) {
		t.Fatalf("empty secret error = %v", err)
	}
	if _, err := NewCapVerifier("https://cap.example", "secret", 0); !errors.Is(err, errCapInvalidTimeout) {
		t.Fatalf("zero timeout error = %v", err)
	}
	bounded, err := NewCapVerifier("https://cap.example", "secret", time.Hour)
	if err != nil || bounded.client.Timeout != maxCapTimeout {
		t.Fatalf("large timeout = (%v, %v), want capped timeout", bounded, err)
	}
	verifier, err := NewCapVerifier("https://cap.example", "secret", time.Second)
	if err != nil {
		t.Fatalf("NewCapVerifier: %v", err)
	}
	for _, token := range []string{"", " \n", strings.Repeat("x", maxCapTokenBytes+1)} {
		if valid, err := verifier.Verify(context.Background(), token); valid || !errors.Is(err, errCapInvalidToken) {
			t.Fatalf("Verify(token length %d) = (%v, %v), want invalid-token error", len(token), valid, err)
		}
	}
}

func TestNewCapVerifierFromFile(t *testing.T) {
	secretPath := filepath.Join(t.TempDir(), "cap-secret")
	if err := os.WriteFile(secretPath, []byte(" \nfile-secret\t\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	verifier, err := NewCapVerifierFromFile("https://cap.example/siteverify", secretPath, time.Second)
	if err != nil {
		t.Fatalf("NewCapVerifierFromFile: %v", err)
	}
	if verifier.secret != "file-secret" {
		t.Fatalf("loaded secret = %q, want trimmed file secret", verifier.secret)
	}
}

func TestNewCapVerifierFromFileRejectsEmptyMissingAndOversizedWithoutLeaking(t *testing.T) {
	tempDir := t.TempDir()
	emptyPath := filepath.Join(tempDir, "empty")
	if err := os.WriteFile(emptyPath, []byte(" \n\t"), 0o600); err != nil {
		t.Fatal(err)
	}
	oversizedPath := filepath.Join(tempDir, "oversized")
	if err := os.WriteFile(oversizedPath, []byte(strings.Repeat("private-file-secret", 300)), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(tempDir, "missing"), emptyPath, oversizedPath} {
		t.Run(filepath.Base(path), func(t *testing.T) {
			_, err := NewCapVerifierFromFile("https://cap.example/siteverify", path, time.Second)
			if !errors.Is(err, errCapSecretFile) {
				t.Fatalf("NewCapVerifierFromFile() error = %v, want secret-file error", err)
			}
			assertDoesNotLeakCredentials(t, err, path, "private-file-secret")
		})
	}
}

func TestCapVerifierHonorsTimeout(t *testing.T) {
	verifier := newTestCapVerifier(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(100 * time.Millisecond)
		_, _ = w.Write([]byte(`{"success":true}`))
	}), 10*time.Millisecond)
	started := time.Now()
	valid, err := verifier.Verify(context.Background(), "token")
	if valid || !errors.Is(err, errCapRequest) {
		t.Fatalf("Verify() = (%v, %v), want request error", valid, err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("Verify took %s, want bounded timeout", elapsed)
	}
}

func TestCapVerifierHonorsCallerContext(t *testing.T) {
	verifier := newTestCapVerifier(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	valid, err := verifier.Verify(ctx, "token")
	if valid || !errors.Is(err, errCapRequest) {
		t.Fatalf("Verify() = (%v, %v), want request error", valid, err)
	}
}

func newTestCapVerifier(t *testing.T, handler http.Handler, timeouts ...time.Duration) *CapVerifier {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	timeout := time.Second
	if len(timeouts) > 0 {
		timeout = timeouts[0]
	}
	verifier, err := NewCapVerifier(server.URL, "private-secret", timeout)
	if err != nil {
		t.Fatalf("NewCapVerifier: %v", err)
	}
	return verifier
}

func assertDoesNotLeakCredentials(t *testing.T, err error, values ...string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error")
	}
	for _, value := range values {
		if value != "" && strings.Contains(err.Error(), value) {
			t.Errorf("error leaked %q: %v", value, err)
		}
	}
}
