package assets

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeS3Credential(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "credential.json")
	if err := os.WriteFile(p, []byte(`{"access_key_id":"test-access","secret_access_key":"test-secret","session_token":"test-token"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type countingReadCloser struct {
	reader    io.Reader
	bytesRead int64
}

func (r *countingReadCloser) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.bytesRead += int64(n)
	return n, err
}

func (r *countingReadCloser) Close() error { return nil }

func TestHTTPObjectClientRejectsNonPublicEndpointsByDefault(t *testing.T) {
	credential := writeS3Credential(t)
	for _, endpoint := range []string{"http://127.0.0.1", "http://0.0.0.0", "http://169.254.169.254", "http://10.0.0.1", "http://224.0.0.1", "http://[::1]"} {
		t.Run(endpoint, func(t *testing.T) {
			if _, err := NewHTTPObjectClient(S3Config{Endpoint: endpoint, Region: "us-east-1"}, credential); err == nil {
				t.Fatal("expected endpoint rejection")
			}
		})
	}
}

func TestHTTPObjectClientPrivateEndpointRequiresExplicitOptInAndSignsRequests(t *testing.T) {
	var sawAuth, sawToken bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=test-access/") && strings.Contains(r.Header.Get("Authorization"), "SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token")
		sawToken = r.Header.Get("X-Amz-Security-Token") == "test-token"
		if r.URL.Query().Get("list-type") != "2" || r.URL.Query().Get("prefix") != "captcha/" {
			http.Error(w, "bad list contract", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/xml")
		fmt.Fprint(w, `<ListBucketResult><Contents><Key>captcha/item.json</Key><Size>12</Size><ETag>etag</ETag><LastModified>2026-07-11T00:00:00Z</LastModified></Contents></ListBucketResult>`)
	}))
	defer server.Close()
	credential := writeS3Credential(t)
	if _, err := NewHTTPObjectClient(S3Config{Endpoint: server.URL, Region: "us-east-1", PathStyle: true}, credential); err == nil {
		t.Fatal("private endpoint must be rejected by default")
	}
	client, err := NewHTTPObjectClient(S3Config{Endpoint: server.URL, Region: "us-east-1", PathStyle: true, AllowPrivateEndpoint: true, RequestTimeout: time.Second}, credential)
	if err != nil {
		t.Fatal(err)
	}
	items, err := client.ListObjects(context.Background(), "bucket", "captcha/")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Key != "captcha/item.json" || !sawAuth || !sawToken {
		t.Fatalf("unexpected SigV4/list contract: items=%+v auth=%v token=%v", items, sawAuth, sawToken)
	}
}

func TestHTTPObjectClientListObjectsFollowsContinuationToken(t *testing.T) {
	var continuationTokens []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		continuationTokens = append(continuationTokens, r.URL.Query().Get("continuation-token"))
		w.Header().Set("Content-Type", "application/xml")
		if len(continuationTokens) == 1 {
			fmt.Fprint(w, s3ListResponseXML(1000, true, "page-2"))
			return
		}
		fmt.Fprint(w, s3ListResponseXML(1, false, ""))
	}))
	defer server.Close()

	client, err := NewHTTPObjectClient(S3Config{Endpoint: server.URL, Region: "us-east-1", PathStyle: true, AllowPrivateEndpoint: true}, writeS3Credential(t))
	if err != nil {
		t.Fatal(err)
	}
	items, err := client.ListObjects(context.Background(), "bucket", "captcha/")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1001 {
		t.Fatalf("expected all pages, got %d objects", len(items))
	}
	if got, want := strings.Join(continuationTokens, ","), ",page-2"; got != want {
		t.Fatalf("unexpected continuation tokens: got %q want %q", got, want)
	}
}

func s3ListResponseXML(count int, truncated bool, token string) string {
	var b strings.Builder
	b.WriteString("<ListBucketResult>")
	for i := 0; i < count; i++ {
		fmt.Fprintf(&b, "<Contents><Key>captcha/item-%04d.json</Key></Contents>", i)
	}
	fmt.Fprintf(&b, "<IsTruncated>%t</IsTruncated>", truncated)
	if token != "" {
		fmt.Fprintf(&b, "<NextContinuationToken>%s</NextContinuationToken>", token)
	}
	b.WriteString("</ListBucketResult>")
	return b.String()
}

func TestHTTPObjectClientRejectsInvalidContinuationResponses(t *testing.T) {
	tests := []struct {
		name  string
		pages []struct {
			count     int
			truncated bool
			token     string
		}
		wantError     string
		wantCallCount int
	}{
		{
			name: "truncated without token",
			pages: []struct {
				count     int
				truncated bool
				token     string
			}{{count: 1, truncated: true}},
			wantError:     "truncated without a continuation token",
			wantCallCount: 1,
		},
		{
			name: "truncated with blank token",
			pages: []struct {
				count     int
				truncated bool
				token     string
			}{{count: 1, truncated: true, token: "   "}},
			wantError:     "truncated without a continuation token",
			wantCallCount: 1,
		},
		{
			name: "repeated token",
			pages: []struct {
				count     int
				truncated bool
				token     string
			}{
				{count: 1, truncated: true, token: "page-a"},
				{count: 1, truncated: true, token: "page-a"},
			},
			wantError:     "continuation token repeated",
			wantCallCount: 2,
		},
		{
			name: "token cycle",
			pages: []struct {
				count     int
				truncated bool
				token     string
			}{
				{count: 1, truncated: true, token: "page-a"},
				{count: 1, truncated: true, token: "page-b"},
				{count: 1, truncated: true, token: "page-a"},
			},
			wantError:     "continuation token repeated",
			wantCallCount: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if calls >= len(tt.pages) {
					http.Error(w, "unexpected extra request", http.StatusInternalServerError)
					return
				}
				page := tt.pages[calls]
				calls++
				w.Header().Set("Content-Type", "application/xml")
				fmt.Fprint(w, s3ListResponseXML(page.count, page.truncated, page.token))
			}))
			defer server.Close()

			client, err := NewHTTPObjectClient(S3Config{Endpoint: server.URL, Region: "us-east-1", PathStyle: true, AllowPrivateEndpoint: true}, writeS3Credential(t))
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.ListObjects(context.Background(), "bucket", "captcha/")
			if err == nil || !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("expected %q, got %v", tt.wantError, err)
			}
			if calls != tt.wantCallCount {
				t.Fatalf("unexpected request count: got %d want %d", calls, tt.wantCallCount)
			}
		})
	}
}

func TestHTTPObjectClientRejectsListPageLimit(t *testing.T) {
	const wantPageLimit = 100
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls > wantPageLimit {
			http.Error(w, "unexpected request beyond page limit", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/xml")
		fmt.Fprint(w, s3ListResponseXML(1, true, fmt.Sprintf("page-%d", calls+1)))
	}))
	defer server.Close()

	client, err := NewHTTPObjectClient(S3Config{Endpoint: server.URL, Region: "us-east-1", PathStyle: true, AllowPrivateEndpoint: true}, writeS3Credential(t))
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.ListObjects(context.Background(), "bucket", "captcha/")
	if err == nil || !strings.Contains(err.Error(), "page limit") {
		t.Fatalf("expected page limit error, got %v", err)
	}
	if calls != wantPageLimit {
		t.Fatalf("unexpected request count: got %d want %d", calls, wantPageLimit)
	}
}

func TestHTTPObjectClientRejectsCumulativeObjectLimit(t *testing.T) {
	const wantObjectLimit = 10_000
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		count := 1000
		truncated := true
		token := fmt.Sprintf("page-%d", calls+1)
		if calls == wantObjectLimit/1000+1 {
			count = 1
			truncated = false
			token = ""
		}
		w.Header().Set("Content-Type", "application/xml")
		fmt.Fprint(w, s3ListResponseXML(count, truncated, token))
	}))
	defer server.Close()

	client, err := NewHTTPObjectClient(S3Config{Endpoint: server.URL, Region: "us-east-1", PathStyle: true, AllowPrivateEndpoint: true}, writeS3Credential(t))
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.ListObjects(context.Background(), "bucket", "captcha/")
	if err == nil || !strings.Contains(err.Error(), "object limit") {
		t.Fatalf("expected object limit error, got %v", err)
	}
	if calls != wantObjectLimit/1000+1 {
		t.Fatalf("unexpected request count: got %d", calls)
	}
}

func TestHTTPObjectClientRejectsCumulativeListResponseBytes(t *testing.T) {
	const wantResponseByteLimit = 8 << 20
	firstPage := s3ListResponseXMLWithPadding(wantResponseByteLimit/2, true, "page-2")
	secondPage := s3ListResponseXMLWithPadding(wantResponseByteLimit/2, false, "")
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/xml")
		if calls == 1 {
			fmt.Fprint(w, firstPage)
			return
		}
		fmt.Fprint(w, secondPage)
	}))
	defer server.Close()

	client, err := NewHTTPObjectClient(S3Config{Endpoint: server.URL, Region: "us-east-1", PathStyle: true, AllowPrivateEndpoint: true}, writeS3Credential(t))
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.ListObjects(context.Background(), "bucket", "captcha/")
	if err == nil || !strings.Contains(err.Error(), "cumulative response byte limit") {
		t.Fatalf("expected cumulative response byte limit error, got %v", err)
	}
	if calls != 2 {
		t.Fatalf("unexpected request count: got %d want 2", calls)
	}
}

func TestHTTPObjectClientBoundsCumulativeResponseBytesWhileReading(t *testing.T) {
	firstPage := s3ListResponseXMLWithPadding(maxS3ListCumulativeResponseBytes-(4<<10), true, "page-2")
	secondPage := s3ListResponseXMLWithPadding(1<<20, false, "")
	remaining := int64(maxS3ListCumulativeResponseBytes - len(firstPage))
	if remaining <= 0 {
		t.Fatalf("first page leaves no cumulative response budget: size=%d", len(firstPage))
	}

	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()
	client, err := NewHTTPObjectClient(S3Config{Endpoint: server.URL, Region: "us-east-1", PathStyle: true, AllowPrivateEndpoint: true}, writeS3Credential(t))
	if err != nil {
		t.Fatal(err)
	}

	var secondBody *countingReadCloser
	calls := 0
	client.client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		var body io.ReadCloser = io.NopCloser(strings.NewReader(firstPage))
		if calls == 2 {
			secondBody = &countingReadCloser{reader: strings.NewReader(secondPage)}
			body = secondBody
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: body, Request: req}, nil
	})

	_, err = client.ListObjects(context.Background(), "bucket", "captcha/")
	if err == nil || !strings.Contains(err.Error(), "cumulative response byte limit") {
		t.Fatalf("expected cumulative response byte limit error, got %v", err)
	}
	if calls != 2 || secondBody == nil {
		t.Fatalf("unexpected page requests: calls=%d second_body=%v", calls, secondBody)
	}
	if secondBody.bytesRead > remaining+1 {
		t.Fatalf("second page read %d bytes with %d bytes remaining in cumulative budget", secondBody.bytesRead, remaining)
	}
}

func TestHTTPObjectClientListObjectsPropagatesCancellationBetweenPages(t *testing.T) {
	secondRequestStarted := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("continuation-token") == "" {
			w.Header().Set("Content-Type", "application/xml")
			fmt.Fprint(w, s3ListResponseXML(1, true, "page-2"))
			return
		}
		close(secondRequestStarted)
		<-r.Context().Done()
	}))
	defer server.Close()

	client, err := NewHTTPObjectClient(S3Config{Endpoint: server.URL, Region: "us-east-1", PathStyle: true, AllowPrivateEndpoint: true}, writeS3Credential(t))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		_, listErr := client.ListObjects(ctx, "bucket", "captcha/")
		errCh <- listErr
	}()
	<-secondRequestStarted
	cancel()

	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context cancellation, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("ListObjects did not return after cancellation")
	}
}

func s3ListResponseXMLWithPadding(padding int, truncated bool, token string) string {
	response := s3ListResponseXML(1, truncated, token)
	return strings.Replace(response, "</ListBucketResult>", "<Padding>"+strings.Repeat("x", padding)+"</Padding></ListBucketResult>", 1)
}

func TestHTTPObjectClientLimitsListResponseAndClosesErrorBodies(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = io.CopyN(w, strings.NewReader(strings.Repeat("x", 8192)), 8192)
	}))
	defer server.Close()
	client, err := NewHTTPObjectClient(S3Config{Endpoint: server.URL, Region: "us-east-1", PathStyle: true, AllowPrivateEndpoint: true}, writeS3Credential(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.ListObjects(context.Background(), "bucket", ""); err == nil || !strings.Contains(err.Error(), "status 502") {
		t.Fatalf("expected bounded status error, got %v", err)
	}
}
