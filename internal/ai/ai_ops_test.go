package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

func TestOpenAICompatibleDiscoveryUsesConfiguredPathsAndParsesBalance(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/gateway/models":
			if got := r.Header.Get("Authorization"); got != "Bearer secret" {
				t.Fatalf("authorization = %q", got)
			}
			_, _ = fmt.Fprint(w, `{"data":[{"id":"actual-model","owned_by":"gateway"},{"id":"actual-model"}]}`)
		case "/gateway/quota":
			_, _ = fmt.Fprint(w, `{"data":{"balance":12.5,"currency":"USD","used":2.5}}`)
		case "/gateway/usage":
			_, _ = fmt.Fprint(w, `{"usage":{"total_tokens":321,"requests":7}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cfg := config.AIConfig{
		Enabled: true, Provider: "openai", APIBase: server.URL, APIKey: "secret", Model: "actual-model", AllowPrivateAPIBase: true,
		ModelListPath: "/gateway/models", BalancePath: "/gateway/quota", UsagePath: "/gateway/usage",
	}
	client := NewClient(cfg, server.Client())
	discovery, err := client.DiscoverModels(context.Background())
	if err != nil {
		t.Fatalf("discover models: %v", err)
	}
	if discovery.Status != ModelDiscoveryAvailable || len(discovery.Models) != 1 || discovery.Models[0].ID != "actual-model" {
		t.Fatalf("unexpected discovery: %+v", discovery)
	}
	balance, err := client.FetchBalance(context.Background())
	if err != nil {
		t.Fatalf("fetch balance: %v", err)
	}
	if balance.Available != 12.5 || balance.Used != 2.5 || balance.Currency != "USD" {
		t.Fatalf("unexpected balance: %+v", balance)
	}
	usage, err := client.FetchProviderUsage(context.Background())
	if err != nil {
		t.Fatalf("fetch usage: %v", err)
	}
	if usage.TotalTokens != 321 || usage.CallCount != 7 {
		t.Fatalf("unexpected provider usage: %+v", usage)
	}
}

func TestProviderJSONEndpointRetries429WithBoundedRetryAfter(t *testing.T) {
	requests := 0
	client := NewClient(config.AIConfig{Enabled: true, Provider: "openai", APIBase: "https://provider.example/v1", APIKey: "secret", Model: "model", ModelListPath: "models"}, &http.Client{Transport: aiRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		requests++
		if requests == 1 {
			resp := jsonResponse(http.StatusTooManyRequests, `{"error":{"message":"busy"}}`)
			resp.Header.Set("Retry-After", "0")
			return resp, nil
		}
		return jsonResponse(http.StatusOK, `{"data":[{"id":"recovered"}]}`), nil
	})})
	discovery, err := client.DiscoverModels(context.Background())
	if err != nil || discovery.Status != ModelDiscoveryAvailable || len(discovery.Models) != 1 || requests != 2 {
		t.Fatalf("429 retry failed: discovery=%+v err=%v requests=%d", discovery, err, requests)
	}
}

func TestProviderMetadataRetries503OnlyOnceAndClosesBodies(t *testing.T) {
	requests := 0
	closed := 0
	client := NewClient(config.AIConfig{Enabled: true, Provider: "openai", APIBase: "https://provider.example/v1", APIKey: "secret", Model: "model", ModelListPath: "models"}, &http.Client{Transport: aiRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodGet {
			t.Fatalf("method = %s, want GET", req.Method)
		}
		requests++
		if requests == 1 {
			return responseWithClose(http.StatusServiceUnavailable, `{"error":{"message":"busy"}}`, &closed), nil
		}
		return responseWithClose(http.StatusOK, `{"data":[{"id":"recovered"}]}`, &closed), nil
	})})
	discovery, err := client.DiscoverModels(context.Background())
	if err != nil || discovery.Status != ModelDiscoveryAvailable || len(discovery.Models) != 1 || requests != 2 || closed != 2 {
		t.Fatalf("503 retry failed: discovery=%+v err=%v requests=%d closed=%d", discovery, err, requests, closed)
	}
}

func TestProviderJSONEndpointRetries503OnlyOnce(t *testing.T) {
	requests := 0
	client := NewClient(config.AIConfig{Enabled: true, Provider: "openai", APIBase: "https://provider.example/v1", APIKey: "secret", Model: "model", BalancePath: "quota"}, &http.Client{Transport: aiRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		requests++
		if req.Method != http.MethodGet {
			t.Fatalf("method = %s, want GET", req.Method)
		}
		if requests == 1 {
			return jsonResponse(http.StatusServiceUnavailable, `{"error":{}}`), nil
		}
		return jsonResponse(http.StatusOK, `{"data":{"balance":4}}`), nil
	})})
	balance, err := client.FetchBalance(context.Background())
	if err != nil || balance.Available != 4 || requests != 2 {
		t.Fatalf("503 JSON retry failed: balance=%+v err=%v requests=%d", balance, err, requests)
	}
}

func TestProviderMetadataRetryAfterBoundsAndCancellation(t *testing.T) {
	for _, raw := range []string{"-1", "999999999999999999999999"} {
		t.Run(raw, func(t *testing.T) {
			requests := 0
			client := NewClient(config.AIConfig{Enabled: true, Provider: "openai", APIBase: "https://provider.example/v1", APIKey: "secret", Model: "model", ModelListPath: "models"}, &http.Client{Transport: aiRoundTripFunc(func(*http.Request) (*http.Response, error) {
				requests++
				if requests == 1 {
					resp := responseWithClose(http.StatusServiceUnavailable, `{"error":{}}`, new(int))
					resp.Header.Set("Retry-After", raw)
					return resp, nil
				}
				return jsonResponse(http.StatusOK, `{"data":[{"id":"recovered"}]}`), nil
			})})
			start := time.Now()
			_, err := client.DiscoverModels(context.Background())
			if err != nil || requests != 2 || time.Since(start) > 500*time.Millisecond {
				t.Fatalf("Retry-After %q not bounded: err=%v requests=%d elapsed=%s", raw, err, requests, time.Since(start))
			}
		})
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	requests := 0
	client := NewClient(config.AIConfig{Enabled: true, Provider: "openai", APIBase: "https://provider.example/v1", APIKey: "secret", Model: "model", ModelListPath: "models"}, &http.Client{Transport: aiRoundTripFunc(func(*http.Request) (*http.Response, error) {
		requests++
		resp := responseWithClose(http.StatusServiceUnavailable, `{"error":{}}`, new(int))
		resp.Header.Set("Retry-After", "2")
		cancel()
		return resp, nil
	})})
	_, err := client.DiscoverModels(ctx)
	if !errors.Is(err, context.Canceled) || requests != 1 {
		t.Fatalf("cancellation did not stop retry: err=%v requests=%d", err, requests)
	}
}

func TestAnthropicDiscoveryIsExplicitlyUnsupportedWithoutCatalog(t *testing.T) {
	client := NewClient(config.AIConfig{
		Enabled: true, Provider: "anthropic", APIBase: "https://example.invalid/v1", APIKey: "secret", Model: "claude-test",
	}, nil)
	discovery, err := client.DiscoverModels(context.Background())
	if err != nil {
		t.Fatalf("unsupported discovery should be represented in result: %v", err)
	}
	if discovery.Status != ModelDiscoveryUnsupported || len(discovery.Models) != 0 || discovery.Reason == "" {
		t.Fatalf("unexpected unsupported result: %+v", discovery)
	}
}

func TestAnthropicDiscoveryUsesOnlyConfiguredCatalog(t *testing.T) {
	client := NewClient(config.AIConfig{
		Enabled: true, Provider: "anthropic", APIBase: "https://example.invalid/v1", APIKey: "secret", Model: "claude-invoke",
		ConfiguredCatalog: []config.AIModelCatalogEntry{{ID: "claude-invoke", DisplayName: "Claude Visible", ContextWindow: 200000}},
	}, nil)
	discovery, err := client.DiscoverModels(context.Background())
	if err != nil {
		t.Fatalf("configured catalog: %v", err)
	}
	if discovery.Status != ModelDiscoveryConfigured || len(discovery.Models) != 1 || discovery.Models[0].DisplayName != "Claude Visible" {
		t.Fatalf("unexpected configured result: %+v", discovery)
	}
}

func TestAnthropicDiscoveryUsesExplicitEndpointWithAnthropicHeaders(t *testing.T) {
	client := NewClient(config.AIConfig{
		Enabled: true, Provider: "anthropic", APIBase: "https://anthropic.example/v1", APIKey: "secret", Model: "claude-invoke", ModelListPath: "models",
	}, &http.Client{Transport: aiRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() != "https://anthropic.example/v1/models" {
			t.Fatalf("model endpoint = %s", req.URL)
		}
		if req.Header.Get("x-api-key") != "secret" || req.Header.Get("anthropic-version") == "" {
			t.Fatalf("missing Anthropic discovery headers: %+v", req.Header)
		}
		return jsonResponse(http.StatusOK, `{"data":[{"id":"claude-invoke","display_name":"Claude Explicit"}]}`), nil
	})})

	discovery, err := client.DiscoverModels(context.Background())
	if err != nil {
		t.Fatalf("discover explicit Anthropic catalog: %v", err)
	}
	if discovery.Status != ModelDiscoveryAvailable || len(discovery.Models) != 1 || discovery.Models[0].ID != "claude-invoke" {
		t.Fatalf("unexpected Anthropic discovery: %+v", discovery)
	}
}

func TestUsageStoreAggregatesBoundedRangesAndFormatsMetadata(t *testing.T) {
	store := NewUsageStore(UsageStoreOptions{Now: func() time.Time { return time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC) }})
	store.Record(UsageEvent{At: time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC), Provider: "openai", Model: "gpt", InputTokens: 1200, OutputTokens: 800})
	store.Record(UsageEvent{At: time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC), Provider: "openai", Model: "gpt", InputTokens: 1, OutputTokens: 2})
	store.WaitForIdle()
	snapshot, err := store.Snapshot(UsageRange{Start: time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC), End: time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if snapshot.CallCount != 1 || snapshot.TotalTokens != 2000 || snapshot.TotalTokensFormatted != "2.00K" {
		t.Fatalf("unexpected snapshot: %+v", snapshot)
	}
	if got := FormatUsageNumber(1_250_000); got != "1.25M" {
		t.Fatalf("formatted number = %q", got)
	}
	if got := FormatUsageNumber(1_250_000_000); got != "1.25B" {
		t.Fatalf("formatted billion = %q", got)
	}
}

func TestUsageStoreEvictsOldestEventsAtConfiguredCapacity(t *testing.T) {
	now := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	store := NewUsageStore(UsageStoreOptions{Now: func() time.Time { return now }, MaxEvents: 2})
	store.Record(UsageEvent{At: now.Add(-3 * time.Minute), Provider: "openai", Model: "old", TotalTokens: 1})
	store.Record(UsageEvent{At: now.Add(-2 * time.Minute), Provider: "openai", Model: "middle", TotalTokens: 2})
	store.Record(UsageEvent{At: now.Add(-time.Minute), Provider: "openai", Model: "new", TotalTokens: 3})
	events := store.UsageEvents()
	if len(events) != 2 || events[0].Model != "middle" || events[1].Model != "new" {
		t.Fatalf("bounded eviction kept unexpected events: %+v", events)
	}
}

func TestProviderEndpointRejectsAbsoluteTraversalAndFragmentEscapes(t *testing.T) {
	client := NewClient(config.AIConfig{
		Enabled: true, Provider: "openai", APIBase: "https://provider.example/v1", APIKey: "secret", Model: "model",
	}, &http.Client{Transport: aiRoundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("unsafe provider path reached the network")
		return nil, nil
	})})

	for _, path := range []string{
		"https://attacker.example/models",
		"//attacker.example/models",
		"../models",
		"models/../balance",
		"models#secret-fragment",
		"models\\escape",
	} {
		t.Run(path, func(t *testing.T) {
			if _, err := client.endpoint(path); err == nil {
				t.Fatalf("endpoint(%q) succeeded, want a same-origin path validation error", path)
			}
		})
	}
}

func TestModelDiscoveryCarriesBoundedContextAndReasoningMetadata(t *testing.T) {
	client := NewClient(config.AIConfig{
		Enabled: true, Provider: "openai", APIBase: "https://provider.example/v1", APIKey: "secret", Model: "reasoning-model",
		ContextWindow: 131072, ReasoningEffort: "high", ModelListPath: "models",
	}, &http.Client{Transport: aiRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, `{"data":{"models":[{"id":"reasoning-model","display_name":"Reasoning Display","context_window":999999999,"supported_reasoning_efforts":["low","high","extreme","high"]}]}}`), nil
	})})

	discovery, err := client.DiscoverModels(context.Background())
	if err != nil {
		t.Fatalf("discover models: %v", err)
	}
	if len(discovery.Models) != 1 || discovery.Models[0].ContextWindow != 131072 {
		t.Fatalf("configured context bound was not carried into selected model: %+v", discovery)
	}
	raw, err := json.Marshal(discovery.Models[0])
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.Contains(text, `"reasoning_efforts":["low","high"]`) || strings.Contains(text, "extreme") {
		t.Fatalf("unexpected reasoning metadata: %s", text)
	}
}

func TestOpenAICompatibleRequestCarriesEnumeratedReasoningEffort(t *testing.T) {
	var requestBody []byte
	client := NewClient(config.AIConfig{
		Enabled: true, Provider: "openai", APIBase: "https://provider.example/v1", APIKey: "secret", Model: "reasoning-model", ReasoningEffort: "high",
	}, &http.Client{Transport: aiRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		var err error
		requestBody, err = io.ReadAll(req.Body)
		if err != nil {
			t.Fatalf("read request: %v", err)
		}
		return jsonResponse(http.StatusOK, `{"choices":[{"message":{"content":"ok"}}],"usage":{"prompt_tokens":2,"completion_tokens":1,"total_tokens":3}}`), nil
	})})

	if _, err := client.CompleteWithUsage(context.Background(), []Message{{Role: "user", Content: "ping"}}); err != nil {
		t.Fatalf("complete: %v", err)
	}
	if !bytes.Contains(requestBody, []byte(`"reasoning_effort":"high"`)) {
		t.Fatalf("request omitted configured reasoning effort: %s", requestBody)
	}
}

func TestClientHasUsageStoreIntegrationSeam(t *testing.T) {
	client := NewClient(config.AIConfig{}, &http.Client{Transport: aiRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("not called")
	})})
	if !reflect.ValueOf(client).MethodByName("SetUsageStore").IsValid() {
		t.Fatal("Client.SetUsageStore is required to connect real provider calls to local accounting")
	}
}

func TestUsageStoreRejectsFutureAndOverlongQueries(t *testing.T) {
	now := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	store := NewUsageStore(UsageStoreOptions{Now: func() time.Time { return now }})
	for _, query := range []UsageRange{
		{Start: now.Add(-91 * 24 * time.Hour), End: now},
		{Start: now, End: now.Add(6 * time.Minute)},
		{Start: now.Add(time.Hour), End: now},
	} {
		if _, err := store.Snapshot(query); err == nil {
			t.Fatalf("Snapshot(%+v) succeeded, want bounded range rejection", query)
		}
	}
}

func TestUsageStoreBoundsPerCallCountersAndLabels(t *testing.T) {
	now := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	store := NewUsageStore(UsageStoreOptions{Now: func() time.Time { return now }, MaxEvents: 2})
	store.Record(UsageEvent{
		Provider:    strings.Repeat("p", 1024),
		Model:       strings.Repeat("m", 1024),
		InputTokens: int(^uint(0) >> 1), OutputTokens: int(^uint(0) >> 1), TotalTokens: int(^uint(0) >> 1),
	})
	snapshot, err := store.Snapshot(UsageRange{Start: now.Add(-time.Hour), End: now})
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.InputTokens > 1_000_000_000_000 || snapshot.OutputTokens > 1_000_000_000_000 || snapshot.TotalTokens > 1_000_000_000_000 {
		t.Fatalf("unbounded per-call usage reached aggregate: %+v", snapshot)
	}
	events := store.UsageEvents()
	if len(events) != 1 || len(events[0].Provider) > 512 || len(events[0].Model) > 512 {
		t.Fatalf("usage labels were not bounded: %+v", events)
	}
}

func TestClientRecordsEachProviderCallOnceIncludingStreaming(t *testing.T) {
	now := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	store := NewUsageStore(UsageStoreOptions{Now: func() time.Time { return now }})
	requests := 0
	client := NewClient(config.AIConfig{
		Enabled: true, Provider: "openai", APIBase: "https://provider.example/v1", APIKey: "secret", Model: "actual-model",
	}, &http.Client{Transport: aiRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		requests++
		body, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(body, []byte(`"stream":true`)) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Status:     "200 OK",
				Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
				Body: io.NopCloser(strings.NewReader(
					"data: {\"choices\":[{\"delta\":{\"content\":\"streamed\"}}]}\n\n" +
						"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":4,\"completion_tokens\":3,\"total_tokens\":7}}\n\n" +
						"data: [DONE]\n\n",
				)),
			}, nil
		}
		return jsonResponse(http.StatusOK, `{"choices":[{"message":{"content":"ok"}}],"usage":{"prompt_tokens":2,"completion_tokens":1,"total_tokens":3}}`), nil
	})}).SetUsageStore(store)

	if _, err := client.CompleteWithUsage(context.Background(), []Message{{Role: "user", Content: "one"}}); err != nil {
		t.Fatalf("non-stream completion: %v", err)
	}
	if _, err := client.CompleteWithUsageStream(context.Background(), []Message{{Role: "user", Content: "two"}}, func(AssistantTraceEvent) {}); err != nil {
		t.Fatalf("stream completion: %v", err)
	}
	snapshot, err := store.Snapshot(UsageRange{Start: now.Add(-time.Hour), End: now})
	if err != nil {
		t.Fatal(err)
	}
	if requests != 2 || snapshot.CallCount != 2 || snapshot.InputTokens != 6 || snapshot.OutputTokens != 4 || snapshot.TotalTokens != 10 {
		t.Fatalf("provider calls were not counted exactly once: requests=%d snapshot=%+v", requests, snapshot)
	}
}

func TestClientRecordsFailedProviderCallWithoutLeakingRawBody(t *testing.T) {
	now := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	store := NewUsageStore(UsageStoreOptions{Now: func() time.Time { return now }})
	client := NewClient(config.AIConfig{
		Enabled: true, Provider: "openai", APIBase: "https://provider.example/v1", APIKey: "super-secret-key", Model: "actual-model",
	}, &http.Client{Transport: aiRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusBadRequest, `{"error":{"message":"raw prompt and super-secret-key"}}`), nil
	})}).SetUsageStore(store)

	_, err := client.CompleteWithUsage(context.Background(), []Message{{Role: "user", Content: "sensitive prompt"}})
	if err == nil {
		t.Fatal("expected provider failure")
	}
	if strings.Contains(err.Error(), "raw prompt") || strings.Contains(err.Error(), "super-secret-key") {
		t.Fatalf("provider raw body or credential leaked through error: %v", err)
	}
	snapshot, snapshotErr := store.Snapshot(UsageRange{Start: now.Add(-time.Hour), End: now})
	if snapshotErr != nil {
		t.Fatal(snapshotErr)
	}
	if snapshot.CallCount != 1 || snapshot.TotalTokens != 0 {
		t.Fatalf("failed provider call accounting = %+v", snapshot)
	}
}

func TestStreamingFallbackCountsBothProviderCallsWithoutDoubleCounting(t *testing.T) {
	now := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	store := NewUsageStore(UsageStoreOptions{Now: func() time.Time { return now }})
	requests := 0
	client := NewClient(config.AIConfig{
		Enabled: true, Provider: "openai", APIBase: "https://provider.example/v1", APIKey: "secret", Model: "actual-model",
	}, &http.Client{Transport: aiRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		requests++
		body, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(body, []byte(`"stream":true`)) {
			return jsonResponse(http.StatusNotImplemented, `{"error":{"message":"stream unsupported"}}`), nil
		}
		return jsonResponse(http.StatusOK, `{"choices":[{"message":{"content":"fallback"}}],"usage":{"prompt_tokens":2,"completion_tokens":1,"total_tokens":3}}`), nil
	})}).SetUsageStore(store)

	result, err := client.CompleteWithUsageStream(context.Background(), []Message{{Role: "user", Content: "ping"}}, func(AssistantTraceEvent) {})
	if err != nil || result == nil || result.Content != "fallback" {
		t.Fatalf("fallback completion: result=%+v err=%v", result, err)
	}
	snapshot, err := store.Snapshot(UsageRange{Start: now.Add(-time.Hour), End: now})
	if err != nil {
		t.Fatal(err)
	}
	if requests != 2 || snapshot.CallCount != 2 || snapshot.TotalTokens != 3 {
		t.Fatalf("stream fallback accounting: requests=%d snapshot=%+v", requests, snapshot)
	}
}

func TestClientDisallowsProviderRedirects(t *testing.T) {
	requests := 0
	client := NewClient(config.AIConfig{
		Enabled: true, Provider: "openai", APIBase: "https://provider.example/v1", APIKey: "secret", Model: "actual-model", ModelListPath: "models",
	}, &http.Client{Transport: aiRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		requests++
		if req.URL.Host == "provider.example" {
			response := jsonResponse(http.StatusFound, "")
			response.Header.Set("Location", "https://attacker.example/models")
			return response, nil
		}
		return jsonResponse(http.StatusOK, `{"data":[{"id":"escaped"}]}`), nil
	})})

	if _, err := client.DiscoverModels(context.Background()); err == nil {
		t.Fatal("cross-origin redirect unexpectedly succeeded")
	}
	if requests != 1 {
		t.Fatalf("redirect followed outside provider origin: requests=%d", requests)
	}
}

func TestProviderQuotaParsersSupportNestedGatewayEnvelopes(t *testing.T) {
	balance := parseProviderBalance(map[string]any{
		"data": map[string]any{"data": map[string]any{
			"quota": json.Number("100.5"), "used_quota": json.Number("25.25"), "currency": "USD",
		}},
	}).(ProviderBalance)
	if balance.Limit != 100.5 || balance.Used != 25.25 || balance.Available != 75.25 || balance.Currency != "USD" {
		t.Fatalf("nested balance = %+v", balance)
	}
	usage := parseProviderUsage(map[string]any{
		"data": map[string]any{"usage": map[string]any{
			"prompt_tokens": json.Number("120"), "completion_tokens": json.Number("30"), "request_count": json.Number("4"),
		}},
	}).(ProviderUsage)
	if usage.InputTokens != 120 || usage.OutputTokens != 30 || usage.TotalTokens != 150 || usage.CallCount != 4 {
		t.Fatalf("nested usage = %+v", usage)
	}
}

func jsonResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Status:     fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func responseWithClose(status int, body string, closed *int) *http.Response {
	return &http.Response{StatusCode: status, Status: fmt.Sprintf("%d %s", status, http.StatusText(status)), Header: http.Header{"Content-Type": []string{"application/json"}}, Body: closeTrackingBody{Reader: strings.NewReader(body), closed: closed}}
}

type closeTrackingBody struct {
	*strings.Reader
	closed *int
}

func (b closeTrackingBody) Close() error {
	*b.closed++
	return nil
}
