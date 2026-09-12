package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

func TestOpenAIOfficialEndpointUsesResponsesAPI(t *testing.T) {
	var requestBody map[string]any
	client := NewClient(config.AIConfig{
		Enabled: true, Provider: "openai", APIBase: "https://api.openai.com/v1", APIKey: "secret", Model: "gpt-5", ReasoningEffort: "high", MaxTokens: 2048,
	}, &http.Client{Transport: aiRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path != "/v1/responses" {
			t.Fatalf("request path = %q, want /v1/responses", req.URL.Path)
		}
		if got := req.Header.Get("Authorization"); got != "Bearer secret" {
			t.Fatalf("authorization header = %q", got)
		}
		if err := json.NewDecoder(req.Body).Decode(&requestBody); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		return jsonResponse(http.StatusOK, `{
			"id":"resp_1","object":"response","created_at":1,"status":"completed","model":"gpt-5",
			"output":[
				{"id":"rs_1","type":"reasoning","summary":[{"type":"summary_text","text":"checked evidence"}]},
				{"id":"msg_1","type":"message","status":"completed","role":"assistant","content":[{"type":"output_text","text":"protected","annotations":[]}]}
			],
			"usage":{"input_tokens":11,"output_tokens":4,"total_tokens":15,"input_tokens_details":{"cached_tokens":0},"output_tokens_details":{"reasoning_tokens":2}}
		}`), nil
	})})

	result, err := client.CompleteWithUsage(context.Background(), []Message{
		{Role: "developer", Content: "Follow policy."},
		{Role: "user", Content: "Check this."},
	})
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if result.Content != "protected" || result.ReasoningSummary != "checked evidence" {
		t.Fatalf("unexpected response: %+v", result)
	}
	if result.Usage != (CompletionUsage{InputTokens: 11, OutputTokens: 4, TotalTokens: 15}) {
		t.Fatalf("usage = %+v", result.Usage)
	}
	if requestBody["model"] != "gpt-5" || requestBody["store"] != false || requestBody["max_output_tokens"] != float64(2048) {
		t.Fatalf("unexpected request metadata: %#v", requestBody)
	}
	reasoning, _ := requestBody["reasoning"].(map[string]any)
	if reasoning["effort"] != "high" || reasoning["summary"] != "auto" {
		t.Fatalf("reasoning request = %#v", reasoning)
	}
	input, _ := requestBody["input"].([]any)
	if len(input) != 2 || input[0].(map[string]any)["role"] != "developer" || input[1].(map[string]any)["role"] != "user" {
		t.Fatalf("input roles = %#v", input)
	}
}

func TestOpenAIResponsesPreservesRefusalText(t *testing.T) {
	client := NewClient(config.AIConfig{
		Enabled: true, Provider: "openai-responses", APIBase: "https://gateway.example/v1", APIKey: "secret", Model: "gpt-5",
	}, &http.Client{Transport: aiRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, `{
			"id":"resp_refusal","object":"response","created_at":1,"status":"completed","model":"gpt-5",
			"output":[{"id":"msg_1","type":"message","status":"completed","role":"assistant","content":[{"type":"refusal","refusal":"cannot comply"}]}],
			"usage":{"input_tokens":3,"output_tokens":2,"total_tokens":5,"input_tokens_details":{"cached_tokens":0},"output_tokens_details":{"reasoning_tokens":0}}
		}`), nil
	})})

	result, err := client.CompleteWithUsage(context.Background(), []Message{{Role: "user", Content: "request"}})
	if err != nil {
		t.Fatalf("refusal completion: %v", err)
	}
	if result.Content != "cannot comply" || result.Usage.TotalTokens != 5 {
		t.Fatalf("refusal result = %+v", result)
	}
}

func TestOpenAIResponsesToolPlanUsesFlatFunctionTools(t *testing.T) {
	var requestBody map[string]any
	client := NewClient(config.AIConfig{
		Enabled: true, Provider: "openai-responses", APIBase: "https://gateway.example/v1", APIKey: "secret", Model: "gpt-5",
	}, &http.Client{Transport: aiRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path != "/v1/responses" {
			t.Fatalf("request path = %q", req.URL.Path)
		}
		if err := json.NewDecoder(req.Body).Decode(&requestBody); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		return jsonResponse(http.StatusOK, `{
			"id":"resp_tool","object":"response","created_at":1,"status":"completed","model":"gpt-5",
			"output":[{"id":"call_1","type":"function_call","status":"completed","call_id":"call_1","name":"recent_security_events","arguments":"{\"limit\":7}"}],
			"usage":{"input_tokens":19,"output_tokens":5,"total_tokens":24,"input_tokens_details":{"cached_tokens":0},"output_tokens_details":{"reasoning_tokens":0}}
		}`), nil
	})})

	plan, err := client.CompleteToolPlan(context.Background(), []Message{{Role: "user", Content: "recent events"}}, []map[string]any{{
		"type": "function",
		"function": map[string]any{
			"name":        "recent_security_events",
			"description": "Read recent events.",
			"parameters": map[string]any{
				"type":       "object",
				"properties": map[string]any{"limit": map[string]any{"type": "integer"}},
			},
		},
	}})
	if err != nil {
		t.Fatalf("tool plan: %v", err)
	}
	if plan.Mode != "native_openai_tool_calls" || len(plan.ToolRequests) != 1 || plan.ToolRequests[0].Name != "recent_security_events" {
		t.Fatalf("unexpected plan: %+v", plan)
	}
	if got := plan.ToolRequests[0].Args["limit"]; got != json.Number("7") {
		t.Fatalf("tool limit = %#v", got)
	}
	tools, _ := requestBody["tools"].([]any)
	if len(tools) != 1 {
		t.Fatalf("tools = %#v", tools)
	}
	tool := tools[0].(map[string]any)
	if tool["type"] != "function" || tool["name"] != "recent_security_events" || tool["strict"] != false {
		t.Fatalf("responses tool shape = %#v", tool)
	}
	if _, nested := tool["function"]; nested {
		t.Fatalf("chat-completions tool envelope leaked into responses request: %#v", tool)
	}
}

func TestOpenAIResponsesFallsBackOnlyWhenEndpointIsUnavailable(t *testing.T) {
	paths := make([]string, 0, 2)
	client := NewClient(config.AIConfig{
		Enabled: true, Provider: "openai-responses", APIBase: "https://gateway.example/v1", APIKey: "secret", Model: "legacy-model",
	}, &http.Client{Transport: aiRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		paths = append(paths, req.URL.Path)
		if req.URL.Path == "/v1/responses" {
			return jsonResponse(http.StatusNotFound, `{"error":{"message":"unknown endpoint","type":"invalid_request_error","code":"not_found","param":null}}`), nil
		}
		return jsonResponse(http.StatusOK, `{"choices":[{"message":{"content":"legacy ok"}}],"usage":{"prompt_tokens":2,"completion_tokens":1,"total_tokens":3}}`), nil
	})})

	result, err := client.CompleteWithUsage(context.Background(), []Message{{Role: "user", Content: "ping"}})
	if err != nil || result == nil || result.Content != "legacy ok" {
		t.Fatalf("fallback result=%+v err=%v", result, err)
	}
	if strings.Join(paths, ",") != "/v1/responses,/v1/chat/completions" {
		t.Fatalf("request paths = %v", paths)
	}
}

func TestOpenAIResponsesDoesNotFallbackOnAuthenticationFailure(t *testing.T) {
	requests := 0
	client := NewClient(config.AIConfig{
		Enabled: true, Provider: "openai-responses", APIBase: "https://gateway.example/v1", APIKey: "bad", Model: "gpt-5",
	}, &http.Client{Transport: aiRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		requests++
		if req.URL.Path != "/v1/responses" {
			t.Fatalf("unexpected fallback path %q", req.URL.Path)
		}
		return jsonResponse(http.StatusUnauthorized, `{"error":{"message":"bad key","type":"authentication_error","code":"invalid_api_key","param":null}}`), nil
	})})

	if _, err := client.CompleteWithUsage(context.Background(), []Message{{Role: "user", Content: "ping"}}); err == nil {
		t.Fatal("expected authentication failure")
	}
	if requests != 1 {
		t.Fatalf("requests = %d, want 1", requests)
	}
}

func TestOpenAIResponsesDoesNotFallbackOnAmbiguousOrModel404(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "model not found", body: `{"error":{"message":"model was not found","type":"invalid_request_error","code":"model_not_found","param":"model"}}`},
		{name: "ambiguous hidden denial", body: `{"error":{"message":"not found","type":"not_found","code":"not_found","param":null}}`},
		{name: "hidden authentication denial", body: `{"error":{"message":"resource not found","type":"authentication_error","code":"not_found","param":null}}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			requests := 0
			client := NewClient(config.AIConfig{
				Enabled: true, Provider: "openai-responses", APIBase: "https://gateway.example/v1", APIKey: "secret", Model: "gpt-5",
			}, &http.Client{Transport: aiRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				requests++
				if req.URL.Path != "/v1/responses" {
					t.Fatalf("unexpected fallback path %q", req.URL.Path)
				}
				return jsonResponse(http.StatusNotFound, test.body), nil
			})})

			if _, err := client.CompleteWithUsage(context.Background(), []Message{{Role: "user", Content: "ping"}}); err == nil {
				t.Fatal("expected provider failure")
			}
			if requests != 1 {
				t.Fatalf("requests = %d, want 1", requests)
			}
		})
	}
}

func TestOpenAIResponsesDoesNotFallbackOnAuthenticationOrPermissionErrors(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
	}{
		{name: "bad request api key restriction", status: http.StatusBadRequest, body: `{"error":{"message":"Responses API is not supported for this API key","type":"authentication_error","code":"invalid_api_key","param":null}}`},
		{name: "unprocessable permission denial", status: http.StatusUnprocessableEntity, body: `{"error":{"message":"permission requires chat/completions","type":"permission_error","code":"access_denied","param":null}}`},
		{name: "method hidden by policy", status: http.StatusMethodNotAllowed, body: `{"error":{"message":"method hidden by access policy","type":"forbidden","code":"access_denied","param":null}}`},
		{name: "machine api key code", status: http.StatusBadRequest, body: `{"error":{"message":"chat/completions required","type":"invalid_request_error","code":"invalid_api_key","param":null}}`},
		{name: "machine access code", status: http.StatusMethodNotAllowed, body: `{"error":{"message":"method not allowed","type":"invalid_request_error","code":"access_denied","param":null}}`},
		{name: "machine permission code", status: http.StatusUnprocessableEntity, body: `{"error":{"message":"chat/completions required","type":"invalid_request_error","code":"permission_denied","param":null}}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			requests := 0
			client := NewClient(config.AIConfig{
				Enabled: true, Provider: "openai-responses", APIBase: "https://gateway.example/v1", APIKey: "secret", Model: "gpt-5",
			}, &http.Client{Transport: aiRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				requests++
				if req.URL.Path != "/v1/responses" {
					t.Fatalf("unexpected fallback path %q", req.URL.Path)
				}
				return jsonResponse(test.status, test.body), nil
			})})

			if _, err := client.CompleteWithUsage(context.Background(), []Message{{Role: "user", Content: "ping"}}); err == nil {
				t.Fatal("expected provider failure")
			}
			if requests != 1 {
				t.Fatalf("requests = %d, want 1", requests)
			}
		})
	}
}

func TestOpenAIResponsesNonStreamingFailuresRecordUsage(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "failed status",
			body: `{"id":"resp_failed","object":"response","created_at":1,"status":"failed","model":"gpt-5","error":{"code":"server_error","message":"failed"},"output":[],"usage":{"input_tokens":6,"output_tokens":2,"total_tokens":8,"input_tokens_details":{"cached_tokens":0},"output_tokens_details":{"reasoning_tokens":1}}}`,
		},
		{
			name: "reasoning only",
			body: `{"id":"resp_reasoning","object":"response","created_at":1,"status":"completed","model":"gpt-5","output":[{"id":"rs_1","type":"reasoning","summary":[{"type":"summary_text","text":"reasoned"}]}],"usage":{"input_tokens":7,"output_tokens":3,"total_tokens":10,"input_tokens_details":{"cached_tokens":0},"output_tokens_details":{"reasoning_tokens":3}}}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := NewUsageStore(UsageStoreOptions{})
			client := NewClient(config.AIConfig{
				Enabled: true, Provider: "openai-responses", APIBase: "https://gateway.example/v1", APIKey: "secret", Model: "gpt-5",
			}, &http.Client{Transport: aiRoundTripFunc(func(*http.Request) (*http.Response, error) {
				return jsonResponse(http.StatusOK, test.body), nil
			})}).SetUsageStore(store)

			result, err := client.CompleteWithUsage(context.Background(), []Message{{Role: "user", Content: "ping"}})
			if err == nil {
				t.Fatalf("response unexpectedly succeeded: %+v", result)
			}
			if result == nil || result.Usage.TotalTokens == 0 {
				t.Fatalf("usage-bearing failure result = %+v", result)
			}
			events := store.UsageEvents()
			if len(events) != 1 || events[0].TotalTokens != result.Usage.TotalTokens {
				t.Fatalf("recorded usage = %+v, result=%+v", events, result)
			}
		})
	}
}

func TestOpenAIResponsesNonStreamingToolPlanFailureRecordsUsage(t *testing.T) {
	store := NewUsageStore(UsageStoreOptions{})
	client := NewClient(config.AIConfig{
		Enabled: true, Provider: "openai-responses", APIBase: "https://gateway.example/v1", APIKey: "secret", Model: "gpt-5",
	}, &http.Client{Transport: aiRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, `{"id":"resp_reasoning","object":"response","created_at":1,"status":"completed","model":"gpt-5","output":[{"id":"rs_1","type":"reasoning","summary":[{"type":"summary_text","text":"reasoned"}]}],"usage":{"input_tokens":9,"output_tokens":4,"total_tokens":13,"input_tokens_details":{"cached_tokens":0},"output_tokens_details":{"reasoning_tokens":4}}}`), nil
	})}).SetUsageStore(store)

	plan, err := client.CompleteToolPlan(context.Background(), []Message{{Role: "user", Content: "plan"}}, []map[string]any{{
		"type": "function", "function": map[string]any{"name": "system_summary", "parameters": map[string]any{"type": "object", "properties": map[string]any{}}},
	}})
	if err == nil {
		t.Fatalf("tool plan unexpectedly succeeded: %+v", plan)
	}
	if plan == nil || plan.TotalTokens != 13 {
		t.Fatalf("usage-bearing tool plan = %+v", plan)
	}
	events := store.UsageEvents()
	if len(events) != 1 || events[0].TotalTokens != 13 {
		t.Fatalf("recorded tool plan usage = %+v", events)
	}
}

func TestOpenAIResponsesStreamingCompletion(t *testing.T) {
	var requestBody []byte
	client := NewClient(config.AIConfig{
		Enabled: true, Provider: "openai-responses", APIBase: "https://gateway.example/v1", APIKey: "secret", Model: "gpt-5",
	}, &http.Client{Transport: aiRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		var err error
		requestBody, err = io.ReadAll(req.Body)
		if err != nil {
			t.Fatalf("read request: %v", err)
		}
		return eventStreamResponse(
			`{"type":"response.created","sequence_number":0,"response":{"id":"resp_stream","object":"response","created_at":1,"status":"in_progress","model":"gpt-5","output":[]}}`,
			`{"type":"response.reasoning_summary_text.delta","sequence_number":1,"item_id":"rs_1","output_index":0,"summary_index":0,"delta":"checked "}`,
			`{"type":"response.reasoning_summary_text.delta","sequence_number":2,"item_id":"rs_1","output_index":0,"summary_index":0,"delta":"evidence"}`,
			`{"type":"response.output_text.delta","sequence_number":3,"item_id":"msg_1","output_index":1,"content_index":0,"delta":"safe"}`,
			`{"type":"response.completed","sequence_number":4,"response":{"id":"resp_stream","object":"response","created_at":1,"status":"completed","model":"gpt-5","output":[{"id":"rs_1","type":"reasoning","summary":[{"type":"summary_text","text":"checked evidence"}]},{"id":"msg_1","type":"message","status":"completed","role":"assistant","content":[{"type":"output_text","text":"safe","annotations":[]}]}],"usage":{"input_tokens":5,"output_tokens":2,"total_tokens":7,"input_tokens_details":{"cached_tokens":0},"output_tokens_details":{"reasoning_tokens":1}}}}`,
		), nil
	})})

	events := make([]AssistantTraceEvent, 0)
	result, err := client.CompleteWithUsageStream(context.Background(), []Message{{Role: "user", Content: "ping"}}, func(event AssistantTraceEvent) {
		events = append(events, event)
	})
	if err != nil {
		t.Fatalf("stream completion: %v", err)
	}
	if result.Content != "safe" || result.ReasoningSummary != "checked evidence" || result.Usage.TotalTokens != 7 {
		t.Fatalf("stream result = %+v", result)
	}
	if !bytes.Contains(requestBody, []byte(`"stream":true`)) {
		t.Fatalf("responses stream request omitted stream=true: %s", requestBody)
	}
	if !hasTraceEvent(events, "provider_response_start", "") || !hasTraceEvent(events, "reasoning_delta", "checked ") || !hasTraceEvent(events, "content_delta", "safe") {
		t.Fatalf("stream events = %+v", events)
	}
}

func TestOpenAIResponsesStreamingToolPlan(t *testing.T) {
	client := NewClient(config.AIConfig{
		Enabled: true, Provider: "openai-responses", APIBase: "https://gateway.example/v1", APIKey: "secret", Model: "gpt-5",
	}, &http.Client{Transport: aiRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return eventStreamResponse(
			`{"type":"response.created","sequence_number":0,"response":{"id":"resp_tool_stream","object":"response","created_at":1,"status":"in_progress","model":"gpt-5","output":[]}}`,
			`{"type":"response.output_item.added","sequence_number":1,"output_index":0,"item":{"id":"call_1","type":"function_call","status":"in_progress","call_id":"call_1","name":"recent_security_events","arguments":""}}`,
			`{"type":"response.function_call_arguments.delta","sequence_number":2,"item_id":"call_1","output_index":0,"delta":"{\"limit\":"}`,
			`{"type":"response.function_call_arguments.delta","sequence_number":3,"item_id":"call_1","output_index":0,"delta":"7}"}`,
			`{"type":"response.function_call_arguments.done","sequence_number":4,"item_id":"call_1","output_index":0,"arguments":"{\"limit\":7}"}`,
			`{"type":"response.completed","sequence_number":5,"response":{"id":"resp_tool_stream","object":"response","created_at":1,"status":"completed","model":"gpt-5","output":[{"id":"call_1","type":"function_call","status":"completed","call_id":"call_1","name":"recent_security_events","arguments":"{\"limit\":7}"}],"usage":{"input_tokens":8,"output_tokens":3,"total_tokens":11,"input_tokens_details":{"cached_tokens":0},"output_tokens_details":{"reasoning_tokens":0}}}}`,
		), nil
	})})

	events := make([]AssistantTraceEvent, 0)
	plan, err := client.CompleteToolPlanStream(context.Background(), []Message{{Role: "user", Content: "recent events"}}, []map[string]any{{
		"type": "function",
		"function": map[string]any{
			"name":       "recent_security_events",
			"parameters": map[string]any{"type": "object", "properties": map[string]any{}},
		},
	}}, func(event AssistantTraceEvent) {
		events = append(events, event)
	})
	if err != nil {
		t.Fatalf("stream tool plan: %v", err)
	}
	if plan.Mode != "native_openai_tool_calls_stream" || len(plan.ToolRequests) != 1 || plan.ToolRequests[0].Name != "recent_security_events" {
		t.Fatalf("stream plan = %+v", plan)
	}
	if got := plan.ToolRequests[0].Args["limit"]; got != json.Number("7") {
		t.Fatalf("stream tool limit = %#v", got)
	}
	if !hasTraceEvent(events, "tool_call_delta", `{"limit":`) || !hasTraceEvent(events, "tool_call_delta", `7}`) {
		t.Fatalf("tool stream events = %+v", events)
	}
}

func TestOpenAIResponsesStreamRequiresTerminalEvent(t *testing.T) {
	requests := 0
	client := NewClient(config.AIConfig{
		Enabled: true, Provider: "openai-responses", APIBase: "https://gateway.example/v1", APIKey: "secret", Model: "gpt-5",
	}, &http.Client{Transport: aiRoundTripFunc(func(*http.Request) (*http.Response, error) {
		requests++
		return eventStreamResponse(
			`{"type":"response.created","sequence_number":0,"response":{"id":"resp_truncated","object":"response","created_at":1,"status":"in_progress","model":"gpt-5","output":[]}}`,
		), nil
	})})

	result, err := client.CompleteWithUsageStream(context.Background(), []Message{{Role: "user", Content: "ping"}}, func(AssistantTraceEvent) {})
	if err == nil {
		t.Fatalf("truncated stream unexpectedly succeeded: %+v", result)
	}
	if requests != 1 {
		t.Fatalf("truncated stream was replayed: requests=%d", requests)
	}
}

func TestOpenAIResponsesStreamFailureRecordsNestedUsage(t *testing.T) {
	store := NewUsageStore(UsageStoreOptions{})
	client := NewClient(config.AIConfig{
		Enabled: true, Provider: "openai-responses", APIBase: "https://gateway.example/v1", APIKey: "secret", Model: "gpt-5",
	}, &http.Client{Transport: aiRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return eventStreamResponse(
			`{"type":"response.failed","sequence_number":1,"response":{"id":"resp_failed","object":"response","created_at":1,"status":"failed","model":"gpt-5","error":{"code":"server_error","message":"provider failed"},"output":[],"usage":{"input_tokens":6,"output_tokens":2,"total_tokens":8,"input_tokens_details":{"cached_tokens":0},"output_tokens_details":{"reasoning_tokens":1}}}}`,
		), nil
	})}).SetUsageStore(store)

	result, err := client.CompleteWithUsageStream(context.Background(), []Message{{Role: "user", Content: "ping"}}, func(AssistantTraceEvent) {})
	if err == nil {
		t.Fatalf("failed stream unexpectedly succeeded: %+v", result)
	}
	if result == nil || result.Usage.TotalTokens != 8 {
		t.Fatalf("failed stream usage result = %+v", result)
	}
	events := store.UsageEvents()
	if len(events) != 1 || events[0].InputTokens != 6 || events[0].OutputTokens != 2 || events[0].TotalTokens != 8 {
		t.Fatalf("recorded failed stream usage = %+v", events)
	}
}

func TestOpenAIStreamDoesNotReplayNormalJSONResponse(t *testing.T) {
	requests := 0
	client := NewClient(config.AIConfig{
		Enabled: true, Provider: "openai-responses", APIBase: "https://gateway.example/v1", APIKey: "secret", Model: "legacy-model",
	}, &http.Client{Transport: aiRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		requests++
		if req.URL.Path == "/v1/responses" {
			return jsonResponse(http.StatusNotFound, `{"error":{"message":"unknown endpoint","type":"invalid_request_error","code":"endpoint_not_found","param":null}}`), nil
		}
		if req.URL.Path != "/v1/chat/completions" {
			t.Fatalf("unexpected path %q", req.URL.Path)
		}
		return jsonResponse(http.StatusOK, `{"choices":[{"message":{"content":"already generated"}}],"usage":{"prompt_tokens":2,"completion_tokens":2,"total_tokens":4}}`), nil
	})})

	result, err := client.CompleteWithUsageStream(context.Background(), []Message{{Role: "user", Content: "ping"}}, func(AssistantTraceEvent) {})
	if err == nil {
		t.Fatalf("normal JSON stream response unexpectedly succeeded: %+v", result)
	}
	if requests != 2 {
		t.Fatalf("normal JSON stream response was replayed: requests=%d, want 2", requests)
	}
}

func TestOpenAIStreamFallbackDoesNotRepeatResponsesProbe(t *testing.T) {
	paths := make([]string, 0, 3)
	client := NewClient(config.AIConfig{
		Enabled: true, Provider: "openai-responses", APIBase: "https://gateway.example/v1", APIKey: "secret", Model: "legacy-model",
	}, &http.Client{Transport: aiRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		paths = append(paths, req.URL.Path)
		body, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatalf("read request body: %v", err)
		}
		if req.URL.Path == "/v1/responses" {
			return jsonResponse(http.StatusNotFound, `{"error":{"message":"unknown endpoint","type":"invalid_request_error","code":"endpoint_not_found","param":null}}`), nil
		}
		if bytes.Contains(body, []byte(`"stream":true`)) {
			return jsonResponse(http.StatusBadRequest, `{"error":{"message":"Responses API streaming is not supported","type":"invalid_request_error","code":"unsupported_endpoint","param":"stream"}}`), nil
		}
		return jsonResponse(http.StatusOK, `{"choices":[{"message":{"content":"fallback"}}],"usage":{"prompt_tokens":2,"completion_tokens":1,"total_tokens":3}}`), nil
	})})

	result, err := client.CompleteWithUsageStream(context.Background(), []Message{{Role: "user", Content: "ping"}}, func(AssistantTraceEvent) {})
	if err != nil || result == nil || result.Content != "fallback" {
		t.Fatalf("stream fallback result=%+v err=%v", result, err)
	}
	if strings.Join(paths, ",") != "/v1/responses,/v1/chat/completions,/v1/chat/completions" {
		t.Fatalf("fallback paths = %v", paths)
	}
}

func TestOpenAIResponsesStreamUnsupportedFallsBackToResponsesNonStream(t *testing.T) {
	paths := make([]string, 0, 2)
	client := NewClient(config.AIConfig{
		Enabled: true, Provider: "openai-responses", APIBase: "https://gateway.example/v1", APIKey: "secret", Model: "gpt-5",
	}, &http.Client{Transport: aiRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		paths = append(paths, req.URL.Path)
		body, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatalf("read request body: %v", err)
		}
		if bytes.Contains(body, []byte(`"stream":true`)) {
			return jsonResponse(http.StatusBadRequest, `{"error":{"message":"streaming is not supported","type":"invalid_request_error","code":"stream_unsupported","param":"stream"}}`), nil
		}
		return jsonResponse(http.StatusOK, `{"id":"resp_fallback","object":"response","created_at":1,"status":"completed","model":"gpt-5","output":[{"id":"msg_1","type":"message","status":"completed","role":"assistant","content":[{"type":"output_text","text":"responses fallback","annotations":[]}]}],"usage":{"input_tokens":2,"output_tokens":2,"total_tokens":4,"input_tokens_details":{"cached_tokens":0},"output_tokens_details":{"reasoning_tokens":0}}}`), nil
	})})

	result, err := client.CompleteWithUsageStream(context.Background(), []Message{{Role: "user", Content: "ping"}}, func(AssistantTraceEvent) {})
	if err != nil || result == nil || result.Content != "responses fallback" {
		t.Fatalf("responses non-stream fallback result=%+v err=%v", result, err)
	}
	if strings.Join(paths, ",") != "/v1/responses,/v1/responses" {
		t.Fatalf("fallback paths = %v", paths)
	}
}

func TestOpenAIResponsesToolPlanStreamUnsupportedFallsBackToResponsesNonStream(t *testing.T) {
	paths := make([]string, 0, 2)
	client := NewClient(config.AIConfig{
		Enabled: true, Provider: "openai-responses", APIBase: "https://gateway.example/v1", APIKey: "secret", Model: "gpt-5",
	}, &http.Client{Transport: aiRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		paths = append(paths, req.URL.Path)
		body, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatalf("read request body: %v", err)
		}
		if bytes.Contains(body, []byte(`"stream":true`)) {
			return jsonResponse(http.StatusBadRequest, `{"error":{"message":"Responses API streaming is not supported","type":"invalid_request_error","code":"unsupported_endpoint","param":"stream"}}`), nil
		}
		return jsonResponse(http.StatusOK, `{"id":"resp_tool_fallback","object":"response","created_at":1,"status":"completed","model":"gpt-5","output":[{"id":"call_1","type":"function_call","status":"completed","call_id":"call_1","name":"system_summary","arguments":"{}"}],"usage":{"input_tokens":3,"output_tokens":2,"total_tokens":5,"input_tokens_details":{"cached_tokens":0},"output_tokens_details":{"reasoning_tokens":0}}}`), nil
	})})

	plan, err := client.CompleteToolPlanStream(context.Background(), []Message{{Role: "user", Content: "summarize"}}, []map[string]any{{
		"type": "function", "function": map[string]any{"name": "system_summary", "parameters": map[string]any{"type": "object", "properties": map[string]any{}}},
	}}, func(AssistantTraceEvent) {})
	if err != nil || plan == nil || len(plan.ToolRequests) != 1 || plan.ToolRequests[0].Name != "system_summary" {
		t.Fatalf("responses tool-plan fallback plan=%+v err=%v", plan, err)
	}
	if strings.Join(paths, ",") != "/v1/responses,/v1/responses" {
		t.Fatalf("tool-plan fallback paths = %v", paths)
	}
}

func TestOpenAIChatAliasKeepsChatCompletionsOnOfficialHost(t *testing.T) {
	client := NewClient(config.AIConfig{
		Enabled: true, Provider: "openai-chat", APIBase: "https://api.openai.com/v1", APIKey: "secret", Model: "legacy-model",
	}, &http.Client{Transport: aiRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path != "/v1/chat/completions" {
			t.Fatalf("request path = %q", req.URL.Path)
		}
		return jsonResponse(http.StatusOK, `{"choices":[{"message":{"content":"chat"}}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`), nil
	})})
	result, err := client.CompleteWithUsage(context.Background(), []Message{{Role: "user", Content: "ping"}})
	if err != nil || result.Content != "chat" {
		t.Fatalf("chat alias result=%+v err=%v", result, err)
	}
}

func eventStreamResponse(events ...string) *http.Response {
	var body strings.Builder
	for _, event := range events {
		body.WriteString("data: ")
		body.WriteString(event)
		body.WriteString("\n\n")
	}
	body.WriteString("data: [DONE]\n\n")
	return &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
		Body:       io.NopCloser(strings.NewReader(body.String())),
	}
}

func hasTraceEvent(events []AssistantTraceEvent, kind, message string) bool {
	for _, event := range events {
		if event.Type == kind && (message == "" || event.Message == message) {
			return true
		}
	}
	return false
}
