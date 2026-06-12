package blockpage

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

func TestRendererUsesCustomHTMLAndTraceHeader(t *testing.T) {
	renderer, err := NewRendererFromConfig(config.BlockPageConfig{
		TemplateID:    "minimal",
		CustomEnabled: true,
		CustomHTML:    `<html><body>event={{.EventID}} trace={{.TraceID}} status={{.Status}} type={{.AttackType}}</body></html>`,
	})
	if err != nil {
		t.Fatalf("new renderer: %v", err)
	}
	recorder := httptest.NewRecorder()
	renderer.Render(recorder, http.StatusTooManyRequests, Data{
		TraceID:    "cw-test",
		AttackType: "ratelimit",
		ClientIP:   "203.0.113.8",
		Timestamp:  time.Unix(0, 0).UTC(),
	})
	if recorder.Header().Get("X-CheeseWAF-Trace-ID") != "cw-test" {
		t.Fatalf("missing trace header: %q", recorder.Header().Get("X-CheeseWAF-Trace-ID"))
	}
	body := recorder.Body.String()
	if !strings.Contains(body, "event=cw-test") || !strings.Contains(body, "trace=cw-test") || !strings.Contains(body, "status=429") || !strings.Contains(body, "type=ratelimit") {
		t.Fatalf("custom block page did not render expected data: %s", body)
	}
}

func TestDefaultTemplateIncludesTroubleshootingFields(t *testing.T) {
	renderer := NewRenderer()
	recorder := httptest.NewRecorder()
	renderer.Render(recorder, http.StatusForbidden, Data{
		TraceID:    "cw-visible",
		AttackType: "sqli",
		ClientIP:   "198.51.100.9",
		Timestamp:  time.Unix(0, 0).UTC(),
	})
	body := recorder.Body.String()
	for _, want := range []string{"CheeseWAF", "Security response", "Request could not be completed", "Event / Trace ID", "cw-visible", "sqli", "198.51.100.9", "403 Forbidden"} {
		if !strings.Contains(body, want) {
			t.Fatalf("default template missing %q in %s", want, body)
		}
	}
}

func TestRendererAddsVisibleEventIDWhenCustomHTMLOmitsIt(t *testing.T) {
	renderer, err := NewRendererFromConfig(config.BlockPageConfig{
		TemplateID:    "minimal",
		CustomEnabled: true,
		CustomHTML:    `<html><body><main>blocked by custom page</main></body></html>`,
	})
	if err != nil {
		t.Fatalf("new renderer: %v", err)
	}
	recorder := httptest.NewRecorder()
	renderer.Render(recorder, http.StatusForbidden, Data{
		TraceID:    "cw-custom-visible",
		AttackType: "xss",
		ClientIP:   "203.0.113.10",
		Timestamp:  time.Unix(0, 0).UTC(),
	})
	body := recorder.Body.String()
	if !strings.Contains(body, "Event / Trace ID") || !strings.Contains(body, "cw-custom-visible") {
		t.Fatalf("expected custom page to include visible event id fallback, body=%s", body)
	}
	if !strings.Contains(body, "</main><div") {
		t.Fatalf("expected fallback badge to be injected before </body>, body=%s", body)
	}
}
