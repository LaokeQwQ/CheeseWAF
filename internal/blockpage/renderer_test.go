package blockpage

import (
	"net/http"
	"net/http/httptest"
	"regexp"
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
	if recorder.Header().Get("X-CheeseWAF-Event-ID") != "cw-test" {
		t.Fatalf("missing event header: %q", recorder.Header().Get("X-CheeseWAF-Event-ID"))
	}
	if recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("block pages must not be cached, got %q", recorder.Header().Get("Cache-Control"))
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
	for _, want := range []string{"CheeseWAF", "Security response", "Access was blocked", "When contacting support", "Event / Trace ID", "cw-visible", "sqli", "198.51.100.9", "403 Forbidden", "Blocked"} {
		if !strings.Contains(body, want) {
			t.Fatalf("default template missing %q in %s", want, body)
		}
	}
}

func TestDefaultTemplateLocalizesFromAcceptLanguageAndTimezone(t *testing.T) {
	renderer := NewRenderer()
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://example.test/blocked", nil)
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.1")
	req.Header.Set("Sec-CH-Timezone", "Asia/Shanghai")
	renderer.RenderRequest(recorder, req, http.StatusForbidden, Data{
		TraceID:    "cw-zh-visible",
		AttackType: "sqli",
		ClientIP:   "198.51.100.9",
		Timestamp:  time.Date(2026, 6, 14, 0, 30, 0, 0, time.UTC),
	})
	if recorder.Header().Get("Content-Language") != "zh-CN" {
		t.Fatalf("expected zh-CN content language, got %q", recorder.Header().Get("Content-Language"))
	}
	if !strings.Contains(recorder.Header().Get("Vary"), "Accept-Language") {
		t.Fatalf("expected Vary to include Accept-Language, got %q", recorder.Header().Get("Vary"))
	}
	if !strings.Contains(recorder.Header().Get("Accept-CH"), "Sec-CH-Time-Zone") {
		t.Fatalf("expected Accept-CH timezone hint, got %q", recorder.Header().Get("Accept-CH"))
	}
	body := recorder.Body.String()
	for _, want := range []string{`<html lang="zh-CN"`, "访问已被拦截", "联系支持时请提供事件 / Trace ID", "安全策略已执行", "Asia/Shanghai", "2026-06-14 08:30:00"} {
		if !strings.Contains(body, want) {
			t.Fatalf("localized default template missing %q in %s", want, body)
		}
	}
}

func TestDefaultTemplateSupportsJapaneseFallback(t *testing.T) {
	renderer := NewRenderer()
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://example.test/blocked", nil)
	req.Header.Set("Accept-Language", "ja,en;q=0.5")
	renderer.RenderRequest(recorder, req, http.StatusForbidden, Data{
		TraceID:    "cw-ja-visible",
		AttackType: "xss",
		ClientIP:   "198.51.100.10",
		Timestamp:  time.Unix(0, 0).UTC(),
	})
	body := recorder.Body.String()
	for _, want := range []string{`<html lang="ja"`, "アクセスがブロックされました", "サポートへ連絡する際は Event / Trace ID"} {
		if !strings.Contains(body, want) {
			t.Fatalf("japanese default template missing %q in %s", want, body)
		}
	}
}

func TestAcceptLanguageSkipsUnsupportedHigherPriorityLocale(t *testing.T) {
	renderer := NewRenderer()
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://example.test/blocked", nil)
	req.Header.Set("Accept-Language", "fr-FR,ja;q=0.9,en;q=0.7")
	renderer.RenderRequest(recorder, req, http.StatusForbidden, Data{
		TraceID:   "cw-ja-fallback",
		Timestamp: time.Unix(0, 0).UTC(),
	})
	body := recorder.Body.String()
	if !strings.Contains(body, `<html lang="ja"`) {
		t.Fatalf("expected unsupported preferred locale to fall through to ja, body=%s", body)
	}
	if strings.Contains(body, `<html lang="en"`) {
		t.Fatalf("unsupported preferred locale fell back to English instead of supported lower-priority locale, body=%s", body)
	}
}

func TestDefaultTemplateUsesStandardTimezoneClientHint(t *testing.T) {
	renderer := NewRenderer()
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://example.test/blocked", nil)
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Sec-CH-Time-Zone", "Asia/Tokyo")
	renderer.RenderRequest(recorder, req, http.StatusForbidden, Data{
		TraceID:   "cw-tz-visible",
		Timestamp: time.Date(2026, 6, 14, 0, 30, 0, 0, time.UTC),
	})
	body := recorder.Body.String()
	for _, want := range []string{"Asia/Tokyo", "2026-06-14 09:30:00"} {
		if !strings.Contains(body, want) {
			t.Fatalf("standard timezone client hint missing %q in %s", want, body)
		}
	}
}

func TestBuiltInTemplatesLocalizeFromRequest(t *testing.T) {
	for _, templateID := range []string{"minimal", "brand", "technical"} {
		t.Run(templateID, func(t *testing.T) {
			renderer, err := NewRendererFromConfig(config.BlockPageConfig{TemplateID: templateID})
			if err != nil {
				t.Fatalf("new renderer: %v", err)
			}
			req := httptest.NewRequest(http.MethodGet, "https://example.test/blocked", nil)
			req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.1")
			recorder := httptest.NewRecorder()
			renderer.RenderRequest(recorder, req, http.StatusForbidden, Data{
				TraceID:    "cw-built-in-" + templateID,
				AttackType: "sqli",
				ClientIP:   "198.51.100.21",
				Timestamp:  time.Unix(0, 0).UTC(),
			})
			body := recorder.Body.String()
			if !strings.Contains(body, `lang="zh-CN"`) || !strings.Contains(body, "访问已被拦截") {
				t.Fatalf("template %s did not localize from request, body=%s", templateID, body)
			}
		})
	}
}

func TestTemplateLibraryRendersVisibleTroubleshootingFields(t *testing.T) {
	for _, item := range TemplateLibrary() {
		t.Run(item.ID, func(t *testing.T) {
			renderer, err := NewRendererFromConfig(config.BlockPageConfig{TemplateID: item.ID})
			if err != nil {
				t.Fatalf("new renderer for %s: %v", item.ID, err)
			}
			recorder := httptest.NewRecorder()
			renderer.Render(recorder, http.StatusForbidden, Data{
				EventID:    "cw-library-" + item.ID,
				AttackType: "waf_block",
				ClientIP:   "203.0.113.20",
				Timestamp:  time.Unix(0, 0).UTC(),
			})
			body := recorder.Body.String()
			for _, want := range []string{"CheeseWAF", "cw-library-" + item.ID, "403 Forbidden"} {
				if !strings.Contains(body, want) {
					t.Fatalf("template %s missing %q in %s", item.ID, want, body)
				}
			}
			if recorder.Header().Get("X-CheeseWAF-Event-ID") != "cw-library-"+item.ID {
				t.Fatalf("template %s missing event header: %q", item.ID, recorder.Header().Get("X-CheeseWAF-Event-ID"))
			}
		})
	}
}

func TestHTMLTemplatesKeepLongMobileContentTopVisible(t *testing.T) {
	bodyCentered := regexp.MustCompile(`body\{[^}]*place-items:center`)
	mainCentered := regexp.MustCompile(`main\{[^}]*align-content:center`)
	for _, item := range TemplateLibrary() {
		t.Run(item.ID, func(t *testing.T) {
			html := strings.ToLower(item.HTML)
			if bodyCentered.MatchString(html) || mainCentered.MatchString(html) {
				t.Fatalf("template %s uses full-viewport centering that can hide long mobile content", item.ID)
			}
		})
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
