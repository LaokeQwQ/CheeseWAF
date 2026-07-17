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
	for _, want := range []string{
		"CheeseWAF", "Security response", "Access was blocked", "When contacting support",
		"Event / Trace ID", "cw-visible", "sqli", "198.51.100.9", "403 Forbidden", "Blocked",
		"Your IP", "Performance &amp; security by", "© CheeseCloud Technology",
		"https://github.com/LaokeQwQ/CheeseWAF", "cw-ft-shield",
	} {
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

func TestErrorTemplateLocalizesFromAcceptLanguage(t *testing.T) {
	tests := []struct {
		name   string
		accept string
		locale string
		want   []string
	}{
		{
			name:   "zh-CN",
			accept: "zh-CN,zh;q=0.9,en;q=0.1",
			locale: "zh-CN",
			want:   []string{`<html lang="zh-CN"`, "服务错误", "受保护服务返回错误", "CheeseWAF 未能完成对受保护源站的请求。", "错误已记录", "已记录"},
		},
		{
			name:   "ja",
			accept: "ja,en;q=0.5",
			locale: "ja",
			want:   []string{`<html lang="ja"`, "サービスエラー", "保護対象サービスでエラーが発生しました", "CheeseWAF は保護対象オリジンへのリクエストを完了できませんでした。", "エラー記録済み", "記録済み"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			renderer := NewRenderer()
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "https://example.test/upstream", nil)
			req.Header.Set("Accept-Language", tt.accept)
			renderer.RenderRequest(recorder, req, http.StatusBadGateway, Data{
				TraceID:    "cw-error-visible",
				AttackType: "upstream_error",
				ClientIP:   "198.51.100.11",
				Timestamp:  time.Unix(0, 0).UTC(),
			})
			if recorder.Header().Get("Content-Language") != tt.locale {
				t.Fatalf("expected %s content language, got %q", tt.locale, recorder.Header().Get("Content-Language"))
			}
			body := recorder.Body.String()
			for _, want := range append(tt.want, "cw-error-visible", "502 Bad Gateway") {
				if !strings.Contains(body, want) {
					t.Fatalf("localized error page missing %q in %s", want, body)
				}
			}
		})
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

func TestTimezoneCanInferLocaleWhenAcceptLanguageIsMissing(t *testing.T) {
	renderer := NewRenderer()
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://example.test/blocked", nil)
	req.Header.Set("CloudFront-Viewer-Time-Zone", "Asia/Tokyo")
	renderer.RenderRequest(recorder, req, http.StatusForbidden, Data{
		TraceID:   "cw-tz-ja",
		Timestamp: time.Unix(0, 0).UTC(),
	})
	body := recorder.Body.String()
	if recorder.Header().Get("Content-Language") != "ja" {
		t.Fatalf("expected ja from timezone fallback, got %q", recorder.Header().Get("Content-Language"))
	}
	if !strings.Contains(body, `lang="ja"`) || !strings.Contains(body, "アクセスがブロックされました") {
		t.Fatalf("timezone fallback did not localize body to Japanese: %s", body)
	}
}

func TestAcceptLanguageOverridesTimezoneLocaleInference(t *testing.T) {
	renderer := NewRenderer()
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://example.test/blocked", nil)
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("X-Timezone", "Asia/Tokyo")
	renderer.RenderRequest(recorder, req, http.StatusForbidden, Data{
		TraceID:   "cw-en-in-tokyo",
		Timestamp: time.Unix(0, 0).UTC(),
	})
	body := recorder.Body.String()
	if recorder.Header().Get("Content-Language") != "en" {
		t.Fatalf("expected Accept-Language to win over timezone, got %q", recorder.Header().Get("Content-Language"))
	}
	if !strings.Contains(body, `<html lang="en"`) || !strings.Contains(body, `<h1 data-i18n="headline">Access was blocked</h1>`) {
		t.Fatalf("Accept-Language did not override timezone inference: %s", body)
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

func TestLegacyStaticCustomHTMLFallsBackToLocalizedBuiltInTemplate(t *testing.T) {
	renderer, err := NewRendererFromConfig(config.BlockPageConfig{
		TemplateID:    "minimal",
		CustomEnabled: true,
		CustomHTML: `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Request blocked | CheeseWAF</title>
</head>
<body>
  <h1>Request could not be completed</h1>
  <p>{{if .Message}}{{.Message}}{{else}}The request was stopped by an active CheeseWAF security policy before it reached the protected origin.{{end}}</p>
  <span class="value">{{.Timestamp.Format "2006-01-02 15:04:05 UTC"}}</span>
  <footer>This page was generated by CheeseWAF. The Event / Trace ID maps to the corresponding security or upstream error event in the WAF logs.</footer>
</body>
</html>`,
	})
	if err != nil {
		t.Fatalf("new renderer: %v", err)
	}
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://example.test/blocked", nil)
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.1")
	req.Header.Set("X-Timezone", "Asia/Shanghai")
	renderer.RenderRequest(recorder, req, http.StatusForbidden, Data{
		TraceID:    "cw-legacy-custom",
		AttackType: "sqli",
		ClientIP:   "198.51.100.22",
		Timestamp:  time.Date(2026, 6, 14, 0, 30, 0, 0, time.UTC),
	})
	body := recorder.Body.String()
	for _, want := range []string{`<html lang="zh-CN"`, "访问已被拦截", "安全策略已执行", "Asia/Shanghai", "2026-06-14 08:30:00"} {
		if !strings.Contains(body, want) {
			t.Fatalf("legacy static custom page was not replaced with localized built-in template, missing %q in %s", want, body)
		}
	}
	if strings.Contains(body, "Request could not be completed") || strings.Contains(body, "2006-01-02 15:04:05 UTC") {
		t.Fatalf("legacy static English custom HTML leaked into localized response: %s", body)
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

func TestRendererInjectsBrowserLanguageRuntimeForBuiltInTemplates(t *testing.T) {
	for _, templateID := range []string{"minimal", "brand", "technical"} {
		t.Run(templateID, func(t *testing.T) {
			renderer, err := NewRendererFromConfig(config.BlockPageConfig{TemplateID: templateID})
			if err != nil {
				t.Fatalf("new renderer: %v", err)
			}
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "https://example.test/blocked", nil)
			req.Header.Set("Accept-Language", "en-US,en;q=0.9")
			renderer.RenderRequest(recorder, req, http.StatusForbidden, Data{
				TraceID:   "cw-browser-locale-" + templateID,
				Timestamp: time.Unix(0, 0).UTC(),
			})
			body := recorder.Body.String()
			for _, want := range []string{"cw-language-runtime", "navigator.languages", "zh-CN", "ja", "document.documentElement.lang"} {
				if !strings.Contains(body, want) {
					t.Fatalf("template %s missing browser language runtime marker %q in %s", templateID, want, body)
				}
			}
		})
	}
}

func TestRendererInjectsBrowserLanguageRuntimeForCustomHTML(t *testing.T) {
	renderer, err := NewRendererFromConfig(config.BlockPageConfig{
		TemplateID:    "minimal",
		CustomEnabled: true,
		CustomHTML:    `<html lang="en"><head><title>Request blocked | CheeseWAF</title></head><body><h1>Access was blocked</h1><p>Event / Trace ID</p><main>{{.EventID}}</main></body></html>`,
	})
	if err != nil {
		t.Fatalf("new renderer: %v", err)
	}
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://example.test/blocked", nil)
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	renderer.RenderRequest(recorder, req, http.StatusForbidden, Data{
		TraceID:   "cw-custom-runtime",
		Timestamp: time.Unix(0, 0).UTC(),
	})
	body := recorder.Body.String()
	for _, want := range []string{"cw-language-runtime", "navigator.languages", "Access was blocked", "访问已被拦截", "アクセスがブロックされました"} {
		if !strings.Contains(body, want) {
			t.Fatalf("custom template missing browser language runtime marker %q in %s", want, body)
		}
	}
	if !strings.Contains(body, "cw-custom-runtime") {
		t.Fatalf("custom runtime page lost event id: %s", body)
	}
}
