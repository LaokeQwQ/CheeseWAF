package semantic

import (
	"context"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

func analyze2026Value(t *testing.T, value string) *engine.DetectionResult {
	t.Helper()
	req := httptest.NewRequest("POST", "http://example.com/search?q="+url.QueryEscape(value), nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 test")
	reqCtx, err := engine.NewRequestContext(req, "site-test")
	if err != nil {
		t.Fatal(err)
	}
	result, err := NewAnalyzer("block", 2).Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func nestedQueryEscape(value string, depth int) string {
	for i := 0; i < depth; i++ {
		value = url.QueryEscape(value)
	}
	return value
}

func TestContextualSemantics2026NestedEncoding(t *testing.T) {
	value := nestedQueryEscape(`#set($x="")$x.getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null).exec("id")`, 8)
	result := analyze2026Value(t, value)
	if result == nil || !result.Detected {
		t.Fatalf("nested-encoded payload was not decoded: %+v value=%q", result, value)
	}
}

func TestContextualSemantics2026(t *testing.T) {
	cases := []struct {
		name     string
		value    string
		detected bool
	}{
		// Narrow, execution-reaching shapes.
		{"velocity-reflection", `#set($x="")$x.getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null).exec("id")`, true},
		{"velocity-classloader", `#set($x="")$x.getClass().getClassLoader().loadClass("java.lang.Runtime").getMethod("getRuntime").invoke(null).exec("id")`, true},
		{"spel-star-selector", `*{T(java.lang.Runtime).getRuntime().exec("id")}`, true},
		{"spel-at-selector", `@{T(java.lang.ProcessBuilder).start()}`, true},
		{"velocity-split-chain", `#set($c=$x.getClass())#set($rt=$c.forName("java.lang.Runtime"))#set($m=$rt.getMethod("getRuntime"))#set($r=$m.invoke(null))$r.exec("id")`, true},
		{"velocity-dotclass", `#set($x="")$x.class.forName("java.lang.Runtime").getMethod("getRuntime").invoke(null).exec("id")`, true},
		{"velocity-exploit-quoted-in-security-article-still-detected", `Security advisory example: #set($x="")$x.getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null).exec("id")`, true},
		{"ognl-context-runtime-remains-quarantined", `#context['x']=@java.lang.Runtime@getRuntime(); #context['x'].exec("id")`, false},
		// Generic Java reflection/process expressions have no template syntax;
		// keep them outside this narrow SSTI increment until a parser-backed rule
		// can establish that the value is evaluated by a template engine.
		{"class-forname", `Class.forName("java.lang.Runtime").getMethod("getRuntime").invoke(null).exec("id")`, false},
		{"script-engine", `T(javax.script.ScriptEngineManager).newInstance().getEngineByName("js").eval("java.lang.Runtime.getRuntime().exec('id')")`, false},
		{"process-builder", `new java.lang.ProcessBuilder("id").start()`, false},
		{"fullwidth-velocity-reflection", `＃ｓｅｔ($x="")$x.getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null).exec("id")`, true},
		{"long-value-velocity", strings.Repeat("A", 300) + `#set($x="")$x.getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null).exec("id")`, true},

		// Harmless reflection/type/link/document shapes.
		{"velocity-whitespace-set", `#set ($x="")$x.getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null).exec("id")`, true},
		{"velocity-set-only", `#set($x=1) in a Velocity template`, false},
		{"velocity-classloader-only", `#set($x="")$x.getClass().getClassLoader()`, false},
		{"velocity-string-forname", `#set($x="")$x.getClass().forName("java.lang.String")`, false},
		{"velocity-tostring-method", `#set($x="")$x.getClass().getMethod("toString")`, false},
		{"velocity-getmethod-documentation", `#set($x="")$x.getClass().forName("java.lang.Runtime").getMethod("getRuntime") is documented by the framework`, false},
		{"runtime-reflection-javadoc", `Runtime.getRuntime().getClass().getMethod("availableProcessors") is used in Java API documentation`, false},
		{"spel-arithmetic", `*{7*7} and @{7*7} are SpEL examples`, false},
		{"spel-type-only", `*{T(java.lang.ProcessBuilder)}`, false},
		{"thymeleaf-link", `@{/docs(java.lang.Runtime)}`, false},
		{"velocity-doc", `#set($x="")$x.getClass().forName("java.lang.Runtime") is documented as an example`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := analyze2026Value(t, tc.value)
			got := result != nil && result.Detected
			if got != tc.detected {
				t.Fatalf("detected=%v want=%v result=%+v value=%q", got, tc.detected, result, tc.value)
			}
		})
	}
}
