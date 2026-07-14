package bot

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/captcha"
	"golang.org/x/net/html"
)

const testPNGData = "data:image/png;base64," + "iVBORw0KGgo="

func TestBehaviorPageRendererSecurityAndContract(t *testing.T) {
	page := renderBehaviorPage(t, BehaviorPageInput{
		Challenge: captcha.BehaviorChallenge{Type: captcha.BehaviorCurveSlider, Token: `tok</script><script>alert(1)</script>`, Presentation: captcha.BehaviorPresentation{Kind: "curve_slider", Image: testPNGData, Piece: "data:image/png;base64," + base64.StdEncoding.EncodeToString([]byte("png"))}},
		Nonce:     "nonce-123", ReturnURL: `/done?x=</script><script>alert(2)</script>`, Method: "GET", Locale: "zh-CN",
	})
	doc := parseBehaviorPage(t, page)
	if got := attrByID(doc, "challenge-image", "src"); got != testPNGData {
		t.Fatalf("challenge image src = %q", got)
	}
	if got := attrByID(doc, "challenge-piece", "src"); !strings.HasPrefix(got, "data:image/png;base64,") {
		t.Fatalf("piece image src = %q", got)
	}
	for _, want := range []string{`nonce="nonce-123"`, `/.well-known/cheesewaf/challenge/v1/verify`, `location.replace`, `method:"POST"`} {
		if !strings.Contains(page, want) {
			t.Errorf("missing %q", want)
		}
	}
	for _, bad := range []string{`https://`, `http://`, `answer`, `tok</script>`, `/done?x=</script>`, `innerHTML=P.image`, `innerHTML=P.piece`} {
		if strings.Contains(page, bad) {
			t.Errorf("unsafe output %q", bad)
		}
	}
	if !strings.Contains(page, `\u003c/script\u003e`) {
		t.Fatal("JSON was not safely escaped")
	}
}

func TestBehaviorPageRejectsUnsupportedImageData(t *testing.T) {
	page := renderBehaviorPage(t, BehaviorPageInput{Challenge: captcha.BehaviorChallenge{Type: captcha.BehaviorShapeSlider, Presentation: captcha.BehaviorPresentation{Image: `data:text/html;base64,PHNjcmlwdD4=`, Piece: `data:image/svg+xml,%3Csvg%3E`}}})
	doc := parseBehaviorPage(t, page)
	if attrByID(doc, "challenge-image", "src") != "" || attrByID(doc, "challenge-piece", "src") != "" {
		t.Fatal("unsupported or non-base64 image data was rendered")
	}
}

func TestBehaviorPageRendererLocaleAndNonIdempotentSemantics(t *testing.T) {
	for _, tc := range []struct {
		locale string
		texts  []string
	}{
		{"zh-CN", []string{"验证您是真人", "正在检查您的浏览器", "验证"}},
		{"ja-JP", []string{"人間であることを確認", "ブラウザーを確認しています", "確認"}},
	} {
		page := renderBehaviorPage(t, BehaviorPageInput{Challenge: captcha.BehaviorChallenge{Type: captcha.BehaviorRotate, Token: "t", Presentation: captcha.BehaviorPresentation{Image: testPNGData}}, Locale: tc.locale, Method: "POST", ReturnURL: "/checkout"})
		for _, text := range tc.texts {
			if !strings.Contains(page, text) {
				t.Errorf("locale %s missing %q", tc.locale, text)
			}
		}
		if strings.Contains(page, `"Title":"???`) || strings.Contains(page, `"Checking":"???`) {
			t.Errorf("locale %s contains question-mark placeholders", tc.locale)
		}
		if !strings.Contains(page, `retryOriginal`) || !strings.Contains(page, `"idempotent":false`) {
			t.Fatal("non-idempotent state missing")
		}
	}
}

func TestBehaviorPageLocalizesTypeTitleAndDynamicPrompt(t *testing.T) {
	tests := []struct {
		name       string
		locale     string
		kind       captcha.BehaviorType
		prompt     string
		wantLocale string
		wantTitle  string
		wantPrompt string
	}{
		{"Chinese angle", "zh-CN", captcha.BehaviorAngle, "Select 137 degrees on the dial", "zh-CN", "\u89d2\u5ea6\u9009\u62e9", "\u8bf7\u5728\u523b\u5ea6\u76d8\u4e0a\u9009\u62e9 137 \u5ea6"},
		{"English text", "en-US", captcha.BehaviorTextClick, "Click character \u4e2d", "en-US", "Character selection", "Click character \u4e2d"},
		{"Japanese icon", "ja-JP", captcha.BehaviorIconClick, "Click the star icon", "ja-JP", "\u30a2\u30a4\u30b3\u30f3\u9078\u629e", "\u661f\u306e\u30a2\u30a4\u30b3\u30f3\u3092\u30af\u30ea\u30c3\u30af\u3057\u3066\u304f\u3060\u3055\u3044"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			page := renderBehaviorPage(t, BehaviorPageInput{
				Challenge: captcha.BehaviorChallenge{Type: tc.kind, Token: "opaque-token", Presentation: captcha.BehaviorPresentation{Kind: string(tc.kind), Prompt: tc.prompt, Image: testPNGData}},
				Locale:    tc.locale,
			})
			for _, want := range []string{`lang="` + tc.wantLocale + `"`, `"challengeTitle":"` + tc.wantTitle + `"`, `"prompt":"` + tc.wantPrompt + `"`, `"token":"opaque-token"`} {
				if !strings.Contains(page, want) {
					t.Errorf("page missing %q", want)
				}
			}
			if tc.locale != "en-US" && strings.Contains(page, `"prompt":"`+tc.prompt+`"`) {
				t.Errorf("prompt remained untranslated: %q", tc.prompt)
			}
		})
	}
}

func TestBehaviorPageHasTypeSpecificControls(t *testing.T) {
	page := renderBehaviorPage(t, BehaviorPageInput{Challenge: captcha.BehaviorChallenge{Type: captcha.BehaviorRandom, Token: "t", Presentation: captcha.BehaviorPresentation{Image: testPNGData, Piece: testPNGData}}})
	doc := parseBehaviorPage(t, page)
	for _, id := range []string{"challenge-image", "challenge-piece", "interaction-overlay", "scratch-canvas", "angle-overlay", "drag-handle", "slider-control", "unavailable"} {
		if findByID(doc, id) == nil {
			t.Errorf("missing control %q", id)
		}
	}
	script := scriptText(doc)
	for _, behaviorType := range []captcha.BehaviorType{captcha.BehaviorCurveDraw, captcha.BehaviorCurveSlider, captcha.BehaviorShapeSlider, captcha.BehaviorRestoreSlider, captcha.BehaviorRotate, captcha.BehaviorAngle, captcha.BehaviorScratch, captcha.BehaviorTextClick, captcha.BehaviorIconClick} {
		if !strings.Contains(script, `"`+string(behaviorType)+`"`) {
			t.Errorf("script has no controller for %s", behaviorType)
		}
	}
	for _, behavior := range []string{"marker.remove()", "scratchCanvas", "piece.style.transform", "strip.style.transform", "rotateObject.style.transform", "anglePointer.style.transform"} {
		if !strings.Contains(script, behavior) {
			t.Errorf("missing interactive behavior %q", behavior)
		}
	}
}

func TestBehaviorPageSuccessRequiresServerValid(t *testing.T) {
	script := scriptText(parseBehaviorPage(t, renderBehaviorPage(t, BehaviorPageInput{Challenge: captcha.BehaviorChallenge{Type: captcha.BehaviorPOW, Token: "t"}})))
	if !strings.Contains(script, `const valid=body.valid===true||(body.data&&body.data.valid===true)`) {
		t.Fatal("success is not gated on the server valid field")
	}
	if strings.Contains(script, `body.success===true`) {
		t.Fatal("success accepts a non-valid response")
	}
}

func TestBehaviorPageRotateAndAngleUsePresentationContract(t *testing.T) {
	script := behaviorPageScript(t, captcha.BehaviorRotate, captcha.BehaviorPresentation{Image: testPNGData, InitialAngle: 317, Track: map[string]int{"min_duration_ms": 275}})
	for _, want := range []string{`slider.max="10000"`, `normalizeAngle(Number(P.initial_angle||0)+value*360/10000)`, `response.angle=Math.round(angle)`, `response.track=[{x:0,y:5000,t:0,type:"down"},{x:value,y:5000,t:duration,type:"up"}]`, `response.duration_ms=duration`, `Math.max(0,Number((P.track||{}).min_duration_ms)||0)`} {
		if !strings.Contains(script, want) {
			t.Errorf("rotate/angle contract missing %q", want)
		}
	}
}

func TestBehaviorPageRestoreSliderSubmitsOffsetFromPresentation(t *testing.T) {
	script := behaviorPageScript(t, captcha.BehaviorRestoreSlider, captcha.BehaviorPresentation{Image: testPNGData, InitialOffset: -31, MaxOffset: 64, Track: map[string]int{"min_duration_ms": 180}})
	for _, want := range []string{`const initialOffset=Number(P.initial_offset||0),maxOffset=Math.max(0,Number(P.max_offset)||0),minDuration=Math.max(0,Number((P.track||{}).min_duration_ms)||0)`, `response.offset=Math.round((initialOffset+(value/10000)*2*maxOffset-maxOffset)*100)/100`, `strip.style.transform="translateX("+response.offset+"%)"`, `response.track=[{x:5000,y:5000,t:0,type:"down"},{x:value,y:5000,t:duration,type:"up"}]`, `response.duration_ms=duration`} {
		if !strings.Contains(script, want) {
			t.Errorf("restore slider contract missing %q", want)
		}
	}
}

func TestBehaviorPageTerminalResultsFreezeAndReloadWithGET(t *testing.T) {
	script := behaviorPageScript(t, captcha.BehaviorRotate, captcha.BehaviorPresentation{Image: testPNGData})
	for _, want := range []string{`let terminal=false`, `const freeze=()=>{terminal=true;available=false;active=false;verify.disabled=true;slider.disabled=true;overlay.style.pointerEvents="none";scratchCanvas.style.pointerEvents="none"}`, `const reloadChallenge=()=>setTimeout(()=>location.assign(S.returnURL||location.href),1000)`, `if(terminal||!available)return`, `if(!r.ok||!valid){freeze();status.className="status bad";status.textContent=body.expired?S.text.Expired:S.text.Failed;reloadChallenge();return}`, `freeze();status.className="status ok"`} {
		if !strings.Contains(script, want) {
			t.Errorf("terminal-state contract missing %q", want)
		}
	}
	if strings.Contains(script, `verify.disabled=false`) {
		t.Fatal("failed verification re-enables the consumed challenge")
	}
}

func TestBehaviorPageRendererAcceptLanguageFallback(t *testing.T) {
	page := renderBehaviorPage(t, BehaviorPageInput{Challenge: captcha.BehaviorChallenge{Type: captcha.BehaviorPOW, Token: "t"}, AcceptLanguage: "ja,en;q=0.8"})
	if !strings.Contains(page, `lang="ja-JP"`) {
		t.Fatal("Accept-Language was not applied")
	}
}

func renderBehaviorPage(t *testing.T, input BehaviorPageInput) string {
	t.Helper()
	page, err := NewBehaviorPageRenderer().RenderHTML(input)
	if err != nil {
		t.Fatal(err)
	}
	return page
}

func behaviorPageScript(t *testing.T, kind captcha.BehaviorType, presentation captcha.BehaviorPresentation) string {
	t.Helper()
	presentation.Kind = string(kind)
	return scriptText(parseBehaviorPage(t, renderBehaviorPage(t, BehaviorPageInput{Challenge: captcha.BehaviorChallenge{Type: kind, Token: "opaque-token", Presentation: presentation}, ReturnURL: "/protected/resource", Method: "GET"})))
}

func parseBehaviorPage(t *testing.T, page string) *html.Node {
	t.Helper()
	doc, err := html.Parse(strings.NewReader(page))
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func findByID(node *html.Node, id string) *html.Node {
	if node.Type == html.ElementNode {
		for _, attr := range node.Attr {
			if attr.Key == "id" && attr.Val == id {
				return node
			}
		}
	}
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		if found := findByID(child, id); found != nil {
			return found
		}
	}
	return nil
}

func attrByID(doc *html.Node, id, name string) string {
	node := findByID(doc, id)
	if node == nil {
		return ""
	}
	for _, attr := range node.Attr {
		if attr.Key == name {
			return attr.Val
		}
	}
	return ""
}

func scriptText(node *html.Node) string {
	var b strings.Builder
	var walk func(*html.Node)
	walk = func(current *html.Node) {
		if current.Type == html.ElementNode && current.Data == "script" && current.FirstChild != nil {
			b.WriteString(current.FirstChild.Data)
		}
		for child := current.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(node)
	return b.String()
}
