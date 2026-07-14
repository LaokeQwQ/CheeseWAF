package bot

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/captcha"
)

const behaviorVerifyEndpoint = "/.well-known/cheesewaf/challenge/v1/verify"

type BehaviorPageInput struct {
	Challenge      captcha.BehaviorChallenge
	Nonce          string
	ReturnURL      string
	Method         string
	Locale         string
	AcceptLanguage string
}

type BehaviorPageRenderer struct{ page *template.Template }

type behaviorPageState struct {
	Challenge      captcha.BehaviorChallenge `json:"challenge"`
	ChallengeTitle string                    `json:"challengeTitle"`
	ReturnURL      string                    `json:"returnURL"`
	Locale         string                    `json:"locale"`
	Idempotent     bool                      `json:"idempotent"`
	Text           behaviorPageText          `json:"text"`
}

type behaviorPageText struct {
	Title         string `json:"Title"`
	Checking      string `json:"Checking"`
	Verify        string `json:"Verify"`
	Success       string `json:"Success"`
	RetryOriginal string `json:"retryOriginal"`
	Failed        string `json:"Failed"`
	Expired       string `json:"Expired"`
	Working       string `json:"Working"`
	Hint          string `json:"Hint"`
	Unavailable   string `json:"Unavailable"`
}

type behaviorPageView struct {
	Lang, Nonce string
	State       template.JS
	Image       template.URL
	Piece       template.URL
}

func NewBehaviorPageRenderer() *BehaviorPageRenderer {
	return &BehaviorPageRenderer{page: template.Must(template.New("behavior").Parse(behaviorPageHTML))}
}

func (r *BehaviorPageRenderer) RenderHTML(in BehaviorPageInput) (string, error) {
	locale := behaviorLocale(in.Locale, in.AcceptLanguage)
	method := strings.ToUpper(strings.TrimSpace(in.Method))
	challenge := in.Challenge
	kind := challenge.Type
	if kind == captcha.BehaviorRandom && challenge.Presentation.Kind != "" {
		kind = captcha.BehaviorType(challenge.Presentation.Kind)
	}
	challenge.Presentation.Prompt = behaviorPrompt(locale, kind, challenge.Presentation.Prompt)
	state := behaviorPageState{Challenge: challenge, ChallengeTitle: behaviorTypeTitle(locale, kind), ReturnURL: in.ReturnURL, Locale: locale, Idempotent: method == "" || method == "GET" || method == "HEAD", Text: behaviorText(locale)}
	data, err := json.Marshal(state)
	if err != nil {
		return "", err
	}
	var out bytes.Buffer
	err = r.page.Execute(&out, behaviorPageView{Lang: locale, Nonce: in.Nonce, State: template.JS(data), Image: safeBehaviorImage(in.Challenge.Presentation.Image), Piece: safeBehaviorImage(in.Challenge.Presentation.Piece)})
	return out.String(), err
}

func safeBehaviorImage(value string) template.URL {
	comma := strings.IndexByte(value, ',')
	if comma <= 0 {
		return ""
	}
	mediaType := strings.ToLower(value[:comma])
	switch mediaType {
	case "data:image/png;base64", "data:image/jpeg;base64", "data:image/jpg;base64", "data:image/gif;base64", "data:image/webp;base64", "data:image/avif;base64":
	default:
		return ""
	}
	encoded := value[comma+1:]
	if encoded == "" {
		return ""
	}
	if _, err := base64.StdEncoding.DecodeString(encoded); err != nil {
		return ""
	}
	return template.URL(value)
}

func behaviorLocale(explicit, accept string) string {
	s := strings.ToLower(strings.TrimSpace(explicit))
	if s == "" {
		s = strings.ToLower(strings.TrimSpace(strings.Split(accept, ",")[0]))
	}
	switch {
	case strings.HasPrefix(s, "zh"):
		return "zh-CN"
	case strings.HasPrefix(s, "ja"):
		return "ja-JP"
	default:
		return "en-US"
	}
}

func behaviorText(locale string) behaviorPageText {
	switch locale {
	case "zh-CN":
		return behaviorPageText{"验证您是真人", "正在检查您的浏览器", "验证", "验证完成", "验证已通过，请重新提交原请求", "验证失败，请重试", "挑战已过期，请刷新页面", "正在验证...", "请完成下方操作", "此挑战缺少可用的题面数据，请刷新页面"}
	case "ja-JP":
		return behaviorPageText{"人間であることを確認", "ブラウザーを確認しています", "確認", "確認が完了しました", "確認に成功しました。元の操作をもう一度実行してください", "確認に失敗しました。もう一度お試しください", "チャレンジの期限が切れました。ページを更新してください", "確認しています...", "下の操作を完了してください", "このチャレンジには表示用データがありません。ページを更新してください"}
	default:
		return behaviorPageText{"Verify you are human", "Checking your browser", "Verify", "Verification complete", "Verification passed. Please retry the original request", "Verification failed. Try again", "Challenge expired. Refresh the page", "Verifying...", "Complete the action below", "This challenge is missing usable presentation data. Refresh the page"}
	}
}

func behaviorTypeTitle(locale string, kind captcha.BehaviorType) string {
	titles := map[captcha.BehaviorType][3]string{
		captcha.BehaviorPOW:           {"工作量证明", "Proof of work", "プルーフ・オブ・ワーク"},
		captcha.BehaviorRotate:        {"旋转校正", "Rotation", "回転調整"},
		captcha.BehaviorAngle:         {"角度选择", "Angle selection", "角度選択"},
		captcha.BehaviorTextClick:     {"文字选择", "Character selection", "文字選択"},
		captcha.BehaviorIconClick:     {"图标选择", "Icon selection", "アイコン選択"},
		captcha.BehaviorCurveDraw:     {"曲线描摹", "Curve tracing", "曲線トレース"},
		captcha.BehaviorCurveSlider:   {"曲线滑块", "Curve slider", "曲線スライダー"},
		captcha.BehaviorShapeSlider:   {"拼图滑块", "Puzzle slider", "パズルスライダー"},
		captcha.BehaviorRestoreSlider: {"图像复原", "Image restoration", "画像復元"},
		captcha.BehaviorScratch:       {"刮除验证", "Scratch verification", "スクラッチ認証"},
	}
	values, ok := titles[kind]
	if !ok {
		values = [3]string{"行为验证", "Behavior challenge", "操作認証"}
	}
	switch locale {
	case "zh-CN":
		return values[0]
	case "ja-JP":
		return values[2]
	default:
		return values[1]
	}
}

func behaviorPrompt(locale string, kind captcha.BehaviorType, prompt string) string {
	if locale == "en-US" || strings.TrimSpace(prompt) == "" {
		return prompt
	}
	static := map[captcha.BehaviorType][2]string{
		captcha.BehaviorPOW:           {"计算满足工作量证明目标的随机数", "プルーフ・オブ・ワーク条件を満たす nonce を計算してください"},
		captcha.BehaviorRotate:        {"旋转箭头，使其垂直向上", "矢印が真上を向くまで回転してください"},
		captcha.BehaviorCurveDraw:     {"从圆点开始，沿可见曲线描摹到箭头处", "点から矢印まで、表示された曲線をなぞってください"},
		captcha.BehaviorCurveSlider:   {"沿可见轨道将滑块拖到最末端", "表示された軌道に沿ってハンドルを端までドラッグしてください"},
		captcha.BehaviorShapeSlider:   {"将松散的拼图块拖入匹配的缺口", "パズルピースを一致する切り抜き部分へドラッグしてください"},
		captcha.BehaviorRestoreSlider: {"滑动错位的中间条带，直到图像对齐", "ずれた中央の帯をスライドして画像を揃えてください"},
		captcha.BehaviorScratch:       {"刮除大部分银色遮盖层以显示代码", "銀色のパネルを十分に削ってコードを表示してください"},
	}
	index := 0
	if locale == "ja-JP" {
		index = 1
	}
	if values, ok := static[kind]; ok {
		return values[index]
	}
	switch kind {
	case captcha.BehaviorAngle:
		if value, ok := between(prompt, "Select ", " degrees on the dial"); ok {
			if locale == "zh-CN" {
				return fmt.Sprintf("请在刻度盘上选择 %s 度", value)
			}
			return fmt.Sprintf("ダイヤルで %s 度を選択してください", value)
		}
	case captcha.BehaviorTextClick:
		if value := strings.TrimPrefix(prompt, "Click character "); value != prompt && value != "" {
			if locale == "zh-CN" {
				return "请点击字符 " + value
			}
			return "文字 " + value + " をクリックしてください"
		}
	case captcha.BehaviorIconClick:
		if value, ok := between(prompt, "Click the ", " icon"); ok {
			value = behaviorIconName(locale, value)
			if locale == "zh-CN" {
				return "请点击" + value + "图标"
			}
			return value + "のアイコンをクリックしてください"
		}
	}
	return prompt
}

func between(value, prefix, suffix string) (string, bool) {
	if !strings.HasPrefix(value, prefix) || !strings.HasSuffix(value, suffix) {
		return "", false
	}
	middle := strings.TrimSuffix(strings.TrimPrefix(value, prefix), suffix)
	return middle, middle != ""
}

func behaviorIconName(locale, name string) string {
	names := map[string][2]string{
		"star": {"星形", "星"}, "heart": {"心形", "ハート"}, "diamond": {"菱形", "ひし形"},
		"triangle": {"三角形", "三角形"}, "square": {"正方形", "正方形"}, "circle": {"圆形", "円"},
		"flag": {"旗帜", "旗"}, "bolt": {"闪电", "稲妻"},
	}
	values, ok := names[name]
	if !ok {
		return name
	}
	if locale == "ja-JP" {
		return values[1]
	}
	return values[0]
}

const behaviorPageHTML = `<!doctype html><html lang="{{.Lang}}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><title>CheeseWAF</title><style nonce="{{.Nonce}}">
:root{color-scheme:light;--ink:#202124;--muted:#667085;--line:#d9dde5;--accent:#1769e0;--bad:#b42318;--ok:#16803a}*{box-sizing:border-box}body{margin:0;min-height:100svh;display:grid;place-items:center;background:#f7f8fa;color:var(--ink);font:15px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif}.shell{width:min(92vw,430px);padding:28px 24px;background:#fff;border:1px solid var(--line);border-radius:8px;box-shadow:0 10px 28px #18223012}header{display:flex;align-items:center;gap:12px;margin-bottom:20px}.mark{width:36px;height:36px;display:grid;place-items:center;border:2px solid var(--accent);border-radius:50%;color:var(--accent);font-weight:700}h1{font-size:20px;margin:0;letter-spacing:0}p{margin:4px 0;color:var(--muted)}#stage{position:relative;overflow:hidden;width:100%;aspect-ratio:20/11;border:1px solid var(--line);border-radius:6px;background:#f1f3f6;touch-action:none;user-select:none}#challenge-image,#rotate-object{position:absolute;inset:0;width:100%;height:100%;object-fit:fill;display:block}.layer{position:absolute;inset:0}.hidden{display:none!important}#interaction-overlay{cursor:crosshair}#challenge-piece{position:absolute;width:20%;height:auto;left:4%;top:34%;z-index:3;filter:drop-shadow(0 2px 2px #0005)}#drag-handle{position:absolute;width:26px;height:26px;margin:-13px;border:3px solid #fff;border-radius:50%;background:var(--accent);box-shadow:0 1px 5px #0007;z-index:4;pointer-events:none}#restore-strip{position:absolute;left:5%;right:5%;top:35.45%;height:29.1%;overflow:hidden;z-index:2;pointer-events:none}#restore-strip img{position:absolute;left:-5.56%;top:-121.9%;width:111.12%;height:343.75%;max-width:none}.slider{width:100%;margin:18px 0 4px;accent-color:var(--accent)}#angle-overlay{pointer-events:none}#angle-pointer{position:absolute;left:50%;top:50%;width:3px;height:38%;background:#d02f2f;transform-origin:50% 100%;transform:translate(-50%,-100%) rotate(0deg);border-radius:2px}#scratch-canvas{width:100%;height:100%;cursor:crosshair}.click-dot{position:absolute;width:28px;height:28px;margin:-14px;border-radius:50%;background:#1769e033;border:2px solid var(--accent);z-index:5}.click-dot::after{content:attr(data-order);display:grid;place-items:center;height:100%;font-size:12px;font-style:normal;color:#0b438f}.tiles{position:absolute;inset:0;display:grid;grid-template-columns:repeat(3,1fr);gap:2px;background:#fff}.tile{position:relative;overflow:hidden;margin:0;min-height:0;border:0;border-radius:0;background:#e8edf5;padding:0}.tile span{position:absolute;inset:0;background-repeat:no-repeat;background-size:300% 300%}.tile.selected{outline:3px solid var(--accent);outline-offset:-3px;z-index:2}#unavailable{position:absolute;inset:0;display:grid;place-items:center;padding:24px;text-align:center;color:var(--bad);background:#fff}button#verify{min-height:44px;width:100%;margin-top:14px;border:0;border-radius:6px;background:var(--accent);color:#fff;font:600 15px inherit;cursor:pointer}button:disabled{opacity:.58;cursor:wait}.status{min-height:24px;margin-top:12px;text-align:center}.status.bad{color:var(--bad)}.status.ok{color:var(--ok)}@media(max-width:480px){.shell{width:100%;min-height:100svh;border:0;border-radius:0;padding:24px 18px;box-shadow:none}}@media(prefers-reduced-motion:reduce){*{scroll-behavior:auto!important;animation:none!important;transition:none!important}}
</style></head><body><main class="shell"><header><div class="mark" aria-hidden="true">C</div><div><h1 id="title"></h1><p id="checking"></p></div></header><p id="prompt"></p><div id="stage" role="application" tabindex="0" aria-describedby="prompt"><img id="challenge-image"{{if .Image}} src="{{.Image}}"{{end}} alt=""><div id="rotate-object" class="layer"></div><div id="restore-strip" class="hidden"><img id="restore-strip-image"{{if .Image}} src="{{.Image}}"{{end}} alt=""></div><img id="challenge-piece" class="hidden"{{if .Piece}} src="{{.Piece}}"{{end}} alt=""><div id="interaction-overlay" class="layer"></div><canvas id="scratch-canvas" class="layer hidden"></canvas><div id="angle-overlay" class="layer hidden"><i id="angle-pointer"></i></div><i id="drag-handle" class="hidden"></i><div id="unavailable" class="hidden"></div></div><div id="control"><input id="slider-control" class="slider hidden" type="range" min="0" max="10000" value="0"></div><button id="verify" type="button"></button><div id="status" class="status" role="status" aria-live="polite"></div></main><script nonce="{{.Nonce}}">const S={{.State}};
(()=>{"use strict";const $=id=>document.getElementById(id),stage=$("stage"),image=$("challenge-image"),piece=$("challenge-piece"),overlay=$("interaction-overlay"),scratchCanvas=$("scratch-canvas"),angleOverlay=$("angle-overlay"),anglePointer=$("angle-pointer"),dragHandle=$("drag-handle"),slider=$("slider-control"),unavailable=$("unavailable"),restoreStrip=$("restore-strip"),strip=$("restore-strip-image"),status=$("status"),verify=$("verify"),C=S.challenge,P=C.presentation||{},type=C.type==="random"?(P.kind||"random"):C.type;$("title").textContent=S.challengeTitle||S.text.Title;$("checking").textContent=S.text.Checking;$("prompt").textContent=P.prompt||S.text.Hint;verify.textContent=S.text.Verify;unavailable.textContent=S.text.Unavailable;
const response={token:C.token},track=[],points=[],markers=[];let start=0,active=false,available=true,dragStart=null;let terminal=false;const clamp=n=>Math.max(0,Math.min(10000,Math.round(n))),coord=e=>{const r=stage.getBoundingClientRect();return{x:clamp((e.clientX-r.left)*10000/r.width),y:clamp((e.clientY-r.top)*10000/r.height)}};const add=(q,k)=>{if(track.length<128)track.push({x:q.x,y:q.y,t:Math.max(0,Math.round(performance.now()-start)),type:k})};const showUnavailable=()=>{available=false;unavailable.classList.remove("hidden");overlay.classList.add("hidden");verify.disabled=true};const needImage=()=>{if(!image.getAttribute("src")){showUnavailable();return false}return true};const freeze=()=>{terminal=true;available=false;active=false;verify.disabled=true;slider.disabled=true;overlay.style.pointerEvents="none";scratchCanvas.style.pointerEvents="none"};const reloadChallenge=()=>setTimeout(()=>location.assign(S.returnURL||location.href),1000);
function beginPointer(e){active=true;start=performance.now();track.length=0;dragStart=coord(e);overlay.setPointerCapture(e.pointerId);add(dragStart,"down")}function endPointer(e){if(!active)return;const q=coord(e);add(q,"up");active=false;response.point=q;response.track=track.slice();response.duration_ms=Math.round(performance.now()-start)}
function bindTrack(move){overlay.addEventListener("pointerdown",beginPointer);overlay.addEventListener("pointermove",e=>{if(!active)return;const q=coord(e);add(q,"move");move(q)});overlay.addEventListener("pointerup",e=>{if(!active)return;const q=coord(e);move(q);endPointer(e)});overlay.addEventListener("pointercancel",()=>{active=false;track.length=0;delete response.track})}
function moveHandle(q){dragHandle.classList.remove("hidden");dragHandle.style.left=(q.x/100)+"%";dragHandle.style.top=(q.y/100)+"%"}
function setupContinuous(){if(!needImage())return;if(type==="curve_draw"){bindTrack(()=>{})}else if(type==="curve_slider"){moveHandle({x:900,y:6500});bindTrack(moveHandle)}else if(type==="shape_slider"){if(!piece.getAttribute("src")){showUnavailable();return}piece.classList.remove("hidden");bindTrack(q=>{const dx=q.x-(dragStart?dragStart.x:0),dy=q.y-(dragStart?dragStart.y:0);piece.style.transform="translate("+(dx/100)+"%,"+(dy/100)+"%)"})}else if(type==="restore_slider"){restoreStrip.classList.remove("hidden");slider.classList.remove("hidden");slider.max="10000";slider.value="5000";const initialOffset=Number(P.initial_offset||0),maxOffset=Math.max(0,Number(P.max_offset)||0),minDuration=Math.max(0,Number((P.track||{}).min_duration_ms)||0);const update=()=>{const value=clamp(Number(slider.value)),duration=Math.max(minDuration,Math.round(performance.now()-start));response.offset=Math.round((initialOffset+(value/10000)*2*maxOffset-maxOffset)*100)/100;response.track=[{x:5000,y:5000,t:0,type:"down"},{x:value,y:5000,t:duration,type:"up"}];response.duration_ms=duration;strip.style.transform="translateX("+response.offset+"%)"};slider.onpointerdown=()=>{if(terminal)return;start=performance.now()};slider.oninput=update;slider.onchange=update;update()}}
function setupAngle(){if(!needImage())return;slider.classList.remove("hidden");slider.max="10000";slider.value="0";slider.setAttribute("aria-label",P.prompt||S.text.Hint);const rotateObject=image,normalizeAngle=value=>((value%360)+360)%360,minDuration=Math.max(0,Number((P.track||{}).min_duration_ms)||0),update=()=>{const value=clamp(Number(slider.value)),angle=normalizeAngle(Number(P.initial_angle||0)+value*360/10000),duration=Math.max(minDuration,Math.round(performance.now()-start));response.angle=Math.round(angle);response.track=[{x:0,y:5000,t:0,type:"down"},{x:value,y:5000,t:duration,type:"up"}];response.duration_ms=duration;if(type==="rotate")rotateObject.style.transform="rotate("+angle+"deg)";else anglePointer.style.transform="translate(-50%,-100%) rotate("+angle+"deg)"};slider.onpointerdown=()=>{if(terminal)return;start=performance.now()};slider.oninput=update;slider.onchange=update;if(type==="angle")angleOverlay.classList.remove("hidden");update()}
function setupClicks(){if(!needImage())return;overlay.addEventListener("pointerup",e=>{const q=coord(e),marker=document.createElement("i");marker.className="click-dot";marker.style.left=(q.x/100)+"%";marker.style.top=(q.y/100)+"%";marker.addEventListener("pointerup",event=>{event.stopPropagation();const index=markers.indexOf(marker);if(index<0)return;markers.splice(index,1);points.splice(index,1);marker.remove();delete response.point});if(markers.length){markers[0].remove();markers.length=0;points.length=0}markers.push(marker);points.push(q);overlay.appendChild(marker);response.point=q})}
function setupScratch(){if(!needImage())return;overlay.classList.add("hidden");scratchCanvas.classList.remove("hidden");const ctx=scratchCanvas.getContext("2d");const resize=()=>{scratchCanvas.width=Math.max(1,Math.round(stage.clientWidth*devicePixelRatio));scratchCanvas.height=Math.max(1,Math.round(stage.clientHeight*devicePixelRatio));ctx.setTransform(devicePixelRatio,0,0,devicePixelRatio,0,0);ctx.fillStyle="#aeb6bd";ctx.fillRect(stage.clientWidth*.22,stage.clientHeight*.28,stage.clientWidth*.56,stage.clientHeight*.44)};resize();const scratch=e=>{const q=coord(e),r=stage.getBoundingClientRect();ctx.save();ctx.globalCompositeOperation="destination-out";ctx.beginPath();ctx.arc(e.clientX-r.left,e.clientY-r.top,18,0,Math.PI*2);ctx.fill();ctx.restore();add(q,"move")};scratchCanvas.addEventListener("pointerdown",e=>{active=true;start=performance.now();track.length=0;scratchCanvas.setPointerCapture(e.pointerId);add(coord(e),"down");scratch(e)});scratchCanvas.addEventListener("pointermove",e=>{if(active)scratch(e)});scratchCanvas.addEventListener("pointerup",e=>{if(!active)return;scratch(e);const q=coord(e);add(q,"up");active=false;response.point=q;response.track=track.slice();response.duration_ms=Math.round(performance.now()-start)})}
if(["curve_draw","curve_slider","shape_slider","restore_slider"].includes(type))setupContinuous();else if(["rotate","angle"].includes(type))setupAngle();else if(["text_click","icon_click"].includes(type))setupClicks();else if(type==="scratch")setupScratch();else if(type!=="pow")showUnavailable();
stage.addEventListener("keydown",e=>{if(!available||!["ArrowLeft","ArrowRight","ArrowUp","ArrowDown","Enter"," "].includes(e.key))return;e.preventDefault();const step=e.shiftKey?500:100,q=response.point||{x:5000,y:5000};if(e.key==="ArrowLeft")q.x-=step;if(e.key==="ArrowRight")q.x+=step;if(e.key==="ArrowUp")q.y-=step;if(e.key==="ArrowDown")q.y+=step;q.x=clamp(q.x);q.y=clamp(q.y);response.point=q;moveHandle(q)});
async function pow(){const salt=P.pow_salt||"",bits=P.pow_difficulty||0;if(!salt||!bits)return "";for(let n=0;n<2000000;n++){const v=String(n),buf=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(salt+":"+v)),a=new Uint8Array(buf);let z=0;for(const b of a){if(b===0){z+=8;continue}z+=Math.clz32(b)-24;break}if(z>=bits)return v}return ""}
verify.onclick=async()=>{if(terminal||!available)return;verify.disabled=true;status.className="status";status.textContent=S.text.Working;try{if(type==="pow")response.proof=await pow();const r=await fetch("` + behaviorVerifyEndpoint + `",{method:"POST",headers:{"Content-Type":"application/json","Accept":"application/json"},credentials:"same-origin",cache:"no-store",body:JSON.stringify(response)});let body={};try{body=await r.json()}catch{}const valid=body.valid===true||(body.data&&body.data.valid===true);if(!r.ok||!valid){freeze();status.className="status bad";status.textContent=body.expired?S.text.Expired:S.text.Failed;reloadChallenge();return}freeze();status.className="status ok";status.textContent=S.idempotent?S.text.Success:S.text.RetryOriginal;if(S.idempotent)location.replace(S.returnURL||location.href)}catch(e){freeze();status.className="status bad";status.textContent=S.text.Failed;reloadChallenge()}};
})();</script></body></html>`
