package captcha

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"
)

const browserHarnessProtocolPrefix = "CHEESEWAF_CAPTCHA_BROWSER "

type browserHarnessScenario struct {
	Name    string
	Kind    BehaviorType
	Version int
}

var browserHarnessScenarios = []browserHarnessScenario{
	{Name: "curve_draw", Kind: BehaviorCurveDraw, Version: 3},
	{Name: "curve_slider", Kind: BehaviorCurveSlider, Version: 3},
	{Name: "shape_slider", Kind: BehaviorShapeSlider, Version: 2},
	{Name: "rotate", Kind: BehaviorRotate, Version: 3},
	{Name: "restore_slider", Kind: BehaviorRestoreSlider, Version: 3},
	{Name: "angle", Kind: BehaviorAngle, Version: 3},
	{Name: "scratch", Kind: BehaviorScratch, Version: 3},
	{Name: "text_click", Kind: BehaviorTextClick, Version: 3},
	{Name: "icon_click", Kind: BehaviorIconClick, Version: 3},
}

// Keep the older fixed lifecycle registry on the same version used by CAPTCHA Lab.
func init() {
	for index := range harnessScenarios {
		if harnessScenarios[index].name == "shape_slider" {
			harnessScenarios[index].version = 2
		}
	}
}

type browserHarnessAction struct {
	Value *int            `json:"value,omitempty"`
	Path  []BehaviorPoint `json:"path,omitempty"`
	At    *BehaviorPoint  `json:"at,omitempty"`
}

type browserHarnessPlan struct {
	Interaction string               `json:"interaction"`
	Correct     browserHarnessAction `json:"correct"`
	Wrong       browserHarnessAction `json:"wrong"`
}

type browserHarnessFixture struct {
	opts      BehaviorOptions
	challenge BehaviorChallenge
	opened    behaviorToken
	used      bool
}

type browserHarnessState struct {
	secret   string
	sequence uint64
	byHandle map[string]*browserHarnessFixture
	byToken  map[string]*browserHarnessFixture
}

type browserHarnessRequest struct {
	ID       uint64           `json:"id"`
	Action   string           `json:"action"`
	Scenario string           `json:"scenario,omitempty"`
	Handle   string           `json:"handle,omitempty"`
	Response BehaviorResponse `json:"response,omitempty"`
}

type browserHarnessReply struct {
	ID        uint64              `json:"id,omitempty"`
	OK        bool                `json:"ok"`
	Ready     bool                `json:"ready,omitempty"`
	Error     string              `json:"error,omitempty"`
	Handle    string              `json:"handle,omitempty"`
	Challenge *BehaviorChallenge  `json:"challenge,omitempty"`
	Plan      *browserHarnessPlan `json:"plan,omitempty"`
	Status    int                 `json:"status,omitempty"`
	Result    *BehaviorResult     `json:"result,omitempty"`
	Code      string              `json:"code,omitempty"`
}

func TestBehaviorFixedHarnessShapeMatchesLabV2(t *testing.T) {
	for _, scenario := range harnessScenarios {
		if scenario.name == "shape_slider" {
			if scenario.version != 2 {
				t.Fatal("shape_slider fixed fixture version differs from CAPTCHA Lab")
			}
			return
		}
	}
	t.Fatal("shape_slider fixed fixture is missing")
}

func TestBehaviorBrowserHarnessRegistry(t *testing.T) {
	want := map[string]int{
		"curve_draw": 3, "curve_slider": 3, "shape_slider": 2, "rotate": 3,
		"restore_slider": 3, "angle": 3, "scratch": 3,
		"text_click": 3, "icon_click": 3,
	}
	if len(browserHarnessScenarios) != len(want) {
		t.Fatalf("browser fixture scenario count=%d", len(browserHarnessScenarios))
	}
	seenKinds := map[BehaviorType]bool{}
	for _, scenario := range browserHarnessScenarios {
		version, ok := want[scenario.Name]
		if !ok || version != scenario.Version {
			t.Fatalf("browser fixture registry mismatch for %s", scenario.Name)
		}
		delete(want, scenario.Name)
		seenKinds[scenario.Kind] = true
	}
	if len(want) != 0 {
		missing := make([]string, 0, len(want))
		for name := range want {
			missing = append(missing, name)
		}
		sort.Strings(missing)
		t.Fatalf("browser fixture registry is incomplete: %v", missing)
	}
	for _, kind := range concreteBehaviorTypes {
		if kind != BehaviorPOW && !seenKinds[kind] {
			t.Fatalf("browser fixture does not cover %s", kind)
		}
	}
}

func TestBehaviorBrowserHarnessPlansExerciseVerifier(t *testing.T) {
	state, err := newBrowserHarnessState()
	if err != nil {
		t.Fatal("browser fixture initialization failed")
	}
	for _, scenario := range browserHarnessScenarios {
		wrongFixture, _, err := state.issue(scenario.Name)
		if err != nil {
			t.Fatalf("%s fixture issue failed", scenario.Name)
		}
		plan := makeBrowserHarnessPlan(wrongFixture)
		wrongResponse := browserHarnessResponse(wrongFixture, plan.Interaction, plan.Wrong)
		status, result, _ := state.verify(wrongResponse)
		if status != 200 || result.Valid {
			t.Fatalf("%s wrong lifecycle failed", scenario.Name)
		}
		status, _, code := state.verify(wrongResponse)
		if status != 410 || code != "CAPTCHA_ALREADY_USED" {
			t.Fatalf("%s wrong replay lifecycle failed", scenario.Name)
		}

		correctFixture, _, err := state.issue(scenario.Name)
		if err != nil {
			t.Fatalf("%s replacement fixture issue failed", scenario.Name)
		}
		plan = makeBrowserHarnessPlan(correctFixture)
		correctResponse := browserHarnessResponse(correctFixture, plan.Interaction, plan.Correct)
		status, result, _ = state.verify(correctResponse)
		if status != 200 || !result.Valid {
			t.Fatalf("%s correct lifecycle failed", scenario.Name)
		}
		status, _, code = state.verify(correctResponse)
		if status != 410 || code != "CAPTCHA_ALREADY_USED" {
			t.Fatalf("%s correct replay lifecycle failed", scenario.Name)
		}
	}
}

func TestBehaviorBrowserHarnessPublicChallengeHasNoActionPlan(t *testing.T) {
	state, err := newBrowserHarnessState()
	if err != nil {
		t.Fatal("browser fixture initialization failed")
	}
	fixture, _, err := state.issue("curve_draw")
	if err != nil {
		t.Fatal("browser fixture issue failed")
	}
	encoded, err := json.Marshal(fixture.challenge)
	if err != nil {
		t.Fatal("browser fixture public encoding failed")
	}
	var public map[string]any
	if err := json.Unmarshal(encoded, &public); err != nil {
		t.Fatal("browser fixture public decoding failed")
	}
	wantRoot := map[string]bool{"type": true, "token": true, "expires_at": true, "presentation": true}
	for key := range public {
		if !wantRoot[key] {
			t.Fatalf("browser fixture public challenge has unexpected root field %q", key)
		}
		delete(wantRoot, key)
	}
	if len(wantRoot) != 0 || containsBrowserPlanKey(public) {
		t.Fatal("browser fixture public challenge contains private control material")
	}
}

func TestBehaviorBrowserHarnessProcess(t *testing.T) {
	if os.Getenv("CHEESEWAF_CAPTCHA_BROWSER_HARNESS") != "1" {
		t.Skip("interactive browser fixture process")
	}
	state, err := newBrowserHarnessState()
	if err != nil {
		t.Fatal("browser fixture initialization failed")
	}
	if err := writeBrowserHarnessReply(browserHarnessReply{OK: true, Ready: true}); err != nil {
		t.Fatal("browser fixture ready reply failed")
	}
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 64*1024), 2*1024*1024)
	for scanner.Scan() {
		var request browserHarnessRequest
		if err := json.Unmarshal(scanner.Bytes(), &request); err != nil {
			_ = writeBrowserHarnessReply(browserHarnessReply{OK: false, Error: "invalid_request"})
			continue
		}
		reply, stop := state.handle(request)
		if err := writeBrowserHarnessReply(reply); err != nil {
			t.Fatal("browser fixture reply failed")
		}
		if stop {
			return
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal("browser fixture control channel failed")
	}
}

func newBrowserHarnessState() (*browserHarnessState, error) {
	secretBytes := make([]byte, 32)
	if _, err := rand.Read(secretBytes); err != nil {
		return nil, err
	}
	return &browserHarnessState{
		secret:   base64.RawURLEncoding.EncodeToString(secretBytes),
		byHandle: make(map[string]*browserHarnessFixture),
		byToken:  make(map[string]*browserHarnessFixture),
	}, nil
}

func (state *browserHarnessState) handle(request browserHarnessRequest) (browserHarnessReply, bool) {
	reply := browserHarnessReply{ID: request.ID, OK: true}
	switch request.Action {
	case "issue":
		fixture, handle, err := state.issue(request.Scenario)
		if err != nil {
			return browserHarnessReply{ID: request.ID, OK: false, Error: "issue_failed"}, false
		}
		reply.Handle = handle
		reply.Challenge = &fixture.challenge
	case "plan":
		fixture := state.byHandle[request.Handle]
		if fixture == nil {
			return browserHarnessReply{ID: request.ID, OK: false, Error: "fixture_missing"}, false
		}
		plan := makeBrowserHarnessPlan(fixture)
		reply.Plan = &plan
	case "verify":
		status, result, code := state.verify(request.Response)
		reply.Status, reply.Result, reply.Code = status, &result, code
	case "shutdown":
		return reply, true
	default:
		return browserHarnessReply{ID: request.ID, OK: false, Error: "action_unsupported"}, false
	}
	return reply, false
}

func (state *browserHarnessState) issue(name string) (*browserHarnessFixture, string, error) {
	scenario, ok := findBrowserHarnessScenario(name)
	if !ok {
		return nil, "", fmt.Errorf("unsupported browser fixture scenario")
	}
	state.sequence++
	now := time.Now().UTC()
	legacy := harnessScenario{name: scenario.Name, kind: scenario.Kind, version: scenario.Version}
	opts := harnessOptions(state.secret, now, legacy, state.sequence)
	challenge, err := IssueBehaviorChallenge(opts)
	if err != nil {
		return nil, "", err
	}
	opened, ok := openBehaviorToken(opts, challenge.Token)
	if !ok {
		return nil, "", fmt.Errorf("browser fixture token open failed")
	}
	fixture := &browserHarnessFixture{opts: opts, challenge: challenge, opened: opened}
	handle := fmt.Sprintf("fixture-%d", state.sequence)
	state.byHandle[handle] = fixture
	state.byToken[challenge.Token] = fixture
	return fixture, handle, nil
}

func (state *browserHarnessState) verify(response BehaviorResponse) (int, BehaviorResult, string) {
	fixture := state.byToken[response.Token]
	if fixture == nil || fixture.used {
		return 410, BehaviorResult{}, "CAPTCHA_ALREADY_USED"
	}
	fixture.used = true
	result := VerifyBehaviorChallenge(harnessVerificationOptions(fixture.opts, response), response)
	result.Reason = ""
	return 200, result, ""
}

func findBrowserHarnessScenario(name string) (browserHarnessScenario, bool) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "random" {
		name = "rotate"
	} else if name == "curve_slider_v1" || name == "curve_slider_v2" || name == "curve_slider_v3" {
		name = "curve_slider"
	}
	for _, scenario := range browserHarnessScenarios {
		if scenario.Name == name {
			return scenario, true
		}
	}
	return browserHarnessScenario{}, false
}

func makeBrowserHarnessPlan(fixture *browserHarnessFixture) browserHarnessPlan {
	tok := fixture.opened
	switch tok.Mode {
	case "angle", "slider", "curve_slider", "restore_offset":
		value := browserHarnessRangeValue(fixture)
		wrong := alternateBrowserHarnessRangeValue(value)
		return browserHarnessPlan{Interaction: "range", Correct: browserHarnessAction{Value: &value}, Wrong: browserHarnessAction{Value: &wrong}}
	case "curve":
		return browserHarnessPlan{Interaction: "surface", Correct: browserHarnessAction{Path: append([]BehaviorPoint(nil), tok.Curve...)}, Wrong: browserHarnessAction{Path: wrongBrowserHarnessPath()}}
	case "scratch":
		return browserHarnessPlan{Interaction: "surface", Correct: browserHarnessAction{Path: browserHarnessScratchPath(tok)}, Wrong: browserHarnessAction{Path: wrongBrowserHarnessPath()}}
	case "point":
		correct := tok.Point
		wrong := BehaviorPoint{X: (tok.Point.X + 5000) % behaviorCoordinateMax, Y: (tok.Point.Y + 5000) % behaviorCoordinateMax}
		return browserHarnessPlan{Interaction: "click", Correct: browserHarnessAction{At: &correct}, Wrong: browserHarnessAction{At: &wrong}}
	default:
		return browserHarnessPlan{}
	}
}

func browserHarnessRangeValue(fixture *browserHarnessFixture) int {
	tok, presentation := fixture.opened, fixture.challenge.Presentation
	switch tok.Mode {
	case "angle":
		return normalizeBehaviorAngle(float64(tok.Angle-tok.InitialAngle)) * behaviorCoordinateMax / 360
	case "slider", "curve_slider":
		return tok.Point.X
	case "restore_offset":
		if presentation.MaxOffset <= 0 {
			return 5000
		}
		targetOffset := float64(tok.Point.X) / 100
		value := 5000 + int((targetOffset-float64(presentation.InitialOffset))*5000/float64(presentation.MaxOffset))
		return maxBehavior(0, minBehavior(behaviorCoordinateMax, value))
	default:
		return 0
	}
}

func alternateBrowserHarnessRangeValue(value int) int {
	if value <= behaviorCoordinateMax/2 {
		return minBehavior(behaviorCoordinateMax, value+4000)
	}
	return maxBehavior(0, value-4000)
}

func browserHarnessScratchPath(tok behaviorToken) []BehaviorPoint {
	track := solveScratchHarness(tok, 1200)
	path := make([]BehaviorPoint, len(track))
	for index, entry := range track {
		path[index] = BehaviorPoint{X: entry.X, Y: entry.Y}
	}
	return path
}

func wrongBrowserHarnessPath() []BehaviorPoint {
	path := make([]BehaviorPoint, 16)
	for index := range path {
		path[index] = BehaviorPoint{X: 400 + index*220, Y: 350}
	}
	return path
}

func browserHarnessResponse(fixture *browserHarnessFixture, interaction string, action browserHarnessAction) BehaviorResponse {
	const duration = 1200
	response := BehaviorResponse{Token: fixture.challenge.Token, DurationMS: duration}
	switch interaction {
	case "range":
		if action.Value == nil {
			return response
		}
		value := *action.Value
		start, y := 0, 5000
		switch fixture.opened.Mode {
		case "angle":
			response.Angle = normalizeBehaviorAngle(float64(fixture.opened.InitialAngle) + float64(value)*360/behaviorCoordinateMax)
		case "restore_offset":
			start = 5000
			presentation := fixture.challenge.Presentation
			response.Offset = float64(presentation.InitialOffset) + float64(value-5000)*float64(presentation.MaxOffset)/5000
		case "slider":
			// Match client geometry: piece starts at piece_y and follows track_angle.
			y = expectedSliderTrackY(fixture.opened, value)
			response.Point = &BehaviorPoint{X: value, Y: y}
			// Ensure intermediate track samples also follow the sealed tilt.
			mid := (start + value) / 2
			response.Track = harnessTrack([]BehaviorPoint{
				{X: start, Y: expectedSliderTrackY(fixture.opened, start)},
				{X: mid, Y: expectedSliderTrackY(fixture.opened, mid)},
				{X: value, Y: y},
			}, duration)
			return response
		case "curve_slider":
			start = behaviorCoordinateMax / 2
			response.Point = &BehaviorPoint{X: value, Y: y}
			response.Track = harnessCurveSliderTrack(BehaviorPoint{X: value, Y: y}, duration)
			return response
		}
		response.Track = harnessTrack([]BehaviorPoint{{X: start, Y: y}, {X: (start + value) / 2, Y: y}, {X: value, Y: y}}, duration)
	case "surface":
		response.Track = harnessTrack(action.Path, duration)
	case "click":
		if action.At != nil {
			selected := *action.At
			response.Point = &selected
		}
	}
	return response
}

func containsBrowserPlanKey(value any) bool {
	privateKeys := map[string]bool{"interaction": true, "correct": true, "wrong": true, "path": true, "at": true, "value": true, "handle": true}
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if privateKeys[key] || containsBrowserPlanKey(child) {
				return true
			}
		}
	case []any:
		for _, child := range typed {
			if containsBrowserPlanKey(child) {
				return true
			}
		}
	}
	return false
}

func writeBrowserHarnessReply(reply browserHarnessReply) error {
	encoded, err := json.Marshal(reply)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(os.Stdout, "%s%s\n", browserHarnessProtocolPrefix, encoded)
	return err
}
