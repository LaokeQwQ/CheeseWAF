package captcha

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"testing"
	"time"
)

type harnessScenario struct {
	name    string
	kind    BehaviorType
	version int
}
type harnessResult struct {
	Type                  string `json:"type"`
	WrongRejected         bool   `json:"wrong_rejected"`
	WrongReplayRejected   bool   `json:"wrong_replay_rejected"`
	CorrectAccepted       bool   `json:"correct_accepted"`
	CorrectReplayRejected bool   `json:"correct_replay_rejected"`
}

var harnessScenarios = []harnessScenario{
	{"curve_draw", BehaviorCurveDraw, 3},
	{"curve_slider", BehaviorCurveSlider, 3},
	{"shape_slider", BehaviorShapeSlider, 3},
	{"rotate", BehaviorRotate, 3},
	{"restore_slider", BehaviorRestoreSlider, 3},
	{"angle", BehaviorAngle, 3},
	{"scratch", BehaviorScratch, 3},
	{"text_click", BehaviorTextClick, 3},
	{"icon_click", BehaviorIconClick, 3},
}

func TestBehaviorFixedHarness(t *testing.T) {
	results, err := runBehaviorHarness()
	if err != nil {
		t.Fatal(err)
	}
	for _, result := range results {
		if !result.WrongRejected || !result.WrongReplayRejected || !result.CorrectAccepted || !result.CorrectReplayRejected {
			t.Fatalf("incomplete lifecycle for %s: %+v", result.Type, result)
		}
	}
	if os.Getenv("CHEESEWAF_CAPTCHA_HARNESS_REPORT") == "1" {
		encoded, _ := json.Marshal(results)
		fmt.Printf("CHEESEWAF_CAPTCHA_HARNESS %s\n", encoded)
	}
}

func TestBehaviorFixedHarnessCoversRegisteredNonPOWTypes(t *testing.T) {
	want := map[BehaviorType]bool{}
	for _, kind := range concreteBehaviorTypes {
		if kind != BehaviorPOW {
			want[kind] = true
		}
	}
	for _, scenario := range harnessScenarios {
		delete(want, scenario.kind)
	}
	if len(want) > 0 {
		missing := make([]string, 0, len(want))
		for kind := range want {
			missing = append(missing, string(kind))
		}
		sort.Strings(missing)
		t.Fatalf("missing harness scenarios: %v", missing)
	}
}

func TestBehaviorFixedHarnessReportHasOnlyPublicBooleanFields(t *testing.T) {
	results, err := runBehaviorHarness()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(results)
	if err != nil {
		t.Fatal(err)
	}
	var decoded []map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{"type": true, "wrong_rejected": true, "wrong_replay_rejected": true, "correct_accepted": true, "correct_replay_rejected": true}
	for _, item := range decoded {
		for key := range item {
			if !allowed[key] {
				t.Fatalf("report exposes unexpected field %q", key)
			}
		}
	}
}

func runBehaviorHarness() ([]harnessResult, error) {
	secretBytes := make([]byte, 32)
	if _, err := rand.Read(secretBytes); err != nil {
		return nil, err
	}
	secret := base64.RawURLEncoding.EncodeToString(secretBytes)
	now := time.Now().UTC()
	results := make([]harnessResult, 0, len(harnessScenarios))
	for index, scenario := range harnessScenarios {
		result, err := runHarnessScenario(secret, now, scenario, uint64(index+1))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", scenario.name, err)
		}
		results = append(results, result)
	}
	return results, nil
}

func runHarnessScenario(secret string, now time.Time, scenario harnessScenario, sequence uint64) (harnessResult, error) {
	opts := harnessOptions(secret, now, scenario, sequence)
	wrongChallenge, err := IssueBehaviorChallenge(opts)
	if err != nil {
		return harnessResult{}, err
	}
	wrongToken, ok := openBehaviorToken(opts, wrongChallenge.Token)
	if !ok {
		return harnessResult{}, fmt.Errorf("cannot open wrong token")
	}
	wrong := incorrectHarnessAnswer(solveHarnessAnswer(wrongChallenge.Token, wrongToken))
	wrongUsed := false
	wrongResult := consumeHarness(opts, wrong, &wrongUsed)
	wrongReplay := consumeHarness(opts, solveHarnessAnswer(wrongChallenge.Token, wrongToken), &wrongUsed)

	correctOpts := harnessOptions(secret, now, scenario, sequence+1000)
	correctChallenge, err := IssueBehaviorChallenge(correctOpts)
	if err != nil {
		return harnessResult{}, err
	}
	correctToken, ok := openBehaviorToken(correctOpts, correctChallenge.Token)
	if !ok {
		return harnessResult{}, fmt.Errorf("cannot open correct token")
	}
	correct := solveHarnessAnswer(correctChallenge.Token, correctToken)
	correctUsed := false
	correctResult := consumeHarness(correctOpts, correct, &correctUsed)
	correctReplay := consumeHarness(correctOpts, correct, &correctUsed)
	return harnessResult{scenario.name, !wrongResult.Valid, wrongReplay.Reason == "already_used", correctResult.Valid, correctReplay.Reason == "already_used"}, nil
}

func harnessOptions(secret string, now time.Time, scenario harnessScenario, sequence uint64) BehaviorOptions {
	seed := sha256.Sum256([]byte(fmt.Sprintf("captcha-harness:%s:%d", scenario.name, sequence)))
	return BehaviorOptions{Secret: secret, Purpose: "captcha-e2e-harness", ClientKey: "isolated-run", Path: "/captcha-e2e", Site: "test-process", TTL: 2 * time.Minute, Type: scenario.kind, Version: scenario.version, Intensity: 3, Tolerance: 500, MinDuration: 120 * time.Millisecond, MaxDuration: 2 * time.Minute, MaxTrackPoints: 128, Now: func() time.Time { return now }, Rand: &harnessHashReader{seed: seed}}
}

func consumeHarness(opts BehaviorOptions, response BehaviorResponse, used *bool) BehaviorResult {
	if *used {
		return BehaviorResult{Reason: "already_used"}
	}
	*used = true
	return VerifyBehaviorChallenge(opts, response)
}

func solveHarnessAnswer(token string, tok behaviorToken) BehaviorResponse {
	const duration = 1200
	response := BehaviorResponse{Token: token, DurationMS: duration}
	switch tok.Mode {
	case "angle":
		value := normalizeBehaviorAngle(float64(tok.Angle-tok.InitialAngle)) * behaviorCoordinateMax / 360
		response.Angle = tok.Angle
		response.Track = harnessTrack([]BehaviorPoint{{X: 0, Y: 5000}, {X: value / 2, Y: 5000}, {X: value, Y: 5000}}, duration)
	case "point":
		point := tok.Point
		response.Point = &point
	case "slider":
		point := tok.Point
		response.Point = &point
		response.Track = harnessTrack([]BehaviorPoint{{X: 0, Y: point.Y}, {X: point.X / 2, Y: point.Y}, {X: point.X, Y: point.Y}}, duration)
	case "curve_slider":
		point := tok.Point
		response.Point = &point
		response.Track = harnessCurveSliderTrack(point, duration)
	case "restore_offset":
		response.Offset = float64(tok.Point.X) / 100
		response.Track = harnessTrack([]BehaviorPoint{{X: 0, Y: 5000}, {X: 5000, Y: 5000}, {X: 10000, Y: 5000}}, duration)
	case "curve":
		response.Track = harnessTrack(tok.Curve, duration)
	case "scratch":
		response.Track = solveScratchHarness(tok, duration)
	}
	return response
}

func harnessTrack(points []BehaviorPoint, duration int) []BehaviorTrackPoint {
	track := make([]BehaviorTrackPoint, len(points))
	for index, point := range points {
		t := duration
		if len(points) > 1 {
			t = index * duration / (len(points) - 1)
		}
		kind := "move"
		if index == 0 {
			kind = "down"
		}
		if index == len(points)-1 {
			kind = "up"
		}
		track[index] = BehaviorTrackPoint{X: point.X, Y: point.Y, T: t, Type: kind}
	}
	return track
}

// harnessCurveSliderTrack builds a dense, jittered drag that satisfies anti-bot
// variance checks while still landing on the sealed target.
func harnessCurveSliderTrack(target BehaviorPoint, duration int) []BehaviorTrackPoint {
	if duration < 650 {
		duration = 650
	}
	startX := behaviorCoordinateMax / 2
	// Ease-out sample grid with intentional spatial/temporal jitter.
	fracs := []float64{0, 0.07, 0.16, 0.28, 0.41, 0.54, 0.66, 0.77, 0.87, 0.94, 1.0}
	track := make([]BehaviorTrackPoint, len(fracs))
	for i, frac := range fracs {
		kind := "move"
		if i == 0 {
			kind = "down"
		} else if i == len(fracs)-1 {
			kind = "up"
		}
		x := startX + int(float64(target.X-startX)*frac)
		if i > 0 && i < len(fracs)-1 {
			if i%2 == 0 {
				x += 20 + i*4
			} else {
				x -= 14 + i*3
			}
		}
		if i == len(fracs)-1 {
			x = target.X
		}
		// Non-uniform timing: slower near the end.
		t := int(float64(duration) * (0.55*frac + 0.45*frac*frac))
		if i == len(fracs)-1 {
			t = duration
		}
		track[i] = BehaviorTrackPoint{X: clampVisualCoord(x), Y: target.Y, T: t, Type: kind}
	}
	return track
}

func incorrectHarnessAnswer(response BehaviorResponse) BehaviorResponse {
	response.Angle = (response.Angle + 180) % 360
	response.Offset += 100
	if response.Point != nil {
		point := *response.Point
		point.X = (point.X + 5000) % behaviorCoordinateMax
		response.Point = &point
	}
	if len(response.Track) > 0 {
		response.Track = []BehaviorTrackPoint{{X: 0, Y: 0, T: 0, Type: "down"}, {X: 100, Y: 100, T: response.DurationMS, Type: "up"}}
	}
	return response
}

func solveScratchHarness(tok behaviorToken, duration int) []BehaviorTrackPoint {
	points := make([]BehaviorPoint, 0, 96)
	for _, target := range tok.Targets {
		if len(target) != 4 {
			continue
		}
		margin := 120
		left, top, right, bottom := target[0]+margin, target[1]+margin, target[2]-margin, target[3]-margin
		if left >= right || top >= bottom {
			left, top, right, bottom = target[0], target[1], target[2], target[3]
		}
		for row, y := 0, top; y <= bottom; row, y = row+1, y+600 {
			if row%2 == 0 {
				for x := left; x <= right; x += 600 {
					points = appendScratchPoint(points, BehaviorPoint{X: x, Y: y})
				}
			} else {
				for x := right; x >= left; x -= 600 {
					points = appendScratchPoint(points, BehaviorPoint{X: x, Y: y})
				}
			}
		}
	}
	if len(points) > tok.MaxPoints {
		points = points[:tok.MaxPoints]
	}
	return harnessTrack(points, duration)
}

func appendScratchPoint(points []BehaviorPoint, next BehaviorPoint) []BehaviorPoint {
	if len(points) > 0 {
		last := points[len(points)-1]
		distance := behaviorDistance(last, next)
		steps := int(distance / 1000)
		for step := 1; step <= steps; step++ {
			points = append(points, BehaviorPoint{X: last.X + (next.X-last.X)*step/(steps+1), Y: last.Y + (next.Y-last.Y)*step/(steps+1)})
		}
	}
	return append(points, next)
}

type harnessHashReader struct {
	seed    [32]byte
	counter uint64
	buffer  []byte
}

func (r *harnessHashReader) Read(p []byte) (int, error) {
	for len(r.buffer) < len(p) {
		r.counter++
		block := sha256.Sum256([]byte(fmt.Sprintf("%x:%d", r.seed, r.counter)))
		r.buffer = append(r.buffer, block[:]...)
	}
	copy(p, r.buffer[:len(p)])
	r.buffer = r.buffer[len(p):]
	return len(p), nil
}
