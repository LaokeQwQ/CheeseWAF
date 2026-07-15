package captcha

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestVisualCurveDrawRequiresOrderedCoverageAndContinuity(t *testing.T) {
	now := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	opts := behaviorTestOptions(BehaviorCurveDraw, now)
	challenge, err := IssueBehaviorChallenge(opts)
	if err != nil {
		t.Fatal(err)
	}
	tok, ok := openBehaviorToken(normalizeBehaviorOptions(opts), challenge.Token)
	if !ok {
		t.Fatal("cannot open issued token")
	}
	good := curveDrawResponse(challenge.Token, tok.Curve)
	if result := VerifyBehaviorChallenge(opts, good); !result.Valid {
		t.Fatalf("valid traced curve rejected: %+v", result)
	}

	shortcut := good
	shortcut.Track = []BehaviorTrackPoint{
		{X: tok.Curve[0].X, Y: tok.Curve[0].Y, T: 0, Type: "down"},
		{X: tok.Curve[len(tok.Curve)-1].X, Y: tok.Curve[len(tok.Curve)-1].Y, T: 500, Type: "up"},
	}
	if VerifyBehaviorChallenge(opts, shortcut).Valid {
		t.Fatal("endpoint shortcut accepted")
	}

	reversed := good
	reversed.Track = append([]BehaviorTrackPoint(nil), good.Track...)
	for left, right := 0, len(reversed.Track)-1; left < right; left, right = left+1, right-1 {
		reversed.Track[left], reversed.Track[right] = reversed.Track[right], reversed.Track[left]
	}
	for i := range reversed.Track {
		reversed.Track[i].T = i * 500 / (len(reversed.Track) - 1)
	}
	if VerifyBehaviorChallenge(opts, reversed).Valid {
		t.Fatal("reverse trace accepted")
	}
}

func TestVisualCurveSliderKeepsTargetOffsetSealedAndChecksDrag(t *testing.T) {
	now := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	opts := behaviorTestOptions(BehaviorCurveSlider, now)
	clock := now
	opts.Now = func() time.Time { return clock }
	opts.Version = 1 // callers may still pass old version numbers; product is always V3 align.
	challenge, err := IssueBehaviorChallenge(opts)
	if err != nil {
		t.Fatal(err)
	}
	if challenge.Presentation.Version != 3 {
		t.Fatalf("curve slider must always publish version 3, got %d", challenge.Presentation.Version)
	}
	if challenge.Presentation.Piece == "" {
		t.Fatalf("curve slider missing movable curve piece: %+v", challenge.Presentation)
	}
	tok, ok := openBehaviorToken(normalizeBehaviorOptions(opts), challenge.Token)
	if !ok {
		t.Fatal("cannot open issued token")
	}
	if tok.Version != 3 || tok.Mode != "curve_slider" {
		t.Fatalf("token not sealed as V3 curve slider: %+v", tok)
	}
	public, _ := json.Marshal(challenge.Presentation)
	var presentation map[string]any
	if err := json.Unmarshal(public, &presentation); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"initial_offset", "max_offset"} {
		if _, exposed := presentation[field]; exposed {
			t.Fatalf("presentation exposes derivable slider target through %q: %s", field, public)
		}
	}

	// The initial displacement is sealed with the challenge. The browser only
	// receives a pre-shifted bitmap and the fixed relative movement contract.
	expectedValue := 5000 - tok.InitialOffset*5000/visualCurveSliderMaxOffset
	if absBehavior(tok.Point.X-expectedValue) > 1 {
		t.Fatalf("sealed target %d does not match sealed initial offset (want ~%d)", tok.Point.X, expectedValue)
	}

	good := curveSliderResponse(challenge.Token, tok.Point)
	if result := VerifyBehaviorChallenge(opts, good); result.Valid {
		t.Fatalf("curve slider accepted before its signed minimum elapsed time: %+v", result)
	}
	clock = clock.Add(time.Duration(good.DurationMS) * time.Millisecond)
	if result := VerifyBehaviorChallenge(opts, good); !result.Valid {
		t.Fatalf("valid curve slider response rejected: %+v", result)
	}
	quantizedX := tok.Point.X + 24
	if quantizedX > behaviorCoordinateMax {
		quantizedX = tok.Point.X - 24
	}
	quantized := BehaviorResponse{
		Token:      challenge.Token,
		Point:      &BehaviorPoint{X: quantizedX, Y: 5000},
		DurationMS: 330,
	}
	for index := 0; index < 14; index++ {
		kind := "move"
		if index == 0 {
			kind = "down"
		} else if index == 13 {
			kind = "up"
		}
		quantized.Track = append(quantized.Track, BehaviorTrackPoint{
			X:    5000 + (quantizedX-5000)*index/13,
			Y:    5000,
			T:    index * quantized.DurationMS / 13,
			Type: kind,
		})
	}
	if result := VerifyBehaviorChallenge(opts, quantized); !result.Valid {
		t.Fatalf("physically quantized curve slider response rejected: %+v", result)
	}
	teleport := good
	teleport.Track = []BehaviorTrackPoint{{X: tok.Point.X - 700, Y: tok.Point.Y, T: 0}, {X: tok.Point.X, Y: tok.Point.Y, T: 500}}
	if VerifyBehaviorChallenge(opts, teleport).Valid {
		t.Fatal("two-point synthetic drag accepted")
	}
	// The server-configured minimum duration remains authoritative.
	fast := good
	fast.Track = append([]BehaviorTrackPoint(nil), good.Track...)
	fast.DurationMS = int(opts.MinDuration/time.Millisecond) - 1
	for index := range fast.Track {
		fast.Track[index].T = index * fast.DurationMS / (len(fast.Track) - 1)
	}
	if VerifyBehaviorChallenge(opts, fast).Valid {
		t.Fatal("drag shorter than the configured minimum duration accepted")
	}
	for _, test := range []struct {
		name  string
		lastT int
	}{
		{name: "zero_tail_time", lastT: 0},
		{name: "tail_before_minimum", lastT: tok.MinMS - 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			uncovered := good
			uncovered.Track = append([]BehaviorTrackPoint(nil), good.Track...)
			uncovered.DurationMS = tok.MinMS
			for index := range uncovered.Track {
				uncovered.Track[index].T = index * test.lastT / (len(uncovered.Track) - 1)
			}
			if VerifyBehaviorChallenge(opts, uncovered).Valid {
				t.Fatalf("duration reached %dms but track ended at %dms", uncovered.DurationMS, test.lastT)
			}
		})
	}
	folded := good
	folded.Track = []BehaviorTrackPoint{
		{X: 5000, Y: 5000, T: 0, Type: "down"},
		{X: clampVisualCoord(5000 - (tok.Point.X - 5000)), Y: 5000, T: 160, Type: "move"},
		{X: tok.Point.X, Y: 5000, T: 500, Type: "up"},
	}
	if VerifyBehaviorChallenge(opts, folded).Valid {
		t.Fatal("folded synthetic drag accepted")
	}
	wrong := good
	wrongX := tok.Point.X + opts.Tolerance*3
	if wrongX > behaviorCoordinateMax {
		wrongX = tok.Point.X - opts.Tolerance*3
	}
	wrong.Point = &BehaviorPoint{X: clampVisualCoord(wrongX), Y: tok.Point.Y}
	wrong.Track[len(wrong.Track)-1].X = wrong.Point.X
	if absBehavior(wrong.Point.X-tok.Point.X) <= opts.Tolerance {
		t.Fatalf("test fixture did not produce an out-of-tolerance offset: target=%d wrong=%d", tok.Point.X, wrong.Point.X)
	}
	if VerifyBehaviorChallenge(opts, wrong).Valid {
		t.Fatal("wrong curve offset accepted")
	}
}

func TestVisualCurveSliderRejectsMalformedSealedGeometry(t *testing.T) {
	now := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	opts := normalizeBehaviorOptions(behaviorTestOptions(BehaviorCurveSlider, now))
	challenge, err := IssueBehaviorChallenge(opts)
	if err != nil {
		t.Fatal(err)
	}
	tok, ok := openBehaviorToken(opts, challenge.Token)
	if !ok {
		t.Fatal("cannot open issued token")
	}
	tok.InitialOffset = -visualCurveSliderMaxOffset
	tok.Point.X = behaviorCoordinateMax
	if !validBehaviorTokenShape(tok) {
		t.Fatalf("boundary fixture is not a valid curve slider token: %+v", tok)
	}
	for _, mutate := range []func(*behaviorToken){
		func(value *behaviorToken) { value.InitialOffset = 0 },
		func(value *behaviorToken) { value.InitialOffset = visualCurveSliderMaxOffset + 1 },
		func(value *behaviorToken) { value.Point.X = behaviorCoordinateMax - value.Point.X },
		func(value *behaviorToken) { value.Version = 2 },
	} {
		invalid := tok
		mutate(&invalid)
		if validBehaviorTokenShape(invalid) {
			t.Fatalf("accepted malformed curve slider token: %+v", invalid)
		}
	}
}

func TestVisualCurvePresentationDoesNotExposeStructuredAnswer(t *testing.T) {
	now := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	for _, kind := range []BehaviorType{BehaviorCurveDraw, BehaviorCurveSlider} {
		challenge, err := IssueBehaviorChallenge(behaviorTestOptions(kind, now))
		if err != nil {
			t.Fatal(err)
		}
		public, _ := json.Marshal(challenge.Presentation)
		for _, field := range []string{`"curve"`, `"point"`, `"target"`, `"answer"`} {
			if strings.Contains(string(public), field) {
				t.Fatalf("%s presentation exposes %s: %s", kind, field, public)
			}
		}
	}
}

func curveDrawResponse(token string, curve []BehaviorPoint) BehaviorResponse {
	response := BehaviorResponse{Token: token, DurationMS: 500}
	for i, point := range curve {
		kind := "move"
		if i == 0 {
			kind = "down"
		} else if i == len(curve)-1 {
			kind = "up"
		}
		response.Track = append(response.Track, BehaviorTrackPoint{X: point.X, Y: point.Y, T: i * response.DurationMS / (len(curve) - 1), Type: kind})
	}
	return response
}

func curveSliderResponse(token string, target BehaviorPoint) BehaviorResponse {
	// Dense drag fixture: enough intermediate samples for direction/path checks.
	// Do not require statistical step/time variance — real Chromium tracks are often
	// near-uniform at 16–17ms sample intervals (BUG-074).
	start := behaviorCoordinateMax / 2
	delta := target.X - start
	fractions := []float64{0, 0.08, 0.18, 0.33, 0.48, 0.62, 0.74, 0.84, 0.93, 1.0}
	times := []int{0, 45, 95, 160, 230, 310, 390, 470, 560, 650}
	response := BehaviorResponse{Token: token, Point: &BehaviorPoint{X: target.X, Y: target.Y}, DurationMS: 650}
	for i, frac := range fractions {
		kind := "move"
		if i == 0 {
			kind = "down"
		} else if i == len(fractions)-1 {
			kind = "up"
		}
		x := start + int(float64(delta)*frac)
		// Micro lateral noise on intermediate samples only.
		if i > 0 && i < len(fractions)-1 {
			if i%2 == 0 {
				x += 18 + i*3
			} else {
				x -= 12 + i*2
			}
		}
		if i == len(fractions)-1 {
			x = target.X
		}
		response.Track = append(response.Track, BehaviorTrackPoint{X: clampVisualCoord(x), Y: target.Y, T: times[i], Type: kind})
	}
	return response
}
