package captcha

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
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

func TestVisualCurveSliderKeepsTargetParameterSealedAndChecksDrag(t *testing.T) {
	now := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	opts := behaviorTestOptions(BehaviorCurveSlider, now)
	challenge, err := IssueBehaviorChallenge(opts)
	if err != nil {
		t.Fatal(err)
	}
	tok, ok := openBehaviorToken(normalizeBehaviorOptions(opts), challenge.Token)
	if !ok {
		t.Fatal("cannot open issued token")
	}
	public, _ := json.Marshal(challenge.Presentation)
	if strings.Contains(string(public), strconv.Itoa(tok.Point.X)) {
		t.Fatalf("presentation exposes secret slider target %d", tok.Point.X)
	}

	good := curveSliderResponse(challenge.Token, tok.Point)
	if result := VerifyBehaviorChallenge(opts, good); !result.Valid {
		t.Fatalf("valid curve slider response rejected: %+v", result)
	}
	teleport := good
	teleport.Track = []BehaviorTrackPoint{{X: tok.Point.X - 700, Y: tok.Point.Y, T: 0}, {X: tok.Point.X, Y: tok.Point.Y, T: 500}}
	if VerifyBehaviorChallenge(opts, teleport).Valid {
		t.Fatal("two-point synthetic drag accepted")
	}
	wrong := good
	wrong.Point = &BehaviorPoint{X: clampVisualCoord(tok.Point.X + opts.Tolerance*3), Y: tok.Point.Y}
	wrong.Track[len(wrong.Track)-1].X = wrong.Point.X
	if VerifyBehaviorChallenge(opts, wrong).Valid {
		t.Fatal("wrong curve parameter accepted")
	}
}

func TestSliderCurvePublicFormulaContract(t *testing.T) {
	tests := []struct {
		version   int
		parameter int
		want      []BehaviorPoint
	}{
		{1, 1800, []BehaviorPoint{{900, 5532}, {2950, 5968}, {5000, 5838}, {7050, 5216}, {9100, 4468}}},
		{1, 5000, []BehaviorPoint{{900, 6600}, {2950, 6131}, {5000, 5000}, {7050, 3869}, {9100, 3400}}},
		{2, 5000, []BehaviorPoint{{900, 6152}, {2950, 5000}, {5000, 3848}, {7050, 5000}, {9100, 6152}}},
		{3, 8200, []BehaviorPoint{{900, 5450}, {2950, 4586}, {5000, 4292}, {7050, 3147}, {9100, 4550}}},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("v%d-parameter-%d", test.version, test.parameter), func(t *testing.T) {
			got := sliderCurve(test.parameter, test.version)
			for index, want := range test.want {
				gotIndex := index * 8
				if got[gotIndex] != want {
					t.Fatalf("sample %d mismatch: got %+v want %+v", gotIndex, got[gotIndex], want)
				}
			}
		})
	}
}

func TestSliderCurveVersionsAreDistinctAtSameParameter(t *testing.T) {
	curves := [][]BehaviorPoint{sliderCurve(5000, 1), sliderCurve(5000, 2), sliderCurve(5000, 3)}
	for left := range curves {
		for right := left + 1; right < len(curves); right++ {
			if reflect.DeepEqual(curves[left], curves[right]) {
				t.Fatalf("versions %d and %d produced the same curve", left+1, right+1)
			}
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
	start := clampVisualCoord(target.X - 1800)
	response := BehaviorResponse{Token: token, Point: &BehaviorPoint{X: target.X, Y: target.Y}, DurationMS: 500}
	for i := 0; i < 6; i++ {
		kind := "move"
		if i == 0 {
			kind = "down"
		} else if i == 5 {
			kind = "up"
		}
		response.Track = append(response.Track, BehaviorTrackPoint{X: start + (target.X-start)*i/5, Y: target.Y, T: i * 100, Type: kind})
	}
	return response
}
