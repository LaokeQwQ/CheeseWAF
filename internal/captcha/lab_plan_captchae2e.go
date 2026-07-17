//go:build captchae2e

package captcha

import (
	"fmt"
	"strings"
)

type E2EBehaviorAction struct {
	Value *int            `json:"value,omitempty"`
	Path  []BehaviorPoint `json:"path,omitempty"`
	At    *BehaviorPoint  `json:"at,omitempty"`
}

type E2EBehaviorPlan struct {
	Interaction string            `json:"interaction"`
	Action      E2EBehaviorAction `json:"action"`
}

func BuildE2EBehaviorPlan(opts BehaviorOptions, challenge BehaviorChallenge, variant string) (E2EBehaviorPlan, error) {
	variant = strings.ToLower(strings.TrimSpace(variant))
	if variant != "wrong" && variant != "correct" {
		return E2EBehaviorPlan{}, fmt.Errorf("invalid E2E behavior plan variant")
	}
	if strings.TrimSpace(challenge.Token) == "" || !e2eBehaviorType(challenge.Type) {
		return E2EBehaviorPlan{}, fmt.Errorf("invalid E2E behavior challenge")
	}
	opts = normalizeBehaviorOptions(opts)
	tok, ok := openBehaviorToken(opts, challenge.Token)
	if !ok || tok.Type != challenge.Type {
		return E2EBehaviorPlan{}, fmt.Errorf("E2E behavior challenge does not match its sealed token")
	}

	correct, wrong, interaction, ok := e2eBehaviorActions(tok, challenge.Presentation)
	if !ok {
		return E2EBehaviorPlan{}, fmt.Errorf("unsupported E2E behavior challenge mode")
	}
	action := wrong
	if variant == "correct" {
		action = correct
	}
	return E2EBehaviorPlan{Interaction: interaction, Action: action}, nil
}

func e2eBehaviorActions(tok behaviorToken, presentation BehaviorPresentation) (E2EBehaviorAction, E2EBehaviorAction, string, bool) {
	switch tok.Mode {
	case "angle", "slider", "curve_slider", "restore_offset":
		value := e2eBehaviorRangeValue(tok, presentation)
		wrong := e2eAlternateRangeValue(value)
		return E2EBehaviorAction{Value: &value}, E2EBehaviorAction{Value: &wrong}, "range", true
	case "curve":
		return E2EBehaviorAction{Path: append([]BehaviorPoint(nil), tok.Curve...)}, E2EBehaviorAction{Path: e2eWrongPath()}, "surface", true
	case "scratch":
		return E2EBehaviorAction{Path: e2eScratchPath(tok)}, E2EBehaviorAction{Path: e2eWrongPath()}, "surface", true
	case "point":
		correct := tok.Point
		wrong := BehaviorPoint{X: (tok.Point.X + 5000) % behaviorCoordinateMax, Y: (tok.Point.Y + 5000) % behaviorCoordinateMax}
		return E2EBehaviorAction{At: &correct}, E2EBehaviorAction{At: &wrong}, "click", true
	default:
		return E2EBehaviorAction{}, E2EBehaviorAction{}, "", false
	}
}

func e2eBehaviorRangeValue(tok behaviorToken, presentation BehaviorPresentation) int {
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

func e2eAlternateRangeValue(value int) int {
	if value <= behaviorCoordinateMax/2 {
		return minBehavior(behaviorCoordinateMax, value+4000)
	}
	return maxBehavior(0, value-4000)
}

func e2eScratchPath(tok behaviorToken) []BehaviorPoint {
	points := make([]BehaviorPoint, 0, 96)
	for _, target := range tok.Targets {
		if len(target) != 4 {
			continue
		}
		const margin = 120
		left, top, right, bottom := target[0]+margin, target[1]+margin, target[2]-margin, target[3]-margin
		if left >= right || top >= bottom {
			left, top, right, bottom = target[0], target[1], target[2], target[3]
		}
		for row, y := 0, top; y <= bottom; row, y = row+1, y+600 {
			if row%2 == 0 {
				for x := left; x <= right; x += 600 {
					points = e2eAppendScratchPoint(points, BehaviorPoint{X: x, Y: y})
				}
			} else {
				for x := right; x >= left; x -= 600 {
					points = e2eAppendScratchPoint(points, BehaviorPoint{X: x, Y: y})
				}
			}
		}
	}
	if len(points) > tok.MaxPoints {
		points = points[:tok.MaxPoints]
	}
	return points
}

func e2eAppendScratchPoint(points []BehaviorPoint, next BehaviorPoint) []BehaviorPoint {
	if len(points) > 0 {
		last := points[len(points)-1]
		steps := int(behaviorDistance(last, next) / 1000)
		for step := 1; step <= steps; step++ {
			points = append(points, BehaviorPoint{
				X: last.X + (next.X-last.X)*step/(steps+1),
				Y: last.Y + (next.Y-last.Y)*step/(steps+1),
			})
		}
	}
	return append(points, next)
}

func e2eWrongPath() []BehaviorPoint {
	path := make([]BehaviorPoint, 16)
	for index := range path {
		path[index] = BehaviorPoint{X: 400 + index*220, Y: 350}
	}
	return path
}

func e2eBehaviorType(kind BehaviorType) bool {
	switch kind {
	case BehaviorCurveDraw, BehaviorCurveSlider, BehaviorShapeSlider, BehaviorRotate,
		BehaviorRestoreSlider, BehaviorAngle, BehaviorScratch, BehaviorTextClick, BehaviorIconClick:
		return true
	default:
		return false
	}
}
