package captcha

import (
	"encoding/base64"
	"image"
	"image/png"
	mathrand "math/rand"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestVisualIconClickAnswerIndexDistributionAcrossSeeds(t *testing.T) {
	const samples = 64
	counts := make([]int, selectionCount)

	for seed := int64(1); seed <= samples; seed++ {
		opts := seededVisualOptions(seed)
		var tok behaviorToken
		var presentation BehaviorPresentation
		if err := populateVisualIconClick(opts, &tok, &presentation); err != nil {
			t.Fatalf("seed %d: populate icon click: %v", seed, err)
		}

		index := selectionGridIndexFromPoint(t, tok.Point)
		counts[index]++
		if tok.Mode != "point" || presentation.Kind != string(BehaviorIconClick) {
			t.Fatalf("seed %d: unexpected point contract: mode=%q kind=%q", seed, tok.Mode, presentation.Kind)
		}
		if presentation.Width != selectionWidth || presentation.Height != selectionHeight {
			t.Fatalf("seed %d: unexpected image dimensions: %dx%d", seed, presentation.Width, presentation.Height)
		}
		if !strings.HasPrefix(presentation.Prompt, "请点击") {
			t.Fatalf("seed %d: unexpected prompt %q", seed, presentation.Prompt)
		}
	}

	for index, count := range counts {
		if count == 0 {
			t.Fatalf("answer index %d was never selected across %d deterministic seeds: %v", index, samples, counts)
		}
	}
	if counts[0] >= samples/2 {
		t.Fatalf("a fixed first-cell click remains predictive across seeds: %v", counts)
	}
}

func TestVisualIconClickSealedTargetRejectsFixedFirstCell(t *testing.T) {
	var opts BehaviorOptions
	var challenge BehaviorChallenge
	var tok behaviorToken
	found := false
	for seed := int64(1); seed <= 64; seed++ {
		candidateOpts := seededVisualChallengeOptions(BehaviorIconClick, seed)
		candidateChallenge, err := IssueBehaviorChallenge(candidateOpts)
		if err != nil {
			t.Fatalf("seed %d: issue icon click: %v", seed, err)
		}
		candidate, ok := openBehaviorToken(normalizeBehaviorOptions(candidateOpts), candidateChallenge.Token)
		if !ok {
			t.Fatalf("seed %d: open sealed icon token", seed)
		}
		if selectionGridIndexFromPoint(t, candidate.Point) != 0 {
			opts, challenge, tok, found = candidateOpts, candidateChallenge, candidate, true
			break
		}
	}
	if !found {
		t.Fatal("no non-first icon target found across deterministic seeds")
	}

	fixedFirstCell := BehaviorPoint{X: behaviorCoordinateMax / 8, Y: behaviorCoordinateMax / 4}
	wrong := VerifyBehaviorChallenge(opts, BehaviorResponse{Token: challenge.Token, Point: &fixedFirstCell})
	if wrong.Valid || wrong.Reason != "incorrect" {
		t.Fatalf("fixed first-cell click was not rejected as incorrect: %+v", wrong)
	}
	correctPoint := tok.Point
	correct := VerifyBehaviorChallenge(opts, BehaviorResponse{Token: challenge.Token, Point: &correctPoint})
	if !correct.Valid {
		t.Fatalf("sealed target point rejected: %+v", correct)
	}
}

func TestVisualSelectionGridRectsRemainBoundedAndNonOverlapping(t *testing.T) {
	layouts := [][]image.Point{
		{image.Pt(68, 68), image.Pt(68, 68), image.Pt(68, 68), image.Pt(68, 68), image.Pt(68, 68), image.Pt(68, 68), image.Pt(68, 68), image.Pt(68, 68)},
		{image.Pt(54, 54), image.Pt(54, 54), image.Pt(54, 54), image.Pt(54, 54), image.Pt(54, 54), image.Pt(54, 54), image.Pt(54, 54), image.Pt(54, 54)},
		{image.Pt(52, 52), image.Pt(72, 72), image.Pt(58, 58), image.Pt(66, 66), image.Pt(70, 70), image.Pt(54, 54), image.Pt(64, 64), image.Pt(60, 60)},
	}
	for layoutIndex, sizes := range layouts {
		for seed := int64(1); seed <= 32; seed++ {
			rects, err := selectionGridRects(seededVisualOptions(seed), sizes)
			if err != nil {
				t.Fatalf("layout %d seed %d: %v", layoutIndex, seed, err)
			}
			bounds := image.Rect(0, 0, selectionWidth, selectionHeight)
			for i, rect := range rects {
				if rect.Size() != sizes[i] {
					t.Fatalf("layout %d seed %d: rect %d changed size: got %v want %v", layoutIndex, seed, i, rect.Size(), sizes[i])
				}
				if !rect.In(bounds) {
					t.Fatalf("layout %d seed %d: rect %d outside bounds: %v", layoutIndex, seed, i, rect)
				}
				column, row := i%4, i/4
				cell := image.Rect(column*selectionWidth/4, row*selectionHeight/2, (column+1)*selectionWidth/4, (row+1)*selectionHeight/2)
				if !rect.In(cell.Inset(7)) {
					t.Fatalf("layout %d seed %d: rect %d left its cell safety margin: rect=%v cell=%v", layoutIndex, seed, i, rect, cell)
				}
				for j := 0; j < i; j++ {
					if rect.Overlaps(rects[j]) {
						t.Fatalf("layout %d seed %d: rects %d and %d overlap: %v %v", layoutIndex, seed, i, j, rect, rects[j])
					}
				}
			}
		}
	}
}

func TestVisualIconClickImageKeepsCanvasContract(t *testing.T) {
	opts := seededVisualOptions(20260714)
	var tok behaviorToken
	var presentation BehaviorPresentation
	if err := populateVisualIconClick(opts, &tok, &presentation); err != nil {
		t.Fatal(err)
	}

	imageBounds := decodeVisualPNG(t, presentation.Image).Bounds()
	if imageBounds != image.Rect(0, 0, selectionWidth, selectionHeight) {
		t.Fatalf("unexpected icon image bounds: %v", imageBounds)
	}
	if !promptContainsKnownIconTarget(presentation.Prompt) {
		t.Fatalf("prompt does not describe a known color and icon: %q", presentation.Prompt)
	}
}

func seededVisualOptions(seed int64) BehaviorOptions {
	return BehaviorOptions{Rand: mathrand.New(mathrand.NewSource(seed)), Intensity: 3}
}

func seededVisualChallengeOptions(kind BehaviorType, seed int64) BehaviorOptions {
	opts := seededVisualOptions(seed)
	now := time.Unix(1_752_000_000, 0).UTC()
	opts.Secret = "visual-randomization-test-secret"
	opts.Purpose = "visual-randomization-test"
	opts.ClientKey = "client"
	opts.Path = "/captcha"
	opts.Site = "example.test"
	opts.Type = kind
	opts.Now = func() time.Time { return now }
	return opts
}

func selectionGridIndexFromPoint(t *testing.T, point BehaviorPoint) int {
	t.Helper()
	if !validBehaviorCoord(point.X, point.Y) {
		t.Fatalf("point outside normalized canvas: %+v", point)
	}
	x := point.X * selectionWidth / behaviorCoordinateMax
	y := point.Y * selectionHeight / behaviorCoordinateMax
	column := minBehavior(3, x*4/selectionWidth)
	row := minBehavior(1, y*2/selectionHeight)
	return row*4 + column
}

func selectionGridIndicesFromTargets(t *testing.T, targets [][]int) []int {
	t.Helper()
	indices := make([]int, 0, len(targets))
	seen := make(map[int]struct{}, len(targets))
	for _, target := range targets {
		if len(target) != 4 {
			t.Fatalf("invalid target coordinates: %v", target)
		}
		point := BehaviorPoint{X: (target[0] + target[2]) / 2, Y: (target[1] + target[3]) / 2}
		index := selectionGridIndexFromPoint(t, point)
		if _, exists := seen[index]; exists {
			t.Fatalf("multiple targets occupy grid index %d: %v", index, targets)
		}
		seen[index] = struct{}{}
		indices = append(indices, index)
	}
	return indices
}

func sortedVisualIndices(indices []int) []int {
	sorted := append([]int(nil), indices...)
	sort.Ints(sorted)
	return sorted
}

func decodeVisualPNG(t *testing.T, uri string) image.Image {
	t.Helper()
	const prefix = "data:image/png;base64,"
	if !strings.HasPrefix(uri, prefix) {
		t.Fatalf("missing PNG data URI prefix")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(uri, prefix))
	if err != nil {
		t.Fatalf("decode PNG data URI: %v", err)
	}
	decoded, err := png.Decode(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatalf("decode PNG: %v", err)
	}
	return decoded
}

func promptContainsKnownIconTarget(prompt string) bool {
	knownColor, knownShape := false, false
	for _, palette := range selectionPalette {
		knownColor = knownColor || strings.Contains(prompt, palette.name)
	}
	for _, shape := range iconShapes {
		knownShape = knownShape || strings.Contains(prompt, shape.name)
	}
	return knownColor && knownShape && (strings.Contains(prompt, "最大的") || strings.Contains(prompt, "最小的"))
}
