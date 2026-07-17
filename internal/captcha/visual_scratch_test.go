package captcha

import (
	"fmt"
	"image"
	"strings"
	"testing"
)

func TestVisualScratchTargetSubsetDistributionAcrossSeeds(t *testing.T) {
	const samples = 64
	targeted := make([]int, selectionCount)
	omitted := make([]int, selectionCount)
	combinations := make(map[string]struct{})
	prefixMatches := 0

	for seed := int64(1); seed <= samples; seed++ {
		opts := seededVisualOptions(seed)
		var tok behaviorToken
		var presentation BehaviorPresentation
		if err := populateVisualScratch(opts, &tok, &presentation); err != nil {
			t.Fatalf("seed %d: populate scratch: %v", seed, err)
		}

		indices := selectionGridIndicesFromTargets(t, tok.Targets)
		sorted := sortedVisualIndices(indices)
		combinations[fmt.Sprint(sorted)] = struct{}{}
		prefix := true
		present := make([]bool, selectionCount)
		for i, index := range sorted {
			present[index] = true
			prefix = prefix && index == i
		}
		if prefix {
			prefixMatches++
		}
		for index := range present {
			if present[index] {
				targeted[index]++
			} else {
				omitted[index]++
			}
		}

		if tok.Mode != "scratch" || presentation.Kind != string(BehaviorScratch) {
			t.Fatalf("seed %d: unexpected scratch contract: mode=%q kind=%q", seed, tok.Mode, presentation.Kind)
		}
		if presentation.Width != scratchWidth || presentation.Height != scratchHeight {
			t.Fatalf("seed %d: unexpected scratch dimensions: %dx%d", seed, presentation.Width, presentation.Height)
		}
		if !strings.Contains(presentation.Prompt, fmt.Sprintf("%d 个", len(tok.Targets))) {
			t.Fatalf("seed %d: prompt and sealed target count diverged: prompt=%q targets=%d", seed, presentation.Prompt, len(tok.Targets))
		}
		assertScratchTargetsDoNotOverlap(t, tok.Targets)
	}

	if len(combinations) < selectionCount {
		t.Fatalf("scratch target subsets have insufficient variety: combinations=%d targeted=%v", len(combinations), targeted)
	}
	if prefixMatches >= samples/2 {
		t.Fatalf("scratching the row-major first N cells remains predictive: prefix=%d/%d", prefixMatches, samples)
	}
	for index := 0; index < selectionCount; index++ {
		if targeted[index] == 0 || omitted[index] == 0 {
			t.Fatalf("grid index %d must appear in both target and decoy/blank subsets: targeted=%v omitted=%v", index, targeted, omitted)
		}
	}
}

func TestVerifyVisualScratchRejectsFixedPrefixForGeneratedNonPrefixTargets(t *testing.T) {
	var opts BehaviorOptions
	var challenge BehaviorChallenge
	var tok behaviorToken
	found := false
	for seed := int64(1); seed <= 64; seed++ {
		candidateOpts := seededVisualChallengeOptions(BehaviorScratch, seed)
		candidateChallenge, err := IssueBehaviorChallenge(candidateOpts)
		if err != nil {
			t.Fatalf("seed %d: issue scratch: %v", seed, err)
		}
		candidate, ok := openBehaviorToken(normalizeBehaviorOptions(candidateOpts), candidateChallenge.Token)
		if !ok {
			t.Fatalf("seed %d: open sealed scratch token", seed)
		}
		indices := sortedVisualIndices(selectionGridIndicesFromTargets(t, candidate.Targets))
		prefix := true
		for i, index := range indices {
			prefix = prefix && index == i
		}
		if !prefix {
			opts, challenge, tok, found = candidateOpts, candidateChallenge, candidate, true
			break
		}
	}
	if !found {
		t.Fatal("no non-prefix scratch target set found across deterministic seeds")
	}

	track := fixedScratchPrefixTrack(len(tok.Targets))
	duration := track[len(track)-1].T
	if !scratchTrackContinuous(track) {
		t.Fatal("fixed-prefix test trajectory must pass continuity checks")
	}
	wrong := VerifyBehaviorChallenge(opts, BehaviorResponse{Token: challenge.Token, Track: track, DurationMS: duration})
	if wrong.Valid || wrong.Reason != "incorrect" {
		t.Fatalf("fixed-prefix scratch was not rejected as incorrect: %+v", wrong)
	}
	correctTrack := scratchTargetTrack(tok.Targets)
	correct := VerifyBehaviorChallenge(opts, BehaviorResponse{Token: challenge.Token, Track: correctTrack, DurationMS: correctTrack[len(correctTrack)-1].T})
	if !correct.Valid {
		t.Fatalf("sealed scratch targets rejected: %+v", correct)
	}
}

func TestVisualScratchImageAndMaskKeepCanvasContract(t *testing.T) {
	opts := seededVisualOptions(20260714)
	var tok behaviorToken
	var presentation BehaviorPresentation
	if err := populateVisualScratch(opts, &tok, &presentation); err != nil {
		t.Fatal(err)
	}

	for name, uri := range map[string]string{"image": presentation.Image, "mask": presentation.Piece} {
		bounds := decodeVisualPNG(t, uri).Bounds()
		if bounds != image.Rect(0, 0, scratchWidth, scratchHeight) {
			t.Fatalf("unexpected scratch %s bounds: %v", name, bounds)
		}
	}
	if len(tok.Targets) < 3 || len(tok.Targets) > 5 {
		t.Fatalf("unexpected sealed target count: %d", len(tok.Targets))
	}
}

func TestPaintScratchSegmentUsesPixelBrushDiameter(t *testing.T) {
	const grid = 200
	covered := make([]bool, grid*grid)
	from := BehaviorTrackPoint{X: 1000, Y: 5000}
	to := BehaviorTrackPoint{X: 9000, Y: 5000}

	paintScratchSegment(covered, grid, from, to, scratchBrushDiameter, scratchWidth, scratchHeight)

	if !scratchGridCellCovered(covered, grid, 200, 125) {
		t.Fatal("a point 15px from the stroke center must match the visible 36px brush")
	}
	if scratchGridCellCovered(covered, grid, 200, 131) {
		t.Fatal("a point outside the visible 18px brush radius must not be accepted")
	}
}

func TestPaintScratchSegmentKeepsRoundCaps(t *testing.T) {
	const grid = 200
	covered := make([]bool, grid*grid)
	point := BehaviorTrackPoint{X: 5000, Y: 5000}

	paintScratchSegment(covered, grid, point, point, scratchBrushDiameter, scratchWidth, scratchHeight)

	if !scratchGridCellCovered(covered, grid, 214, 110) {
		t.Fatal("a stationary stroke must reveal the same round brush cap as the canvas")
	}
	if scratchGridCellCovered(covered, grid, 220, 110) {
		t.Fatal("round cap coverage must remain bounded by the visible brush radius")
	}
}

func TestVerifyVisualScratchAcceptsFrontendSizedBrushStrokes(t *testing.T) {
	targets := [][]int{
		{scratchPixelCoord(40, scratchWidth), scratchPixelCoord(40, scratchHeight), scratchPixelCoord(94, scratchWidth), scratchPixelCoord(94, scratchHeight)},
		{scratchPixelCoord(180, scratchWidth), scratchPixelCoord(120, scratchHeight), scratchPixelCoord(234, scratchWidth), scratchPixelCoord(174, scratchHeight)},
	}
	tok := behaviorToken{Targets: targets, Coverage: 82, MinMS: 100, MaxMS: 5000, MaxPoints: 64}
	track := make([]BehaviorTrackPoint, 0, 12)
	for _, target := range targets {
		for _, y := range []int{9, 27, 45} {
			baseX := target[0] * scratchWidth / behaviorCoordinateMax
			baseY := target[1] * scratchHeight / behaviorCoordinateMax
			track = append(track,
				BehaviorTrackPoint{X: scratchPixelCoord(baseX, scratchWidth), Y: scratchPixelCoord(baseY+y, scratchHeight), T: len(track) * 100, Type: "down"},
				BehaviorTrackPoint{X: scratchPixelCoord(baseX+54, scratchWidth), Y: scratchPixelCoord(baseY+y, scratchHeight), T: len(track)*100 + 80, Type: "up"},
			)
		}
	}
	duration := track[len(track)-1].T

	if !verifyVisualScratch(tok, track, duration) {
		t.Fatal("strokes that visibly uncover every target must be accepted by the server")
	}
}

func TestVerifyVisualScratchRejectsWholePanelErasureWithContinuousSegments(t *testing.T) {
	tok := behaviorToken{
		Targets:   [][]int{{1000, 1000, 2500, 2500}, {7000, 7000, 8500, 8500}},
		Coverage:  82,
		MinMS:     100,
		MaxMS:     10000,
		MaxPoints: 1024,
	}
	track := make([]BehaviorTrackPoint, 0, 451)
	for row := 0; row <= 40; row++ {
		y := row * behaviorCoordinateMax / 40
		for column := 0; column <= 10; column++ {
			x := column * behaviorCoordinateMax / 10
			if row%2 == 1 {
				x = behaviorCoordinateMax - x
			}
			pointType := "move"
			if column == 0 {
				pointType = "down"
			} else if column == 10 {
				pointType = "up"
			}
			track = append(track, BehaviorTrackPoint{X: x, Y: y, T: len(track) * 5, Type: pointType})
		}
	}
	duration := track[len(track)-1].T
	if !scratchTrackContinuous(track) {
		t.Fatal("test trajectory must satisfy continuity checks before coverage is evaluated")
	}
	if verifyVisualScratch(tok, track, duration) {
		t.Fatal("erasing nearly the entire panel must remain rejected")
	}
}

func scratchPixelCoord(pixel, extent int) int {
	return pixel * behaviorCoordinateMax / extent
}

func scratchGridCellCovered(covered []bool, grid, pixelX, pixelY int) bool {
	gx := pixelX * grid / scratchWidth
	gy := pixelY * grid / scratchHeight
	return covered[gy*grid+gx]
}

func assertScratchTargetsDoNotOverlap(t *testing.T, targets [][]int) {
	t.Helper()
	regions := make([]image.Rectangle, 0, len(targets))
	for _, target := range targets {
		region := image.Rect(target[0], target[1], target[2], target[3])
		for i, existing := range regions {
			if region.Overlaps(existing) {
				t.Fatalf("scratch targets %d and %d overlap: %v %v", len(regions), i, region, existing)
			}
		}
		regions = append(regions, region)
	}
}

func fixedScratchPrefixTrack(targetCount int) []BehaviorTrackPoint {
	track := make([]BehaviorTrackPoint, 0, targetCount*8)
	elapsed := 0
	for index := 0; index < targetCount; index++ {
		column, row := index%4, index/4
		centerX := column*scratchWidth/4 + scratchWidth/8
		cellTop := row * scratchHeight / 2
		for _, offsetY := range []int{18, 43, 68, 92} {
			track = append(track,
				BehaviorTrackPoint{X: scratchPixelCoord(centerX-27, scratchWidth), Y: scratchPixelCoord(cellTop+offsetY, scratchHeight), T: elapsed, Type: "down"},
				BehaviorTrackPoint{X: scratchPixelCoord(centerX+27, scratchWidth), Y: scratchPixelCoord(cellTop+offsetY, scratchHeight), T: elapsed + 40, Type: "up"},
			)
			elapsed += 80
		}
	}
	return track
}

func scratchTargetTrack(targets [][]int) []BehaviorTrackPoint {
	track := make([]BehaviorTrackPoint, 0, len(targets)*6)
	for _, target := range targets {
		baseX := target[0] * scratchWidth / behaviorCoordinateMax
		baseY := target[1] * scratchHeight / behaviorCoordinateMax
		for _, y := range []int{9, 27, 45} {
			start := len(track) * 100
			track = append(track,
				BehaviorTrackPoint{X: scratchPixelCoord(baseX, scratchWidth), Y: scratchPixelCoord(baseY+y, scratchHeight), T: start, Type: "down"},
				BehaviorTrackPoint{X: scratchPixelCoord(baseX+54, scratchWidth), Y: scratchPixelCoord(baseY+y, scratchHeight), T: start + 80, Type: "up"},
			)
		}
	}
	return track
}
