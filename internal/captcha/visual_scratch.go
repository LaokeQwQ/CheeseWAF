package captcha

import (
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"math"

	"github.com/LaokeQwQ/CheeseWAF/internal/captcha/imageengine"
)

const (
	scratchWidth         = 400
	scratchHeight        = 220
	scratchBrushDiameter = 36
)

func populateVisualScratch(opts BehaviorOptions, tok *behaviorToken, p *BehaviorPresentation) error {
	engine := bitmapEngine(opts)
	canvas, err := visualSelectionCanvas(engine)
	if err != nil {
		return err
	}
	targetCount, err := behaviorRandomInt(opts.Rand, 3, 5)
	if err != nil {
		return err
	}
	shapeIndex, err := behaviorRandomInt(opts.Rand, 0, len(iconShapes)-1)
	if err != nil {
		return err
	}
	shape := iconShapes[shapeIndex]
	total := targetCount + 3
	sizes := make([]image.Point, selectionCount)
	for i := range sizes {
		sizes[i] = image.Pt(54, 54)
	}
	rects, err := selectionGridRects(opts, sizes)
	if err != nil {
		return err
	}
	placement, err := randomPermutation(opts.Rand, selectionCount)
	if err != nil {
		return err
	}
	tok.Targets = make([][]int, 0, targetCount)
	for rank, position := range placement[:total] {
		rect := rects[position]
		itemShape := shape.shape
		if rank >= targetCount {
			itemShape = iconShapes[(shapeIndex+rank+1)%len(iconShapes)].shape
		}
		palette := selectionPalette[(shapeIndex+rank)%len(selectionPalette)].fill
		angle, err := behaviorRandomInt(opts.Rand, -20, 20)
		if err != nil {
			return err
		}
		drawVisualShape(canvas, rect.Min.X+rect.Dx()/2, rect.Min.Y+rect.Dy()/2, 38+rank%3*4, angle, itemShape, palette)
		if rank < targetCount {
			tok.Targets = append(tok.Targets, rectToCoordinates(rect, scratchWidth, scratchHeight))
		}
	}
	if err := addSelectionNoise(engine, canvas, maxBehavior(1, opts.Intensity/2)); err != nil {
		return err
	}
	mask := image.NewRGBA(canvas.Bounds())
	draw.Draw(mask, mask.Bounds(), image.NewUniform(color.RGBA{R: 164, G: 171, B: 179, A: 247}), image.Point{}, draw.Src)
	for y := 0; y < scratchHeight; y += 12 {
		shade := uint8(168 + (y/12)%3*7)
		draw.Draw(mask, image.Rect(0, y, scratchWidth, minBehavior(scratchHeight, y+6)), image.NewUniform(color.RGBA{R: shade, G: shade + 5, B: shade + 9, A: 247}), image.Point{}, draw.Src)
	}
	if err := imageengine.AddNoise(mask, engine.Random, imageengine.NoiseOptions{Dots: 28, Lines: 4, MaxAlpha: 50}); err != nil {
		return err
	}
	tok.Mode = "scratch"
	tok.Region = []int{0, 0, behaviorCoordinateMax, behaviorCoordinateMax}
	tok.Coverage = 82
	p.Kind = string(BehaviorScratch)
	p.Prompt = fmt.Sprintf("请完整刮出 %d 个%s后点击校验", targetCount, shape.name)
	p.Width, p.Height = scratchWidth, scratchHeight
	p.Track = trackPresentation(tok)
	p.Image, err = imageengine.PNGDataURI(canvas, engine.Limits)
	if err != nil {
		return err
	}
	p.Piece, err = imageengine.PNGDataURI(mask, engine.Limits)
	return err
}

func verifyVisualScratch(tok behaviorToken, track []BehaviorTrackPoint, duration int) bool {
	if !validBehaviorTrack(tok, track, duration) || len(tok.Targets) < 2 || len(tok.Targets) > 8 {
		return false
	}
	if len(track) < 12 || !scratchTrackContinuous(track) {
		return false
	}
	const grid = 64
	covered := make([]bool, grid*grid)
	for i := 1; i < len(track); i++ {
		if track[i].Type == "down" || track[i-1].Type == "up" {
			continue
		}
		paintScratchSegment(covered, grid, track[i-1], track[i], scratchBrushDiameter, scratchWidth, scratchHeight)
	}
	totalCovered := 0
	for _, value := range covered {
		if value {
			totalCovered++
		}
	}
	// A human should uncover the requested objects, not erase nearly the entire panel.
	if totalCovered*100/(grid*grid) > 76 {
		return false
	}
	for _, target := range tok.Targets {
		if len(target) != 4 || target[0] < 0 || target[1] < 0 || target[2] > behaviorCoordinateMax || target[3] > behaviorCoordinateMax || target[0] >= target[2] || target[1] >= target[3] {
			return false
		}
		inside, revealed := 0, 0
		for gy := 0; gy < grid; gy++ {
			py := (2*gy + 1) * behaviorCoordinateMax / (2 * grid)
			if py < target[1] || py > target[3] {
				continue
			}
			for gx := 0; gx < grid; gx++ {
				px := (2*gx + 1) * behaviorCoordinateMax / (2 * grid)
				if px < target[0] || px > target[2] {
					continue
				}
				inside++
				if covered[gy*grid+gx] {
					revealed++
				}
			}
		}
		if inside == 0 || revealed*100/inside < tok.Coverage {
			return false
		}
	}
	return true
}

func scratchTrackContinuous(track []BehaviorTrackPoint) bool {
	pathLength := 0.0
	for i := 1; i < len(track); i++ {
		if track[i].Type == "down" || track[i-1].Type == "up" {
			continue
		}
		distance := math.Hypot(float64(track[i].X-track[i-1].X), float64(track[i].Y-track[i-1].Y))
		deltaT := track[i].T - track[i-1].T
		if deltaT < 0 || distance > 1450 || (deltaT == 0 && distance > 180) {
			return false
		}
		pathLength += distance
	}
	return pathLength >= 1800
}

func paintScratchSegment(covered []bool, grid int, from, to BehaviorTrackPoint, brushDiameter, width, height int) {
	if grid <= 0 || width <= 0 || height <= 0 || brushDiameter <= 0 || len(covered) < grid*grid {
		return
	}
	fromX := float64(from.X) * float64(width) / behaviorCoordinateMax
	fromY := float64(from.Y) * float64(height) / behaviorCoordinateMax
	toX := float64(to.X) * float64(width) / behaviorCoordinateMax
	toY := float64(to.Y) * float64(height) / behaviorCoordinateMax
	radiusSquared := math.Pow(float64(brushDiameter)/2, 2)

	for gy := 0; gy < grid; gy++ {
		py := (float64(gy) + .5) * float64(height) / float64(grid)
		for gx := 0; gx < grid; gx++ {
			px := (float64(gx) + .5) * float64(width) / float64(grid)
			if scratchPointSegmentDistanceSquared(px, py, fromX, fromY, toX, toY) <= radiusSquared {
				covered[gy*grid+gx] = true
			}
		}
	}
}

func scratchPointSegmentDistanceSquared(px, py, fromX, fromY, toX, toY float64) float64 {
	dx, dy := toX-fromX, toY-fromY
	lengthSquared := dx*dx + dy*dy
	if lengthSquared == 0 {
		return (px-fromX)*(px-fromX) + (py-fromY)*(py-fromY)
	}
	t := ((px-fromX)*dx + (py-fromY)*dy) / lengthSquared
	t = math.Max(0, math.Min(1, t))
	nearestX, nearestY := fromX+t*dx, fromY+t*dy
	return (px-nearestX)*(px-nearestX) + (py-nearestY)*(py-nearestY)
}

func rectToCoordinates(rect image.Rectangle, width, height int) []int {
	return []int{rect.Min.X * behaviorCoordinateMax / width, rect.Min.Y * behaviorCoordinateMax / height, rect.Max.X * behaviorCoordinateMax / width, rect.Max.Y * behaviorCoordinateMax / height}
}
