package captcha

import (
	"image"
	"image/color"
	"math"

	"github.com/LaokeQwQ/CheeseWAF/internal/captcha/imageengine"
)

const (
	visualCurveSamples         = 33
	visualCurveSliderMaxOffset = 16
)

func populateVisualCurveDraw(opts BehaviorOptions, tok *behaviorToken, p *BehaviorPresentation) error {
	curve, err := randomVisualCurve(opts)
	if err != nil {
		return err
	}
	tok.Mode = "curve"
	tok.Curve = curve
	p.Prompt = "Trace the translucent curve from the start marker to the end marker"
	p.Image, err = renderVisualCurve(opts, curve, true)
	if err != nil {
		return err
	}
	p.Track = trackPresentation(tok)
	return nil
}

// populateVisualCurveSlider issues the V3-style drag-to-align challenge only:
// a fixed dashed guide on the background and a solid curve piece that the user
// translates with a horizontal slider until the two coincide.
func populateVisualCurveSlider(opts BehaviorOptions, tok *behaviorToken, p *BehaviorPresentation) error {
	curve, err := randomVisualCurveV3(opts)
	if err != nil {
		return err
	}
	initialMagnitude, err := behaviorRandomInt(opts.Rand, 10, visualCurveSliderMaxOffset)
	if err != nil {
		return err
	}
	direction, err := behaviorRandomInt(opts.Rand, 0, 1)
	if err != nil {
		return err
	}
	initialOffset := initialMagnitude
	if direction == 0 {
		initialOffset = -initialOffset
	}
	// The bitmap contains the initial displacement. The browser only applies a
	// fixed relative movement, so the public payload cannot reveal the target by
	// combining two numeric offsets.
	targetX := clampVisualCoord(5000 - initialOffset*5000/visualCurveSliderMaxOffset)

	tok.Mode = "curve_slider"
	tok.Version = 3
	tok.Point = BehaviorPoint{X: targetX, Y: behaviorCoordinateMax / 2}
	tok.InitialOffset = initialOffset
	tok.Curve = curve

	p.Version = 3
	p.Prompt = "Drag the solid curve until it overlaps the dashed guide"
	p.Image, err = renderVisualCurveGuide(opts, curve)
	if err != nil {
		return err
	}
	p.Piece, err = renderVisualCurvePiece(opts, curve, initialOffset)
	if err != nil {
		return err
	}
	p.Width, p.Height = bitmapWidth, bitmapHeight
	p.Track = trackPresentation(tok)
	p.Track["min_points"] = 3
	return nil
}

func randomVisualCurve(opts BehaviorOptions) ([]BehaviorPoint, error) {
	values := make([]int, 4)
	ranges := [][2]int{{2500, 7500}, {2500, 7500}, {1200, 8800}, {1200, 8800}}
	for i, limits := range ranges {
		value, err := behaviorRandomInt(opts.Rand, limits[0], limits[1])
		if err != nil {
			return nil, err
		}
		values[i] = value
	}
	return sampleCubicCurve(
		BehaviorPoint{X: 900, Y: values[0]},
		BehaviorPoint{X: 3400, Y: values[2]},
		BehaviorPoint{X: 6600, Y: values[3]},
		BehaviorPoint{X: 9100, Y: values[1]},
		visualCurveSamples,
	), nil
}

// randomVisualCurveV3 builds a multi-bend path with several inflection points so
// the align task is harder than a single cubic hump.
func randomVisualCurveV3(opts BehaviorOptions) ([]BehaviorPoint, error) {
	anchors := make([]BehaviorPoint, 6)
	xRanges := [][2]int{{1600, 2000}, {2800, 3200}, {4000, 4400}, {5600, 6000}, {6800, 7200}, {8000, 8400}}
	for i, limits := range xRanges {
		x, err := behaviorRandomInt(opts.Rand, limits[0], limits[1])
		if err != nil {
			return nil, err
		}
		low, high := 1500, 8500
		if i == 0 || i == len(xRanges)-1 {
			low, high = 2200, 7800
		}
		y, err := behaviorRandomInt(opts.Rand, low, high)
		if err != nil {
			return nil, err
		}
		// Encourage visible zig-zag between consecutive anchors.
		if i > 0 {
			prev := anchors[i-1].Y
			if absBehavior(y-prev) < 1200 {
				if prev < 5000 {
					y = minBehavior(8500, prev+1800)
				} else {
					y = maxBehavior(1500, prev-1800)
				}
			}
		}
		anchors[i] = BehaviorPoint{X: x, Y: y}
	}
	return samplePolyline(anchors, visualCurveSamples), nil
}

func sampleCubicCurve(p0, p1, p2, p3 BehaviorPoint, count int) []BehaviorPoint {
	points := make([]BehaviorPoint, count)
	for i := range points {
		t := float64(i) / float64(count-1)
		u := 1 - t
		x := u*u*u*float64(p0.X) + 3*u*u*t*float64(p1.X) + 3*u*t*t*float64(p2.X) + t*t*t*float64(p3.X)
		y := u*u*u*float64(p0.Y) + 3*u*u*t*float64(p1.Y) + 3*u*t*t*float64(p2.Y) + t*t*t*float64(p3.Y)
		points[i] = BehaviorPoint{X: clampVisualCoord(int(math.Round(x))), Y: clampVisualCoord(int(math.Round(y)))}
	}
	return points
}

func samplePolyline(anchors []BehaviorPoint, count int) []BehaviorPoint {
	if count < 2 || len(anchors) == 0 {
		return append([]BehaviorPoint(nil), anchors...)
	}
	if len(anchors) == 1 {
		out := make([]BehaviorPoint, count)
		for i := range out {
			out[i] = anchors[0]
		}
		return out
	}
	lengths := make([]float64, len(anchors)-1)
	total := 0.0
	for i := 1; i < len(anchors); i++ {
		dx := float64(anchors[i].X - anchors[i-1].X)
		dy := float64(anchors[i].Y - anchors[i-1].Y)
		lengths[i-1] = math.Hypot(dx, dy)
		total += lengths[i-1]
	}
	if total <= 0 {
		out := make([]BehaviorPoint, count)
		for i := range out {
			out[i] = anchors[0]
		}
		return out
	}
	points := make([]BehaviorPoint, count)
	for i := range points {
		target := total * float64(i) / float64(count-1)
		travelled := 0.0
		for seg, length := range lengths {
			if travelled+length < target && seg < len(lengths)-1 {
				travelled += length
				continue
			}
			ratio := 0.0
			if length > 0 {
				ratio = (target - travelled) / length
			}
			from, to := anchors[seg], anchors[seg+1]
			points[i] = BehaviorPoint{
				X: clampVisualCoord(int(math.Round(float64(from.X) + (float64(to.X)-float64(from.X))*ratio))),
				Y: clampVisualCoord(int(math.Round(float64(from.Y) + (float64(to.Y)-float64(from.Y))*ratio))),
			}
			break
		}
	}
	return points
}

func renderVisualCurve(opts BehaviorOptions, curve []BehaviorPoint, endpoints bool) (string, error) {
	if len(curve) < 2 {
		return "", nil
	}
	const scale = 2
	canvas := image.NewRGBA(image.Rect(0, 0, bitmapWidth*scale, bitmapHeight*scale))
	fillVisualCurveBackground(canvas, color.RGBA{R: 238, G: 242, B: 245, A: 255})
	engine := bitmapEngine(opts)
	if err := imageengine.AddNoise(canvas, engine.Random, imageengine.NoiseOptions{Dots: 220, Lines: 4, MaxAlpha: 28}); err != nil {
		return "", err
	}
	points := visualCurvePixels(curve, scale)
	drawVisualCurvePolyline(canvas, points, 14*scale, 0, 0, color.RGBA{R: 255, G: 255, B: 255, A: 158})
	drawVisualCurvePolyline(canvas, points, 3*scale, 5*scale, 7*scale, color.RGBA{R: 101, G: 112, B: 124, A: 72})
	if endpoints {
		drawVisualCurveDisc(canvas, points[0], 7*scale, color.RGBA{R: 244, G: 165, B: 28, A: 255})
		drawVisualCurveDisc(canvas, points[0], 4*scale, color.RGBA{R: 255, G: 255, B: 255, A: 255})
		drawVisualCurveDisc(canvas, points[len(points)-1], 6*scale, color.RGBA{R: 244, G: 165, B: 28, A: 255})
	}
	return imageengine.PNGDataURI(downsampleVisualCurve(canvas, scale), engine.Limits)
}

func renderVisualCurveGuide(opts BehaviorOptions, curve []BehaviorPoint) (string, error) {
	if len(curve) < 2 {
		return "", nil
	}
	const scale = 2
	engine := bitmapEngine(opts)
	canvas, err := renderBitmapBackground(engine, bitmapWidth*scale, bitmapHeight*scale)
	if err != nil {
		// Fall back to flat noise plate if gradient helpers fail.
		canvas = image.NewRGBA(image.Rect(0, 0, bitmapWidth*scale, bitmapHeight*scale))
		fillVisualCurveBackground(canvas, color.RGBA{R: 232, G: 238, B: 244, A: 255})
		if noiseErr := imageengine.AddNoise(canvas, engine.Random, imageengine.NoiseOptions{Dots: 260, Lines: 5, MaxAlpha: 34}); noiseErr != nil {
			return "", noiseErr
		}
	} else if err := imageengine.AddNoise(canvas, engine.Random, imageengine.NoiseOptions{Dots: 180, Lines: 3, MaxAlpha: 26}); err != nil {
		return "", err
	}
	points := visualCurvePixels(curve, scale)
	// Soft halo + dashed dark guide: fixed alignment target on the background.
	drawVisualCurvePolyline(canvas, points, 16*scale, 0, 0, color.RGBA{R: 255, G: 255, B: 255, A: 96})
	drawVisualCurvePolyline(canvas, points, 5*scale, 8*scale, 7*scale, color.RGBA{R: 48, G: 64, B: 84, A: 210})
	return imageengine.PNGDataURI(downsampleVisualCurve(canvas, scale), engine.Limits)
}

func renderVisualCurvePiece(opts BehaviorOptions, curve []BehaviorPoint, initialOffset int) (string, error) {
	if len(curve) < 2 {
		return "", nil
	}
	const scale = 2
	canvas := image.NewRGBA(image.Rect(0, 0, bitmapWidth*scale, bitmapHeight*scale))
	fillVisualCurvePieceTexture(canvas, curve, initialOffset)
	points := visualCurvePixels(curve, scale)
	horizontalShift := float64(initialOffset) * bitmapWidth * scale / 100
	for i := range points {
		points[i].x += horizontalShift
	}
	// The movable curve carries a subtle full-canvas texture. It keeps the visual
	// task readable while preventing a transparent-PNG alpha bounding box from
	// disclosing the horizontal displacement.
	drawVisualCurveDiscSolidPolyline(canvas, points, 13*scale, color.RGBA{R: 255, G: 255, B: 255, A: 255})
	drawVisualCurveDiscSolidPolyline(canvas, points, 6*scale, color.RGBA{R: 245, G: 158, B: 11, A: 255})
	piece := downsampleVisualCurveAlpha(canvas, scale)
	engine := bitmapEngine(opts)
	return imageengine.PNGDataURI(piece, engine.Limits)
}

func fillVisualCurvePieceTexture(dst *image.RGBA, curve []BehaviorPoint, initialOffset int) {
	if dst == nil {
		return
	}
	seed := uint32(0x9e3779b9 ^ uint32(initialOffset*7919))
	for _, point := range curve {
		seed ^= uint32(point.X*31 + point.Y*131)
		seed = seed*1664525 + 1013904223
	}
	for y := dst.Bounds().Min.Y; y < dst.Bounds().Max.Y; y++ {
		for x := dst.Bounds().Min.X; x < dst.Bounds().Max.X; x++ {
			value := visualCurveTextureValue(seed, x, y)
			alpha := uint8(28 + value%19)
			// RGBA is premultiplied: preserve a restrained, blue-gray grain rather
			// than a visible opaque panel over the guide image.
			dst.SetRGBA(x, y, color.RGBA{R: alpha / 2, G: alpha / 2, B: alpha - alpha/5, A: alpha})
		}
	}
}

func visualCurveTextureValue(seed uint32, x, y int) uint32 {
	value := seed ^ uint32(x*0x45d9f3b) ^ uint32(y*0x27d4eb2d)
	value ^= value >> 16
	value *= 0x7feb352d
	value ^= value >> 15
	return value
}

func visualCurvePixels(curve []BehaviorPoint, scale int) []visualCurvePixel {
	points := make([]visualCurvePixel, len(curve))
	for i, point := range curve {
		points[i] = visualCurvePixel{
			x: float64(point.X) * bitmapWidth * float64(scale) / behaviorCoordinateMax,
			y: float64(point.Y) * bitmapHeight * float64(scale) / behaviorCoordinateMax,
		}
	}
	return points
}

type visualCurvePixel struct{ x, y float64 }

func fillVisualCurveBackground(dst *image.RGBA, c color.RGBA) {
	for y := dst.Bounds().Min.Y; y < dst.Bounds().Max.Y; y++ {
		for x := dst.Bounds().Min.X; x < dst.Bounds().Max.X; x++ {
			dst.SetRGBA(x, y, c)
		}
	}
}

func drawVisualCurvePolyline(dst *image.RGBA, points []visualCurvePixel, width int, dash, gap int, c color.RGBA) {
	period := float64(dash + gap)
	travelled := 0.0
	for i := 1; i < len(points); i++ {
		from, to := points[i-1], points[i]
		dx, dy := to.x-from.x, to.y-from.y
		length := math.Hypot(dx, dy)
		steps := maxBehavior(1, int(math.Ceil(length*2)))
		for step := 0; step <= steps; step++ {
			distance := travelled + length*float64(step)/float64(steps)
			if period > 0 && math.Mod(distance, period) >= float64(dash) {
				continue
			}
			t := float64(step) / float64(steps)
			drawVisualCurveDisc(dst, visualCurvePixel{x: from.x + dx*t, y: from.y + dy*t}, width/2, c)
		}
		travelled += length
	}
}

func drawVisualCurveDiscSolidPolyline(dst *image.RGBA, points []visualCurvePixel, width int, c color.RGBA) {
	for i := 1; i < len(points); i++ {
		from, to := points[i-1], points[i]
		dx, dy := to.x-from.x, to.y-from.y
		length := math.Hypot(dx, dy)
		steps := maxBehavior(1, int(math.Ceil(length*2)))
		for step := 0; step <= steps; step++ {
			t := float64(step) / float64(steps)
			drawVisualCurveDiscSolid(dst, visualCurvePixel{x: from.x + dx*t, y: from.y + dy*t}, width/2, c)
		}
	}
}

func drawVisualCurveDisc(dst *image.RGBA, center visualCurvePixel, radius int, c color.RGBA) {
	cx, cy := int(math.Round(center.x)), int(math.Round(center.y))
	r2 := radius * radius
	for y := cy - radius; y <= cy+radius; y++ {
		for x := cx - radius; x <= cx+radius; x++ {
			if (x-cx)*(x-cx)+(y-cy)*(y-cy) > r2 || !image.Pt(x, y).In(dst.Bounds()) {
				continue
			}
			base := dst.RGBAAt(x, y)
			a, inv := uint32(c.A), uint32(255-c.A)
			dst.SetRGBA(x, y, color.RGBA{R: uint8((uint32(c.R)*a + uint32(base.R)*inv) / 255), G: uint8((uint32(c.G)*a + uint32(base.G)*inv) / 255), B: uint8((uint32(c.B)*a + uint32(base.B)*inv) / 255), A: 255})
		}
	}
}

func drawVisualCurveDiscSolid(dst *image.RGBA, center visualCurvePixel, radius int, c color.RGBA) {
	cx, cy := int(math.Round(center.x)), int(math.Round(center.y))
	r2 := radius * radius
	for y := cy - radius; y <= cy+radius; y++ {
		for x := cx - radius; x <= cx+radius; x++ {
			if (x-cx)*(x-cx)+(y-cy)*(y-cy) > r2 || !image.Pt(x, y).In(dst.Bounds()) {
				continue
			}
			dst.SetRGBA(x, y, c)
		}
	}
}

func downsampleVisualCurve(src *image.RGBA, scale int) *image.RGBA {
	dst := image.NewRGBA(image.Rect(0, 0, src.Bounds().Dx()/scale, src.Bounds().Dy()/scale))
	area := uint32(scale * scale)
	for y := 0; y < dst.Bounds().Dy(); y++ {
		for x := 0; x < dst.Bounds().Dx(); x++ {
			var r, g, b uint32
			for sy := 0; sy < scale; sy++ {
				for sx := 0; sx < scale; sx++ {
					pixel := src.RGBAAt(x*scale+sx, y*scale+sy)
					r, g, b = r+uint32(pixel.R), g+uint32(pixel.G), b+uint32(pixel.B)
				}
			}
			dst.SetRGBA(x, y, color.RGBA{R: uint8(r / area), G: uint8(g / area), B: uint8(b / area), A: 255})
		}
	}
	return dst
}

func downsampleVisualCurveAlpha(src *image.RGBA, scale int) *image.RGBA {
	dst := image.NewRGBA(image.Rect(0, 0, src.Bounds().Dx()/scale, src.Bounds().Dy()/scale))
	area := uint32(scale * scale)
	for y := 0; y < dst.Bounds().Dy(); y++ {
		for x := 0; x < dst.Bounds().Dx(); x++ {
			var r, g, b, a uint32
			for sy := 0; sy < scale; sy++ {
				for sx := 0; sx < scale; sx++ {
					pixel := src.RGBAAt(x*scale+sx, y*scale+sy)
					r, g, b, a = r+uint32(pixel.R), g+uint32(pixel.G), b+uint32(pixel.B), a+uint32(pixel.A)
				}
			}
			alpha := uint8(a / area)
			if alpha == 0 {
				dst.SetRGBA(x, y, color.RGBA{})
				continue
			}
			dst.SetRGBA(x, y, color.RGBA{R: uint8(r / area), G: uint8(g / area), B: uint8(b / area), A: alpha})
		}
	}
	return dst
}

func verifyVisualCurveDraw(tok behaviorToken, track []BehaviorTrackPoint, duration int) bool {
	if !validBehaviorTrack(tok, track, duration) || len(tok.Curve) < 16 || len(track) < 8 {
		return false
	}
	tolerance := float64(maxBehavior(tok.Tolerance, 180))
	if behaviorDistance(BehaviorPoint{X: track[0].X, Y: track[0].Y}, tok.Curve[0]) > tolerance*1.35 ||
		behaviorDistance(BehaviorPoint{X: track[len(track)-1].X, Y: track[len(track)-1].Y}, tok.Curve[len(tok.Curve)-1]) > tolerance*1.35 ||
		(track[0].Type != "" && track[0].Type != "down") ||
		(track[len(track)-1].Type != "" && track[len(track)-1].Type != "up") {
		return false
	}
	lastIndex := -1
	covered := make([]bool, len(tok.Curve))
	var totalDistance float64
	for i, point := range track {
		index, distance := nearestVisualCurvePoint(tok.Curve, BehaviorPoint{X: point.X, Y: point.Y})
		if distance > tolerance*1.35 || index < lastIndex-1 {
			return false
		}
		if lastIndex >= 0 && index-lastIndex > 5 {
			return false
		}
		if i > 0 && behaviorDistance(BehaviorPoint{X: track[i-1].X, Y: track[i-1].Y}, BehaviorPoint{X: point.X, Y: point.Y}) > 1500 {
			return false
		}
		covered[index] = true
		totalDistance += distance
		if index > lastIndex {
			lastIndex = index
		}
	}
	if totalDistance/float64(len(track)) > tolerance*.72 {
		return false
	}
	return visualCurveCoverage(covered) >= .72 && lastIndex >= len(tok.Curve)-3
}

func verifyVisualCurveSlider(verifiedAtMS int64, tok behaviorToken, response BehaviorResponse) bool {
	if response.Point == nil || !validBehaviorTrack(tok, response.Track, response.DurationMS) {
		return false
	}
	if len(response.Track) < 3 {
		return false
	}
	tolerance := maxBehavior(tok.Tolerance, 180)
	if absBehavior(response.Point.X-tok.Point.X) > tolerance ||
		absBehavior(response.Point.Y-behaviorCoordinateMax/2) > tolerance ||
		!validBehaviorCoord(response.Point.X, response.Point.Y) {
		return false
	}
	first, last := response.Track[0], response.Track[len(response.Track)-1]
	if tok.IssuedMS <= 0 || verifiedAtMS-tok.IssuedMS < int64(tok.MinMS) || first.T != 0 || last.T != response.DurationMS || last.T < tok.MinMS {
		return false
	}
	if (first.Type != "" && first.Type != "down") || (last.Type != "" && last.Type != "up") {
		return false
	}
	if absBehavior(first.X-behaviorCoordinateMax/2) > tolerance ||
		absBehavior(first.Y-behaviorCoordinateMax/2) > tolerance ||
		absBehavior(last.X-response.Point.X) > tolerance ||
		absBehavior(last.Y-response.Point.Y) > tolerance {
		return false
	}
	netMovement := absBehavior(last.X - first.X)
	if netMovement < 650 {
		return false
	}
	distinct := 1
	totalMovement := 0
	reverseMovement := 0
	direction := 1
	if tok.Point.X < behaviorCoordinateMax/2 {
		direction = -1
	}
	for i := 1; i < len(response.Track); i++ {
		current, previous := response.Track[i], response.Track[i-1]
		if absBehavior(current.Y-behaviorCoordinateMax/2) > tolerance {
			return false
		}
		if i < len(response.Track)-1 && current.Type != "" && current.Type != "move" {
			return false
		}
		delta := current.X - previous.X
		totalMovement += absBehavior(delta)
		if delta*direction < 0 {
			reverseMovement += absBehavior(delta)
		}
		if absBehavior(delta) >= 25 || absBehavior(current.Y-previous.Y) >= 25 {
			distinct++
		}
	}
	if reverseMovement > maxBehavior(tolerance*2, totalMovement/3) ||
		totalMovement > netMovement*2+maxBehavior(500, tolerance*2) {
		return false
	}
	return distinct >= 3
}

func nearestVisualCurvePoint(curve []BehaviorPoint, point BehaviorPoint) (int, float64) {
	bestIndex, bestDistance := -1, math.MaxFloat64
	for i, target := range curve {
		if distance := behaviorDistance(point, target); distance < bestDistance {
			bestIndex, bestDistance = i, distance
		}
	}
	return bestIndex, bestDistance
}

func visualCurveCoverage(covered []bool) float64 {
	const bins = 8
	hit := 0
	for bin := 0; bin < bins; bin++ {
		start := bin * len(covered) / bins
		end := (bin + 1) * len(covered) / bins
		for _, value := range covered[start:end] {
			if value {
				hit++
				break
			}
		}
	}
	return float64(hit) / bins
}

func clampVisualCoord(value int) int {
	return maxBehavior(0, minBehavior(behaviorCoordinateMax, value))
}
