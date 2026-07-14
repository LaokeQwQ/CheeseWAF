package captcha

import (
	"image"
	"image/color"
	"math"

	"github.com/LaokeQwQ/CheeseWAF/internal/captcha/imageengine"
)

const visualCurveSamples = 33

// sliderCurve is mirrored by the browser's public curve formula contract.
const (
	visualCurveCoordinateMax = 10000
	visualCurveCenter        = 5000
	visualCurveStartX        = 900
	visualCurveWidth         = 8200
	visualCurveAmplitudeMin  = 650
	visualCurveAmplitudeSpan = 1900
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

func populateVisualCurveSlider(opts BehaviorOptions, tok *behaviorToken, p *BehaviorPresentation) error {
	target, err := behaviorRandomInt(opts.Rand, 1800, 8200)
	if err != nil {
		return err
	}
	tok.Mode = "curve_slider"
	tok.Point = BehaviorPoint{X: target, Y: behaviorCoordinateMax / 2}
	tok.Curve = sliderCurve(target, opts.Version)
	p.Prompt = "Drag the slider until the white curve overlaps the translucent guide"
	p.Image, err = renderVisualCurve(opts, tok.Curve, false)
	if err != nil {
		return err
	}
	p.Track = trackPresentation(tok)
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

func sliderCurve(parameter, version int) []BehaviorPoint {
	points := make([]BehaviorPoint, visualCurveSamples)
	parameter = clampVisualCoord(parameter)
	amplitude := visualCurveAmplitudeMin + parameter*visualCurveAmplitudeSpan/visualCurveCoordinateMax
	phase := float64(parameter) / visualCurveCoordinateMax * math.Pi
	for i := range points {
		t := float64(i) / float64(len(points)-1)
		x := visualCurveStartX + int(math.Round(t*visualCurveWidth))
		wave := sliderCurveWave(t, phase, version)
		points[i] = BehaviorPoint{X: x, Y: clampVisualCoord(visualCurveCenter + int(math.Round(wave*float64(amplitude))))}
	}
	return points
}

func sliderCurveWave(t, phase float64, version int) float64 {
	switch version {
	case 1:
		return math.Sin(t*math.Pi + phase)
	case 2:
		return math.Sin(t*2*math.Pi+phase) * .72
	default:
		return math.Sin(t*math.Pi+phase)*.62 + math.Sin(t*3*math.Pi-phase)*.24
	}
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
	points := make([]visualCurvePixel, len(curve))
	for i, point := range curve {
		points[i] = visualCurvePixel{
			x: float64(point.X) * bitmapWidth * scale / behaviorCoordinateMax,
			y: float64(point.Y) * bitmapHeight * scale / behaviorCoordinateMax,
		}
	}
	drawVisualCurvePolyline(canvas, points, 14*scale, 0, 0, color.RGBA{R: 255, G: 255, B: 255, A: 158})
	drawVisualCurvePolyline(canvas, points, 3*scale, 5*scale, 7*scale, color.RGBA{R: 101, G: 112, B: 124, A: 72})
	if endpoints {
		drawVisualCurveDisc(canvas, points[0], 7*scale, color.RGBA{R: 244, G: 165, B: 28, A: 255})
		drawVisualCurveDisc(canvas, points[0], 4*scale, color.RGBA{R: 255, G: 255, B: 255, A: 255})
		drawVisualCurveDisc(canvas, points[len(points)-1], 6*scale, color.RGBA{R: 244, G: 165, B: 28, A: 255})
	}
	return imageengine.PNGDataURI(downsampleVisualCurve(canvas, scale), engine.Limits)
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

func verifyVisualCurveSlider(tok behaviorToken, response BehaviorResponse) bool {
	if response.Point == nil || !validBehaviorTrack(tok, response.Track, response.DurationMS) {
		return false
	}
	tolerance := maxBehavior(tok.Tolerance, 180)
	if absBehavior(response.Point.X-tok.Point.X) > tolerance || !validBehaviorCoord(response.Point.X, response.Point.Y) {
		return false
	}
	first, last := response.Track[0], response.Track[len(response.Track)-1]
	if (first.Type != "" && first.Type != "down") || (last.Type != "" && last.Type != "up") {
		return false
	}
	if absBehavior(last.X-response.Point.X) > tolerance || absBehavior(last.Y-response.Point.Y) > tolerance {
		return false
	}
	if behaviorDistance(BehaviorPoint{X: first.X, Y: first.Y}, BehaviorPoint{X: last.X, Y: last.Y}) < 650 {
		return false
	}
	distinct := 1
	for i := 1; i < len(response.Track); i++ {
		if absBehavior(response.Track[i].X-response.Track[i-1].X) >= 25 || absBehavior(response.Track[i].Y-response.Track[i-1].Y) >= 25 {
			distinct++
		}
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

func visualSVGCoord(value, extent int) float64 {
	return float64(value) * float64(extent) / behaviorCoordinateMax
}

func clampVisualCoord(value int) int {
	return maxBehavior(0, minBehavior(behaviorCoordinateMax, value))
}
