package captcha

import (
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"math"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/captcha/imageengine"
)

const (
	selectionWidth  = 400
	selectionHeight = 220
	selectionCount  = 8
)

type visualChoice struct {
	label string
	rect  image.Rectangle
	color color.RGBA
	size  int
	angle int
	shape visualShape
}

type visualShape string

const (
	shapeCircle   visualShape = "circle"
	shapeSquare   visualShape = "square"
	shapeTriangle visualShape = "triangle"
	shapeDiamond  visualShape = "diamond"
	shapeCube     visualShape = "cube"
	shapeCone     visualShape = "cone"
	shapeStar     visualShape = "star"
	shapeHeart    visualShape = "heart"
	shapePackage  visualShape = "package"
	shapeSmile    visualShape = "smile"
)

var textGlyphs = []string{"A", "B", "E", "F", "H", "K", "M", "N", "R", "S", "T", "X", "Y", "2", "3", "4", "5", "6", "7", "8", "9"}

var selectionPalette = []struct {
	name string
	fill color.RGBA
}{
	{"蓝色", color.RGBA{R: 38, G: 108, B: 214, A: 255}},
	{"红色", color.RGBA{R: 208, G: 58, B: 66, A: 255}},
	{"绿色", color.RGBA{R: 32, G: 145, B: 92, A: 255}},
	{"黄色", color.RGBA{R: 224, G: 164, B: 32, A: 255}},
	{"紫色", color.RGBA{R: 126, G: 72, B: 191, A: 255}},
}

var iconShapes = []struct {
	name  string
	shape visualShape
}{
	{"圆形", shapeCircle}, {"正方形", shapeSquare}, {"三角形", shapeTriangle},
	{"菱形", shapeDiamond}, {"正方体", shapeCube}, {"圆锥体", shapeCone},
	{"星形", shapeStar}, {"爱心", shapeHeart}, {"包裹", shapePackage}, {"笑脸", shapeSmile},
}

func populateVisualTextClick(opts BehaviorOptions, tok *behaviorToken, p *BehaviorPresentation) error {
	engine := bitmapEngine(opts)
	canvas, err := visualSelectionCanvas(engine)
	if err != nil {
		return err
	}
	perm, err := randomPermutation(opts.Rand, len(textGlyphs))
	if err != nil {
		return err
	}
	sizes := make([]image.Point, selectionCount)
	for i := range sizes {
		size, err := behaviorRandomInt(opts.Rand, 34, 54)
		if err != nil {
			return err
		}
		sizes[i] = image.Pt(size+18, size+18)
	}
	rects, err := selectionGridRects(opts, sizes)
	if err != nil {
		return err
	}
	choices := make([]visualChoice, selectionCount)
	for i := range choices {
		paletteIndex, err := behaviorRandomInt(opts.Rand, 0, len(selectionPalette)-1)
		if err != nil {
			return err
		}
		angle, err := behaviorRandomInt(opts.Rand, -28, 28)
		if err != nil {
			return err
		}
		choices[i] = visualChoice{label: textGlyphs[perm[i]], rect: rects[i], color: selectionPalette[paletteIndex].fill, size: sizes[i].X - 18, angle: angle}
		glyph := renderGlyph(choices[i].label, choices[i].size, choices[i].color, i%3)
		rotated, err := imageengine.RotateScale(glyph, float64(angle), 1, engine.Limits)
		if err != nil {
			return err
		}
		at := image.Pt(rects[i].Min.X+(rects[i].Dx()-rotated.Bounds().Dx())/2, rects[i].Min.Y+(rects[i].Dy()-rotated.Bounds().Dy())/2)
		draw.Draw(canvas, rotated.Bounds().Sub(rotated.Bounds().Min).Add(at), rotated, rotated.Bounds().Min, draw.Over)
	}
	if err := addSelectionForeground(engine, canvas, opts.Intensity, true); err != nil {
		return err
	}
	target, err := behaviorRandomInt(opts.Rand, 0, len(choices)-1)
	if err != nil {
		return err
	}
	tok.Mode = "point"
	tok.Point = rectCenterCoordinate(choices[target].rect, selectionWidth, selectionHeight)
	p.Kind, p.Prompt = string(BehaviorTextClick), fmt.Sprintf("请点击字符 %s", choices[target].label)
	p.Width, p.Height = selectionWidth, selectionHeight
	p.Image, err = imageengine.PNGDataURI(quantizeSelectionImage(canvas), engine.Limits)
	return err
}

func populateVisualIconClick(opts BehaviorOptions, tok *behaviorToken, p *BehaviorPresentation) error {
	engine := bitmapEngine(opts)
	canvas, err := visualSelectionCanvas(engine)
	if err != nil {
		return err
	}
	shapeIndex, err := behaviorRandomInt(opts.Rand, 0, len(iconShapes)-1)
	if err != nil {
		return err
	}
	colorIndex, err := behaviorRandomInt(opts.Rand, 0, len(selectionPalette)-1)
	if err != nil {
		return err
	}
	wantLargest, err := behaviorRandomInt(opts.Rand, 0, 1)
	if err != nil {
		return err
	}
	targetSize := 58
	qualifier := "最大的"
	if wantLargest == 0 {
		targetSize, qualifier = 30, "最小的"
	}
	sizes := make([]image.Point, selectionCount)
	for i := range sizes {
		sizes[i] = image.Pt(68, 68)
	}
	rects, err := selectionGridRects(opts, sizes)
	if err != nil {
		return err
	}
	placement, err := randomPermutation(opts.Rand, selectionCount)
	if err != nil {
		return err
	}
	choices := make([]visualChoice, selectionCount)
	for role, position := range placement {
		shape := iconShapes[(shapeIndex+role)%len(iconShapes)].shape
		palette := selectionPalette[(colorIndex+role)%len(selectionPalette)]
		size := 38 + (role%3)*6
		if role == 0 {
			shape, palette, size = iconShapes[shapeIndex].shape, selectionPalette[colorIndex], targetSize
		}
		// Add two same-color/same-shape decoys whose sizes cannot tie the unique answer.
		if role == 3 || role == 6 {
			shape, palette = iconShapes[shapeIndex].shape, selectionPalette[colorIndex]
			if wantLargest == 1 {
				size = 34 + role/3
			} else {
				size = 50 + role/3
			}
		}
		angle, err := behaviorRandomInt(opts.Rand, -24, 24)
		if err != nil {
			return err
		}
		choices[position] = visualChoice{rect: rects[position], color: palette.fill, size: size, angle: angle, shape: shape}
	}
	for _, choice := range choices {
		drawVisualShape(canvas, choice.rect.Min.X+choice.rect.Dx()/2, choice.rect.Min.Y+choice.rect.Dy()/2, choice.size, choice.angle, choice.shape, choice.color)
	}
	if err := addSelectionForeground(engine, canvas, maxBehavior(1, opts.Intensity/2), false); err != nil {
		return err
	}
	target := placement[0]
	tok.Mode = "point"
	tok.Point = rectCenterCoordinate(choices[target].rect, selectionWidth, selectionHeight)
	p.Kind = string(BehaviorIconClick)
	p.Prompt = fmt.Sprintf("请点击%s%s%s", qualifier, selectionPalette[colorIndex].name, iconShapes[shapeIndex].name)
	p.Width, p.Height = selectionWidth, selectionHeight
	p.Image, err = imageengine.PNGDataURI(quantizeSelectionImage(canvas), engine.Limits)
	return err
}

func visualSelectionCanvas(engine *imageengine.Engine) (*image.RGBA, error) {
	from, err := randomBitmapColor(engine, 198, 232)
	if err != nil {
		return nil, err
	}
	to, err := randomBitmapColor(engine, 225, 248)
	if err != nil {
		return nil, err
	}
	base, err := (imageengine.GradientBackground{From: from, To: to}).Render(engine, selectionWidth, selectionHeight)
	if err != nil {
		return nil, err
	}
	dst := image.NewRGBA(base.Bounds())
	draw.Draw(dst, dst.Bounds(), base, base.Bounds().Min, draw.Src)
	if err := addSelectionBackground(engine, dst); err != nil {
		return nil, err
	}
	return dst, nil
}

func quantizeSelectionImage(src *image.RGBA) *image.RGBA {
	if src == nil {
		return nil
	}
	dst := image.NewRGBA(src.Bounds())
	for y := src.Bounds().Min.Y; y < src.Bounds().Max.Y; y++ {
		for x := src.Bounds().Min.X; x < src.Bounds().Max.X; x++ {
			pixel := src.RGBAAt(x, y)
			pixel.R = quantizeSelectionChannel(pixel.R)
			pixel.G = quantizeSelectionChannel(pixel.G)
			pixel.B = quantizeSelectionChannel(pixel.B)
			pixel.A = 255
			dst.SetRGBA(x, y, pixel)
		}
	}
	return dst
}

func quantizeSelectionChannel(value uint8) uint8 {
	const step = 12
	quantized := (int(value) + step/2) / step * step
	if quantized > 255 {
		quantized = 255
	}
	return uint8(quantized)
}

func addSelectionBackground(engine *imageengine.Engine, dst *image.RGBA) error {
	// Broad, low-contrast structure raises segmentation cost while preserving readability.
	grid := color.RGBA{R: 70, G: 88, B: 112, A: 30}
	for x := -selectionHeight; x < selectionWidth; x += 23 {
		drawThickSelectionLine(dst, x, 0, x+selectionHeight, selectionHeight, 1, grid)
	}
	for y := 17; y < selectionHeight; y += 31 {
		drawThickSelectionLine(dst, 0, y, selectionWidth, y, 1, color.RGBA{R: 255, G: 255, B: 255, A: 38})
	}
	backgroundPalette := []color.RGBA{
		{R: 45, G: 112, B: 192, A: 36},
		{R: 190, G: 74, B: 104, A: 34},
		{R: 90, G: 146, B: 92, A: 32},
		{R: 151, G: 98, B: 184, A: 34},
	}
	for i := 0; i < 7; i++ {
		x, err := imageengine.RandomInt(engine.Random, -30, selectionWidth+30)
		if err != nil {
			return err
		}
		y, err := imageengine.RandomInt(engine.Random, -24, selectionHeight+24)
		if err != nil {
			return err
		}
		width, err := imageengine.RandomInt(engine.Random, 36, 74)
		if err != nil {
			return err
		}
		shade := backgroundPalette[i%len(backgroundPalette)]
		shade.A = 32
		for stripe := -width; stripe <= width; stripe += 9 {
			drawThickSelectionLine(dst, x+stripe, y-width/2, x+stripe+width/2, y+width/2, 1, shade)
		}
	}
	for band := 0; band < 3; band++ {
		y, err := imageengine.RandomInt(engine.Random, 8, selectionHeight-18)
		if err != nil {
			return err
		}
		shade := backgroundPalette[(band+1)%len(backgroundPalette)]
		shade.A = 26
		drawThickSelectionLine(dst, -20, y, selectionWidth+20, y+38, 3, shade)
	}
	for i := 0; i < 72; i++ {
		x, err := imageengine.RandomInt(engine.Random, -12, selectionWidth)
		if err != nil {
			return err
		}
		y, err := imageengine.RandomInt(engine.Random, 0, selectionHeight)
		if err != nil {
			return err
		}
		length, err := imageengine.RandomInt(engine.Random, 9, 28)
		if err != nil {
			return err
		}
		rise, err := imageengine.RandomInt(engine.Random, -9, 10)
		if err != nil {
			return err
		}
		shade := backgroundPalette[i%len(backgroundPalette)]
		shade.A = 42
		drawLine(dst, x, y, x+length, y+rise, shade)
	}
	return imageengine.AddNoise(dst, engine.Random, imageengine.NoiseOptions{Dots: 18, Lines: 2, MaxAlpha: 36})
}

func addSelectionForeground(engine *imageengine.Engine, dst *image.RGBA, intensity int, textMode bool) error {
	intensity = maxBehavior(1, minBehavior(intensity, 6))
	curves, alpha := 2, uint8(108)
	if !textMode {
		curves, alpha = 1, 62
	}
	for i := 0; i < curves; i++ {
		baseY := selectionHeight / 2
		if textMode {
			baseY = selectionHeight/4 + i*selectionHeight/2
		}
		jitter, err := imageengine.RandomInt(engine.Random, -12, 13)
		if err != nil {
			return err
		}
		baseY += jitter
		amplitude, err := imageengine.RandomInt(engine.Random, 12, 31)
		if err != nil {
			return err
		}
		period, err := imageengine.RandomInt(engine.Random, 58, 108)
		if err != nil {
			return err
		}
		phase, err := imageengine.RandomInt(engine.Random, 0, period)
		if err != nil {
			return err
		}
		shade, err := randomBitmapColor(engine, 30, 205)
		if err != nil {
			return err
		}
		shade.A = alpha
		previousY := baseY
		for x := 0; x < selectionWidth; x += 3 {
			y := baseY + int(float64(amplitude)*math.Sin(float64(x+phase)*2*math.Pi/float64(period)))
			drawThickSelectionLine(dst, maxBehavior(0, x-3), previousY, x, y, 2-i%2, shade)
			previousY = y
		}
	}
	marks := 14 + intensity*3
	if !textMode {
		marks = 7 + intensity
	}
	for i := 0; i < marks; i++ {
		x, err := imageengine.RandomInt(engine.Random, 4, selectionWidth-18)
		if err != nil {
			return err
		}
		y, err := imageengine.RandomInt(engine.Random, 4, selectionHeight-8)
		if err != nil {
			return err
		}
		length, err := imageengine.RandomInt(engine.Random, 7, 24)
		if err != nil {
			return err
		}
		shade, err := randomBitmapColor(engine, 35, 210)
		if err != nil {
			return err
		}
		shade.A = alpha - 24
		drawThickSelectionLine(dst, x, y, x+length, y+(i%3-1)*4, 1, shade)
	}
	return imageengine.AddNoise(dst, engine.Random, imageengine.NoiseOptions{Dots: 10 + intensity*4, Lines: 1 + intensity/2, MaxAlpha: uint8(minBehavior(int(alpha), 88))})
}

func addSelectionNoise(engine *imageengine.Engine, dst *image.RGBA, intensity int) error {
	intensity = maxBehavior(1, minBehavior(intensity, 6))
	return imageengine.AddNoise(dst, engine.Random, imageengine.NoiseOptions{Dots: 36 + intensity*18, Lines: 2 + intensity/2, MaxAlpha: 52})
}

func drawThickSelectionLine(dst *image.RGBA, x0, y0, x1, y1, radius int, shade color.RGBA) {
	for offset := -radius; offset <= radius; offset++ {
		drawLine(dst, x0, y0+offset, x1, y1+offset, shade)
	}
}

func selectionGridRects(opts BehaviorOptions, sizes []image.Point) ([]image.Rectangle, error) {
	if len(sizes) != selectionCount {
		return nil, fmt.Errorf("captcha: invalid selection item count")
	}
	rects := make([]image.Rectangle, len(sizes))
	for i, size := range sizes {
		col, row := i%4, i/4
		cell := image.Rect(col*selectionWidth/4, row*selectionHeight/2, (col+1)*selectionWidth/4, (row+1)*selectionHeight/2)
		maxJitterX := maxBehavior(1, (cell.Dx()-size.X)/2-7)
		maxJitterY := maxBehavior(1, (cell.Dy()-size.Y)/2-7)
		jx, err := behaviorRandomInt(opts.Rand, -maxJitterX, maxJitterX)
		if err != nil {
			return nil, err
		}
		jy, err := behaviorRandomInt(opts.Rand, -maxJitterY, maxJitterY)
		if err != nil {
			return nil, err
		}
		cx, cy := cell.Min.X+cell.Dx()/2+jx, cell.Min.Y+cell.Dy()/2+jy
		rects[i] = image.Rect(cx-size.X/2, cy-size.Y/2, cx+(size.X+1)/2, cy+(size.Y+1)/2)
	}
	return rects, nil
}

func rectCenterCoordinate(rect image.Rectangle, width, height int) BehaviorPoint {
	return BehaviorPoint{X: (rect.Min.X + rect.Dx()/2) * behaviorCoordinateMax / width, Y: (rect.Min.Y + rect.Dy()/2) * behaviorCoordinateMax / height}
}

func renderGlyph(label string, size int, fill color.RGBA, style int) *image.RGBA {
	pattern := glyphPattern(label)
	unit := maxBehavior(3, size/8)
	width, height := 5*unit+unit*2, 7*unit+unit*2
	dst := image.NewRGBA(image.Rect(0, 0, width, height))
	for y, row := range pattern {
		for x := 0; x < 5; x++ {
			if row&(1<<uint(4-x)) == 0 {
				continue
			}
			x0, y0 := unit+x*unit, unit+y*unit
			if style == 1 {
				x0 += (6 - y) * unit / 5
			}
			draw.Draw(dst, image.Rect(x0, y0, x0+unit+style%2, y0+unit), image.NewUniform(fill), image.Point{}, draw.Src)
			if style == 2 {
				draw.Draw(dst, image.Rect(x0+1, y0+1, x0+unit, y0+unit), image.NewUniform(color.RGBA{R: fill.R / 2, G: fill.G / 2, B: fill.B / 2, A: 120}), image.Point{}, draw.Over)
			}
		}
	}
	return dst
}

func glyphPattern(label string) [7]uint8 {
	patterns := map[string][7]uint8{
		"A": {14, 17, 17, 31, 17, 17, 17}, "B": {30, 17, 17, 30, 17, 17, 30},
		"E": {31, 16, 16, 30, 16, 16, 31}, "F": {31, 16, 16, 30, 16, 16, 16},
		"H": {17, 17, 17, 31, 17, 17, 17}, "K": {17, 18, 20, 24, 20, 18, 17},
		"M": {17, 27, 21, 21, 17, 17, 17}, "N": {17, 25, 21, 19, 17, 17, 17},
		"R": {30, 17, 17, 30, 20, 18, 17}, "S": {15, 16, 16, 14, 1, 1, 30},
		"T": {31, 4, 4, 4, 4, 4, 4}, "X": {17, 17, 10, 4, 10, 17, 17},
		"Y": {17, 17, 10, 4, 4, 4, 4}, "2": {14, 17, 1, 2, 4, 8, 31},
		"3": {30, 1, 1, 14, 1, 1, 30}, "4": {2, 6, 10, 18, 31, 2, 2},
		"5": {31, 16, 16, 30, 1, 1, 30}, "6": {14, 16, 16, 30, 17, 17, 14},
		"7": {31, 1, 2, 4, 8, 8, 8}, "8": {14, 17, 17, 14, 17, 17, 14},
		"9": {14, 17, 17, 15, 1, 1, 14},
	}
	return patterns[strings.ToUpper(label)]
}

func drawVisualShape(dst *image.RGBA, cx, cy, size, angle int, shape visualShape, fill color.RGBA) {
	local := image.NewRGBA(image.Rect(0, 0, size+18, size+18))
	lcx, lcy := local.Bounds().Dx()/2, local.Bounds().Dy()/2
	for y := 0; y < local.Bounds().Dy(); y++ {
		for x := 0; x < local.Bounds().Dx(); x++ {
			dx, dy := float64(x-lcx), float64(y-lcy)
			inside := visualShapeContains(shape, dx, dy, float64(size)/2)
			if inside {
				local.SetRGBA(x, y, fill)
			}
		}
	}
	if shape == shapeSmile {
		drawSmileDetails(local, lcx, lcy, size)
	}
	rotated, err := imageengine.RotateScale(local, float64(angle), 1, imageengine.DefaultLimits())
	if err != nil {
		return
	}
	at := image.Pt(cx-rotated.Bounds().Dx()/2, cy-rotated.Bounds().Dy()/2)
	draw.Draw(dst, rotated.Bounds().Sub(rotated.Bounds().Min).Add(at), rotated, rotated.Bounds().Min, draw.Over)
}

func visualShapeContains(shape visualShape, x, y, r float64) bool {
	ax, ay := math.Abs(x), math.Abs(y)
	switch shape {
	case shapeCircle, shapeSmile:
		return x*x+y*y <= r*r
	case shapeSquare, shapePackage:
		return ax <= r*.78 && ay <= r*.78
	case shapeDiamond:
		return ax+ay <= r
	case shapeTriangle, shapeCone:
		return y >= -r*.82 && y <= r*.82 && ax <= (y+r*.82)*.62
	case shapeStar:
		a := math.Atan2(y, x)
		limit := r * (.58 + .34*math.Cos(5*a))
		return math.Hypot(x, y) <= limit
	case shapeHeart:
		nx, ny := x/(r*.72), -y/(r*.72)
		v := nx*nx + ny*ny - 1
		return v*v*v-nx*nx*ny*ny*ny <= 0
	case shapeCube:
		return ax <= r*.72 && ay <= r*.72 || (ax+ay <= r*1.18 && y < 0)
	default:
		return false
	}
}

func drawSmileDetails(dst *image.RGBA, cx, cy, size int) {
	dark := color.RGBA{R: 36, G: 43, B: 51, A: 230}
	r := maxBehavior(2, size/16)
	drawSoftCircle(dst, cx-size/6, cy-size/8, r, dark)
	drawSoftCircle(dst, cx+size/6, cy-size/8, r, dark)
	for x := -size / 5; x <= size/5; x++ {
		y := int(float64(size)/9 - math.Sqrt(math.Max(0, float64(size*size)/40-float64(x*x)))/3)
		if image.Pt(cx+x, cy+y+size/8).In(dst.Bounds()) {
			dst.SetRGBA(cx+x, cy+y+size/8, dark)
		}
	}
}
