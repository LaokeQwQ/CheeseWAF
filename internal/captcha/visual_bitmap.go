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
	bitmapWidth     = 320
	bitmapHeight    = 180
	bitmapPieceSize = 64
)

var sliderShapeKinds = []imageengine.ShapeKind{
	imageengine.ShapePuzzle,
	imageengine.ShapeCircle,
	imageengine.ShapeTriangle,
	imageengine.ShapeSquare,
	imageengine.ShapeDiamond,
	imageengine.ShapeTrapezoid,
	imageengine.ShapeShield,
}

func populateBitmapShapeSlider(opts BehaviorOptions, tok *behaviorToken, p *BehaviorPresentation) error {
	engine := bitmapEngine(opts)
	background, err := renderBitmapBackground(engine, bitmapWidth, bitmapHeight)
	if err != nil {
		return err
	}
	shapeIndex, err := behaviorRandomInt(opts.Rand, 0, len(sliderShapeKinds)-1)
	if err != nil {
		return err
	}
	mask, err := imageengine.NewShapeMask(sliderShapeKinds[shapeIndex], bitmapPieceSize, 7, engine.Limits)
	if err != nil {
		return err
	}
	targetX, err := behaviorRandomInt(opts.Rand, bitmapPieceSize+28, bitmapWidth-bitmapPieceSize-12)
	if err != nil {
		return err
	}
	targetY, err := behaviorRandomInt(opts.Rand, 18, bitmapHeight-bitmapPieceSize-18)
	if err != nil {
		return err
	}
	piece, err := imageengine.ExtractPiece(background, image.Pt(targetX, targetY), mask)
	if err != nil {
		return err
	}
	if err := imageengine.DrawSlot(background, image.Pt(targetX, targetY), mask, color.RGBA{R: 12, G: 18, B: 28, A: 155}, color.RGBA{R: 255, G: 255, B: 255, A: 235}, 3); err != nil {
		return err
	}
	pieceCanvas, err := engine.NewCanvas(bitmapPieceSize, bitmapPieceSize, color.Transparent)
	if err != nil {
		return err
	}
	if err := imageengine.DrawSlot(pieceCanvas.Image(), image.Point{}, mask, color.Transparent, color.RGBA{R: 255, G: 255, B: 255, A: 245}, 3); err != nil {
		return err
	}
	if err := pieceCanvas.DrawLayer(piece, image.Point{}, 255); err != nil {
		return err
	}
	imageURI, err := imageengine.PNGDataURI(background, engine.Limits)
	if err != nil {
		return err
	}
	pieceURI, err := imageengine.PNGDataURI(pieceCanvas.Image(), engine.Limits)
	if err != nil {
		return err
	}
	travel := bitmapWidth - bitmapPieceSize
	tok.Mode = "slider"
	tok.Point = BehaviorPoint{X: targetX * behaviorCoordinateMax / travel, Y: (targetY + bitmapPieceSize/2) * behaviorCoordinateMax / bitmapHeight}
	p.Kind = string(BehaviorShapeSlider)
	p.Image, p.Piece = imageURI, pieceURI
	p.Prompt = "Drag the shape into the matching cutout"
	p.Width, p.Height, p.PieceSize, p.PieceY = bitmapWidth, bitmapHeight, bitmapPieceSize, targetY
	p.Shape = string(sliderShapeKinds[shapeIndex])
	p.Track = trackPresentation(tok)
	return nil
}

func populateBitmapRotate(opts BehaviorOptions, tok *behaviorToken, p *BehaviorPresentation) error {
	engine := bitmapEngine(opts)
	background, err := renderBitmapBackground(engine, bitmapWidth, bitmapHeight)
	if err != nil {
		return err
	}
	drawRotationLandmarks(background, 112)
	initial, err := behaviorRandomInt(opts.Rand, 30, 330)
	if err != nil {
		return err
	}
	uri, err := imageengine.PNGDataURI(background, engine.Limits)
	if err != nil {
		return err
	}
	tok.Mode, tok.Angle = "angle", 0
	p.Kind, p.Image = string(BehaviorRotate), uri
	p.Prompt = "Rotate the center image until its edges align"
	p.Width, p.Height, p.PieceSize, p.InitialAngle = bitmapWidth, bitmapHeight, 112, initial
	p.Track = trackPresentation(tok)
	return nil
}

func populateBitmapAngle(opts BehaviorOptions, tok *behaviorToken, p *BehaviorPresentation) error {
	engine := bitmapEngine(opts)
	background, err := renderBitmapBackground(engine, 220, 220)
	if err != nil {
		return err
	}
	drawRotationLandmarks(background, 164)
	initial, err := behaviorRandomInt(opts.Rand, 30, 330)
	if err != nil {
		return err
	}
	uri, err := imageengine.PNGDataURI(background, engine.Limits)
	if err != nil {
		return err
	}
	tok.Mode, tok.Angle = "angle", 0
	p.Kind, p.Image = string(BehaviorAngle), uri
	p.Prompt = "Rotate the image to its upright position"
	p.Width, p.Height, p.PieceSize, p.InitialAngle = 220, 220, 220, initial
	p.Track = trackPresentation(tok)
	return nil
}

func populateBitmapRestore(opts BehaviorOptions, tok *behaviorToken, p *BehaviorPresentation) error {
	engine := bitmapEngine(opts)
	background, err := renderBitmapBackground(engine, bitmapWidth, bitmapHeight)
	if err != nil {
		return err
	}
	maxOffset, err := behaviorRandomInt(opts.Rand, 22, 34)
	if err != nil {
		return err
	}
	initialMagnitude, err := behaviorRandomInt(opts.Rand, maxOffset/2, maxOffset)
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
	movingPart := "top"
	part, err := behaviorRandomInt(opts.Rand, 0, 1)
	if err != nil {
		return err
	}
	if part == 1 {
		movingPart = "bottom"
	}
	uri, err := imageengine.PNGDataURI(background, engine.Limits)
	if err != nil {
		return err
	}
	tok.Mode = "restore_offset"
	tok.Point = BehaviorPoint{X: 0, Y: behaviorCoordinateMax / 2}
	p.Kind, p.Image = string(BehaviorRestoreSlider), uri
	p.Prompt = "Slide the displaced half until the picture is restored"
	p.Width, p.Height = bitmapWidth, bitmapHeight
	p.MovingPart, p.MaxOffset, p.InitialOffset = movingPart, maxOffset, initialOffset
	p.Track = trackPresentation(tok)
	return nil
}

func bitmapEngine(opts BehaviorOptions) *imageengine.Engine {
	return imageengine.New(imageengine.Limits{MaxWidth: 512, MaxHeight: 512, MaxPixels: 512 * 512, MaxLayers: 32, MaxEncodedBytes: 512 << 10}, imageengine.CryptoRandom{Reader: opts.Rand})
}

func renderBitmapBackground(engine *imageengine.Engine, width, height int) (*image.RGBA, error) {
	if engine == nil {
		return nil, fmt.Errorf("captcha: nil bitmap engine")
	}
	from, err := randomBitmapColor(engine, 34, 116)
	if err != nil {
		return nil, err
	}
	to, err := randomBitmapColor(engine, 112, 214)
	if err != nil {
		return nil, err
	}
	base, err := (imageengine.GradientBackground{From: from, To: to}).Render(engine, width, height)
	if err != nil {
		return nil, err
	}
	dst := image.NewRGBA(base.Bounds())
	draw.Draw(dst, dst.Bounds(), base, base.Bounds().Min, draw.Src)
	for i := 0; i < 18; i++ {
		x, err := imageengine.RandomInt(engine.Random, -width/4, width+width/4)
		if err != nil {
			return nil, err
		}
		y, err := imageengine.RandomInt(engine.Random, -height/4, height+height/4)
		if err != nil {
			return nil, err
		}
		radius, err := imageengine.RandomInt(engine.Random, 10, 44)
		if err != nil {
			return nil, err
		}
		shade, err := randomBitmapColor(engine, 80, 235)
		if err != nil {
			return nil, err
		}
		shade.A = 54
		drawSoftCircle(dst, x, y, radius, shade)
	}
	drawOrientationMark(dst)
	return dst, nil
}

func randomBitmapColor(engine *imageengine.Engine, min, max int) (color.RGBA, error) {
	values := [3]uint8{}
	for i := range values {
		value, err := imageengine.RandomInt(engine.Random, min, max+1)
		if err != nil {
			return color.RGBA{}, err
		}
		values[i] = uint8(value)
	}
	return color.RGBA{R: values[0], G: values[1], B: values[2], A: 255}, nil
}

func drawSoftCircle(dst *image.RGBA, cx, cy, radius int, shade color.RGBA) {
	for y := cy - radius; y <= cy+radius; y++ {
		for x := cx - radius; x <= cx+radius; x++ {
			if !image.Pt(x, y).In(dst.Bounds()) {
				continue
			}
			distance := math.Hypot(float64(x-cx), float64(y-cy))
			if distance > float64(radius) {
				continue
			}
			alpha := uint8(float64(shade.A) * (1 - distance/float64(radius)))
			over := shade
			over.A = alpha
			draw.Draw(dst, image.Rect(x, y, x+1, y+1), &image.Uniform{C: over}, image.Point{}, draw.Over)
		}
	}
}

func drawOrientationMark(dst *image.RGBA) {
	b := dst.Bounds()
	cx := b.Min.X + b.Dx()/2
	top := b.Min.Y + maxBehavior(10, b.Dy()/12)
	mark := color.RGBA{R: 255, G: 255, B: 255, A: 165}
	for y := 0; y < maxBehavior(12, b.Dy()/9); y++ {
		half := y / 2
		for x := cx - half; x <= cx+half; x++ {
			if image.Pt(x, top+y).In(b) {
				dst.Set(x, top+y, mark)
			}
		}
	}
}

func drawRotationLandmarks(dst *image.RGBA, diameter int) {
	if dst == nil || diameter < 32 {
		return
	}
	b := dst.Bounds()
	cx, cy := b.Min.X+b.Dx()/2, b.Min.Y+b.Dy()/2
	radius := diameter / 2
	line := color.RGBA{R: 255, G: 255, B: 255, A: 205}
	accent := color.RGBA{R: 18, G: 52, B: 74, A: 185}
	for offset := -2; offset <= 2; offset++ {
		for x := cx - radius - 18; x <= cx+radius+18; x++ {
			y := cy + (x-cx)/4 + offset
			if image.Pt(x, y).In(b) {
				dst.Set(x, y, line)
			}
		}
	}
	arrowTop := cy - radius/2
	for y := 0; y < maxBehavior(18, diameter/7); y++ {
		half := y / 2
		for x := cx - half; x <= cx+half; x++ {
			if image.Pt(x, arrowTop+y).In(b) {
				dst.Set(x, arrowTop+y, accent)
			}
		}
	}
}
