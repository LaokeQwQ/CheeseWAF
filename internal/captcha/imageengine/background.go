package imageengine

import (
	"image"
	"image/color"
)

type Background interface {
	Render(engine *Engine, width, height int) (image.Image, error)
}

type GradientBackground struct{ From, To color.RGBA }

func (g GradientBackground) Render(engine *Engine, width, height int) (image.Image, error) {
	if engine == nil {
		engine = New(Limits{}, nil)
	}
	if err := engine.Limits.normalized().validateDimensions(width, height); err != nil {
		return nil, err
	}
	dst := image.NewRGBA(image.Rect(0, 0, width, height))
	denominator := height - 1
	if denominator < 1 {
		denominator = 1
	}
	for y := 0; y < height; y++ {
		t := float64(y) / float64(denominator)
		row := color.RGBA{R: interpolate(g.From.R, g.To.R, t), G: interpolate(g.From.G, g.To.G, t), B: interpolate(g.From.B, g.To.B, t), A: interpolate(g.From.A, g.To.A, t)}
		for x := 0; x < width; x++ {
			dst.SetRGBA(x, y, row)
		}
	}
	return dst, nil
}

func CropCover(src image.Image, width, height int, limits Limits) (*image.RGBA, error) {
	if src == nil {
		return nil, ErrInvalidImage
	}
	limits = limits.normalized()
	if err := limits.validateDimensions(width, height); err != nil {
		return nil, err
	}
	b := src.Bounds()
	if b.Empty() || int64(b.Dx()) > limits.MaxPixels/int64(b.Dy()) {
		return nil, ErrInvalidImage
	}
	scaleX, scaleY := float64(width)/float64(b.Dx()), float64(height)/float64(b.Dy())
	scale := scaleX
	if scaleY > scale {
		scale = scaleY
	}
	scaledW, scaledH := int(float64(b.Dx())*scale+0.5), int(float64(b.Dy())*scale+0.5)
	offsetX, offsetY := (scaledW-width)/2, (scaledH-height)/2
	dst := image.NewRGBA(image.Rect(0, 0, width, height))
	for y := 0; y < height; y++ {
		sy := b.Min.Y + (y+offsetY)*b.Dy()/scaledH
		for x := 0; x < width; x++ {
			sx := b.Min.X + (x+offsetX)*b.Dx()/scaledW
			dst.Set(x, y, src.At(sx, sy))
		}
	}
	return dst, nil
}

func interpolate(from, to uint8, t float64) uint8 {
	return uint8(float64(from)*(1-t) + float64(to)*t + 0.5)
}
