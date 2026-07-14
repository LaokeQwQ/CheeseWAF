package imageengine

import (
	"image"
	"image/color"
	"image/draw"
)

type Engine struct {
	Limits Limits
	Random RandomSource
}

func New(limits Limits, rng RandomSource) *Engine {
	if rng == nil {
		rng = CryptoRandom{}
	}
	return &Engine{Limits: limits.normalized(), Random: rng}
}

type Canvas struct {
	image  *image.RGBA
	limits Limits
	layers int
}

func (e *Engine) NewCanvas(width, height int, background color.Color) (*Canvas, error) {
	if e == nil {
		e = New(Limits{}, nil)
	}
	limits := e.Limits.normalized()
	if err := limits.validateDimensions(width, height); err != nil {
		return nil, err
	}
	if background == nil {
		background = color.Transparent
	}
	dst := image.NewRGBA(image.Rect(0, 0, width, height))
	draw.Draw(dst, dst.Bounds(), &image.Uniform{C: background}, image.Point{}, draw.Src)
	return &Canvas{image: dst, limits: limits}, nil
}

func (c *Canvas) Image() *image.RGBA {
	if c == nil {
		return nil
	}
	return c.image
}

func (c *Canvas) DrawLayer(src image.Image, at image.Point, opacity uint8) error {
	if c == nil || c.image == nil || src == nil {
		return ErrInvalidImage
	}
	if c.layers >= c.limits.MaxLayers {
		return ErrResourceLimit
	}
	bounds := src.Bounds()
	dstRect := bounds.Sub(bounds.Min).Add(at).Intersect(c.image.Bounds())
	if !dstRect.Empty() && opacity > 0 {
		srcPoint := bounds.Min.Add(dstRect.Min.Sub(at))
		if opacity == 255 {
			draw.Draw(c.image, dstRect, src, srcPoint, draw.Over)
		} else {
			draw.DrawMask(c.image, dstRect, src, srcPoint, image.NewUniform(color.Alpha{A: opacity}), image.Point{}, draw.Over)
		}
	}
	c.layers++
	return nil
}
