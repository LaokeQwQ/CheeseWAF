package imageengine

import (
	"errors"
	"image"
	"image/color"
)

type NoiseOptions struct {
	Dots, Lines int
	MaxAlpha    uint8
}

func AddNoise(dst *image.RGBA, rng RandomSource, opts NoiseOptions) error {
	if dst == nil || rng == nil || dst.Bounds().Empty() {
		return ErrInvalidImage
	}
	if opts.Dots < 0 || opts.Lines < 0 || opts.Dots > 20_000 || opts.Lines > 1_000 {
		return ErrResourceLimit
	}
	if opts.MaxAlpha == 0 {
		opts.MaxAlpha = 96
	}
	b := dst.Bounds()
	for i := 0; i < opts.Dots; i++ {
		x, err := RandomInt(rng, b.Min.X, b.Max.X)
		if err != nil {
			return err
		}
		y, err := RandomInt(rng, b.Min.Y, b.Max.Y)
		if err != nil {
			return err
		}
		c, err := randomNoiseColor(rng, opts.MaxAlpha)
		if err != nil {
			return err
		}
		blendPixel(dst, x, y, c)
	}
	for i := 0; i < opts.Lines; i++ {
		x0, err := RandomInt(rng, b.Min.X, b.Max.X)
		if err != nil {
			return err
		}
		y0, err := RandomInt(rng, b.Min.Y, b.Max.Y)
		if err != nil {
			return err
		}
		x1, err := RandomInt(rng, b.Min.X, b.Max.X)
		if err != nil {
			return err
		}
		y1, err := RandomInt(rng, b.Min.Y, b.Max.Y)
		if err != nil {
			return err
		}
		c, err := randomNoiseColor(rng, opts.MaxAlpha)
		if err != nil {
			return err
		}
		drawLine(dst, x0, y0, x1, y1, c)
	}
	return nil
}

func randomNoiseColor(rng RandomSource, maxAlpha uint8) (color.RGBA, error) {
	var raw [4]byte
	if _, err := rng.Read(raw[:]); err != nil {
		return color.RGBA{}, err
	}
	if maxAlpha < 16 {
		return color.RGBA{}, errors.New("imageengine: noise alpha too low")
	}
	return color.RGBA{R: raw[0], G: raw[1], B: raw[2], A: 16 + raw[3]%(maxAlpha-15)}, nil
}

func drawLine(dst *image.RGBA, x0, y0, x1, y1 int, c color.RGBA) {
	dx, sx := abs(x1-x0), -1
	if x0 < x1 {
		sx = 1
	}
	dy, sy := -abs(y1-y0), -1
	if y0 < y1 {
		sy = 1
	}
	err := dx + dy
	for {
		blendPixel(dst, x0, y0, c)
		if x0 == x1 && y0 == y1 {
			break
		}
		e2 := 2 * err
		if e2 >= dy {
			err += dy
			x0 += sx
		}
		if e2 <= dx {
			err += dx
			y0 += sy
		}
	}
}

func blendPixel(dst *image.RGBA, x, y int, c color.RGBA) {
	if !image.Pt(x, y).In(dst.Bounds()) {
		return
	}
	base := dst.RGBAAt(x, y)
	a := uint32(c.A)
	inv := uint32(255 - c.A)
	dst.SetRGBA(x, y, color.RGBA{R: uint8((uint32(c.R)*a + uint32(base.R)*inv) / 255), G: uint8((uint32(c.G)*a + uint32(base.G)*inv) / 255), B: uint8((uint32(c.B)*a + uint32(base.B)*inv) / 255), A: uint8(a + uint32(base.A)*inv/255)})
}

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}
