package imageengine

import (
	"image"
	"image/color"
	"math"
)

func RotateScale(src image.Image, degrees, scale float64, limits Limits) (*image.RGBA, error) {
	if src == nil || scale <= 0 || math.IsNaN(scale) || math.IsInf(scale, 0) {
		return nil, ErrInvalidImage
	}
	b := src.Bounds()
	if b.Empty() {
		return nil, ErrInvalidImage
	}
	radians := degrees * math.Pi / 180
	cosA, sinA := math.Abs(math.Cos(radians)), math.Abs(math.Sin(radians))
	width := int(math.Ceil((float64(b.Dx())*cosA + float64(b.Dy())*sinA) * scale))
	height := int(math.Ceil((float64(b.Dx())*sinA + float64(b.Dy())*cosA) * scale))
	limits = limits.normalized()
	if err := limits.validateDimensions(width, height); err != nil {
		return nil, err
	}
	dst := image.NewRGBA(image.Rect(0, 0, width, height))
	cx, cy := float64(b.Min.X+b.Max.X)/2, float64(b.Min.Y+b.Max.Y)/2
	dx, dy := float64(width)/2, float64(height)/2
	cosR, sinR := math.Cos(radians), math.Sin(radians)
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			rx, ry := (float64(x)+0.5-dx)/scale, (float64(y)+0.5-dy)/scale
			sx := cosR*rx + sinR*ry + cx - 0.5
			sy := -sinR*rx + cosR*ry + cy - 0.5
			dst.SetRGBA(x, y, bilinearRGBA(src, sx, sy))
		}
	}
	return dst, nil
}

func bilinearRGBA(src image.Image, x, y float64) color.RGBA {
	b := src.Bounds()
	if x < float64(b.Min.X) || y < float64(b.Min.Y) || x > float64(b.Max.X-1) || y > float64(b.Max.Y-1) {
		return color.RGBA{}
	}
	x0, y0 := int(math.Floor(x)), int(math.Floor(y))
	x1, y1 := x0+1, y0+1
	if x1 >= b.Max.X {
		x1 = b.Max.X - 1
	}
	if y1 >= b.Max.Y {
		y1 = b.Max.Y - 1
	}
	tx, ty := x-float64(x0), y-float64(y0)
	c00 := color.NRGBAModel.Convert(src.At(x0, y0)).(color.NRGBA)
	c10 := color.NRGBAModel.Convert(src.At(x1, y0)).(color.NRGBA)
	c01 := color.NRGBAModel.Convert(src.At(x0, y1)).(color.NRGBA)
	c11 := color.NRGBAModel.Convert(src.At(x1, y1)).(color.NRGBA)
	w00, w10 := (1-tx)*(1-ty), tx*(1-ty)
	w01, w11 := (1-tx)*ty, tx*ty
	alpha := w00*float64(c00.A) + w10*float64(c10.A) + w01*float64(c01.A) + w11*float64(c11.A)
	if alpha <= 0 {
		return color.RGBA{}
	}
	premultiply := func(v00, v10, v01, v11, a00, a10, a01, a11 uint8) uint8 {
		value := w00*float64(v00)*float64(a00) + w10*float64(v10)*float64(a10) +
			w01*float64(v01)*float64(a01) + w11*float64(v11)*float64(a11)
		return uint8(math.Min(255, value/255+0.5))
	}
	return color.RGBA{
		R: premultiply(c00.R, c10.R, c01.R, c11.R, c00.A, c10.A, c01.A, c11.A),
		G: premultiply(c00.G, c10.G, c01.G, c11.G, c00.A, c10.A, c01.A, c11.A),
		B: premultiply(c00.B, c10.B, c01.B, c11.B, c00.A, c10.A, c01.A, c11.A),
		A: uint8(math.Min(255, alpha+0.5)),
	}
}
