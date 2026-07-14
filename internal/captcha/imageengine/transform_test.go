package imageengine

import (
	"image"
	"image/color"
	"testing"
)

func TestRotateScaleTransparentEdgesKeepSourceHue(t *testing.T) {
	src := image.NewRGBA(image.Rect(0, 0, 24, 24))
	fill := color.RGBA{R: 225, G: 38, B: 62, A: 255}
	for y := 5; y < 19; y++ {
		for x := 5; x < 19; x++ {
			src.SetRGBA(x, y, fill)
		}
	}

	rotated, err := RotateScale(src, 23, 1, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	for y := rotated.Bounds().Min.Y; y < rotated.Bounds().Max.Y; y++ {
		for x := rotated.Bounds().Min.X; x < rotated.Bounds().Max.X; x++ {
			pixel := rotated.RGBAAt(x, y)
			if pixel.A == 0 || pixel.A == 255 {
				continue
			}
			if int(pixel.R)*3 < int(pixel.A)*2 || pixel.G > pixel.R/2 || pixel.B > pixel.R/2 {
				t.Fatalf("transparent edge changed hue at (%d,%d): %#v", x, y, pixel)
			}
		}
	}
}
